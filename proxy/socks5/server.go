package socks5

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"

	"github.com/go-gost/gosocks5"

	"github.com/shahradelahi/wiresocks/proxy/statute"
)

const (
	defaultBindAddress = "127.0.0.1:1080"
)

type Server struct {
	Bind                 string
	Listener             net.Listener
	ProxyDial            statute.ProxyDialFunc
	ProxyListenPacket    statute.ProxyListenPacket
	PacketForwardAddress statute.PacketForwardAddress
	Credentials          statute.CredentialStore
	Resolver             statute.NameResolver
	Context              context.Context
	BytesPool            statute.BytesPool
}

func NewServer(options ...ServerOption) *Server {
	s := &Server{
		Bind:              defaultBindAddress,
		ProxyDial:         statute.DefaultProxyDial(),
		ProxyListenPacket: statute.DefaultProxyListenPacket(),
		Context:           statute.DefaultContext(),
		Resolver:          &statute.DefaultResolver{},
	}

	for _, option := range options {
		option(s)
	}
	return s
}

func (s *Server) ListenAndServe() error {
	ctx, cancel := context.WithCancel(s.Context)
	defer cancel()

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("SOCKS5 proxy server shutting down: %w", ctx.Err())
		default:
			conn, err := s.Listener.Accept()
			if err != nil {
				return fmt.Errorf("failed to accept SOCKS5 connection: %w", err)
			}
			go func() {
				defer conn.Close()
				_ = s.ServeConn(conn)
			}()
		}
	}
}

// Custom selector to bridge gosocks5 and statute.CredentialStore
type authSelector struct {
	creds statute.CredentialStore
}

func (s *authSelector) Methods() []uint8 {
	return []uint8{gosocks5.MethodUserPass}
}

func (s *authSelector) Select(methods ...uint8) uint8 {
	for _, m := range methods {
		if m == gosocks5.MethodUserPass {
			return gosocks5.MethodUserPass
		}
	}
	return gosocks5.MethodNoAcceptable
}

func (s *authSelector) OnSelected(method uint8, conn net.Conn) (string, net.Conn, error) {
	if method != gosocks5.MethodUserPass {
		return "", nil, gosocks5.ErrBadMethod
	}
	req, err := gosocks5.ReadUserPassRequest(conn)
	if err != nil {
		return "", nil, err
	}
	if !s.creds.Valid(req.Username, req.Password) {
		_ = gosocks5.NewUserPassResponse(gosocks5.UserPassVer, gosocks5.Failure).Write(conn)
		return "", nil, gosocks5.ErrAuthFailure
	}
	_ = gosocks5.NewUserPassResponse(gosocks5.UserPassVer, gosocks5.Succeeded).Write(conn)
	return req.Username, conn, nil
}

type noAuthSelector struct{}

func (s *noAuthSelector) Methods() []uint8              { return []uint8{gosocks5.MethodNoAuth} }
func (s *noAuthSelector) Select(methods ...uint8) uint8 { return gosocks5.MethodNoAuth }
func (s *noAuthSelector) OnSelected(method uint8, conn net.Conn) (string, net.Conn, error) {
	return "", conn, nil
}

func (s *Server) ServeConn(conn net.Conn) error {
	var selector gosocks5.Selector
	if s.Credentials != nil {
		selector = &authSelector{creds: s.Credentials}
	} else {
		selector = &noAuthSelector{}
	}

	sconn := gosocks5.ServerConn(conn, selector)
	req, err := gosocks5.ReadRequest(sconn)
	if err != nil {
		return err
	}

	switch req.Cmd {
	case gosocks5.CmdConnect:
		return s.handleConnect(sconn, req)
	case gosocks5.CmdUdp:
		return s.handleUDPAssociate(sconn, req)
	default:
		_ = gosocks5.NewReply(gosocks5.CmdUnsupported, nil).Write(sconn)
		return fmt.Errorf("unsupported command: %d", req.Cmd)
	}
}

func (s *Server) handleConnect(conn net.Conn, req *gosocks5.Request) error {
	targetAddr := req.Addr.String()

	if s.Resolver != nil && req.Addr.Type == gosocks5.AddrDomain {
		_, resolvedIP, err := s.Resolver.Resolve(s.Context, req.Addr.Host)
		if err != nil {
			_ = gosocks5.NewReply(gosocks5.HostUnreachable, nil).Write(conn)
			return err
		}
		targetAddr = net.JoinHostPort(resolvedIP.String(), strconv.Itoa(int(req.Addr.Port)))
	}

	target, err := s.ProxyDial(s.Context, "tcp", targetAddr)
	if err != nil {
		_ = gosocks5.NewReply(gosocks5.NetUnreachable, nil).Write(conn)
		return err
	}
	defer target.Close()

	reply := gosocks5.NewReply(gosocks5.Succeeded, toSocksAddr(target.LocalAddr()))
	if err := reply.Write(conn); err != nil {
		return err
	}

	var buf1, buf2 []byte
	if s.BytesPool != nil {
		buf1 = s.BytesPool.Get()
		buf2 = s.BytesPool.Get()
		defer func() {
			s.BytesPool.Put(buf1)
			s.BytesPool.Put(buf2)
		}()
	} else {
		buf1 = make([]byte, 32*1024)
		buf2 = make([]byte, 32*1024)
	}

	return statute.Tunnel(s.Context, target, conn, buf1, buf2)
}

func (s *Server) handleUDPAssociate(tcpConn net.Conn, req *gosocks5.Request) error {
	tcpLocalAddr, ok := tcpConn.LocalAddr().(*net.TCPAddr)
	if !ok {
		_ = gosocks5.NewReply(gosocks5.Failure, nil).Write(tcpConn)
		return errors.New("not a TCP connection")
	}

	// 1. Bind local UDP for the client to send packets to
	localUDPAddr := &net.UDPAddr{IP: tcpLocalAddr.IP, Port: 0}
	clientSideUDP, err := net.ListenUDP("udp", localUDPAddr)
	if err != nil {
		_ = gosocks5.NewReply(gosocks5.Failure, nil).Write(tcpConn)
		return err
	}
	defer clientSideUDP.Close()

	// 2. Create UDP connection via WireGuard netstack BEFORE replying Succeeded.
	// This ensures that if the WireGuard tunnel isn't fully ready, we fail gracefully.
	wgSideUDP, err := s.ProxyListenPacket(s.Context, "udp", "")
	if err != nil {
		_ = gosocks5.NewReply(gosocks5.Failure, nil).Write(tcpConn)
		return err
	}
	defer wgSideUDP.Close()

	// 3. Reply to client with the successfully bound address
	replyAddr := clientSideUDP.LocalAddr().(*net.UDPAddr)
	if replyAddr.IP.IsUnspecified() {
		// Fallback to the IP the TCP connection was established on
		replyAddr.IP = tcpLocalAddr.IP
	}

	reply := gosocks5.NewReply(gosocks5.Succeeded, toSocksAddr(replyAddr))
	if err := reply.Write(tcpConn); err != nil {
		return err
	}

	// 4. Setup state and synchronization
	ctx, cancel := context.WithCancel(s.Context)
	defer cancel()

	var clientAddr net.Addr
	var clientAddrMutex sync.RWMutex

	// If TCP connection closes, kill the UDP association (SOCKS5 Spec requirement)
	go func() {
		defer cancel()
		// Discard reads until EOF to keep connection open without blocking memory
		_, _ = io.Copy(io.Discard, tcpConn)
	}()

	errCh := make(chan error, 2)

	// Upstream: Client -> WG
	go func() {
		buf := make([]byte, 65535)
		for {
			n, cAddr, err := clientSideUDP.ReadFrom(buf)
			if err != nil {
				errCh <- err
				return
			}

			// Store the client's address so we know where to send returning packets
			clientAddrMutex.Lock()
			if clientAddr == nil {
				clientAddr = cAddr
			}
			clientAddrMutex.Unlock()

			// Parse SOCKS5 UDP encapsulation
			d := &gosocks5.UDPDatagram{}
			if _, err := d.ReadFrom(bytes.NewReader(buf[:n])); err != nil {
				continue
			}
			if d.Header.Frag != 0 {
				continue // fragments not supported yet
			}

			targetHost := d.Header.Addr.String()
			if s.Resolver != nil && d.Header.Addr.Type == gosocks5.AddrDomain {
				_, resolvedIP, err := s.Resolver.Resolve(ctx, d.Header.Addr.Host)
				if err == nil {
					targetHost = net.JoinHostPort(resolvedIP.String(), strconv.Itoa(int(d.Header.Addr.Port)))
				}
			}

			targetUDPAddr, err := net.ResolveUDPAddr("udp", targetHost)
			if err != nil {
				continue
			}

			// Send raw payload into WireGuard
			_, _ = wgSideUDP.WriteTo(d.Data, targetUDPAddr)
		}
	}()

	// Downstream: WG -> Client
	go func() {
		buf := make([]byte, 65535)
		for {
			n, srcAddr, err := wgSideUDP.ReadFrom(buf)
			if err != nil {
				errCh <- err
				return
			}

			clientAddrMutex.RLock()
			cAddr := clientAddr
			clientAddrMutex.RUnlock()

			if cAddr == nil {
				continue // Nowhere to send yet
			}

			// Re-encapsulate the payload in a SOCKS5 UDP wrapper
			hdr := gosocks5.NewUDPHeader(0, 0, toSocksAddr(srcAddr))
			d := gosocks5.NewUDPDatagram(hdr, buf[:n])

			var out bytes.Buffer
			_, _ = d.WriteTo(&out)
			_, _ = clientSideUDP.WriteTo(out.Bytes(), cAddr)
		}
	}()

	select {
	case <-ctx.Done():
		return nil
	case err := <-errCh:
		return err
	}
}

func toSocksAddr(addr net.Addr) *gosocks5.Addr {
	host, portStr, _ := net.SplitHostPort(addr.String())
	port, _ := strconv.Atoi(portStr)

	a := &gosocks5.Addr{
		Host: host,
		Port: uint16(port),
	}

	// Ensure the correct Type is set
	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() != nil {
			a.Type = gosocks5.AddrIPv4
		} else {
			a.Type = gosocks5.AddrIPv6
		}
	} else {
		a.Type = gosocks5.AddrDomain
	}

	return a
}
