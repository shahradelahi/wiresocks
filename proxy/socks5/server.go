package socks5

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"

	"github.com/shahradelahi/wiresocks/proxy/statute"
)

// Server is accepting connections and handling the details of the SOCKS5 protocol
type Server struct {
	// bind is the address to listen on
	Bind string

	Listener net.Listener

	// ProxyDial specifies the optional proxyDial function for
	// establishing the transport connection.
	ProxyDial statute.ProxyDialFunc
	// ProxyListenPacket specifies the optional proxyListenPacket function for
	// establishing the transport connection.
	ProxyListenPacket statute.ProxyListenPacket
	// PacketForwardAddress specifies the packet forwarding address
	PacketForwardAddress statute.PacketForwardAddress
	// Credentials provided for username/password authentication
	Credentials statute.CredentialStore
	// Resolver specifies the optional name resolver
	Resolver statute.NameResolver
	// Context is default context
	Context context.Context
	// BytesPool getting and returning temporary bytes for use by io.CopyBuffer
	BytesPool statute.BytesPool
}

func NewServer(options ...ServerOption) *Server {
	s := &Server{
		Bind:                 defaultBindAddress,
		ProxyDial:            statute.DefaultProxyDial(),
		ProxyListenPacket:    statute.DefaultProxyListenPacket(),
		PacketForwardAddress: defaultReplyPacketForwardAddress,
		Context:              statute.DefaultContext(),
		Credentials:          nil,
		Resolver:             &statute.DefaultResolver{},
	}

	for _, option := range options {
		option(s)
	}

	return s
}

func (s *Server) ListenAndServe() error {

	// Create a cancelable context based on s.Context
	ctx, cancel := context.WithCancel(s.Context)
	defer cancel() // Ensure resources are cleaned up

	// Start to accept connections and serve them
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("SOCKS5 proxy server shutting down: %w", ctx.Err())
		default:
			conn, err := s.Listener.Accept()
			if err != nil {
				return fmt.Errorf("failed to accept SOCKS5 connection: %w", err)
			}
			// Start a new goroutine to handle each connection
			// This way, the server can handle multiple connections concurrently
			go func() {
				defer func() {
					_ = conn.Close()
				}()
				_ = s.ServeConn(conn)
			}()
		}
	}
}

func (s *Server) ServeConn(conn net.Conn) error {
	clientAddr := conn.RemoteAddr()
	version, err := readByte(conn)
	if err != nil {
		return fmt.Errorf("failed to read SOCKS version from %s: %w", clientAddr, err)
	}
	if version != socks5Version {
		return fmt.Errorf("unsupported SOCKS version %d from %s, expected %d", version, clientAddr, socks5Version)
	}

	if err := s.authenticate(conn); err != nil {
		return fmt.Errorf("SOCKS5 authentication failed for %s: %w", clientAddr, err)
	}

	return s.handleRequest(conn)
}

func (s *Server) authenticate(conn net.Conn) error {
	methods, err := readBytes(conn)
	if err != nil {
		return fmt.Errorf("failed to read authentication methods from %s: %w", conn.RemoteAddr(), err)
	}

	// If credentials are provided, we require username/password auth
	if s.Credentials != nil {
		if bytes.IndexByte(methods, byte(usernamePasswordAuth)) != -1 {
			if _, err := conn.Write([]byte{socks5Version, byte(usernamePasswordAuth)}); err != nil {
				return fmt.Errorf("failed to write Username/Password auth response to %s: %w", conn.RemoteAddr(), err)
			}
			return s.handleUsernamePasswordAuth(conn)
		}
	} else { // No credentials, so no-auth is fine
		if bytes.IndexByte(methods, byte(noAuth)) != -1 {
			_, err := conn.Write([]byte{socks5Version, byte(noAuth)})
			if err != nil {
				return err
			}
			return nil
		}
	}

	// No acceptable methods
	_, err = conn.Write([]byte{socks5Version, byte(noAcceptable)})
	if err != nil {
		return fmt.Errorf("failed to write no acceptable methods response to %s: %w", conn.RemoteAddr(), err)
	}
	return errNoSupportedAuth
}

func (s *Server) handleUsernamePasswordAuth(conn net.Conn) error {
	version, err := readByte(conn)
	if err != nil {
		return fmt.Errorf("failed to read auth version from %s: %w", conn.RemoteAddr(), err)
	}
	if version != 1 {
		return fmt.Errorf("unsupported auth version %d from %s", version, conn.RemoteAddr())
	}

	username, err := readBytes(conn)
	if err != nil {
		return fmt.Errorf("failed to read username from %s: %w", conn.RemoteAddr(), err)
	}

	password, err := readBytes(conn)
	if err != nil {
		return fmt.Errorf("failed to read password from %s: %w", conn.RemoteAddr(), err)
	}

	if !s.Credentials.Valid(string(username), string(password)) {
		_, err := conn.Write([]byte{userAuthVersion, authFailure}) // failure
		if err != nil {
			return err
		}
		return errUserAuthFailed
	}

	_, err = conn.Write([]byte{userAuthVersion, authSuccess}) // success
	if err != nil {
		return fmt.Errorf("failed to write auth failure response to %s: %w", conn.RemoteAddr(), err)
	}

	return nil
}

func (s *Server) handleRequest(conn net.Conn) error {
	req := &request{
		Version: socks5Version,
		Conn:    conn,
	}

	var header [3]byte
	_, err := io.ReadFull(conn, header[:])
	if err != nil {
		return fmt.Errorf("failed to read request header from %s: %w", conn.RemoteAddr(), err)
	}

	if header[0] != socks5Version {
		return fmt.Errorf("unsupported SOCKS5 command version %d from %s, expected %d", header[0], conn.RemoteAddr(), socks5Version)
	}

	req.Command = Command(header[1])

	dest, err := readAddr(conn)
	if err != nil {
		if errors.Is(err, errUnrecognizedAddrType) {
			_ = sendReply(conn, addrTypeNotSupported, nil)
			return fmt.Errorf("unrecognized address type from %s: %w", conn.RemoteAddr(), err)
		}
		return fmt.Errorf("failed to read destination address from %s: %w", conn.RemoteAddr(), err)
	}
	req.DestinationAddr = dest
	err = s.handle(req)
	if err != nil {
		return fmt.Errorf("error handling SOCKS5 request from %s: %w", conn.RemoteAddr(), err)
	}

	return nil
}

func (s *Server) handle(req *request) error {
	switch req.Command {
	case ConnectCommand:
		return s.handleConnect(req)
	case BindCommand:
		return s.handleBind(req)
	case AssociateCommand:
		return s.handleAssociate(req)
	default:
		if err := sendReply(req.Conn, commandNotSupported, nil); err != nil {
			return fmt.Errorf("failed to send commandNotSupported reply to %s: %w", req.Conn.RemoteAddr(), err)
		}
		return fmt.Errorf("unsupported SOCKS5 command: %v from %s", req.Command, req.Conn.RemoteAddr())
	}
}

func (s *Server) handleConnect(req *request) error {
	targetAddr := req.DestinationAddr.Address()

	if s.Resolver != nil && req.DestinationAddr.Name != "" {
		_, resolvedIP, err := s.Resolver.Resolve(s.Context, req.DestinationAddr.Name)
		if err != nil {
			_ = sendReply(req.Conn, errToReply(err), nil)
			return fmt.Errorf("failed to resolve destination %s: %w", req.DestinationAddr.Name, err)
		}
		targetAddr = net.JoinHostPort(resolvedIP.String(), strconv.Itoa(req.DestinationAddr.Port))
	}

	target, err := s.ProxyDial(s.Context, "tcp", targetAddr)
	if err != nil {
		_ = sendReply(req.Conn, errToReply(err), nil)
		return fmt.Errorf("failed to dial target %s for SOCKS5 CONNECT from %s: %w", targetAddr, req.Conn.RemoteAddr(), err)
	}
	defer func() {
		_ = target.Close()
	}()

	localAddr := target.LocalAddr()
	local, ok := localAddr.(*net.TCPAddr)
	if !ok {
		return fmt.Errorf("failed to get local TCP address for %s: %s://%s", req.Conn.RemoteAddr(), localAddr.Network(), localAddr.String())
	}
	bind := address{IP: local.IP, Port: local.Port}
	if err := sendReply(req.Conn, successReply, &bind); err != nil {
		return fmt.Errorf("failed to send SOCKS5 success reply to %s: %w", req.Conn.RemoteAddr(), err)
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
	return statute.Tunnel(s.Context, target, req.Conn, buf1, buf2)
}

func (s *Server) handleBind(req *request) error {
	ctx, cancel := context.WithCancel(s.Context)
	defer cancel()

	// Create a listener
	listenIP := req.Conn.LocalAddr().(*net.TCPAddr).IP
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: listenIP})
	if err != nil {
		_ = sendReply(req.Conn, serverFailure, nil)
		return fmt.Errorf("failed to listen for SOCKS5 BIND for %s: %w", req.Conn.RemoteAddr(), err)
	}
	defer func() {
		_ = listener.Close()
	}()

	// Send first reply
	listenAddr := listener.Addr().(*net.TCPAddr)
	bindAddr := address{IP: listenAddr.IP, Port: listenAddr.Port}
	if err := sendReply(req.Conn, successReply, &bindAddr); err != nil {
		return fmt.Errorf("failed to send first SOCKS5 reply to %s: %w", req.Conn.RemoteAddr(), err)
	}

	// Wait for incoming connection
	var remoteConn net.Conn
	acceptChan := make(chan error, 1)
	go func() {
		var err error
		remoteConn, err = listener.Accept()
		acceptChan <- err
	}()

	select {
	case err := <-acceptChan:
		if err != nil {
			_ = sendReply(req.Conn, serverFailure, nil)
			return fmt.Errorf("failed to accept incoming connection for SOCKS5 BIND for %s: %w", req.Conn.RemoteAddr(), err)
		}
	case <-ctx.Done():
		_ = sendReply(req.Conn, serverFailure, nil)
		return fmt.Errorf("SOCKS5 BIND accept timeout for %s: %w", req.Conn.RemoteAddr(), ctx.Err())
	}
	defer func() {
		_ = remoteConn.Close()
	}()

	remoteTCPAddr := remoteConn.RemoteAddr().(*net.TCPAddr)
	if req.DestinationAddr.IP != nil && !req.DestinationAddr.IP.IsUnspecified() {
		if !remoteTCPAddr.IP.Equal(req.DestinationAddr.IP) {
			_ = sendReply(req.Conn, ruleFailure, nil)
			return fmt.Errorf("SOCKS5 BIND address mismatch for %s: got %s, want %s", req.Conn.RemoteAddr(), remoteTCPAddr.IP, req.DestinationAddr.IP)
		}
	}

	// Send second reply
	remoteAddr := address{IP: remoteTCPAddr.IP, Port: remoteTCPAddr.Port}
	if err := sendReply(req.Conn, successReply, &remoteAddr); err != nil {
		return fmt.Errorf("failed to send second SOCKS5 reply to %s: %w", req.Conn.RemoteAddr(), err)
	}

	// Tunnel data
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
	return statute.Tunnel(s.Context, remoteConn, req.Conn, buf1, buf2)
}

func (s *Server) handleAssociate(req *request) error {
	destinationAddr := req.DestinationAddr.String()
	udpConn, err := s.ProxyListenPacket(s.Context, "udp", destinationAddr)
	if err != nil {
		_ = sendReply(req.Conn, errToReply(err), nil)
		return fmt.Errorf("failed to listen for SOCKS5 UDP ASSOCIATE on %s for %s: %w", destinationAddr, req.Conn.RemoteAddr(), err)
	}

	ip, port, err := s.PacketForwardAddress(s.Context, destinationAddr, udpConn, req.Conn)
	if err != nil {
		return fmt.Errorf("failed to get packet forward address for %s: %w", req.Conn.RemoteAddr(), err)
	}
	bind := address{IP: ip, Port: port}
	if err := sendReply(req.Conn, successReply, &bind); err != nil {
		return fmt.Errorf("failed to send SOCKS5 success reply to %s: %w", req.Conn.RemoteAddr(), err)
	}

	defer func() {
		_ = udpConn.Close()
	}()

	go func() {
		var buf [1]byte
		for {
			_, err := req.Conn.Read(buf[:])
			if err != nil {
				_ = udpConn.Close()
				break
			}
		}
	}()

	var (
		sourceAddr  net.Addr
		wantSource  string
		targetAddr  net.Addr
		wantTarget  string
		replyPrefix []byte
		buf         [maxUdpPacket]byte
	)

	for {
		n, addr, err := udpConn.ReadFrom(buf[:])
		if err != nil {
			return fmt.Errorf("error reading from UDP connection for SOCKS5 UDP ASSOCIATE for %s: %w", req.Conn.RemoteAddr(), err)
		}

		if sourceAddr == nil {
			sourceAddr = addr
			wantSource = sourceAddr.String()
		}

		gotAddr := addr.String()
		if wantSource == gotAddr {
			// Packet from client to target
			if n < 3 {
				continue
			}
			reader := bytes.NewBuffer(buf[3:n])
			addr, err := readAddr(reader)
			if err != nil {
				continue
			}
			if targetAddr == nil {
				targetAddr = &net.UDPAddr{
					IP:   addr.IP,
					Port: addr.Port,
				}
				wantTarget = targetAddr.String()
			}
			if addr.String() != wantTarget {
				continue
			}
			_, err = udpConn.WriteTo(reader.Bytes(), targetAddr)
			if err != nil {
				return fmt.Errorf("failed to write UDP packet to target %s for SOCKS5 UDP ASSOCIATE: %w", targetAddr.String(), err)
			}
		} else if targetAddr != nil && wantTarget == gotAddr {
			// Packet from target to client
			if replyPrefix == nil {
				b := bytes.NewBuffer(make([]byte, 3, 16))
				err = writeAddrWithStr(b, wantTarget)
				if err != nil {
					return fmt.Errorf("failed to create reply prefix for SOCKS5 UDP ASSOCIATE: %w", err)
				}
				replyPrefix = b.Bytes()
			}
			copy(buf[len(replyPrefix):len(replyPrefix)+n], buf[:n])
			copy(buf[:len(replyPrefix)], replyPrefix)
			_, err = udpConn.WriteTo(buf[:len(replyPrefix)+n], sourceAddr)
			if err != nil {
				return fmt.Errorf("failed to write UDP packet to source %s for SOCKS5 UDP ASSOCIATE: %w", sourceAddr.String(), err)
			}
		} else { //nolint:staticcheck
			// Ignoring UDP packet from unknown source
		}
	}
}

func sendReply(w io.Writer, resp reply, addr *address) error {
	_, err := w.Write([]byte{socks5Version, byte(resp), 0})
	if err != nil {
		return fmt.Errorf("failed to write SOCKS5 reply header: %w", err)
	}
	err = writeAddr(w, addr)
	if err != nil {
		return fmt.Errorf("failed to write SOCKS5 reply address %s: %w", addr.String(), err)
	}
	return err
}

type request struct {
	Version         uint8
	Command         Command
	DestinationAddr *address
	Username        string
	Password        string
	Conn            net.Conn
}

func defaultReplyPacketForwardAddress(_ context.Context, destinationAddr string, packet net.PacketConn, conn net.Conn) (net.IP, int, error) {
	udpLocal := packet.LocalAddr()
	udpLocalAddr, ok := udpLocal.(*net.UDPAddr)
	if !ok {
		return nil, 0, fmt.Errorf("failed to get local UDP address for destination %s: %s://%s", destinationAddr, udpLocal.Network(), udpLocal.String())
	}

	tcpLocal := conn.LocalAddr()
	tcpLocalAddr, ok := tcpLocal.(*net.TCPAddr)
	if !ok {
		return nil, 0, fmt.Errorf("failed to get local TCP address for destination %s: %s://%s", destinationAddr, tcpLocal.Network(), tcpLocal.String())
	}
	return tcpLocalAddr.IP, udpLocalAddr.Port, nil
}
