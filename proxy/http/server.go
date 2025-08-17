package http

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"

	"github.com/shahradelahi/wiresocks/proxy/statute"
)

const (
	defaultBindAddress = "127.0.0.1:8118"

	// Default ports
	defaultHTTPPort  = "80"
	defaultHTTPSPort = "443"

	// HTTP headers
	connectionHeader      = "Connection"
	upgradeHeader         = "Upgrade"
	capsuleProtocolHeader = "Capsule-Protocol"

	// HTTP header values
	connectIP = "connect-ip"
	upgrade   = "upgrade"

	// HTTP responses
	httpConnectionEstablished = "HTTP/1.1 200 Connection Established" + CRLF + CRLF
	httpSwitchingProtocols    = "HTTP/1.1 101 Switching Protocols" + CRLF +
		"Connection: Upgrade" + CRLF +
		"Upgrade: connect-ip" + CRLF +
		"Capsule-Protocol: ?1" + CRLF + CRLF
)

type Server struct {
	// Bind is the address to listen on
	Bind string

	Listener net.Listener

	// ProxyDial specifies the optional proxyDial function for
	// establishing the transport connection.
	ProxyDial statute.ProxyDialFunc
	// Resolver specifies the optional name resolver.
	Resolver statute.NameResolver
	// Context is default context
	Context context.Context
	// BytesPool getting and returning temporary bytes for use by io.CopyBuffer
	BytesPool statute.BytesPool
	// Credentials provided for username/password authentication
	Credentials statute.CredentialStore
	// Authenticator is used to authenticate users.
	Authenticator Authenticator
}

func NewServer(options ...ServerOption) *Server {
	s := &Server{
		Bind:      defaultBindAddress,
		ProxyDial: statute.DefaultProxyDial(),
		Context:   statute.DefaultContext(),
		Resolver:  &statute.DefaultResolver{},
	}

	for _, option := range options {
		option(s)
	}

	if s.Authenticator == nil {
		s.Authenticator = &BasicAuthenticator{
			Credentials: s.Credentials,
		}
	}

	return s
}

func (s *Server) ListenAndServe() error {
	// Create a new listener
	if s.Listener == nil {
		ln, err := net.Listen("tcp", s.Bind)
		if err != nil {
			return err // Return error if binding was unsuccessful
		}
		s.Listener = ln
	}

	s.Bind = s.Listener.Addr().(*net.TCPAddr).String()

	// ensure listener will be closed
	defer func() {
		_ = s.Listener.Close()
	}()

	// Create a cancelable context based on s.Context
	ctx, cancel := context.WithCancel(s.Context)
	defer cancel() // Ensure resources are cleaned up

	// Start to accept connections and serve them
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("HTTP proxy server shutting down: %w", ctx.Err())
		default:
			conn, err := s.Listener.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return nil
				}
				return fmt.Errorf("failed to accept incoming HTTP connection: %w", err)
			}

			// Start a new goroutine to handle each connection
			// This way, the server can handle multiple connections concurrently
			go func() {
				defer func() {
					_ = conn.Close()
				}()
				_ = s.ServeConn(conn) // Maybe an error channel?
			}()
		}
	}
}

func (s *Server) ServeConn(conn net.Conn) error {
	reader := bufio.NewReader(conn)
	req, err := http.ReadRequest(reader)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil // Client closed connection
		}
		return fmt.Errorf("failed to read HTTP request from %s: %w", conn.RemoteAddr(), err)
	}

	if s.Authenticator != nil && !s.Authenticator.Authenticate(req) {
		w := NewHTTPResponseWriter(conn)
		w.Header().Set("Proxy-Authenticate", "Basic realm=\"wiresocks\"")
		w.WriteHeader(http.StatusProxyAuthRequired)
		return fmt.Errorf("authentication failed for %s", conn.RemoteAddr())
	}

	// Handle IP proxying requests (RFC 9484)
	if req.Method == http.MethodGet &&
		strings.EqualFold(req.Header.Get(connectionHeader), upgrade) &&
		strings.EqualFold(req.Header.Get(upgradeHeader), connectIP) {
		return s.handleIPProxy(conn, req)
	}

	// Handle standard HTTP proxy requests
	return s.handleHTTP(conn, req, req.Method == http.MethodConnect)
}

// handleIPProxy handles IP proxying over HTTP (RFC 9484).
func (s *Server) handleIPProxy(conn net.Conn, req *http.Request) error {
	// As per RFC 9484, the "Capsule-Protocol" header must be present.
	if req.Header.Get(capsuleProtocolHeader) != "?1" {
		w := NewHTTPResponseWriter(conn)
		http.Error(w, "Capsule-Protocol header required for connect-ip", http.StatusBadRequest)
		return fmt.Errorf("missing or invalid Capsule-Protocol header from %s: %s", conn.RemoteAddr(), req.Header.Get(capsuleProtocolHeader))
	}

	// Respond with 101 Switching Protocols to establish the tunnel.
	if _, err := conn.Write([]byte(httpSwitchingProtocols)); err != nil {
		return fmt.Errorf("failed to write 101 Switching Protocols to %s: %w", conn.RemoteAddr(), err)
	}

	// TODO: Implement full IP proxying with capsule and datagram handling.
	// For now, we just keep the connection open to represent the tunnel.
	// This will block until the client closes the connection.
	_, err := io.Copy(io.Discard, conn)
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("error during IP proxy tunnel data discard for %s: %w", conn.RemoteAddr(), err)
	}
	return err
}

func (s *Server) handleHTTP(conn net.Conn, req *http.Request, isConnectMethod bool) error {
	host, port, targetAddr := getTarget(req, isConnectMethod)

	if s.Resolver != nil {
		if _, err := netip.ParseAddr(host); err != nil {
			// It's not an IP, so it's a domain name that needs to be resolved.
			_, resolvedIP, err := s.Resolver.Resolve(s.Context, host)
			if err != nil {
				return fmt.Errorf("failed to resolve destination %s: %w", host, err)
			}
			targetAddr = net.JoinHostPort(resolvedIP.String(), port)
		}
	}

	target, err := s.ProxyDial(s.Context, "tcp", targetAddr)
	if err != nil {
		http.Error(
			NewHTTPResponseWriter(conn),
			err.Error(),
			http.StatusServiceUnavailable,
		)
		return fmt.Errorf("failed to dial target %s for %s: %w", targetAddr, conn.RemoteAddr(), err)
	}
	defer func() {
		_ = target.Close()
	}()

	if isConnectMethod {
		if _, err = conn.Write([]byte(httpConnectionEstablished)); err != nil {
			return fmt.Errorf("failed to write 200 Connection Established to %s: %w", conn.RemoteAddr(), err)
		}
	} else {
		if err = req.Write(target); err != nil {
			return fmt.Errorf("failed to write request to target %s for %s: %w", targetAddr, conn.RemoteAddr(), err)
		}
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

// getTarget extracts the host, port, and full address from an HTTP request.
// It uses default ports for HTTP and HTTPS if not specified.
func getTarget(req *http.Request, isConnect bool) (host, port, addr string) {
	host, port, err := net.SplitHostPort(req.URL.Host)
	if err != nil {
		host = req.URL.Host
		if req.URL.Scheme == "https" || isConnect {
			port = defaultHTTPSPort
		} else {
			port = defaultHTTPPort
		}
	}
	addr = net.JoinHostPort(host, port)
	return
}
