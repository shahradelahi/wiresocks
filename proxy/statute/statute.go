package statute

import (
	"context"
	"net"
)

// CredentialStore is an interface for storing and validating user credentials.
type CredentialStore interface {
	Valid(user, password string) bool
}

// StaticCredentials stores a map of username to password.
type StaticCredentials map[string]string

// Valid checks if the given user and password are valid.
func (s StaticCredentials) Valid(user, password string) bool {
	pass, ok := s[user]
	if !ok {
		return false
	}
	return pass == password
}

// NameResolver is used to implement custom name resolution
type NameResolver interface {
	Resolve(ctx context.Context, name string) (context.Context, net.IP, error)
}

// DefaultResolver uses the system DNS to resolve host names
type DefaultResolver struct{}

// Resolve implement interface NameResolver
func (d DefaultResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	addr, err := net.ResolveIPAddr("ip", name)
	if err != nil {
		return ctx, nil, err
	}
	return ctx, addr.IP, err
}

// ProxyDialFunc is used for socks5, socks4 and http
type ProxyDialFunc func(ctx context.Context, network string, address string) (net.Conn, error)

// DefaultProxyDial for ProxyDialFunc type
func DefaultProxyDial() ProxyDialFunc {
	var dialer net.Dialer
	return dialer.DialContext
}

// ProxyListenPacket specifies the optional proxyListenPacket function for
// establishing the transport connection.
type ProxyListenPacket func(ctx context.Context, network string, address string) (net.PacketConn, error)

// DefaultProxyListenPacket for ProxyListenPacket type
func DefaultProxyListenPacket() ProxyListenPacket {
	var listener net.ListenConfig
	return listener.ListenPacket
}

// PacketForwardAddress specifies the packet forwarding address
type PacketForwardAddress func(ctx context.Context, destinationAddr string,
	packet net.PacketConn, conn net.Conn) (net.IP, int, error)

// BytesPool is an interface for getting and returning temporary
// bytes for use by io.CopyBuffer.
type BytesPool interface {
	Get() []byte
	Put([]byte)
}

// DefaultContext for context.Context type
func DefaultContext() context.Context {
	return context.Background()
}
