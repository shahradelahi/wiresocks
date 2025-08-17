package socks5

import (
	"context"
	"net"

	"github.com/shahradelahi/wiresocks/proxy/statute"
)

type ServerOption func(*Server)

func WithListener(ln net.Listener) ServerOption {
	return func(s *Server) {
		s.Listener = ln
	}
}

func WithBind(bindAddress string) ServerOption {
	return func(s *Server) {
		s.Bind = bindAddress
	}
}

func WithProxyDial(proxyDial statute.ProxyDialFunc) ServerOption {
	return func(s *Server) {
		s.ProxyDial = proxyDial
	}
}

func WithProxyListenPacket(proxyListenPacket statute.ProxyListenPacket) ServerOption {
	return func(s *Server) {
		s.ProxyListenPacket = proxyListenPacket
	}
}

func WithPacketForwardAddress(packetForwardAddress statute.PacketForwardAddress) ServerOption {
	return func(s *Server) {
		s.PacketForwardAddress = packetForwardAddress
	}
}

func WithCredentials(creds statute.CredentialStore) ServerOption {
	return func(s *Server) {
		s.Credentials = creds
	}
}

func WithResolver(resolver statute.NameResolver) ServerOption {
	return func(s *Server) {
		s.Resolver = resolver
	}
}

func WithContext(ctx context.Context) ServerOption {
	return func(s *Server) {
		s.Context = ctx
	}
}

func WithBytesPool(bytesPool statute.BytesPool) ServerOption {
	return func(s *Server) {
		s.BytesPool = bytesPool
	}
}
