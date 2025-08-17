package http

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

func WithCredentials(creds statute.CredentialStore) ServerOption {
	return func(s *Server) {
		s.Credentials = creds
	}
}

func WithAuthenticator(authenticator Authenticator) ServerOption {
	return func(s *Server) {
		s.Authenticator = authenticator
	}
}
