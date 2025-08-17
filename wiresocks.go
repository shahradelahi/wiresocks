package wiresocks

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/tun/netstack"

	"github.com/shahradelahi/wiresocks/proxy/http"
	"github.com/shahradelahi/wiresocks/proxy/socks5"
	"github.com/shahradelahi/wiresocks/proxy/statute"
)

// ProxyConfig holds the configuration for the proxies.
type ProxyConfig struct {
	SocksBindAddr *netip.AddrPort
	HttpBindAddr  *netip.AddrPort
	Username      string
	Password      string
}

// ConnectivityTestOptions holds the configuration for the connectivity test.
type ConnectivityTestOptions struct {
	Enabled bool
	URL     string
	Timeout time.Duration
}

type WireSocks struct {
	conf                 *Configuration
	socksBindAddress     *netip.AddrPort
	httpBindAddress      *netip.AddrPort
	username             string
	password             string
	connectivityTestOpts *ConnectivityTestOptions

	vt      *VirtualTun
	httpLn  net.Listener
	socksLn net.Listener
	errCh   chan error

	logger *Logger

	ctx    context.Context
	cancel context.CancelFunc
}

func NewWireSocks(options ...Option) (*WireSocks, error) {
	var dnsAddrs []netip.Addr
	for _, dns := range []string{"1.1.1.1", "1.0.0.1", "2606:4700:4700::1112", "2606:4700:4700::1112"} {
		addr := netip.MustParseAddr(dns)
		dnsAddrs = append(dnsAddrs, addr)
	}

	logger := NewLogger(LogLevelError)

	iface := InterfaceConfig{
		DNS:        dnsAddrs,
		PrivateKey: "",
		Addresses:  []netip.Prefix{},
		MTU:        1280,
		FwMark:     0x0,
	}

	ctx, cancel := context.WithCancel(context.Background())

	s := &WireSocks{
		conf: &Configuration{
			Interface: &iface,
			Peers:     []PeerConfig{},
		},
		connectivityTestOpts: &ConnectivityTestOptions{
			Enabled: false,
			URL:     "https://1.1.1.1/cdn-cgi/trace/",
			Timeout: 10 * time.Second,
		},

		logger: logger,

		ctx:    ctx,
		cancel: cancel,
	}

	for _, option := range options {
		option(s)
	}

	return s, nil
}

func (s *WireSocks) Run() error {
	if s.socksBindAddress == nil && s.httpBindAddress == nil {
		return errors.New("no proxy listeners configured")
	}

	// Establish wireguard on userspace stack
	vt, err := s.startWireguard()
	if err != nil {
		return err
	}
	s.vt = vt
	if s.vt.Dev != nil {
		defer func() {
			s.vt.Dev.Close()
		}()
	}

	if s.connectivityTestOpts.Enabled {
		s.logger.Verbosef("Wiresocks: Performing connectivity test.")
		if err := s.vt.CheckConnectivity(s.ctx, s.connectivityTestOpts.URL, s.connectivityTestOpts.Timeout); err != nil {
			return fmt.Errorf("connectivity test failed: %w", err)
		}
	}

	s.errCh = make(chan error, 2)

	if s.socksBindAddress != nil {
		if err := s.startSocksProxy(); err != nil {
			return err
		}
	}

	if s.httpBindAddress != nil {
		if err := s.startHttpProxy(); err != nil {
			return err
		}
	}

	go func() {
		<-s.ctx.Done()
		s.vt.Stop()
		s.closeListeners()
	}()

	select {
	case err := <-s.errCh:
		s.Stop()
		return err
	case <-s.ctx.Done():
		return nil
	}
}

func (s *WireSocks) Stop() {
	s.logger.Verbosef("Wiresocks: Stopping WireSocks.")
	s.cancel()
	s.closeListeners()
}

func (s *WireSocks) closeListeners() {
	if s.httpLn != nil {
		_ = s.httpLn.Close()
	}
	if s.socksLn != nil {
		_ = s.socksLn.Close()
	}
}

func (s *WireSocks) startSocksProxy() error {
	ln, err := net.Listen("tcp", s.socksBindAddress.String())
	if err != nil {
		return fmt.Errorf("failed to listen on Socks5 address %s: %v", s.socksBindAddress.String(), err)
	}

	if s.socksLn != nil {
		_ = s.socksLn.Close()
	}
	s.socksLn = ln

	opts := []socks5.ServerOption{
		socks5.WithListener(s.socksLn),
		socks5.WithContext(s.ctx),
		socks5.WithProxyDial(s.vt.Tnet.DialContext),
		socks5.WithResolver(s.vt),
	}

	if s.username != "" && s.password != "" {
		opts = append(opts, socks5.WithCredentials(statute.StaticCredentials{
			s.username: s.password,
		}))
	}

	server := socks5.NewServer(opts...)

	go func() {
		if err := server.ListenAndServe(); err != nil {
			s.errCh <- fmt.Errorf("socks5 server server stopped with error: %v", err)
		}
	}()

	s.logger.Verbosef("Wiresocks: Started Socks5 proxy server on %s", s.socksBindAddress.String())

	return nil
}

func (s *WireSocks) startHttpProxy() error {
	ln, err := net.Listen("tcp", s.httpBindAddress.String())
	if err != nil {
		return fmt.Errorf("failed to listen on HTTP address %s: %v", s.httpBindAddress.String(), err)
	}

	if s.httpLn != nil {
		_ = s.httpLn.Close()
	}
	s.httpLn = ln

	opts := []http.ServerOption{
		http.WithListener(s.httpLn),
		http.WithContext(s.ctx),
		http.WithProxyDial(s.vt.Tnet.DialContext),
		http.WithResolver(s.vt),
	}

	if s.username != "" && s.password != "" {
		opts = append(opts, http.WithCredentials(statute.StaticCredentials{
			s.username: s.password,
		}))
	}

	server := http.NewServer(opts...)

	go func() {
		if err := server.ListenAndServe(); err != nil {
			s.errCh <- fmt.Errorf("HTTP server server stopped with error: %v", err)
		}
	}()

	s.logger.Verbosef("Wiresocks: Started HTTP proxy server on %s", s.httpBindAddress.String())

	return nil
}

type Option func(*WireSocks)

func WithLogLevel(loglevel int) Option {
	return func(s *WireSocks) {
		s.logger = NewLogger(loglevel)
	}
}

func WithContext(ctx context.Context) Option {
	return func(s *WireSocks) {
		ctx, cancel := context.WithCancel(ctx)
		s.ctx = ctx
		s.cancel = cancel
	}
}

func WithPeer(peer PeerConfig) Option {
	return func(s *WireSocks) {
		s.conf.Peers = append(s.conf.Peers, peer)
	}
}

func WithPrivateKey(key string) Option {
	return func(s *WireSocks) {
		s.conf.Interface.PrivateKey = key
	}
}

func WithWireguardConfig(conf *Configuration) Option {
	return func(s *WireSocks) {
		if conf.Interface != nil {
			if conf.Interface.PrivateKey != "" {
				s.conf.Interface.PrivateKey = conf.Interface.PrivateKey
			}
			if len(conf.Interface.Addresses) > 0 {
				s.conf.Interface.Addresses = conf.Interface.Addresses
			}
			if len(conf.Interface.DNS) > 0 {
				s.conf.Interface.DNS = conf.Interface.DNS
			}
			if conf.Interface.MTU > 0 {
				s.conf.Interface.MTU = conf.Interface.MTU
			}
			if conf.Interface.FwMark > 0 {
				s.conf.Interface.FwMark = conf.Interface.FwMark
			}
		}

		if len(conf.Peers) > 0 {
			s.conf.Peers = conf.Peers
		}
	}
}

func WithProxyConfig(opts *ProxyConfig) Option {
	return func(s *WireSocks) {
		s.socksBindAddress = opts.SocksBindAddr
		s.httpBindAddress = opts.HttpBindAddr
		s.username = opts.Username
		s.password = opts.Password
	}
}

func WithConnectivityTest(opts *ConnectivityTestOptions) Option {
	return func(s *WireSocks) {
		s.connectivityTestOpts = opts
	}
}

func (s *WireSocks) startWireguard() (*VirtualTun, error) {
	var interfaceAddrs []netip.Addr
	for _, prefix := range s.conf.Interface.Addresses {
		interfaceAddrs = append(interfaceAddrs, prefix.Addr())
	}

	tunDev, tnet, err := netstack.CreateNetTUN(interfaceAddrs, s.conf.Interface.DNS, s.conf.Interface.MTU)
	if err != nil {
		return nil, fmt.Errorf("failed to create netstack TUN device: %w", err)
	}

	s.logger.Verbosef("Wiresocks: Establishing WireGuard connection")
	dev, err := establishWireguard(s.conf, tunDev, s.logger.LogLevel)
	if err != nil {
		return nil, fmt.Errorf("failed to establish WireGuard connection: %w", err)
	}

	return &VirtualTun{Tnet: tnet, Dev: dev, ctx: s.ctx}, nil
}
