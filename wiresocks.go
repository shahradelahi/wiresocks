package wiresocks

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"

	"github.com/shahradelahi/wiresocks/proxy/http"
	"github.com/shahradelahi/wiresocks/proxy/socks5"
	"github.com/shahradelahi/wiresocks/proxy/statute"
)

const (
	defaultSingleHopMTU = 1280
	defaultChainHopMTU  = 1420
	wgOverheadIPv4      = 60
	wgOverheadIPv6      = 80
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
	confs                []*Configuration
	defaultConfigInUse   bool
	socksBindAddress     *netip.AddrPort
	httpBindAddress      *netip.AddrPort
	username             string
	password             string
	connectivityTestOpts *ConnectivityTestOptions

	vtMu    sync.Mutex
	vts     []*VirtualTun
	httpLn  net.Listener
	socksLn net.Listener
	errCh   chan error

	logger *Logger

	ctx    context.Context
	cancel context.CancelFunc
}

func defaultDNSAddrs() []netip.Addr {
	var dnsAddrs []netip.Addr
	for _, dns := range []string{"1.1.1.1", "1.0.0.1", "2606:4700:4700::1112", "2606:4700:4700::1112"} {
		dnsAddrs = append(dnsAddrs, netip.MustParseAddr(dns))
	}
	return dnsAddrs
}

func normalizeConfig(conf *Configuration) *Configuration {
	iface := InterfaceConfig{
		DNS: defaultDNSAddrs(),
	}
	var peers []PeerConfig

	if conf != nil {
		if conf.Interface != nil {
			iface = *conf.Interface
			iface.Addresses = append([]netip.Prefix(nil), conf.Interface.Addresses...)
			if len(conf.Interface.DNS) > 0 {
				iface.DNS = append([]netip.Addr(nil), conf.Interface.DNS...)
			} else {
				iface.DNS = defaultDNSAddrs()
			}
		}
		if len(conf.Peers) > 0 {
			peers = append([]PeerConfig(nil), conf.Peers...)
		}
	}

	return &Configuration{
		Interface: &iface,
		Peers:     peers,
	}
}

func NewWireSocks(options ...Option) (*WireSocks, error) {
	logger := NewLogger(LogLevelError)
	ctx, cancel := context.WithCancel(context.Background())

	s := &WireSocks{
		confs:              []*Configuration{normalizeConfig(nil)},
		defaultConfigInUse: true,
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
	if len(s.confs) == 0 {
		return errors.New("no wireguard configurations provided")
	}

	vts, err := s.startWireguardChain()
	if err != nil {
		return err
	}

	s.vtMu.Lock()
	s.vts = vts
	s.vtMu.Unlock()
	defer s.closeAllVTs()

	exitVT := vts[len(vts)-1]

	if s.connectivityTestOpts.Enabled {
		s.logger.Verbosef("Wiresocks: Performing connectivity test.")
		if err := exitVT.CheckConnectivity(s.ctx, s.connectivityTestOpts.URL, s.connectivityTestOpts.Timeout); err != nil {
			return fmt.Errorf("connectivity test failed: %w", err)
		}
	}

	s.errCh = make(chan error, 2)

	if s.socksBindAddress != nil {
		if err := s.startSocksProxy(exitVT); err != nil {
			return err
		}
	}

	if s.httpBindAddress != nil {
		if err := s.startHttpProxy(exitVT); err != nil {
			return err
		}
	}

	go func() {
		<-s.ctx.Done()
		s.closeListeners()
		s.stopAllVTs()
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

func (s *WireSocks) stopAllVTs() {
	s.vtMu.Lock()
	defer s.vtMu.Unlock()

	for i := len(s.vts) - 1; i >= 0; i-- {
		if s.vts[i] != nil {
			s.vts[i].Stop()
		}
	}
}

func (s *WireSocks) closeAllVTs() {
	s.vtMu.Lock()
	defer s.vtMu.Unlock()

	closeVTsReverse(s.vts)
	s.vts = nil
}

func closeVTsReverse(vts []*VirtualTun) {
	for i := len(vts) - 1; i >= 0; i-- {
		if vts[i] != nil && vts[i].Dev != nil {
			vts[i].Dev.Close()
		}
	}
}

func (s *WireSocks) closeListeners() {
	if s.httpLn != nil {
		_ = s.httpLn.Close()
	}
	if s.socksLn != nil {
		_ = s.socksLn.Close()
	}
}

func selectUDPBindAddr(addrs []netip.Addr) netip.Addr {
	for _, addr := range addrs {
		if unmapped := addr.Unmap(); unmapped.Is4() {
			return unmapped
		}
	}
	for _, addr := range addrs {
		if unmapped := addr.Unmap(); unmapped.Is6() {
			return unmapped
		}
	}
	return netip.IPv4Unspecified()
}

func (s *WireSocks) startSocksProxy(vt *VirtualTun) error {
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
		socks5.WithProxyDial(vt.Tnet.DialContext),
		socks5.WithProxyListenPacket(func(ctx context.Context, network, address string) (net.PacketConn, error) {
			var ap netip.AddrPort
			if address != "" {
				if parsed, err := netip.ParseAddrPort(address); err == nil {
					ap = parsed
				} else if udpAddr, err := net.ResolveUDPAddr(network, address); err == nil && udpAddr != nil {
					ap = udpAddr.AddrPort()
				}
			}
			if !ap.Addr().IsValid() || ap.Addr().IsUnspecified() {
				ap = netip.AddrPortFrom(selectUDPBindAddr(vt.localAddrs), ap.Port())
			}
			return vt.Tnet.ListenUDPAddrPort(ap)
		}),
		socks5.WithResolver(vt),
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

func (s *WireSocks) startHttpProxy(vt *VirtualTun) error {
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
		http.WithProxyDial(vt.Tnet.DialContext),
		http.WithResolver(vt),
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
		if len(s.confs) == 0 {
			s.confs = []*Configuration{normalizeConfig(nil)}
		}
		s.confs[0].Peers = append(s.confs[0].Peers, peer)
		s.defaultConfigInUse = false
	}
}

func WithPrivateKey(key string) Option {
	return func(s *WireSocks) {
		if len(s.confs) == 0 {
			s.confs = []*Configuration{normalizeConfig(nil)}
		}
		s.confs[0].Interface.PrivateKey = key
		s.defaultConfigInUse = false
	}
}

func WithWireguardConfig(conf *Configuration) Option {
	return func(s *WireSocks) {
		if conf == nil {
			return
		}
		if len(s.confs) == 0 {
			s.confs = []*Configuration{normalizeConfig(nil)}
		}

		dst := s.confs[0]
		if conf.Interface != nil {
			mergeInterfaceConfig(dst.Interface, conf.Interface)
		}
		if len(conf.Peers) > 0 {
			dst.Peers = append([]PeerConfig(nil), conf.Peers...)
		}
		s.defaultConfigInUse = false
	}
}

func mergeInterfaceConfig(dst, src *InterfaceConfig) {
	if src.PrivateKey != "" {
		dst.PrivateKey = src.PrivateKey
	}
	if len(src.Addresses) > 0 {
		dst.Addresses = append([]netip.Prefix(nil), src.Addresses...)
	}
	if len(src.DNS) > 0 {
		dst.DNS = append([]netip.Addr(nil), src.DNS...)
	}
	if src.MTU > 0 {
		dst.MTU = src.MTU
	}
	if src.FwMark > 0 {
		dst.FwMark = src.FwMark
	}
	if src.HasAmneziaWGParams() {
		dst.Jc = src.Jc
		dst.Jmin = src.Jmin
		dst.Jmax = src.Jmax
		dst.S1 = src.S1
		dst.S2 = src.S2
		dst.H1 = src.H1
		dst.H2 = src.H2
		dst.H3 = src.H3
		dst.H4 = src.H4
	}
}

// AddWireguardHop appends a WireGuard configuration hop to the tunnel chain.
func AddWireguardHop(conf *Configuration) Option {
	return func(s *WireSocks) {
		if conf == nil {
			return
		}
		normalized := normalizeConfig(conf)
		if s.defaultConfigInUse && len(s.confs) == 1 {
			s.confs[0] = normalized
			s.defaultConfigInUse = false
			return
		}
		s.confs = append(s.confs, normalized)
		s.defaultConfigInUse = false
	}
}

// WithWireguardChain replaces the WireGuard tunnel chain with the given hops in order (first = entry, last = exit).
func WithWireguardChain(confs ...*Configuration) Option {
	return func(s *WireSocks) {
		s.confs = make([]*Configuration, 0, len(confs))
		for _, conf := range confs {
			if conf != nil {
				s.confs = append(s.confs, normalizeConfig(conf))
			}
		}
		s.defaultConfigInUse = false
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

func (s *WireSocks) startWireguardChain() ([]*VirtualTun, error) {
	total := len(s.confs)
	vts := make([]*VirtualTun, 0, total)
	var upstream *VirtualTun
	prevMTU := 0

	for i, conf := range s.confs {
		if err := validateHopConfig(i, total, conf); err != nil {
			closeVTsReverse(vts)
			return nil, err
		}

		mtu, err := s.resolveHopMTU(i, total, conf, upstream, prevMTU)
		if err != nil {
			closeVTsReverse(vts)
			return nil, err
		}

		vt, err := s.startWireguardHop(i, total, conf, upstream, mtu)
		if err != nil {
			closeVTsReverse(vts)
			return nil, fmt.Errorf("hop %d/%d: %w", i+1, total, err)
		}

		vts = append(vts, vt)
		upstream = vt
		prevMTU = mtu
	}

	return vts, nil
}

func validateHopConfig(index, total int, conf *Configuration) error {
	if conf == nil || conf.Interface == nil || conf.Interface.PrivateKey == "" {
		return fmt.Errorf("hop %d/%d: interface PrivateKey is required", index+1, total)
	}
	if len(conf.Peers) == 0 {
		return fmt.Errorf("hop %d/%d: at least one peer is required", index+1, total)
	}
	if index < total-1 && len(conf.Interface.Addresses) == 0 {
		return fmt.Errorf("hop %d/%d: intermediate hop requires at least one interface Address", index+1, total)
	}
	return nil
}

func (s *WireSocks) resolveHopMTU(index, total int, conf *Configuration, upstream *VirtualTun, prevMTU int) (int, error) {
	configured := conf.Interface.MTU

	if index == 0 {
		if configured > 0 {
			return configured, nil
		}
		if total > 1 {
			return defaultChainHopMTU, nil
		}
		return defaultSingleHopMTU, nil
	}

	overhead := wgOverheadIPv4
	if upstream != nil && hasIPv6Addr(upstream.localAddrs) {
		overhead = wgOverheadIPv6
	}

	maxMTU := prevMTU - overhead
	if maxMTU <= 0 {
		return 0, fmt.Errorf("hop %d/%d: upstream MTU (%d) too small for WireGuard overhead (%d)", index+1, total, prevMTU, overhead)
	}

	mtu := maxMTU
	if configured > 0 {
		if configured > maxMTU {
			s.logger.Verbosef("Wiresocks: Clamping hop %d/%d MTU from %d to %d (upstream MTU %d - overhead %d)", index+1, total, configured, maxMTU, prevMTU, overhead)
		} else {
			mtu = configured
		}
	}

	if mtu < defaultSingleHopMTU {
		s.logger.Verbosef("Wiresocks: Hop %d/%d effective MTU (%d) is below %d", index+1, total, mtu, defaultSingleHopMTU)
	}

	return mtu, nil
}

func hasIPv6Addr(addrs []netip.Addr) bool {
	for _, addr := range addrs {
		if addr.Unmap().Is6() {
			return true
		}
	}
	return false
}

func (s *WireSocks) startWireguardHop(index, total int, conf *Configuration, upstream *VirtualTun, mtu int) (*VirtualTun, error) {
	interfaceAddrs := make([]netip.Addr, 0, len(conf.Interface.Addresses))
	for _, prefix := range conf.Interface.Addresses {
		interfaceAddrs = append(interfaceAddrs, prefix.Addr())
	}

	tunDev, tnet, err := netstack.CreateNetTUN(interfaceAddrs, conf.Interface.DNS, mtu)
	if err != nil {
		return nil, fmt.Errorf("failed to create netstack TUN device: %w", err)
	}

	if total > 1 {
		s.logger.Verbosef("Wiresocks: Establishing WireGuard connection (hop %d/%d, MTU %d)", index+1, total, mtu)
	} else {
		s.logger.Verbosef("Wiresocks: Establishing WireGuard connection")
	}

	dev, err := establishWireguard(s.ctx, conf, tunDev, upstream, s.logger.LogLevel)
	if err != nil {
		_ = tunDev.Close()
		return nil, fmt.Errorf("failed to establish WireGuard connection: %w", err)
	}

	return &VirtualTun{
		Tnet:       tnet,
		Dev:        dev,
		ctx:        s.ctx,
		localAddrs: interfaceAddrs,
	}, nil
}
