package wiresocks

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

var (
	_ conn.Bind     = (*netstackBind)(nil)
	_ conn.Endpoint = (*netstackEndpoint)(nil)
)

type netstackEndpoint struct {
	netip.AddrPort
}

func (e *netstackEndpoint) ClearSrc() {}

func (e *netstackEndpoint) SrcToString() string {
	return ""
}

func (e *netstackEndpoint) DstToString() string {
	return e.String()
}

func (e *netstackEndpoint) DstToBytes() []byte {
	b, _ := e.MarshalBinary()
	return b
}

func (e *netstackEndpoint) DstIP() netip.Addr {
	return e.Addr()
}

func (e *netstackEndpoint) SrcIP() netip.Addr {
	return netip.Addr{}
}

// netstackBind implements conn.Bind on top of an upstream netstack.Net.
type netstackBind struct {
	tnet       *netstack.Net
	localAddrs []netip.Addr

	mu     sync.Mutex
	v4Conn *gonet.UDPConn
	v6Conn *gonet.UDPConn
	closed atomic.Bool
}

func NewNetstackBind(tnet *netstack.Net, localAddrs ...netip.Addr) conn.Bind {
	addrs := make([]netip.Addr, len(localAddrs))
	copy(addrs, localAddrs)
	return &netstackBind{
		tnet:       tnet,
		localAddrs: addrs,
	}
}

func (b *netstackBind) resolveBindAddrs() (v4Addr, v6Addr netip.Addr, hasV4, hasV6 bool) {
	if len(b.localAddrs) == 0 {
		return netip.IPv4Unspecified(), netip.IPv6Unspecified(), true, true
	}
	for _, addr := range b.localAddrs {
		addr = addr.Unmap()
		if addr.Is4() && !hasV4 {
			v4Addr = addr
			hasV4 = true
		} else if addr.Is6() && !hasV6 {
			v6Addr = addr
			hasV6 = true
		}
	}
	return v4Addr, v6Addr, hasV4, hasV6
}

func (b *netstackBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.tnet == nil {
		return nil, 0, errors.New("netstack bind: nil netstack")
	}
	if b.v4Conn != nil || b.v6Conn != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}

	b.closed.Store(false)

	v4Addr, v6Addr, hasV4, hasV6 := b.resolveBindAddrs()
	if !hasV4 && !hasV6 {
		return nil, 0, errors.New("netstack bind: no local addresses configured")
	}

	var fns []conn.ReceiveFunc
	actualPort := port

	if hasV4 {
		c, p, err := b.listenUDP(v4Addr, actualPort)
		if err != nil {
			if len(b.localAddrs) > 0 || !hasV6 {
				return nil, 0, fmt.Errorf("netstack bind IPv4 listen: %w", err)
			}
		} else {
			b.v4Conn = c
			actualPort = p
			fns = append(fns, b.makeReceiveFunc(c))
		}
	}

	if hasV6 {
		c, p, err := b.listenUDP(v6Addr, actualPort)
		if err != nil {
			if len(b.localAddrs) > 0 || len(fns) == 0 {
				if b.v4Conn != nil {
					_ = b.v4Conn.Close()
					b.v4Conn = nil
				}
				return nil, 0, fmt.Errorf("netstack bind IPv6 listen: %w", err)
			}
		} else {
			b.v6Conn = c
			if actualPort == 0 {
				actualPort = p
			}
			fns = append(fns, b.makeReceiveFunc(c))
		}
	}

	if len(fns) == 0 {
		return nil, 0, errors.New("netstack bind: failed to open any UDP listener")
	}

	return fns, actualPort, nil
}

func (b *netstackBind) listenUDP(addr netip.Addr, port uint16) (*gonet.UDPConn, uint16, error) {
	c, err := b.tnet.ListenUDPAddrPort(netip.AddrPortFrom(addr, port))
	if err != nil {
		return nil, 0, err
	}

	uaddr, ok := c.LocalAddr().(*net.UDPAddr)
	if !ok {
		_ = c.Close()
		return nil, 0, fmt.Errorf("unexpected local address type %T", c.LocalAddr())
	}

	return c, uint16(uaddr.Port), nil
}

func (b *netstackBind) makeReceiveFunc(c *gonet.UDPConn) conn.ReceiveFunc {
	return func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		n, raddr, err := c.ReadFrom(packets[0])
		if err != nil {
			if b.closed.Load() || errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) {
				return 0, net.ErrClosed
			}
			return 0, err
		}

		uaddr, ok := raddr.(*net.UDPAddr)
		if !ok {
			return 0, fmt.Errorf("unexpected remote address type %T", raddr)
		}

		ap := uaddr.AddrPort()
		ap = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
		sizes[0] = n
		eps[0] = &netstackEndpoint{AddrPort: ap}
		return 1, nil
	}
}

func (b *netstackBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.closed.Store(true)

	var errs []error
	if b.v4Conn != nil {
		if err := b.v4Conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			errs = append(errs, err)
		}
		b.v4Conn = nil
	}
	if b.v6Conn != nil {
		if err := b.v6Conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			errs = append(errs, err)
		}
		b.v6Conn = nil
	}

	return errors.Join(errs...)
}

func (b *netstackBind) SetMark(uint32) error {
	return nil
}

func (b *netstackBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	nep, ok := ep.(*netstackEndpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}

	b.mu.Lock()
	if b.closed.Load() {
		b.mu.Unlock()
		return net.ErrClosed
	}
	var c *gonet.UDPConn
	if nep.Addr().Is4() {
		c = b.v4Conn
	} else if nep.Addr().Is6() {
		c = b.v6Conn
	}
	b.mu.Unlock()

	if c == nil {
		return fmt.Errorf("netstack bind: no socket open for %s", nep.Addr())
	}

	raddr := net.UDPAddrFromAddrPort(nep.AddrPort)
	for _, buf := range bufs {
		if _, err := c.WriteTo(buf, raddr); err != nil {
			return err
		}
	}

	return nil
}

func (b *netstackBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return &netstackEndpoint{
		AddrPort: netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()),
	}, nil
}

func (b *netstackBind) BatchSize() int {
	return 1
}
