package wiresocks

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/device"
	"github.com/amnezia-vpn/amneziawg-go/tun/netstack"
)

// VirtualTun stores a reference to netstack network
type VirtualTun struct {
	Tnet *netstack.Net
	Dev  *device.Device
	ctx  context.Context
}

// Resolve resolves a hostname and returns an IP.
// DNS traffic may or may not be routed depending on VirtualTun's setting
func (vt VirtualTun) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	addr, err := vt.ResolveAddrWithContext(ctx, name)
	if err != nil {
		return nil, nil, err
	}

	return ctx, addr.AsSlice(), nil
}

// ResolveAddrWithContext resolves a hostname and returns an AddrPort.
// DNS traffic may or may not be routed depending on VirtualTun's setting
func (vt VirtualTun) ResolveAddrWithContext(ctx context.Context, name string) (*netip.Addr, error) {
	addrs, err := vt.LookupAddr(ctx, name)
	if err != nil {
		return nil, err
	}

	size := len(addrs)
	if size == 0 {
		return nil, errors.New("no address found for: " + name)
	}

	rand.Shuffle(size, func(i, j int) {
		addrs[i], addrs[j] = addrs[j], addrs[i]
	})

	for _, saddr := range addrs {
		addr := netip.MustParseAddr(saddr)
		return &addr, nil
	}

	return nil, errors.New("no supported IP address found for: " + name)
}

// LookupAddr lookups a hostname.
// DNS traffic may or may not be routed depending on VirtualTun's setting
func (vt VirtualTun) LookupAddr(ctx context.Context, name string) ([]string, error) {
	return vt.Tnet.LookupContextHost(ctx, name)
}

func (vt VirtualTun) Stop() {
	if vt.Dev != nil {
		_ = vt.Dev.Down()
	}
}

func (vt VirtualTun) CheckConnectivity(ctx context.Context, url string, timeout time.Duration) error {
	ctx, cancel := context.WithDeadline(ctx, time.Now().Add(timeout))
	defer cancel()

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("connectivity test timed out: %w", ctx.Err())
		default:
		}

		client := http.Client{Transport: &http.Transport{
			DialContext: vt.Tnet.DialContext,
		}}

		req, err := http.NewRequestWithContext(ctx, "HEAD", url, nil)
		if err != nil {
			return fmt.Errorf("failed to create connectivity test request: %w", err)
		}

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			continue
		}

		return nil
	}
}
