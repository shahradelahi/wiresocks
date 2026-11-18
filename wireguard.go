package wiresocks

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
)

func waitHandshake(ctx context.Context, dev *device.Device) error {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("handshake wait timed out: %w", ctx.Err())
		default:
		}

		get, err := dev.IpcGet()
		if err == nil && hasCompletedHandshake(get) {
			return nil
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("handshake wait timed out: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

func hasCompletedHandshake(ipcState string) bool {
	scanner := bufio.NewScanner(strings.NewReader(ipcState))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			break
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if key == "last_handshake_time_sec" && value != "0" {
			return true
		}
	}
	return false
}

func writeObfuscationIPC(request *bytes.Buffer, iface *InterfaceConfig, isRootHop bool) {
	if iface.HasAmneziaWGParams() {
		writeOpt := func(key string, val *int) {
			if val != nil {
				fmt.Fprintf(request, "%s=%d\n", key, *val)
			}
		}
		writeOpt("jc", iface.Jc)
		writeOpt("jmin", iface.Jmin)
		writeOpt("jmax", iface.Jmax)
		writeOpt("s1", iface.S1)
		writeOpt("s2", iface.S2)
		writeOpt("h1", iface.H1)
		writeOpt("h2", iface.H2)
		writeOpt("h3", iface.H3)
		writeOpt("h4", iface.H4)
		return
	}

	if isRootHop {
		// Default AmneziaWG parameters for entry hop obfuscation
		request.WriteString("jc=10\n")
		request.WriteString("jmin=50\n")
		request.WriteString("jmax=1000\n")
		request.WriteString("s1=0\n")
		request.WriteString("s2=0\n")
		request.WriteString("h1=1\n")
		request.WriteString("h2=2\n")
		request.WriteString("h3=3\n")
		request.WriteString("h4=4\n")
	}
}

func resolvePeerEndpoint(ctx context.Context, endpoint string, upstream *VirtualTun) (string, error) {
	if upstream == nil {
		addr, err := ParseResolveAddressPort(endpoint, false, "1.1.1.1")
		if err != nil {
			return "", err
		}
		return addr.String(), nil
	}

	host, portStr, err := net.SplitHostPort(endpoint)
	if err != nil {
		return "", fmt.Errorf("invalid endpoint %q: %w", endpoint, err)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return "", fmt.Errorf("invalid endpoint port %q", portStr)
	}

	if addr, err := netip.ParseAddr(host); err == nil {
		return netip.AddrPortFrom(addr.Unmap(), uint16(port)).String(), nil
	}

	resolved, err := upstream.ResolveAddrWithContext(ctx, host)
	if err != nil {
		return "", fmt.Errorf("failed to resolve endpoint %q through upstream tunnel: %w", host, err)
	}

	return netip.AddrPortFrom(resolved.Unmap(), uint16(port)).String(), nil
}

func createIPCRequest(ctx context.Context, conf *Configuration, upstream *VirtualTun) (string, error) {
	var request bytes.Buffer

	fmt.Fprintf(&request, "private_key=%s\n", conf.Interface.PrivateKey)
	writeObfuscationIPC(&request, conf.Interface, upstream == nil)

	for _, peer := range conf.Peers {
		fmt.Fprintf(&request, "public_key=%s\n", peer.PublicKey)
		keepAlive := peer.KeepAlive
		if keepAlive <= 0 {
			keepAlive = 10
		}
		fmt.Fprintf(&request, "persistent_keepalive_interval=%d\n", keepAlive)
		if peer.PreSharedKey != "" {
			fmt.Fprintf(&request, "preshared_key=%s\n", peer.PreSharedKey)
		}

		if peer.Endpoint != "" {
			resolved, err := resolvePeerEndpoint(ctx, peer.Endpoint, upstream)
			if err != nil {
				return "", err
			}
			fmt.Fprintf(&request, "endpoint=%s\n", resolved)
		}

		if len(peer.AllowedIPs) > 0 {
			for _, ip := range peer.AllowedIPs {
				fmt.Fprintf(&request, "allowed_ip=%s\n", ip.String())
			}
		} else {
			request.WriteString("allowed_ip=0.0.0.0/0\nallowed_ip=::0/0\n")
		}
	}

	return request.String(), nil
}

func establishWireguard(ctx context.Context, conf *Configuration, tunDev tun.Device, upstream *VirtualTun, logLevel int) (*device.Device, error) {
	request, err := createIPCRequest(ctx, conf, upstream)
	if err != nil {
		return nil, fmt.Errorf("failed to create IPC request: %w", err)
	}

	var bind conn.Bind
	if upstream != nil {
		bind = NewNetstackBind(upstream.Tnet, upstream.localAddrs...)
	} else {
		bind = conn.NewDefaultBind()
	}

	dev := device.NewDevice(
		tunDev,
		bind,
		device.NewLogger(logLevel, ""),
	)

	if err := dev.IpcSet(request); err != nil {
		dev.Close()
		return nil, fmt.Errorf("failed to set IPC configuration: %w", err)
	}

	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("failed to bring up device: %w", err)
	}

	handshakeCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	if err := waitHandshake(handshakeCtx, dev); err != nil {
		_ = dev.BindClose()
		dev.Close()
		return nil, fmt.Errorf("handshake failed: %w", err)
	}

	return dev, nil
}
