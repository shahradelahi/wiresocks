package wiresocks

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/conn"
	"github.com/amnezia-vpn/amneziawg-go/device"
	"github.com/amnezia-vpn/amneziawg-go/tun"
)

func waitHandshake(ctx context.Context, dev *device.Device) error {
	lastHandshakeSecs := "0"
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("handshake wait timed out: %w", ctx.Err())
		default:
		}

		get, err := dev.IpcGet()
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(strings.NewReader(get))
		for scanner.Scan() {
			line := scanner.Text()
			if line == "" {
				break
			}

			key, value, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}

			if key == "last_handshake_time_sec" {
				lastHandshakeSecs = value
				break
			}
		}
		if lastHandshakeSecs != "0" {
			return nil
		}

		time.Sleep(1 * time.Second)
	}
}

func createIPCRequest(conf *Configuration) (string, error) {
	var request bytes.Buffer

	request.WriteString(fmt.Sprintf("private_key=%s\n", conf.Interface.PrivateKey))
	//request.WriteString(fmt.Sprintf("fwmark=%d\n", conf.Interface.FwMark))

	// AmneziaWG parameters for obfuscation
	request.WriteString("jc=10\n")
	request.WriteString("jmin=50\n")
	request.WriteString("jmax=1000\n")
	request.WriteString("s1=0\n")
	request.WriteString("s2=0\n")
	request.WriteString("h1=1\n")
	request.WriteString("h2=2\n")
	request.WriteString("h3=3\n")
	request.WriteString("h4=4\n")

	for _, peer := range conf.Peers {
		request.WriteString(fmt.Sprintf("public_key=%s\n", peer.PublicKey))
		request.WriteString("persistent_keepalive_interval=10\n")
		request.WriteString(fmt.Sprintf("preshared_key=%s\n", peer.PreSharedKey))

		addr, err := ParseResolveAddressPort(peer.Endpoint, false, "1.1.1.1")
		if err == nil {
			peer.Endpoint = addr.String()
		}
		request.WriteString(fmt.Sprintf("endpoint=%s\n", peer.Endpoint))

		if len(peer.AllowedIPs) > 0 {
			for _, ip := range peer.AllowedIPs {
				request.WriteString(fmt.Sprintf("allowed_ip=%s\n", ip.String()))
			}
		} else {
			request.WriteString("allowed_ip=0.0.0.0/0\nallowed_ip=::0/0\n")
		}
	}

	return request.String(), nil
}

func establishWireguard(conf *Configuration, tunDev tun.Device, logLevel int) (*device.Device, error) {
	request, err := createIPCRequest(conf)
	if err != nil {
		return nil, fmt.Errorf("failed to create IPC request: %w", err)
	}

	dev := device.NewDevice(
		tunDev,
		conn.NewDefaultBind(),
		device.NewLogger(logLevel, ""),
	)

	if err := dev.IpcSet(request); err != nil {
		return nil, fmt.Errorf("failed to set IPC configuration: %w", err)
	}

	if err := dev.Up(); err != nil {
		return nil, fmt.Errorf("failed to bring up device: %w", err)
	}

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(15*time.Second))
	defer cancel()

	if err := waitHandshake(ctx, dev); err != nil {
		_ = dev.BindClose()
		dev.Close()
		return nil, fmt.Errorf("handshake failed: %w", err)
	}

	return dev, nil
}
