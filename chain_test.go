package wiresocks

import (
	"bufio"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
)

func generateWGKeyPairHex(t *testing.T) (privHex, pubHex string) {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate X25519 key: %v", err)
	}
	return hex.EncodeToString(priv.Bytes()), hex.EncodeToString(priv.PublicKey().Bytes())
}

func freeTCPAddrPort(t *testing.T) netip.AddrPort {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to allocate free TCP port: %v", err)
	}
	defer ln.Close()
	addr := ln.Addr().(*net.TCPAddr)
	return addr.AddrPort()
}

func startTestWGServer(t *testing.T, privHex, peerPubHex string, serverAddr, peerAllowedIP netip.Prefix, bind conn.Bind) (*device.Device, *netstack.Net, uint16) {
	t.Helper()

	tunDev, tnet, err := netstack.CreateNetTUN([]netip.Addr{serverAddr.Addr()}, nil, 1420)
	if err != nil {
		t.Fatalf("failed to create server netstack TUN: %v", err)
	}

	dev := device.NewDevice(tunDev, bind, device.NewLogger(device.LogLevelSilent, ""))
	t.Cleanup(func() {
		dev.Close()
	})

	var ipc strings.Builder
	fmt.Fprintf(&ipc, "private_key=%s\n", privHex)
	fmt.Fprintf(&ipc, "public_key=%s\n", peerPubHex)
	fmt.Fprintf(&ipc, "allowed_ip=%s\n", peerAllowedIP.String())

	if err := dev.IpcSet(ipc.String()); err != nil {
		t.Fatalf("server IpcSet failed: %v", err)
	}
	if err := dev.Up(); err != nil {
		t.Fatalf("server Up failed: %v", err)
	}

	state, err := dev.IpcGet()
	if err != nil {
		t.Fatalf("server IpcGet failed: %v", err)
	}

	var listenPort uint16
	scanner := bufio.NewScanner(strings.NewReader(state))
	for scanner.Scan() {
		k, v, ok := strings.Cut(scanner.Text(), "=")
		if ok && k == "listen_port" {
			p, err := strconv.Atoi(v)
			if err != nil {
				t.Fatalf("invalid listen_port %q: %v", v, err)
			}
			listenPort = uint16(p)
			break
		}
	}
	if listenPort == 0 {
		t.Fatalf("failed to determine server listen_port from IPC state:\n%s", state)
	}

	return dev, tnet, listenPort
}

// startTestDNSServer serves a single A record response for any UDP DNS query on tnet.
func startTestDNSServer(t *testing.T, tnet *netstack.Net, listenAddr netip.AddrPort, answerIP [4]byte) {
	t.Helper()

	pc, err := tnet.ListenUDPAddrPort(listenAddr)
	if err != nil {
		t.Fatalf("failed to start in-tunnel DNS server: %v", err)
	}
	t.Cleanup(func() {
		_ = pc.Close()
	})

	go func() {
		buf := make([]byte, 512)
		for {
			n, raddr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if n < 12 {
				continue
			}

			// Locate end of QNAME (terminating 0-length label) + QTYPE(2) + QCLASS(2).
			idx := 12
			for idx < n && buf[idx] != 0 {
				idx += int(buf[idx]) + 1
			}
			if idx+5 > n {
				continue
			}
			qEnd := idx + 5

			resp := make([]byte, 0, qEnd+16)
			resp = append(resp, buf[:2]...)             // ID
			resp = append(resp, 0x81, 0x80)             // QR=1, RD=1, RA=1, RCODE=0
			resp = append(resp, 0x00, 0x01)             // QDCOUNT=1
			resp = append(resp, 0x00, 0x01)             // ANCOUNT=1
			resp = append(resp, 0x00, 0x00, 0x00, 0x00) // NSCOUNT=0, ARCOUNT=0
			resp = append(resp, buf[12:qEnd]...)        // Question
			resp = append(resp, 0xc0, 0x0c)             // Name pointer to offset 12
			resp = append(resp, 0x00, 0x01)             // Type A
			resp = append(resp, 0x00, 0x01)             // Class IN
			resp = append(resp, 0x00, 0x00, 0x00, 0x3c) // TTL 60s
			resp = append(resp, 0x00, 0x04)             // RDLENGTH 4
			resp = append(resp, answerIP[:]...)         // IPv4 address
			_, _ = pc.WriteTo(resp, raddr)
		}
	}()
}

func dialViaSOCKS5(proxyAddr, targetHost string, targetPort uint16) (net.Conn, error) {
	c, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		return nil, err
	}

	// Greeting: version 5, 1 method (no auth = 0x00)
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		c.Close()
		return nil, err
	}
	var methodResp [2]byte
	if _, err := io.ReadFull(c, methodResp[:]); err != nil {
		c.Close()
		return nil, err
	}
	if methodResp[0] != 0x05 || methodResp[1] != 0x00 {
		c.Close()
		return nil, fmt.Errorf("unexpected SOCKS5 method selection: %v", methodResp)
	}

	// CONNECT request with domain name (ATYP=0x03)
	req := make([]byte, 0, 7+len(targetHost))
	req = append(req, 0x05, 0x01, 0x00, 0x03, byte(len(targetHost)))
	req = append(req, targetHost...)
	var portBuf [2]byte
	binary.BigEndian.PutUint16(portBuf[:], targetPort)
	req = append(req, portBuf[:]...)

	if _, err := c.Write(req); err != nil {
		c.Close()
		return nil, err
	}

	var hdr [4]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		c.Close()
		return nil, err
	}
	if hdr[1] != 0x00 {
		c.Close()
		return nil, fmt.Errorf("SOCKS5 CONNECT failed with code %d", hdr[1])
	}

	switch hdr[3] {
	case 0x01:
		var rest [6]byte
		_, err = io.ReadFull(c, rest[:])
	case 0x03:
		var ln [1]byte
		if _, err = io.ReadFull(c, ln[:]); err == nil {
			rest := make([]byte, int(ln[0])+2)
			_, err = io.ReadFull(c, rest)
		}
	case 0x04:
		var rest [18]byte
		_, err = io.ReadFull(c, rest[:])
	}
	if err != nil {
		c.Close()
		return nil, err
	}

	return c, nil
}

func TestNetstackBindUnit(t *testing.T) {
	localIP := netip.MustParseAddr("10.50.0.1")
	tunDev, tnet, err := netstack.CreateNetTUN([]netip.Addr{localIP}, nil, 1420)
	if err != nil {
		t.Fatal(err)
	}
	defer tunDev.Close()

	b := NewNetstackBind(tnet, localIP)
	if b.BatchSize() != 1 {
		t.Fatalf("expected BatchSize 1, got %d", b.BatchSize())
	}
	if err := b.SetMark(42); err != nil {
		t.Fatalf("SetMark should be a no-op, got: %v", err)
	}

	ep, err := b.ParseEndpoint("10.50.0.2:51820")
	if err != nil {
		t.Fatal(err)
	}
	if ep.DstToString() != "10.50.0.2:51820" || ep.DstIP().String() != "10.50.0.2" {
		t.Fatalf("unexpected endpoint values: %s / %s", ep.DstToString(), ep.DstIP())
	}
	if len(ep.DstToBytes()) == 0 {
		t.Fatal("expected non-empty DstToBytes")
	}

	fns, port, err := b.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(fns) != 1 || port == 0 {
		t.Fatalf("expected 1 receive func and non-zero port, got %d / %d", len(fns), port)
	}

	if _, _, err := b.Open(0); !errors.Is(err, conn.ErrBindAlreadyOpen) {
		t.Fatalf("expected ErrBindAlreadyOpen, got: %v", err)
	}

	if err := b.Send([][]byte{[]byte("bad")}, &conn.StdNetEndpoint{}); !errors.Is(err, conn.ErrWrongEndpointType) {
		t.Fatalf("expected ErrWrongEndpointType, got: %v", err)
	}

	recvDone := make(chan error, 1)
	go func() {
		bufs := [][]byte{make([]byte, 128)}
		sizes := make([]int, 1)
		eps := make([]conn.Endpoint, 1)
		_, recvErr := fns[0](bufs, sizes, eps)
		recvDone <- recvErr
	}()

	time.Sleep(25 * time.Millisecond)
	if err := b.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	select {
	case recvErr := <-recvDone:
		if !errors.Is(recvErr, net.ErrClosed) {
			t.Fatalf("expected net.ErrClosed after Close, got: %v", recvErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ReceiveFunc did not unblock after Close")
	}
}

func TestResolveHopMTU(t *testing.T) {
	ws, err := NewWireSocks()
	if err != nil {
		t.Fatal(err)
	}

	// Single hop default MTU is 1280
	mtu, err := ws.resolveHopMTU(0, 1, &Configuration{Interface: &InterfaceConfig{}}, nil, 0)
	if err != nil || mtu != 1280 {
		t.Fatalf("expected 1280 for single hop, got %d (%v)", mtu, err)
	}

	// Chain hop 1 default MTU is 1420
	mtu1, err := ws.resolveHopMTU(0, 2, &Configuration{Interface: &InterfaceConfig{}}, nil, 0)
	if err != nil || mtu1 != 1420 {
		t.Fatalf("expected 1420 for chain hop 1, got %d (%v)", mtu1, err)
	}

	// Hop 2 over IPv4 upstream cascades to 1420 - 60 = 1360
	v4Upstream := &VirtualTun{localAddrs: []netip.Addr{netip.MustParseAddr("10.0.0.2")}}
	mtu2, err := ws.resolveHopMTU(1, 2, &Configuration{Interface: &InterfaceConfig{}}, v4Upstream, mtu1)
	if err != nil || mtu2 != 1360 {
		t.Fatalf("expected 1360 for IPv4 hop 2, got %d (%v)", mtu2, err)
	}

	// Hop 2 with explicit larger MTU gets clamped to 1360
	mtu2Clamped, err := ws.resolveHopMTU(1, 2, &Configuration{Interface: &InterfaceConfig{MTU: 1500}}, v4Upstream, mtu1)
	if err != nil || mtu2Clamped != 1360 {
		t.Fatalf("expected clamped 1360, got %d (%v)", mtu2Clamped, err)
	}

	// Hop 2 over IPv6 upstream cascades to 1420 - 80 = 1340
	v6Upstream := &VirtualTun{localAddrs: []netip.Addr{netip.MustParseAddr("fd00::2")}}
	mtu2v6, err := ws.resolveHopMTU(1, 2, &Configuration{Interface: &InterfaceConfig{}}, v6Upstream, mtu1)
	if err != nil || mtu2v6 != 1340 {
		t.Fatalf("expected 1340 for IPv6 hop 2, got %d (%v)", mtu2v6, err)
	}

	// Upstream MTU too small returns error
	if _, err := ws.resolveHopMTU(1, 2, &Configuration{Interface: &InterfaceConfig{}}, v4Upstream, 50); err == nil {
		t.Fatal("expected error when upstream MTU is smaller than WireGuard overhead")
	}
}

func TestCreateIPCRequestChaining(t *testing.T) {
	privHex, pubHex := generateWGKeyPairHex(t)
	conf := &Configuration{
		Interface: &InterfaceConfig{
			PrivateKey: privHex,
		},
		Peers: []PeerConfig{
			{
				PublicKey: pubHex,
				Endpoint:  "10.10.0.1:51820",
				KeepAlive: 25,
			},
		},
	}

	// Hop 1 (upstream == nil): emits default AWG params
	ipc1, err := createIPCRequest(context.Background(), conf, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ipc1, "jc=10\n") {
		t.Fatalf("expected default jc=10 on root hop, got:\n%s", ipc1)
	}
	if !strings.Contains(ipc1, "persistent_keepalive_interval=25\n") {
		t.Fatalf("expected keepalive 25, got:\n%s", ipc1)
	}

	// Hop 2 (upstream != nil): uses temporary keepalive 25 for startup handshake, omits jc unless explicitly configured
	upstream := &VirtualTun{}
	ipc2, err := createIPCRequest(context.Background(), conf, upstream)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(ipc2, "jc=") {
		t.Fatalf("expected jc to be omitted on chained hop without explicit AWG config, got:\n%s", ipc2)
	}
	if !strings.Contains(ipc2, "persistent_keepalive_interval=25\n") {
		t.Fatalf("expected startup keepalive 25, got:\n%s", ipc2)
	}
}

func TestWireSocksChainValidationAndOptions(t *testing.T) {
	priv1, pub1 := generateWGKeyPairHex(t)
	priv2, pub2 := generateWGKeyPairHex(t)

	hop1NoAddr := &Configuration{
		Interface: &InterfaceConfig{PrivateKey: priv1},
		Peers:     []PeerConfig{{PublicKey: pub1, Endpoint: "127.0.0.1:51820"}},
	}
	hop2 := &Configuration{
		Interface: &InterfaceConfig{
			PrivateKey: priv2,
			Addresses:  []netip.Prefix{netip.MustParsePrefix("10.20.0.2/32")},
		},
		Peers: []PeerConfig{{PublicKey: pub2, Endpoint: "10.10.0.1:51820"}},
	}

	socksAddr := freeTCPAddrPort(t)
	ws, err := NewWireSocks(
		AddWireguardHop(hop1NoAddr),
		AddWireguardHop(hop2),
		WithProxyConfig(&ProxyConfig{SocksBindAddr: &socksAddr}),
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(ws.confs) != 2 {
		t.Fatalf("expected 2 hops, got %d", len(ws.confs))
	}

	if err := ws.Run(); err == nil || !strings.Contains(err.Error(), "intermediate hop requires") {
		t.Fatalf("expected intermediate hop address validation error, got: %v", err)
	}
}

func TestTwoHopWireguardChainE2E(t *testing.T) {
	// Keypairs for Hop 1 (Client1 <-> Server1) and Hop 2 (Client2 <-> Server2)
	c1Priv, c1Pub := generateWGKeyPairHex(t)
	s1Priv, s1Pub := generateWGKeyPairHex(t)
	c2Priv, c2Pub := generateWGKeyPairHex(t)
	s2Priv, s2Pub := generateWGKeyPairHex(t)

	// Start Server 1 on host loopback
	_, s1Tnet, s1Port := startTestWGServer(
		t,
		s1Priv,
		c1Pub,
		netip.MustParsePrefix("10.10.0.1/24"),
		netip.MustParsePrefix("10.10.0.2/32"),
		conn.NewDefaultBind(),
	)

	// Start an in-tunnel DNS server inside Server 1's netstack at 10.10.0.1:53
	startTestDNSServer(t, s1Tnet, netip.MustParseAddrPort("10.10.0.1:53"), [4]byte{10, 10, 0, 1})

	// Start Server 2 INSIDE Server 1's netstack via NewNetstackBind
	_, s2Tnet, s2Port := startTestWGServer(
		t,
		s2Priv,
		c2Pub,
		netip.MustParsePrefix("10.20.0.1/24"),
		netip.MustParsePrefix("10.20.0.2/32"),
		NewNetstackBind(s1Tnet, netip.MustParseAddr("10.10.0.1")),
	)

	// Start an HTTP server INSIDE Server 2's netstack at 10.20.0.1:8080
	ln, err := s2Tnet.ListenTCPAddrPort(netip.MustParseAddrPort("10.20.0.1:8080"))
	if err != nil {
		t.Fatalf("failed to listen inside Server 2 netstack: %v", err)
	}
	defer ln.Close()

	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("hello from hop 2 exit"))
		}),
	}
	go func() {
		_ = srv.Serve(ln)
	}()
	defer srv.Close()

	// Start a UDP echo server INSIDE Server 2's netstack at 10.20.0.1:9090
	udpConn, err := s2Tnet.ListenUDPAddrPort(netip.MustParseAddrPort("10.20.0.1:9090"))
	if err != nil {
		t.Fatalf("failed to listen UDP inside Server 2 netstack: %v", err)
	}
	defer udpConn.Close()
	go func() {
		buf := make([]byte, 1024)
		for {
			n, raddr, err := udpConn.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = udpConn.WriteTo(buf[:n], raddr)
		}
	}()

	// Configure Hop 1 -> Server 1 on 127.0.0.1:s1Port, DNS = 10.10.0.1
	hop1 := &Configuration{
		Interface: &InterfaceConfig{
			PrivateKey: c1Priv,
			Addresses:  []netip.Prefix{netip.MustParsePrefix("10.10.0.2/32")},
			DNS:        []netip.Addr{netip.MustParseAddr("10.10.0.1")},
		},
		Peers: []PeerConfig{
			{
				PublicKey:  s1Pub,
				Endpoint:   fmt.Sprintf("127.0.0.1:%d", s1Port),
				AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
				KeepAlive:  5,
			},
		},
	}

	// Configure Hop 2 -> Server 2 using a hostname resolved through Hop 1's tunnel DNS!
	hop2 := &Configuration{
		Interface: &InterfaceConfig{
			PrivateKey: c2Priv,
			Addresses:  []netip.Prefix{netip.MustParsePrefix("10.20.0.2/32")},
		},
		Peers: []PeerConfig{
			{
				PublicKey:  s2Pub,
				Endpoint:   fmt.Sprintf("hop2.internal:%d", s2Port),
				AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
				KeepAlive:  5,
			},
		},
	}

	socksAddr := freeTCPAddrPort(t)
	httpAddr := freeTCPAddrPort(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ws, err := NewWireSocks(
		WithContext(ctx),
		WithWireguardChain(hop1, hop2),
		WithProxyConfig(&ProxyConfig{
			SocksBindAddr: &socksAddr,
			HttpBindAddr:  &httpAddr,
		}),
		WithLogLevel(LogLevelSilent),
	)
	if err != nil {
		t.Fatal(err)
	}

	runErrCh := make(chan error, 1)
	go func() {
		runErrCh <- ws.Run()
	}()

	// Wait until HTTP proxy listener is accepting connections
	deadline := time.Now().Add(15 * time.Second)
	for {
		c, dialErr := net.DialTimeout("tcp", httpAddr.String(), 200*time.Millisecond)
		if dialErr == nil {
			_ = c.Close()
			break
		}
		select {
		case runErr := <-runErrCh:
			t.Fatalf("WireSocks exited early: %v", runErr)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for proxies to start")
		}
		time.Sleep(50 * time.Millisecond)
	}

	// 1. Test HTTP proxy through the 2-hop chain
	proxyURL, _ := url.Parse("http://" + httpAddr.String())
	httpClient := &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
	}
	resp, err := httpClient.Get("http://10.20.0.1:8080/test")
	if err != nil {
		t.Fatalf("HTTP request via 2-hop proxy failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "hello from hop 2 exit" {
		t.Fatalf("unexpected HTTP proxy response: %q", string(body))
	}

	// 2. Test SOCKS5 proxy through the 2-hop chain
	socksConn, err := dialViaSOCKS5(socksAddr.String(), "10.20.0.1", 8080)
	if err != nil {
		t.Fatalf("SOCKS5 dial via 2-hop proxy failed: %v", err)
	}
	defer socksConn.Close()
	_ = socksConn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(socksConn, "GET / HTTP/1.1\r\nHost: 10.20.0.1\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatalf("SOCKS5 write failed: %v", err)
	}
	socksResp, err := io.ReadAll(socksConn)
	if err != nil {
		t.Fatalf("SOCKS5 read failed: %v", err)
	}
	if !strings.Contains(string(socksResp), "hello from hop 2 exit") {
		t.Fatalf("unexpected SOCKS5 response:\n%s", string(socksResp))
	}

	// 3. Test SOCKS5 UDP ASSOCIATE through the 2-hop chain
	socksTCPConn, err := net.DialTimeout("tcp", socksAddr.String(), 5*time.Second)
	if err != nil {
		t.Fatalf("SOCKS5 TCP dial for UDP ASSOCIATE failed: %v", err)
	}
	defer socksTCPConn.Close()

	if _, err := socksTCPConn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("SOCKS5 greeting failed: %v", err)
	}
	var mResp [2]byte
	if _, err := io.ReadFull(socksTCPConn, mResp[:]); err != nil || mResp[0] != 0x05 || mResp[1] != 0x00 {
		t.Fatalf("SOCKS5 auth failed: %v", err)
	}

	// Request CmdUDP (0x03)
	if _, err := socksTCPConn.Write([]byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatalf("SOCKS5 UDP ASSOCIATE request failed: %v", err)
	}

	var assocHdr [4]byte
	if _, err := io.ReadFull(socksTCPConn, assocHdr[:]); err != nil || assocHdr[1] != 0x00 {
		t.Fatalf("SOCKS5 UDP ASSOCIATE failed with header: %v, err: %v", assocHdr, err)
	}

	var relayIP net.IP
	var relayPort uint16
	switch assocHdr[3] {
	case 0x01: // IPv4
		var buf [6]byte
		if _, err := io.ReadFull(socksTCPConn, buf[:]); err != nil {
			t.Fatalf("failed to read SOCKS5 relay IPv4: %v", err)
		}
		relayIP = net.IP(buf[:4])
		relayPort = binary.BigEndian.Uint16(buf[4:6])
	case 0x04: // IPv6
		var buf [18]byte
		if _, err := io.ReadFull(socksTCPConn, buf[:]); err != nil {
			t.Fatalf("failed to read SOCKS5 relay IPv6: %v", err)
		}
		relayIP = net.IP(buf[:16])
		relayPort = binary.BigEndian.Uint16(buf[16:18])
	default:
		t.Fatalf("unsupported ATYP in UDP ASSOCIATE response: %d", assocHdr[3])
	}

	if relayIP.IsUnspecified() {
		relayIP = net.ParseIP("127.0.0.1")
	}

	clientUDP, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: relayIP, Port: int(relayPort)})
	if err != nil {
		t.Fatalf("failed to dial SOCKS5 UDP relay: %v", err)
	}
	defer clientUDP.Close()

	// Build SOCKS5 UDP header for 10.20.0.1:9090
	// RSV(2) | FRAG(1) | ATYP(1) | DST.ADDR(4) | DST.PORT(2) | Payload
	udpPayload := []byte("ping udp echo")
	reqBuf := make([]byte, 0, 10+len(udpPayload))
	reqBuf = append(reqBuf, 0x00, 0x00, 0x00, 0x01)
	reqBuf = append(reqBuf, net.ParseIP("10.20.0.1").To4()...)
	var pBuf [2]byte
	binary.BigEndian.PutUint16(pBuf[:], 9090)
	reqBuf = append(reqBuf, pBuf[:]...)
	reqBuf = append(reqBuf, udpPayload...)

	_ = clientUDP.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := clientUDP.Write(reqBuf); err != nil {
		t.Fatalf("failed to write UDP packet to relay: %v", err)
	}

	recvBuf := make([]byte, 1024)
	n, err := clientUDP.Read(recvBuf)
	if err != nil {
		t.Fatalf("failed to read UDP packet from relay: %v", err)
	}

	if n < 10 {
		t.Fatalf("UDP relay response too short: %d bytes", n)
	}
	if string(recvBuf[10:n]) != "ping udp echo" {
		t.Fatalf("unexpected UDP echo response: %q", string(recvBuf[10:n]))
	}

	// Verify graceful shutdown
	ws.Stop()
	select {
	case runErr := <-runErrCh:
		if runErr != nil {
			t.Fatalf("expected nil on Stop, got: %v", runErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("WireSocks did not shut down cleanly within timeout")
	}
}
