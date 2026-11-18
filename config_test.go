package wiresocks

import (
	"testing"
)

func TestWireguardConfWithoutSubnet(t *testing.T) {
	const config = `
[Interface]
PrivateKey = dGhpcyBpcyBhIHRlc3QgcHJpdmF0ZSBleS4uLi4uLi4=
Address = 10.10.0.1
DNS = 8.8.8.8

[Peer]
PublicKey = dGhpcyBpcyBhIHRlc3QgcHVibGljIGtleS4uLi4uLi4=
AllowedIPs = 0.0.0.0/0
Endpoint = 1.2.3.4:51820
PersistentKeepalive = 25`

	_, err := ParseConfigFromText(config)
	if err != nil {
		t.Fatal(err)
	}
}

func TestWireguardConfWithSubnet(t *testing.T) {
	const config = `
[Interface]
PrivateKey = anotherkeyanotherkeyanotherkeyanotherkeynow=
Address = 192.168.1.5/24
DNS = 8.8.4.4

[Peer]
PublicKey = onemorekeyonemorekeyonemorekeyonemorekeynow=
AllowedIPs = 192.168.1.0/24
Endpoint = 5.6.7.8:51820
PersistentKeepalive = 15`

	_, err := ParseConfigFromText(config)
	if err != nil {
		t.Fatal(err)
	}
}

func TestWireguardConfWithManyAddress(t *testing.T) {
	const config = `
[Interface]
PrivateKey = anotherkeyanotherkeyanotherkeyanotherkeynow=
Address = 172.16.0.100/32,fd00::100/128
DNS = 208.67.222.222,208.67.220.220

[Peer]
PublicKey = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
AllowedIPs = 0.0.0.0/0,::/0
Endpoint = 9.9.9.9:51820`

	_, err := ParseConfigFromText(config)
	if err != nil {
		t.Fatal(err)
	}
}

func TestWireguardConfWithoutAddress(t *testing.T) {
	const config = `
[Interface]
PrivateKey = anotherkeyanotherkeyanotherkeyanotherkeynow=
DNS = 1.1.1.1
MTU = 1380

[Peer]
PublicKey = onemorekeyonemorekeyonemorekeyonemorekeynow=
AllowedIPs = 0.0.0.0/0
Endpoint = 5.6.7.8:51820`

	cfg, err := ParseConfigFromText(config)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Interface.PrivateKey == "" {
		t.Fatal("expected PrivateKey to be parsed even when Address is omitted")
	}
	if cfg.Interface.MTU != 1380 {
		t.Fatalf("expected MTU 1380, got %d", cfg.Interface.MTU)
	}
	if len(cfg.Interface.DNS) != 1 || cfg.Interface.DNS[0].String() != "1.1.1.1" {
		t.Fatalf("unexpected DNS: %v", cfg.Interface.DNS)
	}
}

func TestWireguardConfWithAmneziaParams(t *testing.T) {
	const config = `
[Interface]
PrivateKey = anotherkeyanotherkeyanotherkeyanotherkeynow=
Address = 10.0.0.2/32
Jc = 4
Jmin = 40
Jmax = 70
S1 = 15
S2 = 25
H1 = 101
H2 = 102
H3 = 103
H4 = 104

[Peer]
PublicKey = onemorekeyonemorekeyonemorekeyonemorekeynow=
AllowedIPs = 0.0.0.0/0
Endpoint = 5.6.7.8:51820`

	cfg, err := ParseConfigFromText(config)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Interface.HasAmneziaWGParams() {
		t.Fatal("expected HasAmneziaWGParams to return true")
	}
	if *cfg.Interface.Jc != 4 || *cfg.Interface.Jmin != 40 || *cfg.Interface.Jmax != 70 {
		t.Fatalf("unexpected junk params: %v %v %v", cfg.Interface.Jc, cfg.Interface.Jmin, cfg.Interface.Jmax)
	}
	if *cfg.Interface.S1 != 15 || *cfg.Interface.S2 != 25 {
		t.Fatalf("unexpected padding params: %v %v", cfg.Interface.S1, cfg.Interface.S2)
	}
	if *cfg.Interface.H1 != 101 || *cfg.Interface.H4 != 104 {
		t.Fatalf("unexpected header params: %v %v", cfg.Interface.H1, cfg.Interface.H4)
	}

	rendered, err := cfg.String()
	if err != nil {
		t.Fatal(err)
	}
	reparsed, err := ParseConfigFromText(rendered)
	if err != nil {
		t.Fatal(err)
	}
	if *reparsed.Interface.Jc != 4 || *reparsed.Interface.H4 != 104 {
		t.Fatalf("round-trip mismatch: Jc=%v H4=%v", reparsed.Interface.Jc, reparsed.Interface.H4)
	}
}
