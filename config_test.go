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
