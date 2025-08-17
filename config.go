package wiresocks

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/go-ini/ini"
)

type PeerConfig struct {
	PublicKey    string
	PreSharedKey string
	Endpoint     string
	KeepAlive    int
	AllowedIPs   []netip.Prefix
}

type InterfaceConfig struct {
	PrivateKey string
	Addresses  []netip.Prefix
	DNS        []netip.Addr
	MTU        int
	FwMark     uint32
}

type Configuration struct {
	Interface *InterfaceConfig
	Peers     []PeerConfig
}

func (c *Configuration) String() (string, error) {
	var b strings.Builder

	// [Interface] section
	b.WriteString("[Interface]\n")
	if c.Interface.PrivateKey != "" {
		privKeyB64, err := EncodeHexToBase64(c.Interface.PrivateKey)
		if err != nil {
			return "", err
		}
		b.WriteString(fmt.Sprintf("PrivateKey = %s\n", privKeyB64))
	}
	if len(c.Interface.Addresses) > 0 {
		var addrs []string
		for _, addr := range c.Interface.Addresses {
			addrs = append(addrs, addr.String())
		}
		b.WriteString(fmt.Sprintf("Address = %s\n", strings.Join(addrs, ", ")))
	}
	if len(c.Interface.DNS) > 0 {
		var dns []string
		for _, d := range c.Interface.DNS {
			dns = append(dns, d.String())
		}
		b.WriteString(fmt.Sprintf("DNS = %s\n", strings.Join(dns, ", ")))
	}
	if c.Interface.MTU != 0 {
		b.WriteString(fmt.Sprintf("MTU = %d\n", c.Interface.MTU))
	}

	// [Peer] sections
	for _, peer := range c.Peers {
		b.WriteString("\n[Peer]\n")
		if peer.PublicKey != "" {

			pubKeyB64, err := EncodeHexToBase64(peer.PublicKey)
			if err != nil {
				return "", err
			}
			b.WriteString(fmt.Sprintf("PublicKey = %s\n", pubKeyB64))
		}
		if peer.PreSharedKey != "" && peer.PreSharedKey != "0000000000000000000000000000000000000000000000000000000000000000" {
			pskB64, err := EncodeHexToBase64(peer.PreSharedKey)
			if err != nil {
				return "", err
			}
			b.WriteString(fmt.Sprintf("PresharedKey = %s\n", pskB64))
		}
		if len(peer.AllowedIPs) > 0 {
			var ips []string
			for _, ip := range peer.AllowedIPs {
				ips = append(ips, ip.String())
			}
			b.WriteString(fmt.Sprintf("AllowedIPs = %s\n", strings.Join(ips, ", ")))
		}
		if peer.Endpoint != "" {
			b.WriteString(fmt.Sprintf("Endpoint = %s\n", peer.Endpoint))
		}
		if peer.KeepAlive != 0 {
			b.WriteString(fmt.Sprintf("PersistentKeepalive = %d\n", peer.KeepAlive))
		}
	}

	return b.String(), nil
}

// ParseInterface parses the [Interface] section
func ParseInterface(cfg *ini.File) (InterfaceConfig, error) {
	device := InterfaceConfig{}
	interfaces, err := cfg.SectionsByName("Interface")
	if len(interfaces) != 1 || err != nil {
		return InterfaceConfig{}, errors.New("only one [Interface] is expected")
	}
	iface := interfaces[0]

	key := iface.Key("Address")
	if key == nil {
		return InterfaceConfig{}, nil
	}

	var addresses []netip.Prefix
	for _, str := range key.StringsWithShadows(",") {
		str = strings.TrimSpace(str)
		prefix, err := netip.ParsePrefix(str)
		if err != nil {
			addr, err2 := netip.ParseAddr(str)
			if err2 != nil {
				return InterfaceConfig{}, fmt.Errorf("address %q is not a valid IP address or CIDR prefix: %w", str, err)
			}
			if addr.Is4() {
				prefix = netip.PrefixFrom(addr, 32)
			} else {
				prefix = netip.PrefixFrom(addr, 128)
			}
		}
		addresses = append(addresses, prefix)
	}
	device.Addresses = addresses

	key = iface.Key("PrivateKey")
	if key == nil {
		return InterfaceConfig{}, errors.New("PrivateKey should not be empty")
	}

	privateKeyHex, err := EncodeBase64ToHex(key.String())
	if err != nil {
		return InterfaceConfig{}, err
	}
	device.PrivateKey = privateKeyHex

	if sectionKey, err := iface.GetKey("DNS"); err == nil {
		addrs := sectionKey.StringsWithShadows(",")
		device.DNS = make([]netip.Addr, len(addrs))
		for i, addr := range addrs {
			ip, err := netip.ParseAddr(addr)
			if err != nil {
				return InterfaceConfig{}, err
			}
			device.DNS[i] = ip
		}
	}

	if sectionKey, err := iface.GetKey("MTU"); err == nil {
		value, err := sectionKey.Int()
		if err != nil {
			return InterfaceConfig{}, err
		}
		device.MTU = value
	}

	if sectionKey, err := iface.GetKey("FwMark"); err == nil {
		value, err := sectionKey.Int()
		if err != nil {
			return InterfaceConfig{}, err
		}
		device.FwMark = uint32(value)
	}

	return device, nil
}

// ParsePeers parses the [Peer] section and extract the information into `peers`
func ParsePeers(cfg *ini.File) ([]PeerConfig, error) {
	sections, err := cfg.SectionsByName("Peer")
	if len(sections) < 1 || err != nil {
		return nil, errors.New("at least one [Peer] is expected")
	}

	peers := make([]PeerConfig, len(sections))
	for i, section := range sections {
		peer := PeerConfig{
			PreSharedKey: "0000000000000000000000000000000000000000000000000000000000000000",
			KeepAlive:    0,
		}

		if sectionKey, err := section.GetKey("PublicKey"); err == nil {
			value, err := EncodeBase64ToHex(sectionKey.String())
			if err != nil {
				return nil, err
			}
			peer.PublicKey = value
		}

		if sectionKey, err := section.GetKey("PreSharedKey"); err == nil {
			value, err := EncodeBase64ToHex(sectionKey.String())
			if err != nil {
				return nil, err
			}
			peer.PreSharedKey = value
		}

		if sectionKey, err := section.GetKey("PersistentKeepalive"); err == nil {
			value, err := sectionKey.Int()
			if err != nil {
				return nil, err
			}
			peer.KeepAlive = value
		}

		if sectionKey, err := section.GetKey("AllowedIPs"); err == nil {
			var ips []netip.Prefix
			for _, str := range sectionKey.StringsWithShadows(",") {
				str = strings.TrimSpace(str)
				prefix, err := ParsePrefixOrAddr(str)
				if err != nil {
					return nil, err
				}
				ips = append(ips, prefix)
			}
			peer.AllowedIPs = ips
		}

		if sectionKey, err := section.GetKey("Endpoint"); err == nil {
			peer.Endpoint = sectionKey.String()
		}

		peers[i] = peer
	}

	return peers, nil
}

// ParseConfig takes the path of a configuration file and parses it into Configuration
func ParseConfig(path string) (*Configuration, error) {
	iniOpt := ini.LoadOptions{
		Insensitive:            true,
		AllowShadows:           true,
		AllowNonUniqueSections: true,
	}

	cfg, err := ini.LoadSources(iniOpt, path)
	if err != nil {
		return nil, err
	}

	iface, err := ParseInterface(cfg)
	if err != nil {
		return nil, err
	}

	peers, err := ParsePeers(cfg)
	if err != nil {
		return nil, err
	}

	return &Configuration{Interface: &iface, Peers: peers}, nil
}
