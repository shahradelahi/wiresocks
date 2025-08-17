package wiresocks

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"math/rand"
	"net"
	"net/netip"
	"strconv"
	"time"
)

// RandomIPFromPrefix returns a random IP from the provided CIDR prefix.
// Supports IPv4 and IPv6. Does not support mapped inputs.
func RandomIPFromPrefix(cidr netip.Prefix) (netip.Addr, error) {
	startingAddress := cidr.Masked().Addr()
	if startingAddress.Is4In6() {
		return netip.Addr{}, errors.New("mapped v4 addresses not supported")
	}

	prefixLen := cidr.Bits()
	if prefixLen == -1 {
		return netip.Addr{}, fmt.Errorf("invalid cidr: %s", cidr)
	}

	// Initialise rand number generator
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	// Find the bit length of the Host portion of the provided CIDR
	// prefix
	hostLen := big.NewInt(int64(startingAddress.BitLen() - prefixLen))

	// Find the max value for our random number
	max := new(big.Int).Exp(big.NewInt(2), hostLen, nil)

	// Generate the random number
	randInt := new(big.Int).Rand(rng, max)

	// Get the first address in the CIDR prefix in 16-bytes form
	startingAddress16 := startingAddress.As16()

	// Convert the first address into a decimal number
	startingAddressInt := new(big.Int).SetBytes(startingAddress16[:])

	// Add the random number to the decimal form of the starting address
	// to get a random address in the desired range
	randomAddressInt := new(big.Int).Add(startingAddressInt, randInt)

	// Convert the random address from decimal form back into netip.Addr
	randomAddress, ok := netip.AddrFromSlice(randomAddressInt.FillBytes(make([]byte, 16)))
	if !ok {
		return netip.Addr{}, fmt.Errorf("failed to generate random IP from CIDR: %s", cidr)
	}

	// Unmap any mapped v4 addresses before return
	return randomAddress.Unmap(), nil
}

func ParseResolveAddressPort(hostname string, includev6 bool, dnsServer string) (netip.AddrPort, error) {
	// Attempt to split the hostname into a host and port
	host, port, err := net.SplitHostPort(hostname)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("can't parse provided hostname into host and port: %w", err)
	}

	// Convert the string port to a uint16
	portInt, err := strconv.Atoi(port)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("error parsing port: %w", err)
	}

	if portInt < 1 || portInt > 65535 {
		return netip.AddrPort{}, fmt.Errorf("port number %d is out of range", portInt)
	}

	// Attempt to parse the host into an IP. Return on success.
	addr, err := netip.ParseAddr(host)
	if err == nil {
		return netip.AddrPortFrom(addr.Unmap(), uint16(portInt)), nil
	}

	// Use Go's built-in DNS resolver
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return net.Dial("udp", net.JoinHostPort(dnsServer, "53"))
		},
	}

	// If the host wasn't an IP, perform a lookup
	ips, err := resolver.LookupIP(context.Background(), "ip", host)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("hostname lookup failed: %w", err)
	}

	for _, ip := range ips {
		// Take the first IP and then return it
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			continue
		}

		if addr.Unmap().Is4() {
			return netip.AddrPortFrom(addr.Unmap(), uint16(portInt)), nil
		} else if includev6 {
			return netip.AddrPortFrom(addr.Unmap(), uint16(portInt)), nil
		}
	}

	return netip.AddrPort{}, errors.New("no valid IP addresses found")
}

// ParsePrefixOrAddr parses s as a netip.Prefix. If that fails, it
// parses s as a netip.Addr and returns it as a full-prefix.
func ParsePrefixOrAddr(s string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p, nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("parsing %q: %w", s, err)
	}
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

// MustParsePrefixOrAddr parses s as a netip.Prefix. If that fails, it
// parses s as a netip.Addr and returns it as a full-prefix.
// It panics if parsing as an address fails.
func MustParsePrefixOrAddr(s string) netip.Prefix {
	p, err := ParsePrefixOrAddr(s)
	if err != nil {
		panic(err)
	}
	return p
}

func EncodeHexToBase64(key string) (string, error) {
	decoded, err := hex.DecodeString(key)
	if err != nil {
		return "", fmt.Errorf("invalid hex string: %s", key)
	}
	if len(decoded) != 32 {
		return "", fmt.Errorf("key should be 32 bytes, but it is %d bytes", len(decoded))
	}
	return base64.StdEncoding.EncodeToString(decoded), nil
}

func EncodeBase64ToHex(key string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return "", fmt.Errorf("invalid base64 string: %s", key)
	}
	if len(decoded) != 32 {
		return "", fmt.Errorf("key should be 32 bytes: %s", key)
	}
	return hex.EncodeToString(decoded), nil
}
