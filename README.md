# 🔌 wiresocks

[![MIT licensed](https://img.shields.io/badge/license-MIT-blue)](./LICENSE) 
[![Go Report Card](https://goreportcard.com/badge/github.com/shahradelahi/wiresocks)](https://goreportcard.com/report/github.com/shahradelahi/wiresocks) 
[![Go Reference](https://pkg.go.dev/badge/github.com/shahradelahi/wiresocks.svg)](https://pkg.go.dev/github.com/shahradelahi/wiresocks)

A user-space WireGuard client that exposes a SOCKS and HTTP proxy.

`wiresocks` allows you to connect to a WireGuard peer and route traffic from any application through the tunnel by
connecting to the local proxy server. It runs entirely in user-space, meaning it does not require elevated privileges to
operate.

## Table of Contents

- [Motivation](#-motivation)
- [Features](#-features)
- [Installation](#-installation)
  - [From Source (Recommended)](#from-source-recommended)
  - [From GitHub Releases](#from-github-releases)
  - [Building from Source](#building-from-source)
- [Usage](#-usage)
  - [Command-line Flags](#command-line-flags)
- [Usage as a Library](#-usage-as-a-library)
  - [Installation](#installation)
  - [Example Usage](#example-usage)
- [Docker](#-docker)
  - [Building the Image](#building-the-image)
  - [Running the Container](#running-the-container)
- [Configuration](#-configuration)
- [Contributing](#-contributing)
- [License](#license)

## 💡 Motivation

Many WireGuard clients require kernel-level access or route all system traffic through the tunnel by default.
`wiresocks` was created to provide a more flexible, lightweight alternative that:

- **Runs without root:** Operates entirely in user-space, enhancing security and simplifying setup.
- **Offers per-application tunneling:** By exposing a proxy, it allows you to selectively route traffic from specific
  applications (like web browsers or torrent clients) without affecting the rest of your system.
- **Is simple and portable:** As a single, cross-platform binary, it is easy to deploy and run anywhere.

## ✨ Features

- **User-Space WireGuard:** Connects to a WireGuard peer without needing kernel modules or root access.
- **SOCKS and HTTP Proxy:** Exposes both SOCKS and HTTP proxies to tunnel application traffic, with optional authentication.
- **Full SOCKS Support:** Implements SOCKS5 with TCP (`CONNECT`) and UDP (`ASSOCIATE`) support.
- **Standard Configuration:** Uses a standard `wg-quick`-style configuration file.
- **Cross-Platform:** Written in Go, it can be built for Linux, macOS, Windows, and more.

## 🚀 Installation

There are multiple ways to install `wiresocks`.

### From Source (Recommended)

To install the latest version, use `go install`:

```bash
go install github.com/shahradelahi/wiresocks/cmd/wiresocks@latest
```

### From GitHub Releases

You can download pre-compiled binaries for various operating systems and architectures from
the [GitHub Releases](https://github.com/shahradelahi/wiresocks/releases) page.

### Building from Source

Clone the repository and use the `Makefile` to build the binary.

```bash
git clone https://github.com/shahradelahi/wiresocks.git
cd wiresocks
make wiresocks
```

The compiled binary will be located in the `build/` directory.

## ⚙️ Usage

Run `wiresocks` from the command line, providing the path to your WireGuard configuration file.

```bash
./build/wiresocks -c ./config.conf
```

### Command-line Flags

- `-c`, `--config <path>`: Path to the WireGuard configuration file (default: `./config.conf`).
- `--socks-addr <addr:port>`: SOCKS5 proxy bind address.
- `--http-addr <addr:port>`: HTTP proxy bind address.
- `-p`, `--password <password>`: Proxy password for authentication (optional).
- `-u`, `--username <username>`: Proxy username for authentication (optional).
- `--silent`: Enable silent mode.
- `-v`, `--version`: Show version information and exit.

**Example:** Run with a SOCKS proxy on port 1080 and an HTTP proxy on port 8118.

```bash
./build/wiresocks -c /etc/wireguard/wg0.conf --socks-addr 127.0.0.1:1080 --http-addr 127.0.0.1:8118
```

## 📚 Usage as a Library

`wiresocks` can also be used as a library in your Go projects to embed WireGuard proxy functionality directly into your applications.

### Installation

To add `wiresocks` to your Go project, use `go get`:

```bash
go get github.com/shahradelahi/wiresocks
```

### Example Usage

Here's a basic example of how to start a `wiresocks` instance programmatically:

```go
package main

import (
	"context"
	"log"
	"net/netip"
	"time"

	"github.com/shahradelahi/wiresocks"
)

func main() {
	// Define WireGuard interface configuration
	iface := wiresocks.InterfaceConfig{
		PrivateKey: "YOUR_PRIVATE_KEY_HEX", // Replace with your actual private key
		Addresses: []netip.Prefix{
			netip.MustParsePrefix("10.0.0.2/32"),
		},
		DNS: []netip.Addr{
			netip.MustParseAddr("1.1.1.1"),
		},
		MTU: 1420,
	}

	// Define WireGuard peer configuration
	peer := wiresocks.PeerConfig{
		PublicKey: "PEER_PUBLIC_KEY_HEX",    // Replace with your peer's public key
		Endpoint:  "peer.example.com:51820", // Replace with your peer's endpoint
		AllowedIPs: []netip.Prefix{
			netip.MustParsePrefix("0.0.0.0/0"),
			netip.MustParsePrefix("::/0"),
		},
		PersistentKeepalive: 25,
	}

	// Define proxy configuration
	socksAddr := netip.MustParseAddrPort("127.0.0.1:1080")
	httpAddr := netip.MustParseAddrPort("127.0.0.1:8118")
	proxyOpts := &wiresocks.ProxyConfig{
		SocksBindAddr: &socksAddr,
		HttpBindAddr:  &httpAddr,
		Username:      "myuser",
		Password:      "mypassword",
	}

	// Create a new WireSocks instance
	ws, err := wiresocks.NewWireSocks(
		wiresocks.WithContext(context.Background()),
		wiresocks.WithWireguardConfig(&wiresocks.Configuration{
			Interface: &iface,
			Peers:     []wiresocks.PeerConfig{peer},
		}),
		wiresocks.WithProxyConfig(proxyOpts),
		wiresocks.WithLogLevel(wiresocks.LogLevelVerbose),
		wiresocks.WithConnectivityTest(&wiresocks.ConnectivityTestOptions{
			Enabled: true,
			URL:     "https://1.1.1.1/cdn-cgi/trace/",
			Timeout: 10 * time.Second,
		}),
	)
	if err != nil {
		log.Fatalf("Failed to create WireSocks instance: %v", err)
	}

	// Run WireSocks in a goroutine
	go func() {
		if err := ws.Run(); err != nil {
			log.Fatalf("WireSocks failed to run: %v", err)
		}
	}()

	// Keep the main goroutine alive until interrupted
	select {
	case <-context.Background().Done():
		// Handle shutdown gracefully
	}
}
```

## 🐳 Docker

You can also run `wiresocks` using Docker.

### Building the Image

Build the Docker image using the provided `Dockerfile`:

```bash
docker build -t wiresocks .
```

### Running the Container

When running the container, you must mount your configuration file and expose the necessary ports.

```bash
docker run -d \
  --name wiresocks \
  -v /path/to/your/config.conf:/etc/wiresocks/config.conf:ro \
  -p 1080:1080 \
  --restart=unless-stopped \
  wiresocks
```

This command runs `wiresocks` in the background, mounts your local `config.conf` as read-only, and exposes the SOCKS
proxy on port 1080.

To use an HTTP proxy, add the `-h` flag and expose its port:

```bash
docker run -d \
  --name wiresocks \
  -v /path/to/your/config.conf:/etc/wiresocks/config.conf:ro \
  -p 1080:1080 \
  -p 8118:8118 \
  --restart=unless-stopped \
  wiresocks -h 0.0.0.0:8118
```

**Note:** Inside the container, the proxy must bind to `0.0.0.0` to be accessible from outside.

## 📁 Configuration

`wiresocks` uses a configuration file format that is compatible with `wg-quick`.

The file must contain one `[Interface]` section and at least one `[Peer]` section.

**Example `config.conf`:**

```ini
[Interface]
# The private key for the client (this machine)
PrivateKey = <your-private-key>

# (Optional) IP addresses to assign to the interface
Address = 10.0.0.2/32

# (Optional) DNS servers to use for resolution
DNS = 1.1.1.1

# (Optional) MTU for the interface
MTU = 1420

[Peer]
# The public key of the WireGuard peer (the server)
PublicKey = <peer-public-key>

# (Optional) A pre-shared key for an extra layer of security
PresharedKey = <your-preshared-key>

# A comma-separated list of IPs to be routed through the tunnel
AllowedIPs = 0.0.0.0/0, ::/0

# The public endpoint of the WireGuard peer
Endpoint = <peer-ip-or-hostname>:<peer-port>

# (Optional) Keepalive interval in seconds
PersistentKeepalive = 25
```

## 🤝 Contributing

Want to contribute? Awesome! To show your support is to star the project, or to raise issues on [GitHub](https://github.com/shahradelahi/wiresocks)

Thanks again for your support, it is much appreciated! 🙏

## License

[MIT](/LICENSE) © [Shahrad Elahi](https://github.com/shahradelahi)
