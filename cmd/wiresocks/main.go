package main

import (
	"context"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/shahradelahi/wiresocks"
	"github.com/shahradelahi/wiresocks/internal/version"
)

// default paths for wiresocks config file
var defaultConfigPaths = []string{
	"/etc/wiresocks/config.conf",
	"./config.conf",
}

// Global variables to hold flag values
var (
	configFile string
	silent     bool
	socksAddr  string
	httpAddr   string
	username   string
	password   string
)

// check if default config file paths exist
func configFilePath() (string, bool) {
	for _, path := range defaultConfigPaths {
		if _, err := os.Stat(path); err == nil {
			return path, true
		}
	}
	return "", false
}

func fatal(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

var rootCmd = &cobra.Command{
	Use:     "wiresocks",
	Short:   "A user-space WireGuard client that exposes a SOCKS and HTTP proxy.",
	Version: version.String(),
	RunE: func(cmd *cobra.Command, args []string) error {
		if configFile == "" {
			if path, configExist := configFilePath(); configExist {
				configFile = path
			} else {
				return fmt.Errorf("path to a configuration file is required")
			}
		}

		conf, err := wiresocks.ParseConfig(configFile)
		if err != nil {
			return fmt.Errorf("failed to parse config file: %v", err)
		}

		proxyOpts := &wiresocks.ProxyConfig{
			Username: username,
			Password: password,
		}

		if socksAddr != "" {
			addr, err := netip.ParseAddrPort(socksAddr)
			if err != nil {
				return fmt.Errorf("failed to parse SOCKS address: %v", err)
			}
			proxyOpts.SocksBindAddr = &addr
		}

		if httpAddr != "" {
			addr, err := netip.ParseAddrPort(httpAddr)
			if err != nil {
				return fmt.Errorf("failed to parse HTTP address: %v", err)
			}
			proxyOpts.HttpBindAddr = &addr
		}

		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		ctx, cancel := context.WithCancel(context.Background())

		logLevel := wiresocks.LogLevelVerbose
		if silent {
			logLevel = wiresocks.LogLevelSilent
		}

		ws, err := wiresocks.NewWireSocks(
			wiresocks.WithContext(ctx),
			wiresocks.WithWireguardConfig(conf),
			wiresocks.WithProxyConfig(proxyOpts),
			wiresocks.WithLogLevel(logLevel),
		)

		if err != nil {
			return fmt.Errorf("failed to create a new WireSocks instance: %v", err)
		}

		go func() {
			<-sigChan
			cancel()
		}()

		go func() {
			if err := ws.Run(); err != nil {
				fatal(fmt.Errorf("wiresocks failed to run: %v", err))
			}
		}()

		<-ctx.Done()
		return nil
	},
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&configFile, "config", "c", "", "Path to the configuration file.")
	rootCmd.PersistentFlags().BoolVar(&silent, "silent", false, "Enable silent mode.")
	rootCmd.PersistentFlags().StringVar(&socksAddr, "socks-addr", "", "SOCKS5 proxy bind address.")
	rootCmd.PersistentFlags().StringVar(&httpAddr, "http-addr", "", "HTTP proxy bind address.")
	rootCmd.PersistentFlags().StringVarP(&username, "username", "u", "", "Proxy username for authentication (optional).")
	rootCmd.PersistentFlags().StringVarP(&password, "password", "p", "", "Proxy password for authentication (optional).")

	// Set custom version template to show only the version string
	rootCmd.SetVersionTemplate(fmt.Sprintf("{{.Version}}\n%s\n", version.BuildString()))
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
