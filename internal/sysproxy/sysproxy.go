// Package sysproxy routes macOS system-wide HTTP/HTTPS traffic through a
// local proxy address, snapshotting first so Restore puts back exactly what
// was there before. Changes are always user-initiated and visible in System
// Settings; nothing is modified silently.
package sysproxy

import (
	"fmt"
	"strconv"
	"strings"
)

// Setting is the proxy state of one network service and protocol.
type Setting struct {
	Enabled bool
	Server  string
	Port    int
}

// parseServices extracts service names from `networksetup
// -listallnetworkservices` output: skip the asterisk header note and disabled
// (starred) services.
func parseServices(out string) []string {
	var services []string
	for i, line := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		if i == 0 || strings.TrimSpace(line) == "" || strings.HasPrefix(line, "*") {
			continue
		}
		services = append(services, strings.TrimSpace(line))
	}
	return services
}

// parseProxy extracts the enabled flag, server, and port from
// `networksetup -getwebproxy` / `-getsecurewebproxy` output.
func parseProxy(out string) (Setting, error) {
	s := Setting{Port: 0}
	for _, line := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch strings.TrimSpace(key) {
		case "Enabled":
			s.Enabled = value == "Yes"
		case "Server":
			s.Server = value
		case "Port":
			port, err := strconv.Atoi(value)
			if err != nil {
				return s, fmt.Errorf("proxy port %q: %w", value, err)
			}
			s.Port = port
		}
	}
	// "Enabled: Yes" with an empty server is a state networksetup itself can
	// produce (the address write auto-enables); accept and reproduce it rather
	// than failing to snapshot.
	return s, nil
}
