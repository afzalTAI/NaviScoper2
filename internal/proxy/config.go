package proxy

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"naviscopereborn/internal/doh"
)

// Config describes new implementation policies, not recovered legacy settings.
// Start with DefaultConfig; zero timeouts are rejected rather than unbounded.
type Config struct {
	ListenAddress       string
	DenyDomains         []string
	StripRequestCookies bool
	ConnectPorts        []int
	RequestTimeout      time.Duration
	TunnelTimeout       time.Duration
	ShutdownTimeout     time.Duration
	// SecureDNS names a DNS-over-HTTPS preset (cloudflare, google, quad9,
	// opendns) or an https URL with an IP-literal host. Empty uses the
	// system resolver.
	SecureDNS string
	// UpstreamURL chains every outbound connection through a SOCKS5 or HTTP
	// CONNECT provider ("socks5://[user:pass@]host:port" / "http://…").
	// Empty dials direct. Explicit opt-in only; the environment is ignored.
	UpstreamURL string
}

func DefaultConfig() Config {
	return Config{ListenAddress: "127.0.0.1:8081", ConnectPorts: []int{443}, RequestTimeout: 2 * time.Minute, TunnelTimeout: 10 * time.Minute, ShutdownTimeout: 5 * time.Second}
}

func (c Config) validate() error {
	host, port, err := net.SplitHostPort(c.ListenAddress)
	if err != nil {
		return fmt.Errorf("listen address must be an IPv4 loopback address and port")
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.To4() == nil || !ip.IsLoopback() || strings.Contains(host, ":") {
		return fmt.Errorf("listen address must use literal IPv4 loopback")
	}
	if _, err = validPort(port); err != nil {
		return err
	}
	if c.RequestTimeout <= 0 || c.TunnelTimeout <= 0 || c.ShutdownTimeout <= 0 {
		return fmt.Errorf("all timeouts must be positive")
	}
	if len(c.ConnectPorts) == 0 {
		return fmt.Errorf("at least one CONNECT port is required")
	}
	for _, p := range c.ConnectPorts {
		if p < 1 || p > 65535 {
			return fmt.Errorf("CONNECT port must be 1–65535")
		}
	}
	for _, h := range c.DenyDomains {
		if _, err := normalizeHost(h); err != nil {
			return fmt.Errorf("invalid deny domain %q: %w", h, err)
		}
	}
	if c.SecureDNS != "" {
		if _, ok := doh.Presets()[c.SecureDNS]; !ok {
			u, err := url.Parse(c.SecureDNS)
			if err != nil || u.Scheme != "https" || u.Host == "" {
				return fmt.Errorf("secure DNS must be a preset name or an https URL")
			}
			if ip := net.ParseIP(u.Hostname()); ip == nil {
				return fmt.Errorf("secure DNS URL must use an IP-literal host (no bootstrap address available)")
			}
		}
	}
	if c.UpstreamURL != "" {
		u, err := url.Parse(c.UpstreamURL)
		if err != nil || (u.Scheme != "socks5" && u.Scheme != "http") || u.Host == "" {
			return fmt.Errorf("upstream must be socks5://host:port or http://host:port")
		}
	}
	return nil
}

func validPort(s string) (int, error) {
	if s == "" {
		return 0, fmt.Errorf("port is required")
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("port must be numeric")
		}
	}
	p, err := strconv.Atoi(s)
	if err != nil || p < 1 || p > 65535 {
		return 0, fmt.Errorf("port must be 1–65535")
	}
	return p, nil
}

func normalizeHost(h string) (string, error) {
	h = strings.ToLower(strings.TrimSuffix(h, "."))
	if ip := net.ParseIP(h); ip != nil {
		return ip.String(), nil
	}
	if h == "" || len(h) > 253 {
		return "", fmt.Errorf("invalid hostname length")
	}
	for _, label := range strings.Split(h, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("invalid hostname label")
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", fmt.Errorf("hostname must be ASCII DNS name or IP address")
			}
		}
	}
	return h, nil
}

// target validates an authority before it reaches the network. CONNECT requires
// an explicit port; HTTP permits an omitted port (80).
func target(authority string, explicitPort bool) (string, int, error) {
	if authority == "" || strings.ContainsAny(authority, "/@?#\\%\t\r\n ") {
		return "", 0, fmt.Errorf("invalid target authority")
	}
	host, port, err := net.SplitHostPort(authority)
	if err != nil {
		if explicitPort {
			return "", 0, fmt.Errorf("CONNECT requires host:port")
		}
		if strings.HasPrefix(authority, "[") && strings.HasSuffix(authority, "]") {
			host = strings.TrimSuffix(strings.TrimPrefix(authority, "["), "]")
		} else if !strings.Contains(authority, ":") {
			host = authority
		} else {
			return "", 0, fmt.Errorf("invalid target authority")
		}
		port = "80"
	}
	host, err = normalizeHost(host)
	if err != nil {
		return "", 0, err
	}
	p, err := validPort(port)
	return host, p, err
}
