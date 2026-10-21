// Package upstream provides dialers that tunnel TCP connections through an
// upstream proxy, either a SOCKS5 server (RFC 1928, RFC 1929) or an HTTP proxy
// that supports the CONNECT method.
package upstream

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// handshakeTimeout bounds a proxy handshake when the caller's context has no
// earlier deadline.
const handshakeTimeout = 10 * time.Second

// Dialer establishes a TCP connection to addr through an upstream proxy.
// addr is always "host:port"; host may be a name or an IP literal.
type Dialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

// Parse builds a Dialer from a proxy URL. Supported forms are
// "socks5://[user:pass@]host:port" and "http://[user:pass@]host:port".
// An empty string yields a nil Dialer and a nil error, meaning "no upstream".
func Parse(raw string) (Dialer, error) { return ParseWithDialer(raw, nil) }

// ParseWithDialer behaves like Parse but reaches the proxy server through
// base when it is non-nil (base dials the proxy's own address, enabling
// secure-DNS resolution of the proxy host). A nil base uses the default
// resolver, matching Parse.
func ParseWithDialer(raw string, base Dialer) (Dialer, error) {
	if raw == "" {
		return nil, nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("upstream: invalid proxy URL %q: %w", raw, err)
	}
	if u.Scheme == "" || u.Opaque != "" {
		return nil, fmt.Errorf("upstream: proxy URL %q needs a scheme (socks5:// or http://)", raw)
	}
	if u.Path != "" && u.Path != "/" {
		return nil, fmt.Errorf("upstream: proxy URL %q must not have a path", raw)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("upstream: proxy URL %q must not have a query or fragment", raw)
	}
	addr, err := proxyAddr(u.Host, raw)
	if err != nil {
		return nil, err
	}
	user, pass, err := credentials(u, raw)
	if err != nil {
		return nil, err
	}
	switch strings.ToLower(u.Scheme) {
	case "socks5":
		return &socksDialer{addr: addr, user: user, pass: pass, base: base}, nil
	case "http":
		return &httpDialer{addr: addr, user: user, pass: pass, base: base}, nil
	default:
		return nil, fmt.Errorf("upstream: unsupported proxy scheme %q in %q (want socks5:// or http://)", u.Scheme, raw)
	}
}

// dialWith reaches the proxy server through base, or the default resolver
// when base is nil.
func dialWith(ctx context.Context, base Dialer, addr string) (net.Conn, error) {
	if base == nil {
		return dialProxy(ctx, addr)
	}
	conn, err := base.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("upstream: dial proxy %s: %w", addr, err)
	}
	return conn, nil
}

// proxyAddr validates the authority of a proxy URL and returns it as host:port.
func proxyAddr(hostport, raw string) (string, error) {
	if hostport == "" {
		return "", fmt.Errorf("upstream: proxy URL %q has no host", raw)
	}
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return "", fmt.Errorf("upstream: proxy URL %q needs a host:port address", raw)
	}
	if host == "" {
		return "", fmt.Errorf("upstream: proxy URL %q has no host", raw)
	}
	if _, err := parsePort(port); err != nil {
		return "", fmt.Errorf("upstream: proxy URL %q has an invalid port %q", raw, port)
	}
	return net.JoinHostPort(host, port), nil
}

// credentials extracts the percent-decoded userinfo of a proxy URL.
func credentials(u *url.URL, raw string) (user, pass string, err error) {
	if u.User == nil {
		return "", "", nil
	}
	user = u.User.Username()
	pass, _ = u.User.Password()
	if user == "" {
		return "", "", fmt.Errorf("upstream: proxy URL %q has an empty username", raw)
	}
	if len(user) > 255 || len(pass) > 255 {
		return "", "", fmt.Errorf("upstream: proxy URL %q credentials exceed 255 bytes", raw)
	}
	return user, pass, nil
}

// parsePort converts a decimal port string to a number in [1, 65535].
func parsePort(port string) (uint16, error) {
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil || n == 0 {
		return 0, errors.New("invalid port")
	}
	return uint16(n), nil
}

// splitTarget validates a dial request and splits it into host and port.
func splitTarget(network, addr string) (string, uint16, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return "", 0, fmt.Errorf("upstream: unsupported network %q", network)
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, fmt.Errorf("upstream: invalid address %q: %w", addr, err)
	}
	if host == "" {
		return "", 0, fmt.Errorf("upstream: address %q has no host", addr)
	}
	n, err := parsePort(port)
	if err != nil {
		return "", 0, fmt.Errorf("upstream: address %q has an invalid port %q", addr, port)
	}
	return host, n, nil
}

// deadline returns the handshake deadline: the earlier of the context deadline
// and now+handshakeTimeout.
func deadline(ctx context.Context) time.Time {
	d := time.Now().Add(handshakeTimeout)
	if cd, ok := ctx.Deadline(); ok && cd.Before(d) {
		return cd
	}
	return d
}

// guard runs a handshake under a deadline derived from ctx, unblocking it if
// ctx is cancelled, and clears the connection deadlines on success.
func guard(ctx context.Context, conn net.Conn, fn func() error) error {
	if err := conn.SetDeadline(deadline(ctx)); err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	err := fn()
	stop()
	// A done context wins: the deadline we installed may itself be what broke
	// the handshake, and the caller cares about the cancellation.
	if cerr := ctx.Err(); cerr != nil {
		return fmt.Errorf("upstream: proxy handshake aborted: %w", cerr)
	}
	if err != nil {
		// The socket deadline can fire a hair before the context timer; both
		// mean the same thing to the caller.
		if cd, ok := ctx.Deadline(); ok && errors.Is(err, os.ErrDeadlineExceeded) && !time.Now().Before(cd) {
			return fmt.Errorf("upstream: proxy handshake aborted: %w", context.DeadlineExceeded)
		}
		return err
	}
	return conn.SetDeadline(time.Time{})
}

// dialProxy opens a TCP connection to the proxy itself using the default
// resolver.
func dialProxy(ctx context.Context, addr string) (net.Conn, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("upstream: dial proxy %s: %w", addr, err)
	}
	return conn, nil
}
