// Package outbound builds the dial chain used for every connection leaving
// NaviScope: optional DNS-over-HTTPS name resolution, then an optional
// SOCKS5/HTTP-CONNECT upstream tunnel, then the wire. It is shared by the
// explicit proxy and the transparent TUN router.
package outbound

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"syscall"
	"time"

	"naviscopereborn/internal/doh"
	"naviscopereborn/internal/upstream"
)

// Options configures the chain. BindControl, when set, is attached to the
// base sockets (TUN mode pins them to the physical interface so outbound
// traffic can never loop back into the tunnel).
type Options struct {
	SecureDNS   string
	UpstreamURL string
	BindControl func(network, address string, c syscall.RawConn) error
}

// Dial returns the chain's dial function. Validation happens here so callers
// fail fast on bad -secure-dns/-upstream values.
func Dial(o Options) (func(ctx context.Context, network, addr string) (net.Conn, error), error) {
	base := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second, Control: o.BindControl}
	var resolver *doh.Resolver
	if o.SecureDNS != "" {
		preset, ok := doh.Presets()[o.SecureDNS]
		if !ok {
			u, err := url.Parse(o.SecureDNS)
			if err != nil || u.Scheme != "https" || u.Host == "" {
				return nil, fmt.Errorf("secure DNS must be a preset name or an https URL")
			}
			if net.ParseIP(u.Hostname()) == nil {
				return nil, fmt.Errorf("secure DNS URL must use an IP-literal host (no bootstrap address available)")
			}
			preset = doh.Preset{Endpoint: o.SecureDNS, Bootstrap: []string{u.Hostname()}}
		}
		resolver = doh.New(preset)
	}
	dialResolved := func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		if resolver != nil && net.ParseIP(host) == nil {
			addrs, rerr := resolver.LookupIP(ctx, host)
			if rerr != nil {
				// Hostnames stay out of error text by policy.
				return nil, fmt.Errorf("secure DNS lookup failed: %w", rerr)
			}
			var last error
			for _, a := range addrs {
				conn, derr := base.DialContext(ctx, network, net.JoinHostPort(a.String(), port))
				if derr == nil {
					return conn, nil
				}
				last = derr
			}
			return nil, last
		}
		return base.DialContext(ctx, network, addr)
	}
	if o.UpstreamURL == "" {
		return dialResolved, nil
	}
	dialer, err := upstream.ParseWithDialer(o.UpstreamURL, dialFunc(dialResolved))
	if err != nil {
		return nil, err
	}
	return dialer.DialContext, nil
}

// dialFunc adapts a function to the upstream.Dialer interface.
type dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

func (f dialFunc) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return f(ctx, network, addr)
}
