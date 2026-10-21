package proxy

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"time"

	"naviscopereborn/internal/doh"
	"naviscopereborn/internal/upstream"
)

// secure-DNS resolver when set (never the system resolver for those lookups),
// and connections optionally tunnel through an explicit upstream provider.
// HTTPS remains end-to-end: TLS always uses the original hostname for SNI and
// verification, independent of which IP the dialer connects to.
func (p *Proxy) dialChain(cfg Config) (func(ctx context.Context, network, addr string) (net.Conn, error), error) {
	base := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	var resolver *doh.Resolver
	if cfg.SecureDNS != "" {
		preset, ok := doh.Presets()[cfg.SecureDNS]
		if !ok {
			u, _ := url.Parse(cfg.SecureDNS) // validate() checked this parses
			preset = doh.Preset{Endpoint: cfg.SecureDNS, Bootstrap: []string{u.Hostname()}}
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
	if cfg.UpstreamURL == "" {
		return dialResolved, nil
	}
	dialer, err := upstream.ParseWithDialer(cfg.UpstreamURL, dialFunc(dialResolved))
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
