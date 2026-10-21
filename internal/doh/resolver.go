// Package doh implements a strict DNS-over-HTTPS (RFC 8484) resolver.
//
// The resolver reaches its provider through bootstrap IP literals only and
// never consults the system resolver, so hostname lookups cannot leak to the
// local DNS configuration. Host names are never logged.
package doh

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	dohMediaType = "application/dns-message"

	dialTimeout      = 2 * time.Second
	handshakeTimeout = 2 * time.Second
	requestTimeout   = 5 * time.Second
	idleTimeout      = 90 * time.Second

	maxResponseBytes = 64 << 10
)

// ErrNoAddresses reports that the provider answered authoritatively but no
// address of a usable family exists for the host.
var ErrNoAddresses = errors.New("doh: no addresses for host")

// errNoSuchName is the LookupIP failure for a name the provider says does not
// exist. It matches both ErrNoAddresses (so existing callers keep working) and
// ErrNXDomain (so raw-DNS callers can answer with the NXDOMAIN rcode).
var errNoSuchName = fmt.Errorf("%w: %w", ErrNoAddresses, ErrNXDomain)

// Resolver performs A and AAAA lookups against one DoH endpoint and caches the
// results. It is safe for concurrent use.
type Resolver struct {
	endpoint string
	client   atomic.Pointer[http.Client]

	mu    sync.Mutex
	cache map[string]cacheEntry
}

// New builds a resolver for the given preset. Bootstrap entries that are not IP
// literals are dropped, because dialing a name would require the system
// resolver.
func New(p Preset) *Resolver {
	r := &Resolver{endpoint: p.Endpoint, cache: make(map[string]cacheEntry)}
	serverName, port := endpointTarget(p.Endpoint)
	r.client.Store(newClient(serverName, port, bootstrapAddrs(p, serverName)))
	return r
}

// setClient replaces the HTTP client; used by tests to inject a transport.
func (r *Resolver) setClient(c *http.Client) { r.client.Store(c) }

// endpointTarget extracts the TLS server name and port from an https endpoint.
func endpointTarget(endpoint string) (serverName, port string) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Hostname() == "" {
		return "", "443"
	}
	port = u.Port()
	if port == "" {
		port = "443"
	}
	return u.Hostname(), port
}

func bootstrapAddrs(p Preset, serverName string) []string {
	addrs := make([]string, 0, len(p.Bootstrap)+1)
	for _, candidate := range p.Bootstrap {
		if _, err := netip.ParseAddr(candidate); err == nil {
			addrs = append(addrs, candidate)
		}
	}
	if len(addrs) == 0 {
		if _, err := netip.ParseAddr(serverName); err == nil {
			addrs = append(addrs, serverName)
		}
	}
	return addrs
}

// bootstrapDialer connects to a fixed set of IP literals, rotating the starting
// entry per dial and trying the remaining ones on failure.
type bootstrapDialer struct {
	addrs []string
	port  string
	next  atomic.Uint32
	net   net.Dialer
}

func (b *bootstrapDialer) DialContext(ctx context.Context, network, _ string) (net.Conn, error) {
	if len(b.addrs) == 0 {
		return nil, errors.New("doh: no bootstrap addresses configured")
	}
	start := int(b.next.Add(1) - 1)
	var lastErr error
	for i := range b.addrs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		target := net.JoinHostPort(b.addrs[(start+i)%len(b.addrs)], b.port)
		conn, err := b.net.DialContext(ctx, network, target)
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func newClient(serverName, port string, bootstrap []string) *http.Client {
	dialer := &bootstrapDialer{
		addrs: bootstrap,
		port:  port,
		net:   net.Dialer{Timeout: dialTimeout},
	}
	transport := &http.Transport{
		DialContext:           dialer.DialContext,
		TLSClientConfig:       &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   handshakeTimeout,
		ResponseHeaderTimeout: requestTimeout,
		MaxIdleConns:          4,
		IdleConnTimeout:       idleTimeout,
	}
	return &http.Client{Transport: transport, Timeout: requestTimeout}
}

// LookupIP resolves host to IPv4 and IPv6 addresses. It follows CNAME chains
// contained in the answer and never falls back to the system resolver.
func (r *Resolver) LookupIP(ctx context.Context, host string) ([]netip.Addr, error) {
	name, err := normalizeHost(host)
	if err != nil {
		return nil, err
	}
	if addr, err := netip.ParseAddr(name); err == nil {
		return []netip.Addr{addr.Unmap()}, nil
	}
	if entry, ok := r.cacheGet(name, time.Now()); ok {
		return addrsOrError(entry.addrs, entry.nxdomain)
	}
	addrs, ttl, nxdomain, err := r.lookupBoth(ctx, name)
	if err != nil {
		return nil, err
	}
	r.cachePut(name, addrs, nxdomain, ttl, time.Now())
	return addrsOrError(addrs, nxdomain)
}

// addrsOrError turns a lookup outcome into the LookupIP result. An empty
// answer is ErrNoAddresses; a non-existent name additionally matches
// ErrNXDomain so that raw-DNS callers can rebuild the NXDOMAIN rcode.
func addrsOrError(addrs []netip.Addr, nxdomain bool) ([]netip.Addr, error) {
	if len(addrs) > 0 {
		return addrs, nil
	}
	if nxdomain {
		return nil, errNoSuchName
	}
	return nil, ErrNoAddresses
}

// normalizeHost lowercases the host and removes an optional trailing dot or
// IPv6 brackets.
func normalizeHost(host string) (string, error) {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	if host == "" {
		return "", errors.New("doh: empty host name")
	}
	return host, nil
}

type queryResult struct {
	addrs []netip.Addr
	ttl   uint32
	err   error
}

// lookupBoth issues the A and AAAA queries concurrently. The lookup succeeds if
// at least one of them is answered by the server. The third result reports that
// every answer was NXDOMAIN, i.e. the name itself does not exist.
func (r *Resolver) lookupBoth(ctx context.Context, name string) ([]netip.Addr, time.Duration, bool, error) {
	var wg sync.WaitGroup
	results := make([]queryResult, 2)
	for i, qtype := range [2]uint16{typeA, typeAAAA} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			addrs, ttl, err := r.exchange(ctx, name, qtype)
			results[i] = queryResult{addrs: addrs, ttl: ttl, err: err}
		}()
	}
	wg.Wait()

	var addrs []netip.Addr
	ttl := ^uint32(0)
	answered := false
	noError := false
	var firstErr error
	for _, res := range results {
		switch {
		case res.err == nil:
			answered = true
			noError = true
			addrs = append(addrs, res.addrs...)
			if len(res.addrs) > 0 {
				ttl = minTTLOf(ttl, res.ttl)
			}
		case errors.Is(res.err, ErrNXDomain):
			answered = true
		case firstErr == nil:
			firstErr = res.err
		}
	}
	if !answered {
		return nil, 0, false, firstErr
	}
	if len(addrs) == 0 {
		return nil, negativeTTL, !noError, nil
	}
	return dedupe(addrs), clampTTL(ttl), false, nil
}

func dedupe(addrs []netip.Addr) []netip.Addr {
	out := make([]netip.Addr, 0, len(addrs))
	seen := make(map[netip.Addr]bool, len(addrs))
	for _, addr := range addrs {
		if !seen[addr] {
			seen[addr] = true
			out = append(out, addr)
		}
	}
	return out
}

// exchange performs one RFC 8484 POST query and decodes the response.
func (r *Resolver) exchange(ctx context.Context, name string, qtype uint16) ([]netip.Addr, uint32, error) {
	id, err := randomID()
	if err != nil {
		return nil, 0, err
	}
	query, err := encodeQuery(id, name, qtype)
	if err != nil {
		return nil, 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.endpoint, bytes.NewReader(query))
	if err != nil {
		return nil, 0, fmt.Errorf("doh: build request: %w", err)
	}
	req.Header.Set("Content-Type", dohMediaType)
	req.Header.Set("Accept", dohMediaType)
	req.ContentLength = int64(len(query))

	resp, err := r.client.Load().Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("doh: query failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("doh: unexpected status %d", resp.StatusCode)
	}
	if mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type")); err != nil || mediaType != dohMediaType {
		return nil, 0, errors.New("doh: unexpected response content type")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, 0, fmt.Errorf("doh: read response: %w", err)
	}
	if len(body) > maxResponseBytes {
		return nil, 0, errors.New("doh: response too large")
	}
	return decodeResponse(body, id, name, qtype)
}

func randomID() (uint16, error) {
	var buf [2]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return 0, fmt.Errorf("doh: random id: %w", err)
	}
	return binary.BigEndian.Uint16(buf[:]), nil
}
