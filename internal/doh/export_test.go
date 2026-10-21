package doh

import (
	"net/http"
	"net/netip"
	"strings"
	"time"
)

// Hooks for the external test package. They exist only in test builds.

const (
	TypeA     = typeA
	TypeAAAA  = typeAAAA
	TypeCNAME = typeCNAME
	ClassIN   = classIN

	NegativeTTL     = negativeTTL
	MinTTL          = minTTL
	MaxCacheEntries = maxCacheEntries
)

// SetClient injects an HTTP client, bypassing the bootstrap transport.
func (r *Resolver) SetClient(c *http.Client) { r.setClient(c) }

func (r *Resolver) CacheLen() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.cache)
}

func (r *Resolver) CacheGet(name string, now time.Time) ([]netip.Addr, bool) {
	return r.cacheGet(name, now)
}

func (r *Resolver) CachePut(name string, addrs []netip.Addr, ttl time.Duration, now time.Time) {
	r.cachePut(name, addrs, ttl, now)
}

// ParseQuery decodes a query produced by this package; test servers use it to
// answer self-encoded questions.
func ParseQuery(msg []byte) (id uint16, host string, qtype uint16, err error) {
	m, err := parseMessage(msg)
	if err != nil {
		return 0, "", 0, err
	}
	return m.id, strings.TrimSuffix(m.qname, "."), m.qtype, nil
}
