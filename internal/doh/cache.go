package doh

import (
	"net/netip"
	"time"
)

const (
	// negativeTTL bounds how long an empty answer is remembered.
	negativeTTL = 30 * time.Second
	// minTTL and maxTTL clamp provider TTLs to a sane range.
	minTTL = 5 * time.Second
	maxTTL = time.Hour
	// maxCacheEntries caps memory use; the cache is a hint, not a database.
	maxCacheEntries = 512
)

type cacheEntry struct {
	addrs     []netip.Addr
	expiresAt time.Time
}

func clampTTL(seconds uint32) time.Duration {
	ttl := time.Duration(seconds) * time.Second
	if seconds > uint32(maxTTL/time.Second) || ttl > maxTTL {
		return maxTTL
	}
	if ttl < minTTL {
		return minTTL
	}
	return ttl
}

// cacheGet returns the cached addresses for name. The second result reports a
// live entry; an empty address slice is a cached negative answer.
func (r *Resolver) cacheGet(name string, now time.Time) ([]netip.Addr, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, ok := r.cache[name]
	if !ok {
		return nil, false
	}
	if !now.Before(entry.expiresAt) {
		delete(r.cache, name)
		return nil, false
	}
	return append([]netip.Addr(nil), entry.addrs...), true
}

// cachePut stores addresses for ttl. Empty results are stored as negative
// entries so repeated failures do not hammer the provider.
func (r *Resolver) cachePut(name string, addrs []netip.Addr, ttl time.Duration, now time.Time) {
	if ttl <= 0 {
		return
	}
	stored := append([]netip.Addr(nil), addrs...)
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.cache[name]; !exists && len(r.cache) >= maxCacheEntries {
		r.evictLocked(now)
	}
	r.cache[name] = cacheEntry{addrs: stored, expiresAt: now.Add(ttl)}
}

// evictLocked drops expired entries first and then arbitrary ones until there
// is room for one more entry.
func (r *Resolver) evictLocked(now time.Time) {
	for name, entry := range r.cache {
		if !now.Before(entry.expiresAt) {
			delete(r.cache, name)
		}
	}
	for name := range r.cache {
		if len(r.cache) < maxCacheEntries {
			return
		}
		delete(r.cache, name)
	}
}
