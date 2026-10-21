package doh

import (
	"fmt"
	"net/netip"
	"testing"
	"time"
)

func testResolver() *Resolver {
	return New(Preset{Endpoint: "https://example.invalid/dns-query", Bootstrap: []string{"192.0.2.1"}})
}

func TestCacheHitAndExpiry(t *testing.T) {
	r := testResolver()
	now := time.Unix(1700000000, 0)
	addrs := []netip.Addr{netip.MustParseAddr("192.0.2.9")}
	r.cachePut("a.test", addrs, false, 10*time.Second, now)

	got, ok := r.cacheGet("a.test", now.Add(9*time.Second))
	if !ok || len(got.addrs) != 1 || got.addrs[0] != addrs[0] {
		t.Fatalf("cacheGet = %v, %v, want hit", got.addrs, ok)
	}
	// The returned slice must not alias the stored one.
	got.addrs[0] = netip.MustParseAddr("10.0.0.1")
	if again, _ := r.cacheGet("a.test", now); again.addrs[0] != addrs[0] {
		t.Fatalf("cache entry mutated through returned slice: %v", again.addrs)
	}

	if _, ok := r.cacheGet("a.test", now.Add(10*time.Second)); ok {
		t.Fatal("entry must expire exactly at its TTL")
	}
	if r.CacheLen() != 0 {
		t.Fatalf("expired entry not dropped, len = %d", r.CacheLen())
	}
	if _, ok := r.cacheGet("missing.test", now); ok {
		t.Fatal("unexpected hit for unknown host")
	}
}

func TestCacheNegativeEntry(t *testing.T) {
	r := testResolver()
	now := time.Unix(1700000000, 0)
	r.cachePut("nx.test", nil, true, negativeTTL, now)

	entry, ok := r.cacheGet("nx.test", now.Add(29*time.Second))
	if !ok {
		t.Fatal("negative entry should be cached")
	}
	if len(entry.addrs) != 0 {
		t.Fatalf("addrs = %v, want empty", entry.addrs)
	}
	if !entry.nxdomain {
		t.Fatal("nxdomain flag lost by the cache")
	}
	if _, ok := r.cacheGet("nx.test", now.Add(negativeTTL)); ok {
		t.Fatal("negative entry outlived its TTL")
	}
}

func TestCacheZeroTTLNotStored(t *testing.T) {
	r := testResolver()
	r.cachePut("a.test", []netip.Addr{netip.MustParseAddr("192.0.2.1")}, false, 0, time.Now())
	if r.CacheLen() != 0 {
		t.Fatalf("len = %d, want 0", r.CacheLen())
	}
}

func TestCacheEvictionCap(t *testing.T) {
	r := testResolver()
	now := time.Unix(1700000000, 0)
	addr := []netip.Addr{netip.MustParseAddr("192.0.2.1")}

	// Expired entries are the first eviction victims.
	r.cachePut("stale.test", addr, false, time.Second, now.Add(-time.Hour))
	for i := range maxCacheEntries + 100 {
		r.cachePut(fmt.Sprintf("h%d.test", i), addr, false, time.Minute, now)
		if got := r.CacheLen(); got > maxCacheEntries {
			t.Fatalf("cache grew to %d entries, cap is %d", got, maxCacheEntries)
		}
	}
	if _, ok := r.cacheGet("stale.test", now); ok {
		t.Fatal("expired entry survived eviction")
	}
	if r.CacheLen() != maxCacheEntries {
		t.Fatalf("len = %d, want %d", r.CacheLen(), maxCacheEntries)
	}
	// Re-inserting an existing key must not evict anything.
	r.cachePut("h0.test", addr, false, time.Minute, now)
	if r.CacheLen() != maxCacheEntries {
		t.Fatalf("len = %d after refresh, want %d", r.CacheLen(), maxCacheEntries)
	}
}

func TestClampTTL(t *testing.T) {
	cases := []struct {
		in   uint32
		want time.Duration
	}{
		{0, minTTL},
		{1, minTTL},
		{60, time.Minute},
		{3600, maxTTL},
		{86400, maxTTL},
		{^uint32(0), maxTTL},
	}
	for _, tc := range cases {
		if got := clampTTL(tc.in); got != tc.want {
			t.Errorf("clampTTL(%d) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestCacheConcurrentAccess(t *testing.T) {
	r := testResolver()
	addr := []netip.Addr{netip.MustParseAddr("192.0.2.1")}
	done := make(chan struct{})
	for worker := range 4 {
		go func() {
			defer func() { done <- struct{}{} }()
			for i := range 200 {
				key := fmt.Sprintf("w%d-%d.test", worker, i)
				r.cachePut(key, addr, false, time.Minute, time.Now())
				r.cacheGet(key, time.Now())
			}
		}()
	}
	for range 4 {
		<-done
	}
}
