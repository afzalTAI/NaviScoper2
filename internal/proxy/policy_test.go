package proxy

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func TestLivePolicyUpdatesAndCounters(t *testing.T) {
	p, err := New(DefaultConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	rules := []string{"Example.COM.", "example.com"}
	if err := p.UpdatePolicy(Policy{DenyDomains: rules, StripRequestCookies: true}); err != nil {
		t.Fatal(err)
	}
	rules[0] = "changed.test"
	if !p.blocked("sub.example.com") || len(p.Policy().DenyDomains) != 1 {
		t.Fatal("policy not normalized/copied")
	}
	copy := p.Policy()
	copy.DenyDomains[0] = "changed.test"
	if !p.blocked("example.com") {
		t.Fatal("policy snapshot shares mutable slice")
	}
	r := httptest.NewRequest("GET", "http://example.com/", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	if w.Code != 403 || p.Stats().Blocked != 1 || p.Stats().HTTPRequests != 1 {
		t.Fatal("blocked request not counted")
	}
	if err := p.UpdatePolicy(Policy{DenyDomains: []string{"https://bad.test"}}); err == nil {
		t.Fatal("invalid policy accepted")
	}
	if !p.blocked("example.com") {
		t.Fatal("invalid update changed active policy")
	}
	p.forward.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("Cookie") != "" {
			t.Error("live cookie removal did not apply")
		}
		return responseFor(r), nil
	})
	other := httptest.NewRequest("GET", "http://allowed.test/", nil)
	other.Header.Set("Cookie", "remove=1")
	p.ServeHTTP(httptest.NewRecorder(), other)
	if err := p.UpdatePolicy(Policy{}); err != nil {
		t.Fatal(err)
	}
	p.forward.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("Cookie") != "keep=1" {
			t.Error("cookie setting did not update")
		}
		return responseFor(r), nil
	})
	r = httptest.NewRequest("GET", "http://example.com/", nil)
	r.Header.Set("Cookie", "keep=1")
	p.ServeHTTP(httptest.NewRecorder(), r)
	if p.Stats().ActiveHTTP != 0 {
		t.Fatal("request still active")
	}
}
func TestConcurrentPolicyAccess(t *testing.T) {
	p, err := New(DefaultConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_ = p.UpdatePolicy(Policy{DenyDomains: []string{"example.com"}})
				p.blocked("sub.example.com")
				_ = p.Policy()
				_ = p.Stats()
			}
		}()
	}
	wg.Wait()
}
