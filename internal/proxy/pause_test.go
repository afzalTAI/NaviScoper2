package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Paused filtering suspends deny rules and cookie stripping for new requests
// while forwarding continues; the CONNECT port whitelist stays enforced.
func TestPauseSuspendsFiltersButNotBoundaries(t *testing.T) {
	p, err := New(DefaultConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if err := p.UpdatePolicy(Policy{DenyDomains: []string{"example.com"}, StripRequestCookies: true}); err != nil {
		t.Fatal(err)
	}
	p.SetPaused(true)
	if !p.Paused() || !p.Stats().Paused {
		t.Fatal("pause state not visible")
	}
	if p.blocked("example.com") {
		t.Fatal("paused proxy still blocks")
	}
	var sawCookie string
	p.forward.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		sawCookie = r.Header.Get("Cookie")
		return responseFor(r), nil
	})
	r := httptest.NewRequest("GET", "http://example.com/", nil)
	r.Header.Set("Cookie", "session=keep")
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	if w.Code != 200 || sawCookie != "session=keep" {
		t.Fatalf("paused forward changed: code=%d cookie=%q", w.Code, sawCookie)
	}
	if p.Stats().Blocked != 0 {
		t.Fatal("paused proxy counted a block")
	}
	// The CONNECT port whitelist is a boundary and must survive pausing.
	req := httptest.NewRequest(http.MethodConnect, "http://blocked.example:443/", nil)
	req.RequestURI = "blocked.example:22"
	req.URL.Host = "blocked.example:22"
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != 403 {
		t.Fatalf("paused proxy bypassed CONNECT port whitelist: %d", rec.Code)
	}
	p.SetPaused(false)
	if !p.blocked("example.com") {
		t.Fatal("deny rule must apply again after resume")
	}
	p.forward.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) { return responseFor(r), nil })
	w = httptest.NewRecorder()
	p.ServeHTTP(w, httptest.NewRequest("GET", "http://example.com/", nil))
	if w.Code != 403 || p.Stats().Blocked != 2 {
		t.Fatalf("resume did not restore blocking: code=%d blocked=%d", w.Code, p.Stats().Blocked)
	}
}
