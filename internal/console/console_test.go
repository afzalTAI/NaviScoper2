package console

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"naviscopereborn/internal/proxy"
)

func fixture(t *testing.T) (*Console, *proxy.Proxy) {
	t.Helper()
	p, err := proxy.New(proxy.DefaultConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	c, err := New(p, "127.0.0.1:8082")
	if err != nil {
		t.Fatal(err)
	}
	return c, p
}
func request(c *Console, method, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "http://127.0.0.1:8082"+path, strings.NewReader(body))
	r.Header.Set("Origin", "http://127.0.0.1:8082")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-NaviScope-Token", c.token)
	w := httptest.NewRecorder()
	c.ServeHTTP(w, r)
	return w
}
func TestEmbeddedInterfaceAndState(t *testing.T) {
	c, _ := fixture(t)
	for _, path := range []string{"/", "/app.js", "/style.css", "/api/state"} {
		w := request(c, "GET", path, "")
		if w.Code != 200 {
			t.Fatalf("%s: %d", path, w.Code)
		}
		if w.Header().Get("Content-Security-Policy") == "" || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("missing protection headers")
		}
	}
	if !strings.Contains(request(c, "GET", "/", "").Body.String(), "NaviScope") {
		t.Fatal("missing UI")
	}
	var state struct {
		Policy proxy.Policy `json:"policy"`
		Stats  proxy.Stats  `json:"stats"`
	}
	if err := json.Unmarshal(request(c, "GET", "/api/state", "").Body.Bytes(), &state); err != nil {
		t.Fatal(err)
	}
}
func TestPolicyAPI(t *testing.T) {
	c, p := fixture(t)
	w := request(c, "PUT", "/api/policy", `{"denyDomains":["Example.COM."],"stripRequestCookies":true}`)
	if w.Code != 200 || !p.Policy().StripRequestCookies || p.Policy().DenyDomains[0] != "example.com" {
		t.Fatalf("save: %d %s", w.Code, w.Body.String())
	}
	for _, body := range []string{`{"denyDomains":["https://bad.test"]}`, `{"unknown":true}`, `{} {}`, `{"denyDomains":123}`, `null`, `{}`, `{"denyDomains":[]}`} {
		if w := request(c, "PUT", "/api/policy", body); w.Code != 400 {
			t.Fatalf("accepted %s: %d", body, w.Code)
		}
	}
	if !p.Policy().StripRequestCookies {
		t.Fatal("invalid update changed policy")
	}
}
func TestConsoleRejectsCrossOriginAndRebinding(t *testing.T) {
	c, p := fixture(t)
	for _, tc := range []struct{ host, origin, token, site string }{
		{"evil.test:8082", "http://127.0.0.1:8082", c.token, "same-origin"},
		{"127.0.0.1:8082", "https://evil.test", c.token, "cross-site"},
		{"127.0.0.1:8082", "http://127.0.0.1:8082", "wrong", "same-origin"},
		{"127.0.0.1:8082", "", c.token, "none"},
	} {
		r := httptest.NewRequest("PUT", "http://127.0.0.1:8082/api/policy", strings.NewReader(`{"denyDomains":["example.com"]}`))
		r.Host = tc.host
		r.Header.Set("Origin", tc.origin)
		r.Header.Set("X-NaviScope-Token", tc.token)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Sec-Fetch-Site", tc.site)
		w := httptest.NewRecorder()
		c.ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Fatalf("accepted %+v: %d", tc, w.Code)
		}
	}
	if len(p.Policy().DenyDomains) != 0 {
		t.Fatal("cross-origin policy update applied")
	}
	r := httptest.NewRequest("GET", "http://evil.test/api/state", nil)
	w := httptest.NewRecorder()
	c.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("state exposed through another Host")
	}
}
func TestConsoleRejectsUnsafeAddressAndOversizedJSON(t *testing.T) {
	c, p := fixture(t)
	for _, addr := range []string{"0.0.0.0:8082", "localhost:8082", "127.0.0.1:0", "[::1]:8082"} {
		if _, err := New(p, addr); err == nil {
			t.Errorf("accepted %s", addr)
		}
	}
	if w := request(c, "PUT", "/api/policy", `{"denyDomains":["`+strings.Repeat("x", 70000)+`"]}`); w.Code != 400 {
		t.Fatalf("oversized body: %d", w.Code)
	}
	if w := request(c, "POST", "/api/policy", `{}`); w.Code != 405 {
		t.Fatalf("wrong method: %d", w.Code)
	}
}
