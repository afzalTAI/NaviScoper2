package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func newTestProxy(t *testing.T, cfg Config) (*Proxy, *httptest.Server, *http.Client) {
	t.Helper()
	p, err := New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	s := httptest.NewServer(p)
	tr := &http.Transport{Proxy: http.ProxyURL(mustURL(t, s.URL))}
	t.Cleanup(func() { tr.CloseIdleConnections(); p.Close(); s.Close() })
	return p, s, &http.Client{Transport: tr}
}
func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, e := url.Parse(s)
	if e != nil {
		t.Fatal(e)
	}
	return u
}

func TestForwardingAndHeaders(t *testing.T) {
	received := make(chan *http.Request, 1)
	body := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		body <- string(b)
		received <- r.Clone(r.Context())
		w.Header().Add("Set-Cookie", "a=1")
		w.Header().Add("Set-Cookie", "b=2")
		w.Header().Set("Connection", "X-Response-Secret")
		w.Header().Set("X-Response-Secret", "hidden")
		w.WriteHeader(201)
		_, _ = io.WriteString(w, "response")
	}))
	defer upstream.Close()
	cfg := DefaultConfig()
	cfg.StripRequestCookies = true
	_, _, client := newTestProxy(t, cfg)
	req, _ := http.NewRequest("POST", upstream.URL+"/path?q=1", strings.NewReader("payload"))
	req.Header.Set("Cookie", "session=secret")
	req.Header.Set("Proxy-Authorization", "Basic secret")
	req.Header.Set("Connection", "X-Request-Secret")
	req.Header.Set("X-Request-Secret", "hidden")
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	if res.StatusCode != 201 || string(b) != "response" || len(res.Header.Values("Set-Cookie")) != 2 {
		t.Fatalf("bad response: %v %q", res, b)
	}
	if res.Header.Get("X-Response-Secret") != "" {
		t.Fatal("response hop header leaked")
	}
	r := <-received
	if r.Method != "POST" || r.URL.RequestURI() != "/path?q=1" || r.Host != strings.TrimPrefix(upstream.URL, "http://") || <-body != "payload" {
		t.Fatal("request semantics changed")
	}
	for _, h := range []string{"Cookie", "Proxy-Authorization", "X-Request-Secret"} {
		if r.Header.Get(h) != "" {
			t.Errorf("leaked %s", h)
		}
	}
}

func TestDomainPolicy(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DenyDomains = []string{"Example.COM.", "127.0.0.1"}
	p, err := New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	for _, host := range []string{"example.com", "sub.example.com", "EXAMPLE.COM.", "127.0.0.1"} {
		if !p.blocked(host) {
			t.Errorf("allowed %s", host)
		}
	}
	for _, host := range []string{"notexample.com", "example.com.evil", "127.0.0.11"} {
		if p.blocked(host) {
			t.Errorf("blocked %s", host)
		}
	}
	r := httptest.NewRequest("GET", "http://sub.example.com/", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status %d", w.Code)
	}
}

func TestRejectInvalidRequests(t *testing.T) {
	p, err := New(DefaultConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	for _, target := range []string{"/relative", "https://example.com/", "http://user:pass@example.com/", "http://example.com:0/", "http://example.com:65536/"} {
		t.Run(target, func(t *testing.T) {
			r := httptest.NewRequest("GET", target, nil)
			w := httptest.NewRecorder()
			p.ServeHTTP(w, r)
			if w.Code != 400 {
				t.Fatalf("status %d", w.Code)
			}
		})
	}
}

func TestConfigValidation(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:8081", ":8081", "localhost:8081", "[::1]:8081", "127.0.0.1:0", "127.0.0.1:99999"} {
		cfg := DefaultConfig()
		cfg.ListenAddress = addr
		if _, err := New(cfg, nil); err == nil {
			t.Errorf("accepted %s", addr)
		}
	}
	cfg := DefaultConfig()
	cfg.ConnectPorts = []int{0}
	if _, err := New(cfg, nil); err == nil {
		t.Error("accepted port 0")
	}
	cfg = DefaultConfig()
	cfg.RequestTimeout = 0
	if _, err := New(cfg, nil); err == nil {
		t.Error("accepted unbounded timeout")
	}
}

func TestTargetAuthorities(t *testing.T) {
	for _, tc := range []struct {
		authority, host string
		port            int
		connect         bool
	}{
		{"Example.COM.:8080", "example.com", 8080, false},
		{"example.com", "example.com", 80, false},
		{"[::1]:443", "::1", 443, true},
		{"[::1]", "::1", 80, false},
		{"[::ffff:127.0.0.1]:443", "127.0.0.1", 443, true},
	} {
		host, port, err := target(tc.authority, tc.connect)
		if err != nil || host != tc.host || port != tc.port {
			t.Errorf("%s: %s %d %v", tc.authority, host, port, err)
		}
	}
	for _, s := range []string{"example.com:", "example.com:-1", "example.com:+443", "a..b:443", "-bad.example:443", "example.com:443/path", "[fe80::1%lo0]:443", "example.com.:0"} {
		if _, _, err := target(s, true); err == nil {
			t.Errorf("accepted %q", s)
		}
	}
}
