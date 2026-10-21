package proxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func responseFor(r *http.Request) *http.Response {
	return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("ok")), Request: r}
}

// In-process transport fixtures exercise the handler without opening sockets.
// The complementary localhost tests exercise the actual HTTP/TCP transports.
func TestForwardPreservesQueryHostAndDefaultCookies(t *testing.T) {
	p, err := New(DefaultConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	p.forward.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.RawQuery != "a=1;b=2&bad=%zz" {
			t.Errorf("query changed: %q", r.URL.RawQuery)
		}
		if r.Host != "example.com" || r.RequestURI != "" {
			t.Errorf("outbound host/request URI: %s %s", r.Host, r.RequestURI)
		}
		if r.Header.Get("Cookie") != "session=keep" {
			t.Error("default removed cookies")
		}
		if r.Header.Get("Proxy-Authorization") != "" || r.Header.Get("X-Hop") != "" || r.Header.Get("X-Forwarded-For") != "" {
			t.Error("hop/proxy identity leaked")
		}
		return responseFor(r), nil
	})
	r := httptest.NewRequest("GET", "http://example.com/path?a=1;b=2&bad=%zz", nil)
	r.Host = "conflicting.example"
	r.Header.Set("Cookie", "session=keep")
	r.Header.Set("Proxy-Authorization", "secret")
	r.Header.Set("Connection", "X-Hop")
	r.Header.Set("X-Hop", "secret")
	r.Header.Set("X-Forwarded-For", "secret")
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("status %d", w.Code)
	}
}

func TestUpstreamFailureAndDeadline(t *testing.T) {
	for _, mode := range []string{"failure", "timeout", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.RequestTimeout = 20 * time.Millisecond
			p, err := New(cfg, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			p.forward.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if mode == "failure" {
					return nil, errors.New("secret URL and credentials")
				}
				<-r.Context().Done()
				return nil, r.Context().Err()
			})
			r := httptest.NewRequest("GET", "http://example.com/secret?token=secret", nil)
			if mode == "canceled" {
				ctx, cancel := context.WithCancel(r.Context())
				cancel()
				r = r.WithContext(ctx)
			}
			w := httptest.NewRecorder()
			p.ServeHTTP(w, r)
			want := 502
			if mode == "timeout" {
				want = 504
			}
			if w.Code != want || strings.Contains(w.Body.String(), "secret") {
				t.Fatalf("status/body: %d %q", w.Code, w.Body.String())
			}
		})
	}
}

func TestMetadataExcludesSensitiveFields(t *testing.T) {
	var log bytes.Buffer
	p, err := New(DefaultConfig(), slog.New(slog.NewJSONHandler(&log, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	p.forward.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) { return responseFor(r), nil })
	r := httptest.NewRequest("POST", "http://example.com/SECRET_PATH?token=SECRET_QUERY", strings.NewReader("SECRET_BODY"))
	r.Header.Set("Cookie", "SECRET_COOKIE")
	r.Header.Set("Authorization", "SECRET_AUTH")
	r.Header.Set("Proxy-Authorization", "SECRET_PROXY_AUTH")
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	if strings.Contains(log.String(), "SECRET") || !strings.Contains(log.String(), "example.com") {
		t.Fatalf("bad metadata log: %s", log.String())
	}
}

func TestHopHeadersCookieRemovalAndResponseTrailers(t *testing.T) {
	cfg := DefaultConfig()
	cfg.StripRequestCookies = true
	p, err := New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	p.forward.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		for _, h := range []string{"Cookie", "Proxy-Authorization", "Proxy-Connection", "Keep-Alive", "X-Hop"} {
			if r.Header.Get(h) != "" {
				t.Errorf("leaked %s", h)
			}
		}
		res := responseFor(r)
		res.Header.Set("Connection", "X-Hop")
		res.Header.Set("X-Hop", "secret")
		res.Header.Add("Set-Cookie", "a=1")
		res.Header.Add("Set-Cookie", "b=2")
		res.Trailer = http.Header{"X-Checksum": []string{"complete"}}
		return res, nil
	})
	r := httptest.NewRequest("POST", "http://example.com/", strings.NewReader("payload"))
	for _, h := range []string{"Cookie", "Proxy-Authorization", "Proxy-Connection", "Keep-Alive", "X-Hop"} {
		r.Header.Set(h, "secret")
	}
	r.Header.Set("Connection", "X-Hop")
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	res := w.Result()
	defer res.Body.Close()
	_, _ = io.ReadAll(res.Body)
	if len(res.Header.Values("Set-Cookie")) != 2 || res.Header.Get("X-Hop") != "" || res.Trailer.Get("X-Checksum") != "complete" {
		t.Fatalf("bad headers/trailers: %v %v", res.Header, res.Trailer)
	}
}

func TestForwardStreamsBeforeUpstreamEOF(t *testing.T) {
	p, err := New(DefaultConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	reader, writer := io.Pipe()
	p.forward.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		res := responseFor(r)
		res.Body = reader
		res.ContentLength = -1
		return res, nil
	})
	first := make(chan struct{}, 1)
	w := &streamWriter{ResponseRecorder: httptest.NewRecorder(), first: first}
	done := make(chan struct{})
	go func() { defer close(done); p.ServeHTTP(w, httptest.NewRequest("GET", "http://example.com/", nil)) }()
	defer writer.Close()
	go func() { _, _ = io.WriteString(writer, "first chunk") }()
	select {
	case <-first:
	case <-time.After(time.Second):
		t.Fatal("proxy buffered until EOF")
	}
	_ = writer.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("forwarder did not finish")
	}
	if w.Body.String() != "first chunk" {
		t.Fatalf("%q", w.Body.String())
	}
}

type streamWriter struct {
	*httptest.ResponseRecorder
	first chan struct{}
}

func (w *streamWriter) Write(b []byte) (int, error) {
	n, err := w.ResponseRecorder.Write(b)
	select {
	case w.first <- struct{}{}:
	default:
	}
	return n, err
}
