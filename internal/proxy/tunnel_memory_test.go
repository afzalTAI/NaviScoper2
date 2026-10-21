package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type hijackWriter struct {
	*httptest.ResponseRecorder
	conn net.Conn
	rw   *bufio.ReadWriter
}

func (w hijackWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) { return w.conn, w.rw, nil }

func TestCONNECTInMemoryBufferedTrafficAndCleanup(t *testing.T) {
	for _, mode := range []string{"close", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.TunnelTimeout = 100 * time.Millisecond
			p, err := New(cfg, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			client, proxyClient := net.Pipe()
			proxyUpstream, upstream := net.Pipe()
			defer client.Close()
			defer proxyClient.Close()
			defer proxyUpstream.Close()
			defer upstream.Close()
			_ = client.SetDeadline(time.Now().Add(2 * time.Second))
			_ = upstream.SetDeadline(time.Now().Add(2 * time.Second))
			p.transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
				if address != "example.com:443" {
					t.Errorf("dial target: %s", address)
				}
				return proxyUpstream, nil
			}
			fixtureDone := make(chan struct{})
			go func() {
				defer close(fixtureDone)
				b := make([]byte, 8)
				if _, err := io.ReadFull(upstream, b); err == nil {
					_, _ = upstream.Write(append([]byte("echo:"), b...))
				}
				_, _ = io.Copy(io.Discard, upstream)
			}()
			// Model bytes read ahead by net/http before Hijack: they precede socket data.
			rw := bufio.NewReadWriter(bufio.NewReader(io.MultiReader(strings.NewReader("buffered"), proxyClient)), bufio.NewWriter(proxyClient))
			w := hijackWriter{httptest.NewRecorder(), proxyClient, rw}
			r := httptest.NewRequest("CONNECT", "example.com:443", nil)
			r.URL.Scheme = ""
			r.RequestURI = "example.com:443"
			done := make(chan struct{})
			go func() { defer close(done); p.ServeHTTP(w, r) }()
			reader := bufio.NewReader(client)
			res, err := http.ReadResponse(reader, &http.Request{Method: "CONNECT"})
			if err != nil {
				t.Fatal(err)
			}
			if res.StatusCode != 200 {
				t.Fatalf("status %d", res.StatusCode)
			}
			b := make([]byte, len("echo:buffered"))
			if _, err = io.ReadFull(reader, b); err != nil || string(b) != "echo:buffered" {
				t.Fatalf("%q %v", b, err)
			}
			if mode == "close" {
				p.Close()
			}
			if _, err := reader.ReadByte(); err == nil {
				t.Fatal("connection remained open")
			}
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("handler leaked")
			}
			select {
			case <-fixtureDone:
			case <-time.After(2 * time.Second):
				t.Fatal("upstream leaked")
			}
			p.mu.Lock()
			active := len(p.tunnels)
			p.mu.Unlock()
			if active != 0 {
				t.Fatal("tunnel not unregistered")
			}
		})
	}
}

func TestCONNECTInMemoryFailureAndShutdownDialCancellation(t *testing.T) {
	for _, mode := range []string{"failure", "shutdown"} {
		t.Run(mode, func(t *testing.T) {
			p, err := New(DefaultConfig(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			started := make(chan struct{})
			p.transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
				close(started)
				if mode == "shutdown" {
					<-ctx.Done()
				}
				return nil, fmt.Errorf("sensitive upstream error")
			}
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			rec := httptest.NewRecorder()
			w := hijackWriter{rec, a, bufio.NewReadWriter(bufio.NewReader(a), bufio.NewWriter(a))}
			r := httptest.NewRequest("CONNECT", "example.com:443", nil)
			r.URL.Scheme = ""
			r.RequestURI = "example.com:443"
			done := make(chan struct{})
			go func() { defer close(done); p.ServeHTTP(w, r) }()
			select {
			case <-started:
			case <-time.After(time.Second):
				t.Fatal("dial did not start")
			}
			if mode == "shutdown" {
				p.Close()
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("dial not canceled")
			}
			if rec.Code != 502 || strings.Contains(rec.Body.String(), "sensitive") {
				t.Fatalf("%d %q", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestCONNECTPolicyAndValidationWithoutDial(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DenyDomains = []string{"blocked.test"}
	p, err := New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	p.transport.DialContext = func(context.Context, string, string) (net.Conn, error) {
		t.Error("invalid target reached dialer")
		return nil, fmt.Errorf("unexpected dial")
	}
	for _, tc := range []struct {
		authority string
		status    int
	}{
		{"blocked.test:443", 403}, {"sub.blocked.test:443", 403},
		{"example.com:80", 403}, {"example.com:0", 400}, {"example.com:65536", 400},
		{"example.com:abc", 400}, {"example.com", 400}, {"user@example.com:443", 400},
		{"example.com:443", 501}, // recorder does not support hijacking
	} {
		t.Run(tc.authority, func(t *testing.T) {
			r := httptest.NewRequest("CONNECT", "example.com:443", nil)
			r.RequestURI = tc.authority
			r.URL.Host = tc.authority
			w := httptest.NewRecorder()
			p.ServeHTTP(w, r)
			if w.Code != tc.status {
				t.Fatalf("status %d, want %d", w.Code, tc.status)
			}
		})
	}
	r := httptest.NewRequest("CONNECT", "example.com:443", strings.NewReader("unexpected body"))
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	if w.Code != 400 {
		t.Fatalf("accepted CONNECT body: %d", w.Code)
	}
}
