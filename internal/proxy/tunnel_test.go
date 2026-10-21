package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func tcpFixture(t *testing.T, fn func(net.Conn)) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _ = c.SetDeadline(time.Now().Add(3 * time.Second)); fn(c) }()
		}
	}()
	t.Cleanup(func() { ln.Close(); <-done })
	return ln
}
func connectClient(t *testing.T, server, target, payload string) (net.Conn, *bufio.Reader, *http.Response) {
	t.Helper()
	c, err := net.DialTimeout("tcp", strings.TrimPrefix(server, "http://"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	_, err = fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n%s", target, target, payload)
	if err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(c)
	res, err := http.ReadResponse(reader, &http.Request{Method: "CONNECT"})
	if err != nil {
		t.Fatal(err)
	}
	return c, reader, res
}
func fixtureConfig(ln net.Listener) Config {
	cfg := DefaultConfig()
	_, s, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(s)
	cfg.ConnectPorts = []int{port}
	return cfg
}

func TestCONNECTBufferedBytesAndClientHalfClose(t *testing.T) {
	upstream := tcpFixture(t, func(c net.Conn) {
		b, err := io.ReadAll(c)
		if err == nil {
			_, _ = c.Write(append([]byte("reply:"), b...))
		}
	})
	_, server, _ := newTestProxy(t, fixtureConfig(upstream))
	c, reader, res := connectClient(t, server.URL, upstream.Addr().String(), "buffered")
	if res.StatusCode != 200 {
		t.Fatalf("status %d", res.StatusCode)
	}
	if err := c.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(reader)
	if err != nil || string(got) != "reply:buffered" {
		t.Fatalf("%q %v", got, err)
	}
}

func TestCONNECTUpstreamHalfClose(t *testing.T) {
	got := make(chan string, 1)
	upstream := tcpFixture(t, func(c net.Conn) {
		_, _ = io.WriteString(c, "greeting")
		_ = c.(*net.TCPConn).CloseWrite()
		b, _ := io.ReadAll(c)
		got <- string(b)
	})
	_, server, _ := newTestProxy(t, fixtureConfig(upstream))
	c, reader, res := connectClient(t, server.URL, upstream.Addr().String(), "")
	if res.StatusCode != 200 {
		t.Fatalf("status %d", res.StatusCode)
	}
	greeting, err := io.ReadAll(reader)
	if err != nil || string(greeting) != "greeting" {
		t.Fatalf("%q %v", greeting, err)
	}
	_, _ = io.WriteString(c, "after EOF")
	_ = c.(*net.TCPConn).CloseWrite()
	select {
	case b := <-got:
		if b != "after EOF" {
			t.Fatalf("%q", b)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("upstream did not drain")
	}
}

func TestCONNECTTLSRemainsEndToEnd(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Cookie") != "secret=1" {
			t.Error("TLS cookie modified")
		}
		_, _ = io.WriteString(w, "encrypted response")
	}))
	defer upstream.Close()
	address := strings.TrimPrefix(upstream.URL, "https://")
	_, portString, _ := net.SplitHostPort(address)
	port, _ := strconv.Atoi(portString)
	cfg := DefaultConfig()
	cfg.ConnectPorts = []int{port}
	cfg.StripRequestCookies = true
	_, server, client := newTestProxy(t, cfg)
	// Trust only this local fixture's certificate; never disable verification.
	client.Transport.(*http.Transport).TLSClientConfig = &tls.Config{RootCAs: upstream.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs}
	req, _ := http.NewRequest("GET", upstream.URL, nil)
	req.Header.Set("Cookie", "secret=1")
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	if string(b) != "encrypted response" {
		t.Fatalf("%q via %s", b, server.URL)
	}
}

func TestCONNECTRejectsTargets(t *testing.T) {
	_, server, _ := newTestProxy(t, DefaultConfig())
	for _, target := range []string{"example.com:80", "example.com:0", "example.com:65536", "example.com:abc", "user@example.com:443", "example.com"} {
		t.Run(target, func(t *testing.T) {
			_, _, res := connectClient(t, server.URL, target, "")
			defer res.Body.Close()
			if res.StatusCode != 400 && res.StatusCode != 403 {
				t.Fatalf("status %d", res.StatusCode)
			}
		})
	}
	cfg := DefaultConfig()
	cfg.DenyDomains = []string{"example.com"}
	_, server, _ = newTestProxy(t, cfg)
	_, _, res := connectClient(t, server.URL, "sub.example.com:443", "")
	defer res.Body.Close()
	if res.StatusCode != 403 {
		t.Fatalf("status %d", res.StatusCode)
	}
}

func TestCONNECTDeadlineAndClose(t *testing.T) {
	for _, mode := range []string{"deadline", "close"} {
		t.Run(mode, func(t *testing.T) {
			upstream := tcpFixture(t, func(c net.Conn) { _, _ = io.Copy(c, c) })
			cfg := fixtureConfig(upstream)
			if mode == "deadline" {
				cfg.TunnelTimeout = 50 * time.Millisecond
			}
			p, server, _ := newTestProxy(t, cfg)
			c, reader, res := connectClient(t, server.URL, upstream.Addr().String(), "")
			if res.StatusCode != 200 {
				t.Fatalf("status %d", res.StatusCode)
			}
			if mode == "close" {
				p.Close()
			}
			_, err := reader.ReadByte()
			if err == nil {
				t.Fatal("tunnel remained open")
			}
			if e, ok := err.(net.Error); ok && e.Timeout() {
				t.Fatal("test client timed out; proxy did not close tunnel")
			}
			_ = c.Close()
		})
	}
}

func TestServeCancellationClosesTunnelAndListener(t *testing.T) {
	upstream := tcpFixture(t, func(c net.Conn) { _, _ = io.Copy(c, c) })
	cfg := fixtureConfig(upstream)
	p, err := New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- p.Serve(ctx, ln) }()
	_, reader, res := connectClient(t, "http://"+ln.Addr().String(), upstream.Addr().String(), "")
	if res.StatusCode != 200 {
		t.Fatalf("status %d", res.StatusCode)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("shutdown hung")
	}
	if _, err := reader.ReadByte(); err == nil {
		t.Fatal("tunnel open after shutdown")
	}
	c, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
	if err == nil {
		c.Close()
		t.Fatal("listener still open")
	}
}
