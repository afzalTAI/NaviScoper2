package doh

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestBootstrapDialerFallsBackAndRotates(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split: %v", err)
	}

	// 127.0.0.2 is loopback with nothing bound to this port (and on some
	// systems not configured at all), so the first candidate fails and the
	// dialer must try the next one. A short timeout keeps the test quick.
	d := &bootstrapDialer{
		addrs: []string{"127.0.0.2", "127.0.0.1"},
		port:  port,
		net:   net.Dialer{Timeout: 300 * time.Millisecond},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for attempt := range 2 {
		conn, err := d.DialContext(ctx, "tcp", "cloudflare-dns.com:443")
		if err != nil {
			t.Fatalf("attempt %d: dial: %v", attempt, err)
		}
		host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
		if host != "127.0.0.1" {
			t.Fatalf("attempt %d: connected to %s, want 127.0.0.1", attempt, host)
		}
		conn.Close()
	}
	if got := d.next.Load(); got != 2 {
		t.Fatalf("rotation counter = %d, want 2", got)
	}
}

func TestBootstrapDialerWithoutAddresses(t *testing.T) {
	d := &bootstrapDialer{port: "443"}
	_, err := d.DialContext(context.Background(), "tcp", "dns.google:443")
	if err == nil || !strings.Contains(err.Error(), "no bootstrap addresses") {
		t.Fatalf("err = %v, want no bootstrap addresses", err)
	}
}

func TestBootstrapDialerHonorsContext(t *testing.T) {
	d := &bootstrapDialer{addrs: []string{"192.0.2.1"}, port: "443", net: net.Dialer{Timeout: dialTimeout}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := d.DialContext(ctx, "tcp", "dns.google:443"); err == nil {
		t.Fatal("expected context error")
	}
}

func TestNewConfiguresTLSAndBootstrap(t *testing.T) {
	r := New(Presets()["cloudflare"])
	transport, ok := r.client.Load().Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type = %T", r.client.Load().Transport)
	}
	if got := transport.TLSClientConfig.ServerName; got != "cloudflare-dns.com" {
		t.Fatalf("ServerName = %q, want the endpoint host", got)
	}
	if transport.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		t.Fatalf("MinVersion = %#x", transport.TLSClientConfig.MinVersion)
	}
	if transport.DialContext == nil {
		t.Fatal("transport must dial through the bootstrap dialer")
	}
	if r.client.Load().Timeout != requestTimeout {
		t.Fatalf("client timeout = %v", r.client.Load().Timeout)
	}
}

func TestEndpointTargetAndBootstrapFiltering(t *testing.T) {
	name, port := endpointTarget("https://dns.google/dns-query")
	if name != "dns.google" || port != "443" {
		t.Fatalf("got %q %q", name, port)
	}
	if name, port := endpointTarget("https://127.0.0.1:8443/dns-query"); name != "127.0.0.1" || port != "8443" {
		t.Fatalf("got %q %q", name, port)
	}
	if name, port := endpointTarget("://bad"); name != "" || port != "443" {
		t.Fatalf("got %q %q", name, port)
	}

	// Host names are rejected: dialing one would need the system resolver.
	got := bootstrapAddrs(Preset{Bootstrap: []string{"resolver.example", "1.1.1.1", "2606:4700:4700::1111"}}, "dns.example")
	if len(got) != 2 || got[0] != "1.1.1.1" || got[1] != "2606:4700:4700::1111" {
		t.Fatalf("bootstrapAddrs = %v", got)
	}
	// An endpoint given as an IP literal is its own bootstrap.
	if got := bootstrapAddrs(Preset{}, "9.9.9.9"); len(got) != 1 || got[0] != "9.9.9.9" {
		t.Fatalf("bootstrapAddrs = %v", got)
	}
	if got := bootstrapAddrs(Preset{}, "dns.example"); len(got) != 0 {
		t.Fatalf("bootstrapAddrs = %v, want empty", got)
	}
}

func TestNormalizeHost(t *testing.T) {
	cases := map[string]string{
		"Example.COM.":  "example.com",
		" example.com ": "example.com",
		"[::1]":         "::1",
	}
	for in, want := range cases {
		got, err := normalizeHost(in)
		if err != nil || got != want {
			t.Errorf("normalizeHost(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", ".", "  "} {
		if _, err := normalizeHost(in); err == nil {
			t.Errorf("normalizeHost(%q): expected error", in)
		}
	}
}
