package proxy

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

func TestConfigValidatesRoutingFields(t *testing.T) {
	base := DefaultConfig()
	good := []Config{
		base,
		with(base, "SecureDNS", "cloudflare"),
		with(base, "SecureDNS", "https://1.1.1.1/dns-query"),
		with(base, "UpstreamURL", "socks5://127.0.0.1:1080"),
		with(base, "UpstreamURL", "http://user:pass@127.0.0.1:3128"),
	}
	bad := []Config{
		with(base, "SecureDNS", "notapreset"),
		with(base, "SecureDNS", "http://1.1.1.1/dns-query"),
		with(base, "SecureDNS", "https://dns.example.net/dns-query"),
		with(base, "UpstreamURL", "127.0.0.1:1080"),
		with(base, "UpstreamURL", "ftp://127.0.0.1:1080"),
	}
	for i, cfg := range good {
		if err := cfg.validate(); err != nil {
			t.Fatalf("good[%d] rejected: %v", i, err)
		}
	}
	for i, cfg := range bad {
		if err := cfg.validate(); err == nil {
			t.Fatalf("bad[%d] accepted", i)
		}
	}
}

// with returns cfg with one string field overridden; only routing fields are
// used, keeping the table readable.
func with(base Config, field, value string) Config {
	switch field {
	case "SecureDNS":
		base.SecureDNS = value
	case "UpstreamURL":
		base.UpstreamURL = value
	}
	return base
}

// The proxy's outbound dialer must honor the upstream chain: dialing any
// address speaks CONNECT to the configured provider, not to the target.
func TestDialChainUsesUpstream(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	saw := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		line, _ := bufio.NewReader(conn).ReadString('\n')
		conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
		conn.Close()
		saw <- strings.TrimSpace(line)
	}()
	cfg := DefaultConfig()
	cfg.UpstreamURL = "http://" + ln.Addr().String()
	p, err := New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := p.transport.DialContext(ctx, "tcp", "target.example:443")
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	select {
	case line := <-saw:
		if line != "CONNECT target.example:443 HTTP/1.1" {
			t.Fatalf("upstream saw %q", line)
		}
	default:
		t.Fatal("upstream never saw the CONNECT")
	}
}
