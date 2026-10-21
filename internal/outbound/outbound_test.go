package outbound

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

func TestOptionsValidation(t *testing.T) {
	bad := []Options{
		{SecureDNS: "notapreset"},
		{SecureDNS: "http://1.1.1.1/dns-query"},
		{SecureDNS: "https://dns.example.net/dns-query"},
		{UpstreamURL: "127.0.0.1:1080"},
		{UpstreamURL: "ftp://127.0.0.1:1080"},
	}
	for i, o := range bad {
		if _, err := Dial(o); err == nil {
			t.Fatalf("bad[%d] accepted", i)
		}
	}
	for _, o := range []Options{{}, {SecureDNS: "cloudflare"}, {UpstreamURL: "socks5://127.0.0.1:1080"}} {
		if _, err := Dial(o); err != nil {
			t.Fatalf("good %+v rejected: %v", o, err)
		}
	}
}

// The chain must honor the upstream provider: dialing any address speaks
// CONNECT to the configured proxy, not to the target.
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
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
		conn.Close()
		saw <- strings.TrimSpace(line)
	}()
	dial, err := Dial(Options{UpstreamURL: "http://" + ln.Addr().String()})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := dial(ctx, "tcp", "target.example:443")
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
