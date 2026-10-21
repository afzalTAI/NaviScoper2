package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"naviscopereborn/internal/proxy"
)

func TestParseConfig(t *testing.T) {
	cfg, metadata, err := ParseFlags([]string{"-listen", "127.0.0.2:8082", "-deny", "example.com,ads.example.org", "-connect-ports", "443,8443", "-strip-request-cookies", "-metadata-log", "-request-timeout", "30s"}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ListenAddress != "127.0.0.2:8082" || len(cfg.DenyDomains) != 2 || len(cfg.ConnectPorts) != 2 || !cfg.StripRequestCookies || !metadata || cfg.RequestTimeout != 30*time.Second {
		t.Fatalf("bad config: %+v", cfg)
	}
}

func TestFrontendFlags(t *testing.T) {
	cfg, _, err := ParseFlags([]string{"-ui-listen", "127.0.0.1:8083", "-no-ui"}, &bytes.Buffer{})
	if err != nil || cfg.UIListen != "127.0.0.1:8083" || !cfg.NoUI {
		t.Fatalf("frontend flags: %+v %v", cfg, err)
	}
}

func TestRoutingFlags(t *testing.T) {
	cfg, _, err := ParseFlags([]string{"-secure-dns", "cloudflare", "-upstream", "socks5://user:pass@127.0.0.1:1080"}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SecureDNS != "cloudflare" || cfg.UpstreamURL != "socks5://user:pass@127.0.0.1:1080" {
		t.Fatalf("routing flags: %+v", cfg.Config)
	}
}

func TestRejectsInvalidFlags(t *testing.T) {
	for _, args := range [][]string{{"-connect-ports", "no"}, {"-connect-ports", ""}, {"-connect-ports", "443,"}, {"unexpected"}} {
		var output bytes.Buffer
		if _, _, err := ParseFlags(args, &output); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
}

func TestHelpTextListsDefaults(t *testing.T) {
	var output bytes.Buffer
	if _, _, err := ParseFlags([]string{"-help"}, &output); err != nil && !strings.Contains(err.Error(), "flag: help requested") {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "127.0.0.1:8081") {
		t.Fatal("help missing default listen address")
	}
}

// Defaults must stay aligned with the approved proxy foundation.
func TestDefaultsMatchProxyPackage(t *testing.T) {
	cfg, _, err := ParseFlags(nil, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	def := proxy.DefaultConfig()
	if cfg.ListenAddress != def.ListenAddress || cfg.RequestTimeout != def.RequestTimeout || cfg.TunnelTimeout != def.TunnelTimeout || cfg.ShutdownTimeout != def.ShutdownTimeout || len(cfg.ConnectPorts) != len(def.ConnectPorts) {

		t.Fatalf("cli defaults drifted: %+v", cfg.Config)
	}
}

func TestGoRunArtifactDetection(t *testing.T) {
	artifacts := []string{
		"/var/folders/8j/x/T/go-build2588970476/b001/exe/nscope",
		"/Users/afzal/Library/Caches/go-build/07/07ac0a4d3957-nscope",
	}
	for _, exe := range artifacts {
		if !GoRunArtifact(exe) {
			t.Fatalf("expected go run artifact: %s", exe)
		}
	}
	for _, exe := range []string{"/usr/local/bin/nscope", "C:\\Tools\\nscope.exe", "/tmp/go-buildtool-check"} {
		if GoRunArtifact(exe) {
			t.Fatalf("false positive on installed path: %s", exe)
		}
	}
}

func TestWatchParentCancelsOnReparent(t *testing.T) {
	ppid := make(chan int, 4)
	ppid <- 4242
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tick := make(chan time.Time)
	done := make(chan struct{})
	go func() {
		WatchParent(ctx, cancel, func() int { return <-ppid }, tick)
		close(done)
	}()
	tick <- time.Now()
	ppid <- 4242 // same parent: keep running
	select {
	case <-ctx.Done():
		t.Fatal("cancelled while parent alive")
	case <-time.After(50 * time.Millisecond):
	}
	tick <- time.Now()
	ppid <- 1 // reparented: original parent died
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("parent death did not cancel run context")
	}
	<-done
}

func TestWatchParentSkipsDetachedStart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tick := make(chan time.Time)
	done := make(chan struct{})
	go func() {
		WatchParent(ctx, cancel, func() int { return 1 }, tick)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("detached start did not return promptly")
	}
	select {
	case <-ctx.Done():
		t.Fatal("detached start must not cancel")
	default:
	}
}
