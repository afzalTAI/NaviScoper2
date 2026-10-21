package main

import (
	"strings"
	"testing"
	"time"

	"naviscopereborn/internal/proxy"
)

func TestStatusTextShowsStateAndCounters(t *testing.T) {
	s := proxy.Stats{UptimeSeconds: int64(75 * time.Minute.Seconds()), HTTPRequests: 12, ConnectRequests: 3, Blocked: 2, ActiveTunnels: 1}
	got := statusText(s)
	for _, want := range []string{"Running · up 1h15m", "12 HTTP · 3 CONNECT · 2 blocked · 1 tunnels"} {
		if !strings.Contains(got, want) {
			t.Fatalf("status %q missing %q", got, want)
		}
	}
	s.Paused = true
	if got = statusText(s); !strings.Contains(got, "Paused — forwarding without rules") {
		t.Fatalf("paused state not shown: %q", got)
	}
}

func TestStatusTextUptimeShapes(t *testing.T) {
	for _, tc := range []struct {
		secs int64
		want string
	}{{0, "up 0m"}, {59, "up 0m"}, {60, "up 1m"}, {3661, "up 1h1m"}, {86400 + 7200, "up 26h0m"}} {
		if got := statusText(proxy.Stats{UptimeSeconds: tc.secs}); !strings.Contains(got, tc.want) {
			t.Fatalf("uptime %ds: %q missing %q", tc.secs, got, tc.want)
		}
	}
}
