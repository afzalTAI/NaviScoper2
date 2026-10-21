package main

import (
	"fmt"
	"time"

	"naviscopereborn/internal/proxy"
)

// statusText renders the two-line menu status row: state with uptime, then
// session counters. Pure formatting; AppKit refreshes it on every menu open.
func statusText(s proxy.Stats) string {
	state := "Running"
	if s.Paused {
		state = "Paused — forwarding without rules"
	}
	d := (time.Duration(s.UptimeSeconds) * time.Second).Truncate(time.Minute)
	uptime := "0m"
	if d >= time.Hour {
		uptime = fmt.Sprintf("%dh%dm", int(d.Hours()), int(d.Minutes())%60)
	} else if d > 0 {
		uptime = fmt.Sprintf("%dm", int(d.Minutes()))
	}
	return fmt.Sprintf("%s · up %s\n%d HTTP · %d CONNECT · %d blocked · %d tunnels",
		state, uptime, s.HTTPRequests, s.ConnectRequests, s.Blocked, s.ActiveTunnels)
}
