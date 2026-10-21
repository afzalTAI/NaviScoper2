package proxy

import (
	"fmt"
	"time"
)

// Policy is a new runtime control; legacy filtering algorithms are not inferred.
// Changes affect subsequent requests, not already established CONNECT tunnels.
type Policy struct {
	DenyDomains         []string `json:"denyDomains"`
	StripRequestCookies bool     `json:"stripRequestCookies"`
}

func (p *Proxy) UpdatePolicy(policy Policy) error {
	if len(policy.DenyDomains) > 1000 {
		return fmt.Errorf("use at most 1000 domain rules")
	}
	clean := Policy{DenyDomains: make([]string, 0, len(policy.DenyDomains)), StripRequestCookies: policy.StripRequestCookies}
	seen := make(map[string]bool)
	for _, rule := range policy.DenyDomains {
		host, err := normalizeHost(rule)
		if err != nil {
			return fmt.Errorf("invalid domain %q: %w", rule, err)
		}
		if !seen[host] {
			clean.DenyDomains = append(clean.DenyDomains, host)
			seen[host] = true
		}
	}
	p.policy.Store(&clean)
	return nil
}

// SetPaused suspends deny rules and cookie stripping for new requests while
// forwarding continues. Established tunnels and the CONNECT port whitelist are
// unaffected. A deliberate menu-agent control, not legacy behavior.
func (p *Proxy) SetPaused(paused bool) { p.paused.Store(paused) }
func (p *Proxy) Paused() bool          { return p.paused.Load() }

// DomainBlocked reports whether the active (unpaused) policy blocks host.
// Exported for the transparent router's DNS filter.
func (p *Proxy) DomainBlocked(host string) bool {
	return !p.Paused() && p.blocked(host)
}

func (p *Proxy) Policy() Policy {
	policy := *p.policy.Load()
	policy.DenyDomains = append([]string{}, policy.DenyDomains...)
	return policy
}

// Configuration returns a copy, including the currently active policy.
func (p *Proxy) Configuration() Config {
	cfg := p.cfg
	policy := p.Policy()
	cfg.DenyDomains = policy.DenyDomains
	cfg.StripRequestCookies = policy.StripRequestCookies
	cfg.ConnectPorts = append([]int{}, cfg.ConnectPorts...)
	return cfg
}

type Stats struct {
	Running         bool   `json:"running"`
	Paused          bool   `json:"paused"`
	UptimeSeconds   int64  `json:"uptimeSeconds"`
	HTTPRequests    uint64 `json:"httpRequests"`
	ConnectRequests uint64 `json:"connectRequests"`
	Blocked         uint64 `json:"blocked"`
	UpstreamErrors  uint64 `json:"upstreamErrors"`
	ActiveHTTP      int64  `json:"activeHTTP"`
	ActiveTunnels   int    `json:"activeTunnels"`
}

func (p *Proxy) Stats() Stats {
	p.mu.Lock()
	tunnels := len(p.tunnels)
	p.mu.Unlock()
	return Stats{Running: p.running.Load(), Paused: p.paused.Load(), UptimeSeconds: int64(time.Since(p.started).Seconds()), HTTPRequests: p.httpRequests.Load(), ConnectRequests: p.connectRequests.Load(), Blocked: p.blockedCount.Load(), UpstreamErrors: p.upstreamErrors.Load(), ActiveHTTP: p.activeHTTP.Load(), ActiveTunnels: tunnels}
}
