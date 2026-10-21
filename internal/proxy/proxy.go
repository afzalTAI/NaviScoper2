// Package proxy implements a new portable proxy foundation. Legacy evidence is
// documented in reference/code-reference.md; this is not recovered source.
package proxy

import (
	"context"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"naviscopereborn/internal/outbound"
)

type Proxy struct {
	policy          atomic.Pointer[Policy]
	started         time.Time
	running         atomic.Bool
	httpRequests    atomic.Uint64
	connectRequests atomic.Uint64
	blockedCount    atomic.Uint64
	upstreamErrors  atomic.Uint64
	activeHTTP      atomic.Int64
	paused          atomic.Bool
	cfg             Config
	logger          *slog.Logger
	transport       *http.Transport
	forward         *httputil.ReverseProxy
	tunnelCtx       context.Context
	cancelTunnels   context.CancelFunc
	mu              sync.Mutex
	closing         bool
	tunnels         map[net.Conn]net.Conn
	tunnelWG        sync.WaitGroup
}

func New(cfg Config, logger *slog.Logger) (*Proxy, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	cfg.DenyDomains = append([]string(nil), cfg.DenyDomains...)
	for i, h := range cfg.DenyDomains {
		cfg.DenyDomains[i], _ = normalizeHost(h)
	}
	cfg.ConnectPorts = append([]int(nil), cfg.ConnectPorts...)
	ctx, cancel := context.WithCancel(context.Background())
	p := &Proxy{cfg: cfg, logger: logger, tunnelCtx: ctx, cancelTunnels: cancel, tunnels: make(map[net.Conn]net.Conn)}
	p.started = time.Now()
	if err := p.UpdatePolicy(Policy{DenyDomains: cfg.DenyDomains, StripRequestCookies: cfg.StripRequestCookies}); err != nil {
		cancel()
		return nil, err
	}
	dial, err := outbound.Dial(outbound.Options{SecureDNS: cfg.SecureDNS, UpstreamURL: cfg.UpstreamURL})
	if err != nil {
		cancel()
		return nil, err
	}
	// New design: no environment proxy (an upstream is an explicit opt-in),
	// finite waits, bounded idle pool, and no transparent decompression or
	// TLS interception.
	p.transport = &http.Transport{
		Proxy: nil, DialContext: dial,
		MaxIdleConns: 100, MaxIdleConnsPerHost: 8, IdleConnTimeout: 90 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second, ExpectContinueTimeout: time.Second,
		DisableCompression: true, MaxResponseHeaderBytes: 1 << 20,
	}
	p.forward = &httputil.ReverseProxy{
		Transport: p.transport, FlushInterval: -1, ErrorLog: log.New(io.Discard, "", 0),
		Rewrite: func(r *httputil.ProxyRequest) {
			r.Out.Host = r.In.URL.Host
			r.Out.RequestURI = ""
			// An explicit proxy forwards query bytes without interpreting them.
			r.Out.URL.RawQuery = r.In.URL.RawQuery
			r.Out.Header.Del("Proxy-Authorization")
			r.Out.Header.Del("Proxy-Authenticate")
			// Paused filtering forwards cookies untouched by deliberate choice.
			if !p.paused.Load() && p.policy.Load().StripRequestCookies {
				r.Out.Header.Del("Cookie")
			}
		},
		ModifyResponse: func(r *http.Response) error {
			if r.StatusCode == http.StatusSwitchingProtocols {
				return fmt.Errorf("protocol upgrades unsupported")
			}
			r.Header.Del("Proxy-Authenticate")
			r.Header.Del("Proxy-Authorization")
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			p.upstreamErrors.Add(1)
			status := http.StatusBadGateway
			if r.Context().Err() == context.DeadlineExceeded {
				status = http.StatusGatewayTimeout
			}
			http.Error(w, http.StatusText(status), status)
		},
	}
	return p, nil
}

func (p *Proxy) blocked(host string) bool {
	// Paused filtering suspends deny rules for new requests; the CONNECT port
	// whitelist below stays enforced because it is a boundary, not a filter.
	if p.paused.Load() {
		return false
	}
	host, _ = normalizeHost(host)
	for _, rule := range p.policy.Load().DenyDomains {
		if host == rule || net.ParseIP(rule) == nil && strings.HasSuffix(host, "."+rule) {
			return true
		}
	}
	return false
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.connectRequests.Add(1)
		p.connect(w, r)
		return
	}
	p.httpRequests.Add(1)
	if r.URL.Scheme != "http" || r.URL.Host == "" || r.URL.User != nil || r.URL.Fragment != "" || r.URL.Opaque != "" {
		http.Error(w, "expected absolute http:// URL; use CONNECT for HTTPS", 400)
		return
	}
	host, port, err := target(r.URL.Host, false)
	if err != nil {
		http.Error(w, "invalid HTTP target", 400)
		return
	}
	if p.blocked(host) {
		p.blockedCount.Add(1)
		http.Error(w, "target blocked", 403)
		return
	}
	if r.Header.Get("Upgrade") != "" {
		http.Error(w, "protocol upgrades unsupported", 501)
		return
	}
	if p.logger != nil {
		p.logger.Info("proxy request", "operation", "http", "host", host, "port", port)
	}
	p.activeHTTP.Add(1)
	defer p.activeHTTP.Add(-1)
	ctx, cancel := context.WithTimeout(r.Context(), p.cfg.RequestTimeout)
	defer cancel()
	p.forward.ServeHTTP(w, r.WithContext(ctx))
}

// Close stops new tunnels, cancels pending tunnel dials, and waits for both copy
// directions to exit. http.Server.Shutdown alone does not close hijacked sockets.
func (p *Proxy) Close() {
	p.mu.Lock()
	p.closing = true
	p.cancelTunnels()
	for client, upstream := range p.tunnels {
		_ = client.Close()
		_ = upstream.Close()
	}
	p.mu.Unlock()
	p.tunnelWG.Wait()
	p.transport.CloseIdleConnections()
}

// Serve owns the listener. Cancellation immediately closes tunnels and lets HTTP
// requests drain for ShutdownTimeout, then cancels and closes remaining requests.
func (p *Proxy) Serve(ctx context.Context, ln net.Listener) error {
	addr, ok := ln.Addr().(*net.TCPAddr)
	if !ok || !addr.IP.IsLoopback() || addr.IP.To4() == nil {
		ln.Close()
		return fmt.Errorf("listener must use IPv4 loopback")
	}
	p.running.Store(true)
	defer p.running.Store(false)
	base, cancel := context.WithCancel(context.Background())
	defer cancel()
	server := &http.Server{Handler: p, ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout: p.cfg.RequestTimeout, WriteTimeout: p.cfg.RequestTimeout, IdleTimeout: 60 * time.Second,
		MaxHeaderBytes: 1 << 20, BaseContext: func(net.Listener) context.Context { return base },
		ErrorLog: log.New(io.Discard, "", 0),
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(ln) }()
	var serveErr error
	select {
	case <-ctx.Done():
	case serveErr = <-done:
	}
	p.Close()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), p.cfg.ShutdownTimeout)
	defer shutdownCancel()
	err := server.Shutdown(shutdownCtx)
	cancel()
	if err != nil {
		_ = server.Close()
	}
	p.transport.CloseIdleConnections()
	if serveErr != nil && serveErr != http.ErrServerClosed {
		return serveErr
	}
	return err
}
