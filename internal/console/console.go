// Package console serves an embedded, local-only browser interface. This is a
// new design choice, independent of the legacy application's Windows toolbar.
package console

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"naviscopereborn/internal/proxy"
)

//go:embed web/*
var assets embed.FS

type Console struct {
	proxy          *proxy.Proxy
	address, token string
}

func New(p *proxy.Proxy, address string) (*Console, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("UI address must be a literal IPv4 loopback address and port")
	}
	ip := net.ParseIP(host)
	n, err := strconv.Atoi(port)
	if ip == nil || ip.To4() == nil || strings.Contains(host, ":") || !ip.IsLoopback() || err != nil || n < 1 || n > 65535 {
		return nil, fmt.Errorf("UI address must use IPv4 loopback and port 1–65535")
	}
	if address != net.JoinHostPort(ip.String(), strconv.Itoa(n)) {
		return nil, fmt.Errorf("UI address must use canonical IPv4 and port notation")
	}
	return &Console{proxy: p, address: address, token: rand.Text()}, nil
}

func (c *Console) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
	if r.Host != c.address {
		http.Error(w, "open the console at its configured loopback address", 403)
		return
	}
	origin := "http://" + c.address
	if strings.HasPrefix(r.URL.Path, "/api/") && (r.Header.Get("Sec-Fetch-Site") == "cross-site" || r.Header.Get("Origin") != "" && r.Header.Get("Origin") != origin) {
		http.Error(w, "same-origin requests required", 403)
		return
	}
	switch r.URL.Path {
	case "/api/state":
		if r.Method != "GET" {
			methodNotAllowed(w, "GET")
			return
		}
		cfg := c.proxy.Configuration()
		writeJSON(w, map[string]any{"stats": c.proxy.Stats(), "policy": c.proxy.Policy(), "config": map[string]any{
			"listenAddress": cfg.ListenAddress, "connectPorts": cfg.ConnectPorts,
			"requestTimeout": cfg.RequestTimeout.String(), "tunnelTimeout": cfg.TunnelTimeout.String(), "shutdownTimeout": cfg.ShutdownTimeout.String(),
		}})
	case "/api/policy":
		if r.Method != "PUT" {
			methodNotAllowed(w, "PUT")
			return
		}
		if r.Header.Get("Origin") != origin || subtle.ConstantTimeCompare([]byte(r.Header.Get("X-NaviScope-Token")), []byte(c.token)) != 1 {
			http.Error(w, "reload the console before saving", 403)
			return
		}
		contentType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || contentType != "application/json" {
			http.Error(w, "JSON body required", 415)
			return
		}
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
		decoder.DisallowUnknownFields()
		var update struct {
			DenyDomains         *[]string `json:"denyDomains"`
			StripRequestCookies *bool     `json:"stripRequestCookies"`
		}
		if err := decoder.Decode(&update); err != nil {
			http.Error(w, "invalid policy JSON (64 KiB maximum)", 400)
			return
		}
		if err := decoder.Decode(&struct{}{}); err != io.EOF {
			http.Error(w, "expected one JSON object", 400)
			return
		}
		if update.DenyDomains == nil || update.StripRequestCookies == nil {
			http.Error(w, "denyDomains and stripRequestCookies are required", 400)
			return
		}
		policy := proxy.Policy{DenyDomains: *update.DenyDomains, StripRequestCookies: *update.StripRequestCookies}
		if err := c.proxy.UpdatePolicy(policy); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		writeJSON(w, c.proxy.Policy())
	case "/", "/app.js", "/style.css", "/favicon.svg":
		if r.Method != "GET" && r.Method != "HEAD" {
			methodNotAllowed(w, "GET, HEAD")
			return
		}
		file := strings.TrimPrefix(r.URL.Path, "/")
		if file == "" {
			file = "index.html"
		}
		body, err := assets.ReadFile("web/" + file)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		types := map[string]string{"index.html": "text/html; charset=utf-8", "app.js": "text/javascript; charset=utf-8", "style.css": "text/css; charset=utf-8", "favicon.svg": "image/svg+xml"}
		w.Header().Set("Content-Type", types[file])
		if file == "index.html" {
			body = []byte(strings.ReplaceAll(string(body), "{{TOKEN}}", html.EscapeString(c.token)))
		}
		if r.Method == "GET" {
			_, _ = w.Write(body)
		}
	default:
		http.NotFound(w, r)
	}
}
func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}
func methodNotAllowed(w http.ResponseWriter, allow string) {
	w.Header().Set("Allow", allow)
	http.Error(w, "method not allowed", 405)
}

// Serve owns the dedicated console listener, never the proxy listener.
func (c *Console) Serve(ctx context.Context, ln net.Listener) error {
	server := &http.Server{Handler: c, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10, ErrorLog: log.New(io.Discard, "", 0)}
	done := make(chan error, 1)
	go func() { done <- server.Serve(ln) }()
	var serveErr error
	select {
	case <-ctx.Done():
	case serveErr = <-done:
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		_ = server.Close()
		return err
	}
	if errors.Is(serveErr, http.ErrServerClosed) {
		return nil
	}
	return serveErr
}
