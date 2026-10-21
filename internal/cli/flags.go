// Package cli holds flag parsing and process-lifecycle helpers shared by the
// nscope commands. It is deliberately dependency-free standard library.
package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"naviscopereborn/internal/proxy"
)

// Options is the shared command-line configuration for the proxy commands.
type Options struct {
	proxy.Config
	UIListen string
	NoUI     bool
}

// ParseFlags validates the shared flag set. The bool result reports metadata
// logging. ParseFlags performs no I/O beyond flag errors on output.
func ParseFlags(args []string, output io.Writer) (Options, bool, error) {
	cfg := Options{Config: proxy.DefaultConfig(), UIListen: "127.0.0.1:8082"}
	fs := flag.NewFlagSet("nscope", flag.ContinueOnError)
	fs.SetOutput(output)
	fs.StringVar(&cfg.UIListen, "ui-listen", cfg.UIListen, "local browser interface address")
	fs.BoolVar(&cfg.NoUI, "no-ui", false, "run without the browser interface")
	fs.StringVar(&cfg.ListenAddress, "listen", cfg.ListenAddress, "literal IPv4 loopback address and port")
	deny := fs.String("deny", "", "comma-separated blocked domains/IPs (domains include subdomains)")
	ports := fs.String("connect-ports", "443", "comma-separated permitted CONNECT destination ports")
	fs.BoolVar(&cfg.StripRequestCookies, "strip-request-cookies", false, "remove outbound HTTP Cookie headers; HTTPS remains encrypted")
	metadata := fs.Bool("metadata-log", false, "log operation and target host/port only")
	fs.DurationVar(&cfg.RequestTimeout, "request-timeout", cfg.RequestTimeout, "total HTTP request/response timeout")
	fs.DurationVar(&cfg.TunnelTimeout, "tunnel-timeout", cfg.TunnelTimeout, "maximum CONNECT tunnel lifetime")
	fs.StringVar(&cfg.SecureDNS, "secure-dns", "", "DNS-over-HTTPS preset (cloudflare, google, quad9, opendns) or https://IP/dns-query URL; empty uses the system resolver")
	fs.StringVar(&cfg.UpstreamURL, "upstream", "", "tunnel all outbound traffic through socks5://[user:pass@]host:port or http://host:port")
	if err := fs.Parse(args); err != nil {
		return cfg, false, err
	}
	if fs.NArg() != 0 {
		return cfg, false, fmt.Errorf("unexpected positional arguments")
	}
	if *deny != "" {
		for _, h := range strings.Split(*deny, ",") {
			cfg.DenyDomains = append(cfg.DenyDomains, strings.TrimSpace(h))
		}
	}
	cfg.ConnectPorts = nil
	for _, s := range strings.Split(*ports, ",") {
		s = strings.TrimSpace(s)
		for _, c := range s {
			if c < '0' || c > '9' {
				return cfg, false, fmt.Errorf("CONNECT ports must be numeric")
			}
		}
		port, err := strconv.Atoi(s)
		if err != nil {
			return cfg, false, fmt.Errorf("CONNECT ports must be numeric")
		}
		cfg.ConnectPorts = append(cfg.ConnectPorts, port)
	}
	return cfg, *metadata, nil
}

// StopSignals returns a context canceled by the usual stop signals. Default
// signal disposition is restored on the first stop so a second Ctrl-C
// force-terminates instead of waiting out the graceful drain.
func StopSignals() context.Context {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		<-ctx.Done()
		stop()
	}()
	return ctx
}

// ParentWatchdog returns ctx wrapped so that, when running as a `go run`
// build artifact, the process shuts down if its parent is force-killed
// (macOS and Windows have no PDEATHSIG). Installed binaries pass through.
func ParentWatchdog(ctx context.Context) context.Context {
	exe, err := os.Executable()
	if err != nil || !GoRunArtifact(exe) {
		return ctx
	}
	wrapped, cancel := context.WithCancel(ctx)
	ticker := time.NewTicker(500 * time.Millisecond)
	go func() {
		defer ticker.Stop()
		WatchParent(wrapped, cancel, os.Getppid, ticker.C)
	}()
	return wrapped
}

// GoRunArtifact reports whether the executable lives in a `go run` build
// directory: the exact "go-build" cache dir or a "go-buildNNN" (digits only)
// temp component. Path inspection is the only portable signal; installed
// binaries never match.
func GoRunArtifact(exe string) bool {
	for _, part := range strings.Split(exe, string(os.PathSeparator)) {
		if part == "go-build" {
			return true
		}
		suffix, ok := strings.CutPrefix(part, "go-build")
		if ok && suffix != "" && strings.Trim(suffix, "0123456789") == "" {
			return true
		}
	}
	return false
}

// WatchParent cancels the run when the original parent exits and the process
// is reparented. Skipped when already detached at startup (ppid 1).
func WatchParent(ctx context.Context, cancel context.CancelFunc, getppid func() int, tick <-chan time.Time) {
	origin := getppid()
	if origin <= 1 {
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick:
			if getppid() != origin {
				cancel()
				return
			}
		}
	}
}
