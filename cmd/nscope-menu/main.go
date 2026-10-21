// nscope-menu runs the proxy with a macOS menu-bar agent (status item).
// It is a packaging of the same proxy foundation as cmd/nscope, not a
// reconstruction of the legacy Windows toolbar.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"

	"naviscopereborn/internal/cli"
	"naviscopereborn/internal/console"
	"naviscopereborn/internal/proxy"
	"naviscopereborn/internal/sysproxy"
)

// menuApp is the state the menu agent reads and mutates from AppKit actions.
type menuApp struct {
	proxy        *proxy.Proxy
	dashboardURL string
	quit         func()
	router       *sysproxy.Manager
	proxyAddr    string
}

func main() {
	ctx := cli.ParentWatchdog(cli.StopSignals())
	if err := run(ctx, os.Args[1:], os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "nscope-menu:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, output io.Writer) error {
	cfg, metadata, err := cli.ParseFlags(args, output)
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}
	if err != nil {
		return err
	}
	var logger *slog.Logger
	if metadata {
		logger = slog.New(slog.NewJSONHandler(output, nil))
	}
	p, err := proxy.New(cfg.Config, logger)
	if err != nil {
		return err
	}
	defer p.Close()
	var ui *console.Console
	if !cfg.NoUI {
		ui, err = console.New(p, cfg.UIListen)
		if err != nil {
			return err
		}
	}
	ln, err := net.Listen("tcp4", cfg.ListenAddress)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer ln.Close()
	app := &menuApp{proxy: p, router: sysproxy.New(), proxyAddr: ln.Addr().String()}
	if cfg.NoUI {
		return serveWithMenu(ctx, app, p, ui, ln, nil, output)
	}
	uiListener, err := net.Listen("tcp4", cfg.UIListen)
	if err != nil {
		return fmt.Errorf("UI listen: %w", err)
	}
	defer uiListener.Close()
	app.dashboardURL = "http://" + uiListener.Addr().String()
	fmt.Fprintln(output, "nscope listening on", ln.Addr(), "(manual browser proxy configuration required)")
	fmt.Fprintln(output, "NaviScope interface: "+app.dashboardURL)
	return serveWithMenu(ctx, app, p, ui, ln, uiListener, output)
}

// serveWithMenu runs the servers in the background and blocks in the menu
// loop until quit. The menu is the only foreground surface; stdout stays quiet.
func serveWithMenu(ctx context.Context, app *menuApp, p *proxy.Proxy, ui *console.Console, ln net.Listener, uiListener net.Listener, output io.Writer) error {
	serveCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	app.quit = cancel
	results := make(chan error, 2)
	go func() { results <- p.Serve(serveCtx, ln) }()
	if ui != nil {
		go func() { results <- ui.Serve(serveCtx, uiListener) }()
	}
	err := runMenu(serveCtx, app)
	// Restore first while the proxy still serves, then stop the servers.
	if restoreErr := app.router.Restore(); restoreErr != nil {
		err = errors.Join(err, restoreErr)
	}
	cancel()
	if uiListener != nil {
		return errors.Join(err, <-results, <-results)
	}
	return errors.Join(err, <-results)
}
