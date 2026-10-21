// nscope is a new standard-library implementation, not the legacy executable.
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
)

func main() {
	ctx := cli.ParentWatchdog(cli.StopSignals())
	if err := run(ctx, os.Args[1:], os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "nscope:", err)
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
	if cfg.TUN {
		stopTunnel, err := startTunnel(ctx, cfg, p, output)
		if err != nil {
			return err
		}
		defer stopTunnel()
	}
	if cfg.NoUI {
		fmt.Fprintln(output, "nscope listening on", ln.Addr(), "(manual browser proxy configuration required)")
		return p.Serve(ctx, ln)
	}
	uiListener, err := net.Listen("tcp4", cfg.UIListen)
	if err != nil {
		return fmt.Errorf("UI listen: %w", err)
	}
	defer uiListener.Close()
	fmt.Fprintln(output, "nscope listening on", ln.Addr(), "(manual browser proxy configuration required)")
	fmt.Fprintln(output, "NaviScope interface: http://"+uiListener.Addr().String())
	serveCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan error, 2)
	go func() { results <- p.Serve(serveCtx, ln) }()
	go func() { results <- ui.Serve(serveCtx, uiListener) }()
	first := <-results
	cancel()
	return errors.Join(first, <-results)
}
