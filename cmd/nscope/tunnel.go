package main

import (
	"context"
	"fmt"
	"io"
	"naviscopereborn/internal/cli"
	"naviscopereborn/internal/doh"
	"naviscopereborn/internal/outbound"
	"naviscopereborn/internal/proxy"
	"naviscopereborn/internal/tunroute"
	"naviscopereborn/internal/tunstack"
	"net"
	"time"
)

// startTunnel brings up transparent routing: a utun device carries all IPv4
// traffic into the netstack; TCP flows ride the outbound chain, DNS is always
// DoH (the system resolver would loop into the tunnel), and other UDP is
// relayed directly. All NaviScope sockets are pinned to the physical
// interface so they bypass the tunnel. Returns a stop function; safe to call
// only behind tunroute's root check.
func startTunnel(ctx context.Context, cfg cli.Options, p *proxy.Proxy, output io.Writer) (func(), error) {
	dev, err := tunroute.Start()
	if err != nil {
		return nil, err
	}
	iface, err := tunroute.DefaultInterface()
	if err != nil {
		dev.Close()
		return nil, err
	}
	bind := tunroute.BindControl(iface)
	dial, err := outbound.Dial(outbound.Options{SecureDNS: cfg.SecureDNS, UpstreamURL: cfg.UpstreamURL, BindControl: bind})
	if err != nil {
		dev.Close()
		return nil, err
	}
	// In the tunnel, DNS must be DoH; default to Cloudflare when unset.
	spec := cfg.SecureDNS
	if spec == "" {
		spec = "cloudflare"
	}
	preset, err := doh.PresetFor(spec)
	if err != nil {
		dev.Close()
		return nil, err
	}
	resolver := doh.New(preset)
	dns := func(ctx context.Context, query []byte) ([]byte, error) {
		return doh.ResolveWire(ctx, resolver, query, p.DomainBlocked)
	}
	udpDial := func(ctx context.Context, addr string) (net.Conn, error) {
		var d net.Dialer
		d.Timeout = 10 * time.Second
		d.Control = bind
		return d.DialContext(ctx, "udp", addr)
	}
	router, err := tunstack.Start(tunstack.Config{Dial: dial, DNS: dns, DialUDP: udpDial})
	if err != nil {
		dev.Close()
		return nil, err
	}
	if err := router.AttachDevice(dev); err != nil {
		router.Close()
		dev.Close()
		return nil, err
	}
	fmt.Fprintln(output, "transparent routing active on", dev.Name(), "— all IPv4; DNS via DoH ("+spec+"); upstream pinned to", iface)
	go func() {
		<-ctx.Done()
		router.Close()
	}()
	return func() { _ = dev.Close() }, nil
}
