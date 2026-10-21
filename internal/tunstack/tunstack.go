// Package tunstack runs a userspace TCP/IP stack (gvisor netstack) over the
// utun link: every TCP flow is dialed through the outbound chain, DNS is
// answered by the in-process DoH forwarder, and remaining UDP is relayed
// directly. This is the transparent-routing engine; HTTPS stays end-to-end.
package tunstack

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/sagernet/gvisor/pkg/buffer"
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/gvisor/pkg/tcpip/link/channel"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv4"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/tcp"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/udp"
	"github.com/sagernet/gvisor/pkg/waiter"
)

const (
	nicID        = 1
	tunnelMTU    = 1500
	dialTimeout  = 10 * time.Second
	udpIdleTTL   = 30 * time.Second
	copyChunk    = 32 * 1024
	dnsPort      = 53
	tcpBacklog   = 512
	maxDNSPacket = 64 * 1024
)

// Config supplies the outbound behaviors. Dial serves TCP flows, DNS answers
// wire-format DNS queries, DialUDP relays non-DNS UDP (both must bypass the
// tunnel via bound sockets).
type Config struct {
	Dial    func(ctx context.Context, network, addr string) (net.Conn, error)
	DNS     func(ctx context.Context, query []byte) ([]byte, error)
	DialUDP func(ctx context.Context, addr string) (net.Conn, error) // connected UDP
	Logger  io.Writer
}

// Router owns the netstack and its forwarders.
type Router struct {
	cfg    Config
	s      *stack.Stack
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// Start builds the stack with TCP and UDP forwarders attached.
func Start(cfg Config) (*Router, error) {
	if cfg.Dial == nil || cfg.DNS == nil || cfg.DialUDP == nil {
		return nil, fmt.Errorf("tunstack: Dial, DNS, and DialUDP are required")
	}
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	ctx, cancel := context.WithCancel(context.Background())
	r := &Router{cfg: cfg, s: s, ctx: ctx, cancel: cancel}
	tcpFwd := tcp.NewForwarder(s, 0, tcpBacklog, r.handleTCP)
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)
	udpFwd := udp.NewForwarder(s, func(req *udp.ForwarderRequest) bool {
		r.handleUDP(req)
		return true
	})
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)
	return r, nil
}

// Attach connects the stack to a link endpoint (the utun device in
// production, a channel endpoint in tests) and enables spoofing so the
// forwarders can answer on behalf of any destination address.
func (r *Router) Attach(ep stack.LinkEndpoint) error {
	if err := r.s.CreateNIC(nicID, ep); err != nil {
		return fmt.Errorf("tunstack: create NIC: %s", err)
	}
	addr := tcpip.AddrFrom4([4]byte{198, 18, 0, 1})
	if err := r.s.AddProtocolAddress(nicID, tcpip.ProtocolAddress{
		Protocol:          header.IPv4ProtocolNumber,
		AddressWithPrefix: addr.WithPrefix(),
	}, stack.AddressProperties{}); err != nil {
		return fmt.Errorf("tunstack: add address: %s", err)
	}
	r.s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: nicID}})
	r.s.SetPromiscuousMode(nicID, true)
	r.s.SetSpoofing(nicID, true)
	return nil
}

// Close stops the stack and waits for flow handlers.
func (r *Router) Close() {
	r.cancel()
	r.s.Close()
	r.wg.Wait()
}

// Device is the OS tunnel interface: raw IP packets in and out.
type Device interface {
	Read(buf []byte) (int, error)
	Write(buf []byte) (int, error)
}

// AttachDevice bridges the OS device to the stack through a channel link,
// building fresh packet buffers per datagram (correct reference handling) in
// both directions.
func (r *Router) AttachDevice(dev Device) error {
	ep := channel.New(512, tunnelMTU, "")
	if err := r.Attach(ep); err != nil {
		return err
	}
	r.wg.Add(2)
	go func() {
		// device → stack
		defer r.wg.Done()
		buf := make([]byte, tunnelMTU+header.IPv4MinimumSize)
		for {
			n, err := dev.Read(buf)
			if err != nil {
				return
			}
			if n == 0 {
				continue
			}
			payload := buffer.MakeWithData(buf[:n])
			pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: payload})
			ep.InjectInbound(header.IPv4ProtocolNumber, pkt)
			pkt.DecRef()
		}
	}()
	go func() {
		// stack → device
		defer r.wg.Done()
		for {
			pkt := ep.ReadContext(r.ctx)
			if pkt == nil {
				return
			}
			data := pkt.ToBuffer()
			raw := data.Flatten()
			if len(raw) > tunnelMTU+header.IPv4MinimumSize {
				pkt.DecRef()
				continue
			}
			_, _ = dev.Write(raw)
			pkt.DecRef()
		}
	}()
	return nil
}

// handleTCP bridges one intercepted TCP flow to the outbound chain. Port 53
// flows get DNS-over-TCP framing instead of a raw tunnel.
func (r *Router) handleTCP(req *tcp.ForwarderRequest) {
	id := req.ID()
	target := net.JoinHostPort(id.LocalAddress.String(), fmt.Sprint(id.LocalPort))
	var wq waiter.Queue
	ep, err := req.CreateEndpoint(&wq)
	if err != nil {
		req.Complete(true)
		return
	}
	req.Complete(false)
	conn := gonet.NewTCPConn(&wq, ep)
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		defer conn.Close()
		if id.LocalPort == dnsPort {
			r.serveDNSOverTCP(conn)
			return
		}
		ctx, cancel := context.WithTimeout(r.ctx, dialTimeout)
		defer cancel()
		upstream, err := r.cfg.Dial(ctx, "tcp", target)
		if err != nil {
			return
		}
		defer upstream.Close()
		r.relay(conn, upstream)
	}()
}

// relay copies both directions until either side closes.
func (r *Router) relay(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst io.WriteCloser, src io.Reader) {
		_, _ = io.Copy(dst, src)
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	_ = a.SetDeadline(time.Now())
	_ = b.SetDeadline(time.Now())
	<-done
}

// serveDNSOverTCP speaks RFC 1035 TCP framing: 2-byte length prefixes.
func (r *Router) serveDNSOverTCP(conn net.Conn) {
	defer conn.Close()
	var length [2]byte
	for {
		if _, err := io.ReadFull(conn, length[:]); err != nil {
			return
		}
		n := binary.BigEndian.Uint16(length[:])
		if n == 0 || int(n) > maxDNSPacket {
			return
		}
		query := make([]byte, n)
		if _, err := io.ReadFull(conn, query); err != nil {
			return
		}
		ctx, cancel := context.WithTimeout(r.ctx, dialTimeout)
		answer, err := r.cfg.DNS(ctx, query)
		cancel()
		if err != nil {
			return
		}
		if len(answer) > maxDNSPacket {
			return
		}
		binary.BigEndian.PutUint16(length[:], uint16(len(answer)))
		if _, err := conn.Write(length[:]); err != nil {
			return
		}
		if _, err := conn.Write(answer); err != nil {
			return
		}
	}
}

// handleUDP answers DNS datagrams directly and relays everything else with
// an idle timeout.
func (r *Router) handleUDP(req *udp.ForwarderRequest) {
	id := req.ID()
	target := net.JoinHostPort(id.LocalAddress.String(), fmt.Sprint(id.LocalPort))
	var wq waiter.Queue
	ep, err := req.CreateEndpoint(&wq)
	if err != nil {
		return
	}
	conn := gonet.NewUDPConn(&wq, ep)
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		defer conn.Close()
		if id.LocalPort == dnsPort {
			r.serveDNSUDP(conn)
			return
		}
		ctx, cancel := context.WithTimeout(r.ctx, dialTimeout)
		defer cancel()
		remote, err := r.cfg.DialUDP(ctx, target)
		if err != nil {
			return
		}
		defer remote.Close()
		buf := make([]byte, tunnelMTU)
		var clientAddr *net.UDPAddr
		for {
			_ = remote.SetReadDeadline(time.Now().Add(udpIdleTTL))
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			if addr != nil {
				clientAddr = udpAddrOf(addr)
			}
			if _, err := remote.Write(buf[:n]); err != nil {
				return
			}
			n, err = remote.Read(buf)
			if err != nil {
				return
			}
			if clientAddr != nil {
				if _, err := conn.WriteTo(buf[:n], clientAddr); err != nil {
					return
				}
			}
		}
	}()
}

func udpAddrOf(a net.Addr) *net.UDPAddr {
	if u, ok := a.(*net.UDPAddr); ok {
		return u
	}
	return nil
}

// serveDNSUDP answers one query per datagram until the flow idles out.
func (r *Router) serveDNSUDP(conn *gonet.UDPConn) {
	defer conn.Close()
	buf := make([]byte, tunnelMTU)
	var last time.Time
	for {
		if !last.IsZero() && time.Since(last) > udpIdleTTL {
			return
		}
		_ = conn.SetReadDeadline(time.Now().Add(udpIdleTTL))
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}
		last = time.Now()
		ctx, cancel := context.WithTimeout(r.ctx, dialTimeout)
		answer, rerr := r.cfg.DNS(ctx, buf[:n])
		cancel()
		if rerr != nil {
			continue
		}
		if addr != nil {
			if _, werr := conn.WriteTo(answer, udpAddrOf(addr)); werr != nil {
				return
			}
		}
	}
}

// ChannelLink builds a channel-based link endpoint for in-process tests.
func ChannelLink() *channel.Endpoint {
	return channel.New(512, tunnelMTU, "")
}
