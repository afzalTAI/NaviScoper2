package tunstack

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/gvisor/pkg/tcpip/link/veth"

	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv4"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/tcp"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/udp"
)

// clientStack builds a second netstack that plays the intercepted device,
// connected to the router through a veth pair (the fork ships one; it handles
// packet reference counting that a manual channel pump gets wrong).
func clientStack(t *testing.T) (*stack.Stack, stack.LinkEndpoint) {
	t.Helper()
	clientLink, routerLink := veth.NewPair(tunnelMTU, veth.DefaultBacklogSize)
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	if err := s.CreateNIC(2, clientLink); err != nil {
		t.Fatalf("client NIC: %s", err)
	}
	if err := s.AddProtocolAddress(2, tcpip.ProtocolAddress{
		Protocol:          header.IPv4ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFrom4([4]byte{10, 0, 0, 2}).WithPrefix(),
	}, stack.AddressProperties{}); err != nil {
		t.Fatalf("client address: %s", err)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 2}})
	return s, routerLink
}

// TestTCPInterceptedAndForwarded drives a TCP connection from a client
// netstack through the router into a real local echo server.
func TestTCPInterceptedAndForwarded(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			conn, err := echo.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = c.Write([]byte("echo:"))
				buf := make([]byte, 128)
				c.SetReadDeadline(time.Now().Add(3 * time.Second))
				n, _ := c.Read(buf)
				_, _ = c.Write(buf[:n])
			}(conn)
		}
	}()
	var dialed string
	router, err := Start(Config{
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialed = addr
			var d net.Dialer
			return d.DialContext(ctx, network, echo.Addr().String())
		},
		DNS: func(ctx context.Context, query []byte) ([]byte, error) {
			return nil, net.ErrClosed
		},
		DialUDP: func(ctx context.Context, addr string) (net.Conn, error) {
			return nil, net.ErrClosed
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer router.Close()
	cs, routerLink := clientStack(t)
	defer cs.Close()
	if err := router.Attach(routerLink); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	flow, err := gonet.DialContextTCP(ctx, cs, tcpip.FullAddress{
		Addr: tcpip.AddrFrom4([4]byte{1, 2, 3, 4}),
		Port: 4242,
		NIC:  2,
	}, header.IPv4ProtocolNumber)
	if err != nil {
		t.Fatalf("dial through tunnel: %v", err)
	}
	defer flow.Close()
	if _, err := flow.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	var payload []byte
	got := make([]byte, 128)
	_ = flow.SetReadDeadline(time.Now().Add(3 * time.Second))
	for len(payload) < len("echo:hello") {
		n, err := flow.Read(got)
		if err != nil {
			t.Fatalf("read through tunnel: %v (got %q)", err, payload)
		}
		payload = append(payload, got[:n]...)
	}
	if string(payload) != "echo:hello" {
		t.Fatalf("payload %q", payload)
	}
	if dialed != "1.2.3.4:4242" {
		t.Fatalf("intercepted destination was %q, want 1.2.3.4:4242", dialed)
	}
}

// dnsQuery builds a minimal A query for name.example.
func dnsQuery(id uint16) []byte {
	q := []byte{byte(id >> 8), byte(id), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, label := range []string{"name", "example"} {
		q = append(q, byte(len(label)))
		q = append(q, label...)
	}
	return append(q, 0, 0, 1, 0, 1) // null root, A, IN
}

// TestUDPDNSAnsweredInTunnel sends a DNS datagram from the client netstack to
// an arbitrary resolver address and expects the router's DNS callback to answer.
func TestUDPDNSAnsweredInTunnel(t *testing.T) {
	answer := dnsQuery(0xBEEF)
	answer[2] = 0x81 // QR=1, RD=1
	answer[3] = 0x80 // RA=1
	var queried []byte
	router, err := Start(Config{
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return nil, net.ErrClosed
		},
		DNS: func(ctx context.Context, query []byte) ([]byte, error) {
			queried = append([]byte(nil), query...)
			return answer[len(queried):], nil // echo-style canned answer
		},
		DialUDP: func(ctx context.Context, addr string) (net.Conn, error) {
			return nil, net.ErrClosed
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	cs, routerLink := clientStack(t)
	defer cs.Close()
	if err := router.Attach(routerLink); err != nil {
		t.Fatal(err)
	}

	raddr := tcpip.FullAddress{
		Addr: tcpip.AddrFrom4([4]byte{198, 51, 100, 7}),
		Port: 53,
		NIC:  2,
	}
	conn, err := gonet.DialUDP(cs, nil, &raddr, header.IPv4ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	query := dnsQuery(0xBEEF)
	if _, err := conn.Write(query); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 512)
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("dns read: %v", err)
	}
	if !bytes.Equal(buf[:n], answer[len(query):]) {
		t.Fatalf("dns answer %x", buf[:n])
	}
	if !bytes.Equal(queried, query) {
		t.Fatalf("query forwarded to DNS callback differs: %x", queried)
	}
	if len(answer) < 13 || binary.BigEndian.Uint16(answer[:2]) != 0xBEEF {
		t.Fatal("sanity")
	}
}
