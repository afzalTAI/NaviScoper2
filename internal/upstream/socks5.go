package upstream

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
)

// SOCKS5 protocol constants (RFC 1928, RFC 1929).
const (
	socksVersion   = 0x05
	socksAuthNone  = 0x00
	socksAuthUser  = 0x02
	socksNoAccept  = 0xFF
	socksConnect   = 0x01
	socksReserved  = 0x00
	socksAuthVer   = 0x01
	socksAuthOK    = 0x00
	socksAddrIPv4  = 0x01
	socksAddrFQDN  = 0x03
	socksAddrIPv6  = 0x04
	socksReplyOKay = 0x00
)

// socksDialer tunnels connections through a SOCKS5 proxy.
type socksDialer struct {
	addr string
	user string
	pass string
	base Dialer
}

// DialContext connects to addr through the SOCKS5 proxy.
func (d *socksDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := splitTarget(network, addr)
	if err != nil {
		return nil, err
	}
	conn, err := dialWith(ctx, d.base, d.addr)
	if err != nil {
		return nil, err
	}
	err = guard(ctx, conn, func() error { return d.handshake(conn, host, port) })
	if err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// handshake performs method negotiation, optional authentication and the
// CONNECT request.
func (d *socksDialer) handshake(conn net.Conn, host string, port uint16) error {
	if err := d.negotiate(conn); err != nil {
		return err
	}
	return d.connect(conn, host, port)
}

// negotiate offers the supported authentication methods and runs the one the
// server selects.
func (d *socksDialer) negotiate(conn net.Conn) error {
	greeting := []byte{socksVersion, 1, socksAuthNone}
	if d.user != "" {
		greeting = []byte{socksVersion, 2, socksAuthNone, socksAuthUser}
	}
	if _, err := conn.Write(greeting); err != nil {
		return fmt.Errorf("upstream: socks5 write greeting: %w", err)
	}
	var reply [2]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		return fmt.Errorf("upstream: socks5 read method selection: %w", err)
	}
	if reply[0] != socksVersion {
		return fmt.Errorf("upstream: socks5 proxy replied with version 0x%02x, want 0x05", reply[0])
	}
	switch reply[1] {
	case socksAuthNone:
		return nil
	case socksAuthUser:
		if d.user == "" {
			return fmt.Errorf("upstream: socks5 proxy requested username/password auth but no credentials were configured")
		}
		return d.authenticate(conn)
	case socksNoAccept:
		return fmt.Errorf("upstream: socks5 proxy rejected all offered authentication methods")
	default:
		return fmt.Errorf("upstream: socks5 proxy selected unsupported authentication method 0x%02x", reply[1])
	}
}

// authenticate runs the username/password subnegotiation of RFC 1929.
func (d *socksDialer) authenticate(conn net.Conn) error {
	msg := make([]byte, 0, 3+len(d.user)+len(d.pass))
	msg = append(msg, socksAuthVer, byte(len(d.user)))
	msg = append(msg, d.user...)
	msg = append(msg, byte(len(d.pass)))
	msg = append(msg, d.pass...)
	if _, err := conn.Write(msg); err != nil {
		return fmt.Errorf("upstream: socks5 write credentials: %w", err)
	}
	var reply [2]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		return fmt.Errorf("upstream: socks5 read auth reply: %w", err)
	}
	if reply[0] != socksAuthVer {
		return fmt.Errorf("upstream: socks5 auth reply has version 0x%02x, want 0x01", reply[0])
	}
	if reply[1] != socksAuthOK {
		return fmt.Errorf("upstream: socks5 proxy rejected the supplied credentials (status 0x%02x)", reply[1])
	}
	return nil
}

// connect issues the CONNECT request and reads the reply.
func (d *socksDialer) connect(conn net.Conn, host string, port uint16) error {
	req, err := socksRequest(host, port)
	if err != nil {
		return err
	}
	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("upstream: socks5 write connect request: %w", err)
	}
	var head [4]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return fmt.Errorf("upstream: socks5 read connect reply: %w", err)
	}
	if head[0] != socksVersion {
		return fmt.Errorf("upstream: socks5 connect reply has version 0x%02x, want 0x05", head[0])
	}
	if head[1] != socksReplyOKay {
		return fmt.Errorf("upstream: socks5 connect to %s failed: %s", net.JoinHostPort(host, strconv.Itoa(int(port))), replyMessage(head[1]))
	}
	return skipBoundAddr(conn, head[3])
}

// socksRequest encodes a CONNECT request for host:port.
func socksRequest(host string, port uint16) ([]byte, error) {
	req := []byte{socksVersion, socksConnect, socksReserved}
	switch ip := net.ParseIP(host); {
	case ip == nil:
		if len(host) > 255 {
			return nil, fmt.Errorf("upstream: socks5 destination host %q exceeds 255 bytes", host)
		}
		req = append(req, socksAddrFQDN, byte(len(host)))
		req = append(req, host...)
	case ip.To4() != nil:
		req = append(req, socksAddrIPv4)
		req = append(req, ip.To4()...)
	default:
		req = append(req, socksAddrIPv6)
		req = append(req, ip.To16()...)
	}
	return binary.BigEndian.AppendUint16(req, port), nil
}

// skipBoundAddr consumes the bound address and port that follow a reply.
func skipBoundAddr(conn net.Conn, atyp byte) error {
	var n int
	switch atyp {
	case socksAddrIPv4:
		n = net.IPv4len
	case socksAddrIPv6:
		n = net.IPv6len
	case socksAddrFQDN:
		var length [1]byte
		if _, err := io.ReadFull(conn, length[:]); err != nil {
			return fmt.Errorf("upstream: socks5 read bound address length: %w", err)
		}
		n = int(length[0])
	default:
		return fmt.Errorf("upstream: socks5 connect reply has unknown address type 0x%02x", atyp)
	}
	if _, err := io.ReadFull(conn, make([]byte, n+2)); err != nil {
		return fmt.Errorf("upstream: socks5 read bound address: %w", err)
	}
	return nil
}

// replyMessage describes a SOCKS5 reply code.
func replyMessage(code byte) string {
	switch code {
	case 0x01:
		return "general SOCKS server failure"
	case 0x02:
		return "connection not allowed by ruleset"
	case 0x03:
		return "network unreachable"
	case 0x04:
		return "host unreachable"
	case 0x05:
		return "connection refused"
	case 0x06:
		return "TTL expired"
	case 0x07:
		return "command not supported"
	case 0x08:
		return "address type not supported"
	default:
		return fmt.Sprintf("unknown reply code 0x%02x", code)
	}
}
