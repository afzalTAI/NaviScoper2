package upstream

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
)

// httpDialer tunnels connections through an HTTP proxy using CONNECT.
type httpDialer struct {
	addr string
	user string
	pass string
	base Dialer
}

// DialContext connects to addr through the HTTP proxy.
func (d *httpDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := splitTarget(network, addr)
	if err != nil {
		return nil, err
	}
	target := net.JoinHostPort(host, strconv.Itoa(int(port)))
	conn, err := dialWith(ctx, d.base, d.addr)
	if err != nil {
		return nil, err
	}
	tunnel := net.Conn(conn)
	err = guard(ctx, conn, func() error {
		var herr error
		tunnel, herr = d.handshake(conn, target)
		return herr
	})
	if err != nil {
		conn.Close()
		return nil, err
	}
	return tunnel, nil
}

// handshake sends the CONNECT request, validates the proxy response and
// returns the tunnelled connection.
func (d *httpDialer) handshake(conn net.Conn, target string) (net.Conn, error) {
	if _, err := conn.Write([]byte(d.request(target))); err != nil {
		return nil, fmt.Errorf("upstream: http connect write request: %w", err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return nil, fmt.Errorf("upstream: http connect read response: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("upstream: http connect to %s failed: %s", target, resp.Status)
	}
	if n := br.Buffered(); n > 0 {
		// The proxy already sent tunnel data; replay it before the socket.
		return &bufferedConn{Conn: conn, r: io.MultiReader(io.LimitReader(br, int64(n)), conn)}, nil
	}
	return conn, nil
}

// bufferedConn prepends already-buffered bytes to a connection's reads.
type bufferedConn struct {
	net.Conn
	r io.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// request renders the CONNECT request line and headers.
func (d *httpDialer) request(target string) string {
	var b strings.Builder
	b.WriteString("CONNECT " + target + " HTTP/1.1\r\n")
	b.WriteString("Host: " + target + "\r\n")
	if d.user != "" {
		creds := base64.StdEncoding.EncodeToString([]byte(d.user + ":" + d.pass))
		b.WriteString("Proxy-Authorization: Basic " + creds + "\r\n")
	}
	b.WriteString("\r\n")
	return b.String()
}
