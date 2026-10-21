package upstream

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// serve starts a one-shot TCP server running script and returns its address.
func serve(t *testing.T, script func(c net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	done := make(chan struct{})
	t.Cleanup(func() { <-done })
	t.Cleanup(func() { ln.Close() })
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		script(c)
	}()
	return ln.Addr().String()
}

// recorder collects byte blobs sent by the client under test.
type recorder struct {
	ch chan []byte
}

func newRecorder() *recorder { return &recorder{ch: make(chan []byte, 8)} }

func (r *recorder) put(b []byte) { r.ch <- append([]byte(nil), b...) }

// next returns the next recorded blob, failing the test if none arrives.
func (r *recorder) next(t *testing.T) []byte {
	t.Helper()
	select {
	case b := <-r.ch:
		return b
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for client bytes")
		return nil
	}
}

// readSocksRequest reads a complete SOCKS5 CONNECT request from c.
func readSocksRequest(c net.Conn) ([]byte, error) {
	head := make([]byte, 4)
	if _, err := io.ReadFull(c, head); err != nil {
		return nil, err
	}
	var n int
	switch head[3] {
	case socksAddrIPv4:
		n = 4
	case socksAddrIPv6:
		n = 16
	case socksAddrFQDN:
		var length [1]byte
		if _, err := io.ReadFull(c, length[:]); err != nil {
			return nil, err
		}
		head = append(head, length[0])
		n = int(length[0])
	default:
		return head, errors.New("unknown atyp")
	}
	rest := make([]byte, n+2)
	if _, err := io.ReadFull(c, rest); err != nil {
		return nil, err
	}
	return append(head, rest...), nil
}

// readHTTPHead reads request bytes through the blank line terminating headers.
func readHTTPHead(c net.Conn) ([]byte, error) {
	br := bufio.NewReader(c)
	var buf []byte
	for {
		line, err := br.ReadBytes('\n')
		buf = append(buf, line...)
		if err != nil {
			return buf, err
		}
		if string(line) == "\r\n" {
			return buf, nil
		}
	}
}

func dialTimeout(t *testing.T) (context.Context, context.CancelFunc) {
	t.Helper()
	return context.WithTimeout(context.Background(), 5*time.Second)
}

func mustParse(t *testing.T, raw string) Dialer {
	t.Helper()
	d, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse(%q): %v", raw, err)
	}
	if d == nil {
		t.Fatalf("Parse(%q) returned a nil dialer", raw)
	}
	return d
}

func TestParseEmptyYieldsNoDialer(t *testing.T) {
	d, err := Parse("")
	if err != nil {
		t.Fatalf("Parse(\"\"): %v", err)
	}
	if d != nil {
		t.Fatalf("Parse(\"\") = %v, want nil", d)
	}
}

func TestParseAccepted(t *testing.T) {
	cases := []struct {
		raw        string
		socks      bool
		addr       string
		user, pass string
	}{
		{raw: "socks5://127.0.0.1:1080", socks: true, addr: "127.0.0.1:1080"},
		{raw: "socks5://user:pass@warp.local:40000", socks: true, addr: "warp.local:40000", user: "user", pass: "pass"},
		{raw: "socks5://us%40er:p%3Ass@[::1]:1080", socks: true, addr: "[::1]:1080", user: "us@er", pass: "p:ss"},
		{raw: "http://proxy.example:8080", addr: "proxy.example:8080"},
		{raw: "http://user:pass@proxy.example:8080/", addr: "proxy.example:8080", user: "user", pass: "pass"},
		{raw: "HTTP://proxy.example:8080", addr: "proxy.example:8080"},
	}
	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			d := mustParse(t, tc.raw)
			var addr, user, pass string
			switch v := d.(type) {
			case *socksDialer:
				if !tc.socks {
					t.Fatalf("got socks dialer, want http dialer")
				}
				addr, user, pass = v.addr, v.user, v.pass
			case *httpDialer:
				if tc.socks {
					t.Fatalf("got http dialer, want socks dialer")
				}
				addr, user, pass = v.addr, v.user, v.pass
			default:
				t.Fatalf("unexpected dialer type %T", d)
			}
			if addr != tc.addr || user != tc.user || pass != tc.pass {
				t.Fatalf("got addr=%q user=%q pass=%q, want %q/%q/%q", addr, user, pass, tc.addr, tc.user, tc.pass)
			}
		})
	}
}

func TestParseRejected(t *testing.T) {
	cases := []string{
		"127.0.0.1:1080",
		"localhost:1080",
		"socks5://127.0.0.1",
		"socks5://:1080",
		"socks5://127.0.0.1:0",
		"socks5://127.0.0.1:nope",
		"socks4://127.0.0.1:1080",
		"socks5h://127.0.0.1:1080",
		"https://proxy.example:8443",
		"http://",
		"http://proxy.example:8080/path",
		"http://proxy.example:8080?x=1",
		"http://:pass@proxy.example:8080",
		"://proxy.example:8080",
	}
	for _, raw := range cases {
		t.Run(raw, func(t *testing.T) {
			d, err := Parse(raw)
			if err == nil {
				t.Fatalf("Parse(%q) = %v, want error", raw, d)
			}
			if d != nil {
				t.Fatalf("Parse(%q) returned dialer %v with error %v", raw, d, err)
			}
			if !strings.HasPrefix(err.Error(), "upstream: ") {
				t.Fatalf("error %q lacks the package prefix", err)
			}
		})
	}
}

func TestSocksConnectDomainNoAuth(t *testing.T) {
	rec := newRecorder()
	addr := serve(t, func(c net.Conn) {
		greeting := make([]byte, 3)
		if _, err := io.ReadFull(c, greeting); err != nil {
			t.Errorf("read greeting: %v", err)
			return
		}
		rec.put(greeting)
		c.Write([]byte{0x05, 0x00})
		req, err := readSocksRequest(c)
		if err != nil {
			t.Errorf("read request: %v", err)
			return
		}
		rec.put(req)
		c.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x1F, 0x90})
		c.Write([]byte("payload"))
	})

	ctx, cancel := dialTimeout(t)
	defer cancel()
	conn, err := mustParse(t, "socks5://"+addr).DialContext(ctx, "tcp", "example.com:443")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()

	if got, want := rec.next(t), []byte{0x05, 0x01, 0x00}; !bytes.Equal(got, want) {
		t.Fatalf("greeting = % x, want % x", got, want)
	}
	want := []byte{0x05, 0x01, 0x00, 0x03, 11}
	want = append(want, "example.com"...)
	want = append(want, 0x01, 0xBB)
	if got := rec.next(t); !bytes.Equal(got, want) {
		t.Fatalf("request = % x, want % x", got, want)
	}

	payload := make([]byte, 7)
	if _, err := io.ReadFull(conn, payload); err != nil {
		t.Fatalf("read payload: %v", err)
	}
	if string(payload) != "payload" {
		t.Fatalf("payload = %q", payload)
	}
}

func TestSocksConnectIPv4Atyp(t *testing.T) {
	rec := newRecorder()
	addr := serve(t, func(c net.Conn) {
		io.ReadFull(c, make([]byte, 3))
		c.Write([]byte{0x05, 0x00})
		req, err := readSocksRequest(c)
		if err != nil {
			t.Errorf("read request: %v", err)
			return
		}
		rec.put(req)
		c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	})

	ctx, cancel := dialTimeout(t)
	defer cancel()
	conn, err := mustParse(t, "socks5://"+addr).DialContext(ctx, "tcp", "93.184.216.34:80")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()
	want := []byte{0x05, 0x01, 0x00, 0x01, 93, 184, 216, 34, 0x00, 0x50}
	if got := rec.next(t); !bytes.Equal(got, want) {
		t.Fatalf("request = % x, want % x", got, want)
	}
}

func TestSocksConnectIPv6Atyp(t *testing.T) {
	rec := newRecorder()
	addr := serve(t, func(c net.Conn) {
		io.ReadFull(c, make([]byte, 3))
		c.Write([]byte{0x05, 0x00})
		req, err := readSocksRequest(c)
		if err != nil {
			t.Errorf("read request: %v", err)
			return
		}
		rec.put(req)
		reply := []byte{0x05, 0x00, 0x00, 0x04}
		reply = append(reply, net.ParseIP("::1").To16()...)
		reply = append(reply, 0x01, 0xBB)
		c.Write(reply)
	})

	ctx, cancel := dialTimeout(t)
	defer cancel()
	conn, err := mustParse(t, "socks5://"+addr).DialContext(ctx, "tcp", "[2001:db8::1]:443")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()
	want := []byte{0x05, 0x01, 0x00, 0x04}
	want = append(want, net.ParseIP("2001:db8::1").To16()...)
	want = append(want, 0x01, 0xBB)
	if got := rec.next(t); !bytes.Equal(got, want) {
		t.Fatalf("request = % x, want % x", got, want)
	}
}

func TestSocksUserPassAuth(t *testing.T) {
	rec := newRecorder()
	addr := serve(t, func(c net.Conn) {
		greeting := make([]byte, 4)
		if _, err := io.ReadFull(c, greeting); err != nil {
			t.Errorf("read greeting: %v", err)
			return
		}
		rec.put(greeting)
		c.Write([]byte{0x05, 0x02})
		head := make([]byte, 2)
		if _, err := io.ReadFull(c, head); err != nil {
			t.Errorf("read auth head: %v", err)
			return
		}
		user := make([]byte, head[1])
		io.ReadFull(c, user)
		var plen [1]byte
		io.ReadFull(c, plen[:])
		pass := make([]byte, plen[0])
		io.ReadFull(c, pass)
		auth := append(append(head, user...), plen[0])
		rec.put(append(auth, pass...))
		c.Write([]byte{0x01, 0x00})
		if _, err := readSocksRequest(c); err != nil {
			t.Errorf("read request: %v", err)
			return
		}
		// Reply with a domain-typed bound address to exercise that skip path.
		reply := []byte{0x05, 0x00, 0x00, 0x03, 3}
		reply = append(reply, "abc"...)
		reply = append(reply, 0x00, 0x50, 'o', 'k')
		c.Write(reply)
	})

	ctx, cancel := dialTimeout(t)
	defer cancel()
	conn, err := mustParse(t, "socks5://us%40er:p%3Ass@"+addr).DialContext(ctx, "tcp", "example.com:443")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()

	if got, want := rec.next(t), []byte{0x05, 0x02, 0x00, 0x02}; !bytes.Equal(got, want) {
		t.Fatalf("greeting = % x, want % x", got, want)
	}
	want := []byte{0x01, 5}
	want = append(want, "us@er"...)
	want = append(want, 4)
	want = append(want, "p:ss"...)
	if got := rec.next(t); !bytes.Equal(got, want) {
		t.Fatalf("auth = % x, want % x", got, want)
	}
	tail := make([]byte, 2)
	if _, err := io.ReadFull(conn, tail); err != nil {
		t.Fatalf("read tail: %v", err)
	}
	if string(tail) != "ok" {
		t.Fatalf("tail = %q, want %q", tail, "ok")
	}
}

func TestSocksHandshakeFailures(t *testing.T) {
	cases := []struct {
		name   string
		url    string
		script func(c net.Conn)
		want   string
	}{
		{
			name: "no acceptable methods",
			script: func(c net.Conn) {
				io.ReadFull(c, make([]byte, 3))
				c.Write([]byte{0x05, 0xFF})
			},
			want: "rejected all offered authentication methods",
		},
		{
			name: "unsupported method",
			script: func(c net.Conn) {
				io.ReadFull(c, make([]byte, 3))
				c.Write([]byte{0x05, 0x01})
			},
			want: "unsupported authentication method 0x01",
		},
		{
			name: "auth requested without credentials",
			script: func(c net.Conn) {
				io.ReadFull(c, make([]byte, 3))
				c.Write([]byte{0x05, 0x02})
			},
			want: "no credentials were configured",
		},
		{
			name: "bad credentials",
			url:  "u:p@",
			script: func(c net.Conn) {
				io.ReadFull(c, make([]byte, 4))
				c.Write([]byte{0x05, 0x02})
				io.ReadFull(c, make([]byte, 5))
				c.Write([]byte{0x01, 0x01})
			},
			want: "rejected the supplied credentials (status 0x01)",
		},
		{
			name: "wrong greeting version",
			script: func(c net.Conn) {
				io.ReadFull(c, make([]byte, 3))
				c.Write([]byte{0x04, 0x00})
			},
			want: "replied with version 0x04",
		},
		{
			name: "connection not allowed",
			script: func(c net.Conn) {
				io.ReadFull(c, make([]byte, 3))
				c.Write([]byte{0x05, 0x00})
				readSocksRequest(c)
				c.Write([]byte{0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			},
			want: "connection not allowed by ruleset",
		},
		{
			name: "host unreachable",
			script: func(c net.Conn) {
				io.ReadFull(c, make([]byte, 3))
				c.Write([]byte{0x05, 0x00})
				readSocksRequest(c)
				c.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			},
			want: "host unreachable",
		},
		{
			name: "unknown reply code",
			script: func(c net.Conn) {
				io.ReadFull(c, make([]byte, 3))
				c.Write([]byte{0x05, 0x00})
				readSocksRequest(c)
				c.Write([]byte{0x05, 0x7F, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			},
			want: "unknown reply code 0x7f",
		},
		{
			name: "unknown bound address type",
			script: func(c net.Conn) {
				io.ReadFull(c, make([]byte, 3))
				c.Write([]byte{0x05, 0x00})
				readSocksRequest(c)
				c.Write([]byte{0x05, 0x00, 0x00, 0x09, 0, 0, 0, 0, 0, 0})
			},
			want: "unknown address type 0x09",
		},
		{
			name: "garbage then close",
			script: func(c net.Conn) {
				io.ReadFull(c, make([]byte, 3))
				c.Write([]byte{0x05, 0x00})
				readSocksRequest(c)
				c.Write([]byte{0x05, 0x00})
			},
			want: "read connect reply",
		},
		{
			name: "immediate close",
			script: func(c net.Conn) {
				c.Close()
			},
			want: "read method selection",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			addr := serve(t, tc.script)
			ctx, cancel := dialTimeout(t)
			defer cancel()
			conn, err := mustParse(t, "socks5://"+tc.url+addr).DialContext(ctx, "tcp", "example.com:443")
			if err == nil {
				conn.Close()
				t.Fatal("DialContext succeeded, want error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %q, want it to contain %q", err, tc.want)
			}
		})
	}
}

func TestSocksContextCancelled(t *testing.T) {
	addr := serve(t, func(c net.Conn) {
		io.ReadFull(c, make([]byte, 3))
		c.Read(make([]byte, 1)) // stall until the client goes away
	})
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	defer cancel()
	conn, err := mustParse(t, "socks5://"+addr).DialContext(ctx, "tcp", "example.com:443")
	if err == nil {
		conn.Close()
		t.Fatal("DialContext succeeded, want cancellation error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}

func TestSocksContextDeadline(t *testing.T) {
	addr := serve(t, func(c net.Conn) {
		io.ReadFull(c, make([]byte, 3))
		c.Read(make([]byte, 1))
	})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	conn, err := mustParse(t, "socks5://"+addr).DialContext(ctx, "tcp", "example.com:443")
	if err == nil {
		conn.Close()
		t.Fatal("DialContext succeeded, want deadline error")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want context.DeadlineExceeded", err)
	}
}

func TestSocksRejectsBadDialArguments(t *testing.T) {
	d := mustParse(t, "socks5://127.0.0.1:1080")
	ctx := context.Background()
	for _, tc := range []struct{ network, addr, want string }{
		{"udp", "example.com:443", "unsupported network"},
		{"tcp", "example.com", "invalid address"},
		{"tcp", "example.com:0", "invalid port"},
		{"tcp", ":443", "no host"},
	} {
		if _, err := d.DialContext(ctx, tc.network, tc.addr); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("DialContext(%q, %q) error = %v, want %q", tc.network, tc.addr, err, tc.want)
		}
	}
}

func TestHTTPConnectHappyPath(t *testing.T) {
	rec := newRecorder()
	addr := serve(t, func(c net.Conn) {
		head, err := readHTTPHead(c)
		if err != nil {
			t.Errorf("read head: %v", err)
			return
		}
		rec.put(head)
		c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		c.Write([]byte("payload"))
	})

	ctx, cancel := dialTimeout(t)
	defer cancel()
	conn, err := mustParse(t, "http://"+addr).DialContext(ctx, "tcp", "example.com:443")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()

	want := "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"
	if got := string(rec.next(t)); got != want {
		t.Fatalf("request = %q, want %q", got, want)
	}
	payload := make([]byte, 7)
	if _, err := io.ReadFull(conn, payload); err != nil {
		t.Fatalf("read payload: %v", err)
	}
	if string(payload) != "payload" {
		t.Fatalf("payload = %q", payload)
	}
}

func TestHTTPConnectReplaysCoalescedPayload(t *testing.T) {
	addr := serve(t, func(c net.Conn) {
		if _, err := readHTTPHead(c); err != nil {
			t.Errorf("read head: %v", err)
			return
		}
		// Response and tunnel data in a single write: the client's header
		// reader buffers both and must not drop the payload.
		c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\nearly-bytes"))
		c.Write([]byte("-late"))
	})

	ctx, cancel := dialTimeout(t)
	defer cancel()
	conn, err := mustParse(t, "http://"+addr).DialContext(ctx, "tcp", "example.com:443")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()
	got := make([]byte, len("early-bytes-late"))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read payload: %v", err)
	}
	if string(got) != "early-bytes-late" {
		t.Fatalf("payload = %q, want %q", got, "early-bytes-late")
	}
}

func TestHTTPConnectProxyAuthorization(t *testing.T) {
	rec := newRecorder()
	addr := serve(t, func(c net.Conn) {
		head, err := readHTTPHead(c)
		if err != nil {
			t.Errorf("read head: %v", err)
			return
		}
		rec.put(head)
		c.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
	})

	ctx, cancel := dialTimeout(t)
	defer cancel()
	conn, err := mustParse(t, "http://user:pa%3Ass@"+addr).DialContext(ctx, "tcp", "[2001:db8::1]:8443")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()

	creds := base64.StdEncoding.EncodeToString([]byte("user:pa:ss"))
	want := "CONNECT [2001:db8::1]:8443 HTTP/1.1\r\n" +
		"Host: [2001:db8::1]:8443\r\n" +
		"Proxy-Authorization: Basic " + creds + "\r\n\r\n"
	if got := string(rec.next(t)); got != want {
		t.Fatalf("request = %q, want %q", got, want)
	}
}

func TestHTTPConnectFailures(t *testing.T) {
	cases := []struct {
		name  string
		reply string
		want  string
	}{
		{
			name:  "proxy auth required",
			reply: "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"x\"\r\nContent-Length: 0\r\n\r\n",
			want:  "407 Proxy Authentication Required",
		},
		{
			name:  "bad gateway",
			reply: "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n",
			want:  "502 Bad Gateway",
		},
		{
			name:  "redirect is not success",
			reply: "HTTP/1.1 301 Moved Permanently\r\nLocation: /x\r\nContent-Length: 0\r\n\r\n",
			want:  "301 Moved Permanently",
		},
		{
			name:  "garbage status line",
			reply: "not-http at all\r\n\r\n",
			want:  "read response",
		},
		{
			name:  "garbage header",
			reply: "HTTP/1.1 200 OK\r\nthis is not a header\r\n\r\n",
			want:  "read response",
		},
		{
			name:  "empty reply",
			reply: "",
			want:  "read response",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reply := tc.reply
			addr := serve(t, func(c net.Conn) {
				if _, err := readHTTPHead(c); err != nil {
					t.Errorf("read head: %v", err)
					return
				}
				c.Write([]byte(reply))
			})
			ctx, cancel := dialTimeout(t)
			defer cancel()
			conn, err := mustParse(t, "http://"+addr).DialContext(ctx, "tcp", "example.com:443")
			if err == nil {
				conn.Close()
				t.Fatal("DialContext succeeded, want error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %q, want it to contain %q", err, tc.want)
			}
		})
	}
}

func TestHTTPConnectContextCancelled(t *testing.T) {
	addr := serve(t, func(c net.Conn) {
		readHTTPHead(c)
		c.Read(make([]byte, 1))
	})
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	defer cancel()
	conn, err := mustParse(t, "http://"+addr).DialContext(ctx, "tcp", "example.com:443")
	if err == nil {
		conn.Close()
		t.Fatal("DialContext succeeded, want cancellation error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}

func TestDialProxyUnreachable(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	ctx, cancel := dialTimeout(t)
	defer cancel()
	for _, raw := range []string{"socks5://" + addr, "http://" + addr} {
		if _, err := mustParse(t, raw).DialContext(ctx, "tcp", "example.com:443"); err == nil {
			t.Fatalf("%s: DialContext succeeded, want error", raw)
		} else if !strings.Contains(err.Error(), "dial proxy") {
			t.Fatalf("%s: error = %q, want it to mention dial proxy", raw, err)
		}
	}
}

func TestDeadlineHonoursEarlierContext(t *testing.T) {
	near := time.Now().Add(time.Second)
	ctx, cancel := context.WithDeadline(context.Background(), near)
	defer cancel()
	if got := deadline(ctx); !got.Equal(near) {
		t.Fatalf("deadline = %v, want %v", got, near)
	}
	plain := deadline(context.Background())
	if d := time.Until(plain); d <= 9*time.Second || d > handshakeTimeout {
		t.Fatalf("default deadline is %v away, want ~%v", d, handshakeTimeout)
	}
}
