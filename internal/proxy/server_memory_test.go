package proxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// memoryListener carries the actual HTTP/TLS protocols over net.Pipe. It tests
// server/transport integration without binding a port; it does not emulate TCP
// half-close semantics, which are covered by the localhost tunnel tests.
type memoryListener struct {
	connections chan net.Conn
	closed      chan struct{}
	once        sync.Once
	dials       atomic.Int32
}

func newMemoryListener(t *testing.T) *memoryListener {
	t.Helper()
	l := &memoryListener{connections: make(chan net.Conn), closed: make(chan struct{})}
	t.Cleanup(func() { l.Close() })
	return l
}
func (l *memoryListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.connections:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}
func (l *memoryListener) Close() error   { l.once.Do(func() { close(l.closed) }); return nil }
func (l *memoryListener) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8081} }
func (l *memoryListener) dial(ctx context.Context, network, address string) (net.Conn, error) {
	a, b := net.Pipe()
	select {
	case l.connections <- a:
		l.dials.Add(1)
		return b, nil
	case <-l.closed:
		a.Close()
		b.Close()
		return nil, net.ErrClosed
	case <-ctx.Done():
		a.Close()
		b.Close()
		return nil, ctx.Err()
	}
}

func TestHTTPInMemoryTransportReuseAndShutdown(t *testing.T) {
	upstreamListener := newMemoryListener(t)
	upstream := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if r.Host != "origin.test" || string(b) != "payload" {
			t.Error("HTTP semantics changed")
		}
		w.Header().Add("Set-Cookie", "a=1")
		w.Header().Add("Set-Cookie", "b=2")
		w.WriteHeader(201)
		_, _ = io.WriteString(w, "streamed response")
	})}
	go upstream.Serve(upstreamListener)
	t.Cleanup(func() { upstream.Close() })
	p, err := New(DefaultConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	p.transport.DialContext = upstreamListener.dial
	listener := newMemoryListener(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- p.Serve(ctx, listener) }()
	tr := &http.Transport{DialContext: listener.dial, Proxy: http.ProxyURL(mustURL(t, "http://proxy.test:8081"))}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 2 * time.Second}
	for i := 0; i < 2; i++ {
		// Explicit-proxy wire format is produced using ProxyURL.
		req, _ := http.NewRequest("POST", "http://origin.test/path?q=1", strings.NewReader("payload"))
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(res.Body)
		res.Body.Close()
		if err != nil || res.StatusCode != 201 || string(b) != "streamed response" || len(res.Header.Values("Set-Cookie")) != 2 {
			t.Fatalf("bad response: %d %q %v", res.StatusCode, b, err)
		}
	}
	if upstreamListener.dials.Load() != 1 {
		t.Fatalf("upstream not reused: %d", upstreamListener.dials.Load())
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown hung")
	}
}

func TestTLSInMemoryEndToEnd(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "origin.test"}, DNSNames: []string{"origin.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	upstreamListener := newMemoryListener(t)
	tlsListener := tls.NewListener(upstreamListener, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12})
	upstream := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || r.Header.Get("Cookie") != "encrypted=secret" {
			t.Error("TLS or cookie changed")
		}
		_, _ = io.WriteString(w, "end-to-end TLS")
	})}
	go upstream.Serve(tlsListener)
	t.Cleanup(func() { upstream.Close() })
	cfg := DefaultConfig()
	cfg.StripRequestCookies = true
	p, err := New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	p.transport.DialContext = upstreamListener.dial
	listener := newMemoryListener(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- p.Serve(ctx, listener) }()
	tr := &http.Transport{DialContext: listener.dial, Proxy: http.ProxyURL(mustURL(t, "http://proxy.test:8081")), TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 2 * time.Second}
	req, _ := http.NewRequest("GET", "https://origin.test/secret?token=secret", nil)
	req.Header.Set("Cookie", "encrypted=secret")
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil || string(b) != "end-to-end TLS" {
		t.Fatalf("%q %v", b, err)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("TLS tunnel shutdown hung")
	}
}

func TestShutdownInMemoryDrainsOrCancelsHTTP(t *testing.T) {
	for _, mode := range []string{"drain", "force"} {
		t.Run(mode, func(t *testing.T) {
			started := make(chan struct{})
			release := make(chan struct{})
			upstreamCanceled := make(chan struct{})
			var releaseOnce sync.Once
			defer releaseOnce.Do(func() { close(release) })
			upstreamListener := newMemoryListener(t)
			upstream := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				close(started)
				select {
				case <-release:
					_, _ = io.WriteString(w, "finished")
				case <-r.Context().Done():
				}
				close(upstreamCanceled)
			})}
			go upstream.Serve(upstreamListener)
			defer upstream.Close()
			cfg := DefaultConfig()
			if mode == "force" {
				cfg.ShutdownTimeout = 30 * time.Millisecond
			}
			p, err := New(cfg, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			p.transport.DialContext = upstreamListener.dial
			listener := newMemoryListener(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- p.Serve(ctx, listener) }()
			tr := &http.Transport{DialContext: listener.dial, Proxy: http.ProxyURL(mustURL(t, "http://proxy.test:8081"))}
			defer tr.CloseIdleConnections()
			client := &http.Client{Transport: tr, Timeout: 2 * time.Second}
			result := make(chan error, 1)
			go func() {
				res, err := client.Get("http://origin.test/")
				if err == nil {
					b, e := io.ReadAll(res.Body)
					res.Body.Close()
					err = e
					if mode == "drain" && string(b) != "finished" {
						err = errors.New("truncated response")
					}
				}
				result <- err
			}()
			select {
			case <-started:
			case <-time.After(time.Second):
				t.Fatal("request did not start")
			}
			cancel()
			select {
			case <-listener.closed:
			case <-time.After(time.Second):
				t.Fatal("shutdown did not close listener")
			}
			if mode == "drain" {
				releaseOnce.Do(func() { close(release) })
			}
			select {
			case err := <-done:
				if mode == "drain" && err != nil || mode == "force" && !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("shutdown: %v", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("shutdown hung")
			}
			select {
			case err := <-result:
				if mode == "drain" && err != nil {
					t.Fatal(err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("request did not finish")
			}
			select {
			case <-upstreamCanceled:
			case <-time.After(time.Second):
				t.Fatal("upstream request leaked")
			}
		})
	}
}
