package proxy

import (
	"context"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"
)

func (p *Proxy) connect(w http.ResponseWriter, r *http.Request) {
	host, port, err := target(r.RequestURI, true)
	if err != nil || r.URL.Host != r.RequestURI || r.ContentLength > 0 || len(r.TransferEncoding) > 0 {
		http.Error(w, "CONNECT requires a host:port authority and no body", 400)
		return
	}
	if p.blocked(host) {
		p.blockedCount.Add(1)
		http.Error(w, "target blocked", 403)
		return
	}
	allowed := false
	for _, v := range p.cfg.ConnectPorts {
		if v == port {
			allowed = true
			break
		}
	}
	if !allowed {
		p.blockedCount.Add(1)
		http.Error(w, "CONNECT destination port not allowed", 403)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "CONNECT requires HTTP/1.x", 501)
		return
	}
	if p.logger != nil {
		p.logger.Info("proxy request", "operation", "connect", "host", host, "port", port)
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	stop := context.AfterFunc(p.tunnelCtx, cancel)
	defer stop()
	upstream, err := p.transport.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		p.upstreamErrors.Add(1)
		http.Error(w, "CONNECT upstream unavailable", 502)
		return
	}
	defer upstream.Close()
	client, rw, err := hj.Hijack()
	if err != nil {
		return
	}
	defer client.Close()
	p.mu.Lock()
	if p.closing {
		p.mu.Unlock()
		return
	}
	p.tunnels[client] = upstream
	p.tunnelWG.Add(1)
	p.mu.Unlock()
	defer func() { p.mu.Lock(); delete(p.tunnels, client); p.mu.Unlock(); p.tunnelWG.Done() }()
	// Hijack preserves unread bytes in rw.Reader. Replace inherited HTTP deadlines
	// with a finite total tunnel lifetime; TLS remains entirely between endpoints.
	deadline := time.Now().Add(p.cfg.TunnelTimeout)
	if client.SetDeadline(deadline) != nil || upstream.SetDeadline(deadline) != nil {
		return
	}
	if _, err = rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if rw.Flush() != nil {
		return
	}
	done := make(chan struct{})
	go func() { copyHalf(upstream, rw, client); close(done) }()
	copyHalf(client, upstream, upstream)
	<-done
}

// A clean EOF half-closes the destination so the other direction can drain.
// On a copy error both sockets close to release the sibling goroutine promptly.
func copyHalf(dst net.Conn, src io.Reader, other net.Conn) {
	_, err := io.Copy(dst, src)
	if err != nil {
		_ = dst.Close()
		_ = other.Close()
		return
	}
	if tcp, ok := dst.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
	} else {
		_ = dst.Close()
	}
}
