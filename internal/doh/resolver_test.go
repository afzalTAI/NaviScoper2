package doh_test

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"naviscopereborn/internal/doh"
)

// The helpers below encode DNS messages independently of the package under
// test, so a passing round trip exercises both directions of the wire code.

func encodeTestName(name string) []byte {
	name = strings.TrimSuffix(name, ".")
	out := make([]byte, 0, len(name)+2)
	for _, label := range strings.Split(name, ".") {
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	return append(out, 0)
}

type testRecord struct {
	name  string
	rtype uint16
	ttl   uint32
	rdata []byte
}

func addrRecord(name string, addr string, ttl uint32) testRecord {
	ip := netip.MustParseAddr(addr)
	if ip.Is4() {
		v4 := ip.As4()
		return testRecord{name: name, rtype: doh.TypeA, ttl: ttl, rdata: v4[:]}
	}
	v6 := ip.As16()
	return testRecord{name: name, rtype: doh.TypeAAAA, ttl: ttl, rdata: v6[:]}
}

func cnameRecord(name, target string, ttl uint32) testRecord {
	return testRecord{name: name, rtype: doh.TypeCNAME, ttl: ttl, rdata: encodeTestName(target)}
}

func buildResponse(id uint16, qname string, qtype, rcode uint16, recs []testRecord) []byte {
	msg := make([]byte, 12)
	binary.BigEndian.PutUint16(msg[0:2], id)
	binary.BigEndian.PutUint16(msg[2:4], 0x8180|rcode)
	binary.BigEndian.PutUint16(msg[4:6], 1)
	binary.BigEndian.PutUint16(msg[6:8], uint16(len(recs)))
	msg = append(msg, encodeTestName(qname)...)
	msg = binary.BigEndian.AppendUint16(msg, qtype)
	msg = binary.BigEndian.AppendUint16(msg, doh.ClassIN)
	for _, rec := range recs {
		msg = append(msg, encodeTestName(rec.name)...)
		msg = binary.BigEndian.AppendUint16(msg, rec.rtype)
		msg = binary.BigEndian.AppendUint16(msg, doh.ClassIN)
		msg = binary.BigEndian.AppendUint32(msg, rec.ttl)
		msg = binary.BigEndian.AppendUint16(msg, uint16(len(rec.rdata)))
		msg = append(msg, rec.rdata...)
	}
	return msg
}

// answerFunc produces the records (and rcode) for one decoded question.
type answerFunc func(host string, qtype uint16) (uint16, []testRecord)

type dnsServer struct {
	t        *testing.T
	srv      *httptest.Server
	answer   answerFunc
	mu       sync.Mutex
	requests int

	status      int
	contentType string
}

func newDNSServer(t *testing.T, answer answerFunc) *dnsServer {
	t.Helper()
	s := &dnsServer{t: t, answer: answer, status: http.StatusOK, contentType: "application/dns-message"}
	s.srv = httptest.NewTLSServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *dnsServer) serve(w http.ResponseWriter, req *http.Request) {
	s.mu.Lock()
	s.requests++
	status, contentType := s.status, s.contentType
	s.mu.Unlock()

	if req.Method != http.MethodPost {
		s.t.Errorf("method = %s, want POST", req.Method)
	}
	if ct := req.Header.Get("Content-Type"); ct != "application/dns-message" {
		s.t.Errorf("request content type = %q", ct)
	}
	if accept := req.Header.Get("Accept"); accept != "application/dns-message" {
		s.t.Errorf("accept = %q", accept)
	}
	body, err := io.ReadAll(io.LimitReader(req.Body, 1<<16))
	if err != nil {
		s.t.Errorf("read body: %v", err)
		return
	}
	id, host, qtype, err := doh.ParseQuery(body)
	if err != nil {
		s.t.Errorf("parse query: %v", err)
		return
	}
	rcode, recs := s.answer(host, qtype)
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(status)
	if status == http.StatusOK {
		w.Write(buildResponse(id, host, qtype, rcode, recs))
	}
}

func (s *dnsServer) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.requests
}

func (s *dnsServer) resolver() *doh.Resolver {
	r := doh.New(doh.Preset{Endpoint: s.srv.URL + "/dns-query", Bootstrap: []string{"127.0.0.1"}})
	client := s.srv.Client()
	client.Timeout = 5 * time.Second
	r.SetClient(client)
	return r
}

func addrStrings(addrs []netip.Addr) []string {
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.String())
	}
	return out
}

func TestLookupIPRoundTripAndCache(t *testing.T) {
	srv := newDNSServer(t, func(host string, qtype uint16) (uint16, []testRecord) {
		if host != "www.example.com" {
			return 3, nil
		}
		switch qtype {
		case doh.TypeA:
			return 0, []testRecord{
				cnameRecord("www.example.com", "cdn.example.net", 300),
				addrRecord("cdn.example.net", "93.184.216.34", 120),
			}
		case doh.TypeAAAA:
			return 0, []testRecord{addrRecord("www.example.com", "2001:db8::1", 60)}
		}
		return 0, nil
	})
	r := srv.resolver()

	addrs, err := r.LookupIP(context.Background(), "WWW.Example.com.")
	if err != nil {
		t.Fatalf("LookupIP: %v", err)
	}
	got := addrStrings(addrs)
	if len(got) != 2 || got[0] != "93.184.216.34" || got[1] != "2001:db8::1" {
		t.Fatalf("addrs = %v", got)
	}
	if srv.count() != 2 {
		t.Fatalf("requests = %d, want 2 (A and AAAA)", srv.count())
	}

	if _, err := r.LookupIP(context.Background(), "www.example.com"); err != nil {
		t.Fatalf("second LookupIP: %v", err)
	}
	if srv.count() != 2 {
		t.Fatalf("requests = %d, want cached second lookup", srv.count())
	}
	if r.CacheLen() != 1 {
		t.Fatalf("cache len = %d, want 1", r.CacheLen())
	}
}

func TestLookupIPNXDomainCachesNegative(t *testing.T) {
	srv := newDNSServer(t, func(string, uint16) (uint16, []testRecord) { return 3, nil })
	r := srv.resolver()

	if _, err := r.LookupIP(context.Background(), "nope.example"); !errors.Is(err, doh.ErrNoAddresses) {
		t.Fatalf("err = %v, want ErrNoAddresses", err)
	}
	if _, err := r.LookupIP(context.Background(), "nope.example"); !errors.Is(err, doh.ErrNoAddresses) {
		t.Fatalf("cached err = %v, want ErrNoAddresses", err)
	}
	if srv.count() != 2 {
		t.Fatalf("requests = %d, want 2 (negative answer cached)", srv.count())
	}
	addrs, ok := r.CacheGet("nope.example", time.Now())
	if !ok || len(addrs) != 0 {
		t.Fatalf("negative cache entry = %v, %v", addrs, ok)
	}
	if _, ok := r.CacheGet("nope.example", time.Now().Add(doh.NegativeTTL)); ok {
		t.Fatal("negative entry outlived 30s TTL")
	}
}

func TestLookupIPNoDataIsNegative(t *testing.T) {
	srv := newDNSServer(t, func(string, uint16) (uint16, []testRecord) { return 0, nil })
	r := srv.resolver()
	if _, err := r.LookupIP(context.Background(), "empty.example"); !errors.Is(err, doh.ErrNoAddresses) {
		t.Fatalf("err = %v, want ErrNoAddresses", err)
	}
}

func TestLookupIPPartialFailureStillResolves(t *testing.T) {
	srv := newDNSServer(t, func(host string, qtype uint16) (uint16, []testRecord) {
		if qtype == doh.TypeAAAA {
			return 2, nil // SERVFAIL for the AAAA half
		}
		return 0, []testRecord{addrRecord(host, "198.51.100.7", 90)}
	})
	r := srv.resolver()
	addrs, err := r.LookupIP(context.Background(), "half.example")
	if err != nil {
		t.Fatalf("LookupIP: %v", err)
	}
	if len(addrs) != 1 || addrs[0].String() != "198.51.100.7" {
		t.Fatalf("addrs = %v", addrStrings(addrs))
	}
}

func TestLookupIPServerFailuresAreNotCached(t *testing.T) {
	srv := newDNSServer(t, func(string, uint16) (uint16, []testRecord) { return 2, nil })
	r := srv.resolver()
	_, err := r.LookupIP(context.Background(), "fail.example")
	if err == nil || !strings.Contains(err.Error(), "rcode 2") {
		t.Fatalf("err = %v, want rcode 2", err)
	}
	if r.CacheLen() != 0 {
		t.Fatalf("cache len = %d, want 0", r.CacheLen())
	}
}

func TestLookupIPRejectsHTTPStatusAndContentType(t *testing.T) {
	srv := newDNSServer(t, func(string, uint16) (uint16, []testRecord) { return 0, nil })
	r := srv.resolver()

	srv.mu.Lock()
	srv.status = http.StatusServiceUnavailable
	srv.mu.Unlock()
	if _, err := r.LookupIP(context.Background(), "a.example"); err == nil || !strings.Contains(err.Error(), "unexpected status 503") {
		t.Fatalf("err = %v, want status error", err)
	}

	srv.mu.Lock()
	srv.status = http.StatusOK
	srv.contentType = "text/html"
	srv.mu.Unlock()
	if _, err := r.LookupIP(context.Background(), "b.example"); err == nil || !strings.Contains(err.Error(), "content type") {
		t.Fatalf("err = %v, want content type error", err)
	}
}

func TestLookupIPHonorsContext(t *testing.T) {
	srv := newDNSServer(t, func(host string, qtype uint16) (uint16, []testRecord) {
		return 0, []testRecord{addrRecord(host, "203.0.113.1", 60)}
	})
	r := srv.resolver()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.LookupIP(ctx, "slow.example"); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if r.CacheLen() != 0 {
		t.Fatalf("cache len = %d, want 0", r.CacheLen())
	}
}

func TestLookupIPLiteralsSkipTheNetwork(t *testing.T) {
	srv := newDNSServer(t, func(string, uint16) (uint16, []testRecord) { return 0, nil })
	r := srv.resolver()
	for _, literal := range []string{"192.0.2.10", "2001:db8::2", "[2001:db8::3]"} {
		addrs, err := r.LookupIP(context.Background(), literal)
		if err != nil || len(addrs) != 1 {
			t.Fatalf("LookupIP(%q) = %v, %v", literal, addrs, err)
		}
	}
	if srv.count() != 0 {
		t.Fatalf("requests = %d, want 0 for IP literals", srv.count())
	}
}

func TestLookupIPRejectsInvalidHost(t *testing.T) {
	srv := newDNSServer(t, func(string, uint16) (uint16, []testRecord) { return 0, nil })
	r := srv.resolver()
	for _, host := range []string{"", ".", "a..b", strings.Repeat("x", 64) + ".example"} {
		if _, err := r.LookupIP(context.Background(), host); err == nil {
			t.Errorf("LookupIP(%q): expected error", host)
		}
	}
	if srv.count() != 0 {
		t.Fatalf("requests = %d, want 0", srv.count())
	}
}

func TestLookupIPConcurrent(t *testing.T) {
	srv := newDNSServer(t, func(host string, qtype uint16) (uint16, []testRecord) {
		if qtype == doh.TypeAAAA {
			return 0, nil
		}
		return 0, []testRecord{addrRecord(host, "203.0.113.9", 300)}
	})
	r := srv.resolver()
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			host := "h" + string(rune('a'+i%4)) + ".example"
			if _, err := r.LookupIP(context.Background(), host); err != nil {
				t.Errorf("LookupIP: %v", err)
			}
		}()
	}
	wg.Wait()
}

func TestPresets(t *testing.T) {
	want := map[string]doh.Preset{
		"cloudflare": {Endpoint: "https://cloudflare-dns.com/dns-query", Bootstrap: []string{"1.1.1.1", "1.0.0.1"}},
		"google":     {Endpoint: "https://dns.google/dns-query", Bootstrap: []string{"8.8.8.8", "8.8.4.4"}},
		"quad9":      {Endpoint: "https://dns.quad9.net/dns-query", Bootstrap: []string{"9.9.9.9", "149.112.112.112"}},
		"opendns":    {Endpoint: "https://doh.opendns.com/dns-query", Bootstrap: []string{"208.67.222.222", "208.67.220.220"}},
	}
	got := Presets(t)
	if len(got) != len(want) {
		t.Fatalf("preset count = %d, want %d", len(got), len(want))
	}
	for name, expected := range want {
		actual, ok := got[name]
		if !ok {
			t.Fatalf("missing preset %q", name)
		}
		if actual.Endpoint != expected.Endpoint {
			t.Errorf("%s endpoint = %q, want %q", name, actual.Endpoint, expected.Endpoint)
		}
		if strings.Join(actual.Bootstrap, ",") != strings.Join(expected.Bootstrap, ",") {
			t.Errorf("%s bootstrap = %v, want %v", name, actual.Bootstrap, expected.Bootstrap)
		}
		if !strings.HasPrefix(actual.Endpoint, "https://") {
			t.Errorf("%s endpoint is not https", name)
		}
		for _, ip := range actual.Bootstrap {
			if _, err := netip.ParseAddr(ip); err != nil {
				t.Errorf("%s bootstrap %q is not an IP literal", name, ip)
			}
		}
	}
}

// Presets returns a fresh map; mutating it must not affect later callers.
func Presets(t *testing.T) map[string]doh.Preset {
	t.Helper()
	first := doh.Presets()
	first["cloudflare"] = doh.Preset{Endpoint: "https://evil.example/"}
	delete(first, "google")
	second := doh.Presets()
	if second["cloudflare"].Endpoint != "https://cloudflare-dns.com/dns-query" || len(second) != 4 {
		t.Fatalf("Presets() is not independent per call: %v", second)
	}
	return second
}
