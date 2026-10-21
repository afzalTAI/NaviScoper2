package doh_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net/http"
	"net/netip"
	"testing"

	"naviscopereborn/internal/doh"
)

// buildQuery encodes a client query independently of the package under test.
func buildQuery(id uint16, name string, qtype uint16, rd bool) []byte {
	msg := make([]byte, 12)
	binary.BigEndian.PutUint16(msg[0:2], id)
	if rd {
		binary.BigEndian.PutUint16(msg[2:4], doh.FlagRD)
	}
	binary.BigEndian.PutUint16(msg[4:6], 1)
	msg = append(msg, encodeTestName(name)...)
	msg = binary.BigEndian.AppendUint16(msg, qtype)
	msg = binary.BigEndian.AppendUint16(msg, doh.ClassIN)
	return msg
}

// questionBytes returns the question section of a message.
func questionBytes(t *testing.T, msg []byte) []byte {
	t.Helper()
	if len(msg) < 12 {
		t.Fatalf("message too short: %d bytes", len(msg))
	}
	off := 12
	for off < len(msg) && msg[off] != 0 {
		if msg[off]&0xC0 != 0 {
			t.Fatalf("compressed name at offset %d", off)
		}
		off += 1 + int(msg[off])
	}
	if off+5 > len(msg) {
		t.Fatal("truncated question section")
	}
	return msg[12 : off+5]
}

// checkReplyShape asserts the parts every reply must share with its query.
func checkReplyShape(t *testing.T, query, reply []byte, wantRcode uint16, wantAnswers int) doh.Message {
	t.Helper()
	m, err := doh.ParseResponse(reply)
	if err != nil {
		t.Fatalf("ParseResponse: %v", err)
	}
	wantID := binary.BigEndian.Uint16(query[0:2])
	if m.ID != wantID {
		t.Errorf("id = %#04x, want %#04x", m.ID, wantID)
	}
	if m.Flags&doh.FlagQR == 0 {
		t.Error("QR not set in reply")
	}
	if m.Flags&doh.FlagRA == 0 {
		t.Error("RA not set in reply")
	}
	wantRD := binary.BigEndian.Uint16(query[2:4]) & doh.FlagRD
	if m.Flags&doh.FlagRD != wantRD {
		t.Errorf("RD = %#04x, want %#04x", m.Flags&doh.FlagRD, wantRD)
	}
	if got := m.Flags & doh.RcodeMask; got != wantRcode {
		t.Errorf("rcode = %d, want %d", got, wantRcode)
	}
	if m.Questions != 1 {
		t.Errorf("questions = %d, want 1", m.Questions)
	}
	if got, want := questionBytes(t, reply), questionBytes(t, query); !bytes.Equal(got, want) {
		t.Errorf("question echo = %x, want %x", got, want)
	}
	if len(m.Answers) != wantAnswers {
		t.Fatalf("answers = %d, want %d", len(m.Answers), wantAnswers)
	}
	return m
}

func checkAddrAnswer(t *testing.T, a doh.Answer, qname string, qtype uint16, want string) {
	t.Helper()
	if a.Name != qname {
		t.Errorf("answer name = %q, want %q", a.Name, qname)
	}
	if a.Type != qtype {
		t.Errorf("answer type = %d, want %d", a.Type, qtype)
	}
	if a.Class != doh.ClassIN {
		t.Errorf("answer class = %d, want %d", a.Class, doh.ClassIN)
	}
	if a.TTL != doh.AnswerTTL {
		t.Errorf("answer ttl = %d, want %d", a.TTL, doh.AnswerTTL)
	}
	addr, ok := netip.AddrFromSlice(a.Data)
	if !ok {
		t.Fatalf("rdata %x is not an address", a.Data)
	}
	if got := addr.Unmap().String(); got != want {
		t.Errorf("rdata = %s, want %s", got, want)
	}
	wantLen := 4
	if qtype == doh.TypeAAAA {
		wantLen = 16
	}
	if len(a.Data) != wantLen {
		t.Errorf("rdlength = %d, want %d", len(a.Data), wantLen)
	}
}

func dualStackServer(t *testing.T) *dnsServer {
	t.Helper()
	return newDNSServer(t, func(host string, qtype uint16) (uint16, []testRecord) {
		if host != "www.example.com" {
			return doh.RcodeNXDomain, nil
		}
		switch qtype {
		case doh.TypeA:
			return doh.RcodeNoError, []testRecord{
				addrRecord(host, "93.184.216.34", 300),
				addrRecord(host, "93.184.216.35", 300),
			}
		default:
			return doh.RcodeNoError, []testRecord{addrRecord(host, "2001:db8::1", 300)}
		}
	})
}

func TestResolveWireARoundTrip(t *testing.T) {
	srv := dualStackServer(t)
	r := srv.resolver()

	// Mixed case is preserved byte for byte in the echoed question.
	query := buildQuery(0xBEEF, "WWW.Example.com", doh.TypeA, true)
	reply, err := doh.ResolveWire(context.Background(), r, query, nil)
	if err != nil {
		t.Fatalf("ResolveWire: %v", err)
	}
	m := checkReplyShape(t, query, reply, doh.RcodeNoError, 2)
	if m.QType != doh.TypeA || m.QClass != doh.ClassIN {
		t.Errorf("question = type %d class %d", m.QType, m.QClass)
	}
	checkAddrAnswer(t, m.Answers[0], "www.example.com.", doh.TypeA, "93.184.216.34")
	checkAddrAnswer(t, m.Answers[1], "www.example.com.", doh.TypeA, "93.184.216.35")
	// The answer NAME must be the 0xC00C pointer back to the question.
	qlen := len(questionBytes(t, reply))
	if ptr := reply[12+qlen : 12+qlen+2]; ptr[0] != 0xC0 || ptr[1] != 0x0C {
		t.Errorf("answer name = %x, want c00c pointer", ptr)
	}
}

func TestResolveWireAAAAFamily(t *testing.T) {
	srv := dualStackServer(t)
	r := srv.resolver()

	query := buildQuery(0x0101, "www.example.com", doh.TypeAAAA, true)
	reply, err := doh.ResolveWire(context.Background(), r, query, nil)
	if err != nil {
		t.Fatalf("ResolveWire: %v", err)
	}
	m := checkReplyShape(t, query, reply, doh.RcodeNoError, 1)
	checkAddrAnswer(t, m.Answers[0], "www.example.com.", doh.TypeAAAA, "2001:db8::1")
}

func TestResolveWireRecursionNotDesired(t *testing.T) {
	srv := dualStackServer(t)
	r := srv.resolver()

	query := buildQuery(0x0202, "www.example.com", doh.TypeA, false)
	reply, err := doh.ResolveWire(context.Background(), r, query, nil)
	if err != nil {
		t.Fatalf("ResolveWire: %v", err)
	}
	checkReplyShape(t, query, reply, doh.RcodeNoError, 2)
}

// failTransport fails every request, proving that a code path never dials out.
type failTransport struct{ t *testing.T }

func (f failTransport) RoundTrip(*http.Request) (*http.Response, error) {
	f.t.Error("unexpected HTTP request")
	return nil, errors.New("transport must not be used")
}

func TestResolveWireBlockedNeverResolves(t *testing.T) {
	srv := dualStackServer(t)
	r := srv.resolver()
	r.SetClient(&http.Client{Transport: failTransport{t: t}})

	var seen []string
	blocked := func(name string) bool {
		seen = append(seen, name)
		return true
	}
	query := buildQuery(0x1234, "Ads.Example.NET", doh.TypeA, true)
	reply, err := doh.ResolveWire(context.Background(), r, query, blocked)
	if err != nil {
		t.Fatalf("ResolveWire: %v", err)
	}
	checkReplyShape(t, query, reply, doh.RcodeNXDomain, 0)
	if len(seen) != 1 || seen[0] != "ads.example.net" {
		t.Errorf("blocked callback saw %v, want [ads.example.net]", seen)
	}
	if srv.count() != 0 {
		t.Errorf("fixture saw %d requests, want 0", srv.count())
	}
}

func TestResolveWireBlockedCallbackFalseResolves(t *testing.T) {
	srv := dualStackServer(t)
	r := srv.resolver()

	query := buildQuery(0x4321, "www.example.com", doh.TypeA, true)
	reply, err := doh.ResolveWire(context.Background(), r, query, func(string) bool { return false })
	if err != nil {
		t.Fatalf("ResolveWire: %v", err)
	}
	checkReplyShape(t, query, reply, doh.RcodeNoError, 2)
}

func TestResolveWireNXDomainPropagates(t *testing.T) {
	srv := newDNSServer(t, func(string, uint16) (uint16, []testRecord) {
		return doh.RcodeNXDomain, nil
	})
	r := srv.resolver()

	query := buildQuery(0x5555, "nope.example", doh.TypeA, true)
	reply, err := doh.ResolveWire(context.Background(), r, query, nil)
	if err != nil {
		t.Fatalf("ResolveWire: %v", err)
	}
	checkReplyShape(t, query, reply, doh.RcodeNXDomain, 0)

	// The same answer must come out of the negative cache.
	before := srv.count()
	reply, err = doh.ResolveWire(context.Background(), r, query, nil)
	if err != nil {
		t.Fatalf("cached ResolveWire: %v", err)
	}
	checkReplyShape(t, query, reply, doh.RcodeNXDomain, 0)
	if srv.count() != before {
		t.Errorf("cached query hit the network: %d requests, want %d", srv.count(), before)
	}
}

func TestResolveWireNoDataIsNoError(t *testing.T) {
	srv := newDNSServer(t, func(string, uint16) (uint16, []testRecord) {
		return doh.RcodeNoError, nil
	})
	r := srv.resolver()

	query := buildQuery(0x6666, "empty.example", doh.TypeA, true)
	reply, err := doh.ResolveWire(context.Background(), r, query, nil)
	if err != nil {
		t.Fatalf("ResolveWire: %v", err)
	}
	checkReplyShape(t, query, reply, doh.RcodeNoError, 0)
}

// A name that only has AAAA records answers an A query with NOERROR and no
// answer records rather than leaking the IPv6 address into an A response.
func TestResolveWireWrongFamilyIsEmpty(t *testing.T) {
	srv := newDNSServer(t, func(host string, qtype uint16) (uint16, []testRecord) {
		if qtype == doh.TypeAAAA {
			return doh.RcodeNoError, []testRecord{addrRecord(host, "2001:db8::2", 120)}
		}
		return doh.RcodeNoError, nil
	})
	r := srv.resolver()

	query := buildQuery(0x7777, "v6only.example", doh.TypeA, true)
	reply, err := doh.ResolveWire(context.Background(), r, query, nil)
	if err != nil {
		t.Fatalf("ResolveWire: %v", err)
	}
	checkReplyShape(t, query, reply, doh.RcodeNoError, 0)
}

func TestResolveWireRejectsMalformedQueries(t *testing.T) {
	good := buildQuery(0x0001, "www.example.com", doh.TypeA, true)

	twoQuestions := append([]byte(nil), good...)
	binary.BigEndian.PutUint16(twoQuestions[4:6], 2)
	twoQuestions = append(twoQuestions, encodeTestName("www.example.org")...)
	twoQuestions = binary.BigEndian.AppendUint16(twoQuestions, doh.TypeA)
	twoQuestions = binary.BigEndian.AppendUint16(twoQuestions, doh.ClassIN)

	zeroQuestions := append([]byte(nil), good...)
	binary.BigEndian.PutUint16(zeroQuestions[4:6], 0)

	mxQuery := buildQuery(0x0002, "www.example.com", 15, true)
	cnameQuery := buildQuery(0x0003, "www.example.com", doh.TypeCNAME, true)

	chaosQuery := buildQuery(0x0004, "www.example.com", doh.TypeA, true)
	binary.BigEndian.PutUint16(chaosQuery[len(chaosQuery)-2:], 3) // CH class

	isResponse := append([]byte(nil), good...)
	binary.BigEndian.PutUint16(isResponse[2:4], doh.FlagQR)

	notifyOpcode := append([]byte(nil), good...)
	binary.BigEndian.PutUint16(notifyOpcode[2:4], doh.FlagRD|(4<<11))

	compressed := make([]byte, 12)
	binary.BigEndian.PutUint16(compressed[0:2], 0x0005)
	binary.BigEndian.PutUint16(compressed[2:4], doh.FlagRD)
	binary.BigEndian.PutUint16(compressed[4:6], 1)
	compressed = append(compressed, 0xC0, 0x04) // pointer into the header
	compressed = binary.BigEndian.AppendUint16(compressed, doh.TypeA)
	compressed = binary.BigEndian.AppendUint16(compressed, doh.ClassIN)

	rootQuery := make([]byte, 12)
	binary.BigEndian.PutUint16(rootQuery[4:6], 1)
	rootQuery = append(rootQuery, 0)
	rootQuery = binary.BigEndian.AppendUint16(rootQuery, doh.TypeA)
	rootQuery = binary.BigEndian.AppendUint16(rootQuery, doh.ClassIN)

	cases := []struct {
		name  string
		query []byte
	}{
		{"empty", nil},
		{"short header", good[:8]},
		{"truncated name", good[:14]},
		{"truncated question", good[:len(good)-3]},
		{"zero questions", zeroQuestions},
		{"two questions", twoQuestions},
		{"qtype MX", mxQuery},
		{"qtype CNAME", cnameQuery},
		{"class CH", chaosQuery},
		{"response not query", isResponse},
		{"opcode notify", notifyOpcode},
		{"compressed question name", compressed},
		{"root name", rootQuery},
	}

	// Any lookup attempt is a bug: malformed queries must be rejected before
	// the resolver is used.
	srv := dualStackServer(t)
	r := srv.resolver()
	r.SetClient(&http.Client{Transport: failTransport{t: t}})

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reply, err := doh.ResolveWire(context.Background(), r, tc.query, nil)
			if err == nil {
				t.Fatalf("ResolveWire accepted %s: %x", tc.name, reply)
			}
			if reply != nil {
				t.Errorf("reply = %x, want nil on error", reply)
			}
		})
	}
	if srv.count() != 0 {
		t.Errorf("fixture saw %d requests, want 0", srv.count())
	}
}

func TestResolveWireNilResolver(t *testing.T) {
	if _, err := doh.ResolveWire(context.Background(), nil, buildQuery(1, "a.test", doh.TypeA, true), nil); err == nil {
		t.Fatal("nil resolver accepted")
	}
}

func TestResolveWireTransportErrorIsReported(t *testing.T) {
	srv := dualStackServer(t)
	r := srv.resolver()
	r.SetClient(&http.Client{Transport: errTransport{}})

	if _, err := doh.ResolveWire(context.Background(), r, buildQuery(9, "www.example.com", doh.TypeA, true), nil); err == nil {
		t.Fatal("transport failure not reported")
	}
}

type errTransport struct{}

func (errTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("dial failed")
}
