package doh

import (
	"bytes"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func TestEncodeQueryGoldenBytes(t *testing.T) {
	got, err := encodeQuery(0x1234, "example.com", typeA)
	if err != nil {
		t.Fatalf("encodeQuery: %v", err)
	}
	want := []byte{
		0x12, 0x34, // id
		0x01, 0x00, // flags: RD only
		0x00, 0x01, // qdcount
		0x00, 0x00, // ancount
		0x00, 0x00, // nscount
		0x00, 0x00, // arcount
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,
		0x00, 0x01, // qtype A
		0x00, 0x01, // qclass IN
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("query bytes:\ngot  %x\nwant %x", got, want)
	}
}

func TestEncodeQueryAAAATrailingDot(t *testing.T) {
	got, err := encodeQuery(0x0001, "a.b.", typeAAAA)
	if err != nil {
		t.Fatalf("encodeQuery: %v", err)
	}
	want := []byte{
		0x00, 0x01,
		0x01, 0x00,
		0x00, 0x01,
		0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00,
		0x01, 'a',
		0x01, 'b',
		0x00,
		0x00, 0x1c, // qtype AAAA
		0x00, 0x01,
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("query bytes:\ngot  %x\nwant %x", got, want)
	}
}

func TestEncodeNameRejectsInvalid(t *testing.T) {
	cases := map[string]string{
		"empty":        "",
		"root only":    ".",
		"empty label":  "a..b",
		"long label":   strings.Repeat("x", 64) + ".com",
		"long name":    strings.Repeat("abcdefgh.", 30) + "com",
		"space":        "exa mple.com",
		"control byte": "exa\x00mple.com",
		"non ascii":    "exämple.com",
	}
	for name, host := range cases {
		if _, err := encodeName(host); err == nil {
			t.Errorf("%s: expected error for %q", name, host)
		}
	}
}

// response builds a DNS message from literal sections.
func response(t *testing.T, header []byte, sections ...[]byte) []byte {
	t.Helper()
	msg := append([]byte(nil), header...)
	for _, s := range sections {
		msg = append(msg, s...)
	}
	return msg
}

func header(id, flags uint16, qd, an int) []byte {
	return []byte{
		byte(id >> 8), byte(id),
		byte(flags >> 8), byte(flags),
		byte(qd >> 8), byte(qd),
		byte(an >> 8), byte(an),
		0, 0,
		0, 0,
	}
}

// question returns the wire bytes of "www.example.com IN A" starting at offset
// 12, so that "example.com" lives at offset 16.
func question(qtype uint16) []byte {
	q := []byte{
		0x03, 'w', 'w', 'w',
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,
	}
	return append(q, 0x00, byte(qtype), 0x00, 0x01)
}

// compressedCNAMEFixture answers www.example.com with a CNAME to
// cdn.example.com (compressed against the question) and an A record whose owner
// name is a pointer into the CNAME rdata.
func compressedCNAMEFixture(t *testing.T, id uint16) []byte {
	t.Helper()
	cname := []byte{
		0xC0, 0x0C, // name -> offset 12 (www.example.com)
		0x00, 0x05, // type CNAME
		0x00, 0x01, // class IN
		0x00, 0x00, 0x01, 0x2C, // ttl 300
		0x00, 0x06, // rdlength
		0x03, 'c', 'd', 'n', 0xC0, 0x10, // cdn + pointer to offset 16 (example.com)
	}
	a := []byte{
		0xC0, 0x2D, // name -> offset 45 (the "cdn.example.com" rdata)
		0x00, 0x01, // type A
		0x00, 0x01, // class IN
		0x00, 0x00, 0x00, 0x3C, // ttl 60
		0x00, 0x04,
		93, 184, 216, 34,
	}
	msg := response(t, header(id, flagQR|flagRD, 1, 2), question(typeA), cname, a)
	if msg[45] != 0x03 || string(msg[46:49]) != "cdn" {
		t.Fatalf("fixture offsets drifted: byte 45 = %#x", msg[45])
	}
	return msg
}

func TestDecodeResponseFollowsCompressedCNAME(t *testing.T) {
	msg := compressedCNAMEFixture(t, 0xABCD)
	addrs, ttl, err := decodeResponse(msg, 0xABCD, "www.example.com", typeA)
	if err != nil {
		t.Fatalf("decodeResponse: %v", err)
	}
	want := []netip.Addr{netip.MustParseAddr("93.184.216.34")}
	if len(addrs) != 1 || addrs[0] != want[0] {
		t.Fatalf("addrs = %v, want %v", addrs, want)
	}
	if ttl != 60 {
		t.Fatalf("ttl = %d, want 60 (smallest on the chain)", ttl)
	}
}

func TestDecodeResponseAAAAAndMixedTypes(t *testing.T) {
	aaaa := []byte{
		0xC0, 0x0C,
		0x00, 0x1C, // AAAA
		0x00, 0x01,
		0x00, 0x00, 0x00, 0x1E, // ttl 30
		0x00, 0x10,
		0x26, 0x06, 0x28, 0x00, 0x02, 0x20, 0x00, 0x01,
		0x02, 0x48, 0x18, 0x93, 0x25, 0xc8, 0x19, 0x46,
	}
	ipv4 := []byte{
		0xC0, 0x0C,
		0x00, 0x01, // A, must be ignored for an AAAA query
		0x00, 0x01,
		0x00, 0x00, 0x00, 0x05,
		0x00, 0x04,
		1, 2, 3, 4,
	}
	msg := response(t, header(0x0007, flagQR, 1, 2), question(typeAAAA), aaaa, ipv4)
	addrs, ttl, err := decodeResponse(msg, 0x0007, "WWW.Example.COM", typeAAAA)
	if err != nil {
		t.Fatalf("decodeResponse: %v", err)
	}
	if len(addrs) != 1 || addrs[0] != netip.MustParseAddr("2606:2800:220:1:248:1893:25c8:1946") {
		t.Fatalf("addrs = %v", addrs)
	}
	if ttl != 30 {
		t.Fatalf("ttl = %d, want 30", ttl)
	}
}

func TestDecodeResponseNXDomain(t *testing.T) {
	msg := response(t, header(0x0042, flagQR|rcodeNXDomain, 1, 0), question(typeA))
	_, _, err := decodeResponse(msg, 0x0042, "www.example.com", typeA)
	if !errors.Is(err, ErrNXDomain) {
		t.Fatalf("err = %v, want ErrNXDomain", err)
	}
}

func TestDecodeResponseNoDataIsEmpty(t *testing.T) {
	msg := response(t, header(0x0042, flagQR, 1, 0), question(typeA))
	addrs, ttl, err := decodeResponse(msg, 0x0042, "www.example.com", typeA)
	if err != nil {
		t.Fatalf("decodeResponse: %v", err)
	}
	if len(addrs) != 0 || ttl != 0 {
		t.Fatalf("addrs = %v, ttl = %d, want empty", addrs, ttl)
	}
}

func TestDecodeResponseRejectsMalformed(t *testing.T) {
	good := compressedCNAMEFixture(t, 0xABCD)

	truncatedRecord := append([]byte(nil), good[:len(good)-3]...)

	badPointer := response(t, header(0xABCD, flagQR, 1, 0))
	badPointer = append(badPointer, 0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01) // name points at itself

	forwardPointer := response(t, header(0xABCD, flagQR, 1, 0))
	forwardPointer = append(forwardPointer, 0xC0, 0x20, 0x00, 0x01, 0x00, 0x01)

	badLabelLen := response(t, header(0xABCD, flagQR, 1, 0))
	badLabelLen = append(badLabelLen, 0x80, 'x', 0x00, 0x00, 0x01, 0x00, 0x01)

	wrongQuestion := response(t, header(0xABCD, flagQR, 1, 0), question(typeAAAA))

	tests := []struct {
		name string
		msg  []byte
		id   uint16
		want string
	}{
		{"short header", good[:8], 0xABCD, "shorter than header"},
		{"truncated record", truncatedRecord, 0xABCD, "out of range"},
		{"truncated question", good[:20], 0xABCD, "truncated"},
		{"self pointer", badPointer, 0xABCD, "forward compression pointer"},
		{"forward pointer", forwardPointer, 0xABCD, "forward compression pointer"},
		{"invalid label length", badLabelLen, 0xABCD, "invalid label length"},
		{"wrong id", good, 0x0001, "id mismatch"},
		{"question mismatch", wrongQuestion, 0xABCD, "does not match"},
	}
	for _, tc := range tests {
		_, _, err := decodeResponse(tc.msg, tc.id, "www.example.com", typeA)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want substring %q", tc.name, err, tc.want)
		}
	}
}

func TestDecodeResponseRejectsFlagsAndRcodes(t *testing.T) {
	for _, tc := range []struct {
		name  string
		flags uint16
		want  string
	}{
		{"not a reply", flagRD, "not a reply"},
		{"truncated bit", flagQR | flagTC, "truncated response"},
		{"servfail", flagQR | 2, "rcode 2"},
		{"refused", flagQR | 5, "rcode 5"},
		{"notimp", flagQR | 4, "rcode 4"},
	} {
		msg := response(t, header(0x1111, tc.flags, 1, 0), question(typeA))
		_, _, err := decodeResponse(msg, 0x1111, "www.example.com", typeA)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want substring %q", tc.name, err, tc.want)
		}
	}
}

func TestParseNameRejectsTooManyPointerHops(t *testing.T) {
	// A backwards chain of pointers terminating at the root label: legal per
	// byte, but deep enough to trip the hop limit.
	msg := make([]byte, headerLen)
	msg = append(msg, 0x00) // root label at offset 12
	prev := headerLen
	last := 0
	for range maxPointerHops + 8 {
		last = len(msg)
		msg = append(msg, 0xC0|byte(prev>>8), byte(prev))
		prev = last
	}
	if _, _, err := parseName(msg, last); err == nil || !strings.Contains(err.Error(), "compression pointer loop") {
		t.Fatalf("err = %v, want compression pointer loop", err)
	}
	// A short chain is still accepted.
	if name, _, err := parseName(msg, headerLen+1); err != nil || name != "." {
		t.Fatalf("name = %q, err = %v, want root", name, err)
	}
}

func TestCollectAddrsStopsOnCNAMELoop(t *testing.T) {
	answers := []record{
		{name: "a.test.", rtype: typeCNAME, class: classIN, ttl: 10, cname: "b.test.", hasCNA: true},
		{name: "b.test.", rtype: typeCNAME, class: classIN, ttl: 10, cname: "a.test.", hasCNA: true},
	}
	addrs, ttl := collectAddrs(answers, "a.test", typeA)
	if len(addrs) != 0 || ttl != 0 {
		t.Fatalf("addrs = %v, ttl = %d, want none", addrs, ttl)
	}
}

func TestCollectAddrsIgnoresForeignRecords(t *testing.T) {
	answers := []record{
		{name: "other.test.", rtype: typeA, class: classIN, ttl: 10, data: []byte{9, 9, 9, 9}},
		{name: "a.test.", rtype: typeA, class: 3, ttl: 10, data: []byte{8, 8, 8, 8}},
		{name: "a.test.", rtype: typeA, class: classIN, ttl: 10, data: []byte{1, 1, 1}},
		{name: "a.test.", rtype: typeA, class: classIN, ttl: 77, data: []byte{7, 7, 7, 7}},
	}
	addrs, ttl := collectAddrs(answers, "a.test", typeA)
	if len(addrs) != 1 || addrs[0] != netip.MustParseAddr("7.7.7.7") || ttl != 77 {
		t.Fatalf("addrs = %v, ttl = %d", addrs, ttl)
	}
}
