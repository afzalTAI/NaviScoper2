package doh

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// Hand-rolled RFC 1035 message handling. Only the subset needed for A/AAAA
// lookups is implemented: one question per query, answer section parsing with
// name compression and CNAME chains.
const (
	typeA     uint16 = 1
	typeCNAME uint16 = 5
	typeAAAA  uint16 = 28

	classIN uint16 = 1

	headerLen      = 12
	maxNameLen     = 255
	maxLabelLen    = 63
	maxPointerHops = 32

	flagQR uint16 = 0x8000
	flagTC uint16 = 0x0200
	flagRD uint16 = 0x0100

	rcodeMask     uint16 = 0x000F
	rcodeNoError  uint16 = 0
	rcodeNXDomain uint16 = 3
)

// errNXDomain reports an authoritative "name does not exist" answer. It is a
// normal, cacheable outcome rather than a transport failure.
var errNXDomain = errors.New("doh: name does not exist")

// record is one resource record from the answer section. cname is set only for
// CNAME records and already has compression pointers expanded.
type record struct {
	name   string
	rtype  uint16
	class  uint16
	ttl    uint32
	data   []byte
	cname  string
	hasCNA bool
}

// encodeName writes host as a sequence of length-prefixed labels terminated by
// the root label.
func encodeName(host string) ([]byte, error) {
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return nil, errors.New("doh: empty host name")
	}
	if len(host)+2 > maxNameLen {
		return nil, errors.New("doh: host name too long")
	}
	out := make([]byte, 0, len(host)+2)
	for _, label := range strings.Split(host, ".") {
		if label == "" {
			return nil, errors.New("doh: empty label in host name")
		}
		if len(label) > maxLabelLen {
			return nil, errors.New("doh: label longer than 63 bytes")
		}
		for _, c := range label {
			if c <= 0x20 || c >= 0x7f {
				return nil, errors.New("doh: host name contains invalid byte")
			}
		}
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	return append(out, 0), nil
}

// encodeQuery builds a standard recursive query with a single question.
func encodeQuery(id uint16, host string, qtype uint16) ([]byte, error) {
	qname, err := encodeName(host)
	if err != nil {
		return nil, err
	}
	msg := make([]byte, headerLen, headerLen+len(qname)+4)
	binary.BigEndian.PutUint16(msg[0:2], id)
	binary.BigEndian.PutUint16(msg[2:4], flagRD)
	binary.BigEndian.PutUint16(msg[4:6], 1)
	msg = append(msg, qname...)
	msg = binary.BigEndian.AppendUint16(msg, qtype)
	msg = binary.BigEndian.AppendUint16(msg, classIN)
	return msg, nil
}

// parseName expands the name starting at off and returns the offset of the
// first byte after the name in the enclosing record. Compression pointers must
// point strictly backwards and are additionally bounded by maxPointerHops.
func parseName(msg []byte, off int) (string, int, error) {
	if off < 0 || off >= len(msg) {
		return "", 0, errors.New("doh: name offset out of range")
	}
	var name strings.Builder
	next := -1
	hops := 0
	pos := off
	for {
		if pos >= len(msg) {
			return "", 0, errors.New("doh: truncated name")
		}
		b := msg[pos]
		switch {
		case b == 0:
			pos++
			if next < 0 {
				next = pos
			}
			if name.Len() == 0 {
				return ".", next, nil
			}
			return name.String(), next, nil
		case b&0xC0 == 0xC0:
			if pos+1 >= len(msg) {
				return "", 0, errors.New("doh: truncated compression pointer")
			}
			target := int(b&0x3F)<<8 | int(msg[pos+1])
			if target >= pos {
				return "", 0, errors.New("doh: forward compression pointer")
			}
			hops++
			if hops > maxPointerHops {
				return "", 0, errors.New("doh: compression pointer loop")
			}
			if next < 0 {
				next = pos + 2
			}
			pos = target
		case b&0xC0 == 0:
			length := int(b)
			if pos+1+length > len(msg) {
				return "", 0, errors.New("doh: truncated label")
			}
			if name.Len()+length+1 > maxNameLen {
				return "", 0, errors.New("doh: name longer than 255 bytes")
			}
			name.WriteString(strings.ToLower(string(msg[pos+1 : pos+1+length])))
			name.WriteByte('.')
			pos += 1 + length
		default:
			return "", 0, errors.New("doh: invalid label length")
		}
	}
}

// message is the decoded subset of a DNS response that this package needs.
type message struct {
	id        uint16
	flags     uint16
	qname     string
	qtype     uint16
	qclass    uint16
	questions int
	answers   []record
}

func parseMessage(msg []byte) (*message, error) {
	if len(msg) < headerLen {
		return nil, errors.New("doh: response shorter than header")
	}
	m := &message{
		id:        binary.BigEndian.Uint16(msg[0:2]),
		flags:     binary.BigEndian.Uint16(msg[2:4]),
		questions: int(binary.BigEndian.Uint16(msg[4:6])),
	}
	anCount := int(binary.BigEndian.Uint16(msg[6:8]))
	off := headerLen
	for i := range m.questions {
		name, next, err := parseName(msg, off)
		if err != nil {
			return nil, err
		}
		if next+4 > len(msg) {
			return nil, errors.New("doh: truncated question section")
		}
		if i == 0 {
			m.qname = name
			m.qtype = binary.BigEndian.Uint16(msg[next : next+2])
			m.qclass = binary.BigEndian.Uint16(msg[next+2 : next+4])
		}
		off = next + 4
	}
	m.answers = make([]record, 0, min(anCount, 64))
	for range anCount {
		rec, next, err := parseRecord(msg, off)
		if err != nil {
			return nil, err
		}
		m.answers = append(m.answers, rec)
		off = next
	}
	return m, nil
}

func parseRecord(msg []byte, off int) (record, int, error) {
	name, next, err := parseName(msg, off)
	if err != nil {
		return record{}, 0, err
	}
	if next+10 > len(msg) {
		return record{}, 0, errors.New("doh: truncated resource record")
	}
	rec := record{
		name:  name,
		rtype: binary.BigEndian.Uint16(msg[next : next+2]),
		class: binary.BigEndian.Uint16(msg[next+2 : next+4]),
		ttl:   binary.BigEndian.Uint32(msg[next+4 : next+8]),
	}
	rdLen := int(binary.BigEndian.Uint16(msg[next+8 : next+10]))
	rdStart := next + 10
	if rdStart+rdLen > len(msg) {
		return record{}, 0, errors.New("doh: resource record data out of range")
	}
	rec.data = msg[rdStart : rdStart+rdLen]
	if rec.rtype == typeCNAME {
		cname, cnext, err := parseName(msg, rdStart)
		if err != nil {
			return record{}, 0, err
		}
		if cnext > rdStart+rdLen {
			return record{}, 0, errors.New("doh: CNAME data overruns record")
		}
		rec.cname = cname
		rec.hasCNA = true
	}
	return rec, rdStart + rdLen, nil
}

// fqdn returns the lowercase, dot-terminated form used for record comparison.
func fqdn(host string) string {
	host = strings.ToLower(host)
	if strings.HasSuffix(host, ".") {
		return host
	}
	return host + "."
}

func addrFromRData(data []byte, rtype uint16) (netip.Addr, bool) {
	switch rtype {
	case typeA:
		if len(data) != 4 {
			return netip.Addr{}, false
		}
		return netip.AddrFrom4([4]byte(data)), true
	case typeAAAA:
		if len(data) != 16 {
			return netip.Addr{}, false
		}
		return netip.AddrFrom16([16]byte(data)).Unmap(), true
	default:
		return netip.Addr{}, false
	}
}

// collectAddrs walks the CNAME chain inside the answer section and returns the
// addresses of qtype reachable from qname plus the smallest TTL seen on the
// path. Records that do not belong to the chain are ignored.
func collectAddrs(answers []record, qname string, qtype uint16) ([]netip.Addr, uint32) {
	target := fqdn(qname)
	seen := make(map[string]bool, len(answers)+1)
	var addrs []netip.Addr
	ttl := ^uint32(0)
	for range len(answers) + 1 {
		if seen[target] {
			break
		}
		seen[target] = true
		next := ""
		for _, rec := range answers {
			if rec.class != classIN || rec.name != target {
				continue
			}
			switch rec.rtype {
			case qtype:
				if addr, ok := addrFromRData(rec.data, qtype); ok {
					addrs = append(addrs, addr)
					ttl = minTTLOf(ttl, rec.ttl)
				}
			case typeCNAME:
				if rec.hasCNA && next == "" {
					next = rec.cname
					ttl = minTTLOf(ttl, rec.ttl)
				}
			}
		}
		if len(addrs) > 0 || next == "" {
			break
		}
		target = next
	}
	if len(addrs) == 0 {
		return nil, 0
	}
	return addrs, ttl
}

func minTTLOf(a, b uint32) uint32 {
	if b < a {
		return b
	}
	return a
}

// decodeResponse validates a response against the question that produced it
// and extracts the answer addresses. A NXDOMAIN answer is reported as
// errNXDomain.
func decodeResponse(msg []byte, id uint16, host string, qtype uint16) ([]netip.Addr, uint32, error) {
	m, err := parseMessage(msg)
	if err != nil {
		return nil, 0, err
	}
	if m.id != id {
		return nil, 0, errors.New("doh: response id mismatch")
	}
	if m.flags&flagQR == 0 {
		return nil, 0, errors.New("doh: response is not a reply")
	}
	if m.flags&flagTC != 0 {
		return nil, 0, errors.New("doh: truncated response")
	}
	switch rcode := m.flags & rcodeMask; rcode {
	case rcodeNoError:
	case rcodeNXDomain:
		return nil, 0, errNXDomain
	default:
		return nil, 0, fmt.Errorf("doh: server returned rcode %d", rcode)
	}
	if m.questions != 1 {
		return nil, 0, errors.New("doh: response does not carry exactly one question")
	}
	if m.qname != fqdn(host) || m.qtype != qtype || m.qclass != classIN {
		return nil, 0, errors.New("doh: response question does not match query")
	}
	addrs, ttl := collectAddrs(m.answers, host, qtype)
	return addrs, ttl, nil
}
