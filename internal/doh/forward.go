package doh

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// Raw DNS forwarding: an in-tunnel listener hands plaintext RFC 1035 queries to
// ResolveWire, which answers them from the DoH resolver without ever speaking
// plaintext DNS on the wire.

// answerTTL is the TTL advertised on synthesized answer records. It is short on
// purpose: the authoritative TTL lives in the resolver cache, and clients
// should come back rather than pin an address.
const answerTTL uint32 = 60

// wireQuestion is the single question of an accepted query.
type wireQuestion struct {
	id    uint16
	rd    bool
	name  string // lowercase, without the trailing root dot
	qtype uint16
	raw   []byte // question section exactly as received, for a verbatim echo
}

// ResolveWire answers a raw DNS query with a raw DNS response.
//
// query must be a standard query carrying exactly one IN-class A or AAAA
// question; anything else is rejected with a descriptive error and no response
// is produced. When blocked is non-nil and reports true for the query name
// (lowercased, without the trailing dot), the name is refused with NXDOMAIN and
// no network traffic happens at all. Otherwise the name is resolved through r
// and the addresses of the requested family are returned as answer records.
func ResolveWire(ctx context.Context, r *Resolver, query []byte, blocked func(name string) bool) ([]byte, error) {
	if r == nil {
		return nil, errors.New("doh: nil resolver")
	}
	q, err := parseWireQuery(query)
	if err != nil {
		return nil, err
	}
	if blocked != nil && blocked(q.name) {
		return buildWireReply(q, rcodeNXDomain, nil), nil
	}
	addrs, err := r.LookupIP(ctx, q.name)
	switch {
	case err == nil:
	case errors.Is(err, ErrNXDomain):
		return buildWireReply(q, rcodeNXDomain, nil), nil
	case errors.Is(err, ErrNoAddresses):
		addrs = nil
	default:
		return nil, err
	}
	return buildWireReply(q, rcodeNoError, addrsOfType(addrs, q.qtype)), nil
}

// parseWireQuery validates a client query and extracts the single question.
func parseWireQuery(query []byte) (wireQuestion, error) {
	if len(query) < headerLen {
		return wireQuestion{}, errors.New("doh: query shorter than DNS header")
	}
	flags := binary.BigEndian.Uint16(query[2:4])
	if flags&flagQR != 0 {
		return wireQuestion{}, errors.New("doh: message is a response, not a query")
	}
	if opcode := (flags & opcodeMask) >> 11; opcode != opcodeQuery {
		return wireQuestion{}, fmt.Errorf("doh: unsupported opcode %d", opcode)
	}
	if count := binary.BigEndian.Uint16(query[4:6]); count != 1 {
		return wireQuestion{}, fmt.Errorf("doh: query carries %d questions, want exactly 1", count)
	}
	name, next, err := parseName(query, headerLen)
	if err != nil {
		return wireQuestion{}, fmt.Errorf("doh: query name: %w", err)
	}
	if next+4 > len(query) {
		return wireQuestion{}, errors.New("doh: truncated question section")
	}
	host := strings.TrimSuffix(name, ".")
	if host == "" {
		return wireQuestion{}, errors.New("doh: query for the root name")
	}
	// The response echoes the question bytes verbatim, so the name must be a
	// plain, uncompressed label sequence: re-encoding it has to yield exactly
	// as many bytes as the query spent on it.
	encoded, err := encodeName(host)
	if err != nil {
		return wireQuestion{}, fmt.Errorf("doh: query name: %w", err)
	}
	if len(encoded) != next-headerLen {
		return wireQuestion{}, errors.New("doh: compressed name in question section")
	}
	qtype := binary.BigEndian.Uint16(query[next : next+2])
	if qclass := binary.BigEndian.Uint16(query[next+2 : next+4]); qclass != classIN {
		return wireQuestion{}, fmt.Errorf("doh: unsupported query class %d", qclass)
	}
	if qtype != typeA && qtype != typeAAAA {
		return wireQuestion{}, fmt.Errorf("doh: unsupported query type %d", qtype)
	}
	return wireQuestion{
		id:    binary.BigEndian.Uint16(query[0:2]),
		rd:    flags&flagRD != 0,
		name:  host,
		qtype: qtype,
		raw:   query[headerLen : next+4],
	}, nil
}

// addrsOfType keeps the addresses whose family matches qtype.
func addrsOfType(addrs []netip.Addr, qtype uint16) []netip.Addr {
	out := make([]netip.Addr, 0, len(addrs))
	for _, addr := range addrs {
		addr = addr.Unmap()
		if (qtype == typeA && addr.Is4()) || (qtype == typeAAAA && addr.Is6()) {
			out = append(out, addr)
		}
	}
	return out
}

// buildWireReply renders the response for q: the question is echoed byte for
// byte and every answer record points its NAME back at it.
func buildWireReply(q wireQuestion, rcode uint16, addrs []netip.Addr) []byte {
	rdLen := 4
	if q.qtype == typeAAAA {
		rdLen = 16
	}
	msg := make([]byte, headerLen, headerLen+len(q.raw)+len(addrs)*(12+rdLen))
	flags := flagQR | flagRA | rcode
	if q.rd {
		flags |= flagRD
	}
	binary.BigEndian.PutUint16(msg[0:2], q.id)
	binary.BigEndian.PutUint16(msg[2:4], flags)
	binary.BigEndian.PutUint16(msg[4:6], 1)
	binary.BigEndian.PutUint16(msg[6:8], uint16(len(addrs)))
	msg = append(msg, q.raw...)
	for _, addr := range addrs {
		// 0xC00C is the compression pointer to the question name, which always
		// starts right after the 12-byte header.
		msg = binary.BigEndian.AppendUint16(msg, 0xC000|headerLen)
		msg = binary.BigEndian.AppendUint16(msg, q.qtype)
		msg = binary.BigEndian.AppendUint16(msg, classIN)
		msg = binary.BigEndian.AppendUint32(msg, answerTTL)
		msg = binary.BigEndian.AppendUint16(msg, uint16(rdLen))
		if q.qtype == typeA {
			v4 := addr.As4()
			msg = append(msg, v4[:]...)
			continue
		}
		v6 := addr.As16()
		msg = append(msg, v6[:]...)
	}
	return msg
}
