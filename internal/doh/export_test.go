package doh

import (
	"net/http"
	"net/netip"
	"strings"
	"time"
)

// Hooks for the external test package. They exist only in test builds.

const (
	TypeA     = typeA
	TypeAAAA  = typeAAAA
	TypeCNAME = typeCNAME
	ClassIN   = classIN

	NegativeTTL     = negativeTTL
	MinTTL          = minTTL
	MaxCacheEntries = maxCacheEntries

	FlagQR        = flagQR
	FlagRD        = flagRD
	FlagRA        = flagRA
	RcodeMask     = rcodeMask
	RcodeNoError  = rcodeNoError
	RcodeNXDomain = rcodeNXDomain
	AnswerTTL     = answerTTL
)

// SetClient injects an HTTP client, bypassing the bootstrap transport.
func (r *Resolver) SetClient(c *http.Client) { r.setClient(c) }

func (r *Resolver) CacheLen() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.cache)
}

func (r *Resolver) CacheGet(name string, now time.Time) ([]netip.Addr, bool) {
	entry, ok := r.cacheGet(name, now)
	return entry.addrs, ok
}

func (r *Resolver) CachePut(name string, addrs []netip.Addr, ttl time.Duration, now time.Time) {
	r.cachePut(name, addrs, false, ttl, now)
}

// Answer is one decoded resource record of a parsed response.
type Answer struct {
	Name  string
	Type  uint16
	Class uint16
	TTL   uint32
	Data  []byte
}

// Message is a response decoded with the package's own parser.
type Message struct {
	ID        uint16
	Flags     uint16
	Questions int
	QName     string
	QType     uint16
	QClass    uint16
	Answers   []Answer
}

// ParseResponse decodes a wire response so tests can inspect it without
// reimplementing the parser.
func ParseResponse(msg []byte) (Message, error) {
	m, err := parseMessage(msg)
	if err != nil {
		return Message{}, err
	}
	out := Message{
		ID:        m.id,
		Flags:     m.flags,
		Questions: m.questions,
		QName:     m.qname,
		QType:     m.qtype,
		QClass:    m.qclass,
		Answers:   make([]Answer, 0, len(m.answers)),
	}
	for _, rec := range m.answers {
		out.Answers = append(out.Answers, Answer{Name: rec.name, Type: rec.rtype, Class: rec.class, TTL: rec.ttl, Data: rec.data})
	}
	return out, nil
}

// ParseQuery decodes a query produced by this package; test servers use it to
// answer self-encoded questions.
func ParseQuery(msg []byte) (id uint16, host string, qtype uint16, err error) {
	m, err := parseMessage(msg)
	if err != nil {
		return 0, "", 0, err
	}
	return m.id, strings.TrimSuffix(m.qname, "."), m.qtype, nil
}
