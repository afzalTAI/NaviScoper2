package doh

// Preset describes one DNS-over-HTTPS provider. Endpoint is an https URL that
// accepts RFC 8484 POST queries. Bootstrap holds IP literals used to reach the
// endpoint so that resolving the endpoint itself never needs the system
// resolver.
type Preset struct {
	Endpoint  string
	Bootstrap []string
}

// Presets returns the built-in providers keyed by short name. The returned map
// and slices are copies, so callers may modify them freely.
func Presets() map[string]Preset {
	return map[string]Preset{
		"cloudflare": {
			Endpoint:  "https://cloudflare-dns.com/dns-query",
			Bootstrap: []string{"1.1.1.1", "1.0.0.1"},
		},
		"google": {
			Endpoint:  "https://dns.google/dns-query",
			Bootstrap: []string{"8.8.8.8", "8.8.4.4"},
		},
		"quad9": {
			Endpoint:  "https://dns.quad9.net/dns-query",
			Bootstrap: []string{"9.9.9.9", "149.112.112.112"},
		},
		"opendns": {
			Endpoint:  "https://doh.opendns.com/dns-query",
			Bootstrap: []string{"208.67.222.222", "208.67.220.220"},
		},
	}
}
