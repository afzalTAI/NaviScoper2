package doh

import "testing"

func TestPresetFor(t *testing.T) {
	for _, name := range []string{"cloudflare", "google", "quad9", "opendns"} {
		p, err := PresetFor(name)
		if err != nil || p.Endpoint == "" || len(p.Bootstrap) == 0 {
			t.Fatalf("preset %s: %+v err %v", name, p, err)
		}
	}
	p, err := PresetFor("https://9.9.9.9/dns-query")
	if err != nil || p.Bootstrap[0] != "9.9.9.9" {
		t.Fatalf("custom URL: %+v err %v", p, err)
	}
	for _, bad := range []string{"", "notapreset", "http://9.9.9.9/dns-query", "https://dns.example.net/dns-query"} {
		if _, err := PresetFor(bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}
