package doh

import (
	"fmt"
	"net"
	"net/url"
)

// PresetFor resolves a -secure-dns specification: a preset name, or an https
// URL whose host is an IP literal (it becomes its own bootstrap).
func PresetFor(spec string) (Preset, error) {
	if preset, ok := Presets()[spec]; ok {
		return preset, nil
	}
	u, err := url.Parse(spec)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return Preset{}, fmt.Errorf("secure DNS must be a preset name or an https URL")
	}
	host := u.Hostname()
	if ip := net.ParseIP(host); ip == nil {
		return Preset{}, fmt.Errorf("secure DNS URL must use an IP-literal host (no bootstrap address available)")
	}
	return Preset{Endpoint: spec, Bootstrap: []string{host}}, nil
}
