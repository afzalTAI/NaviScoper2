//go:build darwin

package sysproxy

import (
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"
)

// runner executes networksetup and returns stdout. Injectable for tests.
type runner func(args ...string) (string, error)

func networksetup(args ...string) (string, error) {
	out, err := exec.Command("networksetup", args...).Output()
	if err != nil {
		detail := ""
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			detail = strings.TrimSpace(string(exitErr.Stderr))
		}
		return "", fmt.Errorf("networksetup %s: %w %s", strings.Join(args, " "), err, detail)
	}
	return string(out), nil
}

// writeKind selects the web or secure web proxy commands.
type writeKind struct{ set, state string }

var kinds = [2]writeKind{
	{"-setwebproxy", "-setwebproxystate"},
	{"-setsecurewebproxy", "-setsecurewebproxystate"},
}

func readKind(service string) [2]string {
	return [2]string{"-getwebproxy", "-getsecurewebproxy"}
}

// Manager owns one routing session: Route() snapshots, applies, and marks the
// change; Restore() puts back the snapshot. Safe for concurrent use.
type Manager struct {
	mu       sync.Mutex
	run      runner
	applied  bool
	addr     string
	snapshot map[string][2]Setting // service → {web, secure}
}

func New() *Manager { return &Manager{run: networksetup} }

func newManager(run runner) *Manager { return &Manager{run: run} }

// Routing reports whether this manager currently routes system traffic.
func (m *Manager) Routing() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.applied
}

// readState captures one service's web and secure proxy settings.
func (m *Manager) readState(service string) ([2]Setting, error) {
	var state [2]Setting
	for i, get := range readKind(service) {
		out, err := m.run(get, service)
		if err != nil {
			return state, err
		}
		setting, err := parseProxy(out)
		if err != nil {
			return state, fmt.Errorf("%s %s: %w", get, service, err)
		}
		state[i] = setting
	}
	return state, nil
}

// writeState applies one service's web and secure settings. The address is
// written first (it auto-enables), then the on/off state, so the pair always
// lands exactly on the requested snapshot.
func (m *Manager) writeState(service string, state [2]Setting) error {
	for i, kind := range kinds {
		s := state[i]
		// Always write the address ("" clears it), then the on/off state, so
		// an originally-empty setting returns to Enabled: No with no address.
		if _, err := m.run(kind.set, service, s.Server, strconv.Itoa(s.Port)); err != nil {
			return err
		}
		enabled := "off"
		if s.Enabled {
			enabled = "on"
		}
		if _, err := m.run(kind.state, service, enabled); err != nil {
			return err
		}
	}
	return nil
}

// Route points every active network service's HTTP/HTTPS proxy at addr
// (host:port). Idempotent: a second call while routed is a no-op.
func (m *Manager) Route(addr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.applied {
		return nil
	}
	host, portStr, err := net.SplitHostPort(addr)
	ip := net.ParseIP(host)
	if err != nil || ip == nil || ip.To4() == nil {
		return fmt.Errorf("route address must be an IPv4 host:port, got %q", addr)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("route port must be 1–65535, got %q", addr)
	}
	listOut, err := m.run("-listallnetworkservices")
	if err != nil {
		return err
	}
	snapshot := make(map[string][2]Setting)
	var written []string
	var errs []error
	for _, service := range parseServices(listOut) {
		before, err := m.readState(service)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		snapshot[service] = before
		target := [2]Setting{{Enabled: true, Server: host, Port: port}, {Enabled: true, Server: host, Port: port}}
		if err := m.writeState(service, target); err != nil {
			errs = append(errs, err)
			continue
		}
		written = append(written, service)
	}
	// System settings mutate all-or-nothing: on any failure, roll back the
	// services already written so a rejected Route never leaves a half-routed
	// system behind.
	if len(errs) > 0 || len(written) == 0 {
		for _, service := range written {
			if err := m.writeState(service, snapshot[service]); err != nil {
				errs = append(errs, fmt.Errorf("rollback of %s failed: %w", service, err))
			}
		}
		if len(written) == 0 {
			errs = append(errs, errors.New("no network service could be routed"))
		}
		return fmt.Errorf("routing rolled back: %w", errors.Join(errs...))
	}
	m.applied = true
	m.addr = addr
	m.snapshot = snapshot
	return nil
}

// Restore puts back the settings captured by Route. A no-op if not routed.
func (m *Manager) Restore() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.applied {
		return nil
	}
	var errs []error
	for service, state := range m.snapshot {
		if err := m.writeState(service, state); err != nil {
			errs = append(errs, err)
		}
	}
	m.applied = false
	m.addr = ""
	m.snapshot = nil
	return errors.Join(errs...)
}
