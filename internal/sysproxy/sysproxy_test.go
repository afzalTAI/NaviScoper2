package sysproxy

import (
	"fmt"
	"strings"
	"sync"
	"testing"
)

func TestParseServices(t *testing.T) {
	out := "An asterisk (*) denotes that a network service is disabled.\nEthernet\nAX88179A\n*Hidden VPN\nUSB 10/100 LAN\n\nWi-Fi\n"
	got := parseServices(out)
	want := []string{"Ethernet", "AX88179A", "USB 10/100 LAN", "Wi-Fi"}
	if len(got) != len(want) {
		t.Fatalf("services %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("service %d = %q want %q", i, got[i], want[i])
		}
	}
}

func TestParseProxy(t *testing.T) {
	for _, tc := range []struct {
		name, out string
		want      Setting
		wantErr   bool
	}{
		{"off", "Enabled: No\nServer: \nPort: 0\nAuthenticated Proxy Enabled: 0\n", Setting{}, false},
		{"on", "Enabled: Yes\nServer: 10.0.0.2\nPort: 3128\nAuthenticated Proxy Enabled: 0\n", Setting{Enabled: true, Server: "10.0.0.2", Port: 3128}, false},
		{"disabled-with-address", "Enabled: No\nServer: corp.example\nPort: 8080\n", Setting{Server: "corp.example", Port: 8080}, false},
		{"enabled-no-server", "Enabled: Yes\nServer: \nPort: 0\n", Setting{Enabled: true}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseProxy(tc.out)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %+v", got)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("got %+v err %v want %+v", got, err, tc.want)
			}
		})
	}
}

// fakeRunner scripts networksetup without touching the system.
type fakeRunner struct {
	mu       sync.Mutex
	calls    [][]string
	webState map[string]string // service → -getwebproxy output
	secure   map[string]string // service → -getsecurewebproxy output
	services string
	fail     map[string]bool // joined-args substring → fail
}

func (f *fakeRunner) run(args ...string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, args)
	joined := strings.Join(args, " ")
	for frag := range f.fail {
		if strings.Contains(joined, frag) {
			return "", fmt.Errorf("scripted failure for %q", frag)
		}
	}
	switch args[0] {
	case "-listallnetworkservices":
		return f.services, nil
	case "-getwebproxy":
		return f.webState[args[1]], nil
	case "-getsecurewebproxy":
		return f.secure[args[1]], nil
	}
	return "", nil
}

func newFake() *fakeRunner {
	off := "Enabled: No\nServer: \nPort: 0\nAuthenticated Proxy Enabled: 0\n"
	corp := "Enabled: Yes\nServer: 10.0.0.2\nPort: 3128\nAuthenticated Proxy Enabled: 0\n"
	return &fakeRunner{
		services: "An asterisk (*) denotes that a network service is disabled.\nEthernet\nWi-Fi\n",
		webState: map[string]string{"Ethernet": off, "Wi-Fi": corp},
		secure:   map[string]string{"Ethernet": off, "Wi-Fi": off},
	}
}

func TestRouteSnapshotsAndRestores(t *testing.T) {
	f := newFake()
	m := newManager(f.run)
	if err := m.Route("127.0.0.1:8081"); err != nil {
		t.Fatal(err)
	}
	if !m.Routing() {
		t.Fatal("not routed after Route")
	}
	if err := m.Route("127.0.0.1:9999"); err != nil {
		t.Fatal("second Route must be a no-op")
	}
	// Wi-Fi must be re-pointed, both protocols.
	for _, want := range [][]string{{"-setwebproxy", "Wi-Fi", "127.0.0.1", "8081"}, {"-setsecurewebproxy", "Wi-Fi", "127.0.0.1", "8081"}} {
		found := false
		for _, call := range f.calls {
			if fmt.Sprint(call) == fmt.Sprint(want) {
				found = true
			}
		}
		if !found {
			t.Fatalf("missing call %v", want)
		}
	}
	if err := m.Restore(); err != nil {
		t.Fatal(err)
	}
	if m.Routing() {
		t.Fatal("still routed after Restore")
	}
	// Restore writes back the original corp proxy on Wi-Fi web, and off elsewhere.
	restoreWeb := false
	for _, call := range f.calls {
		if len(call) == 4 && call[0] == "-setwebproxy" && call[1] == "Wi-Fi" && call[2] == "10.0.0.2" && call[3] == "3128" {
			restoreWeb = true
		}
	}
	if !restoreWeb {
		t.Fatal("Restore did not put back the original Wi-Fi proxy")
	}
	if err := m.Restore(); err != nil {
		t.Fatal("second Restore must be a no-op")
	}
}

func TestRouteRejectsBadAddress(t *testing.T) {
	f := newFake()
	m := newManager(f.run)
	for _, addr := range []string{"localhost:8081", "127.0.0.1", "127.0.0.1:0", "127.0.0.1:99999", "[::1]:8081"} {
		if err := m.Route(addr); err == nil {
			t.Fatalf("accepted %q", addr)
		}
	}
}

// Any partial failure must roll back already-written services.
func TestRouteRollsBackOnPartialFailure(t *testing.T) {
	f := newFake()
	f.webState["Ethernet"] = "Enabled: Yes\nServer: \nPort: 0\n" // unparseable-ish read is fine now; poison a write instead
	f.fail = map[string]bool{"-setsecurewebproxy Wi-Fi": true}
	m := newManager(f.run)
	if err := m.Route("127.0.0.1:8081"); err == nil {
		t.Fatal("expected error")
	}
	if m.Routing() {
		t.Fatal("marked routed after failed Route")
	}
	// Ethernet (written before Wi-Fi failed) must have been restored.
	restored := false
	for i, call := range f.calls {
		if len(call) == 4 && call[0] == "-setwebproxy" && call[1] == "Ethernet" && call[2] == "" && call[3] == "0" && i > 0 {
			restored = true
		}
	}
	if !restored {
		t.Fatal("partial route did not roll back Ethernet")
	}
}
func TestRouteFailsCleanlyWhenNothingApplies(t *testing.T) {
	f := newFake()
	f.fail = map[string]bool{"-setwebproxy": true, "-setsecurewebproxy": true}
	m := newManager(f.run)
	if err := m.Route("127.0.0.1:8081"); err == nil {
		t.Fatal("expected failure when no service could be routed")
	}
	if m.Routing() {
		t.Fatal("marked routed despite total failure")
	}
}
