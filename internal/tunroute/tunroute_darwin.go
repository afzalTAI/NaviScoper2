//go:build darwin

// Package tunroute creates a utun interface and routes the IPv4 default path
// through it, Warp-style. Transparent-routing stage 2: all device TCP/UDP
// enters the tunnel; NaviScope's own sockets are pinned to the physical
// interface via IP_BOUND_IF so they can never loop back.
package tunroute

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"
)

const (
	utunControlName = "com.apple.net.utun"
	// Point-to-point pair; 198.18.0.0/15 is reserved for benchmarking
	// (RFC 2544) and unused on real networks.
	tunLocal = "198.18.0.1"
	tunPeer  = "198.18.0.2"
	// AF_SYSTEM socket parameters for utun (xnu sys/domain.h).
	afSyProtoControl = 2 // SYSPROTO_CONTROL
	afSysControl     = 2 // AF_SYS_CONTROL
	// _IOWR('N', 3, struct ctl_info): identify the utun controller.
	ctlIOCGInfo = 0xC0644E03
	// BSD socket option: bind an IPv4 socket to an interface index.
	ipBoundIf = 25
	mtu       = 1500
)

// ctlInfo mirrors xnu's struct ctl_info.
type ctlInfo struct {
	id   uint32
	name [96]byte
}

// sockaddrCtl mirrors xnu's struct sockaddr_ctl.
type sockaddrCtl struct {
	scLen    uint8
	family   uint8
	sysAddr  uint16 // AF_SYS_CONTROL
	scID     uint32
	scUnit   uint32
	reserved [5]uint32
}

// Device is the established tunnel. Close removes the routes and closes the
// interface (the interface also vanishes if the process dies, so a crash
// self-heals the routing table).
type Device struct {
	fd     int
	name   string
	rbuf   []byte
	wbuf   []byte
	closed bool
}

// DefaultInterface returns the name of the current default-route interface
// (for example en0) before the tunnel changes routing.
func DefaultInterface() (string, error) {
	out, err := exec.Command("route", "-n", "get", "default").Output()
	if err != nil {
		return "", fmt.Errorf("tunroute: cannot read default route: %w", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "interface:") {
			name := strings.TrimSpace(strings.TrimPrefix(line, "interface:"))
			if name != "" {
				return name, nil
			}
		}
	}
	return "", errors.New("tunroute: no default interface found")
}

// Start opens a utun, configures it, and installs the two /1 routes that
// cover the whole IPv4 space (more specific than any existing default route,
// trivially removable). Requires root.
func Start() (*Device, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("tunroute: transparent routing requires root — rerun with sudo")
	}
	fd, err := syscall.Socket(syscall.AF_SYSTEM, syscall.SOCK_DGRAM, afSyProtoControl)
	if err != nil {
		return nil, fmt.Errorf("tunroute: control socket: %w", err)
	}
	dev := &Device{fd: fd, rbuf: make([]byte, 4+mtu), wbuf: make([]byte, 4+mtu)}
	var info ctlInfo
	copy(info.name[:], utunControlName)
	if err := ioctlPtr(fd, ctlIOCGInfo, unsafe.Pointer(&info)); err != nil {
		syscall.Close(fd)
		if errors.Is(err, syscall.ENOENT) {
			return nil, errors.New("tunroute: this macOS restricts utun to entitled apps (verified on macOS 27: the kernel refuses the controller lookup even for root); transparent routing here requires a Network Extension build — see README")
		}
		return nil, fmt.Errorf("tunroute: utun controller unavailable: %w", err)
	}
	addr := sockaddrCtl{sysAddr: afSysControl, scID: info.id} // scUnit 0: kernel picks the next unit
	addr.scLen = uint8(unsafe.Sizeof(addr))
	addr.family = syscall.AF_SYSTEM
	if _, _, errno := syscall.Syscall(syscall.SYS_CONNECT, uintptr(fd), uintptr(unsafe.Pointer(&addr)), uintptr(unsafe.Sizeof(addr))); errno != 0 {
		syscall.Close(fd)
		return nil, fmt.Errorf("tunroute: utun connect: %w", errno)
	}
	var raw syscall.RawSockaddrAny
	size := uint32(unsafe.Sizeof(raw))
	if _, _, errno := syscall.Syscall(syscall.SYS_GETSOCKNAME, uintptr(fd), uintptr(unsafe.Pointer(&raw)), uintptr(unsafe.Pointer(&size))); errno != 0 {
		syscall.Close(fd)
		return nil, fmt.Errorf("tunroute: utun unit: %w", errno)
	}
	ctl := (*sockaddrCtl)(unsafe.Pointer(&raw.Addr))
	dev.name = fmt.Sprintf("utun%d", ctl.scUnit-1)

	for _, args := range [][]string{
		{"ifconfig", dev.name, tunLocal, tunPeer, "up"},
		{"route", "-n", "add", "-net", "0.0.0.0/1", "-interface", dev.name},
		{"route", "-n", "add", "-net", "128.0.0.0/1", "-interface", dev.name},
	} {
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
			dev.Close()
			return nil, fmt.Errorf("tunroute: %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
		}
	}
	return dev, nil
}

// Name returns the utun interface name (utunN).
func (d *Device) Name() string { return d.name }

// Read receives one raw IP packet. macOS utun prefixes each packet with a
// 4-byte address family, which is stripped here.
func (d *Device) Read(ip []byte) (int, error) {
	if d.closed {
		return 0, net.ErrClosed
	}
	n, err := syscall.Read(d.fd, d.rbuf)
	if err != nil {
		return 0, err
	}
	if n <= 4 {
		return 0, nil
	}
	return copy(ip, d.rbuf[4:n]), nil
}

// Write sends one raw IP packet, adding the 4-byte AF_INET prefix.
func (d *Device) Write(ip []byte) (int, error) {
	if d.closed {
		return 0, net.ErrClosed
	}
	d.wbuf[3] = syscall.AF_INET
	copy(d.wbuf[4:], ip)
	if _, err := syscall.Write(d.fd, d.wbuf[:4+len(ip)]); err != nil {
		return 0, err
	}
	return len(ip), nil
}

// Close removes the routes and closes the interface.
func (d *Device) Close() error {
	if d.closed {
		return nil
	}
	d.closed = true
	for _, netCIDR := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		_, _ = exec.Command("route", "-n", "delete", "-net", netCIDR).CombinedOutput()
	}
	return syscall.Close(d.fd)
}

// BindControl returns a socket Control hook that pins sockets to the named
// physical interface so NaviScope's own traffic bypasses the tunnel. IPv6
// sockets skip the pin (no IPv6 routes enter the tunnel, so no loop is
// possible); a failed IPv4 pin is fatal.
func BindControl(iface string) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		var ctlErr error
		err := c.Control(func(fd uintptr) {
			if strings.HasPrefix(network, "tcp6") || strings.HasPrefix(network, "udp6") {
				return
			}
			idx, err := interfaceIndex(iface)
			if err != nil {
				ctlErr = err
				return
			}
			if err := syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, ipBoundIf, int(idx)); err != nil {
				ctlErr = fmt.Errorf("tunroute: pin to %s failed: %w", iface, err)
			}
		})
		if err != nil {
			return err
		}
		return ctlErr
	}
}

func interfaceIndex(name string) (uint32, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return 0, fmt.Errorf("tunroute: interface %s: %w", name, err)
	}
	return uint32(iface.Index), nil
}

func ioctlPtr(fd int, req uint, arg unsafe.Pointer) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(req), uintptr(arg))
	if errno != 0 {
		return errno
	}
	return nil
}
