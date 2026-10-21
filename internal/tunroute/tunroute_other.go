//go:build !darwin

// Package tunroute: transparent routing is macOS-only at this stage.
package tunroute

import (
	"errors"
	"syscall"
)

type Device struct{}

func DefaultInterface() (string, error) {
	return "", errors.New("tunroute: transparent routing requires macOS")
}
func Start() (*Device, error)  { return nil, errors.New("tunroute: transparent routing requires macOS") }
func (d *Device) Name() string { return "" }
func (d *Device) Read(b []byte) (int, error) {
	return 0, errors.New("tunroute: transparent routing requires macOS")
}
func (d *Device) Write(b []byte) (int, error) {
	return 0, errors.New("tunroute: transparent routing requires macOS")
}
func (d *Device) Close() error { return nil }

// BindControl exists so non-darwin builds compile; transparent routing never
// starts there, so sockets need no pinning.
func BindControl(iface string) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error { return nil }
}
