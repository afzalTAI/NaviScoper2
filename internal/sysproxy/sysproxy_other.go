//go:build !darwin

package sysproxy

import "errors"

// A non-macOS build keeps the API compiling; routing simply reports it needs
// macOS, matching the menu agent's platform story. Restore is a no-op because
// nothing can have been routed.
type Manager struct{}

func New() *Manager { return &Manager{} }

func (m *Manager) Routing() bool           { return false }
func (m *Manager) Route(addr string) error { return errors.New("system routing requires macOS") }
func (m *Manager) Restore() error          { return nil }
