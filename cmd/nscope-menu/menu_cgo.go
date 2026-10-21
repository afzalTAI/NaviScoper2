//go:build darwin

package main

// #cgo darwin CFLAGS: -x objective-c -fobjc-arc
// #cgo darwin LDFLAGS: -framework Cocoa
// #include "menu.h"
import "C"

import (
	"context"

	"runtime"
	"sync/atomic"

	"unsafe"

	"naviscopereborn/internal/proxy"
)

// AppKit may only instantiate UI objects on the process's initial thread.
// Pin the main goroutine to it before scheduling can migrate it; runMenu
// relies on this pin when it calls into Cocoa.
func init() { runtime.LockOSThread() }

// activeApp holds the menu state AppKit actions act on. AppKit invokes every
// callback on the main thread, so a plain atomic pointer suffices.
var activeApp atomic.Pointer[menuApp]

// writeCStr copies text into a fixed C buffer with NUL termination.
func writeCStr(buf *C.char, n C.int, text string) {
	if n <= 0 {
		return
	}
	b := unsafe.Slice((*byte)(unsafe.Pointer(buf)), int(n))
	if len(text) >= len(b) {
		text = text[:len(b)-1]
	}
	copy(b, text)
	b[len(text)] = 0
}

//export navi_status_text
func navi_status_text(buf *C.char, n C.int) {
	var s proxy.Stats
	if app := activeApp.Load(); app != nil {
		s = app.proxy.Stats()
	}
	writeCStr(buf, n, statusText(s))
}

//export navi_enabled
func navi_enabled() C.int {
	app := activeApp.Load()
	if app == nil || app.proxy.Paused() {
		return 0
	}
	return 1
}

//export navi_toggle
func navi_toggle() {
	if app := activeApp.Load(); app != nil {
		app.proxy.SetPaused(!app.proxy.Paused())
	}
}

//export navi_route_enabled
func navi_route_enabled() C.int {
	app := activeApp.Load()
	if app == nil || !app.router.Routing() {
		return 0
	}
	return 1
}

//export navi_route_toggle
func navi_route_toggle() {
	app := activeApp.Load()
	if app == nil {
		return
	}
	// networksetup writes take up to a few seconds; keep the menu responsive.
	go func() {
		if app.router.Routing() {
			app.router.Restore()
			return
		}
		app.router.Route(app.proxyAddr)
	}()
}

//export navi_dashboard_url
func navi_dashboard_url(buf *C.char, n C.int) {
	var url string
	if app := activeApp.Load(); app != nil {
		url = app.dashboardURL
	}
	writeCStr(buf, n, url)
}

//export navi_quit
func navi_quit() {
	if app := activeApp.Load(); app != nil && app.quit != nil {
		app.quit()
	}
}

// runMenu installs the status item and blocks in the AppKit run loop until
// the app quits or ctx is canceled. Must run on the locked main OS thread.
func runMenu(ctx context.Context, app *menuApp) error {
	activeApp.Store(app)
	stop := context.AfterFunc(ctx, func() { C.navi_menu_stop() })
	defer stop()
	runtime.LockOSThread()
	C.navi_menu_run()
	activeApp.Store(nil)
	return nil
}
