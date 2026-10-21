# Approved first Go build: portable local proxy

Status: proxy foundation approved by the user and implemented. All six targets cross-compile. See VALIDATION.md for executed checks and remaining native socket/runtime validation.

## Objective and assumptions

One bounded capability: a command-line explicit HTTP/HTTPS proxy, inspired by the inspected Naviscope behavior. The first build targets macOS, Linux, and Windows on amd64/arm64, using Go's standard library. Manual browser proxy configuration is assumed. This is a new implementation with an evidence reference, not recovered original source.

## Behavior

- Listen on IPv4 loopback, default `127.0.0.1:8081`; validate configuration and reject non-loopback listening addresses.
- Forward ordinary HTTP with correct streaming, Host semantics, hop-by-hop header removal, cancellation, connection reuse, and finite network timeouts.
- Support HTTPS using CONNECT byte tunneling, preserve buffered client bytes, support bidirectional closure, bound tunnel lifetime, and close active tunnels on shutdown.
- Support an optional host/domain deny list and optional removal of outbound HTTP Cookie headers. Domain matching respects label boundaries. For HTTPS, policies apply to the CONNECT target; cookie contents remain encrypted.
- Preserve TLS end-to-end. Restrict CONNECT to configured destination ports, default 443.
- Provide optional metadata logging that excludes credentials, cookies, bodies, URL queries, and full URL paths by default.
- Graceful shutdown and clear errors for unsupported requests.

HTML rewriting and prefetching are subsequent increments after their original logic and desired modern behavior are better specified. The first build is a proxy foundation; it will not advertise complete Naviscope feature parity. Automatic browser changes, native desktop GUI/tray, self-updates, clock changes, and MTU tuning are outside this slice.

## Structure and style

`cmd/nscope/main.go`: CLI and shutdown. `cmd/nscope-menu/`: macOS menu-bar agent packaging the same proxy (cgo/AppKit, darwin-only; a non-darwin stub preserves compilation). `internal/cli/`: shared flag parsing and process-lifecycle helpers. `internal/proxy/`: forwarding, tunnels, policies, tests. `internal/doh/`: DNS-over-HTTPS resolution (RFC 8484/1035, stdlib only). `internal/upstream/`: SOCKS5 (RFC 1928/1929) and HTTP CONNECT chaining. `internal/sysproxy/`: macOS system-proxy routing with snapshot/restore. `README.md`: setup, examples, limitations. `.gitignore`: build outputs and local config.

Use gofmt, standard errors, context cancellation, small functions, and comments identifying evidence-derived behavior versus new policy. Example style: `func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request)`.

## Build and validation commands

```sh
go test -race ./...
go vet ./...
go build -o dist/nscope ./cmd/nscope
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -o dist/nscope-darwin-arm64 ./cmd/nscope
CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -o dist/nscope-darwin-amd64 ./cmd/nscope
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o dist/nscope-linux-arm64 ./cmd/nscope
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o dist/nscope-linux-amd64 ./cmd/nscope
CGO_ENABLED=0 GOOS=windows GOARCH=arm64 go build -o dist/nscope-windows-arm64.exe ./cmd/nscope
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o dist/nscope-windows-amd64.exe ./cmd/nscope
```

Cross-compilation verifies compilation, not native runtime compatibility. Runtime tests on each OS remain necessary before claiming release support.

## Tests and acceptance

Use Go testing and local httptest fixtures. Verify forwarding methods/bodies/status, duplicate response headers, hop-by-hop removal (including Connection-nominated fields), upstream failures, optional cookie stripping, domain boundaries, CONNECT traffic including buffered data, invalid authorities/ports, tunnel cleanup, and graceful shutdown. No test executes the legacy executable or contacts its embedded service endpoints.

Success: automated tests and vet pass on the host, six cross-builds succeed, and README accurately distinguishes tested behavior from planned features.

## Boundaries

Always: preserve the inspected executable; label reconstructions honestly; test network behavior with local fixtures; validate target requests.
Ask before: changing the approved capability scope or adding external dependencies.
Never: execute the original application in this phase; silently alter browser/system settings; call legacy update/registration endpoints.

## Proposed build order

1. HTTP forwarding plus local integration tests.
2. HTTPS CONNECT, tunnel lifecycle, and shutdown tests.
3. Host rules, cookie control, CLI/config, documentation.
4. Race/vet checks and six target builds; record what ran versus what merely compiled.

The user approved this CLI proxy foundation. HTML filtering, prefetching, and desktop integration remain later scope decisions. Configuration in this first build is through CLI flags; no JSON configuration file is loaded.

## Browser interface extension

The user requested a frontend after approving the proxy foundation. A new local browser console is now embedded in the binary and served at `127.0.0.1:8082` by default (`-ui-listen` / `-no-ui`). It shows aggregate session counts, connection limits, and manual browser setup instructions. It edits domain rules and HTTP request-cookie stripping without restarting; updates affect subsequent requests and are not persisted across process restarts.

The console is a new design choice, not a reconstruction of the legacy toolbar. A dedicated loopback listener, exact Host validation, same-origin checks, a per-process update token, bounded JSON, and a restrictive Content Security Policy protect its controls. It collects no browsing URLs, bodies, cookies, or credentials. No external dependencies or browser/system setting changes were introduced.

## macOS menu-bar agent

The user requested a clickable menu-bar agent. `scripts/build-macos-app.sh` assembles `dist/NaviScope.app` (LSUIElement, no Dock icon) from `cmd/nscope-menu` with no dependencies beyond the system Cocoa framework. macOS places status agents on the right side of the menu bar; the left side belongs to the foreground application. The menu shows session status, a **Filtering enabled** toggle, **Route system traffic** (below), **Open dashboard…** (hidden with `-no-ui`), and **Quit**. Pausing suspends deny rules and cookie stripping for new requests while forwarding continues; the CONNECT port whitelist, loopback binding, and end-to-end TLS remain enforced while paused. Quit and stop signals follow the same graceful drain as the CLI.

## System routing, secure DNS, and upstream chaining

The user requested Warp-style automatic routing. Stage 1 shipped: (a) the menu agent's **Route system traffic** toggle — `internal/sysproxy` snapshots each network service's HTTP/HTTPS proxy via `networksetup`, applies `127.0.0.1:8081` all-or-nothing (rollback on partial failure), and restores the snapshot on quit; `scripts/unset-system-proxy.sh` is the force-kill escape hatch; (b) `-secure-dns` — `internal/doh` resolves names over DoH with pinned bootstrap IPs, strict no-system-fallback, TTL cache, and a raw-wire API (`ResolveWire`) for the in-tunnel DNS forwarder; (c) `-upstream` — `internal/upstream` chains every outbound connection (HTTP and CONNECT) through a SOCKS5 or HTTP CONNECT provider; combining it with Cloudflare Warp's local proxy yields Warp-style tunneling. HTTPS remains end-to-end encrypted; paused filtering does not suspend the CONNECT port whitelist.

Stage 2 shipped as `-tun` (macOS, root, CLI-only): `internal/tunroute` opens a `utun` device via the `com.apple.net.utun` system control socket, installs 0.0.0.0/1 + 128.0.0.0/1 routes (self-healing on process death), and pins every NaviScope socket to the physical interface with `IP_BOUND_IF` so outbound traffic cannot loop into the tunnel. `internal/tunstack` runs the gvisor userspace network stack (module: `github.com/sagernet/gvisor`, the module-friendly trim of gvisor netstack — upstream `gvisor.dev/gvisor` ships a malformed test package that current Go loaders reject): TCP flows dial through the shared `internal/outbound` chain, port 53 (UDP and TCP) is answered by `doh.ResolveWire` (deny rules return NXDOMAIN; DNS is always DoH in the tunnel because a system-resolver fallback would loop), and other UDP is relayed directly with an idle timeout. **macOS 27 gate:** this OS refuses the utun controller lookup for every ordinary process (verified as root via native C), so `-tun` there reports the restriction at startup; full capture on macOS 27 requires an Apple-entitled Network Extension build (future work). Limitations: IPv4 only, non-DNS UDP bypasses `-upstream`, filtering is domain-level (DNS) rather than URL-level, and the menu agent declines `-tun` with instructions.

## Distribution packaging

`scripts/build-dmg.sh` produces `dist/NaviScope-<version>-universal.dmg` (arm64+amd64, app icon, drag-to-Applications, ad-hoc signed; Gatekeeper needs one right-click → Open). Minimum macOS 10.15 — the Go runtime's floor; Sierra 10.12 is unreachable with a maintained toolchain. Ubuntu 24.04+ (.deb) and Windows 11 packages are the next planned targets; all six CLI cross-builds already pass.


