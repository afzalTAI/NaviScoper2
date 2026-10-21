# NaviScopeReborn

A portable Go explicit HTTP/HTTPS proxy with a local browser interface for macOS, Linux, and Windows. This is a new standard-library implementation inspired by inspected Naviscope behavior, not recovered original source or complete feature parity.

## Build and run

Requires Go 1.26 or newer; no external dependencies.

```sh
go build -o dist/nscope ./cmd/nscope
./dist/nscope
# Or run from source:
go run ./cmd/nscope
```

Open **http://127.0.0.1:8082** after starting NaviScope. The browser interface is embedded in the binary; no Node installation, asset directory, or internet connection is required.

The interface shows session request counts, active connections, blocked requests, and connection limits. Add/remove domain rules and change HTTP cookie stripping, then select **Save changes**. Policy changes apply to subsequent requests; established HTTPS tunnels are unaffected. UI changes last for the current process only. Restarting restores the startup flags.

On Windows, build with `go build -o dist/nscope.exe ./cmd/nscope`, then run `.\dist\nscope.exe`. Set your browser's HTTP and HTTPS proxy manually to `127.0.0.1:8081`. No browser/system settings are changed. Stop with Ctrl+C; Unix SIGTERM also requests graceful shutdown.

Stop with Ctrl+C (or Unix SIGTERM/SIGHUP) for a graceful shutdown; a second Ctrl+C force-quits immediately. When started with `go run`, NaviScope also watches its parent: if the `go run` process is force-killed (IDE stop buttons, `kill -9`) instead of interrupted, the child exits on its own rather than lingering on ports 8081/8082. A leftover instance from before this safeguard can be removed with `pkill -f nscope`.

### Route all system traffic automatically

The macOS agent's **Route system traffic** row points the system-wide HTTP/HTTPS proxy at NaviScope (snapshot first; quitting restores exactly what was there). It needs an admin-group user, applies to apps that honor system proxy settings (browsers, most GUI apps — not CLI tools or DNS), and is never changed silently. After a force-kill (`kill -9`), run `sh scripts/unset-system-proxy.sh` to restore.

### Secure DNS and upstream tunneling

```sh
./dist/nscope -secure-dns cloudflare   # or google, quad9, opendns, or https://IP/dns-query
./dist/nscope -upstream socks5://127.0.0.1:40000   # e.g. Cloudflare Warp's local proxy
./dist/nscope -secure-dns quad9 -upstream http://proxy.example.net:3128
```

`-secure-dns` resolves every hostname via DNS-over-HTTPS to the chosen provider (bootstrap IPs pinned; no system-resolver fallback; custom URLs must use an IP-literal host). `-upstream` chains all outbound traffic through a SOCKS5 or HTTP CONNECT provider — run Cloudflare Warp in proxy mode (`warp-cli set-mode proxy`, SOCKS5 on 127.0.0.1:40000) and point NaviScope at it for Warp-style tunneling. HTTPS stays end-to-end encrypted in both modes.

## macOS menu-bar agent

macOS can package the same proxy as a menu-bar agent (status item on the **right** side of the menu bar; the left side is reserved for app menus and cannot host agents):

```sh
sh scripts/build-macos-app.sh   # builds dist/NaviScope.app (ad-hoc signed)
open dist/NaviScope.app
```

The agent has no Dock icon and shows a live menu: session status, a **Filtering enabled** toggle, **Open dashboard…**, and **Quit NaviScope**. Pausing keeps traffic flowing while suspending deny rules and cookie stripping; the CONNECT port whitelist stays enforced. Stop signals (Ctrl+C in a terminal, SIGTERM/SIGHUP) use the same graceful drain as the CLI. The agent is macOS-only (`cmd/nscope-menu`, cgo/AppKit, no new dependencies); on other platforms it compiles to a stub that reports that the agent requires macOS. Startup flags are the same as the CLI, e.g. `open dist/NaviScope.app --args -deny example.com`.

### Distributable DMG

```sh
sh scripts/build-dmg.sh   # dist/NaviScope-0.1-universal.dmg (arm64 + amd64)
```

The DMG carries the menu-bar agent (universal binary, app icon, drag-to-Applications layout). It is ad-hoc signed: on another Mac, right-click → **Open** once to pass Gatekeeper. Minimum macOS is **10.15 Catalina** — the Go runtime's floor; no maintained toolchain can target Sierra (10.12). Ubuntu 24.04+ (.deb) and Windows 11 packages are planned next; the CLI (`dist/nscope[-<os>-<arch>]`) already builds for all six targets.

```sh
./dist/nscope -deny example.com,ads.example.org -strip-request-cookies
./dist/nscope -connect-ports 443,8443 -metadata-log
curl --noproxy '' --proxy http://127.0.0.1:8081 http://127.0.0.1:8000/
```

## Configuration

Startup configuration is through CLI flags; no configuration file is read. Domain rules and cookie stripping can also be changed in the browser interface during a session.

| Flag | Default | Behavior |
|---|---|---|
| `-listen` | `127.0.0.1:8081` | Literal IPv4 loopback only; ports 1–65535 |
| `-ui-listen` | `127.0.0.1:8082` | Local browser interface; literal IPv4 loopback only |
| `-no-ui` | false | Start the proxy without the browser interface |
| `-deny` | empty | Comma-separated domains/IPs; domains include subdomains, matched at label boundaries |
| `-strip-request-cookies` | false | Removes outgoing HTTP `Cookie`; preserves response `Set-Cookie` |
| `-connect-ports` | `443` | Allowed CONNECT destination ports |
| `-metadata-log` | false | JSON operation and target host/port; no credentials, cookies, bodies, paths, or queries |
| `-secure-dns` | empty | DoH preset (`cloudflare`, `google`, `quad9`, `opendns`) or `https://IP/dns-query`; empty = system resolver |
| `-upstream` | empty | Chain all outbound traffic via `socks5://[user:pass@]host:port` or `http://host:port` |
| `-request-timeout` | `2m` | Total HTTP exchange and client read/write bound |
| `-tunnel-timeout` | `10m` | Maximum CONNECT tunnel lifetime |
| `-shutdown-timeout` | `5s` | HTTP drain period before forced cancellation |

Timeouts must be positive. Upstream dialing is bounded to 10s, response headers to 15s, client headers to 10s, and idle client connections to 60s. CONNECT sockets close immediately on shutdown; ordinary HTTP requests drain within the grace period.

HTTP forwarding streams bodies and preserves status, duplicate response headers, trailers, target Host, and query bytes. Hop-by-hop headers and proxy credentials are removed. The upstream transport ignores environment proxy variables and reuses connections. Upstream connection failures return 502; an expired HTTP request deadline returns 504 if headers have not already been sent. Interrupted streamed responses are closed rather than replaced with an error body.

HTTPS uses CONNECT byte tunneling with end-to-end TLS: no generated certificates or decryption. HTTPS policies apply to the requested CONNECT host/port; HTTPS cookies remain encrypted. Domain rules match the requested hostname, not resolved IPs or DNS aliases. ASCII DNS names (including punycode) and IP literals are supported; wildcards, URL rules, and Unicode hostnames are rejected.

## Tests and cross-builds

```sh
go test -race ./...
go vet ./...
./scripts/cross-build.sh
```

The console has its own loopback listener. It requires the configured Host, rejects cross-origin API access, and requires a per-process token and same-origin JSON PUT for edits. Scripts, styles, and icons are served locally with a restrictive Content Security Policy. The interface stores aggregate counters, not browsing URLs, headers, bodies, or credentials. Open the printed numeric address rather than a hostname alias.

Tests use in-process fixtures and localhost HTTP/TLS/TCP servers. They never run the legacy executable or call embedded service endpoints. The build script produces six CGO-free binaries in `dist/`; it does not execute them. See [VALIDATION.md](VALIDATION.md) for checks actually performed and sandbox limitations. Compilation alone does not establish native runtime compatibility.

## Scope and evidence

The first proxy foundation is approved and implemented. HTML rewriting, prefetch/cache, native desktop/tray integration, automatic browser changes, updates, clock changes, and MTU tuning are outside this build.

- [Approved specification](SPEC.md)
- [Annotated legacy evidence](reference/code-reference.md)
- [Static inspection report](reference/inspection-report.md)
- [Original application disassembly](reference/application-disassembly.txt)
- [Imports and resource inventory](reference/inventory.json)

Confirmed legacy evidence includes listener calls, HTTP templates, selected browser-configuration routines, and a conditional cookie-inclusion branch. Loopback-only port 8081, explicit cookie stripping, domain policy, restricted CONNECT, timeouts, metadata logging, and the local browser console are **new design choices**. The original cookie predicate and complete filtering/cache algorithms remain unknown. Reference files are preserved; the original EXE has never been executed during this work and is not included in the project.
