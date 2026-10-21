# NaviScope

A fast, local HTTP/HTTPS proxy for macOS, Linux, and Windows — with a macOS menu-bar agent, secure DNS, upstream chaining, and a built-in web console. Standard library only; no third-party dependencies.

NaviScope sits between your apps and the internet: it forwards HTTP, tunnels HTTPS end-to-end without decrypting it, filters domains you choose, can resolve every hostname over encrypted DNS, and can chain all traffic through an upstream provider (for example Cloudflare Warp). You stay in control from a menu-bar icon or a browser dashboard — nothing about your system is changed silently.

## Features

| Capability | What it does |
|---|---|
| **HTTP forwarding** | Explicit-proxy forwarding with hop-by-hop header hygiene, query/host preservation, and bounded timeouts |
| **HTTPS tunneling** | CONNECT byte tunnels — end-to-end TLS between you and the site; NaviScope never decrypts, strips, or caches HTTPS |
| **Domain filtering** | Block domains (subdomains included) and strip outbound HTTP cookies, editable live from the console or menu |
| **Menu-bar agent** (macOS) | Status, filtering on/off, system-traffic routing, dashboard, and quit — one click in the menu bar |
| **System routing** (macOS) | Point the system-wide proxy at NaviScope with automatic snapshot/restore |
| **Secure DNS** | DNS-over-HTTPS via Cloudflare, Google, Quad9, or OpenDNS — no plaintext DNS, no ISP visibility |
| **Upstream chaining** | Route all traffic through a SOCKS5 or HTTP CONNECT provider (Warp, corporate proxy, self-hosted) |
| **Web console** | Live counters, policy editing, and connection instructions at `127.0.0.1:8082` |
| **Hard boundaries** | IPv4 loopback-only listeners, CONNECT port whitelist, bounded tunnels, graceful shutdown, race-tested |

## Install (macOS)

Requires Go 1.26+ and Xcode Command Line Tools.

```sh
git clone https://github.com/afzalTAI/NaviScoper2.git
cd NaviScoper2
sh scripts/build-dmg.sh        # → dist/NaviScope-0.1-universal.dmg
open dist/NaviScope-0.1-universal.dmg   # drag NaviScope into Applications
```

- **Universal binary** — Apple Silicon and Intel in one app.
- Minimum macOS: **10.15 Catalina**.
- The DMG is ad-hoc signed: right-click → **Open** once to pass Gatekeeper.
- No Dock icon — look for the antenna icon 📡 on the **right** side of the menu bar.

Then flip **Route system traffic** in the agent menu, or point your browser's HTTP/HTTPS proxy at `127.0.0.1:8081` manually.

## Quick start (any OS)

```sh
go build -o dist/nscope ./cmd/nscope
./dist/nscope
# or straight from source:
go run ./cmd/nscope
```

Set your browser or system proxy to `127.0.0.1:8081` and open **http://127.0.0.1:8082** for the console. Stop with Ctrl-C (press twice to force-quit immediately); SIGTERM/SIGHUP also drain gracefully.

## The menu-bar agent (macOS)

Built with `sh scripts/build-macos-app.sh` (or taken from the DMG), the agent runs the full proxy plus:

| Menu row | Behavior |
|---|---|
| **Status** (grayed) | State, uptime, and live counters — refreshed every time the menu opens |
| **Filtering enabled** | Pause/resume: traffic keeps flowing while deny rules and cookie stripping are suspended; the CONNECT port whitelist stays enforced |
| **Route system traffic** | Sets the macOS system-wide HTTP/HTTPS proxy to NaviScope (snapshots first; quitting restores exactly what was there; needs an admin-group user) |
| **Open dashboard…** | Opens the web console |
| **Quit NaviScope** | Same graceful drain as Ctrl-C |

All startup flags work: `open NaviScope.app --args -deny example.com -secure-dns quad9`.

If the app is ever force-killed while routing system traffic, run `sh scripts/unset-system-proxy.sh` to restore your settings. Routing applies to apps that honor system proxy settings (browsers and most GUI apps); command-line tools and raw DNS are unaffected.

## Secure DNS

Resolve every hostname over DNS-over-HTTPS — your ISP (or anyone on the network) no longer sees your DNS lookups:

```sh
./dist/nscope -secure-dns cloudflare   # or google | quad9 | opendns
./dist/nscope -secure-dns https://1.1.1.1/dns-query   # custom endpoint (IP-literal host)
```

- Preset providers use pinned bootstrap IPs; the endpoint hostname itself never leaks to plaintext DNS.
- Strict mode: if DoH fails, lookups fail — there is no silent fallback to the system resolver.
- A/AAAA queries, CNAME chains, and compression handled per RFC 1035/8484, with a TTL-honoring cache.
- Hostnames never appear in logs or error messages.

## Upstream chaining (Warp-style tunneling)

Send all NaviScope traffic through a SOCKS5 or HTTP CONNECT provider:

```sh
./dist/nscope -upstream socks5://127.0.0.1:40000          # Cloudflare Warp local proxy
./dist/nscope -upstream http://user:pass@proxy.example.net:3128
./dist/nscope -secure-dns quad9 -upstream socks5://127.0.0.1:40000
```

To combine with [Cloudflare Warp](https://1.1.1.1): install Warp, run `warp-cli set-mode proxy` (SOCKS5 on `127.0.0.1:40000`), then start NaviScope with the upstream flag above. Every outbound connection — HTTP and HTTPS tunnels alike — flows through the provider; HTTPS remains end-to-end encrypted.


## Transparent routing (all traffic, sudo)

Stage 2 of automatic routing captures **all** IPv4 traffic — every app, CLI tools, DNS — through a `utun` device into NaviScope's userspace network stack:

```sh
sudo ./dist/nscope -tun                       # all traffic; DNS via DoH (cloudflare default)
sudo ./dist/nscope -tun -secure-dns quad9 -upstream socks5://127.0.0.1:40000
```

- **macOS 27 gate**: Apple restricts raw utun creation to entitled apps on macOS 27 (`-tun` reports this at startup; verified with a native-C probe as root — the kernel refuses the `com.apple.net.utun` controller lookup). On affected systems use **Route system traffic** plus `-upstream` (Warp) instead, which covers apps that honor system proxy settings without a TUN device.
- NaviScope's own sockets are pinned to the physical interface (`IP_BOUND_IF`) so they can never loop back into the tunnel.
- Non-DNS UDP is relayed directly (not through an upstream).
- Crash-safe: the tunnel routes vanish with the process, so a killed tunnel self-heals the routing table.
- HTTPS stays end-to-end encrypted; filtering inside the tunnel is domain-based (via DNS) rather than URL-based.

## Web console

`http://127.0.0.1:8082` (disable with `-no-ui`) shows session request counts, tunnel attempts, blocked requests, active connections, and connection limits. Edit blocked domains and cookie stripping live — changes apply to new requests immediately and last for the session. The console is loopback-only, host-pinned, token-guarded, and served with a restrictive CSP.

## Configuration

All configuration is via flags (no config files). The menu agent accepts the same flags via `--args`.

| Flag | Default | Behavior |
|---|---|---|
| `-listen` | `127.0.0.1:8081` | Proxy listener; literal IPv4 loopback only |
| `-ui-listen` | `127.0.0.1:8082` | Console listener; literal IPv4 loopback only |
| `-no-ui` | false | Run the proxy without the console |
| `-deny` | empty | Comma-separated domains/IPs to block; subdomains included |
| `-strip-request-cookies` | false | Remove outbound HTTP `Cookie` headers (response `Set-Cookie` untouched; HTTPS unaffected) |
| `-connect-ports` | `443` | Permitted CONNECT destination ports |
| `-secure-dns` | empty | DoH preset (`cloudflare`, `google`, `quad9`, `opendns`) or `https://IP/dns-query`; empty = system resolver |
| `-upstream` | empty | Chain all outbound traffic via `socks5://[user:pass@]host:port` or `http://host:port` |
| `-tun` | false | Transparent routing of all IPv4 traffic via utun (requires sudo; CLI only; DNS forced to DoH) |
| `-metadata-log` | false | JSON log of operation and target host/port only — never credentials, cookies, bodies, paths, or queries |
| `-request-timeout` | `2m` | Total HTTP exchange bound |
| `-tunnel-timeout` | `10m` | Maximum CONNECT tunnel lifetime |
| `-shutdown-timeout` | `5s` | HTTP drain period before forced cancellation |

## Building

```sh
go test -race ./...     # full suite, race detector
go vet ./...
go build -o dist/nscope ./cmd/nscope
sh scripts/cross-build.sh   # all six targets: darwin/linux/windows × amd64/arm64
sh scripts/build-macos-app.sh   # dist/NaviScope.app (universal)
sh scripts/build-dmg.sh         # dist/NaviScope-<version>-universal.dmg
```

Project layout:

```
cmd/nscope/          CLI proxy
internal/tunroute/   utun device, routes, and interface pinning
internal/tunstack/   userspace TCP/IP stack (gvisor) bridging flows to the outbound chain
cmd/nscope-menu/     macOS menu-bar agent (cgo/AppKit; stub elsewhere)
internal/proxy/      forwarding, tunnels, policies, pause mode
internal/doh/        DNS-over-HTTPS resolver (RFC 8484/1035)
internal/upstream/   SOCKS5 + HTTP CONNECT chaining (RFC 1928/1929)
internal/sysproxy/   macOS system-proxy routing with snapshot/restore
internal/console/    embedded web console
internal/cli/        shared flags and process lifecycle
scripts/             build + packaging + emergency unroute helpers
```

## Security notes

- Listeners bind to literal IPv4 loopback only; the proxy is not reachable from the network.
- HTTPS is never decrypted, re-signed, or inspected — NaviScope sees destinations, not contents.
- CONNECT destinations are whitelisted by port; tunnel lifetimes are bounded.
- System settings change only through explicit toggles, are snapshotted first, and are restored on quit (rollback on any partial failure).
- The console is loopback-only with host pinning, same-origin checks, a per-process token, and a strict CSP.
- Browsing URLs, bodies, cookies, and credentials are never logged.

## Roadmap

- TUN mode: IPv6 capture, non-DNS UDP via upstream, menu-agent integration
- Ubuntu 24.04+ (`.deb`) and Windows 11 packages
- Notarized DMG with a Developer ID

## License

Provided as-is for personal use. See repository for details.
