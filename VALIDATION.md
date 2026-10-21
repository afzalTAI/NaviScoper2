# Validation record

Date: 2026-10-21. Host: macOS arm64, Go 1.26.0. No external dependencies were added. The original application was never executed and reference material was not modified.

## Completed

- **25 top-level tests, plus subtests, passed with race detection** using the selection below. Tests cover CLI validation/help, HTTP target validation, domain boundaries, default/stripped cookies, hop-by-hop headers, duplicate headers, trailers, original query bytes, response streaming, errors, cancellation, metadata redaction, buffered CONNECT traffic, tunnel lifetime/cleanup, and pending-dial cancellation.
- In-memory server/transport integration tests exchanged actual HTTP and TLS protocol messages over `net.Pipe`. They verified upstream connection reuse, end-to-end TLS with certificate verification, encrypted-cookie preservation, listener shutdown, normal HTTP draining, and cancellation after the shutdown deadline. These tests do not exercise OS TCP behavior.
- `go vet ./...` passed; Go files are formatted with `gofmt`.
- `go build -trimpath -o dist/nscope ./cmd/nscope` passed. The newly built native CLI's `-help` ran successfully.
- `./scripts/cross-build.sh` succeeded for all six targets with `CGO_ENABLED=0`. `file` confirmed the expected Mach-O, ELF, and PE architectures.

| Target | Artifact | Result |
|---|---|---|
| macOS amd64 | `dist/nscope-darwin-amd64` | Compiled |
| macOS arm64 | `dist/nscope-darwin-arm64` | Compiled |
| Linux amd64 | `dist/nscope-linux-amd64` | Compiled |
| Linux arm64 | `dist/nscope-linux-arm64` | Compiled |
| Windows amd64 | `dist/nscope-windows-amd64.exe` | Compiled |
| Windows arm64 | `dist/nscope-windows-arm64.exe` | Compiled |

The writable temporary cache was required by the execution sandbox:

```sh
export GOCACHE=/private/tmp/naviscope-go-cache
go test -race ./... -run 'Test(ParseConfig|CLIRejectsInvalidConfiguration|HelpDoesNotStartListener|DomainPolicy|RejectInvalidRequests|ConfigValidation|TargetAuthorities|ForwardPreservesQueryHostAndDefaultCookies|UpstreamFailureAndDeadline|MetadataExcludesSensitiveFields|HopHeadersCookieRemovalAndResponseTrailers|ForwardStreamsBeforeUpstreamEOF|CONNECTInMemory.*|CONNECTPolicyAndValidationWithoutDial|HTTPInMemoryTransportReuseAndShutdown|TLSInMemoryEndToEnd|ShutdownInMemoryDrainsOrCancelsHTTP|FrontendFlags|LivePolicyUpdatesAndCounters|ConcurrentPolicyAccess|EmbeddedInterfaceAndState|PolicyAPI|ConsoleRejects.*)$' -timeout 30s -v
go vet ./...
./scripts/cross-build.sh
```

## Pending validation

The full `go test -race ./... -timeout 30s` command was attempted. It fails when `httptest.NewServer` tries to bind a localhost fixture: `bind: operation not permitted`. This session's automatic approval review rejected sandbox escalation. Tests were not disabled or converted into silent skips.

Seven localhost test functions remain unvalidated here: HTTP forwarding through sockets; client and upstream TCP half-close; HTTPS through TCP; invalid CONNECT authorities/ports and blocked hosts through sockets; tunnel deadline/close through sockets; and shutdown of a socket listener with an active tunnel. Their source is in `internal/proxy/proxy_test.go` and `internal/proxy/tunnel_test.go`.

Run the complete suite on a machine that permits localhost listeners:

```sh
go test -race ./...
go vet ./...
```

## Browser interface validation

The frontend extension adds race-tested live policy updates and immutable snapshots, aggregate counters, concurrent access checks, embedded asset/API responses, CLI frontend flags, validation of policy JSON, oversized-body rejection, and cross-origin/Host/token protection tests. Invalid policy updates preserve the active rules, including null or incomplete updates.

`node --check internal/console/web/app.js` passed. `go vet ./...` and all six embedded-frontend cross-builds passed. No npm packages were added.

Live startup was attempted with `go run ./cmd/nscope`; the sandbox rejected binding `127.0.0.1:8081`. Chrome DevTools automation also failed because its browser profile was already in use. Visual/responsive checks and end-to-end browser interactions therefore remain **unverified**. No existing browser process was stopped or profile modified.

Live shutdown validation (2026-10-21, macOS/arm64): `go run ./cmd/nscope` with terminal-style process-group SIGINT exits cleanly; SIGTERM to the `go` parent exits cleanly; SIGKILL of the `go` parent previously left an orphaned child holding 8081/8082 (reproduced, including a leftover orphan from an earlier session) and now exits within ~1s via the parent watchdog. The installed `dist/nscope` binary exits immediately on SIGINT. Verified with `go test -race ./...` and `go vet ./...` passing.

Menu-bar agent validation (2026-10-21, macOS/arm64): `sh scripts/build-macos-app.sh` built an ad-hoc signed `dist/NaviScope.app` (plist lint OK). `open` launched it parented to launchd; ports 8081/8082 served, `-deny example.com` produced 403 for the blocked host and 200 for an allowed host, and `/api/state` reported `paused:false`. `sample` confirmed `navi_menu_run → -[NSApplication run]` on the main thread (status item installed; earlier non-main-thread instantiation crashed and was fixed by pinning the main goroutine in `init`). Two SIGTERM runs exited cleanly with ports released. Pause/toggle and visual menu appearance were **not** machine-verified: the sandbox lacks screen-capture and assistive access. `gofmt`, `go vet ./...`, `go test -race ./...`, the six CGO_ENABLED=0 cross-builds, and a CGO_ENABLED=0 linux build of `cmd/nscope-menu` (stub) all passed.

Routing, secure DNS, upstream, and DMG validation (2026-10-21, macOS/arm64): `internal/sysproxy` Route applied 127.0.0.1:8081 system-wide (scutil showed HTTP/HTTPS enabled to it during the window) and Restore returned every service to its exact prior state (verified per-service via networksetup); a live partial-failure incident forced an all-or-nothing rollback redesign, now unit-tested, and the polluted services were manually restored. Live DoH: `-secure-dns cloudflare` proxied http://example.org with 200. Live chaining: `-upstream http://127.0.0.1:8096` delivered HTTPS 200 through the second instance with its connect counter 0→1 (an http:// URL through the chain 502s because the upstream NaviScope correctly enforces its 443-only CONNECT whitelist — policy, not breakage). `scripts/build-dmg.sh` produced a 12.6 MB universal DMG; the mounted image's app served 200 via its proxy and exited on SIGTERM with ports released (one run needed several seconds, within the 5s drain budget). `gofmt`, `go vet ./...`, `go test -race ./...` (all seven packages), and all six `CGO_ENABLED=0` cross-builds passed. Menu clicks (including Route system traffic) remain unverified by machine (no assistive/screen access); unit tests cover the underlying Manager logic.

Native socket/runtime checks on all six OS/architecture combinations remain required before claiming release support. The full acceptance gate in SPEC.md is therefore **not yet satisfied**, despite successful compilation and in-process validation.
