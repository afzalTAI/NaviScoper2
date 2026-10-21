# Repository Guidelines

## Project Structure & Module Organization

NaviScopeReborn is a planned portable Go reimplementation of selected Naviscope behaviors. Implementation has not started; `SPEC.md` awaits scope review.

- `README.md`: project status and reference entry points.
- `SPEC.md`: proposed proxy behavior, architecture, boundaries, and acceptance criteria.
- `reference/`: annotated reconstruction, disassembly, strings, and resource inventories. Preserve evidence and distinguish **Observed**, **Reconstructed**, and **Proposed** claims.
- Planned: `cmd/nscope/main.go` for CLI and shutdown; `internal/proxy/` for forwarding, tunnels, policies, and colocated tests.
- `dist/` and `config.local.json` are ignored build outputs and local configuration.

## Build, Test, and Development Commands

These commands apply after the Go module and implementation exist; they cannot currently run successfully:

```sh
go build -o dist/nscope ./cmd/nscope  # Build the CLI
go run ./cmd/nscope                  # Run locally
go test -race ./...                  # Run tests with race detection
go vet ./...                        # Run static checks
gofmt -w cmd internal               # Format Go source
```

Use the six macOS/Linux/Windows amd64/arm64 cross-build commands in `SPEC.md` before release. Record compilation and native runtime verification separately.

## Coding Style & Naming Conventions

Use standard Go formatting (`gofmt`, including tab indentation), idiomatic exported names, lowercase package names, and `*_test.go` test files. Prefer small functions, standard errors, and context cancellation. Keep the proposed shared core within the standard library. Identify evidence-derived behavior and deliberate new policies in comments. Obtain scope agreement before adding dependencies or expanding capabilities.

## Testing Guidelines

Use Go’s `testing` package and local `net/http/httptest` fixtures. Cover HTTP forwarding, header handling, cookie stripping, domain boundaries, CONNECT validation and buffered bytes, tunnel cleanup, and graceful shutdown. No numeric coverage threshold is specified; acceptance requires passing tests, race checks, vet, and target builds. Never execute the legacy application or contact its embedded service endpoints.

## Commit & Pull Request Guidelines

This checkout has no Git metadata, so existing commit conventions cannot be verified. Use concise, imperative commit subjects. PRs should explain the behavior changed, reference relevant specification sections or issues, and list validation results and limitations. Update documentation when scope or supported behavior changes.

## Security & Configuration

Preserve end-to-end TLS, enforce loopback listening, and restrict CONNECT destination ports as specified. Exclude credentials, cookies, bodies, queries, and full paths from default logs. Do not silently change browser or system settings.
