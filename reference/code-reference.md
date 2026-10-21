# Naviscope code reference for a portable Go rebuild

This reference connects inspected x86 instructions to readable behavior and proposed Go equivalents. It is **not original source**, not a complete decompilation, and not evidence that an equivalent Go product has been built. The original executable remains unexecuted.

Binary: embedded `naviscope.exe`, SHA-256 `d712af9bf617502b30a6872cc120868f855aec7866fc503a9196fd13cb0bc652`. All addresses below use preferred image base 0x00400000.

## Reading the evidence

- **Observed:** present in the binary or verified disassembly.
- **Reconstructed:** a readable interpretation of selected instructions, with analyst-assigned names and omitted low-level details.
- **Proposed:** a new implementation decision, not attributed to the old program.

The full instruction listing is in [application-disassembly.txt](application-disassembly.txt). Search for each address without the `0x` prefix. The listing has real addresses and import annotations; nearest-export labels after addresses must not be mistaken for function names. Source variables, original function boundaries, C/C++ types, and source filenames remain largely unknown.

## 1. Listen for browser connections

**Observed:** the routine parses a configured port near 0x43D349, uses 81 when its low 16 bits are zero, converts it to network byte order, binds, listens, and elsewhere accepts connections.

```asm
43d349: push 0x47dde2       ; configured port text
43d34e: call 0x44e470       ; conversion helper, interpreted as numeric conversion
43d356: test ax, ax
43d359: jne  0x43d37d
...                        ; default-port text copied into configuration
43d379: mov  ax, 0x51      ; fallback 81
43d37d: push eax
43d37e: call 0x44c4a4      ; WSOCK32 ordinal 9: htons
...
43d3b0: call 0x44c4bc      ; WSOCK32 ordinal 2: bind
...
43d3fc: push 5             ; backlog
43d405: call 0x44c4b6      ; WSOCK32 ordinal 13: listen
```

**Reconstructed concept:**

```text
port = convert(configuredPort)
if low16(port) == 0:
    configuredPort = "81"
    port = 81
address.family = IPv4
address.port = htons(port)
bind(socket, address)
listen(socket, backlog=5)
```

The inspected code also initializes the address field to zero at 0x43D341. A loopback restriction must therefore be verified in acceptance/filtering code, not inferred from the browser pointing at localhost. UI strings alone do not establish enforcement.

**Proposed Go equivalent:** use `net.Listen("tcp", "127.0.0.1:8081")` and `http.Server.Serve`. Go handles byte order and socket details. A loopback listener and unprivileged port are deliberate modern choices, not translations of the original bind address. Do not reproduce unvalidated integer truncation from the legacy parser.

## 2. Route browser HTTP through the proxy

**Observed Netscape references:**

| Instruction | Referenced text / operation |
|---|---|
| 0x447D7F | Search `network.proxy.type` |
| 0x447D9E | Select `user_pref("network.proxy.type", 1);` when absent |
| 0x447DD7–0x447E4F | Find value, validate, preserve numeric setting, change first value character to `1` |
| 0x447E52 | Search `network.proxy.http"` |
| 0x447E6D | Select `user_pref("network.proxy.http", "127.0.0.1");` when absent |
| 0x447F69 / 0x447F9C | HTTP proxy port key and template references |

**Observed Windows registry references:** routine at 0x448AD0 queries and updates `ProxyEnable`, reads `ProxyServer`, invokes 0x4488B0 to construct proxy text, and writes `ProxyServer`. The registry key string is `Software\Microsoft\Windows\CurrentVersion\Internet Settings`.

**Observed formatter at 0x4488B0:** an empty existing proxy string produces `http=127.0.0.1:<port>`. A separate branch expands a plain proxy into protocol fields, with this format string:

```text
ftp=%s:%s;gopher=%s:%s;http=127.0.0.1:%s;https=%s:%s;socks=%s:%s
```

**Proposed portable approach:** configure a browser manually, or use its explicit proxy settings for a development profile. Do not carry Windows registry writes or Netscape `prefs.js` edits into the shared core. Future automatic integration belongs in separate `*_windows.go`, `*_darwin.go`, and `*_linux.go` adapters with saved previous settings and an explicit restore operation.

## 3. Conditionally include cookies

**Observed code:**

```asm
43c0d0: cmp byte ptr [eax], 0  ; skip if cookie buffer empty
43c0d3: je  0x43c193
...
43c0e6: call 0x43b000          ; predicate not fully reconstructed
43c0ee: test eax, eax
43c0f0: je  0x43c193
43c0f6: test byte ptr [esp+0x28], 0x02
43c0fb: jne 0x43c193
43c101: mov edi, 0x4749e4      ; literal "Cookie: "
...                          ; append header name and cookie value
```

**Reconstructed Go-like reference, not a runnable implementation:**

```go
// Names describe observed roles; original names and predicate semantics are unknown.
if cookieValue != "" && legacyPredicate(context) && flags&0x02 == 0 {
    appendRequestHeader("Cookie", cookieValue)
}
```

**Proposed Go policy:** a clearly named `StripRequestCookies` setting removes the outbound request's `Cookie` header. Keep response `Set-Cookie` handling independent: stripping request cookies is not the same operation as preventing a browser from storing cookies. Do not claim that the unknown original predicate is already reproduced.

## 4. Process HTTP and HTML

**Observed strings:**

- `GET /%s HTTP/1.0` and `GET http://%s:%d/%s HTTP/1.0`.
- HTTP response templates including 200, 302, 304, and 400.
- `<!-- BEGIN Naviscope Ad Blocker //-->` and corresponding end marker.
- `accept-encoding: `, `Content-length:`, `Cookie: `.
- JavaScript templates communicating with special `---naviscope---` hostnames.

These support an HTTP intermediary with response modification. They do not identify a complete parser or exact modern equivalent.

**Proposed Go design:** accept explicit-proxy HTTP requests, validate their absolute target URLs, clone requests, clear `RequestURI`, remove hop-by-hop and proxy credentials, then forward with a dedicated `http.Transport` whose `Proxy` is nil. That prevents accidental reuse of environment proxy configuration and loops. Preserve streaming for responses that do not need transformation.

For HTML rules, use a real HTML tokenizer/parser rather than regular expressions. Transform only supported `text/html` responses within a configured size bound. Handle content encoding, Content-Length, validators, and compressed/partial responses explicitly. Request-cookie policy and host blocking can ship before HTML rewriting; the latter should not be silently advertised as complete.

## 5. Prefetch and cache

**Documented by the embedded help, not fully traced:** prefetch links by displayed link phrases; configurable cache count and traversal depth; optional per-site rules. The help notes a cache-count range of 5–100. Complete scheduling and eviction logic is not recovered.

**Proposed later Go implementation:** a bounded queue and worker pool, GET-only candidates, same-origin by default, finite depth/bytes/concurrency, cancellation, and explicit cache semantics. Make this opt-in. Existing cookies, authorization, and personalized responses must be considered before selecting cache keys or sharing entries. A general web crawler would not be an equivalent substitute.

## 6. Installer container

**Observed layout:** gzip starts at installer file offset 0x1E400 and occupies 505,026 bytes. Its decoded body starts with four little-endian uint32 values:

```text
[1277440, 481341, 1650, 0]
[application bytes][WinHelp bytes][help contents text]
```

All lengths account exactly for the 1,760,447-byte decoded body. This is useful for extraction/reproducibility, but a Go rebuild does not need this old installer format. Use per-platform binaries and a portable configuration file.

## 7. Evidence-to-Go map

| Legacy component | Evidence strength | Portable Go direction |
|---|---|---|
| Connection listener | Traced calls | `net.Listener`, `http.Server` |
| Outbound HTTP | Imports + request templates + selected code | `http.Transport`, explicit proxy handler |
| Cookie inclusion | Selected branch traced | Independent request-cookie policy |
| Browser configuration | Selected routines traced | Manual setup first, later OS adapters |
| HTML ad filtering | Templates/help; algorithm incomplete | Tokenizer-based transform with fixtures |
| Prefetch cache | Help; scheduler incomplete | Separate bounded queue/cache stage |
| Registry/configuration | Imports, strings, selected code | JSON file plus platform config directory |
| Toolbar/tray | Resources and Windows imports | Later desktop UI layer |
| Legacy updates/time/MTU changes | Strings/imports | Separate product decisions |

## 8. Realistic source recovery status

Available now: full offline assembly listing, imported API names/ordinals, preserved exports, strings with addresses, resources inventory, selected manual reconstructions, and this implementation map.

Still needed for deeper fidelity: native decompiler output, function boundary/type recovery, call graphs for filtering/prefetching, config layout recovery, and fixture-based behavior specifications. Original C/C++ source, comments, project files, and server source have not been recovered. Any new Go program should state which behaviors are implemented and which are inferred or omitted.

Official implementation references: [Go HTTP](https://pkg.go.dev/net/http), [Go HTTP proxy helpers](https://pkg.go.dev/net/http/httputil), [Go build target environment](https://go.dev/doc/install/source#environment), [Ghidra](https://github.com/NationalSecurityAgency/ghidra), [REA](https://github.com/morluto/rea).
