# nscope.exe — static inspection and internal walkthrough

Inspected 21 October 2026. Source: `/Users/afzal/Downloads/nscope.exe`.

## Result

This sample is a self-extracting installer containing **Naviscope**, a legacy Windows HTTP proxy/browser utility. It contains substantial evidence for ad filtering, prefetching, browser proxy configuration, HTTP logging, diagnostics, and self-upgrade features. This pass found no substantive evidence of business-data migration, database conversion, or ETL behavior. That is a bounded negative finding, not proof that no such behavior exists anywhere.

The executable and its extracted application were never executed, loaded as libraries, debugged, emulated, or installed. Inspection used file reads, PE parsing, bounded gzip decompression, string extraction, and offline disassembly. No embedded address was contacted and no sample was uploaded to a scanning service. The source was not modified.

## Confirmed file structure

| Property | Installer | Embedded application |
|---|---|---|
| Size | 628,930 bytes | 1,277,440 bytes |
| Format | PE32, x86/i386, Windows GUI | PE32, x86/i386, Windows GUI |
| Preferred image base | 0x00400000 | 0x00400000 |
| Entry point at preferred base | 0x004087C0 | 0x00451C00 |
| PE timestamp | 24 October 1999, 07:02:54 UTC | 24 May 2000, 10:16:48 UTC |
| Linker version | 4.20 | 4.20 |
| CLR directory | Absent | Absent |
| Debug directory | Absent | Absent |
| Authenticode certificate directory | Empty | Empty |
| Named import DLLs | 3 | 10 |

These timestamps are header values, not independently verified build dates. Both files have `.text`, `.rdata`, `.data`, `.idata`, `.rsrc`, and `.reloc` sections. Symbol and line-number stripping flags are set. The application has 214 resource leaves, including UI content and version information; the installer has five.

Installer SHA-256:
`21a71f2648fa796fdc0a52932931b420603880ef2f4eb0f992fdfba6c6b0abbd`

Embedded application SHA-256:
`d712af9bf617502b30a6872cc120868f855aec7866fc503a9196fd13cb0bc652`

## The installer, up close

The installer PE's raw sections end at file offset **0x1E400**. The remaining **505,026 bytes** form a gzip stream. Its original-name header says `compr.dat`. Decompression completed with checksum validation and no unused trailing input, producing **1,760,447 bytes**.

The uncompressed structure is exact:

| Payload offset | Length | Interpretation |
|---|---:|---|
| 0x0 | 16 | Four little-endian 32-bit values: 1,277,440; 481,341; 1,650; 0 |
| 0x10 | 1,277,440 | Valid PE application, exporting module name `naviscope.exe` |
| 0x137E10 | 481,341 | Legacy Windows Help content, with WinHelp signature |
| 0x1AD64D | 1,650 | Help contents text beginning `:Base Navhelp.HLP` |

The sizes plus the 16-byte header account for every byte. The help filenames are supported by installer strings `navhelp.hlp` and `navhelp.cnt`; the payload does not contain a normal archive filename directory.

Wrapper strings include `Setup.exe`, `naviscopi.exe`, `nscopex.gz`, `nscopex.dat`, `COPYTO=`, `NSI%x\\`, and installation error messages. Embedded zlib strings identify deflate/inflate **1.1.3**.

Code near **0x4016DD–0x401748** obtains its own executable path, opens that file, and seeks within it. Code near **0x40181A** formats a temporary-directory name, and **0x401868** calls `CreateDirectoryA`. Further code constructs the compressed/data filenames and writes files. Imports include `CreateProcessA` and `WaitForSingleObject`, supporting a child-installer handoff. Full handoff and cleanup semantics were not reconstructed here.

Interpretation: the large compressed tail is an installer payload. Its compression alone is not evidence of malicious packing.

## Runtime, compiler, version, and dependencies

**Confirmed:** native x86 code, no CLR metadata directory, Microsoft Visual C++ runtime/debug-library text, C runtime routines, and linker version 4.20. No `MSCOREE.dll`, VB runtime, or separate Visual C++ runtime DLL occurs in the ordinary import table.

**Strong inference:** an older Microsoft Visual C/C++ toolchain with substantial statically linked runtime code. Linker metadata is consistent with the Visual C++ 4.x era, but it cannot identify the exact compiler build. Debug-related strings do not restore source symbols or prove the whole program is a debug build.

Version metadata conflicts: the fixed file/product version is **3.5.0.0**, while the string file/product versions are **1.00**. A resource credits Alex Chernyakov and Michael Fritz. Copyright resources mention 1996 while application text mentions 1997–2000. Treat these as embedded claims, not a verified release history.

The application imports **334 entries** across:

| DLL | Count | Relevant capabilities |
|---|---:|---|
| KERNEL32.dll | 126 | File I/O, processes, threads, synchronization, dynamic loading, system time |
| USER32.dll | 116 | Windows UI, messages, DDE, clipboard, legacy help |
| GDI32.dll | 35 | Drawing and printing |
| comdlg32.dll | 5 | File, font, color, print dialogs |
| ADVAPI32.dll | 12 | Windows registry and username |
| VERSION.dll | 3 | File version inspection |
| WSOCK32.dll | 23 | Legacy Winsock networking; imports are by ordinal |
| COMCTL32.dll | 1 | Common-controls ordinal 17 |
| SHELL32.dll | 6 | Tray icon and shell-folder integration |
| ole32.dll | 7 | COM/OLE and drag-and-drop |

The wrapper imports KERNEL32.dll, USER32.dll, and COMCTL32.dll, totaling 86 entries.

Application strings also reference `ICMP.DLL`, `IcmpCreateFile`, `IcmpSendEcho`, `IcmpCloseHandle`, `rasapi32.dll`, and `WININET.DLL`. These are clues for optional/dynamically resolved dependencies; their actual loading paths and runtime availability were not exhaustively traced. Imported `LoadLibraryA` and `GetProcAddress` mean the ordinary import table is not a complete dependency list.

Eight preserved export names include `NR_RegOpen`, `NR_RegClose`, `NR_RegGetKey`, `NR_RegGetEntry`, and registry enumeration/startup/shutdown functions. They give useful analysis anchors. Their provenance and exact on-disk registry format are not established by those names alone.

## Internal application behavior

### 1. Browser configuration — code-backed

The application contains browser-specific configuration for Internet Explorer, Netscape, and Opera. Strings include:

- `Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings`
- `ProxyEnable`, `ProxyServer`
- `\\prefs.js`, `OPERA.INI`
- `user_pref("network.proxy.type", 1);`
- `user_pref("network.proxy.http", "127.0.0.1");`
- `user_pref("network.proxy.http_port", `

In the Netscape code:

- **0x447D7F** references `network.proxy.type` and calls the string-search helper at 0x4273C0.
- **0x447D9E** selects the preference template when that setting is missing; subsequent instructions append it to a buffer.
- **0x447DD7–0x447E4F** parses an existing preference, saves the old numeric value, and changes its value character to `1`; malformed inputs take error exits.
- **0x447E52** searches for the HTTP proxy host preference.
- **0x447E6D** selects the template containing `127.0.0.1` when the host preference is absent.

Readable reconstruction of these branches, with analyst-assigned names:

```text
find the proxy-type preference in the loaded preferences buffer
if missing:
    append the manual-proxy preference template
else:
    find the value and validate its syntax
    preserve its old numeric value
    change it to manual-proxy mode

find the HTTP proxy host preference
if missing:
    append a preference naming 127.0.0.1
else:
    process the existing host preference

process the HTTP proxy port preference
```

This is an explanation of inspected assembly, not recovered original source. The full persistence/restore path has not been audited.

At **0x448AD0**, another routine queries `ProxyEnable`, updates that registry value, reads `ProxyServer`, calls a helper to construct replacement proxy configuration, and writes `ProxyServer` back. The indirect calls resolve to `RegQueryValueExA` and `RegSetValueExA` through the import table. Proxy formatting includes separate FTP, Gopher, HTTP, HTTPS, and SOCKS fields, with the HTTP field redirected to localhost.

### 2. Local network listener — code-backed

UI resource text explicitly identifies a listening-port default of **81**. It also contains a setting to reject non-local connections. These are UI claims; their defaults/enforcement require tracing the associated state.

The networking code independently supports the listener interpretation:

- **0x43D379** loads `0x51` (81), then calls a thunk for WSOCK32 ordinal 9, the legacy `htons` API.
- **0x43D3B0** calls the thunk at 0x44C4BC, which jumps through the import slot for WSOCK32 ordinal 2 (`bind`).
- **0x43D405** calls the thunk at 0x44C4B6, which resolves to ordinal 13 (`listen`), with backlog 5.
- **0x43D16A** calls the thunk for ordinal 1 (`accept`); its failure path references `Network Error on accept(): %d`.

These locations show connection acceptance and listener setup. They do not establish that every listener branch uses port 81 or that the listener is always restricted to loopback.

### 3. HTTP filtering, cookies, prefetching — mixed evidence

Confirmed embedded content includes HTTP request/response templates, HTML/JavaScript injection markers, ad-blocking replacement text, cookie header strings, and help topics for prefetching, comment-pair filtering, background/sound/blink blocking, and site-specific privacy rules.

One inspected request-building branch is especially concrete:

- **0x43C0D0** checks whether a cookie-related buffer is empty.
- **0x43C0E6** calls another predicate.
- **0x43C0F6** tests flag bit `0x02`; when set, the code skips the cookie append block.
- **0x43C101–0x43C15D** appends the literal `Cookie: ` and the buffered cookie value to an output string.

Thus conditional inclusion of a Cookie header is code-backed. The exact meaning of the predicate and flag is inferred from surrounding feature text; it has not been fully recovered.

The help describes prefetching links whose displayed names match configured phrases, keeping a bounded cache and optionally traversing multiple levels. This is strong functional documentation, but this inspection has not traced the complete prefetch scheduler, eviction algorithm, or HTML parser.

### 4. Other capabilities — strings/imports, not runtime observation

Evidence supports intended features for HTTP header/activity logging, a site mapper, Ping/traceroute, browser shortcuts/startup integration, time adjustment, and legacy Windows MTU/RWIN configuration. Imports include `SetSystemTime`; strings describe clock adjustment and Windows 95 network tuning.

Embedded HTTP templates reference Naviscope version checking, upgrades, registration, and a time service, including `/cgibin/vcheck.cgi`, `/cgibin/regcgi.cgi`, and `/cgibin/timecgi.cgi`. These are static historical addresses. They were not contacted, and their availability, ownership today, and actual request contents were not established.

## Migration assessment

No database-client DLL appears in the ordinary imports, and the inspected meaningful strings do not expose a database schema, SQL migration scripts, business-record mappings, or source/target conversion workflow. Arbitrary bitmap/compressed bytes can accidentally spell short fragments such as `sql`; those are not meaningful SQL evidence.

Installation, software upgrade, preferences changes, and browser integration are present. They should not be conflated with business-data migration. This could still have been used in a larger historical workflow, but that role would require outside context.

## Practical reverse engineering and rebuild plan

1. **Analyze the embedded application, not only the wrapper.** This pass has already recovered its exact byte range. Use the application hash above to identify it in later work.
2. **Import it as x86 PE into Ghidra, IDA, or Hopper.** Begin with browser configuration, the listener, cookie handling, registry exports, and feature-string references listed here. Ghidra supplies static disassembly/decompilation; REA can expose supported engines to an agent. Neither guarantees original source recovery.
3. **Use REA only in offline/static mode for this scope.** Avoid launch, attach, injection, emulation, or runtime-observation workflows. REA was not installed or invoked in this pass, and no native decompiler was available on the current command path. The supplied listings are disassembly, not a full decompilation.
4. **Recover behavior into a specification.** Trace the HTTP parser, per-site rules, cookie policy, prefetch queue/cache, persisted settings, and browser restore/uninstall behavior. Document encodings, failure paths, size limits, state structures, and cross-references.
5. **Choose a bounded replacement.** A feature-focused reconstruction is realistic. A faithful, modern, full-product rebuild is substantially harder: original types, names, build files, assets' provenance, server implementations, and exact behavior are not recovered. The code targets old browser preferences, Windows APIs, and HTTP-era assumptions.
6. **Validate with offline fixtures first.** Use synthetic HTTP messages, HTML documents, and copied preference files. For an actual data-migration requirement, obtain representative source/target datasets and expected outputs before deciding this application is relevant. Any later execution of the original would be a separately authorized phase.

HTTPS is explicitly mentioned in proxy configuration templates, but this does not establish TLS interception or modern HTTPS compatibility. A rebuild needs an explicit design for present-day browser traffic and encryption rather than assuming that the original HTTP filters can inspect encrypted responses.

The embedded license text contains a reverse-engineering prohibition. This report records that text as sample content; it makes no determination about its enforceability or your rights.

Tool references: [official REA repository](https://github.com/morluto/rea), [official Ghidra repository](https://github.com/NationalSecurityAgency/ghidra).

## Evidence files and limitations

- `inventory.json`: section layouts, hashes, import entries with addresses, resource leaf locations.
- `application-headers.txt`: PE headers, imports, exports from the recovered application.
- `application-disassembly.txt` and `wrapper-disassembly.txt`: offline x86 listings, with indirect import calls annotated where possible.
- `application-strings.json`: ASCII strings with file offsets and preferred virtual addresses.
- `application-all-strings.json` and `wrapper-all-strings.json`: ASCII and printable UTF-16LE candidates with file offsets. These include unrelated binary coincidences.
- `help-contents.txt`: extracted help topic index.

Addresses assume the preferred image base. Disassembler labels such as `NR_ShutdownRegistry+...` outside the actual exported routine often reflect nearest-symbol formatting; they are not reliable function boundaries. String cross-references were checked against instructions for the highlighted examples, but a full control-flow/type analysis and all-path behavior proof remain outstanding. No claim of malware absence, modern compatibility, or functional equivalence is made.
