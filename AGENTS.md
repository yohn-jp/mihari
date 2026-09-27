# AGENTS.md

## Authority

Read `docs/requirements.md` and `docs/architecture.md` before changing runtime behavior. They define the current product contract.

When code and documentation disagree, do not silently reinterpret the architecture. Fix the code to the documented contract unless the task explicitly changes the contract.

## Product in one sentence

Mihari is a Windows-local diagnostic HTTP(S) proxy that observes where enterprise web traffic succeeds or fails, optionally terminates TLS to see URL paths, and never intentionally bypasses the existing enterprise network path.

## Hard constraints

- Windows PowerShell 5.1 is the language/runtime compatibility floor.
- PowerShell 7 must run the same code.
- Runtime implementation is PowerShell plus platform .NET/Windows APIs already present on the host.
- No Node.js, Python, separately built .NET application, native helper, external PowerShell module, package manager, or embedded C# source compilation.
- Keep `mihari.ps1` thin. Put behavior in small `src/*.ps1` files.
- Initial protocol baseline is HTTP/1.1 + CONNECT + TLS 1.2.
- TLS 1.3 interception, HTTP/2 parsing, HTTP/3, QUIC, packet capture, and kernel drivers are out of scope unless the task explicitly changes scope.
- Do not change global/system proxy settings as part of the normal browser workflow.
- Do not bypass enterprise proxies, TLS controls, firewall policy, or certificate validation.
- Do not persist CA private keys.
- Do not persist per-host leaf certificates.
- Do not disable remote TLS certificate validation globally.
- Do not log credential-bearing headers or bodies by default.

## Core diagnostic principle

Facts and diagnoses are different layers.

A connection timeout is a fact. "The proxy blocked it" is not justified by that fact alone.

A concrete HTTP 407 from an explicit upstream proxy supports `upstream_proxy_auth_required`.

A concrete HTTP 403 from an explicit upstream proxy supports `upstream_proxy_rejected`, but not a claim about the proxy's internal rule.

Inspect mode failing while a comparable Tunnel connection succeeds supports `tls_interception_incompatible`. It does not prove certificate pinning or mTLS individually.

Every diagnosis must point to concrete event/connection/request evidence and preserve ambiguity when the endpoint cannot see the upstream cause.

## Enterprise topology model

Treat these as distinct cases:

1. **Transparent/in-path proxy or SWG**  
   Mihari opens a normal upstream connection. The enterprise device remains in path automatically.

2. **Explicit proxy**  
   Mihari must chain to the selected proxy. CONNECT and concrete proxy responses are observable.

3. **PAC/WPAD**  
   Use platform proxy resolution when possible. If the configured route cannot be resolved deterministically, report unsupported/unresolved. Never silently fall back to Direct in a way that changes policy.

4. **Endpoint agent/firewall redirection**  
   Mihari may not know the redirector exists. Record what the socket/TLS/HTTP layers actually observe; do not invent a topology.

Proxy routing selection belongs in `Upstream.ps1`, not scattered across handlers.

## TLS implementation rules

One active Inspect session owns one ephemeral root CA.

- Unique CA per session.
- RSA key stays in process memory.
- Install a public-only root into `Cert:\CurrentUser\Root`.
- Short validity.
- Subject includes a Mihari marker and session ID.
- Exact-host leaf certificates are generated on demand.
- Leaf SAN matches the requested DNS host/IP.
- Leaves are signed by the session CA and kept only in memory.
- Use a bounded in-memory cache keyed by normalized destination.
- Never install leaves into certificate stores.
- Never use one global wildcard leaf.
- Stop removes the exact session root.
- `cleanup` removes only positively identified Mihari stale roots and is idempotent.

If PowerShell 5.1 on the host lacks the X.509 APIs required to issue a private-key-bearing leaf purely in memory, Inspect capability must fail explicitly. Do not satisfy compatibility by spamming certificate stores.

Upstream TLS uses normal OS/.NET trust validation. Validation failures are evidence.

## HTTP implementation rules

Do not treat an HTTP connection as an arbitrary text stream.

- Read through the CRLF-CRLF header terminator with a maximum size.
- Parse request line and headers case-insensitively where HTTP requires it.
- Respect `Content-Length`.
- Implement chunked bodies correctly before claiming they are supported.
- Strip/handle hop-by-hop headers correctly.
- Keep binary bodies binary.
- Bound buffers.
- URL capture defaults to scheme/host/port/path. Redact query values.
- Never write Authorization, Proxy-Authorization, Cookie, or Set-Cookie values to events.
- Reject ambiguous authority routing rather than forwarding to an unexpected host.

Prefer a small parser that is tested exhaustively over a large proxy abstraction.

## CONNECT modes

### Tunnel

Open/resolve the upstream path, send success to the client when viable, then relay bytes in both directions with bounded buffers. Record duration, byte counts, and the first failing direction/error.

### Inspect

Acknowledge CONNECT, perform TLS 1.2 server authentication using the generated destination leaf, parse HTTP/1.1, then establish the upstream connection/TLS leg and forward the HTTP request.

Tunnel is the diagnostic control for Inspect. Keep their connection metadata comparable.

## Concurrency

Browsers are concurrent.

Use an in-process mechanism compatible with PowerShell 5.1, preferably a bounded `System.Management.Automation.Runspaces.RunspacePool`.

Do not create an unbounded worker per socket. Do not use `Start-Job` for every connection.

Own cancellation and listener shutdown explicitly. Worker exceptions must become events and must not silently kill the server.

## Event model

Write append-only JSON Lines.

Every event contains at least:

- schemaVersion;
- timestamp;
- sessionId;
- connectionId;
- requestId when available;
- mode;
- stage;
- outcome;
- elapsedMs;
- stage-specific data.

Keep the event writer synchronized. A partial line is a defect.

Normalize common failures into stable Mihari error codes while also retaining the .NET exception type/message after secret-safe sanitization.

Do not put diagnosis logic in the event writer.

## Session and cleanup

The session owns listener, worker pool, event stream, ephemeral CA/private key, leaf cache, and lifecycle cancellation.

Persist only non-secret session metadata required for status, report, and stale cleanup.

Normal stop must always attempt CA cleanup in a `finally` path.

Stale cleanup must require positive Mihari ownership markers. Never remove arbitrary certificates based only on age or issuer similarity.

## Browser launcher

Initial browser is Microsoft Edge.

Use a dedicated temporary profile plus `--proxy-server=http://127.0.0.1:<port>`.

Never use a browser flag that disables certificate verification. The session CA trust is the mechanism.

Do not reuse the user's normal profile by default.

If browser discovery fails, report the proxy endpoint and continue to support manual configuration.

## PowerShell 5.1 discipline

Avoid PowerShell 7-only syntax, including:

- ternary expressions;
- null-coalescing operators;
- pipeline chain operators;
- PS7-only cmdlets/parameters.

Prefer ordinary functions and `[pscustomobject]` data contracts over deep class hierarchies.

Use .NET APIs only when they exist in the supported Windows PowerShell environment; capability-check uncertain APIs at startup.

Be careful with `ConvertTo-Json` depth and enum/date serialization. Event output must be deterministic enough for tests.

Avoid global mutable variables. Pass a session/context object explicitly.

## Error handling

Never use empty `catch {}`.

At a boundary, either:

- handle the error and emit a precise fact; or
- add context and rethrow.

Cleanup errors should be reported but should not prevent later cleanup steps from being attempted.

Do not translate all socket/TLS exceptions into one generic "proxy failure."

## Security and privacy

Mihari intentionally handles decrypted web traffic in Inspect mode. Minimize retention.

Default persisted data excludes:

- bodies;
- credentials;
- cookies;
- proxy credentials;
- private keys;
- full arbitrary headers.

Never add "temporary" debug logging of those values.

Bind the proxy to loopback only unless a future explicit requirement changes that contract.

## Testing

Do not require Pester or any downloaded test dependency.

Use repository-owned PowerShell test scripts and fail with nonzero exit codes.

CI must exercise both `powershell` (Windows PowerShell 5.1) and `pwsh` on a Windows runner.

Prioritize tests that prove the product contract:

1. 5.1 parsing/compatibility;
2. HTTP parser/framing/redaction;
3. deterministic diagnosis rules;
4. session CA creation and exact cleanup;
5. in-memory leaf issuance with no leaf-store residue;
6. HTTP forwarding;
7. CONNECT tunnel;
8. TLS 1.2 inspect path capture;
9. abnormal/stale cleanup;
10. end-to-end local smoke test.

Certificate tests must use unique names and remove their artifacts in `finally`.

Tests must not depend on public Internet access.

## Implementation order

When building from an empty repository, converge in this order:

1. compatibility/capability probe;
2. session/event contracts;
3. ephemeral CA + in-memory leaf proof;
4. HTTP parser;
5. loopback listener + bounded workers;
6. Tunnel CONNECT;
7. Inspect CONNECT/TLS;
8. upstream routing/chaining;
9. browser launcher;
10. diagnosis/report;
11. cleanup hardening;
12. Windows PowerShell 5.1 + PowerShell 7 CI smoke.

The CA/leaf proof is the earliest technical risk. Resolve it before spending time on polish.

## Parallel-agent guidance

Parallelize by file ownership and integration seam, not by asking many agents to redesign the system.

Good independent workstreams after contracts are fixed:

- certificate/TLS;
- HTTP parsing/redaction;
- observation/diagnosis;
- listener/tunnel;
- upstream resolution;
- browser/session lifecycle;
- tests/CI.

Keep one integration owner responsible for data contracts and the end-to-end path. Subagents should return concrete patches or findings, not competing architectures.

## Definition of done for the initial implementation

"Implemented" means a Windows CI smoke test proves:

- both Windows PowerShell 5.1 and PowerShell 7 can run Mihari;
- HTTP proxying works;
- CONNECT tunnel works;
- Inspect mode reads an HTTPS URL path over TLS 1.2;
- facts are emitted;
- a report is generated;
- the session CA is removed;
- no per-host leaf certificate remains installed;
- no third-party runtime/package is required.

Do not call the initial implementation complete based only on unit tests or static code review.
