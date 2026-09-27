# AGENTS.md

## Authority

Read `docs/requirements.md`, `docs/architecture.md`, and `docs/architecture-phase-2.md` before changing runtime behavior. They define the product contract.

For Phase 2 work, `docs/architecture-phase-2.md` is the target architecture and delivery authority. Its explicit extensions supersede conflicting initial-stage exclusions and acceptance criteria in older documents or Issues. All unchanged safety, privacy, PowerShell compatibility, and lifecycle constraints remain binding. Do not create a scope blocker from an initial-stage exclusion that Phase 2 explicitly supersedes.

When code and documentation disagree, do not silently reinterpret the architecture. Fix the code to the documented contract unless the task explicitly changes the contract. Do not rewrite mandatory requirements merely to declare incomplete work done.

Phase 2 execution follows milestones M0-M5, with native HTTP/2 tracked separately through the M6 feasibility/capability gate. Keep `docs/phase-2-progress.md` as a compact implementation/proof ledger. Do not confuse unimplemented features with host capability limitations.

## Product in one sentence

Mihari is a Windows-local diagnostic HTTP(S) proxy that observes where enterprise web traffic succeeds or fails, optionally terminates TLS to see URL paths, and never intentionally bypasses the existing enterprise network path.

## Hard constraints

- Windows PowerShell 5.1 is the language/runtime compatibility floor.
- PowerShell 7 must run the same core code; Phase 2 may expose richer native HTTP/2 capabilities only on runtimes proven to support them.
- Runtime implementation is PowerShell plus platform .NET/Windows APIs already present on the host.
- No Node.js, Python, separately built .NET application, native helper, external PowerShell module, package manager, or embedded C# source compilation.
- Self-contained browser HTML/CSS/JavaScript is allowed; no frontend build-system or CDN dependency.
- Keep `mihari.ps1` thin. Put behavior in small `src/*.ps1` files.
- Initial protocol baseline is HTTP/1.1 + CONNECT + TLS 1.2. Phase 2 explicitly authorizes streaming, persistent HTTP/1.1, SSE/WebSocket connection diagnostics, browser-assisted HTTP/2, and gated native HTTP/2.
- TLS 1.3 interception, HTTP/3/QUIC analysis, packet capture, and kernel drivers remain out of scope. Opaque tunnel transport is not native protocol inspection.
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

A concrete HTTP 403 rejecting CONNECT supports rejection by the immediate upstream proxy, but not a claim about its internal rule. A 403 on an origin request through a proxy does not by itself establish who originally generated the response.

Inspect mode failing while a comparable Tunnel trial succeeds supports interception incompatibility only to the extent supported by the trial evidence. It does not prove certificate pinning or mTLS individually. Tunnel bytes alone do not prove application success, and changing the HTTP version at the same time invalidates a one-variable comparison.

Every diagnosis must point to concrete event/connection/request evidence and preserve ambiguity when the endpoint cannot see the upstream cause. Keep tool health separate from traffic failures. Browser, proxy, Windows, operator, and imported evidence must retain their distinct provenance.

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
- Windows Schannel may require a temporary, current-user leaf private-key file during Inspect; dispose it on cache eviction and normal stop. Never write a PFX file.
- Install a public-only root into `Cert:\CurrentUser\Root`.
- Short validity.
- Subject includes a Mihari marker and session ID.
- Exact-host leaf certificates are generated on demand.
- Leaf SAN matches the requested DNS host/IP.
- Leaves are signed by the session CA and their certificate objects stay only in memory.
- Use a bounded in-memory cache keyed by normalized destination.
- Never install leaves into certificate stores.
- Never use one global wildcard leaf.
- Stop removes the exact session root.
- `cleanup` removes only positively identified Mihari stale roots and is idempotent.

If the host lacks the X.509 APIs required to issue an exact-host leaf and use it with `SslStream` through the temporary user-key-file path, Inspect capability must fail explicitly. Do not satisfy compatibility by installing leaves in certificate stores.

Upstream TLS uses normal OS/.NET trust validation. Validation failures are evidence. Record not-performed/unavailable checks honestly rather than implying a full validation suite ran. Local inspection exclusions must never change enterprise routing.

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

Prefer a small parser that is tested exhaustively over a large proxy abstraction. Phase 2 separates framing from streaming body relay and must not retain whole bodies merely to render URL/timing information.

## CONNECT modes

### Tunnel

Open/resolve the upstream path, send success to the client when viable, then relay bytes in both directions with bounded buffers. Record duration, byte counts, and the first failing direction/error.

### Inspect

The initial HTTP/1.1 path acknowledges CONNECT, performs TLS 1.2 server authentication using the generated destination leaf, parses HTTP/1.1, then establishes the upstream connection/TLS leg and forwards the request. Phase 2 extends protocol handling only as specified in its architecture.

Tunnel is the diagnostic control for Inspect. Keep their connection metadata comparable. Pin mode/profile at accepted-connection boundaries; existing persistent connections and streams do not silently change mode.

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

Do not put diagnosis logic in the event writer. Phase 2 adds source/sequence/trial/transport-leg identity with explicit schema compatibility. Session findings and totals must not depend on the current UI page size. Do not rewrite legacy evidence.

## Session and cleanup

The session owns listener, worker pool, event stream, ephemeral CA/private key, leaf cache, and lifecycle cancellation.

Persist only non-secret session metadata required for status, report, and stale cleanup.

Normal stop must always attempt CA cleanup in a `finally` path.

Stale cleanup must require positive Mihari ownership markers. Never remove arbitrary certificates based only on age or issuer similarity. Never delete unverified user key files or kill unrelated browser profiles.

## Browser launcher

Initial browser is Microsoft Edge.

Use a dedicated temporary profile plus `--proxy-server=http://127.0.0.1:<port>`.

Never use a browser flag that disables certificate verification. The session CA trust is the mechanism.

Do not reuse the user's normal profile by default.

If browser discovery fails, report the proxy endpoint and continue to support manual configuration.

For Phase 2 browser observation, attach only to a Mihari-owned diagnostic profile. Honor enterprise restrictions and distinguish requested switches from observed behavior. Do not retain raw DevTools messages, bodies, or debugger control endpoints in evidence.

## PowerShell 5.1 discipline

Avoid PowerShell 7-only syntax in shared code, including:

- ternary expressions;
- null-coalescing operators;
- pipeline chain operators;
- PS7-only cmdlets/parameters.

Prefer ordinary functions and `[pscustomobject]` data contracts over deep class hierarchies.

Use .NET APIs only when they exist in the supported Windows PowerShell environment; capability-check uncertain APIs at startup. Optional richer-runtime features must not prevent the shared runtime from parsing/loading on 5.1.

Be careful with `ConvertTo-Json` depth and enum/date serialization. Event output must be deterministic enough for tests.

Avoid global mutable variables. Pass a session/context object explicitly.

## Source encoding

Windows PowerShell 5.1 can decode BOM-less PowerShell source through the active ANSI code page. Any PowerShell source that embeds HTML or JavaScript must therefore remain ASCII-only unless the file is deliberately stored with a UTF-8 BOM. Use HTML entities or JavaScript Unicode escapes for non-ASCII typography. This is required for locale-independent parsing and UI behavior.

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

The management API must retain loopback Host/Origin checks and protect state-changing actions. Treat imported evidence, notes, URLs, and error text as untrusted data. Offline review must not create CA trust or expose live mutation actions.

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

Phase 2 adds the acceptance proofs in `docs/architecture-phase-2.md`, including real UI actions, history-independent findings, controlled comparisons, source provenance, browser-assisted HTTP/2, bounded streaming, and safe export/import. Native HTTP/2 support requires its own positive runtime-specific proof.

Certificate tests must use unique names and remove their artifacts in `finally`.

Tests must not depend on public Internet access. Batch integration pushes and reuse suite structure instead of adding a CI job for every feature. Preserve coverage when consolidating probes; final implementation HEAD must have passing required Windows CI.

## Implementation order

For Phase 2, follow the milestone/dependency table in `docs/architecture-phase-2.md`. The following initial implementation order is retained as historical context for the core runtime, not as a replacement for Phase 2 delivery:

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

## Parallel-agent guidance

Parallelize by file ownership and integration seam, not by asking many agents to redesign the system.

Keep one integration owner responsible for shared contracts, coherent main checkpoints, and end-to-end verification. Use isolated local worktrees for overlapping workstreams rather than concurrent edits to the same working tree. Subagents return concrete changes or findings, not competing architectures.

Phase 2 explicitly permits coordinator-owned direct commits/pushes to main. Local scratch branches/worktrees are allowed for isolation; feature Issues/PRs and review waits are not required. Do not force-push main or discard unrelated work.

## Definition of done

The initial implementation remains protected by its Windows CI smoke proofs: HTTP proxying, CONNECT tunnel, TLS 1.2 Inspect path capture, facts/report generation, exact session CA removal, no leaf-store residue, and no third-party runtime/package requirement.

Phase 2 completion additionally requires M0-M5 and the exact verification ledger in `docs/architecture-phase-2.md`. Track native HTTP/2 separately through M6. Do not call the work complete based only on static review, mocks, isolated modules, or a green subset of tests.
