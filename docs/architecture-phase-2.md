# Mihari Phase 2 — Enterprise Diagnostic Workbench

Status: approved target architecture and implementation contract. Saving this document does not mean that its features are implemented.

Date: 2026-09-27.

Inspected implementation base: `8ccc392023bdc62c74f4c22d36d25935685d5323`.

## 1. Authority and delivery boundary

This document records the second-stage direction agreed with the product owner: evolve the working local management console into an enterprise diagnostic workbench, retaining the endpoint-side, PowerShell-native deployment model.

Read this document together with [requirements.md](requirements.md), [architecture.md](architecture.md), and [../AGENTS.md](../AGENTS.md). For Phase 2, the explicit decisions here supersede conflicting **initial-stage** scope exclusions, presentation rules, and acceptance criteria. Unchanged safety, privacy, deployment, and lifecycle constraints remain binding. Historical Issues and the initial implementation checklist must not block extensions explicitly authorized here.

There are two delivery boundaries:

- **Phase 2 workbench:** all mandatory capabilities in sections 5–13, delivered through milestones M0–M5. These are implementation requirements, not a menu from which an agent may select only easy features.
- **Native HTTP/2 inspection:** a separately measurable capability, governed by the platform feasibility gate in section 12 and milestone M6. HTTP/2 tunneling, browser-assisted HTTP/2 diagnostics, and the feasibility report are required in Phase 2. Native inspection must not be falsely claimed when only tunneling or browser telemetry exists.

An unavailable host permission or platform API may produce a documented capability limitation. An unimplemented mandatory feature is not a capability limitation. Report partial completion honestly instead of weakening this document to match the code.

Implementation agents own internal function names, modest file decomposition, visual styling, and algorithms within these boundaries. They may not drop accepted capabilities, add external runtimes, lower the PowerShell compatibility floor, or silently change security/protocol semantics.

## 2. Product outcome

Mihari must let an operator follow this chain without collecting a HAR file manually:

**Reproduce an operation → locate its requests → identify the last proven successful stage → inspect supporting evidence → compare a controlled trial → prepare a URL allowlist or TLS-inspection-exclusion proposal.**

The two complementary axes remain:

1. Observe real web traffic at the local proxy, including URL paths when inspection succeeds.
2. Analyze endpoint configuration and optionally collect evidence from Mihari-owned diagnostic browsers.

The three primary workspaces are **Traffic Inspector**, **Dependency / Allowlist Workbench**, and **Evidence-backed Comparison Diagnostics**. Overview is an entry point, not the principal investigation surface.

Mihari is not a replacement for upstream appliance logs. It must distinguish an observable connection peer from the device or policy that originally generated a failure. A local Inspect toggle changes Mihari's behavior, not enterprise TLS inspection further upstream.

## 3. Baseline and concrete implementation seams

The following are observations of the inspected base, not assumptions about future commits:

| Existing responsibility | Phase 2 starting point |
| --- | --- |
| `mihari.ps1`, `src/Cli.ps1`, `src/Session.ps1` | Foreground lifecycle, proxy and UI endpoints, status, reports, browser launch, cleanup. Preserve this working path. |
| `src/Listener.ps1`, `src/Connection.ps1` | Bounded workers, accepted-connection mode, loopback forwarding and self-reference protection. |
| `src/Observation.ps1`, `src/Diagnosis.ps1` | Canonical JSONL facts and deterministic diagnoses. Extend these rather than inventing a second diagnostic engine in JavaScript. |
| `src/ManagementProjection.ps1` | The live projection reads a bounded recent window, currently at most 200 events, and derives findings from that window. Session-wide analysis must become independent of UI pagination. |
| `src/ManagementUi.ps1` | Event-centric UI. `eventTarget()` can duplicate a host for events without a method; UI reverses an already newest-first projection; `success`/`succeeded` presentation is inconsistent. Verify and correct these at the current execution base. |
| `src/Http.ps1`, `src/Tls.ps1` | Initial message handling buffers bodies, uses a 32 MiB body limit, and closes forwarded HTTP connections. Streaming and connection reuse require transport work, not just UI changes. |
| `src/Browser.ps1` | Existing diagnostic launch requests HTTP/1.1/TLS 1.2 compatibility through browser switches. Requested switches are not proof of effective browser behavior. |
| `test/issue3-ui-browser.ps1` | Repository-owned PowerShell/DevTools browser automation already exists. Reuse the technique, not a dependency on test code from production. |

Pinned source references for this baseline:

- [Management projection](https://github.com/yohn-jp/mihari/blob/8ccc392023bdc62c74f4c22d36d25935685d5323/src/ManagementProjection.ps1)
- [Management UI](https://github.com/yohn-jp/mihari/blob/8ccc392023bdc62c74f4c22d36d25935685d5323/src/ManagementUi.ps1)
- [HTTP processing](https://github.com/yohn-jp/mihari/blob/8ccc392023bdc62c74f4c22d36d25935685d5323/src/Http.ps1)
- [TLS processing](https://github.com/yohn-jp/mihari/blob/8ccc392023bdc62c74f4c22d36d25935685d5323/src/Tls.ps1)
- [Browser launcher](https://github.com/yohn-jp/mihari/blob/8ccc392023bdc62c74f4c22d36d25935685d5323/src/Browser.ps1)

Earlier incident logs proved repeated requests targeting Mihari's own endpoint and later failed TCP connection attempts. They did **not**, by themselves, prove why the original self-target request was generated, that Edge's process-specific proxy changed Windows settings, or that the listener process crashed. Preserve this distinction in regressions and future diagnoses. Test direct self-target requests and explicit-proxy self-reference separately.

## 4. Unchanged constraints and explicitly authorized extensions

### Unchanged

- Windows PowerShell 5.1 remains the language and core runtime compatibility floor; PowerShell 7 remains supported.
- Runtime implementation uses PowerShell and APIs available on the host. No Node.js, Python, separate .NET application, third-party native helper, downloaded module, package manager, embedded C# compilation, or reflection-based compilation workaround.
- HTML/CSS/JavaScript served to the existing browser is permitted. It must not require a frontend build system, framework, CDN, or external network resource.
- Proxy, management, and any diagnostic-browser control endpoint remain loopback-only. Do not modify system proxy, firewall, certificate-validation policy, browser enterprise policy, or endpoint-agent configuration to force success.
- Do not bypass enterprise egress routing. A configured but unresolved proxy is not permission to silently connect directly.
- One foreground process owns a live session, its listeners, workers, keys, and shutdown. A Windows service or background installation is not required.
- CA private keys remain process-local. Leaf certificates are not installed in certificate stores. The existing Windows temporary leaf-key-file allowance remains explicit; normal disposal removes owned temporary keys, and unverified key files must never be deleted speculatively.
- No default persistence of bodies, cookies, credentials, arbitrary headers, or unredacted query values.
- PowerShell source embedding UI code remains ASCII-safe; use escapes/entities for typography and localized strings. Dedicated UTF-8 assets must be read with explicit encoding.

### Authorized in Phase 2

Request-centric projections, diagnostic cases and trials, URL dependency analysis, controlled comparisons, richer TLS facts, endpoint snapshots, optional browser telemetry, local evidence import/export, HTTP/1.1 streaming/reuse, SSE and WebSocket connection diagnostics, and the staged HTTP/2 path below.

### Still excluded

Remote administration, cloud accounts/backends, packet-capture drivers, WFP hooks, HTTP/3/QUIC analysis, TLS 1.3 interception, automatic enterprise policy changes, general traffic rewriting, credential collection, arbitrary automatic request replay, plugin frameworks, and an external database service. A portable file-backed model is sufficient.

## 5. Target components and ownership

```text
Proxy / TLS / HTTP observations       Browser observations       Endpoint snapshots
             |                               |                         |
             +------------- privacy-safe, source-labelled facts ------+
                                             |
                                 ordered canonical evidence store
                                             |
                          incremental, replayable domain projections
                              /          |           |          \
                         Traffic    Dependencies   Findings    Comparisons
                              \          |           |          /
                                bounded management query API
                                             |
                           local workbench UI / CLI / evidence export
```

The runtime owns facts. Domain projections own request grouping, dependency graphs, findings, comparison state, and policy candidates. The UI owns presentation and temporary selection state, not diagnostic truth. The management API delegates to the same domain operations as the CLI.

Use the existing source files as entry points. Extract focused files when introducing real responsibilities, for example `TrafficProjection.ps1`, `Case.ps1`, `Dependencies.ps1`, `Comparison.ps1`, `Environment.ps1`, `BrowserObservation.ps1`, `Evidence.ps1`, and focused UI assets. These names are suggestions, not a closed write-scope list. Do not turn `Management.ps1` or its inline UI into another monolith, and do not add unused abstraction layers.

Only one integration owner changes shared contracts at a time. Once producer/consumer contracts are agreed, independent UI views and domain projections can be implemented in parallel.

## 6. Shared data contracts

### 6.1 Cases, trials, and correlation

| Entity | Meaning and minimum identity |
| --- | --- |
| Case | An operator-owned investigation with title, notes, and references to captured sessions/trials. Lightweight metadata, not a ticketing system. |
| Session | A physical runtime lifetime, identified by the existing `sessionId`. |
| Trial | A bounded reproduction attempt: case/session references, immutable diagnostic profile, environment snapshot reference, start/end markers, and operator-recorded business outcome. |
| Marker | Timestamped operation boundary or note, such as login, listing, upload, or observed UI failure. Labels are local user input and are escaped/redacted on export. |
| Request attempt | One observed HTTP exchange or browser attempt. Use the existing `requestId` where available. Connection-only failures and opaque tunnels are valid records with unknown HTTP fields. |
| Logical request group | Optional relationship between retries, redirects, or comparable operations. Never group identical concurrent URLs as proven retries without supporting evidence. |
| Transport leg | `client`, `upstream`, or `end_to_end` for opaque/browser evidence; each has its own connection identity. |
| Stream | An optional HTTP/2 stream identifier, scoped to its transport connection and leg, not a global request ID. |
| Finding | Stable identity, rule version, evidence references, classification, interpretation, limitations, and first/last observed timestamps. |

Request, connection, trial, and case are distinct. HTTP/2 makes their separation necessary: many requests can share one connection, and an intermediary's two legs need not share a stream ID.

A mode change does not rewrite existing connections. Record configuration revisions and the effective mode/profile captured at acceptance. With persistent connections or HTTP/2, show that existing traffic may remain on the prior mode. A clean comparison starts a new trial and a fresh owned diagnostic-browser connection set; never secretly terminate unrelated clients.

### 6.2 Facts and provenance

Retain the existing envelope and correlation fields. Introduce versioned additive fields or an explicit next schema version for incompatible changes; read legacy schema-v1 logs without altering them. At minimum the Phase 2 normalizer represents:

- Existing `schemaVersion`, `timestamp`, `eventId`, `sessionId`, `connectionId`, `requestId`, `mode`, `stage`, `outcome`, `elapsedMs`, and safe `data`.
- `sequence`: ordering within the canonical session writer, independent of clock ties.
- `source`: `proxy`, `browser`, `windows`, `operator`, or `import`, plus source-local identity/version when applicable.
- Optional case/trial/configuration revision references, transport leg, upstream connection identity, and stream identity.
- Monotonic timing and clock identity where available. Preserve browser timing origin and the uncertainty of cross-source alignment.
- Coverage flags: observed, unknown, unsupported, permission-denied, truncated, or lost. Missing data is not a successful result.

An evidence reference identifies its source session and event, not just a short display row number. Browser IDs are scoped to their browser target/session and redirect occurrence. Correlation edges say `direct`, `supported`, or `heuristic` and carry reasons. Multiple possible matches remain ambiguous.

Do not inject tracing headers, alter URL parameters, or replay traffic merely to simplify correlation.

### 6.3 Timing and result semantics

Keep request outcome, HTTP status, browser outcome, TLS validation, and tool health separate. Store phase durations only when actually measured; do not subtract unrelated existing `elapsedMs` values or display an unobserved DNS/TLS phase as zero.

A transport byte relay completing is not proof of HTTP or business success. HTTP 200 is not proof of successful application behavior. Browser cache/Service Worker fulfillment is not an upstream socket exchange. A 403 received on an origin request through a proxy does not identify the response's original author; a rejected CONNECT is evidence that the immediate proxy refused the tunnel, not evidence of its internal rule.

## 7. Evidence storage, projections, and management API

### 7.1 One canonical store

Keep JSONL as the canonical fact log. Persist operator annotations and configuration/trial changes in separate versioned metadata/journals; do not edit historical facts. Derived indexes and snapshots are rebuildable, never a second source of truth.

Ingest incrementally. Tail by stable offsets/sequence, tolerate incomplete final lines, detect rotation, and expose malformed-record counts. Keep a bounded hot set for the UI and disk-backed/replayable history. Never reread the entire session on every 2.5-second poll.

All limits must be finite, configurable where useful, and described by capabilities: active connections, hot request records, page size, API response size, retained bytes, queue length, and import size. Keep current API bounds unless a consumer demonstrably needs an explicitly reviewed increase.

When a disk limit or writer failure is reached, mark capture incomplete and show a persistent operator warning. No silent eviction of canonical evidence. Display hiding, UI pause, capture stop, and evidence deletion are different actions. Evidence deletion is explicit and must not destroy data referenced by an open case without confirmation.

### 7.2 Persistent findings and accurate counters

Calculate session/trial findings from the canonical history or its equivalent incremental projection, not from the last visible 100/200 events. Persist/rebuild their identities and evidence references. Leaving the UI window does not resolve a finding.

Expose separate counts for session total, current filter, loaded page, active requests, transport connections, findings, unclassified traffic failures, tool failures, and missing evidence. A healthy tool observing denied traffic must not label itself broken.

### 7.3 Query and action contract

Keep existing `/api/status`, `/api/health`, `/api/events`, `/api/findings`, `/api/mode`, and `/api/browser` behavior compatible while extending their envelopes where safe. Add versioned bounded routes for requests/details, cases/trials/markers, dependencies/policy proposals, comparisons, environment/capabilities, and evidence bundles as they become real consumers.

List responses carry items, stable cursor/revision, ordering, scope totals, coverage/truncation, and capture freshness. Request details include references to their raw safe events. Filters and sort order run on the server over the declared scope, not just the visible page. Document exact API names and shapes in code-adjacent contracts before parallel consumers use them.

Actions return accepted/completed/failed state explicitly. Long-running collection, export, or trust operations return bounded job/progress state and must not block listener heartbeats. A browser process starting is only `launched`; traffic verification is a separate observed result.

## 8. Workbench UI requirements

Retain the current visual language, but prioritize a dense investigation layout, readable details, and stable state over decorative cards. No redesign of working runtime semantics for styling convenience.

| Workspace | Mandatory functionality |
| --- | --- |
| Overview | Tool readiness, separate traffic-failure count, listener/CA/capture state, active profile and its interventions, actionable warning links. |
| Traffic | One request attempt per ordinary row; connection-only rows where HTTP is unknown. Columns for time, method, authority, safe path, HTTP/browser outcome, duration, mode/protocol, failure stage, and source. |
| Request detail | Side panel with summary, phase timeline, both transport/TLS legs, safe allowlisted headers, redirects/retries, and linked evidence. Keep selection while data refreshes. |
| Dependencies | Case/trial/operation → host → path tree, first-seen destinations, candidate necessity, existing-policy comparison, and export. |
| Diagnostics | Stable finding groups, unclassified failures, evidence drill-down, limitations, suggested checks, and resolution evidence. |
| TLS & Certificates | Side-by-side TLS legs, certificate and trust details, CA/leaf lifecycle, local inspection exclusions, and safe cleanup state. |
| Environment | Source-specific proxy settings, PAC result, DNS/routes/interfaces/VPN, browser policy and capability limits, snapshot comparison. |
| Compare | Trial selection, changed conditions, new/resolved failures, URL/route/certificate/timing differences, and comparability warnings. |
| Evidence | Case metadata, notes/bookmarks, retained scope, redaction preview, export/import, and offline review. |

Traffic requires host/path-prefix/method/status/mode/protocol/stage/time/source filters, saved views, and presets for failures, 407, TLS failures, slow exchanges, and first-seen destinations. Avoid an unbounded regex engine as the initial search language.

Provide request waterfall and a phase timeline only for observed timings. Label Mihari queue time and overhead separately from upstream time. Preserve unknown intervals. Cancellation, timeout, protocol limitation, traffic rejection, and tool failure have distinct presentation.

UI refresh must preserve selection, scroll, expanded details, filters, and bookmarks. Provide pause-display/resume-live and explicit capture controls with different labels. Old data remains visibly stale after API failure; successful polling of one pane must not erase an unrelated failed-action banner.

Use stable keys, bounded rows/windowing, progressive detail queries, copy-safe IDs/URLs, keyboard navigation, visible focus, non-color-only status, and usable narrow layouts. Add English/Japanese text resources without reintroducing BOM-less PowerShell source corruption.

The screen must never display `0 findings` as proof of a healthy service when failure classification or evidence coverage is incomplete.

## 9. Dependencies, policy candidates, and comparative diagnosis

### 9.1 Required URL workbench

Use operator markers to group observations by business action. Record first/last seen, count, methods, successful/failed outcomes, source, and evidence references for each host/path dependency.

Distinguish `observed`, `necessity_unconfirmed`, and `business_required_confirmed`. Background browser traffic is a candidate classification, not something to silently delete based on vendor hostname. Browser initiator data and operator confirmation can strengthen classification.

Build redirect edges from observed redirect responses/Location and browser redirect chains. Temporal proximity alone is heuristic. Record retries without merging concurrent identical requests into a fictional single attempt.

Generate neutral proposals with scheme, exact host, port, exact path or explicitly confirmed prefix, methods if supported, operation, evidence, necessity state, and rationale. Pattern suggestions such as `/files/{id}` remain suggestions until approved; they are not automatically executable appliance rules.

Import an explicitly documented vendor-neutral rule format supporting exact host and exact/path-prefix matching. Return covered/uncovered/unknown. Unsupported vendor glob/regex semantics remain unknown rather than guessed. Show when a wildcard or prefix widens access beyond observations. Vendor-specific rule generators are later adapters, not a Phase 2 dependency.

Keep **URL access allowlisting** and **enterprise TLS inspection exclusion** as separate proposals. Mihari never applies either upstream policy. Produce JSON/CSV and a human-readable change-request report including business action, required URLs, reproduction conditions, evidence, proposal, and unresolved questions. Escape spreadsheet formula-like cells in CSV exports.

### 9.2 Evidence-backed findings

Each diagnosis contains observed facts, interpretation, alternative causes/limitations, and a next verification step. Use categorical evidence strength (`direct_observation`, `comparison_supported`, `hypothesis`, `undetermined`) instead of invented confidence percentages.

Group repeated instances by rule, destination, and relevant stage/route without losing occurrence count or first/last timestamps. Acknowledged, hidden, no-longer-observed, and resolved-with-evidence are separate states. Do not resolve an incident merely because it aged out of a recent-events page.

At minimum distinguish proxy authentication/tunnel rejection, DNS/TCP/TLS failures, upstream certificate failure, HTTP application error, browser-side failure, unsupported transport, observer queue/resource failure, self-reference, cleanup failure, and unclassified failures. A generic TLS handshake failure does not prove pinning or mTLS. Failure before receiving a peer certificate is not a failed certificate-chain validation.

### 9.3 Controlled trials

Implement Inspect/Tunnel and before/after comparisons around explicit trials. Store mode, protocol profile, per-host local exclusions, browser/version/profile identity, cache/login-state notes, network/upstream fingerprint, rule version, and operator business outcome.

Compare added/removed destinations, first failures, resolved failures, stage timings, routes, certificate identities, and protocol behavior. Clearly identify changed variables, incomplete coverage, and uncertain request matches. A result with multiple changed variables is observational, not a clean causal experiment.

A mode toggle must not silently change HTTP/TLS version policy. Local inspection OFF never means upstream TLS inspection OFF. An opaque tunnel with bytes in both directions is not a successful application trial unless browser or operator evidence supports it.

Do not automatically replay POST/PUT/DELETE, authenticated actions, or downloads. Reproduction remains operator-driven; any future active probes must be explicit, bounded, and use the authorized route.

## 10. TLS, trust, and endpoint analysis

### 10.1 TLS and certificates

Show client-to-Mihari and Mihari-to-upstream peer separately: negotiated protocol, ALPN when exposed, cipher information actually available, observed peer identity, timing, and connection IDs. Never label the observed upstream peer as the origin if interception may exist.

Separate trust-chain result, hostname/SAN match, validity period, EKU, and revocation state. Use `passed`, `failed`, `not_performed`, `unavailable`, or `unknown`, and show validation policy. Preserve normal trust/name verification; instrumentation must not install an always-true callback. Any validation callback used for evidence must retain equivalent acceptance/rejection behavior and be tested on both supported runtimes.

Show chain elements where available, CA issuer/fingerprint changes per destination, short-lived session CA state, cache size, trust insertion/removal, and cleanup failures. A certificate issuer string is not proof of the identity or rule of a corporate security product.

Observe client-certificate-request/selection/sending information only where the platform or diagnostic browser exposes it; mark missing evidence explicitly. Do not export or impersonate users' client certificates to make an intercepted mTLS session succeed.

Implement exact-host local inspection exclusions as recorded configuration revisions for newly accepted connections. Do not equate exclusions with direct routing. Retain one session CA for the runtime; existing inspected connections may still need its material after a toggle. Remove trust at final stop.

Add a cleanup-status view for owned roots and temporary leaf key artifacts. Improve crash recovery only where provider/container identity and session ownership can be verified. Missing ownership metadata must produce an unresolved cleanup item, not a broad user-key-directory deletion.

### 10.2 Endpoint snapshots

Collect read-only, source-labelled snapshots of user Internet Settings, WinHTTP settings when accessible, environment proxy variables, browser enterprise policy, Mihari override, and available PAC configuration/resolution. These have different consumers and precedence; do not flatten them into a fictitious single effective proxy.

For PAC, distinguish configured URL, retrieval status/hash/time, resolver used, evaluated destination, selection result, and error. Do not evaluate PAC with a new untrusted JavaScript host or infer that a configured URL was successfully used. Redact credentials/tokens in configuration URLs. A captured resolver reference is not proof that every future PAC evaluation uses identical external state; record configuration changes and resolution times.

Include interfaces, addresses, DNS configuration, routes/default gateway, and available VPN state. Show before/after snapshots and changes during a trial. Separate configured DNS from a measured DNS operation; explicit proxies can resolve origin names remotely.

Optionally correlate local socket owners and relevant Windows TLS/network events when supported and authorized. PID ownership identifies a local process, not necessarily a browser tab. Missing rights, unsupported APIs, disabled logs, and policy restrictions are first-class capability results, not zero-valued successful snapshots.

Do not disable AppLocker/WDAC/Constrained Language Mode, change managed browser policy, or elevate silently. Collect only relevant network facts rather than a general endpoint inventory. Additional active network checks require an explicit operator action and are marked as probes, not captured business traffic.

## 11. Browser-assisted observation

Browser observation is optional for a live proxy session and independent of Inspect. It supplements arbitrary-app proxy observation rather than replacing it.

Use Edge DevTools Protocol from PowerShell through existing .NET HTTP/WebSocket APIs. Observe only the diagnostic browser/profile started and owned by Mihari. Do not attach to the user's ordinary browser, enable remote debugging for an existing profile, or expose a debugger relay through the management API. Honor enterprise policies that prohibit debugging. [R3, R4]

Capture safe request/response/failure metadata, initiator category, tab/frame context, redirects, browser-observed protocol, cache/Service Worker origin, timing, and browser error information. Do not request response bodies or persist raw DevTools messages. URL, initiator, and error text pass through the same privacy boundary before storage or UI rendering.

Display requested launch configuration and observed transport separately. Record observed proxy traffic as `verified`; preserve `launched_but_unverified` and policy/timeout errors. Never claim a browser switch guarantees a protocol or proxy behavior without checking the resulting traffic.

Browser and proxy results can disagree legitimately. Show browser-only requests, proxy-only requests, cache fulfillment, and application/browser blocking separately. Correlate using scoped source IDs and observed metadata; URL/time matching is heuristic when ambiguous. Do not invent HTTP/2 stream IDs from unrelated browser request IDs.

Allow optional ingestion of an operator-provided NetLog as a separate source. Detect/document the supported format/version; import only recognized safe event fields and retain unsupported-record counts. Never start sensitive NetLog capture automatically or upload raw NetLogs. HAR import is a convenience for existing evidence, not a prerequisite for normal capture. [R7]

Debugger endpoints and discovery files are sensitive control material. Bind locally, use a unique owned temporary profile, avoid logging control URLs/tokens, validate ownership at connection time, and dispose the attachment at session stop. Cleanup must never kill unrelated browser processes. Warn that any retained diagnostic profile may contain browser-managed cookies/history even though Mihari does not log them; offer cleanup once the owned browser is closed.

## 12. HTTP/2 capability ladder

### 12.1 Required distinctions

HTTP version, TLS version, observation source, and interception mode are separate dimensions. HTTP/2 over TLS can use TLS 1.2. A CONNECT tunnel may carry HTTP/2 without Mihari parsing its encrypted contents. ALPN identifies the negotiated application protocol at each TLS leg; HPACK carries compressed headers such as `:path`. [R1, R2]

| Capability | Phase 2 obligation | What may be claimed |
| --- | --- | --- |
| `http1.inspect` | Mandatory, preserve and strengthen both runtimes | Mihari directly observes HTTP/1.1 paths and outcomes. |
| `http2.tunnel` | Mandatory, local real HTTP/2 trial | Opaque HTTP/2 traffic can pass through CONNECT; protocol evidence comes from the endpoints/fixture, not decrypted proxy frames. |
| `browser.network` | Mandatory implementation; explicit unavailable state on restricted hosts | URL/outcome/protocol evidence from the owned diagnostic browser. |
| `http2.browser_assisted` | Mandatory integration | Browser-reported HTTP/2 results alongside proxy connection evidence. No claim of native frame inspection. |
| `http2.inspect` | Gated native extension | Only the verified client/upstream legs and supported runtime combinations. |

### 12.2 Diagnostic profiles

Provide named, versioned profiles:

- `compatibility`: HTTP/1.1 and TLS 1.2 diagnostic policy. Supports the existing Inspect/Tunnel comparison with matching protocol restrictions.
- `http2-observe`: Tunnel with HTTP/2 enabled and optional browser observation. Keep QUIC disabled. Record requested TLS policy and the actual negotiated TLS version if visible; opaque relay is not TLS 1.3 interception.
- `http2-inspect`: expose only after native capability and integration verification succeeds on the selected host/runtime.

Profile changes are explicit and start a new trial. Do not transform `http2-observe` into HTTP/1.1 Inspect when the user flips a switch; explain incompatible combinations and require an explicit profile change. A mode switch and an HTTP-version change must not masquerade as a one-variable comparison.

### 12.3 Early native feasibility gate

Investigate this in parallel with M0, before spending heavily on frame code:

1. Record Windows, PowerShell, CLR/.NET, and available TLS API versions.
2. Prove server-side ALPN selection and client-side ALPN negotiation/readback through platform APIs allowed by this repository.
3. Prove a session-issued leaf works with those APIs and normal upstream certificate validation remains intact.
4. Distinguish PowerShell 5.1 availability from PowerShell 7 availability; a modern .NET API reference is not evidence of .NET Framework support. [R5]
5. Save the executable probe, exact results, and a runtime/leg capability table in `docs/http2-feasibility.md`.

If a supported runtime cannot provide the required ALPN surface under the existing no-external-runtime/no-compiled-helper constraint, keep HTTP/1.1 Inspect and HTTP/2 Tunnel/browser-assisted diagnostics available there. Capability-gated native HTTP/2 on PowerShell 7 is allowed **without making PowerShell 7 mandatory for the workbench**. Do not fake ALPN, disable TLS validation, reflect into private TLS implementation internals, or introduce a binary dependency.

A negative feasibility result is not permission to abandon M0–M5. It is a precise blocked native capability. A positive result authorizes M6; a failed parser implementation or lack of time is not a platform impossibility.

### 12.4 Native protocol target after a positive gate

Implement a bounded connection/stream state machine with separate client/upstream identities, frame validation, negotiated settings, HPACK including dynamic state/Huffman decoding, flow control, stream cancellation, and graceful connection shutdown. Preserve HTTP semantics and trailers. No raw compressed header blocks in retained evidence. Follow RFC 9113 and RFC 7541 rather than an HTTP/1.1 parser with an `h2` label. [R1, R2]

Expose stream waterfall, negotiated limits, observed reset/GOAWAY direction and affected requests, and measured flow-control waits. Unknown information stays unknown. Do not automatically retry non-idempotent operations after a reset. Protocol conversion, if implemented, is visible per leg and must not silently turn streaming gRPC into a buffered HTTP/1.1 approximation.

For gRPC, show HTTP and RPC outcomes separately and decode `grpc-status` only when actually observed in recognized headers/trailers. Preserve streaming/cancellation and keep payloads out of storage. Detailed payload/protobuf inspection is outside this stage. [R6]

## 13. Transfer fidelity, security, and operational evidence

### 13.1 Streaming and observer impact

Separate header/framing parsing from body transfer. Relay bounded byte buffers without persisting bodies or buffering an entire upload/download. Record first byte, last byte, cumulative byte counts, and cancellation/timeout where observable.

Handle Content-Length, chunking, trailers, close-delimited responses, informational responses/Expect behavior, binary data, and half-close correctly. Ambiguous framing is rejected safely; do not weaken parser checks to pass traffic. Bound header/trailer sizes and deadlines independently of streamed body length.

Add persistent HTTP/1.1 exchanges and safe upstream reuse after establishing framing correctness. Key upstream reuse by authority/route/TLS policy and any relevant authentication context; no credential or session mixing. Keep a recorded compatibility option for close-per-exchange behavior rather than silently changing a controlled trial.

Support long-lived SSE transfer and WebSocket upgrade/opaque bidirectional relay with connection metadata and byte counts. Semantic SSE/WebSocket payload collection is not required. Do not infer clean WebSocket close codes from TCP EOF. A long-lived connection must not starve management health or other clients.

Measure observer queue length, worker occupancy, forwarding delays attributable to Mihari, event-writer lag, CPU/memory, retained evidence size, and drop/truncation counters. Display the profile's interventions: TLS termination, protocol constraints, disabled cache if explicitly requested, connection reuse policy, and local exclusions. Do not label Mihari overhead as origin latency.

### 13.2 Local API and untrusted data

Retain exact loopback Host/Origin checks and add session-scoped authorization/CSRF protection for state-changing management actions. No permissive CORS, GET mutations, externally supplied scripts, or generic file-serving routes. Imported cases, notes, URLs, certificate names, headers, and error messages are untrusted; render as text. Enforce request/body/response/time bounds.

Bootstrap any management control secret through a local, narrowly scoped flow; never include it in canonical evidence, exports, URL query logs, or copied diagnostic links. Do not expose browser debugging endpoints as ordinary status fields. Read-only offline mode must not offer active capture, browser launch, or trust mutation actions.

### 13.3 Portable cases and evidence bundles

Implement a versioned file-backed case/session manifest, safe event/annotation files, rule and application revision, diagnostic profile, environment snapshots, capture coverage, and SHA-256 file hashes. Bundle content must exclude CA/leaf keys, debugger controls, browser profiles, credentials, and raw body data.

Export requires a preview showing what is included and what is redacted. Support share-time masking/pseudonyms for internal hostnames, usernames, paths, and identifiers. Pseudonyms must remain consistent within the bundle so comparisons still work. Paths can contain secrets even when query values are masked.

Bundle hashes detect modification; they do not alone prove authorship or trustworthy acquisition. Do not describe them as cryptographic provenance without a separately verified signing identity.

Import validates version, size, hashes, allowed paths, and record bounds. Prevent archive traversal, symlink/reparse-point escape, decompression bombs, script execution, and formula injection. Unknown schema/source records are reported, not executed or silently treated as valid evidence.

Offline review loads a saved case without binding a diagnostic proxy or creating/trusting a CA. Serve the same read-only workbench locally, and reuse canonical projections/diagnosis rules. Reanalysis records its rule version and preserves the original result.

Provide retention/cleanup controls, a distribution manifest and hashes, and documentation for optional enterprise code signing. Do not create a fake signing identity or force signing-certificate enrollment as a runtime requirement.

## 14. Milestones and parallel execution

### 14.1 Milestone acceptance

| Milestone | Integrated deliverable and proof |
| --- | --- |
| **M0 — Contracts and first corrections** | Fix verified presentation defects; establish versioned fact/request/trial/source contracts, legacy reader, and stable bounded query shape. Run the early HTTP/2 feasibility probe. Keep current launch, forwarding, UI and cleanup tests working. |
| **M1 — Traffic investigation** | Request-centric list, filters/saved views, selection-stable detail panel, measured timeline/waterfall, raw evidence drill-down, accurate counters, persistent findings, and separate tool/traffic health. A real local browser request can be selected through its complete event chain. |
| **M2 — Business dependencies** | Cases/trials/markers/notes, host/path dependency tree, redirect/retry relationships, necessity confirmation, neutral existing-policy comparison, allowlist/exclusion proposals, and change-request export. A login/upload fixture produces distinct evidence-backed proposals. |
| **M3 — Comparison and endpoint diagnosis** | Controlled trial comparison, comparable-condition checks, TLS two-leg view, validation-state display, per-host local inspection exclusions, endpoint/PAC/capability snapshots, and differences. Changed configuration produces a traceable, non-overclaimed result. |
| **M4 — Browser-assisted HTTP/2** | Owned Edge observation, cache/initiator/failure correlation, effective profile verification, HTTP/2 Tunnel trial, browser-assisted protocol/URL display, and safe HAR/NetLog import. Native feasibility is documented without claiming unavailable frame details. |
| **M5 — Fidelity and enterprise operation** | Bounded streaming, persistent HTTP/1.1, SSE/WebSocket relay, observer impact/limits, safe portable export/import and offline review, management action protection, retention/cleanup, bilingual UI, distribution guidance, and final regression/performance evidence. |
| **M6 — Native HTTP/2 where proven** | Implement after positive platform gate: actual h2 negotiation and concurrent streams, semantic fidelity, bounded protocol state, resets/GOAWAY/flow-control evidence, and gRPC trailer results. Publish exact runtime/leg support. |

Milestones are useful checkpoints, not review pauses. Continue automatically through M0–M5. Run M6 when its gate permits. Do not stop at a UI mock, isolated module, or a green happy-path unit suite.

### 14.2 Dependency-aware workstreams

After the shared M0 contract is fixed, use independent file ownership and narrow producer/consumer seams:

| Workstream | Primary ownership | Dependencies |
| --- | --- | --- |
| A | Fact normalization, incremental store/query, request projection | Shared contracts; integration owner approves schema changes. |
| B | Workbench shell, Traffic/detail/filter UX | A query contract; can develop against canonical fixtures while A integrates. |
| C | Cases/trials/markers/dependencies/policy proposals | A identity/provenance, shared case/trial contract. |
| D | Findings, comparisons, resolution evidence | A projections and C trial identity. |
| E | TLS evidence, local exclusions, environment/capabilities | Existing TLS/session contracts; C revisions. |
| F | Browser observation/profiles/NetLog and HAR adapters | Existing browser ownership; A provenance. |
| G | HTTP streaming/reuse/SSE/WebSocket and resource instrumentation | Connection/framing contracts; separate from UI file ownership. |
| H | Bundle/privacy/import/offline management/security | A canonical store, C metadata, shared API authorization contract. |
| I | H2 feasibility, then native protocol only where supported | Isolated early probe; A/G contracts before native integration. |
| J | Windows/UI/integration/compatibility/soak verification | Extend the existing harness; assign tests to real feature acceptance. |

One coordinator integrates and publishes. Use up to 20 subagents where work is genuinely independent; 20 agents must not edit `Session.ps1`, `Management.ps1`, or `ManagementUi.ps1` concurrently. Use isolated local worktrees/scratch branches when available. Only the coordinator commits integrated checkpoints to remote `main`. Do not create per-feature Issues/PRs or wait for human review in this authorized implementation phase. Never force-push main or discard unrelated work.

Write permission for the implementation covers the entry point, `src/**`, self-contained UI assets, `test/**`, relevant `docs/**`, README, AGENTS, and repository workflows required for verification. This is not a deny-list of files: the coordinator may include directly required integration files without manufacturing a scope blocker. Do not touch unrelated repositories or machine-wide settings.

## 15. Verification and completion

Use the repository-owned PowerShell harness and local fixtures. No Pester/npm/browser-driver download requirement. Reuse existing Edge DevTools automation for real DOM interactions, not screenshot-only approval or string-presence tests.

Mandatory evidence, on Windows PowerShell 5.1 and PowerShell 7 for the supported capability set:

1. Existing HTTP, CONNECT, TLS 1.2 Inspect, explicit proxy 403/407, self-reference rejection, mode pinning, listener health, CA/leaf disposal, stale cleanup, and UI launch continue to work.
2. Request details link to the correct event chain; identical simultaneous URLs are not falsely merged. Legacy logs display unknown fields honestly.
3. Old findings and session counters survive more events than the UI hot window. Cursor paging has no accidental repeats/gaps; log rotation and partial final lines are visible and recoverable.
4. Real UI filters, detail selection, pause/resume, markers, mode actions, browser launch, and error recovery work. English/Japanese text and markup remain intact under the PowerShell 5.1 source-encoding constraint.
5. Dependencies and change proposals retain evidence and require confirmation before broadening patterns or classifying business necessity. Local inspection exclusion never implies upstream bypass.
6. Trial comparisons identify changed protocol/auth/cache/environment conditions. Opaque bytes and generic TLS failure cannot produce an invented successful HTTP trial, pinning diagnosis, or specific appliance-policy verdict.
7. Browser capture records actual browser-originated traffic, cache/Service Worker cases, source-labelled failures, and ambiguous correlation; controls attach only to owned profiles. API/debugger secrets and sensitive Network fields do not enter logs/bundles.
8. Real h2 traffic passes through a local tunnel fixture; report protocol from actual endpoint/browser evidence. Native tests prove ALPN, stream behavior, and bounded malformed-input handling only on enabled native combinations.
9. A transfer larger than the old 32 MiB limit streams without whole-body memory growth. Early bytes reach the client before origin completion. SSE and WebSocket traffic can remain open while UI, health, mode changes, and other requests stay responsive. Persistent exchanges do not mix framing or credentials.
10. Slow peers, cancellation, full queues, disk limits, and writer failure leave explicit coverage/tool-health evidence instead of a false healthy result or unbounded memory usage.
11. Export/import/offline review round-trip a local case without creating CA trust. Secret sentinels are absent from persistent outputs; malicious HTML/CSV/archives cannot execute or escape the selected import directory.
12. Normal stop tears down both listeners, owned worker/debug connections, and session trust; cleanup refusal remains safe where ownership is unverified. Process-start identity prevents PID-reuse mistakes.

Store measured performance/soak conditions and results, not unsupported throughput claims. Resource limits and tested concurrency must be explicit. If a runtime cannot expose a requested measurement, label it unavailable and test that state.

### CI cost and iteration

Keep verification within existing suite structure where possible. Batch coherent integration checkpoints rather than triggering a full Windows matrix from every subagent. Consolidating redundant probe jobs is allowed only while retaining their coverage. Use bounded concurrency/cancellation for superseded branch runs where appropriate; never treat cancelled/skipped native verification as passing support.

Focused tests first, then the full relevant Windows matrices at integrated milestones and final HEAD. The final implementation push must not skip CI. Do not add public-Internet dependencies or a combinatorial job for every UI feature. Documentation-only changes do not require a runtime matrix.

### Completion ledger

Maintain `docs/phase-2-progress.md` during implementation: milestone/capability, files, proof/test, actual state, and justified platform limitations. Record native HTTP/2 separately. This is a compact delivery ledger, not a replacement for implementation or a new project-management framework.

Phase 2 is complete when M0–M5 meet their acceptance criteria and the exact final main HEAD has passing required Windows verification. Native HTTP/2 is complete only for explicitly verified combinations from M6. Unimplemented mandatory work remains open and must be reported as such. Do not advertise unverified enterprise certification or production readiness from an implementation milestone alone.

## 16. Primary technical references

References describe protocol/platform facts, not proof that a feature works on every Mihari host. Record runtime-specific results in the feasibility/capability evidence.

- **R1:** [RFC 9113 — HTTP/2](https://www.rfc-editor.org/rfc/rfc9113.html): ALPN, streams, connection/stream errors, and protocol semantics.
- **R2:** [RFC 7541 — HPACK](https://www.rfc-editor.org/rfc/rfc7541.html): compressed HTTP/2 fields.
- **R3:** [Microsoft Edge DevTools Protocol](https://learn.microsoft.com/en-us/microsoft-edge/devtools/protocol/): browser-local HTTP/WebSocket control interfaces.
- **R4:** [Chrome DevTools Protocol — Network domain](https://chromedevtools.github.io/devtools-protocol/tot/Network/): source-specific request, response, failure, cache, initiator, and protocol evidence; feature-detect the attached version.
- **R5:** [SslServerAuthenticationOptions.ApplicationProtocols](https://learn.microsoft.com/en-us/dotnet/api/system.net.security.sslserverauthenticationoptions.applicationprotocols): managed ALPN API surface; not a promise of .NET Framework availability.
- **R6:** [gRPC over HTTP/2 protocol](https://grpc.github.io/grpc/core/md_doc__p_r_o_t_o_c_o_l-_h_t_t_p2.html): distinguish HTTP and RPC/trailer outcomes.
- **R7:** [Chromium — providing network details / NetLog](https://www.chromium.org/for-testers/providing-network-details/): capture sensitivity and user-controlled evidence.
- **R8:** [Microsoft — setting WinINet proxy configurations in WinHTTP](https://learn.microsoft.com/en-us/windows/win32/winhttp/setting-wininet-proxy-configurations-in-winhttp): separate configuration consumers and explicit platform resolution.
