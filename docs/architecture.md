# Mihari target architecture

## 1. Architectural intent

Mihari is a diagnostic runtime, not a general-purpose production proxy.

Its architecture is optimized for four properties:

1. **Observability** — preserve evidence for every stage Mihari can directly observe.
2. **Non-bypass** — keep the enterprise network path intact rather than routing around it.
3. **Ephemerality** — TLS interception trust and private key material exist only for a diagnostic session.
4. **Deployability** — run from PowerShell source on a restricted Windows endpoint without installing another runtime.

The implementation should favor small explicit components over a framework.

## 2. Process model

One foreground Mihari process owns one active session.

The process contains:

- the loopback listener;
- a bounded connection worker pool;
- the session CA private key;
- the in-memory leaf certificate cache and its temporary Windows user-key files;
- the event writer;
- session state.

Session state that must survive an abnormal process exit is limited to non-secret metadata needed for cleanup and diagnosis.

Do not persist CA private keys.

## 3. Proposed repository layout

```text
mihari.ps1
AGENTS.md
docs/
  requirements.md
  architecture.md
src/
  Compatibility.ps1
  Session.ps1
  Certificate.ps1
  Listener.ps1
  Connection.ps1
  Http.ps1
  Tls.ps1
  Upstream.ps1
  Observation.ps1
  Diagnosis.ps1
  Browser.ps1
  Cleanup.ps1
test/
  unit/
  integration/
  run.ps1
.github/
  workflows/
    verify.yml
```

The names are guidance, not an excuse to build abstractions without use. Keep the entry point thin and split files by runtime responsibility.

## 4. Compatibility layer

`Compatibility.ps1` owns feature detection.

At startup, verify the APIs actually needed by the selected mode, especially:

- `TcpListener` / `TcpClient`;
- `SslStream`;
- RSA key generation;
- X.509 request/issuance APIs needed for exact-host leaf certificates;
- certificate store access;
- JSON serialization;
- runspace APIs;
- browser discovery where browser launch is requested.

PowerShell 5.1 is the language baseline. Do not use PowerShell 7-only syntax or cmdlets in shared runtime code.

If an API required to satisfy the no-persistent-leaf certificate contract is unavailable, fail capability detection with a precise message. Do not silently fall back to installing one leaf certificate per host.

## 5. Session state

A session has a unique random identifier.

Suggested persistent metadata:

```text
%LOCALAPPDATA%\Mihari\sessions\<session-id>\
  session.json
  events.jsonl
  report.json
  report.txt
```

`session.json` may contain:

- session ID;
- start time;
- process ID;
- mode;
- listener endpoint;
- CA public certificate thumbprint;
- CA subject;
- output schema version.

It must not contain private keys or captured credentials.

The active session marker should allow `status`, `stop`, and `cleanup` to determine whether a recorded process is still alive.

## 6. Concurrency

A browser opens multiple connections concurrently. A single synchronous connection loop is insufficient.

PowerShell 5.1 does not provide the same convenient threading primitives as newer environments. Prefer a bounded `System.Management.Automation.Runspaces.RunspacePool` or another PowerShell-5.1-compatible in-process mechanism.

Requirements:

- bounded worker count;
- one connection context per worker;
- immutable/shared configuration where practical;
- synchronized event writing;
- graceful cancellation on stop;
- worker failure must not terminate the listener silently.

Avoid `Start-Job` as the primary per-connection mechanism because it creates process/remoting overhead and complicates ownership of sockets and session CA state.

## 7. Connection pipeline

For each accepted client connection:

```text
accept
  -> parse proxy request
  -> if plain HTTP:
       resolve upstream route
       forward HTTP
       observe response
     if CONNECT:
       inspect mode:
         acknowledge CONNECT
         terminate client TLS with generated leaf
         parse decrypted HTTP/1.1
         resolve/open upstream
         establish upstream TLS
         forward request
         observe response
       tunnel mode:
         resolve/open upstream tunnel
         acknowledge CONNECT when viable
         relay bytes bidirectionally
  -> close/return connection
```

Emit a fact at every stage boundary and failure.

## 8. HTTP parsing and forwarding

Initial protocol parsing is intentionally HTTP/1.1 only.

The parser must:

- impose maximum request-line and header sizes;
- handle CRLF correctly;
- normalize neither host nor path beyond what is necessary for routing;
- preserve request method and target semantics;
- support `Content-Length`;
- support chunked transfer encoding or explicitly reject/report it until implemented;
- strip hop-by-hop proxy headers as required;
- never persist credential-bearing headers.

Do not implement HTTP by repeatedly converting arbitrary binary buffers to strings. Read headers to the header terminator, then process bodies by framing rules.

For decrypted HTTPS requests, the Host header plus CONNECT authority defines the origin. Reject mismatches that would create ambiguous routing rather than silently forwarding to a different authority.

## 9. TLS interception

### Session CA

Generate one RSA session CA in memory.

Install a public-only copy into `Cert:\CurrentUser\Root`.

The subject should be machine-searchable and session-specific, for example:

```text
CN=Mihari Ephemeral Diagnostic CA <session-id>
```

The trust certificate should have a short lifetime. Cleanup must identify it by both Mihari identity and recorded thumbprint.

### Leaf certificates

When a client starts TLS for a CONNECT destination:

1. normalize the requested authority;
2. look up an exact-host leaf in the bounded session cache;
3. if missing, create an RSA leaf certificate in memory;
4. place the exact DNS name or IP address in SAN;
5. sign it with the session CA;
6. attach the key in memory, then import an in-memory PFX byte array into a temporary current-user key set because Windows Schannel rejects ephemeral server keys;
7. use the imported certificate with `SslStream.AuthenticateAsServer` and dispose it on eviction or stop so Windows deletes its temporary key file;
8. never write a PFX file or import the leaf into CurrentUser or LocalMachine certificate stores.

Do not use a global wildcard certificate.

An abrupt process termination can leave a temporary Windows leaf-key file. Stale cleanup removes only positively identified CA roots; it does not delete unrelated or unverified user key files.

### TLS versions

The first implementation targets TLS 1.2 explicitly for the inspected client and upstream TLS legs.

Do not globally relax remote certificate validation. If upstream TLS validation fails, record the chain/validation evidence available and fail that request.

## 10. Upstream routing

Represent upstream resolution as data, for example:

```text
kind: Direct | ExplicitProxy | Unsupported
endpoint: host:port
source: Override | Platform | None
reason: ...
```

The resolver must be separable from the socket/HTTP forwarding code.

Resolution order:

1. explicit Mihari command-line/config override;
2. platform default proxy resolution when available;
3. direct.

For a transparent enterprise proxy/SWG, the result will normally be Direct; the network device remains in path outside Mihari.

For an explicit proxy, Mihari must send the appropriate proxy request (including CONNECT for HTTPS). Concrete 403/407 and other proxy responses are observation facts.

Do not silently choose Direct when platform configuration clearly indicates a proxy but Mihari cannot interpret it. Return Unsupported with evidence.

## 11. Bidirectional tunnel relay

Tunnel mode should relay both directions until EOF, cancellation, or error.

The relay must:

- avoid unbounded buffering;
- have bounded buffer sizes;
- preserve half-close behavior where practical;
- record which direction failed first;
- record byte counts and duration;
- close both sides deterministically.

This path is also a useful control for diagnosing whether local TLS termination changes the outcome.

## 12. Observation contract

Facts are append-only JSONL records.

Suggested envelope:

```json
{
  "schemaVersion": 1,
  "timestamp": "2026-09-27T00:00:00.000Z",
  "sessionId": "...",
  "connectionId": "...",
  "requestId": "...",
  "mode": "Inspect",
  "stage": "upstream.tls",
  "outcome": "failed",
  "elapsedMs": 123,
  "data": {
    "host": "example.com",
    "port": 443,
    "errorType": "...",
    "errorCode": "..."
  }
}
```

Keep `data` stage-specific. The stable envelope allows the diagnosis engine to remain simple.

Facts should record raw exception type plus a normalized Mihari error code. Do not make the event writer responsible for diagnosis.

## 13. Diagnosis architecture

`Diagnosis.ps1` consumes facts and produces findings.

A finding should contain:

```text
code
summary
scope (session/connection/request/host)
evidenceIds
observedFacts
interpretation
limitations
```

Rules must be deterministic.

Examples:

- upstream proxy response 407 -> `upstream_proxy_auth_required`;
- upstream proxy response 403 -> `upstream_proxy_rejected`;
- client TLS abort in Inspect plus successful matching Tunnel connection -> `tls_interception_incompatible`;
- certificate validation exception on upstream TLS -> `upstream_certificate_invalid`;
- no concrete upstream rejection, only timeout -> timeout/connectivity finding, not "proxy blocked."

The text report is a rendering of structured findings, not a separate source of truth.

## 14. Browser launcher

Initial browser target: Microsoft Edge on Windows.

Launch with:

- a dedicated temporary user-data directory;
- a process-specific `--proxy-server=http://127.0.0.1:<port>`;
- no certificate-error bypass flag;
- optional URL supplied by the user.

Do not modify global Windows proxy settings merely to launch the diagnostic browser.

If Edge cannot be found, report the condition and print the proxy endpoint. Chrome can be a later compatible launcher using the same interface.

Managed browser policy can override command-line behavior. Record the command and process launch result so that this is diagnosable.

## 15. Lifecycle and cleanup

Normal stop:

1. stop accepting connections;
2. signal workers;
3. wait a bounded period;
4. flush and close event output;
5. dispose cached leaves;
6. dispose CA private key;
7. remove the exact trusted CA public certificate;
8. mark session stopped;
9. generate/update the report.

Abnormal termination recovery:

- `cleanup` enumerates Mihari-owned CA certificates;
- validates subject/prefix and, where available, session metadata/thumbprints;
- removes only Mihari-owned stale certificates;
- never removes unrelated roots based on age alone;
- reports every removal and every item it refused to remove.

Cleanup is idempotent.

## 16. Failure semantics

Prefer explicit failure states over best-effort behavior that changes network topology.

Examples:

- proxy configured but unresolved -> fail/report, do not silently go direct;
- CA installation failed -> Inspect mode cannot start;
- leaf generation capability unavailable -> Inspect mode cannot start;
- Tunnel mode may still be available when Inspect capability is unavailable;
- unsupported protocol -> record `unsupported_protocol`;
- report generation failure must not delete the underlying event log.

## 17. Verification strategy

Runtime has no third-party dependencies, so the test harness should also avoid making a package manager mandatory.

Use PowerShell assertions/scripts under `test/`.

CI should run on `windows-latest` with both:

- Windows PowerShell 5.1 (`powershell`);
- installed PowerShell 7 (`pwsh`).

Focused tests should cover:

- HTTP request parsing and framing;
- redaction;
- diagnosis rules;
- upstream route selection;
- exact certificate ownership matching;
- CA creation/trust/removal;
- exact-host leaf issuance and temporary key-file disposal;
- no leaf-store residue;
- plain HTTP proxying;
- CONNECT tunnel relay;
- TLS 1.2 inspection against a local test origin;
- stop and stale cleanup.

Every certificate integration test must use a unique subject and remove its certificates in `finally`.

A final smoke test should start Mihari, run local traffic through it, stop it, and assert that no Mihari test CA remains trusted.

## 18. Deliberate exclusions from the initial architecture

Do not add these merely because they may be useful later:

- GUI/Web UI;
- Windows service installation;
- WFP/filter drivers;
- system-wide proxy mutation;
- packet capture;
- remote telemetry/backend;
- cloud account;
- plugin system;
- database;
- HTTP/2 parser;
- HTTP/3/QUIC;
- generalized certificate management.

The initial product should first prove reliable local observation, TLS inspection comparison, deterministic diagnosis, and safe cleanup.
