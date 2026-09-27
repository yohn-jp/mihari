# Mihari product requirements

## 1. Purpose

Mihari is a local diagnostic proxy for Windows enterprise endpoints.

The problem it solves is not "capture packets." The problem is determining, from the endpoint, which web requests an application or browser requires and at which observable stage those requests fail when enterprise network controls are present.

Typical environments include:

- transparent proxies and Secure Web Gateways;
- explicit HTTP proxies;
- PAC/WPAD-based proxy selection;
- firewall or endpoint-agent traffic redirection;
- TLS inspection;
- FQDN and URL allowlists;
- proxy authentication;
- services that use certificate pinning or mTLS.

A common manual troubleshooting workflow asks a user to collect browser HAR data and then separately inspect proxy/network behavior. Mihari should make the endpoint-side portion of that workflow repeatable and local.

## 2. Product boundary

Mihari observes the endpoint and the responses visible from the endpoint.

It does not claim access to an upstream proxy's internal logs. It must distinguish direct evidence from inference.

Examples:

- an upstream explicit proxy returning HTTP 407 is direct evidence of proxy authentication being required;
- an upstream explicit proxy returning HTTP 403 is direct evidence that the proxy rejected the request, although the proxy's internal rule that caused it is not visible;
- a TCP timeout after handing traffic to the network is evidence of a timeout, not proof of which upstream device dropped it;
- inspection mode failing while tunnel mode succeeds is evidence that TLS interception changes the outcome; it is not sufficient by itself to distinguish certificate pinning from mTLS or another interception-incompatible protocol behavior.

Mihari must never report a more specific cause than its evidence supports.

## 3. Target environment

The baseline target is Windows PowerShell 5.1 on Windows. PowerShell 7 must also be supported.

Runtime dependencies are limited to:

- PowerShell;
- Windows facilities available on the host;
- .NET APIs already available to the selected PowerShell runtime.

The runtime must not require:

- Node.js;
- Python;
- a separately built .NET executable;
- third-party native binaries;
- external PowerShell modules;
- package installation.

The implementation may be split into as many PowerShell source files as needed. "100% PowerShell" does not mean one script file.

Embedded C# compilation is outside the intended implementation model. Prefer PowerShell plus existing .NET types.

## 4. Primary workflow

A diagnostic session is explicit and bounded.

1. Start a Mihari session.
2. Mihari creates a unique session ID and output directory.
3. In inspection mode, Mihari creates one ephemeral session CA and trusts only its public certificate for the current user.
4. Mihari starts a loopback-only local proxy.
5. Mihari launches a diagnostic browser through that local proxy, or prints the proxy endpoint for a caller to configure.
6. The user reproduces the failing workflow.
7. Mihari records structured observations.
8. The user can repeat the workflow in tunnel mode for comparison.
9. Mihari produces a deterministic diagnostic summary from the recorded evidence.
10. Stopping the session removes the trusted session CA and disposes all private key material.
11. A separate cleanup command can remove stale Mihari CA trust left by an abnormal termination.

The default browser launch must not modify the machine-wide proxy configuration. It should use a process-specific proxy argument and a temporary browser profile when the browser supports it.

## 5. Observation modes

### Inspect

Mihari terminates client TLS locally, observes HTTP/1.1 requests, then creates the corresponding upstream connection.

Inspect mode exists to observe the URL path and HTTP-level outcome and to test the effect of TLS interception.

### Tunnel

For HTTPS CONNECT traffic, Mihari relays the byte stream without terminating TLS.

Tunnel mode exists as a controlled comparison against Inspect mode. It can still observe connection metadata, CONNECT targets, timing, socket failures, and any explicit upstream proxy response visible before the tunnel is established.

### Comparison

The diagnostic engine should compare observations by destination and workflow where possible.

The most important comparison is:

- Inspect fails + Tunnel succeeds: TLS interception materially changes the outcome. Classify as interception-incompatible; possible mechanisms include pinning, mTLS, or other TLS/application behavior. Do not claim a specific mechanism without further evidence.
- Inspect and Tunnel both fail at the same observable upstream stage: local TLS interception is not the differentiator.
- Local proxy accepts the request but the upstream proxy returns a concrete rejection: classify the rejection using the returned status/evidence.

A browser run with no Mihari proxy may be used as an external baseline, but Mihari cannot observe traffic that does not traverse Mihari.

## 6. Protocol baseline

Initial required support:

- HTTP/1.1 proxy requests;
- HTTP CONNECT;
- HTTPS inspection using TLS 1.2;
- plain HTTP forwarding;
- IPv4 loopback listener;
- DNS names and explicit ports;
- request methods sufficient for ordinary browser and API traffic, including request bodies;
- persistent connections may be supported, but correctness is more important than connection reuse.

Initial non-goals:

- HTTP/2 frame parsing;
- TLS 1.3 interception;
- HTTP/3;
- QUIC;
- UDP proxying;
- raw packet capture;
- kernel/WFP drivers;
- SOCKS;
- WebSocket-specific semantic inspection.

The diagnostic browser may be forced onto HTTP/1.1/TLS 1.2 behavior where necessary for the initial implementation. Mihari must report unsupported protocol behavior rather than silently misclassify it.

## 7. Enterprise upstream behavior

Transparent/in-path controls are the primary target. In that topology, Mihari connects toward the origin and the enterprise network remains in the path naturally.

Mihari should also support explicit upstream proxy chaining when the upstream proxy is known or can be resolved from the Windows environment.

Upstream resolution is a separate responsibility from request forwarding. It should support:

1. an explicit Mihari override;
2. the Windows/.NET default proxy resolver when usable;
3. direct routing when no explicit proxy applies.

PAC/WPAD resolution is best-effort through platform facilities. If Mihari cannot resolve the configured proxy path deterministically, it must report that limitation rather than bypass the configured enterprise proxy without notice.

Proxy authentication responses such as 407 must be preserved and recorded. Integrated authentication support may depend on the platform path used for upstream chaining; an unsupported authentication scheme must be reported explicitly.

Mihari must not intentionally evade, disable, or route around enterprise egress policy.

## 8. Session CA and TLS interception

Inspection uses one ephemeral root CA per session.

Requirements:

- generate a unique CA keypair at session start;
- CA private key remains process-local and is never written as a PFX/private-key file;
- install only the public CA certificate into the current user's trusted root store;
- use a distinctive Mihari subject plus session identifier so stale trust can be found safely;
- use a short validity period appropriate to a diagnostic session;
- generate leaf certificates on demand for the exact requested host;
- include the correct SAN for the requested DNS name or IP where supported;
- sign leaf certificates with the session CA;
- keep leaf certificate objects only in memory; Windows Schannel may use a temporary, current-user private-key file for an active leaf;
- remove temporary leaf key files on cache eviction and normal session stop; never write a PFX file;
- cache leaf certificates only for the current session, with a bounded cache;
- never install per-host leaf certificates into Windows certificate stores;
- remove the trusted session CA at normal stop;
- provide idempotent stale-CA cleanup for abnormal termination.

Do not use one wildcard certificate for all destinations. Exact-host leaf issuance provides a more faithful TLS surface and avoids persistent certificate-store spam without broadening certificate scope.

Mihari must never disable upstream certificate validation globally. The upstream TLS peer must be validated using the normal Windows/.NET trust model, and certificate validation errors are diagnostic evidence.

## 9. What to record

Every observation belongs to one session and one connection/request correlation chain.

At minimum record:

- timestamp;
- session ID;
- connection ID;
- request ID where HTTP is visible;
- mode: Inspect or Tunnel;
- client endpoint;
- requested host and port;
- HTTP method when visible;
- URL path when visible;
- response status when visible;
- upstream route selected: direct or explicit proxy;
- explicit proxy endpoint when known;
- stage reached;
- outcome;
- elapsed duration;
- exception type and normalized error code/message where relevant;
- TLS protocol/cipher when available;
- upstream certificate subject, issuer, validity, and thumbprint when available;
- whether the upstream certificate chain was accepted;
- concrete proxy status such as 403/407 when visible.

The event stream should be JSON Lines so it can be processed incrementally and without requiring another runtime.

## 10. Privacy defaults

Mihari is a diagnostic observer, not a credential collector.

By default:

- capture scheme, host, port, and URL path;
- do not persist request or response bodies;
- do not persist Cookie, Authorization, Proxy-Authorization, or Set-Cookie values;
- do not persist arbitrary headers unless specifically allowlisted;
- treat query strings as sensitive and redact values by default;
- do not log private keys or session secrets;
- keep logs in a user-scoped output directory.

The architecture can permit explicit future opt-in for more detailed capture, but the initial implementation must not require it.

## 11. Evidence stages

Use a small, stable stage vocabulary. Suggested stages:

- `listener.accept`
- `proxy.request`
- `client.tls`
- `http.request`
- `upstream.resolve`
- `upstream.proxy.connect`
- `upstream.tcp`
- `upstream.tls`
- `upstream.http`
- `response.relay`
- `session.cleanup`

Each event should be a fact. Diagnosis is produced separately from facts.

## 12. Initial deterministic diagnoses

The first diagnostic engine should be rule-based and conservative. Useful classifications include:

- `client_tls_interception_failed`
- `tls_interception_incompatible`
- `upstream_proxy_auth_required`
- `upstream_proxy_rejected`
- `dns_resolution_failed`
- `tcp_connection_failed`
- `upstream_tls_failed`
- `upstream_certificate_invalid`
- `http_error_response`
- `unsupported_protocol`
- `cleanup_incomplete`
- `undetermined_after_upstream_handoff`

Each diagnosis must include the event IDs or connection/request IDs that constitute its evidence. When a rule cannot distinguish multiple causes, the diagnosis text must preserve that ambiguity.

## 13. Initial user interface

The implementation should expose one thin entry point, for example:

```powershell
.\mihari.ps1 start
.\mihari.ps1 start -Mode Inspect -Port 8899
.\mihari.ps1 browser
.\mihari.ps1 status
.\mihari.ps1 report
.\mihari.ps1 stop
.\mihari.ps1 cleanup
```

Exact parameter names may evolve during implementation, but the responsibilities must remain separate:

- start owns session initialization, CA setup, and listener startup;
- browser launches a diagnostic browser without changing global proxy settings;
- status reports active session state;
- report analyzes existing event data;
- stop performs graceful shutdown and certificate cleanup;
- cleanup repairs stale trust/session artifacts.

The entry point should delegate to small PowerShell source files rather than containing the implementation.

## 14. Initial acceptance criteria

The first usable release is complete when all of the following work on Windows:

1. Windows PowerShell 5.1 can parse and run the entry point.
2. PowerShell 7 can run the same implementation.
3. A loopback proxy accepts HTTP/1.1 requests.
4. CONNECT tunnel mode can relay an HTTPS connection.
5. Inspect mode can issue an exact-host leaf certificate from a session CA and read the HTTP request path over TLS 1.2.
6. No per-host certificate remains in a Windows certificate store.
7. Normal stop removes the trusted Mihari CA.
8. Cleanup removes a deliberately orphaned Mihari CA without removing unrelated certificates.
9. The proxy emits structured JSONL facts.
10. A summary command derives conservative diagnoses from those facts.
11. An Edge diagnostic browser can be launched with a temporary profile and Mihari as its process-specific proxy.
12. HTTP/3/QUIC/TLS 1.3-only behavior is reported as unsupported rather than being silently interpreted as an allowlist/proxy failure.
13. Runtime use requires no third-party package or binary.
