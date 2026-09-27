# HTTP/2 feasibility gate

This report tracks managed native HTTP/2 prerequisites separately from HTTP/2 tunneling and browser-assisted observation. A `SslStream` ALPN handshake is a prerequisite only; it does not prove an HTTP/2 parser or native Inspect implementation.

## Executable probe

Run the repository-owned probe once under each Windows runtime:

```powershell
powershell -NoProfile -File .\test\h2-feasibility-proof.ps1
pwsh -NoProfile -File .\test\h2-feasibility-proof.ps1
```

The probe reports the OS, PowerShell edition/version, CLR and runtime versions, `SslStream` assembly, and the exact managed ALPN members it finds. It then creates unique Mihari session CAs and `localhost` leaves using `src/Certificate.ps1`.

When the managed ALPN surface is complete, the probe installs the public test root in `CurrentUser\Root`, runs a loopback TLS 1.2 handshake where the client offers `http/1.1` and `h2` and the server supports `h2`, and reads the negotiated value at both ends. It supplies no certificate validation callback on the client. Root add/remove uses the existing bounded test confirmation operator, targeted to the exact probe process ID. If that API surface is absent, the probe still tests the exact-host leaf through the existing TLS 1.2 `SslStream` path and reports ALPN as unavailable at the managed API surface.

In both cases it creates a second exact-host leaf from an untrusted fixture CA and confirms that a default outbound `SslStream` rejects it without a validation callback. The probe removes the exact installed session root, disposes both leaf caches and CA keys, and verifies the leaf store and temporary user-key files are clear. It uses loopback only and makes no public network requests. Any handshake, validation, or cleanup failure exits nonzero; a missing managed ALPN API is an expected capability result and exits zero after the other checks pass. Running it off Windows exits 2 with `not-run` status.

The positive handshake is deliberately limited to TLS 1.2, matching the existing Inspect server path. It does not claim TLS 1.3 interception, HTTP/2 frame correctness, flow control, concurrent streams, gRPC fidelity, or end-to-end proxy forwarding.

## Windows probe results

Both probe jobs passed in [Actions run 36302954897](https://github.com/yohn-jp/mihari/actions/runs/36302954897), against tested HEAD `eb07cd5871c39cb461ad79226b1ef7b2387667cf` on Microsoft Windows Server 2025, version `10.0.26100.0`. The run as a whole concluded failure because the separate `phase2-transport` suite failed in job `108573967522`; the two HTTP/2 feasibility jobs below individually succeeded.

| Runtime | ALPN API and leg results | Session leaf, validation, cleanup | CI evidence |
| --- | --- | --- | --- |
| Windows PowerShell `5.1.26100.33438`; CLR / `Environment.Version` `4.0.30319.42000`; .NET Framework `4.8.9345.0`; `SslStream` assembly `System, Version=4.0.0.0` | Managed ALPN surface unavailable. The probe found all six required members absent: `SslServerAuthenticationOptions`, `SslClientAuthenticationOptions`, `SslApplicationProtocol`, `SslStream.NegotiatedApplicationProtocol`, and the `AuthenticateAsServerAsync(options)` / `AuthenticateAsClientAsync(options)` overloads. Server selection and client readback therefore cannot be performed through the supported managed `SslStream` API surface. | Exact-host Mihari leaf completed the TLS 1.2 fallback handshake. Default OS validation accepted the temporarily trusted session root and rejected a same-name leaf from an untrusted fixture CA with `AuthenticationException`. Cleanup passed: session root removed, leaves absent from stores, temporary leaf key files removed. | [Job 108573967172](https://github.com/yohn-jp/mihari/actions/runs/36302954897/job/108573967172) |
| PowerShell `7.6.6`; `Environment.Version` / .NET `10.0.12`; `SslStream` assembly `System.Net.Security, Version=10.0.0.0` | Managed client and server ALPN surface complete. The server selected `h2`; the client read back `h2`; both endpoints negotiated TLS 1.2. | Exact-host Mihari leaf completed the handshake under default OS validation with the public session root installed and no callback. A second default `SslStream` client rejected a same-name leaf from an untrusted fixture CA with `AuthenticationException`. Cleanup passed: session root removed, leaves absent from stores, temporary leaf key files removed. | [Job 108573967158](https://github.com/yohn-jp/mihari/actions/runs/36302954897/job/108573967158) |

The Windows PowerShell result is an observed managed-API limitation for this PowerShell 5.1 / .NET Framework combination. It supports marking native `http2.inspect` unavailable on that combination under the no-helper constraint; it does not make HTTP/2 Tunnel or browser-assisted observation unavailable. The PowerShell 7 result passes the ALPN/leaf/validation feasibility gate for the tested runner combination and permits M6 work there. It does not prove an HTTP/2 parser, proxy forwarding, semantic fidelity, concurrency, flow control, gRPC, or native Inspect implementation.

The local development host remains Linux x86_64 (`Linux nixos-dev 6.18.52`) with no `powershell`, `pwsh`, or `dotnet` executable, so the executable probe was not run locally. Runtime results above come from the linked Windows Actions jobs, not from inference about the local host.

## Static source observations

At source baseline `681255bf4f9b9ec900f34a7f986388911e611510`, `src/Certificate.ps1` creates the ephemeral CNG CA, exact-host SAN leaf, and temporary `UserKeySet` key used by Schannel. `src/Tls.ps1` authenticates through the existing TLS 1.2 `SslStream` path and does not configure or read ALPN. This establishes what the source attempted at that baseline, not whether the Windows runtime/API combination succeeds. The probe checks the real runtime and certificate path directly.

## Capability table

| Capability | Windows PowerShell 5.1 | PowerShell 7 | State on this report |
| --- | --- | --- | --- |
| Existing HTTP/1.1 Inspect leaf/TLS 1.2 | Loopback session-leaf TLS 1.2 proof passed; live proxy Inspect remains covered by its separate suite | Loopback session-leaf TLS 1.2 proof passed; live proxy Inspect remains covered by its separate suite | This probe does not replace the existing Inspect tests. |
| `http2.tunnel` | Not measured by this ALPN probe | Not measured by this ALPN probe | Separate mandatory Phase 2 acceptance path. |
| `browser.network` / `http2.browser_assisted` | Not measured by this ALPN probe | Not measured by this ALPN probe | Separate mandatory Phase 2 acceptance path. |
| `http2.inspect` client leg (Mihari to upstream) | ALPN API unavailable in the tested Windows PowerShell 5.1 / .NET Framework combination | Managed ALPN API surface passed; default validation passed positive and negative fixtures | PS7 gate permits M6 work; no native client-leg implementation tested. |
| `http2.inspect` server leg (browser/client to Mihari) | ALPN API unavailable in the tested Windows PowerShell 5.1 / .NET Framework combination | Server selected `h2`; client read back `h2`; session leaf passed default trust | PS7 gate permits M6 work; no native server-leg implementation tested. |
| M6 frame and stream implementation | Not evaluated by this isolated gate | Not evaluated by this isolated gate | No parser implementation is part of this workstream. |

For any future runtime or Windows image, preserve the probe JSON's runtime, `SslStream` assembly, API-member inventory, negotiated ALPN at each leg, validation result, and cleanup result. A complete API surface with a failed handshake is a failed/inconclusive operation result, not evidence of platform impossibility. Only an observed missing required managed API surface supports marking native ALPN unavailable for that runtime under the repository's no-helper constraint.
