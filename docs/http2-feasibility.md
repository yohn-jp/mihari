# HTTP/2 feasibility gate

This report tracks managed native HTTP/2 prerequisites separately from HTTP/2 tunneling and browser-assisted observation. The early `SslStream` ALPN handshake proved feasibility; the later M6 tests below exercise the native parser and live Inspect path separately.

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

The Windows PowerShell result is an observed managed-API limitation for this PowerShell 5.1 / .NET Framework combination. It supports marking native `http2.inspect` unavailable on that combination under the no-helper constraint; it does not make HTTP/2 Tunnel or browser-assisted observation unavailable. The PowerShell 7 result passed the prerequisite gate. The later M6 proof below is the evidence for native forwarding; the feasibility probe alone is not.

The local development host remains Linux x86_64 (`Linux nixos-dev 6.18.52`) with no `powershell`, `pwsh`, or `dotnet` executable, so the executable probe was not run locally. Runtime results above come from the linked Windows Actions jobs, not from inference about the local host.

## Static source observations

At source baseline `681255bf4f9b9ec900f34a7f986388911e611510`, `src/Certificate.ps1` creates the ephemeral CNG CA, exact-host SAN leaf, and temporary `UserKeySet` key used by Schannel. `src/Tls.ps1` authenticates through the existing TLS 1.2 `SslStream` path and does not configure or read ALPN. This establishes what the source attempted at that baseline, not whether the Windows runtime/API combination succeeds. The probe checks the real runtime and certificate path directly.

## Capability table

| Capability | Windows PowerShell 5.1 | PowerShell 7 | State on this report |
| --- | --- | --- | --- |
| Existing HTTP/1.1 Inspect leaf/TLS 1.2 | Loopback session-leaf TLS 1.2 proof passed; live proxy Inspect remains covered by its separate suite | Loopback session-leaf TLS 1.2 proof passed; live proxy Inspect remains covered by its separate suite | This probe does not replace the existing Inspect tests. |
| `http2.tunnel` | Not measured by this ALPN probe | Not measured by this ALPN probe | Separate mandatory Phase 2 acceptance path. |
| `browser.network` / `http2.browser_assisted` | Not measured by this ALPN probe | Not measured by this ALPN probe | Separate mandatory Phase 2 acceptance path. |
| `http2.inspect` client leg (Mihari to upstream) | Managed ALPN API unavailable on the tested runtime; native profile rejects before session start | Production `http2-inspect` profile negotiated `h2` to a loopback TLS origin under normal trust validation | Implemented and live-tested on the tested PS7 runner only. |
| `http2.inspect` server leg (client to Mihari) | Managed ALPN API unavailable on the tested runtime; native profile rejects before session start | Production listener accepted CONNECT, used a session-issued exact-host leaf, and negotiated `h2` with the TLS client | Implemented and live-tested on the tested PS7 runner only. |
| M6 frame and stream implementation | Shared parser/HPACK tests pass, but native TLS transport is unavailable | Bounded frame/HPACK tests pass; direct and production CONNECT fixtures carried two concurrent h2 request/response streams and response bodies | Reset, GOAWAY, flow-wait, and gRPC trailer facts have focused parser tests; the live fixture proves concurrent HTTP/2 transport, not live gRPC interoperability. |

## M6 implementation proof and limits

At HEAD `d86e7e09d275a0743fc7ab2af78d65bac588f22f`, [PowerShell 7 workbench job 108582926192](https://github.com/yohn-jp/mihari/actions/runs/36306087425/job/108582926192) printed `PASS phase2-hpack`, `PASS phase2-http2-native`, and `PASS phase2-http2-tls: direct and production CONNECT two-leg h2, concurrent streams, normal trust, CA cleanup`. The production fixture starts `mihari.ps1` with `-Profile http2-inspect -Mode Inspect`, connects through the actual loopback listener, authenticates the session leaf, forwards two concurrent stream IDs to a local TLS origin, receives their responses, and checks safe JSONL path/ALPN/status facts and exact CA removal. The direct fixture exercises the same native handler separately. This job later failed in the independent finding snapshot test; its whole-suite result is **not green**.

[Windows PowerShell 5.1 workbench job 108581362376](https://github.com/yohn-jp/mihari/actions/runs/36305547329/job/108581362376) passed the shared HPACK/frame tests and the precise native-profile startup rejection. That job later failed in an independent comparison assertion. Its passing parser tests do not make native ALPN available on 5.1.

Native Inspect currently requires `h2` on both TLS legs, uses TLS 1.2, and does not convert an upstream HTTP/1.1 leg. The relay bounds an individual accepted frame to 64 KiB, decoded HPACK header lists to 64 KiB and 128 fields, and active streams to 128; a valid larger SETTINGS advertisement is observed, but an actual frame above the local bound ends the relay with a failure fact. Server push and TLS 1.3 interception are outside this implementation. The focused parser tests cover SETTINGS/ACK and HPACK state, stream IDs, flow-window waits, reset/GOAWAY facts, and an observed `grpc-status` trailer without retaining payloads. Browser-facing M6 rendering and a live gRPC stream are not established by these jobs.

For any future runtime or Windows image, preserve the probe JSON's runtime, `SslStream` assembly, API-member inventory, negotiated ALPN at each leg, validation result, and cleanup result. A complete API surface with a failed handshake is a failed/inconclusive operation result, not evidence of platform impossibility. Only an observed missing required managed API surface supports marking native ALPN unavailable for that runtime under the repository's no-helper constraint.
