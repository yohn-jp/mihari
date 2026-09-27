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

## Results recorded from this checkout

Repository revision inspected: `681255bf4f9b9ec900f34a7f986388911e611510` (`origin/main` at probe creation).

| Runtime / leg | Result | Evidence |
| --- | --- | --- |
| Windows PowerShell 5.1, Mihari server ALPN selection | Not run; Windows PowerShell is unavailable on the current Linux host. | `command -v powershell` returned no executable; `test/h2-feasibility-proof.ps1` was not run. |
| Windows PowerShell 5.1, client ALPN negotiation/readback | Not run; Windows PowerShell is unavailable on the current Linux host. | Same host check. |
| Windows PowerShell 5.1, Mihari session leaf with Schannel | Not run; Windows is unavailable on the current host. | The probe uses `New-MihariCA`, `Get-MihariLeaf`, and loopback `SslStream` on Windows. |
| Windows PowerShell 5.1, default upstream certificate validation | Not run; Windows is unavailable on the current host. | The probe expects default `SslStream` validation to reject a leaf from its second, untrusted fixture CA. |
| PowerShell 7, Mihari server ALPN selection | Not run; `pwsh` is unavailable on the current Linux host. | `command -v pwsh` returned no executable; `test/h2-feasibility-proof.ps1` was not run. |
| PowerShell 7, client ALPN negotiation/readback | Not run; `pwsh` is unavailable on the current Linux host. | Same host check. |
| PowerShell 7, Mihari session leaf with Schannel | Not run; Windows is unavailable on the current host. | The probe uses the production certificate functions and Schannel-backed key file on Windows. |
| PowerShell 7, default upstream certificate validation | Not run; Windows is unavailable on the current host. | The probe uses the default outbound `SslStream` overload without a callback. |

The available host is Linux x86_64 (`Linux nixos-dev 6.18.52`); `command -v powershell`, `command -v pwsh`, and `dotnet --info` found no executable. These are host-availability facts, not evidence that either Windows runtime lacks ALPN or that native HTTP/2 is unavailable there. No runtime capability conclusion is drawn from this host.

## Static source observations

At the inspected revision, `src/Certificate.ps1` creates the ephemeral CNG CA, exact-host SAN leaf, and temporary `UserKeySet` key used by Schannel. `src/Tls.ps1` authenticates through the existing TLS 1.2 `SslStream` path and does not configure or read ALPN. This establishes what the current source attempts, not whether the Windows runtime/API combination succeeds. The probe checks the real runtime and certificate path directly.

## Capability table

| Capability | Windows PowerShell 5.1 | PowerShell 7 | State on this report |
| --- | --- | --- | --- |
| Existing HTTP/1.1 Inspect leaf/TLS 1.2 | Runtime probe not run here | Runtime probe not run here | Keep existing capability behavior; the new probe does not replace the existing Inspect tests. |
| `http2.tunnel` | Not measured by this ALPN probe | Not measured by this ALPN probe | Separate mandatory Phase 2 acceptance path. |
| `browser.network` / `http2.browser_assisted` | Not measured by this ALPN probe | Not measured by this ALPN probe | Separate mandatory Phase 2 acceptance path. |
| `http2.inspect` client leg (Mihari to upstream) | ALPN surface and default validation untested | ALPN surface and default validation untested | No native claim. |
| `http2.inspect` server leg (browser/client to Mihari) | ALPN selection and session leaf untested | ALPN selection and session leaf untested | No native claim. |
| M6 frame and stream implementation | Not evaluated by this isolated gate | Not evaluated by this isolated gate | No parser implementation is part of this workstream. |

After Windows runs, replace each `Not run` entry with the probe JSON's actual values and preserve the runtime, `SslStream` assembly, API-member inventory, negotiated ALPN at each leg, validation result, and cleanup result. A complete API surface with a failed handshake is a failed/inconclusive operation result, not evidence of platform impossibility. Only an observed missing required managed API surface supports marking native ALPN unavailable for that runtime under the repository's no-helper constraint.
