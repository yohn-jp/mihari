# Mihari

Mihari is a Windows-native HTTP(S) diagnostic observation proxy implemented entirely in PowerShell.

It is intended for enterprise endpoint troubleshooting where web traffic can be affected by transparent or explicit proxies, TLS inspection, Secure Web Gateways, firewall redirection, allowlists, certificate pinning, mTLS, or other controls that are difficult to distinguish from the endpoint itself.

Mihari places a local diagnostic proxy in front of the existing network path. It observes what the endpoint attempted, where the request progressed, and what evidence was returned. In inspection mode it terminates TLS with a session-scoped ephemeral CA so that HTTP URL paths can be observed. In tunnel mode it preserves end-to-end TLS so the two modes can be compared.

## Runtime contract

- Windows PowerShell 5.1 compatible.
- PowerShell 7 supported.
- PowerShell and Windows/.NET platform APIs only.
- No Node.js, Python, separate .NET application, native helper binary, package manager, or external PowerShell module is required at runtime.
- HTTP/1.1, CONNECT, and TLS 1.2 are the initial protocol baseline.
- TLS 1.3 interception, HTTP/3, and QUIC are not initial targets.
- Existing enterprise network controls are observed, not bypassed.

## Documentation

- [Product requirements](docs/requirements.md)
- [Target architecture](docs/architecture.md)
- [Agent implementation guidance](AGENTS.md)

## Use

Run in Windows PowerShell 5.1 or PowerShell 7. `start` stays in the foreground and writes session metadata; use another shell for the remaining commands.

```powershell
.\mihari.ps1 start -Mode Inspect -Port 8899
.\mihari.ps1 status
.\mihari.ps1 browser -Url 'https://example.com/'
.\mihari.ps1 report
.\mihari.ps1 stop
.\mihari.ps1 cleanup
```

For an HTTPS control run, start a separate session with `-Mode Tunnel`. To compare evidence from two runs, pass the prior session's `events.jsonl` path to `report -CompareEventsPath`. `-UpstreamProxy http://proxy.example:8080` selects an explicit upstream proxy; without an override, Mihari uses the platform resolver and reports a configured route it cannot honor. `-OutputRoot` selects a user-owned sessions directory. The default is `%LOCALAPPDATA%\Mihari\sessions`.

Inspect trusts a unique public session CA in `CurrentUser\Root` while running. `stop` removes that root and generates `report.json` and `report.txt` beside `events.jsonl`. The CA key and exact-host leaf certificates stay in process memory. `cleanup` removes only stale roots with matching Mihari session metadata.

The initial runtime handles HTTP/1.1, CONNECT, and TLS 1.2 inspection. HTTP/2, HTTP/3/QUIC, and TLS 1.3 interception are outside its protocol baseline and are reported as unsupported when Mihari can identify them. Edge launch uses a temporary profile and a process-specific loopback proxy; if Edge is unavailable, the command reports the endpoint for manual configuration.

Run the repository-owned tests with `test\run.ps1`. GitHub Actions runs them under Windows PowerShell 5.1 and PowerShell 7.
