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

Run in Windows PowerShell 5.1 or PowerShell 7. Running `.\mihari.ps1` with no command shows usage. `start` stays in the foreground and prints the proxy and management UI URLs once both loopback listeners are ready. Open the UI URL in a browser to view live observations and findings, launch diagnostic Edge, and switch new CONNECT connections between Inspect and Tunnel. Use another shell for CLI commands while the session runs.

```powershell
.\mihari.ps1
.\mihari.ps1 start -Mode Inspect -Port 8899 -UiPort 0
.\mihari.ps1 status
.\mihari.ps1 browser -Url 'https://example.com/'
.\mihari.ps1 report
.\mihari.ps1 stop
.\mihari.ps1 cleanup
```

The UI toggle changes only newly accepted connections; existing connections keep their mode. To compare evidence from separate runs, pass a prior session's `events.jsonl` path to `report -CompareEventsPath`. `-UpstreamProxy http://proxy.example:8080` selects an explicit upstream proxy; without an override, Mihari uses the platform resolver captured before launching Edge and reports a configured route it cannot honor. Mihari rejects any route back to its own listener. `-Port 0` and `-UiPort 0` select free, distinct loopback ports. `-OutputRoot` selects a user-owned sessions directory. The default is `%LOCALAPPDATA%\Mihari\sessions`.

Inspect trusts a unique public session CA in `CurrentUser\Root` while running. Windows may ask you to confirm adding or removing that root. `stop` removes it and generates `report.json` and `report.txt` beside `events.jsonl`. The CA private key stays in memory. Exact-host leaf certificates are never installed in certificate stores; Windows keeps their private keys in temporary, current-user key files until cache eviction or normal stop. An abrupt process exit can leave a temporary key file. `cleanup` removes only stale roots with matching Mihari session metadata.

The initial runtime handles HTTP/1.1, CONNECT, and TLS 1.2 inspection. HTTP/2, HTTP/3/QUIC, and TLS 1.3 interception are outside its protocol baseline and are reported as unsupported when Mihari can identify them. Edge launch uses a temporary profile and a process-specific loopback proxy for HTTP and HTTPS, with unsupported browser transports disabled. If Edge is unavailable, the command reports the endpoint for manual configuration. `status` checks both listener health as well as the owner process.

Run the repository-owned tests with `test\run.ps1`. GitHub Actions runs them under Windows PowerShell 5.1 and PowerShell 7.
