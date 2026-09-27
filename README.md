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

The repository is at initial implementation stage.
