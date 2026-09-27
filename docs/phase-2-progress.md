# Phase 2 implementation ledger

Base: remote `main` fetched 2026-09-27 at
`681255bf4f9b9ec900f34a7f986388911e611510`; later main changes are
preserved. The existing untracked `.codegraph/` directory is unrelated and retained.

| Milestone / capability | State | Evidence / remaining gate |
| --- | --- | --- |
| M0 contracts | Implemented, integration verification pending | `docs/phase-2-contracts.md`, `src/Observation.ps1`, `src/ManagementProjection.ps1`; schema-v2 writer/legacy reader passed Windows contracts in run `36303455415`. |
| M0 presentation corrections | Implemented, browser proof pending | `src/ManagementUi.ps1`; real Edge verification is now included in `phase2-workbench`. |
| HTTP/2 feasibility | Gate measured | `docs/http2-feasibility.md`; Windows run `36302954897` jobs `108573967172` (5.1: managed ALPN unavailable) and `108573967158` (7: h2 ALPN both legs, leaf/trust/cleanup passed). The overall run failed elsewhere. |
| M1 Traffic investigation | Integrated candidate, acceptance pending | `src/TrafficProjection.ps1`, `/api/v2/requests`, Traffic UI, real Edge fixture; persistent findings adapter and exact current-HEAD Windows result pending. |
| M2 Business dependencies | Domain implemented, integration pending | `src/Case.ps1`, `src/Dependencies.ps1`; API, UI, fixture and export round-trip pending. |
| M3 Comparison and endpoint | Domain implemented, integration pending | `src/Comparison.ps1`, `src/Environment.ps1`, `src/Tls.ps1`; controlled-trial API/UI and live proof pending. |
| M4 Browser-assisted HTTP/2 | Browser source integrated, acceptance pending | `src/BrowserObservation.ps1`; owned Edge observation and import tests queued on Windows; local h2 Tunnel trial and UI integration pending. |
| M5 Fidelity and enterprise operation | Integrated candidate, acceptance pending | `src/Http.ps1`, `src/Connection.ps1`, `src/Tls.ps1`, `src/Evidence.ps1`; live streaming, offline review, retention, bilingual UI, resource/soak proof pending. |
| M6 native HTTP/2 Inspect | Gated implementation in progress | PS7 gate positive, PS5.1 managed ALPN unavailable on tested runtime. `src/Hpack.ps1` and `src/Http2.ps1` frame unit are integrated; TLS-leg entry, live proxy fixture and Windows verification pending. |

The prior integrated run `36303455415` at `46fc9c8` passed its PowerShell 7
jobs but failed six PowerShell 5.1 jobs after worker initialization. A lazy
evidence-module load correction is in current main; run `36304008666` at
`6625388` is pending. States describe work, not acceptance. Final completion
requires the exact main HEAD to pass the required Windows PowerShell 5.1 and
PowerShell 7 matrix and the architecture's end-to-end conditions.
