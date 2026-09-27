# Phase 2 implementation ledger

Remote `main` was fetched on 2026-09-27 before work began. The Phase 2
architecture commit `681255bf4f9b9ec900f34a7f986388911e611510` and all
later remote-main changes were retained. The unrelated local `.codegraph/`
directory was retained.

| Milestone / capability | Current state | Implementation and verification evidence |
| --- | --- | --- |
| M0 contracts and corrections | Implemented; final HEAD regression pending | `docs/phase-2-contracts.md`, schema-v2 facts and legacy reader, request/trial/source contracts, bounded queries. Both `contracts` jobs passed in run `36314290993`; final HEAD matrix remains required. |
| M1 Traffic investigation | Integrated; real UI gate pending | `TrafficProjection.ps1`, `FindingProjection.ps1`, versioned request/finding API, Traffic UI, byte-offset paging, rotation and partial-line handling. Traffic and finding projection tests passed on both runtimes in run `36314290993`; real Edge Traffic DOM proof has not yet been reached by that workbench run. |
| M2 Business dependencies | Integrated; real UI gate pending | File-backed cases/trials/markers/notes, dependency projection, necessity confirmation, neutral policy comparison, distinct URL and local TLS exclusion proposals, preview/export API and UI. Login/upload and management cases tests passed on both runtimes in run `36314290993`; the later workbench import assertion stopped its DOM tests. |
| M3 Comparison and endpoint diagnosis | Integrated; real UI gate pending | Controlled comparisons, TLS two-leg evidence, host exclusions, environment/capability snapshots, connected API/UI. Findings/comparison and case tests passed on both runtimes in run `36314290993`; real DOM trial comparison remains to run on the integrated HEAD. |
| M4 Browser-assisted HTTP/2 | Backend integrated; full real Edge and import UI gate pending | Owned Edge DevTools observation, bounded target/request maps with explicit dropped counts, effective profile checks, local h2 Tunnel fixture, and safe HAR/NetLog importer/API. PS5.1 real Edge HTTP/HTTPS smoke passed in run `36314290993`; PS7 observer arming failed after launch. Workbench import test reached canonical facts and exposed a wrong NetLog event-index assertion, corrected after that run. Import UI is still being connected. |
| M5 Fidelity and enterprise operation | Transport and impact proof passed; remaining UI/integration gate pending | Bounded streaming, early bytes, persistent HTTP/1.1, SSE/WebSocket, cancellation, evidence bundle/import/offline/retention, protected actions, bilingual UI, distribution manifest. Run `36314290993` transport jobs `108605952610` (5.1) and `108605952568` (7) passed the full queue, health-under-load, slow-peer, capture loss and Overview warning probes. See `docs/phase-2-performance.md`. Real Edge Evidence DOM and final regression remain pending. |
| HTTP/2 feasibility | Measured | Run `36302954897`: jobs `108573967172` (5.1 managed ALPN absent) and `108573967158` (7.6.6 both TLS legs selected h2, trust and cleanup passed). See `docs/http2-feasibility.md`. |
| M6 native HTTP/2 Inspect | Implemented and live-proven on the tested PowerShell 7 runtime; final HEAD gate pending | Run `36314290993` PS7 workbench job `108605952594` passed HPACK/frame tests and direct plus production CONNECT two-leg h2, two simultaneous streams, normal validation and CA cleanup before the later import assertion. PS5.1 job `108605952555` passed shared parser tests and precise startup rejection because its managed ALPN API is absent. Live gRPC interoperability has not been proven. |

The exact final main HEAD must pass the Windows PowerShell 5.1 and PowerShell 7
matrix, including the real Edge DOM and local origin fixtures. A passing
component test on an earlier HEAD does not close that gate. This ledger records
implementation state and measured evidence, not enterprise certification.
