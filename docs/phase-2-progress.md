# Phase 2 implementation ledger

Remote `main` was fetched on 2026-09-27 before work began. Development started
from `681255bf4f9b9ec900f34a7f986388911e611510` without resetting later
changes. The unrelated local `.codegraph/` directory was retained.

| Milestone / capability | Current state | Implementation and verification evidence |
| --- | --- | --- |
| M0 contracts and corrections | Implemented; final HEAD regression pending | `docs/phase-2-contracts.md`, schema-v2 facts and legacy reader, request/trial/source contracts, bounded management queries. Windows contracts and original integration jobs have passed on earlier integration HEADs; final HEAD matrix remains required. |
| M1 Traffic investigation | Integrated; end-to-end workbench gate pending | `TrafficProjection.ps1`, `FindingProjection.ps1`, `/api/v2/requests`, `/api/v2/findings`, Traffic UI, byte-offset paging, rotation and partial-line handling. Real Edge Traffic DOM test is registered in `phase2-workbench`. Run `36304869091` passed traffic projection on both runtimes. The persistent snapshot replacement defect found in run `36306558533` was corrected after that run and is under retest. |
| M2 Business dependencies | Integrated; Windows workbench gate pending | File-backed cases/trials/markers/notes, dependency projection, necessity confirmation, neutral policy comparison, distinct URL and local TLS exclusion proposals, preview/export API and UI. `test/cases-dependencies.ps1` now includes separate login and upload event chains and proposal evidence. |
| M3 Comparison and endpoint diagnosis | Integrated; Windows workbench gate pending | Controlled comparisons, TLS two-leg evidence, host exclusions, environment/capability snapshots, connected API/UI. Empty exclusion arrays are preserved as recorded conditions. The DOM trial comparison test is registered in `phase2-workbench`. |
| M4 Browser-assisted HTTP/2 | Integrated; real Edge verification pending | Owned Edge DevTools observation, cache/initiator/failure facts, profile verification, local h2 Tunnel origin, safe HAR/NetLog import. `browser-observation-edge.ps1` is registered in `phase2-workbench`; that suite has not yet reached it on the current HEAD. |
| M5 Fidelity and enterprise operation | Transport proof passed; remaining UI/integration gate pending | Bounded large transfer, early bytes, persistent HTTP/1.1, SSE/WebSocket, stop cancellation: Windows run `36304473438`, jobs `108578248437` (5.1) and `108578248494` (7). Evidence bundle/import/offline/retention API and connected UI, control protection, bilingual text, resource facts, and distribution manifest tool/docs are integrated. Real Edge Evidence DOM and final regression/soak evidence remain to be verified. |
| HTTP/2 feasibility | Measured | Run `36302954897`: jobs `108573967172` (5.1 managed ALPN absent) and `108573967158` (7.6.6 both TLS legs selected h2, trust and cleanup passed). See `docs/http2-feasibility.md`. |
| M6 native HTTP/2 Inspect | Implemented and live-proven on the tested PowerShell 7 runtime; final HEAD gate pending | Run `36306087425`, job `108582926192`: HPACK/frame tests and direct plus production CONNECT two-leg h2, two simultaneous streams, normal validation, CA cleanup passed. The job later failed in findings. PowerShell 5.1 native ALPN is unavailable on the tested .NET Framework runtime; shared frame/HPACK tests and precise startup rejection passed. Live gRPC interoperability has not been proven. |

The exact final main HEAD must pass the Windows PowerShell 5.1 and PowerShell 7
matrix, including the real Edge DOM and local origin fixtures. A passing
component test on an earlier HEAD does not close that gate. This ledger records
implementation state and measured evidence, not enterprise certification.
