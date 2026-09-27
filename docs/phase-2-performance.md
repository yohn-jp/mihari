# Phase 2 observer impact and limits

The repository-owned `test/phase2-observer-impact.ps1` is the focused local
probe. It must run on both Windows PowerShell 5.1 and PowerShell 7. Results
belong to the exact CI HEAD and should be copied here after integration. No
public endpoint or installed package is used.

## Probe conditions

| Condition | Value |
| --- | --- |
| Proxy mode/profile | Tunnel / compatibility |
| Proxy workers | 2 |
| Accepted-client queue | 4 sockets; FIFO, bound is twice the worker count |
| Concurrent fixture traffic | 2 open CONNECT relays and 4 queued CONNECT requests |
| Soak interval | At least one 5-second `observer.resource` sample at full occupancy |
| Health | Loopback `/api/health` during full proxy occupancy and queue |
| Measurements | Worker occupancy, accepted queue length/peak, saturation intervals, process working set/CPU, evidence bytes, writer wait, health response |
| Evidence quota probes | 4 KiB test quota and an injected disposed writer stream in separate Tunnel sessions |
| Slow peer | 8 MiB file source, 4 KiB socket buffers, non-reading peer, 500 ms write timeout |
| Default evidence quota | 512 MiB per session JSONL; bytes checked before each complete append |

The fixture prints a `MEASURE phase2-impact` line with values from the
canonical resource event. It asserts the finite bounds, a saturated queue
fact, live management response, metadata persistence, and a requested stop
on quota or writer failure. The slow-peer probe requires a bounded write
timeout and prints its elapsed time and exception type. The >32 MiB transfer and concurrent SSE/WebSocket
proof remain in `test/phase2-live-streaming.ps1`. `forwardWriteMs` is measured
in transport relay facts; it is Mihari forwarding time, not origin latency.
Stopping the full-queue fixture requires one cancellation fact per queued
socket; active CONNECT relay cancellation is covered by the transport suite.

## Coverage and limits

Mihari measures the count of sockets accepted into its own bounded queue.
`listener.capacity` records observed saturation intervals; this count is
not a count of dropped requests. The operating-system TCP backlog is also
finite, but .NET `TcpListener` exposes only `Pending()` and does not expose
its exact occupancy or rejected SYN count. Those values remain unavailable.

On a JSONL quota or writer failure, capture is marked incomplete in session
metadata with a stable reason and time before Mihari requests listener stop.
The state remains in metadata after normal cleanup. No further traffic is
intentionally accepted once canonical facts cannot be appended. A physically
full or failing volume can also prevent metadata persistence; Mihari attempts
it and warns, but cannot claim a durable record when storage itself is
unwritable. A retained partial final JSONL line is treated as incomplete
evidence, never as a complete fact.

## Windows results

Pending integration of the focused probe on the final implementation HEAD.
Record both runtime versions, exact CI run/job, measured `MEASURE` lines,
and any failure or unavailable field here. Do not infer throughput or memory
ceilings from this short controlled soak.
