# Phase 2 shared contracts (M0)

This file fixes the producer/consumer boundary for the Phase 2 workstreams. JSONL
facts remain canonical. A schema-v1 event remains readable without alteration;
absent Phase 2 fields mean `unknown`, never success or zero duration.

## Fact envelope and identity

New facts use `schemaVersion: 2` and retain the v1 fields `timestamp`,
`eventId`, `sessionId`, `connectionId`, optional `requestId`, `mode`, `stage`,
`outcome`, `elapsedMs`, and safe `data`. Add `sequence` (positive, strictly
increasing within one session writer), `source` (`proxy`, `browser`, `windows`,
`operator`, `import`), and `coverage` (`observed`, `unknown`, `unsupported`,
`permission_denied`, `truncated`, `lost`). Optional fields are `caseId`,
`trialId`, `configurationRevision`, `transportLeg` (`client`, `upstream`,
`end_to_end`), `upstreamConnectionId`, `streamId`, `sourceIdentity`,
`sourceVersion`, `monotonicTicks`, and `clockId`. Optional fields are omitted
when unknown. `eventId` is globally unique; evidence references contain both
`sessionId` and `eventId`. A stream key also contains leg and connection ID.

Only `Write-MihariEvent` allocates canonical sequence numbers. The entire
allocation, serialization, write, and flush happen under its writer lock.
Producers pass typed, allowlisted fields. They never persist bodies, arbitrary
headers, credentials, debugger controls, or unredacted query values. Imported
records retain source attribution and do not impersonate proxy observations.

## Domain records

`requestKey = sessionId + ':' + requestId` for HTTP attempts. For a
connection without an HTTP request, use `sessionId + ':connection:' +
connectionId`; browser-only attempts use their owned browser target, scoped
request ID, and redirect occurrence. URL/time similarity creates only a
`heuristic` edge with reasons and possible ambiguity. Direct shared IDs create
`direct` edges. Never merge concurrent identical URLs on similarity alone.

Cases have `caseId`, title, notes, and session/trial references. Trials have
`trialId`, `caseId`, `sessionId`, start/end markers, immutable profile and
configuration revision, environment reference, and operator business outcome.
Markers have `markerId`, `trialId`, timestamp, and escaped label/note. These
operator records live in separate versioned metadata/journals, not JSONL fact
rewrites. A finding has stable `findingId`, `ruleVersion`, scope, classification,
evidence references, first/last observed, count, interpretation, limitations,
and resolution state. Only positive resolution evidence sets `resolved`.

## Bounded management queries

Existing routes keep their envelopes. New read routes are `/api/v2/requests`,
`/api/v2/requests/{key}`, `/api/v2/cases`, `/api/v2/trials`,
`/api/v2/dependencies`, `/api/v2/proposals`, `/api/v2/comparisons`,
`/api/v2/environment`, `/api/v2/capabilities`, and `/api/v2/evidence`.
Route handlers delegate to domain functions, with at most 200 list items and
bounded JSON responses. Lists return `items`, `nextCursor`, `revision`,
`ordering`, `scopeTotal`, `coverage`, and `freshnessUtc`. A cursor identifies a
stable file generation and sequence/offset; rotation invalidates it explicitly.
Details return a request record plus safe canonical evidence references/events.
Filters run before paging over the declared session/trial scope.

State changes use POST on the corresponding resource route, with a
session-scoped authorization/CSRF token supplied in a header, an exact loopback
Host/Origin check, bounded JSON body, and explicit accepted/completed/failed
result. The token is never a URL parameter or evidence field. UI and CLI call
the same domain operations. Export/import/offline operations expose bounded
progress and do not block proxy heartbeats.

## Ownership seam

The integration owner controls `Observation.ps1`, `Management.ps1`,
`Session.ps1`, `mihari.ps1`, this contract, and final integration. Independent
workstreams own focused new files and their tests. `ManagementUi.ps1` has one
UI owner. Changes to the shared envelope or routes require coordination with
the integration owner before implementation.
