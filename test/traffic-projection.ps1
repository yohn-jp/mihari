$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path $PSScriptRoot -Parent
. (Join-Path $repoRoot 'src/TrafficProjection.ps1')
. (Join-Path $PSScriptRoot 'TestSupport.ps1')

function New-MihariTrafficProjectionTestEvent {
    param(
        [string]$SessionId,
        [string]$EventId,
        [long]$Sequence,
        [string]$ConnectionId,
        [AllowNull()][string]$RequestId,
        [string]$Stage,
        [string]$Outcome,
        [hashtable]$Data,
        [string]$Source = 'proxy',
        [int]$SchemaVersion = 2
    )
    $event = [ordered]@{
        schemaVersion = $SchemaVersion
        timestamp = '2026-09-27T10:00:00.000Z'
        eventId = $EventId
        sessionId = $SessionId
        connectionId = $ConnectionId
        requestId = $RequestId
        mode = 'Inspect'
        stage = $Stage
        outcome = $Outcome
        elapsedMs = 12
        data = $Data
    }
    if ($SchemaVersion -ge 2) {
        $event.sequence = $Sequence
        $event.source = $Source
        $event.coverage = 'observed'
    }
    return [pscustomobject]$event
}

function Write-MihariTrafficProjectionFixtureLine {
    param([string]$Path, [object]$Event)
    $line = ConvertTo-Json -InputObject $Event -Depth 8 -Compress
    [System.IO.File]::AppendAllText($Path, $line + [Environment]::NewLine, [System.Text.UTF8Encoding]::new($false))
}

function Assert-MihariTrafficProjection {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw ('ASSERTION FAILED: ' + $Message) }
}

$temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('mihari-traffic-projection-' + [Guid]::NewGuid().ToString('N'))
$null = [System.IO.Directory]::CreateDirectory($temporaryRoot)
$sessionId = [Guid]::NewGuid().ToString('N')
$eventsPath = Join-Path $temporaryRoot 'events.jsonl'
$indexPath = Join-Path $temporaryRoot 'traffic-index'
try {
    [System.IO.File]::WriteAllText($eventsPath, '', [System.Text.UTF8Encoding]::new($false))
    $first = New-MihariTrafficProjectionTestEvent -SessionId $sessionId -EventId 'event-1' -Sequence 1 -ConnectionId 'conn-a' -RequestId 'request-a' -Stage 'http.request' -Outcome 'success' -Data @{
        host = 'example.test'; scheme = 'https'; port = 443; path = '/items?id=secret-sentinel'; method = 'GET'; protocol = 'http/1.1'
    }
    $second = New-MihariTrafficProjectionTestEvent -SessionId $sessionId -EventId 'event-2' -Sequence 2 -ConnectionId 'conn-b' -RequestId 'request-b' -Stage 'http.request' -Outcome 'success' -Data @{
        host = 'example.test'; scheme = 'https'; port = 443; path = '/items?id=secret-sentinel'; method = 'GET'; protocol = 'http/1.1'
    }
    $failed = New-MihariTrafficProjectionTestEvent -SessionId $sessionId -EventId 'event-3' -Sequence 3 -ConnectionId 'conn-a' -RequestId 'request-a' -Stage 'upstream.proxy.connect' -Outcome 'rejected' -Data @{
        host = 'example.test'; scheme = 'https'; port = 443; path = '/items?id=secret-sentinel'; method = 'GET'; proxyStatus = 407; protocol = 'http/1.1'
        arbitraryHeader = 'secret-sentinel'; authorization = 'secret-sentinel'
    }
    $opaque = New-MihariTrafficProjectionTestEvent -SessionId $sessionId -EventId 'event-4' -Sequence 4 -ConnectionId 'opaque-1' -RequestId $null -Stage 'tunnel.relay' -Outcome 'success' -Data @{
        host = 'socket.test'; port = 443; bytesClientToUpstream = 64
    }
    $legacy = New-MihariTrafficProjectionTestEvent -SessionId $sessionId -EventId 'legacy-1' -Sequence 0 -ConnectionId 'conn-legacy' -RequestId 'legacy-request' -Stage 'http.request' -Outcome 'success' -Data @{
        host = 'legacy.test'; path = '/legacy'; method = 'POST'
    } -SchemaVersion 1
    foreach ($event in @($first, $second, $failed, $opaque, $legacy)) { Write-MihariTrafficProjectionFixtureLine -Path $eventsPath -Event $event }
    [System.IO.File]::AppendAllText($eventsPath, 'not-json' + [Environment]::NewLine, [System.Text.UTF8Encoding]::new($false))

    $partial = New-MihariTrafficProjectionTestEvent -SessionId $sessionId -EventId 'event-partial' -Sequence 6 -ConnectionId 'conn-partial' -RequestId 'request-partial' -Stage 'http.request' -Outcome 'success' -Data @{
        host = 'partial.test'; path = '/ready'; method = 'GET'
    }
    $partialJson = ConvertTo-Json -InputObject $partial -Depth 8 -Compress
    $splitAt = [int][Math]::Floor($partialJson.Length / 2)
    [System.IO.File]::AppendAllText($eventsPath, $partialJson.Substring(0, $splitAt), [System.Text.UTF8Encoding]::new($false))

    $store = New-MihariTrafficProjectionStore -SessionId $sessionId -EventsPath $eventsPath -IndexDirectory $indexPath -HotLimit 2
    Assert-MihariTrafficProjection ($store.Counters.MalformedLineCount -eq 1) 'malformed complete lines are counted'
    Assert-MihariTrafficProjection ($store.Counters.IncompleteFinalLineCount -eq 1) 'an incomplete final line is reported once'
    Assert-MihariTrafficProjection (-not $store.Backlog) 'an incomplete line is pending input, not an indexed event backlog'

    $all = Get-MihariTrafficRequests -Store $store -Filters @{} -Limit 50
    Assert-MihariTrafficProjection ($all.scopeTotal -eq 4) 'distinct requests and opaque connections are projected'
    Assert-MihariTrafficProjection ($all.items.Count -eq 4) 'the complete indexed scope is returned'
    $sameUrl = @($all.items | Where-Object { $_.host -eq 'example.test' -and $_.path -like '/items*' })
    Assert-MihariTrafficProjection ($sameUrl.Count -eq 2) 'concurrent identical URLs keep distinct request IDs'
    $opaqueRow = @($all.items | Where-Object { $_.connectionOnly -and $_.connectionId -eq 'opaque-1' })
    Assert-MihariTrafficProjection ($opaqueRow.Count -eq 1) 'a connection without an HTTP request gets a connection-only row'
    $legacyRow = @($all.items | Where-Object { $_.requestId -eq 'legacy-request' })[0]
    Assert-MihariTrafficProjection ($legacyRow.source -eq 'unknown' -and $null -eq $legacyRow.firstSequence) 'legacy source and sequence stay unknown'
    Assert-MihariTrafficProjection ($all.coverage.hotRequestCount -le 2) 'the in-memory hot request set is bounded'
    Assert-MihariTrafficProjection ([System.IO.Directory]::GetFiles((Join-Path $indexPath 'requests'), '*.jsonl').Length -eq 4) 'full request history is backed by per-request disk timelines'

    $filtered = Get-MihariTrafficRequests -Store $store -Filters @{ host = 'example.test'; pathPrefix = '/items'; method = 'get'; status = '407'; source = 'proxy'; protocol = 'http/1.1'; stage = 'upstream.proxy.connect'; preset = '407' } -Limit 1
    Assert-MihariTrafficProjection ($filtered.scopeTotal -eq 1 -and $filtered.items.Count -eq 1) 'all filters are evaluated server-side before paging'
    $detail = Get-MihariTrafficRequestDetail -Store $store -Key ($sessionId + ':request-a')
    Assert-MihariTrafficProjection ($detail.events.Count -eq 2 -and $detail.events[1].eventId -eq 'event-3') 'details return the matching safe event chain'
    Assert-MihariTrafficProjection ($detail.evidence.Count -eq 2 -and $detail.evidence[1].sessionId -eq $sessionId -and $detail.evidence[1].eventId -eq 'event-3') 'detail evidence references include session and event IDs'
    $detailJson = ConvertTo-Json -InputObject $detail -Depth 12 -Compress
    Assert-MihariTrafficProjection ($detailJson -notmatch 'secret-sentinel') 'query values and arbitrary credential fields are absent from projected evidence'
    Assert-MihariTrafficProjection ($detail.request.path -eq '/items?id=[REDACTED]') 'URL query values are redacted in request rows'

    $prefix = $partialJson.Substring($splitAt)
    [System.IO.File]::AppendAllText($eventsPath, $prefix + [Environment]::NewLine, [System.Text.UTF8Encoding]::new($false))
    $null = Update-MihariTrafficProjectionStore -Store $store
    Assert-MihariTrafficProjection ($store.Counters.RecoveredPartialLineCount -eq 1) 'the final partial line is recovered when completed'
    $partialRows = Get-MihariTrafficRequests -Store $store -Filters @{ host = 'partial.test' } -Limit 10
    Assert-MihariTrafficProjection ($partialRows.scopeTotal -eq 1) 'a recovered line becomes a request'

    $cursorPage1 = Get-MihariTrafficRequests -Store $store -Filters @{} -Limit 2
    Assert-MihariTrafficProjection ($null -ne $cursorPage1.nextCursor) 'large result sets return a cursor'
    $extra = New-MihariTrafficProjectionTestEvent -SessionId $sessionId -EventId 'event-new' -Sequence 7 -ConnectionId 'conn-new' -RequestId 'request-new' -Stage 'http.request' -Outcome 'success' -Data @{
        host = 'new.test'; path = '/new'; method = 'GET'
    }
    Write-MihariTrafficProjectionFixtureLine -Path $eventsPath -Event $extra
    $null = Update-MihariTrafficProjectionStore -Store $store
    $cursorPage2 = Get-MihariTrafficRequests -Store $store -Filters @{} -Cursor $cursorPage1.nextCursor -Limit 2
    $ids = @()
    $ids += @($cursorPage1.items | ForEach-Object { $_.key })
    $ids += @($cursorPage2.items | ForEach-Object { $_.key })
    Assert-MihariTrafficProjection (@($ids | Select-Object -Unique).Count -eq $ids.Count) 'cursor paging has no repeated request rows'
    Assert-MihariTrafficProjection ($ids -notcontains ($sessionId + ':request-new')) 'a cursor remains on its captured history revision'

    $cursor = $cursorPage1.nextCursor
    $replacement = New-MihariTrafficProjectionTestEvent -SessionId $sessionId -EventId 'event-rotated' -Sequence 1 -ConnectionId 'conn-r' -RequestId 'request-rotated' -Stage 'http.request' -Outcome 'success' -Data @{
        host = 'rotated.test'; path = '/'; method = 'GET'
    }
    [System.IO.File]::WriteAllText($eventsPath, (ConvertTo-Json -InputObject $replacement -Depth 8 -Compress) + [Environment]::NewLine, [System.Text.UTF8Encoding]::new($false))
    $null = Update-MihariTrafficProjectionStore -Store $store
    Assert-MihariTrafficProjection ($store.Counters.RotationCount -ge 1) 'replacement of the canonical file advances the generation'
    $cursorInvalidated = $false
    try { $null = Get-MihariTrafficRequests -Store $store -Filters @{} -Cursor $cursor -Limit 2 }
    catch { $cursorInvalidated = ([string]$_.Exception.Data['mihariCode'] -eq 'cursor_invalidated') }
    Assert-MihariTrafficProjection $cursorInvalidated 'rotation explicitly invalidates cursors from the prior generation'
    Write-Host 'PASS traffic projection: incremental replay, safe request rows, filters, cursors, details, partial lines, rotation'
}
finally {
    if ([System.IO.Directory]::Exists($temporaryRoot)) { [System.IO.Directory]::Delete($temporaryRoot, $true) }
}
