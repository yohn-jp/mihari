param()

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path $PSScriptRoot -Parent
. (Join-Path $repoRoot 'src/Diagnosis.ps1')
. (Join-Path $repoRoot 'src/TrafficProjection.ps1')
. (Join-Path $repoRoot 'src/FindingProjection.ps1')
. (Join-Path $PSScriptRoot 'TestSupport.ps1')

function New-MihariFindingProjectionTestEvent {
    param([string]$SessionId, [int]$Sequence, [string]$HostName, [int]$StatusCode)
    $stage = 'upstream.proxy.connect'
    $outcome = 'rejected'
    return [pscustomobject][ordered]@{
        schemaVersion = 2
        sequence = $Sequence
        timestamp = ([DateTimeOffset]::UtcNow.AddMilliseconds($Sequence)).ToString('o', [Globalization.CultureInfo]::InvariantCulture)
        eventId = ('projection-event-{0:D5}' -f $Sequence)
        sessionId = $SessionId
        connectionId = ('projection-connection-{0:D5}' -f $Sequence)
        requestId = ('projection-request-{0:D5}' -f $Sequence)
        mode = 'Tunnel'
        stage = $stage
        outcome = $outcome
        elapsedMs = 13
        source = 'proxy'
        coverage = 'observed'
        data = [pscustomobject][ordered]@{
            routeKind = 'ExplicitProxy'
            host = $HostName
            port = 443
            method = 'POST'
            path = '/upload?token=projection-secret'
            proxyStatus = $StatusCode
        }
    }
}

function Write-MihariFindingProjectionTestEvent {
    param([string]$Path, [object]$Event)
    $line = ConvertTo-Json -InputObject $Event -Depth 8 -Compress
    [System.IO.File]::AppendAllText($Path, $line + [Environment]::NewLine, [System.Text.UTF8Encoding]::new($false))
}

$temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('mihari-finding-projection-' + [Guid]::NewGuid().ToString('N'))
[void][System.IO.Directory]::CreateDirectory($temporaryRoot)
$sessionId = [Guid]::NewGuid().ToString('N')
$eventsPath = Join-Path $temporaryRoot 'events.jsonl'
$indexPath = Join-Path $temporaryRoot 'index'
$snapshotPath = Join-Path $temporaryRoot 'findings.snapshot.json'
try {
    [System.IO.File]::WriteAllText($eventsPath, '', [System.Text.UTF8Encoding]::new($false))
    for ($sequence = 1; $sequence -le 1150; $sequence++) {
        Write-MihariFindingProjectionTestEvent -Path $eventsPath -Event (New-MihariFindingProjectionTestEvent -SessionId $sessionId -Sequence $sequence -HostName 'blocked.test' -StatusCode 407)
    }
    Write-MihariFindingProjectionTestEvent -Path $eventsPath -Event (New-MihariFindingProjectionTestEvent -SessionId $sessionId -Sequence 1151 -HostName 'denied.test' -StatusCode 403)

    $store = New-MihariTrafficProjectionStore -SessionId $sessionId -EventsPath $eventsPath -IndexDirectory $indexPath -HotLimit 2
    while ($store.Backlog) { $null = Update-MihariTrafficProjectionStore -Store $store -MaximumEventsPerPoll 5000 }

    $firstPage = Get-MihariPersistentFindings -SessionId $sessionId -ProjectionStore $store -SnapshotPath $snapshotPath -Limit 1
    Assert-MihariTest -Condition ($firstPage.scopeTotal -eq 2 -and $firstPage.items.Count -eq 1 -and $firstPage.counts.sessionTotal -eq 2) -Message 'Persistent findings must aggregate indexed event history independently of the two-record hot window.'
    Assert-MihariTest -Condition ($null -ne $firstPage.nextCursor -and -not $firstPage.projectionPending -and $firstPage.coverage -eq 'observed') -Message 'A fully indexed history returns observed coverage and a stable findings cursor.'
    Assert-MihariTest -Condition (($firstPage.items[0].findingId -match '^finding-[0-9a-f]{32}$') -and $firstPage.items[0].count -in @(1, 1150)) -Message 'The first page contains a stable grouped finding.'

    $secondPage = Get-MihariPersistentFindings -SessionId $sessionId -ProjectionStore $store -SnapshotPath $snapshotPath -Limit 1 -Cursor $firstPage.nextCursor
    Assert-MihariTest -Condition ($secondPage.items.Count -eq 1 -and $secondPage.items[0].findingId -ne $firstPage.items[0].findingId -and $secondPage.revision -eq $firstPage.revision) -Message 'Findings pagination has no repeat and stays on its captured revision.'

    $allFindings = Get-MihariPersistentFindings -SessionId $sessionId -ProjectionStore $store -SnapshotPath $snapshotPath -Limit 10
    $grouped407 = @($allFindings.items | Where-Object { $_.code -eq 'upstream_proxy_auth_required' }) | Select-Object -First 1
    Assert-MihariTest -Condition ($grouped407.count -eq 1150 -and $grouped407.evidenceRefs.Count -eq 1150) -Message 'Incremental byte-window replay retains every finding reference beyond the UI hot window.'
    $savedJson = [System.IO.File]::ReadAllText($snapshotPath, [System.Text.Encoding]::UTF8)
    Assert-MihariTest -Condition (-not $savedJson.Contains('projection-secret') -and [System.IO.Directory]::GetFiles($temporaryRoot, 'findings.snapshot.json.tmp.*').Count -eq 0) -Message 'The atomic snapshot keeps redacted evidence and leaves no temporary file.'

    $staleCursor = $firstPage.nextCursor
    Write-MihariFindingProjectionTestEvent -Path $eventsPath -Event (New-MihariFindingProjectionTestEvent -SessionId $sessionId -Sequence 1152 -HostName 'blocked.test' -StatusCode 407)
    $null = Update-MihariTrafficProjectionStore -Store $store -MaximumEventsPerPoll 5000
    $cursorInvalidated = $false
    try { $null = Get-MihariPersistentFindings -SessionId $sessionId -ProjectionStore $store -SnapshotPath $snapshotPath -Limit 1 -Cursor $staleCursor }
    catch { $cursorInvalidated = ([string]$_.Exception.Data['mihariCode'] -eq 'cursor_invalidated') }
    Assert-MihariTest -Condition $cursorInvalidated -Message 'A findings cursor is invalidated when the underlying snapshot revision advances.'
    $afterAppend = Get-MihariPersistentFindings -SessionId $sessionId -ProjectionStore $store -SnapshotPath $snapshotPath -Limit 10
    $groupedAfterAppend = @($afterAppend.items | Where-Object { $_.code -eq 'upstream_proxy_auth_required' }) | Select-Object -First 1
    Assert-MihariTest -Condition ($groupedAfterAppend.count -eq 1151 -and $groupedAfterAppend.resolutionState -eq 'open') -Message 'A new indexed failure advances the existing finding without resolving it.'

    $replacement = New-MihariFindingProjectionTestEvent -SessionId $sessionId -Sequence 1153 -HostName 'after-rotation.test' -StatusCode 407
    [System.IO.File]::WriteAllText($eventsPath, (ConvertTo-Json -InputObject $replacement -Depth 8 -Compress) + [Environment]::NewLine, [System.Text.UTF8Encoding]::new($false))
    $null = Update-MihariTrafficProjectionStore -Store $store -MaximumEventsPerPoll 5000
    $rotationWindow = Get-MihariTrafficProjectionEvents -Store $store -AfterOffset 0 -ExpectedFileGeneration $store.GenerationId -Limit 20
    Assert-MihariTest -Condition ($rotationWindow.events.Count -eq 1 -and [string]$rotationWindow.events[0].generationId -eq [string]$store.GenerationId) -Message 'Byte-offset replay skips stale index rows from earlier file generations.'
    $afterRotation = Get-MihariPersistentFindings -SessionId $sessionId -ProjectionStore $store -SnapshotPath $snapshotPath -Limit 20
    $oldFinding = @($afterRotation.items | Where-Object { $_.findingId -eq $groupedAfterAppend.findingId }) | Select-Object -First 1
    $rotationCheckPassed = ($afterRotation.coverage -eq 'truncated' -and $afterRotation.scopeTotal -ge 2 -and $oldFinding.evidenceAvailability -eq 'possibly_rotated' -and $oldFinding.resolutionState -eq 'open')
    if (-not $rotationCheckPassed) {
        $oldEvidenceAvailability = 'missing'
        $oldResolutionState = 'missing'
        $oldEvidenceCount = 0
        if ($null -ne $oldFinding) {
            $oldEvidenceAvailability = [string]$oldFinding.evidenceAvailability
            $oldResolutionState = [string]$oldFinding.resolutionState
            $oldEvidenceCount = @($oldFinding.evidenceRefs).Count
        }
        Write-Host ('DIAGNOSTIC rotation: coverage={0}; scopeTotal={1}; staleIndexReturned={2}; currentGeneration={3}; oldFindingAvailability={4}; oldFindingState={5}; oldFindingEvidenceCount={6}' -f $afterRotation.coverage, $afterRotation.scopeTotal, $rotationWindow.events.Count, [string]$store.GenerationId, $oldEvidenceAvailability, $oldResolutionState, $oldEvidenceCount)
    }
    Assert-MihariTest -Condition $rotationCheckPassed -Message 'Rotation restarts indexing, retains prior findings, and marks old evidence as possibly rotated.'
    $reobserved = New-MihariFindingProjectionTestEvent -SessionId $sessionId -Sequence 1154 -HostName 'blocked.test' -StatusCode 407
    $mergedAfterReobserve = @(Get-MihariSessionFindings -Events @($reobserved) -PreviousFindings @($oldFinding) | Where-Object { $_.findingId -eq $oldFinding.findingId }) | Select-Object -First 1
    Assert-MihariTest -Condition ($mergedAfterReobserve.evidenceAvailability -eq 'possibly_rotated') -Message 'Later incremental events preserve the possibly-rotated evidence status.'

    $crossSessionRejected = $false
    try { $null = Get-MihariPersistentFindings -SessionId 'other-session' -ProjectionStore $store -SnapshotPath $snapshotPath }
    catch { $crossSessionRejected = $true }
    Assert-MihariTest -Condition $crossSessionRejected -Message 'A findings snapshot cannot mix evidence from another session.'
    Write-Host 'PASS finding projection: indexed incremental replay, atomic snapshot, bounded stable paging, history retention, rotation and coverage'
}
catch {
    $phase = [string]$_.Exception.Data['failurePhase']
    $rootCause = $_.Exception
    $innerDepth = 0
    while ($null -ne $rootCause.InnerException -and $innerDepth -lt 8) {
        $rootCause = $rootCause.InnerException
        $innerDepth++
    }
    $safeMessage = [string]$rootCause.Message
    if (-not [string]::IsNullOrEmpty($temporaryRoot)) { $safeMessage = $safeMessage.Replace($temporaryRoot, '[test-root]') }
    $safeMessage = $safeMessage.Replace('projection-secret', '[redacted]')
    $safeMessage = [System.Text.RegularExpressions.Regex]::Replace($safeMessage, '[\r\n\t]+', ' ')
    if ($safeMessage.Length -gt 240) { $safeMessage = $safeMessage.Substring(0, 240) }
    Write-Host ('DIAGNOSTIC finding snapshot: phase={0}; innerType={1}; hresult=0x{2:X8}; message={3}' -f $phase, $rootCause.GetType().FullName, $rootCause.HResult, $safeMessage)
    throw
}
finally {
    if ([System.IO.Directory]::Exists($temporaryRoot)) { [System.IO.Directory]::Delete($temporaryRoot, $true) }
}
