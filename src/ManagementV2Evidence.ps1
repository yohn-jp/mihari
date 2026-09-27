# Versioned evidence-management routes. Canonical facts come only from the
# TrafficProjection reader; portable bundle construction stays in Evidence.ps1.

function Get-MihariManagementV2EvidenceRoot {
    param([Parameter(Mandatory = $true)]$Session)

    if ([string]::IsNullOrWhiteSpace([string]$Session.OutputRoot)) { throw 'output_root_unavailable' }
    $root = [System.IO.Path]::GetFullPath([string]$Session.OutputRoot)
    Assert-MihariEvidencePathHasNoReparsePoint -Path $root
    return [System.IO.Path]::Combine($root, 'evidence')
}

function Get-MihariManagementV2EvidenceImportRoot {
    param([Parameter(Mandatory = $true)]$Session)
    return [System.IO.Path]::Combine((Get-MihariManagementV2EvidenceRoot -Session $Session), 'imports')
}

function Test-MihariManagementV2EvidencePathWithinRoot {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Root
    )
    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $fullRoot = [System.IO.Path]::GetFullPath($Root).TrimEnd([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
    $prefix = $fullRoot + [System.IO.Path]::DirectorySeparatorChar
    return $fullPath.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)
}

function ConvertTo-MihariManagementV2EvidenceShareProfile {
    param([AllowNull()][object]$Value)

    $profile = [ordered]@{ maskHosts = $true; maskUsernames = $true; maskPaths = $true; maskIdentifiers = $true }
    if ($null -eq $Value) { return [pscustomobject]$profile }
    $properties = @()
    if ($Value -is [System.Collections.IDictionary]) { $properties = @($Value.Keys | ForEach-Object { [string]$_ }) }
    else { $properties = @($Value.PSObject.Properties | ForEach-Object { [string]$_.Name }) }
    foreach ($name in $properties) {
        if ($name -notin @('maskHosts', 'maskUsernames', 'maskPaths', 'maskIdentifiers')) { throw 'invalid_share_profile' }
        $item = Get-MihariEvidenceValue -InputObject $Value -Name $name
        if ($item -isnot [bool]) { throw 'invalid_share_profile' }
        $profile[$name] = [bool]$item
    }
    return [pscustomobject]$profile
}

function Get-MihariManagementV2EvidenceQuery {
    param([AllowNull()][string]$Query, [string[]]$AllowedNames = @())

    $values = [ordered]@{}
    if ([string]::IsNullOrEmpty($Query)) { return $values }
    if ($Query.Length -gt 4096) { throw 'invalid_query' }
    foreach ($part in ($Query -split '&')) {
        if ([string]::IsNullOrEmpty($part)) { continue }
        $separator = $part.IndexOf('=')
        if ($separator -lt 1) { throw 'invalid_query' }
        try {
            $name = [Uri]::UnescapeDataString($part.Substring(0, $separator).Replace('+', ' '))
            $value = [Uri]::UnescapeDataString($part.Substring($separator + 1).Replace('+', ' '))
        }
        catch { throw 'invalid_query' }
        if ($name -notmatch '^[A-Za-z][A-Za-z0-9]{0,39}$' -or $value.Length -gt 2048 -or $values.Contains($name)) { throw 'invalid_query' }
        if ($AllowedNames.Count -gt 0 -and $name -notin $AllowedNames) { throw 'invalid_query' }
        $values[$name] = $value
    }
    return $values
}

function Set-MihariManagementV2EvidenceJobState {
    param(
        [Parameter(Mandatory = $true)]$Session,
        [Parameter(Mandatory = $true)][string]$JobId,
        [Parameter(Mandatory = $true)][string]$State,
        [Parameter(Mandatory = $true)][string]$Phase,
        [int]$CompletedStages = 0,
        [int]$TotalStages = 1,
        [AllowNull()][object]$Result,
        [AllowNull()][string]$ErrorCode
    )

    [System.Threading.Monitor]::Enter($Session.StateLock)
    try {
        if ($null -eq $Session.EvidenceJobs -or -not $Session.EvidenceJobs.ContainsKey($JobId)) { return }
        $job = $Session.EvidenceJobs[$JobId]
        $job.state = $State
        $job.phase = $Phase
        $job.progress = [pscustomobject]@{ completedStages = [Math]::Max(0, $CompletedStages); totalStages = [Math]::Max(1, $TotalStages) }
        if ($null -ne $Result) { $job.result = $Result }
        if (-not [string]::IsNullOrWhiteSpace($ErrorCode)) { $job.errorCode = $ErrorCode }
        if ($State -in @('completed', 'failed', 'cancelled')) {
            $job.completedAtUtc = [DateTime]::UtcNow.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
        }
    }
    finally { [System.Threading.Monitor]::Exit($Session.StateLock) }
}

function Get-MihariManagementV2EvidenceSessionEventPath {
    param(
        [Parameter(Mandatory = $true)]$Session,
        [Parameter(Mandatory = $true)][string]$SessionId
    )

    if ($SessionId -notmatch '^[0-9a-fA-F]{32}$') { return $null }
    $root = [System.IO.Path]::GetFullPath([string]$Session.OutputRoot)
    $directory = [System.IO.Path]::Combine($root, $SessionId)
    if (-not [System.IO.Directory]::Exists($directory)) { return $null }
    Assert-MihariEvidencePathHasNoReparsePoint -Path $directory
    $metadataPath = [System.IO.Path]::Combine($directory, 'session.json')
    $eventsPath = [System.IO.Path]::Combine($directory, 'events.jsonl')
    Assert-MihariEvidencePathHasNoReparsePoint -Path $metadataPath
    Assert-MihariEvidencePathHasNoReparsePoint -Path $eventsPath
    if (-not [System.IO.File]::Exists($metadataPath) -or -not [System.IO.File]::Exists($eventsPath)) { return $null }
    $metadataInfo = New-Object System.IO.FileInfo($metadataPath)
    if ($metadataInfo.Length -gt 1048576) { return $null }
    $metadata = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($metadataPath, [System.Text.Encoding]::UTF8)) -ErrorAction Stop
    if (-not [string]::Equals([string]$metadata.sessionId, $SessionId, [StringComparison]::OrdinalIgnoreCase)) { return $null }
    return $eventsPath
}

function Get-MihariManagementV2EvidenceEvents {
    param(
        [Parameter(Mandatory = $true)]$Session,
        [Parameter(Mandatory = $true)][string[]]$SessionIds,
        [Parameter(Mandatory = $true)][string]$JobId
    )

    $events = New-Object 'System.Collections.Generic.List[object]'
    $sessionCoverage = New-Object 'System.Collections.Generic.List[object]'
    $missingSessions = New-Object 'System.Collections.Generic.List[string]'
    $totalSourceBytes = [long]0
    $maximumSourceBytes = [long]268435456
    $maximumEvents = 100000
    $temporaryIndexes = New-Object 'System.Collections.Generic.List[string]'
    $completed = 1
    $total = [Math]::Max(2, $SessionIds.Count + 1)
    try {
        foreach ($sessionId in $SessionIds) {
            if ($events.Count -ge $maximumEvents) { throw 'case_event_limit_exceeded' }
            $eventPath = Get-MihariManagementV2EvidenceSessionEventPath -Session $Session -SessionId $sessionId
            if ($null -eq $eventPath) {
                $missingSessions.Add($sessionId)
                $sessionCoverage.Add([pscustomobject]@{ sessionId = $sessionId; coverage = 'unknown'; reason = 'canonical_log_unavailable' })
                $completed++
                Set-MihariManagementV2EvidenceJobState -Session $Session -JobId $JobId -State 'running' -Phase 'reading_canonical_events' -CompletedStages $completed -TotalStages $total
                continue
            }
            $eventInfo = New-Object System.IO.FileInfo($eventPath)
            $totalSourceBytes += [long]$eventInfo.Length
            if ($totalSourceBytes -gt $maximumSourceBytes) { throw 'case_event_byte_limit_exceeded' }
            $temporaryIndex = [System.IO.Path]::Combine([string]$Session.OutputDirectory, '.evidence-projection-' + [Guid]::NewGuid().ToString('N'))
            $temporaryIndexes.Add($temporaryIndex)
            $store = New-MihariTrafficProjectionStore -SessionId $sessionId -EventsPath $eventPath -IndexDirectory $temporaryIndex -HotLimit 1
            $projectionCoverage = [pscustomobject]@{
                malformedLineCount = [long]$store.Counters.MalformedLineCount
                incompleteFinalLineCount = [long]$store.Counters.IncompleteFinalLineCount
                recoveredPartialLineCount = [long]$store.Counters.RecoveredPartialLineCount
                rotationCount = [long]$store.Counters.RotationCount
                oversizeLineCount = [long]$store.Counters.OversizeLineCount
                lostPartialLineCount = [long]$store.Counters.LostPartialLineCount
                sequenceViolationCount = [long]$store.Counters.SequenceViolationCount
                unprojectableLineCount = [long]$store.Counters.UnprojectableLineCount
                generation = [int]$store.Generation
                observedEvents = [long]$store.Ordinal
            }
            $coverageName = 'observed'
            if ([long]$projectionCoverage.malformedLineCount -gt 0 -or [long]$projectionCoverage.unprojectableLineCount -gt 0 -or
                [long]$projectionCoverage.incompleteFinalLineCount -gt 0 -or [long]$projectionCoverage.lostPartialLineCount -gt 0 -or
                [long]$projectionCoverage.oversizeLineCount -gt 0) { $coverageName = 'incomplete' }
            $sessionCoverage.Add([pscustomobject]@{ sessionId = $sessionId; coverage = $coverageName; projection = $projectionCoverage })
            $after = [long]0
            do {
                $page = Get-MihariTrafficProjectionEvents -Store $store -AfterOrdinal $after -Limit 20000
                foreach ($row in $page.events) {
                    if ($events.Count -ge $maximumEvents) { throw 'case_event_limit_exceeded' }
                    $events.Add($row.event)
                }
                $after = [long]$page.nextOrdinal
            } while ($page.hasMore)
            $completed++
            Set-MihariManagementV2EvidenceJobState -Session $Session -JobId $JobId -State 'running' -Phase 'reading_canonical_events' -CompletedStages $completed -TotalStages $total
        }
        return [pscustomobject]@{
            Events = @($events.ToArray())
            CaptureCoverage = [pscustomobject]@{
                source = 'canonical_traffic_projection'
                coverage = $(if ($missingSessions.Count -gt 0 -or @($sessionCoverage | Where-Object { $_.coverage -eq 'incomplete' }).Count -gt 0) { 'incomplete' } else { 'observed' })
                sessionCount = $SessionIds.Count
                observedSessionCount = @($sessionCoverage | Where-Object { $_.coverage -ne 'unknown' }).Count
                missingSessionIds = @($missingSessions.ToArray())
                sessions = @($sessionCoverage.ToArray())
                eventCount = $events.Count
                sourceBytes = $totalSourceBytes
                eventLimit = $maximumEvents
                sourceByteLimit = $maximumSourceBytes
            }
        }
    }
    finally {
        foreach ($temporaryIndex in $temporaryIndexes) {
            if ([System.IO.Directory]::Exists($temporaryIndex)) {
                Assert-MihariEvidencePathHasNoReparsePoint -Path $temporaryIndex
                [System.IO.Directory]::Delete($temporaryIndex, $true)
            }
        }
    }
}

function Get-MihariManagementV2EvidenceBundleInputs {
    param(
        [Parameter(Mandatory = $true)]$Session,
        [Parameter(Mandatory = $true)][string]$CaseId,
        [Parameter(Mandatory = $true)][object]$ShareProfile,
        [Parameter(Mandatory = $true)][string]$JobId
    )

    if (-not (Test-MihariCaseId -CaseId $CaseId)) { throw 'invalid_case_id' }
    $caseRoot = [System.IO.Path]::GetFullPath([string]$Session.OutputRoot)
    $null = Initialize-MihariCaseStore -CaseRoot $caseRoot
    $snapshot = Get-MihariCaseStoreSnapshot -CaseRoot $caseRoot
    $caseMatches = @($snapshot.Cases | Where-Object { [string]$_.caseId -eq $CaseId } | Select-Object -First 1)
    if ($caseMatches.Count -eq 0) { throw 'case_not_found' }
    $caseRecord = $caseMatches[0]
    $trials = @($snapshot.Trials | Where-Object { [string]$_.caseId -eq $CaseId } | Select-Object -First 1000)
    $trialIds = @($trials | ForEach-Object { [string]$_.trialId })
    $sessionSet = New-Object 'System.Collections.Generic.List[string]'
    foreach ($sessionId in @($caseRecord.sessionReferences)) {
        if (-not [string]::IsNullOrWhiteSpace([string]$sessionId) -and -not $sessionSet.Contains([string]$sessionId)) { $sessionSet.Add([string]$sessionId) }
    }
    foreach ($trial in $trials) {
        if (-not [string]::IsNullOrWhiteSpace([string]$trial.sessionId) -and -not $sessionSet.Contains([string]$trial.sessionId)) { $sessionSet.Add([string]$trial.sessionId) }
    }
    if ($sessionSet.Count -gt 200) { throw 'case_session_limit_exceeded' }

    $caseNotes = New-Object 'System.Collections.Generic.List[string]'
    $annotations = New-Object 'System.Collections.Generic.List[object]'
    foreach ($note in @($snapshot.Notes | Where-Object { [string]$_.caseId -eq $CaseId -and [string]::IsNullOrEmpty([string]$_.trialId) } | Sort-Object -Property createdAtUtc, noteId)) {
        if ($caseNotes.Count -lt 1000) { $caseNotes.Add([string]$note.text) }
        if ($annotations.Count -lt 10000) {
            $annotations.Add([pscustomobject]@{ annotationId = [string]$note.noteId; caseId = $CaseId; timestamp = [string]$note.createdAtUtc; kind = 'note'; note = [string]$note.text })
        }
    }
    foreach ($trial in $trials) {
        foreach ($marker in @($snapshot.Markers | Where-Object { [string]$_.trialId -eq [string]$trial.trialId } | Sort-Object -Property timestampUtc, markerId)) {
            if ($annotations.Count -ge 10000) { break }
            $annotations.Add([pscustomobject]@{
                markerId = [string]$marker.markerId; caseId = $CaseId; trialId = [string]$trial.trialId
                sessionId = [string]$trial.sessionId; timestamp = [string]$marker.timestampUtc; kind = [string]$marker.boundary
                label = [string]$marker.label; note = [string]$marker.note
            })
        }
        foreach ($note in @($snapshot.Notes | Where-Object { [string]$_.caseId -eq $CaseId -and [string]$_.trialId -eq [string]$trial.trialId } | Sort-Object -Property createdAtUtc, noteId)) {
            if ($annotations.Count -ge 10000) { break }
            $annotations.Add([pscustomobject]@{
                annotationId = [string]$note.noteId; caseId = $CaseId; trialId = [string]$trial.trialId
                timestamp = [string]$note.createdAtUtc; kind = 'note'; note = [string]$note.text
            })
        }
    }
    $portableTrials = New-Object 'System.Collections.Generic.List[object]'
    foreach ($trial in $trials) {
        $trialNotes = @($snapshot.Notes | Where-Object { [string]$_.caseId -eq $CaseId -and [string]$_.trialId -eq [string]$trial.trialId } | ForEach-Object { [string]$_.text })
        $portableTrials.Add([pscustomobject]@{
            trialId = [string]$trial.trialId; caseId = [string]$trial.caseId; sessionId = [string]$trial.sessionId
            startedAtUtc = [string]$trial.startedAtUtc; endedAtUtc = $trial.endedAtUtc
            startMarkerId = [string]$trial.startMarkerId; endMarkerId = $trial.endMarkerId
            configurationRevision = [string]$trial.configurationRevision; profile = $trial.profile
            environmentRef = $trial.environmentReference; businessOutcome = [string]$trial.operatorBusinessOutcome
            operatorNotes = ($trialNotes -join "`n")
        })
    }
    $portableCase = [pscustomobject]@{
        caseId = [string]$caseRecord.caseId; title = [string]$caseRecord.title
        notes = ($caseNotes -join "`n"); sessionRefs = @($sessionSet.ToArray()); trialRefs = @($trialIds)
    }
    Set-MihariManagementV2EvidenceJobState -Session $Session -JobId $JobId -State 'running' -Phase 'reading_canonical_events' -CompletedStages 1 -TotalStages 4
    $eventSnapshot = Get-MihariManagementV2EvidenceEvents -Session $Session -SessionIds ([string[]]$sessionSet.ToArray()) -JobId $JobId
    $findings = @(Get-MihariSessionFindings -Events ([object[]]$eventSnapshot.Events))
    $result = [pscustomobject]@{ schemaVersion = 1; ruleVersion = 'mihari-diagnosis/1'; generatedAtUtc = [DateTime]::UtcNow.ToString('o', [Globalization.CultureInfo]::InvariantCulture); findings = $findings }
    $profile = [pscustomobject]@{
        mode = [string]$Session.Mode; protocol = 'HTTP/1.1'; connectionReuse = [string]$Session.HttpConnectionPolicy
        routeKind = $(if ([string]::IsNullOrWhiteSpace([string]$Session.UpstreamProxy)) { 'unknown' } else { 'explicit_proxy' })
        maxWorkers = [int]$Session.MaxWorkers
    }
    $environment = @()
    if ($null -ne $Session.PlatformProxySnapshot -or $null -ne $Session.Mode) {
        $environment = @([pscustomobject]@{
            capturedAtUtc = [DateTime]::UtcNow.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
            source = 'mihari.evidence_export'; coverage = 'unknown'
            limitations = @('This is an export-time record; historical per-session environment snapshots are not stored in the operator journal.')
        })
    }
    $captureCoverage = $eventSnapshot.CaptureCoverage
    if (@($trials).Count -ge 1000 -or @($snapshot.Notes | Where-Object { [string]$_.caseId -eq $CaseId }).Count -gt 10000) {
        $captureCoverage | Add-Member -NotePropertyName operatorRecordsTruncated -NotePropertyValue $true -Force
    }
    return [pscustomobject]@{
        Case = $portableCase; Trials = @($portableTrials.ToArray()); Events = [object[]]$eventSnapshot.Events
        Annotations = @($annotations.ToArray()); Findings = $findings; OriginalResult = $result
        DiagnosticProfile = $profile; EnvironmentSnapshots = [object[]]$environment
        CaptureCoverage = $captureCoverage; ShareProfile = $ShareProfile; RuleVersion = 'mihari-diagnosis/1'
        ApplicationRevision = 'unknown'
    }
}

function Get-MihariManagementV2EvidencePreview {
    param(
        [Parameter(Mandatory = $true)]$Session,
        [Parameter(Mandatory = $true)][string]$CaseId,
        [Parameter(Mandatory = $true)][object]$ShareProfile
    )
    $inputs = Get-MihariManagementV2EvidenceBundleInputs -Session $Session -CaseId $CaseId -ShareProfile $ShareProfile -JobId ([Guid]::Empty.ToString('N'))
    $previewParameters = @{}
    foreach ($name in @('Case', 'Trials', 'Events', 'Annotations', 'Findings', 'OriginalResult', 'DiagnosticProfile', 'EnvironmentSnapshots', 'CaptureCoverage', 'ShareProfile', 'RuleVersion', 'ApplicationRevision')) {
        $previewParameters[$name] = $inputs.$name
    }
    return (New-MihariEvidenceBundlePreview @previewParameters)
}

function Get-MihariManagementV2EvidenceJobStore {
    param([Parameter(Mandatory = $true)]$Session)

    if ($null -eq $Session.PSObject.Properties['StateLock']) { throw 'session_state_lock_unavailable' }
    [System.Threading.Monitor]::Enter($Session.StateLock)
    try {
        if ($null -eq $Session.PSObject.Properties['EvidenceJobs'] -or $null -eq $Session.EvidenceJobs) {
            $Session | Add-Member -NotePropertyName EvidenceJobs -NotePropertyValue ([hashtable]::Synchronized(@{})) -Force
        }
        if ($null -eq $Session.PSObject.Properties['EvidenceJobOrder'] -or $null -eq $Session.EvidenceJobOrder) {
            $Session | Add-Member -NotePropertyName EvidenceJobOrder -NotePropertyValue (New-Object 'System.Collections.Generic.List[string]') -Force
        }
        if ($null -eq $Session.PSObject.Properties['EvidenceJobWorkers'] -or $null -eq $Session.EvidenceJobWorkers) {
            $Session | Add-Member -NotePropertyName EvidenceJobWorkers -NotePropertyValue ([hashtable]::Synchronized(@{})) -Force
        }
        return $Session.EvidenceJobs
    }
    finally { [System.Threading.Monitor]::Exit($Session.StateLock) }
}

function Complete-MihariManagementV2EvidenceWorker {
    param([Parameter(Mandatory = $true)]$Session, [Parameter(Mandatory = $true)][string]$JobId)

    $worker = $null
    [System.Threading.Monitor]::Enter($Session.StateLock)
    try {
        if ($null -ne $Session.EvidenceJobWorkers -and $Session.EvidenceJobWorkers.ContainsKey($JobId)) {
            $candidate = $Session.EvidenceJobWorkers[$JobId]
            if ($candidate.AsyncResult.IsCompleted -and -not [bool]$candidate.Finalizing) {
                $candidate.Finalizing = $true
                $worker = $candidate
            }
        }
    }
    finally { [System.Threading.Monitor]::Exit($Session.StateLock) }
    if ($null -eq $worker) { return }
    try { $null = $worker.PowerShell.EndInvoke($worker.AsyncResult) }
    catch {
        Set-MihariManagementV2EvidenceJobState -Session $Session -JobId $JobId -State 'failed' -Phase 'worker_failed' -CompletedStages 0 -TotalStages 1 -ErrorCode 'evidence_worker_failed'
    }
    finally {
        try { $worker.PowerShell.Dispose() }
        catch { Write-Warning 'An evidence management worker could not be disposed.' }
        [System.Threading.Monitor]::Enter($Session.StateLock)
        try { $Session.EvidenceJobWorkers.Remove($JobId) }
        finally { [System.Threading.Monitor]::Exit($Session.StateLock) }
    }
}

function Get-MihariManagementV2EvidenceJobView {
    param([Parameter(Mandatory = $true)]$Session, [Parameter(Mandatory = $true)][string]$JobId)

    Complete-MihariManagementV2EvidenceWorker -Session $Session -JobId $JobId
    [System.Threading.Monitor]::Enter($Session.StateLock)
    try {
        if ($null -eq $Session.EvidenceJobs -or -not $Session.EvidenceJobs.ContainsKey($JobId)) { return $null }
        $job = $Session.EvidenceJobs[$JobId]
        return [pscustomobject][ordered]@{
            jobId = [string]$job.jobId; operation = [string]$job.operation; state = [string]$job.state
            phase = [string]$job.phase; progress = $job.progress; acceptedAtUtc = [string]$job.acceptedAtUtc
            completedAtUtc = $job.completedAtUtc; result = $job.result; errorCode = $job.errorCode
        }
    }
    finally { [System.Threading.Monitor]::Exit($Session.StateLock) }
}

function Prune-MihariManagementV2EvidenceJobs {
    param([Parameter(Mandatory = $true)]$Session, [int]$MaximumJobs = 16)

    $workerIds = @()
    [System.Threading.Monitor]::Enter($Session.StateLock)
    try { if ($null -ne $Session.EvidenceJobWorkers) { $workerIds = @($Session.EvidenceJobWorkers.Keys) } }
    finally { [System.Threading.Monitor]::Exit($Session.StateLock) }
    foreach ($id in $workerIds) { Complete-MihariManagementV2EvidenceWorker -Session $Session -JobId ([string]$id) }
    $remove = New-Object 'System.Collections.Generic.List[string]'
    [System.Threading.Monitor]::Enter($Session.StateLock)
    try {
        while ($Session.EvidenceJobOrder.Count -ge $MaximumJobs) {
            $candidateId = $null
            foreach ($id in $Session.EvidenceJobOrder) {
                if (-not $Session.EvidenceJobs.ContainsKey($id)) { $candidateId = $id; break }
                if ([string]$Session.EvidenceJobs[$id].state -notin @('accepted', 'queued', 'running') -and -not $Session.EvidenceJobWorkers.ContainsKey($id)) { $candidateId = $id; break }
            }
            if ($null -eq $candidateId) { throw 'evidence_job_limit_reached' }
            $Session.EvidenceJobs.Remove($candidateId)
            $null = $Session.EvidenceJobOrder.Remove($candidateId)
            $remove.Add($candidateId)
        }
    }
    finally { [System.Threading.Monitor]::Exit($Session.StateLock) }
}

function Start-MihariManagementV2EvidenceJob {
    param(
        [Parameter(Mandatory = $true)]$Session,
        [Parameter(Mandatory = $true)][ValidateSet('export', 'import')][string]$Operation,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Parameters
    )

    if ($null -eq $Session.ManagementWorkerPool -or $null -eq $Session.ManagementListener) { throw 'evidence_management_pool_unavailable' }
    $null = Get-MihariManagementV2EvidenceJobStore -Session $Session
    Prune-MihariManagementV2EvidenceJobs -Session $Session
    $jobId = [Guid]::NewGuid().ToString('N').ToLowerInvariant()
    $now = [DateTime]::UtcNow.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
    $job = [pscustomobject][ordered]@{
        jobId = $jobId; operation = $Operation; state = 'queued'; phase = 'queued'
        progress = [pscustomobject]@{ completedStages = 0; totalStages = $(if ($Operation -eq 'export') { 4 } else { 3 }) }
        acceptedAtUtc = $now; completedAtUtc = $null; result = $null; errorCode = $null
    }
    $powerShell = [System.Management.Automation.PowerShell]::Create()
    $jobScript = @'
param($WorkerSession, $WorkerJobId, $WorkerOperation, $WorkerParameters)
$ErrorActionPreference = 'Stop'
$sourceRoot = [string]$WorkerSession.ManagementSourceRoot
if (Test-Path -LiteralPath (Join-Path $sourceRoot 'src') -PathType Container) { $sourceRoot = Join-Path $sourceRoot 'src' }
if (-not (Test-Path -LiteralPath (Join-Path $sourceRoot 'ManagementV2Evidence.ps1') -PathType Leaf)) { throw 'The evidence management worker source is unavailable.' }
foreach ($sourceFile in (Get-ChildItem -LiteralPath $sourceRoot -Filter '*.ps1' | Sort-Object -Property Name)) { . $sourceFile.FullName }
Invoke-MihariManagementV2EvidenceJob -Session $WorkerSession -JobId $WorkerJobId -Operation $WorkerOperation -Parameters $WorkerParameters
'@
    [System.Threading.Monitor]::Enter($Session.StateLock)
    try {
        if (@($Session.EvidenceJobs.Values | Where-Object { [string]$_.state -in @('accepted', 'queued', 'running') }).Count -gt 0) {
            throw 'evidence_job_busy'
        }
        $Session.EvidenceJobs[$jobId] = $job
        $Session.EvidenceJobOrder.Add($jobId)
        $powerShell.RunspacePool = $Session.ManagementWorkerPool
        $null = $powerShell.AddScript($jobScript).AddArgument($Session).AddArgument($jobId).AddArgument($Operation).AddArgument($Parameters)
        $asyncResult = $powerShell.BeginInvoke()
        $Session.EvidenceJobWorkers[$jobId] = [pscustomobject]@{ PowerShell = $powerShell; AsyncResult = $asyncResult; Finalizing = $false }
    }
    catch {
        if ($Session.EvidenceJobs.ContainsKey($jobId)) { $Session.EvidenceJobs.Remove($jobId) }
        $null = $Session.EvidenceJobOrder.Remove($jobId)
        $powerShell.Dispose()
        throw
    }
    finally { [System.Threading.Monitor]::Exit($Session.StateLock) }
    return [pscustomobject]@{ jobId = $jobId; operation = $Operation; state = 'accepted'; phase = 'queued'; acceptedAtUtc = $now; progress = $job.progress }
}

function Invoke-MihariManagementV2EvidenceJob {
    param(
        [Parameter(Mandatory = $true)]$Session,
        [Parameter(Mandatory = $true)][string]$JobId,
        [Parameter(Mandatory = $true)][ValidateSet('export', 'import')][string]$Operation,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Parameters
    )

    $totalStages = $(if ($Operation -eq 'export') { 4 } else { 3 })
    Set-MihariManagementV2EvidenceJobState -Session $Session -JobId $JobId -State 'running' -Phase 'preparing' -CompletedStages 0 -TotalStages $totalStages
    try {
        if ($Operation -eq 'export') {
            $inputs = Get-MihariManagementV2EvidenceBundleInputs -Session $Session -CaseId ([string]$Parameters.caseId) -ShareProfile $Parameters.shareProfile -JobId $JobId
            Set-MihariManagementV2EvidenceJobState -Session $Session -JobId $JobId -State 'running' -Phase 'writing_bundle' -CompletedStages 3 -TotalStages 4
            $exportParameters = @{}
            foreach ($name in @('DestinationPath', 'Case', 'Trials', 'Events', 'Annotations', 'Findings', 'OriginalResult', 'DiagnosticProfile', 'EnvironmentSnapshots', 'CaptureCoverage', 'ShareProfile', 'RuleVersion', 'ApplicationRevision')) {
                if ($name -eq 'DestinationPath') { $exportParameters[$name] = [string]$Parameters.destinationPath }
                else { $exportParameters[$name] = $inputs.$name }
            }
            $exported = Export-MihariEvidenceBundle @exportParameters
            $result = [pscustomobject]@{
                bundleId = [string]$exported.bundleId; destinationPath = [string]$exported.path
                sha256 = [string]$exported.sha256; preview = $exported.preview
            }
            Set-MihariManagementV2EvidenceJobState -Session $Session -JobId $JobId -State 'completed' -Phase 'completed' -CompletedStages 4 -TotalStages 4 -Result $result
            return
        }

        Set-MihariManagementV2EvidenceJobState -Session $Session -JobId $JobId -State 'running' -Phase 'validating_archive' -CompletedStages 1 -TotalStages 3
        $importRoot = Get-MihariManagementV2EvidenceImportRoot -Session $Session
        $existing = 0
        if ([System.IO.Directory]::Exists($importRoot)) {
            foreach ($directory in [System.IO.Directory]::EnumerateDirectories($importRoot)) {
                $existing++
                if ($existing -ge 200) { throw 'evidence_import_limit_reached' }
            }
        }
        Assert-MihariEvidencePathHasNoReparsePoint -Path $importRoot
        $imported = Import-MihariEvidenceBundle -ArchivePath ([string]$Parameters.sourcePath) -DestinationDirectory $importRoot -MaximumArchiveBytes 67108864 -MaximumExpandedBytes 134217728 -MaximumEntryBytes 67108864 -MaximumEntries 16 -MaximumRecords 100000 -MaximumRecordBytes 65536
        $caseDirectory = [System.IO.Path]::GetFullPath([string]$imported.caseDirectory)
        if (-not (Test-MihariManagementV2EvidencePathWithinRoot -Path $caseDirectory -Root $importRoot)) { throw 'import_destination_invalid' }
        $reviewId = [System.IO.Path]::GetFileName($caseDirectory)
        if ($reviewId -notmatch '^case-[0-9a-f]{32}$') { throw 'import_reference_invalid' }
        Set-MihariManagementV2EvidenceJobState -Session $Session -JobId $JobId -State 'running' -Phase 'review_ready' -CompletedStages 2 -TotalStages 3
        $result = [pscustomobject]@{
            reviewId = $reviewId; readOnly = $true; importedEventCount = [int]$imported.importedEventCount
            importedAnnotationCount = [int]$imported.importedAnnotationCount; unknownRecordCount = [int]$imported.unknownRecordCount
            sourceHashVerified = [bool]$imported.sourceHashVerified; sourceBundleHash = [string]$imported.sourceBundleHash
        }
        Set-MihariManagementV2EvidenceJobState -Session $Session -JobId $JobId -State 'completed' -Phase 'completed' -CompletedStages 3 -TotalStages 3 -Result $result
    }
    catch {
        $errorCode = 'evidence_' + $Operation + '_failed'
        if ($_.Exception.Message -eq 'case_not_found') { $errorCode = 'case_not_found' }
        elseif ($_.Exception.Message -eq 'invalid_case_id') { $errorCode = 'invalid_case_id' }
        elseif ($_.Exception.Message -eq 'case_event_limit_exceeded' -or $_.Exception.Message -eq 'case_event_byte_limit_exceeded') { $errorCode = 'evidence_scope_limit_exceeded' }
        elseif ($_.Exception.Message -eq 'evidence_import_limit_reached') { $errorCode = 'evidence_import_limit_reached' }
        Set-MihariManagementV2EvidenceJobState -Session $Session -JobId $JobId -State 'failed' -Phase 'failed' -CompletedStages 0 -TotalStages $totalStages -ErrorCode $errorCode
    }
}

function Get-MihariManagementV2EvidenceDate {
    param([Parameter(Mandatory = $true)][string]$Value)
    $parsed = [DateTimeOffset]::MinValue
    if ($Value.Length -gt 64 -or -not [DateTimeOffset]::TryParse($Value, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$parsed)) { throw 'invalid_retention_cutoff' }
    return $parsed.UtcDateTime
}

function Get-MihariManagementV2EvidenceOfflinePage {
    param([Parameter(Mandatory = $true)]$OfflineCase, [Parameter(Mandatory = $true)]$Query)

    $limit = 25
    if ($Query.Contains('limit')) {
        if ([string]$Query.limit -notmatch '^\d{1,3}$' -or [int]$Query.limit -lt 1 -or [int]$Query.limit -gt 50) { throw 'invalid_offline_limit' }
        $limit = [int]$Query.limit
    }
    $eventOffset = 0; $findingOffset = 0; $annotationOffset = 0; $trialOffset = 0
    foreach ($name in @('eventOffset', 'findingOffset', 'annotationOffset', 'trialOffset')) {
        if (-not $Query.Contains($name)) { continue }
        if ([string]$Query[$name] -notmatch '^\d{1,6}$') { throw 'invalid_offline_offset' }
        $value = [int]$Query[$name]
        if ($value -gt 100000) { throw 'invalid_offline_offset' }
        switch ($name) {
            'eventOffset' { $eventOffset = $value }
            'findingOffset' { $findingOffset = $value }
            'annotationOffset' { $annotationOffset = $value }
            'trialOffset' { $trialOffset = $value }
        }
    }
    $eventItems = @($OfflineCase.events | Select-Object -Skip $eventOffset -First $limit)
    $findingItems = @($OfflineCase.findings | Select-Object -Skip $findingOffset -First $limit)
    $annotationItems = @($OfflineCase.annotations | Select-Object -Skip $annotationOffset -First $limit)
    $trialItems = @($OfflineCase.manifest.trials | Select-Object -Skip $trialOffset -First $limit)
    $original = $null
    if ($null -ne $OfflineCase.originalResult) {
        $original = [pscustomobject]@{
            ruleVersion = [string]$OfflineCase.originalResult.ruleVersion
            generatedAtUtc = [string]$OfflineCase.originalResult.generatedAtUtc
            findingCount = @($OfflineCase.originalResult.findings).Count
        }
    }
    $result = [pscustomobject][ordered]@{
        readOnly = $true; capabilities = $OfflineCase.capabilities; case = $OfflineCase.manifest.case
        bundle = [pscustomobject]@{
            bundleId = [string]$OfflineCase.manifest.bundleId; schemaVersion = [int]$OfflineCase.manifest.schemaVersion
            createdAtUtc = [string]$OfflineCase.manifest.createdAtUtc; ruleVersion = [string]$OfflineCase.manifest.ruleVersion
            applicationRevision = [string]$OfflineCase.manifest.applicationRevision; integrity = $OfflineCase.manifest.integrity
            redactionSummary = $OfflineCase.manifest.redactionSummary
        }
        captureCoverage = $OfflineCase.environment.captureCoverage
        environmentSnapshots = @($OfflineCase.environment.snapshots)
        events = $eventItems; eventCount = @($OfflineCase.events).Count; nextEventOffset = $(if ($eventOffset + $eventItems.Count -lt @($OfflineCase.events).Count) { $eventOffset + $eventItems.Count } else { $null })
        findings = $findingItems; findingCount = @($OfflineCase.findings).Count; nextFindingOffset = $(if ($findingOffset + $findingItems.Count -lt @($OfflineCase.findings).Count) { $findingOffset + $findingItems.Count } else { $null })
        annotations = $annotationItems; annotationCount = @($OfflineCase.annotations).Count; nextAnnotationOffset = $(if ($annotationOffset + $annotationItems.Count -lt @($OfflineCase.annotations).Count) { $annotationOffset + $annotationItems.Count } else { $null })
        trials = $trialItems; trialCount = @($OfflineCase.manifest.trials).Count; nextTrialOffset = $(if ($trialOffset + $trialItems.Count -lt @($OfflineCase.manifest.trials).Count) { $trialOffset + $trialItems.Count } else { $null })
        originalResult = $original; importReport = $OfflineCase.importReport; unknownRecordCount = [int]$OfflineCase.unknownRecordCount
    }
    $json = ConvertTo-Json -InputObject $result -Depth 12 -Compress -ErrorAction Stop
    while ([System.Text.Encoding]::UTF8.GetByteCount($json) -gt 900000 -and $limit -gt 1) {
        $limit = [Math]::Max(1, [int][Math]::Floor($limit / 2))
        $eventItems = @($OfflineCase.events | Select-Object -Skip $eventOffset -First $limit)
        $findingItems = @($OfflineCase.findings | Select-Object -Skip $findingOffset -First $limit)
        $annotationItems = @($OfflineCase.annotations | Select-Object -Skip $annotationOffset -First $limit)
        $trialItems = @($OfflineCase.manifest.trials | Select-Object -Skip $trialOffset -First $limit)
        $result.events = $eventItems; $result.findings = $findingItems; $result.annotations = $annotationItems; $result.trials = $trialItems
        $result.nextEventOffset = $(if ($eventOffset + $eventItems.Count -lt @($OfflineCase.events).Count) { $eventOffset + $eventItems.Count } else { $null })
        $result.nextFindingOffset = $(if ($findingOffset + $findingItems.Count -lt @($OfflineCase.findings).Count) { $findingOffset + $findingItems.Count } else { $null })
        $result.nextAnnotationOffset = $(if ($annotationOffset + $annotationItems.Count -lt @($OfflineCase.annotations).Count) { $annotationOffset + $annotationItems.Count } else { $null })
        $result.nextTrialOffset = $(if ($trialOffset + $trialItems.Count -lt @($OfflineCase.manifest.trials).Count) { $trialOffset + $trialItems.Count } else { $null })
        $json = ConvertTo-Json -InputObject $result -Depth 12 -Compress -ErrorAction Stop
    }
    if ([System.Text.Encoding]::UTF8.GetByteCount($json) -gt 900000) { throw 'offline_page_too_large' }
    return [pscustomobject]@{ Value = $result; Limit = $limit }
}

function Stop-MihariManagementV2EvidenceJobs {
    param([Parameter(Mandatory = $true)]$Session)

    $errors = New-Object 'System.Collections.Generic.List[string]'
    if ($null -eq $Session.PSObject.Properties['EvidenceJobWorkers'] -or $null -eq $Session.EvidenceJobWorkers) {
        return [pscustomobject]@{ success = $true; errors = @() }
    }
    $workers = New-Object 'System.Collections.Generic.List[object]'
    [System.Threading.Monitor]::Enter($Session.StateLock)
    try {
        foreach ($jobId in @($Session.EvidenceJobWorkers.Keys)) {
            $worker = $Session.EvidenceJobWorkers[$jobId]
            if (-not [bool]$worker.Finalizing) {
                $worker.Finalizing = $true
                $workers.Add([pscustomobject]@{ JobId = [string]$jobId; Worker = $worker })
            }
        }
    }
    finally { [System.Threading.Monitor]::Exit($Session.StateLock) }
    foreach ($entry in $workers) {
        $jobId = [string]$entry.JobId
        $worker = $entry.Worker
        try {
            if (-not $worker.AsyncResult.IsCompleted) { $worker.PowerShell.Stop() }
        }
        catch { $errors.Add('worker_stop_failed') }
        try { $worker.PowerShell.Dispose() }
        catch { $errors.Add('worker_dispose_failed') }
        if ($null -ne $Session.EvidenceJobs -and $Session.EvidenceJobs.ContainsKey($jobId) -and [string]$Session.EvidenceJobs[$jobId].state -in @('accepted', 'queued', 'running')) {
            Set-MihariManagementV2EvidenceJobState -Session $Session -JobId $jobId -State 'cancelled' -Phase 'session_stopped' -CompletedStages 0 -TotalStages 1 -ErrorCode 'session_stopped'
        }
        [System.Threading.Monitor]::Enter($Session.StateLock)
        try { $null = $Session.EvidenceJobWorkers.Remove($jobId) }
        finally { [System.Threading.Monitor]::Exit($Session.StateLock) }
    }
    return [pscustomobject]@{ success = ($errors.Count -eq 0); errors = [string[]]$errors.ToArray() }
}

function Invoke-MihariManagementV2EvidenceRequest {
    param(
        [Parameter(Mandatory = $true)]$Session,
        [Parameter(Mandatory = $true)]$Request
    )

    $method = [string]$Request.Method
    $path = [string]$Request.Path
    if ($method -eq 'GET' -and $path -eq '/api/v2/evidence/preview') {
        try {
            $query = Get-MihariManagementV2EvidenceQuery -Query ([string]$Request.Query) -AllowedNames @('caseId', 'maskHosts', 'maskUsernames', 'maskPaths', 'maskIdentifiers')
            if (-not $query.Contains('caseId') -or -not (Test-MihariCaseId -CaseId ([string]$query.caseId))) { throw 'invalid_case_id' }
            $profile = [ordered]@{ maskHosts = $true; maskUsernames = $true; maskPaths = $true; maskIdentifiers = $true }
            foreach ($name in @('maskHosts', 'maskUsernames', 'maskPaths', 'maskIdentifiers')) {
                if (-not $query.Contains($name)) { continue }
                if ([string]$query[$name] -notin @('true', 'false')) { throw 'invalid_share_profile' }
                $profile[$name] = ([string]$query[$name] -eq 'true')
            }
            $preview = Get-MihariManagementV2EvidencePreview -Session $Session -CaseId ([string]$query.caseId) -ShareProfile ([pscustomobject]$profile)
            return (New-MihariManagementJsonResponse -StatusCode 200 -Value ([pscustomobject]@{ caseId = [string]$query.caseId; preview = $preview }))
        }
        catch {
            if ($_.Exception.Message -eq 'case_not_found') { return (New-MihariManagementErrorResponse -StatusCode 404 -Code 'case_not_found' -Message 'The requested case does not exist.') }
            if ($_.Exception.Message -eq 'invalid_case_id') { return (New-MihariManagementErrorResponse -StatusCode 400 -Code 'invalid_case_id' -Message 'A valid caseId query value is required.') }
            return (New-MihariManagementErrorResponse -StatusCode 400 -Code 'invalid_evidence_preview' -Message 'The case preview query or evidence scope is invalid or exceeds its bounds.')
        }
    }
    if ($method -eq 'POST' -and $path -eq '/api/v2/evidence/export') {
        $body = $null
        try { $body = Read-MihariManagementJsonBody -Request $Request }
        catch {
            if ($_.Exception.Message -eq 'unsupported_media_type') { return (New-MihariManagementErrorResponse -StatusCode 415 -Code 'unsupported_media_type' -Message 'Send a UTF-8 application/json request body.') }
            return (New-MihariManagementErrorResponse -StatusCode 400 -Code 'invalid_json' -Message 'Supply caseId and an optional shareProfile and destinationPath.')
        }
        $caseId = [string](Get-MihariEvidenceValue -InputObject $body -Name 'caseId')
        if (-not (Test-MihariCaseId -CaseId $caseId)) { return (New-MihariManagementErrorResponse -StatusCode 400 -Code 'invalid_case_id' -Message 'A valid caseId is required.') }
        try { $shareProfile = ConvertTo-MihariManagementV2EvidenceShareProfile -Value (Get-MihariEvidenceValue -InputObject $body -Name 'shareProfile') }
        catch { return (New-MihariManagementErrorResponse -StatusCode 400 -Code 'invalid_share_profile' -Message 'Share profile values must be booleans for the supported mask fields.') }
        $evidenceRoot = Get-MihariManagementV2EvidenceRoot -Session $Session
        $exportsRoot = [System.IO.Path]::Combine($evidenceRoot, 'exports')
        $destinationPath = [string](Get-MihariEvidenceValue -InputObject $body -Name 'destinationPath')
        if ([string]::IsNullOrWhiteSpace($destinationPath)) {
            $destinationPath = [System.IO.Path]::Combine($exportsRoot, $caseId + '-' + [Guid]::NewGuid().ToString('N') + '.mihari.zip')
        }
        else {
            if (-not [System.IO.Path]::IsPathRooted($destinationPath)) { return (New-MihariManagementErrorResponse -StatusCode 400 -Code 'invalid_destination' -Message 'destinationPath must be an absolute path under the Mihari output root.') }
            try { $destinationPath = [System.IO.Path]::GetFullPath($destinationPath) }
            catch { return (New-MihariManagementErrorResponse -StatusCode 400 -Code 'invalid_destination' -Message 'destinationPath is invalid.') }
            if (-not (Test-MihariManagementV2EvidencePathWithinRoot -Path $destinationPath -Root ([string]$Session.OutputRoot)) -or
                [System.IO.Path]::GetExtension($destinationPath) -notin @('.zip', '.mihari.zip')) {
                return (New-MihariManagementErrorResponse -StatusCode 400 -Code 'destination_outside_output_root' -Message 'Evidence exports must be written below the Mihari output root as a zip bundle.')
            }
        }
        try {
            Assert-MihariEvidencePathHasNoReparsePoint -Path ([System.IO.Path]::GetDirectoryName($destinationPath))
            if ([System.IO.File]::Exists($destinationPath) -or [System.IO.Directory]::Exists($destinationPath)) { return (New-MihariManagementErrorResponse -StatusCode 409 -Code 'destination_exists' -Message 'The evidence destination already exists.') }
            $parameters = @{ caseId = $caseId; shareProfile = $shareProfile; destinationPath = $destinationPath }
            $job = Start-MihariManagementV2EvidenceJob -Session $Session -Operation 'export' -Parameters $parameters
            return (New-MihariManagementJsonResponse -StatusCode 202 -Value $job)
        }
        catch {
            if ($_.Exception.Message -eq 'evidence_job_busy') { return (New-MihariManagementErrorResponse -StatusCode 409 -Code 'evidence_job_busy' -Message 'Another evidence job is running for this session.') }
            if ($_.Exception.Message -eq 'evidence_job_limit_reached') { return (New-MihariManagementErrorResponse -StatusCode 429 -Code 'evidence_job_limit_reached' -Message 'The bounded evidence job history is full.') }
            return (New-MihariManagementErrorResponse -StatusCode 503 -Code 'evidence_job_unavailable' -Message 'Mihari could not start the evidence export job.')
        }
    }
    if ($method -eq 'POST' -and $path -eq '/api/v2/evidence/import') {
        $body = $null
        try { $body = Read-MihariManagementJsonBody -Request $Request }
        catch {
            if ($_.Exception.Message -eq 'unsupported_media_type') { return (New-MihariManagementErrorResponse -StatusCode 415 -Code 'unsupported_media_type' -Message 'Send a UTF-8 application/json request body.') }
            return (New-MihariManagementErrorResponse -StatusCode 400 -Code 'invalid_json' -Message 'Supply sourcePath in a JSON object.')
        }
        $sourcePath = [string](Get-MihariEvidenceValue -InputObject $body -Name 'sourcePath')
        if ([string]::IsNullOrWhiteSpace($sourcePath) -or $sourcePath.Length -gt 4096) { return (New-MihariManagementErrorResponse -StatusCode 400 -Code 'invalid_source_path' -Message 'An absolute local bundle path is required.') }
        try {
            if (-not [System.IO.Path]::IsPathRooted($sourcePath)) { throw 'invalid_source_path' }
            $sourcePath = [System.IO.Path]::GetFullPath($sourcePath)
            if (-not [System.IO.File]::Exists($sourcePath)) { throw 'source_not_found' }
            Assert-MihariEvidencePathHasNoReparsePoint -Path $sourcePath
            if ((New-Object System.IO.FileInfo($sourcePath)).Length -gt 67108864) { throw 'source_too_large' }
            $parameters = @{ sourcePath = $sourcePath }
            $job = Start-MihariManagementV2EvidenceJob -Session $Session -Operation 'import' -Parameters $parameters
            return (New-MihariManagementJsonResponse -StatusCode 202 -Value $job)
        }
        catch {
            if ($_.Exception.Message -eq 'evidence_job_busy') { return (New-MihariManagementErrorResponse -StatusCode 409 -Code 'evidence_job_busy' -Message 'Another evidence job is running for this session.') }
            if ($_.Exception.Message -eq 'source_not_found') { return (New-MihariManagementErrorResponse -StatusCode 404 -Code 'evidence_source_not_found' -Message 'The local evidence bundle does not exist.') }
            if ($_.Exception.Message -eq 'source_too_large') { return (New-MihariManagementErrorResponse -StatusCode 413 -Code 'evidence_source_too_large' -Message 'The local evidence bundle exceeds the 64 MiB archive limit.') }
            if ($_.Exception.Message -eq 'invalid_source_path') { return (New-MihariManagementErrorResponse -StatusCode 400 -Code 'invalid_source_path' -Message 'An absolute local bundle path is required.') }
            return (New-MihariManagementErrorResponse -StatusCode 503 -Code 'evidence_job_unavailable' -Message 'Mihari could not start the evidence import job.')
        }
    }
    if ($method -eq 'GET' -and $path -match '^/api/v2/evidence/jobs/([0-9a-f]{32})$') {
        $job = Get-MihariManagementV2EvidenceJobView -Session $Session -JobId ([string]$Matches[1])
        if ($null -eq $job) { return (New-MihariManagementErrorResponse -StatusCode 404 -Code 'evidence_job_not_found' -Message 'The evidence job does not exist or has expired.') }
        return (New-MihariManagementJsonResponse -StatusCode 200 -Value $job)
    }
    if ($method -eq 'GET' -and $path -match '^/api/v2/evidence/offline/(case-[0-9a-f]{32})$') {
        $reviewId = [string]$Matches[1]
        try {
            $query = Get-MihariManagementV2EvidenceQuery -Query ([string]$Request.Query) -AllowedNames @('limit', 'eventOffset', 'findingOffset', 'annotationOffset', 'trialOffset')
            $caseDirectory = [System.IO.Path]::Combine((Get-MihariManagementV2EvidenceImportRoot -Session $Session), $reviewId)
            Assert-MihariEvidencePathHasNoReparsePoint -Path $caseDirectory
            if (-not [System.IO.Directory]::Exists($caseDirectory)) { return (New-MihariManagementErrorResponse -StatusCode 404 -Code 'offline_case_not_found' -Message 'The imported read-only case does not exist.') }
            $offline = Read-MihariOfflineEvidenceCase -CaseDirectory $caseDirectory
            $page = Get-MihariManagementV2EvidenceOfflinePage -OfflineCase $offline -Query $query
            return (New-MihariManagementJsonResponse -StatusCode 200 -Value $page.Value)
        }
        catch {
            if ($_.Exception.Message -eq 'invalid_offline_limit' -or $_.Exception.Message -eq 'invalid_offline_offset' -or $_.Exception.Message -eq 'offline_page_too_large') {
                return (New-MihariManagementErrorResponse -StatusCode 400 -Code 'invalid_offline_page' -Message 'The offline review page is invalid or exceeds its response limit.')
            }
            return (New-MihariManagementErrorResponse -StatusCode 422 -Code 'offline_case_invalid' -Message 'The imported evidence case failed local validation.')
        }
    }
    if ($method -eq 'GET' -and $path -eq '/api/v2/evidence/retention') {
        try {
            $query = Get-MihariManagementV2EvidenceQuery -Query ([string]$Request.Query) -AllowedNames @('scope', 'olderThanUtc')
            if ($query.Contains('scope') -and [string]$query.scope -ne 'imports') { throw 'invalid_retention_scope' }
            $importRoot = Get-MihariManagementV2EvidenceImportRoot -Session $Session
            if (-not $query.Contains('olderThanUtc')) {
                return (New-MihariManagementJsonResponse -StatusCode 200 -Value ([pscustomobject]@{
                    supportedScopes = @([pscustomobject]@{ scope = 'imports'; relativeRoot = 'evidence/imports' })
                    deleteRequiresConfirmation = $true; requiredPlanField = 'olderThanUtc'
                    note = 'Pass an explicit olderThanUtc value to preview verified imported cases for cleanup.'
                }))
            }
            $cutoff = Get-MihariManagementV2EvidenceDate -Value ([string]$query.olderThanUtc)
            $plan = Get-MihariEvidenceRetentionPlan -RootPath $importRoot -OlderThanUtc $cutoff
            return (New-MihariManagementJsonResponse -StatusCode 200 -Value ([pscustomobject]@{
                scope = 'imports'; olderThanUtc = $cutoff.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
                eligible = @($plan.eligible | ForEach-Object { [pscustomobject]@{ bundleId = [string]$_.bundleId; createdAtUtc = [string]$_.createdAtUtc } })
                refused = @($plan.refused | ForEach-Object { [pscustomobject]@{ reason = [string]$_.reason } })
                examined = [int]$plan.examined; deleteRequiresConfirmation = $true
            }))
        }
        catch {
            return (New-MihariManagementErrorResponse -StatusCode 400 -Code 'invalid_retention_plan' -Message 'The retention scope or cutoff is invalid.')
        }
    }
    if ($method -eq 'POST' -and $path -eq '/api/v2/evidence/cleanup') {
        $body = $null
        try { $body = Read-MihariManagementJsonBody -Request $Request }
        catch {
            if ($_.Exception.Message -eq 'unsupported_media_type') { return (New-MihariManagementErrorResponse -StatusCode 415 -Code 'unsupported_media_type' -Message 'Send a UTF-8 application/json request body.') }
            return (New-MihariManagementErrorResponse -StatusCode 400 -Code 'invalid_json' -Message 'Supply scope, olderThanUtc, and confirmDeletion in a JSON object.')
        }
        if ([string](Get-MihariEvidenceValue -InputObject $body -Name 'scope') -ne 'imports' -or
            (Get-MihariEvidenceValue -InputObject $body -Name 'confirmDeletion') -isnot [bool] -or
            -not [bool](Get-MihariEvidenceValue -InputObject $body -Name 'confirmDeletion')) {
            return (New-MihariManagementErrorResponse -StatusCode 400 -Code 'cleanup_confirmation_required' -Message 'Cleanup requires scope imports and confirmDeletion true.')
        }
        try {
            $cutoff = Get-MihariManagementV2EvidenceDate -Value ([string](Get-MihariEvidenceValue -InputObject $body -Name 'olderThanUtc'))
            $result = Invoke-MihariEvidenceRetentionCleanup -RootPath (Get-MihariManagementV2EvidenceImportRoot -Session $Session) -OlderThanUtc $cutoff -ConfirmDeletion
            return (New-MihariManagementJsonResponse -StatusCode 200 -Value ([pscustomobject]@{
                state = 'completed'; scope = 'imports'; deletedCount = @($result.deleted).Count
                refused = @($result.refused | ForEach-Object { [pscustomobject]@{ reason = [string]$_.reason } })
                examined = [int]$result.examined
            }))
        }
        catch {
            return (New-MihariManagementErrorResponse -StatusCode 400 -Code 'evidence_cleanup_failed' -Message 'Mihari could not complete the verified import cleanup.')
        }
    }
    if ($path -eq '/api/v2/evidence' -or $path.StartsWith('/api/v2/evidence/')) {
        return (New-MihariManagementErrorResponse -StatusCode 405 -Code 'method_or_route_not_supported' -Message 'The evidence method or route is not supported.')
    }
    return $null
}
