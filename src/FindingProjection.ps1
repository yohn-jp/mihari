function Get-MihariFindingProjectionValue {
    param(
        [Parameter(Mandatory = $false)][AllowNull()][object]$InputObject,
        [Parameter(Mandatory = $true)][string]$Name
    )
    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [System.Collections.IDictionary]) {
        foreach ($key in $InputObject.Keys) {
            if ([string]::Equals([string]$key, $Name, [StringComparison]::OrdinalIgnoreCase)) { return $InputObject[$key] }
        }
        return $null
    }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function New-MihariFindingProjectionError {
    param(
        [Parameter(Mandatory = $true)][string]$Code,
        [Parameter(Mandatory = $true)][string]$Message,
        [Parameter(Mandatory = $false)][AllowNull()][System.Exception]$InnerException
    )
    if ($null -eq $InnerException) { $exception = [System.InvalidOperationException]::new($Message) }
    else { $exception = [System.InvalidOperationException]::new($Message, $InnerException) }
    $exception.Data['mihariCode'] = $Code
    return $exception
}

function Get-MihariFindingProjectionLockName {
    param([Parameter(Mandatory = $true)][string]$SnapshotPath)
    $fullPath = [System.IO.Path]::GetFullPath($SnapshotPath).ToLowerInvariant()
    $algorithm = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hash = $algorithm.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($fullPath))
        return 'mihari_findings_' + ([BitConverter]::ToString($hash)).Replace('-', '').ToLowerInvariant()
    }
    finally { $algorithm.Dispose() }
}

function Read-MihariFindingProjectionSnapshot {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$SessionId
    )
    if (-not [System.IO.File]::Exists($Path)) {
        return [pscustomobject]@{ snapshot = $null; invalid = $false; foreignSession = $false }
    }

    $contents = $null
    try { $contents = [System.IO.File]::ReadAllText($Path, [System.Text.Encoding]::UTF8) }
    catch {
        throw (New-MihariFindingProjectionError -Code 'finding_snapshot_read_error' -Message 'Could not read the persistent findings snapshot.' -InnerException $_.Exception)
    }
    $snapshot = $null
    try { $snapshot = ConvertFrom-Json -InputObject $contents -ErrorAction Stop }
    catch {
        Write-Verbose 'The persistent findings snapshot is not valid JSON; rebuilding it from indexed events.'
        return [pscustomobject]@{ snapshot = $null; invalid = $true; foreignSession = $false }
    }

    $schema = Get-MihariFindingProjectionValue -InputObject $snapshot -Name 'schemaVersion'
    $snapshotSession = Get-MihariFindingProjectionValue -InputObject $snapshot -Name 'sessionId'
    if (-not [string]::Equals([string]$snapshotSession, $SessionId, [StringComparison]::Ordinal)) {
        return [pscustomobject]@{ snapshot = $snapshot; invalid = $false; foreignSession = $true }
    }
    $generation = Get-MihariFindingProjectionValue -InputObject $snapshot -Name 'fileGeneration'
    $offsetValue = Get-MihariFindingProjectionValue -InputObject $snapshot -Name 'nextOffset'
    $ordinalValue = Get-MihariFindingProjectionValue -InputObject $snapshot -Name 'nextOrdinal'
    $offset = 0L
    $ordinal = 0L
    $schemaVersion = 0
    $schemaValid = [int]::TryParse([string]$schema, [ref]$schemaVersion)
    if (-not $schemaValid -or $schemaVersion -ne 1 -or [string]::IsNullOrWhiteSpace([string]$generation) -or
            $null -eq $offsetValue -or -not [long]::TryParse([string]$offsetValue, [ref]$offset) -or $offset -lt 0 -or
            ($null -ne $ordinalValue -and (-not [long]::TryParse([string]$ordinalValue, [ref]$ordinal) -or $ordinal -lt 0)) -or
            $null -eq $snapshot.PSObject.Properties['findings'] -or $null -eq $snapshot.PSObject.Properties['findings'].Value) {
        Write-Verbose 'The persistent findings snapshot has an unsupported or incomplete shape; rebuilding it from indexed events.'
        return [pscustomobject]@{ snapshot = $null; invalid = $true; foreignSession = $false }
    }
    return [pscustomobject]@{ snapshot = $snapshot; invalid = $false; foreignSession = $false }
}

function Write-MihariFindingProjectionSnapshotAtomic {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][object]$Snapshot
    )
    $directory = [System.IO.Path]::GetDirectoryName([System.IO.Path]::GetFullPath($Path))
    try { [void][System.IO.Directory]::CreateDirectory($directory) }
    catch {
        throw (New-MihariFindingProjectionError -Code 'finding_snapshot_write_error' -Message 'Could not create the findings snapshot directory.' -InnerException $_.Exception)
    }

    $temporaryPath = $Path + '.tmp.' + [Guid]::NewGuid().ToString('N')
    $failurePhase = 'serialize'
    try {
        $json = ConvertTo-Json -InputObject $Snapshot -Depth 32 -Compress -ErrorAction Stop
        $failurePhase = 'write_temporary'
        [System.IO.File]::WriteAllText($temporaryPath, $json + [Environment]::NewLine, [System.Text.UTF8Encoding]::new($false))
        if ([System.IO.File]::Exists($Path)) {
            $failurePhase = 'replace'
            # PowerShell coerces a null string argument to an empty path when
            # binding this overload. Reflection preserves null, so no backup
            # copy of the evidence snapshot is left on disk.
            $replace = [System.IO.File].GetMethod('Replace', [type[]]@([string], [string], [string]))
            if ($null -eq $replace) { throw [System.NotSupportedException]::new('Atomic file replacement is unavailable.') }
            [void]$replace.Invoke($null, [object[]]@($temporaryPath, $Path, $null))
        }
        else {
            $failurePhase = 'move_into_place'
            [System.IO.File]::Move($temporaryPath, $Path)
        }
    }
    catch {
        $writeError = $_.Exception
        if ([System.IO.File]::Exists($temporaryPath)) {
            try { [System.IO.File]::Delete($temporaryPath) }
            catch {
                $cleanupError = $_.Exception
                $combined = [System.InvalidOperationException]::new('Could not write or clean up the findings snapshot.', $writeError)
                $combined.Data['cleanupError'] = $cleanupError.GetType().FullName
                $projectionError = New-MihariFindingProjectionError -Code 'finding_snapshot_write_error' -Message 'Could not atomically replace the persistent findings snapshot.' -InnerException $combined
                $projectionError.Data['failurePhase'] = $failurePhase
                throw $projectionError
            }
        }
        $projectionError = New-MihariFindingProjectionError -Code 'finding_snapshot_write_error' -Message 'Could not atomically replace the persistent findings snapshot.' -InnerException $writeError
        $projectionError.Data['failurePhase'] = $failurePhase
        throw $projectionError
    }
}

function Get-MihariFindingProjectionRevision {
    param([Parameter(Mandatory = $true)][object]$Snapshot)
    $parts = New-Object 'System.Collections.Generic.List[string]'
    foreach ($finding in @($Snapshot.findings | Sort-Object -Property findingId)) {
        $parts.Add(([string]$finding.findingId) + ':' + [string]$finding.count + ':' + [string]$finding.resolutionState + ':' + [string]$finding.lastObserved)
    }
    $material = @(
        [string]$Snapshot.sessionId,
        [string]$Snapshot.fileGeneration,
        [string]$Snapshot.nextOffset,
        [string]$Snapshot.nextOrdinal,
        [string]$Snapshot.lastSequence,
        [string]$Snapshot.coverage,
        [string]::Join('|', $parts.ToArray())
    ) -join "`n"
    $algorithm = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hash = $algorithm.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($material))
        $shortHash = ([BitConverter]::ToString($hash)).Replace('-', '').ToLowerInvariant().Substring(0, 24)
        return ([string]$Snapshot.fileGeneration + ':' + [string]$Snapshot.nextOffset + ':' + $shortHash)
    }
    finally { $algorithm.Dispose() }
}

function ConvertFrom-MihariFindingProjectionCursor {
    param([Parameter(Mandatory = $true)][string]$Cursor)
    if ($Cursor.Length -gt 4096) { throw (New-MihariFindingProjectionError -Code 'cursor_invalidated' -Message 'The findings cursor is invalid; restart from the first page.') }
    try {
        $json = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Cursor))
        $payload = ConvertFrom-Json -InputObject $json -ErrorAction Stop
    }
    catch {
        throw (New-MihariFindingProjectionError -Code 'cursor_invalidated' -Message 'The findings cursor is invalid; restart from the first page.' -InnerException $_.Exception)
    }
    return $payload
}

function New-MihariFindingProjectionCursor {
    param(
        [Parameter(Mandatory = $true)][object]$Snapshot,
        [Parameter(Mandatory = $true)][string]$Revision,
        [Parameter(Mandatory = $true)][int]$Position
    )
    $payload = [pscustomobject][ordered]@{
        schemaVersion = 1
        sessionId = [string]$Snapshot.sessionId
        fileGeneration = [string]$Snapshot.fileGeneration
        sequence = [long]$Snapshot.lastSequence
        offset = [long]$Snapshot.nextOffset
        revision = $Revision
        position = $Position
    }
    $json = ConvertTo-Json -InputObject $payload -Depth 4 -Compress
    return [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($json))
}

function Get-MihariPersistentFindings {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$SessionId,
        [Parameter(Mandatory = $true)][object]$ProjectionStore,
        [Parameter(Mandatory = $true)][string]$SnapshotPath,
        [Parameter(Mandatory = $false)][ValidateRange(1, 200)][int]$Limit = 100,
        [Parameter(Mandatory = $false)][AllowNull()][string]$Cursor
    )

    $safeSessionId = ConvertTo-MihariDiagnosisSafeText -Value $SessionId
    if ($null -eq $safeSessionId) { throw [System.ArgumentException]::new('A session ID is required to load persistent findings.') }
    $storeSessionId = Get-MihariFindingProjectionValue -InputObject $ProjectionStore -Name 'SessionId'
    if ($null -ne $storeSessionId -and -not [string]::Equals([string]$storeSessionId, $safeSessionId, [StringComparison]::Ordinal)) {
        throw [System.ArgumentException]::new('The projection store belongs to a different session.')
    }
    if ([string]::IsNullOrWhiteSpace($SnapshotPath)) { throw [System.ArgumentException]::new('A findings snapshot path is required.') }

    $mutex = $null
    $lockAcquired = $false
    try {
        try {
            $mutexName = Get-MihariFindingProjectionLockName -SnapshotPath $SnapshotPath
            $mutex = [System.Threading.Mutex]::new($false, $mutexName)
        }
        catch {
            throw (New-MihariFindingProjectionError -Code 'finding_snapshot_lock_error' -Message 'Could not create the findings snapshot lock.' -InnerException $_.Exception)
        }
        try { $lockAcquired = $mutex.WaitOne(15000) }
        catch [System.Threading.AbandonedMutexException] {
            $lockAcquired = $true
            Write-Verbose 'Recovered the findings snapshot lock after an interrupted writer; the atomic snapshot will be checked and rebuilt if needed.'
        }
        if (-not $lockAcquired) { throw (New-MihariFindingProjectionError -Code 'finding_snapshot_busy' -Message 'The findings snapshot is busy; retry the query.') }

        $fullSnapshotPath = [System.IO.Path]::GetFullPath($SnapshotPath)
        $disk = Read-MihariFindingProjectionSnapshot -Path $fullSnapshotPath -SessionId $safeSessionId
        $previousSnapshot = $disk.snapshot
        $forceHistoryGap = $false
        $startOffset = 0L
        $startOrdinal = 0L
        $expectedGeneration = Get-MihariFindingProjectionValue -InputObject $ProjectionStore -Name 'GenerationId'
        $coverageState = 'unknown'
        $coverageBeforePending = $null
        $coverageCanStartObserved = $true

        if ($null -ne $previousSnapshot -and -not $disk.foreignSession) {
            $savedOffset = 0L
            $savedOrdinal = 0L
            [void][long]::TryParse([string]$previousSnapshot.nextOffset, [ref]$savedOffset)
            [void][long]::TryParse([string]$previousSnapshot.nextOrdinal, [ref]$savedOrdinal)
            $startOffset = $savedOffset
            $startOrdinal = $savedOrdinal
            $expectedGeneration = [string]$previousSnapshot.fileGeneration
            $priorCoverage = [string]$previousSnapshot.coverage
            $priorFindings = @(Get-MihariFindingProjectionValue -InputObject $previousSnapshot -Name 'findings')
            $hasPriorHistory = ($savedOffset -gt 0 -or [long]$previousSnapshot.lastSequence -gt 0 -or $priorFindings.Count -gt 0)
            $coverageState = $priorCoverage
            $coverageCanStartObserved = -not $hasPriorHistory
            $coverageBeforePending = Get-MihariFindingProjectionValue -InputObject $previousSnapshot -Name 'coverageBeforePending'
            if ([bool]$previousSnapshot.projectionPending -and -not [string]::IsNullOrWhiteSpace([string]$coverageBeforePending)) {
                $coverageState = [string]$coverageBeforePending
            }
        }
        elseif ($disk.foreignSession) {
            $startOffset = 0L
            $startOrdinal = 0L
        }

        $maximumBatches = 16
        $batchNumber = 0
        $projectionPending = $false
        $anyBatch = $false
        $cursorReset = $false
        $offset = $startOffset
        $ordinal = $startOrdinal
        $workingSnapshot = $previousSnapshot
        $nextWindow = $true
        while ($nextWindow -and $batchNumber -lt $maximumBatches) {
            $arguments = @{
                Store = $ProjectionStore
                AfterOffset = [long]$offset
                AfterOrdinal = [long]$ordinal
                Limit = 1000
                MaximumBytes = 4194304
            }
            if (-not [string]::IsNullOrWhiteSpace([string]$expectedGeneration)) { $arguments['ExpectedFileGeneration'] = [string]$expectedGeneration }
            $window = $null
            try { $window = Get-MihariTrafficProjectionEvents @arguments }
            catch {
                $failure = $_.Exception
                $mihariCode = [string]$failure.Data['mihariCode']
                if ($mihariCode -ne 'cursor_invalidated' -or $cursorReset) { throw }
                $currentGeneration = Get-MihariFindingProjectionValue -InputObject $ProjectionStore -Name 'GenerationId'
                if ([string]::Equals([string]$currentGeneration, [string]$expectedGeneration, [StringComparison]::Ordinal)) { $forceHistoryGap = $true }
                $expectedGeneration = [string]$currentGeneration
                $offset = 0L
                $ordinal = 0L
                $cursorReset = $true
                $nextWindow = $true
                continue
            }

            $anyBatch = $true
            $batchNumber++
            $events = @($window.events | ForEach-Object { $_.event } | Where-Object { $null -ne $_ })
            $firstSequence = 0L
            $lastSequence = 0L
            if ($null -ne $window.firstSequence) { [void][long]::TryParse([string]$window.firstSequence, [ref]$firstSequence) }
            if ($null -ne $window.lastSequence) { [void][long]::TryParse([string]$window.lastSequence, [ref]$lastSequence) }
            $malformedLineCount = 0
            if ($null -ne $window.malformedLineCount) {
                $malformedLong = 0L
                if ([long]::TryParse([string]$window.malformedLineCount, [ref]$malformedLong)) {
                    $malformedLineCount = [int][Math]::Min([long][int]::MaxValue, [Math]::Max(0L, $malformedLong))
                }
            }
            $readError = $null
            if ($null -ne $window.readError) {
                if ($window.readError -is [bool]) {
                    if ($window.readError) { $readError = 'projection_read_error' }
                }
                elseif (-not [string]::IsNullOrWhiteSpace([string]$window.readError) -and [string]$window.readError -ne 'false') {
                    $readError = [string]$window.readError
                }
            }
            $coverage = 'unknown'
            $storeCounters = Get-MihariFindingProjectionValue -InputObject $ProjectionStore -Name 'Counters'
            $lostPartial = [long](Get-MihariFindingProjectionValue -InputObject $storeCounters -Name 'LostPartialLineCount')
            $unprojectable = [long](Get-MihariFindingProjectionValue -InputObject $storeCounters -Name 'UnprojectableLineCount')
            $sequenceViolations = [long](Get-MihariFindingProjectionValue -InputObject $storeCounters -Name 'SequenceViolationCount')
            $sourceMalformed = [long](Get-MihariFindingProjectionValue -InputObject $storeCounters -Name 'MalformedLineCount')
            $rotationCount = [long](Get-MihariFindingProjectionValue -InputObject $storeCounters -Name 'RotationCount')
            $historyGapDetected = $forceHistoryGap -or $rotationCount -gt 0 -or $malformedLineCount -gt 0 -or $lostPartial -gt 0 -or $unprojectable -gt 0 -or $sequenceViolations -gt 0 -or $sourceMalformed -gt 0
            if ($historyGapDetected -or -not [string]::IsNullOrWhiteSpace($readError)) { $coverage = 'truncated' }
            elseif ($events.Count -gt 0) {
                $batchCoverageObserved = $true
                foreach ($event in $events) {
                    if ([string](Get-MihariFindingProjectionValue -InputObject $event -Name 'coverage') -ne 'observed') { $batchCoverageObserved = $false; break }
                }
                if ($batchCoverageObserved) { $coverage = 'observed' }
            }

            $workingSnapshot = Update-MihariFindingSnapshot -Events $events -PreviousSnapshot $workingSnapshot -SessionId $safeSessionId `
                -FileGeneration ([string]$window.fileGeneration) -FirstSequence $firstSequence -LastSequence $lastSequence `
                -Coverage $coverage -MalformedLineCount $malformedLineCount -ReadError $readError -HistoryGapDetected:($historyGapDetected)
            $workingSnapshot | Add-Member -MemberType NoteProperty -Name nextOffset -Value ([long]$window.nextOffset) -Force
            $workingSnapshot | Add-Member -MemberType NoteProperty -Name nextOrdinal -Value ([long]$window.nextOrdinal) -Force
            $workingSnapshot | Add-Member -MemberType NoteProperty -Name rebuiltSnapshot -Value ([bool]$disk.invalid) -Force
            $workingSnapshot | Add-Member -MemberType NoteProperty -Name foreignSnapshotIgnored -Value ([bool]$disk.foreignSession) -Force
            $workingSnapshot | Add-Member -MemberType NoteProperty -Name lastSequence -Value ([long]$workingSnapshot.lastSequence) -Force
            if ($historyGapDetected) {
                $coverageState = 'truncated'
                $coverageBeforePending = $null
            }
            elseif ($coverage -eq 'unknown' -and $events.Count -gt 0) {
                $coverageCanStartObserved = $false
                $coverageState = 'unknown'
                $coverageBeforePending = $null
            }
            elseif ($coverage -eq 'observed' -and $coverageCanStartObserved) {
                $coverageState = 'observed'
                $coverageCanStartObserved = $false
            }
            $expectedGeneration = [string]$window.fileGeneration
            $newOffset = [long]$window.nextOffset
            $newOrdinal = [long]$window.nextOrdinal
            $hasMore = [bool]$window.hasMore
            $pending = [bool]$window.pending
            if ($hasMore -and $newOffset -le $offset) {
                throw (New-MihariFindingProjectionError -Code 'projection_progress_stalled' -Message 'The indexed event projection did not advance its byte offset.')
            }
            $offset = $newOffset
            $ordinal = $newOrdinal
            $sourcePendingBytes = [long](Get-MihariFindingProjectionValue -InputObject $ProjectionStore -Name 'PendingBytes')
            $sourceDiscarding = [bool](Get-MihariFindingProjectionValue -InputObject $ProjectionStore -Name 'DiscardingLine')
            $projectionPending = $hasMore -or $pending -or $sourcePendingBytes -gt 0 -or $sourceDiscarding -or [bool](Get-MihariFindingProjectionValue -InputObject $ProjectionStore -Name 'Backlog')
            $nextWindow = $hasMore
        }

        if (-not $anyBatch) {
            $currentGeneration = Get-MihariFindingProjectionValue -InputObject $ProjectionStore -Name 'GenerationId'
            $workingSnapshot = Update-MihariFindingSnapshot -Events @() -PreviousSnapshot $previousSnapshot -SessionId $safeSessionId `
                -FileGeneration ([string]$currentGeneration) -Coverage $(if ($forceHistoryGap) { 'truncated' } else { 'unknown' }) `
                -HistoryGapDetected:($forceHistoryGap)
            $workingSnapshot | Add-Member -MemberType NoteProperty -Name nextOffset -Value ([long]$startOffset) -Force
            $workingSnapshot | Add-Member -MemberType NoteProperty -Name nextOrdinal -Value ([long]$startOrdinal) -Force
            $workingSnapshot | Add-Member -MemberType NoteProperty -Name rebuiltSnapshot -Value ([bool]$disk.invalid) -Force
            $workingSnapshot | Add-Member -MemberType NoteProperty -Name foreignSnapshotIgnored -Value ([bool]$disk.foreignSession) -Force
            $sourcePendingBytes = [long](Get-MihariFindingProjectionValue -InputObject $ProjectionStore -Name 'PendingBytes')
            $sourceDiscarding = [bool](Get-MihariFindingProjectionValue -InputObject $ProjectionStore -Name 'DiscardingLine')
            $projectionPending = $sourcePendingBytes -gt 0 -or $sourceDiscarding -or [bool](Get-MihariFindingProjectionValue -InputObject $ProjectionStore -Name 'Backlog')
        }

        if ($workingSnapshot.historyGap) {
            $coverageState = 'truncated'
            $coverageBeforePending = $null
        }
        elseif ($projectionPending) {
            if ($coverageState -ne 'unknown') { $coverageBeforePending = $coverageState }
            $coverageState = 'unknown'
        }
        elseif (-not [string]::IsNullOrWhiteSpace([string]$coverageBeforePending)) {
            $coverageState = [string]$coverageBeforePending
            $coverageBeforePending = $null
        }
        $workingSnapshot.coverage = $coverageState
        $workingSnapshot | Add-Member -MemberType NoteProperty -Name coverageBeforePending -Value $coverageBeforePending -Force
        $workingSnapshot | Add-Member -MemberType NoteProperty -Name projectionPending -Value ([bool]$projectionPending) -Force
        $workingSnapshot | Add-Member -MemberType NoteProperty -Name nextOffset -Value ([long]$offset) -Force
        $workingSnapshot | Add-Member -MemberType NoteProperty -Name nextOrdinal -Value ([long]$ordinal) -Force

        Write-MihariFindingProjectionSnapshotAtomic -Path $fullSnapshotPath -Snapshot $workingSnapshot
        $revision = Get-MihariFindingProjectionRevision -Snapshot $workingSnapshot
        $allFindings = @($workingSnapshot.findings | Sort-Object -Property findingId)
        $position = 0
        if (-not [string]::IsNullOrWhiteSpace($Cursor)) {
            $cursorData = ConvertFrom-MihariFindingProjectionCursor -Cursor $Cursor
            $cursorPosition = 0
            $cursorOffset = -1L
            $cursorSequence = -1L
            $cursorSchemaVersion = 0
            $cursorSchemaValid = [int]::TryParse([string]$cursorData.schemaVersion, [ref]$cursorSchemaVersion)
            if (-not $cursorSchemaValid -or $cursorSchemaVersion -ne 1 -or -not [string]::Equals([string]$cursorData.sessionId, $safeSessionId, [StringComparison]::Ordinal) -or
                    -not [string]::Equals([string]$cursorData.fileGeneration, [string]$workingSnapshot.fileGeneration, [StringComparison]::Ordinal) -or
                    -not [string]::Equals([string]$cursorData.revision, $revision, [StringComparison]::Ordinal) -or
                    -not [int]::TryParse([string]$cursorData.position, [ref]$cursorPosition) -or $cursorPosition -lt 0 -or $cursorPosition -gt $allFindings.Count -or
                    -not [long]::TryParse([string]$cursorData.offset, [ref]$cursorOffset) -or $cursorOffset -ne [long]$workingSnapshot.nextOffset -or
                    -not [long]::TryParse([string]$cursorData.sequence, [ref]$cursorSequence) -or $cursorSequence -ne [long]$workingSnapshot.lastSequence) {
                throw (New-MihariFindingProjectionError -Code 'cursor_invalidated' -Message 'The findings list changed; restart from the first page.')
            }
            $position = $cursorPosition
        }

        $endPosition = [Math]::Min($allFindings.Count, $position + $Limit)
        $items = @()
        if ($endPosition -gt $position) { $items = @($allFindings[$position..($endPosition - 1)]) }
        $nextCursor = $null
        if ($endPosition -lt $allFindings.Count) {
            $nextCursor = New-MihariFindingProjectionCursor -Snapshot $workingSnapshot -Revision $revision -Position $endPosition
        }

        $classificationCounts = [ordered]@{}
        $openCount = 0
        $resolvedCount = 0
        $unclassifiedCount = 0
        $toolFailureCount = 0
        $missingEvidenceCount = 0
        foreach ($finding in $allFindings) {
            $classification = [string]$finding.classification
            if ([string]::IsNullOrWhiteSpace($classification)) { $classification = 'unknown' }
            if (-not $classificationCounts.Contains($classification)) { $classificationCounts[$classification] = 0 }
            $classificationCounts[$classification] = [int]$classificationCounts[$classification] + 1
            if ([string]$finding.resolutionState -eq 'resolved') { $resolvedCount++ }
            else { $openCount++ }
            if ([string]$finding.code -eq 'unclassified_failure') { $unclassifiedCount++ }
            if ([string]$finding.classification -in @('observer_health', 'cleanup')) { $toolFailureCount++ }
            if ([string]$finding.evidenceAvailability -in @('unverified', 'possibly_rotated', 'possibly_missing')) { $missingEvidenceCount++ }
        }
        $freshnessUtc = Get-MihariFindingProjectionValue -InputObject $ProjectionStore -Name 'FreshnessUtc'
        return [pscustomobject][ordered]@{
            items = @($items)
            nextCursor = $nextCursor
            revision = $revision
            ordering = 'findingId_ascending'
            scopeTotal = $allFindings.Count
            coverage = [string]$workingSnapshot.coverage
            freshnessUtc = $freshnessUtc
            projectionPending = [bool]$projectionPending
            counts = [pscustomobject][ordered]@{
                sessionTotal = $allFindings.Count
                currentFilter = $allFindings.Count
                loadedPage = $items.Count
                open = $openCount
                resolved = $resolvedCount
                unclassifiedTrafficFailures = $unclassifiedCount
                toolFailures = $toolFailureCount
                missingEvidence = $missingEvidenceCount
                byClassification = [pscustomobject]$classificationCounts
            }
        }
    }
    finally {
        if ($lockAcquired -and $null -ne $mutex) { $mutex.ReleaseMutex() }
        if ($null -ne $mutex) { $mutex.Dispose() }
    }
}
