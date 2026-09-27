# File-backed operator records for cases, trials, markers, notes, and
# necessity confirmations. Canonical traffic facts remain in events.jsonl.

function Get-MihariCaseField {
    param(
        [AllowNull()][object] $InputObject,
        [Parameter(Mandatory = $true)][string[]] $Names
    )

    if ($null -eq $InputObject) { return $null }
    foreach ($name in $Names) {
        if ($InputObject -is [System.Collections.IDictionary]) {
            foreach ($key in $InputObject.Keys) {
                if ([string]::Equals([string]$key, $name, [System.StringComparison]::OrdinalIgnoreCase)) {
                    return $InputObject[$key]
                }
            }
        }
        else {
            $property = $InputObject.PSObject.Properties[$name]
            if ($null -ne $property) { return $property.Value }
        }
    }
    return $null
}

function ConvertTo-MihariCaseSafeText {
    param(
        [AllowNull()][object] $Value,
        [ValidateRange(1, 8192)][int] $MaximumLength = 512,
        [switch] $AllowLineBreaks
    )

    if ($null -eq $Value -or $Value -is [System.Collections.IDictionary] -or $Value -is [System.Array]) { return $null }
    $text = [string]$Value
    if (Get-Command ConvertTo-MihariSafeText -ErrorAction SilentlyContinue) {
        $text = ConvertTo-MihariSafeText -Text $text
    }
    else {
        $text = [regex]::Replace($text, '(?im)\b(authorization|proxy-authorization|cookie|set-cookie)\s*:\s*[^\r\n]*', '$1: [REDACTED]')
        $text = [regex]::Replace($text, '(?i)(authorization|proxy-authorization|cookie|set-cookie)\s*=\s*[^,\r\n]+', '$1=[REDACTED]')
        $text = [regex]::Replace($text, '([?&][^=&#\s]+)=([^&#\s]*)', '$1=[REDACTED]')
        $text = [regex]::Replace($text, '(?i)(https?://)[^/\s?#@]+@', '$1[REDACTED]@')
    }
    $text = [regex]::Replace($text, '([?&])([^=&#\s]+)=([^&#\s]*)', '$1$2=[REDACTED]')
    $text = [regex]::Replace($text, '([?&])([^=&#\s]+)(?=(&|#|\s|$))', '$1[REDACTED]')
    $text = [regex]::Replace($text, '(?i)(["'']?(?:authorization|proxy-authorization|cookie|set-cookie|password|token|secret|client_secret)["'']?\s*[:=]\s*["'']?)[^,\s}"'']+', '$1[REDACTED]')
    if ($AllowLineBreaks) {
        $text = [regex]::Replace($text, '[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', ' ')
    }
    else {
        $text = [regex]::Replace($text, '[\x00-\x1f\x7f]', ' ')
    }
    $text = $text.Trim()
    if ($text.Length -gt $MaximumLength) { $text = $text.Substring(0, $MaximumLength) }
    if ($text.Length -eq 0) { return $null }
    return $text
}

function ConvertTo-MihariCaseSafeValue {
    param(
        [AllowNull()][object] $Value,
        [int] $Depth = 0,
        [Parameter(Mandatory = $true)][ref] $RedactedCount
    )

    if ($null -eq $Value) { return $null }
    if ($Depth -gt 6) {
        $RedactedCount.Value = [int]$RedactedCount.Value + 1
        return '[OMITTED: depth limit]'
    }
    if ($Value -is [string] -or $Value -is [char] -or $Value.GetType().IsEnum -or
        $Value -is [DateTime] -or $Value -is [DateTimeOffset] -or $Value -is [Guid] -or $Value -is [Uri]) {
        if ($Value -is [DateTime]) { return $Value.ToUniversalTime().ToString('o', [Globalization.CultureInfo]::InvariantCulture) }
        if ($Value -is [DateTimeOffset]) { return $Value.ToUniversalTime().ToString('o', [Globalization.CultureInfo]::InvariantCulture) }
        $safeText = ConvertTo-MihariCaseSafeText -Value ([string]$Value) -MaximumLength 2048
        if ($null -eq $safeText) { return '' }
        return $safeText
    }
    if ($Value -is [bool]) { return $Value }
    if ($Value -is [byte] -or $Value -is [sbyte] -or $Value -is [int16] -or $Value -is [uint16] -or
        $Value -is [int32] -or $Value -is [uint32] -or $Value -is [int64] -or $Value -is [uint64] -or
        $Value -is [decimal] -or $Value -is [single] -or $Value -is [double]) {
        if (($Value -is [double] -or $Value -is [single]) -and ([double]::IsNaN([double]$Value) -or [double]::IsInfinity([double]$Value))) {
            $RedactedCount.Value = [int]$RedactedCount.Value + 1
            return $null
        }
        return $Value
    }
    if ($Value -is [System.Collections.IDictionary] -or $Value -is [pscustomobject]) {
        $pairs = New-Object 'System.Collections.Generic.List[object]'
        if ($Value -is [System.Collections.IDictionary]) {
            foreach ($key in $Value.Keys) { $pairs.Add([pscustomobject]@{ Name = [string]$key; Value = $Value[$key] }) }
        }
        else {
            foreach ($property in $Value.PSObject.Properties) { $pairs.Add([pscustomobject]@{ Name = [string]$property.Name; Value = $property.Value }) }
        }
        $result = [ordered]@{}
        $accepted = 0
        foreach ($pair in @($pairs.ToArray() | Sort-Object -Property Name)) {
            if ($accepted -ge 100) {
                $RedactedCount.Value = [int]$RedactedCount.Value + 1
                break
            }
            $name = [regex]::Replace([string]$pair.Name, '[^A-Za-z0-9_.-]', '')
            if ($name.Length -eq 0) { continue }
            if ($name.Length -gt 64) { $name = $name.Substring(0, 64) }
            if ($name -match '(?i)(authorization|cookie|password|secret|token|credential|private.?key|debugger|control.?url|headers?|body|client.?cert)' ) {
                $RedactedCount.Value = [int]$RedactedCount.Value + 1
                continue
            }
            $result[$name] = ConvertTo-MihariCaseSafeValue -Value $pair.Value -Depth ($Depth + 1) -RedactedCount $RedactedCount
            $accepted++
        }
        return $result
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        $result = New-Object 'System.Collections.Generic.List[object]'
        $accepted = 0
        foreach ($item in $Value) {
            if ($accepted -ge 100) {
                $RedactedCount.Value = [int]$RedactedCount.Value + 1
                break
            }
            $result.Add((ConvertTo-MihariCaseSafeValue -Value $item -Depth ($Depth + 1) -RedactedCount $RedactedCount))
            $accepted++
        }
        return ,@($result.ToArray())
    }
    $RedactedCount.Value = [int]$RedactedCount.Value + 1
    return $null
}

function Enter-MihariCaseStoreLock {
    param([Parameter(Mandatory = $true)][string] $CaseRoot)

    $root = [System.IO.Path]::GetFullPath($CaseRoot)
    [void][System.IO.Directory]::CreateDirectory($root)
    $lockPath = Join-Path $root '.operator.lock'
    $lastError = $null
    for ($attempt = 0; $attempt -lt 80; $attempt++) {
        try {
            return [System.IO.File]::Open($lockPath, [System.IO.FileMode]::OpenOrCreate,
                [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
        }
        catch [System.IO.IOException] {
            $lastError = $_.Exception
            Start-Sleep -Milliseconds 25
        }
    }
    throw ('Timed out acquiring the Mihari case-store lock: {0}' -f $lastError.Message)
}

function Write-MihariCaseStoreJsonAtomic {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][object] $Value
    )

    $directory = [System.IO.Path]::GetDirectoryName($Path)
    if (-not [System.IO.Directory]::Exists($directory)) { [void][System.IO.Directory]::CreateDirectory($directory) }
    $temporaryPath = $Path + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
    $backupPath = $Path + '.' + [Guid]::NewGuid().ToString('N') + '.bak'
    $json = ConvertTo-Json -InputObject $Value -Depth 8 -Compress -ErrorAction Stop
    $encoding = New-Object System.Text.UTF8Encoding($false)
    try {
        [System.IO.File]::WriteAllText($temporaryPath, $json + [Environment]::NewLine, $encoding)
        if ([System.IO.File]::Exists($Path)) { [System.IO.File]::Replace($temporaryPath, $Path, $backupPath) }
        else { [System.IO.File]::Move($temporaryPath, $Path) }
    }
    finally {
        if ([System.IO.File]::Exists($temporaryPath)) { [System.IO.File]::Delete($temporaryPath) }
        if ([System.IO.File]::Exists($backupPath)) { [System.IO.File]::Delete($backupPath) }
    }
}

function Initialize-MihariCaseStore {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][Alias('OutputDirectory', 'StoreRoot')][string] $CaseRoot)

    $root = [System.IO.Path]::GetFullPath($CaseRoot)
    [void][System.IO.Directory]::CreateDirectory($root)
    $lock = Enter-MihariCaseStoreLock -CaseRoot $root
    try {
        $manifestPath = Join-Path $root 'case-store.json'
        if ([System.IO.File]::Exists($manifestPath)) {
            $manifestText = [System.IO.File]::ReadAllText($manifestPath, [System.Text.Encoding]::UTF8)
            $manifest = ConvertFrom-Json -InputObject $manifestText -ErrorAction Stop
            if ([int]$manifest.schemaVersion -ne 1 -or [string]$manifest.kind -ne 'mihari.case-store') {
                throw 'The Mihari case store uses an unsupported manifest version or kind.'
            }
        }
        else {
            $manifest = [ordered]@{
                schemaVersion = 1
                kind = 'mihari.case-store'
                createdAtUtc = [DateTime]::UtcNow.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
                journalFile = 'operator.jsonl'
            }
            Write-MihariCaseStoreJsonAtomic -Path $manifestPath -Value $manifest
        }
        $journalPath = Join-Path $root 'operator.jsonl'
        if (-not [System.IO.File]::Exists($journalPath)) {
            $stream = [System.IO.File]::Open($journalPath, [System.IO.FileMode]::CreateNew,
                [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)
            $stream.Dispose()
        }
        return [pscustomobject]@{ caseRoot = $root; manifestPath = $manifestPath; journalPath = $journalPath; schemaVersion = 1 }
    }
    finally { $lock.Dispose() }
}

function Read-MihariCaseJournalUnlocked {
    param([Parameter(Mandatory = $true)][string] $CaseRoot)

    $journalPath = Join-Path ([System.IO.Path]::GetFullPath($CaseRoot)) 'operator.jsonl'
    $records = New-Object 'System.Collections.Generic.List[object]'
    $result = [pscustomobject]@{ Records = @(); MalformedLineCount = 0; UnknownRecordCount = 0; TruncatedFinalLine = $false; ReadError = $null }
    if (-not [System.IO.File]::Exists($journalPath)) { return $result }
    $file = $null
    $reader = $null
    try {
        $file = [System.IO.File]::Open($journalPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
        if ($file.Length -gt 33554432) { throw 'The Mihari case journal exceeds its 32 MiB read limit.' }
        $reader = New-Object System.IO.StreamReader($file, [System.Text.Encoding]::UTF8, $true)
        $text = $reader.ReadToEnd()
        $lastNewline = $text.LastIndexOf("`n")
        if ($lastNewline -lt 0 -and $text.Length -gt 0) {
            $result.TruncatedFinalLine = $true
            return $result
        }
        if ($lastNewline -lt $text.Length - 1) {
            $result.TruncatedFinalLine = $true
            $text = $text.Substring(0, $lastNewline + 1)
        }
        foreach ($line in $text.Split([char]"`n")) {
            $line = $line.TrimEnd("`r")
            if ([string]::IsNullOrWhiteSpace($line)) { continue }
            try {
                $record = ConvertFrom-Json -InputObject $line -ErrorAction Stop
                if ($null -eq $record -or [int]$record.schemaVersion -ne 1 -or
                    [string]::IsNullOrWhiteSpace([string]$record.recordType)) {
                    $result.UnknownRecordCount++
                    continue
                }
                $records.Add($record)
            }
            catch {
                $result.MalformedLineCount++
            }
        }
        $result.Records = @($records.ToArray())
    }
    catch {
        $result.ReadError = 'case_journal_unavailable'
        throw ('Could not read Mihari case metadata: {0}' -f $_.Exception.Message)
    }
    finally {
        if ($null -ne $reader) { $reader.Dispose() }
        elseif ($null -ne $file) { $file.Dispose() }
    }
    return $result
}

function Get-MihariCaseJournalRevision {
    param([Parameter(Mandatory = $true)][string] $CaseRoot)
    $path = Join-Path ([System.IO.Path]::GetFullPath($CaseRoot)) 'operator.jsonl'
    if (-not [System.IO.File]::Exists($path)) { return 'missing' }
    $info = [System.IO.FileInfo]::new($path)
    return ('{0}-{1}-{2}' -f $info.CreationTimeUtc.Ticks, $info.LastWriteTimeUtc.Ticks, $info.Length)
}

function Get-MihariCaseQueryPage {
    param(
        [Parameter(Mandatory = $true)][object[]] $Items,
        [Parameter(Mandatory = $true)][int] $MaximumItems,
        [Parameter(Mandatory = $true)][string] $Revision,
        [string] $Cursor
    )

    $offset = 0
    if (-not [string]::IsNullOrWhiteSpace($Cursor)) {
        if ($Cursor -notmatch '^case-v1:(?<revision>[^:]+):(?<offset>\d+)$') { throw 'The case query cursor is invalid.' }
        if (-not [string]::Equals([string]$Matches.revision, $Revision, [StringComparison]::Ordinal)) {
            throw 'The case query cursor was invalidated because the operator journal changed.'
        }
        $offset = [int]$Matches.offset
        if ($offset -lt 0 -or $offset -gt $Items.Count) { throw 'The case query cursor offset is invalid.' }
    }
    $page = @($Items | Select-Object -Skip $offset -First $MaximumItems)
    $nextCursor = $null
    if (($offset + $page.Count) -lt $Items.Count) {
        $nextCursor = 'case-v1:' + $Revision + ':' + ($offset + $page.Count).ToString([Globalization.CultureInfo]::InvariantCulture)
    }
    return [pscustomobject]@{ Items = $page; Offset = $offset; NextCursor = $nextCursor; ScopeTotal = [int]$Items.Count; Revision = $Revision }
}

function Add-MihariCaseJournalRecordUnlocked {
    param(
        [Parameter(Mandatory = $true)][string] $CaseRoot,
        [Parameter(Mandatory = $true)][object] $Record
    )

    $path = Join-Path ([System.IO.Path]::GetFullPath($CaseRoot)) 'operator.jsonl'
    $json = ConvertTo-Json -InputObject $Record -Depth 8 -Compress -ErrorAction Stop
    $encoding = New-Object System.Text.UTF8Encoding($false)
    $bytes = $encoding.GetBytes($json + [Environment]::NewLine)
    $stream = $null
    try {
        $stream = [System.IO.File]::Open($path, [System.IO.FileMode]::Append,
            [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush()
    }
    finally { if ($null -ne $stream) { $stream.Dispose() } }
}

function New-MihariCaseId {
    return 'case-' + [Guid]::NewGuid().ToString('N')
}

function New-MihariTrialId {
    return 'trial-' + [Guid]::NewGuid().ToString('N')
}

function Test-MihariCaseId {
    param([AllowNull()][string] $CaseId)
    return ($null -ne $CaseId -and $CaseId -match '^case-[0-9a-fA-F]{32}$')
}

function Test-MihariTrialId {
    param([AllowNull()][string] $TrialId)
    return ($null -ne $TrialId -and $TrialId -match '^trial-[0-9a-fA-F]{32}$')
}

function Get-MihariCaseStoreSnapshotUnlocked {
    param([Parameter(Mandatory = $true)][string] $CaseRoot)

    $journal = Read-MihariCaseJournalUnlocked -CaseRoot $CaseRoot
    $casesById = @{}
    $trialsById = @{}
    $markers = New-Object 'System.Collections.Generic.List[object]'
    $notes = New-Object 'System.Collections.Generic.List[object]'
    $necessity = @{}
    foreach ($record in $journal.Records) {
        switch ([string]$record.recordType) {
            'case' {
                if (-not (Test-MihariCaseId -CaseId ([string]$record.caseId))) { continue }
                $casesById[[string]$record.caseId] = $record
            }
            'trial' {
                if (-not (Test-MihariTrialId -TrialId ([string]$record.trialId))) { continue }
                $trialsById[[string]$record.trialId] = [pscustomobject]@{ Base = $record; Latest = $record }
                if ($null -ne $record.startMarker) { $markers.Add($record.startMarker) }
            }
            'trial-update' {
                $trialKey = [string]$record.trialId
                if ($trialsById.ContainsKey($trialKey)) {
                    $existing = $trialsById[$trialKey]
                    $trialsById[$trialKey] = [pscustomobject]@{ Base = $existing.Base; Latest = $record }
                    if ($null -ne $record.endMarker) { $markers.Add($record.endMarker) }
                }
            }
            'marker' { $markers.Add($record) }
            'note' { $notes.Add($record) }
            'necessity' { $necessity[[string]$record.dependencyId] = $record }
        }
    }

    $trials = New-Object 'System.Collections.Generic.List[object]'
    foreach ($trialId in @($trialsById.Keys | Sort-Object)) {
        $parts = $trialsById[$trialId]
        $base = $parts.Base
        $latest = $parts.Latest
        $trial = [ordered]@{
            schemaVersion = 1
            trialId = [string]$base.trialId
            caseId = [string]$base.caseId
            sessionId = [string]$base.sessionId
            startedAtUtc = [string]$base.startedAtUtc
            startMarkerId = [string]$base.startMarkerId
            profile = $base.profile
            profileRedactedFields = [int]$base.profileRedactedFields
            configurationRevision = $base.configurationRevision
            environmentReference = $base.environmentReference
            status = 'running'
            endedAtUtc = $null
            endMarkerId = $null
            operatorBusinessOutcome = 'unknown'
            revision = [int]$base.revision
        }
        if ($null -ne $latest -and [string]$latest.recordType -eq 'trial-update') {
            $trial['status'] = 'complete'
            $trial['endedAtUtc'] = [string]$latest.endedAtUtc
            $trial['endMarkerId'] = [string]$latest.endMarkerId
            $trial['operatorBusinessOutcome'] = [string]$latest.operatorBusinessOutcome
            $trial['revision'] = [int]$latest.revision
        }
        $trial['markers'] = @($markers.ToArray() | Where-Object { [string]$_.trialId -eq [string]$trial.trialId } | Sort-Object -Property timestampUtc, markerId)
        $trial['notes'] = @($notes.ToArray() | Where-Object { [string]$_.trialId -eq [string]$trial.trialId } | Sort-Object -Property createdAtUtc, noteId)
        $trials.Add([pscustomobject]$trial)
    }
    $caseItems = New-Object 'System.Collections.Generic.List[object]'
    foreach ($caseId in @($casesById.Keys | Sort-Object)) {
        $base = $casesById[$caseId]
        $caseTrials = @($trials.ToArray() | Where-Object { [string]$_.caseId -eq $caseId })
        $sessionReferences = New-Object 'System.Collections.Generic.List[string]'
        foreach ($sessionReference in @($base.sessionReferences)) {
            $safeSession = ConvertTo-MihariCaseSafeText -Value $sessionReference -MaximumLength 128
            if ($null -ne $safeSession -and -not $sessionReferences.Contains($safeSession)) { $sessionReferences.Add($safeSession) }
        }
        foreach ($trial in $caseTrials) {
            if (-not [string]::IsNullOrWhiteSpace([string]$trial.sessionId) -and -not $sessionReferences.Contains([string]$trial.sessionId)) {
                $sessionReferences.Add([string]$trial.sessionId)
            }
        }
        $case = [pscustomobject]@{
            schemaVersion = 1
            caseId = [string]$base.caseId
            title = [string]$base.title
            createdAtUtc = [string]$base.createdAtUtc
            updatedAtUtc = [string]$base.updatedAtUtc
            revision = [int]$base.revision
            sessionReferences = @($sessionReferences.ToArray())
            trialReferences = @($caseTrials | ForEach-Object { [string]$_.trialId })
            notes = @($notes.ToArray() | Where-Object { [string]$_.caseId -eq $caseId -and [string]::IsNullOrWhiteSpace([string]$_.trialId) } | Sort-Object -Property createdAtUtc, noteId)
            trials = $caseTrials
        }
        $caseItems.Add($case)
    }
    return [pscustomobject]@{
        CaseRoot = [System.IO.Path]::GetFullPath($CaseRoot)
        JournalRevision = (Get-MihariCaseJournalRevision -CaseRoot $CaseRoot)
        Cases = @($caseItems.ToArray())
        Trials = @($trials.ToArray())
        Markers = @($markers.ToArray())
        Notes = @($notes.ToArray())
        Necessity = $necessity
        MalformedLineCount = [int]$journal.MalformedLineCount
        UnknownRecordCount = [int]$journal.UnknownRecordCount
        TruncatedFinalLine = [bool]$journal.TruncatedFinalLine
    }
}

function Get-MihariCaseStoreSnapshot {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][Alias('OutputDirectory', 'StoreRoot')][string] $CaseRoot)

    $null = Initialize-MihariCaseStore -CaseRoot $CaseRoot
    $lock = Enter-MihariCaseStoreLock -CaseRoot $CaseRoot
    try { return Get-MihariCaseStoreSnapshotUnlocked -CaseRoot $CaseRoot }
    finally { $lock.Dispose() }
}

function New-MihariCase {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][Alias('OutputDirectory', 'StoreRoot')][string] $CaseRoot,
        [Parameter(Mandatory = $true)][string] $Title,
        [string[]] $SessionReferences = @()
    )

    $safeTitle = ConvertTo-MihariCaseSafeText -Value $Title -MaximumLength 160
    if ($null -eq $safeTitle) { throw 'A non-empty case title is required.' }
    $safeSessions = New-Object 'System.Collections.Generic.List[string]'
    foreach ($sessionId in $SessionReferences) {
        $safeSession = ConvertTo-MihariCaseSafeText -Value $sessionId -MaximumLength 128
        if ($null -ne $safeSession -and -not $safeSessions.Contains($safeSession)) { $safeSessions.Add($safeSession) }
    }
    $null = Initialize-MihariCaseStore -CaseRoot $CaseRoot
    $lock = Enter-MihariCaseStoreLock -CaseRoot $CaseRoot
    try {
        $caseId = New-MihariCaseId
        $now = [DateTime]::UtcNow.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
        $record = [ordered]@{
            schemaVersion = 1; recordType = 'case'; caseId = $caseId; revision = 1
            title = $safeTitle; createdAtUtc = $now; updatedAtUtc = $now
            sessionReferences = @($safeSessions.ToArray())
        }
        Add-MihariCaseJournalRecordUnlocked -CaseRoot $CaseRoot -Record $record
        return [pscustomobject]$record
    }
    finally { $lock.Dispose() }
}

function Set-MihariCase {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][Alias('OutputDirectory', 'StoreRoot')][string] $CaseRoot,
        [Parameter(Mandatory = $true)][string] $CaseId,
        [Parameter(Mandatory = $true)][string] $Title,
        [string[]] $SessionReferences = @()
    )

    if (-not (Test-MihariCaseId -CaseId $CaseId)) { throw 'The case ID is invalid.' }
    $safeTitle = ConvertTo-MihariCaseSafeText -Value $Title -MaximumLength 160
    if ($null -eq $safeTitle) { throw 'A non-empty case title is required.' }
    $safeSessions = New-Object 'System.Collections.Generic.List[string]'
    foreach ($sessionId in $SessionReferences) {
        $safeSession = ConvertTo-MihariCaseSafeText -Value $sessionId -MaximumLength 128
        if ($null -ne $safeSession -and -not $safeSessions.Contains($safeSession)) { $safeSessions.Add($safeSession) }
    }
    $null = Initialize-MihariCaseStore -CaseRoot $CaseRoot
    $lock = Enter-MihariCaseStoreLock -CaseRoot $CaseRoot
    try {
        $snapshot = Get-MihariCaseStoreSnapshotUnlocked -CaseRoot $CaseRoot
        $existing = @($snapshot.Cases | Where-Object { [string]$_.caseId -eq $CaseId } | Select-Object -First 1)
        if ($existing.Count -eq 0) { throw 'The requested case does not exist.' }
        $now = [DateTime]::UtcNow.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
        $record = [ordered]@{
            schemaVersion = 1; recordType = 'case'; caseId = $CaseId; revision = ([int]$existing[0].revision + 1)
            title = $safeTitle; createdAtUtc = [string]$existing[0].createdAtUtc; updatedAtUtc = $now
            sessionReferences = @($safeSessions.ToArray())
        }
        Add-MihariCaseJournalRecordUnlocked -CaseRoot $CaseRoot -Record $record
        return [pscustomobject]$record
    }
    finally { $lock.Dispose() }
}

function Get-MihariCases {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][Alias('OutputDirectory', 'StoreRoot')][string] $CaseRoot,
        [ValidateRange(1, 200)][int] $MaximumItems = 200,
        [string] $Cursor
    )

    $snapshot = Get-MihariCaseStoreSnapshot -CaseRoot $CaseRoot
    $allItems = @($snapshot.Cases | Sort-Object -Property @{ Expression = { $_.updatedAtUtc }; Descending = $true }, @{ Expression = { $_.caseId }; Descending = $false })
    $revision = [string]$snapshot.JournalRevision
    $page = Get-MihariCaseQueryPage -Items $allItems -MaximumItems $MaximumItems -Revision $revision -Cursor $Cursor
    return [pscustomobject]@{
        items = @($page.Items); nextCursor = $page.NextCursor; revision = $page.Revision; ordering = 'updatedAtUtc:desc,caseId:asc'
        scopeTotal = [int]$page.ScopeTotal; coverage = $(if ($snapshot.MalformedLineCount -gt 0 -or $snapshot.TruncatedFinalLine) { 'incomplete' } else { 'observed' })
        freshnessUtc = [DateTime]::UtcNow.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
        malformedLineCount = [int]$snapshot.MalformedLineCount; unknownRecordCount = [int]$snapshot.UnknownRecordCount
    }
}

function Get-MihariCase {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][Alias('OutputDirectory', 'StoreRoot')][string] $CaseRoot,
        [Parameter(Mandatory = $true)][string] $CaseId
    )

    if (-not (Test-MihariCaseId -CaseId $CaseId)) { throw 'The case ID is invalid.' }
    $snapshot = Get-MihariCaseStoreSnapshot -CaseRoot $CaseRoot
    $case = @($snapshot.Cases | Where-Object { [string]$_.caseId -eq $CaseId } | Select-Object -First 1)
    if ($case.Count -eq 0) { return $null }
    return $case[0]
}

function Get-MihariTrial {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][Alias('OutputDirectory', 'StoreRoot')][string] $CaseRoot,
        [Parameter(Mandatory = $true)][string] $TrialId
    )
    if (-not (Test-MihariTrialId -TrialId $TrialId)) { throw 'The trial ID is invalid.' }
    $snapshot = Get-MihariCaseStoreSnapshot -CaseRoot $CaseRoot
    $matches = @($snapshot.Trials | Where-Object { [string]$_.trialId -eq $TrialId } | Select-Object -First 1)
    if ($matches.Count -eq 0) { return $null }
    return $matches[0]
}

function Get-MihariTrials {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][Alias('OutputDirectory', 'StoreRoot')][string] $CaseRoot,
        [string] $CaseId,
        [string] $SessionId,
        [ValidateRange(1, 200)][int] $MaximumItems = 200,
        [string] $Cursor
    )

    if ($CaseId -and -not (Test-MihariCaseId -CaseId $CaseId)) { throw 'The case ID is invalid.' }
    $snapshot = Get-MihariCaseStoreSnapshot -CaseRoot $CaseRoot
    $allItems = @($snapshot.Trials | Where-Object {
            (-not $CaseId -or [string]$_.caseId -eq $CaseId) -and
            (-not $SessionId -or [string]$_.sessionId -eq $SessionId)
        } | Sort-Object -Property @{ Expression = { $_.startedAtUtc }; Descending = $true }, @{ Expression = { $_.trialId }; Descending = $false })
    $revision = [string]$snapshot.JournalRevision
    $page = Get-MihariCaseQueryPage -Items $allItems -MaximumItems $MaximumItems -Revision $revision -Cursor $Cursor
    return [pscustomobject]@{
        items = @($page.Items); nextCursor = $page.NextCursor; revision = $page.Revision
        ordering = 'startedAtUtc:desc,trialId:asc'; scopeTotal = [int]$page.ScopeTotal; coverage = 'observed'
        freshnessUtc = [DateTime]::UtcNow.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
    }
}

function Get-MihariMarkers {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][Alias('OutputDirectory', 'StoreRoot')][string] $CaseRoot,
        [Parameter(Mandatory = $true)][string] $TrialId,
        [ValidateRange(1, 200)][int] $MaximumItems = 200,
        [string] $Cursor
    )

    if (-not (Test-MihariTrialId -TrialId $TrialId)) { throw 'The trial ID is invalid.' }
    $snapshot = Get-MihariCaseStoreSnapshot -CaseRoot $CaseRoot
    $allItems = @($snapshot.Markers | Where-Object { [string]$_.trialId -eq $TrialId } | Sort-Object -Property timestampUtc, markerId)
    $revision = [string]$snapshot.JournalRevision
    $page = Get-MihariCaseQueryPage -Items $allItems -MaximumItems $MaximumItems -Revision $revision -Cursor $Cursor
    return [pscustomobject]@{ items = @($page.Items); nextCursor = $page.NextCursor; revision = $page.Revision; ordering = 'timestampUtc:asc,markerId:asc'; scopeTotal = [int]$page.ScopeTotal; coverage = 'observed'; freshnessUtc = [DateTime]::UtcNow.ToString('o', [Globalization.CultureInfo]::InvariantCulture) }
}

function Get-MihariCaseNotes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][Alias('OutputDirectory', 'StoreRoot')][string] $CaseRoot,
        [Parameter(Mandatory = $true)][string] $CaseId,
        [string] $TrialId,
        [ValidateRange(1, 200)][int] $MaximumItems = 200,
        [string] $Cursor
    )

    if (-not (Test-MihariCaseId -CaseId $CaseId)) { throw 'The case ID is invalid.' }
    if ($TrialId -and -not (Test-MihariTrialId -TrialId $TrialId)) { throw 'The trial ID is invalid.' }
    $snapshot = Get-MihariCaseStoreSnapshot -CaseRoot $CaseRoot
    $allItems = @($snapshot.Notes | Where-Object {
            [string]$_.caseId -eq $CaseId -and (-not $TrialId -or [string]$_.trialId -eq $TrialId)
        } | Sort-Object -Property createdAtUtc, noteId)
    $revision = [string]$snapshot.JournalRevision
    $page = Get-MihariCaseQueryPage -Items $allItems -MaximumItems $MaximumItems -Revision $revision -Cursor $Cursor
    return [pscustomobject]@{ items = @($page.Items); nextCursor = $page.NextCursor; revision = $page.Revision; ordering = 'createdAtUtc:asc,noteId:asc'; scopeTotal = [int]$page.ScopeTotal; coverage = 'observed'; freshnessUtc = [DateTime]::UtcNow.ToString('o', [Globalization.CultureInfo]::InvariantCulture) }
}

function ConvertTo-MihariEnvironmentReference {
    param(
        [AllowNull()][object] $EnvironmentReference,
        [string] $CaseRoot,
        [string] $OutputDirectory
    )

    if ($null -eq $EnvironmentReference) { return $null }
    $snapshotId = Get-MihariCaseField -InputObject $EnvironmentReference -Names @('snapshotId', 'id')
    $capturedAtUtc = Get-MihariCaseField -InputObject $EnvironmentReference -Names @('capturedAtUtc', 'timestampUtc')
    $relativePath = Get-MihariCaseField -InputObject $EnvironmentReference -Names @('relativePath', 'path', 'file')
    $sourceList = Get-MihariCaseField -InputObject $EnvironmentReference -Names @('sources')
    if ($EnvironmentReference -is [string]) { $snapshotId = $EnvironmentReference }
    $result = [ordered]@{}
    $safeId = ConvertTo-MihariCaseSafeText -Value $snapshotId -MaximumLength 128
    if ($null -ne $safeId) { $result['snapshotId'] = $safeId }
    $safeCaptured = ConvertTo-MihariCaseSafeText -Value $capturedAtUtc -MaximumLength 64
    if ($null -ne $safeCaptured) { $result['capturedAtUtc'] = $safeCaptured }
    if ($null -ne $relativePath) {
        $safePath = ConvertTo-MihariCaseSafeText -Value $relativePath -MaximumLength 512
        if ($null -eq $safePath) { throw 'The environment snapshot path is invalid.' }
        if ([System.IO.Path]::IsPathRooted($safePath)) {
            if ([string]::IsNullOrWhiteSpace($OutputDirectory)) { throw 'An absolute environment path requires an explicit output directory for safe relativization.' }
            $base = [System.IO.Path]::GetFullPath($OutputDirectory).TrimEnd([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
            $full = [System.IO.Path]::GetFullPath($safePath)
            if (-not $full.StartsWith($base, [StringComparison]::OrdinalIgnoreCase)) { throw 'The environment snapshot must be inside the supplied output directory.' }
            $safePath = $full.Substring($base.Length)
        }
        $segments = $safePath -split '[\\/]'
        if ($segments -contains '..' -or $safePath -match '^[a-zA-Z]:|^[/\\]') { throw 'The environment snapshot reference must be a safe relative path.' }
        $result['relativePath'] = $safePath
    }
    if ($null -ne $sourceList) {
        $redacted = 0
        $result['sources'] = ConvertTo-MihariCaseSafeValue -Value $sourceList -Depth 0 -RedactedCount ([ref]$redacted)
    }
    if ($result.Count -eq 0) { return $null }
    return $result
}

function New-MihariTrial {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][Alias('OutputDirectory', 'StoreRoot')][string] $CaseRoot,
        [Parameter(Mandatory = $true)][string] $CaseId,
        [Parameter(Mandatory = $true)][string] $SessionId,
        [Parameter(Mandatory = $true)][object] $Profile,
        [Parameter(Mandatory = $true)][string] $ConfigurationRevision,
        [AllowNull()][object] $EnvironmentReference,
        [string] $OutputDirectory
    )

    if (-not (Test-MihariCaseId -CaseId $CaseId)) { throw 'The case ID is invalid.' }
    $safeSession = ConvertTo-MihariCaseSafeText -Value $SessionId -MaximumLength 128
    if ($null -eq $safeSession) { throw 'A session ID is required.' }
    $safeRevision = ConvertTo-MihariCaseSafeText -Value $ConfigurationRevision -MaximumLength 128
    if ($null -eq $safeRevision) { throw 'A configuration revision is required.' }
    $redactedFields = 0
    $profileSnapshot = ConvertTo-MihariCaseSafeValue -Value $Profile -Depth 0 -RedactedCount ([ref]$redactedFields)
    if ($null -eq $profileSnapshot -or $profileSnapshot -isnot [System.Collections.IDictionary]) { throw 'The trial profile must be a safe object.' }
    $environmentSnapshot = ConvertTo-MihariEnvironmentReference -EnvironmentReference $EnvironmentReference -CaseRoot $CaseRoot -OutputDirectory $OutputDirectory
    $null = Initialize-MihariCaseStore -CaseRoot $CaseRoot
    $lock = Enter-MihariCaseStoreLock -CaseRoot $CaseRoot
    try {
        $snapshot = Get-MihariCaseStoreSnapshotUnlocked -CaseRoot $CaseRoot
        if (@($snapshot.Cases | Where-Object { [string]$_.caseId -eq $CaseId }).Count -eq 0) { throw 'The trial case does not exist.' }
        $trialId = New-MihariTrialId
        $now = [DateTime]::UtcNow.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
        $markerId = 'marker-' + [Guid]::NewGuid().ToString('N')
        $startMarker = [ordered]@{
            schemaVersion = 1; recordType = 'marker'; markerId = $markerId; trialId = $trialId; caseId = $CaseId
            timestamp = $now; timestampUtc = $now; boundary = 'trial_start'; label = 'Trial started'; note = $null; source = 'operator'
        }
        $record = [ordered]@{
            schemaVersion = 1; recordType = 'trial'; trialId = $trialId; caseId = $CaseId; sessionId = $safeSession
            revision = 1; startedAtUtc = $now; startMarkerId = $markerId; startMarker = $startMarker
            profile = $profileSnapshot; profileRedactedFields = [int]$redactedFields
            configurationRevision = $safeRevision; environmentReference = $environmentSnapshot
            status = 'running'; operatorBusinessOutcome = 'unknown'
        }
        Add-MihariCaseJournalRecordUnlocked -CaseRoot $CaseRoot -Record $record
        return [pscustomobject]@{
            schemaVersion = 1; trialId = $trialId; caseId = $CaseId; sessionId = $safeSession; revision = 1
            startedAtUtc = $now; startMarkerId = $markerId; profile = $profileSnapshot
            profileRedactedFields = [int]$redactedFields; configurationRevision = $safeRevision
            environmentReference = $environmentSnapshot; status = 'running'; endedAtUtc = $null
            endMarkerId = $null; operatorBusinessOutcome = 'unknown'; markers = @($startMarker); notes = @()
        }
    }
    finally { $lock.Dispose() }
}

function Complete-MihariTrial {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][Alias('OutputDirectory', 'StoreRoot')][string] $CaseRoot,
        [Parameter(Mandatory = $true)][string] $TrialId,
        [ValidateSet('succeeded', 'failed', 'not_reproduced', 'unknown')][string] $OperatorBusinessOutcome = 'unknown',
        [string] $Note
    )

    if (-not (Test-MihariTrialId -TrialId $TrialId)) { throw 'The trial ID is invalid.' }
    $safeNote = ConvertTo-MihariCaseSafeText -Value $Note -MaximumLength 1024
    $null = Initialize-MihariCaseStore -CaseRoot $CaseRoot
    $lock = Enter-MihariCaseStoreLock -CaseRoot $CaseRoot
    try {
        $snapshot = Get-MihariCaseStoreSnapshotUnlocked -CaseRoot $CaseRoot
        $trial = @($snapshot.Trials | Where-Object { [string]$_.trialId -eq $TrialId } | Select-Object -First 1)
        if ($trial.Count -eq 0) { throw 'The requested trial does not exist.' }
        if ([string]$trial[0].status -ne 'running') { throw 'The trial has already ended.' }
        $now = [DateTime]::UtcNow.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
        $markerId = 'marker-' + [Guid]::NewGuid().ToString('N')
        $endMarker = [ordered]@{
            schemaVersion = 1; recordType = 'marker'; markerId = $markerId; trialId = $TrialId; caseId = [string]$trial[0].caseId
            timestamp = $now; timestampUtc = $now; boundary = 'trial_end'; label = 'Trial ended'; note = $safeNote; source = 'operator'
        }
        $record = [ordered]@{
            schemaVersion = 1; recordType = 'trial-update'; trialId = $TrialId; caseId = [string]$trial[0].caseId
            revision = ([int]$trial[0].revision + 1); endedAtUtc = $now; endMarkerId = $markerId
            endMarker = $endMarker; operatorBusinessOutcome = $OperatorBusinessOutcome
        }
        Add-MihariCaseJournalRecordUnlocked -CaseRoot $CaseRoot -Record $record
        return [pscustomobject]@{
            schemaVersion = 1; trialId = $TrialId; caseId = [string]$trial[0].caseId; sessionId = [string]$trial[0].sessionId
            revision = [int]$record.revision; startedAtUtc = [string]$trial[0].startedAtUtc; endedAtUtc = $now
            startMarkerId = [string]$trial[0].startMarkerId; endMarkerId = $markerId; profile = $trial[0].profile
            profileRedactedFields = [int]$trial[0].profileRedactedFields; configurationRevision = [string]$trial[0].configurationRevision
            environmentReference = $trial[0].environmentReference; status = 'complete'
            operatorBusinessOutcome = $OperatorBusinessOutcome; markers = @($trial[0].markers) + @([pscustomobject]$endMarker); notes = @($trial[0].notes)
        }
    }
    finally { $lock.Dispose() }
}

function Add-MihariMarker {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][Alias('OutputDirectory', 'StoreRoot')][string] $CaseRoot,
        [Parameter(Mandatory = $true)][string] $TrialId,
        [Parameter(Mandatory = $true)][ValidateSet('point', 'start', 'end', 'note')][string] $Boundary,
        [Parameter(Mandatory = $true)][string] $Label,
        [string] $Note,
        [DateTimeOffset] $TimestampUtc
    )

    if (-not (Test-MihariTrialId -TrialId $TrialId)) { throw 'The trial ID is invalid.' }
    $safeLabel = ConvertTo-MihariCaseSafeText -Value $Label -MaximumLength 160
    if ($null -eq $safeLabel) { throw 'A marker label is required.' }
    $safeNote = ConvertTo-MihariCaseSafeText -Value $Note -MaximumLength 2048
    if (-not $PSBoundParameters.ContainsKey('TimestampUtc')) { $TimestampUtc = [DateTimeOffset]::UtcNow }
    $timestamp = $TimestampUtc.ToUniversalTime().ToString('o', [Globalization.CultureInfo]::InvariantCulture)
    $null = Initialize-MihariCaseStore -CaseRoot $CaseRoot
    $lock = Enter-MihariCaseStoreLock -CaseRoot $CaseRoot
    try {
        $snapshot = Get-MihariCaseStoreSnapshotUnlocked -CaseRoot $CaseRoot
        $trial = @($snapshot.Trials | Where-Object { [string]$_.trialId -eq $TrialId } | Select-Object -First 1)
        if ($trial.Count -eq 0) { throw 'The marker trial does not exist.' }
        $record = [ordered]@{
            schemaVersion = 1; recordType = 'marker'; markerId = 'marker-' + [Guid]::NewGuid().ToString('N')
            trialId = $TrialId; caseId = [string]$trial[0].caseId; timestamp = $timestamp; timestampUtc = $timestamp
            boundary = $Boundary; label = $safeLabel; note = $safeNote; source = 'operator'
        }
        Add-MihariCaseJournalRecordUnlocked -CaseRoot $CaseRoot -Record $record
        return [pscustomobject]$record
    }
    finally { $lock.Dispose() }
}

function Add-MihariCaseNote {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][Alias('OutputDirectory', 'StoreRoot')][string] $CaseRoot,
        [Parameter(Mandatory = $true)][string] $CaseId,
        [string] $TrialId,
        [Parameter(Mandatory = $true)][string] $Text
    )

    if (-not (Test-MihariCaseId -CaseId $CaseId)) { throw 'The case ID is invalid.' }
    if ($TrialId -and -not (Test-MihariTrialId -TrialId $TrialId)) { throw 'The trial ID is invalid.' }
    $safeText = ConvertTo-MihariCaseSafeText -Value $Text -MaximumLength 4096
    if ($null -eq $safeText) { throw 'A non-empty case note is required.' }
    $null = Initialize-MihariCaseStore -CaseRoot $CaseRoot
    $lock = Enter-MihariCaseStoreLock -CaseRoot $CaseRoot
    try {
        $snapshot = Get-MihariCaseStoreSnapshotUnlocked -CaseRoot $CaseRoot
        if (@($snapshot.Cases | Where-Object { [string]$_.caseId -eq $CaseId }).Count -eq 0) { throw 'The requested case does not exist.' }
        if ($TrialId) {
            $trial = @($snapshot.Trials | Where-Object { [string]$_.trialId -eq $TrialId -and [string]$_.caseId -eq $CaseId })
            if ($trial.Count -eq 0) { throw 'The note trial does not belong to the requested case.' }
        }
        $record = [ordered]@{
            schemaVersion = 1; recordType = 'note'; noteId = 'note-' + [Guid]::NewGuid().ToString('N')
            caseId = $CaseId; trialId = $TrialId; createdAtUtc = [DateTime]::UtcNow.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
            source = 'operator'; text = $safeText
        }
        Add-MihariCaseJournalRecordUnlocked -CaseRoot $CaseRoot -Record $record
        return [pscustomobject]$record
    }
    finally { $lock.Dispose() }
}

function Get-MihariDependencyNecessityRecords {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][Alias('OutputDirectory', 'StoreRoot')][string] $CaseRoot)
    $snapshot = Get-MihariCaseStoreSnapshot -CaseRoot $CaseRoot
    return $snapshot.Necessity
}

function Set-MihariDependencyNecessity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][Alias('OutputDirectory', 'StoreRoot')][string] $CaseRoot,
        [Parameter(Mandatory = $true)][object] $Dependency,
        [Parameter(Mandatory = $true)][ValidateSet('necessity_unconfirmed', 'business_required_confirmed')][string] $State,
        [switch] $ConfirmBusinessRequired,
        [string] $Rationale
    )

    $dependencyId = ConvertTo-MihariCaseSafeText -Value (Get-MihariCaseField -InputObject $Dependency -Names @('dependencyId', 'id')) -MaximumLength 128
    if ($null -eq $dependencyId -or $dependencyId -notmatch '^dep-[0-9a-f]{24}$') { throw 'A valid projected dependency is required.' }
    if ($State -eq 'business_required_confirmed' -and -not $ConfirmBusinessRequired) {
        throw 'Explicit business necessity confirmation is required for this state change.'
    }
    $evidence = Get-MihariCaseField -InputObject $Dependency -Names @('evidenceReferences', 'evidence')
    $safeEvidence = New-Object 'System.Collections.Generic.List[object]'
    foreach ($reference in @($evidence)) {
        $sessionId = ConvertTo-MihariCaseSafeText -Value (Get-MihariCaseField -InputObject $reference -Names @('sessionId')) -MaximumLength 128
        $eventId = ConvertTo-MihariCaseSafeText -Value (Get-MihariCaseField -InputObject $reference -Names @('eventId')) -MaximumLength 128
        if ($null -ne $sessionId -and $null -ne $eventId) {
            $safeEvidence.Add([pscustomobject]@{ sessionId = $sessionId; eventId = $eventId })
        }
    }
    if ($State -eq 'business_required_confirmed' -and $safeEvidence.Count -eq 0) {
        throw 'Business necessity cannot be confirmed without evidence references.'
    }
    $safeRationale = ConvertTo-MihariCaseSafeText -Value $Rationale -MaximumLength 1024
    $binding = [ordered]@{}
    foreach ($name in @('caseId', 'trialId', 'scheme', 'host', 'port', 'path')) {
        $value = ConvertTo-MihariCaseSafeText -Value (Get-MihariCaseField -InputObject $Dependency -Names @($name)) -MaximumLength 512
        if ($null -ne $value) { $binding[$name] = $value }
    }
    $null = Initialize-MihariCaseStore -CaseRoot $CaseRoot
    $lock = Enter-MihariCaseStoreLock -CaseRoot $CaseRoot
    try {
        $record = [ordered]@{
            schemaVersion = 1; recordType = 'necessity'; dependencyId = $dependencyId; state = $State
            confirmedAtUtc = [DateTime]::UtcNow.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
            confirmedBy = 'operator'; explicitConfirmation = [bool]$ConfirmBusinessRequired
            rationale = $safeRationale; dependency = $binding; evidenceReferences = @($safeEvidence.ToArray())
        }
        Add-MihariCaseJournalRecordUnlocked -CaseRoot $CaseRoot -Record $record
        return [pscustomobject]$record
    }
    finally { $lock.Dispose() }
}
