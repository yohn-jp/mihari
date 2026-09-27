# Incremental request projections over the canonical session JSONL. The derived
# index contains only allowlisted fields; the event log is never rewritten.

function Get-MihariTrafficMemberValue {
    param([AllowNull()][object]$InputObject, [Parameter(Mandatory = $true)][string]$Name)
    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [System.Collections.IDictionary]) {
        foreach ($key in $InputObject.Keys) {
            if ([string]::Equals([string]$key, $Name, [StringComparison]::OrdinalIgnoreCase)) { return $InputObject[$key] }
        }
        return $null
    }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -ne $property) { return $property.Value }
    return $null
}

function ConvertTo-MihariTrafficText {
    param([AllowNull()][object]$Value, [ValidateRange(1, 4096)][int]$MaximumLength = 256)
    if ($null -eq $Value -or $Value -is [System.Collections.IDictionary] -or $Value -is [System.Array]) { return $null }
    $text = [string]$Value
    $text = [regex]::Replace($text, '[\x00-\x1f\x7f]', ' ')
    $text = [regex]::Replace($text, '(?im)\b(authorization|proxy-authorization|cookie|set-cookie)\s*:\s*[^\r\n]*', '$1: [REDACTED]')
    $text = [regex]::Replace($text, '(?i)(authorization|proxy-authorization|cookie|set-cookie)\s*=\s*[^,\r\n]+', '$1=[REDACTED]')
    $text = [regex]::Replace($text, '([?&][^=&#\s]+)=([^&#\s]*)', '$1=[REDACTED]')
    $text = [regex]::Replace($text, '(?i)(https?://)[^/\s?#@]+@', '$1[REDACTED]@')
    $text = $text.Trim()
    if ($text.Length -gt $MaximumLength) { $text = $text.Substring(0, $MaximumLength) }
    if ($text.Length -eq 0) { return $null }
    return $text
}

function ConvertTo-MihariTrafficPath {
    param([AllowNull()][object]$Value)
    $path = ConvertTo-MihariTrafficText -Value $Value -MaximumLength 2048
    if ($null -eq $path) { return $null }
    $queryIndex = $path.IndexOf('?')
    if ($queryIndex -lt 0) { return $path }
    $basePath = $path.Substring(0, $queryIndex)
    $parts = New-Object 'System.Collections.Generic.List[string]'
    foreach ($part in ($path.Substring($queryIndex + 1) -split '&')) {
        if ($part.Length -eq 0) { continue }
        $equals = $part.IndexOf('=')
        if ($equals -ge 0) { $name = $part.Substring(0, $equals) } else { $name = 'value' }
        $name = [regex]::Replace($name, '[^A-Za-z0-9_.~-]', '')
        if ($name.Length -gt 64) { $name = $name.Substring(0, 64) }
        if ($name.Length -eq 0) { $name = 'value' }
        $parts.Add($name + '=[REDACTED]')
    }
    if ($parts.Count -eq 0) { return $basePath + '?[REDACTED]' }
    return $basePath + '?' + [string]::Join('&', $parts.ToArray())
}

function ConvertTo-MihariTrafficNumber {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value -or $Value -is [bool] -or $Value -is [System.Collections.IDictionary] -or $Value -is [System.Array]) { return $null }
    $number = [decimal]0
    if (-not [decimal]::TryParse([string]$Value, [Globalization.NumberStyles]::Float,
            [Globalization.CultureInfo]::InvariantCulture, [ref]$number)) { return $null }
    return $number
}

function ConvertTo-MihariTrafficSafeEvent {
    param([Parameter(Mandatory = $true)][object]$Event)
    $data = Get-MihariTrafficMemberValue -InputObject $Event -Name 'data'
    $safeData = [ordered]@{}
    $stringFields = @(
        'host', 'scheme', 'method', 'routeKind', 'routeSource', 'proxyHost', 'clientEndpoint',
        'direction', 'tlsProtocol', 'tlsCipher', 'tlsCipherSuite', 'certificateSubject',
        'certificateIssuer', 'certificateThumbprint', 'certificateNotBefore', 'certificateNotAfter',
        'errorType', 'errorCode', 'message', 'reason', 'unsupportedProtocol', 'mode', 'previousMode',
        'tlsAlpn', 'certificateChainState', 'hostnameState', 'validityState', 'ekuState', 'revocationState',
        'validationPolicy', 'peerIdentityRole', 'clientCertificateState', 'protocol', 'initiatorType',
        'browserTargetId', 'browserRequestId', 'browserConnectionId', 'browserError', 'browserTimingOrigin',
        'requestFraming', 'responseFraming', 'connectionPolicy', 'framing'
    )
    foreach ($name in $stringFields) {
        $limit = 256
        if ($name -eq 'certificateSubject' -or $name -eq 'certificateIssuer') { $limit = 512 }
        $value = ConvertTo-MihariTrafficText -Value (Get-MihariTrafficMemberValue -InputObject $data -Name $name) -MaximumLength $limit
        if ($null -ne $value) { $safeData[$name] = $value }
    }
    $path = ConvertTo-MihariTrafficPath -Value (Get-MihariTrafficMemberValue -InputObject $data -Name 'path')
    if ($null -ne $path) { $safeData['path'] = $path }
    foreach ($name in @('port', 'proxyPort', 'statusCode', 'proxyStatus', 'bytesClientToUpstream', 'bytesUpstreamToClient',
            'tlsCipherStrength', 'browserRedirectIndex', 'browserTimingStartMs', 'browserTimingDurationMs',
            'requestBytes', 'responseBytes', 'bytes', 'firstByteMs', 'lastByteMs', 'forwardWriteMs', 'workerOccupancy', 'maxWorkers')) {
        $value = ConvertTo-MihariTrafficNumber -Value (Get-MihariTrafficMemberValue -InputObject $data -Name $name)
        if ($null -ne $value -and $value -ge 0 -and $value -le [decimal][long]::MaxValue) { $safeData[$name] = [long][Math]::Truncate($value) }
    }
    foreach ($name in @('certificateAccepted', 'caTrusted', 'fromDiskCache', 'fromServiceWorker', 'reused', 'queueSaturated')) {
        $value = Get-MihariTrafficMemberValue -InputObject $data -Name $name
        if ($value -is [bool]) { $safeData[$name] = $value }
    }
    $rawChain = Get-MihariTrafficMemberValue -InputObject $data -Name 'certificateChain'
    if ($null -ne $rawChain) {
        $chain = New-Object 'System.Collections.Generic.List[object]'
        foreach ($element in @($rawChain | Select-Object -First 8)) {
            if ($null -eq $element) { continue }
            $chainElement = [ordered]@{}
            foreach ($name in @('subject', 'issuer', 'thumbprint', 'notBefore', 'notAfter')) {
                $value = ConvertTo-MihariTrafficText -Value (Get-MihariTrafficMemberValue -InputObject $element -Name $name) -MaximumLength 256
                if ($null -ne $value) { $chainElement[$name] = $value }
            }
            if ($chainElement.Count -gt 0) { $chain.Add([pscustomobject]$chainElement) }
        }
        $safeData['certificateChain'] = @($chain.ToArray())
    }

    $schema = ConvertTo-MihariTrafficNumber -Value (Get-MihariTrafficMemberValue -InputObject $Event -Name 'schemaVersion')
    $sequence = ConvertTo-MihariTrafficNumber -Value (Get-MihariTrafficMemberValue -InputObject $Event -Name 'sequence')
    if ($null -ne $sequence -and ($sequence -lt 1 -or $sequence -gt [decimal][long]::MaxValue -or [decimal]::Truncate($sequence) -ne $sequence)) { $sequence = $null }
    $source = ConvertTo-MihariTrafficText -Value (Get-MihariTrafficMemberValue -InputObject $Event -Name 'source') -MaximumLength 32
    if ($null -eq $source) { $source = 'unknown' }
    $coverage = ConvertTo-MihariTrafficText -Value (Get-MihariTrafficMemberValue -InputObject $Event -Name 'coverage') -MaximumLength 32
    if ($null -eq $coverage) { $coverage = 'unknown' }
    $elapsed = ConvertTo-MihariTrafficNumber -Value (Get-MihariTrafficMemberValue -InputObject $Event -Name 'elapsedMs')
    if ($null -ne $elapsed -and ($elapsed -lt 0 -or $elapsed -gt [decimal][long]::MaxValue)) { $elapsed = $null }
    $result = [ordered]@{
        schemaVersion = $schema
        sequence = $sequence
        timestamp = (ConvertTo-MihariTrafficText -Value (Get-MihariTrafficMemberValue -InputObject $Event -Name 'timestamp') -MaximumLength 64)
        eventId = (ConvertTo-MihariTrafficText -Value (Get-MihariTrafficMemberValue -InputObject $Event -Name 'eventId') -MaximumLength 128)
        sessionId = (ConvertTo-MihariTrafficText -Value (Get-MihariTrafficMemberValue -InputObject $Event -Name 'sessionId') -MaximumLength 128)
        connectionId = (ConvertTo-MihariTrafficText -Value (Get-MihariTrafficMemberValue -InputObject $Event -Name 'connectionId') -MaximumLength 128)
        requestId = (ConvertTo-MihariTrafficText -Value (Get-MihariTrafficMemberValue -InputObject $Event -Name 'requestId') -MaximumLength 128)
        mode = (ConvertTo-MihariTrafficText -Value (Get-MihariTrafficMemberValue -InputObject $Event -Name 'mode') -MaximumLength 16)
        stage = (ConvertTo-MihariTrafficText -Value (Get-MihariTrafficMemberValue -InputObject $Event -Name 'stage') -MaximumLength 64)
        outcome = (ConvertTo-MihariTrafficText -Value (Get-MihariTrafficMemberValue -InputObject $Event -Name 'outcome') -MaximumLength 32)
        elapsedMs = $elapsed
        source = $source
        coverage = $coverage
        data = [pscustomobject]$safeData
    }
    foreach ($name in @('caseId', 'trialId', 'configurationRevision', 'transportLeg', 'upstreamConnectionId', 'streamId',
            'sourceIdentity', 'sourceVersion', 'monotonicTicks', 'clockId')) {
        $value = Get-MihariTrafficMemberValue -InputObject $Event -Name $name
        if ($null -eq $value) { continue }
        if ($name -eq 'configurationRevision' -or $name -eq 'monotonicTicks') {
            $number = ConvertTo-MihariTrafficNumber -Value $value
            if ($null -ne $number -and $number -ge 0 -and $number -le [decimal][long]::MaxValue -and [decimal]::Truncate($number) -eq $number) { $result[$name] = [long]$number }
        }
        else {
            $limit = 128
            if ($name -eq 'sourceVersion') { $limit = 64 }
            $safe = ConvertTo-MihariTrafficText -Value $value -MaximumLength $limit
            if ($null -ne $safe) { $result[$name] = $safe }
        }
    }
    return [pscustomobject]$result
}

function Get-MihariTrafficRequestKey {
    param([Parameter(Mandatory = $true)][object]$Event, [long]$FallbackOrdinal = 0)
    $sessionId = [string]$Event.sessionId
    if ([string]::IsNullOrWhiteSpace($sessionId)) { return $null }
    $requestId = [string]$Event.requestId
    if (-not [string]::IsNullOrWhiteSpace($requestId)) {
        if ([string]$Event.source -eq 'browser') {
            $targetId = [string]$Event.sourceIdentity
            if ([string]::IsNullOrWhiteSpace($targetId)) { $targetId = [string]$Event.data.browserTargetId }
            $redirect = Get-MihariTrafficMemberValue -InputObject $Event.data -Name 'browserRedirectIndex'
            if ([string]::IsNullOrWhiteSpace($targetId)) {
                $identity = [string]$Event.eventId
                if ([string]::IsNullOrWhiteSpace($identity)) { $identity = 'ordinal-' + $FallbackOrdinal.ToString([Globalization.CultureInfo]::InvariantCulture) }
                return ($sessionId + ':browser-event:' + $identity)
            }
            if ($null -eq $redirect) { $redirect = 0 }
            return ($sessionId + ':browser:' + $targetId.Length.ToString([Globalization.CultureInfo]::InvariantCulture) + ':' + $targetId + ':' + $requestId + ':' + [string]$redirect)
        }
        return ($sessionId + ':' + $requestId)
    }
    $connectionId = [string]$Event.connectionId
    if ([string]::IsNullOrWhiteSpace($connectionId) -or $connectionId -in @('session', 'management')) { return $null }
    return ($sessionId + ':connection:' + $connectionId)
}

function Get-MihariTrafficHash {
    param([Parameter(Mandatory = $true)][string]$Text)
    $algorithm = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hash = $algorithm.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Text))
        return ([BitConverter]::ToString($hash)).Replace('-', '').ToLowerInvariant()
    }
    finally { $algorithm.Dispose() }
}

function Write-MihariTrafficJsonLine {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][object]$Value)
    $json = ConvertTo-Json -InputObject $Value -Depth 12 -Compress -ErrorAction Stop
    $stream = $null
    $writer = $null
    try {
        $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::ReadWrite)
        $writer = [System.IO.StreamWriter]::new($stream, [System.Text.UTF8Encoding]::new($false))
        $writer.WriteLine($json)
        $writer.Flush()
        $stream.Flush()
    }
    finally {
        if ($null -ne $writer) { $writer.Dispose() }
        elseif ($null -ne $stream) { $stream.Dispose() }
    }
}

function Save-MihariTrafficProjectionState {
    param([Parameter(Mandatory = $true)][object]$Store)
    $state = [ordered]@{
        magic = 'MihariTrafficProjectionV1'; sessionId = $Store.SessionId; eventsPath = $Store.EventsPath
        offset = [long]$Store.Offset; generation = [int]$Store.Generation; generationId = [string]$Store.GenerationId
        ordinal = [long]$Store.Ordinal; lastSequence = $Store.LastSequence
        anchorStart = [long]$Store.AnchorStart; anchorLength = [int]$Store.AnchorLength; anchorHash = [string]$Store.AnchorHash
        fileCreatedUtcTicks = [long]$Store.FileCreatedUtcTicks; pendingOffset = [long]$Store.PendingOffset
        pendingBytes = [long]$Store.PendingBytes; discardingLine = [bool]$Store.DiscardingLine
        discardStartOffset = [long]$Store.DiscardStartOffset; discardScanOffset = [long]$Store.DiscardScanOffset
        malformedLineCount = [long]$Store.Counters.MalformedLineCount
        incompleteFinalLineCount = [long]$Store.Counters.IncompleteFinalLineCount
        recoveredPartialLineCount = [long]$Store.Counters.RecoveredPartialLineCount
        rotationCount = [long]$Store.Counters.RotationCount; oversizeLineCount = [long]$Store.Counters.OversizeLineCount
        lostPartialLineCount = [long]$Store.Counters.LostPartialLineCount
        sequenceViolationCount = [long]$Store.Counters.SequenceViolationCount
        unprojectableLineCount = [long]$Store.Counters.UnprojectableLineCount
        freshnessUtc = [string]$Store.FreshnessUtc; lastEventUtc = [string]$Store.LastEventUtc
    }
    $temporaryPath = $Store.StatePath + '.tmp'
    [System.IO.File]::WriteAllText($temporaryPath, (ConvertTo-Json -InputObject $state -Depth 5 -Compress), [System.Text.UTF8Encoding]::new($false))
    if ([System.IO.File]::Exists($Store.StatePath)) {
        try { [System.IO.File]::Replace($temporaryPath, $Store.StatePath, $null) }
        catch {
            $replaceError = $_
            [System.IO.File]::Delete($Store.StatePath)
            try { [System.IO.File]::Move($temporaryPath, $Store.StatePath) }
            catch { throw ('Could not persist projection state ({0}).' -f $replaceError.Exception.GetType().Name) }
        }
    }
    else { [System.IO.File]::Move($temporaryPath, $Store.StatePath) }
}

function Clear-MihariTrafficProjectionIndexes {
    param([Parameter(Mandatory = $true)][string]$RequestsDirectory, [Parameter(Mandatory = $true)][string]$IndexDirectory)
    if ([System.IO.Directory]::Exists($RequestsDirectory)) {
        foreach ($path in [System.IO.Directory]::EnumerateFiles($RequestsDirectory, '*.jsonl')) {
            if ([System.IO.Path]::GetFileName($path) -match '^\d{20}-[a-f0-9]{64}\.jsonl$') { [System.IO.File]::Delete($path) }
        }
    }
    $destinations = Join-Path $IndexDirectory 'destinations'
    if ([System.IO.Directory]::Exists($destinations)) {
        foreach ($path in [System.IO.Directory]::EnumerateFiles($destinations, '*.json')) {
            if ([System.IO.Path]::GetFileName($path) -match '^[a-f0-9]{64}\.json$') { [System.IO.File]::Delete($path) }
        }
    }
    $eventsIndex = Join-Path $IndexDirectory 'events.index.jsonl'
    if ([System.IO.File]::Exists($eventsIndex)) { [System.IO.File]::Delete($eventsIndex) }
    $summaries = Join-Path $IndexDirectory 'request-summaries'
    if ([System.IO.Directory]::Exists($summaries)) {
        foreach ($path in [System.IO.Directory]::EnumerateFiles($summaries, '*.json')) {
            if ([System.IO.Path]::GetFileName($path) -match '^[a-f0-9]{64}\.json$') { [System.IO.File]::Delete($path) }
        }
    }
}

function Import-MihariTrafficProjectionState {
    param([Parameter(Mandatory = $true)][object]$Store)
    if (-not [System.IO.File]::Exists($Store.StatePath)) { return $false }
    try {
        $state = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($Store.StatePath, [System.Text.Encoding]::UTF8)) -ErrorAction Stop
        if ([string]$state.magic -ne 'MihariTrafficProjectionV1' -or [string]$state.sessionId -ne [string]$Store.SessionId -or [string]$state.eventsPath -ne [string]$Store.EventsPath) { return $false }
        $Store.Offset = [long]$state.offset; $Store.Generation = [int]$state.generation
        $Store.GenerationId = [string]$state.generationId; $Store.Ordinal = [long]$state.ordinal
        $Store.LastSequence = $state.lastSequence; $Store.AnchorStart = [long]$state.anchorStart
        $Store.AnchorLength = [int]$state.anchorLength; $Store.AnchorHash = [string]$state.anchorHash
        $Store.FileCreatedUtcTicks = [long]$state.fileCreatedUtcTicks; $Store.PendingOffset = [long]$state.pendingOffset
        $Store.PendingBytes = [long]$state.pendingBytes; $Store.DiscardingLine = [bool]$state.discardingLine
        $Store.DiscardStartOffset = [long]$state.discardStartOffset; $Store.DiscardScanOffset = [long]$state.discardScanOffset
        $Store.Counters.MalformedLineCount = [long]$state.malformedLineCount
        $Store.Counters.IncompleteFinalLineCount = [long]$state.incompleteFinalLineCount
        $Store.Counters.RecoveredPartialLineCount = [long]$state.recoveredPartialLineCount
        $Store.Counters.RotationCount = [long]$state.rotationCount
        $Store.Counters.OversizeLineCount = [long]$state.oversizeLineCount
        $Store.Counters.LostPartialLineCount = [long]$state.lostPartialLineCount
        $Store.Counters.SequenceViolationCount = [long]$state.sequenceViolationCount
        $Store.Counters.UnprojectableLineCount = [long]$state.unprojectableLineCount
        $Store.FreshnessUtc = [string]$state.freshnessUtc; $Store.LastEventUtc = [string]$state.lastEventUtc
        return $true
    }
    catch { return $false }
}

function New-MihariTrafficProjectionStore {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$SessionId,
        [Parameter(Mandatory = $true)][string]$EventsPath,
        [Parameter(Mandatory = $true)][string]$IndexDirectory,
        [ValidateRange(1, 5000)][int]$HotLimit = 500,
        [ValidateRange(1024, 4194304)][int]$MaximumLineBytes = 1048576
    )
    $eventsFullPath = [System.IO.Path]::GetFullPath($EventsPath)
    $indexFullPath = [System.IO.Path]::GetFullPath($IndexDirectory)
    if ([string]::Equals($eventsFullPath, $indexFullPath, [StringComparison]::OrdinalIgnoreCase)) { throw 'Projection index must be separate from the canonical event log.' }
    [void][System.IO.Directory]::CreateDirectory($indexFullPath)
    $requestsDirectory = Join-Path $indexFullPath 'requests'
    $destinationsDirectory = Join-Path $indexFullPath 'destinations'
    $summariesDirectory = Join-Path $indexFullPath 'request-summaries'
    [void][System.IO.Directory]::CreateDirectory($requestsDirectory)
    [void][System.IO.Directory]::CreateDirectory($destinationsDirectory)
    [void][System.IO.Directory]::CreateDirectory($summariesDirectory)
    $store = [pscustomobject]@{
        SessionId = $SessionId; EventsPath = $eventsFullPath; IndexDirectory = $indexFullPath
        RequestsDirectory = $requestsDirectory; DestinationsDirectory = $destinationsDirectory
        SummariesDirectory = $summariesDirectory
        StatePath = (Join-Path $indexFullPath 'projection-state.json')
        EventsIndexPath = (Join-Path $indexFullPath 'events.index.jsonl')
        HotLimit = $HotLimit; MaximumLineBytes = $MaximumLineBytes
        Offset = [long]0; Generation = 1; GenerationId = [Guid]::NewGuid().ToString('N').ToLowerInvariant()
        Ordinal = [long]0; LastSequence = $null; AnchorStart = [long]0; AnchorLength = 0; AnchorHash = ''
        FileCreatedUtcTicks = [long]0; PendingOffset = [long]-1; PendingBytes = [long]0
        DiscardingLine = $false; DiscardStartOffset = [long]-1; DiscardScanOffset = [long]-1
        Counters = [pscustomobject]@{
            MalformedLineCount = [long]0; IncompleteFinalLineCount = [long]0; RecoveredPartialLineCount = [long]0
            RotationCount = [long]0; OversizeLineCount = [long]0; LostPartialLineCount = [long]0
            SequenceViolationCount = [long]0; UnprojectableLineCount = [long]0
        }
        HotRequests = (New-Object 'System.Collections.ArrayList'); HotEvents = (New-Object 'System.Collections.ArrayList')
        NewEvents = @(); FreshnessUtc = $null; LastEventUtc = $null; Backlog = $false
        SyncRoot = (New-Object System.Object)
    }
    if (-not (Import-MihariTrafficProjectionState -Store $store)) {
        Clear-MihariTrafficProjectionIndexes -RequestsDirectory $requestsDirectory -IndexDirectory $indexFullPath
        if ([System.IO.File]::Exists($store.StatePath)) { [System.IO.File]::Delete($store.StatePath) }
    }
    $null = Update-MihariTrafficProjectionStore -Store $store
    return $store
}

function Set-MihariTrafficProjectionAnchor {
    param([Parameter(Mandatory = $true)][object]$Store, [long]$LineStart, [Parameter(Mandatory = $true)][byte[]]$LineBytes)
    $algorithm = [System.Security.Cryptography.SHA256]::Create()
    try { $hash = $algorithm.ComputeHash($LineBytes) } finally { $algorithm.Dispose() }
    $Store.AnchorStart = $LineStart; $Store.AnchorLength = $LineBytes.Length
    $Store.AnchorHash = ([BitConverter]::ToString($hash)).Replace('-', '').ToLowerInvariant()
}

function Test-MihariTrafficProjectionAnchor {
    param([Parameter(Mandatory = $true)][object]$Store, [Parameter(Mandatory = $true)][System.IO.FileStream]$Stream)
    if ([long]$Store.FileCreatedUtcTicks -gt 0 -and [long]$Store.AnchorLength -gt 0) {
        if ([long]$Stream.Length -lt ([long]$Store.AnchorStart + [long]$Store.AnchorLength)) { return $false }
        $position = $Stream.Position
        try {
            $Stream.Position = [long]$Store.AnchorStart
            $bytes = New-Object byte[] ([int]$Store.AnchorLength)
            $read = 0
            while ($read -lt $bytes.Length) {
                $count = $Stream.Read($bytes, $read, $bytes.Length - $read)
                if ($count -le 0) { return $false }
                $read += $count
            }
            $algorithm = [System.Security.Cryptography.SHA256]::Create()
            try { $hash = $algorithm.ComputeHash($bytes) } finally { $algorithm.Dispose() }
            $actual = ([BitConverter]::ToString($hash)).Replace('-', '').ToLowerInvariant()
            return [string]::Equals($actual, [string]$Store.AnchorHash, [StringComparison]::Ordinal)
        }
        finally { $Stream.Position = $position }
    }
    return $true
}

function Reset-MihariTrafficProjectionGeneration {
    param([Parameter(Mandatory = $true)][object]$Store, [long]$FileCreatedUtcTicks)
    if ([long]$Store.PendingOffset -ge 0 -or [bool]$Store.DiscardingLine) { $Store.Counters.LostPartialLineCount++ }
    $Store.Counters.RotationCount++
    $Store.Generation++
    $Store.GenerationId = [Guid]::NewGuid().ToString('N').ToLowerInvariant()
    $Store.Offset = 0; $Store.AnchorStart = 0; $Store.AnchorLength = 0; $Store.AnchorHash = ''
    $Store.FileCreatedUtcTicks = $FileCreatedUtcTicks
    $Store.PendingOffset = -1; $Store.PendingBytes = 0
    $Store.DiscardingLine = $false; $Store.DiscardStartOffset = -1; $Store.DiscardScanOffset = -1
}

function Get-MihariTrafficRequestIndexPath {
    param([Parameter(Mandatory = $true)][object]$Store, [Parameter(Mandatory = $true)][long]$FirstOrdinal, [Parameter(Mandatory = $true)][string]$Key)
    $hash = Get-MihariTrafficHash -Text $Key
    foreach ($candidate in [System.IO.Directory]::EnumerateFiles($Store.RequestsDirectory, '*-' + $hash + '.jsonl')) {
        if ([System.IO.Path]::GetFileName($candidate) -match '^\d{20}-[a-f0-9]{64}\.jsonl$') { return $candidate }
    }
    return (Join-Path $Store.RequestsDirectory ($FirstOrdinal.ToString('D20', [Globalization.CultureInfo]::InvariantCulture) + '-' + $hash + '.jsonl'))
}

function Get-MihariTrafficDestinationKey {
    param([Parameter(Mandatory = $true)][object]$Event)
    $hostName = [string]$Event.data.host
    if ([string]::IsNullOrWhiteSpace($hostName)) { return $null }
    $port = Get-MihariTrafficMemberValue -InputObject $Event.data -Name 'port'
    if ($null -eq $port) { $port = 'unknown' }
    return ($hostName.Trim().TrimEnd('.').ToLowerInvariant() + ':' + [string]$port)
}

function Write-MihariTrafficAtomicJson {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][object]$Value)
    $temporaryPath = $Path + '.tmp'
    [System.IO.File]::WriteAllText($temporaryPath,
        (ConvertTo-Json -InputObject $Value -Depth 10 -Compress), [System.Text.UTF8Encoding]::new($false))
    if ([System.IO.File]::Exists($Path)) {
        try { [System.IO.File]::Replace($temporaryPath, $Path, $null) }
        catch {
            $replaceError = $_
            [System.IO.File]::Delete($Path)
            try { [System.IO.File]::Move($temporaryPath, $Path) }
            catch { throw ('Could not update a traffic summary ({0}).' -f $replaceError.Exception.GetType().Name) }
        }
    }
    else { [System.IO.File]::Move($temporaryPath, $Path) }
}

function Update-MihariTrafficRequestSnapshot {
    param([Parameter(Mandatory = $true)][object]$Store, [Parameter(Mandatory = $true)][object]$Row)
    $key = [string]$Row.requestKey
    if ([string]::IsNullOrWhiteSpace($key)) { return }
    $snapshotPath = Join-Path $Store.SummariesDirectory ((Get-MihariTrafficHash -Text $key) + '.json')
    $snapshot = $null
    if ([System.IO.File]::Exists($snapshotPath)) {
        try {
            $loaded = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($snapshotPath, [System.Text.Encoding]::UTF8)) -ErrorAction Stop
            $snapshot = [ordered]@{}
            foreach ($property in $loaded.PSObject.Properties) { $snapshot[$property.Name] = $property.Value }
        }
        catch { $snapshot = $null }
    }
    if ($null -eq $snapshot) {
        $snapshot = [ordered]@{
            key = $key; sessionId = [string]$Row.event.sessionId; requestId = $Row.event.requestId
            connectionId = $Row.event.connectionId; source = [string]$Row.event.source
            sourceIdentity = $Row.event.sourceIdentity; host = $null; scheme = $null; port = $null
            path = $null; method = $null; statusCode = $null; mode = $null; protocol = $null
            stage = $null; outcome = $null; failureStage = $null; elapsedMs = $null
            startedAt = $Row.event.timestamp; lastEventAt = $Row.event.timestamp
            firstSequence = $Row.event.sequence; lastSequence = $Row.event.sequence
            firstOffset = [long]$Row.offset; lastOffset = [long]$Row.offset
            eventCount = [long]0; coverage = [string]$Row.event.coverage
            transportLeg = $Row.event.transportLeg; upstreamConnectionId = $Row.event.upstreamConnectionId
            streamId = $Row.event.streamId; configurationRevision = $Row.event.configurationRevision
            caseId = $Row.event.caseId; trialId = $Row.event.trialId
            connectionOnly = ($null -eq $Row.event.requestId)
            firstOrdinal = [long]$Row.indexOrdinal; lastOrdinal = [long]$Row.indexOrdinal
            firstDestinationOrdinal = $null; hasFailure = $false; hasTlsFailure = $false; has407 = $false
            stageSet = @()
        }
    }
    $event = $Row.event
    $snapshot.eventCount = [long]$snapshot.eventCount + 1
    $snapshot.requestId = $event.requestId; $snapshot.connectionId = $event.connectionId
    $snapshot.source = [string]$event.source
    if ($null -ne $event.sourceIdentity) { $snapshot.sourceIdentity = $event.sourceIdentity }
    foreach ($name in @('host', 'scheme', 'port', 'path', 'method', 'statusCode')) {
        $value = Get-MihariTrafficMemberValue -InputObject $event.data -Name $name
        if ($name -eq 'statusCode' -and $null -eq $value) { $value = Get-MihariTrafficMemberValue -InputObject $event.data -Name 'proxyStatus' }
        if ($null -ne $value) {
            if ($name -eq 'path') { $snapshot[$name] = ConvertTo-MihariTrafficPath -Value $value }
            elseif ($name -eq 'port' -or $name -eq 'statusCode') { $snapshot[$name] = [long]$value }
            else { $snapshot[$name] = ConvertTo-MihariTrafficText -Value $value -MaximumLength 2048 }
        }
    }
    $protocol = Get-MihariTrafficMemberValue -InputObject $event.data -Name 'protocol'
    if ($null -eq $protocol) { $protocol = Get-MihariTrafficMemberValue -InputObject $event -Name 'protocol' }
    if ($null -ne $protocol) { $snapshot.protocol = ConvertTo-MihariTrafficText -Value $protocol -MaximumLength 64 }
    if ($null -ne $event.mode) { $snapshot.mode = [string]$event.mode }
    if ($null -ne $event.stage) {
        $snapshot.stage = [string]$event.stage
        $stages = New-Object 'System.Collections.Generic.List[string]'
        foreach ($stage in @($snapshot.stageSet)) { if ($null -ne $stage) { $stages.Add([string]$stage) } }
        $known = $false
        foreach ($stage in $stages) { if ([string]::Equals($stage, [string]$event.stage, [StringComparison]::OrdinalIgnoreCase)) { $known = $true; break } }
        if (-not $known -and $stages.Count -lt 128) { $stages.Add([string]$event.stage) }
        $snapshot.stageSet = @($stages.ToArray())
    }
    if ($null -ne $event.outcome) { $snapshot.outcome = [string]$event.outcome }
    if ($null -ne $event.elapsedMs) { $snapshot.elapsedMs = [long]$event.elapsedMs }
    if ($null -ne $event.timestamp) { $snapshot.lastEventAt = [string]$event.timestamp }
    if ($null -ne $event.sequence) { $snapshot.lastSequence = $event.sequence }
    $snapshot.lastOffset = [long]$Row.offset; $snapshot.lastOrdinal = [long]$Row.indexOrdinal
    $snapshot.coverage = [string]$event.coverage
    foreach ($name in @('transportLeg', 'upstreamConnectionId', 'streamId', 'configurationRevision', 'caseId', 'trialId')) {
        if ($null -ne $event.$name) { $snapshot[$name] = $event.$name }
    }
    $failed = Test-MihariTrafficFailureOutcome -Outcome ([string]$event.outcome)
    $status = Get-MihariTrafficMemberValue -InputObject $event.data -Name 'statusCode'
    $proxyStatus = Get-MihariTrafficMemberValue -InputObject $event.data -Name 'proxyStatus'
    if ($null -ne $status -and [long]$status -ge 400) { $failed = $true }
    if ($failed) {
        $snapshot.hasFailure = $true
        $snapshot.failureStage = [string]$event.stage
        if ([string]$event.stage -match '(?i)tls') { $snapshot.hasTlsFailure = $true }
    }
    if (($null -ne $status -and [long]$status -eq 407) -or ($null -ne $proxyStatus -and [long]$proxyStatus -eq 407)) { $snapshot.has407 = $true }
    $destinationKey = Get-MihariTrafficDestinationKey -Event $event
    if ($null -ne $destinationKey) {
        $destinationPath = Join-Path $Store.DestinationsDirectory ((Get-MihariTrafficHash -Text $destinationKey) + '.json')
        if (-not [System.IO.File]::Exists($destinationPath)) {
            $destination = [ordered]@{
                host = [string]$event.data.host; port = $event.data.port; firstOrdinal = [long]$Row.indexOrdinal
                firstOffset = [long]$Row.offset; eventId = $event.eventId; timestamp = $event.timestamp
            }
            Write-MihariTrafficAtomicJson -Path $destinationPath -Value $destination
        }
        if ([string]::Equals([string]$snapshot.host, [string]$event.data.host, [StringComparison]::OrdinalIgnoreCase) -and
            [string]::Equals([string]$snapshot.port, [string]$event.data.port, [StringComparison]::OrdinalIgnoreCase)) {
            $firstDestination = Get-MihariTrafficDestinationFirstOrdinal -Store $Store -HostName ([string]$event.data.host) -Port $event.data.port
            if ($null -ne $firstDestination) { $snapshot.firstDestinationOrdinal = [long]$firstDestination }
        }
    }
    Write-MihariTrafficAtomicJson -Path $snapshotPath -Value $snapshot
}

function Get-MihariTrafficSnapshotSummary {
    param([Parameter(Mandatory = $true)][object]$Snapshot)
    $stageSet = @{}
    foreach ($stage in @($Snapshot.stageSet)) { if (-not [string]::IsNullOrWhiteSpace([string]$stage)) { $stageSet[[string]$stage] = $true } }
    $public = [ordered]@{}
    foreach ($name in @('key', 'sessionId', 'requestId', 'connectionId', 'source', 'sourceIdentity', 'host', 'scheme', 'port',
            'path', 'method', 'statusCode', 'mode', 'protocol', 'stage', 'outcome', 'failureStage', 'elapsedMs',
            'startedAt', 'lastEventAt', 'firstSequence', 'lastSequence', 'firstOffset', 'lastOffset', 'eventCount',
            'coverage', 'transportLeg', 'upstreamConnectionId', 'streamId', 'configurationRevision', 'caseId', 'trialId',
            'connectionOnly', 'firstOrdinal', 'lastOrdinal', 'firstDestinationOrdinal')) {
        $public[$name] = $Snapshot.$name
    }
    return [pscustomobject]@{
        Request = [pscustomobject]$public; StageSet = $stageSet
        HasFailure = [bool]$Snapshot.hasFailure; HasTlsFailure = [bool]$Snapshot.hasTlsFailure; Has407 = [bool]$Snapshot.has407
        FirstOrdinal = [long]$Snapshot.firstOrdinal; LastOrdinal = [long]$Snapshot.lastOrdinal
    }
}

function Add-MihariTrafficProjectionEvent {
    param(
        [Parameter(Mandatory = $true)][object]$Store,
        [Parameter(Mandatory = $true)][object]$Event,
        [Parameter(Mandatory = $true)][long]$Ordinal,
        [Parameter(Mandatory = $true)][long]$Offset,
        [Parameter(Mandatory = $true)][long]$Length
    )
    $key = Get-MihariTrafficRequestKey -Event $Event -FallbackOrdinal $Ordinal
    $row = [ordered]@{
        indexOrdinal = $Ordinal; generation = [int]$Store.Generation; generationId = [string]$Store.GenerationId
        offset = $Offset; length = $Length; sequence = $Event.sequence; eventId = $Event.eventId
        requestKey = $key; event = $Event
    }
    Write-MihariTrafficJsonLine -Path $Store.EventsIndexPath -Value ([pscustomobject]$row)
    if ($null -ne $key) {
        $requestPath = Get-MihariTrafficRequestIndexPath -Store $Store -FirstOrdinal $Ordinal -Key $key
        Write-MihariTrafficJsonLine -Path $requestPath -Value ([pscustomobject]$row)
        $destinationKey = Get-MihariTrafficDestinationKey -Event $Event
        if ($null -ne $destinationKey) {
            $destinationPath = Join-Path $Store.DestinationsDirectory ((Get-MihariTrafficHash -Text $destinationKey) + '.json')
            if (-not [System.IO.File]::Exists($destinationPath)) {
                $destination = [ordered]@{
                    host = [string]$Event.data.host
                    port = (Get-MihariTrafficMemberValue -InputObject $Event.data -Name 'port')
                    firstOrdinal = $Ordinal; firstOffset = $Offset; eventId = $Event.eventId; timestamp = $Event.timestamp
                }
                [System.IO.File]::WriteAllText($destinationPath,
                    (ConvertTo-Json -InputObject $destination -Depth 5 -Compress), [System.Text.UTF8Encoding]::new($false))
            }
        }
        Update-MihariTrafficRequestSnapshot -Store $Store -Row ([pscustomobject]$row)
        $snapshotPath = Join-Path $Store.SummariesDirectory ((Get-MihariTrafficHash -Text $key) + '.json')
        $snapshotValue = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($snapshotPath, [System.Text.Encoding]::UTF8)) -ErrorAction Stop
        $summary = (Get-MihariTrafficSnapshotSummary -Snapshot $snapshotValue).Request
        for ($index = 0; $index -lt $Store.HotRequests.Count; $index++) {
            if ([string]::Equals([string]$Store.HotRequests[$index].key, $key, [StringComparison]::Ordinal)) {
                $Store.HotRequests.RemoveAt($index); break
            }
        }
        [void]$Store.HotRequests.Add($summary)
        while ($Store.HotRequests.Count -gt $Store.HotLimit) { $Store.HotRequests.RemoveAt(0) }
    }
    [void]$Store.HotEvents.Add($Event)
    while ($Store.HotEvents.Count -gt $Store.HotLimit) { $Store.HotEvents.RemoveAt(0) }
    $Store.NewEvents += ,$Event
    $Store.LastEventUtc = [string]$Event.timestamp
}

function Add-MihariTrafficProjectionLine {
    param(
        [Parameter(Mandatory = $true)][object]$Store,
        [Parameter(Mandatory = $true)][byte[]]$LineBytes,
        [Parameter(Mandatory = $true)][long]$LineStart,
        [Parameter(Mandatory = $true)][long]$NextOffset,
        [Parameter(Mandatory = $true)][long]$LineLength
    )
    $Store.Ordinal = [long]$Store.Ordinal + 1
    $line = [System.Text.Encoding]::UTF8.GetString($LineBytes).TrimEnd([char]13)
    if ($line.Length -gt 0 -and [int]$line[0] -eq 0xfeff) { $line = $line.Substring(1) }
    $event = $null
    try {
        if ([string]::IsNullOrWhiteSpace($line)) { throw 'blank_line' }
        $raw = ConvertFrom-Json -InputObject $line -ErrorAction Stop
        if ($null -eq $raw -or $raw -is [System.Array]) { throw 'invalid_record' }
        $event = ConvertTo-MihariTrafficSafeEvent -Event $raw
        if ([string]::IsNullOrWhiteSpace([string]$event.sessionId) -or [string]$event.sessionId -ne [string]$Store.SessionId) {
            $event = $null
            $Store.Counters.UnprojectableLineCount = [long]$Store.Counters.UnprojectableLineCount + 1
        }
    }
    catch {
        $event = $null
        $Store.Counters.MalformedLineCount = [long]$Store.Counters.MalformedLineCount + 1
    }
    if ($null -ne $event) {
        if ($null -ne $event.sequence) {
            $sequence = [long]$event.sequence
            if ($null -ne $Store.LastSequence -and $sequence -le [long]$Store.LastSequence) {
                $Store.Counters.SequenceViolationCount = [long]$Store.Counters.SequenceViolationCount + 1
            }
            if ($null -eq $Store.LastSequence -or $sequence -gt [long]$Store.LastSequence) { $Store.LastSequence = $sequence }
        }
        Add-MihariTrafficProjectionEvent -Store $Store -Event $event -Ordinal ([long]$Store.Ordinal) -Offset $LineStart -Length $LineLength
    }
    Set-MihariTrafficProjectionAnchor -Store $Store -LineStart $LineStart -LineBytes $LineBytes
    $Store.Offset = $NextOffset
    $Store.PendingOffset = -1; $Store.PendingBytes = 0
    if ($null -ne $event) { $Store.FreshnessUtc = [DateTime]::UtcNow.ToString('o', [Globalization.CultureInfo]::InvariantCulture) }
    Save-MihariTrafficProjectionState -Store $Store
}

function Update-MihariTrafficProjectionStore {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][object]$Store,
        [ValidateRange(1, 20000)][int]$MaximumEventsPerPoll = 2048,
        [ValidateRange(65536, 16777216)][int]$MaximumBytesPerPoll = 4194304
    )
    [System.Threading.Monitor]::Enter($Store.SyncRoot)
    try {
        $Store.NewEvents = @()
        if (-not [System.IO.File]::Exists($Store.EventsPath)) {
            $Store.Backlog = $false
            $Store.FreshnessUtc = [DateTime]::UtcNow.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
            Save-MihariTrafficProjectionState -Store $Store
            return $Store
        }
        $share = [System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete
        $stream = [System.IO.File]::Open($Store.EventsPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, $share)
        try {
            $fileInfo = New-Object System.IO.FileInfo($Store.EventsPath)
            $createdTicks = [long]$fileInfo.CreationTimeUtc.Ticks
            $rotated = $false
            if ([long]$Store.FileCreatedUtcTicks -gt 0 -and $createdTicks -gt 0 -and $createdTicks -ne [long]$Store.FileCreatedUtcTicks) { $rotated = $true }
            if ([long]$stream.Length -lt [long]$Store.Offset) { $rotated = $true }
            if (-not $rotated -and [long]$Store.AnchorLength -gt 0 -and -not (Test-MihariTrafficProjectionAnchor -Store $Store -Stream $stream)) { $rotated = $true }
            if ($rotated) { Reset-MihariTrafficProjectionGeneration -Store $Store -FileCreatedUtcTicks $createdTicks }
            elseif ([long]$Store.FileCreatedUtcTicks -eq 0) { $Store.FileCreatedUtcTicks = $createdTicks }

            if ([bool]$Store.DiscardingLine) {
                if ([long]$stream.Length -lt [long]$Store.DiscardScanOffset) {
                    Reset-MihariTrafficProjectionGeneration -Store $Store -FileCreatedUtcTicks $createdTicks
                }
                else {
                    $stream.Position = [long]$Store.DiscardScanOffset
                    $count = [int][Math]::Min([long]$MaximumBytesPerPoll, [long]$stream.Length - $stream.Position)
                    $buffer = New-Object byte[] $count
                    $read = 0
                    while ($read -lt $count) { $got = $stream.Read($buffer, $read, $count - $read); if ($got -le 0) { break }; $read += $got }
                    $newline = [Array]::IndexOf($buffer, [byte]10, 0, $read)
                    if ($newline -ge 0) {
                        $Store.Ordinal = [long]$Store.Ordinal + 1
                        $Store.Counters.MalformedLineCount = [long]$Store.Counters.MalformedLineCount + 1
                        $Store.Offset = [long]$Store.DiscardScanOffset + $newline + 1
                        $Store.DiscardingLine = $false; $Store.DiscardStartOffset = -1; $Store.DiscardScanOffset = -1
                        $Store.PendingOffset = -1; $Store.PendingBytes = 0
                        Save-MihariTrafficProjectionState -Store $Store
                    }
                    else {
                        $Store.DiscardScanOffset = [long]$Store.DiscardScanOffset + $read
                        if ($read -gt 0) { Save-MihariTrafficProjectionState -Store $Store }
                        $Store.Backlog = $true
                        return $Store
                    }
                }
            }

            $processed = 0
            while ($processed -lt $MaximumEventsPerPoll -and [long]$Store.Offset -lt [long]$stream.Length) {
                $baseOffset = [long]$Store.Offset
                $stream.Position = $baseOffset
                $count = [int][Math]::Min([long]$MaximumBytesPerPoll, [long]$stream.Length - $stream.Position)
                if ($count -le 0) { break }
                $buffer = New-Object byte[] $count
                $read = 0
                while ($read -lt $count) { $got = $stream.Read($buffer, $read, $count - $read); if ($got -le 0) { break }; $read += $got }
                if ($read -le 0) { break }
                $position = 0
                while ($position -lt $read -and $processed -lt $MaximumEventsPerPoll) {
                    $newline = [Array]::IndexOf($buffer, [byte]10, $position, $read - $position)
                    if ($newline -lt 0) {
                        $partialLength = $read - $position
                        if ($partialLength -gt $Store.MaximumLineBytes) {
                            $Store.DiscardingLine = $true
                            $Store.DiscardStartOffset = $baseOffset + $position
                            $Store.DiscardScanOffset = $baseOffset + $read
                            $Store.Counters.OversizeLineCount = [long]$Store.Counters.OversizeLineCount + 1
                            if ([long]$Store.PendingOffset -ne [long]$Store.DiscardStartOffset) {
                                $Store.Counters.IncompleteFinalLineCount = [long]$Store.Counters.IncompleteFinalLineCount + 1
                            }
                            $Store.PendingOffset = [long]$Store.DiscardStartOffset
                            $Store.PendingBytes = [long]$Store.DiscardScanOffset - [long]$Store.DiscardStartOffset
                        }
                        elseif ($partialLength -gt 0) {
                            $pendingAt = $baseOffset + $position
                            if ([long]$Store.PendingOffset -ne $pendingAt) {
                                $Store.Counters.IncompleteFinalLineCount = [long]$Store.Counters.IncompleteFinalLineCount + 1
                                $Store.PendingOffset = $pendingAt
                            }
                            $Store.PendingBytes = $partialLength
                        }
                        break
                    }
                    $lineLength = $newline - $position
                    $lineStart = $baseOffset + $position
                    $nextOffset = $baseOffset + $newline + 1
                    if ($lineLength -gt $Store.MaximumLineBytes) {
                        $Store.Ordinal = [long]$Store.Ordinal + 1
                        $Store.Counters.MalformedLineCount = [long]$Store.Counters.MalformedLineCount + 1
                        $Store.Counters.OversizeLineCount = [long]$Store.Counters.OversizeLineCount + 1
                        $Store.Offset = $nextOffset; $Store.PendingOffset = -1; $Store.PendingBytes = 0
                        Save-MihariTrafficProjectionState -Store $Store
                    }
                    else {
                        $lineBytes = New-Object byte[] $lineLength
                        if ($lineLength -gt 0) { [Array]::Copy($buffer, $position, $lineBytes, 0, $lineLength) }
                        if ([long]$Store.PendingOffset -eq $lineStart) { $Store.Counters.RecoveredPartialLineCount++ }
                        Add-MihariTrafficProjectionLine -Store $Store -LineBytes $lineBytes -LineStart $lineStart -NextOffset $nextOffset -LineLength ($lineLength + 1)
                    }
                    $processed++
                    $position = $newline + 1
                }
                if ($position -lt $read -and $processed -ge $MaximumEventsPerPoll) { break }
                if ($Store.DiscardingLine -or $position -ge $read) { break }
            }
            $pendingOnly = ([long]$Store.PendingOffset -ge 0 -and -not [bool]$Store.DiscardingLine -and
                [long]$Store.PendingOffset -eq [long]$Store.Offset -and [long]$Store.PendingBytes -eq ([long]$stream.Length - [long]$Store.Offset))
            $Store.Backlog = (([long]$Store.Offset -lt [long]$stream.Length) -and -not $pendingOnly)
            $Store.FreshnessUtc = [DateTime]::UtcNow.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
            Save-MihariTrafficProjectionState -Store $Store
            return $Store
        }
        finally { $stream.Dispose() }
    }
    finally { [System.Threading.Monitor]::Exit($Store.SyncRoot) }
}

function Get-MihariTrafficNormalizedFilters {
    param([AllowNull()][System.Collections.IDictionary]$Filters)
    $result = [ordered]@{}
    foreach ($name in @('host', 'pathPrefix', 'method', 'status', 'mode', 'protocol', 'stage', 'source', 'fromUtc', 'toUtc', 'preset')) {
        $value = $null
        if ($null -ne $Filters) {
            foreach ($key in $Filters.Keys) {
                if ([string]::Equals([string]$key, $name, [StringComparison]::OrdinalIgnoreCase)) { $value = $Filters[$key]; break }
            }
        }
        if ($null -eq $value -or [string]::IsNullOrWhiteSpace([string]$value)) { continue }
        $text = ([string]$value).Trim()
        if ($text.Length -gt 512) { throw [System.ArgumentException]::new(('The {0} filter exceeds 512 characters.' -f $name)) }
        if ($name -eq 'fromUtc' -or $name -eq 'toUtc') {
            $date = [DateTimeOffset]::MinValue
            $styles = [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal
            if (-not [DateTimeOffset]::TryParse($text, [Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$date)) {
                throw [System.ArgumentException]::new(('The {0} filter must be a UTC timestamp.' -f $name))
            }
            $text = $date.ToUniversalTime().ToString('o', [Globalization.CultureInfo]::InvariantCulture)
        }
        elseif ($name -eq 'status') {
            if ($text -notmatch '^(\d{3}|[1-5]xx|unknown)$') { throw [System.ArgumentException]::new('Status must be a code, 1xx through 5xx, or unknown.') }
            $text = $text.ToLowerInvariant()
        }
        elseif ($name -eq 'preset') {
            $text = $text.ToLowerInvariant()
            if ($text -notin @('failures', '407', 'tls-failures', 'slow', 'first-seen')) {
                throw [System.ArgumentException]::new('The requested traffic preset is unsupported.')
            }
        }
        elseif ($name -in @('method', 'mode', 'protocol', 'stage', 'source')) { $text = $text.ToLowerInvariant() }
        $result[$name] = $text
    }
    if ($result.Contains('fromUtc') -and $result.Contains('toUtc') -and
        [DateTimeOffset]::Parse([string]$result.fromUtc) -gt [DateTimeOffset]::Parse([string]$result.toUtc)) {
        throw [System.ArgumentException]::new('The fromUtc filter must not be later than toUtc.')
    }
    return $result
}

function Get-MihariTrafficFilterHash {
    param([Parameter(Mandatory = $true)][System.Collections.IDictionary]$Filters)
    return Get-MihariTrafficHash -Text (ConvertTo-Json -InputObject $Filters -Depth 4 -Compress -ErrorAction Stop)
}

function ConvertTo-MihariTrafficCursor {
    param([Parameter(Mandatory = $true)][object]$Value)
    $json = ConvertTo-Json -InputObject $Value -Depth 5 -Compress -ErrorAction Stop
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
    return ([Convert]::ToBase64String($bytes)).TrimEnd('=') -replace '\+', '-' -replace '/', '_'
}

function ConvertFrom-MihariTrafficCursor {
    param([Parameter(Mandatory = $true)][string]$Cursor)
    if ($Cursor.Length -gt 4096) { throw [System.ArgumentException]::new('The traffic cursor is too large.') }
    try {
        $value = $Cursor.Replace('-', '+').Replace('_', '/')
        while (($value.Length % 4) -ne 0) { $value += '=' }
        $bytes = [Convert]::FromBase64String($value)
        if ($bytes.Length -gt 3072) { throw 'cursor_too_large' }
        return (ConvertFrom-Json -InputObject ([System.Text.Encoding]::UTF8.GetString($bytes)) -ErrorAction Stop)
    }
    catch { throw [System.ArgumentException]::new('The traffic cursor is invalid.') }
}

function Test-MihariTrafficFailureOutcome {
    param([AllowNull()][string]$Outcome)
    $value = ([string]$Outcome -replace '[^A-Za-z]', '').ToLowerInvariant()
    return ($value -in @('failed', 'failure', 'error', 'unsupported', 'rejected', 'cancelled', 'canceled', 'timeout', 'timedout'))
}

function Get-MihariTrafficDestinationFirstOrdinal {
    param([Parameter(Mandatory = $true)][object]$Store, [Parameter(Mandatory = $true)][string]$HostName, [AllowNull()][object]$Port)
    if ([string]::IsNullOrWhiteSpace($HostName)) { return $null }
    if ($null -eq $Port) { $portText = 'unknown' } else { $portText = [string]$Port }
    $key = $HostName.Trim().TrimEnd('.').ToLowerInvariant() + ':' + $portText
    $path = Join-Path $Store.DestinationsDirectory ((Get-MihariTrafficHash -Text $key) + '.json')
    if (-not [System.IO.File]::Exists($path)) { return $null }
    try {
        $value = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($path, [System.Text.Encoding]::UTF8)) -ErrorAction Stop
        return [long]$value.firstOrdinal
    }
    catch { return $null }
}

function Get-MihariTrafficAttemptSummary {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][long]$MaximumOrdinal, [Parameter(Mandatory = $true)][object]$Store)
    $reader = $null
    $request = $null
    $firstOrdinal = [long]0
    $lastOrdinal = [long]0
    $stages = @{}
    $hasFailure = $false
    $hasTlsFailure = $false
    $has407 = $false
    $failureStage = $null
    try {
        $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete)
        $reader = New-Object System.IO.StreamReader($stream, [System.Text.Encoding]::UTF8, $true)
        while (-not $reader.EndOfStream) {
            $line = $reader.ReadLine()
            if ($null -eq $line -or $line.Length -gt 2097152) { continue }
            $row = $null
            try { $row = ConvertFrom-Json -InputObject $line -ErrorAction Stop } catch { continue }
            if ([long]$row.indexOrdinal -gt $MaximumOrdinal -or $null -eq $row.event) { continue }
            $event = $row.event
            if ($firstOrdinal -eq 0) {
                $firstOrdinal = [long]$row.indexOrdinal
                $request = [ordered]@{
                    key = [string]$row.requestKey; sessionId = [string]$event.sessionId; requestId = $event.requestId
                    connectionId = $event.connectionId; source = [string]$event.source; sourceIdentity = $event.sourceIdentity
                    host = $null; scheme = $null; port = $null; path = $null; method = $null; statusCode = $null
                    mode = $null; protocol = $null; stage = $null; outcome = $null; failureStage = $null
                    elapsedMs = $null; startedAt = $event.timestamp; lastEventAt = $event.timestamp
                    firstSequence = $event.sequence; lastSequence = $event.sequence; firstOffset = [long]$row.offset
                    lastOffset = [long]$row.offset; eventCount = [long]0; coverage = [string]$event.coverage
                    transportLeg = $event.transportLeg; upstreamConnectionId = $event.upstreamConnectionId
                    streamId = $event.streamId; configurationRevision = $event.configurationRevision
                    caseId = $event.caseId; trialId = $event.trialId; connectionOnly = ($null -eq $event.requestId)
                }
            }
            $lastOrdinal = [long]$row.indexOrdinal
            $request.eventCount = [long]$request.eventCount + 1
            $request.requestId = $event.requestId; $request.connectionId = $event.connectionId
            $request.source = [string]$event.source
            if ($null -ne $event.sourceIdentity) { $request.sourceIdentity = $event.sourceIdentity }
            foreach ($name in @('host', 'scheme', 'port', 'path', 'method', 'statusCode')) {
                $value = Get-MihariTrafficMemberValue -InputObject $event.data -Name $name
                if ($name -eq 'statusCode' -and $null -eq $value) { $value = Get-MihariTrafficMemberValue -InputObject $event.data -Name 'proxyStatus' }
                if ($null -ne $value) {
                    if ($name -eq 'path') { $request[$name] = ConvertTo-MihariTrafficPath -Value $value }
                    elseif ($name -eq 'port' -or $name -eq 'statusCode') { $request[$name] = [long]$value }
                    else { $request[$name] = ConvertTo-MihariTrafficText -Value $value -MaximumLength 2048 }
                }
            }
            $protocol = Get-MihariTrafficMemberValue -InputObject $event.data -Name 'protocol'
            if ($null -eq $protocol) { $protocol = Get-MihariTrafficMemberValue -InputObject $event -Name 'protocol' }
            if ($null -ne $protocol) { $request.protocol = ConvertTo-MihariTrafficText -Value $protocol -MaximumLength 64 }
            if ($null -ne $event.mode) { $request.mode = [string]$event.mode }
            if ($null -ne $event.stage) { $request.stage = [string]$event.stage; $stages[[string]$event.stage] = $true }
            if ($null -ne $event.outcome) { $request.outcome = [string]$event.outcome }
            if ($null -ne $event.elapsedMs) { $request.elapsedMs = [long]$event.elapsedMs }
            if ($null -ne $event.timestamp) { $request.lastEventAt = [string]$event.timestamp }
            if ($null -ne $event.sequence) { $request.lastSequence = $event.sequence }
            $request.lastOffset = [long]$row.offset; $request.coverage = [string]$event.coverage
            foreach ($name in @('transportLeg', 'upstreamConnectionId', 'streamId', 'configurationRevision', 'caseId', 'trialId')) {
                if ($null -ne $event.$name) { $request[$name] = $event.$name }
            }
            $failed = Test-MihariTrafficFailureOutcome -Outcome ([string]$event.outcome)
            $status = Get-MihariTrafficMemberValue -InputObject $event.data -Name 'statusCode'
            $proxyStatus = Get-MihariTrafficMemberValue -InputObject $event.data -Name 'proxyStatus'
            if ($null -ne $status -and [long]$status -ge 400) { $failed = $true }
            if ($failed) {
                $hasFailure = $true; $failureStage = [string]$event.stage
                if ([string]$event.stage -match '(?i)tls') { $hasTlsFailure = $true }
            }
            if (($null -ne $status -and [long]$status -eq 407) -or ($null -ne $proxyStatus -and [long]$proxyStatus -eq 407)) { $has407 = $true }
        }
    }
    catch {
        if ($null -ne $reader) { $reader.Dispose(); $reader = $null }
        return $null
    }
    finally { if ($null -ne $reader) { $reader.Dispose() } }
    if ($null -eq $request) { return $null }
    $request.failureStage = $failureStage
    $request.firstOrdinal = $firstOrdinal
    $request.lastOrdinal = $lastOrdinal
    $request.firstDestinationOrdinal = Get-MihariTrafficDestinationFirstOrdinal -Store $Store -HostName ([string]$request.host) -Port $request.port
    return [pscustomobject]@{
        Request = [pscustomobject]$request; StageSet = $stages; HasFailure = $hasFailure
        HasTlsFailure = $hasTlsFailure; Has407 = $has407; FirstOrdinal = $firstOrdinal; LastOrdinal = $lastOrdinal
    }
}

function Test-MihariTrafficRequestMatches {
    param([Parameter(Mandatory = $true)][object]$Summary, [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Filters)
    $request = $Summary.Request
    if ($Filters.Contains('host') -and ([string]$request.host).IndexOf([string]$Filters.host, [StringComparison]::OrdinalIgnoreCase) -lt 0) { return $false }
    if ($Filters.Contains('pathPrefix') -and ([string]$request.path).IndexOf([string]$Filters.pathPrefix, [StringComparison]::OrdinalIgnoreCase) -ne 0) { return $false }
    if ($Filters.Contains('method') -and -not [string]::Equals([string]$request.method, [string]$Filters.method, [StringComparison]::OrdinalIgnoreCase)) { return $false }
    if ($Filters.Contains('status')) {
        $status = [string]$Filters.status
        if ($status -eq 'unknown' -and $null -ne $request.statusCode) { return $false }
        if ($status -match '^([1-5])xx$' -and ($null -eq $request.statusCode -or [Math]::Floor(([long]$request.statusCode) / 100) -ne [int]$Matches[1])) { return $false }
        if ($status -match '^\d{3}$' -and ([string]$request.statusCode) -ne $status) { return $false }
    }
    if ($Filters.Contains('mode') -and -not [string]::Equals([string]$request.mode, [string]$Filters.mode, [StringComparison]::OrdinalIgnoreCase)) { return $false }
    if ($Filters.Contains('protocol') -and -not [string]::Equals([string]$request.protocol, [string]$Filters.protocol, [StringComparison]::OrdinalIgnoreCase)) { return $false }
    if ($Filters.Contains('stage')) {
        $found = $false
        foreach ($stage in $Summary.StageSet.Keys) {
            if ([string]::Equals([string]$stage, [string]$Filters.stage, [StringComparison]::OrdinalIgnoreCase)) { $found = $true; break }
        }
        if (-not $found) { return $false }
    }
    if ($Filters.Contains('source') -and -not [string]::Equals([string]$request.source, [string]$Filters.source, [StringComparison]::OrdinalIgnoreCase)) { return $false }
    if ($Filters.Contains('fromUtc') -or $Filters.Contains('toUtc')) {
        $timestamp = [DateTimeOffset]::MinValue
        $styles = [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal
        if (-not [DateTimeOffset]::TryParse([string]$request.startedAt, [Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$timestamp)) { return $false }
        if ($Filters.Contains('fromUtc') -and $timestamp -lt [DateTimeOffset]::Parse([string]$Filters.fromUtc)) { return $false }
        if ($Filters.Contains('toUtc') -and $timestamp -gt [DateTimeOffset]::Parse([string]$Filters.toUtc)) { return $false }
    }
    if ($Filters.Contains('preset')) {
        switch ([string]$Filters.preset) {
            'failures' { if (-not $Summary.HasFailure) { return $false } }
            '407' { if (-not $Summary.Has407) { return $false } }
            'tls-failures' { if (-not $Summary.HasTlsFailure) { return $false } }
            'slow' { if ($null -eq $request.elapsedMs -or [long]$request.elapsedMs -lt 1000) { return $false } }
            'first-seen' { if ($null -eq $request.firstDestinationOrdinal -or [long]$request.firstDestinationOrdinal -ne [long]$Summary.FirstOrdinal) { return $false } }
        }
    }
    return $true
}

function Get-MihariTrafficRequests {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][object]$Store,
        [AllowNull()][System.Collections.IDictionary]$Filters,
        [AllowNull()][string]$Cursor,
        [ValidateRange(1, 200)][int]$Limit = 100
    )
    $normalized = Get-MihariTrafficNormalizedFilters -Filters $Filters
    $filterHash = Get-MihariTrafficFilterHash -Filters $normalized
    $snapshotOrdinal = [long]$Store.Ordinal; $snapshotOffset = [long]$Store.Offset
    $generationId = [string]$Store.GenerationId
    $cursorOrdinal = [long]-1; $cursorKey = ''
    if (-not [string]::IsNullOrWhiteSpace($Cursor)) {
        $value = ConvertFrom-MihariTrafficCursor -Cursor $Cursor
        if ([int]$value.version -ne 1 -or [string]$value.sessionId -ne [string]$Store.SessionId -or [string]$value.filterHash -ne $filterHash) {
            throw [System.ArgumentException]::new('The traffic cursor does not match this request.')
        }
        if ([string]$value.generationId -ne $generationId) {
            $invalid = [System.InvalidOperationException]::new('The event file rotated; restart paging.')
            $invalid.Data['mihariCode'] = 'cursor_invalidated'
            throw $invalid
        }
        $snapshotOrdinal = [long]$value.snapshotOrdinal; $snapshotOffset = [long]$value.snapshotOffset
        if ($snapshotOrdinal -gt [long]$Store.Ordinal) {
            $invalid = [System.InvalidOperationException]::new('The cursor is ahead of indexed history.')
            $invalid.Data['mihariCode'] = 'cursor_invalidated'
            throw $invalid
        }
        $cursorOrdinal = [long]$value.lastFirstOrdinal; $cursorKey = [string]$value.lastKey
    }
    $scopeTotal = [long]0
    $candidates = New-Object 'System.Collections.Generic.List[object]'
    foreach ($path in [System.IO.Directory]::EnumerateFiles($Store.RequestsDirectory, '*.jsonl')) {
        $name = [System.IO.Path]::GetFileName($path)
        if ($name -notmatch '^(\d{20})-[a-f0-9]{64}\.jsonl$') { continue }
        $fileOrdinal = [long]::Parse($Matches[1], [Globalization.CultureInfo]::InvariantCulture)
        if ($fileOrdinal -gt $snapshotOrdinal) { continue }
        $summary = $null
        $snapshotPath = Join-Path $Store.SummariesDirectory ($Matches[0].Substring(21, 64) + '.json')
        if ([System.IO.File]::Exists($snapshotPath)) {
            try {
                $snapshotValue = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($snapshotPath, [System.Text.Encoding]::UTF8)) -ErrorAction Stop
                if ([long]$snapshotValue.lastOrdinal -le $snapshotOrdinal) { $summary = Get-MihariTrafficSnapshotSummary -Snapshot $snapshotValue }
            }
            catch { $summary = $null }
        }
        if ($null -eq $summary) { $summary = Get-MihariTrafficAttemptSummary -Path $path -MaximumOrdinal $snapshotOrdinal -Store $Store }
        if ($null -eq $summary -or $summary.FirstOrdinal -eq 0) { continue }
        if (-not (Test-MihariTrafficRequestMatches -Summary $summary -Filters $normalized)) { continue }
        $scopeTotal++
        $key = [string]$summary.Request.key
        if ($cursorOrdinal -ge 0) {
            $after = ($summary.FirstOrdinal -lt $cursorOrdinal)
            if ($summary.FirstOrdinal -eq $cursorOrdinal) { $after = [string]::CompareOrdinal($key, $cursorKey) -gt 0 }
            if (-not $after) { continue }
        }
        $candidates.Add([pscustomobject]@{ FirstOrdinal = $summary.FirstOrdinal; Key = $key; Request = $summary.Request })
        $sorted = @($candidates.ToArray() | Sort-Object -Property @{ Expression = 'FirstOrdinal'; Descending = $true }, @{ Expression = 'Key'; Ascending = $true })
        $candidates.Clear()
        foreach ($item in @($sorted | Select-Object -First ($Limit + 1))) { $candidates.Add($item) }
    }
    $hasMore = ($candidates.Count -gt $Limit)
    $page = @($candidates.ToArray() | Select-Object -First $Limit)
    $nextCursor = $null
    if ($hasMore -and $page.Length -gt 0) {
        $last = $page[$page.Length - 1]
        $payload = [pscustomobject][ordered]@{
            version = 1; sessionId = [string]$Store.SessionId; generationId = $generationId
            snapshotOrdinal = $snapshotOrdinal; snapshotOffset = $snapshotOffset; filterHash = $filterHash
            lastFirstOrdinal = [long]$last.FirstOrdinal; lastKey = [string]$last.Key
        }
        $nextCursor = ConvertTo-MihariTrafficCursor -Value $payload
    }
    $coverage = [pscustomobject][ordered]@{
        malformedLineCount = [long]$Store.Counters.MalformedLineCount
        incompleteFinalLineCount = [long]$Store.Counters.IncompleteFinalLineCount
        recoveredPartialLineCount = [long]$Store.Counters.RecoveredPartialLineCount
        rotationCount = [long]$Store.Counters.RotationCount; oversizeLineCount = [long]$Store.Counters.OversizeLineCount
        lostPartialLineCount = [long]$Store.Counters.LostPartialLineCount
        sequenceViolationCount = [long]$Store.Counters.SequenceViolationCount
        unprojectableLineCount = [long]$Store.Counters.UnprojectableLineCount
        backlog = [bool]$Store.Backlog; generation = [int]$Store.Generation
        hotRequestCount = [int]$Store.HotRequests.Count; hotRequestLimit = [int]$Store.HotLimit
    }
    return [pscustomobject][ordered]@{
        items = @($page | ForEach-Object { $_.Request }); nextCursor = $nextCursor
        revision = ('{0}:{1}:{2}' -f $generationId, $snapshotOrdinal, $snapshotOffset)
        ordering = 'firstObserved.desc,requestKey.asc'; scopeTotal = $scopeTotal
        coverage = $coverage; freshnessUtc = $Store.FreshnessUtc
    }
}

function Get-MihariTrafficRequestDetail {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][object]$Store,
        [Parameter(Mandatory = $true)][string]$Key,
        [ValidateRange(1, 200)][int]$MaximumEvents = 200
    )
    $hash = Get-MihariTrafficHash -Text $Key
    $path = $null
    foreach ($candidate in [System.IO.Directory]::EnumerateFiles($Store.RequestsDirectory, '*-' + $hash + '.jsonl')) {
        if ([System.IO.Path]::GetFileName($candidate) -match '^\d{20}-[a-f0-9]{64}\.jsonl$') { $path = $candidate; break }
    }
    if ($null -eq $path) { return $null }
    $maximumOrdinal = [long]$Store.Ordinal
    $summary = Get-MihariTrafficAttemptSummary -Path $path -MaximumOrdinal $maximumOrdinal -Store $Store
    if ($null -eq $summary -or -not [string]::Equals([string]$summary.Request.key, $Key, [StringComparison]::Ordinal)) { return $null }
    $events = New-Object 'System.Collections.Generic.List[object]'
    $evidence = New-Object 'System.Collections.Generic.List[object]'
    $reader = $null
    try {
        $stream = [System.IO.File]::Open($path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete)
        $reader = New-Object System.IO.StreamReader($stream, [System.Text.Encoding]::UTF8, $true)
        while (-not $reader.EndOfStream) {
            $line = $reader.ReadLine()
            if ($null -eq $line -or $line.Length -gt 2097152) { continue }
            $row = $null
            try { $row = ConvertFrom-Json -InputObject $line -ErrorAction Stop } catch { continue }
            if ([long]$row.indexOrdinal -gt $maximumOrdinal -or $null -eq $row.event) { continue }
            if (-not [string]::Equals([string]$row.requestKey, $Key, [StringComparison]::Ordinal)) { continue }
            if ($events.Count -ge $MaximumEvents) { $events.RemoveAt(0); $evidence.RemoveAt(0) }
            $events.Add($row.event)
            $evidence.Add([pscustomobject][ordered]@{
                sessionId = [string]$row.event.sessionId; eventId = $row.event.eventId
                sequence = $row.event.sequence; generation = [int]$row.generation; offset = [long]$row.offset
            })
        }
    }
    finally { if ($null -ne $reader) { $reader.Dispose() } }
    return [pscustomobject][ordered]@{
        request = $summary.Request; events = @($events.ToArray()); evidence = @($evidence.ToArray())
        eventCount = [long]$summary.Request.eventCount; eventsTruncated = ([long]$summary.Request.eventCount -gt $MaximumEvents)
        revision = ('{0}:{1}:{2}' -f $Store.GenerationId, $maximumOrdinal, $Store.Offset)
    }
}

function Get-MihariTrafficProjectionEvents {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][object]$Store,
        [ValidateRange(0, 2147483647)][long]$AfterOrdinal = 0,
        [ValidateRange(1, 20000)][int]$Limit = 1000
    )
    $events = New-Object 'System.Collections.Generic.List[object]'
    $reader = $null
    $lastOrdinal = $AfterOrdinal
    $hasMore = $false
    if ([System.IO.File]::Exists($Store.EventsIndexPath)) {
        try {
            $stream = [System.IO.File]::Open($Store.EventsIndexPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete)
            $reader = New-Object System.IO.StreamReader($stream, [System.Text.Encoding]::UTF8, $true)
            while (-not $reader.EndOfStream) {
                $line = $reader.ReadLine()
                if ($null -eq $line -or $line.Length -gt 2097152) { continue }
                $row = $null
                try { $row = ConvertFrom-Json -InputObject $line -ErrorAction Stop } catch { continue }
                $ordinal = [long]$row.indexOrdinal
                if ($ordinal -le $AfterOrdinal) { continue }
                if ($events.Count -ge $Limit) { $hasMore = $true; break }
                if ($null -ne $row.event) {
                    $events.Add([pscustomobject]@{ ordinal = $ordinal; offset = [long]$row.offset; generation = [int]$row.generation; event = $row.event })
                }
                $lastOrdinal = $ordinal
            }
        }
        finally { if ($null -ne $reader) { $reader.Dispose() } }
    }
    return [pscustomobject]@{ events = @($events.ToArray()); nextOrdinal = $lastOrdinal; hasMore = $hasMore }
}
