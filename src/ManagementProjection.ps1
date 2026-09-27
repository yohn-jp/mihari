# Safe, bounded projections for the local management API. Event JSONL remains
# the canonical store; this layer exposes only fields the UI needs to render.

function ConvertTo-MihariManagementScalar {
    param(
        [AllowNull()][object] $Value,
        [ValidateRange(1, 1024)][int] $MaximumLength = 256
    )

    if ($null -eq $Value -or $Value -is [System.Collections.IDictionary] -or $Value -is [System.Array]) {
        return $null
    }
    if ($Value -isnot [string] -and $Value -isnot [char] -and -not $Value.GetType().IsPrimitive -and
        $Value -isnot [decimal] -and $Value -isnot [DateTime] -and $Value -isnot [DateTimeOffset]) {
        return $null
    }

    $text = ConvertTo-MihariSafeText -Text ([string]$Value)
    if ($text.Length -gt $MaximumLength) { $text = $text.Substring(0, $MaximumLength) }
    if ($text.Length -eq 0) { return $null }
    return $text
}

function ConvertTo-MihariManagementNumber {
    param([AllowNull()][object] $Value)

    if ($null -eq $Value -or $Value -is [bool] -or
        $Value -is [System.Collections.IDictionary] -or $Value -is [System.Array]) {
        return $null
    }
    $number = [decimal]0
    if (-not [decimal]::TryParse([string]$Value, [Globalization.NumberStyles]::Float,
            [Globalization.CultureInfo]::InvariantCulture, [ref]$number) -or
        $number -lt [decimal]::MinValue -or $number -gt [decimal]::MaxValue) {
        return $null
    }
    return $number
}

function ConvertTo-MihariManagementEvent {
    param([Parameter(Mandatory = $true)][object] $Event)

    $eventId = ConvertTo-MihariManagementScalar -Value (Get-MihariMemberValue -InputObject $Event -Names @('eventId')) -MaximumLength 128
    $sessionId = ConvertTo-MihariManagementScalar -Value (Get-MihariMemberValue -InputObject $Event -Names @('sessionId')) -MaximumLength 128
    $connectionId = ConvertTo-MihariManagementScalar -Value (Get-MihariMemberValue -InputObject $Event -Names @('connectionId')) -MaximumLength 128
    $requestId = ConvertTo-MihariManagementScalar -Value (Get-MihariMemberValue -InputObject $Event -Names @('requestId')) -MaximumLength 128
    $timestamp = ConvertTo-MihariManagementScalar -Value (Get-MihariMemberValue -InputObject $Event -Names @('timestamp')) -MaximumLength 40
    $mode = ConvertTo-MihariManagementScalar -Value (Get-MihariMemberValue -InputObject $Event -Names @('mode')) -MaximumLength 16
    $stage = ConvertTo-MihariManagementScalar -Value (Get-MihariMemberValue -InputObject $Event -Names @('stage')) -MaximumLength 64
    $outcome = ConvertTo-MihariManagementScalar -Value (Get-MihariMemberValue -InputObject $Event -Names @('outcome')) -MaximumLength 32
    $elapsed = ConvertTo-MihariManagementNumber -Value (Get-MihariMemberValue -InputObject $Event -Names @('elapsedMs'))
    $schemaVersion = ConvertTo-MihariManagementNumber -Value (Get-MihariMemberValue -InputObject $Event -Names @('schemaVersion'))
    $sequence = ConvertTo-MihariManagementNumber -Value (Get-MihariMemberValue -InputObject $Event -Names @('sequence'))
    $source = ConvertTo-MihariManagementScalar -Value (Get-MihariMemberValue -InputObject $Event -Names @('source')) -MaximumLength 32
    if ($null -eq $source) { $source = 'proxy' }
    $coverage = ConvertTo-MihariManagementScalar -Value (Get-MihariMemberValue -InputObject $Event -Names @('coverage')) -MaximumLength 32
    if ($null -eq $coverage) { $coverage = 'unknown' }
    $rawData = Get-MihariEventData -Event $Event
    $projectedData = [ordered]@{}

    $stringFields = @(
        'host', 'scheme', 'method', 'routeKind', 'routeSource', 'proxyHost',
        'clientEndpoint', 'direction', 'tlsProtocol', 'tlsCipher', 'tlsCipherSuite', 'certificateSubject',
        'certificateIssuer', 'certificateThumbprint', 'certificateNotBefore',
        'certificateNotAfter', 'errorType', 'errorCode', 'reason',
        'unsupportedProtocol', 'mode', 'previousMode', 'tlsAlpn',
        'certificateChainState', 'hostnameState', 'validityState',
        'ekuState', 'revocationState', 'validationPolicy', 'peerIdentityRole',
        'clientCertificateState', 'protocol', 'initiatorType', 'browserTargetId',
        'browserRequestId', 'browserConnectionId', 'browserFrameId', 'browserError',
        'browserTimingOrigin', 'requestFraming', 'responseFraming',
        'connectionPolicy', 'framing'
    )
    foreach ($name in $stringFields) {
        $value = Get-MihariMemberValue -InputObject $rawData -Names @($name)
        $maximumLength = 256
        if ($name -eq 'certificateSubject' -or $name -eq 'certificateIssuer') { $maximumLength = 512 }
        elseif ($name -eq 'clientEndpoint') { $maximumLength = 128 }
        $safeValue = ConvertTo-MihariManagementScalar -Value $value -MaximumLength $maximumLength
        if ($null -ne $safeValue) { $projectedData[$name] = $safeValue }
    }

    $path = ConvertTo-MihariPath -Value (Get-MihariMemberValue -InputObject $rawData -Names @('path'))
    if ($null -ne $path) { $projectedData['path'] = $path }

    foreach ($name in @('port', 'proxyPort', 'statusCode', 'proxyStatus', 'bytesClientToUpstream', 'bytesUpstreamToClient', 'tlsCipherStrength', 'browserRedirectIndex', 'browserTimingStartMs', 'browserTimingDurationMs', 'requestBytes', 'responseBytes', 'bytes', 'firstByteMs', 'lastByteMs', 'forwardWriteMs', 'workerOccupancy', 'maxWorkers', 'workingSetBytes', 'cpuTotalMs', 'evidenceBytes', 'writerLagMs', 'activeLongLivedCount', 'queueLength', 'queueCapacity', 'queuePeak', 'saturationCount', 'browserDroppedTargetCount', 'browserDroppedRequestCount')) {
        $number = ConvertTo-MihariManagementNumber -Value (Get-MihariMemberValue -InputObject $rawData -Names @($name))
        if ($null -ne $number -and $number -ge 0 -and $number -le [decimal]([long]::MaxValue)) {
            $projectedData[$name] = [long][Math]::Truncate($number)
        }
    }
    foreach ($name in @('certificateAccepted', 'caTrusted', 'fromDiskCache', 'fromServiceWorker', 'reused', 'queueSaturated', 'pendingConnections')) {
        $value = Get-MihariMemberValue -InputObject $rawData -Names @($name)
        if ($value -is [bool]) { $projectedData[$name] = $value }
    }
    $rawChain = Get-MihariMemberValue -InputObject $rawData -Names @('certificateChain')
    if ($null -ne $rawChain) {
        $safeChain = New-Object 'System.Collections.Generic.List[object]'
        foreach ($element in @(@($rawChain) | Select-Object -First 8)) {
            if ($null -eq $element) { continue }
            $safeElement = [ordered]@{}
            foreach ($field in @('subject', 'issuer', 'thumbprint', 'notBefore', 'notAfter')) {
                $safeValue = ConvertTo-MihariManagementScalar -Value (Get-MihariMemberValue -InputObject $element -Names @($field)) -MaximumLength 256
                if ($null -ne $safeValue) { $safeElement[$field] = $safeValue }
            }
            if ($safeElement.Count -gt 0) { $safeChain.Add([pscustomobject]$safeElement) }
        }
        $projectedData['certificateChain'] = @($safeChain.ToArray())
    }

    $eventProjection = [ordered]@{
        schemaVersion = $schemaVersion
        sequence = $sequence
        eventId = $eventId
        timestamp = $timestamp
        sessionId = $sessionId
        connectionId = $connectionId
        requestId = $requestId
        mode = $mode
        stage = $stage
        outcome = $outcome
        elapsedMs = $elapsed
        source = $source
        coverage = $coverage
        data = [pscustomobject]$projectedData
    }
    foreach ($name in @('caseId', 'trialId', 'configurationRevision', 'transportLeg', 'upstreamConnectionId', 'streamId', 'sourceIdentity', 'sourceVersion', 'monotonicTicks', 'clockId')) {
        $value = Get-MihariMemberValue -InputObject $Event -Names @($name)
        if ($null -eq $value) { continue }
        if ($name -in @('configurationRevision', 'monotonicTicks')) {
            $number = ConvertTo-MihariManagementNumber -Value $value
            if ($null -ne $number -and $number -ge 0 -and $number -le [decimal]([long]::MaxValue)) { $eventProjection[$name] = [long]$number }
        }
        else {
            $safeValue = ConvertTo-MihariManagementScalar -Value $value -MaximumLength 128
            if ($null -ne $safeValue) { $eventProjection[$name] = $safeValue }
        }
    }
    return [pscustomobject]$eventProjection
}

function Read-MihariManagementEventWindow {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [ValidateRange(1, 200)][int] $MaximumEvents = 200
    )

    $result = [pscustomobject]@{
        Events = @()
        Truncated = $false
        MalformedLineCount = 0
        ReadError = $null
    }
    if ([string]::IsNullOrWhiteSpace($Path) -or -not [System.IO.File]::Exists($Path)) { return $result }

    # Bound both byte IO and parsed objects. Recent browser activity is the UI's
    # purpose; old event history remains available through the report command.
    $maximumBytes = 2097152
    $stream = $null
    try {
        $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        $fileLength = [long]$stream.Length
        $start = [long][Math]::Max(0, $fileLength - $maximumBytes)
        if ($start -gt 0) { $result.Truncated = $true }
        $stream.Position = $start
        $readLimit = [int][Math]::Min($maximumBytes, $fileLength - $start)
        $bytes = New-Object byte[] $readLimit
        $read = 0
        while ($read -lt $readLimit) {
            $count = $stream.Read($bytes, $read, $readLimit - $read)
            if ($count -le 0) { break }
            $read += $count
        }
        $text = [System.Text.Encoding]::UTF8.GetString($bytes, 0, $read)
        if ($start -gt 0) {
            $firstNewline = $text.IndexOf("`n")
            if ($firstNewline -lt 0) {
                $text = ''
            }
            else {
                $text = $text.Substring($firstNewline + 1)
            }
        }
        $lastNewline = $text.LastIndexOf("`n")
        if ($lastNewline -ge 0) { $text = $text.Substring(0, $lastNewline) }
        else { $text = '' }

        if ($text.Length -eq 0) { return $result }
        $lines = $text.Split([char]"`n")
        $firstIndex = [Math]::Max(0, $lines.Length - $MaximumEvents)
        if ($firstIndex -gt 0) { $result.Truncated = $true }
        $events = New-Object 'System.Collections.Generic.List[object]'
        for ($index = $firstIndex; $index -lt $lines.Length; $index++) {
            $line = $lines[$index].TrimEnd("`r")
            if ([string]::IsNullOrWhiteSpace($line)) { continue }
            try {
                $event = ConvertFrom-Json -InputObject $line -ErrorAction Stop
                if ($null -ne $event) { $events.Add($event) }
            }
            catch {
                $result.MalformedLineCount = [int]$result.MalformedLineCount + 1
            }
        }
        $projected = New-Object 'System.Collections.Generic.List[object]'
        foreach ($event in $events) {
            $projected.Add((ConvertTo-MihariManagementEvent -Event $event))
        }
        $result.Events = @($projected.ToArray())
    }
    catch {
        # The management UI remains usable if the event stream is momentarily
        # unavailable. Do not return exception text, which may contain input.
        $result.ReadError = 'event_stream_unavailable'
    }
    finally {
        if ($null -ne $stream) { $stream.Dispose() }
    }
    return $result
}

function Test-MihariManagementTerminalEvent {
    param([Parameter(Mandatory = $true)][object] $Event)

    $stage = [string]$Event.stage
    if ($stage -in @('tunnel.relay', 'response.relay', 'connection.cleanup')) { return $true }
    $outcome = ([string]$Event.outcome -replace '[^A-Za-z]', '').ToLowerInvariant()
    return @('failed', 'failure', 'error', 'unsupported', 'rejected', 'cancelled', 'canceled') -contains $outcome
}

function Get-MihariManagementConnections {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]] $Events,
        [Parameter(Mandatory = $true)][bool] $SessionRunning,
        [ValidateRange(1, 200)][int] $MaximumConnections = 100
    )

    $groups = @{}
    foreach ($event in $Events) {
        $connectionId = [string]$event.connectionId
        if ([string]::IsNullOrWhiteSpace($connectionId) -or $connectionId -eq 'session') { continue }
        if (-not $groups.ContainsKey($connectionId)) {
            $groups[$connectionId] = New-Object 'System.Collections.Generic.List[object]'
        }
        $groups[$connectionId].Add($event)
    }

    $connections = New-Object 'System.Collections.Generic.List[object]'
    foreach ($connectionId in $groups.Keys) {
        $connectionEvents = $groups[$connectionId]
        if ($connectionEvents.Count -eq 0) { continue }
        $first = $connectionEvents[0]
        $last = $connectionEvents[$connectionEvents.Count - 1]
        $terminal = Test-MihariManagementTerminalEvent -Event $last
        $latestError = $null
        $hostName = $null
        $port = $null
        $path = $null
        $method = $null
        $routeKind = $null
        $routeSource = $null
        $statusCode = $null
        $proxyStatus = $null
        $bytesClientToUpstream = $null
        $bytesUpstreamToClient = $null
        foreach ($event in $connectionEvents) {
            $data = $event.data
            foreach ($name in @('host', 'port', 'path', 'method', 'routeKind', 'routeSource', 'statusCode', 'proxyStatus', 'bytesClientToUpstream', 'bytesUpstreamToClient')) {
                $value = Get-MihariMemberValue -InputObject $data -Names @($name)
                if ($null -eq $value) { continue }
                switch ($name) {
                    'host' { $hostName = $value }
                    'port' { $port = $value }
                    'path' { $path = $value }
                    'method' { $method = $value }
                    'routeKind' { $routeKind = $value }
                    'routeSource' { $routeSource = $value }
                    'statusCode' { $statusCode = $value }
                    'proxyStatus' { $proxyStatus = $value }
                    'bytesClientToUpstream' { $bytesClientToUpstream = $value }
                    'bytesUpstreamToClient' { $bytesUpstreamToClient = $value }
                }
            }
            $outcome = ([string]$event.outcome -replace '[^A-Za-z]', '').ToLowerInvariant()
            if ($outcome -in @('failed', 'failure', 'error', 'unsupported', 'rejected')) { $latestError = $event }
        }

        $isActive = ($SessionRunning -and -not $terminal)
        $connection = [ordered]@{
            connectionId = $connectionId
            requestId = [string]$last.requestId
            mode = [string]$first.mode
            host = $hostName
            port = $port
            method = $method
            path = $path
            routeKind = $routeKind
            routeSource = $routeSource
            statusCode = $statusCode
            proxyStatus = $proxyStatus
            stage = [string]$last.stage
            outcome = [string]$last.outcome
            startedAt = [string]$first.timestamp
            lastEventAt = [string]$last.timestamp
            active = $isActive
            bytesClientToUpstream = $bytesClientToUpstream
            bytesUpstreamToClient = $bytesUpstreamToClient
        }
        if ($null -ne $latestError) {
            $connection['errorCode'] = $latestError.data.errorCode
            $connection['errorType'] = $latestError.data.errorType
        }
        $connections.Add([pscustomobject]$connection)
    }

    $ordered = @($connections.ToArray() | Sort-Object -Property lastEventAt -Descending | Select-Object -First $MaximumConnections)
    $active = @($ordered | Where-Object { $_.active })
    return [pscustomobject]@{
        Active = $active
        Recent = $ordered
    }
}

function ConvertTo-MihariManagementFinding {
    param([Parameter(Mandatory = $true)][object] $Finding)

    $evidenceIds = New-Object 'System.Collections.Generic.List[string]'
    foreach ($id in @($Finding.evidenceIds | Select-Object -First 200)) {
        $safeId = ConvertTo-MihariManagementScalar -Value $id -MaximumLength 128
        if ($null -ne $safeId) { $evidenceIds.Add($safeId) }
    }
    $facts = New-Object 'System.Collections.Generic.List[object]'
    foreach ($fact in @($Finding.observedFacts | Select-Object -First 200)) {
        $safeFact = [ordered]@{}
        foreach ($name in @('eventId', 'stage', 'outcome', 'mode', 'connectionId', 'requestId', 'sessionId', 'host', 'port', 'routeKind', 'responseSource', 'errorCode', 'errorType', 'method')) {
            $value = Get-MihariMemberValue -InputObject $fact -Names @($name)
            $safeValue = ConvertTo-MihariManagementScalar -Value $value -MaximumLength 256
            if ($null -ne $safeValue) { $safeFact[$name] = $safeValue }
        }
        foreach ($name in @('statusCode', 'proxyStatus')) {
            $value = ConvertTo-MihariManagementNumber -Value (Get-MihariMemberValue -InputObject $fact -Names @($name))
            if ($null -ne $value) { $safeFact[$name] = [long][Math]::Truncate($value) }
        }
        $path = ConvertTo-MihariPath -Value (Get-MihariMemberValue -InputObject $fact -Names @('path'))
        if ($null -ne $path) { $safeFact['path'] = $path }
        $facts.Add([pscustomobject]$safeFact)
    }

    return [pscustomobject][ordered]@{
        code = ConvertTo-MihariManagementScalar -Value $Finding.code -MaximumLength 128
        summary = ConvertTo-MihariManagementScalar -Value $Finding.summary -MaximumLength 512
        scope = ConvertTo-MihariManagementScalar -Value $Finding.scope -MaximumLength 32
        evidenceIds = @($evidenceIds.ToArray())
        observedFacts = @($facts.ToArray())
        interpretation = ConvertTo-MihariManagementScalar -Value $Finding.interpretation -MaximumLength 512
        limitations = ConvertTo-MihariManagementScalar -Value $Finding.limitations -MaximumLength 512
    }
}

function Get-MihariManagementSnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][object] $Session,
        [ValidateRange(1, 200)][int] $MaximumEvents = 200
    )

    if (-not (Get-Command Get-MihariDiagnosis -ErrorAction SilentlyContinue)) {
        throw 'The canonical Mihari diagnosis engine is unavailable.'
    }
    $window = Read-MihariManagementEventWindow -Path ([string]$Session.EventsPath) -MaximumEvents $MaximumEvents
    $oldestFirst = @($window.Events)
    $newestFirst = @($oldestFirst | Sort-Object -Property timestamp -Descending)
    $connectionProjection = Get-MihariManagementConnections -Events $oldestFirst -SessionRunning ([string]$Session.Status -eq 'running') -MaximumConnections 100
    $rawFindings = @(Get-MihariDiagnosis -Events $oldestFirst)
    $findings = New-Object 'System.Collections.Generic.List[object]'
    foreach ($finding in $rawFindings) {
        $findings.Add((ConvertTo-MihariManagementFinding -Finding $finding))
    }

    $errors = New-Object 'System.Collections.Generic.List[object]'
    foreach ($event in $newestFirst) {
        $outcome = ([string]$event.outcome -replace '[^A-Za-z]', '').ToLowerInvariant()
        $hasError = $outcome -in @('failed', 'failure', 'error', 'unsupported', 'rejected') -or
            -not [string]::IsNullOrWhiteSpace([string]$event.data.errorCode)
        if ($hasError) {
            $errors.Add($event)
            if ($errors.Count -ge 50) { break }
        }
    }

    $latestEventAt = $null
    if ($newestFirst.Count -gt 0) { $latestEventAt = [string]$newestFirst[0].timestamp }
    return [pscustomobject][ordered]@{
        sessionId = ConvertTo-MihariManagementScalar -Value $Session.Id -MaximumLength 128
        sessionStatus = ConvertTo-MihariManagementScalar -Value $Session.Status -MaximumLength 32
        mode = ConvertTo-MihariManagementScalar -Value $Session.Mode -MaximumLength 16
        eventCount = [int]$oldestFirst.Count
        recentEventCount = [int]$oldestFirst.Count
        truncated = [bool]$window.Truncated
        malformedLineCount = [int]$window.MalformedLineCount
        eventReadError = $window.ReadError
        latestEventAt = $latestEventAt
        recentEvents = @($newestFirst)
        logs = @($newestFirst)
        activeConnections = @($connectionProjection.Active)
        recentConnections = @($connectionProjection.Recent)
        errors = @($errors.ToArray())
        errorCount = [int]$errors.Count
        findings = @($findings.ToArray())
    }
}
