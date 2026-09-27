# Loopback-only management HTTP listener. The proxy loop calls the nonblocking
# accept/poll function; each accepted request runs in a small bounded pool so a
# slow management client cannot stall proxy accepts or its health heartbeat.

function Add-MihariManagementProperty {
    param(
        [Parameter(Mandatory = $true)]$Object,
        [Parameter(Mandatory = $true)][string]$Name,
        [AllowNull()]$Value
    )

    if ($null -eq $Object.PSObject.Properties[$Name]) {
        $Object | Add-Member -NotePropertyName $Name -NotePropertyValue $Value
    }
    else {
        $Object.$Name = $Value
    }
}

function Get-MihariManagementUtcValue {
    param([AllowNull()]$Value)

    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
    try { return ([DateTime]::Parse([string]$Value).ToUniversalTime().ToString('o')) }
    catch { return $null }
}

function Test-MihariManagementHeartbeatFresh {
    param([AllowNull()]$Value)

    $parsed = [DateTime]::MinValue
    if ($null -eq $Value -or -not [DateTime]::TryParse([string]$Value, [ref]$parsed)) { return $false }
    $age = ([DateTime]::UtcNow - $parsed.ToUniversalTime()).TotalSeconds
    return ($age -ge -5 -and $age -le 10)
}

function Test-MihariManagementListenerActive {
    param([AllowNull()]$Listener)

    if ($null -eq $Listener) { return $false }
    try {
        if ($Listener -is [System.Net.Sockets.TcpListener]) {
            # Pending() is nonblocking and throws after Stop().
            $null = $Listener.Pending()
            return $true
        }
        if ($null -ne $Listener.PSObject.Properties['Active']) { return [bool]$Listener.Active }
    }
    catch { return $false }
    return $false
}

function Get-MihariManagementListenerHealth {
    param(
        [AllowNull()]$Listener,
        [AllowNull()]$HeartbeatUtc
    )

    $listening = Test-MihariManagementListenerActive -Listener $Listener
    $heartbeatFresh = Test-MihariManagementHeartbeatFresh -Value $HeartbeatUtc
    return [pscustomobject][ordered]@{
        listening = $listening
        heartbeatFresh = $heartbeatFresh
        healthy = ($listening -and $heartbeatFresh)
        heartbeatUtc = (Get-MihariManagementUtcValue -Value $HeartbeatUtc)
    }
}

function Get-MihariManagementSessionField {
    param(
        [Parameter(Mandatory = $true)]$Session,
        [Parameter(Mandatory = $true)][string]$Name,
        [AllowNull()]$Default = $null
    )

    $property = $Session.PSObject.Properties[$Name]
    if ($null -eq $property -or $null -eq $property.Value) { return $Default }
    return $property.Value
}

function Get-MihariManagementLeafCacheCount {
    param([AllowNull()]$Session)

    if ($null -eq $Session -or $null -eq $Session.LeafCache) { return 0 }
    $cache = $Session.LeafCache
    try {
        [System.Threading.Monitor]::Enter($cache.SyncRoot)
        return [int]$cache.Count
    }
    catch { return 0 }
    finally {
        if ([System.Threading.Monitor]::IsEntered($cache.SyncRoot)) {
            [System.Threading.Monitor]::Exit($cache.SyncRoot)
        }
    }
}

function Get-MihariManagementCaState {
    param([Parameter(Mandatory = $true)]$Session)

    $enabled = ([string]$Session.Mode -eq 'Inspect')
    $trusted = $false
    $subject = $null
    $thumbprint = $null
    if ($null -ne $Session.CA) {
        $subject = [string]$Session.CA.Subject
        $thumbprint = [string]$Session.CA.Thumbprint
        if (Get-Command Test-MihariSessionCATrust -ErrorAction SilentlyContinue) {
            try { $trusted = [bool](Test-MihariSessionCATrust -Session $Session) }
            catch { $trusted = $false }
        }
        elseif ($null -ne $Session.PublicCARoot) {
            $trusted = $true
        }
    }
    return [pscustomobject][ordered]@{
        enabled = $enabled
        trusted = $trusted
        subject = $subject
        thumbprint = $thumbprint
        leafCacheCount = (Get-MihariManagementLeafCacheCount -Session $Session)
    }
}

function Get-MihariManagementUpstreamRoute {
    param(
        [Parameter(Mandatory = $true)]$Session,
        [AllowNull()]$Snapshot
    )

    $captured = Get-MihariManagementSessionField -Session $Session -Name 'PlatformProxySnapshot'
    $capturedAt = $null
    if ($null -ne $captured) { $capturedAt = Get-MihariManagementUtcValue -Value $captured.CapturedAtUtc }

    if (-not [string]::IsNullOrWhiteSpace([string]$Session.UpstreamProxy)) {
        $endpoint = $null
        if (Get-Command Get-MihariSafeProxyEndpoint -ErrorAction SilentlyContinue) {
            $endpoint = Get-MihariSafeProxyEndpoint -Proxy ([string]$Session.UpstreamProxy)
        }
        return [pscustomobject][ordered]@{
            kind = 'ExplicitProxy'
            source = 'Override'
            host = $null
            port = $null
            endpoint = $endpoint
            reason = 'Using the configured Mihari upstream override.'
            snapshotAtUtc = $capturedAt
        }
    }

    # A concrete per-destination selection is more useful than configuration
    # state. The observation projection has already removed sensitive values.
    if ($null -ne $Snapshot -and $null -ne $Snapshot.recentEvents) {
        foreach ($event in @($Snapshot.recentEvents)) {
            if ($null -eq $event) { continue }
            $data = $event.data
            if ($null -eq $data) { continue }
            $routeKind = [string]$data.routeKind
            if ([string]::IsNullOrWhiteSpace($routeKind)) { continue }
            $hostName = [string]$data.proxyHost
            $port = $data.proxyPort
            $endpoint = $null
            if (-not [string]::IsNullOrWhiteSpace($hostName)) {
                if ($null -ne $port -and [string]$port -match '^\d{1,5}$') {
                    if ($hostName.Contains(':') -and -not $hostName.StartsWith('[')) { $hostName = '[' + $hostName + ']' }
                    $endpoint = $hostName + ':' + [string]$port
                }
                else { $endpoint = $hostName }
            }
            return [pscustomobject][ordered]@{
                kind = $routeKind
                source = [string]$data.routeSource
                host = $hostName
                port = $port
                endpoint = $endpoint
                reason = 'Most recent observed destination route.'
                snapshotAtUtc = $capturedAt
            }
        }
    }

    $configuration = $null
    if ($null -ne $captured) { $configuration = $captured.Configuration }
    $configured = $false
    $pacConfigured = $false
    $environmentConfigured = $false
    $errorType = $null
    if ($null -ne $configuration) {
        $configured = [bool]$configuration.Configured
        $pacConfigured = [bool]$configuration.PacConfigured
        $environmentConfigured = [bool]$configuration.EnvironmentConfigured
        $errorType = [string]$configuration.ErrorType
    }
    $kind = 'Direct'
    $source = 'Platform'
    $reason = 'No explicit platform proxy route was captured; Mihari resolves a route per destination.'
    if ($configured -or -not [string]::IsNullOrWhiteSpace($errorType)) {
        $kind = 'PlatformConfigured'
        if ($pacConfigured) { $reason = 'Platform PAC/WPAD configuration was captured; routes are resolved per destination.' }
        elseif ($environmentConfigured) { $reason = 'Platform environment proxy configuration was captured; routes are resolved per destination.' }
        else { $reason = 'Windows proxy configuration was captured; routes are resolved per destination.' }
        if (-not [string]::IsNullOrWhiteSpace($errorType)) { $reason += ' Configuration inspection reported ' + $errorType + '.' }
    }
    return [pscustomobject][ordered]@{
        kind = $kind
        source = $source
        host = $null
        port = $null
        endpoint = $null
        reason = $reason
        snapshotAtUtc = $capturedAt
    }
}

function Get-MihariManagementStatusDocument {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Session)

    $projection = $null
    if (Get-Command Get-MihariManagementSnapshot -ErrorAction SilentlyContinue) {
        try { $projection = Get-MihariManagementSnapshot -Session $Session -MaximumEvents 100 }
        catch { $projection = $null }
    }

    $proxyHealth = Get-MihariManagementListenerHealth -Listener $Session.Listener -HeartbeatUtc $Session.ProxyHeartbeatUtc
    $managementHealth = Get-MihariManagementListenerHealth -Listener $Session.ManagementListener -HeartbeatUtc $Session.ManagementHeartbeatUtc
    if (-not [string]::IsNullOrWhiteSpace([string]$Session.ManagementError)) {
        $managementHealth.healthy = $false
        $managementHealth | Add-Member -NotePropertyName errorCode -NotePropertyValue 'management_worker_failed' -Force
    }
    $captureState = Get-MihariManagementSessionField -Session $Session -Name 'CaptureState'
    $captureAvailable = ($null -ne $captureState)
    $captureIncomplete = $false
    $captureReason = $null
    $captureAtUtc = $null
    $captureEvidenceByteLimit = $null
    $captureQueueCapacity = $null
    $captureQueuePeak = $null
    $captureSaturationCount = $null
    if ($captureAvailable) {
        $rawIncomplete = Get-MihariManagementSessionField -Session $captureState -Name 'Incomplete'
        if ($rawIncomplete -is [bool]) { $captureIncomplete = [bool]$rawIncomplete }
        elseif ([string]$rawIncomplete -match '^(?i:true|false)$') { $captureIncomplete = ([string]$rawIncomplete -ieq 'true') }
        $rawReason = [string](Get-MihariManagementSessionField -Session $captureState -Name 'Reason')
        if ($rawReason -in @('evidence_limit_reached', 'event_writer_failed')) { $captureReason = $rawReason }
        elseif ($captureIncomplete) { $captureReason = 'unknown' }
        $captureAtUtc = Get-MihariManagementUtcValue -Value (Get-MihariManagementSessionField -Session $captureState -Name 'AtUtc')
        $parsedCaptureValue = 0L
        $rawCaptureValue = Get-MihariManagementSessionField -Session $captureState -Name 'EvidenceByteLimit'
        if ($null -ne $rawCaptureValue -and [long]::TryParse([string]$rawCaptureValue, [ref]$parsedCaptureValue) -and $parsedCaptureValue -ge 0) {
            $captureEvidenceByteLimit = $parsedCaptureValue
        }
        $parsedCaptureValue = 0
        $rawCaptureValue = Get-MihariManagementSessionField -Session $captureState -Name 'QueueCapacity'
        if ($null -ne $rawCaptureValue -and [int]::TryParse([string]$rawCaptureValue, [ref]$parsedCaptureValue) -and $parsedCaptureValue -ge 0) {
            $captureQueueCapacity = $parsedCaptureValue
        }
        $parsedCaptureValue = 0
        $rawCaptureValue = Get-MihariManagementSessionField -Session $captureState -Name 'QueuePeak'
        if ($null -ne $rawCaptureValue -and [int]::TryParse([string]$rawCaptureValue, [ref]$parsedCaptureValue) -and $parsedCaptureValue -ge 0) {
            $captureQueuePeak = $parsedCaptureValue
        }
        $parsedCaptureValue = 0L
        $rawCaptureValue = Get-MihariManagementSessionField -Session $captureState -Name 'SaturationCount'
        if ($null -ne $rawCaptureValue -and [long]::TryParse([string]$rawCaptureValue, [ref]$parsedCaptureValue) -and $parsedCaptureValue -ge 0) {
            $captureSaturationCount = $parsedCaptureValue
        }
    }
    $captureDocument = [pscustomobject][ordered]@{
        available = $captureAvailable
        incomplete = $captureIncomplete
        reason = $captureReason
        atUtc = $captureAtUtc
        evidenceByteLimit = $captureEvidenceByteLimit
        queueCapacity = $captureQueueCapacity
        queuePeak = $captureQueuePeak
        saturationCount = $captureSaturationCount
    }
    $status = [string]$Session.Status
    $effectiveStatus = $status
    if ($status -eq 'running' -and (-not $proxyHealth.healthy -or -not $managementHealth.healthy -or $captureIncomplete)) {
        $effectiveStatus = 'unhealthy'
    }

    $proxyPort = 0
    if ($null -ne $Session.ActualPort) { $proxyPort = [int]$Session.ActualPort }
    $managementPort = 0
    if ($null -ne $Session.ActualManagementPort) { $managementPort = [int]$Session.ActualManagementPort }
    $proxyEndpoint = $null
    if ($proxyPort -gt 0) { $proxyEndpoint = 'http://127.0.0.1:' + $proxyPort }
    $managementEndpoint = $null
    if ($managementPort -gt 0) { $managementEndpoint = 'http://127.0.0.1:' + $managementPort + '/' }
    $ca = Get-MihariManagementCaState -Session $Session
    $findingCounts = $null
    $findingCoverage = 'unknown'
    $findingProjectionError = $null
    if (Get-Command Get-MihariManagementV2FindingPage -ErrorAction SilentlyContinue) {
        try {
            $findingPage = Get-MihariManagementV2FindingPage -Session $Session -Limit 1
            $findingCounts = $findingPage.counts
            $findingCoverage = [string]$findingPage.coverage
        }
        catch { $findingProjectionError = 'finding_projection_failed' }
    }

    $sessionDocument = [pscustomobject][ordered]@{
        id = [string]$Session.Id
        sessionId = [string]$Session.Id
        status = $status
        effectiveStatus = $effectiveStatus
        mode = [string]$Session.Mode
        profile = [string]$Session.Profile
        profileVersion = [int]$Session.ProfileVersion
        httpConnectionPolicy = [string]$Session.HttpConnectionPolicy
        configurationRevision = [int]$Session.ConfigurationRevision
        inspectEnabled = ([string]$Session.Mode -eq 'Inspect')
        startedAtUtc = [string]$Session.StartedAtUtc
        processId = [int]$Session.ProcessId
    }

    $errors = @()
    if ($null -ne $projection -and $null -ne $projection.errors) { $errors += @($projection.errors) }
    if ($null -ne $Session.Error) {
        $sessionError = [ordered]@{ code = 'session_error'; message = 'Session reported an initialization or runtime error.' }
        if ($null -ne $Session.Error.type) { $sessionError['errorType'] = [string]$Session.Error.type }
        $errors += [pscustomobject]$sessionError
    }
    if ($null -ne $Session.ManagementError) {
        $errors += [pscustomobject]@{ code = 'management_listener_error'; errorType = [string]$Session.ManagementError }
    }
    $warnings = @()
    if ($captureIncomplete) {
        $captureWarning = [pscustomobject][ordered]@{
            code = 'capture_incomplete'
            severity = 'warning'
            source = 'mihari'
            reason = $captureReason
            atUtc = $captureAtUtc
            message = 'Evidence capture is incomplete.'
        }
        $warnings += $captureWarning
        $errors += $captureWarning
    }
    if ($null -ne $Session.CleanupErrors) { $cleanupErrors = @($Session.CleanupErrors) }
    else { $cleanupErrors = @() }

    $activeConnections = 0
    $recentConnections = @()
    if ($null -ne $Session.ActiveConnectionCount) { $activeConnections = [int]$Session.ActiveConnectionCount }
    if ($null -ne $projection) {
        if ($null -eq $Session.ActiveConnectionCount -and $null -ne $projection.activeConnections) {
            if ($projection.activeConnections -is [System.Array] -or $projection.activeConnections -is [System.Collections.ICollection]) {
                $activeConnections = @($projection.activeConnections).Count
            }
            else { $activeConnections = [int]$projection.activeConnections }
        }
        if ($null -ne $projection.recentConnections) { $recentConnections = @($projection.recentConnections) }
    }

    return [pscustomobject][ordered]@{
        session = $sessionDocument
        effectiveStatus = $effectiveStatus
        proxyEndpoint = $proxyEndpoint
        managementEndpoint = $managementEndpoint
        proxyHealth = $proxyHealth
        managementHealth = $managementHealth
        upstreamRoute = (Get-MihariManagementUpstreamRoute -Session $Session -Snapshot $projection)
        ca = $ca
        profile = [string]$Session.Profile
        profileVersion = [int]$Session.ProfileVersion
        httpConnectionPolicy = [string]$Session.HttpConnectionPolicy
        configurationRevision = [int]$Session.ConfigurationRevision
        activeConnections = $activeConnections
        recentConnections = @($recentConnections | Select-Object -First 100)
        findingCounts = $findingCounts
        findingCoverage = $findingCoverage
        findingProjectionError = $findingProjectionError
        capture = $captureDocument
        warnings = @($warnings)
        errors = @($errors | Select-Object -First 100)
        cleanupErrors = @($cleanupErrors | Select-Object -First 100)
    }
}

function Get-MihariManagementProjection {
    param(
        [Parameter(Mandatory = $true)]$Session,
        [ValidateRange(1, 200)][int]$MaximumEvents = 100
    )

    if (Get-Command Get-MihariManagementSnapshot -ErrorAction SilentlyContinue) {
        return (Get-MihariManagementSnapshot -Session $Session -MaximumEvents $MaximumEvents)
    }
    return [pscustomobject]@{ recentEvents = @(); logs = @(); findings = @(); errors = @(); activeConnections = 0; recentConnections = @() }
}

function Get-MihariManagementQueryLimit {
    param([string]$Query)

    $limit = 100
    if ([string]::IsNullOrEmpty($Query)) { return $limit }
    $seen = $false
    foreach ($item in $Query.TrimStart('?').Split('&')) {
        if ([string]::IsNullOrEmpty($item)) { continue }
        $separator = $item.IndexOf('=')
        $namePart = $item
        $valuePart = $null
        if ($separator -ge 0) {
            $namePart = $item.Substring(0, $separator)
            $valuePart = $item.Substring($separator + 1)
        }
        $name = [Uri]::UnescapeDataString($namePart.Replace('+', ' '))
        if ($name -ne 'limit') { continue }
        if ($seen) { throw [System.ArgumentException]::new('The limit query value must appear once.') }
        $seen = $true
        if ($null -eq $valuePart -or $valuePart -notmatch '^\d{1,3}$') {
            throw [System.ArgumentException]::new('The limit query value must be between 1 and 200.')
        }
        $limit = [int]$valuePart
        if ($limit -lt 1 -or $limit -gt 200) { throw [System.ArgumentException]::new('The limit query value must be between 1 and 200.') }
    }
    return $limit
}

function New-MihariManagementJsonResponse {
    param(
        [Parameter(Mandatory = $true)][int]$StatusCode,
        [Parameter(Mandatory = $true)]$Value
    )

    $json = ConvertTo-Json -InputObject $Value -Depth 12 -Compress -ErrorAction Stop
    $encoding = [System.Text.UTF8Encoding]::new($false)
    $body = $encoding.GetBytes($json)
    if ($body.Length -gt 1048576) {
        $StatusCode = 500
        $body = $encoding.GetBytes('{"error":"response_too_large"}')
    }
    return [pscustomobject]@{ StatusCode = $StatusCode; ContentType = 'application/json; charset=utf-8'; Body = $body }
}

function New-MihariManagementErrorResponse {
    param(
        [Parameter(Mandatory = $true)][int]$StatusCode,
        [Parameter(Mandatory = $true)][string]$Code,
        [Parameter(Mandatory = $true)][string]$Message
    )
    return New-MihariManagementJsonResponse -StatusCode $StatusCode -Value ([pscustomobject]@{ error = $Code; message = $Message })
}

function Get-MihariManagementStatusReason {
    param([int]$StatusCode)
    switch ($StatusCode) {
        200 { return 'OK' }
        400 { return 'Bad Request' }
        409 { return 'Conflict' }
        403 { return 'Forbidden' }
        404 { return 'Not Found' }
        405 { return 'Method Not Allowed' }
        411 { return 'Length Required' }
        413 { return 'Payload Too Large' }
        415 { return 'Unsupported Media Type' }
        417 { return 'Expectation Failed' }
        431 { return 'Request Header Fields Too Large' }
        500 { return 'Internal Server Error' }
        501 { return 'Not Implemented' }
        503 { return 'Service Unavailable' }
        default { return 'Error' }
    }
}

function Write-MihariManagementResponse {
    param(
        [Parameter(Mandatory = $true)][System.Net.Sockets.NetworkStream]$Stream,
        [Parameter(Mandatory = $true)]$Response
    )

    $reason = Get-MihariManagementStatusReason -StatusCode ([int]$Response.StatusCode)
    $head = "HTTP/1.1 $($Response.StatusCode) $reason`r`n" +
        "Content-Type: $($Response.ContentType)`r`n" +
        "Content-Length: $($Response.Body.Length)`r`n" +
        "Connection: close`r`n" +
        "Cache-Control: no-store`r`n" +
        "X-Content-Type-Options: nosniff`r`n" +
        "Referrer-Policy: no-referrer`r`n" +
        "Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src data:; base-uri 'none'; frame-ancestors 'none'`r`n`r`n"
    $headBytes = [System.Text.Encoding]::ASCII.GetBytes($head)
    $Stream.Write($headBytes, 0, $headBytes.Length)
    if ($Response.Body.Length -gt 0) { $Stream.Write($Response.Body, 0, $Response.Body.Length) }
    $Stream.Flush()
}

function Read-MihariManagementRequest {
    param([Parameter(Mandatory = $true)][System.Net.Sockets.NetworkStream]$Stream)

    $headerBytes = New-Object System.Collections.Generic.List[byte]
    $headerComplete = $false
    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    $headerLimit = 16384
    while ($headerBytes.Count -lt $headerLimit -and $timer.ElapsedMilliseconds -lt 2000) {
        $value = $Stream.ReadByte()
        if ($value -lt 0) { throw [System.IO.EndOfStreamException]::new('The management client closed before completing its request.') }
        $headerBytes.Add([byte]$value)
        $count = $headerBytes.Count
        if ($count -ge 4 -and $headerBytes[$count - 4] -eq 13 -and $headerBytes[$count - 3] -eq 10 -and $headerBytes[$count - 2] -eq 13 -and $headerBytes[$count - 1] -eq 10) {
            $headerComplete = $true
            break
        }
    }
    if (-not $headerComplete) {
        if ($headerBytes.Count -ge $headerLimit) { throw [System.IO.InvalidDataException]::new('request_headers_too_large') }
        throw [System.TimeoutException]::new('request_headers_timeout')
    }

    $headerText = [System.Text.Encoding]::ASCII.GetString($headerBytes.ToArray())
    $lines = $headerText.Substring(0, $headerText.Length - 4) -split "`r`n"
    if ($lines.Count -lt 1 -or $lines[0] -notmatch '^([A-Z]+) ([^ ]+) HTTP/1\.[01]$') {
        throw [System.IO.InvalidDataException]::new('invalid_request_line')
    }
    $method = [string]$Matches[1]
    $target = [string]$Matches[2]
    if (-not $target.StartsWith('/') -or $target.StartsWith('//') -or $target.Contains('#')) {
        throw [System.IO.InvalidDataException]::new('invalid_request_target')
    }
    $headers = @{}
    for ($index = 1; $index -lt $lines.Count; $index++) {
        $line = [string]$lines[$index]
        if ($line.Length -eq 0 -or $line[0] -eq ' ' -or $line[0] -eq "`t" -or $line -notmatch '^([!#$%&''*+.^_`|~0-9A-Za-z-]+):[ \t]*(.*)$') {
            throw [System.IO.InvalidDataException]::new('invalid_header')
        }
        $name = ([string]$Matches[1]).ToLowerInvariant()
        $valueText = [string]$Matches[2]
        if ($valueText -match '[\x00-\x08\x0a-\x1f\x7f]') { throw [System.IO.InvalidDataException]::new('invalid_header_value') }
        if ($headers.ContainsKey($name)) { throw [System.IO.InvalidDataException]::new('duplicate_header') }
        $headers[$name] = $valueText.Trim()
    }
    if (-not $headers.ContainsKey('host') -or [string]::IsNullOrWhiteSpace([string]$headers['host'])) {
        throw [System.IO.InvalidDataException]::new('missing_host')
    }
    if ($headers.ContainsKey('transfer-encoding')) { throw [System.NotSupportedException]::new('transfer_encoding_not_supported') }
    if ($headers.ContainsKey('expect')) { throw [System.NotSupportedException]::new('expect_not_supported') }

    $contentLength = 0
    if ($headers.ContainsKey('content-length')) {
        if ([string]$headers['content-length'] -notmatch '^\d{1,8}$') { throw [System.IO.InvalidDataException]::new('invalid_content_length') }
        $contentLength = [int]$headers['content-length']
    }
    if ($contentLength -gt 8192) { throw [System.IO.InvalidDataException]::new('request_body_too_large') }
    if ($method -eq 'POST' -and -not $headers.ContainsKey('content-length')) {
        throw [System.IO.InvalidDataException]::new('content_length_required')
    }

    $body = New-Object byte[] $contentLength
    $offset = 0
    while ($offset -lt $contentLength) {
        if ($timer.ElapsedMilliseconds -ge 3000) { throw [System.TimeoutException]::new('request_body_timeout') }
        $read = $Stream.Read($body, $offset, $contentLength - $offset)
        if ($read -le 0) { throw [System.IO.EndOfStreamException]::new('The management client closed before completing its request body.') }
        $offset += $read
    }

    $path = $target
    $query = ''
    $queryIndex = $target.IndexOf('?')
    if ($queryIndex -ge 0) {
        $path = $target.Substring(0, $queryIndex)
        $query = $target.Substring($queryIndex + 1)
    }
    return [pscustomobject]@{ Method = $method; Target = $target; Path = $path; Query = $query; Headers = $headers; Body = $body }
}

function Test-MihariManagementLoopbackAuthority {
    param(
        [Parameter(Mandatory = $true)][string]$Authority,
        [Parameter(Mandatory = $true)][int]$ExpectedPort
    )

    if ([string]::IsNullOrWhiteSpace($Authority) -or $Authority -match '[\s/@?#]') { return $false }
    $uri = $null
    if (-not [Uri]::TryCreate('http://' + $Authority, [UriKind]::Absolute, [ref]$uri)) { return $false }
    if (-not [string]::IsNullOrEmpty($uri.UserInfo) -or -not [string]::IsNullOrEmpty($uri.AbsolutePath.Trim('/')) -or
        -not [string]::IsNullOrEmpty($uri.Query) -or -not [string]::IsNullOrEmpty($uri.Fragment)) { return $false }
    if ($uri.Port -ne $ExpectedPort) { return $false }
    if ([string]::Equals($uri.Host, 'localhost', [StringComparison]::OrdinalIgnoreCase)) { return $true }
    $address = $null
    if ([System.Net.IPAddress]::TryParse($uri.Host, [ref]$address)) { return [System.Net.IPAddress]::IsLoopback($address) }
    return $false
}

function Test-MihariManagementRequestAuthority {
    param(
        [Parameter(Mandatory = $true)]$Session,
        [Parameter(Mandatory = $true)]$Request
    )

    $port = [int]$Session.ActualManagementPort
    if (-not (Test-MihariManagementLoopbackAuthority -Authority ([string]$Request.Headers['host']) -ExpectedPort $port)) { return $false }
    if ($Request.Method -eq 'POST' -and $Request.Headers.ContainsKey('origin')) {
        $origin = [string]$Request.Headers['origin']
        $originUri = $null
        if (-not [Uri]::TryCreate($origin, [UriKind]::Absolute, [ref]$originUri)) { return $false }
        if ($originUri.Scheme -ne 'http' -or -not (Test-MihariManagementLoopbackAuthority -Authority $originUri.Authority -ExpectedPort $port)) { return $false }
        if (-not [string]::Equals($originUri.Authority, [string]$Request.Headers['host'], [StringComparison]::OrdinalIgnoreCase)) { return $false }
    }
    return $true
}

function Test-MihariManagementActionToken {
    param(
        [Parameter(Mandatory = $true)]$Session,
        [Parameter(Mandatory = $true)]$Request
    )

    $expected = [string]$Session.ControlToken
    if ([string]::IsNullOrWhiteSpace($expected) -or
        -not $Request.Headers.ContainsKey('x-mihari-control-token')) { return $false }
    $provided = [string]$Request.Headers['x-mihari-control-token']
    if ($provided.Length -ne $expected.Length) { return $false }
    $difference = 0
    for ($index = 0; $index -lt $expected.Length; $index++) {
        $difference = $difference -bor ([int]$expected[$index] -bxor [int]$provided[$index])
    }
    return ($difference -eq 0)
}

function Read-MihariManagementJsonBody {
    param([Parameter(Mandatory = $true)]$Request)

    if (-not $Request.Headers.ContainsKey('content-type') -or
        [string]$Request.Headers['content-type'] -notmatch '(?i)^application/json(?:\s*;\s*charset=utf-8)?\s*$') {
        throw [System.Management.Automation.RuntimeException]::new('unsupported_media_type')
    }
    $strictUtf8 = [System.Text.UTF8Encoding]::new($false, $true)
    $text = $strictUtf8.GetString([byte[]]$Request.Body)
    if ([string]::IsNullOrWhiteSpace($text)) { throw [System.ArgumentException]::new('empty_json_body') }
    $value = ConvertFrom-Json -InputObject $text -ErrorAction Stop
    if ($null -eq $value -or $value -is [string] -or $value -is [Array]) { throw [System.ArgumentException]::new('json_object_required') }
    return $value
}

function Invoke-MihariManagementApiRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Session,
        [Parameter(Mandatory = $true)]$Request
    )

    if (-not (Test-MihariManagementRequestAuthority -Session $Session -Request $Request)) {
        return (New-MihariManagementErrorResponse -StatusCode 403 -Code 'invalid_local_origin' -Message 'The request must use the active Mihari loopback origin.')
    }

    $method = [string]$Request.Method
    $path = [string]$Request.Path
    if ($method -eq 'POST' -and -not (Test-MihariManagementActionToken -Session $Session -Request $Request)) {
        return (New-MihariManagementErrorResponse -StatusCode 403 -Code 'invalid_control_token' -Message 'A session control token is required for management actions.')
    }
    if ($path.StartsWith('/api/v2/') -and (Get-Command Invoke-MihariManagementV2Request -ErrorAction SilentlyContinue)) {
        $v2Response = Invoke-MihariManagementV2Request -Session $Session -Request $Request
        if ($null -ne $v2Response) { return $v2Response }
    }
    if ($method -eq 'GET' -and $path -eq '/') {
        if (-not (Get-Command Get-MihariManagementUiHtml -ErrorAction SilentlyContinue)) {
            return (New-MihariManagementErrorResponse -StatusCode 503 -Code 'ui_unavailable' -Message 'The local management UI is unavailable.')
        }
        $html = [string](Get-MihariManagementUiHtml -ControlToken ([string]$Session.ControlToken))
        $encoding = [System.Text.UTF8Encoding]::new($false)
        $body = $encoding.GetBytes($html)
        if ($body.Length -gt 1048576) { return (New-MihariManagementErrorResponse -StatusCode 500 -Code 'ui_too_large' -Message 'The local management UI exceeded its response limit.') }
        return [pscustomobject]@{ StatusCode = 200; ContentType = 'text/html; charset=utf-8'; Body = $body }
    }
    if ($method -eq 'GET' -and ($path -eq '/api/status' -or $path -eq '/api/health')) {
        $status = Get-MihariManagementStatusDocument -Session $Session
        if ($path -eq '/api/health') {
            return (New-MihariManagementJsonResponse -StatusCode 200 -Value ([pscustomobject]@{
                healthy = ($status.proxyHealth.healthy -and $status.managementHealth.healthy -and
                    -not $status.capture.incomplete)
                status = $status.effectiveStatus
                proxyHealth = $status.proxyHealth
                managementHealth = $status.managementHealth
                capture = $status.capture
                warnings = @($status.warnings)
            }))
        }
        return (New-MihariManagementJsonResponse -StatusCode 200 -Value $status)
    }
    if ($method -eq 'GET' -and $path -eq '/api/events') {
        try { $limit = Get-MihariManagementQueryLimit -Query ([string]$Request.Query) }
        catch { return (New-MihariManagementErrorResponse -StatusCode 400 -Code 'invalid_limit' -Message 'The event limit must be between 1 and 200.') }
        $projection = Get-MihariManagementProjection -Session $Session -MaximumEvents $limit
        return (New-MihariManagementJsonResponse -StatusCode 200 -Value ([pscustomobject]@{ events = @($projection.recentEvents) }))
    }
    if ($method -eq 'GET' -and $path -eq '/api/findings') {
        if (Get-Command Get-MihariManagementV2FindingPage -ErrorAction SilentlyContinue) {
            try {
                $page = Get-MihariManagementV2FindingPage -Session $Session -Limit 200
                return (New-MihariManagementJsonResponse -StatusCode 200 -Value ([pscustomobject]@{
                    findings = @($page.items); nextCursor = $page.nextCursor; counts = $page.counts
                    coverage = $page.coverage; freshnessUtc = $page.freshnessUtc
                }))
            }
            catch {
                $projectionType = $_.Exception.GetType().FullName
                $projectionCode = [string]$_.Exception.Data['mihariCode']
                return (New-MihariManagementJsonResponse -StatusCode 503 -Value ([pscustomobject]@{
                    error = 'finding_projection_failed'
                    message = 'The canonical finding history could not be projected.'
                    errorType = $projectionType
                    projectionCode = $projectionCode
                }))
            }
        }
        $projection = Get-MihariManagementProjection -Session $Session -MaximumEvents 200
        return (New-MihariManagementJsonResponse -StatusCode 200 -Value ([pscustomobject]@{ findings = @($projection.findings) }))
    }
    if ($method -eq 'GET' -and $path -eq '/api/browser') {
        if (-not (Get-Command Get-MihariBrowserProfileStatus -ErrorAction SilentlyContinue)) {
            return (New-MihariManagementErrorResponse -StatusCode 503 -Code 'browser_profile_status_unavailable' -Message 'Diagnostic browser profile status is unavailable.')
        }
        try {
            $status = Get-MihariBrowserProfileStatus -SessionMetadata $Session
            return (New-MihariManagementJsonResponse -StatusCode 200 -Value $status)
        }
        catch {
            $errorType = $_.Exception.GetType().FullName
            return (New-MihariManagementJsonResponse -StatusCode 503 -Value ([pscustomobject]@{
                errorCode = 'browser_profile_status_failed'; message = 'Mihari could not verify diagnostic browser profile state.'; errorType = $errorType
            }))
        }
    }
    if ($method -eq 'POST' -and $path -eq '/api/browser/cleanup') {
        try { $body = Read-MihariManagementJsonBody -Request $Request }
        catch {
            if ([string]$_.Exception.Message -eq 'unsupported_media_type') {
                return (New-MihariManagementErrorResponse -StatusCode 415 -Code 'unsupported_media_type' -Message 'Send a UTF-8 application/json request body.')
            }
            return (New-MihariManagementErrorResponse -StatusCode 400 -Code 'invalid_json' -Message 'The request body must confirm cleanup and identify one diagnostic profile.')
        }
        if ($null -eq $body.PSObject.Properties['confirmCleanup'] -or $body.confirmCleanup -ne $true) {
            return (New-MihariManagementErrorResponse -StatusCode 400 -Code 'cleanup_confirmation_required' -Message 'Confirm deletion of this diagnostic Edge profile before cleanup.')
        }
        $profileOwnershipId = ''
        if ($null -ne $body.PSObject.Properties['profileOwnershipId']) { $profileOwnershipId = [string]$body.profileOwnershipId }
        if ($profileOwnershipId -notmatch '^[0-9a-fA-F]{32}$') {
            return (New-MihariManagementErrorResponse -StatusCode 400 -Code 'invalid_profile_id' -Message 'The diagnostic profile ID is invalid.')
        }
        if (-not (Get-Command Invoke-MihariBrowserProfileCleanup -ErrorAction SilentlyContinue)) {
            return (New-MihariManagementErrorResponse -StatusCode 503 -Code 'browser_profile_cleanup_unavailable' -Message 'Diagnostic browser profile cleanup is unavailable.')
        }
        $cleanup = Invoke-MihariBrowserProfileCleanup -SessionMetadata $Session -ProfileOwnershipId $profileOwnershipId
        if (-not $cleanup.success) {
            return (New-MihariManagementJsonResponse -StatusCode 409 -Value $cleanup)
        }
        return (New-MihariManagementJsonResponse -StatusCode 200 -Value $cleanup)
    }
    if ($method -eq 'POST' -and $path -eq '/api/mode') {
        try { $body = Read-MihariManagementJsonBody -Request $Request }
        catch {
            if ([string]$_.Exception.Message -eq 'unsupported_media_type') {
                return (New-MihariManagementErrorResponse -StatusCode 415 -Code 'unsupported_media_type' -Message 'Send a UTF-8 application/json request body.')
            }
            return (New-MihariManagementErrorResponse -StatusCode 400 -Code 'invalid_json' -Message 'The request body must be a JSON object containing mode.')
        }
        $modeValue = [string]$body.mode
        if ($modeValue -notin @('Inspect', 'Tunnel')) {
            return (New-MihariManagementErrorResponse -StatusCode 400 -Code 'invalid_mode' -Message 'Mode must be Inspect or Tunnel.')
        }
        if (-not (Get-Command Set-MihariSessionMode -ErrorAction SilentlyContinue)) {
            return (New-MihariManagementErrorResponse -StatusCode 503 -Code 'mode_control_unavailable' -Message 'Mode control is unavailable in this session.')
        }
        try { $selectedMode = [string](Set-MihariSessionMode -Session $Session -Mode $modeValue) }
        catch {
            $errorType = $_.Exception.GetType().FullName
            return (New-MihariManagementJsonResponse -StatusCode 409 -Value ([pscustomobject]@{
                success = $false; error = 'mode_change_failed'; message = 'Mihari could not change mode.'; errorType = $errorType
            }))
        }
        return (New-MihariManagementJsonResponse -StatusCode 200 -Value ([pscustomobject]@{
            success = $true; mode = $selectedMode; inspectEnabled = ($selectedMode -eq 'Inspect'); ca = (Get-MihariManagementCaState -Session $Session)
        }))
    }
    if ($method -eq 'POST' -and $path -eq '/api/browser') {
        try { $body = Read-MihariManagementJsonBody -Request $Request }
        catch {
            if ([string]$_.Exception.Message -eq 'unsupported_media_type') {
                return (New-MihariManagementErrorResponse -StatusCode 415 -Code 'unsupported_media_type' -Message 'Send a UTF-8 application/json request body.')
            }
            return (New-MihariManagementErrorResponse -StatusCode 400 -Code 'invalid_json' -Message 'The request body must be a JSON object.')
        }
        $url = $null
        if ($null -ne $body.PSObject.Properties['url']) { $url = [string]$body.url }
        if (-not [string]::IsNullOrWhiteSpace($url)) {
            if ($url.Length -gt 2048) { return (New-MihariManagementErrorResponse -StatusCode 400 -Code 'invalid_url' -Message 'The URL must not exceed 2048 characters.') }
            $urlValue = $null
            if (-not [Uri]::TryCreate($url, [UriKind]::Absolute, [ref]$urlValue) -or
                ($urlValue.Scheme -ne 'http' -and $urlValue.Scheme -ne 'https') -or
                -not [string]::IsNullOrEmpty($urlValue.UserInfo)) {
                return (New-MihariManagementErrorResponse -StatusCode 400 -Code 'invalid_url' -Message 'Enter an absolute HTTP or HTTPS URL without credentials.')
            }
        }
        if (-not (Get-Command Start-MihariBrowser -ErrorAction SilentlyContinue)) {
            return (New-MihariManagementErrorResponse -StatusCode 503 -Code 'browser_launch_unavailable' -Message 'The diagnostic browser launcher is unavailable.')
        }
        $launch = Start-MihariBrowser -SessionMetadata $Session -Url $url
        $result = [pscustomobject][ordered]@{
            success = [bool]$launch.Success
            path = $launch.Path
            pid = $launch.Pid
            profilePath = $launch.ProfilePath
            proxyEndpoint = $launch.ProxyEndpoint
            diagnosticProfile = $launch.DiagnosticProfile
            profileVersion = $launch.ProfileVersion
            requestedHttpVersion = $launch.RequestedHttpVersion
            requestedTlsPolicy = $launch.RequestedTlsPolicy
            observationStatus = $launch.ObservationStatus
            observationErrorCode = $launch.ObservationErrorCode
            proxyBehaviorVerification = 'launched_but_unverified'
            profileOwnershipId = $launch.ProfileOwnershipId
            profileWarning = $launch.ProfileWarning
            profileOwnershipWarning = $launch.ProfileOwnershipWarning
            reason = $launch.Reason
        }
        return (New-MihariManagementJsonResponse -StatusCode 200 -Value $result)
    }

    if ($method -notin @('GET', 'POST')) {
        $response = New-MihariManagementErrorResponse -StatusCode 405 -Code 'method_not_allowed' -Message 'Only GET and POST are supported.'
    }
    else {
        $response = New-MihariManagementErrorResponse -StatusCode 404 -Code 'not_found' -Message 'The requested management route does not exist.'
    }
    return $response
}

function Handle-MihariManagementClient {
    param(
        [Parameter(Mandatory = $true)]$Session,
        [Parameter(Mandatory = $true)][System.Net.Sockets.TcpClient]$Client
    )

    $stream = $null
    $request = $null
    $response = $null
    $workerHealthy = $true
    try {
        $Client.ReceiveTimeout = 500
        $Client.SendTimeout = 750
        $Client.NoDelay = $true
        $stream = $Client.GetStream()
        $stream.ReadTimeout = 500
        $stream.WriteTimeout = 750
        $request = Read-MihariManagementRequest -Stream $stream
        $response = Invoke-MihariManagementApiRequest -Session $Session -Request $request
        Write-MihariManagementResponse -Stream $stream -Response $response
    }
    catch [System.IO.InvalidDataException] {
        $message = [string]$_.Exception.Message
        if ($message -eq 'request_headers_too_large') {
            $response = New-MihariManagementErrorResponse -StatusCode 431 -Code 'request_too_large' -Message 'The request headers exceeded the configured limit.'
        }
        elseif ($message -eq 'request_body_too_large') {
            $response = New-MihariManagementErrorResponse -StatusCode 413 -Code 'request_too_large' -Message 'The request body exceeded the configured limit.'
        }
        elseif ($message -eq 'content_length_required') {
            $response = New-MihariManagementErrorResponse -StatusCode 411 -Code 'content_length_required' -Message 'POST requests require Content-Length.'
        }
        else { $response = New-MihariManagementErrorResponse -StatusCode 400 -Code 'invalid_request' -Message 'The HTTP request was malformed.' }
        try { if ($null -ne $stream) { Write-MihariManagementResponse -Stream $stream -Response $response } }
        catch { Write-Warning 'Mihari could not send a malformed-request response.' }
    }
    catch [System.NotSupportedException] {
        $response = New-MihariManagementErrorResponse -StatusCode 501 -Code 'unsupported_request_framing' -Message 'The requested HTTP framing is not supported.'
        try { if ($null -ne $stream) { Write-MihariManagementResponse -Stream $stream -Response $response } }
        catch { Write-Warning 'Mihari could not send an unsupported-framing response.' }
    }
    catch [System.TimeoutException] {
        $response = New-MihariManagementErrorResponse -StatusCode 400 -Code 'request_timeout' -Message 'The management request was not completed before the request deadline.'
        try { if ($null -ne $stream) { Write-MihariManagementResponse -Stream $stream -Response $response } }
        catch { Write-Warning 'Mihari could not send a request-timeout response.' }
    }
    catch {
        # Management boundary errors are intentionally generic; exception
        # messages can contain local paths or caller supplied text.
        if ($null -ne $request -and $null -eq $response) {
            $workerHealthy = $false
            Write-MihariManagementWorkerFailure -Session $Session -ErrorType $_.Exception.GetType().FullName
        }
        try {
            if ($null -ne $stream) {
                $response = New-MihariManagementErrorResponse -StatusCode 500 -Code 'management_request_failed' -Message 'Mihari could not complete the management request.'
                Write-MihariManagementResponse -Stream $stream -Response $response
            }
        }
        catch { Write-Warning 'Mihari could not send a management error response.' }
    }
    finally {
        if ($null -ne $stream) { try { $stream.Dispose() } catch { Write-Warning 'A management response stream could not be disposed.' } }
        try { $Client.Close() } catch { Write-Warning 'A management client socket could not be disposed.' }
    }
    return $workerHealthy
}

function Write-MihariManagementWorkerFailure {
    param(
        [Parameter(Mandatory = $true)]$Session,
        [Parameter(Mandatory = $true)][string]$ErrorType
    )

    $Session.ManagementError = $ErrorType
    if (Get-Command Write-MihariEvent -ErrorAction SilentlyContinue) {
        try {
            $null = Write-MihariEvent -Session $Session -ConnectionId 'management' -Stage 'management.request' -Outcome 'failed' -ElapsedMs 0 -Data @{
                errorType = $ErrorType; errorCode = 'management_worker_failed'
            }
        }
        catch { Write-Warning 'Mihari could not record a management worker failure.' }
    }
}

function Complete-MihariManagementWorker {
    param([Parameter(Mandatory = $true)]$Worker)

    $failed = $false
    try {
        $workerResult = @($Worker.PowerShell.EndInvoke($Worker.AsyncResult))
        if ($workerResult.Count -gt 0 -and $workerResult[$workerResult.Count - 1] -is [bool] -and -not $workerResult[$workerResult.Count - 1]) {
            $failed = $true
        }
        if ($Worker.PowerShell.Streams.Error.Count -gt 0) {
            $failed = $true
            $errorType = 'System.Management.Automation.ErrorRecord'
            if ($null -ne $Worker.PowerShell.Streams.Error[0].Exception) { $errorType = $Worker.PowerShell.Streams.Error[0].Exception.GetType().FullName }
            Write-MihariManagementWorkerFailure -Session $Worker.Session -ErrorType $errorType
        }
    }
    catch {
        $failed = $true
        Write-MihariManagementWorkerFailure -Session $Worker.Session -ErrorType $_.Exception.GetType().FullName
        Write-Warning 'A management request worker ended unexpectedly.'
    }
    finally {
        try { $Worker.Client.Close() } catch { Write-Warning 'A management client socket could not be closed.' }
        $Worker.PowerShell.Dispose()
    }
    if (-not $failed) { $Worker.Session.ManagementError = $null }
}

function Start-MihariManagementListener {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Session)

    if ($null -ne $Session.ManagementListener -and (Test-MihariManagementListenerActive -Listener $Session.ManagementListener)) {
        return [int]$Session.ActualManagementPort
    }
    $port = 0
    if ($null -ne $Session.ManagementPort) { $port = [int]$Session.ManagementPort }
    if ($port -lt 0 -or $port -gt 65535) { throw 'Session.ManagementPort must be between 0 and 65535.' }

    $listener = New-Object System.Net.Sockets.TcpListener -ArgumentList @([System.Net.IPAddress]::Loopback, $port)
    $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, 4)
    $workers = New-Object System.Collections.ArrayList
    $workerScript = @'
param($WorkerSession, $WorkerClient, $WorkerSourceRoot)
$ErrorActionPreference = 'Stop'
try {
    foreach ($sourceFile in (Get-ChildItem -LiteralPath $WorkerSourceRoot -Filter '*.ps1' | Sort-Object Name)) {
        . $sourceFile.FullName
    }
    Handle-MihariManagementClient -Session $WorkerSession -Client $WorkerClient
}
finally {
    try { $WorkerClient.Close() } catch { Write-Warning 'A management worker client could not be closed.' }
}
'@

    $sourceRoot = [string]$Session.SourceRoot
    if (Test-Path -LiteralPath (Join-Path $sourceRoot 'src') -PathType Container) { $sourceRoot = Join-Path $sourceRoot 'src' }
    if (-not (Test-Path -LiteralPath (Join-Path $sourceRoot 'Browser.ps1') -PathType Leaf)) {
        throw 'Session.SourceRoot does not contain the Mihari runtime scripts.'
    }

    try {
        $pool.Open()
        $listener.Start(32)
        $actualPort = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
        Add-MihariManagementProperty -Object $Session -Name 'ManagementListener' -Value $listener
        Add-MihariManagementProperty -Object $Session -Name 'ManagementWorkerPool' -Value $pool
        Add-MihariManagementProperty -Object $Session -Name 'ManagementWorkers' -Value $workers
        Add-MihariManagementProperty -Object $Session -Name 'ManagementWorkerScript' -Value $workerScript
        Add-MihariManagementProperty -Object $Session -Name 'ManagementSourceRoot' -Value $sourceRoot
        Add-MihariManagementProperty -Object $Session -Name 'ActualManagementPort' -Value $actualPort
        Add-MihariManagementProperty -Object $Session -Name 'ManagementHeartbeatUtc' -Value ([DateTime]::UtcNow.ToString('o'))
        Add-MihariManagementProperty -Object $Session -Name 'ManagementStopped' -Value $false
        Add-MihariManagementProperty -Object $Session -Name 'ManagementError' -Value $null
        if (Get-Command Save-MihariSessionMetadata -ErrorAction SilentlyContinue) { [void](Save-MihariSessionMetadata -Session $Session) }
        return $actualPort
    }
    catch {
        try { $listener.Stop() } catch { Write-Warning 'The management listener failed to stop after startup failure.' }
        try { $pool.Close() } catch { Write-Warning 'The management worker pool failed to close after startup failure.' }
        try { $pool.Dispose() } catch { Write-Warning 'The management worker pool failed to dispose after startup failure.' }
        throw
    }
}

function Invoke-MihariManagementPending {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Session)

    $Session.ManagementHeartbeatUtc = [DateTime]::UtcNow.ToString('o')
    if ($null -eq $Session.ManagementListener -or $null -eq $Session.ManagementWorkerPool -or $null -eq $Session.ManagementWorkers) { return }
    if (-not (Test-MihariManagementListenerActive -Listener $Session.ManagementListener)) { return }

    $workers = $Session.ManagementWorkers
    for ($index = $workers.Count - 1; $index -ge 0; $index--) {
        if ($workers[$index].AsyncResult.IsCompleted) {
            $worker = $workers[$index]
            $workers.RemoveAt($index)
            Complete-MihariManagementWorker -Worker $worker
        }
    }
    if ($workers.Count -ge 4) { return }

    try {
        if (-not $Session.ManagementListener.Pending()) { return }
        $client = $Session.ManagementListener.AcceptTcpClient()
        $powerShell = [System.Management.Automation.PowerShell]::Create()
        try {
            $powerShell.RunspacePool = $Session.ManagementWorkerPool
            $null = $powerShell.AddScript($Session.ManagementWorkerScript).AddArgument($Session).AddArgument($client).AddArgument([string]$Session.ManagementSourceRoot)
            $asyncResult = $powerShell.BeginInvoke()
            [void]$workers.Add([pscustomobject]@{ PowerShell = $powerShell; AsyncResult = $asyncResult; Client = $client; Session = $Session })
        }
        catch {
            $powerShell.Dispose()
            $client.Close()
            throw
        }
    }
    catch {
        $Session.ManagementError = $_.Exception.GetType().FullName
        if (Get-Command Write-MihariEvent -ErrorAction SilentlyContinue) {
            try {
                $null = Write-MihariEvent -Session $Session -ConnectionId 'management' -Stage 'management.listener' -Outcome 'failed' -ElapsedMs 0 -Data @{
                    errorType = $_.Exception.GetType().FullName; errorCode = 'management_listener_failed'
                }
            }
            catch { Write-Warning 'Mihari could not record a management listener failure.' }
        }
    }
}

function Stop-MihariManagementListener {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Session)

    Add-MihariManagementProperty -Object $Session -Name 'ManagementStopped' -Value $true
    $cleanupErrors = New-Object System.Collections.ArrayList
    if ($null -ne $Session.ManagementListener) {
        try { $Session.ManagementListener.Stop() }
        catch { [void]$cleanupErrors.Add('management_listener_stop_failed') }
    }
    if ($null -ne $Session.ManagementWorkers) {
        foreach ($worker in @($Session.ManagementWorkers)) {
            try { $worker.Client.Close() }
            catch { [void]$cleanupErrors.Add('management_client_close_failed') }
        }
        foreach ($worker in @($Session.ManagementWorkers)) {
            try { $worker.PowerShell.Stop() }
            catch { [void]$cleanupErrors.Add('management_worker_stop_failed') }
            try { $worker.PowerShell.Dispose() }
            catch { [void]$cleanupErrors.Add('management_worker_dispose_failed') }
        }
        $Session.ManagementWorkers.Clear()
    }
    if ($null -ne $Session.ManagementWorkerPool) {
        try { $Session.ManagementWorkerPool.Close() }
        catch { [void]$cleanupErrors.Add('management_worker_pool_close_failed') }
        try { $Session.ManagementWorkerPool.Dispose() }
        catch { [void]$cleanupErrors.Add('management_worker_pool_dispose_failed') }
    }
    $Session.ManagementHeartbeatUtc = $null
    return [pscustomobject][ordered]@{
        success = ($cleanupErrors.Count -eq 0)
        errors = [string[]]$cleanupErrors.ToArray()
    }
}
