function Get-MihariMemberValue {
    param(
        [Parameter(Mandatory = $false)] [object] $InputObject,
        [Parameter(Mandatory = $true)] [string[]] $Names
    )

    if ($null -eq $InputObject) { return $null }

    foreach ($name in $Names) {
        if ($InputObject -is [System.Collections.IDictionary]) {
            foreach ($key in $InputObject.Keys) {
                if ([string]::Equals([string]$key, $name, [System.StringComparison]::OrdinalIgnoreCase)) {
                    $value = $InputObject[$key]
                    if ($null -ne $value) { return $value }
                }
            }
        }
        else {
            $property = $InputObject.PSObject.Properties[$name]
            if ($null -ne $property -and $null -ne $property.Value) {
                return $property.Value
            }
        }
    }

    return $null
}

function ConvertTo-MihariDiagnosisSafeText {
    param([Parameter(Mandatory = $false)] [object] $Value)

    if ($null -eq $Value) { return $null }
    if ($Value -is [System.Collections.IDictionary] -or $Value -is [System.Array]) { return $null }

    $text = [string]$Value
    $text = [System.Text.RegularExpressions.Regex]::Replace($text, '[\x00-\x1f\x7f]', ' ')
    $text = $text.Trim()
    if ($text.Length -gt 256) { $text = $text.Substring(0, 256) }
    if ($text.Length -eq 0) { return $null }
    return $text
}

function ConvertTo-MihariPath {
    param([Parameter(Mandatory = $false)] [object] $Value)

    $path = ConvertTo-MihariDiagnosisSafeText -Value $Value
    if ($null -eq $path) { return $null }
    $queryIndex = $path.IndexOf('?')
    if ($queryIndex -lt 0) { return $path }

    $basePath = $path.Substring(0, $queryIndex)
    $query = $path.Substring($queryIndex + 1)
    $safeParts = New-Object 'System.Collections.Generic.List[string]'
    foreach ($part in ($query -split '&')) {
        if ($part.Length -eq 0) { continue }
        $equalsIndex = $part.IndexOf('=')
        if ($equalsIndex -ge 0) {
            $key = $part.Substring(0, $equalsIndex)
        }
        else {
            # A keyless query token could itself be a secret, so do not echo it.
            $key = 'value'
        }
        $key = [System.Text.RegularExpressions.Regex]::Replace($key, '[^A-Za-z0-9_.~-]', '')
        if ($key.Length -gt 64) { $key = $key.Substring(0, 64) }
        if ($key.Length -eq 0) { $key = 'value' }
        $safeParts.Add($key + '=[REDACTED]')
    }

    if ($safeParts.Count -eq 0) { return $basePath + '?[REDACTED]' }
    return $basePath + '?' + [string]::Join('&', $safeParts.ToArray())
}

function Get-MihariEventData {
    param([Parameter(Mandatory = $false)] [object] $Event)

    $data = Get-MihariMemberValue -InputObject $Event -Names @('data')
    if ($null -eq $data) { return [pscustomobject]@{} }
    return $data
}

function Get-MihariEventValue {
    param(
        [Parameter(Mandatory = $false)] [object] $Event,
        [Parameter(Mandatory = $true)] [object] $Data,
        [Parameter(Mandatory = $true)] [string[]] $Names
    )

    $value = Get-MihariMemberValue -InputObject $Data -Names $Names
    if ($null -ne $value) { return $value }
    return Get-MihariMemberValue -InputObject $Event -Names $Names
}

function Get-MihariEventRecord {
    param(
        [Parameter(Mandatory = $true)] [object] $Event,
        [Parameter(Mandatory = $true)] [int] $Index
    )

    $data = Get-MihariEventData -Event $Event
    $eventId = ConvertTo-MihariDiagnosisSafeText -Value (Get-MihariEventValue -Event $Event -Data $data -Names @('eventId', 'id'))
    if ($null -eq $eventId) { $eventId = 'event-' + $Index.ToString('D6', [Globalization.CultureInfo]::InvariantCulture) }

    $upstream = Get-MihariMemberValue -InputObject $data -Names @('upstream', 'upstreamRoute', 'route')
    if ($null -eq $upstream) { $upstream = [pscustomobject]@{} }
    $routeKind = Get-MihariMemberValue -InputObject $upstream -Names @('kind', 'routeKind', 'type')
    if ($null -eq $routeKind) {
        $routeKind = Get-MihariEventValue -Event $Event -Data $data -Names @('upstreamKind', 'routeKind', 'upstreamRouteKind')
    }
    $routeToken = ''
    if ($null -ne $routeKind) { $routeToken = ([string]$routeKind -replace '[^A-Za-z]', '').ToLowerInvariant() }
    $explicitFlag = Get-MihariEventValue -Event $Event -Data $data -Names @('explicitProxy', 'isExplicitProxy')
    $isExplicitProxy = ($routeToken -eq 'explicitproxy' -or $routeToken -eq 'explicit')
    if ($null -ne $explicitFlag -and ([string]$explicitFlag).ToLowerInvariant() -eq 'true') { $isExplicitProxy = $true }

    $destinationHost = Get-MihariEventValue -Event $Event -Data $data -Names @('destinationHost', 'host', 'hostname', 'targetHost')
    $port = Get-MihariEventValue -Event $Event -Data $data -Names @('destinationPort', 'port', 'targetPort')
    $proxyStatusValue = Get-MihariEventValue -Event $Event -Data $data -Names @('proxyStatus', 'proxyStatusCode')
    $proxyStatus = $null
    if ($null -ne $proxyStatusValue -and [string]$proxyStatusValue -match '^([1-5][0-9][0-9])$') {
        $proxyStatus = [int]$Matches[1]
    }
    $proxyResponseFlag = Get-MihariEventValue -Event $Event -Data $data -Names @('proxyResponse', 'isProxyResponse', 'upstreamProxyResponse')
    $responseSource = Get-MihariEventValue -Event $Event -Data $data -Names @('responseSource', 'responderKind')
    $responseSourceToken = ''
    if ($null -ne $responseSource) { $responseSourceToken = ([string]$responseSource -replace '[^A-Za-z]', '').ToLowerInvariant() }
    $hasProxyResponseProvenance = ($null -ne $proxyStatus) -or
        ($null -ne $proxyResponseFlag -and ([string]$proxyResponseFlag).ToLowerInvariant() -eq 'true') -or
        (@('explicitproxy', 'upstreamproxy', 'proxy') -contains $responseSourceToken)
    $statusValue = Get-MihariEventValue -Event $Event -Data $data -Names @('statusCode', 'httpStatusCode', 'responseStatusCode')
    $status = $null
    if ($null -ne $statusValue -and [string]$statusValue -match '^([1-5][0-9][0-9])$') {
        $status = [int]$Matches[1]
    }

    $stage = ConvertTo-MihariDiagnosisSafeText -Value (Get-MihariEventValue -Event $Event -Data $data -Names @('stage'))
    $outcome = ConvertTo-MihariDiagnosisSafeText -Value (Get-MihariEventValue -Event $Event -Data $data -Names @('outcome'))
    $mode = ConvertTo-MihariDiagnosisSafeText -Value (Get-MihariEventValue -Event $Event -Data $data -Names @('mode'))
    $errorCode = ConvertTo-MihariDiagnosisSafeText -Value (Get-MihariEventValue -Event $Event -Data $data -Names @('mihariErrorCode', 'errorCode'))
    $errorType = ConvertTo-MihariDiagnosisSafeText -Value (Get-MihariEventValue -Event $Event -Data $data -Names @('errorType', 'exceptionType'))
    $connectionId = ConvertTo-MihariDiagnosisSafeText -Value (Get-MihariEventValue -Event $Event -Data $data -Names @('connectionId'))
    $requestId = ConvertTo-MihariDiagnosisSafeText -Value (Get-MihariEventValue -Event $Event -Data $data -Names @('requestId'))
    $sessionId = ConvertTo-MihariDiagnosisSafeText -Value (Get-MihariEventValue -Event $Event -Data $data -Names @('sessionId'))

    return [pscustomobject]@{
        Event = $Event
        Data = $data
        EventId = $eventId
        Index = $Index
        Stage = $stage
        Outcome = $outcome
        Mode = $mode
        ErrorCode = $errorCode
        ErrorType = $errorType
        ConnectionId = $connectionId
        RequestId = $requestId
        SessionId = $sessionId
        Host = (ConvertTo-MihariDiagnosisSafeText -Value $destinationHost)
        Port = (ConvertTo-MihariDiagnosisSafeText -Value $port)
        Status = $status
        ProxyStatus = $proxyStatus
        RouteKind = (ConvertTo-MihariDiagnosisSafeText -Value $routeKind)
        IsExplicitProxy = $isExplicitProxy
        HasProxyResponseProvenance = $hasProxyResponseProvenance
        ResponseSource = (ConvertTo-MihariDiagnosisSafeText -Value $responseSource)
    }
}

function New-MihariObservedFact {
    param([Parameter(Mandatory = $true)] [object] $Record)

    $fact = [ordered]@{ eventId = $Record.EventId }
    foreach ($name in @('stage', 'outcome', 'mode')) {
        $value = $Record.$name
        if ($null -ne $value) { $fact[$name] = $value }
    }
    if ($null -ne $Record.ConnectionId) { $fact['connectionId'] = $Record.ConnectionId }
    if ($null -ne $Record.RequestId) { $fact['requestId'] = $Record.RequestId }
    if ($null -ne $Record.SessionId) { $fact['sessionId'] = $Record.SessionId }
    if ($null -ne $Record.Host) { $fact['host'] = $Record.Host }
    if ($null -ne $Record.Port) { $fact['port'] = $Record.Port }
    if ($null -ne $Record.RouteKind) { $fact['routeKind'] = $Record.RouteKind }
    if ($null -ne $Record.Status) { $fact['statusCode'] = $Record.Status }
    if ($null -ne $Record.ProxyStatus) { $fact['proxyStatus'] = $Record.ProxyStatus }
    if ($null -ne $Record.ResponseSource) { $fact['responseSource'] = $Record.ResponseSource }
    if ($null -ne $Record.ErrorCode) { $fact['errorCode'] = $Record.ErrorCode }
    if ($null -ne $Record.ErrorType) { $fact['errorType'] = $Record.ErrorType }

    $method = ConvertTo-MihariDiagnosisSafeText -Value (Get-MihariEventValue -Event $Record.Event -Data $Record.Data -Names @('method', 'httpMethod'))
    if ($null -ne $method) { $fact['method'] = $method }
    $path = ConvertTo-MihariPath -Value (Get-MihariEventValue -Event $Record.Event -Data $Record.Data -Names @('path', 'requestPath', 'urlPath'))
    if ($null -ne $path) { $fact['path'] = $path }
    return [pscustomobject]$fact
}

function New-MihariFinding {
    param(
        [Parameter(Mandatory = $true)] [string] $Code,
        [Parameter(Mandatory = $true)] [string] $Summary,
        [Parameter(Mandatory = $true)] [string] $Scope,
        [Parameter(Mandatory = $true)] [object[]] $Records,
        [Parameter(Mandatory = $true)] [string] $Interpretation,
        [Parameter(Mandatory = $true)] [string] $Limitations
    )

    $ids = New-Object 'System.Collections.Generic.List[string]'
    $facts = New-Object 'System.Collections.Generic.List[object]'
    foreach ($record in $Records) {
        if (-not $ids.Contains([string]$record.EventId)) { $ids.Add([string]$record.EventId) }
        $facts.Add((New-MihariObservedFact -Record $record))
    }

    return [pscustomobject][ordered]@{
        code = $Code
        summary = $Summary
        scope = $Scope
        evidenceIds = @($ids.ToArray())
        observedFacts = @($facts.ToArray())
        interpretation = $Interpretation
        limitations = $Limitations
    }
}

function Test-MihariFailedOutcome {
    param([object] $Record)
    if ($null -eq $Record.Outcome) { return $false }
    $value = ([string]$Record.Outcome -replace '[^A-Za-z]', '').ToLowerInvariant()
    return @('failed', 'failure', 'error', 'timedout', 'timeout', 'aborted', 'rejected', 'unsupported') -contains $value
}

function Test-MihariSuccessfulOutcome {
    param([object] $Record)
    if ($null -eq $Record.Outcome) { return $false }
    $value = ([string]$Record.Outcome -replace '[^A-Za-z]', '').ToLowerInvariant()
    return @('success', 'succeeded', 'complete', 'completed', 'established', 'connected', 'ok') -contains $value
}

function Get-MihariDiagnosis {
    [CmdletBinding()]
    param([Parameter(Mandatory = $false)] [object[]] $Events = @())

    $records = New-Object 'System.Collections.Generic.List[object]'
    $index = 0
    foreach ($event in $Events) {
        if ($null -eq $event) { continue }
        $index++
        $records.Add((Get-MihariEventRecord -Event $event -Index $index))
    }

    $findings = New-Object 'System.Collections.Generic.List[object]'
    foreach ($record in $records) {
        $data = $record.Data
        $stageToken = ''
        if ($null -ne $record.Stage) { $stageToken = ([string]$record.Stage -replace '[^A-Za-z]', '').ToLowerInvariant() }
        $proxyStatus = $record.ProxyStatus
        $isProxyConnectResponse = $record.IsExplicitProxy -and $null -ne $proxyStatus -and
            ($stageToken -eq 'upstreamproxyconnect' -or $stageToken -eq 'proxyconnect' -or $stageToken -eq 'upstreamconnectproxy')
        $isHttpProxyResponse = $record.IsExplicitProxy -and $stageToken -eq 'upstreamhttp'
        if (($isProxyConnectResponse -and $proxyStatus -eq 407) -or
            ($isHttpProxyResponse -and $record.Status -eq 407)) {
            $scope = 'connection'
            if ($null -ne $record.RequestId) { $scope = 'request' }
            $findings.Add((New-MihariFinding -Code 'upstream_proxy_auth_required' `
                -Summary 'The explicit upstream proxy returned HTTP 407.' -Scope $scope -Records @($record) `
                -Interpretation 'A concrete HTTP 407 was observed on an explicit upstream proxy route.' `
                -Limitations 'The event does not identify which credentials or authentication policy would satisfy the proxy.'))
        }
        elseif (($isProxyConnectResponse -and $proxyStatus -eq 403) -or
            ($isHttpProxyResponse -and $record.Status -eq 403 -and $record.HasProxyResponseProvenance)) {
            $scope = 'connection'
            if ($null -ne $record.RequestId) { $scope = 'request' }
            $findings.Add((New-MihariFinding -Code 'upstream_proxy_rejected' `
                -Summary 'The explicit upstream proxy returned HTTP 403.' -Scope $scope -Records @($record) `
                -Interpretation 'An explicit upstream proxy returned a concrete HTTP 403 response.' `
                -Limitations 'The proxy response does not reveal the internal rule or policy that caused the rejection.'))
        }

        $errorToken = ''
        if ($null -ne $record.ErrorCode) { $errorToken = ([string]$record.ErrorCode -replace '[^A-Za-z0-9]', '').ToLowerInvariant() }
        if ($errorToken -eq 'upstreamrouteunresolved' -or
            ($stageToken -eq 'upstreamresolve' -and ([string]$record.RouteKind -eq 'Unsupported'))) {
            $scope = 'connection'
            if ($null -ne $record.RequestId) { $scope = 'request' }
            $findings.Add((New-MihariFinding -Code 'upstream_route_unresolved' `
                -Summary 'Mihari could not determine a supported upstream route.' -Scope $scope -Records @($record) `
                -Interpretation 'The configured platform or explicit route could not be honored, so Mihari did not select a different route.' `
                -Limitations 'The event does not establish which network component would have handled the request outside Mihari.'))
        }

        $isCertificateFailure = $errorToken -match '(certificate|cert).*(validation|invalid|trust|chain|name|auth)' -or
            $errorToken -match '(validation|trust|chain|name).*(certificate|cert)'
        if ($isCertificateFailure -and (Test-MihariFailedOutcome -Record $record)) {
            $scope = 'connection'
            if ($null -ne $record.RequestId) { $scope = 'request' }
            $findings.Add((New-MihariFinding -Code 'upstream_certificate_invalid' `
                -Summary 'Upstream TLS certificate validation failed.' -Scope $scope -Records @($record) `
                -Interpretation 'The local TLS stack reported a certificate validation failure on the upstream connection.' `
                -Limitations 'The finding does not distinguish expiry, name mismatch, trust-chain, revocation, or interception causes unless the event records that detail.'))
        }

        $unsupportedValue = Get-MihariEventValue -Event $record.Event -Data $data -Names @('unsupportedProtocol', 'protocol')
        $unsupportedToken = ''
        if ($null -ne $unsupportedValue) { $unsupportedToken = ([string]$unsupportedValue -replace '[^A-Za-z0-9]', '').ToLowerInvariant() }
        $isUnsupported = ($errorToken -eq 'unsupportedprotocol') -or
            ((Test-MihariFailedOutcome -Record $record) -and $unsupportedToken -match '^(http2|http3|quic|tls13|tlsv13)$' -and ($stageToken -match 'protocol|tls|http'))
        if ($isUnsupported) {
            $scope = 'connection'
            if ($null -ne $record.RequestId) { $scope = 'request' }
            $protocolText = ConvertTo-MihariDiagnosisSafeText -Value $unsupportedValue
            if ($null -eq $protocolText) { $protocolText = 'the requested protocol' }
            $findings.Add((New-MihariFinding -Code 'unsupported_protocol' `
                -Summary ('Mihari could not process ' + $protocolText + ' in this session.') -Scope $scope -Records @($record) `
                -Interpretation 'The observed protocol behavior is outside the initial HTTP/1.1, CONNECT, and TLS 1.2 contract.' `
                -Limitations 'This is a capability boundary and does not indicate that a proxy, firewall, or destination rejected the traffic.'))
        }

        $isTimeout = ($errorToken -match 'timeout|timedout') -or ($record.ErrorType -match 'TimeoutException|SocketException' -and $stageToken -match 'connect')
        if ($isTimeout -and (Test-MihariFailedOutcome -Record $record)) {
            $scope = 'connection'
            if ($null -ne $record.RequestId) { $scope = 'request' }
            $findings.Add((New-MihariFinding -Code 'connection_timeout' `
                -Summary 'A connection stage timed out.' -Scope $scope -Records @($record) `
                -Interpretation 'Mihari observed a timeout at the recorded connection stage.' `
                -Limitations 'A timeout alone does not identify which network component or policy caused the delay.'))
        }
    }

    $tunnelSuccesses = New-Object 'System.Collections.Generic.List[object]'
    $inspectTlsFailures = New-Object 'System.Collections.Generic.List[object]'
    foreach ($record in $records) {
        $modeToken = ''
        if ($null -ne $record.Mode) { $modeToken = ([string]$record.Mode -replace '[^A-Za-z]', '').ToLowerInvariant() }
        $stageToken = ''
        if ($null -ne $record.Stage) { $stageToken = ([string]$record.Stage -replace '[^A-Za-z]', '').ToLowerInvariant() }
        $errorToken = ''
        if ($null -ne $record.ErrorCode) { $errorToken = ([string]$record.ErrorCode -replace '[^A-Za-z0-9]', '').ToLowerInvariant() }

        if ($modeToken -eq 'tunnel' -and (Test-MihariSuccessfulOutcome -Record $record) -and
            ($stageToken -match 'tunnelrelay|tunnelcomplete|connectioncomplete|connectionclosed')) {
            $tunnelSuccesses.Add($record)
        }
        if ($modeToken -eq 'inspect' -and (Test-MihariFailedOutcome -Record $record) -and
            (($stageToken -match 'clienttls|tlsclient|inspecttlsclient') -or $errorToken -eq 'clienttlshandshakefailed')) {
            $inspectTlsFailures.Add($record)
        }
    }

    foreach ($inspect in $inspectTlsFailures) {
        if ($null -eq $inspect.Host -or $null -eq $inspect.Port) { continue }
        $inspectAuthority = $inspect.Host.ToLowerInvariant() + ':' + $inspect.Port
        foreach ($tunnel in $tunnelSuccesses) {
            if ($null -eq $tunnel.Host -or $null -eq $tunnel.Port) { continue }
            if (($tunnel.Host.ToLowerInvariant() + ':' + $tunnel.Port) -ne $inspectAuthority) { continue }

            $findings.Add((New-MihariFinding -Code 'tls_interception_incompatible' `
                -Summary ('Inspect failed while Tunnel succeeded for ' + $inspect.Host + ':' + $inspect.Port + '.') `
                -Scope 'host' -Records @($inspect, $tunnel) `
                -Interpretation 'The comparable destination succeeded through Tunnel but the client TLS handshake failed during Inspect.' `
                -Limitations 'This comparison supports an interception-incompatible behavior; it does not distinguish certificate pinning, mTLS, application behavior, or other causes.'))
            break
        }
    }

    return @($findings.ToArray())
}

function New-MihariReportText {
    param([Parameter(Mandatory = $true)] [object] $Report)

    $lines = New-Object 'System.Collections.Generic.List[string]'
    $findings = @($Report.findings)
    $lines.Add('Mihari diagnostic report')
    $lines.Add('Session: ' + [string]$Report.sessionId)
    if ($null -ne $Report.comparisonSessionId) { $lines.Add('Comparison session: ' + [string]$Report.comparisonSessionId) }
    $lines.Add('Events: ' + [string]$Report.eventCount)
    $lines.Add('Primary events: ' + [string]$Report.primaryEventCount)
    $lines.Add('Comparison events: ' + [string]$Report.comparedEventCount)
    $lines.Add('Findings: ' + [string]$findings.Count)
    $lines.Add('')

    if ($findings.Count -eq 0) {
        $lines.Add('No diagnosis is supported by the recorded evidence.')
    }
    else {
        $number = 0
        foreach ($finding in $findings) {
            $number++
            $lines.Add(('{0}. [{1}] {2}' -f $number, $finding.code, $finding.summary))
            $lines.Add('   Scope: ' + $finding.scope)
            $lines.Add('   Evidence: ' + [string]::Join(', ', @($finding.evidenceIds)))
            foreach ($fact in @($finding.observedFacts)) {
                $parts = New-Object 'System.Collections.Generic.List[string]'
                foreach ($name in @('stage', 'outcome', 'mode', 'sessionId', 'host', 'port', 'statusCode', 'proxyStatus', 'errorCode', 'path')) {
                    $value = Get-MihariMemberValue -InputObject $fact -Names @($name)
                    if ($null -ne $value) { $parts.Add($name + '=' + [string]$value) }
                }
                if ($parts.Count -gt 0) { $lines.Add('   Fact: ' + [string]::Join('; ', $parts.ToArray())) }
            }
            $lines.Add('   Interpretation: ' + $finding.interpretation)
            $lines.Add('   Limitations: ' + $finding.limitations)
            $lines.Add('')
        }
    }

    return [string]::Join([Environment]::NewLine, $lines.ToArray()) + [Environment]::NewLine
}

function Add-MihariJsonlEvents {
    param(
        [Parameter(Mandatory = $true)] [string] $Path,
        [Parameter(Mandatory = $true)] [System.Collections.Generic.List[object]] $Events,
        [Parameter(Mandatory = $true)] [string] $LogName
    )

    if (-not [System.IO.File]::Exists($Path)) {
        throw ($LogName + ' events file was not found.')
    }

    $lineNumber = 0
    foreach ($line in [System.IO.File]::ReadAllLines($Path)) {
        $lineNumber++
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        try {
            $Events.Add((ConvertFrom-Json -InputObject $line -ErrorAction Stop))
        }
        catch {
            throw ('Invalid ' + $LogName + ' JSONL event on line ' + $lineNumber + '.')
        }
    }
}

function Get-MihariFirstSessionId {
    param([Parameter(Mandatory = $false)] [object[]] $Events = @())

    foreach ($event in $Events) {
        if ($null -eq $event) { continue }
        $data = Get-MihariEventData -Event $event
        $sessionId = ConvertTo-MihariDiagnosisSafeText -Value (Get-MihariEventValue -Event $event -Data $data -Names @('sessionId'))
        if ($null -ne $sessionId) { return $sessionId }
    }
    return $null
}

function New-MihariReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string] $EventsPath,
        [Parameter(Mandatory = $true)] [string] $OutputDirectory,
        [Parameter(Mandatory = $false)] [string] $CompareEventsPath
    )

    $events = New-Object 'System.Collections.Generic.List[object]'
    Add-MihariJsonlEvents -Path $EventsPath -Events $events -LogName 'Primary'
    $primaryEventCount = $events.Count

    if (-not [string]::IsNullOrWhiteSpace($CompareEventsPath)) {
        $primaryFullPath = [System.IO.Path]::GetFullPath($EventsPath)
        $compareFullPath = [System.IO.Path]::GetFullPath($CompareEventsPath)
        if ([string]::Equals($primaryFullPath, $compareFullPath, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw 'Comparison events must come from a different file.'
        }
        Add-MihariJsonlEvents -Path $CompareEventsPath -Events $events -LogName 'Comparison'
    }

    $allEvents = @($events.ToArray())
    $findings = @(Get-MihariDiagnosis -Events $allEvents)
    $primarySessionId = Get-MihariFirstSessionId -Events @($allEvents | Select-Object -First $primaryEventCount)
    $comparisonEvents = @()
    if ($events.Count -gt $primaryEventCount) {
        $comparisonEvents = @($allEvents | Select-Object -Skip $primaryEventCount)
    }
    $comparisonSessionId = Get-MihariFirstSessionId -Events $comparisonEvents
    $sessionIds = New-Object 'System.Collections.Generic.List[string]'
    foreach ($event in $allEvents) {
        $data = Get-MihariEventData -Event $event
        $sessionId = ConvertTo-MihariDiagnosisSafeText -Value (Get-MihariEventValue -Event $event -Data $data -Names @('sessionId'))
        if ($null -ne $sessionId -and -not $sessionIds.Contains($sessionId)) { $sessionIds.Add($sessionId) }
    }

    [System.IO.Directory]::CreateDirectory($OutputDirectory) | Out-Null
    $jsonPath = [System.IO.Path]::Combine($OutputDirectory, 'report.json')
    $textPath = [System.IO.Path]::Combine($OutputDirectory, 'report.txt')
    $report = [pscustomobject][ordered]@{
        schemaVersion = 1
        sessionId = $primarySessionId
        comparisonSessionId = $comparisonSessionId
        sessionIds = @($sessionIds.ToArray())
        eventCount = $events.Count
        primaryEventCount = $primaryEventCount
        comparedEventCount = $comparisonEvents.Count
        findings = @($findings)
        files = [pscustomobject][ordered]@{ json = $jsonPath; text = $textPath }
    }

    $json = ConvertTo-Json -InputObject $report -Depth 20
    $encoding = [System.Text.UTF8Encoding]::new($false)
    [System.IO.File]::WriteAllText($jsonPath, $json + [Environment]::NewLine, $encoding)
    [System.IO.File]::WriteAllText($textPath, (New-MihariReportText -Report $report), $encoding)
    return $report
}
