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
    $timestamp = ConvertTo-MihariDiagnosisSafeText -Value (Get-MihariEventValue -Event $Record.Event -Data $Record.Data -Names @('timestamp'))
    if ($null -ne $timestamp) { $fact['timestamp'] = $timestamp }
    foreach ($name in @('sequence', 'source', 'trialId', 'caseId', 'configurationRevision', 'transportLeg', 'upstreamConnectionId', 'streamId', 'sourceIdentity', 'sourceVersion', 'protocolProfile', 'proxyAuthState', 'cacheState', 'networkFingerprint')) {
        $value = Get-MihariEventValue -Event $Record.Event -Data $Record.Data -Names @($name)
        if ($null -ne $value) {
            if ($name -eq 'sequence') {
                $sequenceNumber = 0L
                if ([long]::TryParse([string]$value, [ref]$sequenceNumber) -and $sequenceNumber -gt 0) { $fact[$name] = $sequenceNumber }
            }
            else {
                $safeValue = ConvertTo-MihariDiagnosisSafeText -Value $value
                if ($null -ne $safeValue) { $fact[$name] = $safeValue }
            }
        }
    }
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
    $evidenceRefs = New-Object 'System.Collections.Generic.List[object]'
    foreach ($record in $Records) {
        if (-not $ids.Contains([string]$record.EventId)) { $ids.Add([string]$record.EventId) }
        $facts.Add((New-MihariObservedFact -Record $record))
        $evidenceSession = $record.SessionId
        $evidenceRefs.Add([pscustomobject][ordered]@{ sessionId = $evidenceSession; eventId = $record.EventId })
    }

    return [pscustomobject][ordered]@{
        code = $Code
        summary = $Summary
        scope = $Scope
        evidenceIds = @($ids.ToArray())
        evidenceRefs = @($evidenceRefs.ToArray())
        observedFacts = @($facts.ToArray())
        ruleVersion = 'mihari-diagnosis/1'
        classification = (Get-MihariFindingClassification -Code $Code)
        evidenceStrength = (Get-MihariFindingEvidenceStrength -Code $Code)
        interpretation = $Interpretation
        limitations = $Limitations
        nextCheck = (Get-MihariFindingNextCheck -Code $Code)
    }
}

function Get-MihariFindingClassification {
    param([Parameter(Mandatory = $true)][string] $Code)
    switch ($Code) {
        'upstream_proxy_auth_required' { return 'proxy_authentication' }
        'upstream_proxy_rejected' { return 'upstream_proxy_rejection' }
        'upstream_route_unresolved' { return 'upstream_route' }
        'upstream_certificate_invalid' { return 'tls_validation' }
        'tls_interception_incompatible' { return 'interception_compatibility' }
        'client_tls_interception_failed' { return 'interception_compatibility' }
        'unsupported_protocol' { return 'unsupported_transport' }
        'connection_timeout' { return 'connectivity' }
        'dns_resolution_failed' { return 'dns' }
        'tcp_connection_failed' { return 'connectivity' }
        'upstream_tls_failed' { return 'upstream_tls' }
        'http_error_response' { return 'http_application_response' }
        'browser_request_failed' { return 'browser_observation' }
        'observer_resource_failure' { return 'observer_health' }
        'self_reference_rejected' { return 'mihari_safety' }
        'cleanup_incomplete' { return 'cleanup' }
        default { return 'unclassified_failure' }
    }
}

function Get-MihariFindingEvidenceStrength {
    param([Parameter(Mandatory = $true)][string] $Code)
    if ($Code -eq 'tls_interception_incompatible') { return 'comparison_supported' }
    if ($Code -eq 'unclassified_failure') { return 'undetermined' }
    return 'direct_observation'
}

function Get-MihariFindingNextCheck {
    param([Parameter(Mandatory = $true)][string] $Code)
    switch ($Code) {
        'upstream_proxy_auth_required' { return 'Confirm the required authentication scheme and identity with the enterprise proxy administrator.' }
        'upstream_proxy_rejected' { return 'Ask the proxy administrator to identify the request using this event evidence and explain the rejection.' }
        'upstream_route_unresolved' { return 'Verify the configured Windows or explicit proxy route and its PAC/WPAD result.' }
        'upstream_certificate_invalid' { return 'Review the recorded certificate and platform validation details, then compare with a trusted endpoint path.' }
        'tls_interception_incompatible' { return 'Repeat a trial with matching protocol, authentication, cache, and network conditions; collect browser evidence for the failed request.' }
        'client_tls_interception_failed' { return 'Compare with a Tunnel trial using the same protocol, authentication, cache, and network conditions.' }
        'unsupported_protocol' { return 'Repeat with a supported diagnostic profile or collect browser-side protocol evidence.' }
        'connection_timeout' { return 'Repeat the connection attempt and compare DNS, route, and connection-stage evidence.' }
        'dns_resolution_failed' { return 'Repeat name resolution in the same endpoint and network context, then compare the returned address set.' }
        'tcp_connection_failed' { return 'Verify endpoint reachability and the selected upstream route with a comparable trial.' }
        'upstream_tls_failed' { return 'Inspect the upstream TLS stage and certificate-validation state before attributing a cause.' }
        'http_error_response' { return 'Use the response evidence and request correlation data to identify which visible endpoint returned the status.' }
        'browser_request_failed' { return 'Inspect the browser-owned request failure and its initiator/cache context.' }
        'observer_resource_failure' { return 'Check Mihari queue, storage, and writer health before interpreting missing traffic evidence.' }
        'self_reference_rejected' { return 'Review the selected upstream endpoint and ensure it does not point back to Mihari.' }
        'cleanup_incomplete' { return 'Review cleanup evidence and remove only artifacts whose Mihari ownership is positively verified.' }
        default { return 'Collect a comparable trial with request, route, and stage evidence.' }
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

function Get-MihariDiagnosisInstances {
    [CmdletBinding()]
    param([Parameter(Mandatory = $false)] [AllowEmptyCollection()] [object[]] $Events = @())

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

        $failure = Test-MihariFailedOutcome -Record $record
        $sourceValue = Get-MihariEventValue -Event $record.Event -Data $data -Names @('source')
        $sourceToken = ''
        if ($null -ne $sourceValue) { $sourceToken = ([string]$sourceValue -replace '[^A-Za-z]', '').ToLowerInvariant() }
        $isDnsFailure = $failure -and ($stageToken -eq 'upstreamresolve' -or $errorToken -match 'dns|name.?resolution|host.?not.?found')
        if ($isDnsFailure) {
            $scope = 'connection'
            if ($null -ne $record.RequestId) { $scope = 'request' }
            $findings.Add((New-MihariFinding -Code 'dns_resolution_failed' `
                -Summary 'Name resolution failed at the recorded upstream stage.' -Scope $scope -Records @($record) `
                -Interpretation 'The endpoint observed a name-resolution failure for this attempt.' `
                -Limitations 'The event does not identify whether the cause is DNS policy, resolver availability, or a transient network condition.'))
        }
        elseif ($failure -and $stageToken -match 'upstreamtcp|tcpconnect' -and $errorToken -notmatch 'timeout|timedout') {
            $scope = 'connection'
            if ($null -ne $record.RequestId) { $scope = 'request' }
            $findings.Add((New-MihariFinding -Code 'tcp_connection_failed' `
                -Summary 'The upstream TCP connection failed.' -Scope $scope -Records @($record) `
                -Interpretation 'The endpoint observed a TCP connection failure at the recorded upstream stage.' `
                -Limitations 'The event does not identify which network component caused the connection failure.'))
        }
        elseif ($failure -and $stageToken -match 'upstreamtls|upstreamhandshaketls' -and -not $isCertificateFailure) {
            $scope = 'connection'
            if ($null -ne $record.RequestId) { $scope = 'request' }
            $findings.Add((New-MihariFinding -Code 'upstream_tls_failed' `
                -Summary 'The upstream TLS connection failed.' -Scope $scope -Records @($record) `
                -Interpretation 'The upstream TLS stage failed according to the recorded endpoint evidence.' `
                -Limitations 'A generic handshake failure does not prove certificate pinning, mTLS, or a particular upstream policy.'))
        }
        elseif ($failure -and ($stageToken -match 'clienttls|tlsclient|inspecttlsclient' -or $errorToken -eq 'clienttlshandshakefailed')) {
            $scope = 'connection'
            if ($null -ne $record.RequestId) { $scope = 'request' }
            $findings.Add((New-MihariFinding -Code 'client_tls_interception_failed' `
                -Summary 'The client TLS handshake failed during Inspect.' -Scope $scope -Records @($record) `
                -Interpretation 'Mihari observed a TLS handshake failure on the client-facing Inspect leg.' `
                -Limitations 'This event alone does not distinguish certificate pinning, mTLS, protocol mismatch, or other client/application behavior.'))
        }

        if ($null -ne $record.Status -and $record.Status -ge 400 -and $stageToken -match 'httpresponse|upstreamhttp|response' -and
            -not ($isHttpProxyResponse -and $record.Status -in @(403, 407) -and $record.HasProxyResponseProvenance)) {
            $scope = 'connection'
            if ($null -ne $record.RequestId) { $scope = 'request' }
            $findings.Add((New-MihariFinding -Code 'http_error_response' `
                -Summary ('An HTTP response with status ' + $record.Status.ToString([Globalization.CultureInfo]::InvariantCulture) + ' was observed.') -Scope $scope -Records @($record) `
                -Interpretation 'An HTTP error status was visible to Mihari for this exchange.' `
                -Limitations 'Unless explicit-proxy response provenance is present, the event does not establish whether an origin or intermediary generated the response.'))
        }

        if ($failure -and $sourceToken -eq 'browser') {
            $scope = 'request'
            if ($null -eq $record.RequestId) { $scope = 'connection' }
            $findings.Add((New-MihariFinding -Code 'browser_request_failed' `
                -Summary 'The diagnostic browser reported a request failure.' -Scope $scope -Records @($record) `
                -Interpretation 'A browser-owned observation reported this request as failed.' `
                -Limitations 'The browser event alone does not prove whether the failure occurred in Mihari, the network path, or the destination.'))
        }

        if ($failure -and ($errorToken -match 'self.?reference' -or $stageToken -match 'selfreference')) {
            $findings.Add((New-MihariFinding -Code 'self_reference_rejected' `
                -Summary 'Mihari rejected a route that would point back to its own listener.' -Scope 'connection' -Records @($record) `
                -Interpretation 'The safety check detected a self-referential upstream route and prevented forwarding.' `
                -Limitations 'The event describes Mihari route protection, not a destination or enterprise network rejection.'))
        }

        if ($failure -and ($stageToken -match 'cleanup' -or $errorToken -match 'cleanup')) {
            $findings.Add((New-MihariFinding -Code 'cleanup_incomplete' `
                -Summary 'Session cleanup reported an incomplete operation.' -Scope 'session' -Records @($record) `
                -Interpretation 'A cleanup action failed or could not confirm its expected completion.' `
                -Limitations 'Only the artifacts named by the cleanup evidence can be considered affected.'))
        }

        if ($failure -and ($errorToken -match 'queue|writer|disklimit|storage|resourceexhaust|observer')) {
            $findings.Add((New-MihariFinding -Code 'observer_resource_failure' `
                -Summary 'Mihari reported a capture or observer resource failure.' -Scope 'session' -Records @($record) `
                -Interpretation 'The recorded failure concerns Mihari evidence collection or storage health.' `
                -Limitations 'The event does not establish that an observed destination request failed.'))
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
        if ($isTimeout -and (Test-MihariFailedOutcome -Record $record) -and -not $isDnsFailure) {
            $scope = 'connection'
            if ($null -ne $record.RequestId) { $scope = 'request' }
            $findings.Add((New-MihariFinding -Code 'connection_timeout' `
                -Summary 'A connection stage timed out.' -Scope $scope -Records @($record) `
                -Interpretation 'Mihari observed a timeout at the recorded connection stage.' `
                -Limitations 'A timeout alone does not identify which network component or policy caused the delay.'))
        }

        if ($failure -and -not $isDnsFailure -and
            -not ($stageToken -match 'upstreamtcp|tcpconnect') -and
            -not ($stageToken -match 'upstreamtls|upstreamhandshaketls') -and
            -not ($null -ne $record.Status -and $record.Status -ge 400) -and
            $sourceToken -ne 'browser' -and
            -not ($errorToken -match 'self.?reference|cleanup|queue|writer|disklimit|storage|resourceexhaust|observer') -and
            -not $isCertificateFailure -and -not $isUnsupported -and -not $isTimeout -and
            -not ($stageToken -match 'clienttls|tlsclient|inspecttlsclient' -or $errorToken -eq 'clienttlshandshakefailed') -and
            -not $isProxyConnectResponse -and
            -not ($isHttpProxyResponse -and $record.Status -in @(403, 407) -and $record.HasProxyResponseProvenance) -and
            -not ($errorToken -eq 'upstreamrouteunresolved' -or ($stageToken -eq 'upstreamresolve' -and ([string]$record.RouteKind -eq 'Unsupported')))) {
            $scope = 'connection'
            if ($null -ne $record.RequestId) { $scope = 'request' }
            $findings.Add((New-MihariFinding -Code 'unclassified_failure' `
                -Summary 'A failure was observed, but no specific diagnosis rule applies.' -Scope $scope -Records @($record) `
                -Interpretation 'The evidence records a failed stage without a supported more specific classification.' `
                -Limitations 'The available event fields do not justify attributing the failure to a particular endpoint or policy.'))
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
        $inspectTrialId = ConvertTo-MihariDiagnosisSafeText -Value (Get-MihariEventValue -Event $inspect.Event -Data $inspect.Data -Names @('trialId'))
        $inspectCaseId = ConvertTo-MihariDiagnosisSafeText -Value (Get-MihariEventValue -Event $inspect.Event -Data $inspect.Data -Names @('caseId'))
        $inspectProtocolProfile = ConvertTo-MihariDiagnosisSafeText -Value (Get-MihariEventValue -Event $inspect.Event -Data $inspect.Data -Names @('protocolProfile'))
        $inspectAuthState = ConvertTo-MihariDiagnosisSafeText -Value (Get-MihariEventValue -Event $inspect.Event -Data $inspect.Data -Names @('proxyAuthState', 'authenticationState', 'authState'))
        $inspectCacheState = ConvertTo-MihariDiagnosisSafeText -Value (Get-MihariEventValue -Event $inspect.Event -Data $inspect.Data -Names @('cacheState', 'cacheCondition'))
        $inspectNetwork = ConvertTo-MihariDiagnosisSafeText -Value (Get-MihariEventValue -Event $inspect.Event -Data $inspect.Data -Names @('networkFingerprint', 'environmentFingerprint'))
        if ($null -eq $inspectTrialId -or $null -eq $inspectCaseId -or $null -eq $inspectProtocolProfile -or $null -eq $inspectAuthState -or $null -eq $inspectCacheState -or $null -eq $inspectNetwork) { continue }
        $inspectAuthority = $inspect.Host.ToLowerInvariant() + ':' + $inspect.Port
        foreach ($tunnel in $tunnelSuccesses) {
            if ($null -eq $tunnel.Host -or $null -eq $tunnel.Port) { continue }
            if (($tunnel.Host.ToLowerInvariant() + ':' + $tunnel.Port) -ne $inspectAuthority) { continue }
            $tunnelTrialId = ConvertTo-MihariDiagnosisSafeText -Value (Get-MihariEventValue -Event $tunnel.Event -Data $tunnel.Data -Names @('trialId'))
            $tunnelCaseId = ConvertTo-MihariDiagnosisSafeText -Value (Get-MihariEventValue -Event $tunnel.Event -Data $tunnel.Data -Names @('caseId'))
            $tunnelProtocolProfile = ConvertTo-MihariDiagnosisSafeText -Value (Get-MihariEventValue -Event $tunnel.Event -Data $tunnel.Data -Names @('protocolProfile'))
            $tunnelAuthState = ConvertTo-MihariDiagnosisSafeText -Value (Get-MihariEventValue -Event $tunnel.Event -Data $tunnel.Data -Names @('proxyAuthState', 'authenticationState', 'authState'))
            $tunnelCacheState = ConvertTo-MihariDiagnosisSafeText -Value (Get-MihariEventValue -Event $tunnel.Event -Data $tunnel.Data -Names @('cacheState', 'cacheCondition'))
            $tunnelNetwork = ConvertTo-MihariDiagnosisSafeText -Value (Get-MihariEventValue -Event $tunnel.Event -Data $tunnel.Data -Names @('networkFingerprint', 'environmentFingerprint'))
            if ($null -eq $tunnelTrialId -or $null -eq $tunnelCaseId -or $inspectTrialId -eq $tunnelTrialId -or $inspectCaseId -ne $tunnelCaseId -or
                $inspectProtocolProfile -ne $tunnelProtocolProfile -or $inspectAuthState -ne $tunnelAuthState -or
                $inspectCacheState -ne $tunnelCacheState -or $inspectNetwork -ne $tunnelNetwork) { continue }

            $findings.Add((New-MihariFinding -Code 'tls_interception_incompatible' `
                -Summary ('Inspect client TLS failed while the matching Tunnel relay completed for ' + $inspect.Host + ':' + $inspect.Port + '.') `
                -Scope 'host' -Records @($inspect, $tunnel) `
                -Interpretation 'The trials recorded the same protocol profile, authentication state, cache state, and network fingerprint. The client TLS handshake failed during Inspect while the opaque Tunnel relay completed.' `
                -Limitations 'Tunnel relay activity does not prove application success. This supports an interception-incompatible behavior at the observed TLS stage; it does not distinguish certificate pinning, mTLS, or another cause.'))
            break
        }
    }

    return @($findings.ToArray())
}

function Get-MihariStableFindingId {
    param([Parameter(Mandatory = $true)][object] $Identity)

    $serialized = ConvertTo-Json -InputObject $Identity -Depth 8 -Compress
    $encoding = [System.Text.UTF8Encoding]::new($false)
    $algorithm = [System.Security.Cryptography.SHA256]::Create()
    try {
        $digest = $algorithm.ComputeHash($encoding.GetBytes($serialized))
        $hex = ([System.BitConverter]::ToString($digest) -replace '-', '').ToLowerInvariant()
        return 'finding-' + $hex.Substring(0, 32)
    }
    finally { $algorithm.Dispose() }
}

function Get-MihariFindingIdentityParts {
    param([Parameter(Mandatory = $true)][object] $Finding)

    $facts = @($Finding.observedFacts)
    $fact = $null
    if ($facts.Count -gt 0) { $fact = $facts[0] }
    $evidenceRefs = @()
    if ($null -ne $Finding.PSObject.Properties['evidenceRefs']) { $evidenceRefs = @($Finding.evidenceRefs) }
    $sessionId = $null
    $trialId = $null
    $caseId = $null
    if ($evidenceRefs.Count -gt 0) { $sessionId = ConvertTo-MihariDiagnosisSafeText -Value (Get-MihariMemberValue -InputObject $evidenceRefs[0] -Names @('sessionId')) }
    if ($null -eq $sessionId -and $null -ne $fact) { $sessionId = ConvertTo-MihariDiagnosisSafeText -Value (Get-MihariMemberValue -InputObject $fact -Names @('sessionId')) }
    if ($null -ne $fact) {
        $trialId = ConvertTo-MihariDiagnosisSafeText -Value (Get-MihariMemberValue -InputObject $fact -Names @('trialId'))
        $caseId = ConvertTo-MihariDiagnosisSafeText -Value (Get-MihariMemberValue -InputObject $fact -Names @('caseId'))
    }
    $hostName = $null
    $port = $null
    $stage = $null
    $routeKind = $null
    $path = $null
    $method = $null
    $source = $null
    $transportLeg = $null
    $protocolProfile = $null
    $statusCode = $null
    if ($null -ne $fact) {
        $hostName = ConvertTo-MihariDiagnosisSafeText -Value (Get-MihariMemberValue -InputObject $fact -Names @('host'))
        $port = ConvertTo-MihariDiagnosisSafeText -Value (Get-MihariMemberValue -InputObject $fact -Names @('port'))
        $stage = ConvertTo-MihariDiagnosisSafeText -Value (Get-MihariMemberValue -InputObject $fact -Names @('stage'))
        $routeKind = ConvertTo-MihariDiagnosisSafeText -Value (Get-MihariMemberValue -InputObject $fact -Names @('routeKind'))
        $path = ConvertTo-MihariPath -Value (Get-MihariMemberValue -InputObject $fact -Names @('path'))
        $method = ConvertTo-MihariDiagnosisSafeText -Value (Get-MihariMemberValue -InputObject $fact -Names @('method'))
        $source = ConvertTo-MihariDiagnosisSafeText -Value (Get-MihariMemberValue -InputObject $fact -Names @('source'))
        $transportLeg = ConvertTo-MihariDiagnosisSafeText -Value (Get-MihariMemberValue -InputObject $fact -Names @('transportLeg'))
        $protocolProfile = ConvertTo-MihariDiagnosisSafeText -Value (Get-MihariMemberValue -InputObject $fact -Names @('protocolProfile'))
        $statusCode = Get-MihariMemberValue -InputObject $fact -Names @('statusCode', 'proxyStatus')
    }
    if ($null -ne $hostName) { $hostName = $hostName.ToLowerInvariant() }
    if ($null -ne $method) { $method = $method.ToUpperInvariant() }
    if ($null -ne $routeKind) { $routeKind = $routeKind.ToLowerInvariant() }
    $scope = ConvertTo-MihariDiagnosisSafeText -Value $Finding.scope
    $code = ConvertTo-MihariDiagnosisSafeText -Value $Finding.code
    if ($null -eq $scope) { $scope = 'session' }
    if ($null -eq $code) { $code = 'unclassified_failure' }
    if ($code -eq 'tls_interception_incompatible' -and $facts.Count -gt 1) {
        $sessionIds = @($evidenceRefs | ForEach-Object { ConvertTo-MihariDiagnosisSafeText -Value (Get-MihariMemberValue -InputObject $_ -Names @('sessionId')) } | Where-Object { $null -ne $_ } | Sort-Object -Unique)
        if ($sessionIds.Count -gt 0) { $sessionId = [string]::Join('+', $sessionIds) }
        $trialIds = @($facts | ForEach-Object { ConvertTo-MihariDiagnosisSafeText -Value (Get-MihariMemberValue -InputObject $_ -Names @('trialId')) } | Where-Object { $null -ne $_ } | Sort-Object -Unique)
        if ($trialIds.Count -gt 0) { $trialId = [string]::Join('+', $trialIds) }
        $caseIds = @($facts | ForEach-Object { ConvertTo-MihariDiagnosisSafeText -Value (Get-MihariMemberValue -InputObject $_ -Names @('caseId')) } | Where-Object { $null -ne $_ } | Sort-Object -Unique)
        if ($caseIds.Count -gt 0) { $caseId = [string]::Join('+', $caseIds) }
        $stage = 'inspect.client-tls+tunnel.transport'
        $routes = @($facts | ForEach-Object { ConvertTo-MihariDiagnosisSafeText -Value (Get-MihariMemberValue -InputObject $_ -Names @('routeKind')) } | Where-Object { $null -ne $_ } | Sort-Object -Unique)
        if ($routes.Count -gt 0) { $routeKind = [string]::Join('+', $routes) }
    }

    $identity = [ordered]@{
        ruleVersion = 'mihari-diagnosis/1'
        sessionId = $sessionId
        trialId = $trialId
        caseId = $caseId
        code = $code
        scope = $scope
        host = $hostName
        port = $port
        stage = $stage
        routeKind = $routeKind
        transportLeg = $transportLeg
        source = $source
    }
    if ($scope -eq 'request' -or $code -eq 'http_error_response') {
        $identity['path'] = $path
        $identity['method'] = $method
    }
    if ($code -eq 'http_error_response') { $identity['statusCode'] = $statusCode }
    if ($code -eq 'unsupported_protocol' -or $code -eq 'tls_interception_incompatible') { $identity['protocolProfile'] = $protocolProfile }

    return [pscustomobject][ordered]@{
        Identity = [pscustomobject]$identity
        SessionId = $sessionId
        TrialId = $trialId
        CaseId = $caseId
        Host = $hostName
        Port = $port
        Stage = $stage
        RouteKind = $routeKind
    }
}

function Get-MihariFindingReferenceKey {
    param([Parameter(Mandatory = $true)][object] $Reference)
    $sessionId = ConvertTo-MihariDiagnosisSafeText -Value (Get-MihariMemberValue -InputObject $Reference -Names @('sessionId'))
    $eventId = ConvertTo-MihariDiagnosisSafeText -Value (Get-MihariMemberValue -InputObject $Reference -Names @('eventId'))
    if ($null -eq $sessionId) { $sessionId = '?' }
    if ($null -eq $eventId) { $eventId = '?' }
    return $sessionId + ':' + $eventId
}

function Get-MihariFindingObservedAt {
    param([Parameter(Mandatory = $true)][object] $Finding)
    $times = New-Object 'System.Collections.Generic.List[object]'
    foreach ($fact in @($Finding.observedFacts)) {
        $timestamp = ConvertTo-MihariDiagnosisSafeText -Value (Get-MihariMemberValue -InputObject $fact -Names @('timestamp'))
        if ($null -eq $timestamp) { continue }
        $parsed = [DateTimeOffset]::MinValue
        if ([DateTimeOffset]::TryParse($timestamp, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$parsed)) {
            $times.Add([pscustomobject]@{ Timestamp = $timestamp; UtcTicks = $parsed.UtcDateTime.Ticks })
        }
    }
    if ($times.Count -eq 0) { return [pscustomobject]@{ First = $null; Last = $null } }
    $orderedTimes = @($times.ToArray() | Sort-Object -Property UtcTicks)
    return [pscustomobject]@{ First = [string]$orderedTimes[0].Timestamp; Last = [string]$orderedTimes[$orderedTimes.Count - 1].Timestamp }
}

function Compare-MihariDiagnosisTimestamp {
    param(
        [Parameter(Mandatory = $true)][string] $Left,
        [Parameter(Mandatory = $true)][string] $Right
    )
    $leftDate = [DateTimeOffset]::MinValue
    $rightDate = [DateTimeOffset]::MinValue
    $leftValid = [DateTimeOffset]::TryParse($Left, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$leftDate)
    $rightValid = [DateTimeOffset]::TryParse($Right, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$rightDate)
    if ($leftValid -and $rightValid) { return $leftDate.UtcDateTime.Ticks.CompareTo($rightDate.UtcDateTime.Ticks) }
    return [string]::CompareOrdinal($Left, $Right)
}

function Merge-MihariFindingGroups {
    param(
        [Parameter(Mandatory = $false)][AllowEmptyCollection()][object[]] $Findings = @(),
        [Parameter(Mandatory = $false)][AllowEmptyCollection()][object[]] $PreviousFindings = @()
    )

    $groups = New-Object 'System.Collections.Generic.List[object]'
    $groupIndex = @{}
    foreach ($finding in $Findings) {
        if ($null -eq $finding) { continue }
        $parts = Get-MihariFindingIdentityParts -Finding $finding
        $findingId = Get-MihariStableFindingId -Identity $parts.Identity
        if (-not $groupIndex.ContainsKey($findingId)) {
            $group = [pscustomobject][ordered]@{
                findingId = $findingId
                code = $finding.code
                summary = $finding.summary
                scope = $finding.scope
                sessionId = $parts.SessionId
                trialId = $parts.TrialId
                caseId = $parts.CaseId
                ruleVersion = 'mihari-diagnosis/1'
                evidenceRefs = @()
                evidenceIds = @()
                observedFacts = @()
                occurrenceCount = 0
                count = 0
                firstObserved = $null
                lastObserved = $null
                classification = $finding.classification
                evidenceStrength = $finding.evidenceStrength
                interpretation = $finding.interpretation
                limitations = $finding.limitations
                nextCheck = $finding.nextCheck
                resolutionState = 'open'
                resolvedAt = $null
                resolutionEvidence = @()
            }
            $groups.Add($group)
            $groupIndex[$findingId] = $group
        }
        $group = $groupIndex[$findingId]
        $references = New-Object 'System.Collections.Generic.List[object]'
        $facts = New-Object 'System.Collections.Generic.List[object]'
        $referenceKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
        foreach ($reference in @($group.evidenceRefs)) {
            if ($referenceKeys.Add((Get-MihariFindingReferenceKey -Reference $reference))) { $references.Add($reference) }
        }
        foreach ($reference in @($finding.evidenceRefs)) {
            if ($referenceKeys.Add((Get-MihariFindingReferenceKey -Reference $reference))) { $references.Add($reference) }
        }
        $group.evidenceRefs = @($references.ToArray())
        $group.evidenceIds = @($group.evidenceRefs | ForEach-Object { [string]$_.eventId } | Select-Object -Unique)
        $existingFactKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
        foreach ($fact in @($group.observedFacts)) {
            $existingFactKeys.Add((Get-MihariFindingReferenceKey -Reference $fact)) | Out-Null
            $facts.Add($fact)
        }
        foreach ($fact in @($finding.observedFacts)) {
            if ($existingFactKeys.Add((Get-MihariFindingReferenceKey -Reference $fact))) { $facts.Add($fact) }
        }
        $group.observedFacts = @($facts.ToArray())
        $group.occurrenceCount = $group.evidenceRefs.Count
        $group.count = $group.occurrenceCount
        $times = Get-MihariFindingObservedAt -Finding $group
        $findingTimes = Get-MihariFindingObservedAt -Finding $finding
        if ($null -eq $times.First -or ($null -ne $findingTimes.First -and (Compare-MihariDiagnosisTimestamp -Left $findingTimes.First -Right $times.First) -lt 0)) { $group.firstObserved = $findingTimes.First }
        else { $group.firstObserved = $times.First }
        if ($null -eq $times.Last -or ($null -ne $findingTimes.Last -and (Compare-MihariDiagnosisTimestamp -Left $findingTimes.Last -Right $times.Last) -gt 0)) { $group.lastObserved = $findingTimes.Last }
        else { $group.lastObserved = $times.Last }
    }

    foreach ($previous in $PreviousFindings) {
        if ($null -eq $previous -or [string]::IsNullOrWhiteSpace([string]$previous.findingId)) { continue }
        $findingId = [string]$previous.findingId
        if (-not $groupIndex.ContainsKey($findingId)) {
            $groups.Add($previous)
            $groupIndex[$findingId] = $previous
            continue
        }

        $group = $groupIndex[$findingId]
        $references = New-Object 'System.Collections.Generic.List[object]'
        $referenceKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
        foreach ($reference in @($previous.evidenceRefs)) {
            if ($referenceKeys.Add((Get-MihariFindingReferenceKey -Reference $reference))) { $references.Add($reference) }
        }
        foreach ($reference in @($group.evidenceRefs)) {
            if ($referenceKeys.Add((Get-MihariFindingReferenceKey -Reference $reference))) { $references.Add($reference) }
        }
        $group.evidenceRefs = @($references.ToArray())
        $group.evidenceIds = @($group.evidenceRefs | ForEach-Object { [string]$_.eventId } | Select-Object -Unique)
        $facts = New-Object 'System.Collections.Generic.List[object]'
        $factKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
        foreach ($fact in @($previous.observedFacts)) {
            if ($factKeys.Add((Get-MihariFindingReferenceKey -Reference $fact))) { $facts.Add($fact) }
        }
        foreach ($fact in @($group.observedFacts)) {
            if ($factKeys.Add((Get-MihariFindingReferenceKey -Reference $fact))) { $facts.Add($fact) }
        }
        $group.observedFacts = @($facts.ToArray())
        $group.occurrenceCount = $group.evidenceRefs.Count
        $group.count = $group.occurrenceCount
        $oldFirst = ConvertTo-MihariDiagnosisSafeText -Value $previous.firstObserved
        $oldLast = ConvertTo-MihariDiagnosisSafeText -Value $previous.lastObserved
        if ($null -eq $group.firstObserved -or ($null -ne $oldFirst -and (Compare-MihariDiagnosisTimestamp -Left $oldFirst -Right ([string]$group.firstObserved)) -lt 0)) { $group.firstObserved = $oldFirst }
        if ($null -eq $group.lastObserved -or ($null -ne $oldLast -and (Compare-MihariDiagnosisTimestamp -Left $oldLast -Right ([string]$group.lastObserved)) -gt 0)) { $group.lastObserved = $oldLast }
        $previousState = ConvertTo-MihariDiagnosisSafeText -Value $previous.resolutionState
        if ($previousState -eq 'resolved') {
            $resolvedAt = ConvertTo-MihariDiagnosisSafeText -Value $previous.resolvedAt
            $newEvidenceAfterResolution = $false
            $previousReferenceKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
            foreach ($reference in @($previous.evidenceRefs)) {
                $previousReferenceKeys.Add((Get-MihariFindingReferenceKey -Reference $reference)) | Out-Null
            }
            foreach ($fact in @($group.observedFacts)) {
                $factReferenceKey = Get-MihariFindingReferenceKey -Reference $fact
                if ($previousReferenceKeys.Contains($factReferenceKey)) { continue }
                $factTime = ConvertTo-MihariDiagnosisSafeText -Value $fact.timestamp
                if ($null -eq $resolvedAt -or $null -eq $factTime -or (Compare-MihariDiagnosisTimestamp -Left $factTime -Right $resolvedAt) -gt 0) { $newEvidenceAfterResolution = $true; break }
            }
            if ($newEvidenceAfterResolution) { $group.resolutionState = 'reopened' }
            else {
                $group.resolutionState = 'resolved'
                $group.resolvedAt = $previous.resolvedAt
                $group.resolutionEvidence = @($previous.resolutionEvidence)
            }
        }
        elseif ($null -ne $previousState -and $previousState -ne 'open') {
            $group.resolutionState = $previousState
        }
    }

    return @($groups.ToArray())
}

function Get-MihariDiagnosis {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)][AllowEmptyCollection()][object[]] $Events = @(),
        [Parameter(Mandatory = $false)][AllowEmptyCollection()][object[]] $PreviousFindings = @()
    )
    $instances = @(Get-MihariDiagnosisInstances -Events $Events)
    return @(Merge-MihariFindingGroups -Findings $instances -PreviousFindings $PreviousFindings)
}

function Get-MihariSessionFindings {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)][AllowEmptyCollection()][object[]] $Events = @(),
        [Parameter(Mandatory = $false)][AllowEmptyCollection()][object[]] $PreviousFindings = @()
    )
    return @(Get-MihariDiagnosis -Events $Events -PreviousFindings $PreviousFindings)
}

function Update-MihariFindingSnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)][AllowEmptyCollection()][object[]] $Events = @(),
        [Parameter(Mandatory = $false)][AllowNull()][object] $PreviousSnapshot,
        [Parameter(Mandatory = $true)][string] $SessionId,
        [Parameter(Mandatory = $false)][AllowNull()][string] $FileGeneration,
        [Parameter(Mandatory = $false)][long] $FirstSequence = 0,
        [Parameter(Mandatory = $false)][long] $LastSequence = 0,
        [Parameter(Mandatory = $false)][ValidateSet('observed', 'unknown', 'unsupported', 'permission_denied', 'truncated', 'lost')][string] $Coverage = 'unknown',
        [Parameter(Mandatory = $false)][ValidateRange(0, 1000000)][int] $MalformedLineCount = 0,
        [Parameter(Mandatory = $false)][AllowNull()][string] $ReadError,
        [Parameter(Mandatory = $false)][switch] $RebuiltFromCanonicalHistory
    )

    $safeSessionId = ConvertTo-MihariDiagnosisSafeText -Value $SessionId
    if ($null -eq $safeSessionId) { throw 'A session ID is required for a persistent finding snapshot.' }
    $previousSessionId = $null
    $previousGeneration = $null
    $previousLastSequence = 0L
    $previousCoverage = 'unknown'
    $previousHistoryGap = $false
    $previousFindings = @()
    $previousSnapshotIgnored = $false
    if ($null -ne $PreviousSnapshot) {
        $previousSessionId = ConvertTo-MihariDiagnosisSafeText -Value (Get-MihariMemberValue -InputObject $PreviousSnapshot -Names @('sessionId'))
        if ([string]::Equals($previousSessionId, $safeSessionId, [System.StringComparison]::Ordinal)) {
            $previousGeneration = ConvertTo-MihariDiagnosisSafeText -Value (Get-MihariMemberValue -InputObject $PreviousSnapshot -Names @('fileGeneration', 'generation'))
            $previousLastSequenceValue = Get-MihariMemberValue -InputObject $PreviousSnapshot -Names @('lastSequence')
            if ($null -ne $previousLastSequenceValue) { [long]::TryParse([string]$previousLastSequenceValue, [ref]$previousLastSequence) | Out-Null }
            $previousCoverageValue = ConvertTo-MihariDiagnosisSafeText -Value (Get-MihariMemberValue -InputObject $PreviousSnapshot -Names @('coverage'))
            if ($null -ne $previousCoverageValue) { $previousCoverage = $previousCoverageValue }
            $previousHistoryGap = ([string](Get-MihariMemberValue -InputObject $PreviousSnapshot -Names @('historyGap'))).ToLowerInvariant() -eq 'true'
            $previousFindings = @(Get-MihariMemberValue -InputObject $PreviousSnapshot -Names @('findings'))
        }
        else { $previousSnapshotIgnored = $true }
    }

    $eventSequences = New-Object 'System.Collections.Generic.List[long]'
    foreach ($event in $Events) {
        if ($null -eq $event) { continue }
        $eventSessionId = ConvertTo-MihariDiagnosisSafeText -Value (Get-MihariEventValue -Event $event -Data (Get-MihariEventData -Event $event) -Names @('sessionId'))
        if ($null -ne $eventSessionId -and -not [string]::Equals($eventSessionId, $safeSessionId, [System.StringComparison]::Ordinal)) {
            throw 'Finding snapshot events must belong to the requested session.'
        }
        $sequenceValue = Get-MihariEventValue -Event $event -Data (Get-MihariEventData -Event $event) -Names @('sequence')
        $sequence = 0L
        if ($null -ne $sequenceValue -and [long]::TryParse([string]$sequenceValue, [ref]$sequence) -and $sequence -gt 0) { $eventSequences.Add($sequence) }
    }
    if ($FirstSequence -le 0 -and $eventSequences.Count -gt 0) { $FirstSequence = [long](($eventSequences.ToArray() | Measure-Object -Minimum).Minimum) }
    if ($LastSequence -le 0 -and $eventSequences.Count -gt 0) { $LastSequence = [long](($eventSequences.ToArray() | Measure-Object -Maximum).Maximum) }

    $currentGeneration = ConvertTo-MihariDiagnosisSafeText -Value $FileGeneration
    $rotationDetected = ($null -ne $previousGeneration -and $null -ne $currentGeneration -and
        -not [string]::Equals($previousGeneration, $currentGeneration, [System.StringComparison]::Ordinal))
    $sequenceGap = $false
    if ($previousLastSequence -gt 0 -and -not $RebuiltFromCanonicalHistory) {
        if ($FirstSequence -gt 0 -and $FirstSequence -gt ($previousLastSequence + 1)) { $sequenceGap = $true }
        elseif ($FirstSequence -eq 0 -and $LastSequence -gt ($previousLastSequence + 1)) { $sequenceGap = $true }
    }
    $historyGap = $rotationDetected -or $sequenceGap -or $MalformedLineCount -gt 0 -or -not [string]::IsNullOrWhiteSpace($ReadError)
    if ($previousHistoryGap -and -not $RebuiltFromCanonicalHistory) { $historyGap = $true }
    if ($RebuiltFromCanonicalHistory -and $MalformedLineCount -eq 0 -and [string]::IsNullOrWhiteSpace($ReadError) -and -not $sequenceGap) { $historyGap = $false }

    $effectiveCoverage = $Coverage
    if ($historyGap) { $effectiveCoverage = 'truncated' }
    elseif ($effectiveCoverage -eq 'unknown' -and $Events.Count -gt 0) {
        $allObserved = $true
        foreach ($event in $Events) {
            $eventCoverage = ConvertTo-MihariDiagnosisSafeText -Value (Get-MihariEventValue -Event $event -Data (Get-MihariEventData -Event $event) -Names @('coverage'))
            if ($eventCoverage -ne 'observed') { $allObserved = $false; break }
        }
        if ($allObserved) { $effectiveCoverage = 'observed' }
    }
    elseif ($Events.Count -eq 0 -and $Coverage -eq 'unknown' -and $previousCoverage -ne 'unknown') {
        $effectiveCoverage = $previousCoverage
    }

    $findings = @(Get-MihariSessionFindings -Events $Events -PreviousFindings $previousFindings)
    if ($rotationDetected -or $sequenceGap -or $RebuiltFromCanonicalHistory) {
        $evidenceAvailable = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
        if ($RebuiltFromCanonicalHistory) {
            foreach ($event in $Events) {
                $eventId = ConvertTo-MihariDiagnosisSafeText -Value (Get-MihariEventValue -Event $event -Data (Get-MihariEventData -Event $event) -Names @('eventId', 'id'))
                if ($null -ne $eventId) { $evidenceAvailable.Add((Get-MihariFindingReferenceKey -Reference ([pscustomobject]@{ sessionId = $safeSessionId; eventId = $eventId }))) | Out-Null }
            }
        }
        $findingCopies = New-Object 'System.Collections.Generic.List[object]'
        foreach ($finding in $findings) {
            $copy = [ordered]@{}
            foreach ($property in $finding.PSObject.Properties) { $copy[$property.Name] = $property.Value }
            if ($RebuiltFromCanonicalHistory) {
                $allEvidenceAvailable = $true
                foreach ($reference in @($finding.evidenceRefs)) {
                    if (-not $evidenceAvailable.Contains((Get-MihariFindingReferenceKey -Reference $reference))) { $allEvidenceAvailable = $false; break }
                }
                if ($allEvidenceAvailable) { $copy['evidenceAvailability'] = 'verified_in_replay' }
                else { $copy['evidenceAvailability'] = 'unverified' }
            }
            elseif ($rotationDetected -or $sequenceGap) { $copy['evidenceAvailability'] = 'possibly_rotated' }
            $findingCopies.Add([pscustomobject]$copy)
        }
        $findings = @($findingCopies.ToArray())
    }
    $snapshotGeneration = $currentGeneration
    if ($null -eq $snapshotGeneration) { $snapshotGeneration = $previousGeneration }
    $snapshotLastSequence = $LastSequence
    if ($snapshotLastSequence -lt $previousLastSequence) { $snapshotLastSequence = $previousLastSequence }
    return [pscustomobject][ordered]@{
        schemaVersion = 1
        sessionId = $safeSessionId
        fileGeneration = $snapshotGeneration
        firstSequence = $FirstSequence
        lastSequence = $snapshotLastSequence
        historyGap = [bool]$historyGap
        rotationDetected = [bool]$rotationDetected
        sequenceGap = [bool]$sequenceGap
        previousSnapshotIgnored = [bool]$previousSnapshotIgnored
        coverage = $effectiveCoverage
        malformedLineCount = $MalformedLineCount
        readError = (ConvertTo-MihariDiagnosisSafeText -Value $ReadError)
        findings = @($findings)
    }
}

function Set-MihariFindingResolution {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][object] $Finding,
        [Parameter(Mandatory = $true)][object] $ResolutionEvidence
    )

    $positive = Get-MihariMemberValue -InputObject $ResolutionEvidence -Names @('positive')
    $kind = ConvertTo-MihariDiagnosisSafeText -Value (Get-MihariMemberValue -InputObject $ResolutionEvidence -Names @('kind'))
    $observedAt = ConvertTo-MihariDiagnosisSafeText -Value (Get-MihariMemberValue -InputObject $ResolutionEvidence -Names @('observedAt', 'timestamp'))
    $references = @(Get-MihariMemberValue -InputObject $ResolutionEvidence -Names @('evidenceRefs'))
    if ([string]$positive -ne 'True' -or $kind -notin @('successful_comparable_trial', 'operator_verified') -or
        $null -eq $observedAt -or $references.Count -eq 0) {
        throw 'Finding resolution requires positive, timestamped evidence references.'
    }

    $safeReferences = New-Object 'System.Collections.Generic.List[object]'
    foreach ($reference in $references) {
        $sessionId = ConvertTo-MihariDiagnosisSafeText -Value (Get-MihariMemberValue -InputObject $reference -Names @('sessionId'))
        $eventId = ConvertTo-MihariDiagnosisSafeText -Value (Get-MihariMemberValue -InputObject $reference -Names @('eventId'))
        if ($null -eq $sessionId -or $null -eq $eventId) { throw 'Finding resolution evidence references require sessionId and eventId.' }
        $safeReferences.Add([pscustomobject][ordered]@{ sessionId = $sessionId; eventId = $eventId })
    }

    $resolved = [ordered]@{}
    foreach ($property in $Finding.PSObject.Properties) { $resolved[$property.Name] = $property.Value }
    $resolved['resolutionState'] = 'resolved'
    $resolved['resolvedAt'] = $observedAt
    $resolved['resolutionEvidence'] = @([pscustomobject][ordered]@{
        kind = $kind
        observedAt = $observedAt
        evidenceRefs = @($safeReferences.ToArray())
    })
    return [pscustomobject]$resolved
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
        [Parameter(Mandatory = $true)] [AllowEmptyCollection()] [System.Collections.Generic.List[object]] $Events,
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
    param([Parameter(Mandatory = $false)] [AllowEmptyCollection()] [object[]] $Events = @())

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
