function New-MihariEventWriter {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path
    )

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $directory = [System.IO.Path]::GetDirectoryName($fullPath)
    if (-not [string]::IsNullOrEmpty($directory) -and -not [System.IO.Directory]::Exists($directory)) {
        [void][System.IO.Directory]::CreateDirectory($directory)
    }

    $fileStream = [System.IO.File]::Open(
        $fullPath,
        [System.IO.FileMode]::Append,
        [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::Read
    )
    $encoding = [System.Text.UTF8Encoding]::new($false)
    $streamWriter = [System.IO.StreamWriter]::new($fileStream, $encoding)
    $streamWriter.AutoFlush = $true

    # The same writer object is passed into each worker runspace. Monitor protects
    # the full serialization/write/flush operation so records cannot interleave.
    $writer = [pscustomobject]@{
        Path = $fullPath
        Stream = $streamWriter
        SyncRoot = (New-Object System.Object)
        Closed = $false
        Sequence = [long]0
    }
    return $writer
}

function Close-MihariEventWriter {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object] $Writer
    )

    [System.Threading.Monitor]::Enter($Writer.SyncRoot)
    try {
        if (-not $Writer.Closed) {
            $Writer.Stream.Flush()
            $Writer.Stream.Dispose()
            $Writer.Closed = $true
        }
    }
    finally {
        [System.Threading.Monitor]::Exit($Writer.SyncRoot)
    }
}

function Write-MihariEvent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object] $Session,

        [Parameter(Mandatory = $true)]
        [string] $ConnectionId,

        [AllowNull()]
        [string] $RequestId,

        [Parameter(Mandatory = $true)]
        [string] $Stage,

        [Parameter(Mandatory = $true)]
        [string] $Outcome,

        [Parameter(Mandatory = $true)]
        [double] $ElapsedMs,

        [AllowNull()]
        [object] $Data,

        [ValidateSet('Inspect', 'Tunnel')]
        [string] $Mode,

        [ValidateSet('proxy', 'browser', 'windows', 'operator', 'import')]
        [string] $Source = 'proxy',

        [ValidateSet('observed', 'unknown', 'unsupported', 'permission_denied', 'truncated', 'lost')]
        [string] $Coverage = 'observed',

        [AllowNull()][string] $CaseId,
        [AllowNull()][string] $TrialId,
        [AllowNull()][string] $TransportLeg,
        [AllowNull()][string] $UpstreamConnectionId,
        [AllowNull()][string] $StreamId,
        [AllowNull()][string] $SourceIdentity,
        [AllowNull()][string] $SourceVersion,
        [AllowNull()][string] $ClockId,
        [AllowNull()][long] $MonotonicTicks,
        [AllowNull()][int] $ConfigurationRevision
    )

    if (-not $PSBoundParameters.ContainsKey('Mode')) { $Mode = [string]$Session.Mode }
    $safeData = ConvertTo-MihariSafeEventData -Data $Data
    $elapsed = [long][Math]::Max(0, [Math]::Round($ElapsedMs, 0, [MidpointRounding]::AwayFromZero))
    $requestIdValue = $RequestId
    if ([string]::IsNullOrWhiteSpace($requestIdValue)) { $requestIdValue = $null }
    $event = [ordered]@{
        schemaVersion = 2
        timestamp = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ', [Globalization.CultureInfo]::InvariantCulture)
        eventId = [Guid]::NewGuid().ToString('N')
        sessionId = [string]$Session.Id
        connectionId = $ConnectionId
        requestId = $requestIdValue
        mode = $Mode
        stage = $Stage
        outcome = $Outcome
        elapsedMs = $elapsed
        sequence = [long]0
        source = $Source
        coverage = $Coverage
        data = $safeData
    }
    foreach ($name in @('CaseId', 'TrialId', 'TransportLeg', 'UpstreamConnectionId', 'StreamId', 'SourceIdentity', 'SourceVersion', 'ClockId')) {
        $value = Get-Variable -Name $name -ValueOnly
        if (-not [string]::IsNullOrWhiteSpace($value)) {
            $jsonName = $name.Substring(0, 1).ToLowerInvariant() + $name.Substring(1)
            $safeValue = ConvertTo-MihariSafeText -Text $value
            if ($safeValue.Length -gt 128) { $safeValue = $safeValue.Substring(0, 128) }
            $event[$jsonName] = $safeValue
        }
    }
    if ($PSBoundParameters.ContainsKey('ConfigurationRevision')) { $event['configurationRevision'] = $ConfigurationRevision }
    if ($PSBoundParameters.ContainsKey('MonotonicTicks')) { $event['monotonicTicks'] = $MonotonicTicks }
    $writer = $Session.Writer
    [System.Threading.Monitor]::Enter($writer.SyncRoot)
    try {
        if ($writer.Closed) {
            throw 'The Mihari event writer is closed.'
        }
        $writer.Sequence = [long]$writer.Sequence + 1
        $event['sequence'] = [long]$writer.Sequence
        $json = ConvertTo-Json -InputObject $event -Depth 8 -Compress -ErrorAction Stop
        $writer.Stream.WriteLine($json)
        $writer.Stream.Flush()
    }
    finally {
        [System.Threading.Monitor]::Exit($writer.SyncRoot)
    }

    return [pscustomobject]$event
}

function ConvertTo-MihariSafeEventData {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object] $Data
    )

    $stringFields = @(
        'host', 'scheme', 'path', 'method', 'routeKind', 'routeSource', 'proxyHost',
        'clientEndpoint', 'direction', 'tlsProtocol', 'tlsCipher', 'tlsCipherSuite', 'certificateSubject',
        'certificateIssuer', 'certificateThumbprint', 'certificateNotBefore',
        'certificateNotAfter', 'errorType', 'errorCode', 'message', 'reason',
        'unsupportedProtocol', 'mode', 'previousMode', 'tlsAlpn',
        'certificateChainState', 'hostnameState', 'validityState', 'ekuState',
        'revocationState', 'validationPolicy', 'peerIdentityRole',
        'clientCertificateState', 'protocol', 'initiatorType', 'browserTargetId',
        'browserRequestId', 'browserConnectionId', 'browserError',
        'browserTimingOrigin', 'requestFraming', 'responseFraming',
        'connectionPolicy', 'framing'
    )
    $integerFields = @(
        'port', 'statusCode', 'proxyStatus', 'proxyPort', 'bytesClientToUpstream',
        'bytesUpstreamToClient', 'tlsCipherStrength', 'browserRedirectIndex',
        'browserTimingStartMs', 'browserTimingDurationMs', 'requestBytes',
        'responseBytes', 'bytes', 'firstByteMs', 'lastByteMs',
        'forwardWriteMs', 'workerOccupancy', 'maxWorkers'
    )
    $booleanFields = @('certificateAccepted', 'caTrusted', 'fromDiskCache', 'fromServiceWorker', 'reused', 'queueSaturated')
    $allowed = @{}
    foreach ($name in $stringFields) { $allowed[$name] = 'string' }
    foreach ($name in $integerFields) { $allowed[$name] = 'integer' }
    foreach ($name in $booleanFields) { $allowed[$name] = 'boolean' }

    $properties = @{}
    $exception = $null
    if ($null -eq $Data) {
        # Keep the envelope's data value a JSON object even when there is no detail.
    }
    elseif ($Data -is [System.Exception]) {
        $exception = $Data
    }
    elseif ($Data -is [System.Management.Automation.ErrorRecord]) {
        $exception = $Data.Exception
    }
    elseif ($Data -is [System.Collections.IDictionary]) {
        foreach ($key in $Data.Keys) {
            $name = [string]$key
            if ([string]::Equals($name, 'exception', [StringComparison]::OrdinalIgnoreCase) -or
                [string]::Equals($name, 'exceptionRecord', [StringComparison]::OrdinalIgnoreCase)) {
                $candidate = $Data[$key]
                if ($candidate -is [System.Management.Automation.ErrorRecord]) { $candidate = $candidate.Exception }
                if ($candidate -is [System.Exception]) { $exception = $candidate }
                continue
            }
            if ($allowed.ContainsKey($name)) { $properties[$name] = $Data[$key] }
            if ($name -eq 'certificateChain') { $properties[$name] = $Data[$key] }
        }
    }
    else {
        foreach ($property in $Data.PSObject.Properties) {
            $name = [string]$property.Name
            if ([string]::Equals($name, 'exception', [StringComparison]::OrdinalIgnoreCase) -or
                [string]::Equals($name, 'exceptionRecord', [StringComparison]::OrdinalIgnoreCase)) {
                $candidate = $property.Value
                if ($candidate -is [System.Management.Automation.ErrorRecord]) { $candidate = $candidate.Exception }
                if ($candidate -is [System.Exception]) { $exception = $candidate }
                continue
            }
            if ($allowed.ContainsKey($name)) { $properties[$name] = $property.Value }
            if ($name -eq 'certificateChain') { $properties[$name] = $property.Value }
        }
    }

    $result = [ordered]@{}
    $propertyNames = @($properties.Keys | Sort-Object { [string]$_ })
    foreach ($name in $propertyNames) {
        $value = $properties[$name]
        if ($name -eq 'certificateChain') {
            $chain = New-Object 'System.Collections.Generic.List[object]'
            foreach ($element in @(@($value) | Select-Object -First 8)) {
                if ($null -eq $element) { continue }
                $safeElement = [ordered]@{}
                foreach ($field in @('subject', 'issuer', 'thumbprint', 'notBefore', 'notAfter')) {
                    $member = $null
                    if ($element -is [System.Collections.IDictionary]) {
                        foreach ($key in $element.Keys) { if ([string]$key -eq $field) { $member = $element[$key]; break } }
                    }
                    elseif ($null -ne $element.PSObject.Properties[$field]) { $member = $element.PSObject.Properties[$field].Value }
                    if ($null -ne $member) {
                        $safeText = ConvertTo-MihariSafeText -Text ([string]$member)
                        if ($safeText.Length -gt 256) { $safeText = $safeText.Substring(0, 256) }
                        $safeElement[$field] = $safeText
                    }
                }
                if ($safeElement.Count -gt 0) { $chain.Add([pscustomobject]$safeElement) }
            }
            $result[$name] = @($chain.ToArray())
            continue
        }
        $kind = $allowed[$name]
        if ($null -eq $value) { continue }
        if ($kind -eq 'string') {
            if ($value -is [string] -or $value -is [char] -or $value.GetType().IsEnum) {
                $text = ConvertTo-MihariSafeText -Text ([string]$value)
                if ($text.Length -gt 1024) { $text = $text.Substring(0, 1024) }
                $result[$name] = $text
            }
            elseif ($value -is [DateTime]) {
                $result[$name] = $value.ToUniversalTime().ToString('o', [Globalization.CultureInfo]::InvariantCulture)
            }
            elseif ($value -is [DateTimeOffset]) {
                $result[$name] = $value.ToUniversalTime().ToString('o', [Globalization.CultureInfo]::InvariantCulture)
            }
        }
        elseif ($kind -eq 'boolean') {
            if ($value -is [bool]) { $result[$name] = $value }
        }
        else {
            $typeCode = [Type]::GetTypeCode($value.GetType())
            if ($typeCode -in @([TypeCode]::Byte, [TypeCode]::SByte, [TypeCode]::Int16, [TypeCode]::UInt16,
                    [TypeCode]::Int32, [TypeCode]::UInt32, [TypeCode]::Int64, [TypeCode]::UInt64,
                    [TypeCode]::Single, [TypeCode]::Double, [TypeCode]::Decimal)) {
                $number = [double]$value
                if (-not [double]::IsNaN($number) -and -not [double]::IsInfinity($number)) {
                    $result[$name] = $value
                }
            }
        }
    }

    if ($null -ne $exception) {
        $normalized = ConvertTo-MihariExceptionData -Exception $exception
        if (-not $result.Contains('errorCode')) { $result['errorCode'] = $normalized.errorCode }
        if (-not $result.Contains('errorType')) { $result['errorType'] = $normalized.errorType }
        if (-not $result.Contains('message')) { $result['message'] = $normalized.message }
    }

    return $result
}

function ConvertTo-MihariExceptionData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Exception] $Exception
    )

    $current = $Exception
    while ($null -ne $current.InnerException) { $current = $current.InnerException }

    $errorCode = 'operation_failed'
    if ($current -is [System.Net.Sockets.SocketException]) {
        switch ([string]$current.SocketErrorCode) {
            'TimedOut' { $errorCode = 'connection_timeout' }
            'ConnectionRefused' { $errorCode = 'connection_refused' }
            'HostNotFound' { $errorCode = 'dns_resolution_failed' }
            'TryAgain' { $errorCode = 'dns_resolution_failed' }
            'NoData' { $errorCode = 'dns_resolution_failed' }
            'NetworkUnreachable' { $errorCode = 'network_unreachable' }
            'HostUnreachable' { $errorCode = 'host_unreachable' }
            'AccessDenied' { $errorCode = 'socket_access_denied' }
            default { $errorCode = 'socket_error' }
        }
    }
    elseif ($current -is [System.Security.Authentication.AuthenticationException]) {
        $errorCode = 'tls_handshake_failed'
    }
    elseif ($current -is [System.IO.EndOfStreamException]) {
        $errorCode = 'peer_closed_connection'
    }
    elseif ($current -is [System.OperationCanceledException]) {
        $errorCode = 'operation_cancelled'
    }
    elseif ($current -is [System.NotSupportedException]) {
        $errorCode = 'unsupported_protocol'
    }
    elseif ($current -is [System.TimeoutException]) {
        $errorCode = 'operation_timeout'
    }
    elseif ($current -is [System.IO.IOException]) {
        $errorCode = 'io_error'
    }

    $message = ConvertTo-MihariSafeText -Text ([string]$current.Message)
    if ($message.Length -gt 512) { $message = $message.Substring(0, 512) }
    return [pscustomobject]@{
        errorCode = $errorCode
        errorType = $current.GetType().FullName
        message = $message
    }
}

function ConvertTo-MihariSafeText {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [string] $Text
    )

    if ($null -eq $Text) { return '' }
    $safe = $Text
    # Redact credential-bearing headers and common serialized credential fields.
    $safe = [regex]::Replace($safe, '(?im)\b(authorization|proxy-authorization|cookie|set-cookie)\s*:\s*[^\r\n]*', '$1: [REDACTED]')
    $safe = [regex]::Replace($safe, '(?i)(authorization|proxy-authorization|cookie|set-cookie)\s*=\s*[^,\r\n]+', '$1=[REDACTED]')
    # Query values are never retained, including values embedded in exception text.
    $safe = [regex]::Replace($safe, '([?&][^=&#\s]+)=([^&#\s]*)', '$1=[REDACTED]')
    # Strip URL user-info if a platform exception happens to include an absolute URL.
    $safe = [regex]::Replace($safe, '(?i)(https?://)[^/\s?#@]+@', '$1[REDACTED]@')
    return $safe
}
