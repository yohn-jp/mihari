# Portable, bounded Mihari case evidence bundles. This file intentionally uses
# only PowerShell 5.1 and platform .NET APIs. Bundle hashes detect modification;
# they do not identify a trusted author or prove how the evidence was acquired.

[void][System.Reflection.Assembly]::Load('System.IO.Compression')

function Get-MihariEvidenceValue {
    param([AllowNull()][object]$InputObject, [Parameter(Mandatory = $true)][string]$Name)
    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [System.Collections.IDictionary]) {
        if ($InputObject.Contains($Name)) { return $InputObject[$Name] }
        return $null
    }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -ne $property) { return $property.Value }
    return $null
}

function New-MihariEvidenceShareContext {
    param([AllowNull()][object]$ShareProfile)
    $options = [ordered]@{
        maskHosts = $true
        maskUsernames = $true
        maskPaths = $true
        maskIdentifiers = $true
    }
    foreach ($name in @('maskHosts', 'maskUsernames', 'maskPaths', 'maskIdentifiers')) {
        $value = Get-MihariEvidenceValue -InputObject $ShareProfile -Name $name
        if ($value -is [bool]) { $options[$name] = $value }
    }
    $key = New-Object byte[] 32
    $random = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    try { $random.GetBytes($key) }
    finally { $random.Dispose() }
    return [pscustomobject]@{ Options = [pscustomobject]$options; Key = $key; Map = @{} }
}

function Get-MihariEvidencePseudonym {
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)][string]$Kind,
        [Parameter(Mandatory = $true)][object]$Context
    )
    $normalized = $Value
    if ($Kind -in @('host', 'username', 'identifier')) { $normalized = $Value.ToLowerInvariant() }
    $mapKey = $Kind + ':' + $normalized
    if ($Context.Map.ContainsKey($mapKey)) { return [string]$Context.Map[$mapKey] }
    $hmac = [System.Security.Cryptography.HMACSHA256]::new([byte[]]$Context.Key)
    try {
        $digest = $hmac.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($mapKey))
    }
    finally { $hmac.Dispose() }
    $hex = ([System.BitConverter]::ToString($digest)).Replace('-', '').ToLowerInvariant().Substring(0, 12)
    $token = $Kind + '-' + $hex
    $Context.Map[$mapKey] = $token
    return $token
}

function ConvertTo-MihariEvidenceQuerySafe {
    param([AllowNull()][string]$Text)
    if ($null -eq $Text) { return $null }
    $value = [regex]::Replace($Text, '\?([^#\s]*)', {
        param($match)
        if ([string]::IsNullOrEmpty($match.Groups[1].Value)) { return '?' }
        return '?[REDACTED]'
    })
    $value = [regex]::Replace($value, '(?i)(\b(?:authorization|proxy-authorization|cookie|set-cookie|password|passwd|secret|token|api[_-]?key)\s*[:=]\s*)([^,;\s]+)', '$1[REDACTED]')
    $value = [regex]::Replace($value, '(?i)\bBearer\s+[A-Za-z0-9._~+/-]+=*', 'Bearer [REDACTED]')
    $value = [regex]::Replace($value, '(?i)(https?://)[^/@\s]+:[^/@\s]+@', '$1[REDACTED]@')
    $value = [regex]::Replace($value, '(?i)\b[A-Z]:\\(?:[^\\\s]+\\)*[^\\\s,;)]*', '[PATH]')
    return $value
}

function ConvertTo-MihariEvidenceSharedUrl {
    param([AllowNull()][string]$Text, [Parameter(Mandatory = $true)][object]$Context)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    $safeText = ConvertTo-MihariEvidenceQuerySafe -Text $Text
    $uri = $null
    if (-not [Uri]::TryCreate($safeText, [UriKind]::Absolute, [ref]$uri) -or
        $uri.Scheme -notin @('http', 'https') -or [string]::IsNullOrWhiteSpace($uri.Host)) {
        return $safeText
    }
    $hostName = $uri.Host
    if ($Context.Options.maskHosts) {
        $hostName = Get-MihariEvidencePseudonym -Value $hostName -Kind 'host' -Context $Context
    }
    if ($Context.Options.maskPaths -and $uri.AbsolutePath -ne '/') {
        $path = '/' + (Get-MihariEvidencePseudonym -Value $uri.AbsolutePath -Kind 'path' -Context $Context)
    }
    else { $path = $uri.AbsolutePath }
    $portText = ''
    if (-not $uri.IsDefaultPort) { $portText = ':' + $uri.Port.ToString([Globalization.CultureInfo]::InvariantCulture) }
    $queryText = ''
    if (-not [string]::IsNullOrEmpty($uri.Query)) { $queryText = '?[REDACTED]' }
    return $uri.Scheme + '://' + $hostName + $portText + $path + $queryText
}

function ConvertTo-MihariEvidenceSharedText {
    param(
        [AllowNull()][object]$Value,
        [Parameter(Mandatory = $true)][object]$Context,
        [ValidateRange(1, 8192)][int]$MaximumLength = 1024
    )
    if ($null -eq $Value -or $Value -is [System.Collections.IDictionary] -or $Value -is [System.Array]) { return $null }
    if ($Value -isnot [string] -and $Value -isnot [char] -and -not $Value.GetType().IsPrimitive -and
        $Value -isnot [decimal] -and $Value -isnot [DateTime] -and $Value -isnot [DateTimeOffset]) { return $null }
    $text = ConvertTo-MihariEvidenceQuerySafe -Text ([string]$Value)
    $text = [regex]::Replace($text, '(?i)https?://[^\s<>"'']+', {
        param($match)
        return ConvertTo-MihariEvidenceSharedUrl -Text $match.Value -Context $Context
    })
    if ($text.Length -gt $MaximumLength) { $text = $text.Substring(0, $MaximumLength) }
    return $text
}

function ConvertTo-MihariEvidenceShareValue {
    param([string]$Name, [AllowNull()][object]$Value, [object]$Context, [int]$MaximumLength = 1024)
    if ($null -eq $Value) { return $null }
    $lower = $Name.ToLowerInvariant()
    if ($lower -match '(authorization|cookie|password|passwd|secret|token|credential|body|payload|debugger|controlsecret|privatekey|keymaterial|header)') {
        return $null
    }
    if ($Value -is [bool]) { return $Value }
    if ($Value -is [byte] -or $Value -is [int16] -or $Value -is [int32] -or $Value -is [int64] -or
        $Value -is [uint16] -or $Value -is [uint32] -or $Value -is [uint64] -or $Value -is [decimal] -or
        $Value -is [double] -or $Value -is [single]) {
        if ($lower -match '(port|status|count|bytes|sequence|elapsed|duration|ticks|size|limit|version|attempt|redirect|statuscode|status_code|status-code)$') { return $Value }
        return $null
    }
    if ($Value -is [string] -or $Value -is [char] -or $Value -is [DateTime] -or $Value -is [DateTimeOffset]) {
        $text = [string]$Value
        if ($lower -match '^(host|hostname|proxyhost|upstreamhost)$' -and $Context.Options.maskHosts) {
            return (Get-MihariEvidencePseudonym -Value $text -Kind 'host' -Context $Context)
        }
        if ($lower -match '^(path|requestpath|urlpath)$' -and $Context.Options.maskPaths) {
            if ($text -eq '/') { return '/' }
            return '/' + (Get-MihariEvidencePseudonym -Value $text -Kind 'path' -Context $Context)
        }
        if ($lower -match '^(username|user|useridentity)$' -and $Context.Options.maskUsernames) {
            return (Get-MihariEvidencePseudonym -Value $text -Kind 'user' -Context $Context)
        }
        if ($lower -match '(id|identity|revision)$' -and $Context.Options.maskIdentifiers) {
            return (Get-MihariEvidencePseudonym -Value $text -Kind 'identifier' -Context $Context)
        }
        if ($lower -eq 'url') { return (ConvertTo-MihariEvidenceSharedUrl -Text $text -Context $Context) }
        if ($lower -match '^(certificatesubject|certificateissuer)$' -and $Context.Options.maskHosts) {
            return (Get-MihariEvidencePseudonym -Value $text -Kind 'certificate' -Context $Context)
        }
        return ConvertTo-MihariEvidenceSharedText -Value $text -Context $Context -MaximumLength $MaximumLength
    }
    return $null
}

function ConvertTo-MihariEvidenceSafeData {
    param([AllowNull()][object]$Data, [Parameter(Mandatory = $true)][object]$Context)
    $allowed = @(
        'host', 'hostname', 'scheme', 'port', 'method', 'path', 'requestPath', 'urlPath', 'url',
        'statusCode', 'proxyStatus', 'routeKind', 'routeSource', 'proxyHost', 'proxyPort', 'clientEndpoint',
        'direction', 'tlsProtocol', 'tlsCipher', 'certificateSubject', 'certificateIssuer', 'certificateThumbprint',
        'certificateNotBefore', 'certificateNotAfter', 'certificateAccepted', 'chainStatus', 'validationState',
        'errorType', 'errorCode', 'reason', 'errorMessage', 'message', 'unsupportedProtocol', 'mode', 'previousMode',
        'bytesClientToUpstream', 'bytesUpstreamToClient', 'bytesSent', 'bytesReceived', 'firstByteUtc', 'lastByteUtc',
        'requestCount', 'responseCount', 'streamId', 'protocol', 'alpn', 'connectionReuse', 'cacheState', 'source',
        'coverage', 'observed', 'supported', 'available', 'requested', 'effective', 'tlsValidation', 'proxyResponse',
        'targetHost', 'targetPort', 'upstreamConnectionId', 'localEndpoint', 'remoteEndpoint', 'elapsedMs', 'timeoutMs',
        'timeout', 'cancelled', 'truncated', 'droppedCount', 'queueLength', 'workerOccupancy', 'forwardingDelayMs',
        'writerLagMs', 'memoryBytes', 'cpuPercent', 'retainedBytes', 'firstFailureDirection', 'failureStage', 'result'
    )
    $result = [ordered]@{}
    foreach ($name in $allowed) {
        $raw = Get-MihariEvidenceValue -InputObject $Data -Name $name
        if ($null -eq $raw) { continue }
        $safe = ConvertTo-MihariEvidenceShareValue -Name $name -Value $raw -Context $Context -MaximumLength 1024
        if ($null -ne $safe) { $result[$name] = $safe }
    }
    return [pscustomobject]$result
}

function ConvertTo-MihariEvidenceSafeEvent {
    param([Parameter(Mandatory = $true)][object]$Event, [Parameter(Mandatory = $true)][object]$Context)
    $schemaValue = Get-MihariEvidenceValue -InputObject $Event -Name 'schemaVersion'
    $schemaVersion = 0
    if (-not [int]::TryParse([string]$schemaValue, [ref]$schemaVersion) -or $schemaVersion -notin @(1, 2)) {
        return [pscustomobject]@{ Recognized = $false; Reason = 'unknown_schema'; Record = $null }
    }
    foreach ($requiredName in @('timestamp', 'eventId', 'sessionId', 'connectionId', 'mode', 'stage', 'outcome')) {
        $requiredValue = Get-MihariEvidenceValue -InputObject $Event -Name $requiredName
        if ($null -eq $requiredValue -or [string]::IsNullOrWhiteSpace([string]$requiredValue)) {
            return [pscustomobject]@{ Recognized = $false; Reason = 'missing_required_field'; Record = $null }
        }
    }
    $source = Get-MihariEvidenceValue -InputObject $Event -Name 'source'
    if ($null -ne $source -and [string]$source -notin @('proxy', 'browser', 'windows', 'operator', 'import')) {
        return [pscustomobject]@{ Recognized = $false; Reason = 'unknown_source'; Record = $null }
    }
    if ($schemaVersion -eq 2) {
        if ($null -eq $source) { return [pscustomobject]@{ Recognized = $false; Reason = 'missing_v2_field'; Record = $null } }
        $sequenceValue = Get-MihariEvidenceValue -InputObject $Event -Name 'sequence'
        $sequenceNumber = [long]0
        if (-not [long]::TryParse([string]$sequenceValue, [ref]$sequenceNumber) -or $sequenceNumber -le 0) {
            return [pscustomobject]@{ Recognized = $false; Reason = 'invalid_sequence'; Record = $null }
        }
        $coverageValue = Get-MihariEvidenceValue -InputObject $Event -Name 'coverage'
        if ($null -eq $coverageValue) { return [pscustomobject]@{ Recognized = $false; Reason = 'missing_v2_field'; Record = $null } }
        if ([string]$coverageValue -notin @('observed', 'unknown', 'unsupported', 'permission_denied', 'truncated', 'lost')) {
            return [pscustomobject]@{ Recognized = $false; Reason = 'unknown_coverage'; Record = $null }
        }
    }
    $record = [ordered]@{ schemaVersion = $schemaVersion }
    foreach ($name in @('timestamp', 'eventId', 'sessionId', 'connectionId', 'requestId', 'mode', 'stage', 'outcome')) {
        $raw = Get-MihariEvidenceValue -InputObject $Event -Name $name
        if ($null -eq $raw) { continue }
        $safe = ConvertTo-MihariEvidenceShareValue -Name $name -Value $raw -Context $Context -MaximumLength 256
        if ($null -ne $safe) { $record[$name] = $safe }
    }
    $elapsed = Get-MihariEvidenceValue -InputObject $Event -Name 'elapsedMs'
    if ($null -ne $elapsed) {
        $number = [decimal]0
        if ([decimal]::TryParse([string]$elapsed, [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$number) -and $number -ge 0) {
            $record['elapsedMs'] = $number
        }
    }
    if ($schemaVersion -eq 2) {
        foreach ($name in @('sequence', 'monotonicTicks')) {
            $raw = Get-MihariEvidenceValue -InputObject $Event -Name $name
            if ($null -eq $raw) { continue }
            $number = [long]0
            if ([long]::TryParse([string]$raw, [ref]$number) -and $number -ge 0) { $record[$name] = $number }
        }
        foreach ($name in @('source', 'coverage', 'caseId', 'trialId', 'configurationRevision', 'transportLeg', 'upstreamConnectionId', 'streamId', 'sourceIdentity', 'sourceVersion', 'clockId')) {
            $raw = Get-MihariEvidenceValue -InputObject $Event -Name $name
            if ($null -eq $raw) { continue }
            if ($name -eq 'source' -and [string]$raw -notin @('proxy', 'browser', 'windows', 'operator', 'import')) { continue }
            if ($name -eq 'coverage' -and [string]$raw -notin @('observed', 'unknown', 'unsupported', 'permission_denied', 'truncated', 'lost')) { continue }
            if ($name -eq 'transportLeg' -and [string]$raw -notin @('client', 'upstream', 'end_to_end')) { continue }
            $safe = ConvertTo-MihariEvidenceShareValue -Name $name -Value $raw -Context $Context -MaximumLength 256
            if ($null -ne $safe) { $record[$name] = $safe }
        }
    }
    $data = Get-MihariEvidenceValue -InputObject $Event -Name 'data'
    if ($null -ne $data) { $record['data'] = ConvertTo-MihariEvidenceSafeData -Data $data -Context $Context }
    return [pscustomobject]@{ Recognized = $true; Reason = $null; Record = [pscustomobject]$record }
}

function ConvertTo-MihariEvidenceSafeAnnotation {
    param([Parameter(Mandatory = $true)][object]$Annotation, [Parameter(Mandatory = $true)][object]$Context)
    $result = [ordered]@{}
    foreach ($name in @('annotationId', 'markerId', 'caseId', 'trialId', 'sessionId', 'eventId', 'timestamp', 'kind', 'label', 'note', 'bookmark')) {
        $raw = Get-MihariEvidenceValue -InputObject $Annotation -Name $name
        if ($null -eq $raw) { continue }
        $limit = 1024
        if ($name -eq 'note') { $limit = 4096 }
        $safe = ConvertTo-MihariEvidenceShareValue -Name $name -Value $raw -Context $Context -MaximumLength $limit
        if ($null -ne $safe) { $result[$name] = $safe }
    }
    return [pscustomobject]$result
}

function ConvertTo-MihariEvidenceSafeCase {
    param([Parameter(Mandatory = $true)][object]$Case, [Parameter(Mandatory = $true)][object]$Context)
    $caseId = Get-MihariEvidenceValue -InputObject $Case -Name 'caseId'
    if ([string]::IsNullOrWhiteSpace([string]$caseId)) { $caseId = [Guid]::NewGuid().ToString('N') }
    $safeCaseId = ConvertTo-MihariEvidenceShareValue -Name 'caseId' -Value ([string]$caseId) -Context $Context -MaximumLength 256
    if ($null -eq $safeCaseId) { $safeCaseId = Get-MihariEvidencePseudonym -Value ([string]$caseId) -Kind 'identifier' -Context $Context }
    $result = [ordered]@{
        caseId = $safeCaseId
        title = ConvertTo-MihariEvidenceSharedText -Value (Get-MihariEvidenceValue -InputObject $Case -Name 'title') -Context $Context -MaximumLength 256
        notes = ConvertTo-MihariEvidenceSharedText -Value (Get-MihariEvidenceValue -InputObject $Case -Name 'notes') -Context $Context -MaximumLength 4096
        sessionRefs = @()
        trialRefs = @()
    }
    foreach ($name in @('sessionRefs', 'trialRefs')) {
        $values = Get-MihariEvidenceValue -InputObject $Case -Name $name
        $safeValues = New-Object 'System.Collections.Generic.List[string]'
        foreach ($value in @($values)) {
            if ($null -eq $value -or $safeValues.Count -ge 200) { continue }
            if ($Context.Options.maskIdentifiers) {
                $safeValues.Add((Get-MihariEvidencePseudonym -Value ([string]$value) -Kind 'identifier' -Context $Context))
            }
            else {
                $safeValues.Add((ConvertTo-MihariEvidenceSharedText -Value ([string]$value) -Context $Context -MaximumLength 256))
            }
        }
        $result[$name] = @($safeValues.ToArray())
    }
    return [pscustomobject]$result
}

function ConvertTo-MihariEvidenceSafeTrial {
    param([Parameter(Mandatory = $true)][object]$Trial, [Parameter(Mandatory = $true)][object]$Context)
    $allowed = @('trialId', 'caseId', 'sessionId', 'startedAtUtc', 'endedAtUtc', 'startMarkerId', 'endMarkerId', 'configurationRevision', 'profile', 'environmentRef', 'businessOutcome', 'operatorNotes')
    $result = [ordered]@{}
    foreach ($name in $allowed) {
        $raw = Get-MihariEvidenceValue -InputObject $Trial -Name $name
        if ($null -eq $raw) { continue }
        if ($name -eq 'profile' -and $raw -is [System.Collections.IDictionary] -or $name -eq 'profile' -and $null -ne $raw.PSObject) {
            $profile = [ordered]@{}
            foreach ($profileName in @('mode', 'protocol', 'tlsVersion', 'connectionReuse', 'cacheDisabled', 'requestedSwitches', 'observedSwitches', 'localExclusions', 'routeKind', 'profileName')) {
                $profileValue = Get-MihariEvidenceValue -InputObject $raw -Name $profileName
                if ($null -eq $profileValue) { continue }
                if ($profileValue -is [Array]) {
                    $items = New-Object 'System.Collections.Generic.List[object]'
                    foreach ($item in $profileValue) {
                        $safeItem = ConvertTo-MihariEvidenceShareValue -Name $profileName -Value $item -Context $Context -MaximumLength 256
                        if ($null -ne $safeItem) { $items.Add($safeItem) }
                    }
                    $profile[$profileName] = @($items.ToArray())
                }
                else {
                    $safeItem = ConvertTo-MihariEvidenceShareValue -Name $profileName -Value $profileValue -Context $Context -MaximumLength 256
                    if ($null -ne $safeItem) { $profile[$profileName] = $safeItem }
                }
            }
            $result[$name] = [pscustomobject]$profile
            continue
        }
        $safe = ConvertTo-MihariEvidenceShareValue -Name $name -Value $raw -Context $Context -MaximumLength 1024
        if ($null -ne $safe) { $result[$name] = $safe }
    }
    return [pscustomobject]$result
}

function ConvertTo-MihariEvidenceSafeFinding {
    param([Parameter(Mandatory = $true)][object]$Finding, [Parameter(Mandatory = $true)][object]$Context)
    $result = [ordered]@{}
    foreach ($name in @('findingId', 'ruleVersion', 'scope', 'classification', 'code', 'summary', 'interpretation', 'limitations', 'firstObserved', 'lastObserved', 'count', 'resolutionState')) {
        $raw = Get-MihariEvidenceValue -InputObject $Finding -Name $name
        if ($null -eq $raw) { continue }
        $safe = ConvertTo-MihariEvidenceShareValue -Name $name -Value $raw -Context $Context -MaximumLength 2048
        if ($null -ne $safe) { $result[$name] = $safe }
    }
    $refs = Get-MihariEvidenceValue -InputObject $Finding -Name 'evidenceRefs'
    if ($null -eq $refs) { $refs = Get-MihariEvidenceValue -InputObject $Finding -Name 'evidenceIds' }
    if ($null -ne $refs) {
        $safeRefs = New-Object 'System.Collections.Generic.List[object]'
        foreach ($reference in @($refs)) {
            if ($safeRefs.Count -ge 500) { break }
            if ($reference -is [string]) {
                $eventIdValue = ConvertTo-MihariEvidenceShareValue -Name 'eventId' -Value $reference -Context $Context -MaximumLength 256
                if ($null -ne $eventIdValue) { $safeRefs.Add([pscustomobject]@{ eventId = $eventIdValue }) }
            }
            else {
                $eventId = Get-MihariEvidenceValue -InputObject $reference -Name 'eventId'
                $sessionId = Get-MihariEvidenceValue -InputObject $reference -Name 'sessionId'
                if ($null -ne $eventId) {
                    $safeEventId = ConvertTo-MihariEvidenceShareValue -Name 'eventId' -Value ([string]$eventId) -Context $Context -MaximumLength 256
                    $safeRef = [ordered]@{ eventId = $safeEventId }
                    if ($null -ne $sessionId) { $safeRef['sessionId'] = ConvertTo-MihariEvidenceShareValue -Name 'sessionId' -Value ([string]$sessionId) -Context $Context -MaximumLength 256 }
                    $safeRefs.Add([pscustomobject]$safeRef)
                }
            }
        }
        $result['evidenceRefs'] = @($safeRefs.ToArray())
    }
    return [pscustomobject]$result
}

function ConvertTo-MihariEvidenceSafeProfile {
    param([AllowNull()][object]$Profile, [Parameter(Mandatory = $true)][object]$Context)
    if ($null -eq $Profile) { return [pscustomobject]@{} }
    $allowed = @('mode', 'protocol', 'tlsVersion', 'connectionReuse', 'cacheDisabled', 'requestedSwitches', 'observedSwitches', 'localExclusions', 'routeKind', 'profileName', 'proxyHost', 'proxyPort', 'maxWorkers')
    $result = [ordered]@{}
    foreach ($name in $allowed) {
        $raw = Get-MihariEvidenceValue -InputObject $Profile -Name $name
        if ($null -eq $raw) { continue }
        if ($raw -is [Array]) {
            $values = New-Object 'System.Collections.Generic.List[object]'
            foreach ($item in $raw) {
                if ($values.Count -ge 100) { break }
                $safe = ConvertTo-MihariEvidenceShareValue -Name $name -Value $item -Context $Context -MaximumLength 512
                if ($null -ne $safe) { $values.Add($safe) }
            }
            $result[$name] = @($values.ToArray())
        }
        else {
            $safe = ConvertTo-MihariEvidenceShareValue -Name $name -Value $raw -Context $Context -MaximumLength 512
            if ($null -ne $safe) { $result[$name] = $safe }
        }
    }
    return [pscustomobject]$result
}

function ConvertTo-MihariEvidenceSafeEnvironment {
    param([AllowNull()][object]$Environment, [Parameter(Mandatory = $true)][object]$Context)
    $allowed = @('capturedAtUtc', 'source', 'coverage', 'osVersion', 'osBuild', 'powerShellVersion', 'dotNetVersion', 'runtime', 'architecture', 'proxyResolutionSource', 'proxyRouteKind', 'proxyHost', 'proxyPort', 'tlsCapabilities', 'httpCapabilities', 'browserVersion', 'edgeVersion', 'capabilities', 'limitations')
    $items = New-Object 'System.Collections.Generic.List[object]'
    foreach ($snapshot in @($Environment)) {
        if ($null -eq $snapshot -or $items.Count -ge 100) { continue }
        $result = [ordered]@{}
        foreach ($name in $allowed) {
            $raw = Get-MihariEvidenceValue -InputObject $snapshot -Name $name
            if ($null -eq $raw) { continue }
            if ($raw -is [Array]) {
                $values = New-Object 'System.Collections.Generic.List[object]'
                foreach ($item in $raw) {
                    if ($values.Count -ge 100) { break }
                    $safe = ConvertTo-MihariEvidenceShareValue -Name $name -Value $item -Context $Context -MaximumLength 512
                    if ($null -ne $safe) { $values.Add($safe) }
                }
                $result[$name] = @($values.ToArray())
            }
            else {
                $safe = ConvertTo-MihariEvidenceShareValue -Name $name -Value $raw -Context $Context -MaximumLength 512
                if ($null -ne $safe) { $result[$name] = $safe }
            }
        }
        $items.Add([pscustomobject]$result)
    }
    return @($items.ToArray())
}

function Get-MihariEvidenceSha256Bytes {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $digest = $sha.ComputeHash($Bytes) }
    finally { $sha.Dispose() }
    return ([System.BitConverter]::ToString($digest)).Replace('-', '').ToLowerInvariant()
}

function ConvertTo-MihariEvidenceJsonBytes {
    param([Parameter(Mandatory = $true)][object]$Value)
    $json = ConvertTo-Json -InputObject $Value -Depth 32 -Compress
    return ,([System.Text.UTF8Encoding]::new($false).GetBytes($json + "`n"))
}

function New-MihariEvidenceBundleContent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][object]$Case,
        [AllowEmptyCollection()][object[]]$Trials = @(),
        [AllowEmptyCollection()][object[]]$Events = @(),
        [AllowEmptyCollection()][object[]]$Annotations = @(),
        [AllowEmptyCollection()][object[]]$Findings = @(),
        [AllowNull()][object]$OriginalResult,
        [AllowNull()][object]$DiagnosticProfile,
        [AllowEmptyCollection()][object[]]$EnvironmentSnapshots = @(),
        [AllowNull()][object]$CaptureCoverage,
        [AllowNull()][object]$ShareProfile,
        [string]$RuleVersion = 'unknown',
        [string]$ApplicationRevision = 'unknown'
    )
    $context = New-MihariEvidenceShareContext -ShareProfile $ShareProfile
    $safeEvents = New-Object 'System.Collections.Generic.List[object]'
    $unknownEvents = New-Object 'System.Collections.Generic.List[object]'
    $eventBytes = [long]0
    $lastSequences = @{}
    $seenEventIds = @{}
    foreach ($event in @($Events)) {
        if ($safeEvents.Count + $unknownEvents.Count -ge 100000) { break }
        $converted = ConvertTo-MihariEvidenceSafeEvent -Event $event -Context $context
        if ($converted.Recognized) {
            $eventId = [string]$converted.Record.eventId
            if ($seenEventIds.ContainsKey($eventId)) {
                $unknownEvents.Add([pscustomobject]@{ reason = 'duplicate_event_id' })
                continue
            }
            $seenEventIds[$eventId] = $true
            if ($converted.Record.schemaVersion -eq 2) {
                $sessionKey = [string]$converted.Record.sessionId
                if ($lastSequences.ContainsKey($sessionKey) -and [long]$converted.Record.sequence -le [long]$lastSequences[$sessionKey]) {
                    $unknownEvents.Add([pscustomobject]@{ reason = 'invalid_sequence_order' })
                    continue
                }
                $lastSequences[$sessionKey] = [long]$converted.Record.sequence
            }
            $line = ConvertTo-Json -InputObject $converted.Record -Depth 32 -Compress
            $lineBytes = [System.Text.Encoding]::UTF8.GetByteCount($line) + 1
            if ($lineBytes -gt 65536) { $unknownEvents.Add([pscustomobject]@{ reason = 'record_too_large' }); continue }
            $eventBytes += $lineBytes
            if ($eventBytes -gt 33554432) { throw 'The exported event stream exceeds its 32 MiB bound.' }
            $safeEvents.Add($converted.Record)
        }
        else { $unknownEvents.Add([pscustomobject]@{ reason = $converted.Reason }) }
    }
    $safeAnnotations = New-Object 'System.Collections.Generic.List[object]'
    $annotationBytes = [long]0
    foreach ($annotation in @($Annotations)) {
        if ($safeAnnotations.Count -ge 10000) { break }
        $safeAnnotation = ConvertTo-MihariEvidenceSafeAnnotation -Annotation $annotation -Context $context
        $annotationBytes += [System.Text.Encoding]::UTF8.GetByteCount((ConvertTo-Json -InputObject $safeAnnotation -Depth 20 -Compress)) + 1
        if ($annotationBytes -gt 8388608) { throw 'The exported annotation stream exceeds its 8 MiB bound.' }
        $safeAnnotations.Add($safeAnnotation)
    }
    $safeTrials = New-Object 'System.Collections.Generic.List[object]'
    foreach ($trial in @($Trials)) {
        if ($safeTrials.Count -ge 1000) { break }
        $safeTrials.Add((ConvertTo-MihariEvidenceSafeTrial -Trial $trial -Context $context))
    }
    $safeFindings = New-Object 'System.Collections.Generic.List[object]'
    foreach ($finding in @($Findings)) {
        if ($safeFindings.Count -ge 5000) { break }
        $safeFindings.Add((ConvertTo-MihariEvidenceSafeFinding -Finding $finding -Context $context))
    }
    $safeCase = ConvertTo-MihariEvidenceSafeCase -Case $Case -Context $context
    $safeProfile = ConvertTo-MihariEvidenceSafeProfile -Profile $DiagnosticProfile -Context $context
    $safeEnvironment = ConvertTo-MihariEvidenceSafeEnvironment -Environment $EnvironmentSnapshots -Context $context
    $safeCoverage = ConvertTo-MihariEvidenceSafeData -Data $CaptureCoverage -Context $context
    $safeOriginalResult = $null
    if ($null -ne $OriginalResult) {
        $originalFindings = Get-MihariEvidenceValue -InputObject $OriginalResult -Name 'findings'
        $resultFindings = New-Object 'System.Collections.Generic.List[object]'
        foreach ($finding in @($originalFindings)) {
            if ($resultFindings.Count -ge 5000) { break }
            $resultFindings.Add((ConvertTo-MihariEvidenceSafeFinding -Finding $finding -Context $context))
        }
        $safeOriginalResult = [pscustomobject]@{
            schemaVersion = 1
            ruleVersion = (ConvertTo-MihariEvidenceSharedText -Value (Get-MihariEvidenceValue -InputObject $OriginalResult -Name 'ruleVersion') -Context $context -MaximumLength 128)
            generatedAtUtc = (ConvertTo-MihariEvidenceSharedText -Value (Get-MihariEvidenceValue -InputObject $OriginalResult -Name 'generatedAtUtc') -Context $context -MaximumLength 64)
            findings = @($resultFindings.ToArray())
        }
    }
    $files = [ordered]@{}
    $eventLines = New-Object 'System.Collections.Generic.List[string]'
    foreach ($event in $safeEvents) { $eventLines.Add((ConvertTo-Json -InputObject $event -Depth 32 -Compress)) }
    $annotationLines = New-Object 'System.Collections.Generic.List[string]'
    foreach ($annotation in $safeAnnotations) { $annotationLines.Add((ConvertTo-Json -InputObject $annotation -Depth 20 -Compress)) }
    $files['events.jsonl'] = [System.Text.UTF8Encoding]::new($false).GetBytes(($eventLines -join "`n") + "`n")
    $files['annotations.jsonl'] = [System.Text.UTF8Encoding]::new($false).GetBytes(($annotationLines -join "`n") + "`n")
    $environmentPayload = [pscustomobject]@{ snapshots = @($safeEnvironment); captureCoverage = $safeCoverage }
    $files['environment.json'] = ConvertTo-MihariEvidenceJsonBytes -Value $environmentPayload
    if ($null -ne $safeOriginalResult) { $files['original-result.json'] = ConvertTo-MihariEvidenceJsonBytes -Value $safeOriginalResult }
    $exportBytes = [long]0
    foreach ($fileName in $files.Keys) { $exportBytes += ([byte[]]$files[$fileName]).Length }
    if ($exportBytes -gt 67108864) { throw 'The exported evidence bundle exceeds its 64 MiB bound.' }
    $fileRecords = New-Object 'System.Collections.Generic.List[object]'
    foreach ($fileName in $files.Keys) {
        $fileBytes = [byte[]]$files[$fileName]
        $recordCount = $null
        if ($fileName -eq 'events.jsonl') { $recordCount = $safeEvents.Count }
        elseif ($fileName -eq 'annotations.jsonl') { $recordCount = $safeAnnotations.Count }
        $fileRecords.Add([pscustomobject]@{ path = $fileName; bytes = [long]$fileBytes.Length; sha256 = (Get-MihariEvidenceSha256Bytes -Bytes $fileBytes); recordCount = $recordCount })
    }
    $bundleId = [Guid]::NewGuid().ToString('N')
    $manifest = [ordered]@{
        format = 'mihari.case-bundle'
        schemaVersion = 1
        bundleId = $bundleId
        createdAtUtc = [DateTime]::UtcNow.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
        applicationRevision = (ConvertTo-MihariEvidenceSharedText -Value $ApplicationRevision -Context $context -MaximumLength 128)
        ruleVersion = (ConvertTo-MihariEvidenceSharedText -Value $RuleVersion -Context $context -MaximumLength 128)
        case = $safeCase
        trials = @($safeTrials.ToArray())
        findings = @($safeFindings.ToArray())
        diagnosticProfile = $safeProfile
        environmentSnapshots = @($safeEnvironment)
        captureCoverage = $safeCoverage
        shareProfile = $context.Options
        files = @($fileRecords.ToArray())
        redactionSummary = [pscustomobject]@{
            credentialsBodiesHeadersDebuggerControls = 'excluded'
            queryValues = 'redacted'
            hosts = $(if ($context.Options.maskHosts) { 'pseudonymized' } else { 'as captured' })
            usernames = $(if ($context.Options.maskUsernames) { 'pseudonymized' } else { 'as captured' })
            paths = $(if ($context.Options.maskPaths) { 'pseudonymized' } else { 'as captured' })
            identifiers = $(if ($context.Options.maskIdentifiers) { 'pseudonymized' } else { 'as captured' })
            unsupportedEvents = $unknownEvents.Count
            unsupportedEventReasons = @($unknownEvents | Group-Object -Property reason | ForEach-Object { [pscustomobject]@{ reason = $_.Name; count = $_.Count } })
        }
        integrity = [pscustomobject]@{ algorithm = 'SHA-256'; statement = 'Hashes detect file modification and do not establish authorship or trustworthy acquisition.' }
    }
    $manifestBytes = ConvertTo-MihariEvidenceJsonBytes -Value ([pscustomobject]$manifest)
    $files['manifest.json'] = $manifestBytes
    $included = New-Object 'System.Collections.Generic.List[object]'
    foreach ($record in $fileRecords) {
        $included.Add([pscustomobject]@{ path = $record.path; bytes = $record.bytes; records = $record.recordCount })
    }
    $included.Add([pscustomobject]@{ path = 'manifest.json'; bytes = $manifestBytes.Length; records = 1 })
    $preview = [pscustomobject]@{
        bundleId = $bundleId
        schemaVersion = 1
        included = @($included.ToArray())
        redacted = @(
            [pscustomobject]@{ category = 'credentials, cookies, arbitrary headers, bodies, private keys, browser profiles, debugger controls'; treatment = 'excluded' },
            [pscustomobject]@{ category = 'query values'; treatment = 'redacted' },
            [pscustomobject]@{ category = 'hostnames, usernames, paths, identifiers'; treatment = 'controlled by the selected share profile' }
        )
        unsupportedEventCount = $unknownEvents.Count
        unsupportedEventReasons = @($unknownEvents | Group-Object -Property reason | ForEach-Object { [pscustomobject]@{ reason = $_.Name; count = $_.Count } })
        shareProfile = $context.Options
        warning = 'SHA-256 hashes detect modification; they do not prove authorship or acquisition integrity.'
    }
    return [pscustomobject]@{ Files = $files; Manifest = [pscustomobject]$manifest; Preview = $preview }
}

function New-MihariEvidenceBundlePreview {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][object]$Case,
        [AllowEmptyCollection()][object[]]$Trials = @(), [AllowEmptyCollection()][object[]]$Events = @(),
        [AllowEmptyCollection()][object[]]$Annotations = @(), [AllowEmptyCollection()][object[]]$Findings = @(),
        [AllowNull()][object]$OriginalResult, [AllowNull()][object]$DiagnosticProfile,
        [AllowEmptyCollection()][object[]]$EnvironmentSnapshots = @(), [AllowNull()][object]$CaptureCoverage,
        [AllowNull()][object]$ShareProfile, [string]$RuleVersion = 'unknown', [string]$ApplicationRevision = 'unknown'
    )
    $content = New-MihariEvidenceBundleContent @PSBoundParameters
    return $content.Preview
}

function Export-MihariEvidenceBundle {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$DestinationPath,
        [Parameter(Mandatory = $true)][object]$Case,
        [AllowEmptyCollection()][object[]]$Trials = @(), [AllowEmptyCollection()][object[]]$Events = @(),
        [AllowEmptyCollection()][object[]]$Annotations = @(), [AllowEmptyCollection()][object[]]$Findings = @(),
        [AllowNull()][object]$OriginalResult, [AllowNull()][object]$DiagnosticProfile,
        [AllowEmptyCollection()][object[]]$EnvironmentSnapshots = @(), [AllowNull()][object]$CaptureCoverage,
        [AllowNull()][object]$ShareProfile, [string]$RuleVersion = 'unknown', [string]$ApplicationRevision = 'unknown'
    )
    $contentParameters = @{}
    foreach ($key in $PSBoundParameters.Keys) {
        if ($key -ne 'DestinationPath') { $contentParameters[$key] = $PSBoundParameters[$key] }
    }
    $content = New-MihariEvidenceBundleContent @contentParameters
    $target = [System.IO.Path]::GetFullPath($DestinationPath)
    if ([System.IO.File]::Exists($target) -or [System.IO.Directory]::Exists($target)) { throw 'The evidence bundle destination already exists.' }
    $parent = [System.IO.Path]::GetDirectoryName($target)
    if ([string]::IsNullOrWhiteSpace($parent)) { throw 'The evidence bundle destination requires a parent directory.' }
    Assert-MihariEvidencePathHasNoReparsePoint -Path $parent
    [void][System.IO.Directory]::CreateDirectory($parent)
    $temporary = $target + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
    $stream = $null
    $archive = $null
    try {
        $stream = [System.IO.File]::Open($temporary, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
        $archive = [System.IO.Compression.ZipArchive]::new($stream, [System.IO.Compression.ZipArchiveMode]::Create, $true)
        foreach ($name in $content.Files.Keys) {
            $entry = $archive.CreateEntry([string]$name, [System.IO.Compression.CompressionLevel]::Optimal)
            $entryStream = $entry.Open()
            try {
                $bytes = [byte[]]$content.Files[$name]
                $entryStream.Write($bytes, 0, $bytes.Length)
            }
            finally { $entryStream.Dispose() }
        }
        $archive.Dispose()
        $archive = $null
        $stream.Dispose()
        $stream = $null
        [System.IO.File]::Move($temporary, $target)
    }
    finally {
        if ($null -ne $archive) { $archive.Dispose() }
        if ($null -ne $stream) { $stream.Dispose() }
        if ([System.IO.File]::Exists($temporary)) { [System.IO.File]::Delete($temporary) }
    }
    return [pscustomobject]@{ path = $target; bundleId = $content.Manifest.bundleId; preview = $content.Preview; sha256 = (Get-MihariEvidenceFileSha256 -Path $target) }
}

function Get-MihariEvidenceFileSha256 {
    param([Parameter(Mandatory = $true)][string]$Path)
    $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $digest = $sha.ComputeHash($stream) }
    finally { $stream.Dispose(); $sha.Dispose() }
    return ([System.BitConverter]::ToString($digest)).Replace('-', '').ToLowerInvariant()
}

function Test-MihariEvidencePathSafe {
    param([Parameter(Mandatory = $true)][string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name) -or $Name.Contains('\') -or $Name.Contains(':') -or $Name.Contains("`0") -or
        $Name.StartsWith('/') -or $Name.StartsWith('\\') -or $Name -match '(^|/)\.\.?($|/)') { return $false }
    return @('manifest.json', 'events.jsonl', 'annotations.jsonl', 'environment.json', 'original-result.json', 'import-report.json') -contains $Name
}

function Test-MihariEvidenceRelativePath {
    param([Parameter(Mandatory = $true)][string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name) -or $Name.Contains('\') -or $Name.Contains(':') -or $Name.Contains("`0") -or
        $Name.StartsWith('/') -or $Name.StartsWith('\\') -or $Name -match '(^|/)\.\.?($|/)') { return $false }
    foreach ($part in $Name.Split('/')) {
        if ([string]::IsNullOrWhiteSpace($part) -or $part -match '[<>:"|?*]' -or $part.EndsWith('.') -or $part.EndsWith(' ')) { return $false }
    }
    return $true
}

function Test-MihariEvidenceEntryIsSymlink {
    param([Parameter(Mandatory = $true)][System.IO.Compression.ZipArchiveEntry]$Entry)
    $attributes = [int]$Entry.ExternalAttributes
    $unixMode = ($attributes -shr 16) -band 0xF000
    if ($unixMode -eq 0xA000) { return $true }
    if (($attributes -band [int][System.IO.FileAttributes]::ReparsePoint) -ne 0) { return $true }
    return $false
}

function Read-MihariEvidenceZipEntryBytes {
    param(
        [Parameter(Mandatory = $true)][System.IO.Compression.ZipArchiveEntry]$Entry,
        [Parameter(Mandatory = $true)][long]$MaximumBytes,
        [Parameter(Mandatory = $true)][ref]$TotalBytes,
        [Parameter(Mandatory = $true)][long]$MaximumTotalBytes
    )
    if ($Entry.Length -lt 0 -or $Entry.Length -gt $MaximumBytes) { throw 'An evidence bundle entry exceeds the configured size limit.' }
    if ($Entry.Length -gt 1048576 -and $Entry.CompressedLength -gt 0 -and ($Entry.Length / [double]$Entry.CompressedLength) -gt 200) {
        throw 'An evidence bundle entry has an unsafe compression ratio.'
    }
    $memory = New-Object System.IO.MemoryStream
    $input = $Entry.Open()
    $buffer = New-Object byte[] 8192
    $actual = [long]0
    try {
        while (($count = $input.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $actual += $count
            $TotalBytes.Value += $count
            if ($actual -gt $MaximumBytes -or $TotalBytes.Value -gt $MaximumTotalBytes) {
                throw 'An evidence bundle exceeds the configured expanded size limit.'
            }
            $memory.Write($buffer, 0, $count)
        }
        if ($actual -ne $Entry.Length) { throw 'An evidence bundle entry length did not match its archive metadata.' }
        return ,$memory.ToArray()
    }
    finally { $input.Dispose(); $memory.Dispose() }
}

function ConvertFrom-MihariEvidenceJsonBytes {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes, [Parameter(Mandatory = $true)][string]$Name)
    $encoding = [System.Text.UTF8Encoding]::new($false, $true)
    try { $text = $encoding.GetString($Bytes) }
    catch { throw ('Evidence file {0} is not valid UTF-8.' -f $Name) }
    try { return ($text | ConvertFrom-Json -ErrorAction Stop) }
    catch { throw ('Evidence file {0} does not contain valid JSON.' -f $Name) }
}

function Read-MihariEvidenceJsonLines {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [Parameter(Mandatory = $true)][ValidateSet('events.jsonl', 'annotations.jsonl')][string]$Name,
        [Parameter(Mandatory = $true)][object]$Context,
        [ValidateRange(1, 1000000)][int]$MaximumRecords = 100000,
        [ValidateRange(128, 1048576)][int]$MaximumRecordBytes = 65536
    )
    $encoding = [System.Text.UTF8Encoding]::new($false, $true)
    try { $text = $encoding.GetString($Bytes) }
    catch { throw ('Evidence file {0} is not valid UTF-8.' -f $Name) }
    $accepted = New-Object 'System.Collections.Generic.List[object]'
    $unknown = New-Object 'System.Collections.Generic.List[object]'
    $seenEventIds = @{}
    $lastSequences = @{}
    $lines = $text.Split([char]"`n")
    if ($lines.Length -gt ($MaximumRecords + 1)) { throw ('Evidence file {0} exceeds the record count limit.' -f $Name) }
    for ($index = 0; $index -lt $lines.Length; $index++) {
        $line = $lines[$index].TrimEnd("`r")
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        if ([System.Text.Encoding]::UTF8.GetByteCount($line) -gt $MaximumRecordBytes) { throw ('Evidence file {0} has a record above the configured size limit.' -f $Name) }
        try { $record = $line | ConvertFrom-Json -ErrorAction Stop }
        catch { throw ('Evidence file {0} contains malformed JSON at line {1}.' -f $Name, ($index + 1)) }
        if ($accepted.Count + $unknown.Count -ge $MaximumRecords) { throw ('Evidence file {0} exceeds the record count limit.' -f $Name) }
        if ($Name -eq 'events.jsonl') {
            $safe = ConvertTo-MihariEvidenceSafeEvent -Event $record -Context $Context
            if (-not $safe.Recognized) {
                $unknown.Add([pscustomobject]@{ line = $index + 1; reason = $safe.Reason })
                continue
            }
            $eventId = [string]$safe.Record.eventId
            if ($seenEventIds.ContainsKey($eventId)) {
                $unknown.Add([pscustomobject]@{ line = $index + 1; reason = 'duplicate_event_id' })
                continue
            }
            $seenEventIds[$eventId] = $true
            if ($safe.Record.schemaVersion -eq 2) {
                $sessionKey = [string]$safe.Record.sessionId
                if ($lastSequences.ContainsKey($sessionKey) -and [long]$safe.Record.sequence -le [long]$lastSequences[$sessionKey]) {
                    $unknown.Add([pscustomobject]@{ line = $index + 1; reason = 'invalid_sequence_order' })
                    continue
                }
                $lastSequences[$sessionKey] = [long]$safe.Record.sequence
            }
            $accepted.Add($safe.Record)
        }
        else { $accepted.Add((ConvertTo-MihariEvidenceSafeAnnotation -Annotation $record -Context $Context)) }
    }
    return [pscustomobject]@{ Records = @($accepted.ToArray()); Unknown = @($unknown.ToArray()) }
}

function Assert-MihariEvidencePathHasNoReparsePoint {
    param([Parameter(Mandatory = $true)][string]$Path)
    $full = [System.IO.Path]::GetFullPath($Path)
    $root = [System.IO.Path]::GetPathRoot($full)
    $current = $root
    $relative = $full.Substring($root.Length).Split([char[]]@([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar), [StringSplitOptions]::RemoveEmptyEntries)
    foreach ($part in $relative) {
        $current = [System.IO.Path]::Combine($current, $part)
        if ([System.IO.File]::Exists($current) -or [System.IO.Directory]::Exists($current)) {
            $attributes = [System.IO.File]::GetAttributes($current)
            if (($attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Evidence storage cannot use a symbolic link or reparse point.' }
        }
    }
}

function Test-MihariEvidenceManifestFiles {
    param([Parameter(Mandatory = $true)][object]$Manifest, [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Files)
    if ([string](Get-MihariEvidenceValue -InputObject $Manifest -Name 'format') -ne 'mihari.case-bundle' -or
        [int](Get-MihariEvidenceValue -InputObject $Manifest -Name 'schemaVersion') -ne 1) { throw 'The evidence bundle format or schema version is unsupported.' }
    $manifestFiles = Get-MihariEvidenceValue -InputObject $Manifest -Name 'files'
    if ($null -eq $manifestFiles -or @($manifestFiles).Count -gt 8) { throw 'The evidence manifest file list is missing or too large.' }
    $seen = @{}
    foreach ($record in @($manifestFiles)) {
        $name = [string](Get-MihariEvidenceValue -InputObject $record -Name 'path')
        if (-not (Test-MihariEvidencePathSafe -Name $name) -or $name -eq 'manifest.json' -or $seen.ContainsKey($name)) {
            throw 'The evidence manifest contains an unsafe or duplicate file path.'
        }
        $seen[$name] = $true
        if (-not $Files.Contains($name)) { throw ('The evidence bundle is missing {0}.' -f $name) }
        $bytes = [byte[]]$Files[$name]
        $expectedLength = [long](Get-MihariEvidenceValue -InputObject $record -Name 'bytes')
        $expectedHash = [string](Get-MihariEvidenceValue -InputObject $record -Name 'sha256')
        if ($expectedLength -ne $bytes.Length -or $expectedHash -notmatch '^[0-9a-fA-F]{64}$' -or
            -not [string]::Equals($expectedHash, (Get-MihariEvidenceSha256Bytes -Bytes $bytes), [StringComparison]::OrdinalIgnoreCase)) {
            throw ('Evidence file {0} failed its SHA-256 or length check.' -f $name)
        }
    }
    foreach ($name in $Files.Keys) {
        if ($name -eq 'manifest.json') { continue }
        if (-not $seen.ContainsKey([string]$name)) { throw ('Evidence file {0} is not declared by the manifest.' -f $name) }
    }
    if (-not $seen.ContainsKey('events.jsonl') -or -not $seen.ContainsKey('annotations.jsonl') -or -not $seen.ContainsKey('environment.json')) {
        throw 'The evidence bundle is missing a required evidence file.'
    }
}

function Import-MihariEvidenceBundle {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$ArchivePath,
        [Parameter(Mandatory = $true)][string]$DestinationDirectory,
        [ValidateRange(1024, 1073741824)][long]$MaximumArchiveBytes = 67108864,
        [ValidateRange(1024, 1073741824)][long]$MaximumExpandedBytes = 134217728,
        [ValidateRange(1024, 1073741824)][long]$MaximumEntryBytes = 67108864,
        [ValidateRange(1, 1000)][int]$MaximumEntries = 16,
        [ValidateRange(1, 1000000)][int]$MaximumRecords = 100000,
        [ValidateRange(128, 1048576)][int]$MaximumRecordBytes = 65536
    )
    [void][System.Reflection.Assembly]::Load('System.IO.Compression')
    $archiveFull = [System.IO.Path]::GetFullPath($ArchivePath)
    if (-not [System.IO.File]::Exists($archiveFull)) { throw 'The evidence archive does not exist.' }
    Assert-MihariEvidencePathHasNoReparsePoint -Path $archiveFull
    if ((New-Object System.IO.FileInfo($archiveFull)).Length -gt $MaximumArchiveBytes) { throw 'The evidence archive exceeds the configured size limit.' }
    $zipStream = $null
    $archive = $null
    $files = @{}
    $totalBytes = [long]0
    try {
        $zipStream = [System.IO.File]::Open($archiveFull, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
        $archive = [System.IO.Compression.ZipArchive]::new($zipStream, [System.IO.Compression.ZipArchiveMode]::Read, $false)
        if ($archive.Entries.Count -lt 1 -or $archive.Entries.Count -gt $MaximumEntries) { throw 'The evidence archive entry count is outside the configured bounds.' }
        foreach ($entry in $archive.Entries) {
            $name = [string]$entry.FullName
            if (-not (Test-MihariEvidencePathSafe -Name $name) -or $entry.Name -ne $name) { throw 'The evidence archive contains an unsafe path.' }
            if (Test-MihariEvidenceEntryIsSymlink -Entry $entry) { throw 'The evidence archive contains a symbolic link or reparse-point entry.' }
            if ($files.ContainsKey($name)) { throw 'The evidence archive contains duplicate paths.' }
            $files[$name] = Read-MihariEvidenceZipEntryBytes -Entry $entry -MaximumBytes $MaximumEntryBytes -TotalBytes ([ref]$totalBytes) -MaximumTotalBytes $MaximumExpandedBytes
        }
    }
    finally {
        if ($null -ne $archive) { $archive.Dispose() }
        if ($null -ne $zipStream) { $zipStream.Dispose() }
    }
    if (-not $files.ContainsKey('manifest.json')) { throw 'The evidence archive has no manifest.' }
    $manifestBytes = [byte[]]$files['manifest.json']
    if ($manifestBytes.Length -gt 1048576) { throw 'The evidence manifest exceeds the configured size limit.' }
    $manifest = ConvertFrom-MihariEvidenceJsonBytes -Bytes $manifestBytes -Name 'manifest.json'
    Test-MihariEvidenceManifestFiles -Manifest $manifest -Files $files
    $importContext = New-MihariEvidenceShareContext -ShareProfile ([pscustomobject]@{ maskHosts = $true; maskUsernames = $true; maskPaths = $true; maskIdentifiers = $true })
    $eventResult = Read-MihariEvidenceJsonLines -Bytes ([byte[]]$files['events.jsonl']) -Name 'events.jsonl' -Context $importContext -MaximumRecords $MaximumRecords -MaximumRecordBytes $MaximumRecordBytes
    $annotationResult = Read-MihariEvidenceJsonLines -Bytes ([byte[]]$files['annotations.jsonl']) -Name 'annotations.jsonl' -Context $importContext -MaximumRecords 10000 -MaximumRecordBytes $MaximumRecordBytes
    $environment = ConvertFrom-MihariEvidenceJsonBytes -Bytes ([byte[]]$files['environment.json']) -Name 'environment.json'
    $safeEnvironment = ConvertTo-MihariEvidenceSafeEnvironment -Environment (Get-MihariEvidenceValue -InputObject $environment -Name 'snapshots') -Context $importContext
    $coverage = ConvertTo-MihariEvidenceSafeData -Data (Get-MihariEvidenceValue -InputObject $environment -Name 'captureCoverage') -Context $importContext
    $originalResult = $null
    if ($files.ContainsKey('original-result.json')) {
        $rawResult = ConvertFrom-MihariEvidenceJsonBytes -Bytes ([byte[]]$files['original-result.json']) -Name 'original-result.json'
        $safeFindings = New-Object 'System.Collections.Generic.List[object]'
        foreach ($finding in @(Get-MihariEvidenceValue -InputObject $rawResult -Name 'findings')) {
            if ($safeFindings.Count -ge 5000) { break }
            $safeFindings.Add((ConvertTo-MihariEvidenceSafeFinding -Finding $finding -Context $importContext))
        }
        $originalResult = [pscustomobject]@{ schemaVersion = 1; ruleVersion = [string](Get-MihariEvidenceValue -InputObject $rawResult -Name 'ruleVersion'); generatedAtUtc = [string](Get-MihariEvidenceValue -InputObject $rawResult -Name 'generatedAtUtc'); findings = @($safeFindings.ToArray()) }
    }
    $safeManifest = [ordered]@{
        format = 'mihari.case-bundle'; schemaVersion = 1
        bundleId = [string](Get-MihariEvidenceValue -InputObject $manifest -Name 'bundleId')
        createdAtUtc = [string](Get-MihariEvidenceValue -InputObject $manifest -Name 'createdAtUtc')
        applicationRevision = [string](Get-MihariEvidenceValue -InputObject $manifest -Name 'applicationRevision')
        ruleVersion = [string](Get-MihariEvidenceValue -InputObject $manifest -Name 'ruleVersion')
        case = (ConvertTo-MihariEvidenceSafeCase -Case (Get-MihariEvidenceValue -InputObject $manifest -Name 'case') -Context $importContext)
        trials = @()
        findings = @()
        diagnosticProfile = (ConvertTo-MihariEvidenceSafeProfile -Profile (Get-MihariEvidenceValue -InputObject $manifest -Name 'diagnosticProfile') -Context $importContext)
        environmentSnapshots = @($safeEnvironment)
        captureCoverage = $coverage
        shareProfile = $importContext.Options
        redactionSummary = [pscustomobject]@{ import = 'revalidated and sanitized'; unsupportedEvents = $eventResult.Unknown.Count }
        integrity = [pscustomobject]@{ algorithm = 'SHA-256'; sourceBundleHash = (Get-MihariEvidenceFileSha256 -Path $archiveFull); sourceHashMeaning = 'Modification detection only; authorship and acquisition are not established.' }
        import = [pscustomobject]@{ importedAtUtc = [DateTime]::UtcNow.ToString('o', [Globalization.CultureInfo]::InvariantCulture); originalBundleId = [string](Get-MihariEvidenceValue -InputObject $manifest -Name 'bundleId') }
    }
    $trials = New-Object 'System.Collections.Generic.List[object]'
    foreach ($trial in @(Get-MihariEvidenceValue -InputObject $manifest -Name 'trials')) {
        if ($trials.Count -ge 1000) { break }
        $trials.Add((ConvertTo-MihariEvidenceSafeTrial -Trial $trial -Context $importContext))
    }
    $safeManifest['trials'] = @($trials.ToArray())
    $findings = New-Object 'System.Collections.Generic.List[object]'
    foreach ($finding in @(Get-MihariEvidenceValue -InputObject $manifest -Name 'findings')) {
        if ($findings.Count -ge 5000) { break }
        $findings.Add((ConvertTo-MihariEvidenceSafeFinding -Finding $finding -Context $importContext))
    }
    $safeManifest['findings'] = @($findings.ToArray())
    $localFiles = [ordered]@{}
    $eventLines = New-Object 'System.Collections.Generic.List[string]'
    foreach ($event in $eventResult.Records) { $eventLines.Add((ConvertTo-Json -InputObject $event -Depth 32 -Compress)) }
    $annotationLines = New-Object 'System.Collections.Generic.List[string]'
    foreach ($annotation in $annotationResult.Records) { $annotationLines.Add((ConvertTo-Json -InputObject $annotation -Depth 20 -Compress)) }
    $localFiles['events.jsonl'] = [System.Text.UTF8Encoding]::new($false).GetBytes(($eventLines -join "`n") + "`n")
    $localFiles['annotations.jsonl'] = [System.Text.UTF8Encoding]::new($false).GetBytes(($annotationLines -join "`n") + "`n")
    $localFiles['environment.json'] = ConvertTo-MihariEvidenceJsonBytes -Value ([pscustomobject]@{ snapshots = @($safeEnvironment); captureCoverage = $coverage })
    if ($null -ne $originalResult) { $localFiles['original-result.json'] = ConvertTo-MihariEvidenceJsonBytes -Value $originalResult }
    $report = [pscustomobject]@{
        schemaVersion = 1
        sourceBundleHash = (Get-MihariEvidenceFileSha256 -Path $archiveFull)
        verifiedFileCount = @($manifest.files).Count
        importedEventCount = $eventResult.Records.Count
        importedAnnotationCount = $annotationResult.Records.Count
        unknownRecords = @($eventResult.Unknown)
        unknownSourceRecords = @()
        warnings = @('Source hashes were checked. They do not prove authorship or acquisition integrity.', 'Offline review is read-only and does not create listeners or certificate trust.')
    }
    $localFiles['import-report.json'] = ConvertTo-MihariEvidenceJsonBytes -Value $report
    $fileRecords = New-Object 'System.Collections.Generic.List[object]'
    foreach ($name in $localFiles.Keys) {
        $bytes = [byte[]]$localFiles[$name]
        $count = $null
        if ($name -eq 'events.jsonl') { $count = $eventResult.Records.Count }
        elseif ($name -eq 'annotations.jsonl') { $count = $annotationResult.Records.Count }
        $fileRecords.Add([pscustomobject]@{ path = $name; bytes = [long]$bytes.Length; sha256 = (Get-MihariEvidenceSha256Bytes -Bytes $bytes); recordCount = $count })
    }
    $safeManifest['files'] = @($fileRecords.ToArray())
    $localFiles['manifest.json'] = ConvertTo-MihariEvidenceJsonBytes -Value ([pscustomobject]$safeManifest)
    $root = [System.IO.Path]::GetFullPath($DestinationDirectory)
    Assert-MihariEvidencePathHasNoReparsePoint -Path $root
    [void][System.IO.Directory]::CreateDirectory($root)
    Assert-MihariEvidencePathHasNoReparsePoint -Path $root
    $localName = [Guid]::NewGuid().ToString('N')
    $temporaryDirectory = [System.IO.Path]::Combine($root, '.' + $localName + '.importing')
    $finalDirectory = [System.IO.Path]::Combine($root, 'case-' + $localName)
    [void][System.IO.Directory]::CreateDirectory($temporaryDirectory)
    try {
        Assert-MihariEvidencePathHasNoReparsePoint -Path $temporaryDirectory
        foreach ($name in $localFiles.Keys) {
            $destination = [System.IO.Path]::Combine($temporaryDirectory, [string]$name)
            Assert-MihariEvidencePathHasNoReparsePoint -Path $destination
            [System.IO.File]::WriteAllBytes($destination, [byte[]]$localFiles[$name])
        }
        [System.IO.Directory]::Move($temporaryDirectory, $finalDirectory)
    }
    finally {
        if ([System.IO.Directory]::Exists($temporaryDirectory)) { [System.IO.Directory]::Delete($temporaryDirectory, $true) }
    }
    return [pscustomobject]@{
        success = $true
        caseDirectory = $finalDirectory
        bundleId = [string](Get-MihariEvidenceValue -InputObject $manifest -Name 'bundleId')
        importedEventCount = $eventResult.Records.Count
        importedAnnotationCount = $annotationResult.Records.Count
        unknownRecordCount = $eventResult.Unknown.Count
        sourceHashVerified = $true
        sourceBundleHash = $report.sourceBundleHash
        readOnly = $true
    }
}

function Read-MihariOfflineEvidenceCase {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$CaseDirectory)
    $directory = [System.IO.Path]::GetFullPath($CaseDirectory)
    Assert-MihariEvidencePathHasNoReparsePoint -Path $directory
    $manifestPath = [System.IO.Path]::Combine($directory, 'manifest.json')
    if (-not [System.IO.File]::Exists($manifestPath)) { throw 'The offline case has no manifest.' }
    $manifestBytes = [System.IO.File]::ReadAllBytes($manifestPath)
    if ($manifestBytes.Length -gt 1048576) { throw 'The offline case manifest exceeds the configured size limit.' }
    $manifest = ConvertFrom-MihariEvidenceJsonBytes -Bytes $manifestBytes -Name 'manifest.json'
    $files = @{}
    foreach ($record in @(Get-MihariEvidenceValue -InputObject $manifest -Name 'files')) {
        $name = [string](Get-MihariEvidenceValue -InputObject $record -Name 'path')
        if (-not (Test-MihariEvidencePathSafe -Name $name) -or $name -eq 'manifest.json') { throw 'The offline case manifest contains an unsafe path.' }
        $path = [System.IO.Path]::Combine($directory, $name)
        Assert-MihariEvidencePathHasNoReparsePoint -Path $path
        if (-not [System.IO.File]::Exists($path)) { throw ('Offline case file {0} is missing.' -f $name) }
        if ((New-Object System.IO.FileInfo($path)).Length -gt 134217728) { throw 'An offline case file exceeds the configured size limit.' }
        $files[$name] = [System.IO.File]::ReadAllBytes($path)
    }
    Test-MihariEvidenceManifestFiles -Manifest $manifest -Files $files
    $context = New-MihariEvidenceShareContext -ShareProfile ([pscustomobject]@{ maskHosts = $false; maskUsernames = $false; maskPaths = $false; maskIdentifiers = $false })
    $events = Read-MihariEvidenceJsonLines -Bytes ([byte[]]$files['events.jsonl']) -Name 'events.jsonl' -Context $context
    $annotations = Read-MihariEvidenceJsonLines -Bytes ([byte[]]$files['annotations.jsonl']) -Name 'annotations.jsonl' -Context $context -MaximumRecords 10000
    $environment = ConvertFrom-MihariEvidenceJsonBytes -Bytes ([byte[]]$files['environment.json']) -Name 'environment.json'
    $original = $null
    if ($files.ContainsKey('original-result.json')) {
        $rawOriginal = ConvertFrom-MihariEvidenceJsonBytes -Bytes ([byte[]]$files['original-result.json']) -Name 'original-result.json'
        $originalFindings = New-Object 'System.Collections.Generic.List[object]'
        foreach ($finding in @(Get-MihariEvidenceValue -InputObject $rawOriginal -Name 'findings')) {
            if ($originalFindings.Count -ge 5000) { break }
            $originalFindings.Add((ConvertTo-MihariEvidenceSafeFinding -Finding $finding -Context $context))
        }
        $original = [pscustomobject]@{
            schemaVersion = 1
            ruleVersion = (ConvertTo-MihariEvidenceSharedText -Value (Get-MihariEvidenceValue -InputObject $rawOriginal -Name 'ruleVersion') -Context $context -MaximumLength 128)
            generatedAtUtc = (ConvertTo-MihariEvidenceSharedText -Value (Get-MihariEvidenceValue -InputObject $rawOriginal -Name 'generatedAtUtc') -Context $context -MaximumLength 64)
            findings = @($originalFindings.ToArray())
        }
    }
    $importReport = $null
    if ($files.ContainsKey('import-report.json')) {
        $rawReport = ConvertFrom-MihariEvidenceJsonBytes -Bytes ([byte[]]$files['import-report.json']) -Name 'import-report.json'
        $safeUnknown = New-Object 'System.Collections.Generic.List[object]'
        foreach ($item in @(Get-MihariEvidenceValue -InputObject $rawReport -Name 'unknownRecords')) {
            if ($safeUnknown.Count -ge 10000) { break }
            $line = [int]0
            [void][int]::TryParse([string](Get-MihariEvidenceValue -InputObject $item -Name 'line'), [ref]$line)
            $reason = [string](Get-MihariEvidenceValue -InputObject $item -Name 'reason')
            if ($reason -notin @('unknown_schema', 'unknown_source', 'record_too_large', 'missing_required_field', 'missing_v2_field', 'invalid_sequence', 'unknown_coverage', 'duplicate_event_id', 'invalid_sequence_order')) { $reason = 'unknown_record' }
            $safeUnknown.Add([pscustomobject]@{ line = [Math]::Max(0, $line); reason = $reason })
        }
        $importReport = [pscustomobject]@{
            schemaVersion = 1
            sourceBundleHash = [string](Get-MihariEvidenceValue -InputObject $rawReport -Name 'sourceBundleHash')
            verifiedFileCount = [int](Get-MihariEvidenceValue -InputObject $rawReport -Name 'verifiedFileCount')
            importedEventCount = [int](Get-MihariEvidenceValue -InputObject $rawReport -Name 'importedEventCount')
            importedAnnotationCount = [int](Get-MihariEvidenceValue -InputObject $rawReport -Name 'importedAnnotationCount')
            unknownRecords = @($safeUnknown.ToArray())
            warnings = @('Source hashes are modification checks only.', 'Offline review is read-only.')
        }
    }
    $safeCase = ConvertTo-MihariEvidenceSafeCase -Case (Get-MihariEvidenceValue -InputObject $manifest -Name 'case') -Context $context
    $safeTrials = New-Object 'System.Collections.Generic.List[object]'
    foreach ($trial in @(Get-MihariEvidenceValue -InputObject $manifest -Name 'trials')) {
        if ($safeTrials.Count -ge 1000) { break }
        $safeTrials.Add((ConvertTo-MihariEvidenceSafeTrial -Trial $trial -Context $context))
    }
    $safeFindings = New-Object 'System.Collections.Generic.List[object]'
    foreach ($finding in @(Get-MihariEvidenceValue -InputObject $manifest -Name 'findings')) {
        if ($safeFindings.Count -ge 5000) { break }
        $safeFindings.Add((ConvertTo-MihariEvidenceSafeFinding -Finding $finding -Context $context))
    }
    $safeEnvironment = ConvertTo-MihariEvidenceSafeEnvironment -Environment (Get-MihariEvidenceValue -InputObject $environment -Name 'snapshots') -Context $context
    $safeCoverage = ConvertTo-MihariEvidenceSafeData -Data (Get-MihariEvidenceValue -InputObject $environment -Name 'captureCoverage') -Context $context
    $safeFiles = New-Object 'System.Collections.Generic.List[object]'
    foreach ($record in @(Get-MihariEvidenceValue -InputObject $manifest -Name 'files')) {
        $safeFiles.Add([pscustomobject]@{
            path = [string](Get-MihariEvidenceValue -InputObject $record -Name 'path')
            bytes = [long](Get-MihariEvidenceValue -InputObject $record -Name 'bytes')
            sha256 = [string](Get-MihariEvidenceValue -InputObject $record -Name 'sha256')
            recordCount = (Get-MihariEvidenceValue -InputObject $record -Name 'recordCount')
        })
    }
    $offlineManifest = [pscustomobject]@{
        format = 'mihari.case-bundle'; schemaVersion = 1
        bundleId = (ConvertTo-MihariEvidenceSharedText -Value (Get-MihariEvidenceValue -InputObject $manifest -Name 'bundleId') -Context $context -MaximumLength 128)
        createdAtUtc = (ConvertTo-MihariEvidenceSharedText -Value (Get-MihariEvidenceValue -InputObject $manifest -Name 'createdAtUtc') -Context $context -MaximumLength 64)
        applicationRevision = (ConvertTo-MihariEvidenceSharedText -Value (Get-MihariEvidenceValue -InputObject $manifest -Name 'applicationRevision') -Context $context -MaximumLength 128)
        ruleVersion = (ConvertTo-MihariEvidenceSharedText -Value (Get-MihariEvidenceValue -InputObject $manifest -Name 'ruleVersion') -Context $context -MaximumLength 128)
        case = $safeCase; trials = @($safeTrials.ToArray()); findings = @($safeFindings.ToArray())
        diagnosticProfile = (ConvertTo-MihariEvidenceSafeProfile -Profile (Get-MihariEvidenceValue -InputObject $manifest -Name 'diagnosticProfile') -Context $context)
        environmentSnapshots = @($safeEnvironment); captureCoverage = $safeCoverage
        shareProfile = (Get-MihariEvidenceValue -InputObject $manifest -Name 'shareProfile')
        redactionSummary = [pscustomobject]@{ state = 'safe_projection_applied' }
        import = [pscustomobject]@{ importedAtUtc = (ConvertTo-MihariEvidenceSharedText -Value (Get-MihariEvidenceValue -InputObject (Get-MihariEvidenceValue -InputObject $manifest -Name 'import') -Name 'importedAtUtc') -Context $context -MaximumLength 64) }
        integrity = [pscustomobject]@{ algorithm = 'SHA-256'; sourceBundleHash = [string](Get-MihariEvidenceValue -InputObject (Get-MihariEvidenceValue -InputObject $manifest -Name 'integrity') -Name 'sourceBundleHash'); meaning = 'Modification check only.' }
        files = @($safeFiles.ToArray())
    }
    return [pscustomobject]@{
        readOnly = $true
        capabilities = [pscustomobject]@{ capture = $false; browserLaunch = $false; trustMutation = $false; sessionMutation = $false }
        manifest = $offlineManifest
        events = @($events.Records)
        annotations = @($annotations.Records)
        findings = @($safeFindings.ToArray())
        environment = [pscustomobject]@{ snapshots = @($safeEnvironment); captureCoverage = $safeCoverage }
        originalResult = $original
        importReport = $importReport
        unknownRecordCount = $events.Unknown.Count
    }
}

function New-MihariOfflineReanalysisRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][object]$OfflineCase,
        [Parameter(Mandatory = $true)][string]$RuleVersion,
        [AllowEmptyCollection()][object[]]$Findings = @()
    )
    $context = New-MihariEvidenceShareContext -ShareProfile (Get-MihariEvidenceValue -InputObject $OfflineCase.manifest -Name 'shareProfile')
    $safeFindings = New-Object 'System.Collections.Generic.List[object]'
    foreach ($finding in @($Findings)) {
        if ($safeFindings.Count -ge 5000) { break }
        $safeFindings.Add((ConvertTo-MihariEvidenceSafeFinding -Finding $finding -Context $context))
    }
    return [pscustomobject]@{
        schemaVersion = 1
        ruleVersion = ConvertTo-MihariEvidenceSharedText -Value $RuleVersion -Context $context -MaximumLength 128
        analyzedAtUtc = [DateTime]::UtcNow.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
        originalResultPreserved = ($null -ne $OfflineCase.originalResult)
        originalResult = $OfflineCase.originalResult
        findings = @($safeFindings.ToArray())
        readOnly = $true
    }
}

function ConvertTo-MihariSafeCsvCell {
    [CmdletBinding()]
    param([AllowNull()][object]$Value)
    $text = ''
    if ($null -ne $Value) { $text = [string]$Value }
    if ([regex]::IsMatch($text, '^[\s\x00-\x20]*[=+\-@]')) { $text = "'" + $text }
    return '"' + $text.Replace('"', '""') + '"'
}

function Get-MihariEvidenceRetentionPlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$RootPath,
        [Parameter(Mandatory = $true)][DateTime]$OlderThanUtc
    )
    $root = [System.IO.Path]::GetFullPath($RootPath)
    if (-not [System.IO.Directory]::Exists($root)) { return [pscustomobject]@{ eligible = @(); refused = @(); examined = 0 } }
    Assert-MihariEvidencePathHasNoReparsePoint -Path $root
    $eligible = New-Object 'System.Collections.Generic.List[object]'
    $refused = New-Object 'System.Collections.Generic.List[object]'
    $examined = 0
    foreach ($directory in [System.IO.Directory]::GetDirectories($root)) {
        $examined++
        try {
            Assert-MihariEvidencePathHasNoReparsePoint -Path $directory
            $manifestPath = [System.IO.Path]::Combine($directory, 'manifest.json')
            if (-not [System.IO.File]::Exists($manifestPath)) { $refused.Add([pscustomobject]@{ path = $directory; reason = 'no_mihari_manifest' }); continue }
            $manifestInfo = New-Object System.IO.FileInfo($manifestPath)
            if ($manifestInfo.Length -gt 1048576) { $refused.Add([pscustomobject]@{ path = $directory; reason = 'manifest_too_large' }); continue }
            $manifest = ConvertFrom-MihariEvidenceJsonBytes -Bytes ([System.IO.File]::ReadAllBytes($manifestPath)) -Name 'manifest.json'
            if ([string](Get-MihariEvidenceValue -InputObject $manifest -Name 'format') -ne 'mihari.case-bundle' -or
                [int](Get-MihariEvidenceValue -InputObject $manifest -Name 'schemaVersion') -ne 1 -or
                [string]::IsNullOrWhiteSpace([string](Get-MihariEvidenceValue -InputObject $manifest -Name 'bundleId'))) {
                $refused.Add([pscustomobject]@{ path = $directory; reason = 'not_mihari_evidence' }); continue
            }
            $files = @{}
            foreach ($record in @(Get-MihariEvidenceValue -InputObject $manifest -Name 'files')) {
                $leaf = [string](Get-MihariEvidenceValue -InputObject $record -Name 'path')
                if (-not (Test-MihariEvidencePathSafe -Name $leaf) -or $leaf -eq 'manifest.json') { throw 'The evidence manifest contains an unsafe path.' }
                $filePath = [System.IO.Path]::Combine($directory, $leaf)
                Assert-MihariEvidencePathHasNoReparsePoint -Path $filePath
                if (-not [System.IO.File]::Exists($filePath)) { throw 'A declared evidence file is missing.' }
                $fileInfo = New-Object System.IO.FileInfo($filePath)
                if ($fileInfo.Length -gt 134217728) { throw 'A declared evidence file is too large.' }
                $files[$leaf] = [System.IO.File]::ReadAllBytes($filePath)
            }
            Test-MihariEvidenceManifestFiles -Manifest $manifest -Files $files
            $created = [DateTime]::MinValue
            if (-not [DateTime]::TryParse([string](Get-MihariEvidenceValue -InputObject $manifest -Name 'createdAtUtc'), [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$created)) {
                $refused.Add([pscustomobject]@{ path = $directory; reason = 'invalid_created_time' }); continue
            }
            $unexpected = $false
            foreach ($item in [System.IO.Directory]::GetFileSystemEntries($directory)) {
                Assert-MihariEvidencePathHasNoReparsePoint -Path $item
                if ([System.IO.Directory]::Exists($item)) { $unexpected = $true; break }
                $leaf = [System.IO.Path]::GetFileName($item)
                if (-not (Test-MihariEvidencePathSafe -Name $leaf) -or ($leaf -ne 'manifest.json' -and -not $files.ContainsKey($leaf))) { $unexpected = $true; break }
            }
            if ($unexpected) { $refused.Add([pscustomobject]@{ path = $directory; reason = 'unexpected_or_linked_content' }); continue }
            if ($created.ToUniversalTime() -lt $OlderThanUtc.ToUniversalTime()) {
                $eligible.Add([pscustomobject]@{ path = $directory; bundleId = [string](Get-MihariEvidenceValue -InputObject $manifest -Name 'bundleId'); createdAtUtc = $created.ToUniversalTime().ToString('o', [Globalization.CultureInfo]::InvariantCulture) })
            }
        }
        catch {
            $refused.Add([pscustomobject]@{ path = $directory; reason = 'ownership_or_manifest_unverified' })
        }
    }
    return [pscustomobject]@{ eligible = @($eligible.ToArray()); refused = @($refused.ToArray()); examined = $examined; deleteRequiresConfirmation = $true }
}

function Invoke-MihariEvidenceRetentionCleanup {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$RootPath,
        [Parameter(Mandatory = $true)][DateTime]$OlderThanUtc,
        [Parameter(Mandatory = $true)][switch]$ConfirmDeletion
    )
    if (-not $ConfirmDeletion) { throw 'Evidence retention cleanup requires explicit confirmation.' }
    $plan = Get-MihariEvidenceRetentionPlan -RootPath $RootPath -OlderThanUtc $OlderThanUtc
    $deleted = New-Object 'System.Collections.Generic.List[string]'
    $refused = New-Object 'System.Collections.Generic.List[object]'
    foreach ($item in $plan.eligible) {
        try {
            Assert-MihariEvidencePathHasNoReparsePoint -Path $item.path
            [System.IO.Directory]::Delete([string]$item.path, $true)
            $deleted.Add([string]$item.path)
        }
        catch {
            $refused.Add([pscustomobject]@{ path = [string]$item.path; reason = 'delete_failed_or_path_changed' })
        }
    }
    foreach ($item in $plan.refused) { $refused.Add($item) }
    return [pscustomobject]@{ deleted = @($deleted.ToArray()); refused = @($refused.ToArray()); examined = $plan.examined }
}

function New-MihariDistributionManifest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$RootPath,
        [Parameter(Mandatory = $true)][string]$OutputPath,
        [string]$ApplicationRevision = 'unknown',
        [string]$CommitId = 'unknown'
    )
    $root = [System.IO.Path]::GetFullPath($RootPath).TrimEnd([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
    if (-not [System.IO.Directory]::Exists($root)) { throw 'The distribution root does not exist.' }
    Assert-MihariEvidencePathHasNoReparsePoint -Path $root
    $output = [System.IO.Path]::GetFullPath($OutputPath)
    $rootPrefix = $root + [System.IO.Path]::DirectorySeparatorChar
    if (-not $output.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) { throw 'The distribution manifest must be written inside the distribution root.' }
    $outputRelative = $output.Substring($rootPrefix.Length).Replace('\', '/')
    if (-not (Test-MihariEvidenceRelativePath -Name $outputRelative)) { throw 'The distribution manifest path is not safe.' }
    $records = New-Object 'System.Collections.Generic.List[object]'
    $pending = New-Object 'System.Collections.Generic.Stack[string]'
    $pending.Push($root)
    while ($pending.Count -gt 0) {
        $directory = $pending.Pop()
        Assert-MihariEvidencePathHasNoReparsePoint -Path $directory
        foreach ($entryPath in [System.IO.Directory]::GetFileSystemEntries($directory)) {
            Assert-MihariEvidencePathHasNoReparsePoint -Path $entryPath
            $attributes = [System.IO.File]::GetAttributes($entryPath)
            if (($attributes -band [System.IO.FileAttributes]::Directory) -ne 0) { $pending.Push($entryPath); continue }
            $relative = $entryPath.Substring($rootPrefix.Length).Replace('\', '/')
            if ($relative -eq $outputRelative) { continue }
            if ($relative -match '(?i)(\.pfx$|\.key$|private.?key|debugger|browser.?profile|control.?secret)') { throw ('A sensitive artifact is present in the distribution tree: {0}' -f $relative) }
            $info = New-Object System.IO.FileInfo($entryPath)
            if (-not (Test-MihariEvidenceRelativePath -Name $relative)) { throw ('An unsafe distribution path was found: {0}' -f $relative) }
            $records.Add([pscustomobject]@{ path = $relative; bytes = [long]$info.Length; sha256 = (Get-MihariEvidenceFileSha256 -Path $entryPath) })
        }
    }
    $manifest = [pscustomobject]@{
        format = 'mihari.distribution-manifest'
        schemaVersion = 1
        applicationRevision = $ApplicationRevision
        commitId = $CommitId
        algorithm = 'SHA-256'
        generatedAtUtc = [DateTime]::UtcNow.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
        files = @($records.ToArray() | Sort-Object -Property path)
        statement = 'Hashes detect file modification. Authenticity requires a separately verified enterprise signing identity.'
    }
    $parent = [System.IO.Path]::GetDirectoryName($output)
    [void][System.IO.Directory]::CreateDirectory($parent)
    Assert-MihariEvidencePathHasNoReparsePoint -Path $parent
    [System.IO.File]::WriteAllBytes($output, (ConvertTo-MihariEvidenceJsonBytes -Value $manifest))
    return $manifest
}

function Test-MihariDistributionManifest {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$RootPath, [Parameter(Mandatory = $true)][string]$ManifestPath)
    $root = [System.IO.Path]::GetFullPath($RootPath).TrimEnd([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
    $manifestFull = [System.IO.Path]::GetFullPath($ManifestPath)
    Assert-MihariEvidencePathHasNoReparsePoint -Path $root
    Assert-MihariEvidencePathHasNoReparsePoint -Path $manifestFull
    $manifest = ConvertFrom-MihariEvidenceJsonBytes -Bytes ([System.IO.File]::ReadAllBytes($manifestFull)) -Name 'distribution manifest'
    if ([string](Get-MihariEvidenceValue -InputObject $manifest -Name 'format') -ne 'mihari.distribution-manifest' -or
        [int](Get-MihariEvidenceValue -InputObject $manifest -Name 'schemaVersion') -ne 1 -or
        [string](Get-MihariEvidenceValue -InputObject $manifest -Name 'algorithm') -ne 'SHA-256') {
        throw 'The distribution manifest format is unsupported.'
    }
    $errors = New-Object 'System.Collections.Generic.List[string]'
    foreach ($record in @(Get-MihariEvidenceValue -InputObject $manifest -Name 'files')) {
        $relative = [string](Get-MihariEvidenceValue -InputObject $record -Name 'path')
        if (-not (Test-MihariEvidenceRelativePath -Name $relative)) { $errors.Add('unsafe_path'); continue }
        $path = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($root, $relative.Replace('/', [System.IO.Path]::DirectorySeparatorChar)))
        $prefix = $root + [System.IO.Path]::DirectorySeparatorChar
        if (-not $path.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { $errors.Add('path_escape'); continue }
        try { Assert-MihariEvidencePathHasNoReparsePoint -Path $path }
        catch { $errors.Add('reparse_point'); continue }
        if (-not [System.IO.File]::Exists($path)) { $errors.Add('missing_file'); continue }
        $info = New-Object System.IO.FileInfo($path)
        if ($info.Length -ne [long](Get-MihariEvidenceValue -InputObject $record -Name 'bytes') -or
            -not [string]::Equals([string](Get-MihariEvidenceValue -InputObject $record -Name 'sha256'), (Get-MihariEvidenceFileSha256 -Path $path), [StringComparison]::OrdinalIgnoreCase)) {
            $errors.Add('hash_or_length_mismatch')
        }
    }
    return [pscustomobject]@{ valid = ($errors.Count -eq 0); checkedFiles = @($manifest.files).Count; errors = @($errors.ToArray()); authenticityVerified = $false; manifest = $manifest }
}
