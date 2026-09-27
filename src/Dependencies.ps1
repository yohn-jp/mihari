# Dependency projections and vendor-neutral policy candidates. This module
# consumes safe canonical events; it never rewrites facts or infers a request
# identity from a URL and timestamp.

function Get-MihariDependencyValue {
    param(
        [AllowNull()][object] $InputObject,
        [Parameter(Mandatory = $true)][string[]] $Names,
        [switch] $NoEnumerate
    )

    if ($null -eq $InputObject) { return $null }
    foreach ($name in $Names) {
        if ($InputObject -is [System.Collections.IDictionary]) {
            foreach ($key in $InputObject.Keys) {
                if ([string]::Equals([string]$key, $name, [StringComparison]::OrdinalIgnoreCase)) {
                    if ($NoEnumerate) { return ,($InputObject[$key]) }
                    return $InputObject[$key]
                }
            }
        }
        else {
            $property = $InputObject.PSObject.Properties[$name]
            if ($null -ne $property) {
                if ($NoEnumerate) { return ,($property.Value) }
                return $property.Value
            }
        }
    }
    return $null
}

function New-MihariOrdinalHashtable {
    return [System.Collections.Hashtable]::new([System.StringComparer]::Ordinal)
}

function ConvertTo-MihariDependencySafeText {
    param(
        [AllowNull()][object] $Value,
        [ValidateRange(1, 8192)][int] $MaximumLength = 512
    )

    if ($null -eq $Value -or $Value -is [System.Collections.IDictionary] -or $Value -is [System.Array]) { return $null }
    $text = [regex]::Replace([string]$Value, '[\x00-\x1f\x7f]', ' ').Trim()
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
    if ($text.Length -gt $MaximumLength) { $text = $text.Substring(0, $MaximumLength) }
    if ($text.Length -eq 0) { return $null }
    return $text
}

function ConvertTo-MihariDependencyHost {
    param([AllowNull()][object] $Value)

    $hostText = ConvertTo-MihariDependencySafeText -Value $Value -MaximumLength 512
    if ($null -eq $hostText) { return $null }
    $hostText = $hostText.Trim()
    if ($hostText -match '^[a-zA-Z][a-zA-Z0-9+.-]*://') {
        $uri = $null
        if (-not [Uri]::TryCreate($hostText, [UriKind]::Absolute, [ref]$uri)) { return $null }
        $hostText = [string]$uri.IdnHost
    }
    if ($hostText.StartsWith('[') -and $hostText.EndsWith(']')) { $hostText = $hostText.Substring(1, $hostText.Length - 2) }
    $hostText = $hostText.TrimEnd('.').ToLowerInvariant()
    if ($hostText.Length -eq 0 -or $hostText.Contains('@') -or $hostText.Contains('/') -or $hostText.Contains('?') -or $hostText.Contains('#')) { return $null }
    $address = $null
    if ([System.Net.IPAddress]::TryParse($hostText, [ref]$address)) { return $address.ToString().ToLowerInvariant() }
    try { return ([Globalization.IdnMapping]::new()).GetAscii($hostText).ToLowerInvariant() }
    catch { return $null }
}

function ConvertTo-MihariDependencyPath {
    param([AllowNull()][object] $Value)

    $pathText = ConvertTo-MihariDependencySafeText -Value $Value -MaximumLength 4096
    if ($null -eq $pathText) { return $null }
    $pathText = $pathText.Trim()
    if ($pathText -match '^[a-zA-Z][a-zA-Z0-9+.-]*://') {
        $uri = $null
        if ([Uri]::TryCreate($pathText, [UriKind]::Absolute, [ref]$uri)) {
            $pathText = $uri.GetComponents([UriComponents]::Path, [UriFormat]::UriEscaped)
            if (-not $pathText.StartsWith('/')) { $pathText = '/' + $pathText }
            if ([string]::IsNullOrEmpty($pathText)) { $pathText = '/' }
            $pathText += $uri.Query
        }
        else {
            $match = [regex]::Match($pathText, '^[a-zA-Z][a-zA-Z0-9+.-]*://[^/?#]*(?<tail>/[^?#]*)?(?<query>\?[^#]*)?')
            if (-not $match.Success) { return $null }
            $pathText = [string]$match.Groups['tail'].Value + [string]$match.Groups['query'].Value
        }
    }
    $fragment = $pathText.IndexOf('#')
    if ($fragment -ge 0) { $pathText = $pathText.Substring(0, $fragment) }
    if ($pathText -eq '*' -or $pathText.Length -eq 0) { return $pathText }
    if (-not $pathText.StartsWith('/')) { return $null }
    $queryIndex = $pathText.IndexOf('?')
    if ($queryIndex -lt 0) { return $pathText }
    $basePath = $pathText.Substring(0, $queryIndex)
    $query = $pathText.Substring($queryIndex + 1)
    if ($query.Length -eq 0) { return $basePath + '?[REDACTED]' }
    $parts = New-Object 'System.Collections.Generic.List[string]'
    foreach ($part in $query.Split([char]'&')) {
        $equals = $part.IndexOf('=')
        if ($equals -lt 0) { $key = 'value' }
        else { $key = $part.Substring(0, $equals) }
        $key = [regex]::Replace($key, '[^A-Za-z0-9_.~-]', '')
        if ($key.Length -eq 0) { $key = 'value' }
        if ($key.Length -gt 64) { $key = $key.Substring(0, 64) }
        $parts.Add($key + '=[REDACTED]')
    }
    return $basePath + '?' + [string]::Join('&', $parts.ToArray())
}

function ConvertTo-MihariDependencyTarget {
    param([Parameter(Mandatory = $true)][object] $Event)

    $data = Get-MihariDependencyValue -InputObject $Event -Names @('data')
    $hostValue = Get-MihariDependencyValue -InputObject $data -Names @('destinationHost', 'hostname', 'targetHost', 'host')
    if ($null -eq $hostValue) { $hostValue = Get-MihariDependencyValue -InputObject $Event -Names @('destinationHost', 'hostname', 'targetHost', 'host') }
    $schemeValue = Get-MihariDependencyValue -InputObject $data -Names @('scheme', 'urlScheme')
    if ($null -eq $schemeValue) { $schemeValue = Get-MihariDependencyValue -InputObject $Event -Names @('scheme', 'urlScheme') }
    $portValue = Get-MihariDependencyValue -InputObject $data -Names @('destinationPort', 'targetPort', 'port')
    if ($null -eq $portValue) { $portValue = Get-MihariDependencyValue -InputObject $Event -Names @('destinationPort', 'targetPort', 'port') }
    $pathValue = Get-MihariDependencyValue -InputObject $data -Names @('path', 'urlPath', 'requestPath')
    if ($null -eq $pathValue) { $pathValue = Get-MihariDependencyValue -InputObject $Event -Names @('path', 'urlPath', 'requestPath') }
    $urlValue = Get-MihariDependencyValue -InputObject $data -Names @('url', 'requestUrl', 'targetUrl')
    if ($null -eq $urlValue) { $urlValue = Get-MihariDependencyValue -InputObject $Event -Names @('url', 'requestUrl', 'targetUrl') }

    $url = $null
    if ($null -ne $urlValue) { [void][Uri]::TryCreate([string]$urlValue, [UriKind]::Absolute, [ref]$url) }
    if ($null -ne $url) {
        if ($null -eq $hostValue) { $hostValue = $url.IdnHost }
        if ($null -eq $schemeValue) { $schemeValue = $url.Scheme }
        if ($null -eq $portValue) { $portValue = $url.Port }
        if ($null -eq $pathValue) { $pathValue = $url.AbsolutePath + $url.Query }
    }

    $targetHost = ConvertTo-MihariDependencyHost -Value $hostValue
    $scheme = ConvertTo-MihariDependencySafeText -Value $schemeValue -MaximumLength 16
    if ($null -ne $scheme) {
        $scheme = $scheme.ToLowerInvariant()
        if ($scheme -notin @('http', 'https')) { $scheme = $null }
    }
    $port = $null
    if ($null -ne $portValue) {
        $portNumber = 0
        if ([int]::TryParse([string]$portValue, [Globalization.NumberStyles]::Integer, [Globalization.CultureInfo]::InvariantCulture, [ref]$portNumber) -and $portNumber -ge 1 -and $portNumber -le 65535) {
            $port = $portNumber
        }
    }
    if ($null -eq $port -and $null -ne $scheme) {
        if ($scheme -eq 'http') { $port = 80 }
        elseif ($scheme -eq 'https') { $port = 443 }
    }
    $path = ConvertTo-MihariDependencyPath -Value $pathValue
    return [pscustomobject]@{ Scheme = $scheme; Host = $targetHost; Port = $port; Path = $path; QueryObserved = ($null -ne $path -and $path.Contains('?')) }
}

function ConvertTo-MihariDependencyEvent {
    param(
        [Parameter(Mandatory = $true)][object] $Event,
        [Parameter(Mandatory = $true)][int] $Index
    )

    $sessionId = ConvertTo-MihariDependencySafeText -Value (Get-MihariDependencyValue -InputObject $Event -Names @('sessionId')) -MaximumLength 128
    $eventId = ConvertTo-MihariDependencySafeText -Value (Get-MihariDependencyValue -InputObject $Event -Names @('eventId')) -MaximumLength 128
    if ($null -eq $sessionId -or $null -eq $eventId) { return $null }
    $requestId = ConvertTo-MihariDependencySafeText -Value (Get-MihariDependencyValue -InputObject $Event -Names @('requestId')) -MaximumLength 128
    $connectionId = ConvertTo-MihariDependencySafeText -Value (Get-MihariDependencyValue -InputObject $Event -Names @('connectionId')) -MaximumLength 128
    $source = ConvertTo-MihariDependencySafeText -Value (Get-MihariDependencyValue -InputObject $Event -Names @('source')) -MaximumLength 32
    if ($source -notin @('proxy', 'browser', 'windows', 'operator', 'import')) { $source = 'unknown' }
    $sourceIdentity = ConvertTo-MihariDependencySafeText -Value (Get-MihariDependencyValue -InputObject $Event -Names @('sourceIdentity')) -MaximumLength 128
    $redirectOccurrence = ConvertTo-MihariDependencySafeText -Value (Get-MihariDependencyValue -InputObject $Event -Names @('redirectOccurrence')) -MaximumLength 64
    $identityType = 'event'
    if ($null -ne $requestId) {
        if ($source -eq 'browser') {
            if ($null -ne $sourceIdentity) {
                $identityType = 'request'
                $requestKey = $sessionId + ':browser:' + $sourceIdentity + ':' + $requestId
                if ($null -ne $redirectOccurrence) { $requestKey += ':redirect:' + $redirectOccurrence }
            }
            else { $requestKey = $sessionId + ':browser-event:' + $eventId }
        }
        else { $identityType = 'request'; $requestKey = $sessionId + ':' + $requestId }
    }
    elseif ($null -ne $connectionId) {
        $methodValue = Get-MihariDependencyValue -InputObject (Get-MihariDependencyValue -InputObject $Event -Names @('data')) -Names @('method')
        $pathValue = Get-MihariDependencyValue -InputObject (Get-MihariDependencyValue -InputObject $Event -Names @('data')) -Names @('path', 'urlPath', 'requestPath')
        if ($null -ne $methodValue -or $null -ne $pathValue) {
            # An HTTP attempt without a request ID is kept distinct per event.
            $requestKey = $sessionId + ':event:' + $eventId
        }
        else {
            $identityType = 'connection'
            $requestKey = $sessionId + ':connection:' + $connectionId
        }
    }
    else { $requestKey = $sessionId + ':event:' + $eventId }

    $target = ConvertTo-MihariDependencyTarget -Event $Event
    $timestampText = ConvertTo-MihariDependencySafeText -Value (Get-MihariDependencyValue -InputObject $Event -Names @('timestamp', 'timestampUtc')) -MaximumLength 64
    $time = [DateTimeOffset]::MinValue
    $hasTime = ($null -ne $timestampText -and [DateTimeOffset]::TryParse($timestampText, [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal, [ref]$time))
    $method = ConvertTo-MihariDependencySafeText -Value (Get-MihariDependencyValue -InputObject (Get-MihariDependencyValue -InputObject $Event -Names @('data')) -Names @('method')) -MaximumLength 32
    if ($null -ne $method -and $method -notmatch '^[!#$%&''*+.^_`|~0-9A-Za-z-]+$') { $method = $null }
    if ($null -ne $method) { $method = $method.ToUpperInvariant() }
    $stage = ConvertTo-MihariDependencySafeText -Value (Get-MihariDependencyValue -InputObject $Event -Names @('stage')) -MaximumLength 64
    $outcome = ConvertTo-MihariDependencySafeText -Value (Get-MihariDependencyValue -InputObject $Event -Names @('outcome')) -MaximumLength 32
    $statusValue = Get-MihariDependencyValue -InputObject (Get-MihariDependencyValue -InputObject $Event -Names @('data')) -Names @('statusCode', 'httpStatusCode', 'responseStatusCode')
    $statusCode = $null
    $statusNumber = 0
    if ($null -ne $statusValue -and [int]::TryParse([string]$statusValue, [ref]$statusNumber) -and $statusNumber -ge 100 -and $statusNumber -le 599) { $statusCode = $statusNumber }
    $proxyStatusValue = Get-MihariDependencyValue -InputObject (Get-MihariDependencyValue -InputObject $Event -Names @('data')) -Names @('proxyStatus', 'proxyStatusCode')
    $proxyStatus = $null
    $proxyStatusNumber = 0
    if ($null -ne $proxyStatusValue -and [int]::TryParse([string]$proxyStatusValue, [ref]$proxyStatusNumber) -and $proxyStatusNumber -ge 100 -and $proxyStatusNumber -le 599) { $proxyStatus = $proxyStatusNumber }
    $caseId = ConvertTo-MihariDependencySafeText -Value (Get-MihariDependencyValue -InputObject $Event -Names @('caseId')) -MaximumLength 128
    $trialId = ConvertTo-MihariDependencySafeText -Value (Get-MihariDependencyValue -InputObject $Event -Names @('trialId')) -MaximumLength 128
    $sourceVersion = ConvertTo-MihariDependencySafeText -Value (Get-MihariDependencyValue -InputObject $Event -Names @('sourceVersion')) -MaximumLength 64
    $transportLeg = ConvertTo-MihariDependencySafeText -Value (Get-MihariDependencyValue -InputObject $Event -Names @('transportLeg')) -MaximumLength 32
    $sequenceValue = Get-MihariDependencyValue -InputObject $Event -Names @('sequence')
    $sequence = $null
    $sequenceNumber = 0L
    if ($null -ne $sequenceValue -and [long]::TryParse([string]$sequenceValue, [ref]$sequenceNumber) -and $sequenceNumber -gt 0) { $sequence = $sequenceNumber }
    return [pscustomobject]@{
        Index = $Index; SessionId = $sessionId; EventId = $eventId; RequestId = $requestId; ConnectionId = $connectionId
        RequestKey = $requestKey; IdentityType = $identityType; Source = $source; SourceIdentity = $sourceIdentity
        SourceVersion = $sourceVersion; RedirectOccurrence = $redirectOccurrence; TransportLeg = $transportLeg
        CaseId = $caseId; TrialId = $trialId; Target = $target; Method = $method; Stage = $stage; Outcome = $outcome
        StatusCode = $statusCode; ProxyStatus = $proxyStatus; Timestamp = $timestampText; Time = $time; HasTime = $hasTime
        Sequence = $sequence
    }
}

function ConvertTo-MihariDependencyUtc {
    param([AllowNull()][object] $Value)
    if ($null -eq $Value) { return $null }
    $time = [DateTimeOffset]::MinValue
    if ([DateTimeOffset]::TryParse([string]$Value, [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal, [ref]$time)) {
        return $time.ToUniversalTime()
    }
    return $null
}

function Get-MihariDependencyTrialAssignment {
    param(
        [Parameter(Mandatory = $true)][object] $Events,
        [object[]] $Trials = @()
    )

    $directTrialIds = @($Events | Where-Object { $_.TrialId } | Select-Object -ExpandProperty TrialId -Unique)
    $directCaseIds = @($Events | Where-Object { $_.CaseId } | Select-Object -ExpandProperty CaseId -Unique)
    if ($directTrialIds.Count -eq 1) {
        $trial = @($Trials | Where-Object { [string]$_.trialId -eq [string]$directTrialIds[0] } | Select-Object -First 1)
        $sessionIds = @($Events | Select-Object -ExpandProperty SessionId -Unique)
        if ($sessionIds.Count -ne 1 -or ($trial.Count -gt 0 -and [string]$trial[0].sessionId -ne [string]$sessionIds[0])) {
            return [pscustomobject]@{ TrialId = $null; CaseId = $null; Attribution = 'ambiguous'; AmbiguousTrialIds = @($directTrialIds) }
        }
        $caseId = $null
        if ($directCaseIds.Count -eq 1) {
            $caseId = [string]$directCaseIds[0]
            if ($trial.Count -gt 0 -and [string]$trial[0].caseId -ne $caseId) { $caseId = $null }
        }
        elseif ($directCaseIds.Count -eq 0 -and $trial.Count -gt 0) { $caseId = [string]$trial[0].caseId }
        return [pscustomobject]@{ TrialId = [string]$directTrialIds[0]; CaseId = $caseId; Attribution = 'direct'; AmbiguousTrialIds = @() }
    }
    if ($directTrialIds.Count -gt 1 -or $directCaseIds.Count -gt 1) {
        return [pscustomobject]@{ TrialId = $null; CaseId = $null; Attribution = 'ambiguous'; AmbiguousTrialIds = @($directTrialIds) }
    }
    if ($directCaseIds.Count -eq 1) {
        return [pscustomobject]@{ TrialId = $null; CaseId = [string]$directCaseIds[0]; Attribution = 'direct'; AmbiguousTrialIds = @() }
    }

    $sessionIds = @($Events | Select-Object -ExpandProperty SessionId -Unique)
    if ($sessionIds.Count -ne 1) { return [pscustomobject]@{ TrialId = $null; CaseId = $null; Attribution = 'unknown'; AmbiguousTrialIds = @() } }
    $eventTimes = @($Events | Where-Object { $_.HasTime } | ForEach-Object { $_.Time })
    if ($eventTimes.Count -eq 0) { return [pscustomobject]@{ TrialId = $null; CaseId = $null; Attribution = 'unknown'; AmbiguousTrialIds = @() } }
    $first = ($eventTimes | Sort-Object | Select-Object -First 1)
    $last = ($eventTimes | Sort-Object -Descending | Select-Object -First 1)
    $candidates = New-Object 'System.Collections.Generic.List[object]'
    foreach ($trial in $Trials) {
        if ([string]$trial.sessionId -ne [string]$sessionIds[0]) { continue }
        $start = ConvertTo-MihariDependencyUtc -Value $trial.startedAtUtc
        $end = ConvertTo-MihariDependencyUtc -Value $trial.endedAtUtc
        if ($null -eq $start) { continue }
        if ($null -eq $end -and [string]$trial.status -eq 'running') { $end = [DateTimeOffset]::UtcNow }
        if ($null -eq $end) { continue }
        if ($first -ge $start -and $last -le $end) { $candidates.Add($trial) }
    }
    if ($candidates.Count -eq 1) {
        return [pscustomobject]@{ TrialId = [string]$candidates[0].trialId; CaseId = [string]$candidates[0].caseId; Attribution = 'heuristic_time_window'; AmbiguousTrialIds = @() }
    }
    if ($candidates.Count -gt 1) {
        return [pscustomobject]@{ TrialId = $null; CaseId = $null; Attribution = 'ambiguous'; AmbiguousTrialIds = @($candidates.ToArray() | ForEach-Object { [string]$_.trialId }) }
    }
    return [pscustomobject]@{ TrialId = $null; CaseId = $null; Attribution = 'unknown'; AmbiguousTrialIds = @() }
}

function Get-MihariDependencyOperationAssignment {
    param(
        [Parameter(Mandatory = $true)][object[]] $Events,
        [Parameter(Mandatory = $true)][string] $TrialId,
        [object[]] $OperationIntervals = @()
    )

    $candidateIds = New-Object 'System.Collections.Generic.List[string]'
    foreach ($event in $Events) {
        if (-not $event.HasTime) { continue }
        foreach ($interval in $OperationIntervals) {
            if ([string]$interval.TrialId -eq $TrialId -and $event.Time -ge $interval.Start -and $event.Time -le $interval.End) {
                if (-not $candidateIds.Contains([string]$interval.OperationId)) { $candidateIds.Add([string]$interval.OperationId) }
            }
        }
    }
    if ($candidateIds.Count -eq 1) {
        $interval = @($OperationIntervals | Where-Object { [string]$_.OperationId -eq [string]$candidateIds[0] } | Select-Object -First 1)
        return [pscustomobject]@{ OperationId = [string]$candidateIds[0]; OperationLabel = [string]$interval[0].Label; Attribution = 'heuristic_marker_window'; MarkerIds = @($interval[0].MarkerIds) }
    }
    if ($candidateIds.Count -gt 1) {
        return [pscustomobject]@{ OperationId = $null; OperationLabel = $null; Attribution = 'ambiguous'; MarkerIds = @() }
    }
    return [pscustomobject]@{ OperationId = $null; OperationLabel = $null; Attribution = 'unknown'; MarkerIds = @() }
}

function Get-MihariDependencyOperationIntervals {
    param([object[]] $Markers = @())

    $intervals = New-Object 'System.Collections.Generic.List[object]'
    $groups = New-MihariOrdinalHashtable
    foreach ($marker in $Markers) {
        $boundary = [string](Get-MihariDependencyValue -InputObject $marker -Names @('boundary', 'kind'))
        if ($boundary -notin @('start', 'end')) { continue }
        $trialId = ConvertTo-MihariDependencySafeText -Value (Get-MihariDependencyValue -InputObject $marker -Names @('trialId')) -MaximumLength 128
        $label = ConvertTo-MihariDependencySafeText -Value (Get-MihariDependencyValue -InputObject $marker -Names @('label')) -MaximumLength 160
        $markerId = ConvertTo-MihariDependencySafeText -Value (Get-MihariDependencyValue -InputObject $marker -Names @('markerId')) -MaximumLength 128
        $timeText = Get-MihariDependencyValue -InputObject $marker -Names @('timestampUtc', 'timestamp')
        $time = ConvertTo-MihariDependencyUtc -Value $timeText
        if ($null -eq $trialId -or $null -eq $label -or $null -eq $markerId -or $null -eq $time) { continue }
        $key = $trialId + [char]0 + $label
        if (-not $groups.ContainsKey($key)) { $groups[$key] = New-Object 'System.Collections.Generic.List[object]' }
        $groups[$key].Add([pscustomobject]@{ Boundary = $boundary; TrialId = $trialId; Label = $label; MarkerId = $markerId; Time = $time })
    }
    foreach ($key in @($groups.Keys | Sort-Object)) {
        $ordered = @($groups[$key].ToArray() | Sort-Object -Property Time, MarkerId)
        $open = $null
        foreach ($marker in $ordered) {
            if ($marker.Boundary -eq 'start') {
                if ($null -eq $open) { $open = $marker }
                else { $open = $null } # overlapping repeated labels stay unpaired and cannot imply an operation.
                continue
            }
            if ($null -ne $open -and $marker.Time -ge $open.Time) {
                $intervalKey = $open.TrialId + [char]0 + $open.Label + [char]0 + $open.MarkerId + [char]0 + $marker.MarkerId
                $intervals.Add([pscustomobject]@{
                    OperationId = 'op-' + (Get-MihariDependencyHash -Text $intervalKey).Substring(0, 24)
                    TrialId = $open.TrialId; Label = $open.Label; Start = $open.Time; End = $marker.Time
                    MarkerIds = @($open.MarkerId, $marker.MarkerId)
                })
            }
            $open = $null
        }
    }
    return @($intervals.ToArray())
}

function Get-MihariDependencyHash {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string] $Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
        return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    }
    finally { $sha.Dispose() }
}

function Get-MihariDependencyPage {
    param(
        [Parameter(Mandatory = $true)][object[]] $Items,
        [Parameter(Mandatory = $true)][ValidateRange(1, 200)][int] $MaximumItems,
        [Parameter(Mandatory = $true)][ValidateSet('dependencies', 'policy', 'proposals')][string] $Kind,
        [Parameter(Mandatory = $true)][string] $Revision,
        [string] $Cursor
    )

    $offset = 0
    if (-not [string]::IsNullOrWhiteSpace($Cursor)) {
        $escapedKind = [regex]::Escape($Kind)
        if ($Cursor -notmatch ('^' + $escapedKind + '-v1:(?<revision>[0-9a-f]{64}):(?<offset>\d+)$')) {
            throw 'The dependency query cursor is invalid.'
        }
        if (-not [string]::Equals([string]$Matches.revision, $Revision, [StringComparison]::Ordinal)) {
            throw 'The dependency query cursor was invalidated because its source revision changed.'
        }
        $offset = [int]$Matches.offset
        if ($offset -lt 0 -or $offset -gt $Items.Count) { throw 'The dependency query cursor offset is invalid.' }
    }
    $pageItems = @($Items | Select-Object -Skip $offset -First $MaximumItems)
    $nextCursor = $null
    if (($offset + $pageItems.Count) -lt $Items.Count) {
        $nextCursor = $Kind + '-v1:' + $Revision + ':' + ($offset + $pageItems.Count).ToString([Globalization.CultureInfo]::InvariantCulture)
    }
    return [pscustomobject]@{ Items = $pageItems; NextCursor = $nextCursor; Revision = $Revision; ScopeTotal = [int]$Items.Count }
}

function Get-MihariDependencyTargetSummary {
    param([Parameter(Mandatory = $true)][object[]] $Events)

    $targets = New-Object 'System.Collections.Generic.List[object]'
    foreach ($event in $Events) {
        $target = $event.Target
        if ($null -eq $target.Host -and $null -eq $target.Path) { continue }
        $existing = @($targets.ToArray() | Where-Object {
                [string]::Equals([string]$_.Host, [string]$target.Host, [StringComparison]::Ordinal) -and
                [string]::Equals([string]$_.Scheme, [string]$target.Scheme, [StringComparison]::Ordinal) -and
                [string]::Equals([string]$_.Port, [string]$target.Port, [StringComparison]::Ordinal) -and
                [string]::Equals([string]$_.Path, [string]$target.Path, [StringComparison]::Ordinal)
            } | Select-Object -First 1)
        if ($existing.Count -eq 0) { $targets.Add($target) }
    }
    $hosts = @($targets.ToArray() | ForEach-Object { [string]$_.Host } | Where-Object { $_ } | Sort-Object -Unique)
    $schemes = @($targets.ToArray() | ForEach-Object { [string]$_.Scheme } | Where-Object { $_ } | Sort-Object -Unique)
    $ports = @($targets.ToArray() | ForEach-Object { if ($null -ne $_.Port) { [string]$_.Port } } | Where-Object { $_ } | Sort-Object -Unique)
    $paths = @($targets.ToArray() | ForEach-Object { if ($null -ne $_.Path) { [string]$_.Path } } | Sort-Object -Unique)
    $conflict = ($hosts.Count -gt 1 -or $schemes.Count -gt 1 -or $ports.Count -gt 1 -or $paths.Count -gt 1)
    $resultTarget = $null
    if ($targets.Count -eq 1 -or -not $conflict) {
        $resultTarget = [pscustomobject]@{
            Scheme = $(if ($schemes.Count -eq 1) { $schemes[0] } else { $null })
            Host = $(if ($hosts.Count -eq 1) { $hosts[0] } else { $null })
            Port = $(if ($ports.Count -eq 1) { [int]$ports[0] } else { $null })
            Path = $(if ($paths.Count -eq 1) { $paths[0] } else { $null })
            QueryObserved = @($targets.ToArray() | Where-Object { $_.QueryObserved }).Count -gt 0
        }
    }
    return [pscustomobject]@{ Target = $resultTarget; Conflict = $conflict; CandidateCount = $targets.Count }
}

function Get-MihariDependencyAttemptSummary {
    param(
        [Parameter(Mandatory = $true)][object[]] $Events,
        [Parameter(Mandatory = $true)][object] $TargetSummary,
        [Parameter(Mandatory = $true)][object] $TrialAssignment,
        [Parameter(Mandatory = $true)][object] $OperationAssignment
    )

    $ordered = @($Events | Sort-Object -Property @{ Expression = { if ($null -ne $_.Sequence) { [long]$_.Sequence } else { [long]$_.Index } } })
    $timestamps = @($ordered | Where-Object { $_.HasTime } | ForEach-Object { $_.Time })
    $firstSeen = $null
    $lastSeen = $null
    if ($timestamps.Count -gt 0) {
        $firstSeen = ($timestamps | Sort-Object | Select-Object -First 1).ToString('o', [Globalization.CultureInfo]::InvariantCulture)
        $lastSeen = ($timestamps | Sort-Object -Descending | Select-Object -First 1).ToString('o', [Globalization.CultureInfo]::InvariantCulture)
    }
    $evidence = New-Object 'System.Collections.Generic.List[object]'
    $seenEvidence = New-MihariOrdinalHashtable
    $methods = New-Object 'System.Collections.Generic.List[string]'
    $sources = New-Object 'System.Collections.Generic.List[string]'
    $stages = New-Object 'System.Collections.Generic.List[string]'
    $outcomes = New-Object 'System.Collections.Generic.List[string]'
    $statuses = New-Object 'System.Collections.Generic.List[int]'
    $proxyStatuses = New-Object 'System.Collections.Generic.List[int]'
    $connectionIds = New-Object 'System.Collections.Generic.List[string]'
    $transportLegs = New-Object 'System.Collections.Generic.List[string]'
    $sourceVersions = New-Object 'System.Collections.Generic.List[string]'
    foreach ($event in $ordered) {
        $evidenceKey = $event.SessionId + [char]0 + $event.EventId
        if (-not $seenEvidence.ContainsKey($evidenceKey)) {
            $seenEvidence[$evidenceKey] = $true
            $reference = [ordered]@{ sessionId = $event.SessionId; eventId = $event.EventId }
            if ($event.RequestId) { $reference['requestId'] = $event.RequestId }
            if ($event.ConnectionId) { $reference['connectionId'] = $event.ConnectionId }
            if ($event.TransportLeg) { $reference['transportLeg'] = $event.TransportLeg }
            if ($event.Source -ne 'unknown') { $reference['source'] = $event.Source }
            $evidence.Add([pscustomobject]$reference)
        }
        if ($event.Method -and -not $methods.Contains($event.Method)) { $methods.Add($event.Method) }
        if ($event.Source -and -not $sources.Contains($event.Source)) { $sources.Add($event.Source) }
        if ($event.Stage -and -not $stages.Contains($event.Stage)) { $stages.Add($event.Stage) }
        if ($event.Outcome -and -not $outcomes.Contains($event.Outcome)) { $outcomes.Add($event.Outcome) }
        if ($null -ne $event.StatusCode -and -not $statuses.Contains([int]$event.StatusCode)) { $statuses.Add([int]$event.StatusCode) }
        if ($null -ne $event.ProxyStatus -and -not $proxyStatuses.Contains([int]$event.ProxyStatus)) { $proxyStatuses.Add([int]$event.ProxyStatus) }
        if ($event.ConnectionId -and -not $connectionIds.Contains($event.ConnectionId)) { $connectionIds.Add($event.ConnectionId) }
        if ($event.TransportLeg -and -not $transportLegs.Contains($event.TransportLeg)) { $transportLegs.Add($event.TransportLeg) }
        if ($event.SourceVersion -and -not $sourceVersions.Contains($event.SourceVersion)) { $sourceVersions.Add($event.SourceVersion) }
    }
    $httpClass = 'unknown'
    $finalStatuses = @($statuses.ToArray() | Where-Object { $_ -ge 200 })
    if ($finalStatuses.Count -gt 0) {
        $hasHttpSuccess = @($finalStatuses | Where-Object { $_ -lt 400 }).Count -gt 0
        $hasHttpError = @($finalStatuses | Where-Object { $_ -ge 400 }).Count -gt 0
        if ($hasHttpSuccess -and $hasHttpError) { $httpClass = 'mixed_responses' }
        elseif ($hasHttpSuccess) { $httpClass = 'response_2xx_3xx' }
        else { $httpClass = 'response_4xx_5xx' }
    }
    $failureOutcomes = @('failed', 'failure', 'rejected', 'unsupported', 'cancelled', 'timed_out')
    $observedFailure = @($outcomes.ToArray() | Where-Object { $_.ToLowerInvariant() -in $failureOutcomes }).Count -gt 0
    $observedOutcome = 'unknown'
    if ($httpClass -ne 'unknown') { $observedOutcome = 'http_response_observed' }
    elseif ($observedFailure) { $observedOutcome = 'failure_observed' }
    return [pscustomobject]@{
        SessionId = [string]$ordered[0].SessionId; RequestKey = [string]$ordered[0].RequestKey; IdentityType = [string]$ordered[0].IdentityType
        RequestId = $(if (@($ordered | Where-Object { $_.RequestId } | Select-Object -ExpandProperty RequestId -Unique).Count -eq 1) { [string]$ordered[0].RequestId } else { $null })
        ConnectionIds = @($connectionIds.ToArray() | Sort-Object); FirstSeenUtc = $firstSeen; LastSeenUtc = $lastSeen
        Methods = @($methods.ToArray() | Sort-Object); Sources = @($sources.ToArray() | Sort-Object)
        SourceVersions = @($sourceVersions.ToArray() | Sort-Object); Stages = @($stages.ToArray() | Sort-Object)
        ObservedFactsOutcomes = @($outcomes.ToArray() | Sort-Object); HttpStatusCodes = @($statuses.ToArray() | Sort-Object)
        ProxyStatusCodes = @($proxyStatuses.ToArray() | Sort-Object); HttpResponseClass = $httpClass
        ObservedOutcome = $observedOutcome; BusinessOutcome = 'unknown'
        ObservedFailure = $observedFailure; EvidenceReferences = @($evidence.ToArray())
        TransportLegs = @($transportLegs.ToArray()); EventCount = [int]$ordered.Count
        CaseId = $TrialAssignment.CaseId; TrialId = $TrialAssignment.TrialId; TrialAttribution = $TrialAssignment.Attribution
        AmbiguousTrialIds = @($TrialAssignment.AmbiguousTrialIds)
        OperationId = $OperationAssignment.OperationId; OperationLabel = $OperationAssignment.OperationLabel
        OperationAttribution = $OperationAssignment.Attribution; MarkerIds = @($OperationAssignment.MarkerIds)
        Target = $TargetSummary.Target; TargetConflict = [bool]$TargetSummary.Conflict
    }
}

function Get-MihariDependencyProjection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]] $Events,
        [object[]] $Trials = @(),
        [object[]] $Markers = @(),
        [AllowNull()][object] $NecessityRecords,
        [Alias('OutputDirectory', 'StoreRoot')][string] $CaseRoot,
        [ValidateRange(1, 200)][int] $MaximumItems = 200,
        [string] $Cursor
    )

    # Events must represent the complete declared session/trial scope, not the
    # current UI page. Paging below applies only after the full projection.
    if ($CaseRoot) {
        $snapshot = Get-MihariCaseStoreSnapshot -CaseRoot $CaseRoot
        if ($Trials.Count -eq 0) { $Trials = @($snapshot.Trials) }
        if ($Markers.Count -eq 0) { $Markers = @($snapshot.Markers) }
        if ($null -eq $NecessityRecords) { $NecessityRecords = $snapshot.Necessity }
    }
    if ($null -eq $NecessityRecords) { $NecessityRecords = @{} }
    $normalizedEvents = New-Object 'System.Collections.Generic.List[object]'
    $seenEventIds = New-MihariOrdinalHashtable
    $missingIdentityCount = 0
    $duplicateEventCount = 0
    $index = 0
    foreach ($event in $Events) {
        $index++
        $normalized = ConvertTo-MihariDependencyEvent -Event $event -Index $index
        if ($null -eq $normalized) { $missingIdentityCount++; continue }
        $evidenceKey = $normalized.SessionId + [char]0 + $normalized.EventId
        if ($seenEventIds.ContainsKey($evidenceKey)) { $duplicateEventCount++; continue }
        $seenEventIds[$evidenceKey] = $true
        $normalizedEvents.Add($normalized)
    }
    $attemptGroups = New-MihariOrdinalHashtable
    foreach ($event in $normalizedEvents) {
        if (-not $attemptGroups.ContainsKey($event.RequestKey)) { $attemptGroups[$event.RequestKey] = New-Object 'System.Collections.Generic.List[object]' }
        $attemptGroups[$event.RequestKey].Add($event)
    }
    $operationIntervals = Get-MihariDependencyOperationIntervals -Markers $Markers
    $attempts = New-Object 'System.Collections.Generic.List[object]'
    $targetConflictCount = 0
    $heuristicTrialCount = 0
    $ambiguousTrialCount = 0
    $heuristicOperationCount = 0
    $ambiguousOperationCount = 0
    foreach ($requestKey in @($attemptGroups.Keys | Sort-Object)) {
        $attemptEvents = @($attemptGroups[$requestKey].ToArray())
        $trialAssignment = Get-MihariDependencyTrialAssignment -Events $attemptEvents -Trials $Trials
        if ($trialAssignment.Attribution -eq 'heuristic_time_window') { $heuristicTrialCount++ }
        if ($trialAssignment.Attribution -eq 'ambiguous') { $ambiguousTrialCount++ }
        $operationAssignment = [pscustomobject]@{ OperationId = $null; OperationLabel = $null; Attribution = 'unknown'; MarkerIds = @() }
        if ($trialAssignment.TrialId) {
            $operationAssignment = Get-MihariDependencyOperationAssignment -Events $attemptEvents -TrialId ([string]$trialAssignment.TrialId) -OperationIntervals $operationIntervals
        }
        if ($operationAssignment.Attribution -eq 'heuristic_marker_window') { $heuristicOperationCount++ }
        if ($operationAssignment.Attribution -eq 'ambiguous') { $ambiguousOperationCount++ }
        $targetSummary = Get-MihariDependencyTargetSummary -Events $attemptEvents
        if ($targetSummary.Conflict) { $targetConflictCount++ }
        $attempts.Add((Get-MihariDependencyAttemptSummary -Events $attemptEvents -TargetSummary $targetSummary -TrialAssignment $trialAssignment -OperationAssignment $operationAssignment))
    }

    $dependencyGroups = New-MihariOrdinalHashtable
    foreach ($attempt in $attempts) {
        $target = $attempt.Target
        if ($null -eq $target -or $attempt.TargetConflict -or [string]::IsNullOrWhiteSpace([string]$target.Host)) { continue }
        $operationGroup = [string]$attempt.OperationId
        if ($attempt.OperationAttribution -eq 'ambiguous') { $operationGroup = 'ambiguous' }
        $sessionScope = ''
        if (-not $attempt.CaseId -and -not $attempt.TrialId) { $sessionScope = 'session:' + [string]$attempt.SessionId }
        $keyParts = @([string]$attempt.CaseId, [string]$attempt.TrialId, $sessionScope, $operationGroup,
            [string]$target.Scheme, [string]$target.Host, [string]$target.Port, [string]$target.Path)
        $key = [string]::Join([char]0, $keyParts)
        if (-not $dependencyGroups.ContainsKey($key)) { $dependencyGroups[$key] = New-Object 'System.Collections.Generic.List[object]' }
        $dependencyGroups[$key].Add($attempt)
    }

    $dependencies = New-Object 'System.Collections.Generic.List[object]'
    foreach ($key in @($dependencyGroups.Keys | Sort-Object)) {
        $items = @($dependencyGroups[$key].ToArray())
        $firstCandidate = $items[0]
        $target = $firstCandidate.Target
        $refs = New-Object 'System.Collections.Generic.List[object]'
        $seenRefs = New-MihariOrdinalHashtable
        $methods = New-Object 'System.Collections.Generic.List[string]'
        $sources = New-Object 'System.Collections.Generic.List[string]'
        $stages = New-Object 'System.Collections.Generic.List[string]'
        $statuses = New-Object 'System.Collections.Generic.List[int]'
        $proxyStatuses = New-Object 'System.Collections.Generic.List[int]'
        $requestKeys = New-Object 'System.Collections.Generic.List[string]'
        $successfulHttp = 0
        $failedHttp = 0
        $observedFailures = 0
        $unknownOutcomes = 0
        $firstSeen = $null
        $lastSeen = $null
        $trialAttributions = New-Object 'System.Collections.Generic.List[string]'
        $operationAttribution = 'unknown'
        foreach ($attempt in $items) {
            if ($attempt.RequestKey -and -not $requestKeys.Contains($attempt.RequestKey)) { $requestKeys.Add($attempt.RequestKey) }
            foreach ($reference in $attempt.EvidenceReferences) {
                $refKey = [string]$reference.sessionId + [char]0 + [string]$reference.eventId
                if (-not $seenRefs.ContainsKey($refKey)) { $seenRefs[$refKey] = $true; $refs.Add($reference) }
            }
            foreach ($value in $attempt.Methods) { if (-not $methods.Contains([string]$value)) { $methods.Add([string]$value) } }
            foreach ($value in $attempt.Sources) { if (-not $sources.Contains([string]$value)) { $sources.Add([string]$value) } }
            foreach ($value in $attempt.Stages) { if (-not $stages.Contains([string]$value)) { $stages.Add([string]$value) } }
            foreach ($value in $attempt.HttpStatusCodes) { if (-not $statuses.Contains([int]$value)) { $statuses.Add([int]$value) } }
            foreach ($value in $attempt.ProxyStatusCodes) { if (-not $proxyStatuses.Contains([int]$value)) { $proxyStatuses.Add([int]$value) } }
            if ($attempt.HttpResponseClass -eq 'response_2xx_3xx') { $successfulHttp++ }
            elseif ($attempt.HttpResponseClass -eq 'response_4xx_5xx') { $failedHttp++ }
            elseif ($attempt.HttpResponseClass -eq 'mixed_responses') { $successfulHttp++; $failedHttp++ }
            if ($attempt.ObservedFailure) { $observedFailures++ }
            if ($attempt.ObservedOutcome -eq 'unknown') { $unknownOutcomes++ }
            if ($attempt.FirstSeenUtc -and (-not $firstSeen -or [DateTimeOffset]$attempt.FirstSeenUtc -lt [DateTimeOffset]$firstSeen)) { $firstSeen = $attempt.FirstSeenUtc }
            if ($attempt.LastSeenUtc -and (-not $lastSeen -or [DateTimeOffset]$attempt.LastSeenUtc -gt [DateTimeOffset]$lastSeen)) { $lastSeen = $attempt.LastSeenUtc }
            if (-not $trialAttributions.Contains([string]$attempt.TrialAttribution)) { $trialAttributions.Add([string]$attempt.TrialAttribution) }
            if ($attempt.OperationAttribution -eq 'heuristic_marker_window') { $operationAttribution = 'heuristic_marker_window' }
            elseif ($attempt.OperationAttribution -eq 'ambiguous') { $operationAttribution = 'ambiguous' }
        }
        $necessityState = 'necessity_unconfirmed'
        $latestNecessity = $null
        $dependencyId = 'dep-' + (Get-MihariDependencyHash -Text $key).Substring(0, 24)
        if ($NecessityRecords -is [System.Collections.IDictionary] -and $NecessityRecords.Contains($dependencyId)) {
            $latestNecessity = $NecessityRecords[$dependencyId]
            if ([string]$latestNecessity.state -eq 'business_required_confirmed') { $necessityState = 'business_required_confirmed' }
        }
        $trialAttribution = 'unknown'
        if ($trialAttributions.Count -eq 1) { $trialAttribution = [string]$trialAttributions[0] }
        elseif ($trialAttributions.Count -gt 1) { $trialAttribution = 'mixed' }
        $operationId = $null
        $operationLabel = $null
        if ($firstCandidate.OperationAttribution -eq 'heuristic_marker_window') {
            $operationId = $firstCandidate.OperationId; $operationLabel = $firstCandidate.OperationLabel
        }
        elseif ($firstCandidate.OperationAttribution -eq 'ambiguous') { $operationLabel = '[ambiguous marker window]' }
        $dependencies.Add([pscustomobject]@{
            schemaVersion = 1; dependencyId = $dependencyId; caseId = $firstCandidate.CaseId; trialId = $firstCandidate.TrialId
            trialAttribution = $trialAttribution; operationId = $operationId; operationLabel = $operationLabel
            operationAttribution = $firstCandidate.OperationAttribution; scheme = $target.Scheme; host = $target.Host
            port = $target.Port; path = $target.Path; queryObserved = [bool]$target.QueryObserved
            firstSeenUtc = $firstSeen; lastSeenUtc = $lastSeen; attemptCount = [int]$items.Count
            methods = @($methods.ToArray() | Sort-Object); sources = @($sources.ToArray() | Sort-Object)
            stages = @($stages.ToArray() | Sort-Object); httpStatusCodes = @($statuses.ToArray() | Sort-Object)
            proxyStatusCodes = @($proxyStatuses.ToArray() | Sort-Object)
            successfulHttpResponseCount = [int]$successfulHttp; failedHttpResponseCount = [int]$failedHttp
            observedFailureAttemptCount = [int]$observedFailures; unknownOutcomeAttemptCount = [int]$unknownOutcomes
            businessOutcome = 'unknown'; necessityState = $necessityState
            necessityConfirmation = $latestNecessity; requestKeys = @($requestKeys.ToArray() | Sort-Object)
            evidenceReferences = @($refs.ToArray() | Sort-Object -Property sessionId, eventId)
            markerIds = @($items | ForEach-Object { $_.MarkerIds } | Sort-Object -Unique)
            ambiguity = $null
        })
    }

    foreach ($attempt in @($attempts.ToArray() | Where-Object { $_.TargetConflict -or $null -eq $_.Target -or [string]::IsNullOrWhiteSpace([string]$_.Target.Host) })) {
        $dependencyId = 'dep-' + (Get-MihariDependencyHash -Text ($attempt.RequestKey + [char]0 + 'unknown-target')).Substring(0, 24)
        $dependencies.Add([pscustomobject]@{
            schemaVersion = 1; dependencyId = $dependencyId; caseId = $attempt.CaseId; trialId = $attempt.TrialId
            trialAttribution = $attempt.TrialAttribution; operationId = $attempt.OperationId; operationLabel = $attempt.OperationLabel
            operationAttribution = $attempt.OperationAttribution; scheme = $null; host = $null; port = $null; path = $null
            queryObserved = $false; firstSeenUtc = $attempt.FirstSeenUtc; lastSeenUtc = $attempt.LastSeenUtc; attemptCount = 1
            methods = @($attempt.Methods); sources = @($attempt.Sources); stages = @($attempt.Stages)
            httpStatusCodes = @($attempt.HttpStatusCodes); proxyStatusCodes = @($attempt.ProxyStatusCodes)
            successfulHttpResponseCount = [int]($attempt.HttpResponseClass -eq 'response_2xx_3xx')
            failedHttpResponseCount = [int]($attempt.HttpResponseClass -eq 'response_4xx_5xx' -or $attempt.ObservedFailure)
            observedFailureAttemptCount = [int]$attempt.ObservedFailure; unknownOutcomeAttemptCount = [int]($attempt.ObservedOutcome -eq 'unknown')
            businessOutcome = 'unknown'; necessityState = 'necessity_unconfirmed'; necessityConfirmation = $null
            requestKeys = @($attempt.RequestKey); evidenceReferences = @($attempt.EvidenceReferences)
            markerIds = @($attempt.MarkerIds); ambiguity = $(if ($attempt.TargetConflict) { 'conflicting_target_fields_within_direct_attempt' } else { 'destination_host_or_path_unknown' })
        })
    }
    $orderedDependencies = @($dependencies.ToArray() | Sort-Object -Property host, path, trialId, dependencyId)
    $revisionPayload = [pscustomobject]@{
        items = @($orderedDependencies)
        missingIdentityEventCount = [int]$missingIdentityCount
        duplicateEventCount = [int]$duplicateEventCount
        targetConflictAttemptCount = [int]$targetConflictCount
        heuristicTrialAttributionCount = [int]$heuristicTrialCount
        ambiguousTrialAttributionCount = [int]$ambiguousTrialCount
    }
    $revisionJson = ConvertTo-Json -InputObject $revisionPayload -Depth 8 -Compress -ErrorAction Stop
    $revision = Get-MihariDependencyHash -Text $revisionJson
    $page = Get-MihariDependencyPage -Items $orderedDependencies -MaximumItems $MaximumItems -Kind dependencies -Revision $revision -Cursor $Cursor
    return [pscustomobject]@{
        items = @($page.Items)
        nextCursor = $page.NextCursor; revision = $page.Revision; ordering = 'host:path:trialId:dependencyId'
        scopeTotal = [int]$page.ScopeTotal
        coverage = [pscustomobject]@{
            status = $(if ($missingIdentityCount -gt 0 -or $targetConflictCount -gt 0 -or $ambiguousTrialCount -gt 0) { 'incomplete' } else { 'observed' })
            inputEventCount = [int]@($Events).Count; projectedEventCount = [int]$normalizedEvents.Count
            missingIdentityEventCount = [int]$missingIdentityCount; duplicateEventCount = [int]$duplicateEventCount
            targetConflictAttemptCount = [int]$targetConflictCount; heuristicTrialAttributionCount = [int]$heuristicTrialCount
            ambiguousTrialAttributionCount = [int]$ambiguousTrialCount; heuristicOperationAttributionCount = [int]$heuristicOperationCount
            ambiguousOperationAttributionCount = [int]$ambiguousOperationCount
            operationAttributionBasis = 'explicit operator start/end markers and wall-clock event windows; heuristic only'
        }
        freshnessUtc = [DateTime]::UtcNow.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
    }
}

function ConvertTo-MihariNeutralPolicyHost {
    param([AllowNull()][object] $HostValue)
    return ConvertTo-MihariDependencyHost -Value $HostValue
}

function ConvertTo-MihariNeutralPolicyRuleSet {
    param([AllowNull()][object] $PolicyDocument)

    $unsupportedReason = $null
    if ($null -eq $PolicyDocument) { return [pscustomobject]@{ Supported = $false; Reason = 'policy_not_provided'; Rules = @(); UnsupportedRules = @() } }
    if ($PolicyDocument -is [string]) {
        try { $PolicyDocument = ConvertFrom-Json -InputObject $PolicyDocument -ErrorAction Stop }
        catch { return [pscustomobject]@{ Supported = $false; Reason = 'policy_json_invalid'; Rules = @(); UnsupportedRules = @() } }
    }
    $format = ConvertTo-MihariDependencySafeText -Value (Get-MihariDependencyValue -InputObject $PolicyDocument -Names @('format')) -MaximumLength 64
    $version = Get-MihariDependencyValue -InputObject $PolicyDocument -Names @('schemaVersion')
    if ($format -ne 'mihari-neutral-url-policy' -or [int]$version -ne 1) {
        return [pscustomobject]@{ Supported = $false; Reason = 'unsupported_policy_format_or_version'; Rules = @(); UnsupportedRules = @() }
    }
    $rules = Get-MihariDependencyValue -InputObject $PolicyDocument -Names @('rules') -NoEnumerate
    if ($null -eq $rules -or $rules -isnot [System.Collections.IEnumerable] -or $rules -is [string]) {
        return [pscustomobject]@{ Supported = $false; Reason = 'policy_rules_missing'; Rules = @(); UnsupportedRules = @() }
    }
    $normalized = New-Object 'System.Collections.Generic.List[object]'
    $unsupported = New-Object 'System.Collections.Generic.List[object]'
    $ruleCount = 0
    foreach ($rule in $rules) {
        $ruleCount++
        if ($ruleCount -gt 500) { return [pscustomobject]@{ Supported = $false; Reason = 'policy_rule_limit_exceeded'; Rules = @(); UnsupportedRules = @() } }
        $ruleId = ConvertTo-MihariDependencySafeText -Value (Get-MihariDependencyValue -InputObject $rule -Names @('ruleId', 'id')) -MaximumLength 128
        if ($null -eq $ruleId) { $ruleId = 'rule-' + $ruleCount.ToString([Globalization.CultureInfo]::InvariantCulture) }
        $hostText = ConvertTo-MihariDependencySafeText -Value (Get-MihariDependencyValue -InputObject $rule -Names @('host')) -MaximumLength 512
        $normalizedHost = ConvertTo-MihariNeutralPolicyHost -HostValue $hostText
        $matchType = ConvertTo-MihariDependencySafeText -Value (Get-MihariDependencyValue -InputObject $rule -Names @('matchType')) -MaximumLength 32
        $matchType = $(if ($null -eq $matchType) { 'exact' } else { $matchType })
        $path = ConvertTo-MihariDependencySafeText -Value (Get-MihariDependencyValue -InputObject $rule -Names @('path')) -MaximumLength 2048
        $scheme = ConvertTo-MihariDependencySafeText -Value (Get-MihariDependencyValue -InputObject $rule -Names @('scheme')) -MaximumLength 16
        if ($null -ne $scheme) { $scheme = $scheme.ToLowerInvariant() }
        $portValue = Get-MihariDependencyValue -InputObject $rule -Names @('port')
        $port = $null
        $portNumber = 0
        if ($null -ne $portValue) {
            if ([int]::TryParse([string]$portValue, [ref]$portNumber) -and $portNumber -ge 1 -and $portNumber -le 65535) { $port = $portNumber }
        }
        $effect = ConvertTo-MihariDependencySafeText -Value (Get-MihariDependencyValue -InputObject $rule -Names @('effect')) -MaximumLength 16
        $methodsValue = Get-MihariDependencyValue -InputObject $rule -Names @('methods')
        $methods = New-Object 'System.Collections.Generic.List[string]'
        foreach ($method in @($methodsValue)) {
            $safeMethod = ConvertTo-MihariDependencySafeText -Value $method -MaximumLength 32
            if ($safeMethod -and $safeMethod -match '^[!#$%&''*+.^_`|~0-9A-Za-z-]+$' -and -not $methods.Contains($safeMethod.ToUpperInvariant())) {
                $methods.Add($safeMethod.ToUpperInvariant())
            }
        }
        $unknownFields = New-Object 'System.Collections.Generic.List[string]'
        if ($rule -is [System.Collections.IDictionary]) { $fieldNames = @($rule.Keys | ForEach-Object { [string]$_ }) }
        else { $fieldNames = @($rule.PSObject.Properties | ForEach-Object { [string]$_.Name }) }
        foreach ($fieldName in $fieldNames) {
            if ($fieldName -notin @('ruleId', 'id', 'host', 'scheme', 'port', 'matchType', 'path', 'effect', 'methods')) { $unknownFields.Add($fieldName) }
        }
        $isSupported = ($null -ne $normalizedHost -and $matchType -in @('exact', 'pathPrefix') -and
            $null -ne $path -and $path.StartsWith('/') -and $path.IndexOf('?') -lt 0 -and $path -notmatch '[*{}\[\]]' -and
            ($null -eq $scheme -or $scheme -in @('http', 'https')) -and ($null -eq $portValue -or $null -ne $port) -and
            ($null -eq $effect -or $effect -eq 'allow') -and $unknownFields.Count -eq 0)
        if (-not $isSupported) {
            $possibleHost = $normalizedHost
            $unsupported.Add([pscustomobject]@{ ruleId = $ruleId; host = $possibleHost; reason = 'unsupported_rule_semantics' })
            continue
        }
        if ($matchType -eq 'pathPrefix' -and $path.Length -gt 1) { $path = $path.TrimEnd('/') }
        if ($path.Length -eq 0) { $path = '/' }
        $normalized.Add([pscustomobject]@{
            RuleId = $ruleId; Host = $normalizedHost; Scheme = $scheme; Port = $port; MatchType = $matchType
            Path = $path; Methods = @($methods.ToArray())
        })
    }
    return [pscustomobject]@{ Supported = $true; Reason = $unsupportedReason; Rules = @($normalized.ToArray()); UnsupportedRules = @($unsupported.ToArray()) }
}

function Test-MihariNeutralPolicyPathMatch {
    param([Parameter(Mandatory = $true)][object] $Rule, [Parameter(Mandatory = $true)][string] $Path)
    if ($Rule.MatchType -eq 'exact') { return [string]::Equals([string]$Rule.Path, $Path, [StringComparison]::Ordinal) }
    if ($Rule.MatchType -eq 'pathPrefix') {
        if ($Rule.Path -eq '/') { return $Path.StartsWith('/', [StringComparison]::Ordinal) }
        return ([string]::Equals($Path, [string]$Rule.Path, [StringComparison]::Ordinal) -or
            $Path.StartsWith(([string]$Rule.Path).TrimEnd('/') + '/', [StringComparison]::Ordinal))
    }
    return $false
}

function Compare-MihariDependencyPolicy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]] $Dependencies,
        [Parameter(Mandatory = $true)][AllowNull()][object] $PolicyDocument,
        [ValidateRange(1, 200)][int] $MaximumItems = 200,
        [string] $Cursor
    )

    $policy = ConvertTo-MihariNeutralPolicyRuleSet -PolicyDocument $PolicyDocument
    $items = New-Object 'System.Collections.Generic.List[object]'
    foreach ($dependency in $Dependencies) {
        $dependencyId = ConvertTo-MihariDependencySafeText -Value (Get-MihariDependencyValue -InputObject $dependency -Names @('dependencyId')) -MaximumLength 128
        if ($null -eq $dependencyId) { $dependencyId = 'unidentified' }
        $dependencyHost = ConvertTo-MihariNeutralPolicyHost -HostValue (Get-MihariDependencyValue -InputObject $dependency -Names @('host'))
        $scheme = ConvertTo-MihariDependencySafeText -Value (Get-MihariDependencyValue -InputObject $dependency -Names @('scheme')) -MaximumLength 16
        if ($null -ne $scheme) { $scheme = $scheme.ToLowerInvariant() }
        $portValue = Get-MihariDependencyValue -InputObject $dependency -Names @('port')
        $port = $null
        $portNumber = 0
        if ($null -ne $portValue -and [int]::TryParse([string]$portValue, [ref]$portNumber) -and $portNumber -ge 1 -and $portNumber -le 65535) { $port = $portNumber }
        $pathWithQuery = ConvertTo-MihariDependencyPath -Value (Get-MihariDependencyValue -InputObject $dependency -Names @('path'))
        $path = $pathWithQuery
        if ($null -ne $path -and $path.Contains('?')) { $path = $path.Substring(0, $path.IndexOf('?')) }
        $methods = @((Get-MihariDependencyValue -InputObject $dependency -Names @('methods')) | ForEach-Object { ([string]$_).ToUpperInvariant() } | Sort-Object -Unique)
        $status = 'uncovered'
        $reason = 'no_supported_rule_covers_the_observed_authority_and_path'
        $covering = New-Object 'System.Collections.Generic.List[string]'
        $possibleUnknown = New-Object 'System.Collections.Generic.List[string]'
        if (-not $policy.Supported) {
            $status = 'unknown'; $reason = [string]$policy.Reason
        }
        elseif ($null -eq $dependencyHost -or $null -eq $path) {
            $status = 'unknown'; $reason = 'observed_host_or_path_unknown'
        }
        else {
            foreach ($rule in $policy.Rules) {
                if ($rule.Host -ne $dependencyHost) { continue }
                $ruleDimensionsUnknown = (($null -ne $rule.Scheme -and $null -eq $scheme) -or ($null -ne $rule.Port -and $null -eq $port))
                $schemeMatches = ($null -eq $rule.Scheme -or $null -eq $scheme -or $rule.Scheme -eq $scheme)
                $portMatches = ($null -eq $rule.Port -or $null -eq $port -or [int]$rule.Port -eq [int]$port)
                if (-not $schemeMatches -or -not $portMatches) { continue }
                if ($ruleDimensionsUnknown) { $possibleUnknown.Add($rule.RuleId); continue }
                if (-not (Test-MihariNeutralPolicyPathMatch -Rule $rule -Path $path)) { continue }
                if ($rule.Methods.Count -gt 0) {
                    if ($methods.Count -eq 0) { $possibleUnknown.Add($rule.RuleId); continue }
                    $missingMethods = @($methods | Where-Object { $_ -notin $rule.Methods })
                    if ($missingMethods.Count -gt 0) { continue }
                }
                $covering.Add($rule.RuleId)
            }
            foreach ($unknownRule in $policy.UnsupportedRules) {
                if ($null -eq $unknownRule.host -or $unknownRule.host -eq $dependencyHost) { $possibleUnknown.Add([string]$unknownRule.ruleId) }
            }
            if ($covering.Count -gt 0) { $status = 'covered'; $reason = 'covered_by_neutral_exact_or_path_prefix_rule' }
            elseif ($possibleUnknown.Count -gt 0) { $status = 'unknown'; $reason = 'unsupported_or_incomplete_rule_semantics_may_cover_observation' }
        }
        $items.Add([pscustomobject]@{
            dependencyId = $dependencyId; status = $status; reason = $reason
            coveringRuleIds = @($covering.ToArray() | Sort-Object -Unique)
            possibleRuleIds = @($possibleUnknown.ToArray() | Sort-Object -Unique)
            scheme = $scheme; host = $dependencyHost; port = $port; path = $path
        })
    }
    $allItems = @($items.ToArray() | Sort-Object -Property dependencyId)
    $revisionJson = ConvertTo-Json -InputObject @($allItems) -Depth 8 -Compress -ErrorAction Stop
    $revision = Get-MihariDependencyHash -Text ($policy.Reason + [char]0 + $revisionJson)
    $page = Get-MihariDependencyPage -Items $allItems -MaximumItems $MaximumItems -Kind policy -Revision $revision -Cursor $Cursor
    return [pscustomobject]@{
        schemaVersion = 1; policyFormat = 'mihari-neutral-url-policy'; items = @($page.Items)
        nextCursor = $page.NextCursor; revision = $page.Revision; ordering = 'dependencyId:asc'; scopeTotal = [int]$page.ScopeTotal
        coverage = $(if (-not $policy.Supported) { 'unsupported' } elseif ($policy.UnsupportedRules.Count -gt 0) { 'incomplete' } else { 'observed' })
        unsupportedRuleCount = [int]$policy.UnsupportedRules.Count; freshnessUtc = [DateTime]::UtcNow.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
    }
}

function Get-MihariDependencyPolicyStatus {
    param([object[]] $PolicyComparison, [string] $DependencyId)
    if ($null -eq $PolicyComparison) { return 'unknown' }
    $items = Get-MihariDependencyValue -InputObject $PolicyComparison -Names @('items')
    $match = @($items | Where-Object { [string]$_.dependencyId -eq $DependencyId } | Select-Object -First 1)
    if ($match.Count -eq 0) { return 'unknown' }
    return [string]$match[0].status
}

function Test-MihariTlsExclusionEvidence {
    param([Parameter(Mandatory = $true)][object] $Evidence)

    $classification = [string](Get-MihariDependencyValue -InputObject $Evidence -Names @('classification'))
    $strength = [string](Get-MihariDependencyValue -InputObject $Evidence -Names @('evidenceStrength'))
    $inspectFailure = Get-MihariDependencyValue -InputObject $Evidence -Names @('inspectFailureObserved')
    $tunnelOutcome = [string](Get-MihariDependencyValue -InputObject $Evidence -Names @('tunnelBusinessOutcome', 'operatorBusinessOutcome'))
    $sameRoute = Get-MihariDependencyValue -InputObject $Evidence -Names @('sameRoute')
    $sameProtocol = Get-MihariDependencyValue -InputObject $Evidence -Names @('sameProtocolPolicy', 'sameProtocolProfile')
    $conditions = Get-MihariDependencyValue -InputObject $Evidence -Names @('otherConditionsComparable', 'comparableConditions')
    $changedConditions = Get-MihariDependencyValue -InputObject $Evidence -Names @('changedConditions')
    $inspectTrialId = ConvertTo-MihariDependencySafeText -Value (Get-MihariDependencyValue -InputObject $Evidence -Names @('inspectTrialId')) -MaximumLength 128
    $tunnelTrialId = ConvertTo-MihariDependencySafeText -Value (Get-MihariDependencyValue -InputObject $Evidence -Names @('tunnelTrialId')) -MaximumLength 128
    $refs = Get-MihariDependencyValue -InputObject $Evidence -Names @('evidenceReferences', 'evidence')
    $safeRefs = New-Object 'System.Collections.Generic.List[object]'
    $seenRefs = New-MihariOrdinalHashtable
    foreach ($reference in @($refs)) {
        $sessionId = ConvertTo-MihariDependencySafeText -Value (Get-MihariDependencyValue -InputObject $reference -Names @('sessionId')) -MaximumLength 128
        $eventId = ConvertTo-MihariDependencySafeText -Value (Get-MihariDependencyValue -InputObject $reference -Names @('eventId')) -MaximumLength 128
        if ($sessionId -and $eventId) {
            $referenceKey = $sessionId + [char]0 + $eventId
            if (-not $seenRefs.ContainsKey($referenceKey)) {
                $seenRefs[$referenceKey] = $true
                $safeRefs.Add([pscustomobject]@{ sessionId = $sessionId; eventId = $eventId })
            }
        }
    }
    $valid = ($classification -eq 'tls_interception_incompatible' -and $strength -eq 'comparison_supported' -and
        $inspectFailure -eq $true -and $tunnelOutcome -eq 'succeeded' -and $sameRoute -eq $true -and
        $sameProtocol -eq $true -and $conditions -eq $true -and $inspectTrialId -and $tunnelTrialId -and
        $inspectTrialId -ne $tunnelTrialId -and $safeRefs.Count -ge 2)
    if ($null -ne $changedConditions -and @($changedConditions).Count -gt 0) { $valid = $false }
    return [pscustomobject]@{ Valid = $valid; EvidenceReferences = @($safeRefs.ToArray()); InspectTrialId = $inspectTrialId; TunnelTrialId = $tunnelTrialId }
}

function New-MihariPolicyProposals {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]] $Dependencies,
        [object] $PolicyComparison,
        [object[]] $TlsEvidence = @(),
        [ValidateSet('exact', 'pathPrefix')][string] $PathMatch = 'exact',
        [switch] $ConfirmBroadenedPathPrefix,
        [switch] $ConfirmTlsExclusionHostScope,
        [ValidateRange(1, 200)][int] $MaximumItems = 200,
        [string] $Cursor
    )

    $proposals = New-Object 'System.Collections.Generic.List[object]'
    $withheld = New-Object 'System.Collections.Generic.List[object]'
    foreach ($dependency in $Dependencies) {
        $dependencyId = ConvertTo-MihariDependencySafeText -Value (Get-MihariDependencyValue -InputObject $dependency -Names @('dependencyId')) -MaximumLength 128
        $dependencyHost = ConvertTo-MihariNeutralPolicyHost -HostValue (Get-MihariDependencyValue -InputObject $dependency -Names @('host'))
        $scheme = ConvertTo-MihariDependencySafeText -Value (Get-MihariDependencyValue -InputObject $dependency -Names @('scheme')) -MaximumLength 16
        if ($null -ne $scheme) { $scheme = $scheme.ToLowerInvariant() }
        $port = Get-MihariDependencyValue -InputObject $dependency -Names @('port')
        $pathWithQuery = ConvertTo-MihariDependencyPath -Value (Get-MihariDependencyValue -InputObject $dependency -Names @('path'))
        $path = $pathWithQuery
        $queryObserved = [bool](Get-MihariDependencyValue -InputObject $dependency -Names @('queryObserved'))
        if ($null -ne $path -and $path.Contains('?')) { $queryObserved = $true; $path = $path.Substring(0, $path.IndexOf('?')) }
        if (-not $dependencyId -or -not $dependencyHost -or $scheme -notin @('http', 'https') -or $null -eq $port -or $null -eq $path -or -not $path.StartsWith('/')) {
            $withheld.Add([pscustomobject]@{ dependencyId = $dependencyId; reason = 'host_scheme_port_or_exact_path_not_observed' })
            continue
        }
        $policyStatus = Get-MihariDependencyPolicyStatus -PolicyComparison $PolicyComparison -DependencyId $dependencyId
        if ($policyStatus -eq 'covered') { continue }
        $necessityState = ConvertTo-MihariDependencySafeText -Value (Get-MihariDependencyValue -InputObject $dependency -Names @('necessityState')) -MaximumLength 64
        if ($null -eq $necessityState) { $necessityState = 'necessity_unconfirmed' }
        $broadens = ($PathMatch -eq 'pathPrefix')
        $prefixConfirmed = ([bool]$ConfirmBroadenedPathPrefix -and $broadens)
        $proposalStatus = 'candidate'
        $requiredConfirmations = New-Object 'System.Collections.Generic.List[string]'
        if ($necessityState -ne 'business_required_confirmed') { $requiredConfirmations.Add('business_necessity') }
        if ($broadens -and -not $prefixConfirmed) { $requiredConfirmations.Add('broadened_path_prefix') }
        if ($requiredConfirmations.Count -gt 0) { $proposalStatus = 'requires_confirmation' }
        $evidenceRefs = Get-MihariDependencyValue -InputObject $dependency -Names @('evidenceReferences')
        $safeRefs = New-Object 'System.Collections.Generic.List[object]'
        foreach ($reference in @($evidenceRefs)) {
            $sessionId = ConvertTo-MihariDependencySafeText -Value (Get-MihariDependencyValue -InputObject $reference -Names @('sessionId')) -MaximumLength 128
            $eventId = ConvertTo-MihariDependencySafeText -Value (Get-MihariDependencyValue -InputObject $reference -Names @('eventId')) -MaximumLength 128
            if ($sessionId -and $eventId) { $safeRefs.Add([pscustomobject]@{ sessionId = $sessionId; eventId = $eventId }) }
        }
        if ($safeRefs.Count -eq 0) {
            $withheld.Add([pscustomobject]@{ dependencyId = $dependencyId; reason = 'evidence_reference_required' })
            continue
        }
        $methods = @((Get-MihariDependencyValue -InputObject $dependency -Names @('methods')) | ForEach-Object { ([string]$_).ToUpperInvariant() } | Sort-Object -Unique)
        $rationale = 'Observed endpoint evidence supports review of this exact authority and path. Business necessity remains an operator decision.'
        if ($policyStatus -eq 'unknown') { $rationale += ' Existing policy coverage is unknown because the supplied policy semantics were incomplete or unsupported.' }
        $proposalSeed = @('url_allowlist', $dependencyId, $PathMatch, $path, [string]$port) -join [char]0
        $proposals.Add([pscustomobject]@{
            schemaVersion = 1; proposalId = 'proposal-' + (Get-MihariDependencyHash -Text $proposalSeed).Substring(0, 24)
            proposalType = 'url_allowlist'; policyDomain = 'enterprise-url-access'; dependencyId = $dependencyId
            caseId = (Get-MihariDependencyValue -InputObject $dependency -Names @('caseId'))
            trialId = (Get-MihariDependencyValue -InputObject $dependency -Names @('trialId'))
            scheme = $scheme; host = $dependencyHost; port = [int]$port; matchType = $PathMatch; path = $path
            methods = $methods; queryValues = $(if ($queryObserved) { 'redacted; not proposed as match criteria' } else { 'not observed' })
            necessityState = $necessityState; existingPolicyStatus = $policyStatus; proposalStatus = $proposalStatus
            requiresConfirmation = @($requiredConfirmations.ToArray()); broadenedPattern = $broadens
            broadenedPatternConfirmed = $prefixConfirmed; rationale = $rationale
            evidenceReferences = @($safeRefs.ToArray() | Sort-Object -Property sessionId, eventId)
            unresolvedQuestions = @('Does the business operation require this exact URL?','Which enterprise policy owner can verify existing coverage?')
        })
    }

    $seenTlsProposalScopes = New-MihariOrdinalHashtable
    foreach ($tlsEvidence in $TlsEvidence) {
        $validated = Test-MihariTlsExclusionEvidence -Evidence $tlsEvidence
        if (-not $validated.Valid) { continue }
        $tlsHost = ConvertTo-MihariNeutralPolicyHost -HostValue (Get-MihariDependencyValue -InputObject $tlsEvidence -Names @('host', 'destinationHost'))
        if ($null -eq $tlsHost) { continue }
        $caseId = ConvertTo-MihariDependencySafeText -Value (Get-MihariDependencyValue -InputObject $tlsEvidence -Names @('caseId')) -MaximumLength 128
        $matchingDependencies = @($Dependencies | Where-Object {
                (ConvertTo-MihariNeutralPolicyHost -HostValue (Get-MihariDependencyValue -InputObject $_ -Names @('host'))) -eq $tlsHost -and
                ($null -eq $caseId -or [string](Get-MihariDependencyValue -InputObject $_ -Names @('caseId')) -eq $caseId)
            })
        if ($matchingDependencies.Count -eq 0) { continue }
        $comparisonId = ConvertTo-MihariDependencySafeText -Value (Get-MihariDependencyValue -InputObject $tlsEvidence -Names @('comparisonId')) -MaximumLength 128
        if ($null -eq $comparisonId) { $comparisonId = 'comparison-' + (Get-MihariDependencyHash -Text ($validated.InspectTrialId + [char]0 + $validated.TunnelTrialId + [char]0 + $tlsHost)).Substring(0, 24) }
        $scopeKey = [string]$caseId + [char]0 + $comparisonId + [char]0 + $tlsHost
        if ($seenTlsProposalScopes.ContainsKey($scopeKey)) { continue }
        $seenTlsProposalScopes[$scopeKey] = $true
        $dependency = @($matchingDependencies | Sort-Object -Property dependencyId | Select-Object -First 1)[0]
        $dependencyId = ConvertTo-MihariDependencySafeText -Value (Get-MihariDependencyValue -InputObject $dependency -Names @('dependencyId')) -MaximumLength 128
        $necessityState = [string](Get-MihariDependencyValue -InputObject $dependency -Names @('necessityState'))
        $requiredConfirmations = New-Object 'System.Collections.Generic.List[string]'
        if ($necessityState -ne 'business_required_confirmed') { $requiredConfirmations.Add('business_necessity') }
        if (-not $ConfirmTlsExclusionHostScope) { $requiredConfirmations.Add('exact_host_scope') }
        $status = 'candidate'
        if ($requiredConfirmations.Count -gt 0) { $status = 'requires_confirmation' }
        $proposalSeed = @('tls_inspection_exclusion', $dependencyId, $comparisonId, $tlsHost) -join [char]0
        $proposals.Add([pscustomobject]@{
            schemaVersion = 1; proposalId = 'proposal-' + (Get-MihariDependencyHash -Text $proposalSeed).Substring(0, 24)
            proposalType = 'tls_inspection_exclusion'; policyDomain = 'mihari-local-inspection'
            dependencyId = $dependencyId; caseId = $caseId; host = $tlsHost; matchType = 'exact_host'
            localAction = 'New Mihari client connections to this host use Tunnel mode.'
            upstreamRoute = 'unchanged'; upstreamTlsValidation = 'unchanged'; proposalStatus = $status
            necessityState = $(if ($necessityState) { $necessityState } else { 'necessity_unconfirmed' })
            requiresConfirmation = @($requiredConfirmations.ToArray()); exactHostScopeConfirmed = [bool]$ConfirmTlsExclusionHostScope; comparisonId = $comparisonId
            inspectTrialId = $validated.InspectTrialId; tunnelTrialId = $validated.TunnelTrialId
            evidenceStrength = 'comparison_supported'; rationale = 'A comparable Inspect failure and Tunnel business success supports a local inspection exclusion for this exact host; it does not identify pinning or mTLS.'
            limitations = @('Tunnel bytes alone are not application success.','This local Mihari setting does not change upstream routing or enterprise TLS policy.')
            evidenceReferences = @($validated.EvidenceReferences | Sort-Object -Property sessionId, eventId)
            unresolvedQuestions = @('Does the business operation require this destination?','Is an enterprise-side TLS inspection exception separately appropriate?')
        })
    }
    $all = @($proposals.ToArray() | Sort-Object -Property proposalType, host, path, proposalId)
    $revisionJson = ConvertTo-Json -InputObject ([pscustomobject]@{ items = @($all); withheld = @($withheld.ToArray()) }) -Depth 8 -Compress -ErrorAction Stop
    $revision = Get-MihariDependencyHash -Text $revisionJson
    $page = Get-MihariDependencyPage -Items $all -MaximumItems $MaximumItems -Kind proposals -Revision $revision -Cursor $Cursor
    return [pscustomobject]@{
        schemaVersion = 1; items = @($page.Items); nextCursor = $page.NextCursor; revision = $page.Revision
        ordering = 'proposalType:host:path:proposalId'; scopeTotal = [int]$page.ScopeTotal
        coverage = $(if ($withheld.Count -gt 0) { 'incomplete' } else { 'observed' })
        withheld = @($withheld.ToArray()); unsupportedTlsEvidenceCount = [int]@($TlsEvidence | Where-Object { -not (Test-MihariTlsExclusionEvidence -Evidence $_).Valid }).Count
        freshnessUtc = [DateTime]::UtcNow.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
    }
}

function ConvertTo-MihariChangeRequestValue {
    param([AllowNull()][object] $Value, [Parameter(Mandatory = $true)][ref] $RedactedCount)
    return ConvertTo-MihariCaseSafeValue -Value $Value -Depth 0 -RedactedCount $RedactedCount
}

function New-MihariChangeRequestPayload {
    param(
        [object] $Case,
        [object] $Trial,
        [object[]] $Dependencies = @(),
        [object[]] $Proposals = @(),
        [string] $BusinessAction,
        [object] $ReproductionConditions,
        [string[]] $UnresolvedQuestions = @()
    )

    $redactedCount = 0
    $safeCase = $null
    if ($null -ne $Case) {
        $safeCase = [ordered]@{}
        foreach ($field in @('caseId', 'title', 'createdAtUtc', 'updatedAtUtc')) {
            $value = ConvertTo-MihariCaseSafeText -Value (Get-MihariDependencyValue -InputObject $Case -Names @($field)) -MaximumLength 512
            if ($null -ne $value) { $safeCase[$field] = $value }
        }
    }
    $safeTrial = $null
    if ($null -ne $Trial) {
        $safeTrial = [ordered]@{}
        foreach ($field in @('trialId', 'caseId', 'sessionId', 'startedAtUtc', 'endedAtUtc', 'configurationRevision', 'status', 'operatorBusinessOutcome')) {
            $value = ConvertTo-MihariCaseSafeText -Value (Get-MihariDependencyValue -InputObject $Trial -Names @($field)) -MaximumLength 256
            if ($null -ne $value) { $safeTrial[$field] = $value }
        }
        $trialProfile = Get-MihariDependencyValue -InputObject $Trial -Names @('profile')
        if ($null -ne $trialProfile) { $safeTrial['profile'] = ConvertTo-MihariChangeRequestValue -Value $trialProfile -RedactedCount ([ref]$redactedCount) }
        $environment = Get-MihariDependencyValue -InputObject $Trial -Names @('environmentReference')
        if ($null -ne $environment) { $safeTrial['environmentReference'] = ConvertTo-MihariChangeRequestValue -Value $environment -RedactedCount ([ref]$redactedCount) }
    }
    $action = ConvertTo-MihariCaseSafeText -Value $BusinessAction -MaximumLength 512
    if ($null -eq $action -and $null -ne $Trial) {
        $action = ConvertTo-MihariCaseSafeText -Value (Get-MihariDependencyValue -InputObject $Trial -Names @('businessAction')) -MaximumLength 512
    }
    if ($null -eq $action -and $null -ne $Case) { $action = ConvertTo-MihariCaseSafeText -Value (Get-MihariDependencyValue -InputObject $Case -Names @('title')) -MaximumLength 512 }
    $conditions = $null
    if ($null -ne $ReproductionConditions) { $conditions = ConvertTo-MihariChangeRequestValue -Value $ReproductionConditions -RedactedCount ([ref]$redactedCount) }
    elseif ($null -ne $Trial) { $conditions = Get-MihariDependencyValue -InputObject $Trial -Names @('profile') }
    $safeProposals = New-Object 'System.Collections.Generic.List[object]'
    foreach ($proposal in @($Proposals | Sort-Object -Property proposalType, host, path, proposalId)) {
        $safe = [ordered]@{}
        foreach ($field in @('proposalId', 'proposalType', 'policyDomain', 'dependencyId', 'caseId', 'trialId', 'scheme', 'host', 'port', 'matchType', 'path', 'queryValues', 'necessityState', 'existingPolicyStatus', 'proposalStatus', 'broadenedPattern', 'broadenedPatternConfirmed', 'localAction', 'upstreamRoute', 'upstreamTlsValidation', 'comparisonId', 'inspectTrialId', 'tunnelTrialId', 'evidenceStrength', 'rationale')) {
            $value = Get-MihariDependencyValue -InputObject $proposal -Names @($field)
            if ($null -ne $value) {
                if ($value -is [bool] -or $value -is [int] -or $value -is [long]) { $safe[$field] = $value }
                else { $safeText = ConvertTo-MihariCaseSafeText -Value $value -MaximumLength 2048; if ($null -ne $safeText) { $safe[$field] = $safeText } }
            }
        }
        $methods = Get-MihariDependencyValue -InputObject $proposal -Names @('methods')
        if ($null -ne $methods) { $safe['methods'] = @($methods | ForEach-Object { ConvertTo-MihariCaseSafeText -Value $_ -MaximumLength 32 } | Where-Object { $_ }) }
        foreach ($field in @('requiresConfirmation', 'unresolvedQuestions', 'limitations')) {
            $value = Get-MihariDependencyValue -InputObject $proposal -Names @($field)
            if ($null -ne $value) { $safe[$field] = @($value | ForEach-Object { ConvertTo-MihariCaseSafeText -Value $_ -MaximumLength 512 } | Where-Object { $_ }) }
        }
        $references = Get-MihariDependencyValue -InputObject $proposal -Names @('evidenceReferences')
        $safeReferences = New-Object 'System.Collections.Generic.List[object]'
        foreach ($reference in @($references)) {
            $sessionId = ConvertTo-MihariDependencySafeText -Value (Get-MihariDependencyValue -InputObject $reference -Names @('sessionId')) -MaximumLength 128
            $eventId = ConvertTo-MihariDependencySafeText -Value (Get-MihariDependencyValue -InputObject $reference -Names @('eventId')) -MaximumLength 128
            if ($sessionId -and $eventId) { $safeReferences.Add([pscustomobject]@{ sessionId = $sessionId; eventId = $eventId }) }
        }
        $safe['evidenceReferences'] = @($safeReferences.ToArray())
        $safeProposals.Add([pscustomobject]$safe)
    }
    $questions = New-Object 'System.Collections.Generic.List[string]'
    foreach ($question in $UnresolvedQuestions) {
        $safeQuestion = ConvertTo-MihariCaseSafeText -Value $question -MaximumLength 512
        if ($safeQuestion) { $questions.Add($safeQuestion) }
    }
    $document = [ordered]@{
        schemaVersion = 1; format = 'mihari-change-request'; case = $safeCase; trial = $safeTrial
        businessAction = $action; reproductionConditions = $conditions; proposals = @($safeProposals.ToArray())
        requiredUrls = @($safeProposals.ToArray() | Where-Object { $_.proposalType -eq 'url_allowlist' } | ForEach-Object {
                [pscustomobject]@{ scheme = $_.scheme; host = $_.host; port = $_.port; matchType = $_.matchType; path = $_.path; methods = $_.methods }
            })
        unresolvedQuestions = @($questions.ToArray()); redactionSummary = [pscustomobject]@{
            queryValues = 'redacted'; credentialsAndSecretFields = 'omitted or redacted'; bodiesAndRawEvents = 'excluded'
            additionalRedactedFields = [int]$redactedCount
        }
    }
    return [pscustomobject]@{ Payload = [pscustomobject]$document; RedactedCount = [int]$redactedCount }
}

function Get-MihariChangeRequestPreview {
    [CmdletBinding()]
    param(
        [object] $Case,
        [object] $Trial,
        [object[]] $Dependencies = @(),
        [object[]] $Proposals = @(),
        [string] $BusinessAction,
        [object] $ReproductionConditions,
        [string[]] $UnresolvedQuestions = @()
    )

    $built = New-MihariChangeRequestPayload -Case $Case -Trial $Trial -Dependencies $Dependencies -Proposals $Proposals -BusinessAction $BusinessAction -ReproductionConditions $ReproductionConditions -UnresolvedQuestions $UnresolvedQuestions
    $canonical = ConvertTo-Json -InputObject $built.Payload -Depth 8 -Compress -ErrorAction Stop
    $previewId = 'preview-' + (Get-MihariDependencyHash -Text $canonical).Substring(0, 24)
    return [pscustomobject]@{
        schemaVersion = 1; previewId = $previewId; createdAtUtc = [DateTime]::UtcNow.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
        included = [pscustomobject]@{
            case = [bool]($null -ne $built.Payload.case); trial = [bool]($null -ne $built.Payload.trial)
            proposals = [int]@($built.Payload.proposals).Count; allowlistProposals = [int]@($built.Payload.proposals | Where-Object { $_.proposalType -eq 'url_allowlist' }).Count
            localTlsExclusionProposals = [int]@($built.Payload.proposals | Where-Object { $_.proposalType -eq 'tls_inspection_exclusion' }).Count
            evidenceReferences = [int]@($built.Payload.proposals | ForEach-Object { $_.evidenceReferences } | Sort-Object { $_.sessionId + [char]0 + $_.eventId } -Unique).Count
        }
        redacted = [pscustomobject]@{
            queryValues = 'all values'; credentialsAndSecretFields = 'omitted or redacted'; bodiesAndRawEvents = 'excluded'
            additionalFields = [int]$built.RedactedCount
        }
        payload = $built.Payload
    }
}

function ConvertTo-MihariCsvCell {
    param([AllowNull()][object] $Value)
    if ($null -eq $Value) { $text = '' }
    elseif ($Value -is [bool]) { $text = ([string]$Value).ToLowerInvariant() }
    elseif ($Value -is [array]) { $text = [string]::Join('; ', @($Value | ForEach-Object { [string]$_ })) }
    else { $text = [string]$Value }
    $text = ConvertTo-MihariCaseSafeText -Value $text -MaximumLength 4096 -AllowLineBreaks
    if ($null -eq $text) { $text = '' }
    if ($text -match '^\s*[=+@-]') { $text = "'" + $text }
    return '"' + $text.Replace('"', '""') + '"'
}

function ConvertTo-MihariChangeRequestCsv {
    param([Parameter(Mandatory = $true)][object] $Payload)
    $columns = @('businessAction', 'reproductionConditions', 'proposalId', 'proposalType', 'policyDomain', 'caseId', 'trialId', 'scheme', 'host', 'port', 'matchType', 'path', 'methods', 'necessityState', 'existingPolicyStatus', 'proposalStatus', 'requiresConfirmation', 'rationale', 'evidenceReferences')
    $lines = New-Object 'System.Collections.Generic.List[string]'
    $lines.Add([string]::Join(',', @($columns | ForEach-Object { ConvertTo-MihariCsvCell -Value $_ })))
    foreach ($proposal in @($Payload.proposals)) {
        $values = New-Object 'System.Collections.Generic.List[object]'
        foreach ($column in $columns) {
            if ($column -eq 'businessAction') { $value = $Payload.businessAction }
            elseif ($column -eq 'reproductionConditions') { $value = ConvertTo-Json -InputObject $Payload.reproductionConditions -Depth 8 -Compress }
            else { $value = Get-MihariDependencyValue -InputObject $proposal -Names @($column) }
            if ($column -eq 'requiresConfirmation' -and $null -ne $value) { $value = [string]::Join('; ', @($value)) }
            if ($column -eq 'evidenceReferences' -and $null -ne $value) {
                $value = [string]::Join('; ', @($value | ForEach-Object { [string]$_.sessionId + ':' + [string]$_.eventId }))
            }
            $values.Add((ConvertTo-MihariCsvCell -Value $value))
        }
        $lines.Add([string]::Join(',', $values.ToArray()))
    }
    return [string]::Join([Environment]::NewLine, $lines.ToArray()) + [Environment]::NewLine
}

function New-MihariChangeRequestText {
    param([Parameter(Mandatory = $true)][object] $Payload)
    $lines = New-Object 'System.Collections.Generic.List[string]'
    $lines.Add('Mihari evidence-backed change request')
    $lines.Add('Business action: ' + $(if ($Payload.businessAction) { [string]$Payload.businessAction } else { 'unspecified' }))
    if ($null -ne $Payload.case) { $lines.Add('Case: ' + [string]$Payload.case.caseId + ' | ' + [string]$Payload.case.title) }
    if ($null -ne $Payload.trial) {
        $lines.Add('Trial: ' + [string]$Payload.trial.trialId + ' | business outcome: ' + [string]$Payload.trial.operatorBusinessOutcome)
        $lines.Add('Reproduction conditions: ' + (ConvertTo-Json -InputObject $Payload.reproductionConditions -Depth 8 -Compress))
    }
    $lines.Add('')
    $lines.Add('Required URLs / proposals:')
    foreach ($proposal in @($Payload.proposals)) {
        if ($proposal.proposalType -eq 'url_allowlist') {
            $url = [string]$proposal.scheme + '://' + [string]$proposal.host + ':' + [string]$proposal.port + [string]$proposal.path
            $lines.Add(('  {0} [{1}; {2}; methods: {3}]' -f $url, $proposal.matchType, $proposal.proposalStatus, [string]::Join(',', @($proposal.methods))))
        }
        else {
            $lines.Add(('  Local Mihari TLS inspection exclusion for {0} [{1}]' -f $proposal.host, $proposal.proposalStatus))
            $lines.Add('    Enterprise URL routing and upstream TLS validation remain unchanged.')
        }
        $lines.Add('    Necessity: ' + [string]$proposal.necessityState + '; policy coverage: ' + [string]$proposal.existingPolicyStatus)
        $lines.Add('    Rationale: ' + [string]$proposal.rationale)
        foreach ($reference in @($proposal.evidenceReferences)) { $lines.Add('    Evidence: ' + [string]$reference.sessionId + ':' + [string]$reference.eventId) }
        foreach ($limitation in @($proposal.limitations)) { $lines.Add('    Limitation: ' + [string]$limitation) }
    }
    $lines.Add('')
    $lines.Add('Unresolved questions:')
    if (@($Payload.unresolvedQuestions).Count -eq 0) { $lines.Add('  None recorded.') }
    foreach ($question in @($Payload.unresolvedQuestions)) { $lines.Add('  - ' + [string]$question) }
    $lines.Add('')
    $lines.Add('Redaction: query values are redacted; credential fields are omitted or redacted; bodies and raw events are excluded.')
    $lines.Add('Evidence references and hashes identify records; they do not establish authorship or appliance policy.')
    return [string]::Join([Environment]::NewLine, $lines.ToArray()) + [Environment]::NewLine
}

function Write-MihariChangeRequestFileAtomic {
    param([Parameter(Mandatory = $true)][string] $Path, [Parameter(Mandatory = $true)][string] $Text)
    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $directory = [System.IO.Path]::GetDirectoryName($fullPath)
    if (-not [System.IO.Directory]::Exists($directory)) { [void][System.IO.Directory]::CreateDirectory($directory) }
    $temporaryPath = $fullPath + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
    $encoding = [System.Text.UTF8Encoding]::new($false)
    try {
        [System.IO.File]::WriteAllText($temporaryPath, $Text, $encoding)
        if ([System.IO.File]::Exists($fullPath)) { [System.IO.File]::Delete($fullPath) }
        [System.IO.File]::Move($temporaryPath, $fullPath)
    }
    finally { if ([System.IO.File]::Exists($temporaryPath)) { [System.IO.File]::Delete($temporaryPath) } }
}

function Export-MihariChangeRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][ValidateSet('json', 'csv', 'text', 'all')][string] $Format,
        [Parameter(Mandatory = $true)][object] $Preview,
        [object] $Case,
        [object] $Trial,
        [object[]] $Dependencies = @(),
        [object[]] $Proposals = @(),
        [string] $BusinessAction,
        [object] $ReproductionConditions,
        [string[]] $UnresolvedQuestions = @()
    )

    $previewId = ConvertTo-MihariDependencySafeText -Value (Get-MihariDependencyValue -InputObject $Preview -Names @('previewId')) -MaximumLength 128
    if ($null -eq $previewId) { throw 'A change request preview is required before export.' }
    $currentPreview = Get-MihariChangeRequestPreview -Case $Case -Trial $Trial -Dependencies $Dependencies -Proposals $Proposals -BusinessAction $BusinessAction -ReproductionConditions $ReproductionConditions -UnresolvedQuestions $UnresolvedQuestions
    if (-not [string]::Equals($previewId, [string]$currentPreview.previewId, [StringComparison]::Ordinal)) {
        throw 'The change request inputs changed after preview; review a fresh preview before export.'
    }
    $built = New-MihariChangeRequestPayload -Case $Case -Trial $Trial -Dependencies $Dependencies -Proposals $Proposals -BusinessAction $BusinessAction -ReproductionConditions $ReproductionConditions -UnresolvedQuestions $UnresolvedQuestions
    $document = [ordered]@{}
    foreach ($property in $built.Payload.PSObject.Properties) { $document[$property.Name] = $property.Value }
    $document['generatedAtUtc'] = [DateTime]::UtcNow.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
    $json = ConvertTo-Json -InputObject ([pscustomobject]$document) -Depth 8 -Compress -ErrorAction Stop
    $csv = ConvertTo-MihariChangeRequestCsv -Payload ([pscustomobject]$document)
    $report = New-MihariChangeRequestText -Payload ([pscustomobject]$document)
    $base = [System.IO.Path]::GetFullPath($Path)
    if ($Format -eq 'all') {
        $stem = [System.IO.Path]::Combine([System.IO.Path]::GetDirectoryName($base), [System.IO.Path]::GetFileNameWithoutExtension($base))
        $files = @(
            [pscustomobject]@{ format = 'json'; path = $stem + '.json'; content = $json + [Environment]::NewLine },
            [pscustomobject]@{ format = 'csv'; path = $stem + '.csv'; content = $csv },
            [pscustomobject]@{ format = 'text'; path = $stem + '.txt'; content = $report }
        )
    }
    else {
        $extension = '.' + $Format
        if ([System.IO.Path]::GetExtension($base) -ine $extension) { $base += $extension }
        $content = $json + [Environment]::NewLine
        if ($Format -eq 'csv') { $content = $csv }
        elseif ($Format -eq 'text') { $content = $report }
        $files = @([pscustomobject]@{ format = $Format; path = $base; content = $content })
    }
    foreach ($file in $files) { Write-MihariChangeRequestFileAtomic -Path $file.path -Text $file.content }
    return [pscustomobject]@{
        accepted = $true; completed = $true; failed = $false; previewId = $previewId
        files = @($files | ForEach-Object { [pscustomobject]@{ format = $_.format; path = $_.path } })
        included = $currentPreview.included; redacted = $currentPreview.redacted
    }
}
