function Get-MihariBrowserUtcIdentityTicks {
    param([AllowNull()][object] $Value)

    if ($null -eq $Value) { return $null }
    if ($Value -is [DateTimeOffset]) { return [long]$Value.UtcDateTime.Ticks }
    if ($Value -is [DateTime]) {
        if ($Value.Kind -eq [DateTimeKind]::Unspecified) { return $null }
        return [long]$Value.ToUniversalTime().Ticks
    }

    $text = [string]$Value
    if ($text -notmatch '(?i)(?:Z|[+-][0-9]{2}:[0-9]{2})$') { return $null }
    $parsed = [DateTimeOffset]::MinValue
    $parsedSuccessfully = [DateTimeOffset]::TryParse(
        $text,
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::None,
        [ref]$parsed
    )
    if (-not $parsedSuccessfully) { return $null }
    return [long]$parsed.UtcDateTime.Ticks
}

function Test-MihariBrowserUtcIdentityEqual {
    param(
        [AllowNull()][object] $Left,
        [AllowNull()][object] $Right
    )

    $leftTicks = Get-MihariBrowserUtcIdentityTicks -Value $Left
    $rightTicks = Get-MihariBrowserUtcIdentityTicks -Value $Right
    if ($null -eq $leftTicks -or $null -eq $rightTicks) { return $false }
    return ([long]$leftTicks -eq [long]$rightTicks)
}

function Get-MihariBrowserMemberValue {
    param(
        [AllowNull()][object] $InputObject,
        [Parameter(Mandatory = $true)][string] $Name
    )

    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [System.Collections.IDictionary]) {
        foreach ($key in $InputObject.Keys) {
            if ([string]::Equals([string]$key, $Name, [StringComparison]::OrdinalIgnoreCase)) {
                return $InputObject[$key]
            }
        }
        return $null
    }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -ne $property) { return $property.Value }
    return $null
}

function Get-MihariBrowserScopedId {
    param(
        [Parameter(Mandatory = $true)][string] $Scope,
        [Parameter(Mandatory = $true)][string] $Value,
        [string] $Prefix = 'br'
    )

    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Scope + "`n" + $Value)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $digest = $sha.ComputeHash($bytes)
        $hex = [System.BitConverter]::ToString($digest).Replace('-', '').ToLowerInvariant()
        return ($Prefix + '-' + $hex.Substring(0, 24))
    }
    finally { $sha.Dispose() }
}

function ConvertTo-MihariBrowserSafeTarget {
    param([AllowNull()][string] $Url)

    if ([string]::IsNullOrWhiteSpace($Url) -or $Url.Length -gt 16384) { return $null }
    $uri = $null
    if (-not [Uri]::TryCreate($Url, [UriKind]::Absolute, [ref]$uri)) { return $null }
    if ($uri.Scheme -notin @('http', 'https') -or [string]::IsNullOrWhiteSpace($uri.Host)) { return $null }
    $hostName = $uri.DnsSafeHost.ToLowerInvariant()
    if ($hostName.Length -gt 253) { return $null }
    $path = $uri.GetComponents([UriComponents]::Path, [UriFormat]::UriEscaped)
    if ([string]::IsNullOrEmpty($path)) { $path = '/' }
    elseif (-not $path.StartsWith('/')) { $path = '/' + $path }
    if ($path.Length -gt 4096) { $path = $path.Substring(0, 4096) }
    if (Get-Command ConvertTo-MihariSafeText -CommandType Function -ErrorAction SilentlyContinue) {
        $path = ConvertTo-MihariSafeText -Text $path
    }
    else {
        $path = [regex]::Replace($path, '([?&][^=&#\s]+)=([^&#\s]*)', '$1=[REDACTED]')
    }
    return [pscustomobject]@{
        Scheme = $uri.Scheme.ToLowerInvariant()
        Host = $hostName
        Port = [int]$uri.Port
        Path = $path
    }
}

function ConvertTo-MihariBrowserSafeProtocol {
    param([AllowNull()][object] $Protocol)

    if ($null -eq $Protocol) { return $null }
    $value = ([string]$Protocol).Trim().ToLowerInvariant()
    if ($value -notmatch '^[a-z0-9][a-z0-9._/-]{0,31}$') { return $null }
    return $value
}

function ConvertTo-MihariBrowserSafeMethod {
    param([AllowNull()][object] $Method)

    if ($null -eq $Method) { return $null }
    $value = [string]$Method
    if ($value.Length -gt 32 -or $value -notmatch '^[A-Za-z0-9!#$%&''*+.^_`|~-]+$') { return $null }
    return $value.ToUpperInvariant()
}

function ConvertTo-MihariBrowserSafeInitiatorType {
    param([AllowNull()][object] $InitiatorType)

    if ($null -eq $InitiatorType) { return $null }
    $value = ([string]$InitiatorType).ToLowerInvariant()
    if ($value -in @('parser', 'script', 'preload', 'signedexchange', 'preflight', 'other', 'redirect', 'useragent')) {
        return $value
    }
    return $null
}

function ConvertTo-MihariBrowserSafeError {
    param(
        [AllowNull()][object] $ErrorText,
        [AllowNull()][object] $BlockedReason,
        [AllowNull()][object] $CorsError
    )

    if ($null -ne $ErrorText) {
        $value = [string]$ErrorText
        if ($value -match '^net::(ERR_[A-Z0-9_]{1,80})$') { return ('net::' + $Matches[1]) }
    }
    if ($null -ne $BlockedReason) {
        $value = ([string]$BlockedReason).ToLowerInvariant()
        if ($value -in @('inspector', 'other', 'csp', 'mixed-content', 'origin', 'subresource-filter', 'content-type', 'coep-frame-resource-needs-coep-header', 'corp-not-same-origin')) {
            return ('blocked:' + $value)
        }
    }
    if ($null -ne $CorsError) {
        $value = [string]$CorsError
        if ($value -match '^[A-Za-z][A-Za-z0-9_]{0,63}$') { return ('cors:' + $value) }
    }
    return $null
}

function ConvertTo-MihariBrowserSafeRequest {
    param([AllowNull()][object] $Request)

    $target = ConvertTo-MihariBrowserSafeTarget -Url ([string](Get-MihariBrowserMemberValue -InputObject $Request -Name 'url'))
    if ($null -eq $target) { return $null }
    $method = ConvertTo-MihariBrowserSafeMethod -Method (Get-MihariBrowserMemberValue -InputObject $Request -Name 'method')
    if ($null -eq $method) { return $null }
    $authorityPort = ''
    if (($target.Scheme -eq 'https' -and $target.Port -ne 443) -or ($target.Scheme -eq 'http' -and $target.Port -ne 80)) {
        $authorityPort = ':' + $target.Port
    }
    return [pscustomobject]@{
        url = ('{0}://{1}{2}{3}' -f $target.Scheme, $target.Host, $authorityPort, $target.Path)
        method = $method
    }
}

function ConvertTo-MihariBrowserSafeResponse {
    param([AllowNull()][object] $Response)

    if ($null -eq $Response) { return $null }
    $safe = [ordered]@{}
    $status = 0
    $statusValue = Get-MihariBrowserMemberValue -InputObject $Response -Name 'status'
    if ($null -ne $statusValue -and [int]::TryParse([string]$statusValue, [ref]$status) -and $status -ge 100 -and $status -le 599) {
        $safe['status'] = $status
    }
    $protocol = ConvertTo-MihariBrowserSafeProtocol -Protocol (Get-MihariBrowserMemberValue -InputObject $Response -Name 'protocol')
    if ($null -ne $protocol) { $safe['protocol'] = $protocol }
    $connection = Get-MihariBrowserMemberValue -InputObject $Response -Name 'connectionId'
    $connectionNumber = 0L
    if ($null -ne $connection -and [long]::TryParse([string]$connection, [ref]$connectionNumber) -and $connectionNumber -ge 0) {
        $safe['connectionId'] = $connectionNumber
    }
    foreach ($name in @('fromDiskCache', 'fromServiceWorker')) {
        $value = Get-MihariBrowserMemberValue -InputObject $Response -Name $name
        if ($value -is [bool]) { $safe[$name] = $value }
    }
    return [pscustomobject]$safe
}

function ConvertTo-MihariBrowserMonotonicTimestamp {
    param([AllowNull()][object] $Value)

    if ($null -eq $Value -or $Value -is [bool]) { return $null }
    $parsed = 0.0
    if (-not [double]::TryParse([string]$Value, [Globalization.NumberStyles]::Float,
            [Globalization.CultureInfo]::InvariantCulture, [ref]$parsed) -or
        [double]::IsNaN($parsed) -or [double]::IsInfinity($parsed)) { return $null }
    return $parsed
}

function ConvertTo-MihariBrowserRequestFact {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string] $SessionId,
        [Parameter(Mandatory = $true)][int] $ProcessId,
        [Parameter(Mandatory = $true)][string] $TargetId,
        [Parameter(Mandatory = $true)][string] $BrowserRequestId,
        [AllowNull()][string] $FrameId,
        [Parameter(Mandatory = $true)][int] $RedirectIndex,
        [AllowNull()][object] $Request,
        [AllowNull()][object] $Response,
        [AllowNull()][object] $InitiatorType,
        [Parameter(Mandatory = $true)][ValidateSet('completed', 'redirected', 'failed', 'incomplete')][string] $Outcome,
        [AllowNull()][object] $ErrorText,
        [AllowNull()][object] $BlockedReason,
        [AllowNull()][object] $CorsError,
        [AllowNull()][object] $StartTimestamp,
        [AllowNull()][object] $EndTimestamp,
        [AllowNull()][object] $BrowserConnectionId,
        [AllowNull()][object] $FromDiskCache,
        [AllowNull()][object] $FromServiceWorker
    )

    $targetFactId = Get-MihariBrowserScopedId -Scope ($SessionId + ':' + $ProcessId) -Value $TargetId -Prefix 'bt'
    $requestFactId = Get-MihariBrowserScopedId -Scope ($targetFactId + ':' + $BrowserRequestId) -Value ([string]$RedirectIndex) -Prefix 'br'
    $connectionFactId = $null
    $connectionIdText = [string]$BrowserConnectionId
    if (-not [string]::IsNullOrWhiteSpace($connectionIdText) -and $connectionIdText -match '^\d{1,20}$') {
        $connectionFactId = Get-MihariBrowserScopedId -Scope ($SessionId + ':' + $ProcessId) -Value $connectionIdText -Prefix 'bc'
    }
    if ([string]::IsNullOrWhiteSpace($connectionFactId)) {
        # The envelope requires an identity. This per-attempt placeholder cannot
        # merge requests that lack an observed transport connection ID.
        $connectionFactId = 'browser-unknown-' + $requestFactId
    }

    $url = [string](Get-MihariBrowserMemberValue -InputObject $Request -Name 'url')
    $target = ConvertTo-MihariBrowserSafeTarget -Url $url
    $method = ConvertTo-MihariBrowserSafeMethod -Method (Get-MihariBrowserMemberValue -InputObject $Request -Name 'method')
    $initiator = ConvertTo-MihariBrowserSafeInitiatorType -InitiatorType $InitiatorType
    $protocol = ConvertTo-MihariBrowserSafeProtocol -Protocol (Get-MihariBrowserMemberValue -InputObject $Response -Name 'protocol')
    $statusCode = 0
    $statusValue = Get-MihariBrowserMemberValue -InputObject $Response -Name 'status'
    $hasStatus = $null -ne $statusValue -and [int]::TryParse([string]$statusValue, [ref]$statusCode) -and $statusCode -ge 100 -and $statusCode -le 599
    $safeError = ConvertTo-MihariBrowserSafeError -ErrorText $ErrorText -BlockedReason $BlockedReason -CorsError $CorsError
    $data = [ordered]@{
        browserTargetId = $targetFactId
        browserRequestId = $requestFactId
        browserRedirectIndex = $RedirectIndex
    }
    if ($null -ne $FrameId -and $FrameId -match '^[A-Za-z0-9._:-]{1,128}$') {
        $data['browserFrameId'] = Get-MihariBrowserScopedId -Scope $targetFactId -Value $FrameId -Prefix 'bf'
    }
    if ($null -ne $target) {
        $data['scheme'] = $target.Scheme
        $data['host'] = $target.Host
        $data['port'] = $target.Port
        $data['path'] = $target.Path
    }
    if ($null -ne $method) { $data['method'] = $method }
    if ($hasStatus) { $data['statusCode'] = $statusCode }
    if ($null -ne $protocol) { $data['protocol'] = $protocol }
    if ($null -ne $initiator) { $data['initiatorType'] = $initiator }
    if ($null -ne $safeError) { $data['browserError'] = $safeError }
    if ($null -ne $FromDiskCache -and $FromDiskCache -is [bool]) { $data['fromDiskCache'] = $FromDiskCache }
    if ($null -ne $FromServiceWorker -and $FromServiceWorker -is [bool]) { $data['fromServiceWorker'] = $FromServiceWorker }
    if ($null -ne $connectionFactId -and $connectionFactId -notlike 'browser-unknown-*') {
        $data['browserConnectionId'] = $connectionFactId
    }

    $elapsedMs = $null
    $startMonotonic = ConvertTo-MihariBrowserMonotonicTimestamp -Value $StartTimestamp
    $endMonotonic = ConvertTo-MihariBrowserMonotonicTimestamp -Value $EndTimestamp
    if ($null -ne $startMonotonic -and $null -ne $endMonotonic -and $endMonotonic -ge $startMonotonic) {
        $elapsedMs = [long][Math]::Round(($endMonotonic - $startMonotonic) * 1000.0, 0, [MidpointRounding]::AwayFromZero)
        $data['browserTimingOrigin'] = 'cdp_monotonic'
        $data['browserTimingStartMs'] = [long][Math]::Max(0, [Math]::Round($startMonotonic * 1000.0, 0, [MidpointRounding]::AwayFromZero))
        $data['browserTimingDurationMs'] = [long]$elapsedMs
    }
    return [pscustomobject]@{
        ConnectionId = $connectionFactId
        RequestId = $requestFactId
        Outcome = $Outcome
        ElapsedMs = $elapsedMs
        Data = $data
        Coverage = 'observed'
    }
}

function Set-MihariBrowserSessionProperty {
    param(
        [Parameter(Mandatory = $true)][object] $Session,
        [Parameter(Mandatory = $true)][string] $Name,
        [AllowNull()][object] $Value
    )
    $property = $Session.PSObject.Properties[$Name]
    if ($null -eq $property) {
        Add-Member -InputObject $Session -MemberType NoteProperty -Name $Name -Value $Value
    }
    else { $Session.$Name = $Value }
}

function New-MihariBrowserProfileOwnerMarker {
    param(
        [Parameter(Mandatory = $true)][string] $SessionId,
        [Parameter(Mandatory = $true)][object] $Launch
    )

    $safeSessionId = [regex]::Replace($SessionId, '[^A-Za-z0-9_-]', '_')
    $expectedParent = [System.IO.Path]::GetFullPath((Join-Path ([System.IO.Path]::GetTempPath()) 'Mihari'))
    $profilePath = [System.IO.Path]::GetFullPath([string]$Launch.ProfilePath)
    $actualParent = [System.IO.Path]::GetDirectoryName($profilePath)
    $leaf = [System.IO.Path]::GetFileName($profilePath)
    if (-not [string]::Equals($actualParent, $expectedParent, [StringComparison]::OrdinalIgnoreCase) -or
        $leaf -notmatch ('^Edge-' + [regex]::Escape($safeSessionId) + '-[0-9a-fA-F]{32}$')) {
        return $false
    }
    if ([string]::IsNullOrWhiteSpace([string]$Launch.OwnerStartTimeUtc) -or [int]$Launch.Pid -lt 1) {
        return $false
    }
    $marker = [pscustomobject]@{
        schemaVersion = 1
        owner = 'Mihari'
        sessionId = $SessionId
        processId = [int]$Launch.Pid
        processStartTimeUtc = [string]$Launch.OwnerStartTimeUtc
        profilePath = $profilePath
        executablePath = [string]$Launch.Path
    }
    try {
        $markerPath = [System.IO.Path]::Combine($profilePath, 'MihariProfileOwner.json')
        $json = ConvertTo-Json -InputObject $marker -Depth 3 -Compress
        [System.IO.File]::WriteAllText($markerPath, $json, [System.Text.UTF8Encoding]::new($false))
        return $true
    }
    catch {
        return $false
    }
}

function Test-MihariBrowserOwnedProfileArgument {
    param(
        [AllowNull()][string] $CommandLine,
        [Parameter(Mandatory = $true)][string] $ProfilePath
    )

    if ([string]::IsNullOrWhiteSpace($CommandLine) -or $ProfilePath.Length -gt 4096) { return $false }
    try { $fullPath = [System.IO.Path]::GetFullPath($ProfilePath) }
    catch { return $false }
    $escapedPath = [System.Text.RegularExpressions.Regex]::Escape($fullPath)
    $pattern = '(?i)(?:^|[\s"])--user-data-dir=(?:' + $escapedPath + '|"' + $escapedPath + '")(?=$|[\s"])'
    return [System.Text.RegularExpressions.Regex]::IsMatch($CommandLine, $pattern)
}

function Get-MihariBrowserOwnedProfileIdentity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string] $SessionId,
        [Parameter(Mandatory = $true)][object] $Launch,
        [ValidateRange(1, 15)][int] $TimeoutSeconds = 5
    )

    $failure = { param($Code, $Count) [pscustomobject]@{ Success = $false; ProcessId = $null; OwnerStartTimeUtc = $null; ErrorCode = $Code; MatchingProcessCount = [int]$Count } }
    if ($null -eq (Get-Command Get-CimInstance -CommandType Cmdlet -ErrorAction SilentlyContinue)) {
        return (& $failure 'browser_process_inventory_unavailable' 0)
    }
    if ([string]::IsNullOrWhiteSpace([string]$Launch.ProfilePath) -or
        [string]::IsNullOrWhiteSpace([string]$Launch.Path) -or
        [string]::IsNullOrWhiteSpace($SessionId)) {
        return (& $failure 'browser_profile_identity_invalid' 0)
    }

    $profilePath = $null
    $executablePath = $null
    try {
        $profilePath = [System.IO.Path]::GetFullPath([string]$Launch.ProfilePath)
        $executablePath = [System.IO.Path]::GetFullPath([string]$Launch.Path)
    }
    catch { return (& $failure 'browser_profile_identity_invalid' 0) }

    $safeSessionId = [regex]::Replace($SessionId, '[^A-Za-z0-9_-]', '_')
    $expectedParent = [System.IO.Path]::GetFullPath((Join-Path ([System.IO.Path]::GetTempPath()) 'Mihari'))
    $leaf = [System.IO.Path]::GetFileName($profilePath)
    if (-not [string]::Equals([System.IO.Path]::GetDirectoryName($profilePath), $expectedParent, [StringComparison]::OrdinalIgnoreCase) -or
        $leaf -notmatch ('^Edge-' + [regex]::Escape($safeSessionId) + '-[0-9a-fA-F]{32}$')) {
        return (& $failure 'browser_profile_identity_invalid' 0)
    }

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $matchCount = 0
    $previousOwnerProcessId = 0
    $previousOwnerStartTimeUtc = $null
    $stableOwnerPolls = 0
    $lastRootProcessCount = 0
    $unverifiableCount = 0
    do {
        $processes = @()
        try {
            $processes = @(Get-CimInstance -ClassName Win32_Process -Filter "Name = 'msedge.exe'" -ErrorAction Stop)
        }
        catch { return (& $failure 'browser_process_inventory_unavailable' $matchCount) }

        $rootProcesses = New-Object 'System.Collections.Generic.List[object]'
        $profileMatchCount = 0
        $unverifiableCount = 0
        foreach ($processInfo in $processes) {
            $commandLine = [string]$processInfo.CommandLine
            if (-not (Test-MihariBrowserOwnedProfileArgument -CommandLine $commandLine -ProfilePath $profilePath)) { continue }
            $profileMatchCount++
            $inventoryPath = [string]$processInfo.ExecutablePath
            if ([string]::IsNullOrWhiteSpace($inventoryPath)) { $unverifiableCount++; continue }
            try {
                if (-not [string]::Equals([System.IO.Path]::GetFullPath($inventoryPath), $executablePath, [StringComparison]::OrdinalIgnoreCase)) { continue }
                $process = [System.Diagnostics.Process]::GetProcessById([int]$processInfo.ProcessId)
                try {
                    if ($process.HasExited) { continue }
                    $actualPath = [string]$process.MainModule.FileName
                    if (-not [string]::Equals([System.IO.Path]::GetFullPath($actualPath), $executablePath, [StringComparison]::OrdinalIgnoreCase)) { continue }
                    $startTimeUtc = $process.StartTime.ToUniversalTime().ToString('o', [Globalization.CultureInfo]::InvariantCulture)
                    if ([string]::IsNullOrWhiteSpace($startTimeUtc)) { continue }
                    if ($commandLine -match '(?i)(?:^|[\s"])--type=') { continue }
                    $rootProcesses.Add([pscustomobject]@{ ProcessId = [int]$processInfo.ProcessId; OwnerStartTimeUtc = $startTimeUtc })
                }
                finally { $process.Dispose() }
            }
            catch {
                $unverifiableCount++
            }
        }

        $matchCount = $profileMatchCount
        $lastRootProcessCount = $rootProcesses.Count
        if ($rootProcesses.Count -eq 1) {
            $owner = $rootProcesses[0]
            if ([int]$owner.ProcessId -eq $previousOwnerProcessId -and
                [string]$owner.OwnerStartTimeUtc -ceq [string]$previousOwnerStartTimeUtc) {
                $stableOwnerPolls++
            }
            else {
                $previousOwnerProcessId = [int]$owner.ProcessId
                $previousOwnerStartTimeUtc = [string]$owner.OwnerStartTimeUtc
                $stableOwnerPolls = 1
            }
            if ($stableOwnerPolls -ge 2) {
                return [pscustomobject]@{
                    Success = $true; ProcessId = [int]$owner.ProcessId; OwnerStartTimeUtc = [string]$owner.OwnerStartTimeUtc
                    ErrorCode = $null; MatchingProcessCount = $matchCount
                }
            }
        }
        else {
            $previousOwnerProcessId = 0
            $previousOwnerStartTimeUtc = $null
            $stableOwnerPolls = 0
        }
        if ([DateTime]::UtcNow -lt $deadline) {
            if ($rootProcesses.Count -eq 1 -and $stableOwnerPolls -eq 1) { Start-Sleep -Milliseconds 500 }
            else { Start-Sleep -Milliseconds 100 }
        }
    } while ([DateTime]::UtcNow -lt $deadline)

    $errorCode = 'browser_profile_process_not_found'
    if ($lastRootProcessCount -gt 1) { $errorCode = 'browser_profile_owner_ambiguous' }
    elseif ($matchCount -gt 0 -or $unverifiableCount -gt 0) { $errorCode = 'browser_profile_owner_unverifiable' }
    return (& $failure $errorCode $matchCount)
}

function Get-MihariBrowserOwnedProcessVerification {
    param(
        [Parameter(Mandatory = $true)][string] $SessionId,
        [Parameter(Mandatory = $true)][object] $Launch
    )

    $result = { param($Verified, $FailureDetailCode) [pscustomobject]@{ Verified = [bool]$Verified; FailureDetailCode = $FailureDetailCode } }
    if ($null -eq $Launch.Pid -or [int]$Launch.Pid -lt 1 -or
        [string]::IsNullOrWhiteSpace([string]$Launch.OwnerStartTimeUtc) -or
        [string]::IsNullOrWhiteSpace([string]$Launch.ProfilePath) -or
        [string]::IsNullOrWhiteSpace([string]$Launch.Path)) { return (& $result $false 'profile_marker_mismatch') }
    try {
        $profilePath = [System.IO.Path]::GetFullPath([string]$Launch.ProfilePath)
    }
    catch { return (& $result $false 'profile_marker_invalid') }
    try {
        $markerPath = [System.IO.Path]::Combine($profilePath, 'MihariProfileOwner.json')
        if (-not [System.IO.File]::Exists($markerPath)) { return (& $result $false 'profile_marker_missing') }
        try { $fileInfo = Get-Item -LiteralPath $markerPath -ErrorAction Stop }
        catch { return (& $result $false 'profile_marker_invalid') }
        if ($fileInfo.Length -gt 4096) { return (& $result $false 'profile_marker_invalid') }
        try {
            $marker = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($markerPath, [System.Text.Encoding]::UTF8)) -ErrorAction Stop
        }
        catch { return (& $result $false 'profile_marker_invalid') }
        if ([string]$marker.owner -cne 'Mihari' -or [string]$marker.sessionId -cne $SessionId -or
            [int]$marker.processId -ne [int]$Launch.Pid -or
            -not [string]::Equals([string]$marker.profilePath, $profilePath, [StringComparison]::OrdinalIgnoreCase) -or
            -not [string]::Equals([string]$marker.executablePath, [string]$Launch.Path, [StringComparison]::OrdinalIgnoreCase)) {
            return (& $result $false 'profile_marker_mismatch')
        }
        if (-not (Test-MihariBrowserUtcIdentityEqual -Left $marker.processStartTimeUtc -Right $Launch.OwnerStartTimeUtc)) {
            return (& $result $false 'profile_marker_mismatch')
        }
        try {
            $processInventory = @(Get-CimInstance -ClassName Win32_Process -Filter ('ProcessId = {0}' -f [int]$Launch.Pid) -ErrorAction Stop)
        }
        catch { return (& $result $false 'process_inventory_unavailable') }
        if ($processInventory.Count -ne 1 -or [string]$processInventory[0].Name -ine 'msedge.exe') {
            return (& $result $false 'process_inventory_mismatch')
        }
        if (-not (Test-MihariBrowserOwnedProfileArgument -CommandLine ([string]$processInventory[0].CommandLine) -ProfilePath $profilePath)) {
            return (& $result $false 'profile_argument_mismatch')
        }
        if ([string]::IsNullOrWhiteSpace([string]$processInventory[0].ExecutablePath) -or
            -not [string]::Equals([System.IO.Path]::GetFullPath([string]$processInventory[0].ExecutablePath),
                [System.IO.Path]::GetFullPath([string]$Launch.Path), [StringComparison]::OrdinalIgnoreCase)) {
            return (& $result $false 'process_executable_mismatch')
        }
        try { $process = [System.Diagnostics.Process]::GetProcessById([int]$Launch.Pid) }
        catch { return (& $result $false 'process_identity_unavailable') }
        try {
            if ($process.HasExited) { return (& $result $false 'process_identity_unavailable') }
            $actualPath = [string]$process.MainModule.FileName
            $actualStartTicks = Get-MihariBrowserUtcIdentityTicks -Value $process.StartTime.ToUniversalTime()
            $expectedStartTicks = Get-MihariBrowserUtcIdentityTicks -Value $Launch.OwnerStartTimeUtc
            if ($null -eq $actualStartTicks -or $null -eq $expectedStartTicks) {
                return (& $result $false 'process_start_time_mismatch')
            }
            if (-not [string]::Equals([System.IO.Path]::GetFullPath($actualPath), [System.IO.Path]::GetFullPath([string]$Launch.Path), [StringComparison]::OrdinalIgnoreCase)) {
                return (& $result $false 'process_executable_mismatch')
            }
            if ([Math]::Abs([long]$actualStartTicks - [long]$expectedStartTicks) -gt [TimeSpan]::TicksPerSecond) {
                return (& $result $false 'process_start_time_mismatch')
            }
            return (& $result $true $null)
        }
        finally { $process.Dispose() }
    }
    catch { return (& $result $false 'process_identity_unavailable') }
}

function Test-MihariBrowserOwnedProcess {
    param(
        [Parameter(Mandatory = $true)][string] $SessionId,
        [Parameter(Mandatory = $true)][object] $Launch
    )

    $verification = Get-MihariBrowserOwnedProcessVerification -SessionId $SessionId -Launch $Launch
    return [bool]$verification.Verified
}

function Remove-MihariOwnedBrowserProfile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string] $SessionId,
        [Parameter(Mandatory = $true)][string] $ProfilePath
    )

    $safeSessionId = [regex]::Replace($SessionId, '[^A-Za-z0-9_-]', '_')
    $expectedParent = [System.IO.Path]::GetFullPath((Join-Path ([System.IO.Path]::GetTempPath()) 'Mihari'))
    $fullProfilePath = [System.IO.Path]::GetFullPath($ProfilePath)
    $leaf = [System.IO.Path]::GetFileName($fullProfilePath)
    if (-not [string]::Equals([System.IO.Path]::GetDirectoryName($fullProfilePath), $expectedParent, [StringComparison]::OrdinalIgnoreCase) -or
        $leaf -notmatch ('^Edge-' + [regex]::Escape($safeSessionId) + '-[0-9a-fA-F]{32}$')) {
        return [pscustomobject]@{ removed = $false; reason = 'profile_path_not_owned' }
    }
    if (-not [System.IO.Directory]::Exists($fullProfilePath)) {
        return [pscustomobject]@{ removed = $false; reason = 'profile_not_found' }
    }
    $directoryInfo = Get-Item -LiteralPath $fullProfilePath -Force -ErrorAction Stop
    if (($directoryInfo.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        return [pscustomobject]@{ removed = $false; reason = 'profile_path_reparse_point' }
    }
    $markerPath = [System.IO.Path]::Combine($fullProfilePath, 'MihariProfileOwner.json')
    if (-not [System.IO.File]::Exists($markerPath)) {
        return [pscustomobject]@{ removed = $false; reason = 'ownership_marker_missing' }
    }
    try {
        $markerInfo = Get-Item -LiteralPath $markerPath -ErrorAction Stop
        if ($markerInfo.Length -gt 4096) { return [pscustomobject]@{ removed = $false; reason = 'ownership_marker_invalid' } }
        $marker = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($markerPath, [System.Text.Encoding]::UTF8)) -ErrorAction Stop
        if ([string]$marker.owner -cne 'Mihari' -or [string]$marker.sessionId -cne $SessionId -or
            -not [string]::Equals([string]$marker.profilePath, $fullProfilePath, [StringComparison]::OrdinalIgnoreCase) -or
            [int]$marker.processId -lt 1 -or [string]::IsNullOrWhiteSpace([string]$marker.processStartTimeUtc)) {
            return [pscustomobject]@{ removed = $false; reason = 'ownership_marker_mismatch' }
        }
    }
    catch {
        return [pscustomobject]@{ removed = $false; reason = 'ownership_marker_unreadable' }
    }

    if (-not (Get-Command Get-CimInstance -CommandType Cmdlet -ErrorAction SilentlyContinue)) {
        return [pscustomobject]@{ removed = $false; reason = 'browser_process_ownership_unavailable' }
    }
    try {
        $edgeProcesses = @(Get-CimInstance -ClassName Win32_Process -Filter "Name = 'msedge.exe'" -ErrorAction Stop)
        foreach ($edgeProcess in $edgeProcesses) {
            $commandLine = [string]$edgeProcess.CommandLine
            if ([string]::IsNullOrWhiteSpace($commandLine)) {
                return [pscustomobject]@{ removed = $false; reason = 'browser_process_ownership_unverified' }
            }
            if ($commandLine.IndexOf($fullProfilePath, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                return [pscustomobject]@{ removed = $false; reason = 'profile_in_use' }
            }
        }
    }
    catch {
        return [pscustomobject]@{ removed = $false; reason = 'browser_process_ownership_unavailable' }
    }

    try {
        $directories = New-Object System.Collections.Stack
        $directories.Push($fullProfilePath)
        $entryCount = 0
        while ($directories.Count -gt 0) {
            $directoryPath = [string]$directories.Pop()
            foreach ($childPath in [System.IO.Directory]::EnumerateFileSystemEntries($directoryPath)) {
                $entryCount++
                if ($entryCount -gt 100000) {
                    return [pscustomobject]@{ removed = $false; reason = 'profile_scan_limit_reached' }
                }
                $childInfo = Get-Item -LiteralPath $childPath -Force -ErrorAction Stop
                if (($childInfo.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                    return [pscustomobject]@{ removed = $false; reason = 'profile_contains_reparse_point' }
                }
                if ($childInfo.PSIsContainer) {
                    $directories.Push([string]$childInfo.FullName)
                }
            }
        }
        Remove-Item -LiteralPath $fullProfilePath -Recurse -Force -ErrorAction Stop
        if ([System.IO.Directory]::Exists($fullProfilePath)) {
            return [pscustomobject]@{ removed = $false; reason = 'profile_cleanup_incomplete' }
        }
        return [pscustomobject]@{ removed = $true; reason = 'removed' }
    }
    catch {
        return [pscustomobject]@{ removed = $false; reason = 'profile_cleanup_failed' }
    }
}

function Write-MihariBrowserObservationFact {
    param(
        [Parameter(Mandatory = $true)][object] $Session,
        [Parameter(Mandatory = $true)][object] $Launch,
        [Parameter(Mandatory = $true)][string] $Stage,
        [Parameter(Mandatory = $true)][string] $Outcome,
        [AllowNull()][string] $ConnectionId,
        [AllowNull()][string] $RequestId,
        [AllowNull()][object] $ElapsedMs,
        [AllowNull()][object] $Data,
        [Parameter(Mandatory = $true)][ValidateSet('observed', 'unknown', 'unsupported', 'permission_denied', 'truncated', 'lost')][string] $Coverage
    )

    $arguments = @{
        Session = $Session
        ConnectionId = $ConnectionId
        RequestId = $RequestId
        Stage = $Stage
        Outcome = $Outcome
        ElapsedMs = $ElapsedMs
        Data = $Data
        Mode = [string]$Session.Mode
        Source = 'browser'
        Coverage = $Coverage
        TransportLeg = 'end_to_end'
        SourceIdentity = [string]$Launch.SourceIdentity
        SourceVersion = $(if ([string]::IsNullOrWhiteSpace([string]$Launch.SourceVersion)) { 'edge-devtools-protocol' } else { [string]$Launch.SourceVersion })
        ClockId = [string]$Launch.ClockId
    }
    $revision = Get-MihariBrowserMemberValue -InputObject $Session -Name 'ConfigurationRevision'
    if ($null -ne $revision) { $arguments.ConfigurationRevision = [int]$revision }
    $null = Write-MihariEvent @arguments
}

function Get-MihariBrowserDevToolsConnectionInfo {
    param(
        [Parameter(Mandatory = $true)][string] $ProfilePath,
        [Parameter(Mandatory = $true)][System.Threading.CancellationToken] $CancellationToken,
        [int] $TimeoutSeconds = 15
    )

    $portPath = [System.IO.Path]::Combine($ProfilePath, 'DevToolsActivePort')
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $port = 0
    while ([DateTime]::UtcNow -lt $deadline) {
        if ($CancellationToken.IsCancellationRequested) { return $null }
        if ([System.IO.File]::Exists($portPath)) {
            try {
                $portInfo = Get-Item -LiteralPath $portPath -ErrorAction Stop
                if ($portInfo.Length -gt 4096) { return $null }
                $portFile = [System.IO.File]::ReadAllLines($portPath, [System.Text.Encoding]::UTF8)
                if ($portFile.Length -gt 0 -and [int]::TryParse($portFile[0], [ref]$port) -and $port -ge 1 -and $port -le 65535) {
                    break
                }
            }
            catch [System.IO.IOException] {
                # Chromium may still be writing the discovery file; retry until the bounded deadline.
            }
            catch [System.UnauthorizedAccessException] {
                return $null
            }
        }
        Start-Sleep -Milliseconds 100
    }
    if ($port -lt 1) { return $null }

    $request = [System.Net.HttpWebRequest]([System.Net.WebRequest]::Create(('http://127.0.0.1:{0}/json/version' -f $port)))
    $request.Proxy = $null
    $request.AllowAutoRedirect = $false
    $request.Timeout = 3000
    $request.ReadWriteTimeout = 3000
    $request.KeepAlive = $false
    $response = $null
    $reader = $null
    try {
        $response = $request.GetResponse()
        if ([int]$response.StatusCode -ne 200) { return $null }
        $stream = $response.GetResponseStream()
        $reader = [System.IO.StreamReader]::new($stream, [System.Text.Encoding]::UTF8)
        $bodyBuilder = New-Object System.Text.StringBuilder
        $charBuffer = New-Object char[] 4096
        while (($readCount = $reader.Read($charBuffer, 0, $charBuffer.Length)) -gt 0) {
            if ($bodyBuilder.Length + $readCount -gt 65536) { return $null }
            [void]$bodyBuilder.Append($charBuffer, 0, $readCount)
        }
        $body = $bodyBuilder.ToString()
        $document = ConvertFrom-Json -InputObject $body -ErrorAction Stop
        $debugUrl = [string](Get-MihariBrowserMemberValue -InputObject $document -Name 'webSocketDebuggerUrl')
        $uri = $null
        if (-not [Uri]::TryCreate($debugUrl, [UriKind]::Absolute, [ref]$uri) -or
            $uri.Scheme -ne 'ws' -or $uri.Port -ne $port -or -not $uri.IsLoopback -or
            $uri.UserInfo -or $uri.Query -or $uri.Fragment -or
            $uri.AbsolutePath -notmatch '^/devtools/browser/[A-Za-z0-9._-]{8,128}$') { return $null }
        $product = [string](Get-MihariBrowserMemberValue -InputObject $document -Name 'Browser')
        $safeVersion = 'Edge/version_unavailable'
        if ($product -match '^Edg/([0-9]+(?:\.[0-9]+){1,3})$') {
            $safeVersion = 'Edge/' + $Matches[1]
        }
        return [pscustomobject]@{
            Port = $port
            WebSocketUri = ('ws://127.0.0.1:{0}{1}' -f $port, $uri.AbsolutePath)
            SourceVersion = $safeVersion
        }
    }
    catch {
        return $null
    }
    finally {
        if ($null -ne $reader) { $reader.Dispose() }
        if ($null -ne $response) { $response.Close() }
    }
}

function Send-MihariBrowserCdpCommand {
    param(
        [Parameter(Mandatory = $true)][System.Net.WebSockets.ClientWebSocket] $Socket,
        [Parameter(Mandatory = $true)][string] $Method,
        [AllowNull()][object] $Parameters,
        [AllowNull()][string] $SessionId,
        [Parameter(Mandatory = $true)][int] $NextCommandId,
        [Parameter(Mandatory = $true)][System.Threading.CancellationToken] $CancellationToken
    )

    $nextId = $NextCommandId + 1
    $message = [ordered]@{ id = $nextId; method = $Method }
    if ($null -ne $Parameters) { $message.params = $Parameters }
    if (-not [string]::IsNullOrWhiteSpace($SessionId)) { $message.sessionId = $SessionId }
    $json = ConvertTo-Json -InputObject $message -Depth 8 -Compress
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
    $segment = [System.ArraySegment[byte]]::new($bytes)
    $null = $Socket.SendAsync($segment, [System.Net.WebSockets.WebSocketMessageType]::Text, $true, $CancellationToken).GetAwaiter().GetResult()
    return $nextId
}

function Receive-MihariBrowserCdpMessage {
    param(
        [Parameter(Mandatory = $true)][System.Net.WebSockets.ClientWebSocket] $Socket,
        [Parameter(Mandatory = $true)][System.Threading.CancellationToken] $CancellationToken,
        [int] $MaximumBytes = 1048576
    )

    $buffer = New-Object byte[] 16384
    $memory = New-Object System.IO.MemoryStream
    try {
        $complete = $false
        $messageType = [System.Net.WebSockets.WebSocketMessageType]::Text
        while (-not $complete) {
            $segment = [System.ArraySegment[byte]]::new($buffer)
            $received = $Socket.ReceiveAsync($segment, $CancellationToken).GetAwaiter().GetResult()
            if ($received.MessageType -eq [System.Net.WebSockets.WebSocketMessageType]::Close) { return $null }
            $messageType = $received.MessageType
            if ($messageType -ne [System.Net.WebSockets.WebSocketMessageType]::Text) { return $null }
            if ($memory.Length + $received.Count -gt $MaximumBytes) { throw 'browser_cdp_message_too_large' }
            $memory.Write($buffer, 0, $received.Count)
            $complete = $received.EndOfMessage
        }
        $json = [System.Text.Encoding]::UTF8.GetString($memory.ToArray())
        return (ConvertFrom-Json -InputObject $json -ErrorAction Stop)
    }
    finally { $memory.Dispose() }
}

function Complete-MihariBrowserAttempt {
    param(
        [Parameter(Mandatory = $true)][object] $Session,
        [Parameter(Mandatory = $true)][object] $Launch,
        [Parameter(Mandatory = $true)][string] $TargetId,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary] $Record,
        [Parameter(Mandatory = $true)][string] $Outcome,
        [ValidateSet('observed', 'unknown', 'unsupported', 'permission_denied', 'truncated', 'lost')][string] $Coverage = 'observed',
        [AllowNull()][double] $EndTimestamp,
        [AllowNull()][object] $Response,
        [AllowNull()][object] $ErrorText,
        [AllowNull()][object] $BlockedReason,
        [AllowNull()][object] $CorsError
    )

    $connectionValue = Get-MihariBrowserMemberValue -InputObject $Response -Name 'connectionId'
    $disk = Get-MihariBrowserMemberValue -InputObject $Response -Name 'fromDiskCache'
    $serviceWorker = Get-MihariBrowserMemberValue -InputObject $Response -Name 'fromServiceWorker'
    if ($null -eq $disk -and $null -ne $Record.FromDiskCache) { $disk = [bool]$Record.FromDiskCache }
    if ($null -eq $serviceWorker -and $null -ne $Record.FromServiceWorker) { $serviceWorker = [bool]$Record.FromServiceWorker }
    $fact = ConvertTo-MihariBrowserRequestFact -SessionId ([string]$Session.Id) -ProcessId ([int]$Launch.Pid) `
        -TargetId $TargetId -BrowserRequestId ([string]$Record.RequestId) -FrameId ([string]$Record.FrameId) `
        -RedirectIndex ([int]$Record.RedirectIndex) -Request $Record.Request -Response $Response `
        -InitiatorType $Record.Initiator -Outcome $Outcome `
        -ErrorText $ErrorText -BlockedReason $BlockedReason -CorsError $CorsError `
        -StartTimestamp $Record.StartTimestamp -EndTimestamp $EndTimestamp -BrowserConnectionId $connectionValue `
        -FromDiskCache $disk -FromServiceWorker $serviceWorker
    $null = Write-MihariBrowserObservationFact -Session $Session -Launch $Launch -Stage 'browser.network.request' `
        -Outcome $fact.Outcome -ConnectionId $fact.ConnectionId -RequestId $fact.RequestId `
        -ElapsedMs $fact.ElapsedMs -Data $fact.Data -Coverage $Coverage
}

function Add-MihariBrowserObserverTarget {
    param(
        [Parameter(Mandatory = $true)][System.Collections.IDictionary] $TargetSessions,
        [Parameter(Mandatory = $true)][string] $SessionId,
        [Parameter(Mandatory = $true)][string] $TargetId,
        [ValidateRange(1, 4096)][int] $MaximumTargets = 64
    )

    if ($TargetSessions.Contains($SessionId)) {
        return [pscustomobject]@{ Added = $false; AlreadyTracked = $true; Overflow = $false }
    }
    if ($TargetSessions.Count -ge $MaximumTargets) {
        return [pscustomobject]@{ Added = $false; AlreadyTracked = $false; Overflow = $true }
    }
    $TargetSessions[$SessionId] = $TargetId
    return [pscustomobject]@{ Added = $true; AlreadyTracked = $false; Overflow = $false }
}

function Add-MihariBrowserObserverAttempt {
    param(
        [Parameter(Mandatory = $true)][System.Collections.IDictionary] $Attempts,
        [Parameter(Mandatory = $true)][string] $Key,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary] $Record,
        [ValidateRange(1, 100000)][int] $MaximumAttempts = 2048
    )

    if (-not $Attempts.Contains($Key) -and $Attempts.Count -ge $MaximumAttempts) {
        return [pscustomobject]@{ Added = $false; Overflow = $true }
    }
    $Attempts[$Key] = $Record
    return [pscustomobject]@{ Added = $true; Overflow = $false }
}

function Write-MihariBrowserObservationLimitFact {
    param(
        [Parameter(Mandatory = $true)][object] $Session,
        [Parameter(Mandatory = $true)][object] $Launch,
        [Parameter(Mandatory = $true)][ValidateSet('target', 'request')][string] $LimitKind,
        [Parameter(Mandatory = $true)][long] $DroppedCount
    )

    if ($DroppedCount -lt 1) { throw 'The browser observation drop count must be positive.' }
    $errorCode = $LimitKind + '_limit_reached'
    $data = @{ browserError = $errorCode }
    if ($LimitKind -eq 'target') { $data.browserDroppedTargetCount = $DroppedCount }
    else { $data.browserDroppedRequestCount = $DroppedCount }
    $null = Write-MihariBrowserObservationFact -Session $Session -Launch $Launch -Stage 'browser.observation' `
        -Outcome 'observer_limit' -ConnectionId ('browser-profile-' + [string]$Launch.SourceIdentity) `
        -RequestId $null -ElapsedMs $null -Data $data -Coverage 'truncated'
}

function Test-MihariBrowserLimitCountCheckpoint {
    param([Parameter(Mandatory = $true)][long] $Count)

    return ($Count -eq 1 -or (($Count -band ($Count - 1)) -eq 0))
}

function Invoke-MihariBrowserObservationWorker {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][object] $Session,
        [Parameter(Mandatory = $true)][object] $Launch,
        [AllowNull()][string] $InitialUrl
    )

    $token = $Session.BrowserObservationCancellation.Token
    $socket = $null
    $sourceId = [string]$Launch.SourceIdentity
    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    $targetDroppedCount = [long]0
    $requestDroppedCount = [long]0
    $lastReportedTargetDroppedCount = [long]0
    $lastReportedRequestDroppedCount = [long]0
    try {
        if (-not (Test-MihariBrowserOwnedProcess -SessionId ([string]$Session.Id) -Launch $Launch)) {
            throw 'browser_profile_owner_unverified'
        }
        $connectionInfo = Get-MihariBrowserDevToolsConnectionInfo -ProfilePath ([string]$Launch.ProfilePath) `
            -CancellationToken $token -TimeoutSeconds 15
        if ($null -eq $connectionInfo) {
            $null = Write-MihariBrowserObservationFact -Session $Session -Launch $Launch -Stage 'browser.observation' `
                -Outcome 'unavailable' -ConnectionId ('browser-profile-' + $sourceId) -RequestId $null `
                -ElapsedMs $watch.Elapsed.TotalMilliseconds -Data @{ browserError = 'devtools_endpoint_unavailable' } -Coverage 'unknown'
            return
        }
        $Launch.SourceVersion = [string]$connectionInfo.SourceVersion
        if (-not (Test-MihariBrowserOwnedProcess -SessionId ([string]$Session.Id) -Launch $Launch)) {
            throw 'browser_profile_owner_changed'
        }

        $socket = New-Object System.Net.WebSockets.ClientWebSocket
        $socket.Options.KeepAliveInterval = [TimeSpan]::FromSeconds(20)
        $connectSource = [System.Threading.CancellationTokenSource]::CreateLinkedTokenSource($token)
        try {
            $connectSource.CancelAfter(10000)
            $socket.ConnectAsync([Uri]$connectionInfo.WebSocketUri, $connectSource.Token).GetAwaiter().GetResult()
        }
        finally { $connectSource.Dispose() }
        if (-not (Test-MihariBrowserOwnedProcess -SessionId ([string]$Session.Id) -Launch $Launch)) {
            throw 'browser_profile_owner_changed'
        }

        $null = Write-MihariBrowserObservationFact -Session $Session -Launch $Launch -Stage 'browser.observation' `
            -Outcome 'owned_profile_attached' -ConnectionId ('browser-profile-' + $sourceId) -RequestId $null `
            -ElapsedMs $watch.Elapsed.TotalMilliseconds -Data @{} -Coverage 'observed'
        $nextId = 0
        $initialNavigationSent = $false
        $nextId = Send-MihariBrowserCdpCommand -Socket $socket -Method 'Target.setDiscoverTargets' `
            -Parameters @{ discover = $true } -NextCommandId $nextId -CancellationToken $token
        $nextId = Send-MihariBrowserCdpCommand -Socket $socket -Method 'Target.setAutoAttach' `
            -Parameters @{ autoAttach = $true; waitForDebuggerOnStart = $false; flatten = $true } `
            -NextCommandId $nextId -CancellationToken $token

        $targetSessions = @{}
        $attempts = @{}
        $maximumTargets = 64
        $maximumAttempts = 2048
        while (-not $token.IsCancellationRequested -and $socket.State -eq [System.Net.WebSockets.WebSocketState]::Open) {
            $message = Receive-MihariBrowserCdpMessage -Socket $socket -CancellationToken $token
            if ($null -eq $message) { break }
            $method = [string](Get-MihariBrowserMemberValue -InputObject $message -Name 'method')
            if ([string]::IsNullOrWhiteSpace($method)) { continue }
            $parameters = Get-MihariBrowserMemberValue -InputObject $message -Name 'params'
            switch ($method) {
                'Target.attachedToTarget' {
                    $childSession = [string](Get-MihariBrowserMemberValue -InputObject $parameters -Name 'sessionId')
                    $targetInfo = Get-MihariBrowserMemberValue -InputObject $parameters -Name 'targetInfo'
                    $childTarget = [string](Get-MihariBrowserMemberValue -InputObject $targetInfo -Name 'targetId')
                    $targetType = [string](Get-MihariBrowserMemberValue -InputObject $targetInfo -Name 'type')
                    if ($childSession -match '^[A-Za-z0-9._-]{1,128}$' -and
                        $childTarget -match '^[A-Za-z0-9._-]{1,128}$' -and
                        $targetType -in @('page', 'iframe', 'worker', 'service_worker', 'shared_worker')) {
                        $targetAdmission = Add-MihariBrowserObserverTarget -TargetSessions $targetSessions `
                            -SessionId $childSession -TargetId $childTarget -MaximumTargets $maximumTargets
                        if (-not $targetAdmission.Added) {
                            if ($targetAdmission.Overflow) {
                                if ($targetDroppedCount -lt [long]::MaxValue) { $targetDroppedCount++ }
                                if (Test-MihariBrowserLimitCountCheckpoint -Count $targetDroppedCount) {
                                    Write-MihariBrowserObservationLimitFact -Session $Session -Launch $Launch `
                                        -LimitKind 'target' -DroppedCount $targetDroppedCount
                                    $lastReportedTargetDroppedCount = $targetDroppedCount
                                }
                            }
                            continue
                        }
                        $nextId = Send-MihariBrowserCdpCommand -Socket $socket -Method 'Network.enable' -Parameters @{} `
                            -SessionId $childSession -NextCommandId $nextId -CancellationToken $token
                        $nextId = Send-MihariBrowserCdpCommand -Socket $socket -Method 'Page.enable' -Parameters @{} `
                            -SessionId $childSession -NextCommandId $nextId -CancellationToken $token
                        $nextId = Send-MihariBrowserCdpCommand -Socket $socket -Method 'Target.setAutoAttach' `
                            -Parameters @{ autoAttach = $true; waitForDebuggerOnStart = $false; flatten = $true } `
                            -SessionId $childSession -NextCommandId $nextId -CancellationToken $token
                        if (-not $initialNavigationSent -and $targetType -eq 'page' -and
                            -not [string]::IsNullOrWhiteSpace($InitialUrl)) {
                            $nextId = Send-MihariBrowserCdpCommand -Socket $socket -Method 'Page.navigate' `
                                -Parameters @{ url = $InitialUrl } -SessionId $childSession `
                                -NextCommandId $nextId -CancellationToken $token
                            $initialNavigationSent = $true
                        }
                    }
                }
                'Target.detachedFromTarget' {
                    $detached = [string](Get-MihariBrowserMemberValue -InputObject $parameters -Name 'sessionId')
                    if ($targetSessions.ContainsKey($detached)) {
                        $detachedTarget = [string]$targetSessions[$detached]
                        $targetSessions.Remove($detached)
                        foreach ($attemptKey in @($attempts.Keys)) {
                            if ($attempts[$attemptKey].TargetSession -ceq $detached) {
                                $record = $attempts[$attemptKey]
                                Complete-MihariBrowserAttempt -Session $Session -Launch $Launch -TargetId $detachedTarget `
                                    -Record $record -Outcome 'incomplete' -Coverage 'lost' -EndTimestamp $null `
                                    -Response $record.Response -ErrorText $null -BlockedReason $null -CorsError $null
                                $attempts.Remove($attemptKey)
                            }
                        }
                    }
                }
                'Network.requestWillBeSent' {
                    $cdpSession = [string](Get-MihariBrowserMemberValue -InputObject $message -Name 'sessionId')
                    if (-not $targetSessions.ContainsKey($cdpSession)) { continue }
                    $targetId = [string]$targetSessions[$cdpSession]
                    $requestId = [string](Get-MihariBrowserMemberValue -InputObject $parameters -Name 'requestId')
                    if ($requestId -notmatch '^[A-Za-z0-9._:-]{1,256}$') { continue }
                    $attemptKey = $cdpSession + "`n" + $requestId
                    $redirectResponse = Get-MihariBrowserMemberValue -InputObject $parameters -Name 'redirectResponse'
                    $redirectIndex = 0
                    if ($attempts.ContainsKey($attemptKey)) {
                        $previous = $attempts[$attemptKey]
                        if ($null -ne $redirectResponse) {
                            $redirectEnd = 0.0
                            $redirectTimestamp = Get-MihariBrowserMemberValue -InputObject $parameters -Name 'timestamp'
                            $hasRedirectEnd = $null -ne $redirectTimestamp -and [double]::TryParse([string]$redirectTimestamp, [ref]$redirectEnd)
                            $endValue = $null
                            if ($hasRedirectEnd) { $endValue = [double]$redirectEnd }
                            Complete-MihariBrowserAttempt -Session $Session -Launch $Launch -TargetId $targetId `
                                -Record $previous -Outcome 'redirected' -EndTimestamp $endValue -Response $redirectResponse `
                                -ErrorText $null -BlockedReason $null -CorsError $null
                            $redirectIndex = [int]$previous.RedirectIndex + 1
                        }
                        else {
                            $attempts.Remove($attemptKey)
                        }
                    }
                    $request = Get-MihariBrowserMemberValue -InputObject $parameters -Name 'request'
                    $safeRequest = ConvertTo-MihariBrowserSafeRequest -Request $request
                    if ($null -eq $safeRequest) { continue }
                    $frameId = [string](Get-MihariBrowserMemberValue -InputObject $parameters -Name 'frameId')
                    $initiator = Get-MihariBrowserMemberValue -InputObject (Get-MihariBrowserMemberValue -InputObject $parameters -Name 'initiator') -Name 'type'
                    $startTimestamp = 0.0
                    $hasStart = [double]::TryParse([string](Get-MihariBrowserMemberValue -InputObject $parameters -Name 'timestamp'), [ref]$startTimestamp)
                    if (-not $hasStart) { $startTimestamp = $null }
                    $attemptRecord = [ordered]@{
                        RequestId = $requestId
                        Request = $safeRequest
                        FrameId = $frameId
                        Initiator = ConvertTo-MihariBrowserSafeInitiatorType -InitiatorType $initiator
                        TargetSession = $cdpSession
                        RedirectIndex = $redirectIndex
                        StartTimestamp = $startTimestamp
                        Response = $null
                        FromDiskCache = $null
                        FromServiceWorker = $null
                    }
                    $attemptAdmission = Add-MihariBrowserObserverAttempt -Attempts $attempts -Key $attemptKey `
                        -Record $attemptRecord -MaximumAttempts $maximumAttempts
                    if (-not $attemptAdmission.Added) {
                        if ($attemptAdmission.Overflow) {
                            if ($requestDroppedCount -lt [long]::MaxValue) { $requestDroppedCount++ }
                            if (Test-MihariBrowserLimitCountCheckpoint -Count $requestDroppedCount) {
                                Write-MihariBrowserObservationLimitFact -Session $Session -Launch $Launch `
                                    -LimitKind 'request' -DroppedCount $requestDroppedCount
                                $lastReportedRequestDroppedCount = $requestDroppedCount
                            }
                        }
                        continue
                    }
                }
                'Network.responseReceived' {
                    $cdpSession = [string](Get-MihariBrowserMemberValue -InputObject $message -Name 'sessionId')
                    $requestId = [string](Get-MihariBrowserMemberValue -InputObject $parameters -Name 'requestId')
                    $attemptKey = $cdpSession + "`n" + $requestId
                    if (-not $attempts.ContainsKey($attemptKey)) { continue }
                    $response = ConvertTo-MihariBrowserSafeResponse -Response (Get-MihariBrowserMemberValue -InputObject $parameters -Name 'response')
                    $attempts[$attemptKey].Response = $response
                    $diskValue = Get-MihariBrowserMemberValue -InputObject $response -Name 'fromDiskCache'
                    if ($null -ne $diskValue) { $attempts[$attemptKey].FromDiskCache = [bool]$diskValue }
                    $serviceWorkerValue = Get-MihariBrowserMemberValue -InputObject $response -Name 'fromServiceWorker'
                    if ($null -ne $serviceWorkerValue) { $attempts[$attemptKey].FromServiceWorker = [bool]$serviceWorkerValue }
                }
                'Network.requestServedFromCache' {
                    $cdpSession = [string](Get-MihariBrowserMemberValue -InputObject $message -Name 'sessionId')
                    $requestId = [string](Get-MihariBrowserMemberValue -InputObject $parameters -Name 'requestId')
                    $attemptKey = $cdpSession + "`n" + $requestId
                    if ($attempts.ContainsKey($attemptKey)) { $attempts[$attemptKey].FromDiskCache = $true }
                }
                'Network.loadingFinished' {
                    $cdpSession = [string](Get-MihariBrowserMemberValue -InputObject $message -Name 'sessionId')
                    $requestId = [string](Get-MihariBrowserMemberValue -InputObject $parameters -Name 'requestId')
                    $attemptKey = $cdpSession + "`n" + $requestId
                    if (-not $attempts.ContainsKey($attemptKey)) { continue }
                    $record = $attempts[$attemptKey]
                    $attempts.Remove($attemptKey)
                    $endTimestamp = 0.0
                    if (-not [double]::TryParse([string](Get-MihariBrowserMemberValue -InputObject $parameters -Name 'timestamp'), [ref]$endTimestamp)) { $endTimestamp = $null }
                    Complete-MihariBrowserAttempt -Session $Session -Launch $Launch -TargetId ([string]$targetSessions[$cdpSession]) `
                        -Record $record -Outcome 'completed' -EndTimestamp $endTimestamp -Response $record.Response `
                        -ErrorText $null -BlockedReason $null -CorsError $null
                }
                'Network.loadingFailed' {
                    $cdpSession = [string](Get-MihariBrowserMemberValue -InputObject $message -Name 'sessionId')
                    $requestId = [string](Get-MihariBrowserMemberValue -InputObject $parameters -Name 'requestId')
                    $attemptKey = $cdpSession + "`n" + $requestId
                    if (-not $attempts.ContainsKey($attemptKey)) { continue }
                    $record = $attempts[$attemptKey]
                    $attempts.Remove($attemptKey)
                    $endTimestamp = 0.0
                    if (-not [double]::TryParse([string](Get-MihariBrowserMemberValue -InputObject $parameters -Name 'timestamp'), [ref]$endTimestamp)) { $endTimestamp = $null }
                    $cors = Get-MihariBrowserMemberValue -InputObject (Get-MihariBrowserMemberValue -InputObject $parameters -Name 'corsErrorStatus') -Name 'corsError'
                    Complete-MihariBrowserAttempt -Session $Session -Launch $Launch -TargetId ([string]$targetSessions[$cdpSession]) `
                        -Record $record -Outcome 'failed' -EndTimestamp $endTimestamp -Response $record.Response `
                        -ErrorText (Get-MihariBrowserMemberValue -InputObject $parameters -Name 'errorText') `
                        -BlockedReason (Get-MihariBrowserMemberValue -InputObject $parameters -Name 'blockedReason') -CorsError $cors
                }
            }
        }
        if (-not $token.IsCancellationRequested) {
            $null = Write-MihariBrowserObservationFact -Session $Session -Launch $Launch -Stage 'browser.observation' `
                -Outcome 'connection_closed' -ConnectionId ('browser-profile-' + $sourceId) -RequestId $null `
                -ElapsedMs $watch.Elapsed.TotalMilliseconds -Data @{ browserError = 'devtools_connection_closed' } -Coverage 'lost'
        }
    }
    catch [System.OperationCanceledException] {
        # Session stop owns cancellation and closes this attachment without a traffic diagnosis.
    }
    catch {
        $safeFailure = 'browser_observation_failed'
        if ($_.Exception.Message -eq 'browser_profile_owner_unverified') { $safeFailure = 'profile_owner_unverified' }
        elseif ($_.Exception.Message -eq 'browser_profile_owner_changed') { $safeFailure = 'profile_owner_changed' }
        elseif ($_.Exception.Message -eq 'browser_cdp_message_too_large') { $safeFailure = 'cdp_message_too_large' }
        $safeErrorType = [string]$_.Exception.GetType().FullName
        if ($safeErrorType.Length -gt 128) { $safeErrorType = $safeErrorType.Substring(0, 128) }
        try {
            $null = Write-MihariBrowserObservationFact -Session $Session -Launch $Launch -Stage 'browser.observation' `
                -Outcome 'failed' -ConnectionId ('browser-profile-' + $sourceId) -RequestId $null `
                -ElapsedMs $watch.Elapsed.TotalMilliseconds -Data @{ browserError = $safeFailure; errorType = $safeErrorType } -Coverage 'unknown'
        }
        catch {
            Write-Warning ('Mihari could not record browser observation failure ({0}).' -f $_.Exception.GetType().FullName)
        }
    }
    finally {
        if ($targetDroppedCount -gt $lastReportedTargetDroppedCount) {
            try {
                Write-MihariBrowserObservationLimitFact -Session $Session -Launch $Launch `
                    -LimitKind 'target' -DroppedCount $targetDroppedCount
            }
            catch { Write-Warning ('Mihari could not record the final browser target drop count ({0}).' -f $_.Exception.GetType().FullName) }
        }
        if ($requestDroppedCount -gt $lastReportedRequestDroppedCount) {
            try {
                Write-MihariBrowserObservationLimitFact -Session $Session -Launch $Launch `
                    -LimitKind 'request' -DroppedCount $requestDroppedCount
            }
            catch { Write-Warning ('Mihari could not record the final browser request drop count ({0}).' -f $_.Exception.GetType().FullName) }
        }
        if ($null -ne $socket) {
            try {
                if ($socket.State -eq [System.Net.WebSockets.WebSocketState]::Open) {
                    $closeToken = New-Object System.Threading.CancellationTokenSource
                    try {
                        $closeToken.CancelAfter(500)
                        $socket.CloseAsync([System.Net.WebSockets.WebSocketCloseStatus]::NormalClosure, 'session stop', $closeToken.Token).GetAwaiter().GetResult()
                    }
                    finally { $closeToken.Dispose() }
                }
            }
            catch { Write-Warning ('Mihari could not close the owned browser DevTools socket ({0}).' -f $_.Exception.GetType().FullName) }
            $socket.Dispose()
        }
    }
}

function Clear-MihariCompletedBrowserObservationWorkers {
    param([Parameter(Mandatory = $true)][object] $Session)

    if ($null -eq $Session.BrowserObservationWorkers) { return }
    for ($index = $Session.BrowserObservationWorkers.Count - 1; $index -ge 0; $index--) {
        $worker = $Session.BrowserObservationWorkers[$index]
        if (-not $worker.AsyncResult.IsCompleted) { continue }
        try {
            $null = $worker.PowerShell.EndInvoke($worker.AsyncResult)
        }
        catch {
            if (Get-Command Write-MihariEvent -CommandType Function -ErrorAction SilentlyContinue) {
                try {
                    $null = Write-MihariEvent -Session $Session -ConnectionId 'browser-observer' -Stage 'browser.observation' `
                        -Outcome 'worker_failed' -ElapsedMs $null -Source browser -Coverage unknown `
                        -Data @{ browserError = 'observer_worker_failed' }
                }
                catch { Write-Warning ('Mihari could not record browser observer worker failure ({0}).' -f $_.Exception.GetType().FullName) }
            }
        }
        finally {
            $worker.PowerShell.Dispose()
            $Session.BrowserObservationWorkers.RemoveAt($index)
        }
    }
}

function New-MihariBrowserObservationUnavailableResult {
    param(
        [Parameter(Mandatory = $true)][object] $Session,
        [Parameter(Mandatory = $true)][object] $Launch,
        [Parameter(Mandatory = $true)][ValidateSet(
            'profile_owner_unverified', 'profile_owner_changed', 'profile_marker_unverified',
            'observer_limit_reached', 'observer_worker_unavailable', 'session_writer_unavailable',
            'profile_mode_incompatible'
        )][string] $ErrorCode,
        [AllowNull()][string] $FailureDetailCode
    )

    $allowedFailureDetails = @(
        'profile_marker_missing', 'profile_marker_invalid', 'profile_marker_mismatch',
        'process_inventory_unavailable', 'process_inventory_mismatch', 'profile_argument_mismatch',
        'process_executable_mismatch', 'process_identity_unavailable', 'process_start_time_mismatch'
    )
    if ($FailureDetailCode -notin $allowedFailureDetails) { $FailureDetailCode = $null }

    $reason = 'Mihari could not verify or start the owned diagnostic browser observer.'
    switch ($ErrorCode) {
        'profile_owner_unverified' { $reason = 'Mihari could not verify the active Edge process for its owned profile.' }
        'profile_owner_changed' { $reason = 'The active Edge process identity changed while Mihari was arming observation.' }
        'profile_marker_unverified' { $reason = 'Mihari could not verify the ownership marker and process for its diagnostic Edge profile.' }
        'observer_limit_reached' { $reason = 'Mihari reached its bounded diagnostic browser observation limit.' }
        'observer_worker_unavailable' { $reason = 'Mihari could not start its bounded browser observer.' }
        'session_writer_unavailable' { $reason = 'Browser observation requires the live Mihari session event writer.' }
        'profile_mode_incompatible' { $reason = 'The http2-observe profile requires a Tunnel session.' }
    }

    $status = 'unavailable'
    if ($ErrorCode -eq 'session_writer_unavailable') { $status = 'launched_but_unverified' }
    $writer = Get-MihariBrowserMemberValue -InputObject $Session -Name 'Writer'
    if ($null -ne $writer -and -not [bool]$writer.Closed -and
        (Get-MihariBrowserMemberValue -InputObject $Session -Name 'Mode') -in @('Inspect', 'Tunnel')) {
        try {
            if ([string]::IsNullOrWhiteSpace([string]$Launch.SourceIdentity)) {
                $launchValue = [string]$Launch.Pid + ':' + [string]$Launch.ProfilePath
                $Launch.SourceIdentity = Get-MihariBrowserScopedId -Scope ([string]$Session.Id) -Value $launchValue -Prefix 'edge'
                $Launch.ClockId = 'edge-clock-' + [string]$Launch.SourceIdentity
            }
            $data = @{ browserError = $ErrorCode }
            if ($null -ne $FailureDetailCode) { $data.errorCode = $FailureDetailCode }
            $null = Write-MihariBrowserObservationFact -Session $Session -Launch $Launch -Stage 'browser.observation' `
                -Outcome 'unavailable' -ConnectionId ('browser-profile-' + [string]$Launch.SourceIdentity) `
                -RequestId $null -ElapsedMs $null -Data $data -Coverage 'unknown'
        }
        catch {
            Write-Warning ('Mihari could not record the browser observer start failure ({0}).' -f $_.Exception.GetType().FullName)
        }
    }
    return [pscustomobject]@{ Status = $status; ErrorCode = $ErrorCode; FailureDetailCode = $FailureDetailCode; Reason = $reason }
}

function Start-MihariBrowserObservation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][object] $Session,
        [Parameter(Mandatory = $true)][object] $Launch,
        [AllowNull()][string] $InitialUrl
    )

    if ($null -eq $Session.Writer -or $null -eq $Session.Cancellation -or $Session.Writer.Closed) {
        return (New-MihariBrowserObservationUnavailableResult -Session $Session -Launch $Launch -ErrorCode 'session_writer_unavailable')
    }
    if ([string]$Session.Profile -eq 'http2-observe' -and [string]$Session.Mode -ne 'Tunnel') {
        return (New-MihariBrowserObservationUnavailableResult -Session $Session -Launch $Launch -ErrorCode 'profile_mode_incompatible')
    }
    # Allow two bounded 3-second owner scan windows at most, plus the 150 ms retry pause and three 100 ms marker checks.
    $ownerIdentity = Get-MihariBrowserOwnedProfileIdentity -SessionId ([string]$Session.Id) -Launch $Launch -TimeoutSeconds 3
    if (-not $ownerIdentity.Success -and [string]$ownerIdentity.ErrorCode -in @(
        'browser_process_inventory_unavailable', 'browser_profile_process_not_found', 'browser_profile_owner_unverifiable'
    )) {
        Start-Sleep -Milliseconds 150
        $ownerIdentity = Get-MihariBrowserOwnedProfileIdentity -SessionId ([string]$Session.Id) -Launch $Launch -TimeoutSeconds 3
    }
    if (-not $ownerIdentity.Success) {
        return (New-MihariBrowserObservationUnavailableResult -Session $Session -Launch $Launch -ErrorCode 'profile_owner_unverified')
    }
    if ([int]$Launch.Pid -ne [int]$ownerIdentity.ProcessId -or
        -not (Test-MihariBrowserUtcIdentityEqual -Left $Launch.OwnerStartTimeUtc -Right $ownerIdentity.OwnerStartTimeUtc)) {
        return (New-MihariBrowserObservationUnavailableResult -Session $Session -Launch $Launch -ErrorCode 'profile_owner_changed')
    }
    $ownedProcessVerification = $null
    for ($verificationAttempt = 0; $verificationAttempt -lt 3; $verificationAttempt++) {
        $ownedProcessVerification = Get-MihariBrowserOwnedProcessVerification -SessionId ([string]$Session.Id) -Launch $Launch
        if ($ownedProcessVerification.Verified) { break }
        if ($verificationAttempt -lt 2) { Start-Sleep -Milliseconds 100 }
    }
    if ($null -eq $ownedProcessVerification -or -not $ownedProcessVerification.Verified) {
        $failureDetailCode = $null
        if ($null -ne $ownedProcessVerification) { $failureDetailCode = [string]$ownedProcessVerification.FailureDetailCode }
        return (New-MihariBrowserObservationUnavailableResult -Session $Session -Launch $Launch `
            -ErrorCode 'profile_marker_unverified' -FailureDetailCode $failureDetailCode)
    }

    $lock = Get-MihariBrowserMemberValue -InputObject $Session -Name 'BrowserObservationLock'
    if ($null -eq $lock) {
        $lock = Get-MihariBrowserMemberValue -InputObject $Session -Name 'MetadataLock'
        if ($null -eq $lock) {
            $lock = New-Object System.Object
            Set-MihariBrowserSessionProperty -Session $Session -Name 'BrowserObservationLock' -Value $lock
        }
    }
    [System.Threading.Monitor]::Enter($lock)
    try {
        if ($null -eq $Session.BrowserObservationCancellation -or $Session.BrowserObservationCancellation.IsCancellationRequested) {
            Set-MihariBrowserSessionProperty -Session $Session -Name 'BrowserObservationCancellation' -Value (New-Object System.Threading.CancellationTokenSource)
        }
        if ($null -eq $Session.BrowserObservationPool) {
            $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, 2)
            $pool.Open()
            Set-MihariBrowserSessionProperty -Session $Session -Name 'BrowserObservationPool' -Value $pool
        }
        if ($null -eq $Session.BrowserObservationWorkers) {
            Set-MihariBrowserSessionProperty -Session $Session -Name 'BrowserObservationWorkers' -Value (New-Object System.Collections.ArrayList)
        }
        Clear-MihariCompletedBrowserObservationWorkers -Session $Session
        if ($Session.BrowserObservationWorkers.Count -ge 2) {
            return (New-MihariBrowserObservationUnavailableResult -Session $Session -Launch $Launch -ErrorCode 'observer_limit_reached')
        }
        $launch.SourceIdentity = Get-MihariBrowserScopedId -Scope ([string]$Session.Id) -Value ([string]$Launch.Pid + ':' + [string]$Launch.ProfilePath) -Prefix 'edge'
        $launch.ClockId = 'edge-clock-' + $launch.SourceIdentity
        $powerShell = [System.Management.Automation.PowerShell]::Create()
        $powerShell.RunspacePool = $Session.BrowserObservationPool
        $scriptPath = [System.IO.Path]::Combine([string]$Session.SourceRoot, 'src', 'BrowserObservation.ps1')
        if (-not [System.IO.File]::Exists($scriptPath)) {
            $scriptPath = [System.IO.Path]::Combine([string]$Session.SourceRoot, 'BrowserObservation.ps1')
        }
        $observationScriptPath = [System.IO.Path]::Combine([string]$Session.SourceRoot, 'src', 'Observation.ps1')
        if (-not [System.IO.File]::Exists($observationScriptPath)) {
            $observationScriptPath = [System.IO.Path]::Combine([string]$Session.SourceRoot, 'Observation.ps1')
        }
        $workerScript = @'
param($WorkerSession, $WorkerLaunch, $ObservationScriptPath, $WorkerScriptPath, $WorkerInitialUrl)
$ErrorActionPreference = 'Stop'
. $ObservationScriptPath
. $WorkerScriptPath
Invoke-MihariBrowserObservationWorker -Session $WorkerSession -Launch $WorkerLaunch -InitialUrl $WorkerInitialUrl
'@
        $null = $powerShell.AddScript($workerScript).AddArgument($Session).AddArgument($Launch).AddArgument($observationScriptPath).AddArgument($scriptPath).AddArgument($InitialUrl)
        try {
            $asyncResult = $powerShell.BeginInvoke()
            [void]$Session.BrowserObservationWorkers.Add([pscustomobject]@{
                PowerShell = $powerShell
                AsyncResult = $asyncResult
                Launch = $Launch
            })
        }
        catch {
            $powerShell.Dispose()
            throw
        }
        return [pscustomobject]@{ Status = 'launched_but_unverified'; Reason = $null }
    }
    catch {
        return (New-MihariBrowserObservationUnavailableResult -Session $Session -Launch $Launch -ErrorCode 'observer_worker_unavailable')
    }
    finally { [System.Threading.Monitor]::Exit($lock) }
}

function Stop-MihariBrowserObservation {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][object] $Session)

    $errors = New-Object System.Collections.ArrayList
    if ($null -ne $Session.BrowserObservationCancellation) {
        try { $Session.BrowserObservationCancellation.Cancel() }
        catch { [void]$errors.Add('browser_observer_cancel_failed') }
    }
    if ($null -ne $Session.BrowserObservationWorkers) {
        $deadline = [DateTime]::UtcNow.AddSeconds(3)
        while ([DateTime]::UtcNow -lt $deadline) {
            $pending = @($Session.BrowserObservationWorkers | Where-Object { -not $_.AsyncResult.IsCompleted }).Count
            if ($pending -eq 0) { break }
            Start-Sleep -Milliseconds 50
        }
        foreach ($worker in @($Session.BrowserObservationWorkers)) {
            if (-not $worker.AsyncResult.IsCompleted) {
                try { $worker.PowerShell.Stop() }
                catch { [void]$errors.Add('browser_observer_stop_failed') }
            }
            try { $null = $worker.PowerShell.EndInvoke($worker.AsyncResult) }
            catch { [void]$errors.Add('browser_observer_worker_incomplete') }
            try { $worker.PowerShell.Dispose() }
            catch { [void]$errors.Add('browser_observer_worker_dispose_failed') }
        }
        $Session.BrowserObservationWorkers.Clear()
    }
    if ($null -ne $Session.BrowserObservationPool) {
        try { $Session.BrowserObservationPool.Close() }
        catch { [void]$errors.Add('browser_observer_pool_close_failed') }
        try { $Session.BrowserObservationPool.Dispose() }
        catch { [void]$errors.Add('browser_observer_pool_dispose_failed') }
        Set-MihariBrowserSessionProperty -Session $Session -Name 'BrowserObservationPool' -Value $null
    }
    return [pscustomobject]@{ success = ($errors.Count -eq 0); errors = [string[]]$errors.ToArray() }
}

function Get-MihariBrowserImportFileText {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [long] $MaximumBytes = 67108864
    )

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $stream = $null
    $reader = $null
    try {
        $stream = [System.IO.File]::Open($fullPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
        if ($stream.Length -gt $MaximumBytes) { throw 'browser_import_source_too_large' }
        $reader = [System.IO.StreamReader]::new($stream, [System.Text.Encoding]::UTF8, $true, 8192)
        $builder = New-Object System.Text.StringBuilder
        $buffer = New-Object char[] 8192
        while (($count = $reader.Read($buffer, 0, $buffer.Length)) -gt 0) {
            if ($builder.Length + $count -gt $MaximumBytes) { throw 'browser_import_source_too_large' }
            [void]$builder.Append($buffer, 0, $count)
        }
        return $builder.ToString()
    }
    catch {
        if ($_.Exception.Message -eq 'browser_import_source_too_large') { throw }
        throw 'browser_import_source_unavailable'
    }
    finally {
        if ($null -ne $reader) { $reader.Dispose() }
        elseif ($null -ne $stream) { $stream.Dispose() }
    }
}

function New-MihariImportedBrowserRecord {
    param(
        [Parameter(Mandatory = $true)][string] $ImportId,
        [Parameter(Mandatory = $true)][string] $SourceVersion,
        [Parameter(Mandatory = $true)][string] $SourceRecordId,
        [AllowNull()][string] $SourceRequestId,
        [Parameter(Mandatory = $true)][string] $Outcome,
        [AllowNull()][object] $ElapsedMs,
        [AllowNull()][string] $SourceTimestampUtc,
        [Parameter(Mandatory = $true)][object] $Data
    )

    $safeId = Get-MihariBrowserScopedId -Scope $ImportId -Value $SourceRecordId -Prefix 'im'
    $requestIdentity = $SourceRecordId
    if (-not [string]::IsNullOrWhiteSpace($SourceRequestId)) { $requestIdentity = $SourceRequestId }
    $safeRequestId = Get-MihariBrowserScopedId -Scope $ImportId -Value $requestIdentity -Prefix 'ir'
    $record = [ordered]@{
        source = 'import'
        coverage = 'observed'
        sourceIdentity = $ImportId
        sourceVersion = $SourceVersion
        sourceRecordId = $safeId
        sourceRequestId = $safeRequestId
        outcome = $Outcome
        elapsedMs = $ElapsedMs
        data = $Data
    }
    if (-not [string]::IsNullOrWhiteSpace($SourceTimestampUtc)) { $record.sourceTimestampUtc = $SourceTimestampUtc }
    return [pscustomobject]$record
}

function ConvertFrom-MihariHar {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [ValidateRange(1, 100000)][int] $MaximumEntries = 20000,
        [ValidateRange(1024, 67108864)][long] $MaximumBytes = 67108864
    )

    $text = Get-MihariBrowserImportFileText -Path $Path -MaximumBytes $MaximumBytes
    $document = ConvertFrom-Json -InputObject $text -ErrorAction Stop
    $log = Get-MihariBrowserMemberValue -InputObject $document -Name 'log'
    $version = [string](Get-MihariBrowserMemberValue -InputObject $log -Name 'version')
    if ($null -eq $log -or $version -ne '1.2') {
        return [pscustomobject]@{ format = 'HAR'; version = $version; supported = $false; importedCount = 0; unsupportedCount = 1; records = @() }
    }
    $entries = @(Get-MihariBrowserMemberValue -InputObject $log -Name 'entries')
    if ($entries.Count -gt $MaximumEntries) { throw 'HAR entry count exceeds the configured limit.' }
    $importId = [Guid]::NewGuid().ToString('N')
    $records = New-Object System.Collections.ArrayList
    $unsupported = 0
    $index = 0
    foreach ($entry in $entries) {
        $index++
        $request = Get-MihariBrowserMemberValue -InputObject $entry -Name 'request'
        $target = ConvertTo-MihariBrowserSafeTarget -Url ([string](Get-MihariBrowserMemberValue -InputObject $request -Name 'url'))
        $method = ConvertTo-MihariBrowserSafeMethod -Method (Get-MihariBrowserMemberValue -InputObject $request -Name 'method')
        if ($null -eq $target -or $null -eq $method) { $unsupported++; continue }
        $response = Get-MihariBrowserMemberValue -InputObject $entry -Name 'response'
        $data = [ordered]@{
            scheme = $target.Scheme
            host = $target.Host
            port = $target.Port
            path = $target.Path
            method = $method
        }
        $status = 0
        $statusValue = Get-MihariBrowserMemberValue -InputObject $response -Name 'status'
        if ($null -ne $statusValue -and [int]::TryParse([string]$statusValue, [ref]$status) -and $status -ge 100 -and $status -le 599) {
            $data['statusCode'] = $status
        }
        $protocol = ConvertTo-MihariBrowserSafeProtocol -Protocol (Get-MihariBrowserMemberValue -InputObject $response -Name 'httpVersion')
        if ($null -ne $protocol) { $data['protocol'] = $protocol }
        $elapsed = $null
        $time = 0.0
        $timeValue = Get-MihariBrowserMemberValue -InputObject $entry -Name 'time'
        if ($null -ne $timeValue -and [double]::TryParse([string]$timeValue, [ref]$time) -and
            -not [double]::IsNaN($time) -and -not [double]::IsInfinity($time) -and $time -ge 0) {
            $elapsed = [long][Math]::Round($time, 0, [MidpointRounding]::AwayFromZero)
            $data['browserTimingOrigin'] = 'har'
        }
        $sourceTimestampUtc = $null
        $startedDateTime = [string](Get-MihariBrowserMemberValue -InputObject $entry -Name 'startedDateTime')
        $parsedTimestamp = [DateTimeOffset]::MinValue
        if (-not [string]::IsNullOrWhiteSpace($startedDateTime) -and
            [DateTimeOffset]::TryParse($startedDateTime, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$parsedTimestamp)) {
            $sourceTimestampUtc = $parsedTimestamp.ToUniversalTime().ToString('o', [Globalization.CultureInfo]::InvariantCulture)
        }
        $record = New-MihariImportedBrowserRecord -ImportId $importId -SourceVersion 'har-1.2' `
            -SourceRecordId ([string]$index) -Outcome 'imported' -ElapsedMs $elapsed `
            -SourceTimestampUtc $sourceTimestampUtc -Data $data
        [void]$records.Add($record)
    }
    return [pscustomobject]@{
        format = 'HAR'
        version = $version
        supported = $true
        importId = $importId
        importedCount = $records.Count
        unsupportedCount = $unsupported
        records = [object[]]$records.ToArray()
    }
}

function Get-MihariNetLogEventTypeName {
    param(
        [Parameter(Mandatory = $true)][object] $Event,
        [AllowNull()][object] $Constants
    )

    $type = Get-MihariBrowserMemberValue -InputObject $Event -Name 'type'
    if ($type -is [string]) { return $type }
    $eventTypes = Get-MihariBrowserMemberValue -InputObject $Constants -Name 'logEventTypes'
    if ($eventTypes -is [System.Collections.IDictionary]) {
        foreach ($key in $eventTypes.Keys) {
            if ([string]$eventTypes[$key] -ceq [string]$type) { return [string]$key }
        }
    }
    elseif ($null -ne $eventTypes) {
        foreach ($property in $eventTypes.PSObject.Properties) {
            if ([string]$property.Value -ceq [string]$type) { return [string]$property.Name }
        }
    }
    return $null
}

function ConvertFrom-MihariNetLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [ValidateRange(1, 100000)][int] $MaximumEvents = 20000,
        [ValidateRange(1024, 67108864)][long] $MaximumBytes = 67108864
    )

    $text = Get-MihariBrowserImportFileText -Path $Path -MaximumBytes $MaximumBytes
    $document = ConvertFrom-Json -InputObject $text -ErrorAction Stop
    $constants = Get-MihariBrowserMemberValue -InputObject $document -Name 'constants'
    $events = @(Get-MihariBrowserMemberValue -InputObject $document -Name 'events')
    if ($null -eq $constants -or $events.Count -eq 0) {
        return [pscustomobject]@{ format = 'Chromium NetLog JSON'; version = 'unrecognized'; supported = $false; importedCount = 0; unsupportedCount = 1; records = @() }
    }
    if ($events.Count -gt $MaximumEvents) { throw 'NetLog event count exceeds the configured limit.' }
    $importId = [Guid]::NewGuid().ToString('N')
    $records = New-Object System.Collections.ArrayList
    $unsupported = 0
    $index = 0
    foreach ($event in $events) {
        $index++
        $typeName = Get-MihariNetLogEventTypeName -Event $event -Constants $constants
        if ($typeName -notin @('URL_REQUEST_START_JOB', 'URL_REQUEST_REDIRECTED', 'HTTP_TRANSACTION_READ_HEADERS')) {
            $unsupported++
            continue
        }
        $parameters = Get-MihariBrowserMemberValue -InputObject $event -Name 'params'
        $url = Get-MihariBrowserMemberValue -InputObject $parameters -Name 'url'
        if ($null -eq $url) { $url = Get-MihariBrowserMemberValue -InputObject $parameters -Name 'new_url' }
        $target = ConvertTo-MihariBrowserSafeTarget -Url ([string]$url)
        if ($null -eq $target) { $unsupported++; continue }
        $method = ConvertTo-MihariBrowserSafeMethod -Method (Get-MihariBrowserMemberValue -InputObject $parameters -Name 'method')
        $data = [ordered]@{
            scheme = $target.Scheme
            host = $target.Host
            port = $target.Port
            path = $target.Path
        }
        if ($null -ne $method) { $data['method'] = $method }
        $status = 0
        foreach ($statusName in @('status_code', 'response_code')) {
            $statusValue = Get-MihariBrowserMemberValue -InputObject $parameters -Name $statusName
            if ($null -ne $statusValue -and [int]::TryParse([string]$statusValue, [ref]$status) -and $status -ge 100 -and $status -le 599) {
                $data['statusCode'] = $status
                break
            }
        }
        $protocolValue = Get-MihariBrowserMemberValue -InputObject $parameters -Name 'http_version'
        if ($null -eq $protocolValue) { $protocolValue = Get-MihariBrowserMemberValue -InputObject $parameters -Name 'protocol' }
        $protocol = ConvertTo-MihariBrowserSafeProtocol -Protocol $protocolValue
        if ($null -ne $protocol) { $data['protocol'] = $protocol }
        $netError = Get-MihariBrowserMemberValue -InputObject $parameters -Name 'net_error'
        $netErrorValue = 0
        if ($null -ne $netError -and [int]::TryParse([string]$netError, [ref]$netErrorValue)) {
            $data['browserError'] = ('net_error:' + $netErrorValue)
        }
        $source = Get-MihariBrowserMemberValue -InputObject $event -Name 'source'
        $localSourceIdValue = Get-MihariBrowserMemberValue -InputObject $source -Name 'id'
        $sourceTypeValue = Get-MihariBrowserMemberValue -InputObject $source -Name 'type'
        $localSourceId = $null
        $sourceType = $null
        $parsedSourceId = [long]0
        $parsedSourceType = [long]0
        if ($null -ne $localSourceIdValue -and [string]$localSourceIdValue -match '^\d{1,19}$' -and
            [long]::TryParse([string]$localSourceIdValue, [ref]$parsedSourceId) -and $parsedSourceId -ge 0) {
            $localSourceId = [string]$parsedSourceId
        }
        if ($null -ne $sourceTypeValue -and [string]$sourceTypeValue -match '^\d{1,19}$' -and
            [long]::TryParse([string]$sourceTypeValue, [ref]$parsedSourceType) -and $parsedSourceType -ge 0) {
            $sourceType = [string]$parsedSourceType
        }
        $safeRecordId = $typeName + ':' + $(if ($null -ne $localSourceId) { $localSourceId } else { 'unknown' }) + ':' + [string]$index
        $sourceRequestId = $safeRecordId
        if ($null -ne $localSourceId -and $null -ne $sourceType) {
            $sourceRequestId = 'netlog:' + $sourceType + ':' + $localSourceId
        }
        $record = New-MihariImportedBrowserRecord -ImportId $importId -SourceVersion 'chromium-netlog-json-recognized-events-v1' `
            -SourceRecordId $safeRecordId -SourceRequestId $sourceRequestId -Outcome 'imported' -ElapsedMs $null -Data $data
        [void]$records.Add($record)
    }
    return [pscustomobject]@{
        format = 'Chromium NetLog JSON'
        version = 'recognized-v1-events'
        supported = $true
        importId = $importId
        importedCount = $records.Count
        unsupportedCount = $unsupported
        records = [object[]]$records.ToArray()
    }
}

function ConvertTo-MihariBrowserImportEventData {
    param([Parameter(Mandatory = $true)][object] $InputData)

    $data = [ordered]@{}
    foreach ($name in @('scheme', 'host', 'path', 'method', 'protocol', 'browserError', 'browserTimingOrigin')) {
        $value = Get-MihariBrowserMemberValue -InputObject $InputData -Name $name
        if ($null -eq $value) { continue }
        $text = [string]$value
        if ($text.Length -gt 4096) { continue }
        $valid = $true
        switch ($name) {
            'scheme' { if ($text -notin @('http', 'https')) { $valid = $false } }
            'host' { if ($text -notmatch '^[A-Za-z0-9.-]{1,253}$' -and $text -notmatch '^\[[0-9A-Fa-f:.]{2,45}\]$') { $valid = $false } }
            'method' { $text = ConvertTo-MihariBrowserSafeMethod -Method $text; if ($null -eq $text) { $valid = $false } }
            'protocol' { $text = ConvertTo-MihariBrowserSafeProtocol -Protocol $text; if ($null -eq $text) { $valid = $false } }
            'browserError' {
                if ($text -notmatch '^(net::ERR_[A-Z0-9_]{1,80}|blocked:[a-z0-9-]{1,80}|cors:[A-Za-z][A-Za-z0-9_]{0,63}|net_error:-?[0-9]{1,10})$') { $valid = $false }
            }
            'browserTimingOrigin' { if ($text -notin @('har')) { $valid = $false } }
            'path' {
                if (-not $text.StartsWith('/')) { $valid = $false }
                else { $text = [regex]::Replace($text, '([?&][^=&#\s]+)=([^&#\s]*)', '$1=[REDACTED]') }
            }
        }
        if ($valid -and $null -ne $text) { $data[$name] = $text }
    }
    foreach ($name in @('port', 'statusCode')) {
        $value = Get-MihariBrowserMemberValue -InputObject $InputData -Name $name
        $parsed = 0
        if ($null -ne $value -and [int]::TryParse([string]$value, [ref]$parsed)) {
            if (($name -eq 'port' -and $parsed -ge 1 -and $parsed -le 65535) -or
                ($name -eq 'statusCode' -and $parsed -ge 100 -and $parsed -le 599)) {
                $data[$name] = $parsed
            }
        }
    }
    return [pscustomobject]$data
}

function Import-MihariBrowserEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][object] $Session,
        [Parameter(Mandatory = $true)][ValidateSet('har', 'netlog')][string] $Format,
        [Parameter(Mandatory = $true)][string] $Path
    )

    if ($Path.Length -gt 4096 -or -not [System.IO.Path]::IsPathRooted($Path)) { throw 'browser_import_source_unavailable' }
    if (-not [System.IO.File]::Exists($Path)) { throw 'browser_import_source_not_found' }
    try { $fullPath = [System.IO.Path]::GetFullPath($Path) }
    catch { throw 'browser_import_source_unavailable' }
    $writer = Get-MihariBrowserMemberValue -InputObject $Session -Name 'Writer'
    if ($null -eq $writer -or [bool]$writer.Closed -or $null -eq (Get-MihariBrowserMemberValue -InputObject $Session -Name 'Mode')) {
        throw 'browser_import_writer_unavailable'
    }

    $parsed = $null
    try {
        if ($Format -eq 'har') {
            $parsed = ConvertFrom-MihariHar -Path $fullPath -MaximumEntries 20000 -MaximumBytes 67108864
        }
        else {
            $parsed = ConvertFrom-MihariNetLog -Path $fullPath -MaximumEvents 20000 -MaximumBytes 67108864
        }
    }
    catch {
        switch -Exact ($_.Exception.Message) {
            'browser_import_source_too_large' { throw 'browser_import_source_too_large' }
            'HAR entry count exceeds the configured limit.' { throw 'browser_import_record_limit' }
            'NetLog event count exceeds the configured limit.' { throw 'browser_import_record_limit' }
            'browser_import_source_unavailable' { throw 'browser_import_source_unavailable' }
            default { throw 'browser_import_invalid_input' }
        }
    }

    $formatName = [string]$parsed.format
    if (-not [bool]$parsed.supported) {
        return [pscustomobject][ordered]@{
            format = $formatName; supported = $false; sourceIdentity = $null; sourceVersion = $null
            importedCount = 0; unsupportedCount = [int]$parsed.unsupportedCount; coverage = 'unsupported'
        }
    }
    $importId = [string]$parsed.importId
    if ($importId -notmatch '^[0-9a-f]{32}$' -or @($parsed.records).Count -gt 20000) { throw 'browser_import_invalid_input' }
    $sourceVersion = if ($Format -eq 'har') { 'har-1.2' } else { 'chromium-netlog-json-recognized-events-v1' }
    $configurationRevision = Get-MihariBrowserMemberValue -InputObject $Session -Name 'ConfigurationRevision'
    $writtenCount = 0
    foreach ($record in @($parsed.records)) {
        $recordId = [string](Get-MihariBrowserMemberValue -InputObject $record -Name 'sourceRecordId')
        $requestIdentity = [string](Get-MihariBrowserMemberValue -InputObject $record -Name 'sourceRequestId')
        if ($recordId -notmatch '^im-[0-9a-f]{24}$') { throw 'browser_import_invalid_input' }
        if ($requestIdentity -notmatch '^ir-[0-9a-f]{24}$') { $requestIdentity = $recordId }
        $data = ConvertTo-MihariBrowserImportEventData -InputData (Get-MihariBrowserMemberValue -InputObject $record -Name 'data')
        $requestId = 'browser-import-' + $requestIdentity
        $connectionId = 'browser-import-' + $importId + '-' + $recordId
        $arguments = @{
            Session = $Session; ConnectionId = $connectionId; RequestId = $requestId
            Stage = 'browser.network.request'; Outcome = 'imported'
            ElapsedMs = (Get-MihariBrowserMemberValue -InputObject $record -Name 'elapsedMs')
            Data = $data; Mode = [string]$Session.Mode; Source = 'import'; Coverage = 'observed'
            SourceIdentity = $importId; SourceVersion = $sourceVersion
        }
        if ($null -ne $configurationRevision) { $arguments.ConfigurationRevision = [int]$configurationRevision }
        try { $null = Write-MihariEvent @arguments }
        catch { throw 'browser_import_writer_unavailable' }
        $writtenCount++
    }
    $unsupportedCount = [int]$parsed.unsupportedCount
    $coverage = 'observed'
    if ($unsupportedCount -gt 0 -and $writtenCount -eq 0) { $coverage = 'unsupported' }
    elseif ($unsupportedCount -gt 0) { $coverage = 'partial' }
    return [pscustomobject][ordered]@{
        format = $formatName; supported = $true; sourceIdentity = $importId; sourceVersion = $sourceVersion
        importedCount = $writtenCount; unsupportedCount = $unsupportedCount; coverage = $coverage
    }
}
