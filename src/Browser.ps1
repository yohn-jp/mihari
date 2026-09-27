function Get-MihariBrowserMetadataValue {
    param(
        [Parameter(Mandatory = $true)]
        [object] $Metadata,

        [Parameter(Mandatory = $true)]
        [string] $Name
    )

    if ($Metadata -is [System.Collections.IDictionary]) {
        if ($Metadata.Contains($Name)) {
            return $Metadata[$Name]
        }
        return $null
    }

    $property = $Metadata.PSObject.Properties[$Name]
    if ($null -ne $property) {
        return $property.Value
    }
    return $null
}

function Find-MihariEdgeExecutable {
    $candidatePaths = @()

    $command = Get-Command -Name 'msedge.exe' -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($null -ne $command) {
        if (-not [string]::IsNullOrWhiteSpace([string]$command.Source)) {
            $candidatePaths += [string]$command.Source
        }
    }

    $programDirectories = @(
        $env:ProgramFiles,
        ${env:ProgramFiles(x86)},
        $env:LOCALAPPDATA
    )
    foreach ($programDirectory in $programDirectories) {
        if (-not [string]::IsNullOrWhiteSpace([string]$programDirectory)) {
            $candidatePaths += [System.IO.Path]::Combine(
                [string]$programDirectory,
                'Microsoft',
                'Edge',
                'Application',
                'msedge.exe'
            )
        }
    }

    $registryPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe'
    )
    foreach ($registryPath in $registryPaths) {
        $registryKey = Get-Item -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if ($null -ne $registryKey) {
            $registeredPath = [string]$registryKey.GetValue('')
            if (-not [string]::IsNullOrWhiteSpace($registeredPath)) {
                $candidatePaths += $registeredPath.Trim([char]34)
            }
        }
    }

    foreach ($candidatePath in $candidatePaths) {
        if (-not [string]::IsNullOrWhiteSpace([string]$candidatePath) -and
            (Test-Path -LiteralPath $candidatePath -PathType Leaf)) {
            return [System.IO.Path]::GetFullPath($candidatePath)
        }
    }

    return $null
}

function ConvertTo-MihariWindowsArgument {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string] $Value
    )

    # ProcessStartInfo.Arguments is available in .NET Framework, but its
    # argument-list API is not available in Windows PowerShell 5.1. Quote each
    # argument using the Windows command-line escaping rules.
    $builder = New-Object System.Text.StringBuilder
    [void]$builder.Append([char]34)
    $backslashCount = 0

    for ($index = 0; $index -lt $Value.Length; $index++) {
        $character = $Value[$index]
        if ($character -eq [char]92) {
            $backslashCount++
        }
        elseif ($character -eq [char]34) {
            for ($slash = 0; $slash -lt (($backslashCount * 2) + 1); $slash++) {
                [void]$builder.Append([char]92)
            }
            [void]$builder.Append([char]34)
            $backslashCount = 0
        }
        else {
            for ($slash = 0; $slash -lt $backslashCount; $slash++) {
                [void]$builder.Append([char]92)
            }
            [void]$builder.Append($character)
            $backslashCount = 0
        }
    }

    for ($slash = 0; $slash -lt ($backslashCount * 2); $slash++) {
        [void]$builder.Append([char]92)
    }
    [void]$builder.Append([char]34)
    return $builder.ToString()
}

function New-MihariBrowserLaunchResult {
    param(
        [bool] $Success,
        [string] $Path,
        [Nullable[int]] $ProcessId,
        [string] $ProfilePath,
        [string] $ProxyEndpoint,
        [string] $Reason,
        [string] $DiagnosticProfile = 'compatibility',
        [int] $ProfileVersion = 1,
        [string] $RequestedHttpVersion = 'http/1.1',
        [string] $RequestedTlsPolicy = 'maximum_tls_1_2',
        [string] $ObservationStatus = 'launched_but_unverified',
        [string] $OwnerStartTimeUtc
    )

    return [pscustomobject]@{
        Success               = $Success
        Path                  = $Path
        Pid                   = $ProcessId
        ProfilePath           = $ProfilePath
        ProxyEndpoint         = $ProxyEndpoint
        Reason                = $Reason
        DiagnosticProfile     = $DiagnosticProfile
        ProfileVersion        = $ProfileVersion
        RequestedHttpVersion  = $RequestedHttpVersion
        RequestedTlsPolicy    = $RequestedTlsPolicy
        ObservationStatus     = $ObservationStatus
        OwnerStartTimeUtc     = $OwnerStartTimeUtc
        SourceIdentity        = $null
        SourceVersion         = $null
        ClockId               = $null
        ProfileWarning        = $(if (-not [string]::IsNullOrWhiteSpace($ProfilePath)) { 'The diagnostic Edge profile can retain browser-managed cookies and history. Close Edge before cleanup.' } else { $null })
    }
}

function Get-MihariEdgeLaunchArguments {
    param(
        [Parameter(Mandatory = $true)]
        [string] $ProfilePath,

        [Parameter(Mandatory = $true)]
        [string] $ProxyEndpoint,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string] $Url,

        [Parameter(Mandatory = $false)]
        [ValidateSet('compatibility', 'http2-observe', 'http2-inspect')]
        [string] $DiagnosticProfile = 'compatibility'
    )

    # Edge is Chromium based. These switches keep ordinary browser HTTP(S)
    # requests on Mihari, including loopback fixture destinations which Edge
    # otherwise excludes from manually configured proxies. QUIC is not
    # supported by Mihari, and WebRTC must not create an unproxied UDP path.
    $arguments = @(
        ('--user-data-dir={0}' -f $ProfilePath),
        '--remote-debugging-port=0',
        ('--proxy-server={0}' -f $ProxyEndpoint),
        '--proxy-bypass-list=<-loopback>',
        '--disable-quic',
        '--force-webrtc-ip-handling-policy=disable_non_proxied_udp'
    )
    if ($DiagnosticProfile -eq 'compatibility') {
        $arguments += '--disable-http2'
        $arguments += '--ssl-version-max=tls1.2'
    }
    elseif ($DiagnosticProfile -eq 'http2-inspect') {
        $arguments += '--ssl-version-max=tls1.2'
    }
    if (-not [string]::IsNullOrWhiteSpace($Url)) {
        $arguments += $Url
    }
    return ,$arguments
}

function Start-MihariEdgeProcess {
    param(
        [Parameter(Mandatory = $true)]
        [System.Diagnostics.ProcessStartInfo] $StartInfo
    )

    $process = [System.Diagnostics.Process]::Start($StartInfo)
    if ($null -eq $process) {
        return $null
    }

    try {
        return $process.Id
    }
    finally {
        $process.Dispose()
    }
}

function Complete-MihariBrowserLaunch {
    param(
        [Parameter(Mandatory = $true)]
        [object] $SessionMetadata,

        [Parameter(Mandatory = $true)]
        [object] $Result,

        [bool] $UrlProvided
    )

    if (-not [string]::IsNullOrWhiteSpace([string]$Result.Reason)) {
        $safeReason = [string]$Result.Reason
        if (Get-Command -Name 'ConvertTo-MihariSafeText' -CommandType Function -ErrorAction SilentlyContinue) {
            $safeReason = ConvertTo-MihariSafeText -Text $safeReason
        }
        else {
            # Browser.ps1 can be loaded on its own by repository-owned tests.
            # Keep the same query-value redaction at that boundary.
            $safeReason = [System.Text.RegularExpressions.Regex]::Replace(
                $safeReason,
                '([?&][^=&#\s]+)=([^&#\s]*)',
                '$1=[REDACTED]'
            )
            $safeReason = [System.Text.RegularExpressions.Regex]::Replace(
                $safeReason,
                '(?i)(https?://)[^/\s?#@]+@',
                '$1[REDACTED]@'
            )
        }
        if ($safeReason.Length -gt 512) { $safeReason = $safeReason.Substring(0, 512) }
        $Result.Reason = $safeReason
    }

    $outputDirectory = [string](Get-MihariBrowserMetadataValue -Metadata $SessionMetadata -Name 'outputDirectory')
    if ([string]::IsNullOrWhiteSpace($outputDirectory)) {
        return $Result
    }

    # Preserve only the safe launch configuration. The requested URL and raw
    # command-line arguments may contain credentials or query values.
    $browserLaunchSucceeded = [bool]$Result.Success
    $compatibilityProfile = ([string]$Result.DiagnosticProfile -eq 'compatibility')
    $tls12Profile = $compatibilityProfile -or ([string]$Result.DiagnosticProfile -eq 'http2-inspect')
    $launchMetadata = [pscustomobject]@{
        schemaVersion = 2
        timestamp = [DateTime]::UtcNow.ToString('o')
        executablePath = $Result.Path
        profilePath = $Result.ProfilePath
        proxyEndpoint = $Result.ProxyEndpoint
        proxiedSchemes = $(if ($browserLaunchSucceeded) { @('http', 'https') } else { @() })
        loopbackBypassDisabled = $browserLaunchSucceeded
        quicDisabled = $browserLaunchSucceeded
        http2Disabled = ($browserLaunchSucceeded -and $compatibilityProfile)
        nonProxiedWebRtcUdpDisabled = $browserLaunchSucceeded
        maximumTlsVersion = $(if ($browserLaunchSucceeded -and $tls12Profile) { 'tls1.2' } else { $null })
        profile = [string]$Result.DiagnosticProfile
        profileVersion = [int]$Result.ProfileVersion
        requestedProxyServer = $browserLaunchSucceeded
        requestedLoopbackProxying = $browserLaunchSucceeded
        requestedRemoteDebugging = $browserLaunchSucceeded
        requestedQuicDisabled = $browserLaunchSucceeded
        requestedHttp2Disabled = ($browserLaunchSucceeded -and $compatibilityProfile)
        requestedHttp2Enabled = ($browserLaunchSucceeded -and -not $compatibilityProfile)
        requestedHttpVersion = [string]$Result.RequestedHttpVersion
        requestedTlsPolicy = [string]$Result.RequestedTlsPolicy
        observationStatus = [string]$Result.ObservationStatus
        proxyBehaviorVerification = 'launched_but_unverified'
        profileWarning = $Result.ProfileWarning
        processId = $Result.Pid
        success = $Result.Success
        reason = $Result.Reason
        urlProvided = $UrlProvided
    }

    try {
        [void][System.IO.Directory]::CreateDirectory($outputDirectory)
        $metadataPath = [System.IO.Path]::Combine($outputDirectory, 'browser-launch.json')
        $json = ConvertTo-Json -InputObject $launchMetadata -Depth 4
        [System.IO.File]::WriteAllText($metadataPath, $json, [System.Text.Encoding]::UTF8)
    }
    catch {
        $writeFailure = 'Could not write browser launch metadata ({0}).' -f $_.Exception.GetType().FullName
        if ([string]::IsNullOrWhiteSpace([string]$Result.Reason)) {
            $Result.Reason = $writeFailure
        }
        else {
            $Result.Reason = '{0} {1}' -f $Result.Reason, $writeFailure
        }
    }

    return $Result
}

function Get-MihariBrowserProfileSettings {
    param([Parameter(Mandatory = $true)][object] $SessionMetadata)

    $profileName = [string](Get-MihariBrowserMetadataValue -Metadata $SessionMetadata -Name 'profile')
    if ([string]::IsNullOrWhiteSpace($profileName)) {
        $profileName = [string](Get-MihariBrowserMetadataValue -Metadata $SessionMetadata -Name 'Profile')
    }
    if ([string]::IsNullOrWhiteSpace($profileName)) { $profileName = 'compatibility' }
    if ($profileName -notin @('compatibility', 'http2-observe', 'http2-inspect')) {
        throw ('Unsupported Mihari diagnostic browser profile: {0}' -f $profileName)
    }
    if ($profileName -in @('http2-observe', 'http2-inspect')) {
        $modeName = [string](Get-MihariBrowserMetadataValue -Metadata $SessionMetadata -Name 'mode')
        if ([string]::IsNullOrWhiteSpace($modeName)) {
            $modeName = [string](Get-MihariBrowserMetadataValue -Metadata $SessionMetadata -Name 'Mode')
        }
        $requiredMode = 'Tunnel'
        if ($profileName -eq 'http2-inspect') { $requiredMode = 'Inspect' }
        if (-not [string]::IsNullOrWhiteSpace($modeName) -and $modeName -ne $requiredMode) {
            throw ('The {0} diagnostic browser profile requires {1} mode.' -f $profileName, $requiredMode)
        }
    }

    $profileVersion = 1
    $versionValue = Get-MihariBrowserMetadataValue -Metadata $SessionMetadata -Name 'profileVersion'
    if ($null -eq $versionValue) { $versionValue = Get-MihariBrowserMetadataValue -Metadata $SessionMetadata -Name 'ProfileVersion' }
    if ($null -ne $versionValue -and -not [int]::TryParse([string]$versionValue, [ref]$profileVersion)) {
        throw 'The Mihari diagnostic browser profile version is invalid.'
    }
    if ($profileVersion -lt 1) { throw 'The Mihari diagnostic browser profile version must be positive.' }

    if ($profileName -eq 'http2-observe') {
        return [pscustomobject]@{
            Name = $profileName
            Version = $profileVersion
            RequestedHttpVersion = 'allow_h2'
            RequestedTlsPolicy = 'system_default'
        }
    }
    if ($profileName -eq 'http2-inspect') {
        return [pscustomobject]@{
            Name = $profileName
            Version = $profileVersion
            RequestedHttpVersion = 'allow_h2'
            RequestedTlsPolicy = 'maximum_tls_1_2'
        }
    }
    return [pscustomobject]@{
        Name = $profileName
        Version = $profileVersion
        RequestedHttpVersion = 'http/1.1'
        RequestedTlsPolicy = 'maximum_tls_1_2'
    }
}

function Get-MihariBrowserProcessStartTimeUtc {
    param(
        [Parameter(Mandatory = $true)][int] $ProcessId,
        [Parameter(Mandatory = $true)][string] $ExpectedExecutable
    )

    $process = $null
    try {
        $process = [System.Diagnostics.Process]::GetProcessById($ProcessId)
        if ($process.HasExited) { return $null }
        $actualPath = [string]$process.MainModule.FileName
        if (-not [string]::Equals(
                [System.IO.Path]::GetFullPath($actualPath),
                [System.IO.Path]::GetFullPath($ExpectedExecutable),
                [StringComparison]::OrdinalIgnoreCase)) {
            return $null
        }
        return $process.StartTime.ToUniversalTime().ToString('o', [Globalization.CultureInfo]::InvariantCulture)
    }
    catch {
        # A PID without readable executable and start-time identity is not
        # sufficient authority for a DevTools attachment.
        return $null
    }
    finally {
        if ($null -ne $process) { $process.Dispose() }
    }
}

function Start-MihariBrowser {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object] $SessionMetadata,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string] $Url
    )

    try {
        $profile = Get-MihariBrowserProfileSettings -SessionMetadata $SessionMetadata
    }
    catch {
        $result = New-MihariBrowserLaunchResult -Success $false -Path $null -ProcessId $null `
            -ProfilePath $null -ProxyEndpoint $null -Reason $_.Exception.Message
        return (Complete-MihariBrowserLaunch -SessionMetadata $SessionMetadata -Result $result `
            -UrlProvided (-not [string]::IsNullOrWhiteSpace($Url)))
    }

    $portValue = Get-MihariBrowserMetadataValue -Metadata $SessionMetadata -Name 'actualPort'
    if ($null -eq $portValue -or [string]::IsNullOrWhiteSpace([string]$portValue)) {
        $portValue = Get-MihariBrowserMetadataValue -Metadata $SessionMetadata -Name 'port'
    }

    $port = 0
    if (-not [int]::TryParse([string]$portValue, [ref]$port) -or $port -lt 1 -or $port -gt 65535) {
        $result = New-MihariBrowserLaunchResult -Success $false -Path $null -ProcessId $null `
            -ProfilePath $null -ProxyEndpoint $null `
            -Reason 'Session metadata does not contain a valid loopback listener port; configure a browser with the active Mihari endpoint.' `
            -DiagnosticProfile $profile.Name -ProfileVersion $profile.Version `
            -RequestedHttpVersion $profile.RequestedHttpVersion -RequestedTlsPolicy $profile.RequestedTlsPolicy
        return (Complete-MihariBrowserLaunch -SessionMetadata $SessionMetadata -Result $result `
            -UrlProvided (-not [string]::IsNullOrWhiteSpace($Url)))
    }

    $proxyEndpoint = 'http://127.0.0.1:{0}' -f $port
    $edgePath = Find-MihariEdgeExecutable
    if ([string]::IsNullOrWhiteSpace([string]$edgePath)) {
        $result = New-MihariBrowserLaunchResult -Success $false -Path $null -ProcessId $null `
            -ProfilePath $null -ProxyEndpoint $proxyEndpoint `
            -Reason ('Microsoft Edge was not found. Configure a browser manually to use the Mihari proxy at {0}.' -f $proxyEndpoint) `
            -DiagnosticProfile $profile.Name -ProfileVersion $profile.Version `
            -RequestedHttpVersion $profile.RequestedHttpVersion -RequestedTlsPolicy $profile.RequestedTlsPolicy
        return (Complete-MihariBrowserLaunch -SessionMetadata $SessionMetadata -Result $result `
            -UrlProvided (-not [string]::IsNullOrWhiteSpace($Url)))
    }

    $sessionId = [string](Get-MihariBrowserMetadataValue -Metadata $SessionMetadata -Name 'id')
    if ([string]::IsNullOrWhiteSpace($sessionId)) {
        $sessionId = 'session'
    }
    $safeSessionId = [System.Text.RegularExpressions.Regex]::Replace($sessionId, '[^A-Za-z0-9_-]', '_')
    $profilePath = [System.IO.Path]::Combine(
        [System.IO.Path]::GetTempPath(),
        'Mihari',
        ('Edge-{0}-{1}' -f $safeSessionId, [Guid]::NewGuid().ToString('N'))
    )

    try {
        [void][System.IO.Directory]::CreateDirectory($profilePath)
    }
    catch {
        $reason = 'Could not create the temporary Edge profile ({0}).' -f $_.Exception.GetType().FullName
        $result = New-MihariBrowserLaunchResult -Success $false -Path $edgePath -ProcessId $null `
            -ProfilePath $profilePath -ProxyEndpoint $proxyEndpoint -Reason $reason `
            -DiagnosticProfile $profile.Name -ProfileVersion $profile.Version `
            -RequestedHttpVersion $profile.RequestedHttpVersion -RequestedTlsPolicy $profile.RequestedTlsPolicy
        return (Complete-MihariBrowserLaunch -SessionMetadata $SessionMetadata -Result $result `
            -UrlProvided (-not [string]::IsNullOrWhiteSpace($Url)))
    }

    $observerCommand = Get-Command Start-MihariBrowserObservation -CommandType Function -ErrorAction SilentlyContinue
    $writer = Get-MihariBrowserMetadataValue -Metadata $SessionMetadata -Name 'Writer'
    $cancellation = Get-MihariBrowserMetadataValue -Metadata $SessionMetadata -Name 'Cancellation'
    $observerAcceptsInitialUrl = ($null -ne $observerCommand -and $observerCommand.Parameters.ContainsKey('InitialUrl'))
    $liveObserverAvailable = ($observerAcceptsInitialUrl -and $null -ne $writer -and
        -not [bool]$writer.Closed -and $null -ne $cancellation)
    $browserUrl = $Url
    if ($liveObserverAvailable -and -not [string]::IsNullOrWhiteSpace($Url)) {
        # Keep the requested URL in memory and navigate only after observation is armed.
        $browserUrl = 'about:blank'
    }
    $arguments = Get-MihariEdgeLaunchArguments -ProfilePath $profilePath `
        -ProxyEndpoint $proxyEndpoint -Url $browserUrl -DiagnosticProfile $profile.Name
    $quotedArguments = @()
    foreach ($argument in $arguments) {
        $quotedArguments += ConvertTo-MihariWindowsArgument -Value ([string]$argument)
    }

    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $edgePath
    $startInfo.Arguments = [string]::Join(' ', [string[]]$quotedArguments)
    $startInfo.UseShellExecute = $false

    try {
        $processId = Start-MihariEdgeProcess -StartInfo $startInfo
        if ($null -eq $processId) {
            $result = New-MihariBrowserLaunchResult -Success $false -Path $edgePath -ProcessId $null `
                -ProfilePath $profilePath -ProxyEndpoint $proxyEndpoint `
                -Reason 'Windows did not return a process handle when starting Microsoft Edge.' `
                -DiagnosticProfile $profile.Name -ProfileVersion $profile.Version `
                -RequestedHttpVersion $profile.RequestedHttpVersion -RequestedTlsPolicy $profile.RequestedTlsPolicy
            return (Complete-MihariBrowserLaunch -SessionMetadata $SessionMetadata -Result $result `
                -UrlProvided (-not [string]::IsNullOrWhiteSpace($Url)))
        }
        $ownerStartTimeUtc = Get-MihariBrowserProcessStartTimeUtc -ProcessId ([int]$processId) -ExpectedExecutable $edgePath
        $result = New-MihariBrowserLaunchResult -Success $true -Path $edgePath -ProcessId $processId `
            -ProfilePath $profilePath -ProxyEndpoint $proxyEndpoint -Reason $null `
            -DiagnosticProfile $profile.Name -ProfileVersion $profile.Version `
            -RequestedHttpVersion $profile.RequestedHttpVersion -RequestedTlsPolicy $profile.RequestedTlsPolicy `
            -OwnerStartTimeUtc $ownerStartTimeUtc
        if ($null -ne $ownerStartTimeUtc -and $null -ne $observerCommand) {
            if ($liveObserverAvailable) {
                try {
                    $observation = Start-MihariBrowserObservation -Session $SessionMetadata -Launch $result -InitialUrl $Url
                }
                catch {
                    $observation = $null
                }
            }
            else {
                $observation = Start-MihariBrowserObservation -Session $SessionMetadata -Launch $result
            }
            if ($null -ne $observation) {
                $result.ObservationStatus = [string]$observation.Status
                if (-not [string]::IsNullOrWhiteSpace([string]$observation.Reason)) {
                    $result.Reason = [string]$observation.Reason
                }
            }
            if ($liveObserverAvailable -and -not [string]::IsNullOrWhiteSpace($Url) -and
                ($null -eq $observation -or [string]$observation.Status -eq 'unavailable' -or
                    -not [string]::IsNullOrWhiteSpace([string]$observation.Reason))) {
                $result.Success = $false
                $result.Reason = 'Edge started on about:blank, but Mihari could not arm owned-profile observation. The requested URL was not opened.'
            }
        }
        elseif ($null -eq $ownerStartTimeUtc -and
            $null -ne (Get-MihariBrowserMetadataValue -Metadata $SessionMetadata -Name 'Writer')) {
            $result.ObservationStatus = 'launched_but_unverified'
            $result.Reason = 'Edge started, but Mihari could not verify process ownership for browser observation.'
        }
        return (Complete-MihariBrowserLaunch -SessionMetadata $SessionMetadata -Result $result `
            -UrlProvided (-not [string]::IsNullOrWhiteSpace($Url)))
    }
    catch {
        $reason = 'Microsoft Edge could not be started ({0}).' -f $_.Exception.GetType().FullName
        $result = New-MihariBrowserLaunchResult -Success $false -Path $edgePath -ProcessId $null `
            -ProfilePath $profilePath -ProxyEndpoint $proxyEndpoint -Reason $reason `
            -DiagnosticProfile $profile.Name -ProfileVersion $profile.Version `
            -RequestedHttpVersion $profile.RequestedHttpVersion -RequestedTlsPolicy $profile.RequestedTlsPolicy
        return (Complete-MihariBrowserLaunch -SessionMetadata $SessionMetadata -Result $result `
            -UrlProvided (-not [string]::IsNullOrWhiteSpace($Url)))
    }
}

# The observer is a separate runtime responsibility. Loading it here keeps the
# existing fixed source list compatible while still making the feature available
# to the main process and management worker runspaces.
$browserObservationPath = Join-Path $PSScriptRoot 'BrowserObservation.ps1'
if (Test-Path -LiteralPath $browserObservationPath -PathType Leaf) {
    . $browserObservationPath
}
