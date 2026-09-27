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
        [string] $Reason
    )

    return [pscustomobject]@{
        Success      = $Success
        Path         = $Path
        Pid          = $ProcessId
        ProfilePath  = $ProfilePath
        ProxyEndpoint = $ProxyEndpoint
        Reason       = $Reason
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
        [string] $Url
    )

    # Edge is Chromium based. These switches keep ordinary browser HTTP(S)
    # requests on Mihari, including loopback fixture destinations which Edge
    # otherwise excludes from manually configured proxies. QUIC is not
    # supported by Mihari, and WebRTC must not create an unproxied UDP path.
    $arguments = @(
        ('--user-data-dir={0}' -f $ProfilePath),
        ('--proxy-server={0}' -f $ProxyEndpoint),
        '--proxy-bypass-list=<-loopback>',
        '--disable-quic',
        '--disable-http2',
        '--force-webrtc-ip-handling-policy=disable_non_proxied_udp',
        '--ssl-version-max=tls1.2'
    )
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

    $outputDirectory = [string](Get-MihariBrowserMetadataValue -Metadata $SessionMetadata -Name 'outputDirectory')
    if ([string]::IsNullOrWhiteSpace($outputDirectory)) {
        return $Result
    }

    # Preserve only the safe launch configuration. The requested URL and raw
    # command-line arguments may contain credentials or query values.
    $browserLaunchSucceeded = [bool]$Result.Success
    $launchMetadata = [pscustomobject]@{
        schemaVersion = 1
        timestamp = [DateTime]::UtcNow.ToString('o')
        executablePath = $Result.Path
        profilePath = $Result.ProfilePath
        proxyEndpoint = $Result.ProxyEndpoint
        proxiedSchemes = $(if ($browserLaunchSucceeded) { @('http', 'https') } else { @() })
        loopbackBypassDisabled = $browserLaunchSucceeded
        quicDisabled = $browserLaunchSucceeded
        http2Disabled = $browserLaunchSucceeded
        nonProxiedWebRtcUdpDisabled = $browserLaunchSucceeded
        maximumTlsVersion = $(if ($browserLaunchSucceeded) { 'tls1.2' } else { $null })
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
        $writeFailure = 'Could not write browser launch metadata: {0}: {1}' -f $_.Exception.GetType().FullName, $_.Exception.Message
        if ([string]::IsNullOrWhiteSpace([string]$Result.Reason)) {
            $Result.Reason = $writeFailure
        }
        else {
            $Result.Reason = '{0} {1}' -f $Result.Reason, $writeFailure
        }
    }

    return $Result
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

    $portValue = Get-MihariBrowserMetadataValue -Metadata $SessionMetadata -Name 'actualPort'
    if ($null -eq $portValue -or [string]::IsNullOrWhiteSpace([string]$portValue)) {
        $portValue = Get-MihariBrowserMetadataValue -Metadata $SessionMetadata -Name 'port'
    }

    $port = 0
    if (-not [int]::TryParse([string]$portValue, [ref]$port) -or $port -lt 1 -or $port -gt 65535) {
        $result = New-MihariBrowserLaunchResult -Success $false -Path $null -ProcessId $null `
            -ProfilePath $null -ProxyEndpoint $null `
            -Reason 'Session metadata does not contain a valid loopback listener port; configure a browser with the active Mihari endpoint.'
        return (Complete-MihariBrowserLaunch -SessionMetadata $SessionMetadata -Result $result `
            -UrlProvided (-not [string]::IsNullOrWhiteSpace($Url)))
    }

    $proxyEndpoint = 'http://127.0.0.1:{0}' -f $port
    $edgePath = Find-MihariEdgeExecutable
    if ([string]::IsNullOrWhiteSpace([string]$edgePath)) {
        $result = New-MihariBrowserLaunchResult -Success $false -Path $null -ProcessId $null `
            -ProfilePath $null -ProxyEndpoint $proxyEndpoint `
            -Reason ('Microsoft Edge was not found. Configure a browser manually to use the Mihari proxy at {0}.' -f $proxyEndpoint)
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
        $reason = 'Could not create the temporary Edge profile: {0}: {1}' -f $_.Exception.GetType().FullName, $_.Exception.Message
        $result = New-MihariBrowserLaunchResult -Success $false -Path $edgePath -ProcessId $null `
            -ProfilePath $profilePath -ProxyEndpoint $proxyEndpoint -Reason $reason
        return (Complete-MihariBrowserLaunch -SessionMetadata $SessionMetadata -Result $result `
            -UrlProvided (-not [string]::IsNullOrWhiteSpace($Url)))
    }

    $arguments = Get-MihariEdgeLaunchArguments -ProfilePath $profilePath `
        -ProxyEndpoint $proxyEndpoint -Url $Url
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
                -Reason 'Windows did not return a process handle when starting Microsoft Edge.'
            return (Complete-MihariBrowserLaunch -SessionMetadata $SessionMetadata -Result $result `
                -UrlProvided (-not [string]::IsNullOrWhiteSpace($Url)))
        }
        $result = New-MihariBrowserLaunchResult -Success $true -Path $edgePath -ProcessId $processId `
            -ProfilePath $profilePath -ProxyEndpoint $proxyEndpoint -Reason $null
        return (Complete-MihariBrowserLaunch -SessionMetadata $SessionMetadata -Result $result `
            -UrlProvided (-not [string]::IsNullOrWhiteSpace($Url)))
    }
    catch {
        $reason = 'Microsoft Edge could not be started: {0}: {1}' -f $_.Exception.GetType().FullName, $_.Exception.Message
        $result = New-MihariBrowserLaunchResult -Success $false -Path $edgePath -ProcessId $null `
            -ProfilePath $profilePath -ProxyEndpoint $proxyEndpoint -Reason $reason
        return (Complete-MihariBrowserLaunch -SessionMetadata $SessionMetadata -Result $result `
            -UrlProvided (-not [string]::IsNullOrWhiteSpace($Url)))
    }
}
