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
        [string] $OwnerStartTimeUtc,
        [string] $ProfileOwnershipId
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
        ProfileOwnershipId    = $ProfileOwnershipId
        ProfileOwnershipWarning = $null
        SourceIdentity        = $null
        SourceVersion         = $null
        ClockId               = $null
        ProfileWarning        = $(if (-not [string]::IsNullOrWhiteSpace($ProfilePath)) { 'The diagnostic Edge profile can retain browser-managed cookies and history. Close Edge before cleanup.' } else { $null })
    }
}

function Get-MihariBrowserProfileRecordPath {
    param(
        [Parameter(Mandatory = $true)][string] $OutputDirectory,
        [Parameter(Mandatory = $true)][string] $ProfileOwnershipId
    )

    if ($ProfileOwnershipId -notmatch '^[0-9a-fA-F]{32}$') {
        throw 'The diagnostic browser profile ownership ID is invalid.'
    }
    return [System.IO.Path]::Combine($OutputDirectory, ('browser-profile-{0}.json' -f $ProfileOwnershipId.ToLowerInvariant()))
}

function Get-MihariBrowserProfileMarkerPath {
    param([Parameter(Mandatory = $true)][string] $ProfilePath)
    return [System.IO.Path]::Combine($ProfilePath, 'MihariProfileOwner.json')
}

function Test-MihariBrowserProfilePath {
    param(
        [Parameter(Mandatory = $true)][string] $ProfilePath,
        [Parameter(Mandatory = $true)][string] $SessionId
    )

    try {
        $fullPath = [System.IO.Path]::GetFullPath($ProfilePath).TrimEnd([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
        $managedRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), 'Mihari')).TrimEnd([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
        if ([System.IO.Directory]::Exists($managedRoot)) {
            $managedRootInfo = New-Object System.IO.DirectoryInfo($managedRoot)
            if (($managedRootInfo.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { return $false }
        }
        $parent = [System.IO.Directory]::GetParent($fullPath)
        if ($null -eq $parent -or -not [string]::Equals($parent.FullName.TrimEnd([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar), $managedRoot, [StringComparison]::OrdinalIgnoreCase)) {
            return $false
        }
        $safeSessionId = [System.Text.RegularExpressions.Regex]::Replace($SessionId, '[^A-Za-z0-9_-]', '_')
        $prefix = 'Edge-{0}-' -f $safeSessionId
        $leaf = [System.IO.Path]::GetFileName($fullPath)
        if (-not $leaf.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { return $false }
        $suffix = $leaf.Substring($prefix.Length)
        return ($suffix -match '^[0-9a-fA-F]{32}$')
    }
    catch {
        return $false
    }
}

function Set-MihariBrowserProfileOwnership {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][object] $SessionMetadata,
        [Parameter(Mandatory = $true)][object] $Result
    )

    $sessionId = [string](Get-MihariBrowserMetadataValue -Metadata $SessionMetadata -Name 'id')
    $outputDirectory = [string](Get-MihariBrowserMetadataValue -Metadata $SessionMetadata -Name 'outputDirectory')
    if ([string]::IsNullOrWhiteSpace($sessionId) -or [string]::IsNullOrWhiteSpace($outputDirectory) -or
        -not $Result.Success -or $null -eq $Result.Pid -or
        [string]::IsNullOrWhiteSpace([string]$Result.OwnerStartTimeUtc) -or
        [string]::IsNullOrWhiteSpace([string]$Result.Path) -or
        [string]::IsNullOrWhiteSpace([string]$Result.ProfilePath)) {
        return $false
    }

    $profilePath = [System.IO.Path]::GetFullPath([string]$Result.ProfilePath)
    if (-not (Test-MihariBrowserProfilePath -ProfilePath $profilePath -SessionId $sessionId)) {
        return $false
    }

    $ownershipId = [Guid]::NewGuid().ToString('N')
    $recordPath = Get-MihariBrowserProfileRecordPath -OutputDirectory $outputDirectory -ProfileOwnershipId $ownershipId
    $record = [pscustomobject][ordered]@{
        schemaVersion = 1
        sessionId = $sessionId
        profileOwnershipId = $ownershipId
        profilePath = $profilePath
        executablePath = [System.IO.Path]::GetFullPath([string]$Result.Path)
        processId = [int]$Result.Pid
        ownerStartTimeUtc = [string]$Result.OwnerStartTimeUtc
        createdUtc = [DateTime]::UtcNow.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
        cleanupState = 'retained'
        cleanupUtc = $null
    }
    $markerCreated = $false
    $temporaryRecordPath = $recordPath + '.tmp'
    try {
        [void][System.IO.Directory]::CreateDirectory($outputDirectory)
        $json = ConvertTo-Json -InputObject $record -Depth 4
        [System.IO.File]::WriteAllText($temporaryRecordPath, $json, [System.Text.UTF8Encoding]::new($false))
        if (-not (Get-Command New-MihariBrowserProfileOwnerMarker -CommandType Function -ErrorAction SilentlyContinue) -or
            -not (New-MihariBrowserProfileOwnerMarker -SessionId $sessionId -Launch $Result)) {
            throw 'The canonical Mihari browser ownership marker could not be created.'
        }
        $markerCreated = $true
        [System.IO.File]::Move($temporaryRecordPath, $recordPath)
        $Result.ProfileOwnershipId = $ownershipId
        return $true
    }
    catch {
        $markerPath = Get-MihariBrowserProfileMarkerPath -ProfilePath $profilePath
        if ($markerCreated -and [System.IO.File]::Exists($markerPath)) {
            try { [System.IO.File]::Delete($markerPath) }
            catch { $Result.ProfileOwnershipWarning = 'The diagnostic Edge profile is retained, but its ownership marker could not be removed after setup failed.' }
        }
        if ([System.IO.File]::Exists($temporaryRecordPath)) {
            try { [System.IO.File]::Delete($temporaryRecordPath) }
            catch { $Result.ProfileOwnershipWarning = 'The diagnostic Edge profile is retained, but temporary ownership metadata could not be removed.' }
        }
        if ([string]::IsNullOrWhiteSpace([string]$Result.ProfileOwnershipWarning)) {
            $Result.ProfileOwnershipWarning = 'Mihari could not verify ownership metadata for this diagnostic Edge profile; automatic cleanup is unavailable.'
        }
        return $false
    }
}

function Get-MihariBrowserProcesses {
    if ($null -eq (Get-Command Get-CimInstance -CommandType Cmdlet -ErrorAction SilentlyContinue)) {
        throw 'The Windows process inventory API is unavailable.'
    }
    try {
        return @(Get-CimInstance -ClassName Win32_Process -Filter "Name = 'msedge.exe'" -ErrorAction Stop)
    }
    catch {
        $exceptionType = $_.Exception.GetType().FullName
        throw ('The Windows process inventory could not verify Edge profile use ({0}).' -f $exceptionType)
    }
}

function Get-MihariBrowserProfileArgument {
    param([AllowNull()][string] $CommandLine)

    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return $null }
    $match = [System.Text.RegularExpressions.Regex]::Match(
        $CommandLine,
        '(?i)(?:^|\s)--user-data-dir(?:=|\s+)(?:"([^"]+)"|([^\s]+))'
    )
    if (-not $match.Success) { return $null }
    if ($match.Groups[1].Success) { return $match.Groups[1].Value }
    return $match.Groups[2].Value.Trim([char]34)
}

function Get-MihariBrowserProfileRecords {
    param([Parameter(Mandatory = $true)][object] $SessionMetadata)

    $outputDirectory = [string](Get-MihariBrowserMetadataValue -Metadata $SessionMetadata -Name 'outputDirectory')
    if ([string]::IsNullOrWhiteSpace($outputDirectory) -or -not [System.IO.Directory]::Exists($outputDirectory)) { return @() }
    $records = New-Object 'System.Collections.Generic.List[object]'
    foreach ($path in [System.IO.Directory]::GetFiles($outputDirectory, 'browser-profile-*.json', [System.IO.SearchOption]::TopDirectoryOnly)) {
        try {
            $record = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($path, [System.Text.Encoding]::UTF8)) -ErrorAction Stop
            if ($null -eq $record -or [int]$record.schemaVersion -ne 1 -or
                -not [string]::Equals([string]$record.sessionId, [string](Get-MihariBrowserMetadataValue -Metadata $SessionMetadata -Name 'id'), [StringComparison]::Ordinal) -or
                [System.IO.Path]::GetFileName($path) -ne ('browser-profile-{0}.json' -f [string]$record.profileOwnershipId)) {
                continue
            }
            $records.Add($record)
        }
        catch {
            # An unreadable ownership record is not authority to inspect or delete a profile.
            continue
        }
    }
    return @($records.ToArray())
}

function Test-MihariBrowserProfileMarker {
    param(
        [Parameter(Mandatory = $true)][object] $Record,
        [Parameter(Mandatory = $true)][string] $SessionId
    )

    if (-not (Test-MihariBrowserProfilePath -ProfilePath ([string]$Record.profilePath) -SessionId $SessionId) -or
        -not [System.IO.Directory]::Exists([string]$Record.profilePath)) { return $false }
    $markerPath = [System.IO.Path]::Combine([string]$Record.profilePath, 'MihariProfileOwner.json')
    if (-not [System.IO.File]::Exists($markerPath)) { return $false }
    try {
        $marker = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($markerPath, [System.Text.Encoding]::UTF8)) -ErrorAction Stop
        return ($null -ne $marker -and [int]$marker.schemaVersion -eq 1 -and
            [string]$marker.owner -ceq 'Mihari' -and
            [string]::Equals([string]$marker.sessionId, [string]$Record.sessionId, [StringComparison]::Ordinal) -and
            [string]::Equals([string]$marker.profilePath, [string]$Record.profilePath, [StringComparison]::OrdinalIgnoreCase) -and
            [string]::Equals([string]$marker.executablePath, [string]$Record.executablePath, [StringComparison]::OrdinalIgnoreCase) -and
            [int]$marker.processId -eq [int]$Record.processId -and
            [string]::Equals([string]$marker.processStartTimeUtc, [string]$Record.ownerStartTimeUtc, [StringComparison]::Ordinal))
    }
    catch {
        return $false
    }
}

function Get-MihariBrowserProfileState {
    param(
        [Parameter(Mandatory = $true)][object] $SessionMetadata,
        [Parameter(Mandatory = $true)][object] $Record
    )

    $sessionId = [string](Get-MihariBrowserMetadataValue -Metadata $SessionMetadata -Name 'id')
    $profilePath = [string]$Record.profilePath
    $base = [pscustomobject][ordered]@{
        profileOwnershipId = [string]$Record.profileOwnershipId
        retained = $false
        state = 'unverified'
        cleanupAvailable = $false
        warning = $null
    }
    if ([string]$Record.cleanupState -eq 'cleaned') {
        $base.state = 'cleaned'
        return $base
    }
    if (-not (Test-MihariBrowserProfilePath -ProfilePath $profilePath -SessionId $sessionId)) {
        $base.warning = 'This diagnostic profile may retain browser-managed cookies and history. Mihari cannot verify its location or ownership, so cleanup is unavailable.'
        return $base
    }
    if (-not [System.IO.Directory]::Exists($profilePath)) {
        $base.state = 'not_found'
        return $base
    }
    $base.retained = $true
    if (-not (Test-MihariBrowserProfileMarker -Record $Record -SessionId $sessionId)) {
        $base.warning = 'This diagnostic profile may retain browser-managed cookies and history. Mihari could not verify its ownership, so cleanup is unavailable.'
        return $base
    }

    try { $processes = @(Get-MihariBrowserProcesses) }
    catch {
        $base.state = 'process_state_unavailable'
        $base.warning = 'This diagnostic profile may retain browser-managed cookies and history. Mihari could not verify that Edge is closed, so cleanup is unavailable.'
        return $base
    }
    $expectedExecutable = [string]$Record.executablePath
    $matchingProcesses = New-Object 'System.Collections.Generic.List[object]'
    foreach ($process in $processes) {
        $argumentPath = Get-MihariBrowserProfileArgument -CommandLine ([string]$process.CommandLine)
        if ([string]::IsNullOrWhiteSpace($argumentPath)) {
            if ([int]$process.ProcessId -eq [int]$Record.processId) {
                $matchingProcesses.Add($process)
                continue
            }
            $base.state = 'process_identity_unverified'
            $base.warning = 'This diagnostic profile may retain browser-managed cookies and history. Mihari could not identify every Edge profile, so cleanup is unavailable.'
            return $base
        }
        $matchesProfile = $false
        try {
            $matchesProfile = [string]::Equals(
                [System.IO.Path]::GetFullPath($argumentPath).TrimEnd([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar),
                [System.IO.Path]::GetFullPath($profilePath).TrimEnd([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar),
                [StringComparison]::OrdinalIgnoreCase)
        }
        catch { $matchesProfile = $false }
        if (-not $matchesProfile) { continue }
        if (-not [string]::Equals([string]$process.ExecutablePath, $expectedExecutable, [StringComparison]::OrdinalIgnoreCase) -or
            [string]::IsNullOrWhiteSpace([string]$process.ExecutablePath)) {
            $base.state = 'process_identity_unverified'
            $base.warning = 'This diagnostic profile may retain browser-managed cookies and history. An unverified process refers to its profile, so cleanup is unavailable.'
            return $base
        }
        $matchingProcesses.Add($process)
    }
    if ($matchingProcesses.Count -gt 0) {
        $base.state = 'edge_running'
        $base.warning = 'The diagnostic Edge profile may retain browser-managed cookies and history. Close every Edge process using this profile before cleanup; Mihari will not close browser processes.'
        return $base
    }
    $base.state = 'ready'
    $base.cleanupAvailable = $true
    $base.warning = 'Diagnostic Edge is closed. This retained profile may contain browser-managed cookies and history, which Mihari does not log. Confirm below to remove it.'
    return $base
}

function Get-MihariBrowserProfileStatus {
    param([Parameter(Mandatory = $true)][object] $SessionMetadata)

    $profiles = New-Object 'System.Collections.Generic.List[object]'
    foreach ($record in @(Get-MihariBrowserProfileRecords -SessionMetadata $SessionMetadata)) {
        $state = Get-MihariBrowserProfileState -SessionMetadata $SessionMetadata -Record $record
        if ($state.retained) { $profiles.Add($state) }
    }
    return [pscustomobject][ordered]@{ profiles = @($profiles.ToArray()) }
}

function Invoke-MihariBrowserProfileCleanup {
    param(
        [Parameter(Mandatory = $true)][object] $SessionMetadata,
        [Parameter(Mandatory = $true)][string] $ProfileOwnershipId
    )

    if ($ProfileOwnershipId -notmatch '^[0-9a-fA-F]{32}$') {
        return [pscustomobject]@{ success = $false; errorCode = 'invalid_profile_id'; message = 'The diagnostic profile ID is invalid.' }
    }
    $recordPath = Get-MihariBrowserProfileRecordPath -OutputDirectory ([string](Get-MihariBrowserMetadataValue -Metadata $SessionMetadata -Name 'outputDirectory')) -ProfileOwnershipId $ProfileOwnershipId
    $record = $null
    foreach ($candidate in @(Get-MihariBrowserProfileRecords -SessionMetadata $SessionMetadata)) {
        if ([string]::Equals([string]$candidate.profileOwnershipId, $ProfileOwnershipId, [StringComparison]::OrdinalIgnoreCase)) { $record = $candidate; break }
    }
    if ($null -eq $record) {
        return [pscustomobject]@{ success = $false; errorCode = 'profile_not_owned'; message = 'Mihari has no verified ownership record for this profile.' }
    }
    $state = Get-MihariBrowserProfileState -SessionMetadata $SessionMetadata -Record $record
    if (-not $state.cleanupAvailable) {
        return [pscustomobject]@{ success = $false; errorCode = 'profile_cleanup_unavailable'; message = [string]$state.warning; profile = $state }
    }
    # Recheck process and ownership immediately before deleting. The action never closes or terminates Edge.
    $state = Get-MihariBrowserProfileState -SessionMetadata $SessionMetadata -Record $record
    if (-not $state.cleanupAvailable) {
        return [pscustomobject]@{ success = $false; errorCode = 'profile_cleanup_unavailable'; message = [string]$state.warning; profile = $state }
    }
    try {
        if (-not (Get-Command Remove-MihariOwnedBrowserProfile -CommandType Function -ErrorAction SilentlyContinue)) {
            return [pscustomobject]@{ success = $false; errorCode = 'profile_cleanup_unavailable'; message = 'The canonical Mihari profile removal function is unavailable.' }
        }
        $removal = Remove-MihariOwnedBrowserProfile -SessionId ([string]$record.sessionId) -ProfilePath ([string]$record.profilePath)
        if (-not $removal.removed) {
            return [pscustomobject]@{ success = $false; errorCode = 'profile_cleanup_unavailable'; message = ('Mihari could not verify safe profile removal ({0}).' -f [string]$removal.reason) }
        }
        if ([System.IO.Directory]::Exists([string]$record.profilePath)) { throw 'The diagnostic profile directory remains after deletion.' }
        $record.cleanupState = 'cleaned'
        $record.cleanupUtc = [DateTime]::UtcNow.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
        [System.IO.File]::WriteAllText($recordPath, (ConvertTo-Json -InputObject $record -Depth 4), [System.Text.UTF8Encoding]::new($false))
        return [pscustomobject]@{ success = $true; errorCode = $null; message = 'The verified diagnostic Edge profile was deleted.'; profileOwnershipId = $ProfileOwnershipId; state = 'cleaned' }
    }
    catch {
        $errorType = $_.Exception.GetType().FullName
        return [pscustomobject]@{ success = $false; errorCode = 'profile_cleanup_failed'; message = ('Mihari could not remove the verified diagnostic profile ({0}).' -f $errorType) }
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
        profileOwnershipId = $Result.ProfileOwnershipId
        profileOwnershipWarning = $Result.ProfileOwnershipWarning
        ownerStartTimeUtc = $Result.OwnerStartTimeUtc
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
        # Delay the requested navigation until the owned DevTools observer has
        # enabled Network/Page capture. Keep the raw URL only in this call.
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
        if ($null -ne $ownerStartTimeUtc) {
            [void](Set-MihariBrowserProfileOwnership -SessionMetadata $SessionMetadata -Result $result)
        }
        if ($null -ne $ownerStartTimeUtc -and
            $null -ne $observerCommand) {
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
            if ($liveObserverAvailable -and -not [string]::IsNullOrWhiteSpace($Url)) {
                $result.Success = $false
                $result.ObservationStatus = 'unavailable'
                $result.Reason = 'Edge started on about:blank, but Mihari could not verify its owned process identity. The requested URL was not opened.'
            }
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
