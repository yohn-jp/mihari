$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path $PSScriptRoot -Parent
. (Join-Path $repoRoot 'src/Browser.ps1')
. (Join-Path $repoRoot 'src/BrowserObservation.ps1')
. (Join-Path $repoRoot 'src/Management.ps1')
. (Join-Path $repoRoot 'src/ManagementUi.ps1')

function Assert-MihariBrowserProfileTest {
    param([bool] $Condition, [string] $Message)
    if (-not $Condition) { throw ('ASSERTION FAILED: ' + $Message) }
}

function New-MihariBrowserProfileRequest {
    param(
        [Parameter(Mandatory = $true)][string] $Method,
        [Parameter(Mandatory = $true)][string] $Path,
        [AllowNull()][object] $Body,
        [string] $Token,
        [string] $Origin = 'http://127.0.0.1:49123',
        [string] $HostHeader = '127.0.0.1:49123'
    )
    $headers = @{}
    $headers['host'] = $HostHeader
    if ($null -ne $Origin) { $headers['origin'] = $Origin }
    if ($null -ne $Token) { $headers['x-mihari-control-token'] = $Token }
    $headers['content-type'] = 'application/json; charset=utf-8'
    $bytes = [byte[]]@()
    if ($null -ne $Body) {
        $json = ConvertTo-Json -InputObject $Body -Depth 6 -Compress
        $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes($json)
    }
    return [pscustomobject]@{ Method = $Method; Path = $Path; Query = ''; Headers = $headers; Body = $bytes }
}

function Invoke-MihariBrowserProfileTestRoute {
    param([Parameter(Mandatory = $true)]$Session, [Parameter(Mandatory = $true)]$Request)
    $response = Invoke-MihariManagementApiRequest -Session $Session -Request $Request
    $json = [System.Text.UTF8Encoding]::new($false).GetString([byte[]]$response.Body)
    return [pscustomobject]@{ StatusCode = [int]$response.StatusCode; Value = (ConvertFrom-Json -InputObject $json -ErrorAction Stop) }
}

$temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('mihari-browser-profile-test-' + [Guid]::NewGuid().ToString('N'))
$outputDirectory = Join-Path $temporaryRoot 'session'
[void][System.IO.Directory]::CreateDirectory($outputDirectory)
$script:profileProcessInventory = @()
Set-Item -Path Function:\Get-MihariBrowserProcesses -Value {
    return @($script:profileProcessInventory)
}
function Get-CimInstance {
    [CmdletBinding()]
    param([string]$ClassName, [string]$Filter)
    if ($ClassName -ne 'Win32_Process') { throw 'Unexpected process inventory query in profile cleanup test.' }
    return @($script:profileProcessInventory)
}

$sessionId = 'profile-test-' + [Guid]::NewGuid().ToString('N')
$session = [pscustomobject]@{
    Id = $sessionId
    OutputDirectory = $outputDirectory
    ActualManagementPort = 49123
    ControlToken = 'profile-cleanup-control-token'
}
$safeSessionId = [System.Text.RegularExpressions.Regex]::Replace($sessionId, '[^A-Za-z0-9_-]', '_')
$profileRoot = Join-Path ([System.IO.Path]::GetTempPath()) 'Mihari'
$profilePath = Join-Path $profileRoot ('Edge-{0}-{1}' -f $safeSessionId, [Guid]::NewGuid().ToString('N'))
$unrelatedPath = Join-Path $profileRoot ('Edge-unrelated-{0}' -f [Guid]::NewGuid().ToString('N'))
$overflowProfilePath = Join-Path $profileRoot ('Edge-{0}-{1}' -f $safeSessionId, [Guid]::NewGuid().ToString('N'))
$executablePath = Join-Path $temporaryRoot 'msedge.exe'
$ownershipId = $null
$cleanupFailure = $null

try {
    [void][System.IO.Directory]::CreateDirectory($profilePath)
    [void][System.IO.Directory]::CreateDirectory($unrelatedPath)
    [System.IO.File]::WriteAllText((Join-Path $profilePath 'History'), 'retained fixture data')
    [System.IO.File]::WriteAllText((Join-Path $unrelatedPath 'History'), 'unrelated profile data')
    $launch = [pscustomobject]@{
        Success = $true
        Pid = 765432
        Path = $executablePath
        ProfilePath = $profilePath
        OwnerStartTimeUtc = '2026-09-01T01:02:03.0000000Z'
        ProfileOwnershipId = $null
    }
    Assert-MihariBrowserProfileTest (Set-MihariBrowserProfileOwnership -SessionMetadata $session -Result $launch) 'A fresh Mihari profile with a verified launch identity receives an ownership record and marker.'
    $ownershipId = [string]$launch.ProfileOwnershipId
    Assert-MihariBrowserProfileTest ($ownershipId -match '^[0-9a-f]{32}$') 'The ownership ID is a generated fixed-format value.'
    $profileRecord = (Get-MihariBrowserProfileRecords -SessionMetadata $session)[0]
    $parsedOwnerTime = (ConvertFrom-Json -InputObject ('{"ownerStartTimeUtc":"' + $launch.OwnerStartTimeUtc + '"}')).ownerStartTimeUtc
    $equivalentOffsetTime = [DateTimeOffset]::Parse([string]$launch.OwnerStartTimeUtc, [Globalization.CultureInfo]::InvariantCulture).ToOffset([TimeSpan]::FromHours(1)).ToString('o', [Globalization.CultureInfo]::InvariantCulture)
    $oneTickLater = [DateTimeOffset]::Parse([string]$launch.OwnerStartTimeUtc, [Globalization.CultureInfo]::InvariantCulture).UtcDateTime.AddTicks(1).ToString('o', [Globalization.CultureInfo]::InvariantCulture)
    Assert-MihariBrowserProfileTest ((Test-MihariBrowserUtcIdentityEqual -Left $parsedOwnerTime -Right $launch.OwnerStartTimeUtc) -and
        (Test-MihariBrowserUtcIdentityEqual -Left $equivalentOffsetTime -Right $launch.OwnerStartTimeUtc) -and
        -not (Test-MihariBrowserUtcIdentityEqual -Left $oneTickLater -Right $launch.OwnerStartTimeUtc) -and
        -not (Test-MihariBrowserUtcIdentityEqual -Left '2026-09-01T01:02:03.0000000' -Right $launch.OwnerStartTimeUtc)) 'UTC ownership identity accepts equivalent explicit offsets and rejects drift or timestamps without a zone.'
    $profileMarkerPath = Get-MihariBrowserProfileMarkerPath -ProfilePath $profilePath
    Assert-MihariBrowserProfileTest ([System.IO.File]::Exists($profileMarkerPath) -and
        (Test-MihariBrowserProfileMarker -Record $profileRecord -SessionId $sessionId)) 'The canonical BrowserObservation ownership marker must match the persisted profile identity.'
    $profileMarker = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($profileMarkerPath, [System.Text.Encoding]::UTF8))
    $profileMarker.processStartTimeUtc = $equivalentOffsetTime
    [System.IO.File]::WriteAllText($profileMarkerPath, (ConvertTo-Json -InputObject $profileMarker -Compress), [System.Text.UTF8Encoding]::new($false))
    Assert-MihariBrowserProfileTest (Test-MihariBrowserProfileMarker -Record $profileRecord -SessionId $sessionId) 'The persisted profile marker must compare equivalent UTC offsets across ConvertFrom-Json runtimes.'
    $profileMarker.processStartTimeUtc = $oneTickLater
    [System.IO.File]::WriteAllText($profileMarkerPath, (ConvertTo-Json -InputObject $profileMarker -Compress), [System.Text.UTF8Encoding]::new($false))
    Assert-MihariBrowserProfileTest (-not (Test-MihariBrowserProfileMarker -Record $profileRecord -SessionId $sessionId)) 'The persisted profile marker must reject a one-tick start-time identity drift.'
    $profileMarker.processStartTimeUtc = $launch.OwnerStartTimeUtc
    [System.IO.File]::WriteAllText($profileMarkerPath, (ConvertTo-Json -InputObject $profileMarker -Compress), [System.Text.UTF8Encoding]::new($false))
    $restoredProfileRecord = (Get-MihariBrowserProfileRecords -SessionMetadata $session -ProfileOwnershipId $ownershipId)[0]
    Assert-MihariBrowserProfileTest (Test-MihariBrowserProfileMarker -Record $restoredProfileRecord -SessionId $sessionId) 'The restored marker must still match the persisted record before cleanup.'

    $unrelatedProfileProcess = [pscustomobject]@{
        ProcessId = 1234
        ExecutablePath = $executablePath
        CommandLine = ('"{0}" --user-data-dir="{1}"' -f $executablePath, $unrelatedPath)
    }
    $script:profileProcessInventory = @($unrelatedProfileProcess)
    $status = Get-MihariBrowserProfileStatus -SessionMetadata $session
    Assert-MihariBrowserProfileTest ($status.profiles.Count -eq 1 -and $status.profiles[0].state -eq 'ready' -and $status.profiles[0].cleanupAvailable) 'An unrelated Edge profile does not block cleanup of the exact owned profile.'

    $ownedProfileProcess = [pscustomobject]@{
        ProcessId = [int]$launch.Pid
        ExecutablePath = $executablePath
        CommandLine = ('"{0}" --user-data-dir="{1}"' -f $executablePath, $profilePath)
    }
    $script:profileProcessInventory = @($unrelatedProfileProcess, $ownedProfileProcess)
    $runningStatus = Get-MihariBrowserProfileStatus -SessionMetadata $session
    Assert-MihariBrowserProfileTest ($runningStatus.profiles[0].state -eq 'edge_running' -and -not $runningStatus.profiles[0].cleanupAvailable) 'Cleanup remains unavailable while an Edge process uses the owned profile.'
    $runningCleanup = Invoke-MihariBrowserProfileTestRoute -Session $session -Request (New-MihariBrowserProfileRequest -Method POST -Path '/api/browser/cleanup' -Token $session.ControlToken -Body ([pscustomobject]@{ profileOwnershipId = $ownershipId; confirmCleanup = $true }))
    Assert-MihariBrowserProfileTest ($runningCleanup.StatusCode -eq 409 -and [System.IO.Directory]::Exists($profilePath)) 'The protected cleanup route refuses a live profile and preserves its files.'

    $script:profileProcessInventory = @($unrelatedProfileProcess)
    $missingToken = Invoke-MihariBrowserProfileTestRoute -Session $session -Request (New-MihariBrowserProfileRequest -Method POST -Path '/api/browser/cleanup' -Body ([pscustomobject]@{ profileOwnershipId = $ownershipId; confirmCleanup = $true }))
    Assert-MihariBrowserProfileTest ($missingToken.StatusCode -eq 403 -and [System.IO.Directory]::Exists($profilePath)) 'Cleanup requires the existing session control token.'
    $wrongOrigin = Invoke-MihariBrowserProfileTestRoute -Session $session -Request (New-MihariBrowserProfileRequest -Method POST -Path '/api/browser/cleanup' -Token $session.ControlToken -Origin 'http://127.0.0.1:49124' -Body ([pscustomobject]@{ profileOwnershipId = $ownershipId; confirmCleanup = $true }))
    Assert-MihariBrowserProfileTest ($wrongOrigin.StatusCode -eq 403 -and [System.IO.Directory]::Exists($profilePath)) 'Cleanup rejects a mismatched loopback Origin.'
    $noConfirmation = Invoke-MihariBrowserProfileTestRoute -Session $session -Request (New-MihariBrowserProfileRequest -Method POST -Path '/api/browser/cleanup' -Token $session.ControlToken -Body ([pscustomobject]@{ profileOwnershipId = $ownershipId; confirmCleanup = $false }))
    Assert-MihariBrowserProfileTest ($noConfirmation.StatusCode -eq 400 -and [System.IO.Directory]::Exists($profilePath)) 'Cleanup requires explicit operator confirmation in the request body.'

    Set-Item -Path Function:\Get-MihariBrowserProcesses -Value { throw 'fixture inventory unavailable' }
    $unknownStatus = Get-MihariBrowserProfileStatus -SessionMetadata $session
    Assert-MihariBrowserProfileTest ($unknownStatus.profiles[0].state -eq 'process_state_unavailable' -and -not $unknownStatus.profiles[0].cleanupAvailable) 'Unknown Edge process state fails closed.'

    Set-Item -Path Function:\Get-MihariBrowserProcesses -Value { return @($script:profileProcessInventory) }
    $getStatus = Invoke-MihariBrowserProfileTestRoute -Session $session -Request (New-MihariBrowserProfileRequest -Method GET -Path '/api/browser' -Token $null)
    Assert-MihariBrowserProfileTest ($getStatus.StatusCode -eq 200 -and $getStatus.Value.profiles.Count -eq 1 -and $getStatus.Value.profiles[0].cleanupAvailable) 'GET /api/browser exposes live verified profile state for the UI.'
    Set-Item -Path Function:\Get-MihariBrowserProcesses -Value { throw 'fixture inventory unavailable' }
    $unavailableCleanup = Invoke-MihariBrowserProfileTestRoute -Session $session -Request (New-MihariBrowserProfileRequest -Method POST -Path '/api/browser/cleanup' -Token $session.ControlToken -Body ([pscustomobject]@{ profileOwnershipId = $ownershipId; confirmCleanup = $true }))
    Assert-MihariBrowserProfileTest ($unavailableCleanup.StatusCode -eq 409 -and $unavailableCleanup.Value.errorCode -eq 'profile_cleanup_unavailable' -and
        $unavailableCleanup.Value.profile.state -eq 'process_state_unavailable' -and [System.IO.Directory]::Exists($profilePath)) 'Cleanup must fail closed and preserve the profile if the shared Edge process inventory is unavailable.'
    Set-Item -Path Function:\Get-MihariBrowserProcesses -Value { return @($script:profileProcessInventory) }
    $cleaned = Invoke-MihariBrowserProfileTestRoute -Session $session -Request (New-MihariBrowserProfileRequest -Method POST -Path '/api/browser/cleanup' -Token $session.ControlToken -Body ([pscustomobject]@{ profileOwnershipId = $ownershipId; confirmCleanup = $true }))
    $cleanupCode = [string]$cleaned.Value.errorCode
    if ($cleanupCode -notin @('invalid_profile_id', 'profile_not_owned', 'profile_cleanup_unavailable', 'profile_cleanup_failed')) { $cleanupCode = 'none_or_unknown' }
    $cleanupState = [string]$cleaned.Value.state
    if ([string]::IsNullOrWhiteSpace($cleanupState) -and $null -ne $cleaned.Value.profile) { $cleanupState = [string]$cleaned.Value.profile.state }
    if ($cleanupState -notin @('cleaned', 'unverified', 'not_found', 'ready', 'edge_running', 'process_state_unavailable', 'process_identity_unverified')) { $cleanupState = 'none_or_unknown' }
    $cleanupDetail = 'none'
    $cleanupMessage = [string]$cleaned.Value.message
    if ($cleanupMessage -match 'safe profile removal \(([^)]+)\)\.') {
        if ($Matches[1] -in @('profile_path_not_owned', 'profile_not_found', 'profile_path_reparse_point', 'ownership_marker_missing', 'ownership_marker_invalid', 'ownership_marker_mismatch', 'ownership_marker_unreadable', 'browser_process_ownership_unavailable', 'browser_process_ownership_unverified', 'profile_in_use')) {
            $cleanupDetail = [string]$Matches[1]
        }
        else { $cleanupDetail = 'other_fixed_removal_reason' }
    }
    $cleanupDiagnostic = 'status={0};errorCode={1};state={2};detail={3}' -f [int]$cleaned.StatusCode, $cleanupCode, $cleanupState, $cleanupDetail
    Assert-MihariBrowserProfileTest ($cleaned.StatusCode -eq 200 -and $cleaned.Value.success -and $cleaned.Value.state -eq 'cleaned') ('Confirmed cleanup removes the exact closed Mihari profile (' + $cleanupDiagnostic + ').')
    Assert-MihariBrowserProfileTest (-not [System.IO.Directory]::Exists($profilePath) -and [System.IO.Directory]::Exists($unrelatedPath)) 'Cleanup deletes only the selected Mihari profile and preserves unrelated profile data.'

    for ($index = 0; $index -lt 40; $index++) {
        $inventoryId = $index.ToString('x32')
        $inventoryProfilePath = Join-Path $profileRoot ('Edge-{0}-{1}' -f $safeSessionId, $inventoryId)
        $inventoryRecord = [pscustomobject][ordered]@{
            schemaVersion = 1
            sessionId = $sessionId
            profileOwnershipId = $inventoryId
            profilePath = $inventoryProfilePath
            executablePath = $executablePath
            processId = (900000 + $index)
            ownerStartTimeUtc = [DateTime]::UtcNow.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
            createdUtc = [DateTime]::UtcNow.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
            cleanupState = 'retained'
            cleanupUtc = $null
        }
        $inventoryPath = Get-MihariBrowserProfileRecordPath -OutputDirectory $outputDirectory -ProfileOwnershipId $inventoryId
        [System.IO.File]::WriteAllText($inventoryPath, (ConvertTo-Json -InputObject $inventoryRecord -Depth 4), [System.Text.UTF8Encoding]::new($false))
    }
    [void][System.IO.Directory]::CreateDirectory($overflowProfilePath)
    $overflowLaunch = [pscustomobject]@{
        Success = $true
        Pid = 765433
        Path = $executablePath
        ProfilePath = $overflowProfilePath
        OwnerStartTimeUtc = [DateTime]::UtcNow.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
        ProfileOwnershipId = $null
    }
    Assert-MihariBrowserProfileTest (Set-MihariBrowserProfileOwnership -SessionMetadata $session -Result $overflowLaunch) 'A selected profile can have its exact ownership record resolved even when the status inventory is bounded.'
    $overflowOwnershipId = [string]$overflowLaunch.ProfileOwnershipId
    $oversizedId = 'e' * 32
    $oversizedPath = Get-MihariBrowserProfileRecordPath -OutputDirectory $outputDirectory -ProfileOwnershipId $oversizedId
    $oversizedBytes = New-Object byte[] 16385
    [System.IO.File]::WriteAllBytes($oversizedPath, $oversizedBytes)
    $oversizedInventory = Get-MihariBrowserProfileRecords -SessionMetadata $session -ProfileOwnershipId $oversizedId -IncludeCoverage
    Assert-MihariBrowserProfileTest ($oversizedInventory.partial -and $oversizedInventory.records.Count -eq 0) 'Oversized profile metadata is not read or trusted.'
    $boundedStatus = Get-MihariBrowserProfileStatus -SessionMetadata $session
    Assert-MihariBrowserProfileTest ($boundedStatus.truncated -and $boundedStatus.recordsScanned -eq $boundedStatus.recordLimit -and
        [string]$boundedStatus.warning -match 'reached its safety limit') 'The browser API must report a persistent warning when profile inventory reaches its safety limit.'
    $overflowCleanup = Invoke-MihariBrowserProfileTestRoute -Session $session -Request (New-MihariBrowserProfileRequest -Method POST -Path '/api/browser/cleanup' -Token $session.ControlToken -Body ([pscustomobject]@{ profileOwnershipId = $overflowOwnershipId; confirmCleanup = $true }))
    Assert-MihariBrowserProfileTest ($overflowCleanup.StatusCode -eq 200 -and $overflowCleanup.Value.success -and
        -not [System.IO.Directory]::Exists($overflowProfilePath)) 'Exact-ID cleanup remains available after the status page reports a truncated profile inventory.'
    $html = Get-MihariManagementUiHtml -ControlToken $session.ControlToken
    Assert-MihariBrowserProfileTest ($html.Contains('data-profile-inventory-warning')) 'The connected browser UI must display profile inventory coverage warnings.'
    Write-Host 'PASS browser-profile-cleanup: exact ownership marker, process state, protected API, explicit confirmation, and selected-profile-only deletion'
}
finally {
    if ([System.IO.Directory]::Exists($profilePath)) {
        try { [System.IO.Directory]::Delete($profilePath, $true) }
        catch { $cleanupFailure = $_; Write-Warning ('Owned browser profile fixture cleanup failed: ' + $_.Exception.Message) }
    }
    if ([System.IO.Directory]::Exists($unrelatedPath)) {
        try { [System.IO.Directory]::Delete($unrelatedPath, $true) }
        catch { $cleanupFailure = $_; Write-Warning ('Unrelated browser profile fixture cleanup failed: ' + $_.Exception.Message) }
    }
    if ([System.IO.Directory]::Exists($overflowProfilePath)) {
        try { [System.IO.Directory]::Delete($overflowProfilePath, $true) }
        catch { $cleanupFailure = $_; Write-Warning ('Overflow browser profile fixture cleanup failed: ' + $_.Exception.Message) }
    }
    if ([System.IO.Directory]::Exists($profileRoot)) {
        $remaining = @(Get-ChildItem -LiteralPath $profileRoot -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -in @([System.IO.Path]::GetFileName($profilePath), [System.IO.Path]::GetFileName($unrelatedPath), [System.IO.Path]::GetFileName($overflowProfilePath)) })
        if ($remaining.Count -gt 0) { $cleanupFailure = [System.InvalidOperationException]::new('A browser profile test directory remains.') }
    }
    if ([System.IO.Directory]::Exists($temporaryRoot)) {
        try { [System.IO.Directory]::Delete($temporaryRoot, $true) }
        catch { $cleanupFailure = $_; Write-Warning ('Browser profile test output cleanup failed: ' + $_.Exception.Message) }
    }
}
if ($null -ne $cleanupFailure) { throw $cleanupFailure }
