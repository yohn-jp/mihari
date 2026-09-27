param()

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'TestSupport.ps1')
if ($env:OS -ne 'Windows_NT') {
    Write-Warning 'Certificate-store cleanup tests require Windows; skipped on this platform.'
    return
}

$sourceRoot = Join-Path (Split-Path $PSScriptRoot -Parent) 'src'
. (Join-Path $sourceRoot 'Certificate.ps1')
. (Join-Path $sourceRoot 'Session.ps1')
. (Join-Path $sourceRoot 'Cleanup.ps1')

$outputRoot = Join-Path ([IO.Path]::GetTempPath()) ('mihari-cleanup-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($outputRoot)
$owned = $null
$unmatched = $null
$ownedInstalled = $false
$unmatchedInstalled = $false
$cleanupFailures = New-Object 'System.Collections.Generic.List[string]'
try {
    $ownedId = [guid]::NewGuid().ToString('N')
    $owned = New-MihariCA -SessionId $ownedId
    $ownedPublic = Install-MihariCARoot -CA $owned
    $ownedInstalled = $true
    $ownedPublic.Dispose()

    $unmatchedId = [guid]::NewGuid().ToString('N')
    $unmatched = New-MihariCA -SessionId $unmatchedId
    $unmatchedPublic = Install-MihariCARoot -CA $unmatched
    $unmatchedInstalled = $true
    $unmatchedPublic.Dispose()

    $ownedDirectory = Join-Path $outputRoot $ownedId
    [void][IO.Directory]::CreateDirectory($ownedDirectory)
    $metadata = [ordered]@{
        schemaVersion = 1
        sessionId = $ownedId
        outputDirectory = [IO.Path]::GetFullPath($ownedDirectory)
        caSubject = $owned.Subject
        caThumbprint = $owned.Thumbprint
        processId = -1
        processStartTimeUtc = ''
        status = 'running'
    }
    Write-MihariJsonFileAtomic -Path (Join-Path $ownedDirectory 'session.json') -Value $metadata

    $firstCleanup = Invoke-MihariCleanup -OutputRoot $outputRoot
    Assert-MihariTest -Condition ($firstCleanup.removedCount -eq 1) -Message 'Cleanup must remove one positively identified stale Mihari CA.'
    Assert-MihariTest -Condition (@($firstCleanup.removed | Where-Object { $_.thumbprint -eq $owned.Thumbprint }).Count -eq 1) -Message 'Cleanup must report the exact CA removed from trust.'
    Assert-MihariTest -Condition (@($firstCleanup.refused | Where-Object { $_.thumbprint -eq $unmatched.Thumbprint }).Count -eq 1) -Message 'Cleanup must refuse a Mihari-marked root with no matching session metadata.'
    Assert-MihariTest -Condition (Test-MihariTestThumbprintAbsent -Thumbprint $owned.Thumbprint) -Message 'The positively identified stale root must be absent after cleanup.'
    Assert-MihariTest -Condition (-not (Test-MihariTestThumbprintAbsent -Thumbprint $unmatched.Thumbprint)) -Message 'The unmatched Mihari-marked root must remain untouched.'

    $savedMetadata = ConvertFrom-Json -InputObject ([IO.File]::ReadAllText((Join-Path $ownedDirectory 'session.json'))) -ErrorAction Stop
    Assert-MihariTest -Condition ($savedMetadata.status -eq 'orphaned_cleaned') -Message 'Cleanup must record stale cleanup in session metadata.'
    $secondCleanup = Invoke-MihariCleanup -OutputRoot $outputRoot
    Assert-MihariTest -Condition ($secondCleanup.removedCount -eq 0) -Message 'Cleanup must be idempotent.'
    Assert-MihariTest -Condition (-not (Test-MihariTestThumbprintAbsent -Thumbprint $unmatched.Thumbprint)) -Message 'Repeated cleanup must continue to preserve unmatched trust.'
    Write-Host 'PASS stale cleanup: exact metadata ownership required, unowned roots preserved, removal idempotent'
}
finally {
    if ($ownedInstalled -and $null -ne $owned) {
        try { [void](Remove-MihariCARoot -Thumbprint $owned.Thumbprint -Subject $owned.Subject) }
        catch { $cleanupFailures.Add("owned test root removal: $($_.Exception.Message)") }
    }
    if ($unmatchedInstalled -and $null -ne $unmatched) {
        try { [void](Remove-MihariCARoot -Thumbprint $unmatched.Thumbprint -Subject $unmatched.Subject) }
        catch { $cleanupFailures.Add("unmatched test root removal: $($_.Exception.Message)") }
    }
    if ($null -ne $owned) {
        try { $owned.Certificate.Dispose(); $owned.PrivateKey.Dispose() }
        catch { $cleanupFailures.Add("owned test key disposal: $($_.Exception.Message)") }
    }
    if ($null -ne $unmatched) {
        try { $unmatched.Certificate.Dispose(); $unmatched.PrivateKey.Dispose() }
        catch { $cleanupFailures.Add("unmatched test key disposal: $($_.Exception.Message)") }
    }
    try { Remove-Item -LiteralPath $outputRoot -Recurse -Force -ErrorAction Stop }
    catch { $cleanupFailures.Add("temporary cleanup metadata removal: $($_.Exception.Message)") }
    if ($null -ne $owned -and -not (Test-MihariTestThumbprintAbsent -Thumbprint $owned.Thumbprint)) {
        $cleanupFailures.Add('owned test root remained installed')
    }
    if ($null -ne $unmatched -and -not (Test-MihariTestThumbprintAbsent -Thumbprint $unmatched.Thumbprint)) {
        $cleanupFailures.Add('unmatched test root remained installed after explicit test cleanup')
    }
    if ($cleanupFailures.Count -gt 0) { throw ('Stale cleanup test cleanup failed: ' + ($cleanupFailures -join '; ')) }
}
