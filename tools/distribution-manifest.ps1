[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidateSet('Create', 'Verify')][string]$Action,
    [Parameter(Mandatory = $true)][string]$RootPath,
    [string]$ManifestPath,
    [string]$ApplicationRevision = 'unknown',
    [string]$CommitId = 'unknown'
)

$ErrorActionPreference = 'Stop'

$repositoryRoot = [System.IO.DirectoryInfo]::new($PSScriptRoot).Parent.FullName
$evidencePath = [System.IO.Path]::Combine($repositoryRoot, 'src', 'Evidence.ps1')
if (-not [System.IO.File]::Exists($evidencePath)) {
    throw 'The canonical Mihari evidence implementation was not found beside this distribution tool.'
}

. $evidencePath

if ([string]::IsNullOrWhiteSpace($ManifestPath)) {
    $ManifestPath = [System.IO.Path]::Combine($RootPath, 'distribution-manifest.json')
}

if ($Action -eq 'Create') {
    New-MihariDistributionManifest `
        -RootPath $RootPath `
        -OutputPath $ManifestPath `
        -ApplicationRevision $ApplicationRevision `
        -CommitId $CommitId
    return
}

$verification = Test-MihariDistributionManifest -RootPath $RootPath -ManifestPath $ManifestPath
if (-not $verification.valid) {
    throw ('Distribution manifest verification failed: ' + ($verification.errors -join ', '))
}

return $verification
