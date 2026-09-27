param(
    [ValidateSet('all', 'certificate', 'contracts', 'findings-comparison', 'finding-projection', 'traffic-projection', 'browser', 'browser-profile-cleanup', 'browser-observation', 'stale-cleanup', 'runtime-basic', 'integration', 'issue3-management', 'issue3-edge-smoke', 'issue3-ui-browser', 'issue3-connection', 'upstream-self-reference', 'phase2-transport', 'phase2-evidence', 'phase2-workbench')]
    [string] $Suite = 'all'
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path $PSScriptRoot -Parent
$artifactDirectory = $env:MIHARI_TEST_ARTIFACT_DIR
$transcriptPath = $null
if ($artifactDirectory) {
    if (-not (Test-Path -LiteralPath $artifactDirectory)) {
        New-Item -ItemType Directory -Path $artifactDirectory -Force | Out-Null
    }
    $transcriptPath = Join-Path $artifactDirectory ("mihari-tests-{0}.log" -f ([guid]::NewGuid().ToString('N')))
    Start-Transcript -Path $transcriptPath -Force | Out-Null
}

$exitCode = 0
try {
    Write-Host ("Mihari tests on {0}, PowerShell {1}" -f $env:COMPUTERNAME, $PSVersionTable.PSVersion)
    $sourceFiles = @(
        Get-ChildItem -LiteralPath (Join-Path $repoRoot 'src') -Filter '*.ps1' -File -Recurse -ErrorAction SilentlyContinue
        Get-ChildItem -LiteralPath $repoRoot -Filter '*.ps1' -File -ErrorAction SilentlyContinue
        Get-ChildItem -LiteralPath $PSScriptRoot -Filter '*.ps1' -File -Recurse
    ) | Sort-Object -Unique -Property FullName
    foreach ($file in $sourceFiles) {
        $tokens = $null
        $parseErrors = $null
        [void] [System.Management.Automation.Language.Parser]::ParseFile(
            $file.FullName,
            [ref] $tokens,
            [ref] $parseErrors
        )
        if ($parseErrors.Count -gt 0) {
            $details = ($parseErrors | ForEach-Object { '{0}:{1}: {2}' -f $_.Extent.StartLineNumber, $_.Extent.StartColumnNumber, $_.Message }) -join [Environment]::NewLine
            throw ("PowerShell parse errors in {0}:{1}{2}" -f $file.FullName, [Environment]::NewLine, $details)
        }
    }
    Write-Host ("PASS parse: {0} PowerShell files" -f $sourceFiles.Count)

    if ($Suite -eq 'all') {
        $selectedSuites = @('certificate', 'contracts', 'findings-comparison', 'finding-projection', 'traffic-projection', 'browser', 'browser-observation', 'stale-cleanup', 'runtime-basic', 'integration', 'issue3-management', 'issue3-edge-smoke', 'issue3-ui-browser', 'issue3-connection', 'upstream-self-reference', 'phase2-transport', 'phase2-evidence', 'phase2-workbench')
    }
    else {
        $selectedSuites = @($Suite)
    }
    foreach ($selectedSuite in $selectedSuites) {
        if ($env:OS -ne 'Windows_NT' -and $selectedSuite -in @('certificate', 'browser-profile-cleanup', 'stale-cleanup', 'runtime-basic', 'integration', 'issue3-management', 'issue3-edge-smoke', 'issue3-ui-browser', 'phase2-workbench')) {
            Write-Warning ("Skipping suite '{0}': Windows certificate/runtime integration is required." -f $selectedSuite)
            continue
        }
        Write-Host ("RUN suite: {0}" -f $selectedSuite)
        switch ($selectedSuite) {
            'certificate' { & (Join-Path $PSScriptRoot 'certificate.ps1') }
            'contracts' { & (Join-Path $PSScriptRoot 'contracts.ps1') }
            'findings-comparison' { & (Join-Path $PSScriptRoot 'findings-comparison.ps1') }
            'finding-projection' { & (Join-Path $PSScriptRoot 'finding-projection.ps1') }
            'traffic-projection' { & (Join-Path $PSScriptRoot 'traffic-projection.ps1') }
            'browser' { & (Join-Path $PSScriptRoot 'browser.ps1') }
            'browser-profile-cleanup' { & (Join-Path $PSScriptRoot 'browser-profile-cleanup.ps1') }
            'browser-observation' { & (Join-Path $PSScriptRoot 'browser-observation.ps1') }
            'stale-cleanup' { & (Join-Path $PSScriptRoot 'stale-cleanup.ps1') }
            'runtime-basic' { & (Join-Path $PSScriptRoot 'runtime-basic.ps1') }
            'integration' { & (Join-Path $PSScriptRoot 'integration.ps1') }
            'issue3-management' { & (Join-Path $PSScriptRoot 'issue3-management.ps1') }
            'issue3-edge-smoke' { & (Join-Path $PSScriptRoot 'issue3-edge-smoke.ps1') }
            'issue3-ui-browser' { & (Join-Path $PSScriptRoot 'issue3-ui-browser.ps1') }
            'issue3-connection' { & (Join-Path $PSScriptRoot 'issue3-connection.ps1') }
            'upstream-self-reference' { & (Join-Path $PSScriptRoot 'upstream-self-reference.ps1') }
            'phase2-transport' {
                & (Join-Path $PSScriptRoot 'phase2-streaming.ps1')
                & (Join-Path $PSScriptRoot 'phase2-observer-impact.ps1')
                & (Join-Path $PSScriptRoot 'phase2-tls-environment.ps1')
                & (Join-Path $PSScriptRoot 'phase2-inspect-streaming.ps1')
                & (Join-Path $PSScriptRoot 'phase2-live-streaming.ps1')
                & (Join-Path $PSScriptRoot 'management-capture-status.ps1')
            }
            'phase2-evidence' { & (Join-Path $PSScriptRoot 'phase2-evidence.ps1') }
            'phase2-workbench' {
                & (Join-Path $PSScriptRoot 'phase2-hpack.ps1')
                & (Join-Path $PSScriptRoot 'phase2-http2-native.ps1')
                & (Join-Path $PSScriptRoot 'phase2-http2-tls.ps1')
                & (Join-Path $PSScriptRoot 'traffic-projection.ps1')
                & (Join-Path $PSScriptRoot 'findings-comparison.ps1')
                & (Join-Path $PSScriptRoot 'finding-projection.ps1')
                & (Join-Path $PSScriptRoot 'cases-dependencies.ps1')
                & (Join-Path $PSScriptRoot 'phase2-management-cases.ps1')
                & (Join-Path $PSScriptRoot 'phase2-evidence.ps1')
                & (Join-Path $PSScriptRoot 'phase2-management-evidence.ps1')
                & (Join-Path $PSScriptRoot 'browser-observation.ps1')
                & (Join-Path $PSScriptRoot 'browser-profile-cleanup.ps1')
                & (Join-Path $PSScriptRoot 'browser-observation-edge.ps1')
                & (Join-Path $PSScriptRoot 'phase2-ui-browser.ps1')
            }
        }
    }
}
catch {
    $exitCode = 1
    if (-not [string]::IsNullOrWhiteSpace([string]$_.ScriptStackTrace)) {
        Write-Warning ('Test script stack: ' + [string]$_.ScriptStackTrace)
    }
    Write-Error -ErrorRecord $_
}
finally {
    if ($transcriptPath) {
        Stop-Transcript | Out-Null
    }
}
exit $exitCode
