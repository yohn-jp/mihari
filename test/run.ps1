param()

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

    if ($env:OS -ne 'Windows_NT') {
        Write-Warning 'Windows certificate/runtime integration tests require Windows; static parse check completed.'
    }
    else {
        & (Join-Path $PSScriptRoot 'certificate.ps1')
    }
}
catch {
    $exitCode = 1
    Write-Error -ErrorRecord $_
}
finally {
    if ($transcriptPath) {
        Stop-Transcript | Out-Null
    }
}
exit $exitCode
