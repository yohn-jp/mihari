param()

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'TestSupport.ps1')
. (Join-Path (Split-Path $PSScriptRoot -Parent) 'src/Browser.ps1')

$temporaryDirectory = Join-Path ([IO.Path]::GetTempPath()) ('mihari-browser-test-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($temporaryDirectory)
$originalDiscovery = (Get-Command Find-MihariEdgeExecutable -CommandType Function).ScriptBlock
try {
    Set-Item -Path Function:\Find-MihariEdgeExecutable -Value { return $null }
    $metadata = [pscustomobject]@{
        id = [guid]::NewGuid().ToString('N')
        actualPort = 32123
        outputDirectory = $temporaryDirectory
    }
    $result = Start-MihariBrowser -SessionMetadata $metadata -Url 'https://example.test/path?token=browser-secret'
    Assert-MihariTest -Condition (-not $result.Success) -Message 'Unavailable Edge discovery must return an explicit unsupported result.'
    Assert-MihariTest -Condition ($result.ProxyEndpoint -eq 'http://127.0.0.1:32123') -Message 'Manual configuration must receive the exact loopback proxy endpoint.'
    Assert-MihariTest -Condition ($result.Reason -match 'Microsoft Edge was not found' -and $result.Reason.Contains($result.ProxyEndpoint)) -Message 'The Edge discovery failure must explain the condition and manual proxy endpoint.'
    $launchPath = Join-Path $temporaryDirectory 'browser-launch.json'
    Assert-MihariTest -Condition ([IO.File]::Exists($launchPath)) -Message 'Browser discovery outcome must be recorded in session metadata.'
    $launchText = [IO.File]::ReadAllText($launchPath)
    Assert-MihariTest -Condition (-not $launchText.Contains('browser-secret')) -Message 'Browser launch metadata must not retain URL query values.'
    $launchMetadata = ConvertFrom-Json -InputObject $launchText -ErrorAction Stop
    Assert-MihariTest -Condition ($launchMetadata.success -eq $false -and $launchMetadata.urlProvided -eq $true -and $launchMetadata.proxyEndpoint -eq $result.ProxyEndpoint) -Message 'Browser metadata must retain only safe launch state.'
    Write-Host 'PASS browser: Edge discovery failure reports a precise manual loopback proxy endpoint without retaining URL secrets'
}
finally {
    Set-Item -Path Function:\Find-MihariEdgeExecutable -Value $originalDiscovery
    Remove-Item -LiteralPath $temporaryDirectory -Recurse -Force -ErrorAction SilentlyContinue
}
