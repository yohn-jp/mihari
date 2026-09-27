param()

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'TestSupport.ps1')
. (Join-Path (Split-Path $PSScriptRoot -Parent) 'src/Browser.ps1')

$temporaryDirectory = Join-Path ([IO.Path]::GetTempPath()) ('mihari-browser-test-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($temporaryDirectory)
$originalDiscovery = (Get-Command Find-MihariEdgeExecutable -CommandType Function).ScriptBlock
$originalStartProcess = (Get-Command Start-MihariEdgeProcess -CommandType Function).ScriptBlock
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

    $script:capturedEdgeStartInfo = $null
    Set-Item -Path Function:\Find-MihariEdgeExecutable -Value { return 'C:\MihariTest\msedge.exe' }
    Set-Item -Path Function:\Start-MihariEdgeProcess -Value {
        param([System.Diagnostics.ProcessStartInfo] $StartInfo)
        $script:capturedEdgeStartInfo = $StartInfo
        return 4242
    }
    $metadataWithReservedPort = [pscustomobject]@{
        id = [guid]::NewGuid().ToString('N')
        actualPort = 44444
        port = 32123
        outputDirectory = $temporaryDirectory
    }
    $launched = Start-MihariBrowser -SessionMetadata $metadataWithReservedPort `
        -Url 'http://127.0.0.1:49999/fixture?token=browser-secret'
    Assert-MihariTest -Condition ($launched.Success -and $launched.Pid -eq 4242) -Message 'Browser launch must report the created Edge process.'
    Assert-MihariTest -Condition ($launched.ProxyEndpoint -eq 'http://127.0.0.1:44444') -Message 'Edge must use the actual proxy listener port when a reserved port differs.'
    Assert-MihariTest -Condition ($script:capturedEdgeStartInfo.FileName -eq 'C:\MihariTest\msedge.exe') -Message 'Browser launch must start the discovered Edge executable.'
    Assert-MihariTest -Condition ($script:capturedEdgeStartInfo.Arguments.Contains('--proxy-server=http://127.0.0.1:44444')) -Message 'Edge must receive the active Mihari proxy for HTTP and HTTPS.'
    Assert-MihariTest -Condition ($script:capturedEdgeStartInfo.Arguments.Contains('--proxy-bypass-list=<-loopback>')) -Message 'Edge must not implicitly bypass Mihari for loopback fixture targets.'
    Assert-MihariTest -Condition ($script:capturedEdgeStartInfo.Arguments.Contains('--disable-quic')) -Message 'Edge must not use unsupported QUIC/HTTP3 transport.'
    Assert-MihariTest -Condition ($script:capturedEdgeStartInfo.Arguments.Contains('--disable-http2')) -Message 'Edge must use the supported HTTP/1.1 protocol baseline.'
    Assert-MihariTest -Condition ($script:capturedEdgeStartInfo.Arguments.Contains('--force-webrtc-ip-handling-policy=disable_non_proxied_udp')) -Message 'Edge must not open an unproxied WebRTC UDP path.'
    Assert-MihariTest -Condition ($script:capturedEdgeStartInfo.Arguments.Contains('--ssl-version-max=tls1.2')) -Message 'Edge must stay within Mihari TLS 1.2 support.'
    Assert-MihariTest -Condition (-not $script:capturedEdgeStartInfo.Arguments.Contains('ignore-certificate-errors') -and -not $script:capturedEdgeStartInfo.Arguments.Contains('ignore-ssl-errors')) -Message 'Edge must retain normal certificate validation.'
    Assert-MihariTest -Condition ($script:capturedEdgeStartInfo.Arguments.Contains('--user-data-dir=') -and $launched.ProfilePath.StartsWith([IO.Path]::GetTempPath(), [StringComparison]::OrdinalIgnoreCase)) -Message 'Edge must use an isolated temporary profile.'
    $launchText = [IO.File]::ReadAllText($launchPath)
    Assert-MihariTest -Condition (-not $launchText.Contains('browser-secret')) -Message 'Successful launch metadata must not retain URL query values.'
    $launchMetadata = ConvertFrom-Json -InputObject $launchText -ErrorAction Stop
    Assert-MihariTest -Condition ($launchMetadata.proxiedSchemes.Count -eq 2 -and $launchMetadata.loopbackBypassDisabled -and $launchMetadata.quicDisabled -and $launchMetadata.http2Disabled -and $launchMetadata.nonProxiedWebRtcUdpDisabled -and $launchMetadata.maximumTlsVersion -eq 'tls1.2') -Message 'Session metadata must report the enforced Edge transport policy.'
    Write-Host 'PASS browser: Edge uses an isolated profile and Mihari proxy, including loopback, while restricting unsupported transports'
}
finally {
    Set-Item -Path Function:\Find-MihariEdgeExecutable -Value $originalDiscovery
    Set-Item -Path Function:\Start-MihariEdgeProcess -Value $originalStartProcess
    Remove-Variable -Name capturedEdgeStartInfo -Scope Script -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $temporaryDirectory -Recurse -Force -ErrorAction SilentlyContinue
}
