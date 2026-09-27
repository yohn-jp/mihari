param()

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'TestSupport.ps1')
. (Join-Path (Split-Path $PSScriptRoot -Parent) 'src/Browser.ps1')

$temporaryDirectory = Join-Path ([IO.Path]::GetTempPath()) ('mihari-browser-test-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($temporaryDirectory)
$originalDiscovery = (Get-Command Find-MihariEdgeExecutable -CommandType Function).ScriptBlock
$originalStartProcess = (Get-Command Start-MihariEdgeProcess -CommandType Function).ScriptBlock
$originalOwnerIdentity = (Get-Command Get-MihariBrowserOwnedProfileIdentity -CommandType Function).ScriptBlock
$originalBrowserObservation = (Get-Command Start-MihariBrowserObservation -CommandType Function).ScriptBlock
$liveProfilePath = $null
$failedProfilePath = $null
$observerFailureProfilePath = $null
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
    Assert-MihariTest -Condition ($script:capturedEdgeStartInfo.Arguments.Contains('--remote-debugging-port=0')) -Message 'Only the unique Mihari-owned diagnostic profile may request an ephemeral local DevTools endpoint.'
    Assert-MihariTest -Condition ($script:capturedEdgeStartInfo.Arguments.Contains('--disable-quic')) -Message 'Edge must not use unsupported QUIC/HTTP3 transport.'
    Assert-MihariTest -Condition ($script:capturedEdgeStartInfo.Arguments.Contains('--disable-http2')) -Message 'Edge must use the supported HTTP/1.1 protocol baseline.'
    Assert-MihariTest -Condition ($script:capturedEdgeStartInfo.Arguments.Contains('--force-webrtc-ip-handling-policy=disable_non_proxied_udp')) -Message 'Edge must not open an unproxied WebRTC UDP path.'
    Assert-MihariTest -Condition ($script:capturedEdgeStartInfo.Arguments.Contains('--ssl-version-max=tls1.2')) -Message 'Edge must stay within Mihari TLS 1.2 support.'
    Assert-MihariTest -Condition (-not $script:capturedEdgeStartInfo.Arguments.Contains('ignore-certificate-errors') -and -not $script:capturedEdgeStartInfo.Arguments.Contains('ignore-ssl-errors')) -Message 'Edge must retain normal certificate validation.'
    Assert-MihariTest -Condition ($script:capturedEdgeStartInfo.Arguments.Contains('--user-data-dir=') -and $launched.ProfilePath.StartsWith([IO.Path]::GetTempPath(), [StringComparison]::OrdinalIgnoreCase)) -Message 'Edge must use an isolated temporary profile.'
    $launchText = [IO.File]::ReadAllText($launchPath)
    Assert-MihariTest -Condition (-not $launchText.Contains('browser-secret')) -Message 'Successful launch metadata must not retain URL query values.'
    $launchMetadata = ConvertFrom-Json -InputObject $launchText -ErrorAction Stop
    Assert-MihariTest -Condition ($launchMetadata.proxiedSchemes.Count -eq 2 -and $launchMetadata.loopbackBypassDisabled -and $launchMetadata.quicDisabled -and $launchMetadata.http2Disabled -and $launchMetadata.nonProxiedWebRtcUdpDisabled -and $launchMetadata.maximumTlsVersion -eq 'tls1.2') -Message 'Compatibility metadata must retain the requested Edge transport policy.'
    Assert-MihariTest -Condition ($launchMetadata.profile -eq 'compatibility' -and $launchMetadata.requestedRemoteDebugging -and $launchMetadata.requestedHttp2Disabled -and $launchMetadata.observationStatus -eq 'launched_but_unverified' -and $launchMetadata.proxyBehaviorVerification -eq 'launched_but_unverified') -Message 'Requested browser switches must remain separate from observed behavior.'

    $h2Metadata = [pscustomobject]@{
        id = [guid]::NewGuid().ToString('N')
        profile = 'http2-observe'
        mode = 'Tunnel'
        actualPort = 45555
        outputDirectory = $temporaryDirectory
    }
    $h2Launch = Start-MihariBrowser -SessionMetadata $h2Metadata -Url 'https://example.test/h2?token=browser-secret'
    Assert-MihariTest -Condition ($h2Launch.Success -and $h2Launch.DiagnosticProfile -eq 'http2-observe' -and $h2Launch.RequestedHttpVersion -eq 'allow_h2') -Message 'The HTTP/2 diagnostic profile must be retained in the launch result.'
    Assert-MihariTest -Condition ($script:capturedEdgeStartInfo.Arguments.Contains('--disable-quic')) -Message 'The HTTP/2 diagnostic profile must keep QUIC disabled.'
    Assert-MihariTest -Condition (-not $script:capturedEdgeStartInfo.Arguments.Contains('--disable-http2') -and -not $script:capturedEdgeStartInfo.Arguments.Contains('--ssl-version-max=tls1.2')) -Message 'The HTTP/2 diagnostic profile must allow browser-negotiated HTTP/2 and preserve the requested system TLS policy.'
    $launchText = [IO.File]::ReadAllText($launchPath)
    $launchMetadata = ConvertFrom-Json -InputObject $launchText -ErrorAction Stop
    Assert-MihariTest -Condition ($launchMetadata.profile -eq 'http2-observe' -and $launchMetadata.requestedHttp2Enabled -and $launchMetadata.requestedTlsPolicy -eq 'system_default' -and $null -eq $launchMetadata.maximumTlsVersion -and -not $launchMetadata.http2Disabled) -Message 'The HTTP/2 profile must persist requested policy without claiming an observed protocol.'

    $h2InspectMetadata = [pscustomobject]@{
        id = [guid]::NewGuid().ToString('N')
        profile = 'http2-inspect'
        mode = 'Inspect'
        actualPort = 46666
        outputDirectory = $temporaryDirectory
    }
    $h2InspectLaunch = Start-MihariBrowser -SessionMetadata $h2InspectMetadata -Url 'https://example.test/h2'
    Assert-MihariTest -Condition ($h2InspectLaunch.Success -and $h2InspectLaunch.DiagnosticProfile -eq 'http2-inspect' -and $h2InspectLaunch.RequestedHttpVersion -eq 'allow_h2') -Message 'The native HTTP/2 Inspect profile must be retained in the browser launch result.'
    Assert-MihariTest -Condition (-not $script:capturedEdgeStartInfo.Arguments.Contains('--disable-http2') -and $script:capturedEdgeStartInfo.Arguments.Contains('--ssl-version-max=tls1.2')) -Message 'The native HTTP/2 Inspect profile must allow h2 while keeping the client TLS leg at TLS 1.2.'
    $launchText = [IO.File]::ReadAllText($launchPath)
    $launchMetadata = ConvertFrom-Json -InputObject $launchText -ErrorAction Stop
    Assert-MihariTest -Condition ($launchMetadata.profile -eq 'http2-inspect' -and $launchMetadata.requestedHttp2Enabled -and $launchMetadata.requestedTlsPolicy -eq 'maximum_tls_1_2' -and $launchMetadata.maximumTlsVersion -eq 'tls1.2' -and -not $launchMetadata.http2Disabled) -Message 'HTTP/2 Inspect metadata must record requested h2 and TLS 1.2 without claiming a negotiated protocol.'

    $script:capturedInitialUrl = $null
    Set-Item -Path Function:\Get-MihariBrowserOwnedProfileIdentity -Value {
        param([string] $SessionId, [object] $Launch, [int] $TimeoutSeconds)
        return [pscustomobject]@{
            Success = $true
            ProcessId = 5252
            OwnerStartTimeUtc = '2026-09-01T01:02:03.0000000Z'
            ErrorCode = $null
            MatchingProcessCount = 1
        }
    }
    Set-Item -Path Function:\Start-MihariBrowserObservation -Value {
        param([object] $Session, [object] $Launch, [string] $InitialUrl)
        $script:capturedInitialUrl = $InitialUrl
        return [pscustomobject]@{ Status = 'attached'; Reason = $null }
    }
    $liveMetadata = [pscustomobject]@{
        id = [guid]::NewGuid().ToString('N')
        actualPort = 48888
        outputDirectory = $temporaryDirectory
        Writer = [pscustomobject]@{ Closed = $false }
        Cancellation = [pscustomobject]@{}
    }
    $liveUrl = 'https://example.test/observed?token=browser-secret'
    $liveLaunch = Start-MihariBrowser -SessionMetadata $liveMetadata -Url $liveUrl
    $liveProfilePath = [string]$liveLaunch.ProfilePath
    Assert-MihariTest -Condition ($liveLaunch.Success -and $liveLaunch.Pid -eq 5252 -and $liveLaunch.OwnerStartTimeUtc -eq '2026-09-01T01:02:03.0000000Z') -Message 'Live observation launch must use the verified browser-root process identity rather than the Edge launcher PID.'
    Assert-MihariTest -Condition ($script:capturedEdgeStartInfo.Arguments.Contains('about:blank') -and -not $script:capturedEdgeStartInfo.Arguments.Contains('example.test')) -Message 'A live observed URL must not navigate until the owner observer is armed.'
    Assert-MihariTest -Condition ($script:capturedInitialUrl -eq $liveUrl -and $null -eq $liveLaunch.PSObject.Properties['InitialNavigationUrl']) -Message 'The requested URL is passed only in memory to the observer and is absent from launch results.'
    $liveRecords = @(Get-MihariBrowserProfileRecords -SessionMetadata $liveMetadata)
    Assert-MihariTest -Condition ($liveRecords.Count -eq 1 -and [int]$liveRecords[0].processId -eq 5252 -and $liveRecords[0].ownerStartTimeUtc -eq '2026-09-01T01:02:03.0000000Z') -Message 'The profile ownership record must use the final verified browser-root identity.'
    $liveLaunchText = [IO.File]::ReadAllText((Join-Path $temporaryDirectory 'browser-launch.json'))
    Assert-MihariTest -Condition (-not $liveLaunchText.Contains('browser-secret') -and -not $liveLaunchText.Contains('example.test')) -Message 'The requested URL must not be written into browser launch metadata.'

    Set-Item -Path Function:\Get-MihariBrowserOwnedProfileIdentity -Value {
        param([string] $SessionId, [object] $Launch, [int] $TimeoutSeconds)
        return [pscustomobject]@{
            Success = $false
            ProcessId = $null
            OwnerStartTimeUtc = $null
            ErrorCode = 'browser_profile_owner_unverifiable'
            MatchingProcessCount = 1
        }
    }
    $failedIdentityLaunch = Start-MihariBrowser -SessionMetadata $liveMetadata -Url $liveUrl
    $failedProfilePath = [string]$failedIdentityLaunch.ProfilePath
    Assert-MihariTest -Condition (-not $failedIdentityLaunch.Success -and $failedIdentityLaunch.ObservationStatus -eq 'unavailable' -and $failedIdentityLaunch.Reason -match 'requested URL was not opened') -Message 'If the profile owner cannot be verified, deferred navigation must fail clearly instead of opening an unobserved URL.'
    Assert-MihariTest -Condition ($script:capturedEdgeStartInfo.Arguments.Contains('about:blank') -and -not $script:capturedEdgeStartInfo.Arguments.Contains('example.test')) -Message 'An unverified live profile must remain at about:blank.'

    Set-Item -Path Function:\Get-MihariBrowserOwnedProfileIdentity -Value {
        param([string] $SessionId, [object] $Launch, [int] $TimeoutSeconds)
        return [pscustomobject]@{
            Success = $true
            ProcessId = 5252
            OwnerStartTimeUtc = '2026-09-01T01:02:03.0000000Z'
            ErrorCode = $null
            MatchingProcessCount = 1
        }
    }
    Set-Item -Path Function:\Start-MihariBrowserObservation -Value {
        param([object] $Session, [object] $Launch, [string] $InitialUrl)
        return [pscustomobject]@{
            Status = 'unavailable'
            ErrorCode = 'profile_owner_unverified'
            Reason = 'Unsafe ws://127.0.0.1:9222/devtools/browser/private-endpoint?token=control-secret'
        }
    }
    $observerFailureLaunch = Start-MihariBrowser -SessionMetadata $liveMetadata -Url $liveUrl
    $observerFailureProfilePath = [string]$observerFailureLaunch.ProfilePath
    Assert-MihariTest -Condition (-not $observerFailureLaunch.Success -and
        $observerFailureLaunch.ObservationErrorCode -eq 'profile_owner_unverified' -and
        $observerFailureLaunch.Reason -match 'could not verify the active Edge process' -and
        -not $observerFailureLaunch.Reason.Contains('9222') -and
        -not $observerFailureLaunch.Reason.Contains('control-secret')) 'Observer failures must retain only an allowlisted code and fixed safe reason.'
    $failureLaunchText = [IO.File]::ReadAllText((Join-Path $temporaryDirectory 'browser-launch.json'))
    Assert-MihariTest -Condition ($failureLaunchText.Contains('profile_owner_unverified') -and
        -not $failureLaunchText.Contains('control-secret') -and -not $failureLaunchText.Contains('devtools/browser')) 'Launch metadata must expose the safe observer code without debugger-control data.'

    $invalidH2InspectMetadata = [pscustomobject]@{
        id = [guid]::NewGuid().ToString('N')
        profile = 'http2-inspect'
        mode = 'Tunnel'
        actualPort = 47777
        outputDirectory = $temporaryDirectory
    }
    $invalidH2InspectLaunch = Start-MihariBrowser -SessionMetadata $invalidH2InspectMetadata
    Assert-MihariTest -Condition (-not $invalidH2InspectLaunch.Success -and $invalidH2InspectLaunch.Reason -match 'requires Inspect mode') -Message 'The HTTP/2 Inspect profile must reject a Tunnel session.'

    $invalidH2Metadata = [pscustomobject]@{
        id = [guid]::NewGuid().ToString('N')
        profile = 'http2-observe'
        mode = 'Inspect'
        actualPort = 45555
        outputDirectory = $temporaryDirectory
    }
    $invalidH2Launch = Start-MihariBrowser -SessionMetadata $invalidH2Metadata
    Assert-MihariTest -Condition (-not $invalidH2Launch.Success -and $invalidH2Launch.Reason -match 'requires Tunnel mode') -Message 'The HTTP/2 diagnostic profile must reject an incompatible Inspect session.'

    $rawReasonResult = New-MihariBrowserLaunchResult -Success $false -Path $null -ProcessId $null `
        -ProfilePath $null -ProxyEndpoint $null `
        -Reason 'Launch failed for https://user:password@example.test/path?token=browser-secret'
    $sanitizedReasonResult = Complete-MihariBrowserLaunch -SessionMetadata $metadataWithReservedPort `
        -Result $rawReasonResult -UrlProvided $true
    Assert-MihariTest -Condition (-not $sanitizedReasonResult.Reason.Contains('browser-secret') -and -not $sanitizedReasonResult.Reason.Contains('user:password')) -Message 'Browser launch reason sanitization must redact URL query values and user info.'

    Set-Item -Path Function:\Start-MihariEdgeProcess -Value {
        param([System.Diagnostics.ProcessStartInfo] $StartInfo)
        throw 'Failed to start C:\Users\private\Edge\msedge.exe for https://example.test/path?token=browser-secret'
    }
    $failedLaunch = Start-MihariBrowser -SessionMetadata $metadataWithReservedPort `
        -Url 'https://example.test/path?token=browser-secret'
    Assert-MihariTest -Condition (-not $failedLaunch.Success) -Message 'An Edge process creation error must be reported.'
    Assert-MihariTest -Condition (-not $failedLaunch.Reason.Contains('C:\Users\private') -and -not $failedLaunch.Reason.Contains('browser-secret')) -Message 'Browser launch reasons must not expose local paths or URL query values.'
    $launchText = [IO.File]::ReadAllText($launchPath)
    Assert-MihariTest -Condition (-not $launchText.Contains('C:\Users\private') -and -not $launchText.Contains('browser-secret')) -Message 'Persisted browser launch metadata must not expose local paths or URL query values.'
    Write-Host 'PASS browser: Edge uses an isolated profile and Mihari proxy, including loopback, while restricting unsupported transports'
}
finally {
    Set-Item -Path Function:\Find-MihariEdgeExecutable -Value $originalDiscovery
    Set-Item -Path Function:\Start-MihariEdgeProcess -Value $originalStartProcess
    Set-Item -Path Function:\Get-MihariBrowserOwnedProfileIdentity -Value $originalOwnerIdentity
    Set-Item -Path Function:\Start-MihariBrowserObservation -Value $originalBrowserObservation
    foreach ($ownedTestProfile in @($liveProfilePath, $failedProfilePath, $observerFailureProfilePath)) {
        if (-not [string]::IsNullOrWhiteSpace($ownedTestProfile) -and [IO.Directory]::Exists($ownedTestProfile)) {
            Remove-Item -LiteralPath $ownedTestProfile -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    Remove-Variable -Name capturedEdgeStartInfo -Scope Script -ErrorAction SilentlyContinue
    Remove-Variable -Name capturedInitialUrl -Scope Script -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $temporaryDirectory -Recurse -Force -ErrorAction SilentlyContinue
}
