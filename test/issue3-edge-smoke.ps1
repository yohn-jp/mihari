param()

$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') {
    Write-Warning 'The Issue #3 real Edge smoke test requires Windows; it is not a mock-only test.'
    return
}

. (Join-Path $PSScriptRoot 'TestSupport.ps1')
. (Join-Path $PSScriptRoot 'integration.ps1') -LoadHelpersOnly

function Invoke-MihariIssue3ManagementRequest {
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [ValidateSet('GET', 'POST')][string]$Method = 'GET',
        [AllowNull()][string]$Body
    )

    $request = [System.Net.HttpWebRequest]::Create($Uri)
    $request.Method = $Method
    $request.Proxy = $null
    $request.Timeout = 10000
    $request.ReadWriteTimeout = 10000
    if ($Method -eq 'POST') {
        $authority = ([Uri]$Uri).GetLeftPart([UriPartial]::Authority) + '/'
        $page = Invoke-MihariIssue3ManagementRequest -Uri $authority -Method GET -Body $null
        $tokenMatch = [regex]::Match([string]$page.Content, 'var CONTROL_TOKEN="(?<token>[A-Za-z0-9_-]+)";')
        Assert-MihariTest -Condition $tokenMatch.Success -Message 'The owned management page must bootstrap an in-memory action token.'
        $request.Headers['X-Mihari-Control-Token'] = $tokenMatch.Groups['token'].Value
        # .NET Framework sends Expect: 100-continue by default. The small
        # management listener intentionally does not support that extension.
        $request.ServicePoint.Expect100Continue = $false
        $request.ContentType = 'application/json'
        $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes([string]$Body)
        $request.ContentLength = $bodyBytes.Length
        $requestStream = $request.GetRequestStream()
        try { $requestStream.Write($bodyBytes, 0, $bodyBytes.Length) }
        finally { $requestStream.Dispose() }
    }

    $response = $null
    try { $response = $request.GetResponse() }
    catch [System.Net.WebException] {
        $errorResponse = $_.Exception.Response
        if ($null -eq $errorResponse) { throw }
        $statusCode = [int]$errorResponse.StatusCode
        $errorCode = $null
        try {
            $errorStream = $errorResponse.GetResponseStream()
            if ($null -ne $errorStream) {
                $errorReader = [System.IO.StreamReader]::new($errorStream, [System.Text.Encoding]::UTF8)
                try {
                    $errorBuffer = New-Object char[] 4096
                    $errorLength = $errorReader.Read($errorBuffer, 0, $errorBuffer.Length)
                    $errorContent = [string]::new([char[]]$errorBuffer, 0, $errorLength)
                }
                finally { $errorReader.Dispose() }
                $errorDocument = $null
                try { $errorDocument = ConvertFrom-Json -InputObject $errorContent -ErrorAction Stop }
                catch { $errorDocument = $null }
                if ($null -ne $errorDocument) {
                    foreach ($propertyName in @('error', 'code')) {
                        $property = $errorDocument.PSObject.Properties[$propertyName]
                        if ($null -ne $property -and [string]$property.Value -match '^[A-Za-z0-9_.-]{1,80}$') {
                            $errorCode = [string]$property.Value
                            break
                        }
                    }
                }
            }
        }
        catch {
            $errorCode = $null
        }
        finally { $errorResponse.Close() }
        if ($errorCode) { throw ('Management {0} request returned HTTP {1} ({2}).' -f $Method, $statusCode, $errorCode) }
        throw ('Management {0} request returned HTTP {1}.' -f $Method, $statusCode)
    }
    try {
        $reader = [System.IO.StreamReader]::new($response.GetResponseStream(), [System.Text.Encoding]::UTF8)
        try { $content = $reader.ReadToEnd() }
        finally { $reader.Dispose() }
        return [pscustomobject]@{ StatusCode = [int]$response.StatusCode; ContentType = [string]$response.ContentType; Content = $content }
    }
    finally { $response.Dispose() }
}

function Get-MihariIssue3EdgeProcesses {
    param([Parameter(Mandatory = $true)][string]$ProfilePath)
    $matches = New-Object 'System.Collections.Generic.List[object]'
    foreach ($processInfo in @(Get-CimInstance -ClassName Win32_Process -Filter "Name = 'msedge.exe'" -ErrorAction Stop)) {
        $commandLine = [string]$processInfo.CommandLine
        if (-not [string]::IsNullOrWhiteSpace($commandLine) -and
            $commandLine.IndexOf($ProfilePath, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
            $matches.Add($processInfo)
        }
    }
    return @($matches.ToArray())
}

function Stop-MihariIssue3EdgeProfile {
    param([string]$ProfilePath)
    if ([string]::IsNullOrWhiteSpace($ProfilePath)) { return }

    $deadline = [DateTime]::UtcNow.AddSeconds(8)
    do {
        $profileProcesses = @(Get-MihariIssue3EdgeProcesses -ProfilePath $ProfilePath)
        foreach ($processInfo in $profileProcesses) {
            try { Stop-Process -Id ([int]$processInfo.ProcessId) -Force -ErrorAction Stop }
            catch {
                # Edge can exit between the CIM snapshot and Stop-Process. Treat
                # that race as normal only when the unique profile no longer
                # identifies the process; a surviving process is retried below
                # and fails the final cleanup assertion if it cannot be stopped.
                $processIdStillUsesProfile = @(
                    Get-MihariIssue3EdgeProcesses -ProfilePath $ProfilePath |
                        Where-Object { [int]$_.ProcessId -eq [int]$processInfo.ProcessId }
                )
                if ($processIdStillUsesProfile.Count -gt 0) {
                    Write-Verbose ('Edge process {0} is still using the test profile; retrying cleanup.' -f $processInfo.ProcessId)
                }
            }
        }
        if ($profileProcesses.Count -eq 0) { break }
        Start-Sleep -Milliseconds 200
    } while ([DateTime]::UtcNow -lt $deadline)
    $remainingProcesses = @(Get-MihariIssue3EdgeProcesses -ProfilePath $ProfilePath)
    if ($remainingProcesses.Count -gt 0) {
        throw ('Could not stop all Edge processes using the test profile: ' + ([string]::Join(', ', @($remainingProcesses | ForEach-Object { [string]$_.ProcessId }))))
    }
    if (Test-Path -LiteralPath $ProfilePath) {
        Remove-Item -LiteralPath $ProfilePath -Recurse -Force -ErrorAction Stop
        if (Test-Path -LiteralPath $ProfilePath) { throw 'The dedicated Edge test profile remained after removal.' }
    }
}

function Get-MihariIssue3TargetEvents {
    param([Parameter(Mandatory = $true)][string]$EventsPath, [Parameter(Mandatory = $true)][string]$Path, [int]$TimeoutSeconds = 25)
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        if ([IO.File]::Exists($EventsPath)) {
            foreach ($line in (Read-MihariTestCompleteLiveLines -Path $EventsPath)) {
                $event = ConvertFrom-Json -InputObject $line -ErrorAction Stop
                if ($event.stage -eq 'proxy.request' -and $event.data.path -eq $Path) {
                    $connectionId = [string]$event.connectionId
                    $requestId = [string]$event.requestId
                    $chain = New-Object 'System.Collections.Generic.List[object]'
                    foreach ($candidateLine in (Read-MihariTestCompleteLiveLines -Path $EventsPath)) {
                        $candidate = ConvertFrom-Json -InputObject $candidateLine -ErrorAction Stop
                        if ([string]$candidate.connectionId -eq $connectionId -and
                            [string]$candidate.requestId -eq $requestId) {
                            $chain.Add($candidate)
                        }
                    }
                    $completedResponse = @($chain | Where-Object { $_.stage -eq 'response.relay' -and $_.outcome -eq 'success' })
                    if ($completedResponse.Count -gt 0) {
                        return @($chain.ToArray())
                    }
                }
            }
        }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    return @()
}

function Get-MihariIssue3ConnectEvents {
    param(
        [Parameter(Mandatory = $true)][string]$EventsPath,
        [Parameter(Mandatory = $true)][string]$HostName,
        [Parameter(Mandatory = $true)][int]$Port,
        [int]$TimeoutSeconds = 20
    )
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        if ([IO.File]::Exists($EventsPath)) {
            foreach ($line in (Read-MihariTestCompleteLiveLines -Path $EventsPath)) {
                $event = ConvertFrom-Json -InputObject $line -ErrorAction Stop
                if ($event.stage -eq 'proxy.request' -and $event.data.method -eq 'CONNECT' -and
                    $event.data.host -eq $HostName -and [int]$event.data.port -eq $Port) {
                    $connectionId = [string]$event.connectionId
                    $requestId = [string]$event.requestId
                    $chain = New-Object 'System.Collections.Generic.List[object]'
                    foreach ($candidateLine in (Read-MihariTestCompleteLiveLines -Path $EventsPath)) {
                        $candidate = ConvertFrom-Json -InputObject $candidateLine -ErrorAction Stop
                        if ([string]$candidate.connectionId -eq $connectionId -and
                            [string]$candidate.requestId -eq $requestId) {
                            $chain.Add($candidate)
                        }
                    }
                    $tcpSuccess = @($chain | Where-Object { $_.stage -eq 'upstream.tcp' -and $_.outcome -eq 'success' })
                    $relayEvents = @($chain | Where-Object {
                        $_.stage -eq 'tunnel.relay' -and [long]$_.data.bytesClientToUpstream -gt 0
                    })
                    if ($tcpSuccess.Count -gt 0 -and $relayEvents.Count -gt 0) {
                        return @($chain.ToArray())
                    }
                }
            }
        }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    return @()
}

function Get-MihariIssue3SafeEventSummary {
    param([string]$EventsPath)
    if (-not [IO.File]::Exists($EventsPath)) { return 'event file was not created' }
    $summary = New-Object 'System.Collections.Generic.List[string]'
    foreach ($line in (Read-MihariTestCompleteLiveLines -Path $EventsPath)) {
        try { $event = ConvertFrom-Json -InputObject $line -ErrorAction Stop }
        catch { continue }
        $stage = [string]$event.stage
        $outcome = [string]$event.outcome
        $code = [string]$event.data.errorCode
        $hostName = [string]$event.data.host
        $port = [string]$event.data.port
        $summary.Add(('{0} {1} {2}:{3} {4}' -f $stage, $outcome, $hostName, $port, $code).Trim())
    }
    if ($summary.Count -eq 0) { return 'no complete event lines were written' }
    return ($summary -join '; ')
}

function Write-MihariIssue3FixtureResponse {
    param([Parameter(Mandatory = $true)][System.IO.Stream]$Stream)
    $body = '<!doctype html><html><head><title>Mihari local browser fixture</title><link rel="icon" href="data:,"></head><body>local fixture ok</body></html>'
    $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($body)
    $headers = [System.Text.Encoding]::ASCII.GetBytes("HTTP/1.1 200 OK`r`nContent-Type: text/html; charset=utf-8`r`nContent-Length: $($bodyBytes.Length)`r`nConnection: close`r`n`r`n")
    $Stream.Write($headers, 0, $headers.Length)
    $Stream.Write($bodyBytes, 0, $bodyBytes.Length)
    $Stream.Flush()
}

$tempRoot = Join-Path ([IO.Path]::GetTempPath()) ('mihari-issue3-edge-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($tempRoot)
$child = $null
$metadata = $null
$originListener = $null
$originClient = $null
$browserProfilePath = $null
$browserProcessId = $null
$stopFailure = $null
$browserCleanupFailure = $null

try {
    $outputRoot = Join-Path $tempRoot 'session'
    $child = Start-MihariTestProcess -Command start -OutputRoot $outputRoot -Mode Tunnel -Port 0
    $metadata = Wait-MihariTestSession -Child $child
    $proxyPort = [int]$metadata.actualPort
    $managementPort = [int]$metadata.actualManagementPort
    Assert-MihariTest -Condition ($proxyPort -gt 0 -and $managementPort -gt 0 -and $proxyPort -ne $managementPort) -Message 'The browser smoke session must publish distinct active proxy and management listeners.'

    $managementBase = 'http://127.0.0.1:{0}' -f $managementPort
    $page = Invoke-MihariIssue3ManagementRequest -Uri ($managementBase + '/')
    Assert-MihariTest -Condition ($page.StatusCode -eq 200 -and $page.ContentType -match '(?i)text/html' -and $page.Content -match '(?i)<html') -Message 'The management server must serve its UI HTML over its actual loopback listener.'
    Assert-MihariTest -Condition ($page.Content.Contains('id="launch-browser"') -and $page.Content.Contains("browser:'/api/browser'")) -Message 'The served UI must expose its Edge action through the local browser API.'

    $originListener = New-MihariTestListener
    $originPort = ([System.Net.IPEndPoint]$originListener.LocalEndpoint).Port
    $fixturePath = '/issue3-edge-' + [guid]::NewGuid().ToString('N')
    $fixtureUrl = 'http://127.0.0.1:{0}{1}' -f $originPort, $fixturePath
    $originAccept = $originListener.AcceptTcpClientAsync()
    $launchBody = ConvertTo-Json -InputObject @{ url = $fixtureUrl } -Compress -Depth 3
    $launchResponse = Invoke-MihariIssue3ManagementRequest -Uri ($managementBase + '/api/browser') -Method POST -Body $launchBody
    Assert-MihariTest -Condition ($launchResponse.StatusCode -eq 200 -and $launchResponse.ContentType -match '(?i)application/json') -Message 'The management browser action must return a successful JSON response.'
    $launch = ConvertFrom-Json -InputObject $launchResponse.Content -ErrorAction Stop

    if (-not $launch.success -and [string]$launch.reason -match '(?i)Microsoft Edge was not found') {
        throw ('Microsoft Edge is absent on this Windows runner; Issue #3 requires real browser-originated fixture traffic, so this suite cannot pass by skipping. API response: ' + [string]$launchResponse.Content)
    }
        $browserProfilePath = [string]$launch.profilePath
        if ($null -ne $launch.pid -and [string]$launch.pid -match '^\d+$') { $browserProcessId = [int]$launch.pid }
    Assert-MihariTest -Condition ([bool]$launch.success) -Message ('The UI browser action must launch the real diagnostic Edge process. API response: ' + [string]$launchResponse.Content)
        Assert-MihariTest -Condition (-not [string]::IsNullOrWhiteSpace($browserProfilePath) -and (Test-Path -LiteralPath $browserProfilePath -PathType Container)) -Message 'The launched Edge process must use a dedicated temporary profile.'
        Assert-MihariTest -Condition ([string]$launch.proxyEndpoint -eq ('http://127.0.0.1:{0}' -f $proxyPort)) -Message 'The management launch result must identify the active Mihari proxy endpoint.'

        if (-not $originAccept.Wait(25000)) {
            $safeSummary = Get-MihariIssue3SafeEventSummary -EventsPath ([string]$metadata.eventsPath)
            throw ('Real Edge did not reach the local fixture listener through Mihari. Safe session event summary: ' + $safeSummary)
        }
        $originClient = $originAccept.Result
        $originStream = $originClient.GetStream()
        $originRequest = Read-MihariTestHeaderText -Stream $originStream -Context 'Edge local fixture request'
        Assert-MihariTest -Condition ($originRequest.StartsWith(('GET {0} HTTP/1.1' -f $fixturePath)) -and $originRequest -match ('(?im)^Host:\s*127\.0\.0\.1:' + $originPort + '\s*\r?$')) -Message 'A real Edge request for the unique loopback fixture must arrive at the fixture through Mihari.'
        Write-MihariIssue3FixtureResponse -Stream $originStream
        $originStream.Dispose()
        $originClient.Close()
        $originClient = $null
        $originListener.Stop()
        $originListener = $null

        $targetEvents = @(Get-MihariIssue3TargetEvents -EventsPath ([string]$metadata.eventsPath) -Path $fixturePath)
        Assert-MihariTest -Condition ($targetEvents.Count -ge 6) -Message 'Mihari must emit the complete HTTP event chain for the browser-originated request to the local fixture.'
        $targetRequest = @($targetEvents | Where-Object { $_.stage -eq 'proxy.request' }) | Select-Object -First 1
        $targetHttp = @($targetEvents | Where-Object { $_.stage -eq 'http.request' }) | Select-Object -First 1
        $targetRoute = @($targetEvents | Where-Object { $_.stage -eq 'upstream.resolve' }) | Select-Object -First 1
        $targetTcp = @($targetEvents | Where-Object { $_.stage -eq 'upstream.tcp' }) | Select-Object -First 1
        $targetUpstreamHttp = @($targetEvents | Where-Object { $_.stage -eq 'upstream.http' }) | Select-Object -First 1
        $targetResponse = @($targetEvents | Where-Object { $_.stage -eq 'response.relay' }) | Select-Object -First 1
        Assert-MihariTest -Condition ($null -ne $targetRequest -and $targetRequest.data.host -eq '127.0.0.1' -and [int]$targetRequest.data.port -eq $originPort) -Message 'Mihari must observe the browser request with the fixture authority, not its own listener authority.'
        Assert-MihariTest -Condition ($null -ne $targetHttp -and $targetHttp.data.method -eq 'GET' -and $targetHttp.data.path -eq $fixturePath) -Message 'Mihari must record the browser-originated HTTP request path.'
        Assert-MihariTest -Condition ($null -ne $targetRoute -and $targetRoute.outcome -eq 'success' -and $targetRoute.data.routeKind -in @('Direct', 'ExplicitProxy')) -Message 'The browser request must resolve through a concrete non-self upstream route.'
        Assert-MihariTest -Condition ($null -ne $targetTcp -and $targetTcp.outcome -eq 'success') -Message 'Mihari must establish the fixture upstream connection for real browser traffic.'
        Assert-MihariTest -Condition ($null -ne $targetUpstreamHttp -and $targetUpstreamHttp.outcome -eq 'success' -and [int]$targetUpstreamHttp.data.statusCode -eq 200) -Message 'Mihari must observe the local fixture HTTP response before relaying it to Edge.'
        Assert-MihariTest -Condition ($null -ne $targetResponse -and $targetResponse.outcome -eq 'success' -and [int]$targetResponse.data.statusCode -eq 200) -Message 'Mihari must relay the local fixture response to real Edge.'

        foreach ($line in (Read-MihariTestCompleteLiveLines -Path ([string]$metadata.eventsPath))) {
            $event = ConvertFrom-Json -InputObject $line -ErrorAction Stop
            Assert-MihariTest -Condition ([string]$event.data.errorCode -ne 'upstream_route_self_reference') -Message 'No browser flow may resolve Mihari back to its own listener.'
            if ($event.data.host -eq '127.0.0.1' -and $null -ne $event.data.port) {
                Assert-MihariTest -Condition ([int]$event.data.port -ne $proxyPort) -Message 'Browser traffic must never select the Mihari proxy listener as its own upstream target.'
            }
        }

        $browserMetadataPath = Join-Path ([string]$metadata.outputDirectory) 'browser-launch.json'
        Assert-MihariTest -Condition ([IO.File]::Exists($browserMetadataPath)) -Message 'The canonical browser launcher must persist its safe transport configuration.'
        $browserMetadata = ConvertFrom-Json -InputObject (Read-MihariTestLiveText -Path $browserMetadataPath) -ErrorAction Stop
        Assert-MihariTest -Condition ($browserMetadata.success -eq $true -and $browserMetadata.loopbackBypassDisabled -eq $true -and $browserMetadata.quicDisabled -eq $true -and $browserMetadata.http2Disabled -eq $true -and $browserMetadata.nonProxiedWebRtcUdpDisabled -eq $true -and $browserMetadata.maximumTlsVersion -eq 'tls1.2' -and @($browserMetadata.proxiedSchemes) -contains 'http' -and @($browserMetadata.proxiedSchemes) -contains 'https') -Message 'The diagnostic Edge launch must proxy HTTP and HTTPS, disable supported escape transports, and retain normal certificate verification.'

        $edgeProcesses = @()
        $edgeDeadline = [DateTime]::UtcNow.AddSeconds(10)
        do {
            $edgeProcesses = @(Get-MihariIssue3EdgeProcesses -ProfilePath $browserProfilePath)
            if ($edgeProcesses.Count -gt 0) { break }
            Start-Sleep -Milliseconds 200
        } while ([DateTime]::UtcNow -lt $edgeDeadline)
        Assert-MihariTest -Condition ($edgeProcesses.Count -gt 0) -Message 'The real Edge process must retain the dedicated profile and the forced proxy command line.'
        $edgeProcess = $null
        if ($browserProcessId -gt 0) {
            $edgeProcess = @($edgeProcesses | Where-Object { [int]$_.ProcessId -eq $browserProcessId }) | Select-Object -First 1
        }
        if ($null -eq $edgeProcess) {
            $edgeProcess = @($edgeProcesses | Where-Object {
                ([string]$_.CommandLine).IndexOf(('--proxy-server=http://127.0.0.1:{0}' -f $proxyPort), [System.StringComparison]::OrdinalIgnoreCase) -ge 0
            }) | Select-Object -First 1
        }
        Assert-MihariTest -Condition ($null -ne $edgeProcess) -Message 'The real Edge browser process must retain the forced Mihari proxy command line.'
        $edgeCommandLine = [string]$edgeProcess.CommandLine
        Assert-MihariTest -Condition ($edgeCommandLine.IndexOf(('--proxy-server=http://127.0.0.1:{0}' -f $proxyPort), [System.StringComparison]::OrdinalIgnoreCase) -ge 0 -and $edgeCommandLine.IndexOf('--proxy-bypass-list=<-loopback>', [System.StringComparison]::OrdinalIgnoreCase) -ge 0) -Message 'The running Edge command line must force both HTTP and HTTPS through Mihari, including loopback destinations.'
        Assert-MihariTest -Condition ($edgeCommandLine.IndexOf('--disable-quic', [System.StringComparison]::OrdinalIgnoreCase) -ge 0 -and $edgeCommandLine.IndexOf('--disable-http2', [System.StringComparison]::OrdinalIgnoreCase) -ge 0 -and $edgeCommandLine.IndexOf('--force-webrtc-ip-handling-policy=disable_non_proxied_udp', [System.StringComparison]::OrdinalIgnoreCase) -ge 0 -and $edgeCommandLine.IndexOf('--ssl-version-max=tls1.2', [System.StringComparison]::OrdinalIgnoreCase) -ge 0) -Message 'The running Edge command line must stay within Mihari supported QUIC/HTTP2/TLS baseline and disable non-proxied WebRTC UDP.'
        Assert-MihariTest -Condition ($edgeCommandLine -notmatch '(?i)--(ignore-certificate-errors|allow-insecure-localhost)') -Message 'The diagnostic Edge process must not disable certificate validation.'

        # Launch a second real Edge profile at a raw local TLS endpoint. The
        # fixture deliberately has no certificate: successful TLS is not the
        # purpose here. Receiving ClientHello bytes plus Mihari CONNECT/Tunnel
        # events proves HTTPS traversed the supported proxy without a bypass.
        Stop-MihariIssue3EdgeProfile -ProfilePath $browserProfilePath
        $browserProfilePath = $null
        $browserProcessId = $null
        $originListener = New-MihariTestListener
        $tlsFixturePort = ([System.Net.IPEndPoint]$originListener.LocalEndpoint).Port
        $tlsFixtureUrl = 'https://127.0.0.1:{0}/issue3-tls-{1}' -f $tlsFixturePort, [guid]::NewGuid().ToString('N')
        $tlsLaunchBody = ConvertTo-Json -InputObject @{ url = $tlsFixtureUrl } -Compress -Depth 3
        $tlsLaunchResponse = Invoke-MihariIssue3ManagementRequest -Uri ($managementBase + '/api/browser') -Method POST -Body $tlsLaunchBody
        Assert-MihariTest -Condition ($tlsLaunchResponse.StatusCode -eq 200 -and $tlsLaunchResponse.ContentType -match '(?i)application/json') -Message 'The management browser action must launch Edge at a local HTTPS fixture.'
        $tlsLaunch = ConvertFrom-Json -InputObject $tlsLaunchResponse.Content -ErrorAction Stop
        $browserProfilePath = [string]$tlsLaunch.profilePath
        if ($null -ne $tlsLaunch.pid -and [string]$tlsLaunch.pid -match '^\d+$') { $browserProcessId = [int]$tlsLaunch.pid }
        Assert-MihariTest -Condition ([bool]$tlsLaunch.success) -Message ('The UI browser action must launch the real diagnostic Edge process for HTTPS. API response: ' + [string]$tlsLaunchResponse.Content)
        Assert-MihariTest -Condition (-not [string]::IsNullOrWhiteSpace($browserProfilePath) -and (Test-Path -LiteralPath $browserProfilePath -PathType Container)) -Message 'The HTTPS Edge launch must use its own temporary profile.'

        $clientHelloRecordType = -1
        $clientHelloAttempts = New-Object 'System.Collections.Generic.List[string]'
        $tlsReadFailureType = $null
        $tlsAcceptDeadline = [DateTime]::UtcNow.AddSeconds(30)
        for ($attempt = 1; $attempt -le 8 -and [DateTime]::UtcNow -lt $tlsAcceptDeadline; $attempt++) {
            $tlsAccept = $originListener.AcceptTcpClientAsync()
            $remainingWait = [int][Math]::Max(1, ($tlsAcceptDeadline - [DateTime]::UtcNow).TotalMilliseconds)
            if (-not $tlsAccept.Wait($remainingWait)) { break }
            $originClient = $tlsAccept.Result
            $tlsFixtureStream = $originClient.GetStream()
            $tlsFixtureStream.ReadTimeout = 3000
            $attemptRecordType = -1
            $attemptReadFailureType = $null
            try { $attemptRecordType = $tlsFixtureStream.ReadByte() }
            catch { $attemptReadFailureType = $_.Exception.GetType().FullName }
            $clientHelloAttempts.Add(('attempt={0},firstByte={1},readFailureType={2}' -f $attempt, $attemptRecordType, $attemptReadFailureType))
            $originClient.Close()
            $originClient = $null
            if ($attemptRecordType -eq 22) {
                $clientHelloRecordType = $attemptRecordType
                $tlsReadFailureType = $attemptReadFailureType
                break
            }
        }
        $originListener.Stop()
        $originListener = $null

        $connectEvents = @(Get-MihariIssue3ConnectEvents -EventsPath ([string]$metadata.eventsPath) -HostName '127.0.0.1' -Port $tlsFixturePort)
        if ($connectEvents.Count -eq 0) {
            $safeSummary = Get-MihariIssue3SafeEventSummary -EventsPath ([string]$metadata.eventsPath)
            throw ('Real Edge did not send TLS through a completed Mihari HTTPS tunnel within eight fixture accepts. Safe fixture attempts: {0}; Mihari event summary: {1}' -f ($clientHelloAttempts -join '; '), $safeSummary)
        }
        $connectRequest = @($connectEvents | Where-Object { $_.stage -eq 'proxy.request' }) | Select-Object -First 1
        $connectRoute = @($connectEvents | Where-Object { $_.stage -eq 'upstream.resolve' }) | Select-Object -First 1
        $connectTcp = @($connectEvents | Where-Object { $_.stage -eq 'upstream.tcp' }) | Select-Object -First 1
        $connectRelay = @($connectEvents | Where-Object { $_.stage -eq 'tunnel.relay' }) | Select-Object -First 1
        $connectChainSummary = New-Object 'System.Collections.Generic.List[string]'
        foreach ($connectEvent in $connectEvents) {
            $summaryLine = '{0}={1}' -f [string]$connectEvent.stage, [string]$connectEvent.outcome
            if ($connectEvent.stage -eq 'tunnel.relay') {
                $summaryLine += ' clientToUpstreamBytes={0}' -f [long]$connectEvent.data.bytesClientToUpstream
            }
            if ($connectEvent.data.errorCode) { $summaryLine += ' errorCode={0}' -f [string]$connectEvent.data.errorCode }
            $connectChainSummary.Add($summaryLine)
        }
        Assert-MihariTest -Condition ($connectRequest.mode -eq 'Tunnel' -and $connectRequest.data.method -eq 'CONNECT' -and [int]$connectRequest.data.port -eq $tlsFixturePort) -Message 'Mihari must observe real Edge HTTPS as a CONNECT accepted in Tunnel mode.'
        Assert-MihariTest -Condition ($connectRoute.outcome -eq 'success' -and $connectTcp.outcome -eq 'success') -Message 'Mihari must resolve and connect the browser HTTPS tunnel to the local TLS fixture.'
        if ($clientHelloRecordType -ne 22 -or $null -ne $tlsReadFailureType) {
            throw ('The local HTTPS fixture did not receive TLS record type 22. Safe fixture attempts: {0}; matching Mihari CONNECT chain: {1}' -f ($clientHelloAttempts -join '; '), ($connectChainSummary -join '; '))
        }
        Assert-MihariTest -Condition ([long]$connectRelay.data.bytesClientToUpstream -gt 0) -Message 'Mihari must relay Edge TLS handshake bytes unchanged to the local HTTPS fixture.'
        $clientTlsEvents = @($connectEvents | Where-Object { $_.stage -eq 'client.tls' })
        Assert-MihariTest -Condition ($clientTlsEvents.Count -eq 0) -Message 'Tunnel mode must not terminate the HTTPS fixture TLS handshake.'
        foreach ($line in (Read-MihariTestCompleteLiveLines -Path ([string]$metadata.eventsPath))) {
            $event = ConvertFrom-Json -InputObject $line -ErrorAction Stop
            Assert-MihariTest -Condition ([string]$event.data.errorCode -ne 'upstream_route_self_reference') -Message 'No browser flow may resolve Mihari back to its own listener.'
            if ($event.data.host -eq '127.0.0.1' -and $null -ne $event.data.port) {
                Assert-MihariTest -Condition ([int]$event.data.port -ne $proxyPort) -Message 'Browser traffic must never select the Mihari proxy listener as its own upstream target.'
            }
        }

    Write-Host 'PASS issue3-edge-smoke: UI-launched Microsoft Edge sent HTTP and HTTPS fixture traffic through Mihari; observations confirm no recursive self-routing.'
}
finally {
    if ($null -ne $originClient) {
        try { $originClient.Close() }
        catch { Write-Warning ("Edge fixture client cleanup failed: {0}" -f $_.Exception.Message) }
    }
    if ($null -ne $originListener) {
        try { $originListener.Stop() }
        catch { Write-Warning ("Edge fixture listener cleanup failed: {0}" -f $_.Exception.Message) }
    }
    try { Stop-MihariIssue3EdgeProfile -ProfilePath $browserProfilePath }
    catch {
        $browserCleanupFailure = $_
        Write-Warning ("Diagnostic Edge process cleanup failed: {0}" -f $_.Exception.Message)
    }
    if ($null -ne $child -and $null -ne $metadata -and -not $child.Process.HasExited) {
        try {
            [void](Stop-MihariTestSession -Child $child -Metadata $metadata)
        }
        catch {
            $stopFailure = $_
            Write-Warning ("Issue #3 Edge smoke session cleanup failed: {0}" -f $_.Exception.Message)
        }
    }
    if ($null -ne $child) {
        if (-not $child.Process.HasExited) {
            try { $child.Process.Kill(); [void]$child.Process.WaitForExit(5000) }
            catch { Write-Warning ("Mihari process cleanup failed: {0}" -f $_.Exception.Message) }
        }
        if ($child.Process.HasExited) { $child.Process.Dispose() }
    }
    if (Test-Path -LiteralPath $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

if ($null -ne $stopFailure) { throw $stopFailure }
if ($null -ne $browserCleanupFailure) { throw $browserCleanupFailure }
