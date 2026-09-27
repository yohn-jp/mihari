param()

$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') {
    Write-Warning 'The owned Edge HTTP/2 observation test requires Windows.'
    return
}

. (Join-Path $PSScriptRoot 'TestSupport.ps1')
. (Join-Path $PSScriptRoot 'integration.ps1') -LoadHelpersOnly
. (Join-Path (Split-Path $PSScriptRoot -Parent) 'src/Browser.ps1')
. (Join-Path (Split-Path $PSScriptRoot -Parent) 'src/Certificate.ps1')

function Start-MihariH2FixtureProcess {
    param(
        [Parameter(Mandatory = $true)][string] $PwshPath,
        [Parameter(Mandatory = $true)][string] $ReadyPath,
        [Parameter(Mandatory = $true)][string] $StopPath,
        [Parameter(Mandatory = $true)][string] $TransactionsPath,
        [Parameter(Mandatory = $true)][string] $ErrorPath
    )

    $info = New-Object System.Diagnostics.ProcessStartInfo
    $info.FileName = $PwshPath
    $scriptPath = Join-Path $PSScriptRoot 'h2-browser-origin.ps1'
    $arguments = @('-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File',
        (ConvertTo-MihariTestProcessArgument -Value $scriptPath),
        '-ReadyPath', (ConvertTo-MihariTestProcessArgument -Value $ReadyPath),
        '-StopPath', (ConvertTo-MihariTestProcessArgument -Value $StopPath),
        '-TransactionsPath', (ConvertTo-MihariTestProcessArgument -Value $TransactionsPath),
        '-ErrorPath', (ConvertTo-MihariTestProcessArgument -Value $ErrorPath))
    $info.Arguments = [string]::Join(' ', $arguments)
    $info.WorkingDirectory = Split-Path $PSScriptRoot -Parent
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    foreach ($name in @('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy')) {
        $info.EnvironmentVariables.Remove($name)
    }
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $info
    if (-not $process.Start()) { throw 'Could not start the PowerShell 7 local h2 fixture.' }
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    return [pscustomobject]@{ Process = $process; Stdout = $stdout; Stderr = $stderr }
}

function Start-MihariH2ProfileSession {
    param([Parameter(Mandatory = $true)][string] $OutputRoot, [int] $Port = 0)

    $executableName = 'powershell.exe'
    if ($PSVersionTable.PSEdition -eq 'Core') { $executableName = 'pwsh.exe' }
    $executablePath = Join-Path $PSHOME $executableName
    $info = New-Object System.Diagnostics.ProcessStartInfo
    $info.FileName = $executablePath
    $arguments = @('-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File',
        (ConvertTo-MihariTestProcessArgument -Value (Join-Path (Split-Path $PSScriptRoot -Parent) 'mihari.ps1')),
        'start', '-Mode', 'Tunnel', '-Profile', 'http2-observe', '-Port', [string]$Port, '-OutputRoot',
        (ConvertTo-MihariTestProcessArgument -Value $OutputRoot))
    $info.Arguments = [string]::Join(' ', $arguments)
    $info.WorkingDirectory = Split-Path $PSScriptRoot -Parent
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    foreach ($name in @('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy')) {
        $info.EnvironmentVariables.Remove($name)
    }
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $info
    if (-not $process.Start()) { throw 'Could not start the Mihari h2 Tunnel session.' }
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    return [pscustomobject]@{ Process = $process; Stdout = $stdout; Stderr = $stderr; OutputRoot = $OutputRoot }
}

function Invoke-MihariH2BrowserLaunch {
    param([Parameter(Mandatory = $true)][string] $Uri)

    $metadataPath = Join-Path $script:sessionMetadata.outputDirectory 'session.json'
    $liveMetadata = ConvertFrom-Json -InputObject (Read-MihariTestLiveText -Path $metadataPath) -ErrorAction Stop
    $authority = 'http://127.0.0.1:{0}' -f [int]$liveMetadata.actualManagementPort
    $pageRequest = [System.Net.HttpWebRequest]::Create($authority + '/')
    $pageRequest.Proxy = $null
    $pageRequest.Method = 'GET'
    $pageRequest.Timeout = 20000
    $pageResponse = $pageRequest.GetResponse()
    try {
        $pageReader = [System.IO.StreamReader]::new($pageResponse.GetResponseStream(), [System.Text.Encoding]::UTF8)
        try { $pageText = $pageReader.ReadToEnd() }
        finally { $pageReader.Dispose() }
    }
    finally { $pageResponse.Dispose() }
    $controlTokenMatch = [regex]::Match($pageText, 'var CONTROL_TOKEN="(?<token>[A-Za-z0-9_-]+)";')
    if (-not $controlTokenMatch.Success) { throw 'The active Mihari page did not provide its in-memory browser-action token.' }

    $endpoint = $authority + '/api/browser'
    $request = [System.Net.HttpWebRequest]::Create($endpoint)
    $request.Proxy = $null
    $request.Method = 'POST'
    $request.ServicePoint.Expect100Continue = $false
    $request.KeepAlive = $false
    $request.ContentType = 'application/json; charset=utf-8'
    $request.Timeout = 20000
    $request.ReadWriteTimeout = 20000
    $request.Headers['X-Mihari-Control-Token'] = $controlTokenMatch.Groups['token'].Value
    $body = [System.Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject @{ url = $Uri } -Compress -Depth 3))
    $request.ContentLength = $body.Length
    $requestStream = $request.GetRequestStream()
    try { $requestStream.Write($body, 0, $body.Length); $requestStream.Flush() }
    finally { $requestStream.Dispose() }
    $response = $request.GetResponse()
    try {
        $reader = [System.IO.StreamReader]::new($response.GetResponseStream(), [System.Text.Encoding]::UTF8)
        try { return (ConvertFrom-Json -InputObject $reader.ReadToEnd() -ErrorAction Stop) }
        finally { $reader.Dispose() }
    }
    finally { $response.Dispose() }
}

function Wait-MihariBrowserH2Event {
    param(
        [Parameter(Mandatory = $true)][string] $EventsPath,
        [Parameter(Mandatory = $true)][int] $OriginPort,
        [Parameter(Mandatory = $true)][string] $TransactionsPath,
        [AllowNull()][string] $ObservationStatus,
        [int] $TimeoutSeconds = 30
    )

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        foreach ($line in (Read-MihariTestCompleteLiveLines -Path $EventsPath)) {
            $event = ConvertFrom-Json -InputObject $line -ErrorAction Stop
            if ($event.source -eq 'browser' -and $event.stage -eq 'browser.network.request' -and
                $event.mode -eq 'Tunnel' -and $event.data.scheme -eq 'https' -and $event.data.host -eq 'localhost' -and
                [int]$event.data.port -eq $OriginPort -and $event.data.path -eq '/' -and
                $event.data.protocol -eq 'h2' -and $event.data.statusCode -eq 200 -and
                $event.data.initiatorType -eq 'script') {
                return $event
            }
        }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    $diagnostics = Get-MihariBrowserH2TimeoutDiagnostics -EventsPath $EventsPath -TransactionsPath $TransactionsPath -OriginPort $OriginPort -ObservationStatus $ObservationStatus
    $diagnosticJson = ConvertTo-Json -InputObject $diagnostics -Depth 6 -Compress
    if ($diagnosticJson.Length -gt 6000) { $diagnosticJson = $diagnosticJson.Substring(0, 6000) }
    Write-Warning ('Safe local h2 observation timeout summary: ' + $diagnosticJson)
    throw 'The owned Edge observer did not record the local h2 fetch as a browser-originated request.'
}

function Get-MihariBrowserH2TimeoutDiagnostics {
    param(
        [Parameter(Mandatory = $true)][string] $EventsPath,
        [Parameter(Mandatory = $true)][string] $TransactionsPath,
        [Parameter(Mandatory = $true)][int] $OriginPort,
        [AllowNull()][string] $ObservationStatus
    )

    $eventSummary = New-Object 'System.Collections.Generic.List[object]'
    if ([IO.File]::Exists($EventsPath)) {
        foreach ($line in (Read-MihariTestCompleteLiveLines -Path $EventsPath | Select-Object -Last 512)) {
            try { $event = ConvertFrom-Json -InputObject $line -ErrorAction Stop }
            catch { continue }
            $data = $event.data
            $stage = [string]$event.stage
            $browserHealth = ([string]$event.source -eq 'browser' -and $stage -eq 'browser.observation')
            $originTraffic = ([string]$data.host -eq 'localhost' -and [string]$data.port -eq [string]$OriginPort)
            if (-not $browserHealth -and -not $originTraffic) { continue }
            $summary = [pscustomobject][ordered]@{
                source = [string]$event.source; stage = $stage; outcome = [string]$event.outcome; coverage = [string]$event.coverage
                host = [string]$data.host; port = $data.port; path = [string]$data.path; method = [string]$data.method
                protocol = [string]$data.protocol; statusCode = $data.statusCode; initiatorType = [string]$data.initiatorType
                browserError = [string]$data.browserError; errorType = [string]$data.errorType
                bytesClientToUpstream = $data.bytesClientToUpstream
                bytesUpstreamToClient = $data.bytesUpstreamToClient
            }
            if ($eventSummary.Count -ge 24) { $eventSummary.RemoveAt(0) }
            [void]$eventSummary.Add($summary)
        }
    }
    $transactions = New-Object 'System.Collections.Generic.List[object]'
    if ([IO.File]::Exists($TransactionsPath)) {
        foreach ($line in (Read-MihariTestCompleteLiveLines -Path $TransactionsPath | Select-Object -Last 16)) {
            try { $transaction = ConvertFrom-Json -InputObject $line -ErrorAction Stop }
            catch { continue }
            [void]$transactions.Add([pscustomobject][ordered]@{
                alpnProtocol = [string]$transaction.alpnProtocol; requestPathRootObserved = [bool]$transaction.requestPathRootObserved
                responseStatus = $transaction.responseStatus; responseHeadersSent = [bool]$transaction.responseHeadersSent
                responseBodyBytes = $transaction.responseBodyBytes
            })
        }
    }
    return [pscustomobject][ordered]@{
        observationStatus = $ObservationStatus; originPort = $OriginPort
        events = [object[]]$eventSummary.ToArray(); fixtureTransactions = [object[]]$transactions.ToArray()
    }
}

function Wait-MihariBrowserH2TunnelEvidence {
    param(
        [Parameter(Mandatory = $true)][string] $EventsPath,
        [Parameter(Mandatory = $true)][int] $OriginPort,
        [Parameter(Mandatory = $true)][string] $TransactionsPath,
        [AllowNull()][string] $ObservationStatus,
        [int] $TimeoutSeconds = 20
    )

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $events = @(Read-MihariTestCompleteLiveLines -Path $EventsPath | ForEach-Object { ConvertFrom-Json -InputObject $_ -ErrorAction Stop })
        $connects = @($events | Where-Object {
            $_.source -eq 'proxy' -and $_.mode -eq 'Tunnel' -and $_.stage -eq 'proxy.request' -and $_.outcome -eq 'success' -and
            $_.data.method -eq 'CONNECT' -and $_.data.host -eq 'localhost' -and [int]$_.data.port -eq $OriginPort
        })
        $relays = @($events | Where-Object {
            $_.source -eq 'proxy' -and $_.mode -eq 'Tunnel' -and $_.stage -eq 'tunnel.relay' -and $_.outcome -eq 'success' -and
            $_.data.host -eq 'localhost' -and [int]$_.data.port -eq $OriginPort -and
            [long]$_.data.bytesClientToUpstream -gt 0 -and [long]$_.data.bytesUpstreamToClient -gt 0
        })
        foreach ($relay in $relays) {
            $connect = $null
            foreach ($candidate in $connects) {
                if ([string]$candidate.connectionId -ceq [string]$relay.connectionId -and
                    [string]$candidate.requestId -ceq [string]$relay.requestId) { $connect = $candidate; break }
            }
            if ($null -ne $connect) {
                return [pscustomobject]@{ Connect = $connect; Relay = $relay }
            }
        }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    $diagnostics = Get-MihariBrowserH2TimeoutDiagnostics -EventsPath $EventsPath -TransactionsPath $TransactionsPath `
        -OriginPort $OriginPort -ObservationStatus $ObservationStatus
    $diagnosticJson = ConvertTo-Json -InputObject $diagnostics -Depth 6 -Compress
    if ($diagnosticJson.Length -gt 6000) { $diagnosticJson = $diagnosticJson.Substring(0, 6000) }
    Write-Warning ('Safe local h2 tunnel summary: ' + $diagnosticJson)
    throw 'The local h2 fixture did not produce a matching Mihari CONNECT and positive tunnel relay evidence pair.'
}

function Stop-MihariH2OwnedEdgeProfile {
    param(
        [Parameter(Mandatory = $true)][string] $SessionId,
        [Parameter(Mandatory = $true)][string] $ProfilePath,
        [Parameter(Mandatory = $true)][int] $ProcessId
    )

    if ([string]::IsNullOrWhiteSpace($ProfilePath) -or $ProcessId -lt 1) { return }
    $markerPath = Join-Path $ProfilePath 'MihariProfileOwner.json'
    if (-not [IO.File]::Exists($markerPath)) { throw 'Owned Edge cleanup marker is missing.' }
    $marker = ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($markerPath, [Text.Encoding]::UTF8)) -ErrorAction Stop
    $launch = [pscustomobject]@{
        Pid = $ProcessId
        ProfilePath = $ProfilePath
        Path = [string]$marker.executablePath
        OwnerStartTimeUtc = [string]$marker.processStartTimeUtc
    }
    if (-not (Test-MihariBrowserOwnedProcess -SessionId $SessionId -Launch $launch)) {
        throw 'Edge profile cleanup refused an unverified process identity.'
    }
    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    do {
        $processes = @(Get-CimInstance -ClassName Win32_Process -Filter "Name = 'msedge.exe'" -ErrorAction Stop |
            Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_.CommandLine) -and
                ([string]$_.CommandLine).IndexOf($ProfilePath, [StringComparison]::OrdinalIgnoreCase) -ge 0 })
        foreach ($processInfo in $processes) {
            try { Stop-Process -Id ([int]$processInfo.ProcessId) -Force -ErrorAction Stop }
            catch {
                $stillOwned = @(Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $([int]$processInfo.ProcessId)" -ErrorAction SilentlyContinue |
                    Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_.CommandLine) -and
                        ([string]$_.CommandLine).IndexOf($ProfilePath, [StringComparison]::OrdinalIgnoreCase) -ge 0 })
                if ($stillOwned.Count -gt 0) { throw 'Could not stop an Edge process using the exact diagnostic profile.' }
            }
        }
        if ($processes.Count -eq 0) { break }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    $remaining = @(Get-CimInstance -ClassName Win32_Process -Filter "Name = 'msedge.exe'" -ErrorAction Stop |
        Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_.CommandLine) -and
            ([string]$_.CommandLine).IndexOf($ProfilePath, [StringComparison]::OrdinalIgnoreCase) -ge 0 })
    if ($remaining.Count -gt 0) { throw 'Edge retained processes for its exact diagnostic profile after cleanup.' }
    $removed = Remove-MihariOwnedBrowserProfile -SessionId $SessionId -ProfilePath $ProfilePath
    if (-not $removed.removed) { throw ('Owned Edge profile cleanup failed: ' + [string]$removed.reason) }
}

$pwshCommand = Get-Command pwsh.exe -CommandType Application -ErrorAction SilentlyContinue
if ($null -eq $pwshCommand) { throw 'PowerShell 7 is required for the local managed TLS/ALPN h2 fixture.' }
$tempRoot = Join-Path ([IO.Path]::GetTempPath()) ('mihari-browser-h2-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($tempRoot)
$readyPath = Join-Path $tempRoot 'fixture-ready.json'
$stopPath = Join-Path $tempRoot 'fixture-stop'
$transactionsPath = Join-Path $tempRoot 'fixture-transactions.jsonl'
$fixtureErrorPath = Join-Path $tempRoot 'fixture-error.json'
$fixture = $null
$fixtureReady = $null
$fixtureRoot = $null
$fixtureRootPublic = $null
$fixtureInstalledRoot = $null
$sessionChild = $null
$sessionMetadata = $null
$browserLaunch = $null
$diagnosticProfilePath = $null
$diagnosticProcessId = 0
$cleanupFailures = New-Object 'System.Collections.Generic.List[string]'
try {
    $fixture = Start-MihariH2FixtureProcess -PwshPath $pwshCommand.Source -ReadyPath $readyPath -StopPath $stopPath `
        -TransactionsPath $transactionsPath -ErrorPath $fixtureErrorPath
    $readyDeadline = [DateTime]::UtcNow.AddSeconds(30)
    do {
        if ($fixture.Process.HasExited) {
            throw ('Local h2 fixture exited early ({0}). stderr={1}' -f $fixture.Process.ExitCode, $fixture.Stderr.Result)
        }
        if ([IO.File]::Exists($readyPath)) { break }
        if ([IO.File]::Exists($fixtureErrorPath)) { throw ('Local h2 fixture failed: ' + [IO.File]::ReadAllText($fixtureErrorPath)) }
        Start-Sleep -Milliseconds 50
    } while ([DateTime]::UtcNow -lt $readyDeadline)
    Assert-MihariTest -Condition ([IO.File]::Exists($readyPath)) -Message 'Local h2 fixture did not publish its loopback endpoint.'
    $fixtureReady = ConvertFrom-Json -InputObject (Read-MihariTestLiveText -Path $readyPath) -ErrorAction Stop
    $fixtureRootPublic = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
        [IO.File]::ReadAllBytes([string]$fixtureReady.publicCertificatePath)
    )
    $fixtureRoot = [pscustomobject]@{ Certificate = $fixtureRootPublic; Thumbprint = [string]$fixtureReady.caThumbprint }
    Assert-MihariTest -Condition (Test-MihariCAOwnership -Certificate $fixtureRootPublic -Thumbprint ([string]$fixtureReady.caThumbprint)) -Message 'The fixture root must have positive Mihari ownership markers.'
    $fixtureInstalledRoot = Invoke-MihariTestRootConfirmation -Operation Add -Action { Install-MihariCARoot -CA $fixtureRoot }

    $outputRoot = Join-Path $tempRoot 'mihari-session'
    $sessionChild = Start-MihariH2ProfileSession -OutputRoot $outputRoot
    $sessionMetadata = Wait-MihariTestSession -Child $sessionChild
    Assert-MihariTest -Condition ($sessionMetadata.mode -eq 'Tunnel' -and $sessionMetadata.profile -eq 'http2-observe') -Message 'The h2 trial must use an immutable HTTP/2 observe Tunnel profile.'
    $originUrl = 'https://localhost:{0}/' -f [int]$fixtureReady.port
    $browserLaunch = Invoke-MihariH2BrowserLaunch -Uri $originUrl
    Assert-MihariTest -Condition ([bool]$browserLaunch.success -and $browserLaunch.proxyEndpoint -eq ('http://127.0.0.1:{0}' -f [int]$sessionMetadata.actualPort)) -Message 'The live Management browser action must launch the Mihari-owned diagnostic Edge profile through Mihari.'
    $browserEvent = Wait-MihariBrowserH2Event -EventsPath ([string]$sessionMetadata.eventsPath) `
        -OriginPort ([int]$fixtureReady.port) -TransactionsPath $transactionsPath -ObservationStatus ([string]$browserLaunch.observationStatus)

    $launchPath = Join-Path ([string]$sessionMetadata.outputDirectory) 'browser-launch.json'
    Assert-MihariTest -Condition ([IO.File]::Exists($launchPath)) -Message 'The diagnostic browser launch profile must be persisted.'
    $launchJson = Read-MihariTestLiveText -Path $launchPath
    $launchMetadata = ConvertFrom-Json -InputObject $launchJson -ErrorAction Stop
    $diagnosticProfilePath = [string]$launchMetadata.profilePath
    $diagnosticProcessId = [int]$launchMetadata.processId
    Assert-MihariTest -Condition ($launchMetadata.profile -eq 'http2-observe' -and $launchMetadata.requestedRemoteDebugging -and $launchMetadata.requestedHttp2Enabled -and
        $launchMetadata.requestedTlsPolicy -eq 'system_default' -and $launchMetadata.proxyBehaviorVerification -eq 'launched_but_unverified') -Message 'The launch record must distinguish requested h2 profile settings from verified behavior.'
    Assert-MihariTest -Condition ($browserEvent.source -eq 'browser' -and $browserEvent.sourceVersion -like 'Edge/*' -and
        $browserEvent.coverage -eq 'observed' -and $browserEvent.data.protocol -eq 'h2' -and
        $browserEvent.data.browserRequestId -match '^br-' -and $browserEvent.data.browserTargetId -match '^bt-' -and
        $browserEvent.data.browserFrameId -match '^bf-' -and $browserEvent.data.browserConnectionId -match '^bc-') -Message 'The browser event must contain actual Edge h2 evidence and only scoped identifiers.'
    Assert-MihariTest -Condition ($null -ne $browserEvent.elapsedMs -and $browserEvent.elapsedMs -ge 0 -and
        $browserEvent.data.browserTimingOrigin -eq 'cdp_monotonic') -Message 'The browser request must report timing only when CDP supplies paired monotonic values.'

    $transactionsDeadline = [DateTime]::UtcNow.AddSeconds(15)
    do {
        if ([IO.File]::Exists($transactionsPath)) {
            $transactions = @(Read-MihariTestCompleteLiveLines -Path $transactionsPath | ForEach-Object { ConvertFrom-Json -InputObject $_ -ErrorAction Stop })
            if (@($transactions | Where-Object { $_.alpnProtocol -eq 'h2' -and $_.requestPathRootObserved -and $_.responseStatus -eq 200 -and $_.responseHeadersSent }).Count -ge 2) { break }
        }
        if ([IO.File]::Exists($fixtureErrorPath)) { throw ('Local h2 fixture failed: ' + [IO.File]::ReadAllText($fixtureErrorPath)) }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $transactionsDeadline)
    Assert-MihariTest -Condition (@($transactions | Where-Object { $_.alpnProtocol -eq 'h2' -and $_.requestPathRootObserved -and $_.responseStatus -eq 200 -and $_.responseHeadersSent }).Count -ge 2) -Message 'The local TLS endpoint must receive real h2 HEADERS for `/` and send h2 200 responses through the opaque CONNECT tunnel.'

    $tunnelEvidence = Wait-MihariBrowserH2TunnelEvidence -EventsPath ([string]$sessionMetadata.eventsPath) `
        -OriginPort ([int]$fixtureReady.port) -TransactionsPath $transactionsPath -ObservationStatus ([string]$browserLaunch.observationStatus)
    Assert-MihariTest -Condition ($tunnelEvidence.Connect.data.method -eq 'CONNECT' -and
        $tunnelEvidence.Connect.data.host -eq 'localhost' -and [int]$tunnelEvidence.Connect.data.port -eq [int]$fixtureReady.port -and
        $tunnelEvidence.Relay.outcome -eq 'success' -and [long]$tunnelEvidence.Relay.data.bytesClientToUpstream -gt 0 -and
        [long]$tunnelEvidence.Relay.data.bytesUpstreamToClient -gt 0) -Message 'The same host and port must have positive browser-to-origin and origin-to-browser tunnel relay evidence.'

    Write-Host ('PASS browser-observation-edge: Edge reported h2 for {0}; Mihari CONNECT and bidirectional Tunnel relay facts matched the local fixture.' -f [string]$browserEvent.data.path)
}
finally {
    [IO.File]::WriteAllText($stopPath, 'stop', [Text.Encoding]::ASCII)
    if ($null -ne $sessionChild -and -not $sessionChild.Process.HasExited) {
        if ($null -ne $sessionMetadata) {
            try { Stop-MihariTestSession -Child $sessionChild -Metadata $sessionMetadata }
            catch { $cleanupFailures.Add(('Mihari h2 session cleanup: ' + $_.Exception.Message)) }
        }
        else {
            try { $sessionChild.Process.Kill(); $sessionChild.Process.WaitForExit(5000) }
            catch { $cleanupFailures.Add(('Mihari h2 startup cleanup: ' + $_.Exception.GetType().FullName)) }
        }
    }
    if ($null -ne $sessionMetadata -and -not [string]::IsNullOrWhiteSpace([string]$diagnosticProfilePath)) {
        try { Stop-MihariH2OwnedEdgeProfile -SessionId ([string]$sessionMetadata.sessionId) -ProfilePath $diagnosticProfilePath -ProcessId $diagnosticProcessId }
        catch { $cleanupFailures.Add(('Owned Edge profile cleanup: ' + $_.Exception.Message)) }
    }
    if ($null -ne $fixture -and -not $fixture.Process.HasExited) {
        $deadline = [DateTime]::UtcNow.AddSeconds(15)
        while (-not $fixture.Process.WaitForExit(100) -and [DateTime]::UtcNow -lt $deadline) { }
        if (-not $fixture.Process.HasExited) {
            try { $fixture.Process.Kill(); $fixture.Process.WaitForExit(3000) }
            catch { $cleanupFailures.Add(('Local h2 fixture process cleanup: ' + $_.Exception.GetType().FullName)) }
        }
        if ($fixture.Process.HasExited -and $fixture.Process.ExitCode -ne 0) {
            $cleanupFailures.Add(('Local h2 fixture exited with {0}; stderr={1}' -f $fixture.Process.ExitCode, $fixture.Stderr.Result))
        }
    }
    if ($null -ne $fixtureReady) {
        if (-not (Test-MihariTestThumbprintAbsent -Thumbprint ([string]$fixtureReady.leafThumbprint))) {
            $cleanupFailures.Add('The local h2 fixture leaf certificate remained in a certificate store.')
        }
        if (-not (Test-MihariTestNoLeavesForIssuer -IssuerSubject ([string]$fixtureReady.caSubject))) {
            $cleanupFailures.Add('The local h2 fixture left an issued leaf certificate in a certificate store.')
        }
    }
    if ($null -ne $fixtureReady -and -not (Test-MihariTestThumbprintAbsent -Thumbprint ([string]$fixtureReady.caThumbprint))) {
        try {
            $removed = Invoke-MihariTestRootConfirmation -Operation Remove -Action {
                Remove-MihariCARoot -Thumbprint ([string]$fixtureReady.caThumbprint) -Subject ([string]$fixtureReady.caSubject)
            }
            if ($removed -ne 1) { $cleanupFailures.Add(('Local h2 fixture root cleanup removed {0} certificates.' -f $removed)) }
            if (-not (Test-MihariTestThumbprintAbsent -Thumbprint ([string]$fixtureReady.caThumbprint))) {
                $cleanupFailures.Add('Local h2 fixture root remains in CurrentUser Root.')
            }
        }
        catch { $cleanupFailures.Add(('Local h2 fixture root cleanup: ' + $_.Exception.Message)) }
    }
    if ($null -ne $fixtureInstalledRoot) { $fixtureInstalledRoot.Dispose() }
    if ($null -ne $fixtureRootPublic) { $fixtureRootPublic.Dispose() }
    if ($null -ne $fixture) { $fixture.Process.Dispose() }
    Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    if ($cleanupFailures.Count -gt 0) { throw ('Browser h2 test cleanup failed: ' + ($cleanupFailures -join '; ')) }
}
