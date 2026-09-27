param()

$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') {
    Write-Warning 'The local runtime smoke suite requires Windows PowerShell/.NET socket APIs.'
    return
}

# Load the shared process, loopback fixture, framing, and report helpers without
# running the TLS/CA integration path.
. (Join-Path $PSScriptRoot 'integration.ps1') -LoadHelpersOnly

function Assert-MihariRuntimeBasicBytes {
    param(
        [Parameter(Mandatory = $true)][byte[]] $Expected,
        [Parameter(Mandatory = $true)][byte[]] $Actual,
        [Parameter(Mandatory = $true)][string] $Message
    )
    $same = $Expected.Length -eq $Actual.Length
    if ($same) {
        for ($index = 0; $index -lt $Expected.Length; $index++) {
            if ($Expected[$index] -ne $Actual[$index]) { $same = $false; break }
        }
    }
    Assert-MihariTest -Condition $same -Message $Message
}

$tempRoot = Join-Path ([IO.Path]::GetTempPath()) ('mihari-basic-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($tempRoot)
$tunnelChild = $null
$proxyStatusChild = $null
$originListener = $null
$proxyStatusListener = $null
$proxyClient = $null
$originClient = $null
$proxyStatusMetadata = $null
$finalCleanupFailures = New-Object 'System.Collections.Generic.List[string]'

try {
    # Plain HTTP proxying and binary CONNECT relay share a Tunnel session. No
    # CA, TLS fixture, or external destination is created by this suite.
    $tunnelRoot = Join-Path $tempRoot 'tunnel'
    $tunnelChild = Start-MihariTestProcess -Command start -OutputRoot $tunnelRoot -Mode Tunnel -Port 0
    $tunnelMetadata = Wait-MihariTestSession -Child $tunnelChild
    $proxyPort = [int]$tunnelMetadata.actualPort

    $originListener = New-MihariTestListener
    $originPort = ([System.Net.IPEndPoint]$originListener.LocalEndpoint).Port
    $acceptTask = $originListener.AcceptTcpClientAsync()
    $proxyClient = [System.Net.Sockets.TcpClient]::new()
    $proxyClient.Connect('127.0.0.1', $proxyPort)
    $proxyStream = $proxyClient.GetStream()
    $requestText = "GET http://127.0.0.1:$originPort/basic/http?token=basic-secret HTTP/1.1`r`nHost: 127.0.0.1:$originPort`r`nAuthorization: Bearer basic-auth-secret`r`nCookie: session=basic-cookie-secret`r`nConnection: close`r`n`r`n"
    $requestBytes = [System.Text.Encoding]::ASCII.GetBytes($requestText)
    $proxyStream.Write($requestBytes, 0, $requestBytes.Length)
    $proxyStream.Flush()
    Assert-MihariTest -Condition ($acceptTask.Wait(15000)) -Message 'HTTP proxy did not connect to the local origin fixture.'
    $originClient = $acceptTask.Result
    $originStream = $originClient.GetStream()
    $originRequest = Read-MihariTestHeaderText -Stream $originStream
    Assert-MihariTest -Condition ($originRequest.StartsWith("GET /basic/http?token=basic-secret HTTP/1.1")) -Message 'HTTP proxy must forward the origin-form path and query.'
    Assert-MihariTest -Condition ($originRequest -match '(?im)^Authorization: Bearer basic-auth-secret\r?$' -and $originRequest -match '(?im)^Cookie: session=basic-cookie-secret\r?$') -Message 'HTTP proxy must forward end-to-end credentials to the local origin.'
    Write-MihariTestHttpResponse -Stream $originStream
    $httpResponse = Read-MihariTestHttpResponse -Stream $proxyStream
    Assert-MihariTest -Condition ($httpResponse.Headers.StartsWith('HTTP/1.1 200') -and $httpResponse.Body -eq 'ok') -Message 'HTTP proxy must return the local origin response.'
    $proxyClient.Close(); $proxyClient = $null
    $originClient.Close(); $originClient = $null
    $originListener.Stop(); $originListener = $null
    $httpEvent = Wait-MihariTestEvent -EventsPath ([string]$tunnelMetadata.eventsPath) -Stage 'http.request'
    Assert-MihariTest -Condition ($httpEvent.data.path -eq '/basic/http?token=[REDACTED]') -Message 'HTTP event must retain its path while redacting the query value.'

    # The opaque tunnel fixture exchanges bytes in both directions and then
    # half-closes each side. It uses loopback TCP only, without a TLS handshake.
    $originListener = New-MihariTestListener
    $originPort = ([System.Net.IPEndPoint]$originListener.LocalEndpoint).Port
    $acceptTask = $originListener.AcceptTcpClientAsync()
    $proxyClient = [System.Net.Sockets.TcpClient]::new()
    $proxyClient.Connect('127.0.0.1', $proxyPort)
    $proxyStream = $proxyClient.GetStream()
    $connectWire = [System.Text.Encoding]::ASCII.GetBytes("CONNECT 127.0.0.1:$originPort HTTP/1.1`r`nHost: 127.0.0.1:$originPort`r`n`r`n")
    $proxyStream.Write($connectWire, 0, $connectWire.Length)
    $proxyStream.Flush()
    $connectResponse = Read-MihariTestHeaderText -Stream $proxyStream
    Assert-MihariTest -Condition ($connectResponse.StartsWith('HTTP/1.1 200')) -Message 'CONNECT Tunnel must return success after connecting to the local fixture.'
    Assert-MihariTest -Condition ($acceptTask.Wait(15000)) -Message 'CONNECT Tunnel did not connect to the local TCP fixture.'
    $originClient = $acceptTask.Result
    $originStream = $originClient.GetStream()
    $clientPayload = [byte[]]@(0, 255, 127, 13, 10, 65, 1)
    $originPayload = [byte[]]@(254, 0, 2, 128, 66)
    $proxyStream.Write($clientPayload, 0, $clientPayload.Length)
    $proxyStream.Flush()
    $proxyClient.Client.Shutdown([System.Net.Sockets.SocketShutdown]::Send)
    $forwardedPayload = Read-MihariTestExactBytes -Stream $originStream -Count $clientPayload.Length
    Assert-MihariRuntimeBasicBytes -Expected $clientPayload -Actual $forwardedPayload -Message 'CONNECT Tunnel must relay client bytes without text conversion.'
    $originStream.ReadTimeout = 15000
    Assert-MihariTest -Condition ($originStream.ReadByte() -eq -1) -Message 'CONNECT Tunnel must relay client half-close to the origin.'
    $originStream.Write($originPayload, 0, $originPayload.Length)
    $originStream.Flush()
    $originClient.Client.Shutdown([System.Net.Sockets.SocketShutdown]::Send)
    $relayedPayload = Read-MihariTestExactBytes -Stream $proxyStream -Count $originPayload.Length
    Assert-MihariRuntimeBasicBytes -Expected $originPayload -Actual $relayedPayload -Message 'CONNECT Tunnel must relay origin bytes back to the client.'
    $proxyStream.ReadTimeout = 15000
    Assert-MihariTest -Condition ($proxyStream.ReadByte() -eq -1) -Message 'CONNECT Tunnel must relay origin half-close to the client.'
    $proxyClient.Close(); $proxyClient = $null
    $originClient.Close(); $originClient = $null
    $originListener.Stop(); $originListener = $null
    $relayEvent = Wait-MihariTestEvent -EventsPath ([string]$tunnelMetadata.eventsPath) -Stage 'tunnel.relay'
    Assert-MihariTest -Condition ($relayEvent.data.bytesClientToUpstream -eq $clientPayload.Length -and $relayEvent.data.bytesUpstreamToClient -eq $originPayload.Length) -Message 'CONNECT Tunnel event must count relayed bytes in both directions.'

    $tunnelFinal = Stop-MihariTestSession -Child $tunnelChild -Metadata $tunnelMetadata
    $tunnelChild.Process.Dispose()
    $tunnelChild = $null
    Assert-MihariTest -Condition ([string]::IsNullOrEmpty([string]$tunnelFinal.caThumbprint)) -Message 'Tunnel mode must not create or trust a session CA.'
    Invoke-MihariTestReportCommand -OutputRoot $tunnelRoot
    $tunnelLines = [IO.File]::ReadAllLines([string]$tunnelFinal.eventsPath)
    Assert-MihariTest -Condition ($tunnelLines.Length -ge 8) -Message 'HTTP forwarding and CONNECT relay must emit structured observations.'
    foreach ($line in $tunnelLines) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $event = ConvertFrom-Json -InputObject $line -ErrorAction Stop
        Assert-MihariTest -Condition ($event.schemaVersion -eq 1 -and $event.timestamp -and $event.sessionId -and $event.connectionId -and $event.mode -and $event.stage -and $event.outcome -and $null -ne $event.elapsedMs) -Message 'Every basic-session JSONL event must have the required envelope.'
    }
    $tunnelEventText = [string]::Join("`n", $tunnelLines)
    foreach ($secret in @('basic-secret', 'basic-auth-secret', 'basic-cookie-secret')) {
        Assert-MihariTest -Condition (-not $tunnelEventText.Contains($secret)) -Message 'Basic-session JSONL must not retain query values or credential headers.'
    }
    $tunnelReport = ConvertFrom-Json -InputObject ([IO.File]::ReadAllText([string]$tunnelFinal.reportJsonPath)) -ErrorAction Stop
    Assert-MihariTest -Condition ($tunnelReport.eventCount -ge 8 -and [IO.File]::Exists([string]$tunnelFinal.reportTextPath)) -Message 'Basic Tunnel stop must generate JSON and text reports.'

    # A local explicit proxy fixture returns concrete 407 and 403 responses.
    $proxyStatusListener = New-MihariTestListener
    $proxyStatusPort = ([System.Net.IPEndPoint]$proxyStatusListener.LocalEndpoint).Port
    $proxyStatusRoot = Join-Path $tempRoot 'explicit-proxy'
    $proxyStatusChild = Start-MihariTestProcess -Command start -OutputRoot $proxyStatusRoot -Mode Tunnel -Port 0 -UpstreamProxy ("http://127.0.0.1:{0}" -f $proxyStatusPort)
    $proxyStatusMetadata = Wait-MihariTestSession -Child $proxyStatusChild
    [void](Invoke-MihariTestExplicitProxyStatus -ProxyListener $proxyStatusListener -MihariPort ([int]$proxyStatusMetadata.actualPort) -StatusCode 407)
    [void](Wait-MihariTestEvent -EventsPath ([string]$proxyStatusMetadata.eventsPath) -Stage 'upstream.proxy.connect')
    [void](Invoke-MihariTestExplicitProxyStatus -ProxyListener $proxyStatusListener -MihariPort ([int]$proxyStatusMetadata.actualPort) -StatusCode 403 -ProxyAuthorization 'Basic proxy-secret')
    [void](Wait-MihariTestEvent -EventsPath ([string]$proxyStatusMetadata.eventsPath) -Stage 'upstream.proxy.connect')
    $proxyStatusFinal = Stop-MihariTestSession -Child $proxyStatusChild -Metadata $proxyStatusMetadata
    $proxyStatusChild.Process.Dispose()
    $proxyStatusChild = $null
    Invoke-MihariTestReportCommand -OutputRoot $proxyStatusRoot

    $proxyEventIds = @{}
    $observedProxyStatuses = New-Object 'System.Collections.Generic.List[int]'
    $proxyEventLines = [IO.File]::ReadAllLines([string]$proxyStatusFinal.eventsPath)
    foreach ($line in $proxyEventLines) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        Assert-MihariTest -Condition (-not $line.Contains('proxy-secret')) -Message 'JSONL must not retain an explicit proxy credential.'
        $event = ConvertFrom-Json -InputObject $line -ErrorAction Stop
        if ($event.stage -eq 'upstream.proxy.connect') {
            $observedProxyStatuses.Add([int]$event.data.proxyStatus)
            $proxyEventIds[[string]$event.data.proxyStatus] = [string]$event.eventId
        }
    }
    Assert-MihariTest -Condition ($observedProxyStatuses -contains 407 -and $observedProxyStatuses -contains 403) -Message 'JSONL must preserve concrete upstream proxy 407 and 403 facts.'
    $proxyReport = ConvertFrom-Json -InputObject ([IO.File]::ReadAllText([string]$proxyStatusFinal.reportJsonPath)) -ErrorAction Stop
    $proxyFindingCodes = @($proxyReport.findings | ForEach-Object { $_.code })
    Assert-MihariTest -Condition ($proxyFindingCodes -contains 'upstream_proxy_auth_required' -and $proxyFindingCodes -contains 'upstream_proxy_rejected') -Message 'Reports must diagnose explicit proxy 407 and 403 responses.'
    Assert-MihariTest -Condition (@($proxyReport.findings | Where-Object { $_.code -eq 'upstream_proxy_auth_required' -and $_.evidenceIds -contains $proxyEventIds['407'] }).Count -eq 1) -Message 'The 407 report finding must cite its event evidence.'
    Assert-MihariTest -Condition (@($proxyReport.findings | Where-Object { $_.code -eq 'upstream_proxy_rejected' -and $_.evidenceIds -contains $proxyEventIds['403'] }).Count -eq 1) -Message 'The 403 report finding must cite its event evidence.'

    Write-Host 'PASS runtime-basic: start/stop, HTTP forwarding, binary CONNECT relay, JSONL privacy, reports, explicit 403/407 evidence'
}
finally {
    foreach ($client in @($proxyClient, $originClient)) {
        if ($null -ne $client) { try { $client.Close() } catch { $finalCleanupFailures.Add("Loopback socket cleanup failed: $($_.Exception.Message)") } }
    }
    if ($null -ne $originListener) { try { $originListener.Stop() } catch { $finalCleanupFailures.Add("Loopback fixture listener cleanup failed: $($_.Exception.Message)") } }
    if ($null -ne $proxyStatusListener) { try { $proxyStatusListener.Stop() } catch { $finalCleanupFailures.Add("Explicit proxy fixture cleanup failed: $($_.Exception.Message)") } }
    foreach ($child in @($tunnelChild, $proxyStatusChild)) {
        if ($null -eq $child) { continue }
        try {
            $active = $null
            $activePath = Join-Path $child.OutputRoot 'active-session.json'
            if ([IO.File]::Exists($activePath)) {
                try { $active = ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($activePath)) }
                catch { $finalCleanupFailures.Add("Could not read session metadata during cleanup: $($_.Exception.Message)") }
            }
            if (-not $child.Process.HasExited) {
                if ($null -ne $active -and -not $child.StopAttempted) {
                    try { Stop-MihariTestSession -Child $child -Metadata $active | Out-Null }
                    catch { $finalCleanupFailures.Add("Mihari basic-session cleanup failed: $($_.Exception.Message)") }
                }
                if (-not $child.Process.HasExited) {
                    try { $child.Process.Kill(); $child.Process.WaitForExit(5000) }
                    catch { $finalCleanupFailures.Add("Mihari basic-session process cleanup failed: $($_.Exception.Message)") }
                }
            }
            if ($child.Process.HasExited) { $child.Process.Dispose() }
        }
        catch { $finalCleanupFailures.Add("Mihari basic-session cleanup failed: $($_.Exception.Message)") }
    }
    try { Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction Stop }
    catch { $finalCleanupFailures.Add("Could not remove the basic-session output directory: $($_.Exception.Message)") }
}

if ($finalCleanupFailures.Count -gt 0) {
    throw ('Basic runtime test cleanup failed: ' + ($finalCleanupFailures -join '; '))
}
