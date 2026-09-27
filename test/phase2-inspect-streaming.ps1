param()

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'integration.ps1') -LoadHelpersOnly
if ($env:OS -ne 'Windows_NT') {
    Write-Warning 'Inspect streaming requires the Windows certificate and TLS fixture.'
    return
}

$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('mihari-inspect-stream-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($testRoot)
$identity = $null
$child = $null
$metadata = $null
$addOperator = $null
$originListener = $null
$originClient = $null
$originTls = $null
$proxyClient = $null
$proxyTls = $null
$final = $null
$cleanupErrors = New-Object 'System.Collections.Generic.List[string]'
try {
    $identity = New-MihariTestFixtureTlsIdentity
    $child = Start-MihariTestProcess -Command start -OutputRoot $testRoot -Mode Inspect -Port 0
    $addOperator = Start-MihariTestRootConfirmation -Operation Add -TargetProcessId $child.Process.Id
    $metadata = Wait-MihariTestSession -Child $child
    Complete-MihariTestRootConfirmation -Operator $addOperator
    Stop-MihariTestRootConfirmation -Operator $addOperator
    $addOperator = $null

    $originListener = New-MihariTestListener
    $originPort = ([System.Net.IPEndPoint]$originListener.LocalEndpoint).Port
    $acceptTask = $originListener.AcceptTcpClientAsync()
    $proxyClient = [System.Net.Sockets.TcpClient]::new()
    $proxyClient.Connect('127.0.0.1', [int]$metadata.actualPort)
    $proxyStream = $proxyClient.GetStream()
    $connectWire = [Text.Encoding]::ASCII.GetBytes("CONNECT 127.0.0.1:$originPort HTTP/1.1`r`nHost: 127.0.0.1:$originPort`r`n`r`n")
    $proxyStream.Write($connectWire, 0, $connectWire.Length)
    $proxyStream.Flush()
    $connectReply = Read-MihariTestHeaderText -Stream $proxyStream -Context 'Inspect streaming CONNECT'
    Assert-MihariTest -Condition ($connectReply.StartsWith('HTTP/1.1 200')) -Message 'Inspect streaming fixture must establish CONNECT.'
    $proxyTls = [System.Net.Security.SslStream]::new($proxyStream, $true)
    $clientAuth = Begin-MihariTestTlsClientAuthentication -Stream $proxyTls -TargetHost '127.0.0.1'
    Complete-MihariTestTlsAuthentication -ClientStream $proxyTls -ClientResult $clientAuth

    $bodyLength = 34 * 1024 * 1024
    $body = [byte[]]::new($bodyLength)
    $requestWire = [Text.Encoding]::ASCII.GetBytes("POST /large HTTP/1.1`r`nHost: 127.0.0.1:$originPort`r`nContent-Length: $bodyLength`r`nConnection: keep-alive`r`n`r`n")
    $proxyTls.Write($requestWire, 0, $requestWire.Length)
    $proxyTls.Flush()
    $bodyWrite = $proxyTls.BeginWrite($body, 0, $body.Length, $null, $null)

    Assert-MihariTest -Condition ($acceptTask.Wait(15000)) -Message 'Inspect must open upstream before buffering a 34 MiB request body.'
    $originClient = $acceptTask.Result
    $originTls = [System.Net.Security.SslStream]::new($originClient.GetStream(), $true)
    $serverAuth = Begin-MihariTestTlsServerAuthentication -Stream $originTls -Certificate $identity.Leaf
    Complete-MihariTestTlsAuthentication -ServerStream $originTls -ServerResult $serverAuth
    $firstHead = Read-MihariTestHeaderText -Stream $originTls -Context 'streamed Inspect request'
    Assert-MihariTest -Condition ($firstHead.StartsWith('POST /large HTTP/1.1')) -Message 'Inspected request headers must reach origin before body completion.'
    Assert-MihariTest -Condition ($firstHead -match '(?im)^Content-Length: 35651584\r?$') -Message 'The large request framing must be preserved.'
    $readBuffer = [byte[]]::new(65536)
    [long]$received = 0
    while ($received -lt $bodyLength) {
        $wanted = [int][Math]::Min([long]$readBuffer.Length, ([long]$bodyLength - $received))
        $read = $originTls.Read($readBuffer, 0, $wanted)
        if ($read -le 0) { throw 'The inspected upload ended before its declared length.' }
        $received += $read
    }
    $proxyTls.EndWrite($bodyWrite)
    $body = $null
    $firstResponse = [Text.Encoding]::ASCII.GetBytes("HTTP/1.1 200 OK`r`nContent-Length: 2`r`nConnection: keep-alive`r`n`r`nok")
    $originTls.Write($firstResponse, 0, $firstResponse.Length)
    $originTls.Flush()
    $receivedResponse = Read-MihariTestHttpResponse -Stream $proxyTls
    Assert-MihariTest -Condition ($receivedResponse.Body -eq 'ok') -Message 'Inspect must relay the large upload response.'

    $secondWire = [Text.Encoding]::ASCII.GetBytes("GET /second HTTP/1.1`r`nHost: 127.0.0.1:$originPort`r`nConnection: close`r`n`r`n")
    $proxyTls.Write($secondWire, 0, $secondWire.Length)
    $proxyTls.Flush()
    $secondHead = Read-MihariTestHeaderText -Stream $originTls -Context 'persistent Inspect request'
    Assert-MihariTest -Condition ($secondHead.StartsWith('GET /second HTTP/1.1')) -Message 'The second request must reuse the inspected client and upstream TLS legs.'
    $secondResponse = [Text.Encoding]::ASCII.GetBytes("HTTP/1.1 200 OK`r`nContent-Length: 6`r`nConnection: close`r`n`r`nsecond")
    $originTls.Write($secondResponse, 0, $secondResponse.Length)
    $originTls.Flush()
    $lastResponse = Read-MihariTestHttpResponse -Stream $proxyTls
    Assert-MihariTest -Condition ($lastResponse.Body -eq 'second') -Message 'The second inspected response must be relayed without framing mix-up.'
    $proxyTls.Dispose(); $proxyTls = $null
    $originTls.Dispose(); $originTls = $null
    $proxyClient.Dispose(); $proxyClient = $null
    $originClient.Dispose(); $originClient = $null
    $originListener.Stop(); $originListener = $null

    $final = Stop-MihariTestSession -Child $child -Metadata $metadata
    $child.Process.Dispose(); $child = $null
    $events = @([IO.File]::ReadAllLines([string]$final.eventsPath) | Where-Object { $_ } | ForEach-Object { ConvertFrom-Json -InputObject $_ -ErrorAction Stop })
    $requestEvents = @($events | Where-Object { $_.stage -eq 'http.request' -and $_.data.path -in @('/large', '/second') })
    Assert-MihariTest -Condition ($requestEvents.Count -eq 2 -and $requestEvents[0].requestId -ne $requestEvents[1].requestId) -Message 'Persistent inspected exchanges must retain distinct request IDs.'
    $tcpEvents = @($events | Where-Object { $_.stage -eq 'upstream.tcp' -and $_.upstreamConnectionId })
    Assert-MihariTest -Condition ($tcpEvents.Count -ge 2 -and $tcpEvents[0].upstreamConnectionId -eq $tcpEvents[1].upstreamConnectionId -and $tcpEvents[1].data.reused) -Message 'The second inspected exchange must reuse the same upstream connection identity.'
    Assert-MihariTest -Condition (@($events | Where-Object { $_.stage -eq 'upstream.http' -and $_.data.requestBytes -eq $bodyLength }).Count -eq 1) -Message 'Large upload byte count must come from actual streamed transfer.'
    Write-Host 'PASS phase2-inspect-streaming'
}
finally {
    Stop-MihariTestRootConfirmation -Operator $addOperator
    if ($null -ne $proxyTls) { try { $proxyTls.Dispose() } catch { $cleanupErrors.Add($_.Exception.Message) } }
    if ($null -ne $originTls) { try { $originTls.Dispose() } catch { $cleanupErrors.Add($_.Exception.Message) } }
    if ($null -ne $proxyClient) { try { $proxyClient.Dispose() } catch { $cleanupErrors.Add($_.Exception.Message) } }
    if ($null -ne $originClient) { try { $originClient.Dispose() } catch { $cleanupErrors.Add($_.Exception.Message) } }
    if ($null -ne $originListener) { try { $originListener.Stop() } catch { $cleanupErrors.Add($_.Exception.Message) } }
    if ($null -ne $child) {
        if ($null -ne $metadata -and -not $child.Process.HasExited) {
            try { $null = Stop-MihariTestSession -Child $child -Metadata $metadata }
            catch { $cleanupErrors.Add('Mihari stop: ' + $_.Exception.Message) }
        }
        if (-not $child.Process.HasExited) {
            try { $child.Process.Kill(); $child.Process.WaitForExit(5000) }
            catch { $cleanupErrors.Add('Mihari process: ' + $_.Exception.Message) }
        }
        $child.Process.Dispose()
    }
    if ($null -ne $identity) {
        try { Remove-MihariTestFixtureTlsIdentity -Identity $identity }
        catch { $cleanupErrors.Add('fixture CA/leaf: ' + $_.Exception.Message) }
    }
    if ($cleanupErrors.Count -gt 0) { throw ('Inspect streaming fixture cleanup failed: ' + ($cleanupErrors -join '; ')) }
}
