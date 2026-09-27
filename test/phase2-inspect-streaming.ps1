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
$fixtureStage = 'setup'
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
    $fixtureStage = 'CONNECT reply'
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
    $fixtureStage = 'large upload request header'
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
    $fixtureStage = 'large upload response'
    $receivedResponse = Read-MihariTestHttpResponse -Stream $proxyTls
    Assert-MihariTest -Condition ($receivedResponse.Body -eq 'ok') -Message 'Inspect must relay the large upload response.'

    $secondWire = [Text.Encoding]::ASCII.GetBytes("GET /second HTTP/1.1`r`nHost: 127.0.0.1:$originPort`r`nConnection: keep-alive`r`n`r`n")
    $proxyTls.Write($secondWire, 0, $secondWire.Length)
    $proxyTls.Flush()
    $fixtureStage = 'persistent request header'
    $secondHead = Read-MihariTestHeaderText -Stream $originTls -Context 'persistent Inspect request'
    Assert-MihariTest -Condition ($secondHead.StartsWith('GET /second HTTP/1.1')) -Message 'The second request must reuse the inspected client and upstream TLS legs.'
    $secondResponse = [Text.Encoding]::ASCII.GetBytes("HTTP/1.1 200 OK`r`nContent-Length: 6`r`nConnection: keep-alive`r`n`r`nsecond")
    $originTls.Write($secondResponse, 0, $secondResponse.Length)
    $originTls.Flush()
    $fixtureStage = 'persistent response'
    $lastResponse = Read-MihariTestHttpResponse -Stream $proxyTls
    Assert-MihariTest -Condition ($lastResponse.Body -eq 'second') -Message 'The second inspected response must be relayed without framing mix-up.'

    $continueWire = [Text.Encoding]::ASCII.GetBytes("POST /expect-continue HTTP/1.1`r`nHost: 127.0.0.1:$originPort`r`nContent-Length: 4`r`nExpect: 100-continue`r`nConnection: keep-alive`r`n`r`n")
    $proxyTls.Write($continueWire, 0, $continueWire.Length)
    $proxyTls.Flush()
    $fixtureStage = 'Expect request header'
    $continueHead = Read-MihariTestHeaderText -Stream $originTls -Context 'Inspect Expect request'
    Assert-MihariTest -Condition ($continueHead.StartsWith('POST /expect-continue HTTP/1.1')) -Message 'Inspect must forward Expect headers before reading the body.'
    $fixtureStage = 'Expect 100 Continue'
    $continueReply = Read-MihariTestHeaderText -Stream $proxyTls -Context 'Inspect local 100 Continue'
    Assert-MihariTest -Condition ($continueReply.StartsWith('HTTP/1.1 100')) -Message 'Inspect must release an Expect client when upstream sends no interim response.'
    $continueBody = [Text.Encoding]::ASCII.GetBytes('body')
    $proxyTls.Write($continueBody, 0, $continueBody.Length)
    $proxyTls.Flush()
    $originBody = Read-MihariTestExactBytes -Stream $originTls -Count 4
    Assert-MihariTest -Condition ([Text.Encoding]::ASCII.GetString($originBody) -eq 'body') -Message 'Inspect must stream the continued body after the interim response.'
    $continuedResponse = [Text.Encoding]::ASCII.GetBytes("HTTP/1.1 200 OK`r`nContent-Length: 9`r`nConnection: keep-alive`r`n`r`ncontinued")
    $originTls.Write($continuedResponse, 0, $continuedResponse.Length)
    $originTls.Flush()
    $fixtureStage = 'Expect final response'
    $continuedClientResponse = Read-MihariTestHttpResponse -Stream $proxyTls
    Assert-MihariTest -Condition ($continuedClientResponse.Body -eq 'continued') -Message 'Inspect must relay the completed Expect exchange.'

    $rejectWire = [Text.Encoding]::ASCII.GetBytes("POST /expect-reject HTTP/1.1`r`nHost: 127.0.0.1:$originPort`r`nContent-Length: 4`r`nExpect: 100-continue`r`nConnection: close`r`n`r`n")
    $proxyTls.Write($rejectWire, 0, $rejectWire.Length)
    $proxyTls.Flush()
    $fixtureStage = 'early rejection request header'
    $rejectHead = Read-MihariTestHeaderText -Stream $originTls -Context 'Inspect early rejection request'
    Assert-MihariTest -Condition ($rejectHead.StartsWith('POST /expect-reject HTTP/1.1')) -Message 'Inspect must present Expect headers to origin before an early final response.'
    $rejectResponse = [Text.Encoding]::ASCII.GetBytes("HTTP/1.1 417 Expectation Failed`r`nContent-Length: 0`r`nConnection: close`r`n`r`n")
    $originTls.Write($rejectResponse, 0, $rejectResponse.Length)
    $originTls.Flush()
    $fixtureStage = 'early rejection final response'
    $rejectedClientResponse = Read-MihariTestHttpResponse -Stream $proxyTls
    Assert-MihariTest -Condition ($rejectedClientResponse.Headers.StartsWith('HTTP/1.1 417')) -Message 'Inspect must forward an early final response without requesting the body.'
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
    Assert-MihariTest -Condition ($tcpEvents.Count -ge 4 -and $tcpEvents[0].upstreamConnectionId -eq $tcpEvents[1].upstreamConnectionId -and $tcpEvents[1].data.reused) -Message 'The second inspected exchange must reuse the same upstream connection identity.'
    Assert-MihariTest -Condition (@($events | Where-Object { $_.stage -eq 'upstream.http' -and $_.data.path -eq '/expect-reject' -and $_.data.requestBytes -eq 0 -and $_.data.statusCode -eq 417 }).Count -eq 1) -Message 'Early final Inspect response must record zero forwarded request-body bytes.'
    Assert-MihariTest -Condition (@($events | Where-Object { $_.stage -eq 'upstream.http' -and $_.data.requestBytes -eq $bodyLength }).Count -eq 1) -Message 'Large upload byte count must come from actual streamed transfer.'
    Write-Host 'PASS phase2-inspect-streaming'
}
catch {
    throw ('Inspect streaming fixture at ' + $fixtureStage + ': ' + $_.Exception.Message)
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
