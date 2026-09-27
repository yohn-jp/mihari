param()

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'integration.ps1') -LoadHelpersOnly
if ($env:OS -ne 'Windows_NT') { return }

function Invoke-MihariLiveManagement {
    param([string]$Endpoint, [string]$Method = 'GET', $Body, [string]$Token)
    $request = [System.Net.HttpWebRequest][System.Net.WebRequest]::Create($Endpoint)
    # The management fixture reads the JSON body directly; avoid a client-side
    # 100-continue wait before the action reaches it.
    $request.ServicePoint.Expect100Continue = $false
    $request.Method = $Method
    $request.Proxy = $null
    $request.KeepAlive = $false
    $request.Timeout = 10000
    $request.ReadWriteTimeout = 10000
    if ($Token) { $request.Headers['X-Mihari-Control-Token'] = $Token }
    if ($null -ne $Body) {
        $request.ContentType = 'application/json; charset=utf-8'
        $wire = [Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $Body -Compress -Depth 5))
        $request.ContentLength = $wire.Length
        $stream = $request.GetRequestStream()
        try { $stream.Write($wire, 0, $wire.Length) }
        finally { $stream.Dispose() }
    }
    $response = $null
    try { $response = $request.GetResponse() }
    catch [System.Net.WebException] {
        if ($null -eq $_.Exception.Response) { throw }
        $response = $_.Exception.Response
    }
    try {
        $reader = New-Object System.IO.StreamReader -ArgumentList @($response.GetResponseStream(), [Text.Encoding]::UTF8)
        try { $text = $reader.ReadToEnd() }
        finally { $reader.Dispose() }
        $json = $null
        if ([string]$response.ContentType -match 'json') { $json = ConvertFrom-Json -InputObject $text -ErrorAction Stop }
        return [pscustomobject]@{ StatusCode = [int]$response.StatusCode; Text = $text; Json = $json }
    }
    finally { $response.Close() }
}

function New-MihariLiveProxyClient {
    param([int]$ProxyPort, [int]$OriginPort, [string]$Path, [string]$ExtraHeaders = '')
    $client = [System.Net.Sockets.TcpClient]::new()
    $client.Connect('127.0.0.1', $ProxyPort)
    $stream = $client.GetStream()
    $stream.ReadTimeout = 10000
    $stream.WriteTimeout = 10000
    $wire = [Text.Encoding]::ASCII.GetBytes("GET http://127.0.0.1:$OriginPort$Path HTTP/1.1`r`nHost: 127.0.0.1:$OriginPort`r`n$ExtraHeaders`r`n")
    $stream.Write($wire, 0, $wire.Length)
    return [pscustomobject]@{ Client = $client; Stream = $stream }
}

function Test-MihariLiveOrdinaryExchange {
    param([int]$ProxyPort, [int]$OriginPort, [System.Net.Sockets.TcpListener]$OriginListener, [string]$Path)
    $accept = $OriginListener.AcceptTcpClientAsync()
    $proxy = $null
    $origin = $null
    try {
        $proxy = New-MihariLiveProxyClient -ProxyPort $ProxyPort -OriginPort $OriginPort -Path $Path -ExtraHeaders "Connection: close`r`n"
        Assert-MihariTest -Condition ($accept.Wait(10000)) -Message 'An ordinary request must reach the fixture while a long-lived exchange is open.'
        $origin = $accept.Result
        $originStream = $origin.GetStream()
        $request = Read-MihariTestHeaderText -Stream $originStream
        Assert-MihariTest -Condition ($request.StartsWith("GET $Path HTTP/1.1")) -Message 'Concurrent origin request path must remain intact.'
        Write-MihariTestHttpResponse -Stream $originStream -Body 'ok'
        $response = Read-MihariTestHttpResponse -Stream $proxy.Stream
        Assert-MihariTest -Condition ($response.Headers.StartsWith('HTTP/1.1 200') -and $response.Body -eq 'ok') -Message 'A second client must receive its own origin response.'
    }
    finally {
        if ($null -ne $origin) { $origin.Close() }
        if ($null -ne $proxy) { $proxy.Client.Close() }
    }
}

$temporary = Join-Path ([IO.Path]::GetTempPath()) ('mihari-live-streaming-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($temporary)
$child = $null
$metadata = $null
$originListener = $null
$sseProxy = $null
$sseOrigin = $null
$wsProxy = $null
$wsOrigin = $null
$addOperator = $null
try {
    $originListener = New-MihariTestListener
    $originPort = ([System.Net.IPEndPoint]$originListener.LocalEndpoint).Port
    $child = Start-MihariTestProcess -Command start -OutputRoot $temporary -Mode Tunnel -Port 0
    $metadata = Wait-MihariTestSession -Child $child
    $proxyPort = [int]$metadata.actualPort
    $management = 'http://127.0.0.1:' + [int]$metadata.actualManagementPort + '/'

    # A persistent client and origin socket carry two separately framed requests.
    $keepAccept = $originListener.AcceptTcpClientAsync()
    $keepProxy = $null
    $keepOrigin = $null
    try {
        $keepProxy = New-MihariLiveProxyClient -ProxyPort $proxyPort -OriginPort $originPort -Path '/first'
        Assert-MihariTest -Condition ($keepAccept.Wait(10000)) -Message 'Persistent first request must reach the origin.'
        $keepOrigin = $keepAccept.Result
        $keepStream = $keepOrigin.GetStream()
        $first = Read-MihariTestHeaderText -Stream $keepStream
        Assert-MihariTest -Condition ($first.StartsWith('GET /first HTTP/1.1')) -Message 'Persistent first request path must be correct.'
        $firstResponse = [Text.Encoding]::ASCII.GetBytes("HTTP/1.1 200 OK`r`nContent-Length: 3`r`n`r`none")
        $keepStream.Write($firstResponse, 0, $firstResponse.Length)
        $firstRead = Read-MihariTestHttpResponse -Stream $keepProxy.Stream
        Assert-MihariTest -Condition ($firstRead.Body -eq 'one') -Message 'Persistent first response body must be correct.'
        $secondWire = [Text.Encoding]::ASCII.GetBytes("GET http://127.0.0.1:$originPort/second HTTP/1.1`r`nHost: 127.0.0.1:$originPort`r`nConnection: close`r`n`r`n")
        $keepProxy.Stream.Write($secondWire, 0, $secondWire.Length)
        $second = Read-MihariTestHeaderText -Stream $keepStream
        Assert-MihariTest -Condition ($second.StartsWith('GET /second HTTP/1.1')) -Message 'The second request must reuse the same origin connection with correct framing.'
        Write-MihariTestHttpResponse -Stream $keepStream -Body 'two'
        $secondRead = Read-MihariTestHttpResponse -Stream $keepProxy.Stream
        Assert-MihariTest -Condition ($secondRead.Body -eq 'two') -Message 'Persistent second response must not mix with the first.'
    }
    finally {
        if ($null -ne $keepOrigin) { $keepOrigin.Close() }
        if ($null -ne $keepProxy) { $keepProxy.Client.Close() }
    }

    $expectAccept = $originListener.AcceptTcpClientAsync()
    $expectClient = [System.Net.Sockets.TcpClient]::new()
    $expectOrigin = $null
    try {
        $expectClient.Connect('127.0.0.1', $proxyPort)
        $expectStream = $expectClient.GetStream()
        $expectStream.ReadTimeout = 10000
        $expectWire = [Text.Encoding]::ASCII.GetBytes("POST http://127.0.0.1:$originPort/expect HTTP/1.1`r`nHost: 127.0.0.1:$originPort`r`nContent-Length: 4`r`nExpect: 100-continue`r`nConnection: close`r`n`r`n")
        $expectStream.Write($expectWire, 0, $expectWire.Length)
        Assert-MihariTest -Condition ($expectAccept.Wait(10000)) -Message 'Expect request headers must reach origin before the client sends a body.'
        $expectOrigin = $expectAccept.Result
        $expectOriginStream = $expectOrigin.GetStream()
        $expectRequest = Read-MihariTestHeaderText -Stream $expectOriginStream
        Assert-MihariTest -Condition ($expectRequest.StartsWith('POST /expect HTTP/1.1')) -Message 'Expect request target must be forwarded.'
        $earlyFinal = [Text.Encoding]::ASCII.GetBytes("HTTP/1.1 417 Expectation Failed`r`nContent-Length: 0`r`nConnection: close`r`n`r`n")
        $expectOriginStream.Write($earlyFinal, 0, $earlyFinal.Length)
        $expectReply = Read-MihariTestHeaderText -Stream $expectStream
        Assert-MihariTest -Condition ($expectReply.StartsWith('HTTP/1.1 417')) -Message 'An early origin 417 must reach the client without a synthetic 100 or uploaded body.'
        Assert-MihariTest -Condition ($expectOrigin.Client.Available -eq 0) -Message 'An early final response must not trigger body forwarding.'
    }
    finally {
        if ($null -ne $expectOrigin) { $expectOrigin.Close() }
        $expectClient.Close()
    }

    # The first bytes of a >32 MiB response arrive before the origin finishes.
    $largeLength = [long]33554433
    $largePath = Join-Path $temporary 'large-fixture.bin'
    $largeFile = [System.IO.FileStream]::new($largePath, [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    $largeProxy = $null
    $largeOrigin = $null
    try {
        $largeFile.SetLength($largeLength)
        $largeFile.Position = 0
        $largeFile.WriteByte(0x5A)
        $largeFile.Position = $largeLength - 1
        $largeFile.WriteByte(0xA5)
        $largeFile.Position = 0
        $largeAccept = $originListener.AcceptTcpClientAsync()
        $largeProxy = New-MihariLiveProxyClient -ProxyPort $proxyPort -OriginPort $originPort -Path '/large' -ExtraHeaders "Connection: close`r`n"
        Assert-MihariTest -Condition ($largeAccept.Wait(10000)) -Message 'Large response request must reach the local origin.'
        $largeOrigin = $largeAccept.Result
        $largeOriginStream = $largeOrigin.GetStream()
        $null = Read-MihariTestHeaderText -Stream $largeOriginStream
        $largeHead = [Text.Encoding]::ASCII.GetBytes("HTTP/1.1 200 OK`r`nContent-Length: $largeLength`r`nConnection: close`r`n`r`n")
        $largeOriginStream.Write($largeHead, 0, $largeHead.Length)
        $firstPart = New-Object 'byte[]' 16384
        $null = $largeFile.Read($firstPart, 0, $firstPart.Length)
        $largeOriginStream.Write($firstPart, 0, $firstPart.Length)
        $largeResponseHead = Read-MihariTestHeaderText -Stream $largeProxy.Stream
        $largeLengthPattern = '(?im)^Content-Length:\s*' + $largeLength + '\s*$'
        Assert-MihariTest -Condition ($largeResponseHead -match $largeLengthPattern) -Message 'Large response headers must arrive before origin completion.'
        $firstPartAtClient = Read-MihariTestExactBytes -Stream $largeProxy.Stream -Count 16384
        Assert-MihariTest -Condition ($firstPartAtClient[0] -eq 0x5A) -Message 'Early large-response body bytes must reach the client before origin completion.'
        $copyTask = $largeFile.CopyToAsync($largeOriginStream, 16384)
        $remaining = $largeLength - 16384
        $readBuffer = New-Object 'byte[]' 16384
        $lastByte = 0
        while ($remaining -gt 0) {
            $wanted = [int][Math]::Min([long]$readBuffer.Length, $remaining)
            $read = $largeProxy.Stream.Read($readBuffer, 0, $wanted)
            if ($read -le 0) { throw 'Large response ended before Content-Length.' }
            $lastByte = $readBuffer[$read - 1]
            $remaining -= $read
        }
        Assert-MihariTest -Condition ($copyTask.Wait(30000) -and $lastByte -eq 0xA5) -Message 'The entire >32 MiB binary response must stream intact.'
    }
    finally {
        if ($null -ne $largeOrigin) { $largeOrigin.Close() }
        if ($null -ne $largeProxy) { $largeProxy.Client.Close() }
        $largeFile.Dispose()
    }

    # SSE remains open while management and another proxy worker respond.
    $sseAccept = $originListener.AcceptTcpClientAsync()
    $sseProxy = New-MihariLiveProxyClient -ProxyPort $proxyPort -OriginPort $originPort -Path '/events' -ExtraHeaders "Accept: text/event-stream`r`n"
    Assert-MihariTest -Condition ($sseAccept.Wait(10000)) -Message 'SSE request must reach the local origin.'
    $sseOrigin = $sseAccept.Result
    $sseStream = $sseOrigin.GetStream()
    $sseRequest = Read-MihariTestHeaderText -Stream $sseStream
    Assert-MihariTest -Condition ($sseRequest.StartsWith('GET /events HTTP/1.1')) -Message 'SSE origin request path must be correct.'
    $sseHead = [Text.Encoding]::ASCII.GetBytes("HTTP/1.1 200 OK`r`nContent-Type: text/event-stream`r`nTransfer-Encoding: chunked`r`n`r`n")
    $sseStream.Write($sseHead, 0, $sseHead.Length)
    $sseHeaders = Read-MihariTestHeaderText -Stream $sseProxy.Stream
    Assert-MihariTest -Condition ($sseHeaders -match '(?im)^Content-Type: text/event-stream\r?$') -Message 'SSE headers must reach the client before origin completion.'
    $firstSseChunk = [Text.Encoding]::ASCII.GetBytes("9`r`ndata: x`n`n`r`n")
    $sseStream.Write($firstSseChunk, 0, $firstSseChunk.Length)
    $observedSseChunk = Read-MihariTestExactBytes -Stream $sseProxy.Stream -Count $firstSseChunk.Length
    Assert-MihariTest -Condition ([Text.Encoding]::ASCII.GetString($observedSseChunk) -eq [Text.Encoding]::ASCII.GetString($firstSseChunk)) -Message 'SSE bytes must reach the client before stream end.'
    Test-MihariLiveOrdinaryExchange -ProxyPort $proxyPort -OriginPort $originPort -OriginListener $originListener -Path '/during-sse'
    $health = Invoke-MihariLiveManagement -Endpoint ($management + 'api/health')
    Assert-MihariTest -Condition ($health.StatusCode -eq 200 -and [bool]$health.Json.healthy) -Message 'Management health must respond while SSE is open.'
    $sseEnd = [Text.Encoding]::ASCII.GetBytes("0`r`n`r`n")
    $sseStream.Write($sseEnd, 0, $sseEnd.Length)
    $null = Read-MihariTestExactBytes -Stream $sseProxy.Stream -Count $sseEnd.Length
    $sseOrigin.Close(); $sseOrigin = $null
    $sseProxy.Client.Close(); $sseProxy = $null

    # A WebSocket upgrade carries opaque bytes in both directions.
    $wsAccept = $originListener.AcceptTcpClientAsync()
    $wsHeaders = "Connection: Upgrade`r`nUpgrade: websocket`r`nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==`r`nSec-WebSocket-Version: 13`r`n"
    $wsProxy = New-MihariLiveProxyClient -ProxyPort $proxyPort -OriginPort $originPort -Path '/socket' -ExtraHeaders $wsHeaders
    Assert-MihariTest -Condition ($wsAccept.Wait(10000)) -Message 'WebSocket upgrade must reach the local origin.'
    $wsOrigin = $wsAccept.Result
    $wsStream = $wsOrigin.GetStream()
    $wsRequest = Read-MihariTestHeaderText -Stream $wsStream
    Assert-MihariTest -Condition ($wsRequest -match '(?im)^Upgrade: websocket\r?$') -Message 'WebSocket Upgrade must survive forwarding.'
    $wsReply = [Text.Encoding]::ASCII.GetBytes("HTTP/1.1 101 Switching Protocols`r`nConnection: Upgrade`r`nUpgrade: websocket`r`nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=`r`n`r`n")
    $wsStream.Write($wsReply, 0, $wsReply.Length)
    $clientUpgrade = Read-MihariTestHeaderText -Stream $wsProxy.Stream
    Assert-MihariTest -Condition ($clientUpgrade.StartsWith('HTTP/1.1 101')) -Message 'A valid WebSocket upgrade must reach the client.'
    $clientPayload = [Text.Encoding]::ASCII.GetBytes('abc')
    $wsProxy.Stream.Write($clientPayload, 0, $clientPayload.Length)
    $upstreamPayload = Read-MihariTestExactBytes -Stream $wsStream -Count 3
    Assert-MihariTest -Condition ([Text.Encoding]::ASCII.GetString($upstreamPayload) -eq 'abc') -Message 'WebSocket client bytes must relay upstream.'
    $originPayload = [Text.Encoding]::ASCII.GetBytes('xyz')
    $wsStream.Write($originPayload, 0, $originPayload.Length)
    $downstreamPayload = Read-MihariTestExactBytes -Stream $wsProxy.Stream -Count 3
    Assert-MihariTest -Condition ([Text.Encoding]::ASCII.GetString($downstreamPayload) -eq 'xyz') -Message 'WebSocket origin bytes must relay to the client.'
    Test-MihariLiveOrdinaryExchange -ProxyPort $proxyPort -OriginPort $originPort -OriginListener $originListener -Path '/during-websocket'
    $health = Invoke-MihariLiveManagement -Endpoint ($management + 'api/health')
    Assert-MihariTest -Condition ($health.StatusCode -eq 200 -and [bool]$health.Json.healthy) -Message 'Management health must respond while WebSocket is open.'

    # The action token comes only from the owned management page, not evidence.
    $page = Invoke-MihariLiveManagement -Endpoint $management
    $tokenMatch = [regex]::Match($page.Text, 'var CONTROL_TOKEN="(?<token>[A-Za-z0-9_-]+)";')
    Assert-MihariTest -Condition $tokenMatch.Success -Message 'The owned management page must carry its session action token.'
    $token = $tokenMatch.Groups['token'].Value
    $addOperator = Start-MihariTestRootConfirmation -Operation Add -TargetProcessId $child.Process.Id
    $modeResult = Invoke-MihariLiveManagement -Endpoint ($management + 'api/mode') -Method POST -Body @{ mode = 'Inspect' } -Token $token
    $modeError = $null
    if ($null -ne $modeResult.Json) { $modeError = [string]$modeResult.Json.code + [string]$modeResult.Json.error }
    Assert-MihariTest -Condition ($modeResult.StatusCode -eq 200) -Message ('Mode action must respond while WebSocket remains open (HTTP {0}, error {1}).' -f $modeResult.StatusCode, $modeError)
    Complete-MihariTestRootConfirmation -Operator $addOperator
    Stop-MihariTestRootConfirmation -Operator $addOperator
    $addOperator = $null
    $status = Invoke-MihariLiveManagement -Endpoint ($management + 'api/status')
    Assert-MihariTest -Condition ($status.Json.session.mode -eq 'Inspect') -Message 'The mode action must update the live session while the older WebSocket stays open.'
    $back = Invoke-MihariLiveManagement -Endpoint ($management + 'api/mode') -Method POST -Body @{ mode = 'Tunnel' } -Token $token
    Assert-MihariTest -Condition ($back.StatusCode -eq 200) -Message 'The mode can return to Tunnel while WebSocket remains open.'
    $wsProxy.Stream.Write($clientPayload, 0, $clientPayload.Length)
    $upstreamPayload = Read-MihariTestExactBytes -Stream $wsStream -Count 3
    Assert-MihariTest -Condition ([Text.Encoding]::ASCII.GetString($upstreamPayload) -eq 'abc') -Message 'The accepted WebSocket mode must remain pinned after mode changes.'

    # Stop must cancel the owned long-lived relay and preserve its fact.
    $final = Stop-MihariTestSession -Child $child -Metadata $metadata
    $events = @([IO.File]::ReadAllLines([string]$final.eventsPath) | ForEach-Object { ConvertFrom-Json -InputObject $_ -ErrorAction Stop })
    Assert-MihariTest -Condition (@($events | Where-Object { $_.stage -eq 'websocket.relay' -and $_.outcome -eq 'cancelled' }).Count -ge 1) -Message 'Stop must record cancellation of the owned WebSocket relay.'
    Assert-MihariTest -Condition (@($events | Where-Object { $_.stage -eq 'response.relay' -and $_.data.path -eq '/events' -and $_.data.responseBytes -gt 0 }).Count -ge 1) -Message 'SSE relay must record measured bytes without body retention.'
    Write-Host 'PASS phase2-live-streaming: persistent exchanges, SSE/WebSocket relay, health/mode concurrency, stop cancellation'
}
finally {
    Stop-MihariTestRootConfirmation -Operator $addOperator
    if ($null -ne $sseOrigin) { $sseOrigin.Close() }
    if ($null -ne $sseProxy) { $sseProxy.Client.Close() }
    if ($null -ne $wsOrigin) { $wsOrigin.Close() }
    if ($null -ne $wsProxy) { $wsProxy.Client.Close() }
    if ($null -ne $originListener) { $originListener.Stop() }
    if ($null -ne $child) {
        if (-not $child.Process.HasExited) {
            try {
                if ($null -ne $metadata) { $null = Stop-MihariTestSession -Child $child -Metadata $metadata }
                else { $child.Process.Kill(); $child.Process.WaitForExit(5000) }
            }
            catch {
                Write-Warning ("Live streaming fixture stop failed: {0}" -f $_.Exception.Message)
                if (-not $child.Process.HasExited) { $child.Process.Kill(); $child.Process.WaitForExit(5000) }
            }
        }
        $child.Process.Dispose()
    }
    if ([IO.Directory]::Exists($temporary)) { [IO.Directory]::Delete($temporary, $true) }
}
