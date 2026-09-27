param()

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'TestSupport.ps1')
$root = Split-Path $PSScriptRoot -Parent
$sourceRoot = Join-Path $root 'src'
. (Join-Path $PSScriptRoot 'integration.ps1') -LoadHelpersOnly
. (Join-Path $sourceRoot 'Certificate.ps1')
. (Join-Path $sourceRoot 'Upstream.ps1')
. (Join-Path $sourceRoot 'Http.ps1')
. (Join-Path $sourceRoot 'Observation.ps1')
. (Join-Path $sourceRoot 'Connection.ps1')
. (Join-Path $sourceRoot 'Tls.ps1')
. (Join-Path $sourceRoot 'Hpack.ps1')
. (Join-Path $sourceRoot 'Http2.ps1')
. (Join-Path $sourceRoot 'Http2Tls.ps1')

if ($env:OS -ne 'Windows_NT') { Write-Host 'SKIP phase2-http2-tls: Windows certificate fixture required'; return }
if (-not (Test-MihariHttp2RuntimeCapability).Available) {
    Assert-MihariTest -Condition ($PSVersionTable.PSEdition -eq 'Desktop') -Message 'PowerShell 7 must expose the positive ALPN gate on this Windows runner.'
    Write-Host 'PASS phase2-http2-tls: Windows PowerShell 5.1 native capability unavailable'
    return
}

function New-MihariTestNativeFrame {
    param([int]$Type,[int]$Flags,[int]$StreamId,[byte[]]$Payload = [byte[]]@())
    $wire = [byte[]]::new(9 + $Payload.Length)
    $wire[0] = [byte](($Payload.Length -shr 16) -band 255)
    $wire[1] = [byte](($Payload.Length -shr 8) -band 255)
    $wire[2] = [byte]($Payload.Length -band 255)
    $wire[3] = [byte]$Type
    $wire[4] = [byte]$Flags
    $wire[5] = [byte](($StreamId -shr 24) -band 127)
    $wire[6] = [byte](($StreamId -shr 16) -band 255)
    $wire[7] = [byte](($StreamId -shr 8) -band 255)
    $wire[8] = [byte]($StreamId -band 255)
    if ($Payload.Length -gt 0) { [Array]::Copy($Payload,0,$wire,9,$Payload.Length) }
    return ,$wire
}

function Read-MihariTestNativeExact {
    param([IO.Stream]$Stream,[int]$Length)
    $buffer = [byte[]]::new($Length)
    $offset = 0
    while ($offset -lt $Length) {
        $count = $Stream.Read($buffer,$offset,$Length-$offset)
        if ($count -le 0) { throw [IO.EndOfStreamException]::new('Local HTTP/2 fixture closed early.') }
        $offset += $count
    }
    return ,$buffer
}

function Read-MihariTestNativeFrame {
    param([IO.Stream]$Stream)
    $header = Read-MihariTestNativeExact -Stream $Stream -Length 9
    $length = ([int]$header[0] -shl 16) -bor ([int]$header[1] -shl 8) -bor [int]$header[2]
    if ($length -gt 16384) { throw [IO.InvalidDataException]::new('Fixture received an oversized HTTP/2 frame.') }
    $payload = Read-MihariTestNativeExact -Stream $Stream -Length $length
    $id = ([int]$header[5] -shl 24) -bor ([int]$header[6] -shl 16) -bor ([int]$header[7] -shl 8) -bor [int]$header[8]
    return [pscustomobject]@{ Type = [int]$header[3]; Flags = [int]$header[4]; StreamId = $id; Payload = $payload }
}

function Complete-MihariTestNativeWorker {
    param($Worker,[string]$Name)
    if ($null -eq $Worker) { return }
    if (-not $Worker.Async.AsyncWaitHandle.WaitOne(30000)) { $Worker.Powershell.Stop(); throw "$Name worker timed out." }
    $null = $Worker.Powershell.EndInvoke($Worker.Async)
    if ($Worker.Powershell.HadErrors -or $Worker.Powershell.Streams.Error.Count -gt 0) {
        throw ("$Name worker failed: " + ($Worker.Powershell.Streams.Error | Out-String))
    }
}

$fixture = $null
$writer = $null
$originListener = $null
$proxyListener = $null
$client = $null
$clientTls = $null
$originWorker = $null
$proxyWorker = $null
$temp = Join-Path ([IO.Path]::GetTempPath()) ('mihari-h2-native-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($temp)
try {
    $fixture = New-MihariTestFixtureTlsIdentity
    $writer = New-MihariEventWriter -Path (Join-Path $temp 'events.jsonl')
    $session = $fixture.Session
    $session | Add-Member -NotePropertyName Id -NotePropertyValue ([guid]::NewGuid().ToString('N'))
    $session | Add-Member -NotePropertyName Mode -NotePropertyValue 'Inspect'
    $session | Add-Member -NotePropertyName Writer -NotePropertyValue $writer
    $session | Add-Member -NotePropertyName UpstreamProxy -NotePropertyValue $null
    $session | Add-Member -NotePropertyName PlatformProxySnapshot -NotePropertyValue ([pscustomobject]@{ PlatformProxy = $null; Configuration = [pscustomobject]@{ Configured = $false; PacConfigured = $false; EnvironmentConfigured = $false; ErrorType = $null }; ErrorType = $null })
    $session | Add-Member -NotePropertyName MaxWorkers -NotePropertyValue 4
    $session | Add-Member -NotePropertyName ActiveLongLivedCount -NotePropertyValue 0
    $session | Add-Member -NotePropertyName StateLock -NotePropertyValue (New-Object object)
    $session | Add-Member -NotePropertyName ActiveUpstreamClients -NotePropertyValue ([hashtable]::Synchronized(@{}))
    $session | Add-Member -NotePropertyName Cancellation -NotePropertyValue ([Threading.CancellationTokenSource]::new())
    $session | Add-Member -NotePropertyName StopPath -NotePropertyValue $null
    $originListener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,0)
    $originListener.Start()
    $originPort = ([Net.IPEndPoint]$originListener.LocalEndpoint).Port
    $proxyListener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,0)
    $proxyListener.Start()
    $proxyPort = ([Net.IPEndPoint]$proxyListener.LocalEndpoint).Port
    $session | Add-Member -NotePropertyName ActualPort -NotePropertyValue $proxyPort

    $originScript = @'
param($Listener,$Leaf,$SourceRoot)
$ErrorActionPreference = 'Stop'
function New-MihariTestNativeFrame {
    param([int]$Type,[int]$Flags,[int]$StreamId,[byte[]]$Payload = [byte[]]@())
    $wire = [byte[]]::new(9 + $Payload.Length)
    $wire[0] = [byte](($Payload.Length -shr 16) -band 255)
    $wire[1] = [byte](($Payload.Length -shr 8) -band 255)
    $wire[2] = [byte]($Payload.Length -band 255)
    $wire[3] = [byte]$Type; $wire[4] = [byte]$Flags
    $wire[5] = [byte](($StreamId -shr 24) -band 127)
    $wire[6] = [byte](($StreamId -shr 16) -band 255)
    $wire[7] = [byte](($StreamId -shr 8) -band 255)
    $wire[8] = [byte]($StreamId -band 255)
    if ($Payload.Length -gt 0) { [Array]::Copy($Payload,0,$wire,9,$Payload.Length) }
    return ,$wire
}
function Read-MihariTestNativeExact {
    param([IO.Stream]$Stream,[int]$Length)
    $buffer = [byte[]]::new($Length); $offset = 0
    while ($offset -lt $Length) {
        $count = $Stream.Read($buffer,$offset,$Length-$offset)
        if ($count -le 0) { throw [IO.EndOfStreamException]::new('Local HTTP/2 fixture closed early.') }
        $offset += $count
    }
    return ,$buffer
}
function Read-MihariTestNativeFrame {
    param([IO.Stream]$Stream)
    $header = Read-MihariTestNativeExact -Stream $Stream -Length 9
    $length = ([int]$header[0] -shl 16) -bor ([int]$header[1] -shl 8) -bor [int]$header[2]
    if ($length -gt 16384) { throw [IO.InvalidDataException]::new('Fixture received an oversized HTTP/2 frame.') }
    $payload = Read-MihariTestNativeExact -Stream $Stream -Length $length
    $id = ([int]$header[5] -shl 24) -bor ([int]$header[6] -shl 16) -bor ([int]$header[7] -shl 8) -bor [int]$header[8]
    return [pscustomobject]@{ Type = [int]$header[3]; Flags = [int]$header[4]; StreamId = $id; Payload = $payload }
}
. (Join-Path $SourceRoot 'Hpack.ps1')
. (Join-Path $SourceRoot 'Http2.ps1')
. (Join-Path $SourceRoot 'Http2Tls.ps1')
$socket = $null; $tls = $null
try {
    $socket = $Listener.AcceptTcpClient()
    $tls = [Net.Security.SslStream]::new($socket.GetStream(),$true)
    $tls.ReadTimeout = 15000; $tls.WriteTimeout = 15000
    $options = New-MihariHttp2TlsOptions -Role Server -Certificate $Leaf
    Invoke-MihariHttp2TlsAuthentication -Tls $tls -Options $options -Role Server
    if ((Get-MihariHttp2NegotiatedProtocol -Tls $tls) -ne 'h2') { throw 'Origin fixture did not select h2.' }
    $settings = New-MihariTestNativeFrame -Type 4 -Flags 0 -StreamId 0
    $tls.Write($settings,0,$settings.Length)
    $preface = Read-MihariTestNativeExact -Stream $tls -Length 24
    if ([Text.Encoding]::ASCII.GetString($preface) -ne "PRI * HTTP/2.0`r`n`r`nSM`r`n`r`n") { throw 'Origin fixture received invalid preface.' }
    $seen = New-Object 'System.Collections.Generic.List[int]'
    while ($seen.Count -lt 2) {
        $frame = Read-MihariTestNativeFrame -Stream $tls
        if ($frame.Type -eq 4 -and ($frame.Flags -band 1) -eq 0) {
            $ack = New-MihariTestNativeFrame -Type 4 -Flags 1 -StreamId 0
            $tls.Write($ack,0,$ack.Length)
        }
        if ($frame.Type -eq 1 -and ($frame.Flags -band 4) -ne 0) { $seen.Add($frame.StreamId) }
    }
    if ($seen.Count -ne 2 -or -not $seen.Contains(1) -or -not $seen.Contains(3)) { throw 'Origin fixture did not receive two concurrent streams.' }
    foreach ($id in @(3,1)) {
        $headers = New-MihariTestNativeFrame -Type 1 -Flags 4 -StreamId $id -Payload ([byte[]]@(0x88))
        $body = New-MihariTestNativeFrame -Type 0 -Flags 1 -StreamId $id -Payload ([Text.Encoding]::ASCII.GetBytes(('response-' + $id)))
        $tls.Write($headers,0,$headers.Length)
        $tls.Write($body,0,$body.Length)
    }
    $tls.Flush()
}
finally { if ($null -ne $tls) { $tls.Dispose() }; if ($null -ne $socket) { $socket.Dispose() } }
'@
    $originPowerShell = [PowerShell]::Create()
    $null = $originPowerShell.AddScript($originScript).AddArgument($originListener).AddArgument($fixture.Leaf).AddArgument($sourceRoot)
    $originWorker = [pscustomobject]@{ Powershell = $originPowerShell; Async = $originPowerShell.BeginInvoke() }

    $proxyAccept = $proxyListener.AcceptTcpClientAsync()
    $client = [Net.Sockets.TcpClient]::new()
    $client.Connect('127.0.0.1',$proxyPort)
    Assert-MihariTest -Condition ($proxyAccept.Wait(10000)) -Message 'Native proxy fixture did not accept a client.'
    $accepted = $proxyAccept.Result
    $proxyScript = @'
param($Session,$Accepted,$HostName,$Port,$SourceRoot)
$ErrorActionPreference = 'Stop'
foreach ($name in @('Certificate.ps1','Upstream.ps1','Http.ps1','Observation.ps1','Connection.ps1','Tls.ps1','Hpack.ps1','Http2.ps1','Http2Tls.ps1')) { . (Join-Path $SourceRoot $name) }
try { Invoke-MihariHttp2Inspect -Session $Session -ClientStream $Accepted.GetStream() -ConnectHost $HostName -ConnectPort $Port -ConnectionId 'native-client' -ConnectionMode Inspect -AcceptedConfigurationRevision 1 }
finally { $Accepted.Dispose() }
'@
    $proxyPowerShell = [PowerShell]::Create()
    $null = $proxyPowerShell.AddScript($proxyScript).AddArgument($session).AddArgument($accepted).AddArgument('127.0.0.1').AddArgument($originPort).AddArgument($sourceRoot)
    $proxyWorker = [pscustomobject]@{ Powershell = $proxyPowerShell; Async = $proxyPowerShell.BeginInvoke() }

    $clientTls = [Net.Security.SslStream]::new($client.GetStream(),$true)
    $clientTls.ReadTimeout = 15000; $clientTls.WriteTimeout = 15000
    $options = New-MihariHttp2TlsOptions -Role Client -TargetHost '127.0.0.1'
    Invoke-MihariHttp2TlsAuthentication -Tls $clientTls -Options $options -Role Client
    Assert-MihariTest -Condition ((Get-MihariHttp2NegotiatedProtocol -Tls $clientTls) -eq 'h2') -Message 'Client fixture must negotiate h2 with the session leaf.'
    $preface = [Text.Encoding]::ASCII.GetBytes("PRI * HTTP/2.0`r`n`r`nSM`r`n`r`n")
    $settings = New-MihariTestNativeFrame -Type 4 -Flags 0 -StreamId 0
    $clientTls.Write($preface,0,$preface.Length)
    $clientTls.Write($settings,0,$settings.Length)
    $encoder = New-MihariHpackContext -MaxTableSize 4096
    foreach ($id in @(1,3)) {
        $block = Encode-MihariHpackBlock -Context $encoder -Headers @(
            [pscustomobject]@{ name = ':method'; value = 'GET' },
            [pscustomobject]@{ name = ':scheme'; value = 'https' },
            [pscustomobject]@{ name = ':authority'; value = ('127.0.0.1:' + $originPort) },
            [pscustomobject]@{ name = ':path'; value = ('/native-' + $id + '?token=secret') }
        )
        $headers = New-MihariTestNativeFrame -Type 1 -Flags 5 -StreamId $id -Payload $block
        $clientTls.Write($headers,0,$headers.Length)
    }
    $clientTls.Flush()
    $completed = @{}
    while ($completed.Count -lt 2) {
        $frame = Read-MihariTestNativeFrame -Stream $clientTls
        if ($frame.Type -eq 4 -and ($frame.Flags -band 1) -eq 0) {
            $ack = New-MihariTestNativeFrame -Type 4 -Flags 1 -StreamId 0
            $clientTls.Write($ack,0,$ack.Length)
        }
        if ($frame.Type -eq 0 -and ($frame.Flags -band 1) -ne 0) { $completed[$frame.StreamId] = [Text.Encoding]::ASCII.GetString($frame.Payload) }
    }
    Assert-MihariTest -Condition ($completed[1] -eq 'response-1' -and $completed[3] -eq 'response-3') -Message 'Both concurrent h2 streams must preserve their binary response bodies.'
    $clientTls.Dispose(); $clientTls = $null
    Complete-MihariTestNativeWorker -Worker $originWorker -Name 'Origin'
    Complete-MihariTestNativeWorker -Worker $proxyWorker -Name 'Proxy'
    Close-MihariEventWriter -Writer $writer; $writer = $null
    $events = [IO.File]::ReadAllText((Join-Path $temp 'events.jsonl'))
    Assert-MihariTest -Condition ($events.Contains('"tlsAlpn":"h2"') -and $events.Contains('"transportLeg":"upstream"')) -Message 'Both native TLS legs must emit measured ALPN evidence.'
    Assert-MihariTest -Condition ($events.Contains('/native-1?token=REDACTED') -and $events.Contains('/native-3?token=REDACTED') -and -not $events.Contains('secret')) -Message 'Native stream facts must retain safe paths for both streams.'
    Assert-MihariTest -Condition ($events.Contains('"statusCode":200') -and $events.Contains('http2.stream')) -Message 'Native h2 response and stream outcomes must be observed.'
    Write-Host 'PASS phase2-http2-tls: real two-leg ALPN h2, concurrent streams, normal trust, safe evidence'
}
finally {
    if ($null -ne $clientTls) { $clientTls.Dispose() }
    if ($null -ne $client) { $client.Dispose() }
    if ($null -ne $proxyWorker) { try { $proxyWorker.Powershell.Stop() } catch { $null = $_ }; $proxyWorker.Powershell.Dispose() }
    if ($null -ne $originWorker) { try { $originWorker.Powershell.Stop() } catch { $null = $_ }; $originWorker.Powershell.Dispose() }
    if ($null -ne $proxyListener) { $proxyListener.Stop() }
    if ($null -ne $originListener) { $originListener.Stop() }
    if ($null -ne $writer) { Close-MihariEventWriter -Writer $writer }
    if ($null -ne $fixture) { Remove-MihariTestFixtureTlsIdentity -Identity $fixture }
    if ([IO.Directory]::Exists($temp)) { [IO.Directory]::Delete($temp,$true) }
}
