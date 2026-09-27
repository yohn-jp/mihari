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
function Start-MihariTestNativeProcess {
    param([string]$OutputRoot)
    $executable = Join-Path $PSHOME $(if ($PSVersionTable.PSEdition -eq 'Core') { 'pwsh.exe' } else { 'powershell.exe' })
    $entry = Join-Path $root 'mihari.ps1'
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $executable
    $info.Arguments = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File {0} start -Mode Inspect -Profile http2-inspect -Port 0 -UiPort 0 -MaxWorkers 4 -OutputRoot {1}' -f
        (ConvertTo-MihariTestProcessArgument -Value $entry), (ConvertTo-MihariTestProcessArgument -Value $OutputRoot)
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    foreach ($name in @('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','http_proxy','https_proxy','all_proxy')) { $info.EnvironmentVariables.Remove($name) }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $info
    if (-not $process.Start()) { throw 'Could not start the native profile test process.' }
    return [pscustomobject]@{ Process = $process; Stdout = $process.StandardOutput.ReadToEndAsync(); Stderr = $process.StandardError.ReadToEndAsync(); OutputRoot = $OutputRoot }
}
if (-not (Test-MihariHttp2RuntimeCapability).Available) {
    Assert-MihariTest -Condition ($PSVersionTable.PSEdition -eq 'Desktop') -Message 'PowerShell 7 must expose the positive ALPN gate on this Windows runner.'
    $gateRoot = Join-Path ([IO.Path]::GetTempPath()) ('mihari-h2-gate-' + [guid]::NewGuid().ToString('N'))
    $gate = Start-MihariTestNativeProcess -OutputRoot $gateRoot
    try {
        Assert-MihariTest -Condition ($gate.Process.WaitForExit(15000)) -Message 'The 5.1 native profile gate must reject before listener startup.'
        $gate.Process.WaitForExit()
        $gateText = [string]$gate.Stderr.Result + [string]$gate.Stdout.Result
        Assert-MihariTest -Condition ($gate.Process.ExitCode -ne 0 -and $gateText -match 'managed ALPN API surface') -Message 'PowerShell 5.1 must reject native Inspect with a precise ALPN reason.'
        Assert-MihariTest -Condition (-not [IO.File]::Exists((Join-Path $gateRoot 'active-session.json'))) -Message 'A rejected 5.1 native profile must not create a session.'
    }
    finally { if (-not $gate.Process.HasExited) { $gate.Process.Kill(); $gate.Process.WaitForExit(5000) }; $gate.Process.Dispose(); if ([IO.Directory]::Exists($gateRoot)) { [IO.Directory]::Delete($gateRoot,$true) } }
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
$endOriginWorker = $null
$nativeChild = $null
$nativeMetadata = $null
$nativeAddOperator = $null
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
    # SslStream leaves the underlying socket open by design. Close it so the
    # relay sees EOF before waiting for its worker to finish.
    $client.Dispose(); $client = $null
    Complete-MihariTestNativeWorker -Worker $originWorker -Name 'Origin'
    Complete-MihariTestNativeWorker -Worker $proxyWorker -Name 'Proxy'
    Close-MihariEventWriter -Writer $writer; $writer = $null
    $events = [IO.File]::ReadAllText((Join-Path $temp 'events.jsonl'))
    Assert-MihariTest -Condition ($events.Contains('"tlsAlpn":"h2"') -and $events.Contains('"transportLeg":"upstream"')) -Message 'Both native TLS legs must emit measured ALPN evidence.'
    Assert-MihariTest -Condition ($events.Contains('/native-1?token=REDACTED') -and $events.Contains('/native-3?token=REDACTED') -and -not $events.Contains('secret')) -Message 'Native stream facts must retain safe paths for both streams.'
    Assert-MihariTest -Condition ($events.Contains('"statusCode":200') -and $events.Contains('http2.stream')) -Message 'Native h2 response and stream outcomes must be observed.'

    # Exercise the actual entry point, listener and CONNECT dispatch, including
    # the session CA trust/cleanup path. The origin fixture remains loopback.
    $endOriginPowerShell = [PowerShell]::Create()
    $null = $endOriginPowerShell.AddScript($originScript).AddArgument($originListener).AddArgument($fixture.Leaf).AddArgument($sourceRoot)
    $endOriginWorker = [pscustomobject]@{ Powershell = $endOriginPowerShell; Async = $endOriginPowerShell.BeginInvoke() }
    $nativeChild = Start-MihariTestNativeProcess -OutputRoot (Join-Path $temp 'native-session')
    $nativeAddOperator = Start-MihariTestRootConfirmation -Operation Add -TargetProcessId $nativeChild.Process.Id
    $nativeMetadata = Wait-MihariTestSession -Child $nativeChild
    Complete-MihariTestRootConfirmation -Operator $nativeAddOperator
    Stop-MihariTestRootConfirmation -Operator $nativeAddOperator
    $nativeAddOperator = $null
    Assert-MihariTest -Condition ($nativeMetadata.profile -eq 'http2-inspect') -Message 'The running session must pin the native Inspect profile.'
    $client = [Net.Sockets.TcpClient]::new()
    $client.Connect('127.0.0.1',[int]$nativeMetadata.actualPort)
    $proxyStream = $client.GetStream()
    $connect = [Text.Encoding]::ASCII.GetBytes("CONNECT 127.0.0.1:$originPort HTTP/1.1`r`nHost: 127.0.0.1:$originPort`r`n`r`n")
    $proxyStream.Write($connect,0,$connect.Length)
    $proxyStream.Flush()
    $connectResponse = Read-MihariTestHeaderText -Stream $proxyStream -Context 'native Inspect CONNECT response'
    Assert-MihariTest -Condition ($connectResponse.StartsWith('HTTP/1.1 200')) -Message 'The production listener must acknowledge native Inspect CONNECT.'
    $clientTls = [Net.Security.SslStream]::new($proxyStream,$true)
    $clientTls.ReadTimeout = 15000; $clientTls.WriteTimeout = 15000
    $options = New-MihariHttp2TlsOptions -Role Client -TargetHost '127.0.0.1'
    Invoke-MihariHttp2TlsAuthentication -Tls $clientTls -Options $options -Role Client
    Assert-MihariTest -Condition ((Get-MihariHttp2NegotiatedProtocol -Tls $clientTls) -eq 'h2') -Message 'The production session leaf must negotiate native h2.'
    $clientTls.Write($preface,0,$preface.Length)
    $clientTls.Write($settings,0,$settings.Length)
    $encoder = New-MihariHpackContext -MaxTableSize 4096
    foreach ($id in @(1,3)) {
        $block = Encode-MihariHpackBlock -Context $encoder -Headers @(
            [pscustomobject]@{ name = ':method'; value = 'GET' },
            [pscustomobject]@{ name = ':scheme'; value = 'https' },
            [pscustomobject]@{ name = ':authority'; value = ('127.0.0.1:' + $originPort) },
            [pscustomobject]@{ name = ':path'; value = ('/entry-' + $id + '?token=entry-secret') }
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
    Assert-MihariTest -Condition ($completed[1] -eq 'response-1' -and $completed[3] -eq 'response-3') -Message 'Production CONNECT must carry both native h2 streams.'
    $clientTls.Dispose(); $clientTls = $null
    $client.Dispose(); $client = $null
    Complete-MihariTestNativeWorker -Worker $endOriginWorker -Name 'End-to-end origin'
    $nativeFinal = Stop-MihariTestSession -Child $nativeChild -Metadata $nativeMetadata
    $endEvents = [IO.File]::ReadAllText([string]$nativeFinal.eventsPath)
    Assert-MihariTest -Condition ($endEvents.Contains('"tlsAlpn":"h2"') -and $endEvents.Contains('/entry-1?token=REDACTED') -and $endEvents.Contains('/entry-3?token=REDACTED')) -Message 'Production JSONL must contain actual ALPN and safe path observations.'
    Assert-MihariTest -Condition (-not $endEvents.Contains('entry-secret') -and $endEvents.Contains('"statusCode":200')) -Message 'Production events must exclude query secrets and retain response status.'
    Write-Host 'PASS phase2-http2-tls: direct and production CONNECT two-leg h2, concurrent streams, normal trust, CA cleanup'
}
finally {
    if ($null -ne $clientTls) { $clientTls.Dispose() }
    if ($null -ne $client) { $client.Dispose() }
    if ($null -ne $nativeAddOperator) { Stop-MihariTestRootConfirmation -Operator $nativeAddOperator }
    if ($null -ne $nativeChild) {
        if ($null -ne $nativeMetadata -and $null -eq $nativeChild.PSObject.Properties['StopAttempted']) {
            try { $null = Stop-MihariTestSession -Child $nativeChild -Metadata $nativeMetadata }
            catch { Write-Warning ('Native session cleanup failed: ' + $_.Exception.Message) }
        }
        if (-not $nativeChild.Process.HasExited) { try { $nativeChild.Process.Kill(); $nativeChild.Process.WaitForExit(5000) } catch { Write-Warning ('Native child termination failed: ' + $_.Exception.Message) } }
        $nativeChild.Process.Dispose()
    }
    if ($null -ne $proxyListener) { $proxyListener.Stop() }
    if ($null -ne $originListener) { $originListener.Stop() }
    if ($null -ne $proxyWorker) { try { $proxyWorker.Powershell.Stop() } catch { $null = $_ }; $proxyWorker.Powershell.Dispose() }
    if ($null -ne $originWorker) { try { $originWorker.Powershell.Stop() } catch { $null = $_ }; $originWorker.Powershell.Dispose() }
    if ($null -ne $endOriginWorker) { try { $endOriginWorker.Powershell.Stop() } catch { $null = $_ }; $endOriginWorker.Powershell.Dispose() }
    if ($null -ne $writer) { Close-MihariEventWriter -Writer $writer }
    if ($null -ne $fixture) { Remove-MihariTestFixtureTlsIdentity -Identity $fixture }
    if ([IO.Directory]::Exists($temp)) { [IO.Directory]::Delete($temp,$true) }
}
