param()

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'integration.ps1') -LoadHelpersOnly
if ($env:OS -ne 'Windows_NT') { return }

$repoRoot = Split-Path $PSScriptRoot -Parent
$sourceRoot = Join-Path $repoRoot 'src'
foreach ($name in @('Observation', 'Http', 'Upstream', 'Cleanup', 'Session', 'Diagnosis')) {
    . (Join-Path $sourceRoot ($name + '.ps1'))
}

function Start-MihariImpactChild {
    param([string]$OutputRoot)
    $executableName = 'powershell.exe'
    if ($PSVersionTable.PSEdition -eq 'Core') { $executableName = 'pwsh.exe' }
    $info = New-Object System.Diagnostics.ProcessStartInfo
    $info.FileName = Join-Path $PSHOME $executableName
    $scriptArgument = ConvertTo-MihariTestProcessArgument -Value (Join-Path $repoRoot 'mihari.ps1')
    $outputArgument = ConvertTo-MihariTestProcessArgument -Value $OutputRoot
    $info.Arguments = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File {0} start -Mode Tunnel -Port 0 -UiPort 0 -MaxWorkers 2 -OutputRoot {1}' -f $scriptArgument, $outputArgument
    $info.WorkingDirectory = $repoRoot
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    foreach ($name in @('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy')) {
        $info.EnvironmentVariables.Remove($name)
    }
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $info
    if (-not $process.Start()) { throw 'Could not start Mihari impact fixture.' }
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    return [pscustomobject]@{ Process = $process; Stdout = $stdout; Stderr = $stderr; OutputRoot = $OutputRoot }
}

function New-MihariImpactTunnel {
    param([int]$ProxyPort, [int]$OriginPort, $OriginListener)
    $accept = $OriginListener.AcceptTcpClientAsync()
    $client = [System.Net.Sockets.TcpClient]::new()
    $client.Connect('127.0.0.1', $ProxyPort)
    $stream = $client.GetStream()
    $stream.ReadTimeout = 10000
    $wire = [Text.Encoding]::ASCII.GetBytes("CONNECT 127.0.0.1:$OriginPort HTTP/1.1`r`nHost: 127.0.0.1:$OriginPort`r`n`r`n")
    $stream.Write($wire, 0, $wire.Length)
    Assert-MihariTest -Condition ($accept.Wait(10000)) -Message 'Held CONNECT must reach its local origin.'
    $origin = $accept.Result
    $reply = Read-MihariTestHeaderText -Stream $stream
    Assert-MihariTest -Condition ($reply.StartsWith('HTTP/1.1 200')) -Message 'Held CONNECT must establish a tunnel.'
    return [pscustomobject]@{ Client = $client; Origin = $origin }
}

function Get-MihariImpactEvents {
    param([string]$Path)
    $events = New-Object 'System.Collections.Generic.List[object]'
    foreach ($line in (Read-MihariTestCompleteLiveLines -Path $Path)) {
        try { $events.Add((ConvertFrom-Json -InputObject $line -ErrorAction Stop)) }
        catch { throw 'The observer wrote an invalid complete JSONL record.' }
    }
    return ,$events.ToArray()
}

$temporary = Join-Path ([IO.Path]::GetTempPath()) ('mihari-impact-' + [Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($temporary)
$child = $null
$metadata = $null
$originListener = $null
$tunnels = New-Object 'System.Collections.Generic.List[object]'
$queued = New-Object 'System.Collections.Generic.List[object]'
try {
    $originListener = New-MihariTestListener
    $originPort = ([System.Net.IPEndPoint]$originListener.LocalEndpoint).Port
    $child = Start-MihariImpactChild -OutputRoot (Join-Path $temporary 'live')
    $metadata = Wait-MihariTestSession -Child $child
    $proxyPort = [int]$metadata.actualPort
    for ($i = 0; $i -lt 2; $i++) {
        $tunnels.Add((New-MihariImpactTunnel -ProxyPort $proxyPort -OriginPort $originPort -OriginListener $originListener))
    }
    for ($i = 0; $i -lt 4; $i++) {
        $client = [System.Net.Sockets.TcpClient]::new()
        $client.Connect('127.0.0.1', $proxyPort)
        $stream = $client.GetStream()
        $wire = [Text.Encoding]::ASCII.GetBytes("CONNECT 127.0.0.1:$originPort HTTP/1.1`r`nHost: 127.0.0.1:$originPort`r`n`r`n")
        $stream.Write($wire, 0, $wire.Length)
        $queued.Add($client)
    }

    $resource = $null
    $capacity = $null
    $deadline = [DateTime]::UtcNow.AddSeconds(12)
    while ([DateTime]::UtcNow -lt $deadline) {
        foreach ($event in (Get-MihariImpactEvents -Path ([string]$metadata.eventsPath))) {
            if ($event.stage -eq 'observer.resource' -and [int]$event.data.workerOccupancy -eq 2 -and
                [int]$event.data.queueLength -eq 4) { $resource = $event }
            if ($event.stage -eq 'listener.capacity' -and [bool]$event.data.queueSaturated -and
                [int]$event.data.queueLength -eq 4) { $capacity = $event }
        }
        if ($null -ne $resource -and $null -ne $capacity) { break }
        Start-Sleep -Milliseconds 100
    }
    Assert-MihariTest -Condition ($null -ne $resource -and $null -ne $capacity) -Message 'A full bounded queue must leave resource and saturation facts.'
    Assert-MihariTest -Condition ([int]$resource.data.maxWorkers -eq 2 -and [int]$resource.data.queueCapacity -eq 4 -and
        [long]$resource.data.workingSetBytes -gt 0 -and [double]$resource.data.cpuTotalMs -ge 0 -and
        [long]$resource.data.evidenceBytes -gt 0 -and [double]$resource.data.writerLagMs -ge 0) -Message 'Resource facts must contain measured bounds and process values.'
    $healthRequest = [System.Net.HttpWebRequest][System.Net.WebRequest]::Create(('http://127.0.0.1:{0}/api/health' -f [int]$metadata.actualManagementPort))
    $healthRequest.Proxy = $null
    $healthRequest.Timeout = 5000
    $healthResponse = $healthRequest.GetResponse()
    try { Assert-MihariTest -Condition ([int]$healthResponse.StatusCode -eq 200) -Message 'Management health must respond while the proxy queue is full.' }
    finally { $healthResponse.Close() }
    Write-Host ('MEASURE phase2-impact runtime={0} workers=2 queue=4/4 peak={1} saturation={2} workingSetBytes={3} cpuTotalMs={4} evidenceBytes={5} writerLagMs={6}' -f
        $PSVersionTable.PSVersion, $resource.data.queuePeak, $resource.data.saturationCount,
        $resource.data.workingSetBytes, $resource.data.cpuTotalMs, $resource.data.evidenceBytes, $resource.data.writerLagMs)

    $final = Stop-MihariTestSession -Child $child -Metadata $metadata
    Assert-MihariTest -Condition (-not [bool]$final.capture.incomplete -and [int]$final.capture.queuePeak -eq 4 -and
        [long]$final.capture.saturationCount -ge 1) -Message 'Clean stop must persist measured queue bounds without false capture loss.'
    $child.Process.Dispose(); $child = $null

    # Exercise the canonical writer and persisted session state with a small,
    # explicit test limit. No real disk is filled and no body is persisted.
    $limitSession = New-MihariSession -Mode Tunnel -Port 0 -OutputRoot (Join-Path $temporary 'limit') -EvidenceByteLimit 4096
    try {
        $limitError = $null
        for ($i = 0; $i -lt 30; $i++) {
            try {
                $null = Write-MihariEvent -Session $limitSession -ConnectionId 'limit' -Stage 'observer.resource' -Outcome 'success' -ElapsedMs 0 -Data @{ reason = ('bounded-' + $i) }
            }
            catch { $limitError = $_; break }
        }
        Assert-MihariTest -Condition ($null -ne $limitError -and $limitSession.CaptureState.Incomplete -and
            $limitSession.CaptureState.Reason -eq 'evidence_limit_reached' -and
            [IO.File]::Exists([string]$limitSession.StopPath) -and
            $limitSession.Writer.BytesWritten -le 4096) -Message 'Evidence limit must stop capture and persist incomplete state without exceeding its bound.'
        $saved = ConvertFrom-Json -InputObject ([IO.File]::ReadAllText([string]$limitSession.MetadataPath))
        Assert-MihariTest -Condition ($saved.capture.incomplete -and $saved.capture.reason -eq 'evidence_limit_reached') -Message 'Evidence-limit loss must survive in session metadata.'
    }
    finally { $null = Stop-MihariSession -Session $limitSession }

    $writerSession = New-MihariSession -Mode Tunnel -Port 0 -OutputRoot (Join-Path $temporary 'writer')
    try {
        $writerSession.Writer.Stream.BaseStream.Dispose()
        $failed = $false
        try { $null = Write-MihariEvent -Session $writerSession -ConnectionId 'writer' -Stage 'observer.resource' -Outcome 'success' -ElapsedMs 0 -Data @{} }
        catch { $failed = $true }
        $saved = ConvertFrom-Json -InputObject ([IO.File]::ReadAllText([string]$writerSession.MetadataPath))
        Assert-MihariTest -Condition ($failed -and $saved.capture.incomplete -and
            $saved.capture.reason -eq 'event_writer_failed' -and [IO.File]::Exists([string]$writerSession.StopPath)) -Message 'Writer failure must persist tool-health loss and request capture stop.'
    }
    finally { $null = Stop-MihariSession -Session $writerSession }

    $slowListener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $slowListener.Start()
    $slowClient = $null
    $slowPeer = $null
    $slowSource = $null
    try {
        $slowPort = ([System.Net.IPEndPoint]$slowListener.LocalEndpoint).Port
        $slowAccept = $slowListener.AcceptTcpClientAsync()
        $slowClient = [System.Net.Sockets.TcpClient]::new()
        $slowClient.SendBufferSize = 4096
        $slowClient.Connect('127.0.0.1', $slowPort)
        Assert-MihariTest -Condition ($slowAccept.Wait(5000)) -Message 'Slow-peer fixture must accept the relay socket.'
        $slowPeer = $slowAccept.Result
        $slowPeer.ReceiveBufferSize = 4096
        $slowDestination = $slowClient.GetStream()
        $slowDestination.WriteTimeout = 500
        $slowPath = Join-Path $temporary 'slow-source.bin'
        $slowSource = [IO.File]::Open($slowPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
        $slowSource.SetLength(8388608)
        $slowSource.Position = 0
        $slowTimer = [Diagnostics.Stopwatch]::StartNew()
        $slowFailure = $null
        try {
            $null = Copy-MihariHttpBody -Source $slowSource -Destination $slowDestination -Framing ([pscustomobject]@{ Kind = 'ContentLength'; Length = 8388608 })
        }
        catch { $slowFailure = $_.Exception }
        $slowTimer.Stop()
        Assert-MihariTest -Condition ($null -ne $slowFailure -and $slowTimer.ElapsedMilliseconds -lt 10000) -Message 'A non-reading peer must time out without an unbounded body buffer.'
        Write-Host ('MEASURE phase2-slow-peer bytes=8388608 writeTimeoutMs=500 elapsedMs={0} failureType={1}' -f $slowTimer.ElapsedMilliseconds, $slowFailure.GetBaseException().GetType().FullName)
    }
    finally {
        if ($null -ne $slowSource) { $slowSource.Dispose() }
        if ($null -ne $slowPeer) { $slowPeer.Close() }
        if ($null -ne $slowClient) { $slowClient.Close() }
        $slowListener.Stop()
    }
    Write-Host 'PASS phase2-observer-impact: bounded queue, resource facts, slow peer, health under load, durable capture-limit and writer-failure state'
}
finally {
    foreach ($client in $queued) { try { $client.Close() } catch { Write-Warning 'Queued fixture socket cleanup failed.' } }
    foreach ($pair in $tunnels) {
        try { $pair.Client.Close() } catch { Write-Warning 'Tunnel fixture client cleanup failed.' }
        try { $pair.Origin.Close() } catch { Write-Warning 'Tunnel fixture origin cleanup failed.' }
    }
    if ($null -ne $originListener) { $originListener.Stop() }
    if ($null -ne $child) {
        if (-not $child.Process.HasExited) {
            try { if ($null -ne $metadata) { $null = Stop-MihariTestSession -Child $child -Metadata $metadata } }
            catch { if (-not $child.Process.HasExited) { $child.Process.Kill(); $child.Process.WaitForExit(5000) } }
        }
        $child.Process.Dispose()
    }
    if ([IO.Directory]::Exists($temporary)) { [IO.Directory]::Delete($temporary, $true) }
}
