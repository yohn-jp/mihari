param()

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'TestSupport.ps1')
$root = Split-Path $PSScriptRoot -Parent
. (Join-Path (Join-Path $root 'src') 'Http.ps1')
. (Join-Path (Join-Path $root 'src') 'Observation.ps1')
. (Join-Path (Join-Path $root 'src') 'Hpack.ps1')
. (Join-Path (Join-Path $root 'src') 'Http2.ps1')

function New-MihariTestH2Frame {
    param([int]$Type, [int]$Flags, [int]$StreamId, [byte[]]$Payload = [byte[]]@())
    $length = $Payload.Length
    $wire = [byte[]]::new(9 + $length)
    $wire[0] = [byte](($length -shr 16) -band 255)
    $wire[1] = [byte](($length -shr 8) -band 255)
    $wire[2] = [byte]($length -band 255)
    $wire[3] = [byte]$Type
    $wire[4] = [byte]$Flags
    $wire[5] = [byte](($StreamId -shr 24) -band 127)
    $wire[6] = [byte](($StreamId -shr 16) -band 255)
    $wire[7] = [byte](($StreamId -shr 8) -band 255)
    $wire[8] = [byte]($StreamId -band 255)
    if ($length -gt 0) { [Array]::Copy($Payload,0,$wire,9,$length) }
    return ,$wire
}

function Assert-MihariTestH2Rejected {
    param([scriptblock]$Action, [string]$Message)
    $rejected = $false
    try { $null = & $Action }
    catch [System.IO.InvalidDataException] { $rejected = $true }
    Assert-MihariTest -Condition $rejected -Message $Message
}

$capability = Test-MihariHttp2RuntimeCapability
Assert-MihariTest -Condition ($null -ne $capability.Members -and $capability.Members.Count -ge 7) -Message 'Native capability must be checked member by member.'
if ($PSVersionTable.PSEdition -eq 'Desktop') {
    Assert-MihariTest -Condition (-not $capability.Available) -Message 'Windows PowerShell 5.1 must not claim the modern ALPN API.'
}

$client = New-MihariHttp2Direction -Leg client
$upstream = New-MihariHttp2Direction -Leg upstream
$preface = [Text.Encoding]::ASCII.GetBytes("PRI * HTTP/2.0`r`n`r`nSM`r`n`r`n")
$settings = New-MihariTestH2Frame -Type 4 -Flags 0 -StreamId 0
$input = [byte[]]::new($preface.Length + $settings.Length)
[Array]::Copy($preface,0,$input,0,$preface.Length)
[Array]::Copy($settings,0,$input,$preface.Length,$settings.Length)
$first = (Add-MihariHttp2Input -State $client -Bytes $input -Count 13).Items
Assert-MihariTest -Condition ($first.Count -eq 0) -Message 'A partial preface must wait for the remaining bytes.'
$remainder = [byte[]]::new($input.Length - 13)
[Array]::Copy($input,13,$remainder,0,$remainder.Length)
$second = (Add-MihariHttp2Input -State $client -Bytes $remainder -Count $remainder.Length).Items
Assert-MihariTest -Condition ($second.Count -eq 2 -and $second[0].Preface -and $second[1].Type -eq 4) -Message 'Preface and SETTINGS must parse incrementally.'

$bad = New-MihariHttp2Direction -Leg client
$badBytes = [byte[]]::new(24)
Assert-MihariTestH2Rejected -Message 'Malformed preface must fail before forwarding.' -Action { Add-MihariHttp2Input -State $bad -Bytes $badBytes -Count $badBytes.Length }
$oversize = New-MihariHttp2Direction -Leg upstream
$hugeHeader = [byte[]]@(0, 64, 1, 0, 0, 0, 0, 0, 1)
Assert-MihariTestH2Rejected -Message 'An oversized frame must fail at its header.' -Action { Add-MihariHttp2Input -State $oversize -Bytes $hugeHeader -Count $hugeHeader.Length }

$temporary = Join-Path ([IO.Path]::GetTempPath()) ('mihari-http2-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($temporary)
$writer = New-MihariEventWriter -Path (Join-Path $temporary 'events.jsonl')
try {
    $session = [pscustomobject]@{ Id = [guid]::NewGuid().ToString('N'); Mode = 'Inspect'; Writer = $writer }
    $ctx = [pscustomobject]@{ Session = $session; ConnectionId = 'client-leg'; UpstreamConnectionId = 'upstream-leg'; Host = 'localhost'; Port = 443; Mode = 'Inspect'; ConfigurationRevision = 1; Clock = [Diagnostics.Stopwatch]::StartNew(); Streams = @{} }
    $client = New-MihariHttp2Direction -Leg client
    $upstream = New-MihariHttp2Direction -Leg upstream
    $null = Invoke-MihariHttp2Frame -Context $ctx -State $client -Opposite $upstream -Frame ([pscustomobject]@{ Preface = $true; Bytes = $preface })
    foreach ($direction in @($client,$upstream)) {
        $frame = (Add-MihariHttp2Input -State $direction -Bytes $settings -Count $settings.Length).Items[0]
        $null = Invoke-MihariHttp2Frame -Context $ctx -State $direction -Opposite $(if ($direction.Leg -eq 'client') { $upstream } else { $client }) -Frame $frame
    }
    $requestEncoder = New-MihariHpackContext -MaxTableSize 4096
    $responseEncoder = New-MihariHpackContext -MaxTableSize 4096
    $requestBlock = Encode-MihariHpackBlock -Context $requestEncoder -Headers @(
        [pscustomobject]@{ name = ':method'; value = 'GET' },
        [pscustomobject]@{ name = ':scheme'; value = 'https' },
        [pscustomobject]@{ name = ':authority'; value = 'localhost' },
        [pscustomobject]@{ name = ':path'; value = '/one?token=topsecret' }
    )
    foreach ($id in @(1,3)) {
        $wire = New-MihariTestH2Frame -Type 1 -Flags 5 -StreamId $id -Payload $requestBlock
        $frame = (Add-MihariHttp2Input -State $client -Bytes $wire -Count $wire.Length).Items[0]
        $forwarded = (Invoke-MihariHttp2Frame -Context $ctx -State $client -Opposite $upstream -Frame $frame).Frames
        Assert-MihariTest -Condition ($forwarded.Count -eq 1 -and $ctx.Streams.ContainsKey($id)) -Message 'Independent concurrent request streams must forward.'
    }
    $responseBlock = Encode-MihariHpackBlock -Context $responseEncoder -Headers @([pscustomobject]@{ name = ':status'; value = '200' })
    foreach ($id in @(3,1)) {
        $wire = New-MihariTestH2Frame -Type 1 -Flags 5 -StreamId $id -Payload $responseBlock
        $frame = (Add-MihariHttp2Input -State $upstream -Bytes $wire -Count $wire.Length).Items[0]
        $null = Invoke-MihariHttp2Frame -Context $ctx -State $upstream -Opposite $client -Frame $frame
    }
    Assert-MihariTest -Condition ($ctx.Streams.Count -eq 0) -Message 'Both concurrent streams must close independently.'
    $requestBlock = Encode-MihariHpackBlock -Context $requestEncoder -Headers @(
        [pscustomobject]@{ name = ':method'; value = 'POST' },
        [pscustomobject]@{ name = ':scheme'; value = 'https' },
        [pscustomobject]@{ name = ':authority'; value = 'localhost' },
        [pscustomobject]@{ name = ':path'; value = '/rpc.Service/Call' }
    )
    $wire = New-MihariTestH2Frame -Type 1 -Flags 5 -StreamId 5 -Payload $requestBlock
    $frame = (Add-MihariHttp2Input -State $client -Bytes $wire -Count $wire.Length).Items[0]
    $null = Invoke-MihariHttp2Frame -Context $ctx -State $client -Opposite $upstream -Frame $frame
    $wire = New-MihariTestH2Frame -Type 1 -Flags 4 -StreamId 5 -Payload $responseBlock
    $frame = (Add-MihariHttp2Input -State $upstream -Bytes $wire -Count $wire.Length).Items[0]
    $null = Invoke-MihariHttp2Frame -Context $ctx -State $upstream -Opposite $client -Frame $frame
    $trailers = Encode-MihariHpackBlock -Context $responseEncoder -Headers @([pscustomobject]@{ name = 'grpc-status'; value = '0' })
    $wire = New-MihariTestH2Frame -Type 1 -Flags 5 -StreamId 5 -Payload $trailers
    $frame = (Add-MihariHttp2Input -State $upstream -Bytes $wire -Count $wire.Length).Items[0]
    $null = Invoke-MihariHttp2Frame -Context $ctx -State $upstream -Opposite $client -Frame $frame
    Assert-MihariTest -Condition ($ctx.Streams.Count -eq 0) -Message 'gRPC trailer status must close the stream.'

    $wire = New-MihariTestH2Frame -Type 1 -Flags 5 -StreamId 7 -Payload $requestBlock
    $frame = (Add-MihariHttp2Input -State $client -Bytes $wire -Count $wire.Length).Items[0]
    $null = Invoke-MihariHttp2Frame -Context $ctx -State $client -Opposite $upstream -Frame $frame
    $resetPayload = [byte[]]@(0,0,0,8)
    $wire = New-MihariTestH2Frame -Type 3 -Flags 0 -StreamId 7 -Payload $resetPayload
    $frame = (Add-MihariHttp2Input -State $upstream -Bytes $wire -Count $wire.Length).Items[0]
    $null = Invoke-MihariHttp2Frame -Context $ctx -State $upstream -Opposite $client -Frame $frame
    Assert-MihariTest -Condition ($ctx.Streams.Count -eq 0) -Message 'RST_STREAM must cancel just its stream.'
    $broken = New-MihariHttp2Direction -Leg client
    $broken.FirstSettings = $false
    $continuation = New-MihariTestH2Frame -Type 9 -Flags 4 -StreamId 1
    $frame = (Add-MihariHttp2Input -State $broken -Bytes $continuation -Count $continuation.Length).Items[0]
    Assert-MihariTestH2Rejected -Message 'Orphan CONTINUATION must fail.' -Action { Invoke-MihariHttp2Frame -Context $ctx -State $broken -Opposite $upstream -Frame $frame }
}
finally {
    Close-MihariEventWriter -Writer $writer
    $events = [IO.File]::ReadAllText((Join-Path $temporary 'events.jsonl'))
    Assert-MihariTest -Condition ($events.Contains('/one?token=REDACTED') -and -not $events.Contains('topsecret')) -Message 'HTTP/2 path evidence must redact query values.'
    Assert-MihariTest -Condition ($events.Contains('http2.grpc_status') -and $events.Contains('http2.reset')) -Message 'RPC trailer and reset facts must remain distinct.'
    [IO.Directory]::Delete($temporary,$true)
}
Write-Host 'PASS phase2-http2-native: bounded frame parser, concurrent streams, safe path evidence'
