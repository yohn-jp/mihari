param()

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'TestSupport.ps1')
. (Join-Path (Join-Path (Split-Path $PSScriptRoot -Parent) 'src') 'Http.ps1')
. (Join-Path (Join-Path (Split-Path $PSScriptRoot -Parent) 'src') 'Connection.ps1')

$temporary = Join-Path ([IO.Path]::GetTempPath()) ('mihari-streaming-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($temporary)
$source = $null
$destination = $null
try {
    $bodyLength = [long]33554433
    $header = [Text.Encoding]::ASCII.GetBytes("POST /large HTTP/1.1`r`nHost: example.test`r`nContent-Length: $bodyLength`r`n`r`n")
    $sourcePath = Join-Path $temporary 'large-source.bin'
    $destinationPath = Join-Path $temporary 'large-destination.bin'
    $source = New-Object System.IO.FileStream -ArgumentList @($sourcePath, [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    $source.SetLength($header.Length + $bodyLength)
    $source.Position = 0
    $source.Write($header, 0, $header.Length)
    $source.WriteByte(0x5A)
    $source.Position = $header.Length + $bodyLength - 1
    $source.WriteByte(0xA5)
    $source.Position = 0
    $destination = New-Object System.IO.FileStream -ArgumentList @($destinationPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    $message = Read-MihariHttpHead -Stream $source -Kind Request
    $framing = Get-MihariHttpBodyFraming -Message $message -Kind Request
    Assert-MihariTest -Condition ($message.Body.Length -eq 0 -and $framing.Kind -eq 'ContentLength' -and $framing.Length -eq $bodyLength) -Message 'Large request headers must parse without retaining a body.'
    $transfer = Copy-MihariHttpBody -Source $source -Destination $destination -Framing $framing
    Assert-MihariTest -Condition ($transfer.Bytes -eq $bodyLength -and $destination.Length -eq $bodyLength) -Message 'A body larger than 32 MiB must stream to its destination.'
    $destination.Position = 0
    Assert-MihariTest -Condition ($destination.ReadByte() -eq 0x5A) -Message 'The first binary byte must arrive intact.'
    $destination.Position = $bodyLength - 1
    Assert-MihariTest -Condition ($destination.ReadByte() -eq 0xA5) -Message 'The last binary byte must arrive intact.'
    $source.Dispose(); $source = $null
    $destination.Dispose(); $destination = $null

    $wire = [Text.Encoding]::ASCII.GetBytes("POST /first HTTP/1.1`r`nHost: example.test`r`nTransfer-Encoding: chunked`r`n`r`n3`r`nabc`r`n0`r`nX-Trace: safe`r`n`r`nGET /second HTTP/1.1`r`nHost: example.test`r`n`r`n")
    $input = New-Object System.IO.MemoryStream
    $input.Write($wire, 0, $wire.Length)
    $input.Position = 0
    $output = New-Object System.IO.MemoryStream
    try {
        $first = Read-MihariHttpHead -Stream $input -Kind Request
        $firstFraming = Get-MihariHttpBodyFraming -Message $first -Kind Request
        $firstTransfer = Copy-MihariHttpBody -Source $input -Destination $output -Framing $firstFraming
        $second = Read-MihariHttpHead -Stream $input -Kind Request
        Assert-MihariTest -Condition ($firstTransfer.Bytes -eq $output.Length -and $second.Target -eq '/second') -Message 'Chunk trailers must end before the next persistent request.'
        Assert-MihariTest -Condition ((Get-MihariHttpBodyFraming -Message $second -Kind Request).Kind -eq 'None') -Message 'The next request must retain its own framing.'
    }
    finally { $input.Dispose(); $output.Dispose() }

    $short = New-Object System.IO.MemoryStream
    $shortBytes = [Text.Encoding]::ASCII.GetBytes('early')
    $short.Write($shortBytes, 0, $shortBytes.Length)
    $short.Position = 0
    $partial = New-Object System.IO.MemoryStream
    try {
        $failed = $false
        try { $null = Copy-MihariHttpBody -Source $short -Destination $partial -Framing ([pscustomobject]@{ Kind = 'ContentLength'; Length = [long]10 }) }
        catch [System.IO.EndOfStreamException] { $failed = $true }
        Assert-MihariTest -Condition ($failed -and $partial.Length -eq 5) -Message 'Early bytes must reach the client before an incomplete origin body ends.'
    }
    finally { $short.Dispose(); $partial.Dispose() }

    $earlyReplyWire = [Text.Encoding]::ASCII.GetBytes("HTTP/1.1 417 Expectation Failed`r`nContent-Length: 0`r`n`r`n")
    $afterFirstByte = New-Object System.IO.MemoryStream
    try {
        $afterFirstByte.Write($earlyReplyWire, 1, $earlyReplyWire.Length - 1)
        $afterFirstByte.Position = 0
        $earlyReply = Read-MihariHttpHead -Stream $afterFirstByte -Kind Response -InitialByte $earlyReplyWire[0]
        Assert-MihariTest -Condition ($earlyReply.StatusCode -eq 417 -and
            (Get-MihariHttpBodyFraming -Message $earlyReply -Kind Response).Length -eq 0) -Message 'An upstream response detected by its first byte must parse without losing framing.'
    }
    finally { $afterFirstByte.Dispose() }

    $upgradeWire = [Text.Encoding]::ASCII.GetBytes("GET /chat HTTP/1.1`r`nHost: example.test`r`nConnection: Upgrade`r`nUpgrade: websocket`r`nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==`r`nSec-WebSocket-Version: 13`r`n`r`n")
    $upgradeInput = New-Object System.IO.MemoryStream
    $upgradeInput.Write($upgradeWire, 0, $upgradeWire.Length)
    $upgradeInput.Position = 0
    $upgradeOutput = New-Object System.IO.MemoryStream
    try {
        $upgrade = Read-MihariHttpHead -Stream $upgradeInput -Kind Request
        Assert-MihariTest -Condition (Test-MihariWebSocketRequest -Message $upgrade) -Message 'A valid WebSocket upgrade must be recognized.'
        Write-MihariHttpHead -Stream $upgradeOutput -Message $upgrade -UpgradeWebSocket
        $outgoing = [Text.Encoding]::ASCII.GetString($upgradeOutput.ToArray())
        Assert-MihariTest -Condition ($outgoing -match '(?im)^Connection: Upgrade\r?$' -and $outgoing -match '(?im)^Upgrade: websocket\r?$') -Message 'WebSocket handshake headers must survive forwarding.'
    }
    finally { $upgradeInput.Dispose(); $upgradeOutput.Dispose() }
    $capacity = [pscustomobject]@{ StateLock = New-Object object; MaxWorkers = 1; ActiveLongLivedCount = 0 }
    Assert-MihariTest -Condition (-not (Enter-MihariLongLivedSlot -Session $capacity)) -Message 'One worker must be reserved when the pool has only one worker.'
    $capacity.MaxWorkers = 2
    Assert-MihariTest -Condition (Enter-MihariLongLivedSlot -Session $capacity) -Message 'A two-worker pool must admit one long-lived exchange.'
    Assert-MihariTest -Condition (-not (Enter-MihariLongLivedSlot -Session $capacity)) -Message 'A second long-lived exchange must leave ordinary request capacity.'
    Exit-MihariLongLivedSlot -Session $capacity
    Assert-MihariTest -Condition ($capacity.ActiveLongLivedCount -eq 0) -Message 'Long-lived worker capacity must return after relay completion.'
    Write-Host 'PASS phase2-streaming: >32 MiB streaming, early bytes, persistent framing, WebSocket upgrade'
}
finally {
    if ($null -ne $source) { $source.Dispose() }
    if ($null -ne $destination) { $destination.Dispose() }
    if ([IO.Directory]::Exists($temporary)) { [IO.Directory]::Delete($temporary, $true) }
}
