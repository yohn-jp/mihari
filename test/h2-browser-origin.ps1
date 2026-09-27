param(
    [Parameter(Mandatory = $true)][string] $ReadyPath,
    [Parameter(Mandatory = $true)][string] $StopPath,
    [Parameter(Mandatory = $true)][string] $TransactionsPath,
    [Parameter(Mandatory = $true)][string] $ErrorPath
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path $PSScriptRoot -Parent
. (Join-Path $repoRoot 'src/Certificate.ps1')

function Read-MihariH2FixtureBytes {
    param([Parameter(Mandatory = $true)][System.IO.Stream] $Stream, [Parameter(Mandatory = $true)][int] $Count)

    $buffer = New-Object 'byte[]' $Count
    $offset = 0
    while ($offset -lt $Count) {
        $read = $Stream.Read($buffer, $offset, $Count - $offset)
        if ($read -le 0) { throw 'h2 peer closed before a complete frame was received.' }
        $offset += $read
    }
    return ,$buffer
}

function Read-MihariH2FixtureFrame {
    param([Parameter(Mandatory = $true)][System.IO.Stream] $Stream)

    $header = Read-MihariH2FixtureBytes -Stream $Stream -Count 9
    $length = ([int]$header[0] -shl 16) -bor ([int]$header[1] -shl 8) -bor [int]$header[2]
    if ($length -gt 16384) { throw 'h2 client frame exceeded the default frame-size limit.' }
    $streamId = (([long]$header[5] -band 0x7f) -shl 24) -bor
        ([long]$header[6] -shl 16) -bor ([long]$header[7] -shl 8) -bor [long]$header[8]
    $payload = [byte[]]@()
    if ($length -gt 0) { $payload = Read-MihariH2FixtureBytes -Stream $Stream -Count $length }
    return [pscustomobject]@{
        Length = $length
        Type = [int]$header[3]
        Flags = [int]$header[4]
        StreamId = [long]$streamId
        Payload = $payload
    }
}

function Write-MihariH2FixtureFrame {
    param(
        [Parameter(Mandatory = $true)][System.IO.Stream] $Stream,
        [Parameter(Mandatory = $true)][int] $Type,
        [Parameter(Mandatory = $true)][int] $Flags,
        [Parameter(Mandatory = $true)][long] $StreamId,
        [AllowEmptyCollection()][byte[]] $Payload = [byte[]]@()
    )

    if ($Payload.Length -gt 16384) { throw 'h2 server fixture frame exceeds the default frame-size limit.' }
    $length = $Payload.Length
    $header = New-Object byte[] 9
    $header[0] = [byte](($length -shr 16) -band 0xff)
    $header[1] = [byte](($length -shr 8) -band 0xff)
    $header[2] = [byte]($length -band 0xff)
    $header[3] = [byte]$Type
    $header[4] = [byte]$Flags
    $header[5] = [byte](($StreamId -shr 24) -band 0x7f)
    $header[6] = [byte](($StreamId -shr 16) -band 0xff)
    $header[7] = [byte](($StreamId -shr 8) -band 0xff)
    $header[8] = [byte]($StreamId -band 0xff)
    $Stream.Write($header, 0, $header.Length)
    if ($Payload.Length -gt 0) { $Stream.Write($Payload, 0, $Payload.Length) }
    $Stream.Flush()
}

function Read-MihariHpackInteger {
    param(
        [Parameter(Mandatory = $true)][byte[]] $Bytes,
        [Parameter(Mandatory = $true)][ref] $Offset,
        [Parameter(Mandatory = $true)][int] $PrefixBits
    )

    if ($Offset.Value -ge $Bytes.Length) { throw 'h2 HPACK integer is truncated.' }
    $mask = (1 -shl $PrefixBits) - 1
    $first = [int]$Bytes[$Offset.Value]
    $Offset.Value++
    $value = $first -band $mask
    if ($value -lt $mask) { return [long]$value }
    $shift = 0
    do {
        if ($Offset.Value -ge $Bytes.Length -or $shift -gt 28) { throw 'h2 HPACK integer is invalid.' }
        $part = [int]$Bytes[$Offset.Value]
        $Offset.Value++
        $value += ([long]($part -band 0x7f) -shl $shift)
        $shift += 7
    } while (($part -band 0x80) -ne 0)
    return [long]$value
}

function Skip-MihariHpackString {
    param([Parameter(Mandatory = $true)][byte[]] $Bytes, [Parameter(Mandatory = $true)][ref] $Offset)

    if ($Offset.Value -ge $Bytes.Length) { throw 'h2 HPACK string is truncated.' }
    $length = Read-MihariHpackInteger -Bytes $Bytes -Offset $Offset -PrefixBits 7
    if ($length -gt ($Bytes.Length - $Offset.Value)) { throw 'h2 HPACK string length exceeds its header block.' }
    $offsetValue = [int]$Offset.Value
    $Offset.Value = $offsetValue + [int]$length
    return [pscustomobject]@{ Huffman = (([int]$Bytes[$offsetValue - 1] -band 0x80) -ne 0); Length = [int]$length; Offset = $offsetValue }
}

function Test-MihariHpackRootPath {
    param([Parameter(Mandatory = $true)][byte[]] $HeaderBlock)

    $offset = 0
    while ($offset -lt $HeaderBlock.Length) {
        $first = [int]$HeaderBlock[$offset]
        if (($first -band 0x80) -ne 0) {
            $index = Read-MihariHpackInteger -Bytes $HeaderBlock -Offset ([ref]$offset) -PrefixBits 7
            if ($index -eq 4) { return $true } # Static table entry :path: /
            continue
        }

        if (($first -band 0x40) -ne 0) { $prefix = 6 }
        elseif (($first -band 0x20) -ne 0) {
            $null = Read-MihariHpackInteger -Bytes $HeaderBlock -Offset ([ref]$offset) -PrefixBits 5
            continue
        }
        else { $prefix = 4 }

        $nameIndex = Read-MihariHpackInteger -Bytes $HeaderBlock -Offset ([ref]$offset) -PrefixBits $prefix
        if ($nameIndex -eq 0) {
            $null = Skip-MihariHpackString -Bytes $HeaderBlock -Offset ([ref]$offset)
        }
        $value = Skip-MihariHpackString -Bytes $HeaderBlock -Offset ([ref]$offset)
        if ($nameIndex -eq 4 -and -not $value.Huffman -and $value.Length -eq 1 -and
            [char]$HeaderBlock[$value.Offset] -eq '/') { return $true }
    }
    return $false
}

function Get-MihariH2FixtureHeaderBlock {
    param([Parameter(Mandatory = $true)] $FirstFrame, [Parameter(Mandatory = $true)][System.IO.Stream] $Stream)

    $memory = New-Object System.IO.MemoryStream
    try {
        $payloadOffset = 0
        $padding = 0
        if (($FirstFrame.Flags -band 0x08) -ne 0) {
            if ($FirstFrame.Payload.Length -lt 1) { throw 'h2 padded HEADERS frame is invalid.' }
            $padding = [int]$FirstFrame.Payload[0]
            $payloadOffset = 1
        }
        if (($FirstFrame.Flags -band 0x20) -ne 0) { $payloadOffset += 5 }
        $blockLength = $FirstFrame.Payload.Length - $payloadOffset - $padding
        if ($blockLength -lt 0) { throw 'h2 HEADERS frame padding is invalid.' }
        $memory.Write($FirstFrame.Payload, $payloadOffset, $blockLength)
        $complete = ($FirstFrame.Flags -band 0x04) -ne 0
        while (-not $complete) {
            $continuation = Read-MihariH2FixtureFrame -Stream $Stream
            if ($continuation.Type -ne 9 -or $continuation.StreamId -ne $FirstFrame.StreamId) {
                throw 'h2 HEADERS block was not followed by its matching CONTINUATION frame.'
            }
            $memory.Write($continuation.Payload, 0, $continuation.Payload.Length)
            if ($memory.Length -gt 65536) { throw 'h2 request header block exceeded the fixture limit.' }
            $complete = ($continuation.Flags -band 0x04) -ne 0
        }
        if ($memory.Length -gt 65536) { throw 'h2 request header block exceeded the fixture limit.' }
        return ,([byte[]]$memory.ToArray())
    }
    finally { $memory.Dispose() }
}

function Get-MihariH2FixtureProtocolList {
    $list = New-Object 'System.Collections.Generic.List[System.Net.Security.SslApplicationProtocol]'
    $list.Add([System.Net.Security.SslApplicationProtocol]::Http2)
    return ,$list
}

function Write-MihariH2FixtureResponse {
    param(
        [Parameter(Mandatory = $true)][System.IO.Stream] $Stream,
        [Parameter(Mandatory = $true)][long] $StreamId,
        [Parameter(Mandatory = $true)][byte[]] $Body
    )

    # HPACK static index 8 is :status 200; literal names 28, 31, and 24 are
    # content-length, content-type, and cache-control.
    $headerBlock = New-Object 'System.Collections.Generic.List[byte]'
    $headerBlock.Add([byte]0x88)
    $contentLengthName = [byte[]]@(0x0f, 0x0d)
    foreach ($value in $contentLengthName) { $headerBlock.Add([byte]$value) }
    $contentLength = [System.Text.Encoding]::ASCII.GetBytes([string]$Body.Length)
    $headerBlock.Add([byte]$contentLength.Length)
    foreach ($value in $contentLength) { $headerBlock.Add([byte]$value) }
    foreach ($value in @([byte]0x0f, [byte]0x10)) { $headerBlock.Add($value) }
    $contentType = [System.Text.Encoding]::ASCII.GetBytes('text/html; charset=utf-8')
    $headerBlock.Add([byte]$contentType.Length)
    foreach ($value in $contentType) { $headerBlock.Add([byte]$value) }
    foreach ($value in @([byte]0x0f, [byte]0x09)) { $headerBlock.Add($value) }
    $cacheControl = [System.Text.Encoding]::ASCII.GetBytes('no-store')
    $headerBlock.Add([byte]$cacheControl.Length)
    foreach ($value in $cacheControl) { $headerBlock.Add([byte]$value) }
    Write-MihariH2FixtureFrame -Stream $Stream -Type 1 -Flags 4 -StreamId $StreamId -Payload ([byte[]]$headerBlock.ToArray())
    if ($Body.Length -eq 0) {
        Write-MihariH2FixtureFrame -Stream $Stream -Type 0 -Flags 1 -StreamId $StreamId -Payload ([byte[]]@())
    }
    else {
        Write-MihariH2FixtureFrame -Stream $Stream -Type 0 -Flags 1 -StreamId $StreamId -Payload $Body
    }
}

function Invoke-MihariH2FixtureConnection {
    param(
        [Parameter(Mandatory = $true)][System.Net.Sockets.TcpClient] $Client,
        [Parameter(Mandatory = $true)][System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate,
        [Parameter(Mandatory = $true)][string] $TransactionsFile
    )

    $tls = $null
    try {
        $Client.ReceiveTimeout = 10000
        $Client.SendTimeout = 10000
        $tls = [System.Net.Security.SslStream]::new($Client.GetStream(), $false)
        $tls.ReadTimeout = 10000
        $tls.WriteTimeout = 10000
        $options = [System.Net.Security.SslServerAuthenticationOptions]::new()
        $options.ServerCertificate = $Certificate
        $options.EnabledSslProtocols = [System.Security.Authentication.SslProtocols]::Tls12
        $options.ApplicationProtocols = Get-MihariH2FixtureProtocolList
        $tls.AuthenticateAsServerAsync($options).GetAwaiter().GetResult()
        $protocolBytes = $tls.NegotiatedApplicationProtocol.Protocol.ToArray()
        $protocol = [System.Text.Encoding]::ASCII.GetString($protocolBytes)
        if ($protocol -ne 'h2') { throw ('Expected h2 ALPN; server negotiated {0}.' -f $protocol) }

        $preface = [System.Text.Encoding]::ASCII.GetString((Read-MihariH2FixtureBytes -Stream $tls -Count 24))
        if ($preface -cne "PRI * HTTP/2.0`r`n`r`nSM`r`n`r`n") { throw 'h2 client connection preface was invalid.' }
        Write-MihariH2FixtureFrame -Stream $tls -Type 4 -Flags 0 -StreamId 0 -Payload ([byte[]]@())

        $rootTransactionCount = 0
        $totalTransactionCount = 0
        $fixtureDeadline = [DateTime]::UtcNow.AddSeconds(12)
        while ($rootTransactionCount -lt 2 -and $totalTransactionCount -lt 64 -and [DateTime]::UtcNow -lt $fixtureDeadline) {
            $frame = Read-MihariH2FixtureFrame -Stream $tls
            if ($frame.Type -eq 4 -and ($frame.Flags -band 0x01) -eq 0) {
                Write-MihariH2FixtureFrame -Stream $tls -Type 4 -Flags 1 -StreamId 0 -Payload ([byte[]]@())
                continue
            }
            if ($frame.Type -eq 6 -and ($frame.Flags -band 0x01) -eq 0) {
                Write-MihariH2FixtureFrame -Stream $tls -Type 6 -Flags 1 -StreamId 0 -Payload $frame.Payload
                continue
            }
            if ($frame.Type -ne 1 -or $frame.StreamId -le 0) { continue }

            $headerBlock = Get-MihariH2FixtureHeaderBlock -FirstFrame $frame -Stream $tls
            $rootPathObserved = Test-MihariHpackRootPath -HeaderBlock $headerBlock
            $totalTransactionCount++
            $body = [byte[]]@()
            if ($rootPathObserved) { $rootTransactionCount++ }
            if ($rootPathObserved -and $rootTransactionCount -eq 1) {
                $page = '<!doctype html><html><body><script>setTimeout(function(){fetch("/")},500)</script>h2 tunnel fixture</body></html>'
                $body = [System.Text.Encoding]::UTF8.GetBytes($page)
            }
            Write-MihariH2FixtureResponse -Stream $tls -StreamId $frame.StreamId -Body $body
            $record = [pscustomobject]@{
                alpnProtocol = $protocol
                streamId = [long]$frame.StreamId
                requestPathRootObserved = [bool]$rootPathObserved
                responseStatus = 200
                responseHeadersSent = $true
                responseBodyBytes = [int]$body.Length
            }
            [System.IO.File]::AppendAllText($TransactionsFile, (ConvertTo-Json -InputObject $record -Compress) + [Environment]::NewLine, [System.Text.Encoding]::UTF8)
        }
        if ($rootTransactionCount -lt 2) { throw 'The local h2 fixture did not receive the initial root GET and its delayed script fetch within the bounded stream window.' }
    }
    finally {
        if ($null -ne $tls) { $tls.Dispose() }
        $Client.Close()
    }
}

$ca = $null
$leafSession = $null
$leaf = $null
$listener = $null
$publicCertificatePath = [System.IO.Path]::ChangeExtension($ReadyPath, '.cer')
$errorDocument = $null
try {
    $ca = New-MihariCA -SessionId ([guid]::NewGuid().ToString('N'))
    $leafSession = [pscustomobject]@{ CA = $ca; LeafCache = [hashtable]::Synchronized(@{}) }
    $leaf = Get-MihariLeaf -Session $leafSession -DestinationHost 'localhost'
    $publicCa = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
        $ca.Certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
    )
    try { [System.IO.File]::WriteAllBytes($publicCertificatePath, $publicCa.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)) }
    finally { $publicCa.Dispose() }

    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $listener.Start()
    $port = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
    $ready = [pscustomobject]@{
        port = [int]$port
        caSubject = [string]$ca.Subject
        caThumbprint = [string]$ca.Thumbprint
        leafThumbprint = [string]$leaf.Thumbprint
        publicCertificatePath = $publicCertificatePath
    }
    [System.IO.File]::WriteAllText($ReadyPath, (ConvertTo-Json -InputObject $ready -Compress), [System.Text.Encoding]::UTF8)

    while (-not [System.IO.File]::Exists($StopPath)) {
        $accept = $listener.AcceptTcpClientAsync()
        if (-not $accept.Wait(250)) { continue }
        $client = $accept.Result
        try { Invoke-MihariH2FixtureConnection -Client $client -Certificate $leaf -TransactionsFile $TransactionsPath }
        catch {
            if (-not [System.IO.File]::Exists($StopPath)) {
                $errorDocument = [pscustomobject]@{ errorType = $_.Exception.GetType().FullName; message = $_.Exception.Message }
                [System.IO.File]::WriteAllText($ErrorPath, (ConvertTo-Json -InputObject $errorDocument -Compress), [System.Text.Encoding]::UTF8)
            }
        }
    }
}
catch {
    $errorDocument = [pscustomobject]@{ errorType = $_.Exception.GetType().FullName; message = $_.Exception.Message }
    try { [System.IO.File]::WriteAllText($ErrorPath, (ConvertTo-Json -InputObject $errorDocument -Compress), [System.Text.Encoding]::UTF8) }
    catch { Write-Warning ('Could not record local h2 fixture error ({0}).' -f $_.Exception.GetType().FullName) }
}
finally {
    if ($null -ne $listener) { $listener.Stop() }
    if ($null -ne $leaf -and $null -ne $leafSession) {
        try { Release-MihariLeaf -Session $leafSession -Certificate $leaf }
        catch { Write-Warning ('Could not release local h2 fixture leaf ({0}).' -f $_.Exception.GetType().FullName) }
        try { Clear-MihariLeafCache -Session $leafSession }
        catch { Write-Warning ('Could not clear local h2 fixture leaf cache ({0}).' -f $_.Exception.GetType().FullName) }
    }
    if ($null -ne $ca) {
        try { $ca.Certificate.Dispose(); $ca.PrivateKey.Dispose() }
        catch { Write-Warning ('Could not dispose local h2 fixture CA ({0}).' -f $_.Exception.GetType().FullName) }
    }
}

if ($null -ne $errorDocument) { exit 1 }
exit 0
