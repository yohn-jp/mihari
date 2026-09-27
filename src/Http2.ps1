# Native HTTP/2 frame relay for the PowerShell 7 ALPN path. The two TLS legs
# retain their own connection IDs even though this byte-preserving relay keeps
# stream numbers unchanged. No payload or compressed field block is an event.

function Resolve-MihariHttp2Type {
    param([string]$Name)
    $found = [type]::GetType($Name, $false)
    if ($null -ne $found) { return $found }
    foreach ($assembly in [AppDomain]::CurrentDomain.GetAssemblies()) {
        $found = $assembly.GetType($Name, $false)
        if ($null -ne $found) { return $found }
    }
    return $null
}

function Test-MihariHttp2AuthenticationMethod {
    param([type]$SslType, [type]$OptionsType, [string]$Name)
    if ($null -eq $OptionsType) { return $false }
    foreach ($method in $SslType.GetMethods()) {
        if ($method.Name -ne $Name -and $method.Name -ne ($Name + 'Async')) { continue }
        $parameters = $method.GetParameters()
        if ($parameters.Length -gt 0 -and $parameters[0].ParameterType -eq $OptionsType) { return $true }
    }
    return $false
}

function Test-MihariHttp2RuntimeCapability {
    $ssl = [System.Net.Security.SslStream]
    $server = Resolve-MihariHttp2Type -Name 'System.Net.Security.SslServerAuthenticationOptions'
    $client = Resolve-MihariHttp2Type -Name 'System.Net.Security.SslClientAuthenticationOptions'
    $alpn = Resolve-MihariHttp2Type -Name 'System.Net.Security.SslApplicationProtocol'
    $members = [ordered]@{
        serverOptions = ($null -ne $server)
        clientOptions = ($null -ne $client)
        applicationProtocol = ($null -ne $alpn)
        serverProtocols = ($null -ne $server -and $null -ne $server.GetProperty('ApplicationProtocols'))
        clientProtocols = ($null -ne $client -and $null -ne $client.GetProperty('ApplicationProtocols'))
        negotiatedProtocol = ($null -ne $ssl.GetProperty('NegotiatedApplicationProtocol'))
        serverAuthenticate = (Test-MihariHttp2AuthenticationMethod -SslType $ssl -OptionsType $server -Name 'AuthenticateAsServer')
        clientAuthenticate = (Test-MihariHttp2AuthenticationMethod -SslType $ssl -OptionsType $client -Name 'AuthenticateAsClient')
    }
    $available = $true
    foreach ($value in $members.Values) { if (-not $value) { $available = $false } }
    return [pscustomobject]@{ Available = $available; Members = $members; Runtime = [string]$PSVersionTable.PSVersion }
}

function Get-MihariHttp2NegotiatedProtocol {
    param([System.Net.Security.SslStream]$Tls)
    $property = $Tls.GetType().GetProperty('NegotiatedApplicationProtocol')
    if ($null -eq $property) { return $null }
    $selected = $property.GetValue($Tls, $null)
    if ($null -eq $selected) { return $null }
    $protocol = $selected.GetType().GetProperty('Protocol').GetValue($selected, $null)
    if ($protocol -is [byte[]]) { return [Text.Encoding]::ASCII.GetString($protocol) }
    $toArray = $protocol.GetType().GetMethod('ToArray', [type[]]@())
    if ($null -eq $toArray) { return $null }
    return [Text.Encoding]::ASCII.GetString([byte[]]$toArray.Invoke($protocol, [object[]]@()))
}

function Get-MihariHttp2UInt32 {
    param([byte[]]$Bytes, [int]$Offset)
    return ([long]$Bytes[$Offset] -shl 24) -bor ([long]$Bytes[$Offset+1] -shl 16) -bor ([long]$Bytes[$Offset+2] -shl 8) -bor [long]$Bytes[$Offset+3]
}

function New-MihariHttp2Direction {
    param([ValidateSet('client','upstream')][string]$Leg)
    return [pscustomobject]@{
        Leg = $Leg
        # One maximum supported frame plus one TLS read, so a read containing
        # the end of a frame and the start of the next can be drained safely.
        Pending = [byte[]]::new(81929)
        PendingLength = 0
        Preface = ($Leg -eq 'client')
        FirstSettings = $true
        MaxFrame = 16384
        ContinuationStream = 0
        HeaderBlock = New-Object System.IO.MemoryStream
        HeldFrames = New-Object 'System.Collections.Generic.List[object]'
        HeaderEndStream = $false
        Hpack = New-MihariHpackContext -MaxTableSize 4096
        PendingTableLimits = New-Object 'System.Collections.Generic.List[object]'
        LastOpenedStream = 0
        InitialWindow = [long]65535
        ConnectionWindow = [long]65535
        ConnectionFlowWaitStarted = $null
        StreamWindows = @{}
        FlowWaitStarted = @{}
        Settings = @{ maxConcurrentStreams = $null; maxFrameSize = 16384; initialWindowSize = 65535; headerTableSize = 4096 }
        GoAway = $false
    }
}

function Add-MihariHttp2Input {
    param($State, [byte[]]$Bytes, [int]$Count)
    if ($Count -lt 0 -or $Count -gt $Bytes.Length -or $State.PendingLength + $Count -gt $State.Pending.Length) {
        throw [System.IO.InvalidDataException]::new('HTTP/2 input exceeds the bounded frame buffer.')
    }
    [Array]::Copy($Bytes, 0, $State.Pending, $State.PendingLength, $Count)
    $State.PendingLength += $Count
    $ready = New-Object 'System.Collections.Generic.List[object]'
    $prefaceBytes = [System.Text.Encoding]::ASCII.GetBytes("PRI * HTTP/2.0`r`n`r`nSM`r`n`r`n")
    while ($true) {
        if ($State.Preface) {
            if ($State.PendingLength -lt 24) { break }
            for ($i = 0; $i -lt 24; $i++) {
                if ($State.Pending[$i] -ne $prefaceBytes[$i]) { throw [System.IO.InvalidDataException]::new('Invalid HTTP/2 client preface.') }
            }
            $ready.Add([pscustomobject]@{ Preface = $true; Bytes = $prefaceBytes })
            [Array]::Copy($State.Pending, 24, $State.Pending, 0, $State.PendingLength - 24)
            $State.PendingLength -= 24
            $State.Preface = $false
        }
        if ($State.PendingLength -lt 9) { break }
        $length = ([int]$State.Pending[0] -shl 16) -bor ([int]$State.Pending[1] -shl 8) -bor [int]$State.Pending[2]
        if ($length -gt [int]$State.MaxFrame -or $length -gt 65536) {
            throw [System.IO.InvalidDataException]::new('HTTP/2 frame exceeds negotiated or local bounded size.')
        }
        if ($State.PendingLength -lt 9 + $length) { break }
        $wire = [byte[]]::new(9 + $length)
        [Array]::Copy($State.Pending, 0, $wire, 0, $wire.Length)
        $remaining = $State.PendingLength - $wire.Length
        if ($remaining -gt 0) { [Array]::Copy($State.Pending, $wire.Length, $State.Pending, 0, $remaining) }
        $State.PendingLength = $remaining
        $streamId = [int]((Get-MihariHttp2UInt32 -Bytes $wire -Offset 5) -band 0x7fffffff)
        $ready.Add([pscustomobject]@{ Preface = $false; Bytes = $wire; Length = $length; Type = [int]$wire[3]; Flags = [int]$wire[4]; StreamId = $streamId })
    }
    return [pscustomobject]@{ Items = $ready.ToArray() }
}

function Get-MihariHttp2HeaderFragment {
    param($Frame)
    $start = 9
    $end = 9 + $Frame.Length
    if (($Frame.Flags -band 8) -ne 0) {
        if ($Frame.Length -lt 1) { throw [System.IO.InvalidDataException]::new('HTTP/2 padded HEADERS has no pad length.') }
        $pad = [int]$Frame.Bytes[9]
        $start++
        $end -= $pad
    }
    if (($Frame.Flags -band 32) -ne 0) { $start += 5 }
    if ($start -gt $end) { throw [System.IO.InvalidDataException]::new('Invalid HTTP/2 HEADERS padding or priority.') }
    $fragment = [byte[]]::new($end - $start)
    if ($fragment.Length -gt 0) { [Array]::Copy($Frame.Bytes, $start, $fragment, 0, $fragment.Length) }
    return ,$fragment
}

function Assert-MihariHttp2HeaderSemantics {
    param([object[]]$Headers, [bool]$Request, [bool]$Trailer, [string]$ConnectHost, [int]$ConnectPort)
    $pseudoSeen = @{}
    $regularSeen = $false
    $safe = @{}
    foreach ($field in $Headers) {
        $name = [string]$field.name
        $value = [string]$field.value
        if ($name -cne $name.ToLowerInvariant() -or $name -match '[^\x21-\x7e]' -or $name.Length -eq 0) {
            throw [System.IO.InvalidDataException]::new('Invalid HTTP/2 field name.')
        }
        if ($name.StartsWith(':')) {
            $allowed = $(if ($Request) { @(':method',':scheme',':authority',':path') } else { @(':status') })
            if ($name -notin $allowed) { throw [System.IO.InvalidDataException]::new('Unexpected HTTP/2 pseudo field.') }
            if ($Trailer -or $regularSeen -or $pseudoSeen.ContainsKey($name)) { throw [System.IO.InvalidDataException]::new('Invalid HTTP/2 pseudo field ordering.') }
            $pseudoSeen[$name] = $true
        }
        else { $regularSeen = $true }
        if ($name -in @('connection','proxy-connection','keep-alive','transfer-encoding','upgrade')) {
            throw [System.IO.InvalidDataException]::new('Forbidden HTTP/2 connection field.')
        }
        if ($name -eq 'te' -and $value -cne 'trailers') { throw [System.IO.InvalidDataException]::new('Invalid HTTP/2 TE field.') }
        if ($name -in @(':method',':scheme',':authority',':path',':status','grpc-status','content-type')) {
            if ($value.Length -gt 4096) { throw [System.IO.InvalidDataException]::new('HTTP/2 field value exceeds bound.') }
            $safe[$name] = $value
        }
    }
    if (-not $Trailer) {
        if ($Request) {
            if (-not $safe.ContainsKey(':method') -or -not $safe.ContainsKey(':scheme') -or -not $safe.ContainsKey(':authority') -or -not $safe.ContainsKey(':path')) {
                throw [System.IO.InvalidDataException]::new('Required HTTP/2 request pseudo fields are missing.')
            }
            if ($safe[':scheme'] -cne 'https' -or $safe[':method'] -eq 'CONNECT') {
                throw [System.IO.InvalidDataException]::new('Unsupported HTTP/2 request form.')
            }
            if ($safe[':method'].Length -gt 32 -or $safe[':method'] -cnotmatch '^[!#$%&''*+.^_`|~0-9A-Z-]+$') {
                throw [System.IO.InvalidDataException]::new('Invalid HTTP/2 method token.')
            }
            $authority = $safe[':authority']
            try { $uri = [Uri]::new(('https://' + $authority + '/')) }
            catch { throw [System.IO.InvalidDataException]::new('Invalid HTTP/2 authority.') }
            if (-not [string]::Equals($uri.DnsSafeHost.TrimEnd('.'), $ConnectHost.TrimEnd('.'), [StringComparison]::OrdinalIgnoreCase) -or $uri.Port -ne $ConnectPort -or $authority -match '[@/?#]') {
                throw [System.IO.InvalidDataException]::new('HTTP/2 authority differs from CONNECT destination.')
            }
            if (-not $safe[':path'].StartsWith('/') -or $safe[':path'] -match '[\x00-\x1f\x7f#]') { throw [System.IO.InvalidDataException]::new('Invalid HTTP/2 path.') }
        }
        else {
            $status = 0
            if (-not $safe.ContainsKey(':status') -or -not [int]::TryParse($safe[':status'], [ref]$status) -or $status -lt 100 -or $status -gt 599) {
                throw [System.IO.InvalidDataException]::new('Invalid HTTP/2 response status.')
            }
        }
    }
    return $safe
}

function Write-MihariHttp2Fact {
    param($Context, $State, [int]$StreamId, [string]$Stage, [string]$Outcome, [hashtable]$Data)
    $requestId = $null
    if ($StreamId -ne 0 -and $Context.Streams.ContainsKey($StreamId)) { $requestId = $Context.Streams[$StreamId].RequestId }
    $null = Write-MihariEvent -Session $Context.Session -ConnectionId $Context.ConnectionId -RequestId $requestId `
        -UpstreamConnectionId $Context.UpstreamConnectionId -StreamId ([string]$StreamId) -TransportLeg $State.Leg `
        -ConfigurationRevision $Context.ConfigurationRevision -Mode $Context.Mode -Stage $Stage -Outcome $Outcome `
        -ElapsedMs $Context.Clock.ElapsedMilliseconds -Data $Data
}

function Invoke-MihariHttp2Frame {
    param($Context, $State, $Opposite, $Frame)
    $forward = New-Object 'System.Collections.Generic.List[object]'
    if ($Frame.Preface) { $forward.Add($Frame.Bytes); return [pscustomobject]@{ Frames = $forward.ToArray() } }
    $type = $Frame.Type
    $flags = $Frame.Flags
    $id = $Frame.StreamId
    $len = $Frame.Length
    $bytes = $Frame.Bytes
    if ($State.FirstSettings) {
        if ($type -ne 4 -or $id -ne 0 -or ($flags -band 1) -ne 0) { throw [System.IO.InvalidDataException]::new('First HTTP/2 frame must be SETTINGS.') }
        $State.FirstSettings = $false
    }
    if ($State.ContinuationStream -ne 0 -and ($type -ne 9 -or $id -ne $State.ContinuationStream)) {
        throw [System.IO.InvalidDataException]::new('HTTP/2 header block was interrupted.')
    }
    if ($type -eq 9 -and $State.ContinuationStream -eq 0) { throw [System.IO.InvalidDataException]::new('Unexpected HTTP/2 CONTINUATION.') }
    if ($type -in @(0,1,2,3,5,9) -and $id -eq 0) { throw [System.IO.InvalidDataException]::new('HTTP/2 stream frame used stream zero.') }
    if ($type -in @(4,6,7) -and $id -ne 0) { throw [System.IO.InvalidDataException]::new('HTTP/2 connection frame used nonzero stream.') }
    switch ($type) {
        0 { # DATA: no body is retained.
            $pad = 0
            if (($flags -band 8) -ne 0) {
                if ($len -lt 1) { throw [System.IO.InvalidDataException]::new('Invalid padded HTTP/2 DATA.') }
                $pad = [int]$bytes[9] + 1
                if ($pad -gt $len) { throw [System.IO.InvalidDataException]::new('Invalid HTTP/2 DATA padding.') }
            }
            if (-not $Context.Streams.ContainsKey($id)) { throw [System.IO.InvalidDataException]::new('DATA on an unopened HTTP/2 stream.') }
            $stream = $Context.Streams[$id]
            if ($stream.Reset) { throw [System.IO.InvalidDataException]::new('DATA on a reset HTTP/2 stream.') }
            if (($State.Leg -eq 'client' -and ($stream.RequestHeaders -eq 0 -or $stream.RequestClosed)) -or
                ($State.Leg -eq 'upstream' -and ($stream.ResponseHeaders -eq 0 -or $stream.ResponseClosed))) {
                throw [System.IO.InvalidDataException]::new('DATA before headers or after END_STREAM.')
            }
            $key = [string]$id
            if (-not $State.StreamWindows.ContainsKey($key)) { $State.StreamWindows[$key] = [long]$State.InitialWindow }
            $State.ConnectionWindow -= $len
            $State.StreamWindows[$key] = [long]$State.StreamWindows[$key] - $len
            if ($State.ConnectionWindow -lt 0 -or [long]$State.StreamWindows[$key] -lt 0) {
                throw [System.IO.InvalidDataException]::new('HTTP/2 flow-control window exceeded.')
            }
            if ($State.ConnectionWindow -eq 0 -and $null -eq $State.ConnectionFlowWaitStarted) { $State.ConnectionFlowWaitStarted = $Context.Clock.ElapsedMilliseconds }
            if ([long]$State.StreamWindows[$key] -eq 0 -and -not $State.FlowWaitStarted.ContainsKey($key)) { $State.FlowWaitStarted[$key] = $Context.Clock.ElapsedMilliseconds }
            if ($State.Leg -eq 'client') { $stream.RequestBytes += ($len - $pad) } else { $stream.ResponseBytes += ($len - $pad) }
            if (($flags -band 1) -ne 0) { if ($State.Leg -eq 'client') { $stream.RequestClosed = $true } else { $stream.ResponseClosed = $true } }
        }
        1 { # HEADERS and its CONTINUATION frames are held until HPACK validates.
            if ($id % 2 -eq 0 -and $State.Leg -eq 'client') { throw [System.IO.InvalidDataException]::new('Client HTTP/2 stream ID must be odd.') }
            if ($State.Leg -eq 'client' -and -not $Context.Streams.ContainsKey($id)) {
                $peerLimit = $Opposite.Settings.maxConcurrentStreams
                if ($id -le $State.LastOpenedStream -or $Context.Streams.Count -ge 128 -or $State.GoAway -or $Opposite.GoAway -or ($null -ne $peerLimit -and $Context.Streams.Count -ge [long]$peerLimit)) {
                    throw [System.IO.InvalidDataException]::new('HTTP/2 stream limit or ordering violation.')
                }
                $State.LastOpenedStream = $id
                $Context.Streams[$id] = [pscustomobject]@{ RequestId = [guid]::NewGuid().ToString('N'); RequestHeaders = 0; ResponseHeaders = 0; RequestClosed = $false; ResponseClosed = $false; Reset = $false; RequestBytes = [long]0; ResponseBytes = [long]0; StartedMs = $Context.Clock.ElapsedMilliseconds; Status = $null; GrpcStatus = $null }
            }
            if (-not $Context.Streams.ContainsKey($id)) { throw [System.IO.InvalidDataException]::new('HEADERS on unopened HTTP/2 stream.') }
            $stream = $Context.Streams[$id]
            if (($State.Leg -eq 'client' -and $stream.RequestClosed) -or ($State.Leg -eq 'upstream' -and $stream.ResponseClosed)) {
                throw [System.IO.InvalidDataException]::new('HEADERS after END_STREAM.')
            }
            $State.HeaderBlock.SetLength(0)
            $State.HeldFrames.Clear()
            $State.HeldFrames.Add($bytes)
            $State.HeaderEndStream = (($flags -band 1) -ne 0)
            $fragment = Get-MihariHttp2HeaderFragment -Frame $Frame
            $State.HeaderBlock.Write($fragment, 0, $fragment.Length)
            $State.ContinuationStream = $id
        }
        2 { if ($len -ne 5) { throw [System.IO.InvalidDataException]::new('Invalid HTTP/2 PRIORITY size.') } }
        3 {
            if ($len -ne 4 -or -not $Context.Streams.ContainsKey($id)) { throw [System.IO.InvalidDataException]::new('Invalid HTTP/2 RST_STREAM.') }
            $Context.Streams[$id].Reset = $true
            Write-MihariHttp2Fact -Context $Context -State $State -StreamId $id -Stage 'http2.reset' -Outcome 'observed' -Data @{ errorCode = ('0x{0:x8}' -f (Get-MihariHttp2UInt32 -Bytes $bytes -Offset 9)); direction = $State.Leg }
        }
        4 {
            if (($flags -band 1) -ne 0) {
                if ($len -ne 0) { throw [System.IO.InvalidDataException]::new('HTTP/2 SETTINGS ACK has payload.') }
                if ($State.PendingTableLimits.Count -eq 0) { throw [System.IO.InvalidDataException]::new('Unexpected HTTP/2 SETTINGS ACK.') }
                $acknowledgedLimit = $State.PendingTableLimits[0]
                $State.PendingTableLimits.RemoveAt(0)
                if ($null -ne $acknowledgedLimit) { $State.Hpack.MaxTableSize = [int]$acknowledgedLimit }
            }
            else {
                if ($len % 6 -ne 0) { throw [System.IO.InvalidDataException]::new('Invalid HTTP/2 SETTINGS size.') }
                $tableLimit = $null
                for ($offset = 9; $offset -lt $bytes.Length; $offset += 6) {
                    $setting = ([int]$bytes[$offset] -shl 8) -bor [int]$bytes[$offset+1]
                    $value = Get-MihariHttp2UInt32 -Bytes $bytes -Offset ($offset + 2)
                    switch ($setting) {
                        1 {
                            if ($value -gt 4096) { throw [System.IO.InvalidDataException]::new('HTTP/2 header table exceeds local bound.') }
                            $State.Settings.headerTableSize = $value
                            $tableLimit = [int]$value
                        }
                        2 { if ($value -gt 1) { throw [System.IO.InvalidDataException]::new('Invalid HTTP/2 ENABLE_PUSH.') } }
                        3 { $State.Settings.maxConcurrentStreams = $value }
                        4 {
                            if ($value -gt 0x7fffffff) { throw [System.IO.InvalidDataException]::new('Invalid HTTP/2 initial window.') }
                            $delta = [long]$value - [long]$Opposite.InitialWindow
                            $Opposite.InitialWindow = [long]$value
                            foreach ($key in @($Opposite.StreamWindows.Keys)) { $Opposite.StreamWindows[$key] = [long]$Opposite.StreamWindows[$key] + $delta }
                            $State.Settings.initialWindowSize = $value
                        }
                        5 {
                            if ($value -lt 16384 -or $value -gt 65536) { throw [System.IO.InvalidDataException]::new('HTTP/2 maximum frame size exceeds local bound.') }
                            $Opposite.MaxFrame = [int]$value
                            $State.Settings.maxFrameSize = $value
                        }
                        6 { $State.Settings.maxHeaderListSize = $value }
                    }
                }
                $Opposite.PendingTableLimits.Add($tableLimit)
                Write-MihariHttp2Fact -Context $Context -State $State -StreamId 0 -Stage 'http2.settings' -Outcome 'observed' -Data @{ maxConcurrentStreams = $State.Settings.maxConcurrentStreams; maxFrameSize = $State.Settings.maxFrameSize; initialWindowSize = $State.Settings.initialWindowSize; headerTableSize = $State.Settings.headerTableSize }
            }
        }
        5 { throw [System.NotSupportedException]::new('HTTP/2 server push is outside the bounded native relay.') }
        6 { if ($len -ne 8) { throw [System.IO.InvalidDataException]::new('Invalid HTTP/2 PING size.') } }
        7 {
            if ($len -lt 8) { throw [System.IO.InvalidDataException]::new('Invalid HTTP/2 GOAWAY size.') }
            $State.GoAway = $true
            $last = [int]((Get-MihariHttp2UInt32 -Bytes $bytes -Offset 9) -band 0x7fffffff)
            Write-MihariHttp2Fact -Context $Context -State $State -StreamId 0 -Stage 'http2.goaway' -Outcome 'observed' -Data @{ lastStreamId = $last; errorCode = ('0x{0:x8}' -f (Get-MihariHttp2UInt32 -Bytes $bytes -Offset 13)); direction = $State.Leg }
        }
        8 {
            if ($len -ne 4) { throw [System.IO.InvalidDataException]::new('Invalid HTTP/2 WINDOW_UPDATE size.') }
            $increment = (Get-MihariHttp2UInt32 -Bytes $bytes -Offset 9) -band 0x7fffffff
            if ($increment -eq 0) { throw [System.IO.InvalidDataException]::new('Zero HTTP/2 WINDOW_UPDATE increment.') }
            if ($id -eq 0) {
                $Opposite.ConnectionWindow += $increment
                if ($null -ne $Opposite.ConnectionFlowWaitStarted) {
                    $wait = $Context.Clock.ElapsedMilliseconds - [long]$Opposite.ConnectionFlowWaitStarted
                    $Opposite.ConnectionFlowWaitStarted = $null
                    Write-MihariHttp2Fact -Context $Context -State $Opposite -StreamId 0 -Stage 'http2.flow_wait' -Outcome 'observed' -Data @{ waitMs = $wait; scope = 'connection'; direction = $Opposite.Leg }
                }
            }
            else {
                $key = [string]$id
                if (-not $Context.Streams.ContainsKey($id)) { break }
                if (-not $Opposite.StreamWindows.ContainsKey($key)) { $Opposite.StreamWindows[$key] = [long]$Opposite.InitialWindow }
                $Opposite.StreamWindows[$key] = [long]$Opposite.StreamWindows[$key] + $increment
                if ($Opposite.FlowWaitStarted.ContainsKey($key)) {
                    $wait = $Context.Clock.ElapsedMilliseconds - [long]$Opposite.FlowWaitStarted[$key]
                    $null = $Opposite.FlowWaitStarted.Remove($key)
                    Write-MihariHttp2Fact -Context $Context -State $Opposite -StreamId $id -Stage 'http2.flow_wait' -Outcome 'observed' -Data @{ waitMs = $wait; scope = 'stream'; direction = $Opposite.Leg }
                }
            }
            if ($Opposite.ConnectionWindow -gt 0x7fffffff -or ($id -ne 0 -and [long]$Opposite.StreamWindows[[string]$id] -gt 0x7fffffff)) {
                throw [System.IO.InvalidDataException]::new('HTTP/2 flow-control window overflow.')
            }
        }
        9 {
            $State.HeldFrames.Add($bytes)
            $State.HeaderBlock.Write($bytes, 9, $len)
        }
        default { # Unknown extension frames are forwarded, with bounded size.
            if ($State.ContinuationStream -ne 0) { throw [System.IO.InvalidDataException]::new('HTTP/2 extension interrupted header block.') }
        }
    }
    if ($State.HeaderBlock.Length -gt 65536) { throw [System.IO.InvalidDataException]::new('HTTP/2 field block exceeds local bound.') }
    if ($type -eq 1 -or $type -eq 9) {
        if (($flags -band 4) -eq 0) { return [pscustomobject]@{ Frames = $forward.ToArray() } }
        $headers = Decode-MihariHpackBlock -Context $State.Hpack -Bytes $State.HeaderBlock.ToArray()
        $stream = $Context.Streams[$id]
        $isRequest = ($State.Leg -eq 'client')
        $trailer = $(if ($isRequest) { $stream.RequestHeaders -gt 0 } else { $stream.ResponseHeaders -gt 0 })
        $safe = Assert-MihariHttp2HeaderSemantics -Headers $headers -Request $isRequest -Trailer $trailer -ConnectHost $Context.Host -ConnectPort $Context.Port
        if ($isRequest) {
            $stream.RequestHeaders++
            if (-not $trailer) {
                Write-MihariHttp2Fact -Context $Context -State $State -StreamId $id -Stage 'http.request' -Outcome 'succeeded' -Data @{ host = $Context.Host; port = $Context.Port; method = $safe[':method']; path = (Get-MihariSafePath -Target $safe[':path']); httpVersion = 'HTTP/2' }
            }
        }
        else {
            if (-not $trailer) {
                $status = [int]$safe[':status']
                if ($status -ge 200) { $stream.ResponseHeaders++ ; $stream.Status = $status }
                Write-MihariHttp2Fact -Context $Context -State $State -StreamId $id -Stage 'upstream.http' -Outcome 'succeeded' -Data @{ host = $Context.Host; port = $Context.Port; statusCode = $status; httpVersion = 'HTTP/2'; informational = ($status -lt 200) }
            }
            else { $stream.ResponseHeaders++ }
        }
        if (-not $isRequest -and $safe.ContainsKey('grpc-status')) {
            $grpcCode = 0
            if ([int]::TryParse([string]$safe['grpc-status'], [ref]$grpcCode) -and $grpcCode -ge 0 -and $grpcCode -le 16) {
                $stream.GrpcStatus = $grpcCode
                Write-MihariHttp2Fact -Context $Context -State $State -StreamId $id -Stage 'http2.grpc_status' -Outcome 'observed' -Data @{ grpcStatus = $grpcCode; headerSection = $(if ($trailer) { 'trailer' } else { 'initial' }); httpStatus = $stream.Status }
            }
        }
        if ($State.HeaderEndStream) { if ($isRequest) { $stream.RequestClosed = $true } else { $stream.ResponseClosed = $true } }
        foreach ($held in $State.HeldFrames) { $forward.Add($held) }
        $State.HeldFrames.Clear()
        $State.HeaderBlock.SetLength(0)
        $State.ContinuationStream = 0
    }
    else { $forward.Add($bytes) }
    if ($id -ne 0 -and $Context.Streams.ContainsKey($id)) {
        $stream = $Context.Streams[$id]
        if (($stream.RequestClosed -and $stream.ResponseClosed) -or $stream.Reset) {
            if (-not $stream.Reset) {
                Write-MihariHttp2Fact -Context $Context -State $State -StreamId $id -Stage 'response.relay' -Outcome 'succeeded' -Data @{ host = $Context.Host; port = $Context.Port; responseBytes = $stream.ResponseBytes; statusCode = $stream.Status; httpVersion = 'HTTP/2' }
            }
            Write-MihariHttp2Fact -Context $Context -State $State -StreamId $id -Stage 'http2.stream' -Outcome $(if ($stream.Reset) { 'reset' } else { 'completed' }) -Data @{ requestBytes = $stream.RequestBytes; responseBytes = $stream.ResponseBytes; statusCode = $stream.Status; grpcStatus = $stream.GrpcStatus; durationMs = ($Context.Clock.ElapsedMilliseconds - $stream.StartedMs) }
            $null = $Context.Streams.Remove($id)
            $null = $State.StreamWindows.Remove([string]$id)
            $null = $Opposite.StreamWindows.Remove([string]$id)
        }
    }
    return [pscustomobject]@{ Frames = $forward.ToArray() }
}

function Invoke-MihariHttp2Relay {
    param(
        [Parameter(Mandatory=$true)]$Session,
        [Parameter(Mandatory=$true)][System.IO.Stream]$ClientTls,
        [Parameter(Mandatory=$true)][System.IO.Stream]$UpstreamTls,
        [Parameter(Mandatory=$true)][string]$ConnectionId,
        [Parameter(Mandatory=$true)][string]$UpstreamConnectionId,
        [Parameter(Mandatory=$true)][string]$ConnectHost,
        [Parameter(Mandatory=$true)][int]$ConnectPort,
        [string]$ConnectionMode = 'Inspect',
        [int]$AcceptedConfigurationRevision = 0
    )
    if (-not (Test-MihariHttp2RuntimeCapability).Available) { throw [System.NotSupportedException]::new('Native HTTP/2 ALPN API is unavailable on this runtime.') }
    foreach ($tls in @($ClientTls,$UpstreamTls)) {
        $alpn = Get-MihariHttp2NegotiatedProtocol -Tls $tls
        if ($alpn -ne 'h2') { throw [System.NotSupportedException]::new('Both TLS legs must negotiate h2 for native Inspect.') }
    }
    $context = [pscustomobject]@{ Session = $Session; ConnectionId = $ConnectionId; UpstreamConnectionId = $UpstreamConnectionId; Host = $ConnectHost; Port = $ConnectPort; Mode = $ConnectionMode; ConfigurationRevision = $AcceptedConfigurationRevision; Clock = [System.Diagnostics.Stopwatch]::StartNew(); Streams = @{} }
    $client = New-MihariHttp2Direction -Leg 'client'
    $upstream = New-MihariHttp2Direction -Leg 'upstream'
    $buffers = @([byte[]]::new(16384), [byte[]]::new(16384))
    $streams = @($ClientTls,$UpstreamTls)
    $states = @($client,$upstream)
    $pending = @($ClientTls.BeginRead($buffers[0],0,$buffers[0].Length,$null,$null), $UpstreamTls.BeginRead($buffers[1],0,$buffers[1].Length,$null,$null))
    [long]$toUpstream = 0
    [long]$toClient = 0
    try {
        while ($true) {
            if (Test-MihariConnectionStopping -Session $Session) { break }
            $handles = [System.Threading.WaitHandle[]]@($pending[0].AsyncWaitHandle,$pending[1].AsyncWaitHandle)
            $index = [System.Threading.WaitHandle]::WaitAny($handles,100)
            if ($index -eq [System.Threading.WaitHandle]::WaitTimeout) { continue }
            $count = $streams[$index].EndRead($pending[$index])
            if ($count -eq 0) { break }
            $state = $states[$index]
            $other = $states[1-$index]
            $inputBatch = Add-MihariHttp2Input -State $state -Bytes $buffers[$index] -Count $count
            foreach ($frame in $inputBatch.Items) {
                $validated = Invoke-MihariHttp2Frame -Context $context -State $state -Opposite $other -Frame $frame
                foreach ($wire in $validated.Frames) {
                    $streams[1-$index].Write($wire,0,$wire.Length)
                    if ($index -eq 0) { $toUpstream += $wire.Length } else { $toClient += $wire.Length }
                }
            }
            $streams[1-$index].Flush()
            $pending[$index] = $streams[$index].BeginRead($buffers[$index],0,$buffers[$index].Length,$null,$null)
        }
        Write-MihariHttp2Fact -Context $context -State $client -StreamId 0 -Stage 'http2.relay' -Outcome 'completed' -Data @{ bytesClientToUpstream = $toUpstream; bytesUpstreamToClient = $toClient; activeStreamsAtClose = $context.Streams.Count }
    }
    catch {
        Write-MihariHttp2Fact -Context $context -State $client -StreamId 0 -Stage 'http2.relay' -Outcome 'failed' -Data @{ errorCode = 'http2_relay_failed'; errorType = $_.Exception.GetType().FullName; bytesClientToUpstream = $toUpstream; bytesUpstreamToClient = $toClient }
        throw
    }
}
