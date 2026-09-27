# One accepted socket is handled by one bounded listener worker. This file owns
# client-side HTTP dispatch and the byte relay; route selection stays in Upstream.

function Write-MihariProxyStatus {
    param(
        [Parameter(Mandatory = $true)][System.IO.Stream]$Stream,
        [Parameter(Mandatory = $true)][int]$StatusCode,
        [Parameter(Mandatory = $true)][string]$Reason,
        [bool]$ConnectSuccess = $false,
        $ProxyAuthenticate
    )

    # A proxy's reason phrase and challenge are network input. Keep them out of
    # the response header syntax if a peer sends unusual characters.
    $safeReason = ($Reason -replace '[\r\n\x00-\x1f\x7f]', ' ').Trim()
    if ([string]::IsNullOrWhiteSpace($safeReason)) { $safeReason = 'Status' }
    $lines = New-Object 'System.Collections.Generic.List[string]'
    $lines.Add(('HTTP/1.1 {0} {1}' -f $StatusCode, $safeReason))
    if (-not $ConnectSuccess) {
        $lines.Add('Content-Length: 0')
        $lines.Add('Connection: close')
        if ($null -ne $ProxyAuthenticate -and $StatusCode -eq 407) {
            foreach ($challenge in @($ProxyAuthenticate)) {
                    $safeChallenge = ([string]$challenge -replace '[\r\n\x00-\x1f\x7f]', ' ').Trim()
                    if ($safeChallenge.Length -gt 0 -and $safeChallenge.Length -le 4096) {
                        $lines.Add(('Proxy-Authenticate: {0}' -f $safeChallenge))
                    }
            }
        }
    }
    $wire = [System.Text.Encoding]::ASCII.GetBytes(($lines -join "`r`n") + "`r`n`r`n")
    $Stream.Write($wire, 0, $wire.Length)
    $Stream.Flush()
}

function Test-MihariConnectionStopping {
    param($Session)
    if ($null -ne $Session.PSObject.Properties['Cancellation'] -and
        $null -ne $Session.Cancellation -and $Session.Cancellation.IsCancellationRequested) {
        return $true
    }
    if ($null -ne $Session.PSObject.Properties['StopPath'] -and
        -not [string]::IsNullOrWhiteSpace([string]$Session.StopPath)) {
        return (Test-Path -LiteralPath $Session.StopPath)
    }
    return $false
}

function Register-MihariActiveUpstream {
    param($Session, [string]$ConnectionId, [System.Net.Sockets.TcpClient]$Client)
    if ($null -ne $Session.PSObject.Properties['ActiveUpstreamClients'] -and
        $null -ne $Session.ActiveUpstreamClients) {
        $Session.ActiveUpstreamClients[$ConnectionId] = $Client
    }
}

function Unregister-MihariActiveUpstream {
    param($Session, [string]$ConnectionId)
    if ($null -ne $Session.PSObject.Properties['ActiveUpstreamClients'] -and
        $null -ne $Session.ActiveUpstreamClients) {
        $null = $Session.ActiveUpstreamClients.Remove($ConnectionId)
    }
}

function Enter-MihariLongLivedSlot {
    param($Session)
    [System.Threading.Monitor]::Enter($Session.StateLock)
    try {
        if ([int]$Session.ActiveLongLivedCount -ge ([int]$Session.MaxWorkers - 1)) { return $false }
        $Session.ActiveLongLivedCount = [int]$Session.ActiveLongLivedCount + 1
        return $true
    }
    finally { [System.Threading.Monitor]::Exit($Session.StateLock) }
}

function Exit-MihariLongLivedSlot {
    param($Session)
    [System.Threading.Monitor]::Enter($Session.StateLock)
    try {
        if ([int]$Session.ActiveLongLivedCount -gt 0) {
            $Session.ActiveLongLivedCount = [int]$Session.ActiveLongLivedCount - 1
        }
    }
    finally { [System.Threading.Monitor]::Exit($Session.StateLock) }
}

function Invoke-MihariTunnelRelay {
    param(
        [Parameter(Mandatory = $true)]$Session,
        [Parameter(Mandatory = $true)][System.Net.Sockets.TcpClient]$Client,
        [Parameter(Mandatory = $true)][System.Net.Sockets.TcpClient]$Upstream
    )

    $clientSocket = $Client.Client
    $upstreamSocket = $Upstream.Client
    $clientStream = $Client.GetStream()
    $upstreamStream = $Upstream.GetStream()
    $clientStream.WriteTimeout = 30000
    $upstreamStream.WriteTimeout = 30000
    $toUpstream = New-Object byte[] 16384
    $toClient = New-Object byte[] 16384
    [long]$clientBytes = 0
    [long]$upstreamBytes = 0
    $clientEof = $false
    $upstreamEof = $false
    $firstFailure = $null
    $failureDirection = $null
    $cancelled = $false

    while (-not ($clientEof -and $upstreamEof)) {
        if (Test-MihariConnectionStopping -Session $Session) {
            $cancelled = $true
            break
        }
        $moved = $false
        if (-not $clientEof) {
            try {
                if ($clientSocket.Poll(0, [System.Net.Sockets.SelectMode]::SelectRead)) {
                    $count = $clientStream.Read($toUpstream, 0, $toUpstream.Length)
                    if ($count -eq 0) {
                        $clientEof = $true
                        try { $upstreamSocket.Shutdown([System.Net.Sockets.SocketShutdown]::Send) }
                        catch [System.Net.Sockets.SocketException] { $null = $_ } # Peer already closed.
                        catch [System.ObjectDisposedException] { $null = $_ } # Stop closed the peer.
                    } else {
                        $upstreamStream.Write($toUpstream, 0, $count)
                        $clientBytes += $count
                    }
                    $moved = $true
                }
            } catch {
                $firstFailure = $_.Exception
                $failureDirection = 'client_to_upstream'
                break
            }
        }
        if (-not $upstreamEof) {
            try {
                if ($upstreamSocket.Poll(0, [System.Net.Sockets.SelectMode]::SelectRead)) {
                    $count = $upstreamStream.Read($toClient, 0, $toClient.Length)
                    if ($count -eq 0) {
                        $upstreamEof = $true
                        try { $clientSocket.Shutdown([System.Net.Sockets.SocketShutdown]::Send) }
                        catch [System.Net.Sockets.SocketException] { $null = $_ } # Peer already closed.
                        catch [System.ObjectDisposedException] { $null = $_ } # Stop closed the peer.
                    } else {
                        $clientStream.Write($toClient, 0, $count)
                        $upstreamBytes += $count
                    }
                    $moved = $true
                }
            } catch {
                $firstFailure = $_.Exception
                $failureDirection = 'upstream_to_client'
                break
            }
        }
        if (-not $moved) { [System.Threading.Thread]::Sleep(20) }
    }
    if ($null -ne $firstFailure -and (Test-MihariConnectionStopping -Session $Session)) {
        $cancelled = $true
        $firstFailure = $null
        $failureDirection = $null
    }

    return [pscustomobject]@{
        ClientToUpstreamBytes = $clientBytes
        UpstreamToClientBytes = $upstreamBytes
        FirstFailureDirection = $failureDirection
        Exception = $firstFailure
        Cancelled = $cancelled
    }
}

function New-MihariRouteUri {
    param($Target)
    if ($Target.OriginTarget -eq '*') {
        $builder = New-Object System.UriBuilder -ArgumentList @($Target.Scheme, $Target.Host, ([int]$Target.Port), '/')
        return $builder.Uri
    }
    return (New-Object System.Uri -ArgumentList @([string]$Target.AbsoluteTarget))
}

function Handle-MihariConnection {
    param(
        [Parameter(Mandatory = $true)]$Session,
        [Parameter(Mandatory = $true)][System.Net.Sockets.TcpClient]$Client,
        [ValidateSet('Inspect', 'Tunnel')][string]$AcceptedMode,
        [int]$AcceptedConfigurationRevision = 0,
        [ValidateSet('reuse', 'close')][string]$AcceptedHttpConnectionPolicy,
        [string[]]$AcceptedLocalInspectExclusions = @()
    )

    # The listener passes the mode captured when it accepted the socket. Direct
    # callers retain the old behavior, with a single snapshot at entry.
    if (-not $PSBoundParameters.ContainsKey('AcceptedMode')) { $AcceptedMode = [string]$Session.Mode }
    if (-not $PSBoundParameters.ContainsKey('AcceptedHttpConnectionPolicy')) {
        $AcceptedHttpConnectionPolicy = 'reuse'
        if ($null -ne $Session.PSObject.Properties['HttpConnectionPolicy']) {
            $AcceptedHttpConnectionPolicy = [string]$Session.HttpConnectionPolicy
        }
    }
    if (-not $PSBoundParameters.ContainsKey('AcceptedLocalInspectExclusions') -and
        $null -ne $Session.PSObject.Properties['LocalInspectExclusions']) {
        $AcceptedLocalInspectExclusions = @($Session.LocalInspectExclusions)
    }
    $connectionId = [guid]::NewGuid().ToString('N')
    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    $stage = 'proxy.request'
    $responseStarted = $false
    $hostName = $null
    $targetPort = 0
    $routeKind = $null
    $upstream = $null
    $clientStream = $null
    $requestId = $null
    $eventWriterFailed = $false
    $upstreamKey = $null
    $exchangeCount = 0
    $longLivedSlot = $false
    try {
        $clientStream = $Client.GetStream()
        $clientStream.ReadTimeout = 30000
        $clientStream.WriteTimeout = 30000
        $clientEndpoint = $null
        if ($null -ne $Client.Client.RemoteEndPoint) { $clientEndpoint = $Client.Client.RemoteEndPoint.ToString() }
        $null = Write-MihariEvent -Session $Session -ConfigurationRevision $AcceptedConfigurationRevision -ConnectionId $connectionId -Stage 'listener.accept' -Outcome 'success' -ElapsedMs $timer.ElapsedMilliseconds -Mode $AcceptedMode -Data @{
            clientEndpoint = $clientEndpoint
        }
        while ($true) {
        $requestId = $null
        $responseStarted = $false
        $stage = 'proxy.request'
        $request = Read-MihariHttpHead -Stream $clientStream -Kind Request
        if ($null -eq $request) { break }
        $exchangeCount++
        if ($exchangeCount -gt 1000) {
            throw [System.IO.InvalidDataException]::new('The HTTP connection exceeded 1000 exchanges.')
        }
        $requestId = [guid]::NewGuid().ToString('N')
        $target = Get-MihariTarget -Message $request
        $hostName = [string]$target.Host
        $targetPort = [int]$target.Port
        $isConnect = [string]::Equals([string]$request.Method, 'CONNECT', [System.StringComparison]::OrdinalIgnoreCase)
        if ($isConnect -and $AcceptedMode -eq 'Inspect' -and $AcceptedLocalInspectExclusions.Count -gt 0) {
            if (Test-MihariLocalInspectExclusion -HostName $hostName -ExcludedHosts $AcceptedLocalInspectExclusions) {
                $AcceptedMode = 'Tunnel'
                $null = Write-MihariEvent -Session $Session -ConfigurationRevision $AcceptedConfigurationRevision -ConnectionId $connectionId -RequestId $requestId -Stage 'local.inspect.exclusion' -Outcome 'success' -ElapsedMs $timer.ElapsedMilliseconds -Mode $AcceptedMode -Data @{
                    host = $hostName; port = $targetPort; reason = 'Exact-host local inspection exclusion; upstream route is unchanged.'
                }
            }
        }
        $safePath = $null
        if (-not $isConnect) { $safePath = Get-MihariSafePath -Target $target.Path }
        $null = Write-MihariEvent -Session $Session -ConfigurationRevision $AcceptedConfigurationRevision -ConnectionId $connectionId -RequestId $requestId -Stage 'proxy.request' -Outcome 'success' -ElapsedMs $timer.ElapsedMilliseconds -Mode $AcceptedMode -Data @{
            clientEndpoint = $clientEndpoint; method = $request.Method; host = $hostName; port = $targetPort; path = $safePath
        }

        $requestFraming = Get-MihariHttpBodyFraming -Message $request -Kind Request

        if ($isConnect) {
            if ($requestFraming.Kind -ne 'None' -and
                -not ($requestFraming.Kind -eq 'ContentLength' -and $requestFraming.Length -eq 0)) {
                throw [System.IO.InvalidDataException]::new('CONNECT must not carry a request body.')
            }
            if ($AcceptedMode -eq 'Inspect') {
                if ($null -eq $Session.CA -or $null -eq $Session.PublicCARoot -or
                    -not (Test-MihariSessionCATrust -Session $Session)) {
                    throw (New-Object System.InvalidOperationException -ArgumentList 'Inspect requires a trusted session CA before accepting CONNECT.')
                }
                Write-MihariProxyStatus -Stream $clientStream -StatusCode 200 -Reason 'Connection Established' -ConnectSuccess $true
                $responseStarted = $true
                Invoke-MihariInspect -Session $Session -ClientStream $clientStream -ConnectHost $hostName -ConnectPort $targetPort -ConnectionId $connectionId -ConnectionMode $AcceptedMode -AcceptedConfigurationRevision $AcceptedConfigurationRevision -AcceptedHttpConnectionPolicy $AcceptedHttpConnectionPolicy -AcceptedConnectionElapsedMs $timer.ElapsedMilliseconds -ProxyAuthorization (Get-MihariHeaderText -Headers $request.Headers -Name 'Proxy-Authorization')
                return
            }
            if ($AcceptedMode -ne 'Tunnel') {
                throw (New-Object System.NotSupportedException -ArgumentList 'Unsupported CONNECT mode.')
            }
            $stage = 'upstream.resolve'
            $routeUri = New-Object System.UriBuilder -ArgumentList 'https', $hostName, $targetPort
            $route = Resolve-MihariRoute -Uri $routeUri.Uri -Override $Session.UpstreamProxy -PlatformSnapshot $Session.PlatformProxySnapshot -MihariProxyPort $Session.ActualPort
            $routeKind = [string]$route.Kind
            if ($routeKind -eq 'Unsupported') {
                $routeErrorCode = 'upstream_route_unresolved'
                if (-not [string]::IsNullOrWhiteSpace([string]$route.ErrorCode)) { $routeErrorCode = [string]$route.ErrorCode }
                $null = Write-MihariEvent -Session $Session -ConfigurationRevision $AcceptedConfigurationRevision -ConnectionId $connectionId -RequestId $requestId -Stage $stage -Outcome 'unsupported' -ElapsedMs $timer.ElapsedMilliseconds -Mode $AcceptedMode -Data @{
                    host = $hostName; port = $targetPort; routeKind = $routeKind; routeSource = $route.Source; reason = $route.Reason; errorCode = $routeErrorCode
                }
                Write-MihariProxyStatus -Stream $clientStream -StatusCode 502 -Reason 'Upstream Route Unresolved'
                $responseStarted = $true
                return
            }
            $null = Write-MihariEvent -Session $Session -ConfigurationRevision $AcceptedConfigurationRevision -ConnectionId $connectionId -RequestId $requestId -Stage $stage -Outcome 'success' -ElapsedMs $timer.ElapsedMilliseconds -Mode $AcceptedMode -Data @{
                host = $hostName; port = $targetPort; routeKind = $routeKind; routeSource = $route.Source; proxyHost = $(if ($routeKind -eq 'ExplicitProxy') { $route.Host } else { $null }); proxyPort = $(if ($routeKind -eq 'ExplicitProxy') { $route.Port } else { $null })
            }
            $stage = $(if ($routeKind -eq 'ExplicitProxy') { 'upstream.proxy.connect' } else { 'upstream.tcp' })
            $upstream = Open-MihariUpstream -Route $route -TargetHost $hostName -TargetPort $targetPort -Tunnel $true -ProxyAuthorization (Get-MihariHeaderText -Headers $request.Headers -Name 'Proxy-Authorization')
            if ($null -ne $upstream.Client) { Register-MihariActiveUpstream -Session $Session -ConnectionId $connectionId -Client $upstream.Client }
            if ($null -ne $upstream.ProxyStatus) {
                $proxyStatus = [int]$upstream.ProxyStatus.StatusCode
                $proxyOutcome = $(if ($proxyStatus -ge 200 -and $proxyStatus -lt 300) { 'success' } else { 'rejected' })
                $null = Write-MihariEvent -Session $Session -ConfigurationRevision $AcceptedConfigurationRevision -ConnectionId $connectionId -RequestId $requestId -Stage 'upstream.proxy.connect' -Outcome $proxyOutcome -ElapsedMs $timer.ElapsedMilliseconds -Mode $AcceptedMode -Data @{
                    host = $hostName; port = $targetPort; routeKind = 'ExplicitProxy'; proxyHost = $route.Host; proxyPort = $route.Port; proxyStatus = $proxyStatus
                }
                if ($proxyStatus -lt 200 -or $proxyStatus -ge 300) {
                    Write-MihariProxyStatus -Stream $clientStream -StatusCode $proxyStatus -Reason $upstream.ProxyStatus.ReasonPhrase -ProxyAuthenticate $upstream.ProxyStatus.ProxyAuthenticate
                    $responseStarted = $true
                    return
                }
            } else {
                $null = Write-MihariEvent -Session $Session -ConfigurationRevision $AcceptedConfigurationRevision -ConnectionId $connectionId -RequestId $requestId -Stage 'upstream.tcp' -Outcome 'success' -ElapsedMs $timer.ElapsedMilliseconds -Mode $AcceptedMode -Data @{
                    host = $hostName; port = $targetPort; routeKind = $routeKind
                }
            }
            Write-MihariProxyStatus -Stream $clientStream -StatusCode 200 -Reason 'Connection Established' -ConnectSuccess $true
            $responseStarted = $true
            $stage = 'tunnel.relay'
            $relay = Invoke-MihariTunnelRelay -Session $Session -Client $Client -Upstream $upstream.Client
            $relayOutcome = 'success'
            if ($relay.Cancelled) { $relayOutcome = 'cancelled' }
            if ($null -ne $relay.Exception) { $relayOutcome = 'failed' }
            $null = Write-MihariEvent -Session $Session -ConfigurationRevision $AcceptedConfigurationRevision -ConnectionId $connectionId -RequestId $requestId -Stage $stage -Outcome $relayOutcome -ElapsedMs $timer.ElapsedMilliseconds -Mode $AcceptedMode -Data @{
                host = $hostName; port = $targetPort; routeKind = $routeKind; bytesClientToUpstream = $relay.ClientToUpstreamBytes; bytesUpstreamToClient = $relay.UpstreamToClientBytes; direction = $relay.FirstFailureDirection; exception = $relay.Exception
            }
            return
        }

        if ($target.Scheme -ne 'http') {
            throw [System.NotSupportedException]::new('Plain proxy requests require HTTP/1.1 over http; use CONNECT for HTTPS.')
        }
        $webSocket = Test-MihariWebSocketRequest -Message $request
        if ($webSocket -and $requestFraming.Kind -ne 'None') {
            throw [System.IO.InvalidDataException]::new('A WebSocket upgrade cannot carry an HTTP request body.')
        }
        $expect = Get-MihariHeaderText -Headers $request.Headers -Name 'Expect'
        if ($expect -and $expect -ine '100-continue') {
            throw [System.NotSupportedException]::new('Only Expect: 100-continue is supported.')
        }
        $hasCredentials = ($request.Headers.Contains('Authorization') -or
            $request.Headers.Contains('Proxy-Authorization') -or $request.Headers.Contains('Cookie'))
        $requestKeepAlive = (Test-MihariHttpKeepAlive -Message $request) -and
            $request.Version -eq 'HTTP/1.1' -and $AcceptedHttpConnectionPolicy -eq 'reuse' -and
            -not $hasCredentials -and -not $webSocket
        $null = Write-MihariEvent -Session $Session -ConfigurationRevision $AcceptedConfigurationRevision -ConnectionId $connectionId -RequestId $requestId -Stage 'http.request' -Outcome 'success' -ElapsedMs $timer.ElapsedMilliseconds -Mode $AcceptedMode -Data @{
            host = $hostName; port = $targetPort; path = $safePath; method = $request.Method; requestFraming = $requestFraming.Kind; connectionPolicy = $AcceptedHttpConnectionPolicy
        }
        $stage = 'upstream.resolve'
        $uri = New-MihariRouteUri -Target $target
        $route = Resolve-MihariRoute -Uri $uri -Override $Session.UpstreamProxy -PlatformSnapshot $Session.PlatformProxySnapshot -MihariProxyPort $Session.ActualPort
        $routeKind = [string]$route.Kind
        if ($routeKind -eq 'Unsupported') {
            $routeErrorCode = 'upstream_route_unresolved'
            if (-not [string]::IsNullOrWhiteSpace([string]$route.ErrorCode)) { $routeErrorCode = [string]$route.ErrorCode }
            $null = Write-MihariEvent -Session $Session -ConfigurationRevision $AcceptedConfigurationRevision -ConnectionId $connectionId -RequestId $requestId -Stage $stage -Outcome 'unsupported' -ElapsedMs $timer.ElapsedMilliseconds -Mode $AcceptedMode -Data @{
                host = $hostName; port = $targetPort; path = $safePath; routeKind = $routeKind; routeSource = $route.Source; reason = $route.Reason; errorCode = $routeErrorCode
            }
            Write-MihariProxyStatus -Stream $clientStream -StatusCode 502 -Reason 'Upstream Route Unresolved'
            $responseStarted = $true
            return
        }
        $null = Write-MihariEvent -Session $Session -ConfigurationRevision $AcceptedConfigurationRevision -ConnectionId $connectionId -RequestId $requestId -Stage $stage -Outcome 'success' -ElapsedMs $timer.ElapsedMilliseconds -Mode $AcceptedMode -Data @{
            host = $hostName; port = $targetPort; path = $safePath; routeKind = $routeKind; routeSource = $route.Source; proxyHost = $(if ($routeKind -eq 'ExplicitProxy') { $route.Host } else { $null }); proxyPort = $(if ($routeKind -eq 'ExplicitProxy') { $route.Port } else { $null })
        }
        if ($target.OriginTarget -eq '*' -and $routeKind -eq 'ExplicitProxy') {
            throw [System.NotSupportedException]::new('OPTIONS * cannot be routed through an explicit proxy in this implementation.')
        }
        $currentKey = $routeKind + '|' + $hostName + ':' + $targetPort
        if ($routeKind -eq 'ExplicitProxy') { $currentKey += '|' + $route.Host + ':' + $route.Port }
        $reused = ($null -ne $upstream -and $upstreamKey -eq $currentKey -and
            -not $hasCredentials -and -not $webSocket)
        if ($null -ne $upstream -and -not $reused) {
            Unregister-MihariActiveUpstream -Session $Session -ConnectionId $connectionId
            $upstream.Client.Dispose()
            $upstream = $null
            $upstreamKey = $null
        }
        $stage = 'upstream.tcp'
        if (-not $reused) {
            $upstream = Open-MihariUpstream -Route $route -TargetHost $hostName -TargetPort $targetPort -Tunnel $false
            $upstreamKey = $currentKey
            if ($null -ne $upstream.Client) { Register-MihariActiveUpstream -Session $Session -ConnectionId $connectionId -Client $upstream.Client }
        }
        $null = Write-MihariEvent -Session $Session -ConfigurationRevision $AcceptedConfigurationRevision -ConnectionId $connectionId -RequestId $requestId -Stage $stage -Outcome 'success' -ElapsedMs $timer.ElapsedMilliseconds -Mode $AcceptedMode -Data @{
            host = $hostName; port = $targetPort; routeKind = $routeKind; reused = $reused
        }
        $forwardTarget = $target.OriginTarget
        if ($routeKind -eq 'ExplicitProxy') { $forwardTarget = $target.AbsoluteTarget }
        $stage = 'upstream.http'
        Write-MihariHttpHead -Stream $upstream.Stream -Message $request -RequestTarget $forwardTarget -CloseConnection:(-not $requestKeepAlive -and -not $webSocket) -ForwardProxyAuthorization:($routeKind -eq 'ExplicitProxy') -UpgradeWebSocket:$webSocket
        $response = $null
        $earlyFinal = $false
        if ($expect) {
            $continueReceived = $false
            $preBodyResponses = 0
            while ($upstream.Client.Client.Poll(2000000, [System.Net.Sockets.SelectMode]::SelectRead)) {
                $response = Read-MihariHttpHead -Stream $upstream.Stream -Kind Response -RequestMethod $request.Method
                if ($null -eq $response) { throw [System.IO.EndOfStreamException]::new('Upstream closed before the expected HTTP response.') }
                if ([int]$response.StatusCode -eq 100) {
                    Write-MihariHttpHead -Stream $clientStream -Message $response
                    $responseStarted = $true
                    $continueReceived = $true
                    $response = $null
                    break
                }
                if ([int]$response.StatusCode -ge 200 -or [int]$response.StatusCode -eq 101) {
                    $earlyFinal = $true
                    break
                }
                $preBodyResponses++
                if ($preBodyResponses -gt 8) { throw [System.IO.InvalidDataException]::new('Too many informational HTTP responses.') }
                Write-MihariHttpHead -Stream $clientStream -Message $response
                $responseStarted = $true
                $response = $null
            }
            if (-not $continueReceived -and -not $earlyFinal) {
                Write-MihariProxyStatus -Stream $clientStream -StatusCode 100 -Reason 'Continue' -ConnectSuccess $true
                $responseStarted = $true
            }
        }
        $requestTransfer = [pscustomobject]@{ Bytes = [long]0 }
        if (-not $earlyFinal) {
            $requestTransfer = Copy-MihariHttpBody -Source $clientStream -Destination $upstream.Stream -Framing $requestFraming -Session $Session
            $response = Read-MihariHttpHead -Stream $upstream.Stream -Kind Response -RequestMethod $request.Method
        }
        if ($null -eq $response) { throw [System.IO.EndOfStreamException]::new('Upstream closed before an HTTP response.') }
        $informationalCount = 0
        while ([int]$response.StatusCode -ge 100 -and [int]$response.StatusCode -lt 200 -and [int]$response.StatusCode -ne 101) {
            $informationalCount++
            if ($informationalCount -gt 8) { throw [System.IO.InvalidDataException]::new('Too many informational HTTP responses.') }
            if ([int]$response.StatusCode -ne 100 -or -not $expect) {
                Write-MihariHttpHead -Stream $clientStream -Message $response
                $responseStarted = $true
            }
            $response = Read-MihariHttpHead -Stream $upstream.Stream -Kind Response -RequestMethod $request.Method
            if ($null -eq $response) { throw [System.IO.EndOfStreamException]::new('Upstream closed after an informational HTTP response.') }
        }
        if ([int]$response.StatusCode -eq 101 -and -not $webSocket) {
            throw [System.NotSupportedException]::new('Unexpected HTTP protocol upgrade.')
        }
        $acceptedWebSocket = $false
        if ($webSocket) { $acceptedWebSocket = Test-MihariWebSocketResponse -Message $response -Request $request }
        $responseFraming = Get-MihariHttpBodyFraming -Message $response -Kind Response -RequestMethod $request.Method
        $responseKeepAlive = (Test-MihariHttpKeepAlive -Message $response) -and
            $response.Version -eq 'HTTP/1.1' -and $responseFraming.Reusable -and $requestKeepAlive -and -not $acceptedWebSocket -and -not $earlyFinal
        $null = Write-MihariEvent -Session $Session -ConfigurationRevision $AcceptedConfigurationRevision -ConnectionId $connectionId -RequestId $requestId -Stage $stage -Outcome 'success' -ElapsedMs $timer.ElapsedMilliseconds -Mode $AcceptedMode -Data @{
            host = $hostName; port = $targetPort; path = $safePath; routeKind = $routeKind; method = $request.Method; statusCode = [int]$response.StatusCode; requestBytes = $requestTransfer.Bytes; responseFraming = $responseFraming.Kind
        }
        $stage = 'response.relay'
        $preserveProxyChallenge = ($routeKind -eq 'ExplicitProxy' -and [int]$response.StatusCode -eq 407)
        $contentType = Get-MihariHeaderText -Headers $response.Headers -Name 'Content-Type'
        $isSse = ($contentType -and $contentType -match '^text/event-stream(?:\s*;|\s*$)')
        if ($acceptedWebSocket -or $isSse) {
            if (-not (Enter-MihariLongLivedSlot -Session $Session)) {
                $null = Write-MihariEvent -Session $Session -ConfigurationRevision $AcceptedConfigurationRevision -ConnectionId $connectionId -RequestId $requestId -Stage 'observer.capacity' -Outcome 'rejected' -ElapsedMs $timer.ElapsedMilliseconds -Mode $AcceptedMode -Data @{
                    host = $hostName; port = $targetPort; path = $safePath; errorCode = 'long_lived_worker_limit'; workerOccupancy = [int]$Session.ActiveConnectionCount; maxWorkers = [int]$Session.MaxWorkers
                }
                Write-MihariProxyStatus -Stream $clientStream -StatusCode 503 -Reason 'Long-Lived Worker Limit'
                $responseStarted = $true
                return
            }
            $longLivedSlot = $true
        }
        if ($isSse) {
            $upstream.Stream.ReadTimeout = 600000
        }
        $responseStarted = $true
        Write-MihariHttpHead -Stream $clientStream -Message $response -CloseConnection:(-not $responseKeepAlive -and -not $acceptedWebSocket) -PreserveProxyAuthenticate:$preserveProxyChallenge -UpgradeWebSocket:$acceptedWebSocket
        if ($acceptedWebSocket) {
            $stage = 'websocket.relay'
            $relay = Invoke-MihariTunnelRelay -Session $Session -Client $Client -Upstream $upstream.Client
            $relayOutcome = 'success'
            if ($relay.Cancelled) { $relayOutcome = 'cancelled' }
            if ($null -ne $relay.Exception) { $relayOutcome = 'failed' }
            $null = Write-MihariEvent -Session $Session -ConfigurationRevision $AcceptedConfigurationRevision -ConnectionId $connectionId -RequestId $requestId -Stage $stage -Outcome $relayOutcome -ElapsedMs $timer.ElapsedMilliseconds -Mode $AcceptedMode -Data @{
                host = $hostName; port = $targetPort; path = $safePath; bytesClientToUpstream = $relay.ClientToUpstreamBytes; bytesUpstreamToClient = $relay.UpstreamToClientBytes; direction = $relay.FirstFailureDirection; exception = $relay.Exception
            }
            return
        }
        $bodyRelayStartedMs = $timer.ElapsedMilliseconds
        $responseTransfer = Copy-MihariHttpBody -Source $upstream.Stream -Destination $clientStream -Framing $responseFraming -Session $Session
        $firstByteAtMs = $null
        $lastByteAtMs = $null
        if ($null -ne $responseTransfer.FirstByteMs) { $firstByteAtMs = $bodyRelayStartedMs + $responseTransfer.FirstByteMs }
        if ($null -ne $responseTransfer.LastByteMs) { $lastByteAtMs = $bodyRelayStartedMs + $responseTransfer.LastByteMs }
        $null = Write-MihariEvent -Session $Session -ConfigurationRevision $AcceptedConfigurationRevision -ConnectionId $connectionId -RequestId $requestId -Stage $stage -Outcome 'success' -ElapsedMs $timer.ElapsedMilliseconds -Mode $AcceptedMode -Data @{
            host = $hostName; port = $targetPort; path = $safePath; statusCode = [int]$response.StatusCode; responseBytes = $responseTransfer.Bytes; firstByteMs = $firstByteAtMs; lastByteMs = $lastByteAtMs; forwardWriteMs = $responseTransfer.ForwardWriteMs; framing = $responseTransfer.Framing
        }
        if ($isSse -and $longLivedSlot) {
            Exit-MihariLongLivedSlot -Session $Session
            $longLivedSlot = $false
        }
        if (-not $responseKeepAlive) { break }
        # Idle keep-alive sockets must not consume the bounded worker pool
        # indefinitely or turn an ordinary idle expiry into a failure fact.
        if (-not $Client.Client.Poll(5000000, [System.Net.Sockets.SelectMode]::SelectRead)) { break }
        }
    } catch {
        $failure = $_.Exception
        $rootFailure = $failure.GetBaseException()
        $outcome = 'failed'
        $status = 502
        $reason = 'Bad Gateway'
        $failureData = @{
            host = $hostName; port = $targetPort; routeKind = $routeKind; exception = $failure
        }
        if (Test-MihariConnectionStopping -Session $Session) {
            $outcome = 'cancelled'
            $failureData.errorCode = 'session_cancelled'
        } elseif ($rootFailure -is [System.OperationCanceledException]) {
            $outcome = 'cancelled'
            $failureData.errorCode = 'relay_cancelled'
        } elseif ($rootFailure -is [System.NotSupportedException]) {
            $outcome = 'unsupported'
            $status = 501
            $reason = 'Unsupported Protocol'
            $failureData.errorCode = 'unsupported_protocol'
            if ($rootFailure.Message -match 'HTTP/2') { $failureData.unsupportedProtocol = 'HTTP/2' }
        } elseif ($rootFailure -is [System.IO.InvalidDataException] -or $rootFailure -is [System.ArgumentException]) {
            $status = 400
            $reason = 'Bad Request'
        }
        try {
            $null = Write-MihariEvent -Session $Session -ConfigurationRevision $AcceptedConfigurationRevision -ConnectionId $connectionId -RequestId $requestId -Stage $stage -Outcome $outcome -ElapsedMs $timer.ElapsedMilliseconds -Mode $AcceptedMode -Data $failureData
        } catch {
            # Event storage failed. Preserve the original failure for the worker
            # boundary rather than recursively attempting another event write.
            $eventWriterFailed = $true
            throw (New-Object System.AggregateException -ArgumentList 'Connection handling and event writing both failed.', @($failure, $_.Exception))
        }
        if (-not $responseStarted -and $null -ne $clientStream -and $outcome -ne 'cancelled') {
            try { Write-MihariProxyStatus -Stream $clientStream -StatusCode $status -Reason $reason }
            catch [System.IO.IOException] { $null = $_ } # The failing client may already be gone.
            catch [System.ObjectDisposedException] { $null = $_ } # Stop may have closed the socket.
        }
    } finally {
        $cleanupError = $null
        if ($longLivedSlot) { Exit-MihariLongLivedSlot -Session $Session }
        Unregister-MihariActiveUpstream -Session $Session -ConnectionId $connectionId
        if ($null -ne $upstream) {
            if ($null -ne $upstream.Client) {
                try { $upstream.Client.Dispose() }
                catch { $cleanupError = $_.Exception }
            }
        }
        try { $Client.Dispose() }
        catch { if ($null -eq $cleanupError) { $cleanupError = $_.Exception } }
        $timer.Stop()

        $cleanupOutcome = 'success'
        if ($null -ne $cleanupError) { $cleanupOutcome = 'failed' }
        $cleanupData = @{ host = $hostName; routeKind = $routeKind; exception = $cleanupError }
        if ($targetPort -gt 0) { $cleanupData.port = $targetPort }
        $writer = $Session.Writer
        if (-not $eventWriterFailed -and $null -ne $writer) {
            if ($writer.Closed) {
                if (-not (Test-MihariConnectionStopping -Session $Session)) {
                    throw 'The Mihari event writer closed before the connection completed.'
                }
            }
            else {
                try {
                    $null = Write-MihariEvent -Session $Session -ConfigurationRevision $AcceptedConfigurationRevision -ConnectionId $connectionId -RequestId $requestId -Stage 'connection.cleanup' -Outcome $cleanupOutcome -ElapsedMs $timer.ElapsedMilliseconds -Mode $AcceptedMode -Data $cleanupData
                }
                catch {
                    # Stop may close the writer after the open check. Other
                    # writer failures reach the worker boundary.
                    if (-not ($writer.Closed -and (Test-MihariConnectionStopping -Session $Session))) { throw }
                }
            }
        }
    }
}
