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
        [ValidateSet('Inspect', 'Tunnel')][string]$AcceptedMode
    )

    # The listener passes the mode captured when it accepted the socket. Direct
    # callers retain the old behavior, with a single snapshot at entry.
    if (-not $PSBoundParameters.ContainsKey('AcceptedMode')) { $AcceptedMode = [string]$Session.Mode }
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
    try {
        $clientStream = $Client.GetStream()
        $clientStream.ReadTimeout = 30000
        $clientStream.WriteTimeout = 30000
        $clientEndpoint = $null
        if ($null -ne $Client.Client.RemoteEndPoint) { $clientEndpoint = $Client.Client.RemoteEndPoint.ToString() }
        $null = Write-MihariEvent -Session $Session -ConnectionId $connectionId -Stage 'listener.accept' -Outcome 'success' -ElapsedMs $timer.ElapsedMilliseconds -Mode $AcceptedMode -Data @{
            clientEndpoint = $clientEndpoint
        }
        $request = Read-MihariHttpMessage -Stream $clientStream -Kind Request
        if ($null -eq $request) { return }
        $requestId = [guid]::NewGuid().ToString('N')
        $target = Get-MihariTarget -Message $request
        $hostName = [string]$target.Host
        $targetPort = [int]$target.Port
        $isConnect = [string]::Equals([string]$request.Method, 'CONNECT', [System.StringComparison]::OrdinalIgnoreCase)
        $safePath = $null
        if (-not $isConnect) { $safePath = Get-MihariSafePath -Target $target.Path }
        $null = Write-MihariEvent -Session $Session -ConnectionId $connectionId -RequestId $requestId -Stage 'proxy.request' -Outcome 'success' -ElapsedMs $timer.ElapsedMilliseconds -Mode $AcceptedMode -Data @{
            clientEndpoint = $clientEndpoint; method = $request.Method; host = $hostName; port = $targetPort; path = $safePath
        }

        if ($isConnect) {
            if ($AcceptedMode -eq 'Inspect') {
                if ($null -eq $Session.CA -or $null -eq $Session.PublicCARoot -or
                    -not (Test-MihariSessionCATrust -Session $Session)) {
                    throw (New-Object System.InvalidOperationException -ArgumentList 'Inspect requires a trusted session CA before accepting CONNECT.')
                }
                Write-MihariProxyStatus -Stream $clientStream -StatusCode 200 -Reason 'Connection Established' -ConnectSuccess $true
                $responseStarted = $true
                Invoke-MihariInspect -Session $Session -ClientStream $clientStream -ConnectHost $hostName -ConnectPort $targetPort -ConnectionId $connectionId -ConnectionMode $AcceptedMode -ProxyAuthorization (Get-MihariHeaderText -Headers $request.Headers -Name 'Proxy-Authorization')
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
                $null = Write-MihariEvent -Session $Session -ConnectionId $connectionId -RequestId $requestId -Stage $stage -Outcome 'unsupported' -ElapsedMs $timer.ElapsedMilliseconds -Mode $AcceptedMode -Data @{
                    host = $hostName; port = $targetPort; routeKind = $routeKind; routeSource = $route.Source; reason = $route.Reason; errorCode = $routeErrorCode
                }
                Write-MihariProxyStatus -Stream $clientStream -StatusCode 502 -Reason 'Upstream Route Unresolved'
                $responseStarted = $true
                return
            }
            $null = Write-MihariEvent -Session $Session -ConnectionId $connectionId -RequestId $requestId -Stage $stage -Outcome 'success' -ElapsedMs $timer.ElapsedMilliseconds -Mode $AcceptedMode -Data @{
                host = $hostName; port = $targetPort; routeKind = $routeKind; routeSource = $route.Source; proxyHost = $(if ($routeKind -eq 'ExplicitProxy') { $route.Host } else { $null }); proxyPort = $(if ($routeKind -eq 'ExplicitProxy') { $route.Port } else { $null })
            }
            $stage = $(if ($routeKind -eq 'ExplicitProxy') { 'upstream.proxy.connect' } else { 'upstream.tcp' })
            $upstream = Open-MihariUpstream -Route $route -TargetHost $hostName -TargetPort $targetPort -Tunnel $true -ProxyAuthorization (Get-MihariHeaderText -Headers $request.Headers -Name 'Proxy-Authorization')
            if ($null -ne $upstream.ProxyStatus) {
                $proxyStatus = [int]$upstream.ProxyStatus.StatusCode
                $proxyOutcome = $(if ($proxyStatus -ge 200 -and $proxyStatus -lt 300) { 'success' } else { 'rejected' })
                $null = Write-MihariEvent -Session $Session -ConnectionId $connectionId -RequestId $requestId -Stage 'upstream.proxy.connect' -Outcome $proxyOutcome -ElapsedMs $timer.ElapsedMilliseconds -Mode $AcceptedMode -Data @{
                    host = $hostName; port = $targetPort; routeKind = 'ExplicitProxy'; proxyHost = $route.Host; proxyPort = $route.Port; proxyStatus = $proxyStatus
                }
                if ($proxyStatus -lt 200 -or $proxyStatus -ge 300) {
                    Write-MihariProxyStatus -Stream $clientStream -StatusCode $proxyStatus -Reason $upstream.ProxyStatus.ReasonPhrase -ProxyAuthenticate $upstream.ProxyStatus.ProxyAuthenticate
                    $responseStarted = $true
                    return
                }
            } else {
                $null = Write-MihariEvent -Session $Session -ConnectionId $connectionId -RequestId $requestId -Stage 'upstream.tcp' -Outcome 'success' -ElapsedMs $timer.ElapsedMilliseconds -Mode $AcceptedMode -Data @{
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
            $null = Write-MihariEvent -Session $Session -ConnectionId $connectionId -RequestId $requestId -Stage $stage -Outcome $relayOutcome -ElapsedMs $timer.ElapsedMilliseconds -Mode $AcceptedMode -Data @{
                host = $hostName; port = $targetPort; routeKind = $routeKind; bytesClientToUpstream = $relay.ClientToUpstreamBytes; bytesUpstreamToClient = $relay.UpstreamToClientBytes; direction = $relay.FirstFailureDirection; exception = $relay.Exception
            }
            return
        }

        if ($target.Scheme -ne 'http') {
            throw (New-Object System.NotSupportedException -ArgumentList 'Plain proxy requests require HTTP/1.1 over http; use CONNECT for HTTPS.')
        }
        $null = Write-MihariEvent -Session $Session -ConnectionId $connectionId -RequestId $requestId -Stage 'http.request' -Outcome 'success' -ElapsedMs $timer.ElapsedMilliseconds -Mode $AcceptedMode -Data @{
            host = $hostName; port = $targetPort; path = $safePath; method = $request.Method
        }
        $stage = 'upstream.resolve'
        $uri = New-MihariRouteUri -Target $target
        $route = Resolve-MihariRoute -Uri $uri -Override $Session.UpstreamProxy -PlatformSnapshot $Session.PlatformProxySnapshot -MihariProxyPort $Session.ActualPort
        $routeKind = [string]$route.Kind
        if ($routeKind -eq 'Unsupported') {
            $routeErrorCode = 'upstream_route_unresolved'
            if (-not [string]::IsNullOrWhiteSpace([string]$route.ErrorCode)) { $routeErrorCode = [string]$route.ErrorCode }
            $null = Write-MihariEvent -Session $Session -ConnectionId $connectionId -RequestId $requestId -Stage $stage -Outcome 'unsupported' -ElapsedMs $timer.ElapsedMilliseconds -Mode $AcceptedMode -Data @{
                host = $hostName; port = $targetPort; path = $safePath; routeKind = $routeKind; routeSource = $route.Source; reason = $route.Reason; errorCode = $routeErrorCode
            }
            Write-MihariProxyStatus -Stream $clientStream -StatusCode 502 -Reason 'Upstream Route Unresolved'
            $responseStarted = $true
            return
        }
        $null = Write-MihariEvent -Session $Session -ConnectionId $connectionId -RequestId $requestId -Stage $stage -Outcome 'success' -ElapsedMs $timer.ElapsedMilliseconds -Mode $AcceptedMode -Data @{
            host = $hostName; port = $targetPort; path = $safePath; routeKind = $routeKind; routeSource = $route.Source; proxyHost = $(if ($routeKind -eq 'ExplicitProxy') { $route.Host } else { $null }); proxyPort = $(if ($routeKind -eq 'ExplicitProxy') { $route.Port } else { $null })
        }
        if ($target.OriginTarget -eq '*' -and $routeKind -eq 'ExplicitProxy') {
            throw (New-Object System.NotSupportedException -ArgumentList 'OPTIONS * cannot be routed through an explicit proxy in this implementation.')
        }
        $stage = 'upstream.tcp'
        $upstream = Open-MihariUpstream -Route $route -TargetHost $hostName -TargetPort $targetPort -Tunnel $false
        $null = Write-MihariEvent -Session $Session -ConnectionId $connectionId -RequestId $requestId -Stage $stage -Outcome 'success' -ElapsedMs $timer.ElapsedMilliseconds -Mode $AcceptedMode -Data @{
            host = $hostName; port = $targetPort; routeKind = $routeKind
        }
        $forwardTarget = $target.OriginTarget
        if ($routeKind -eq 'ExplicitProxy') { $forwardTarget = $target.AbsoluteTarget }
        $stage = 'upstream.http'
        Write-MihariHttpMessage -Stream $upstream.Stream -Message $request -RequestTarget $forwardTarget -CloseConnection -ForwardProxyAuthorization:($routeKind -eq 'ExplicitProxy')
        $response = Read-MihariHttpMessage -Stream $upstream.Stream -Kind Response -RequestMethod $request.Method
        if ($null -eq $response) { throw (New-Object System.IO.EndOfStreamException -ArgumentList 'Upstream closed before an HTTP response.') }
        $informationalCount = 0
        while ([int]$response.StatusCode -ge 100 -and [int]$response.StatusCode -lt 200) {
            $informationalCount++
            if ($informationalCount -gt 8) {
                throw (New-Object System.IO.InvalidDataException -ArgumentList 'Too many informational HTTP responses.')
            }
            $response = Read-MihariHttpMessage -Stream $upstream.Stream -Kind Response -RequestMethod $request.Method
            if ($null -eq $response) { throw (New-Object System.IO.EndOfStreamException -ArgumentList 'Upstream closed after an informational HTTP response.') }
        }
        $null = Write-MihariEvent -Session $Session -ConnectionId $connectionId -RequestId $requestId -Stage $stage -Outcome 'success' -ElapsedMs $timer.ElapsedMilliseconds -Mode $AcceptedMode -Data @{
            host = $hostName; port = $targetPort; path = $safePath; routeKind = $routeKind; method = $request.Method; statusCode = [int]$response.StatusCode
        }
        $stage = 'response.relay'
        $responseStarted = $true
        $preserveProxyChallenge = ($routeKind -eq 'ExplicitProxy' -and [int]$response.StatusCode -eq 407)
        Write-MihariHttpMessage -Stream $clientStream -Message $response -CloseConnection -PreserveProxyAuthenticate:$preserveProxyChallenge
        $null = Write-MihariEvent -Session $Session -ConnectionId $connectionId -RequestId $requestId -Stage $stage -Outcome 'success' -ElapsedMs $timer.ElapsedMilliseconds -Mode $AcceptedMode -Data @{
            host = $hostName; port = $targetPort; path = $safePath; statusCode = [int]$response.StatusCode
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
        if ($rootFailure -is [System.NotSupportedException]) {
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
            $null = Write-MihariEvent -Session $Session -ConnectionId $connectionId -RequestId $requestId -Stage $stage -Outcome $outcome -ElapsedMs $timer.ElapsedMilliseconds -Mode $AcceptedMode -Data $failureData
        } catch {
            # Event storage failed. Preserve the original failure for the worker
            # boundary rather than recursively attempting another event write.
            $eventWriterFailed = $true
            throw (New-Object System.AggregateException -ArgumentList 'Connection handling and event writing both failed.', @($failure, $_.Exception))
        }
        if (-not $responseStarted -and $null -ne $clientStream) {
            try { Write-MihariProxyStatus -Stream $clientStream -StatusCode $status -Reason $reason }
            catch [System.IO.IOException] { $null = $_ } # The failing client may already be gone.
            catch [System.ObjectDisposedException] { $null = $_ } # Stop may have closed the socket.
        }
    } finally {
        $cleanupError = $null
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
        if (-not $eventWriterFailed -and $null -ne $writer -and -not $writer.Closed) {
            try {
                $null = Write-MihariEvent -Session $Session -ConnectionId $connectionId -RequestId $requestId -Stage 'connection.cleanup' -Outcome $cleanupOutcome -ElapsedMs $timer.ElapsedMilliseconds -Mode $AcceptedMode -Data $cleanupData
            }
            catch {
                # Stop may close the writer after the open check. Other writer
                # failures reach the worker boundary as observable failures.
                if (-not $writer.Closed) { throw }
            }
        }
    }
}
