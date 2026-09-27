function Invoke-MihariInspect {
    param(
        [Parameter(Mandatory=$true)]$Session,
        [Parameter(Mandatory=$true)][System.IO.Stream]$ClientStream,
        [Parameter(Mandatory=$true)][string]$ConnectHost,
        [Parameter(Mandatory=$true)][int]$ConnectPort,
        [Parameter(Mandatory=$true)][string]$ConnectionId,
        [AllowNull()][string]$ProxyAuthorization
    )

    $requestId = $null
    $clientTls = $null
    $upstreamTls = $null
    $upstream = $null
    $route = $null
    $leaf = $null
    $stage = 'client.tls'
    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        # Connection.ps1 has already acknowledged CONNECT. Keep the underlying
        # client socket owned by that handler while this TLS wrapper is disposed.
        $leaf = Get-MihariLeaf -Session $Session -Host $ConnectHost
        $clientTls = New-Object System.Net.Security.SslStream -ArgumentList @($ClientStream, $true)
        $clientTls.ReadTimeout = 30000
        $clientTls.WriteTimeout = 30000
        $clientTls.AuthenticateAsServer($leaf, $false, [System.Security.Authentication.SslProtocols]::Tls12, $false)
        $null = Write-MihariEvent -Session $Session -ConnectionId $ConnectionId -Stage 'client.tls' -Outcome 'succeeded' -ElapsedMs $timer.ElapsedMilliseconds -Data @{
            host = $ConnectHost; port = $ConnectPort
            tlsProtocol = $clientTls.SslProtocol.ToString()
            tlsCipher = $clientTls.CipherAlgorithm.ToString()
        }

        $stage = 'http.request'
        $timer.Restart()
        $request = Read-MihariHttpMessage -Stream $clientTls -Kind Request
        if ($null -eq $request) { return }
        $requestId = [Guid]::NewGuid().ToString('N')
        $target = Get-MihariTarget -Message $request -ConnectHost $ConnectHost -ConnectPort $ConnectPort
        if ($target.Scheme -ne 'https') {
            throw (New-Object System.NotSupportedException -ArgumentList @('Inspected CONNECT requires an HTTPS HTTP/1.1 request.'))
        }
        $safePath = Get-MihariSafePath -Target $target.Path
        $null = Write-MihariEvent -Session $Session -ConnectionId $ConnectionId -RequestId $requestId -Stage 'http.request' -Outcome 'succeeded' -ElapsedMs $timer.ElapsedMilliseconds -Data @{
            host = $ConnectHost; port = $ConnectPort; method = $request.Method; path = $safePath
        }

        $stage = 'upstream.resolve'
        $timer.Restart()
        $builder = New-Object System.UriBuilder -ArgumentList @('https', $ConnectHost, $ConnectPort, '/')
        $route = Resolve-MihariRoute -Uri $builder.Uri -Override $Session.UpstreamProxy
        $routeData = @{ host = $ConnectHost; port = $ConnectPort; routeKind = $route.Kind; routeSource = $route.Source }
        if ($route.Kind -eq 'ExplicitProxy') {
            $routeData.proxyHost = $route.Host
            $routeData.proxyPort = $route.Port
        }
        if ($route.Kind -eq 'Unsupported') {
            $routeData.reason = $route.Reason
            $routeData.errorCode = 'upstream_route_unresolved'
            $null = Write-MihariEvent -Session $Session -ConnectionId $ConnectionId -RequestId $requestId -Stage $stage -Outcome 'failed' -ElapsedMs $timer.ElapsedMilliseconds -Data $routeData
            $wire = [System.Text.Encoding]::ASCII.GetBytes("HTTP/1.1 502 Upstream Route Unresolved`r`nContent-Length: 0`r`nConnection: close`r`n`r`n")
            $clientTls.Write($wire, 0, $wire.Length)
            $clientTls.Flush()
            return
        }
        $null = Write-MihariEvent -Session $Session -ConnectionId $ConnectionId -RequestId $requestId -Stage $stage -Outcome 'succeeded' -ElapsedMs $timer.ElapsedMilliseconds -Data $routeData

        $stage = 'upstream.tcp'
        $timer.Restart()
        $upstream = Open-MihariUpstream -Route $route -TargetHost $ConnectHost -TargetPort $ConnectPort -Tunnel:$true -ProxyAuthorization $ProxyAuthorization
        if ($null -eq $upstream -or $null -eq $upstream.Stream) {
            throw (New-Object System.IO.IOException -ArgumentList @('Upstream connection did not return a stream.'))
        }
        $upstream.Stream.ReadTimeout = 30000
        $upstream.Stream.WriteTimeout = 30000
        $null = Write-MihariEvent -Session $Session -ConnectionId $ConnectionId -RequestId $requestId -Stage $stage -Outcome 'succeeded' -ElapsedMs $timer.ElapsedMilliseconds -Data $routeData

        if ($null -ne $upstream.ProxyStatus) {
            $stage = 'upstream.proxy.connect'
            $proxyStatus = [int]$upstream.ProxyStatus.StatusCode
            $proxyData = @{ host = $ConnectHost; port = $ConnectPort; routeKind = 'ExplicitProxy'; proxyStatus = $proxyStatus; proxyHost = $route.Host; proxyPort = $route.Port }
            if ($proxyStatus -ne 200) {
                $null = Write-MihariEvent -Session $Session -ConnectionId $ConnectionId -RequestId $requestId -Stage $stage -Outcome 'failed' -ElapsedMs $timer.ElapsedMilliseconds -Data $proxyData
                # The browser already has a TLS channel with Mihari. Report the
                # concrete upstream proxy status as an HTTP response inside it.
                $statusText = [string]$proxyStatus
                $wire = [System.Text.Encoding]::ASCII.GetBytes("HTTP/1.1 $statusText Upstream Proxy Response`r`nContent-Length: 0`r`nConnection: close`r`n`r`n")
                $clientTls.Write($wire, 0, $wire.Length)
                $clientTls.Flush()
                return
            }
            $null = Write-MihariEvent -Session $Session -ConnectionId $ConnectionId -RequestId $requestId -Stage $stage -Outcome 'succeeded' -ElapsedMs $timer.ElapsedMilliseconds -Data $proxyData
        }

        $stage = 'upstream.tls'
        $timer.Restart()
        # No custom validation callback: .NET/Windows performs normal trust and
        # hostname validation, including for an explicit proxy CONNECT tunnel.
        $upstreamTls = New-Object System.Net.Security.SslStream -ArgumentList @($upstream.Stream, $true)
        $upstreamTls.ReadTimeout = 30000
        $upstreamTls.WriteTimeout = 30000
        $emptyCerts = New-Object System.Security.Cryptography.X509Certificates.X509CertificateCollection
        # Keep .NET's normal chain and hostname checks. Revocation probing is
        # optional in this overload and blocks local/private CAs without CRLs.
        $upstreamTls.AuthenticateAsClient($ConnectHost, $emptyCerts, [System.Security.Authentication.SslProtocols]::Tls12, $false)
        $tlsData = @{ host = $ConnectHost; port = $ConnectPort; certificateAccepted = $true; tlsProtocol = $upstreamTls.SslProtocol.ToString(); tlsCipher = $upstreamTls.CipherAlgorithm.ToString() }
        if ($null -ne $upstreamTls.RemoteCertificate) {
            $peer = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @($upstreamTls.RemoteCertificate)
            try {
                $tlsData.certificateSubject = $peer.Subject
                $tlsData.certificateIssuer = $peer.Issuer
                $tlsData.certificateThumbprint = $peer.Thumbprint
                $tlsData.certificateNotBefore = $peer.NotBefore.ToUniversalTime().ToString('o')
                $tlsData.certificateNotAfter = $peer.NotAfter.ToUniversalTime().ToString('o')
            } finally {
                $peer.Dispose()
            }
        }
        $null = Write-MihariEvent -Session $Session -ConnectionId $ConnectionId -RequestId $requestId -Stage $stage -Outcome 'succeeded' -ElapsedMs $timer.ElapsedMilliseconds -Data $tlsData

        $stage = 'upstream.http'
        $timer.Restart()
        Write-MihariHttpMessage -Stream $upstreamTls -Message $request -RequestTarget $target.UpstreamTarget -CloseConnection
        $upstreamTls.Flush()
        $response = Read-MihariHttpMessage -Stream $upstreamTls -Kind Response -RequestMethod $request.Method
        $informationalCount = 0
        while ($null -ne $response -and [int]$response.StatusCode -ge 100 -and [int]$response.StatusCode -lt 200) {
            if ([int]$response.StatusCode -eq 101) {
                throw (New-Object System.NotSupportedException -ArgumentList @('HTTP protocol upgrade is outside the initial Inspect contract.'))
            }
            $informationalCount++
            if ($informationalCount -gt 8) {
                throw (New-Object System.IO.InvalidDataException -ArgumentList @('Too many informational HTTP responses from upstream.'))
            }
            $response = Read-MihariHttpMessage -Stream $upstreamTls -Kind Response -RequestMethod $request.Method
        }
        if ($null -eq $response) {
            throw (New-Object System.IO.IOException -ArgumentList @('Upstream closed before an HTTP response.'))
        }
        $null = Write-MihariEvent -Session $Session -ConnectionId $ConnectionId -RequestId $requestId -Stage $stage -Outcome 'succeeded' -ElapsedMs $timer.ElapsedMilliseconds -Data @{
            host = $ConnectHost; port = $ConnectPort; method = $request.Method; path = $safePath; statusCode = [int]$response.StatusCode
        }

        $stage = 'response.relay'
        $timer.Restart()
        Write-MihariHttpMessage -Stream $clientTls -Message $response -CloseConnection
        $clientTls.Flush()
        $null = Write-MihariEvent -Session $Session -ConnectionId $ConnectionId -RequestId $requestId -Stage $stage -Outcome 'succeeded' -ElapsedMs $timer.ElapsedMilliseconds -Data @{
            host = $ConnectHost; port = $ConnectPort; statusCode = [int]$response.StatusCode
        }
    } catch {
        $failure = @{ host = $ConnectHost; port = $ConnectPort; exception = $_ }
        if ($stage -eq 'upstream.tls') { $failure.certificateAccepted = $false }
        if ($null -ne $route) { $failure.routeKind = $route.Kind }
        if ($stage -eq 'http.request' -and $_.Exception -is [System.NotSupportedException]) {
            $failure.errorCode = 'unsupported_protocol'
        }
        $null = Write-MihariEvent -Session $Session -ConnectionId $ConnectionId -RequestId $requestId -Stage $stage -Outcome 'failed' -ElapsedMs $timer.ElapsedMilliseconds -Data $failure
    } finally {
        $cleanupErrors = New-Object 'System.Collections.Generic.List[System.Exception]'
        try { if ($null -ne $upstreamTls) { $upstreamTls.Dispose() } }
        catch { $cleanupErrors.Add($_.Exception) }
        if ($null -ne $upstream) {
            try { if ($null -ne $upstream.Stream) { $upstream.Stream.Dispose() } }
            catch { $cleanupErrors.Add($_.Exception) }
            try { if ($null -ne $upstream.Client) { $upstream.Client.Dispose() } }
            catch { $cleanupErrors.Add($_.Exception) }
        }
        try { if ($null -ne $clientTls) { $clientTls.Dispose() } }
        catch { $cleanupErrors.Add($_.Exception) }
        try { if ($null -ne $leaf) { Release-MihariLeaf -Session $Session -Certificate $leaf } }
        catch { $cleanupErrors.Add($_.Exception) }
        foreach ($cleanupError in $cleanupErrors) {
            $null = Write-MihariEvent -Session $Session -ConnectionId $ConnectionId -RequestId $requestId -Stage 'connection.cleanup' -Outcome 'failed' -ElapsedMs 0 -Data @{
                host = $ConnectHost; port = $ConnectPort; exception = $cleanupError
            }
        }
    }
}
