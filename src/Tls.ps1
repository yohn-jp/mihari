function Get-MihariTlsProtocolFacts {
    param([Parameter(Mandatory=$true)][System.Net.Security.SslStream]$Tls)
    $facts = @{
        tlsProtocol = $Tls.SslProtocol.ToString()
        tlsCipher = $Tls.CipherAlgorithm.ToString()
        tlsCipherStrength = [int]$Tls.CipherStrength
    }
    foreach ($item in @(
        @{ Property = 'NegotiatedApplicationProtocol'; Field = 'tlsAlpn' },
        @{ Property = 'NegotiatedCipherSuite'; Field = 'tlsCipherSuite' }
    )) {
        $property = $Tls.GetType().GetProperty($item.Property)
        if ($null -eq $property) { continue }
        try {
            $value = $property.GetValue($Tls, $null)
            if ($null -ne $value) {
                $display = [string]$value.ToString()
                if (-not [string]::IsNullOrWhiteSpace($display)) { $facts[$item.Field] = $display }
            }
        }
        catch [System.Reflection.TargetInvocationException] {
            # Runtime exposes the property but not a negotiated value on this leg.
        }
    }
    return $facts
}

function Get-MihariTlsCertificateFacts {
    param([AllowNull()][System.Security.Cryptography.X509Certificates.X509Certificate]$Certificate)
    $facts = @{}
    if ($null -eq $Certificate) { return $facts }
    $peer = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @($Certificate)
    try {
        $facts.certificateSubject = [string]$peer.Subject
        $facts.certificateIssuer = [string]$peer.Issuer
        $facts.certificateThumbprint = [string]$peer.Thumbprint
        $facts.certificateNotBefore = $peer.NotBefore.ToUniversalTime().ToString('o')
        $facts.certificateNotAfter = $peer.NotAfter.ToUniversalTime().ToString('o')
        $now = [DateTime]::UtcNow
        $facts.validityState = $(if ($now -ge $peer.NotBefore.ToUniversalTime() -and $now -le $peer.NotAfter.ToUniversalTime()) { 'passed' } else { 'failed' })
        $facts.ekuState = 'passed'
        foreach ($extension in $peer.Extensions) {
            if ($extension.Oid.Value -ne '2.5.29.37') { continue }
            $eku = $extension -as [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]
            if ($null -eq $eku) {
                $eku = [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($extension, $extension.Critical)
            }
            $serverAllowed = $false
            foreach ($usage in $eku.EnhancedKeyUsages) {
                if ($usage.Value -in @('1.3.6.1.5.5.7.3.1', '2.5.29.37.0')) { $serverAllowed = $true; break }
            }
            if (-not $serverAllowed) { $facts.ekuState = 'failed' }
            break
        }
    }
    finally { $peer.Dispose() }
    return $facts
}

function Get-MihariTlsValidationFacts {
    param([Parameter(Mandatory=$true)]$Capture)
    $facts = @{
        validationPolicy = 'system_chain_and_hostname; revocation_not_performed'
        certificateChainState = 'unknown'
        hostnameState = 'unknown'
        validityState = 'unknown'
        ekuState = 'not_performed'
        revocationState = 'not_performed'
        clientCertificateState = 'not_performed'
        peerIdentityRole = 'observed_upstream_tls_peer'
    }
    if (-not $Capture.Invoked) { return $facts }
    $facts.certificateAccepted = [bool]$Capture.Accepted
    if (-not [string]::IsNullOrWhiteSpace([string]$Capture.EvidenceErrorType)) {
        $facts.certificateChainState = 'unavailable'
        $facts.hostnameState = 'unavailable'
        $facts.validityState = 'unavailable'
        return $facts
    }
    if ($null -eq $Capture.CertificateFacts -or $Capture.CertificateFacts.Count -eq 0) {
        $facts.certificateChainState = 'not_performed'
        $facts.hostnameState = 'not_performed'
        $facts.validityState = 'not_performed'
        return $facts
    }
    foreach ($key in $Capture.CertificateFacts.Keys) { $facts[$key] = $Capture.CertificateFacts[$key] }
    $errors = [System.Net.Security.SslPolicyErrors]$Capture.PolicyErrors
    $chainErrors = [System.Net.Security.SslPolicyErrors]::RemoteCertificateChainErrors
    $nameMismatch = [System.Net.Security.SslPolicyErrors]::RemoteCertificateNameMismatch
    if (($errors -band $chainErrors) -ne 0) { $facts.certificateChainState = 'failed' }
    elseif ($Capture.ChainProvided) { $facts.certificateChainState = 'passed' }
    $facts.hostnameState = $(if (($errors -band $nameMismatch) -ne 0) { 'failed' } else { 'passed' })
    if ($Capture.ChainElements.Count -gt 0) { $facts.certificateChain = $Capture.ChainElements }
    return $facts
}

function New-MihariTlsValidationCapture {
    return [pscustomobject]@{
        Invoked = $false
        Accepted = $false
        PolicyErrors = [System.Net.Security.SslPolicyErrors]::None
        CertificateFacts = @{}
        ChainElements = @()
        ChainStatus = @()
        ChainProvided = $false
        EvidenceErrorType = $null
    }
}

function New-MihariTlsValidationCallback {
    param([Parameter(Mandatory=$true)]$Capture)
    # GetNewClosure gives the delegate its own module scope. Capture the helper
    # scriptblock explicitly so it remains callable inside that scope.
    $factReader = ${function:Get-MihariTlsCertificateFacts}
    $handler = {
        param($sender, $certificate, $chain, $errors)
        $Capture.Invoked = $true
        $Capture.PolicyErrors = $errors
        $Capture.Accepted = ($errors -eq [System.Net.Security.SslPolicyErrors]::None)
        try {
            if ($null -eq $certificate) { $Capture.CertificateFacts = @{} }
            else { $Capture.CertificateFacts = & $factReader -Certificate $certificate }
            if ($null -ne $chain) {
                $Capture.ChainProvided = $true
                $elements = New-Object 'System.Collections.Generic.List[object]'
                foreach ($element in $chain.ChainElements) {
                    if ($elements.Count -ge 8) { break }
                    $item = & $factReader -Certificate $element.Certificate
                    $elements.Add([pscustomobject]@{
                        subject = $item.certificateSubject
                        issuer = $item.certificateIssuer
                        thumbprint = $item.certificateThumbprint
                        notBefore = $item.certificateNotBefore
                        notAfter = $item.certificateNotAfter
                    })
                }
                $Capture.ChainElements = $elements.ToArray()
                $statuses = New-Object 'System.Collections.Generic.List[string]'
                foreach ($status in $chain.ChainStatus) {
                    if ($statuses.Count -ge 16) { break }
                    $statuses.Add($status.Status.ToString())
                }
                $Capture.ChainStatus = $statuses.ToArray()
            }
        }
        catch {
            # Evidence failure does not change the platform's trust decision.
            $Capture.CertificateFacts = @{}
            $Capture.EvidenceErrorType = $_.Exception.GetType().FullName
        }
        return [bool]$Capture.Accepted
    }.GetNewClosure()
    return [System.Net.Security.RemoteCertificateValidationCallback]$handler
}

function Invoke-MihariTlsDuplexRelay {
    param(
        [Parameter(Mandatory=$true)][System.IO.Stream]$ClientStream,
        [Parameter(Mandatory=$true)][System.IO.Stream]$UpstreamStream,
        [Parameter(Mandatory=$true)]$Session
    )
    $clientBuffer = [byte[]]::new(16384)
    $upstreamBuffer = [byte[]]::new(16384)
    [long]$clientBytes = 0
    [long]$upstreamBytes = 0
    $direction = $null
    $failure = $null
    $cancelled = $false
    $clientRead = $ClientStream.BeginRead($clientBuffer, 0, $clientBuffer.Length, $null, $null)
    $upstreamRead = $UpstreamStream.BeginRead($upstreamBuffer, 0, $upstreamBuffer.Length, $null, $null)
    try {
        while ($true) {
            if (Test-MihariConnectionStopping -Session $Session) { $cancelled = $true; break }
            $handles = [System.Threading.WaitHandle[]]@($clientRead.AsyncWaitHandle, $upstreamRead.AsyncWaitHandle)
            $completed = [System.Threading.WaitHandle]::WaitAny($handles, 100)
            if ($completed -eq [System.Threading.WaitHandle]::WaitTimeout) { continue }
            if ($completed -eq 0) {
                $direction = 'client_to_upstream'
                $read = $ClientStream.EndRead($clientRead)
                if ($read -le 0) { break }
                $UpstreamStream.Write($clientBuffer, 0, $read)
                $UpstreamStream.Flush()
                $clientBytes += $read
                $clientRead = $ClientStream.BeginRead($clientBuffer, 0, $clientBuffer.Length, $null, $null)
            }
            else {
                $direction = 'upstream_to_client'
                $read = $UpstreamStream.EndRead($upstreamRead)
                if ($read -le 0) { break }
                $ClientStream.Write($upstreamBuffer, 0, $read)
                $ClientStream.Flush()
                $upstreamBytes += $read
                $upstreamRead = $UpstreamStream.BeginRead($upstreamBuffer, 0, $upstreamBuffer.Length, $null, $null)
            }
        }
    }
    catch { $failure = $_.Exception }
    return [pscustomobject]@{
        ClientToUpstreamBytes = $clientBytes
        UpstreamToClientBytes = $upstreamBytes
        FirstFailureDirection = $(if ($null -ne $failure) { $direction } else { $null })
        Exception = $failure
        Cancelled = $cancelled
    }
}

function Invoke-MihariInspect {
    param(
        [Parameter(Mandatory=$true)]$Session,
        [Parameter(Mandatory=$true)][System.IO.Stream]$ClientStream,
        [Parameter(Mandatory=$true)][string]$ConnectHost,
        [Parameter(Mandatory=$true)][int]$ConnectPort,
        [Parameter(Mandatory=$true)][string]$ConnectionId,
        [ValidateSet('Inspect', 'Tunnel')][string]$ConnectionMode,
        [AllowNull()][string]$ProxyAuthorization,
        [AllowNull()][string]$AcceptedConfigurationRevision,
        [long]$AcceptedConnectionElapsedMs = 0,
        [ValidateSet('close', 'reuse')][string]$AcceptedHttpConnectionPolicy = 'close'
    )

    if (-not $PSBoundParameters.ContainsKey('ConnectionMode')) { $ConnectionMode = [string]$Session.Mode }
    $requestId = $null
    $clientTls = $null
    $upstreamTls = $null
    $upstream = $null
    $route = $null
    $leaf = $null
    $upstreamConnectionId = $null
    $upstreamKey = $null
    $exchangeCount = 0
    $longLivedSlot = $false
    $validationCapture = New-MihariTlsValidationCapture
    $stage = 'client.tls'
    $connectionClock = [System.Diagnostics.Stopwatch]::StartNew()
    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        # Connection.ps1 has already acknowledged CONNECT. Keep the underlying
        # client socket owned by that handler while this TLS wrapper is disposed.
        $leaf = Get-MihariLeaf -Session $Session -Host $ConnectHost
        $clientTls = New-Object System.Net.Security.SslStream -ArgumentList @($ClientStream, $true)
        $clientTls.ReadTimeout = 30000
        $clientTls.WriteTimeout = 30000
        $clientTls.AuthenticateAsServer($leaf, $false, [System.Security.Authentication.SslProtocols]::Tls12, $false)
        $clientTlsData = Get-MihariTlsProtocolFacts -Tls $clientTls
        $clientTlsData.host = $ConnectHost
        $clientTlsData.port = $ConnectPort
        $clientTlsData.peerIdentityRole = 'local_inspection_leaf'
        $clientTlsData.clientCertificateState = 'not_performed'
        $clientTlsData.validationPolicy = 'session_issued_exact_host_leaf; client_certificate_not_requested'
        $clientTlsData.certificateSubject = [string]$leaf.Subject
        $clientTlsData.certificateIssuer = [string]$leaf.Issuer
        $clientTlsData.certificateThumbprint = [string]$leaf.Thumbprint
        $null = Write-MihariEvent -Session $Session -ConfigurationRevision $AcceptedConfigurationRevision -ConnectionId $ConnectionId -Stage 'client.tls' -Outcome 'succeeded' -ElapsedMs $timer.ElapsedMilliseconds -Mode $ConnectionMode -TransportLeg 'client' -Data $clientTlsData

        while ($true) {
        if (Test-MihariConnectionStopping -Session $Session) { break }
        $requestId = $null
        $stage = 'http.request'
        $timer.Restart()
        $request = Read-MihariHttpHead -Stream $clientTls -Kind Request
        if ($null -eq $request) { break }
        $exchangeCount++
        if ($exchangeCount -gt 1000) { throw [System.IO.InvalidDataException]::new('The inspected HTTP connection exceeded 1000 exchanges.') }
        $requestId = [Guid]::NewGuid().ToString('N')
        $target = Get-MihariTarget -Message $request -ConnectHost $ConnectHost -ConnectPort $ConnectPort
        if ($target.Scheme -ne 'https') {
            throw (New-Object System.NotSupportedException -ArgumentList @('Inspected CONNECT requires an HTTPS HTTP/1.1 request.'))
        }
        $safePath = Get-MihariSafePath -Target $target.Path
        $requestFraming = Get-MihariHttpBodyFraming -Message $request -Kind Request
        $webSocket = Test-MihariWebSocketRequest -Message $request
        if ($webSocket -and $requestFraming.Kind -ne 'None') {
            throw [System.IO.InvalidDataException]::new('A WebSocket upgrade cannot carry an HTTP request body.')
        }
        $expect = Get-MihariHeaderText -Headers $request.Headers -Name 'Expect'
        if ($expect) {
            throw [System.NotSupportedException]::new('Expect is unavailable on the inspected TLS path.')
        }
        $hasCredentials = ($request.Headers.Contains('Authorization') -or
            $request.Headers.Contains('Proxy-Authorization') -or $request.Headers.Contains('Cookie'))
        $requestKeepAlive = (Test-MihariHttpKeepAlive -Message $request) -and
            $request.Version -eq 'HTTP/1.1' -and $AcceptedHttpConnectionPolicy -eq 'reuse' -and
            -not $hasCredentials -and -not $webSocket
        $null = Write-MihariEvent -Session $Session -ConfigurationRevision $AcceptedConfigurationRevision -ConnectionId $ConnectionId -RequestId $requestId -Stage 'http.request' -Outcome 'succeeded' -ElapsedMs $timer.ElapsedMilliseconds -Mode $ConnectionMode -Data @{
            host = $ConnectHost; port = $ConnectPort; method = $request.Method; path = $safePath; requestFraming = $requestFraming.Kind; connectionPolicy = $AcceptedHttpConnectionPolicy
        }

        $stage = 'upstream.resolve'
        $timer.Restart()
        $builder = New-Object System.UriBuilder -ArgumentList @('https', $ConnectHost, $ConnectPort, '/')
        $route = Resolve-MihariRoute -Uri $builder.Uri -Override $Session.UpstreamProxy -PlatformSnapshot $Session.PlatformProxySnapshot -MihariProxyPort $Session.ActualPort
        $routeData = @{ host = $ConnectHost; port = $ConnectPort; routeKind = $route.Kind; routeSource = $route.Source }
        if ($route.Kind -eq 'ExplicitProxy') {
            $routeData.proxyHost = $route.Host
            $routeData.proxyPort = $route.Port
        }
        if ($route.Kind -eq 'Unsupported') {
            $routeData.reason = $route.Reason
            $routeData.errorCode = 'upstream_route_unresolved'
            if (-not [string]::IsNullOrWhiteSpace([string]$route.ErrorCode)) { $routeData.errorCode = [string]$route.ErrorCode }
            $null = Write-MihariEvent -Session $Session -ConfigurationRevision $AcceptedConfigurationRevision -ConnectionId $ConnectionId -RequestId $requestId -Stage $stage -Outcome 'failed' -ElapsedMs $timer.ElapsedMilliseconds -Mode $ConnectionMode -Data $routeData
            $wire = [System.Text.Encoding]::ASCII.GetBytes("HTTP/1.1 502 Upstream Route Unresolved`r`nContent-Length: 0`r`nConnection: close`r`n`r`n")
            $clientTls.Write($wire, 0, $wire.Length)
            $clientTls.Flush()
            return
        }
        $null = Write-MihariEvent -Session $Session -ConfigurationRevision $AcceptedConfigurationRevision -ConnectionId $ConnectionId -RequestId $requestId -Stage $stage -Outcome 'succeeded' -ElapsedMs $timer.ElapsedMilliseconds -Mode $ConnectionMode -Data $routeData

        $currentKey = [string]$route.Kind + '|' + $ConnectHost + ':' + $ConnectPort
        if ($route.Kind -eq 'ExplicitProxy') { $currentKey += '|' + [string]$route.Host + ':' + [string]$route.Port }
        $reused = ($null -ne $upstreamTls -and $null -ne $upstream -and $upstreamKey -eq $currentKey -and $requestKeepAlive)
        if ($null -ne $upstream -and -not $reused) {
            Unregister-MihariActiveUpstream -Session $Session -ConnectionId $ConnectionId
            if ($null -ne $upstreamTls) { $upstreamTls.Dispose(); $upstreamTls = $null }
            $upstream.Client.Dispose()
            $upstream = $null
            $upstreamConnectionId = $null
        }
        $stage = 'upstream.tcp'
        $timer.Restart()
        if (-not $reused) {
            $upstreamConnectionId = [Guid]::NewGuid().ToString('N')
            $upstream = Open-MihariUpstream -Route $route -TargetHost $ConnectHost -TargetPort $ConnectPort -Tunnel:$true -ProxyAuthorization $ProxyAuthorization
            if ($null -eq $upstream -or $null -eq $upstream.Stream) {
                throw [System.IO.IOException]::new('Upstream connection did not return a stream.')
            }
            $upstreamKey = $currentKey
            if ($null -ne $upstream.Client) { Register-MihariActiveUpstream -Session $Session -ConnectionId $ConnectionId -Client $upstream.Client }
            $upstream.Stream.ReadTimeout = 30000
            $upstream.Stream.WriteTimeout = 30000
        }
        $tcpData = @{}
        foreach ($key in $routeData.Keys) { $tcpData[$key] = $routeData[$key] }
        $tcpData.reused = $reused
        $null = Write-MihariEvent -Session $Session -ConfigurationRevision $AcceptedConfigurationRevision -ConnectionId $ConnectionId -RequestId $requestId -UpstreamConnectionId $upstreamConnectionId -Stage $stage -Outcome 'succeeded' -ElapsedMs $timer.ElapsedMilliseconds -Mode $ConnectionMode -TransportLeg 'upstream' -Data $tcpData

        if (-not $reused) {
            if ($null -ne $upstream.ProxyStatus) {
                $stage = 'upstream.proxy.connect'
                $proxyStatus = [int]$upstream.ProxyStatus.StatusCode
                $proxyData = @{ host = $ConnectHost; port = $ConnectPort; routeKind = 'ExplicitProxy'; proxyStatus = $proxyStatus; proxyHost = $route.Host; proxyPort = $route.Port }
                if ($proxyStatus -ne 200) {
                    $null = Write-MihariEvent -Session $Session -ConfigurationRevision $AcceptedConfigurationRevision -ConnectionId $ConnectionId -RequestId $requestId -UpstreamConnectionId $upstreamConnectionId -Stage $stage -Outcome 'failed' -ElapsedMs $timer.ElapsedMilliseconds -Mode $ConnectionMode -TransportLeg 'upstream' -Data $proxyData
                    $statusText = [string]$proxyStatus
                    $wire = [System.Text.Encoding]::ASCII.GetBytes("HTTP/1.1 $statusText Upstream Proxy Response`r`nContent-Length: 0`r`nConnection: close`r`n`r`n")
                    $clientTls.Write($wire, 0, $wire.Length)
                    $clientTls.Flush()
                    return
                }
                $null = Write-MihariEvent -Session $Session -ConfigurationRevision $AcceptedConfigurationRevision -ConnectionId $ConnectionId -RequestId $requestId -UpstreamConnectionId $upstreamConnectionId -Stage $stage -Outcome 'succeeded' -ElapsedMs $timer.ElapsedMilliseconds -Mode $ConnectionMode -TransportLeg 'upstream' -Data $proxyData
            }

            $stage = 'upstream.tls'
            $timer.Restart()
            $validationCapture = New-MihariTlsValidationCapture
            # This callback returns the normal .NET trust/name decision.
            $validationCallback = New-MihariTlsValidationCallback -Capture $validationCapture
            $upstreamTls = [System.Net.Security.SslStream]::new($upstream.Stream, $true, $validationCallback)
            $upstreamTls.ReadTimeout = 30000
            $upstreamTls.WriteTimeout = 30000
            $emptyCerts = New-Object System.Security.Cryptography.X509Certificates.X509CertificateCollection
            $upstreamTls.AuthenticateAsClient($ConnectHost, $emptyCerts, [System.Security.Authentication.SslProtocols]::Tls12, $false)
            $tlsData = Get-MihariTlsProtocolFacts -Tls $upstreamTls
            $tlsData.host = $ConnectHost
            $tlsData.port = $ConnectPort
            $validationFacts = Get-MihariTlsValidationFacts -Capture $validationCapture
            foreach ($key in $validationFacts.Keys) { $tlsData[$key] = $validationFacts[$key] }
            $null = Write-MihariEvent -Session $Session -ConfigurationRevision $AcceptedConfigurationRevision -ConnectionId $ConnectionId -RequestId $requestId -UpstreamConnectionId $upstreamConnectionId -Stage $stage -Outcome 'succeeded' -ElapsedMs $timer.ElapsedMilliseconds -Mode $ConnectionMode -TransportLeg 'upstream' -Data $tlsData
        }

        $stage = 'upstream.http'
        $timer.Restart()
        Write-MihariHttpHead -Stream $upstreamTls -Message $request -RequestTarget $target.UpstreamTarget -CloseConnection:(-not $requestKeepAlive -and -not $webSocket) -UpgradeWebSocket:$webSocket
        $upstreamTls.Flush()
        $requestTransfer = Copy-MihariHttpBody -Source $clientTls -Destination $upstreamTls -Framing $requestFraming -Session $Session
        $upstreamTls.Flush()
        $response = Read-MihariHttpHead -Stream $upstreamTls -Kind Response -RequestMethod $request.Method
        $informationalCount = 0
        while ($null -ne $response -and [int]$response.StatusCode -ge 100 -and [int]$response.StatusCode -lt 200 -and [int]$response.StatusCode -ne 101) {
            $informationalCount++
            if ($informationalCount -gt 8) {
                throw (New-Object System.IO.InvalidDataException -ArgumentList @('Too many informational HTTP responses from upstream.'))
            }
            Write-MihariHttpHead -Stream $clientTls -Message $response
            $clientTls.Flush()
            $response = Read-MihariHttpHead -Stream $upstreamTls -Kind Response -RequestMethod $request.Method
        }
        if ($null -eq $response) {
            throw (New-Object System.IO.IOException -ArgumentList @('Upstream closed before an HTTP response.'))
        }
        if ([int]$response.StatusCode -eq 101 -and -not $webSocket) {
            throw [System.NotSupportedException]::new('Unexpected HTTP protocol upgrade.')
        }
        $acceptedWebSocket = $false
        if ($webSocket) { $acceptedWebSocket = Test-MihariWebSocketResponse -Message $response }
        $responseFraming = Get-MihariHttpBodyFraming -Message $response -Kind Response -RequestMethod $request.Method
        $responseKeepAlive = (Test-MihariHttpKeepAlive -Message $response) -and
            $response.Version -eq 'HTTP/1.1' -and $responseFraming.Reusable -and
            $requestKeepAlive -and -not $acceptedWebSocket
        $contentType = Get-MihariHeaderText -Headers $response.Headers -Name 'Content-Type'
        $isSse = ($contentType -and $contentType -match '^text/event-stream(?:\s*;|\s*$)')
        if ($acceptedWebSocket -or $isSse) {
            if (-not (Enter-MihariLongLivedSlot -Session $Session)) {
                $null = Write-MihariEvent -Session $Session -ConfigurationRevision $AcceptedConfigurationRevision -ConnectionId $ConnectionId -RequestId $requestId -Stage 'observer.capacity' -Outcome 'rejected' -ElapsedMs $timer.ElapsedMilliseconds -Mode $ConnectionMode -Data @{
                    host = $ConnectHost; port = $ConnectPort; path = $safePath; errorCode = 'long_lived_worker_limit'; workerOccupancy = [int]$Session.ActiveConnectionCount; maxWorkers = [int]$Session.MaxWorkers
                }
                $wire = [System.Text.Encoding]::ASCII.GetBytes("HTTP/1.1 503 Long-Lived Worker Limit`r`nContent-Length: 0`r`nConnection: close`r`n`r`n")
                $clientTls.Write($wire, 0, $wire.Length)
                $clientTls.Flush()
                break
            }
            $longLivedSlot = $true
        }
        if ($isSse) { $upstreamTls.ReadTimeout = 600000 }
        $null = Write-MihariEvent -Session $Session -ConfigurationRevision $AcceptedConfigurationRevision -ConnectionId $ConnectionId -RequestId $requestId -UpstreamConnectionId $upstreamConnectionId -Stage $stage -Outcome 'succeeded' -ElapsedMs $timer.ElapsedMilliseconds -Mode $ConnectionMode -TransportLeg 'upstream' -Data @{
            host = $ConnectHost; port = $ConnectPort; method = $request.Method; path = $safePath; statusCode = [int]$response.StatusCode; requestBytes = $requestTransfer.Bytes; responseFraming = $responseFraming.Kind
        }

        $stage = 'response.relay'
        $timer.Restart()
        Write-MihariHttpHead -Stream $clientTls -Message $response -CloseConnection:(-not $responseKeepAlive -and -not $acceptedWebSocket) -UpgradeWebSocket:$acceptedWebSocket
        $clientTls.Flush()
        if ($acceptedWebSocket) {
            $stage = 'websocket.relay'
            $relay = Invoke-MihariTlsDuplexRelay -ClientStream $clientTls -UpstreamStream $upstreamTls -Session $Session
            $relayOutcome = 'succeeded'
            if ($relay.Cancelled) { $relayOutcome = 'cancelled' }
            if ($null -ne $relay.Exception) { $relayOutcome = 'failed' }
            $null = Write-MihariEvent -Session $Session -ConfigurationRevision $AcceptedConfigurationRevision -ConnectionId $ConnectionId -RequestId $requestId -UpstreamConnectionId $upstreamConnectionId -Stage $stage -Outcome $relayOutcome -ElapsedMs $timer.ElapsedMilliseconds -Mode $ConnectionMode -Data @{
                host = $ConnectHost; port = $ConnectPort; path = $safePath; bytesClientToUpstream = $relay.ClientToUpstreamBytes; bytesUpstreamToClient = $relay.UpstreamToClientBytes; direction = $relay.FirstFailureDirection; exception = $relay.Exception
            }
            break
        }
        $bodyRelayStartedMs = $AcceptedConnectionElapsedMs + $connectionClock.ElapsedMilliseconds
        $responseTransfer = Copy-MihariHttpBody -Source $upstreamTls -Destination $clientTls -Framing $responseFraming -Session $Session
        $firstByteAtMs = $null
        $lastByteAtMs = $null
        if ($null -ne $responseTransfer.FirstByteMs) { $firstByteAtMs = $bodyRelayStartedMs + $responseTransfer.FirstByteMs }
        if ($null -ne $responseTransfer.LastByteMs) { $lastByteAtMs = $bodyRelayStartedMs + $responseTransfer.LastByteMs }
        $clientTls.Flush()
        $null = Write-MihariEvent -Session $Session -ConfigurationRevision $AcceptedConfigurationRevision -ConnectionId $ConnectionId -RequestId $requestId -UpstreamConnectionId $upstreamConnectionId -Stage $stage -Outcome 'succeeded' -ElapsedMs $timer.ElapsedMilliseconds -Mode $ConnectionMode -Data @{
            host = $ConnectHost; port = $ConnectPort; statusCode = [int]$response.StatusCode; responseBytes = $responseTransfer.Bytes; firstByteMs = $firstByteAtMs; lastByteMs = $lastByteAtMs; forwardWriteMs = $responseTransfer.ForwardWriteMs; framing = $responseTransfer.Framing
        }
        if ($isSse -and $longLivedSlot) {
            Exit-MihariLongLivedSlot -Session $Session
            $longLivedSlot = $false
        }
        if (-not $responseKeepAlive) { break }
        }
    } catch {
        $failure = @{ host = $ConnectHost; port = $ConnectPort; exception = $_ }
        if ($stage -eq 'upstream.tls') {
            $validationFacts = Get-MihariTlsValidationFacts -Capture $validationCapture
            foreach ($key in $validationFacts.Keys) { $failure[$key] = $validationFacts[$key] }
        }
        if ($null -ne $route) { $failure.routeKind = $route.Kind }
        if ($stage -eq 'http.request' -and $_.Exception -is [System.NotSupportedException]) {
            $failure.errorCode = 'unsupported_protocol'
        }
        if ($stage -eq 'client.tls') {
            $failure.peerIdentityRole = 'local_inspection_leaf'
            $null = Write-MihariEvent -Session $Session -ConfigurationRevision $AcceptedConfigurationRevision -ConnectionId $ConnectionId -RequestId $requestId -Stage $stage -Outcome 'failed' -ElapsedMs $timer.ElapsedMilliseconds -Mode $ConnectionMode -TransportLeg 'client' -Data $failure
        }
        elseif ($stage -like 'upstream.*') {
            $null = Write-MihariEvent -Session $Session -ConfigurationRevision $AcceptedConfigurationRevision -ConnectionId $ConnectionId -RequestId $requestId -UpstreamConnectionId $upstreamConnectionId -Stage $stage -Outcome 'failed' -ElapsedMs $timer.ElapsedMilliseconds -Mode $ConnectionMode -TransportLeg 'upstream' -Data $failure
        }
        else {
            $null = Write-MihariEvent -Session $Session -ConfigurationRevision $AcceptedConfigurationRevision -ConnectionId $ConnectionId -RequestId $requestId -UpstreamConnectionId $upstreamConnectionId -Stage $stage -Outcome 'failed' -ElapsedMs $timer.ElapsedMilliseconds -Mode $ConnectionMode -Data $failure
        }
    } finally {
        $cleanupErrors = New-Object 'System.Collections.Generic.List[System.Exception]'
        if ($longLivedSlot) {
            try { Exit-MihariLongLivedSlot -Session $Session }
            catch { $cleanupErrors.Add($_.Exception) }
        }
        try { Unregister-MihariActiveUpstream -Session $Session -ConnectionId $ConnectionId }
        catch { $cleanupErrors.Add($_.Exception) }
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
            $null = Write-MihariEvent -Session $Session -ConfigurationRevision $AcceptedConfigurationRevision -ConnectionId $ConnectionId -RequestId $requestId -UpstreamConnectionId $upstreamConnectionId -Stage 'connection.cleanup' -Outcome 'failed' -ElapsedMs 0 -Mode $ConnectionMode -Data @{
                host = $ConnectHost; port = $ConnectPort; exception = $cleanupError
            }
        }
    }
}
