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
    $handler = {
        param($sender, $certificate, $chain, $errors)
        $Capture.Invoked = $true
        $Capture.PolicyErrors = $errors
        $Capture.Accepted = ($errors -eq [System.Net.Security.SslPolicyErrors]::None)
        try {
            $Capture.CertificateFacts = Get-MihariTlsCertificateFacts -Certificate $certificate
            if ($null -ne $chain) {
                $Capture.ChainProvided = $true
                $elements = New-Object 'System.Collections.Generic.List[object]'
                foreach ($element in $chain.ChainElements) {
                    if ($elements.Count -ge 8) { break }
                    $item = Get-MihariTlsCertificateFacts -Certificate $element.Certificate
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

function Invoke-MihariInspect {
    param(
        [Parameter(Mandatory=$true)]$Session,
        [Parameter(Mandatory=$true)][System.IO.Stream]$ClientStream,
        [Parameter(Mandatory=$true)][string]$ConnectHost,
        [Parameter(Mandatory=$true)][int]$ConnectPort,
        [Parameter(Mandatory=$true)][string]$ConnectionId,
        [ValidateSet('Inspect', 'Tunnel')][string]$ConnectionMode,
        [AllowNull()][string]$ProxyAuthorization
    )

    if (-not $PSBoundParameters.ContainsKey('ConnectionMode')) { $ConnectionMode = [string]$Session.Mode }
    $requestId = $null
    $clientTls = $null
    $upstreamTls = $null
    $upstream = $null
    $route = $null
    $leaf = $null
    $validationCapture = New-MihariTlsValidationCapture
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
        $clientTlsData = Get-MihariTlsProtocolFacts -Tls $clientTls
        $clientTlsData.host = $ConnectHost
        $clientTlsData.port = $ConnectPort
        $clientTlsData.peerIdentityRole = 'local_inspection_leaf'
        $clientTlsData.clientCertificateState = 'not_performed'
        $clientTlsData.validationPolicy = 'session_issued_exact_host_leaf; client_certificate_not_requested'
        $clientTlsData.certificateSubject = [string]$leaf.Subject
        $clientTlsData.certificateIssuer = [string]$leaf.Issuer
        $clientTlsData.certificateThumbprint = [string]$leaf.Thumbprint
        $null = Write-MihariEvent -Session $Session -ConnectionId $ConnectionId -Stage 'client.tls' -Outcome 'succeeded' -ElapsedMs $timer.ElapsedMilliseconds -Mode $ConnectionMode -TransportLeg 'client' -Data $clientTlsData

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
        $null = Write-MihariEvent -Session $Session -ConnectionId $ConnectionId -RequestId $requestId -Stage 'http.request' -Outcome 'succeeded' -ElapsedMs $timer.ElapsedMilliseconds -Mode $ConnectionMode -Data @{
            host = $ConnectHost; port = $ConnectPort; method = $request.Method; path = $safePath
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
            $null = Write-MihariEvent -Session $Session -ConnectionId $ConnectionId -RequestId $requestId -Stage $stage -Outcome 'failed' -ElapsedMs $timer.ElapsedMilliseconds -Mode $ConnectionMode -Data $routeData
            $wire = [System.Text.Encoding]::ASCII.GetBytes("HTTP/1.1 502 Upstream Route Unresolved`r`nContent-Length: 0`r`nConnection: close`r`n`r`n")
            $clientTls.Write($wire, 0, $wire.Length)
            $clientTls.Flush()
            return
        }
        $null = Write-MihariEvent -Session $Session -ConnectionId $ConnectionId -RequestId $requestId -Stage $stage -Outcome 'succeeded' -ElapsedMs $timer.ElapsedMilliseconds -Mode $ConnectionMode -Data $routeData

        $stage = 'upstream.tcp'
        $timer.Restart()
        $upstream = Open-MihariUpstream -Route $route -TargetHost $ConnectHost -TargetPort $ConnectPort -Tunnel:$true -ProxyAuthorization $ProxyAuthorization
        if ($null -eq $upstream -or $null -eq $upstream.Stream) {
            throw (New-Object System.IO.IOException -ArgumentList @('Upstream connection did not return a stream.'))
        }
        $upstream.Stream.ReadTimeout = 30000
        $upstream.Stream.WriteTimeout = 30000
        $null = Write-MihariEvent -Session $Session -ConnectionId $ConnectionId -RequestId $requestId -Stage $stage -Outcome 'succeeded' -ElapsedMs $timer.ElapsedMilliseconds -Mode $ConnectionMode -Data $routeData

        if ($null -ne $upstream.ProxyStatus) {
            $stage = 'upstream.proxy.connect'
            $proxyStatus = [int]$upstream.ProxyStatus.StatusCode
            $proxyData = @{ host = $ConnectHost; port = $ConnectPort; routeKind = 'ExplicitProxy'; proxyStatus = $proxyStatus; proxyHost = $route.Host; proxyPort = $route.Port }
            if ($proxyStatus -ne 200) {
                $null = Write-MihariEvent -Session $Session -ConnectionId $ConnectionId -RequestId $requestId -Stage $stage -Outcome 'failed' -ElapsedMs $timer.ElapsedMilliseconds -Mode $ConnectionMode -Data $proxyData
                # The browser already has a TLS channel with Mihari. Report the
                # concrete upstream proxy status as an HTTP response inside it.
                $statusText = [string]$proxyStatus
                $wire = [System.Text.Encoding]::ASCII.GetBytes("HTTP/1.1 $statusText Upstream Proxy Response`r`nContent-Length: 0`r`nConnection: close`r`n`r`n")
                $clientTls.Write($wire, 0, $wire.Length)
                $clientTls.Flush()
                return
            }
            $null = Write-MihariEvent -Session $Session -ConnectionId $ConnectionId -RequestId $requestId -Stage $stage -Outcome 'succeeded' -ElapsedMs $timer.ElapsedMilliseconds -Mode $ConnectionMode -Data $proxyData
        }

        $stage = 'upstream.tls'
        $timer.Restart()
        # The callback records platform policy errors and returns exactly the
        # ordinary .NET acceptance decision. No trust or name check is bypassed.
        $validationCallback = New-MihariTlsValidationCallback -Capture $validationCapture
        $upstreamTls = [System.Net.Security.SslStream]::new($upstream.Stream, $true, $validationCallback)
        $upstreamTls.ReadTimeout = 30000
        $upstreamTls.WriteTimeout = 30000
        $emptyCerts = New-Object System.Security.Cryptography.X509Certificates.X509CertificateCollection
        # Keep .NET's normal chain and hostname checks. Revocation probing is
        # optional in this overload and blocks local/private CAs without CRLs.
        $upstreamTls.AuthenticateAsClient($ConnectHost, $emptyCerts, [System.Security.Authentication.SslProtocols]::Tls12, $false)
        $tlsData = Get-MihariTlsProtocolFacts -Tls $upstreamTls
        $tlsData.host = $ConnectHost
        $tlsData.port = $ConnectPort
        $validationFacts = Get-MihariTlsValidationFacts -Capture $validationCapture
        foreach ($key in $validationFacts.Keys) { $tlsData[$key] = $validationFacts[$key] }
        $null = Write-MihariEvent -Session $Session -ConnectionId $ConnectionId -RequestId $requestId -Stage $stage -Outcome 'succeeded' -ElapsedMs $timer.ElapsedMilliseconds -Mode $ConnectionMode -TransportLeg 'upstream' -Data $tlsData

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
        $null = Write-MihariEvent -Session $Session -ConnectionId $ConnectionId -RequestId $requestId -Stage $stage -Outcome 'succeeded' -ElapsedMs $timer.ElapsedMilliseconds -Mode $ConnectionMode -Data @{
            host = $ConnectHost; port = $ConnectPort; method = $request.Method; path = $safePath; statusCode = [int]$response.StatusCode
        }

        $stage = 'response.relay'
        $timer.Restart()
        Write-MihariHttpMessage -Stream $clientTls -Message $response -CloseConnection
        $clientTls.Flush()
        $null = Write-MihariEvent -Session $Session -ConnectionId $ConnectionId -RequestId $requestId -Stage $stage -Outcome 'succeeded' -ElapsedMs $timer.ElapsedMilliseconds -Mode $ConnectionMode -Data @{
            host = $ConnectHost; port = $ConnectPort; statusCode = [int]$response.StatusCode
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
            $null = Write-MihariEvent -Session $Session -ConnectionId $ConnectionId -RequestId $requestId -Stage $stage -Outcome 'failed' -ElapsedMs $timer.ElapsedMilliseconds -Mode $ConnectionMode -TransportLeg 'client' -Data $failure
        }
        elseif ($stage -eq 'upstream.tls') {
            $null = Write-MihariEvent -Session $Session -ConnectionId $ConnectionId -RequestId $requestId -Stage $stage -Outcome 'failed' -ElapsedMs $timer.ElapsedMilliseconds -Mode $ConnectionMode -TransportLeg 'upstream' -Data $failure
        }
        else {
            $null = Write-MihariEvent -Session $Session -ConnectionId $ConnectionId -RequestId $requestId -Stage $stage -Outcome 'failed' -ElapsedMs $timer.ElapsedMilliseconds -Mode $ConnectionMode -Data $failure
        }
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
            $null = Write-MihariEvent -Session $Session -ConnectionId $ConnectionId -RequestId $requestId -Stage 'connection.cleanup' -Outcome 'failed' -ElapsedMs 0 -Mode $ConnectionMode -Data @{
                host = $ConnectHost; port = $ConnectPort; exception = $cleanupError
            }
        }
    }
}
