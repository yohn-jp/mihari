# PowerShell 7 native HTTP/2 Inspect TLS legs. All optional types are resolved
# at runtime so Windows PowerShell 5.1 can parse and load this file unchanged.

function New-MihariHttp2AlpnList {
    param([string[]]$Names)
    $protocolType = Resolve-MihariHttp2Type -Name 'System.Net.Security.SslApplicationProtocol'
    if ($null -eq $protocolType) { throw [System.NotSupportedException]::new('SslApplicationProtocol is unavailable.') }
    $listType = [System.Collections.Generic.List[int]].GetGenericTypeDefinition().MakeGenericType([type[]]@($protocolType))
    $list = [Activator]::CreateInstance($listType)
    $add = $listType.GetMethod('Add')
    foreach ($name in $Names) {
        $member = $(if ($name -eq 'h2') { 'Http2' } elseif ($name -eq 'http/1.1') { 'Http11' } else { throw [System.ArgumentException]::new('Unsupported ALPN protocol.') })
        $value = $null
        $property = $protocolType.GetProperty($member, [Reflection.BindingFlags]::Public -bor [Reflection.BindingFlags]::Static)
        if ($null -ne $property) { $value = $property.GetValue($null, $null) }
        if ($null -eq $value) {
            $field = $protocolType.GetField($member, [Reflection.BindingFlags]::Public -bor [Reflection.BindingFlags]::Static)
            if ($null -ne $field) { $value = $field.GetValue($null) }
        }
        if ($null -eq $value) { throw [System.NotSupportedException]::new('The selected runtime lacks a required ALPN protocol constant.') }
        [void]$add.Invoke($list, [object[]]@($value))
    }
    return ,$list
}

function Set-MihariHttp2TlsOption {
    param($Options, [string]$Name, $Value)
    $property = $Options.GetType().GetProperty($Name)
    if ($null -eq $property -or -not $property.CanWrite) { throw [System.NotSupportedException]::new('A required managed TLS option is unavailable.') }
    $property.SetValue($Options, $Value, $null)
}

function New-MihariHttp2TlsOptions {
    param([ValidateSet('Server','Client')][string]$Role, $Certificate, [string]$TargetHost)
    $typeName = $(if ($Role -eq 'Server') { 'System.Net.Security.SslServerAuthenticationOptions' } else { 'System.Net.Security.SslClientAuthenticationOptions' })
    $optionType = Resolve-MihariHttp2Type -Name $typeName
    if ($null -eq $optionType) { throw [System.NotSupportedException]::new('Managed TLS ALPN options are unavailable.') }
    $options = [Activator]::CreateInstance($optionType)
    Set-MihariHttp2TlsOption -Options $options -Name 'EnabledSslProtocols' -Value ([System.Security.Authentication.SslProtocols]::Tls12)
    Set-MihariHttp2TlsOption -Options $options -Name 'ApplicationProtocols' -Value (New-MihariHttp2AlpnList -Names @('h2'))
    if ($Role -eq 'Server') { Set-MihariHttp2TlsOption -Options $options -Name 'ServerCertificate' -Value $Certificate }
    else { Set-MihariHttp2TlsOption -Options $options -Name 'TargetHost' -Value $TargetHost }
    return $options
}

function Invoke-MihariHttp2TlsAuthentication {
    param([System.Net.Security.SslStream]$Tls, $Options, [ValidateSet('Server','Client')][string]$Role, [int]$TimeoutMs = 30000)
    $name = $(if ($Role -eq 'Server') { 'AuthenticateAsServer' } else { 'AuthenticateAsClient' })
    $optionType = $Options.GetType()
    $sync = $null
    $async = $null
    foreach ($method in $Tls.GetType().GetMethods()) {
        $parameters = $method.GetParameters()
        if ($parameters.Length -eq 0 -or $parameters[0].ParameterType -ne $optionType) { continue }
        if ($method.Name -eq $name -and $parameters.Length -eq 1) { $sync = $method }
        elseif ($method.Name -eq ($name + 'Async')) { $async = $method }
    }
    if ($null -ne $async) {
        $parameters = $async.GetParameters()
        $args = New-Object 'object[]' $parameters.Length
        $args[0] = $Options
        for ($i = 1; $i -lt $parameters.Length; $i++) {
            if ($parameters[$i].ParameterType.FullName -eq 'System.Threading.CancellationToken') { $args[$i] = [Threading.CancellationToken]::None }
            elseif ($parameters[$i].HasDefaultValue) { $args[$i] = $parameters[$i].DefaultValue }
            else { $args[$i] = [Activator]::CreateInstance($parameters[$i].ParameterType) }
        }
        $task = $async.Invoke($Tls, $args)
        if (-not $task.Wait($TimeoutMs)) { throw [System.TimeoutException]::new('Managed TLS authentication timed out.') }
        $task.GetAwaiter().GetResult()
        return
    }
    if ($null -ne $sync) { [void]$sync.Invoke($Tls, [object[]]@($Options)); return }
    throw [System.NotSupportedException]::new('Managed TLS authentication with ALPN options is unavailable.')
}

function Invoke-MihariHttp2Inspect {
    param(
        [Parameter(Mandatory=$true)]$Session,
        [Parameter(Mandatory=$true)][System.IO.Stream]$ClientStream,
        [Parameter(Mandatory=$true)][string]$ConnectHost,
        [Parameter(Mandatory=$true)][int]$ConnectPort,
        [Parameter(Mandatory=$true)][string]$ConnectionId,
        [ValidateSet('Inspect','Tunnel')][string]$ConnectionMode = 'Inspect',
        [AllowNull()][string]$ProxyAuthorization,
        [int]$AcceptedConfigurationRevision = 0
    )
    if (-not (Test-MihariHttp2RuntimeCapability).Available) { throw [System.NotSupportedException]::new('Native HTTP/2 ALPN is unavailable on this runtime.') }
    $leaf = $null
    $clientTls = $null
    $upstream = $null
    $upstreamTls = $null
    $upstreamConnectionId = $null
    $route = $null
    $validationCapture = New-MihariTlsValidationCapture
    $stage = 'observer.capacity'
    $clock = [Diagnostics.Stopwatch]::StartNew()
    $longLivedSlot = $false
    try {
        if (-not (Enter-MihariLongLivedSlot -Session $Session)) {
            throw [System.IO.IOException]::new('The bounded long-lived connection capacity is full.')
        }
        $longLivedSlot = $true
        $stage = 'client.tls'
        $leaf = Get-MihariLeaf -Session $Session -DestinationHost $ConnectHost
        $clientTls = [System.Net.Security.SslStream]::new($ClientStream, $true)
        $clientTls.ReadTimeout = 30000
        $clientTls.WriteTimeout = 30000
        $serverOptions = New-MihariHttp2TlsOptions -Role Server -Certificate $leaf
        Invoke-MihariHttp2TlsAuthentication -Tls $clientTls -Options $serverOptions -Role Server
        if ((Get-MihariHttp2NegotiatedProtocol -Tls $clientTls) -ne 'h2') {
            throw [System.NotSupportedException]::new('The client TLS leg did not negotiate h2.')
        }
        $clientFacts = Get-MihariTlsProtocolFacts -Tls $clientTls
        $clientFacts.tlsAlpn = 'h2'
        $clientFacts.host = $ConnectHost
        $clientFacts.port = $ConnectPort
        $clientFacts.peerIdentityRole = 'local_inspection_leaf'
        $clientFacts.clientCertificateState = 'not_performed'
        $clientFacts.validationPolicy = 'session_issued_exact_host_leaf; client_certificate_not_requested'
        $clientFacts.certificateSubject = [string]$leaf.Subject
        $clientFacts.certificateIssuer = [string]$leaf.Issuer
        $clientFacts.certificateThumbprint = [string]$leaf.Thumbprint
        $null = Write-MihariEvent -Session $Session -ConnectionId $ConnectionId -Mode $ConnectionMode -ConfigurationRevision $AcceptedConfigurationRevision -TransportLeg 'client' -Stage 'client.tls' -Outcome 'succeeded' -ElapsedMs $clock.ElapsedMilliseconds -Data $clientFacts

        $stage = 'upstream.resolve'
        $uri = [UriBuilder]::new('https', $ConnectHost, $ConnectPort, '/')
        $route = Resolve-MihariRoute -Uri $uri.Uri -Override $Session.UpstreamProxy -PlatformSnapshot $Session.PlatformProxySnapshot -MihariProxyPort $Session.ActualPort
        $routeFacts = @{ host = $ConnectHost; port = $ConnectPort; routeKind = $route.Kind; routeSource = $route.Source }
        if ($route.Kind -eq 'ExplicitProxy') { $routeFacts.proxyHost = $route.Host; $routeFacts.proxyPort = $route.Port }
        if ($route.Kind -eq 'Unsupported') {
            $routeFacts.errorCode = $(if ($route.ErrorCode) { $route.ErrorCode } else { 'upstream_route_unresolved' })
            $routeFacts.reason = $route.Reason
            $null = Write-MihariEvent -Session $Session -ConnectionId $ConnectionId -Mode $ConnectionMode -ConfigurationRevision $AcceptedConfigurationRevision -Stage $stage -Outcome 'failed' -ElapsedMs $clock.ElapsedMilliseconds -Data $routeFacts
            return
        }
        $null = Write-MihariEvent -Session $Session -ConnectionId $ConnectionId -Mode $ConnectionMode -ConfigurationRevision $AcceptedConfigurationRevision -Stage $stage -Outcome 'succeeded' -ElapsedMs $clock.ElapsedMilliseconds -Data $routeFacts

        $stage = 'upstream.tcp'
        $upstreamConnectionId = [guid]::NewGuid().ToString('N')
        $upstream = Open-MihariUpstream -Route $route -TargetHost $ConnectHost -TargetPort $ConnectPort -Tunnel:$true -ProxyAuthorization $ProxyAuthorization
        if ($null -eq $upstream -or $null -eq $upstream.Stream) { throw [IO.IOException]::new('Upstream connection returned no stream.') }
        if ($null -ne $upstream.Client) { Register-MihariActiveUpstream -Session $Session -ConnectionId $ConnectionId -Client $upstream.Client }
        $null = Write-MihariEvent -Session $Session -ConnectionId $ConnectionId -UpstreamConnectionId $upstreamConnectionId -Mode $ConnectionMode -ConfigurationRevision $AcceptedConfigurationRevision -TransportLeg 'upstream' -Stage $stage -Outcome 'succeeded' -ElapsedMs $clock.ElapsedMilliseconds -Data $routeFacts
        if ($null -ne $upstream.ProxyStatus) {
            $stage = 'upstream.proxy.connect'
            $proxyFacts = @{ host = $ConnectHost; port = $ConnectPort; routeKind = $route.Kind; proxyStatus = [int]$upstream.ProxyStatus.StatusCode; proxyHost = $route.Host; proxyPort = $route.Port }
            $outcome = $(if ($proxyFacts.proxyStatus -eq 200) { 'succeeded' } else { 'failed' })
            $null = Write-MihariEvent -Session $Session -ConnectionId $ConnectionId -UpstreamConnectionId $upstreamConnectionId -Mode $ConnectionMode -ConfigurationRevision $AcceptedConfigurationRevision -TransportLeg 'upstream' -Stage $stage -Outcome $outcome -ElapsedMs $clock.ElapsedMilliseconds -Data $proxyFacts
            if ($proxyFacts.proxyStatus -ne 200) { return }
        }

        $stage = 'upstream.tls'
        $validationCapture = New-MihariTlsValidationCapture
        $callback = New-MihariTlsValidationCallback -Capture $validationCapture
        $upstreamTls = [System.Net.Security.SslStream]::new($upstream.Stream, $true, $callback)
        $upstreamTls.ReadTimeout = 30000
        $upstreamTls.WriteTimeout = 30000
        $clientOptions = New-MihariHttp2TlsOptions -Role Client -TargetHost $ConnectHost
        Invoke-MihariHttp2TlsAuthentication -Tls $upstreamTls -Options $clientOptions -Role Client
        $upstreamFacts = Get-MihariTlsProtocolFacts -Tls $upstreamTls
        $upstreamFacts.tlsAlpn = Get-MihariHttp2NegotiatedProtocol -Tls $upstreamTls
        $upstreamFacts.host = $ConnectHost
        $upstreamFacts.port = $ConnectPort
        $validation = Get-MihariTlsValidationFacts -Capture $validationCapture
        foreach ($key in $validation.Keys) { $upstreamFacts[$key] = $validation[$key] }
        $null = Write-MihariEvent -Session $Session -ConnectionId $ConnectionId -UpstreamConnectionId $upstreamConnectionId -Mode $ConnectionMode -ConfigurationRevision $AcceptedConfigurationRevision -TransportLeg 'upstream' -Stage $stage -Outcome 'succeeded' -ElapsedMs $clock.ElapsedMilliseconds -Data $upstreamFacts
        if ($upstreamFacts.tlsAlpn -ne 'h2') { throw [System.NotSupportedException]::new('The upstream TLS leg did not negotiate h2; protocol conversion is unavailable.') }

        $stage = 'http2.relay'
        Invoke-MihariHttp2Relay -Session $Session -ClientTls $clientTls -UpstreamTls $upstreamTls -ConnectionId $ConnectionId -UpstreamConnectionId $upstreamConnectionId -ConnectHost $ConnectHost -ConnectPort $ConnectPort -ConnectionMode $ConnectionMode -AcceptedConfigurationRevision $AcceptedConfigurationRevision
    }
    catch {
        $facts = @{ host = $ConnectHost; port = $ConnectPort; exception = $_; errorCode = 'http2_inspect_failed' }
        if ($stage -eq 'observer.capacity') { $facts.errorCode = 'long_lived_worker_limit' }
        if ($stage -eq 'client.tls' -and $_.Exception -is [System.NotSupportedException]) { $facts.errorCode = 'http2_client_alpn_mismatch' }
        if ($stage -eq 'upstream.tls' -and $_.Exception -is [System.NotSupportedException]) { $facts.errorCode = 'http2_upstream_alpn_mismatch' }
        if ($stage -eq 'upstream.tls') {
            $validation = Get-MihariTlsValidationFacts -Capture $validationCapture
            foreach ($key in $validation.Keys) { $facts[$key] = $validation[$key] }
        }
        if ($null -ne $route) { $facts.routeKind = $route.Kind }
        $leg = $(if ($stage -eq 'client.tls') { 'client' } elseif ($stage -like 'upstream.*') { 'upstream' } else { 'end_to_end' })
        if ($stage -ne 'http2.relay') {
            $null = Write-MihariEvent -Session $Session -ConnectionId $ConnectionId -UpstreamConnectionId $upstreamConnectionId -Mode $ConnectionMode -ConfigurationRevision $AcceptedConfigurationRevision -TransportLeg $leg -Stage $stage -Outcome 'failed' -ElapsedMs $clock.ElapsedMilliseconds -Data $facts
        }
    }
    finally {
        $cleanupErrors = New-Object 'System.Collections.Generic.List[System.Exception]'
        try { Unregister-MihariActiveUpstream -Session $Session -ConnectionId $ConnectionId } catch { $cleanupErrors.Add($_.Exception) }
        try { if ($null -ne $upstreamTls) { $upstreamTls.Dispose() } } catch { $cleanupErrors.Add($_.Exception) }
        if ($null -ne $upstream) {
            try { if ($null -ne $upstream.Stream) { $upstream.Stream.Dispose() } } catch { $cleanupErrors.Add($_.Exception) }
            try { if ($null -ne $upstream.Client) { $upstream.Client.Dispose() } } catch { $cleanupErrors.Add($_.Exception) }
        }
        try { if ($null -ne $clientTls) { $clientTls.Dispose() } } catch { $cleanupErrors.Add($_.Exception) }
        try { if ($null -ne $leaf) { Release-MihariLeaf -Session $Session -Certificate $leaf } } catch { $cleanupErrors.Add($_.Exception) }
        if ($longLivedSlot) { try { Exit-MihariLongLivedSlot -Session $Session } catch { $cleanupErrors.Add($_.Exception) } }
        foreach ($error in $cleanupErrors) {
            $null = Write-MihariEvent -Session $Session -ConnectionId $ConnectionId -UpstreamConnectionId $upstreamConnectionId -Mode $ConnectionMode -ConfigurationRevision $AcceptedConfigurationRevision -Stage 'connection.cleanup' -Outcome 'failed' -ElapsedMs $clock.ElapsedMilliseconds -Data @{ host = $ConnectHost; port = $ConnectPort; exception = $error }
        }
    }
}
