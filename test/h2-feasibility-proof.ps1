[CmdletBinding()]
param(
    [ValidateRange(1000, 60000)]
    [int] $TimeoutMilliseconds = 15000
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path $PSScriptRoot -Parent
$sourceRoot = Join-Path $repoRoot 'src'
$result = [ordered]@{}
$cleanupFailures = New-Object 'System.Collections.Generic.List[string]'
$failure = $null
$primaryCA = $null
$untrustedCA = $null
$publicRoot = $null
$primaryLeaf = $null
$untrustedLeaf = $null
$primaryKeyFile = $null
$untrustedKeyFile = $null
$primarySession = [pscustomobject]@{ CA = $null; LeafCache = (New-Object 'System.Collections.Hashtable') }
$untrustedSession = [pscustomobject]@{ CA = $null; LeafCache = (New-Object 'System.Collections.Hashtable') }
$rootInstalled = $false
$listener = $null
$clientTcp = $null
$serverTcp = $null
$clientTls = $null
$serverTls = $null

function Resolve-ProbeType {
    param([Parameter(Mandatory = $true)][string] $Name)

    $resolved = [System.Type]::GetType($Name, $false)
    if ($null -ne $resolved) { return $resolved }
    foreach ($assembly in [AppDomain]::CurrentDomain.GetAssemblies()) {
        $resolved = $assembly.GetType($Name, $false)
        if ($null -ne $resolved) { return $resolved }
    }
    return $null
}

function Find-ProbeMethod {
    param(
        [Parameter(Mandatory = $true)][System.Type] $Type,
        [Parameter(Mandatory = $true)][string] $Name,
        [Parameter(Mandatory = $true)][System.Type] $FirstParameterType
    )

    foreach ($method in $Type.GetMethods([System.Reflection.BindingFlags]::Public -bor [System.Reflection.BindingFlags]::Instance)) {
        if ($method.Name -ne $Name) { continue }
        $parameters = $method.GetParameters()
        if ($parameters.Count -gt 0 -and $parameters[0].ParameterType -eq $FirstParameterType) {
            return $method
        }
    }
    return $null
}

function Get-ProbeProtocolConstant {
    param(
        [Parameter(Mandatory = $true)][System.Type] $ProtocolType,
        [Parameter(Mandatory = $true)][string] $Name,
        [Parameter(Mandatory = $true)][string] $WireValue
    )

    $field = $ProtocolType.GetField($Name, [System.Reflection.BindingFlags]::Public -bor [System.Reflection.BindingFlags]::Static)
    if ($null -ne $field) { return $field.GetValue($null) }
    $property = $ProtocolType.GetProperty($Name, [System.Reflection.BindingFlags]::Public -bor [System.Reflection.BindingFlags]::Static)
    if ($null -ne $property) { return $property.GetValue($null, $null) }
    $constructor = $ProtocolType.GetConstructor([type[]]@([byte[]]))
    if ($null -ne $constructor) {
        $bytes = [System.Text.Encoding]::ASCII.GetBytes($WireValue)
        return $constructor.Invoke([object[]]@($bytes))
    }
    return $null
}

function New-ProbeProtocolList {
    param(
        [Parameter(Mandatory = $true)][System.Type] $ProtocolType,
        [Parameter(Mandatory = $true)][object[]] $Protocols
    )

    $genericListType = Resolve-ProbeType -Name 'System.Collections.Generic.List`1'
    if ($null -eq $genericListType) { throw 'System.Collections.Generic.List<T> is unavailable.' }
    $listType = $genericListType.MakeGenericType([type[]]@($ProtocolType))
    $list = [Activator]::CreateInstance($listType)
    $add = $listType.GetMethod('Add')
    foreach ($protocol in $Protocols) {
        [void] $add.Invoke($list, [object[]]@($protocol))
    }
    return $list
}

function Set-ProbeProperty {
    param(
        [Parameter(Mandatory = $true)][object] $Target,
        [Parameter(Mandatory = $true)][string] $Name,
        [Parameter(Mandatory = $true)][object] $Value
    )

    $property = $Target.GetType().GetProperty($Name)
    if ($null -eq $property -or -not $property.CanWrite) {
        throw ("Required TLS option property is unavailable: {0}.{1}" -f $Target.GetType().FullName, $Name)
    }
    $property.SetValue($Target, $Value, $null)
}

function Invoke-ProbeAuthenticationAsync {
    param(
        [Parameter(Mandatory = $true)][System.Net.Security.SslStream] $Stream,
        [Parameter(Mandatory = $true)][System.Reflection.MethodInfo] $Method,
        [Parameter(Mandatory = $true)][object] $Options
    )

    $parameters = $Method.GetParameters()
    $arguments = New-Object 'object[]' $parameters.Count
    $arguments[0] = $Options
    for ($index = 1; $index -lt $parameters.Count; $index++) {
        if ($parameters[$index].ParameterType.FullName -eq 'System.Threading.CancellationToken') {
            $arguments[$index] = [System.Threading.CancellationToken]::None
        }
        elseif ($parameters[$index].HasDefaultValue) {
            $arguments[$index] = $parameters[$index].DefaultValue
        }
        else {
            $arguments[$index] = [Activator]::CreateInstance($parameters[$index].ParameterType)
        }
    }
    $task = $Method.Invoke($Stream, $arguments)
    if ($null -eq $task -or $task -isnot [System.Threading.Tasks.Task]) {
        throw 'The SslStream authentication API did not return a Task.'
    }
    return $task
}

function New-ProbeLoopbackPair {
    param([Parameter(Mandatory = $true)][int] $WaitMilliseconds)

    $localListener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $localClient = $null
    $localServer = $null
    try {
        $localListener.Start()
        $port = ([System.Net.IPEndPoint] $localListener.LocalEndpoint).Port
        $acceptTask = $localListener.AcceptTcpClientAsync()
        $localClient = [System.Net.Sockets.TcpClient]::new()
        $connectTask = $localClient.ConnectAsync('127.0.0.1', $port)
        if (-not $connectTask.Wait($WaitMilliseconds)) { throw 'Loopback TCP connect timed out.' }
        if (-not $acceptTask.Wait($WaitMilliseconds)) { throw 'Loopback TCP accept timed out.' }
        $localServer = $acceptTask.Result
        $localClient.ReceiveTimeout = $WaitMilliseconds
        $localClient.SendTimeout = $WaitMilliseconds
        $localServer.ReceiveTimeout = $WaitMilliseconds
        $localServer.SendTimeout = $WaitMilliseconds
        return [pscustomobject]@{
            Listener = $localListener
            Client = $localClient
            Server = $localServer
        }
    }
    catch {
        if ($null -ne $localServer) { $localServer.Close() }
        if ($null -ne $localClient) { $localClient.Close() }
        $localListener.Stop()
        throw ("Could not open loopback TLS fixture: {0}" -f $_.Exception.Message)
    }
}

function Get-ProbeLeafKeyFile {
    param([Parameter(Mandatory = $true)][System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate)

    $privateKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
    try {
        $profile = [Environment]::GetFolderPath([Environment+SpecialFolder]::ApplicationData)
        if ($privateKey -is [System.Security.Cryptography.RSACng]) {
            $key = $privateKey.Key
            if ($key.IsEphemeral -or [string]::IsNullOrWhiteSpace($key.UniqueName)) {
                throw 'Schannel leaf did not acquire a named temporary CNG key.'
            }
            return Join-Path $profile ('Microsoft\Crypto\Keys\' + $key.UniqueName)
        }
        if ($privateKey -is [System.Security.Cryptography.RSACryptoServiceProvider]) {
            $info = $privateKey.CspKeyContainerInfo
            if ([string]::IsNullOrWhiteSpace($info.UniqueKeyContainerName)) {
                throw 'Schannel leaf did not acquire a named temporary CAPI key.'
            }
            $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
            return Join-Path $profile ('Microsoft\Crypto\RSA\' + $sid + '\' + $info.UniqueKeyContainerName)
        }
        throw ("Unexpected TLS leaf key provider: {0}" -f $privateKey.GetType().FullName)
    }
    finally {
        if ($null -ne $privateKey) { $privateKey.Dispose() }
    }
}

function Get-ProbeNegotiatedProtocol {
    param([Parameter(Mandatory = $true)][System.Net.Security.SslStream] $Stream)

    $negotiated = $Stream.GetType().GetProperty('NegotiatedApplicationProtocol').GetValue($Stream, $null)
    $protocolProperty = $negotiated.GetType().GetProperty('Protocol')
    if ($null -eq $protocolProperty) { throw 'Negotiated SslApplicationProtocol has no Protocol property.' }
    $value = $protocolProperty.GetValue($negotiated, $null)
    if ($value -is [byte[]]) { return [System.Text.Encoding]::ASCII.GetString($value) }
    $toArray = $value.GetType().GetMethod('ToArray', [type[]]@())
    if ($null -eq $toArray) { throw 'Could not read the negotiated ALPN protocol bytes.' }
    $bytes = $toArray.Invoke($value, [object[]]@())
    return [System.Text.Encoding]::ASCII.GetString([byte[]]$bytes)
}

function Invoke-ProbeTls12LeafHandshake {
    param(
        [Parameter(Mandatory = $true)][System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate,
        [Parameter(Mandatory = $true)][int] $WaitMilliseconds
    )

    $pair = New-ProbeLoopbackPair -WaitMilliseconds $WaitMilliseconds
    $serverStream = $null
    $clientStream = $null
    try {
        $serverStream = [System.Net.Security.SslStream]::new($pair.Server.GetStream(), $false)
        $clientStream = [System.Net.Security.SslStream]::new($pair.Client.GetStream(), $false)
        $serverAuth = $serverStream.BeginAuthenticateAsServer(
            $Certificate, $false, [System.Security.Authentication.SslProtocols]::Tls12, $false, $null, $null
        )
        $clientStream.AuthenticateAsClient('localhost', $null, [System.Security.Authentication.SslProtocols]::Tls12, $false)
        if (-not $serverAuth.AsyncWaitHandle.WaitOne($WaitMilliseconds)) { throw 'TLS 1.2 server authentication timed out.' }
        $serverStream.EndAuthenticateAsServer($serverAuth)
        if ($serverStream.SslProtocol -ne [System.Security.Authentication.SslProtocols]::Tls12 -or
            $clientStream.SslProtocol -ne [System.Security.Authentication.SslProtocols]::Tls12) {
            throw 'The leaf fixture did not negotiate TLS 1.2 on both endpoints.'
        }
        $remote = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($clientStream.RemoteCertificate)
        try {
            if ($remote.Thumbprint -ine $Certificate.Thumbprint) { throw 'The client did not receive the expected session leaf.' }
        }
        finally { $remote.Dispose() }
        return $true
    }
    finally {
        if ($null -ne $clientStream) { $clientStream.Dispose() }
        if ($null -ne $serverStream) { $serverStream.Dispose() }
        $pair.Client.Close()
        $pair.Server.Close()
        $pair.Listener.Stop()
    }
}

function Invoke-ProbeAlpnLeafHandshake {
    param(
        [Parameter(Mandatory = $true)][System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate,
        [Parameter(Mandatory = $true)][System.Type] $ServerOptionsType,
        [Parameter(Mandatory = $true)][System.Type] $ClientOptionsType,
        [Parameter(Mandatory = $true)][System.Type] $ProtocolType,
        [Parameter(Mandatory = $true)][System.Reflection.MethodInfo] $ServerMethod,
        [Parameter(Mandatory = $true)][System.Reflection.MethodInfo] $ClientMethod,
        [Parameter(Mandatory = $true)][int] $WaitMilliseconds
    )

    $http2 = Get-ProbeProtocolConstant -ProtocolType $ProtocolType -Name 'Http2' -WireValue 'h2'
    $http11 = Get-ProbeProtocolConstant -ProtocolType $ProtocolType -Name 'Http11' -WireValue 'http/1.1'
    if ($null -eq $http2 -or $null -eq $http11) { throw 'The runtime does not expose HTTP/2 and HTTP/1.1 ALPN protocol values.' }
    $pair = New-ProbeLoopbackPair -WaitMilliseconds $WaitMilliseconds
    $serverStream = $null
    $clientStream = $null
    try {
        $serverStream = [System.Net.Security.SslStream]::new($pair.Server.GetStream(), $false)
        $clientStream = [System.Net.Security.SslStream]::new($pair.Client.GetStream(), $false)
        $serverOptions = [Activator]::CreateInstance($ServerOptionsType)
        $clientOptions = [Activator]::CreateInstance($ClientOptionsType)
        Set-ProbeProperty -Target $serverOptions -Name 'ServerCertificate' -Value $Certificate
        Set-ProbeProperty -Target $serverOptions -Name 'EnabledSslProtocols' -Value ([System.Security.Authentication.SslProtocols]::Tls12)
        Set-ProbeProperty -Target $serverOptions -Name 'ApplicationProtocols' -Value (New-ProbeProtocolList -ProtocolType $ProtocolType -Protocols @($http2))
        Set-ProbeProperty -Target $clientOptions -Name 'TargetHost' -Value 'localhost'
        Set-ProbeProperty -Target $clientOptions -Name 'EnabledSslProtocols' -Value ([System.Security.Authentication.SslProtocols]::Tls12)
        Set-ProbeProperty -Target $clientOptions -Name 'ApplicationProtocols' -Value (New-ProbeProtocolList -ProtocolType $ProtocolType -Protocols @($http11, $http2))

        # The client uses default OS certificate validation. The temporary session root is
        # installed for this positive fixture and removed by the outer finally block.
        $serverTask = Invoke-ProbeAuthenticationAsync -Stream $serverStream -Method $ServerMethod -Options $serverOptions
        $clientTask = Invoke-ProbeAuthenticationAsync -Stream $clientStream -Method $ClientMethod -Options $clientOptions
        $tasks = [System.Threading.Tasks.Task[]]@($serverTask, $clientTask)
        if (-not [System.Threading.Tasks.Task]::WaitAll($tasks, $WaitMilliseconds)) {
            throw 'ALPN TLS handshake timed out.'
        }
        if ($serverStream.SslProtocol -ne [System.Security.Authentication.SslProtocols]::Tls12 -or
            $clientStream.SslProtocol -ne [System.Security.Authentication.SslProtocols]::Tls12) {
            throw 'The ALPN fixture did not negotiate TLS 1.2 on both endpoints.'
        }
        $serverProtocol = Get-ProbeNegotiatedProtocol -Stream $serverStream
        $clientProtocol = Get-ProbeNegotiatedProtocol -Stream $clientStream
        if ($serverProtocol -ne 'h2' -or $clientProtocol -ne 'h2') {
            throw ("Expected h2 on both endpoints; server observed '{0}', client observed '{1}'." -f $serverProtocol, $clientProtocol)
        }
        return [pscustomobject]@{
            ServerSelected = $serverProtocol
            ClientNegotiated = $clientProtocol
            TlsVersionServer = $serverStream.SslProtocol.ToString()
            TlsVersionClient = $clientStream.SslProtocol.ToString()
            ClientValidationCallback = 'not supplied; default OS validation accepted the installed session root'
        }
    }
    finally {
        if ($null -ne $clientStream) { $clientStream.Dispose() }
        if ($null -ne $serverStream) { $serverStream.Dispose() }
        $pair.Client.Close()
        $pair.Server.Close()
        $pair.Listener.Stop()
    }
}

function Invoke-ProbeDefaultValidationRejectsUntrustedLeaf {
    param(
        [Parameter(Mandatory = $true)][System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate,
        [Parameter(Mandatory = $true)][int] $WaitMilliseconds
    )

    $pair = New-ProbeLoopbackPair -WaitMilliseconds $WaitMilliseconds
    $serverStream = $null
    $clientStream = $null
    $serverError = $null
    try {
        $serverStream = [System.Net.Security.SslStream]::new($pair.Server.GetStream(), $false)
        $clientStream = [System.Net.Security.SslStream]::new($pair.Client.GetStream(), $false)
        $serverAuth = $serverStream.BeginAuthenticateAsServer(
            $Certificate, $false, [System.Security.Authentication.SslProtocols]::Tls12, $false, $null, $null
        )
        $rejected = $false
        $clientErrorType = $null
        try {
            # Deliberately use the overload without a RemoteCertificateValidationCallback.
            $clientStream.AuthenticateAsClient('localhost', $null, [System.Security.Authentication.SslProtocols]::Tls12, $false)
        }
        catch [System.Security.Authentication.AuthenticationException] {
            $rejected = $true
            $clientErrorType = $_.Exception.GetType().FullName
        }
        if (-not $rejected) { throw 'Default SslStream validation accepted a leaf issued by an untrusted fixture CA.' }
        if ($serverAuth.AsyncWaitHandle.WaitOne($WaitMilliseconds)) {
            try { $serverStream.EndAuthenticateAsServer($serverAuth) }
            catch { $serverError = $_.Exception.GetType().FullName }
        }
        return [pscustomobject]@{
            Result = 'passed: default client validation rejected an otherwise name-matching leaf from an untrusted fixture CA'
            ClientExceptionType = $clientErrorType
            ServerPeerAlertType = $serverError
            ClientValidationCallback = 'not supplied'
        }
    }
    finally {
        if ($null -ne $clientStream) { $clientStream.Dispose() }
        if ($null -ne $serverStream) { $serverStream.Dispose() }
        $pair.Client.Close()
        $pair.Server.Close()
        $pair.Listener.Stop()
    }
}

function Test-ProbeRootAbsent {
    param([Parameter(Mandatory = $true)][string] $Thumbprint)
    $store = [System.Security.Cryptography.X509Certificates.X509Store]::new(
        [System.Security.Cryptography.X509Certificates.StoreName]::Root,
        [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
    )
    try {
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
        foreach ($certificate in $store.Certificates) {
            try {
                if ($certificate.Thumbprint -ieq $Thumbprint) { return $false }
            }
            finally { $certificate.Dispose() }
        }
        return $true
    }
    finally {
        $store.Close()
        $store.Dispose()
    }
}

$runtimeInformationType = Resolve-ProbeType -Name 'System.Runtime.InteropServices.RuntimeInformation'
$frameworkDescription = $null
if ($null -ne $runtimeInformationType) {
    $frameworkProperty = $runtimeInformationType.GetProperty('FrameworkDescription')
    if ($null -ne $frameworkProperty) { $frameworkDescription = $frameworkProperty.GetValue($null, $null) }
}
$clrVersion = $null
if ($PSVersionTable.ContainsKey('CLRVersion')) { $clrVersion = [string]$PSVersionTable.CLRVersion }
$runtimeVersion = [string][Environment]::Version
$osVersion = [Environment]::OSVersion
$sslStreamType = Resolve-ProbeType -Name 'System.Net.Security.SslStream'
$serverOptionsType = Resolve-ProbeType -Name 'System.Net.Security.SslServerAuthenticationOptions'
$clientOptionsType = Resolve-ProbeType -Name 'System.Net.Security.SslClientAuthenticationOptions'
$protocolType = Resolve-ProbeType -Name 'System.Net.Security.SslApplicationProtocol'

$result['runtime'] = [ordered]@{
    osPlatform = [string]$osVersion.Platform
    osVersion = [string]$osVersion.Version
    osDescription = [string]$osVersion.VersionString
    powershellEdition = [string]$PSVersionTable.PSEdition
    powershellVersion = [string]$PSVersionTable.PSVersion
    clrVersion = $clrVersion
    environmentRuntimeVersion = $runtimeVersion
    frameworkDescription = $frameworkDescription
    sslStreamAssembly = if ($null -ne $sslStreamType) { $sslStreamType.Assembly.FullName } else { $null }
}

if ($env:OS -ne 'Windows_NT') {
    $result['status'] = 'not-run'
    $result['reason'] = 'The session certificate and Schannel leaf proof requires Windows.'
    Write-Output ($result | ConvertTo-Json -Depth 8)
    exit 2
}

. (Join-Path $sourceRoot 'Certificate.ps1')
. (Join-Path $PSScriptRoot 'TestSupport.ps1')

$sslMethods = @()
if ($null -ne $sslStreamType) {
    foreach ($method in $sslStreamType.GetMethods([System.Reflection.BindingFlags]::Public -bor [System.Reflection.BindingFlags]::Instance)) {
        if ($method.Name -in @('AuthenticateAsServerAsync', 'AuthenticateAsClientAsync')) {
            $sslMethods += $method.ToString()
        }
    }
}
$serverProtocolProperty = $null
$clientProtocolProperty = $null
$negotiatedProtocolProperty = $null
$serverMethod = $null
$clientMethod = $null
if ($null -ne $serverOptionsType) { $serverProtocolProperty = $serverOptionsType.GetProperty('ApplicationProtocols') }
if ($null -ne $clientOptionsType) { $clientProtocolProperty = $clientOptionsType.GetProperty('ApplicationProtocols') }
if ($null -ne $sslStreamType) { $negotiatedProtocolProperty = $sslStreamType.GetProperty('NegotiatedApplicationProtocol') }
if ($null -ne $sslStreamType -and $null -ne $serverOptionsType) {
    $serverMethod = Find-ProbeMethod -Type $sslStreamType -Name 'AuthenticateAsServerAsync' -FirstParameterType $serverOptionsType
}
if ($null -ne $sslStreamType -and $null -ne $clientOptionsType) {
    $clientMethod = Find-ProbeMethod -Type $sslStreamType -Name 'AuthenticateAsClientAsync' -FirstParameterType $clientOptionsType
}
$missingAlpnSurface = New-Object 'System.Collections.Generic.List[string]'
if ($null -eq $serverOptionsType) { $missingAlpnSurface.Add('SslServerAuthenticationOptions') }
elseif ($null -eq $serverProtocolProperty -or -not $serverProtocolProperty.CanWrite) { $missingAlpnSurface.Add('SslServerAuthenticationOptions.ApplicationProtocols') }
if ($null -eq $clientOptionsType) { $missingAlpnSurface.Add('SslClientAuthenticationOptions') }
elseif ($null -eq $clientProtocolProperty -or -not $clientProtocolProperty.CanWrite) { $missingAlpnSurface.Add('SslClientAuthenticationOptions.ApplicationProtocols') }
if ($null -eq $protocolType) { $missingAlpnSurface.Add('SslApplicationProtocol') }
if ($null -eq $negotiatedProtocolProperty) { $missingAlpnSurface.Add('SslStream.NegotiatedApplicationProtocol') }
if ($null -eq $serverMethod) { $missingAlpnSurface.Add('SslStream.AuthenticateAsServerAsync(options)') }
if ($null -eq $clientMethod) { $missingAlpnSurface.Add('SslStream.AuthenticateAsClientAsync(options)') }

$result['tlsApi'] = [ordered]@{
    alpnSurfaceComplete = ($missingAlpnSurface.Count -eq 0)
    missingAlpnMembers = @($missingAlpnSurface.ToArray())
    serverOptionsAssembly = if ($null -ne $serverOptionsType) { $serverOptionsType.Assembly.FullName } else { $null }
    clientOptionsAssembly = if ($null -ne $clientOptionsType) { $clientOptionsType.Assembly.FullName } else { $null }
    protocolAssembly = if ($null -ne $protocolType) { $protocolType.Assembly.FullName } else { $null }
    authenticationOverloads = @($sslMethods)
    certificateRequestAvailable = ($null -ne (Resolve-ProbeType -Name 'System.Security.Cryptography.X509Certificates.CertificateRequest'))
    subjectAlternativeNameBuilderAvailable = ($null -ne (Resolve-ProbeType -Name 'System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder'))
    rsaCertificateExtensionsAvailable = ($null -ne (Resolve-ProbeType -Name 'System.Security.Cryptography.X509Certificates.RSACertificateExtensions'))
}

try {
    Write-Host '[h2-probe] Creating two unique in-memory Mihari CAs and exact-host leaves.'
    $primaryCA = New-MihariCA -SessionId ([guid]::NewGuid().ToString('N'))
    $primarySession.CA = $primaryCA
    $primaryLeaf = Get-MihariLeaf -Session $primarySession -DestinationHost 'localhost'
    $primaryKeyFile = Get-ProbeLeafKeyFile -Certificate $primaryLeaf
    if (-not (Test-Path -LiteralPath $primaryKeyFile -PathType Leaf)) {
        throw 'The active exact-host leaf has no temporary current-user key file for Schannel.'
    }
    if (-not (Test-MihariTestThumbprintAbsent -Thumbprint $primaryLeaf.Thumbprint)) {
        throw 'The primary per-host leaf is present in a certificate store.'
    }

    $publicRoot = Install-MihariCARoot -CA $primaryCA
    $rootInstalled = $true
    if ($publicRoot.HasPrivateKey) { throw 'The installed test root unexpectedly contains a private key.' }
    $result['leaf'] = [ordered]@{
        exactHost = 'localhost'
        leafHasPrivateKey = [bool]$primaryLeaf.HasPrivateKey
        temporaryCurrentUserKeyFilePresentDuringUse = [bool](Test-Path -LiteralPath $primaryKeyFile -PathType Leaf)
        leafAbsentFromCertificateStoresDuringUse = [bool](Test-MihariTestThumbprintAbsent -Thumbprint $primaryLeaf.Thumbprint)
        publicSessionRootInstalledForPositiveValidation = $true
    }

    if ($missingAlpnSurface.Count -eq 0) {
        Write-Host '[h2-probe] Testing server ALPN selection, client ALPN readback, TLS 1.2, and the Mihari leaf.'
        $alpnResult = Invoke-ProbeAlpnLeafHandshake `
            -Certificate $primaryLeaf `
            -ServerOptionsType $serverOptionsType `
            -ClientOptionsType $clientOptionsType `
            -ProtocolType $protocolType `
            -ServerMethod $serverMethod `
            -ClientMethod $clientMethod `
            -WaitMilliseconds $TimeoutMilliseconds
        $result['alpn'] = [ordered]@{
            status = 'passed'
            serverSelected = $alpnResult.ServerSelected
            clientNegotiated = $alpnResult.ClientNegotiated
            tlsVersionServer = $alpnResult.TlsVersionServer
            tlsVersionClient = $alpnResult.TlsVersionClient
            clientValidation = $alpnResult.ClientValidationCallback
        }
    }
    else {
        Write-Host '[h2-probe] ALPN managed API surface is incomplete; testing the same exact-host leaf over the existing TLS 1.2 SslStream path.'
        [void](Invoke-ProbeTls12LeafHandshake -Certificate $primaryLeaf -WaitMilliseconds $TimeoutMilliseconds)
        $result['alpn'] = [ordered]@{
            status = 'unavailable-api-surface'
            missingMembers = @($missingAlpnSurface.ToArray())
            leafTls12Fallback = 'passed'
        }
    }
    $result['leaf']['tlsHandshake'] = 'passed'

    $removed = Remove-MihariCARoot -Thumbprint $primaryCA.Thumbprint -Subject $primaryCA.Subject
    $rootInstalled = $false
    if ($removed -ne 1) { throw ("Expected to remove one exact session root; removed {0}." -f $removed) }
    if (-not (Test-ProbeRootAbsent -Thumbprint $primaryCA.Thumbprint)) { throw 'The exact session root remains in CurrentUser Root after cleanup.' }
    $publicRoot.Dispose()
    $publicRoot = $null

    Write-Host '[h2-probe] Testing that a default outbound SslStream rejects an untrusted session leaf.'
    $untrustedCA = New-MihariCA -SessionId ([guid]::NewGuid().ToString('N'))
    $untrustedSession.CA = $untrustedCA
    $untrustedLeaf = Get-MihariLeaf -Session $untrustedSession -DestinationHost 'localhost'
    $untrustedKeyFile = Get-ProbeLeafKeyFile -Certificate $untrustedLeaf
    if (-not (Test-ProbeRootAbsent -Thumbprint $untrustedCA.Thumbprint)) {
        throw 'The negative-validation fixture CA unexpectedly exists in CurrentUser Root.'
    }
    if (-not (Test-MihariTestThumbprintAbsent -Thumbprint $untrustedLeaf.Thumbprint)) {
        throw 'The negative-validation fixture leaf unexpectedly exists in a certificate store.'
    }
    $validationResult = Invoke-ProbeDefaultValidationRejectsUntrustedLeaf -Certificate $untrustedLeaf -WaitMilliseconds $TimeoutMilliseconds
    $result['defaultUpstreamValidation'] = $validationResult
    $result['status'] = 'passed'
}
catch {
    $failure = $_
    $result['status'] = 'failed'
    $result['failureType'] = $_.Exception.GetType().FullName
    $result['failureMessage'] = $_.Exception.Message
}
finally {
    if ($null -ne $publicRoot) {
        try { $publicRoot.Dispose() }
        catch { $cleanupFailures.Add(('public root object dispose: ' + $_.Exception.Message)) }
    }
    if ($rootInstalled -and $null -ne $primaryCA) {
        try {
            $removed = Remove-MihariCARoot -Thumbprint $primaryCA.Thumbprint -Subject $primaryCA.Subject
            if ($removed -ne 1 -and -not (Test-ProbeRootAbsent -Thumbprint $primaryCA.Thumbprint)) {
                $cleanupFailures.Add(('exact session root cleanup removed {0} certificate(s)' -f $removed))
            }
        }
        catch { $cleanupFailures.Add(('exact session root cleanup: ' + $_.Exception.Message)) }
    }
    if ($null -ne $primaryLeaf) {
        try { Release-MihariLeaf -Session $primarySession -Certificate $primaryLeaf }
        catch { $cleanupFailures.Add(('primary leaf lease cleanup: ' + $_.Exception.Message)) }
    }
    if ($null -ne $untrustedLeaf) {
        try { Release-MihariLeaf -Session $untrustedSession -Certificate $untrustedLeaf }
        catch { $cleanupFailures.Add(('untrusted leaf lease cleanup: ' + $_.Exception.Message)) }
    }
    try { Clear-MihariLeafCache -Session $primarySession }
    catch { $cleanupFailures.Add(('primary leaf cache cleanup: ' + $_.Exception.Message)) }
    try { Clear-MihariLeafCache -Session $untrustedSession }
    catch { $cleanupFailures.Add(('untrusted leaf cache cleanup: ' + $_.Exception.Message)) }
    if ($null -ne $primaryCA) {
        try { $primaryCA.Certificate.Dispose() }
        catch { $cleanupFailures.Add(('primary CA certificate cleanup: ' + $_.Exception.Message)) }
        try { $primaryCA.PrivateKey.Dispose() }
        catch { $cleanupFailures.Add(('primary CA key cleanup: ' + $_.Exception.Message)) }
    }
    if ($null -ne $untrustedCA) {
        try { $untrustedCA.Certificate.Dispose() }
        catch { $cleanupFailures.Add(('untrusted CA certificate cleanup: ' + $_.Exception.Message)) }
        try { $untrustedCA.PrivateKey.Dispose() }
        catch { $cleanupFailures.Add(('untrusted CA key cleanup: ' + $_.Exception.Message)) }
    }
    foreach ($keyFile in @($primaryKeyFile, $untrustedKeyFile)) {
        if ([string]::IsNullOrWhiteSpace($keyFile)) { continue }
        for ($attempt = 0; $attempt -lt 30 -and (Test-Path -LiteralPath $keyFile); $attempt++) {
            [System.Threading.Thread]::Sleep(100)
        }
        if (Test-Path -LiteralPath $keyFile) {
            $cleanupFailures.Add(('temporary current-user leaf key remains after cache disposal: ' + $keyFile))
        }
    }
    if ($null -ne $primaryLeaf) {
        try {
            if (-not (Test-MihariTestThumbprintAbsent -Thumbprint $primaryLeaf.Thumbprint)) {
                $cleanupFailures.Add('primary exact-host leaf remains in a certificate store')
            }
        }
        catch { $cleanupFailures.Add(('primary leaf store verification: ' + $_.Exception.Message)) }
    }
    if ($null -ne $untrustedLeaf) {
        try {
            if (-not (Test-MihariTestThumbprintAbsent -Thumbprint $untrustedLeaf.Thumbprint)) {
                $cleanupFailures.Add('untrusted exact-host leaf remains in a certificate store')
            }
        }
        catch { $cleanupFailures.Add(('untrusted leaf store verification: ' + $_.Exception.Message)) }
    }
    if ($null -ne $primaryCA) {
        try {
            if (-not (Test-ProbeRootAbsent -Thumbprint $primaryCA.Thumbprint)) {
                $cleanupFailures.Add('primary session root remains in CurrentUser Root')
            }
        }
        catch { $cleanupFailures.Add(('primary root store verification: ' + $_.Exception.Message)) }
    }
    if ($null -ne $untrustedCA) {
        try {
            if (-not (Test-ProbeRootAbsent -Thumbprint $untrustedCA.Thumbprint)) {
                $cleanupFailures.Add('untrusted fixture root unexpectedly exists in CurrentUser Root')
            }
        }
        catch { $cleanupFailures.Add(('untrusted root store verification: ' + $_.Exception.Message)) }
    }
    if ($cleanupFailures.Count -gt 0) {
        $result['cleanup'] = [ordered]@{ status = 'failed'; errors = @($cleanupFailures.ToArray()) }
        $result['status'] = 'failed'
    }
    else {
        $result['cleanup'] = [ordered]@{
            status = 'passed'
            sessionRootRemoved = ($null -ne $primaryCA)
            perHostLeavesAbsentFromStores = $true
            temporaryLeafKeyFilesRemoved = (($null -ne $primaryKeyFile) -and ($null -ne $untrustedKeyFile))
        }
    }
}

Write-Output ($result | ConvertTo-Json -Depth 8)
if ($failure -or $cleanupFailures.Count -gt 0) { exit 1 }
exit 0
