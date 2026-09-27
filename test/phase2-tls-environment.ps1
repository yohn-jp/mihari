param()

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'TestSupport.ps1')
. (Join-Path (Split-Path $PSScriptRoot -Parent) 'src/Certificate.ps1')
. (Join-Path (Split-Path $PSScriptRoot -Parent) 'src/Upstream.ps1')
. (Join-Path (Split-Path $PSScriptRoot -Parent) 'src/Environment.ps1')
. (Join-Path (Split-Path $PSScriptRoot -Parent) 'src/Tls.ps1')

$unobserved = Get-MihariTlsValidationFacts -Capture (New-MihariTlsValidationCapture)
Assert-MihariTest -Condition (-not $unobserved.ContainsKey('certificateAccepted')) -Message 'A handshake without a validation callback must not be called a certificate rejection.'
Assert-MihariTest -Condition ($unobserved.certificateChainState -eq 'unknown') -Message 'Unobserved chain state must stay unknown.'
Assert-MihariTest -Condition ($unobserved.revocationState -eq 'not_performed') -Message 'Disabled revocation probing must be explicit.'

$capture = New-MihariTlsValidationCapture
$callback = New-MihariTlsValidationCallback -Capture $capture
$accepted = $callback.Invoke($null, $null, $null, [System.Net.Security.SslPolicyErrors]::RemoteCertificateNameMismatch)
Assert-MihariTest -Condition (-not $accepted) -Message 'A name mismatch must be rejected by the evidence callback.'
$failed = Get-MihariTlsValidationFacts -Capture $capture
Assert-MihariTest -Condition ($failed.certificateAccepted -eq $false) -Message 'Callback rejection must be recorded.'
Assert-MihariTest -Condition ($failed.certificateChainState -eq 'not_performed') -Message 'Missing peer certificate must not become a chain failure.'

Assert-MihariTest -Condition (Test-MihariLocalInspectExclusion -HostName 'Example.COM.' -ExcludedHosts @('example.com')) -Message 'Exact DNS exclusion must normalize case and trailing dot.'
Assert-MihariTest -Condition (-not (Test-MihariLocalInspectExclusion -HostName 'child.example.com' -ExcludedHosts @('example.com'))) -Message 'Exact-host exclusion must not match subdomains.'
Assert-MihariTest -Condition (-not (Test-MihariLocalInspectExclusion -HostName 'example.com' -ExcludedHosts @('*.example.com'))) -Message 'Wildcard entries must not broaden local exclusions.'

$oldProxy = [Environment]::GetEnvironmentVariable('HTTP_PROXY')
try {
    [Environment]::SetEnvironmentVariable('HTTP_PROXY', 'http://user:secret@example.invalid/path-token?token=secret')
    $snapshot = Get-MihariEnvironmentSnapshot
    $json = ConvertTo-Json -InputObject $snapshot -Depth 12 -Compress
    Assert-MihariTest -Condition ($json -notmatch 'secret|path-token|user:') -Message 'Environment snapshot must not retain proxy credentials or URL tokens.'
    Assert-MihariTest -Condition ($snapshot.sources.environmentVariables.values.HTTP_PROXY.endpoint -eq 'http://example.invalid') -Message 'Safe endpoint must retain only scheme and authority.'
    Assert-MihariTest -Condition ($snapshot.sources.routes.coverage -eq 'unavailable') -Message 'Unqueried route table must be marked unavailable.'
    Assert-MihariTest -Condition ($snapshot.sources.pacResolution.retrieval -eq 'not_performed') -Message 'A configured PAC URL must not imply successful retrieval.'
}
finally { [Environment]::SetEnvironmentVariable('HTTP_PROXY', $oldProxy) }

$status = Get-MihariCertificateCleanupStatus -Session ([pscustomobject]@{ CA = $null; LeafCache = $null })
Assert-MihariTest -Condition ($status.caTrustCoverage -eq 'not_performed') -Message 'Missing session CA must not be reported as removed.'
Assert-MihariTest -Condition ($status.temporaryLeafKeyFiles -eq 'unavailable') -Message 'Unverified temporary key files must remain unavailable.'

function Invoke-MihariTestValidationHandshake {
    param(
        [Parameter(Mandatory=$true)][System.Security.Cryptography.X509Certificates.X509Certificate2]$ServerCertificate,
        [Parameter(Mandatory=$true)][string]$TargetHost
    )
    $listener = $null
    $client = $null
    $server = $null
    $serverTls = $null
    $clientTls = $null
    $capture = New-MihariTlsValidationCapture
    try {
        $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
        $listener.Start()
        $port = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
        $accept = $listener.AcceptTcpClientAsync()
        $client = [System.Net.Sockets.TcpClient]::new()
        $client.Connect('127.0.0.1', $port)
        Assert-MihariTest -Condition ($accept.Wait(10000)) -Message 'Validation fixture did not accept its local client.'
        $server = $accept.Result
        $serverTls = [System.Net.Security.SslStream]::new($server.GetStream(), $true)
        $clientTls = [System.Net.Security.SslStream]::new($client.GetStream(), $true, (New-MihariTlsValidationCallback -Capture $capture))
        $clientTls.ReadTimeout = 10000
        $clientTls.WriteTimeout = 10000
        $serverTls.ReadTimeout = 10000
        $serverTls.WriteTimeout = 10000
        $serverAuth = $serverTls.BeginAuthenticateAsServer($ServerCertificate, $false, [System.Security.Authentication.SslProtocols]::Tls12, $false, $null, $null)
        $succeeded = $false
        $clientError = $null
        try {
            $clientTls.AuthenticateAsClient($TargetHost, (New-Object System.Security.Cryptography.X509Certificates.X509CertificateCollection), [System.Security.Authentication.SslProtocols]::Tls12, $false)
            $succeeded = $true
        }
        catch { $clientError = $_.Exception.GetType().FullName }
        if ($serverAuth.AsyncWaitHandle.WaitOne(10000)) {
            try { $serverTls.EndAuthenticateAsServer($serverAuth) }
            catch {
                if ($succeeded) { throw }
            }
        }
        elseif ($succeeded) { throw 'Validation fixture server handshake did not complete.' }
        return [pscustomobject]@{ Succeeded = $succeeded; ClientErrorType = $clientError; Capture = $capture; Facts = (Get-MihariTlsValidationFacts -Capture $capture) }
    }
    finally {
        if ($null -ne $clientTls) { $clientTls.Dispose() }
        if ($null -ne $serverTls) { $serverTls.Dispose() }
        if ($null -ne $client) { $client.Dispose() }
        if ($null -ne $server) { $server.Dispose() }
        if ($null -ne $listener) { $listener.Stop() }
    }
}

if ($env:OS -eq 'Windows_NT') {
    . (Join-Path $PSScriptRoot 'integration.ps1') -LoadHelpersOnly
    $trusted = $null
    $untrustedCa = $null
    $untrustedSession = $null
    $untrustedLeaf = $null
    try {
        $trusted = New-MihariTestFixtureTlsIdentity
        $nameMismatch = Invoke-MihariTestValidationHandshake -ServerCertificate $trusted.Leaf -TargetHost 'localhost'
        Assert-MihariTest -Condition (-not $nameMismatch.Succeeded -and $nameMismatch.Capture.Invoked) -Message 'Normal hostname mismatch must reject the TLS peer.'
        Assert-MihariTest -Condition ($nameMismatch.Facts.hostnameState -eq 'failed') -Message 'Name mismatch must be attributed to hostname validation.'
        Assert-MihariTest -Condition ($nameMismatch.Facts.certificateAccepted -eq $false) -Message 'Name mismatch must not be accepted by the callback.'

        $untrustedCa = New-MihariCA -SessionId ([guid]::NewGuid().ToString('N'))
        $untrustedSession = [pscustomobject]@{ CA = $untrustedCa; LeafCache = ([hashtable]::Synchronized(@{})) }
        $untrustedLeaf = Get-MihariLeaf -Session $untrustedSession -DestinationHost '127.0.0.1'
        $trustFailure = Invoke-MihariTestValidationHandshake -ServerCertificate $untrustedLeaf -TargetHost '127.0.0.1'
        Assert-MihariTest -Condition (-not $trustFailure.Succeeded -and $trustFailure.Capture.Invoked) -Message 'Untrusted local CA must reject the TLS peer.'
        Assert-MihariTest -Condition ($trustFailure.Facts.certificateChainState -eq 'failed') -Message 'Untrusted CA must be attributed to chain validation.'
        Assert-MihariTest -Condition ($trustFailure.Facts.certificateAccepted -eq $false) -Message 'Untrusted CA must not be accepted by the callback.'
    }
    finally {
        if ($null -ne $untrustedLeaf) { Release-MihariLeaf -Session $untrustedSession -Certificate $untrustedLeaf }
        if ($null -ne $untrustedSession) { Clear-MihariLeafCache -Session $untrustedSession }
        if ($null -ne $untrustedCa) { $untrustedCa.Certificate.Dispose(); $untrustedCa.PrivateKey.Dispose() }
        if ($null -ne $trusted) { Remove-MihariTestFixtureTlsIdentity -Identity $trusted }
    }
}

Write-Host 'PASS phase2-tls-environment'
