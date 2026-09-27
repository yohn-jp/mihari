param()

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'TestSupport.ps1')
. (Join-Path (Split-Path $PSScriptRoot -Parent) 'src/Certificate.ps1')
. (Join-Path (Split-Path $PSScriptRoot -Parent) 'src/Compatibility.ps1')

$capability = Test-MihariCapability -Mode Inspect
Assert-MihariTest -Condition $capability.Available -Message ("Inspect certificate APIs unavailable: {0}" -f $capability.Reason)

$sessionId = [guid]::NewGuid().ToString('N')
$ca = $null
$publicRoot = $null
$leaf = $null
$listener = $null
$client = $null
$serverClient = $null
$clientTls = $null
$serverTls = $null
$installed = $false
$cache = $null
$leafLeases = New-Object 'System.Collections.Generic.List[System.Security.Cryptography.X509Certificates.X509Certificate2]'
$cleanupFailures = New-Object 'System.Collections.Generic.List[string]'

try {
    $ca = New-MihariCA -SessionId $sessionId
    Assert-MihariTest -Condition ($ca.Certificate.HasPrivateKey) -Message 'Session CA certificate must hold its private key in memory.'
    Assert-MihariTest -Condition ($ca.PrivateKey.Key.IsEphemeral) -Message 'Session CA RSA key must be ephemeral.'
    Assert-MihariTest -Condition ($ca.Subject -match [regex]::Escape($sessionId)) -Message 'Session CA subject must carry its unique session marker.'

    $publicRoot = Install-MihariCARoot -CA $ca
    $installed = $true
    Assert-MihariTest -Condition (-not $publicRoot.HasPrivateKey) -Message 'Only the public session CA may be installed in CurrentUser Root.'

    $cache = New-Object 'System.Collections.Hashtable'
    $session = [pscustomobject]@{ CA = $ca; LeafCache = $cache }
    $leaf = Get-MihariLeaf -Session $session -DestinationHost 'localhost'
    $leafLeases.Add($leaf)
    Assert-MihariTest -Condition ($leaf.HasPrivateKey) -Message 'The exact-host leaf must have an in-memory private key.'
    Assert-MihariTest -Condition (Test-MihariTestThumbprintAbsent -Thumbprint $leaf.Thumbprint) -Message 'An exact-host leaf must not be installed in any certificate store.'

    $sanExtension = $null
    foreach ($extension in $leaf.Extensions) {
        if ($extension.Oid.Value -eq '2.5.29.17') {
            $sanExtension = $extension
            break
        }
    }
    Assert-MihariTest -Condition ($null -ne $sanExtension) -Message 'Leaf certificate must contain a subject alternative name.'
    Assert-MihariTest -Condition ($sanExtension.Format($false) -match 'localhost') -Message 'Leaf SAN must match the exact requested host.'

    $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0)
    $listener.Start()
    $port = ([System.Net.IPEndPoint] $listener.LocalEndpoint).Port
    $acceptTask = $listener.AcceptTcpClientAsync()
    $client = New-Object System.Net.Sockets.TcpClient
    $client.Connect('127.0.0.1', $port)
    Assert-MihariTest -Condition ($acceptTask.Wait(10000)) -Message 'The local TLS proof server did not accept the client.'
    $serverClient = $acceptTask.Result

    $serverTls = [System.Net.Security.SslStream]::new($serverClient.GetStream(), $false)
    $clientTls = [System.Net.Security.SslStream]::new($client.GetStream(), $false)
    $serverAuth = $serverTls.BeginAuthenticateAsServer(
        $leaf,
        $false,
        [System.Security.Authentication.SslProtocols]::Tls12,
        $false,
        $null,
        $null
    )
    $clientTls.AuthenticateAsClient(
        'localhost',
        $null,
        [System.Security.Authentication.SslProtocols]::Tls12,
        $false
    )
    $serverTls.EndAuthenticateAsServer($serverAuth)
    Assert-MihariTest -Condition ($clientTls.SslProtocol -eq [System.Security.Authentication.SslProtocols]::Tls12) -Message 'The in-memory leaf must complete TLS 1.2 server authentication.'
    $reply = [System.Text.Encoding]::ASCII.GetBytes('ok')
    $serverTls.Write($reply, 0, $reply.Length)
    $readBuffer = New-Object 'byte[]' 2
    $readCount = $clientTls.Read($readBuffer, 0, $readBuffer.Length)
    Assert-MihariTest -Condition ($readCount -eq 2 -and [System.Text.Encoding]::ASCII.GetString($readBuffer, 0, $readCount) -eq 'ok') -Message 'TLS proof server response did not arrive.'

    $sameLeaf = Get-MihariLeaf -Session $session -DestinationHost 'LOCALHOST.'
    $leafLeases.Add($sameLeaf)
    Assert-MihariTest -Condition ($sameLeaf.Thumbprint -eq $leaf.Thumbprint) -Message 'Normalized equivalent hosts must reuse the session leaf cache.'
    Assert-MihariTest -Condition ((Test-MihariTestStoreCertificates -StoreName ([System.Security.Cryptography.X509Certificates.StoreName]::Root) -StoreLocation ([System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser) | Where-Object { $_.Thumbprint -eq $ca.Thumbprint }).Count -eq 1) -Message 'The public CA root must be installed once in CurrentUser Root.'
    Write-Host 'PASS certificate: ephemeral CA, public trust, exact-host in-memory leaf, TLS 1.2, bounded-cache lookup, no leaf-store residue'
}
finally {
    if ($null -ne $clientTls) { try { $clientTls.Dispose() } catch { $cleanupFailures.Add("client TLS disposal: $($_.Exception.Message)") } }
    if ($null -ne $serverTls) { try { $serverTls.Dispose() } catch { $cleanupFailures.Add("server TLS disposal: $($_.Exception.Message)") } }
    if ($null -ne $client) { try { $client.Close() } catch { $cleanupFailures.Add("client socket disposal: $($_.Exception.Message)") } }
    if ($null -ne $serverClient) { try { $serverClient.Close() } catch { $cleanupFailures.Add("server socket disposal: $($_.Exception.Message)") } }
    if ($null -ne $listener) { try { $listener.Stop() } catch { $cleanupFailures.Add("listener disposal: $($_.Exception.Message)") } }
    if ($null -ne $cache) {
        $session = [pscustomobject]@{ LeafCache = $cache }
        foreach ($leasedLeaf in $leafLeases) {
            try { Release-MihariLeaf -Session $session -Certificate $leasedLeaf }
            catch { $cleanupFailures.Add("leaf lease release: $($_.Exception.Message)") }
        }
        try { Clear-MihariLeafCache -Session $session }
        catch { $cleanupFailures.Add("leaf-cache disposal: $($_.Exception.Message)") }
    }
    if ($installed -and $null -ne $ca) {
        try {
            $removed = Remove-MihariCARoot -Thumbprint $ca.Thumbprint -Subject $ca.Subject
            if ($removed -ne 1) { $cleanupFailures.Add('Normal certificate cleanup did not remove exactly one trusted session CA.') }
            $installed = $false
        }
        catch { $cleanupFailures.Add("CA root removal: $($_.Exception.Message)") }
    }
    if ($null -ne $publicRoot) { try { $publicRoot.Dispose() } catch { $cleanupFailures.Add("public root disposal: $($_.Exception.Message)") } }
    if ($null -ne $ca) {
        try { $ca.Certificate.Dispose() } catch { $cleanupFailures.Add("CA certificate disposal: $($_.Exception.Message)") }
        try { $ca.PrivateKey.Dispose() } catch { $cleanupFailures.Add("CA private key disposal: $($_.Exception.Message)") }
    }
    if ($null -ne $ca) {
        try {
            $remainingRoots = @(Test-MihariTestStoreCertificates -StoreName ([System.Security.Cryptography.X509Certificates.StoreName]::Root) -StoreLocation ([System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser) | Where-Object { $_.Thumbprint -eq $ca.Thumbprint })
            if ($remainingRoots.Count -ne 0) { $cleanupFailures.Add('Session CA remains in CurrentUser Root after cleanup.') }
        }
        catch { $cleanupFailures.Add("CA store verification: $($_.Exception.Message)") }
    }
    if ($null -ne $leaf) {
        try {
            if (-not (Test-MihariTestThumbprintAbsent -Thumbprint $leaf.Thumbprint)) { $cleanupFailures.Add('A per-host leaf remains installed after cleanup.') }
        }
        catch { $cleanupFailures.Add("leaf store verification: $($_.Exception.Message)") }
    }
    if ($cleanupFailures.Count -gt 0) {
        throw ('Certificate test cleanup failed: ' + ($cleanupFailures -join '; '))
    }
}
