param(
    [ValidateSet('Parent', 'Client')][string] $Role = 'Parent',
    [int] $Port,
    [string] $ExpectedThumbprint
)

$ErrorActionPreference = 'Stop'

if ($env:OS -ne 'Windows_NT') { throw 'The in-memory TLS leaf proof requires Windows.' }

if ($Role -eq 'Client') {
    # Test only: accept the exact certificate presented by this loopback fixture.
    # This does not test Windows root trust or Mihari's production TLS validation.
    $client = $null
    $tls = $null
    try {
        if ($ExpectedThumbprint -notmatch '^[0-9a-fA-F]{40}$') { throw 'Invalid expected leaf thumbprint.' }
        $client = New-Object System.Net.Sockets.TcpClient
        $client.ReceiveTimeout = 5000
        $client.SendTimeout = 5000
        $connect = $client.ConnectAsync('127.0.0.1', $Port)
        if (-not $connect.Wait(5000)) { throw 'Loopback TLS client connect timed out.' }
        $validateFixtureCertificate = [System.Net.Security.RemoteCertificateValidationCallback] {
            param($sender, $certificate, $chain, $policyErrors)
            return ($null -ne $certificate -and $certificate.GetCertHashString() -ieq $ExpectedThumbprint)
        }
        $tls = [System.Net.Security.SslStream]::new($client.GetStream(), $false, $validateFixtureCertificate)
        $tls.ReadTimeout = 5000
        $tls.WriteTimeout = 5000
        $tls.AuthenticateAsClient('localhost', $null, [System.Security.Authentication.SslProtocols]::Tls12, $false)
        if ($tls.SslProtocol -ne [System.Security.Authentication.SslProtocols]::Tls12) {
            throw 'The loopback client did not negotiate TLS 1.2.'
        }
        $buffer = New-Object 'byte[]' 2
        $read = $tls.Read($buffer, 0, $buffer.Length)
        if ($read -ne 2 -or [System.Text.Encoding]::ASCII.GetString($buffer, 0, $read) -ne 'ok') {
            throw 'The TLS proof response was missing.'
        }
        Write-Host '[leaf-proof] client completed TLS 1.2 using test-only exact-thumbprint validation; OS trust untested.'
    }
    finally {
        if ($null -ne $tls) { $tls.Dispose() }
        if ($null -ne $client) { $client.Close() }
    }
    exit 0
}

. (Join-Path $PSScriptRoot 'TestSupport.ps1')
. (Join-Path (Split-Path $PSScriptRoot -Parent) 'src/Certificate.ps1')
$ca = $null
$cache = New-Object 'System.Collections.Hashtable'
$session = [pscustomobject]@{ CA = $null; LeafCache = $cache }
$leaf = $null
$leafThumbprint = $null
$listener = $null
$serverClient = $null
$serverTls = $null
$clientProcess = $null
$cleanupFailures = New-Object 'System.Collections.Generic.List[string]'

try {
    Write-Host '[leaf-proof] creating unique in-memory CA; no root installation will be attempted.'
    $ca = New-MihariCA -SessionId ([guid]::NewGuid().ToString('N'))
    $session.CA = $ca
    $leaf = Get-MihariLeaf -Session $session -DestinationHost 'localhost'
    $leafThumbprint = $leaf.Thumbprint
    Assert-MihariTest -Condition $leaf.HasPrivateKey -Message 'The exact-host leaf needs a private key in memory.'
    Assert-MihariTest -Condition $cache['localhost'].PrivateKey.Key.IsEphemeral -Message 'The exact-host RSA key must be ephemeral.'
    Assert-MihariTest -Condition (Test-MihariTestThumbprintAbsent -Thumbprint $leafThumbprint) -Message 'The leaf must not be in a certificate store.'
    Assert-MihariTest -Condition (Test-MihariTestThumbprintAbsent -Thumbprint $ca.Thumbprint) -Message 'The CA must not be in a certificate store for this isolated proof.'

    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $listener.Start()
    $port = ([System.Net.IPEndPoint] $listener.LocalEndpoint).Port
    $executable = Join-Path $PSHOME 'powershell.exe'
    if ($PSVersionTable.PSEdition -eq 'Core') { $executable = Join-Path $PSHOME 'pwsh.exe' }
    $info = New-Object System.Diagnostics.ProcessStartInfo
    $info.FileName = $executable
    $info.Arguments = '-NoProfile -NonInteractive -File "{0}" -Role Client -Port {1} -ExpectedThumbprint {2}' -f $PSCommandPath, $port, $leafThumbprint
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $clientProcess = New-Object System.Diagnostics.Process
    $clientProcess.StartInfo = $info
    if (-not $clientProcess.Start()) { throw 'Could not start bounded loopback TLS client.' }

    $accept = $listener.AcceptTcpClientAsync()
    if (-not $accept.Wait(5000)) { throw 'Loopback TLS server accept timed out.' }
    $serverClient = $accept.Result
    $serverClient.ReceiveTimeout = 5000
    $serverClient.SendTimeout = 5000
    $serverTls = [System.Net.Security.SslStream]::new($serverClient.GetStream(), $false)
    $serverTls.ReadTimeout = 5000
    $serverTls.WriteTimeout = 5000
    Write-Host '[leaf-proof] beginning SslStream TLS 1.2 server authentication with ephemeral leaf.'
    $authentication = $serverTls.BeginAuthenticateAsServer(
        $leaf, $false, [System.Security.Authentication.SslProtocols]::Tls12, $false, $null, $null
    )
    if (-not $authentication.AsyncWaitHandle.WaitOne(10000)) {
        throw 'SslStream TLS 1.2 server authentication timed out.'
    }
    $serverTls.EndAuthenticateAsServer($authentication)
    Assert-MihariTest -Condition ($serverTls.SslProtocol -eq [System.Security.Authentication.SslProtocols]::Tls12) -Message 'SslStream server did not negotiate TLS 1.2.'
    $reply = [System.Text.Encoding]::ASCII.GetBytes('ok')
    $serverTls.Write($reply, 0, $reply.Length)
    if (-not $clientProcess.WaitForExit(5000)) { throw 'Loopback TLS client did not finish.' }
    $clientOutput = $clientProcess.StandardOutput.ReadToEnd().Trim()
    $clientError = $clientProcess.StandardError.ReadToEnd().Trim()
    if ($clientOutput) { Write-Host $clientOutput }
    if ($clientProcess.ExitCode -ne 0) {
        throw "Loopback TLS client failed with exit code $($clientProcess.ExitCode): $clientError"
    }
    Assert-MihariTest -Condition (Test-MihariTestThumbprintAbsent -Thumbprint $leafThumbprint) -Message 'TLS authentication installed the leaf in a certificate store.'
    Assert-MihariTest -Condition (Test-MihariTestThumbprintAbsent -Thumbprint $ca.Thumbprint) -Message 'TLS authentication installed the CA in a certificate store.'
    Write-Host 'PASS leaf-proof: exact-host ephemeral leaf completed SslStream TLS 1.2 without root installation.'
}
finally {
    if ($null -ne $clientProcess) {
        try {
            if (-not $clientProcess.HasExited) {
                $clientProcess.Kill()
                [void] $clientProcess.WaitForExit(3000)
            }
            $clientOutput = $clientProcess.StandardOutput.ReadToEnd().Trim()
            $clientError = $clientProcess.StandardError.ReadToEnd().Trim()
            if ($clientOutput) { Write-Host $clientOutput }
            if ($clientError) { Write-Host "[leaf-proof] client error: $clientError" }
        }
        catch { $cleanupFailures.Add("client process cleanup: $($_.Exception.Message)") }
        finally { $clientProcess.Dispose() }
    }
    if ($null -ne $serverTls) { try { $serverTls.Dispose() } catch { $cleanupFailures.Add("server TLS cleanup: $($_.Exception.Message)") } }
    if ($null -ne $serverClient) { try { $serverClient.Close() } catch { $cleanupFailures.Add("server socket cleanup: $($_.Exception.Message)") } }
    if ($null -ne $listener) { try { $listener.Stop() } catch { $cleanupFailures.Add("listener cleanup: $($_.Exception.Message)") } }
    if ($null -ne $leaf) {
        try { Release-MihariLeaf -Session $session -Certificate $leaf }
        catch { $cleanupFailures.Add("leaf lease cleanup: $($_.Exception.Message)") }
    }
    try { Clear-MihariLeafCache -Session $session }
    catch { $cleanupFailures.Add("leaf cache cleanup: $($_.Exception.Message)") }
    if ($null -ne $ca) {
        try { $ca.Certificate.Dispose() } catch { $cleanupFailures.Add("CA certificate cleanup: $($_.Exception.Message)") }
        try { $ca.PrivateKey.Dispose() } catch { $cleanupFailures.Add("CA key cleanup: $($_.Exception.Message)") }
    }
    if ($null -ne $leafThumbprint) {
        try {
            if (-not (Test-MihariTestThumbprintAbsent -Thumbprint $leafThumbprint)) {
                $cleanupFailures.Add('The exact-host leaf remains in a certificate store.')
            }
        }
        catch { $cleanupFailures.Add("leaf store verification: $($_.Exception.Message)") }
    }
    if ($cleanupFailures.Count -gt 0) { throw ('Leaf proof cleanup failed: ' + ($cleanupFailures -join '; ')) }
}
