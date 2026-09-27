# Keys are explicitly ephemeral CNG keys. No PFX or private key is exported.
function New-MihariEphemeralRsa {
    [CmdletBinding()]
    param([int] $KeySize = 2048)

    # RSACng generates its own unnamed key. Calling CngKey.Create with a
    # PowerShell $null string argument can bind as an empty (persistent) name.
    $rsa = [System.Security.Cryptography.RSACng]::new($KeySize)
    try {
        $key = $rsa.Key
        if (-not $key.IsEphemeral) {
            throw 'CNG returned a persistent RSA key; Inspect cannot start.'
        }
        if ($rsa.KeySize -ne $KeySize) {
            throw 'CNG returned an RSA key with an unexpected size.'
        }
        return $rsa
    }
    catch {
        $rsa.Dispose()
        throw
    }
}

function New-MihariCA {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string] $SessionId)

    $parsedId = [guid]::Empty
    if (-not [guid]::TryParse($SessionId, [ref] $parsedId)) {
        throw 'The Mihari session ID must be a GUID.'
    }
    $canonicalId = $parsedId.ToString('N')
    $subject = "CN=Mihari Ephemeral Diagnostic CA $canonicalId"
    $rsa = $null
    $certificate = $null
    try {
        $rsa = New-MihariEphemeralRsa
        $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
            $subject,
            $rsa,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
        )
        $request.CertificateExtensions.Add(
            [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($true, $false, 0, $true)
        )
        $caUsage = [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyCertSign -bor
            [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::CrlSign
        $request.CertificateExtensions.Add(
            [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new($caUsage, $true)
        )
        $request.CertificateExtensions.Add(
            [System.Security.Cryptography.X509Certificates.X509SubjectKeyIdentifierExtension]::new($request.PublicKey, $false)
        )
        $now = [DateTimeOffset]::UtcNow
        $certificate = $request.CreateSelfSigned($now.AddMinutes(-5), $now.AddHours(12))
        if (-not $certificate.HasPrivateKey) {
            throw 'The session CA was created without an in-memory private key.'
        }
        [pscustomobject]@{
            Certificate = $certificate
            PrivateKey = $rsa
            Thumbprint = $certificate.Thumbprint
            Subject = $certificate.Subject
        }
    }
    catch {
        if ($null -ne $certificate) { $certificate.Dispose() }
        if ($null -ne $rsa) { $rsa.Dispose() }
        throw "Could not create an in-memory Mihari CA: $($_.Exception.Message)"
    }
}

function Install-MihariCARoot {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)] $CA)

    if (-not (Test-MihariCAOwnership -Certificate $CA.Certificate -Thumbprint $CA.Thumbprint)) {
        throw 'Refusing to install a certificate without Mihari CA ownership markers.'
    }
    $public = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
        $CA.Certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
    )
    try {
        if ($public.HasPrivateKey) {
            throw 'Refusing to install a CA certificate with a private key.'
        }
        $store = [System.Security.Cryptography.X509Certificates.X509Store]::new(
            [System.Security.Cryptography.X509Certificates.StoreName]::Root,
            [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
        )
        try {
            $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
            $store.Add($public)
        }
        finally {
            $store.Close()
        }
        return $public
    }
    catch {
        $public.Dispose()
        throw "Could not trust the public Mihari CA in CurrentUser Root: $($_.Exception.Message)"
    }
}

function Test-MihariCAOwnership {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate,
        [string] $Thumbprint
    )

    if ($Certificate.Subject -cnotmatch '^CN=Mihari Ephemeral Diagnostic CA [0-9a-f]{32}$') { return $false }
    if ($Certificate.Subject -cne $Certificate.Issuer) { return $false }
    if ($Thumbprint -and $Certificate.Thumbprint -ine $Thumbprint) { return $false }
    $isCA = $false
    foreach ($extension in $Certificate.Extensions) {
        if ($extension -is [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]) {
            $isCA = $extension.CertificateAuthority
            break
        }
    }
    return $isCA
}

function Remove-MihariCARoot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string] $Thumbprint,
        [Parameter(Mandatory = $true)][string] $Subject
    )

    if ($Subject -cnotmatch '^CN=Mihari Ephemeral Diagnostic CA [0-9a-f]{32}$' -or
        $Thumbprint -notmatch '^[0-9a-fA-F]{40}$') {
        throw 'Refusing to remove a root without exact Mihari CA identity.'
    }
    $store = [System.Security.Cryptography.X509Certificates.X509Store]::new(
        [System.Security.Cryptography.X509Certificates.StoreName]::Root,
        [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
    )
    $removed = 0
    try {
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        $matches = $store.Certificates.Find(
            [System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint,
            $Thumbprint,
            $false
        )
        foreach ($certificate in $matches) {
            if ($certificate.Subject -cne $Subject) { continue }
            if (-not (Test-MihariCAOwnership -Certificate $certificate -Thumbprint $Thumbprint)) { continue }
            $store.Remove($certificate)
            $removed++
        }
    }
    finally {
        $store.Close()
    }
    return $removed
}

function ConvertTo-MihariCertificateHost {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string] $DestinationHost)

    $name = $DestinationHost.Trim()
    if ($name.StartsWith('[') -and $name.EndsWith(']')) {
        $name = $name.Substring(1, $name.Length - 2)
    }
    $address = $null
    if ([System.Net.IPAddress]::TryParse($name, [ref] $address)) {
        return [pscustomobject]@{ Name = $address.ToString().ToLowerInvariant(); Address = $address }
    }
    if ($name.EndsWith('.')) { $name = $name.TrimEnd('.') }
    try {
        $name = ([System.Globalization.IdnMapping]::new()).GetAscii($name).ToLowerInvariant()
    }
    catch {
        throw "Invalid CONNECT host name: $($_.Exception.Message)"
    }
    if ($name.Length -lt 1 -or $name.Length -gt 253 -or
        [System.Uri]::CheckHostName($name) -ne [System.UriHostNameType]::Dns) {
        throw 'Invalid CONNECT DNS host name.'
    }
    return [pscustomobject]@{ Name = $name; Address = $null }
}

function New-MihariLeafCertificate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] $CA,
        [Parameter(Mandatory = $true)] $NormalizedHost
    )

    $rsa = $null
    $issued = $null
    $certificate = $null
    try {
        $rsa = New-MihariEphemeralRsa
        $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
            "CN=$($NormalizedHost.Name)",
            $rsa,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
        )
        $request.CertificateExtensions.Add(
            [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($false, $false, 0, $true)
        )
        $leafUsage = [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature -bor
            [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyEncipherment
        $request.CertificateExtensions.Add(
            [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new($leafUsage, $true)
        )
        $serverAuth = [System.Security.Cryptography.OidCollection]::new()
        [void] $serverAuth.Add([System.Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.1'))
        $request.CertificateExtensions.Add(
            [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($serverAuth, $false)
        )
        $san = [System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
        if ($null -ne $NormalizedHost.Address) {
            $san.AddIpAddress($NormalizedHost.Address)
        }
        else {
            $san.AddDnsName($NormalizedHost.Name)
        }
        $request.CertificateExtensions.Add($san.Build($false))
        $serial = New-Object 'byte[]' 16
        $random = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        try { $random.GetBytes($serial) }
        finally { $random.Dispose() }
        $serial[0] = [byte] (($serial[0] -band 0x7f) -bor 1)
        $now = [DateTimeOffset]::UtcNow
        $issued = $request.Create($CA.Certificate, $now.AddMinutes(-1), $now.AddHours(6), $serial)
        $certificate = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::CopyWithPrivateKey($issued, $rsa)
        if (-not $certificate.HasPrivateKey) {
            throw 'The exact-host leaf lacks an in-memory private key.'
        }
        return [pscustomobject]@{
            Certificate = $certificate
            PrivateKey = $rsa
            LastUsedUtc = $now.UtcDateTime
            InUse = 0
        }
    }
    catch {
        if ($null -ne $certificate) { $certificate.Dispose() }
        if ($null -ne $rsa) { $rsa.Dispose() }
        throw "Could not issue an in-memory leaf for $($NormalizedHost.Name): $($_.Exception.Message)"
    }
    finally {
        if ($null -ne $issued) { $issued.Dispose() }
    }
}

function Get-MihariLeaf {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] $Session,
        [Parameter(Mandatory = $true)][Alias('Host')][string] $DestinationHost
    )

    $normalized = ConvertTo-MihariCertificateHost -DestinationHost $DestinationHost
    $cache = $Session.LeafCache
    if ($null -eq $cache) { throw 'Inspect session has no leaf cache.' }
    [System.Threading.Monitor]::Enter($cache.SyncRoot)
    try {
        if ($cache.ContainsKey($normalized.Name)) {
            $item = $cache[$normalized.Name]
            $item.LastUsedUtc = [DateTime]::UtcNow
            $item.InUse++
            return $item.Certificate
        }
        if ($cache.Count -ge 64) {
            $oldestKey = $null
            $oldestTime = [DateTime]::MaxValue
            foreach ($entry in $cache.GetEnumerator()) {
                if ($entry.Value.InUse -eq 0 -and $entry.Value.LastUsedUtc -lt $oldestTime) {
                    $oldestKey = $entry.Key
                    $oldestTime = $entry.Value.LastUsedUtc
                }
            }
            if ($null -eq $oldestKey) {
                throw 'The in-memory leaf cache is full with active TLS handshakes.'
            }
            $oldest = $cache[$oldestKey]
            $cache.Remove($oldestKey)
            $oldest.Certificate.Dispose()
            $oldest.PrivateKey.Dispose()
        }
        $item = New-MihariLeafCertificate -CA $Session.CA -NormalizedHost $normalized
        $item.InUse = 1
        $cache[$normalized.Name] = $item
        return $item.Certificate
    }
    finally {
        [System.Threading.Monitor]::Exit($cache.SyncRoot)
    }
}

function Release-MihariLeaf {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] $Session,
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate
    )

    $cache = $Session.LeafCache
    [System.Threading.Monitor]::Enter($cache.SyncRoot)
    try {
        foreach ($item in $cache.Values) {
            if ([object]::ReferenceEquals($item.Certificate, $Certificate)) {
                if ($item.InUse -le 0) { throw 'Mihari leaf lease was released more than once.' }
                $item.InUse--
                return
            }
        }
        throw 'Mihari leaf lease was not found in the active cache.'
    }
    finally {
        [System.Threading.Monitor]::Exit($cache.SyncRoot)
    }
}

function Clear-MihariLeafCache {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)] $Session)

    $cache = $Session.LeafCache
    if ($null -eq $cache) { return }
    [System.Threading.Monitor]::Enter($cache.SyncRoot)
    try {
        foreach ($item in $cache.Values) {
            if ($item.InUse -ne 0) {
                throw 'Cannot clear Mihari leaf cache while TLS handshakes are active.'
            }
        }
        foreach ($item in $cache.Values) {
            $item.Certificate.Dispose()
            $item.PrivateKey.Dispose()
        }
        $cache.Clear()
    }
    finally {
        [System.Threading.Monitor]::Exit($cache.SyncRoot)
    }
}
