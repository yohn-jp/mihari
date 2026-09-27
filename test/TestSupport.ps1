function Assert-MihariTest {
    param(
        [Parameter(Mandatory = $true)][bool] $Condition,
        [Parameter(Mandatory = $true)][string] $Message
    )
    if (-not $Condition) {
        throw "ASSERTION FAILED: $Message"
    }
}

function Get-MihariTestFreePort {
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    try {
        $listener.Start()
        return ([System.Net.IPEndPoint] $listener.LocalEndpoint).Port
    }
    finally {
        $listener.Stop()
    }
}

function Get-MihariTestStoreCertificates {
    param(
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.StoreName] $StoreName,
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.StoreLocation] $StoreLocation
    )
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($StoreName, $StoreLocation)
    try {
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
        return @($store.Certificates)
    }
    finally {
        $store.Close()
        $store.Dispose()
    }
}

function Test-MihariTestThumbprintAbsent {
    param([Parameter(Mandatory = $true)][string] $Thumbprint)
    $found = $false
    foreach ($location in @(
        [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser,
        [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine
    )) {
        foreach ($name in @(
            [System.Security.Cryptography.X509Certificates.StoreName]::AddressBook,
            [System.Security.Cryptography.X509Certificates.StoreName]::AuthRoot,
            [System.Security.Cryptography.X509Certificates.StoreName]::CertificateAuthority,
            [System.Security.Cryptography.X509Certificates.StoreName]::Disallowed,
            [System.Security.Cryptography.X509Certificates.StoreName]::My,
            [System.Security.Cryptography.X509Certificates.StoreName]::Root,
            [System.Security.Cryptography.X509Certificates.StoreName]::TrustedPeople,
            [System.Security.Cryptography.X509Certificates.StoreName]::TrustedPublisher
        )) {
            $certificates = Get-MihariTestStoreCertificates -StoreName $name -StoreLocation $location
            foreach ($certificate in $certificates) {
                try {
                    if ($certificate.Thumbprint -ieq $Thumbprint) { $found = $true }
                }
                finally { $certificate.Dispose() }
            }
        }
    }
    return (-not $found)
}

function Test-MihariTestNoLeavesForIssuer {
    param([Parameter(Mandatory = $true)][string] $IssuerSubject)
    $found = $false
    foreach ($location in @(
        [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser,
        [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine
    )) {
        foreach ($name in @(
            [System.Security.Cryptography.X509Certificates.StoreName]::AddressBook,
            [System.Security.Cryptography.X509Certificates.StoreName]::AuthRoot,
            [System.Security.Cryptography.X509Certificates.StoreName]::CertificateAuthority,
            [System.Security.Cryptography.X509Certificates.StoreName]::Disallowed,
            [System.Security.Cryptography.X509Certificates.StoreName]::My,
            [System.Security.Cryptography.X509Certificates.StoreName]::Root,
            [System.Security.Cryptography.X509Certificates.StoreName]::TrustedPeople,
            [System.Security.Cryptography.X509Certificates.StoreName]::TrustedPublisher
        )) {
            $certificates = Get-MihariTestStoreCertificates -StoreName $name -StoreLocation $location
            foreach ($certificate in $certificates) {
                try {
                    if ($certificate.Issuer -ceq $IssuerSubject -and $certificate.Subject -cne $IssuerSubject) { $found = $true }
                }
                finally { $certificate.Dispose() }
            }
        }
    }
    return (-not $found)
}
