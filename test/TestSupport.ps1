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
    $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0)
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
    foreach ($location in @(
        [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser,
        [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine
    )) {
        foreach ($name in @(
            [System.Security.Cryptography.X509Certificates.StoreName]::My,
            [System.Security.Cryptography.X509Certificates.StoreName]::Root
        )) {
            foreach ($certificate in (Get-MihariTestStoreCertificates -StoreName $name -StoreLocation $location)) {
                if ($certificate.Thumbprint -ieq $Thumbprint) {
                    return $false
                }
            }
        }
    }
    return $true
}
