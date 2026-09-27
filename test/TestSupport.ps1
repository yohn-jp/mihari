function Assert-MihariTest {
    param(
        [Parameter(Mandatory = $true)][bool] $Condition,
        [Parameter(Mandatory = $true)][string] $Message
    )
    if (-not $Condition) {
        throw "ASSERTION FAILED: $Message"
    }
}

function Start-MihariTestRootConfirmation {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('Add', 'Remove')][string] $Operation,
        [Parameter(Mandatory = $true)][int] $TargetProcessId
    )
    if ($env:OS -ne 'Windows_NT') { throw 'Root confirmation tests require Windows.' }
    $executable = Join-Path $PSHOME 'powershell.exe'
    if ($PSVersionTable.PSEdition -eq 'Core') { $executable = Join-Path $PSHOME 'pwsh.exe' }
    $scriptPath = Join-Path $PSScriptRoot 'CertPromptOperator.ps1'
    $info = New-Object System.Diagnostics.ProcessStartInfo
    $info.FileName = $executable
    $info.Arguments = '-NoProfile -NonInteractive -File "{0}" -Operation {1} -TargetProcessId {2}' -f
        $scriptPath.Replace('"', '""'), $Operation, $TargetProcessId
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $info
    if (-not $process.Start()) { throw 'Could not start the test certificate prompt operator.' }
    return [pscustomobject]@{
        Process = $process
        Stdout = $process.StandardOutput.ReadToEndAsync()
        Stderr = $process.StandardError.ReadToEndAsync()
        Operation = $Operation
    }
}

function Complete-MihariTestRootConfirmation {
    param([Parameter(Mandatory = $true)] $Operator)
    $process = $Operator.Process
    if (-not $process.WaitForExit(20000)) {
        throw "The $($Operator.Operation) certificate prompt operator timed out."
    }
    $process.WaitForExit()
    if ($process.ExitCode -ne 0) {
        throw ("The {0} certificate prompt operator failed ({1}). stdout={2} stderr={3}" -f
            $Operator.Operation, $process.ExitCode, $Operator.Stdout.Result, $Operator.Stderr.Result)
    }
    Write-Host $Operator.Stdout.Result.Trim()
}

function Stop-MihariTestRootConfirmation {
    param($Operator)
    if ($null -eq $Operator) { return }
    $process = $Operator.Process
    try {
        if (-not $process.HasExited) {
            try { $process.Kill() }
            catch [System.InvalidOperationException] {
                Write-Host '[test] certificate prompt operator exited before termination'
            }
            [void] $process.WaitForExit(3000)
        }
    }
    finally { $process.Dispose() }
}

function Invoke-MihariTestRootConfirmation {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('Add', 'Remove')][string] $Operation,
        [Parameter(Mandatory = $true)][scriptblock] $Action
    )
    $operator = Start-MihariTestRootConfirmation -Operation $Operation -TargetProcessId $PID
    try {
        $result = & $Action
        Complete-MihariTestRootConfirmation -Operator $operator
        return $result
    }
    finally { Stop-MihariTestRootConfirmation -Operator $operator }
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
