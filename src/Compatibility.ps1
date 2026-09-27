# Capability detection is deliberately side-effect free. Certificate creation and
# store access are exercised by the Inspect session startup and integration tests.
function Test-MihariCapability {
    [CmdletBinding()]
    param(
        [ValidateSet('Inspect', 'Tunnel')]
        [string] $Mode = 'Tunnel'
    )

    $missing = New-Object 'System.Collections.Generic.List[string]'
    if ($env:OS -ne 'Windows_NT') {
        $missing.Add('Windows is required for the local certificate store and CNG keys')
    }

    $commonTypes = @(
        'System.Net.Sockets.TcpListener',
        'System.Net.Sockets.TcpClient',
        'System.Management.Automation.Runspaces.RunspacePool',
        'System.Security.Authentication.SslProtocols',
        'System.Net.Security.SslStream'
    )
    foreach ($typeName in $commonTypes) {
        if ($null -eq ($typeName -as [type])) {
            $missing.Add("Missing platform type: $typeName")
        }
    }

    if ($Mode -eq 'Inspect') {
        $inspectTypes = @(
            'System.Security.Cryptography.RSACng',
            'System.Security.Cryptography.CngKey',
            'System.Security.Cryptography.CngKeyCreationParameters',
            'System.Security.Cryptography.X509Certificates.CertificateRequest',
            'System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder',
            'System.Security.Cryptography.X509Certificates.RSACertificateExtensions',
            'System.Security.Cryptography.X509Certificates.X509Store'
        )
        foreach ($typeName in $inspectTypes) {
            if ($null -eq ($typeName -as [type])) {
                $missing.Add("Missing in-memory certificate API: $typeName")
            }
        }

        $requestType = 'System.Security.Cryptography.X509Certificates.CertificateRequest' -as [type]
        if ($null -ne $requestType) {
            foreach ($methodName in @('CreateSelfSigned', 'Create')) {
                if (@($requestType.GetMethods() | Where-Object { $_.Name -eq $methodName }).Count -eq 0) {
                    $missing.Add("Missing certificate issuance API: CertificateRequest.$methodName")
                }
            }
        }
        $copyType = 'System.Security.Cryptography.X509Certificates.RSACertificateExtensions' -as [type]
        if ($null -ne $copyType -and @($copyType.GetMethods() | Where-Object { $_.Name -eq 'CopyWithPrivateKey' }).Count -eq 0) {
            $missing.Add('Missing in-memory private-key attachment API: RSACertificateExtensions.CopyWithPrivateKey')
        }
    }

    [pscustomobject]@{
        Mode = $Mode
        Available = ($missing.Count -eq 0)
        Reason = ($missing -join '; ')
    }
}
