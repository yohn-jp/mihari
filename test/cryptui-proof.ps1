param()

# Probe the documented Windows no-UI certificate import API against the exact
# CurrentUser Root store. This script is deliberately separate from runtime.
$ErrorActionPreference = 'Stop'
. (Join-Path (Split-Path $PSScriptRoot -Parent) 'src/Certificate.ps1')

function New-CryptUiProbeBinding {
    $assemblyName = [System.Reflection.AssemblyName]::new('MihariCryptUiProbe' + [guid]::NewGuid().ToString('N'))
    $access = [System.Reflection.Emit.AssemblyBuilderAccess]::Run
    $signature = [Type[]] @([System.Reflection.AssemblyName], [System.Reflection.Emit.AssemblyBuilderAccess])
    $staticFactory = [System.Reflection.Emit.AssemblyBuilder].GetMethod('DefineDynamicAssembly', $signature)
    if ($null -ne $staticFactory) {
        $builder = [System.Reflection.Emit.AssemblyBuilder]::DefineDynamicAssembly($assemblyName, $access)
    }
    else {
        $builder = [AppDomain]::CurrentDomain.DefineDynamicAssembly($assemblyName, $access)
    }
    $module = $builder.DefineDynamicModule('Native')
    $type = $module.DefineType('CryptUi', [System.Reflection.TypeAttributes]::Public)
    $attributes = [System.Reflection.MethodAttributes]::Public -bor
        [System.Reflection.MethodAttributes]::Static -bor
        [System.Reflection.MethodAttributes]::PinvokeImpl
    $parameterTypes = [Type[]] @([int], [IntPtr], [IntPtr], [IntPtr], [IntPtr])
    $method = $type.DefinePInvokeMethod(
        'CryptUIWizImport', 'cryptui.dll', $attributes,
        [System.Reflection.CallingConventions]::Standard,
        [bool], $parameterTypes,
        [System.Runtime.InteropServices.CallingConvention]::Winapi,
        [System.Runtime.InteropServices.CharSet]::Unicode
    )
    $method.SetImplementationFlags($method.GetMethodImplementationFlags() -bor
        [System.Reflection.MethodImplAttributes]::PreserveSig)
    $created = $type.CreateType()
    return $created.GetMethod('CryptUIWizImport')
}

$ca = $null
$public = $null
$store = $null
$storeOpened = $false
$src = [IntPtr]::Zero
$emptyPassword = [IntPtr]::Zero
$installed = $false
$thumbprint = $null
$subject = $null
try {
    Write-Host '[cryptui] create unique CA'
    $ca = New-MihariCA -SessionId ([guid]::NewGuid().ToString('N'))
    $thumbprint = $ca.Thumbprint
    $subject = $ca.Subject
    $public = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
        $ca.Certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
    )
    if ($public.HasPrivateKey) { throw 'Probe public CA unexpectedly contains a private key.' }

    $store = [System.Security.Cryptography.X509Certificates.X509Store]::new(
        [System.Security.Cryptography.X509Certificates.StoreName]::Root,
        [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
    )
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    $storeOpened = $true
    $binding = New-CryptUiProbeBinding

    # CRYPTUI_WIZ_IMPORT_SRC_INFO: DWORD, DWORD, pointer union, DWORD,
    # aligned LPCWSTR. The source is the public certificate's PCCERT_CONTEXT.
    $passwordOffset = if ([IntPtr]::Size -eq 8) { 24 } else { 16 }
    $sourceSize = $passwordOffset + [IntPtr]::Size
    $src = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($sourceSize)
    for ($i = 0; $i -lt $sourceSize; $i++) {
        [System.Runtime.InteropServices.Marshal]::WriteByte($src, $i, 0)
    }
    $emptyPassword = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni('')
    [System.Runtime.InteropServices.Marshal]::WriteInt32($src, 0, $sourceSize)
    [System.Runtime.InteropServices.Marshal]::WriteInt32($src, 4, 2) # CERT_CONTEXT
    [System.Runtime.InteropServices.Marshal]::WriteIntPtr($src, 8, $public.Handle)
    [System.Runtime.InteropServices.Marshal]::WriteInt32($src, 8 + [IntPtr]::Size, 0)
    [System.Runtime.InteropServices.Marshal]::WriteIntPtr($src, $passwordOffset, $emptyPassword)

    Write-Host '[cryptui] before no-UI import'
    $result = $binding.Invoke($null, [object[]] @(
        [int] 1, [IntPtr]::Zero, [IntPtr]::Zero, $src, $store.StoreHandle
    ))
    Write-Host "[cryptui] after no-UI import: $result"
    if (-not $result) {
        throw 'CryptUIWizImport returned false.'
    }
    $installed = $true
    $matches = $store.Certificates.Find(
        [System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint,
        $thumbprint, $false
    )
    if ($matches.Count -ne 1 -or $matches[0].HasPrivateKey) {
        throw 'No-UI import did not place exactly one public CA into CurrentUser Root.'
    }
    Write-Host '[cryptui] PASS public root installed without UI'
}
finally {
    if ($null -ne $store) {
        if ($null -ne $thumbprint -and $storeOpened) {
            $present = $store.Certificates.Find(
                [System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint,
                $thumbprint, $false
            )
            if ($present.Count -gt 0) { $installed = $true }
        }
        if ($storeOpened) { $store.Close() }
    }
    if ($src -ne [IntPtr]::Zero) { [System.Runtime.InteropServices.Marshal]::FreeHGlobal($src) }
    if ($emptyPassword -ne [IntPtr]::Zero) { [System.Runtime.InteropServices.Marshal]::FreeHGlobal($emptyPassword) }
    if ($null -ne $public) { $public.Dispose() }
    if ($installed) {
        Write-Host '[cryptui] before exact root removal'
        $removed = Remove-MihariCARoot -Thumbprint $thumbprint -Subject $subject
        Write-Host "[cryptui] after exact root removal: $removed"
        if ($removed -ne 1) { throw "Expected to remove one root, removed $removed." }
    }
    if ($null -ne $ca) {
        $ca.Certificate.Dispose()
        $ca.PrivateKey.Dispose()
    }
}
