param(
    [ValidateSet('Parent', 'Worker', 'Operator')][string] $Role = 'Parent',
    [ValidateSet('Add', 'Remove')][string] $Operation = 'Add',
    [string] $PublicCertificatePath,
    [string] $Thumbprint,
    [string] $Subject,
    [int] $WorkerProcessId
)

# CI-only probe: explicitly confirm the OS warning for this test's own unique
# public Mihari CA. It never changes protected-root policy or installs a key.
$ErrorActionPreference = 'Stop'

function Test-ExactProbeRoot {
    param([string] $ExpectedThumbprint, [string] $ExpectedSubject)
    $store = [System.Security.Cryptography.X509Certificates.X509Store]::new(
        [System.Security.Cryptography.X509Certificates.StoreName]::Root,
        [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
    )
    try {
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
        $matches = $store.Certificates.Find(
            [System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint,
            $ExpectedThumbprint, $false
        )
        foreach ($cert in $matches) {
            if ($cert.Subject -ceq $ExpectedSubject -and -not $cert.HasPrivateKey) { return $true }
        }
        return $false
    }
    finally { $store.Close() }
}

function New-ProbeNativeBinding {
    $name = [System.Reflection.AssemblyName]::new('MihariTrustConfirm' + [guid]::NewGuid().ToString('N'))
    $access = [System.Reflection.Emit.AssemblyBuilderAccess]::Run
    $signature = [Type[]] @([System.Reflection.AssemblyName], [System.Reflection.Emit.AssemblyBuilderAccess])
    $factory = [System.Reflection.Emit.AssemblyBuilder].GetMethod('DefineDynamicAssembly', $signature)
    if ($null -ne $factory) {
        $builder = [System.Reflection.Emit.AssemblyBuilder]::DefineDynamicAssembly($name, $access)
    }
    else { $builder = [AppDomain]::CurrentDomain.DefineDynamicAssembly($name, $access) }
    $module = $builder.DefineDynamicModule('Native')
    $type = $module.DefineType('User32', [System.Reflection.TypeAttributes]::Public)
    $attributes = [System.Reflection.MethodAttributes]::Public -bor
        [System.Reflection.MethodAttributes]::Static -bor
        [System.Reflection.MethodAttributes]::PinvokeImpl
    $method = $type.DefinePInvokeMethod(
        'PostMessageW', 'user32.dll', $attributes,
        [System.Reflection.CallingConventions]::Standard,
        [bool], [Type[]] @([IntPtr], [int], [IntPtr], [IntPtr]),
        [System.Runtime.InteropServices.CallingConvention]::Winapi,
        [System.Runtime.InteropServices.CharSet]::Unicode
    )
    $method.SetImplementationFlags($method.GetMethodImplementationFlags() -bor
        [System.Reflection.MethodImplAttributes]::PreserveSig)
    $ownerMethod = $type.DefinePInvokeMethod(
        'GetWindow', 'user32.dll', $attributes,
        [System.Reflection.CallingConventions]::Standard,
        [IntPtr], [Type[]] @([IntPtr], [int]),
        [System.Runtime.InteropServices.CallingConvention]::Winapi,
        [System.Runtime.InteropServices.CharSet]::Unicode
    )
    $ownerMethod.SetImplementationFlags($ownerMethod.GetMethodImplementationFlags() -bor
        [System.Reflection.MethodImplAttributes]::PreserveSig)
    $pidMethod = $type.DefinePInvokeMethod(
        'GetWindowThreadProcessId', 'user32.dll', $attributes,
        [System.Reflection.CallingConventions]::Standard,
        [uint32], [Type[]] @([IntPtr], [uint32].MakeByRefType()),
        [System.Runtime.InteropServices.CallingConvention]::Winapi,
        [System.Runtime.InteropServices.CharSet]::Unicode
    )
    $pidMethod.SetImplementationFlags($pidMethod.GetMethodImplementationFlags() -bor
        [System.Reflection.MethodImplAttributes]::PreserveSig)
    $created = $type.CreateType()
    return [pscustomobject] @{
        PostMessage = $created.GetMethod('PostMessageW')
        GetWindow = $created.GetMethod('GetWindow')
        GetPid = $created.GetMethod('GetWindowThreadProcessId')
    }
}

function Start-ProbeChild {
    param([string] $ChildRole, [string] $ChildOperation, [int] $TargetProcessId)
    $executable = Join-Path $PSHOME 'powershell.exe'
    if ($PSVersionTable.PSEdition -eq 'Core') { $executable = Join-Path $PSHOME 'pwsh.exe' }
    $escapedScript = $PSCommandPath.Replace('"', '""')
    $escapedCert = $PublicCertificatePath.Replace('"', '""')
    $escapedSubject = $Subject.Replace('"', '""')
    $arguments = '-NoProfile -NonInteractive -File "{0}" -Role {1} -Operation {2} -PublicCertificatePath "{3}" -Thumbprint {4} -Subject "{5}" -WorkerProcessId {6}' -f
        $escapedScript, $ChildRole, $ChildOperation, $escapedCert, $Thumbprint, $escapedSubject, $TargetProcessId
    $info = New-Object System.Diagnostics.ProcessStartInfo
    $info.FileName = $executable
    $info.Arguments = $arguments
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $info
    if (-not $process.Start()) { throw "Could not start $ChildRole child." }
    return $process
}

function Stop-ProbeChild {
    param([System.Diagnostics.Process] $Process)
    if ($null -eq $Process) { return }
    try {
        if (-not $Process.HasExited) {
            try { $Process.Kill() }
            catch [System.InvalidOperationException] {
                Write-Host '[trust-confirm] child exited before termination'
            }
            [void] $Process.WaitForExit(2000)
        }
    }
    finally { $Process.Dispose() }
}

function Invoke-ProbeAction {
    param([string] $Action)
    $worker = $null
    $operator = $null
    try {
        $worker = Start-ProbeChild -ChildRole Worker -ChildOperation $Action -TargetProcessId 0
        Write-Host "[trust-confirm] $Action worker pid=$($worker.Id)"
        $operator = Start-ProbeChild -ChildRole Operator -ChildOperation $Action -TargetProcessId $worker.Id
        if (-not $operator.WaitForExit(12000)) {
            throw "$Action confirmation operator timed out."
        }
        $operatorOutput = $operator.StandardOutput.ReadToEnd().Trim()
        $operatorError = $operator.StandardError.ReadToEnd().Trim()
        if ($operatorOutput) { Write-Host $operatorOutput }
        if ($operatorError) { Write-Host $operatorError }
        if ($operator.ExitCode -ne 0) { throw "$Action confirmation operator failed." }
        if (-not $worker.WaitForExit(3000)) { throw "$Action worker remained blocked after confirmation." }
        $workerOutput = $worker.StandardOutput.ReadToEnd().Trim()
        $workerError = $worker.StandardError.ReadToEnd().Trim()
        if ($workerOutput) { Write-Host $workerOutput }
        if ($workerError) { Write-Host $workerError }
        if ($worker.ExitCode -ne 0) { throw "$Action worker failed with exit code $($worker.ExitCode)." }
    }
    finally {
        Stop-ProbeChild -Process $operator
        Stop-ProbeChild -Process $worker
    }
}

if ($Role -eq 'Worker') {
    if ($Subject -cnotmatch '^CN=Mihari Ephemeral Diagnostic CA [0-9a-f]{32}$' -or
        $Thumbprint -notmatch '^[0-9a-fA-F]{40}$') {
        throw 'Refusing an unmarked trust probe root.'
    }
    $store = [System.Security.Cryptography.X509Certificates.X509Store]::new(
        [System.Security.Cryptography.X509Certificates.StoreName]::Root,
        [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
    )
    try {
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        if ($Operation -eq 'Add') {
            $public = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($PublicCertificatePath)
            try {
                if ($public.HasPrivateKey -or $public.Thumbprint -ine $Thumbprint -or $public.Subject -cne $Subject) {
                    throw 'Public CA identity mismatch.'
                }
                $store.Add($public)
                Write-Host '[trust-confirm] public root add returned'
            }
            finally { $public.Dispose() }
        }
        else {
            $matches = $store.Certificates.Find(
                [System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint,
                $Thumbprint, $false
            )
            foreach ($cert in $matches) {
                if ($cert.Subject -ceq $Subject -and -not $cert.HasPrivateKey) {
                    $store.Remove($cert)
                    Write-Host '[trust-confirm] exact root remove returned'
                }
            }
        }
    }
    finally { $store.Close() }
    exit 0
}

if ($Role -eq 'Operator') {
    Add-Type -AssemblyName UIAutomationClient
    $root = [System.Windows.Automation.AutomationElement]::RootElement
    $condition = [System.Windows.Automation.Condition]::TrueCondition
    $native = New-ProbeNativeBinding
    $deadline = [DateTime]::UtcNow.AddSeconds(8)
    do {
        $windows = $root.FindAll([System.Windows.Automation.TreeScope]::Children, $condition)
        for ($i = 0; $i -lt $windows.Count; $i++) {
            $window = $windows.Item($i)
            try {
                $title = [string] $window.Current.Name
                $processId = [int] $window.Current.ProcessId
                $handle = [IntPtr] $window.Current.NativeWindowHandle
            }
            catch { continue } # Window closed during enumeration.
            if ($title -cne 'Security Warning' -or $handle -eq [IntPtr]::Zero) { continue }
            $owner = [IntPtr] $native.GetWindow.Invoke($null, [object[]] @($handle, [int] 4)) # GW_OWNER
            $ownerPid = 0
            if ($owner -ne [IntPtr]::Zero) {
                $pidArguments = [object[]] @($owner, [uint32] 0)
                [void] $native.GetPid.Invoke($null, $pidArguments)
                $ownerPid = [int] $pidArguments[1]
            }
            if ($processId -ne $WorkerProcessId -and $ownerPid -ne $WorkerProcessId) {
                Write-Host "[trust-confirm] refused unassociated warning pid=$processId ownerPid=$ownerPid"
                continue
            }
            Write-Host "[trust-confirm] exact worker warning hwnd=$handle pid=$processId ownerPid=$ownerPid"
            $posted = $native.PostMessage.Invoke($null, [object[]] @(
                $handle, [int] 0x111, [IntPtr]::new(6), [IntPtr]::Zero
            ))
            if (-not $posted) { throw 'Could not post the Yes command to the exact worker warning.' }
            Write-Host '[trust-confirm] posted IDYES to exact worker warning'
            exit 0
        }
        if ($null -eq (Get-Process -Id $WorkerProcessId -ErrorAction SilentlyContinue)) { break }
        Start-Sleep -Milliseconds 200
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "No Security Warning owned by worker PID $WorkerProcessId was found."
}

if ($env:OS -ne 'Windows_NT') { throw 'Windows is required.' }
. (Join-Path (Split-Path $PSScriptRoot -Parent) 'src/Certificate.ps1')
$directory = Join-Path ([IO.Path]::GetTempPath()) ('mihari-trust-confirm-' + [guid]::NewGuid().ToString('N'))
[void] [IO.Directory]::CreateDirectory($directory)
$PublicCertificatePath = Join-Path $directory 'public-ca.cer'
$ca = $null
$cleanupFailure = $null
try {
    $ca = New-MihariCA -SessionId ([guid]::NewGuid().ToString('N'))
    $Thumbprint = $ca.Thumbprint
    $Subject = $ca.Subject
    [IO.File]::WriteAllBytes(
        $PublicCertificatePath,
        $ca.Certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
    )
    Invoke-ProbeAction -Action Add
    if (-not (Test-ExactProbeRoot -ExpectedThumbprint $Thumbprint -ExpectedSubject $Subject)) {
        throw 'The exact public CA was not installed after confirmation.'
    }
    Write-Host '[trust-confirm] PASS public CA trusted in CurrentUser Root'
}
finally {
    if ($null -ne $ca) {
        try {
            if (Test-ExactProbeRoot -ExpectedThumbprint $Thumbprint -ExpectedSubject $Subject) {
                Invoke-ProbeAction -Action Remove
            }
            if (Test-ExactProbeRoot -ExpectedThumbprint $Thumbprint -ExpectedSubject $Subject) {
                $cleanupFailure = 'The exact probe CA remained trusted after removal.'
            }
        }
        catch { $cleanupFailure = "Probe root cleanup failed: $($_.Exception.Message)" }
        $ca.Certificate.Dispose()
        $ca.PrivateKey.Dispose()
    }
    try { [IO.Directory]::Delete($directory, $true) }
    catch { if (-not $cleanupFailure) { $cleanupFailure = "Public certificate file cleanup failed: $($_.Exception.Message)" } }
    if ($cleanupFailure) { throw $cleanupFailure }
}
