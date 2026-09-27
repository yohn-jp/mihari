param(
    [Parameter(Mandatory = $true)][ValidateSet('Add', 'Remove')][string] $Operation,
    [Parameter(Mandatory = $true)][int] $TargetProcessId,
    [int] $TimeoutSeconds = 15
)

# CI test operator for the Windows protected-root dialog. Only a warning
# associated with the exact test-owned process receives an explicit Yes.
$ErrorActionPreference = 'Stop'

function New-MihariTestWindowBinding {
    $name = [System.Reflection.AssemblyName]::new('MihariTestWindow' + [guid]::NewGuid().ToString('N'))
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
    $post = $type.DefinePInvokeMethod(
        'PostMessageW', 'user32.dll', $attributes,
        [System.Reflection.CallingConventions]::Standard,
        [bool], [Type[]] @([IntPtr], [int], [IntPtr], [IntPtr]),
        [System.Runtime.InteropServices.CallingConvention]::Winapi,
        [System.Runtime.InteropServices.CharSet]::Unicode
    )
    $post.SetImplementationFlags($post.GetMethodImplementationFlags() -bor
        [System.Reflection.MethodImplAttributes]::PreserveSig)
    $getOwner = $type.DefinePInvokeMethod(
        'GetWindow', 'user32.dll', $attributes,
        [System.Reflection.CallingConventions]::Standard,
        [IntPtr], [Type[]] @([IntPtr], [int]),
        [System.Runtime.InteropServices.CallingConvention]::Winapi,
        [System.Runtime.InteropServices.CharSet]::Unicode
    )
    $getOwner.SetImplementationFlags($getOwner.GetMethodImplementationFlags() -bor
        [System.Reflection.MethodImplAttributes]::PreserveSig)
    $getPid = $type.DefinePInvokeMethod(
        'GetWindowThreadProcessId', 'user32.dll', $attributes,
        [System.Reflection.CallingConventions]::Standard,
        [uint32], [Type[]] @([IntPtr], [uint32].MakeByRefType()),
        [System.Runtime.InteropServices.CallingConvention]::Winapi,
        [System.Runtime.InteropServices.CharSet]::Unicode
    )
    $getPid.SetImplementationFlags($getPid.GetMethodImplementationFlags() -bor
        [System.Reflection.MethodImplAttributes]::PreserveSig)
    $created = $type.CreateType()
    return [pscustomobject]@{
        Post = $created.GetMethod('PostMessageW')
        Owner = $created.GetMethod('GetWindow')
        Pid = $created.GetMethod('GetWindowThreadProcessId')
    }
}

if ($env:OS -ne 'Windows_NT') { throw 'Certificate prompt operator requires Windows.' }
if ($TargetProcessId -le 0 -or $TargetProcessId -eq $PID) { throw 'Invalid test target process ID.' }
Add-Type -AssemblyName UIAutomationClient
$native = New-MihariTestWindowBinding
$root = [System.Windows.Automation.AutomationElement]::RootElement
$condition = [System.Windows.Automation.Condition]::TrueCondition
$title = 'Security Warning'
if ($Operation -eq 'Remove') { $title = 'Root Certificate Store' }
$deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
do {
    $windows = $root.FindAll([System.Windows.Automation.TreeScope]::Children, $condition)
    for ($i = 0; $i -lt $windows.Count; $i++) {
        $window = $windows.Item($i)
        try {
            $windowTitle = [string] $window.Current.Name
            $windowPid = [int] $window.Current.ProcessId
            $handle = [IntPtr] $window.Current.NativeWindowHandle
        }
        catch { continue } # Dialog closed during enumeration.
        if ($windowTitle -cne $title -or $handle -eq [IntPtr]::Zero) { continue }
        $owner = [IntPtr] $native.Owner.Invoke($null, [object[]] @($handle, [int] 4))
        $ownerPid = 0
        if ($owner -ne [IntPtr]::Zero) {
            $pidArgs = [object[]] @($owner, [uint32] 0)
            [void] $native.Pid.Invoke($null, $pidArgs)
            $ownerPid = [int] $pidArgs[1]
        }
        if ($windowPid -ne $TargetProcessId -and $ownerPid -ne $TargetProcessId) { continue }
        $posted = $native.Post.Invoke($null, [object[]] @(
            $handle, [int] 0x111, [IntPtr]::new(6), [IntPtr]::Zero
        ))
        if (-not $posted) { throw 'Could not confirm the exact certificate dialog.' }
        Write-Host "Confirmed $Operation dialog for test PID $TargetProcessId."
        exit 0
    }
    if ($null -eq (Get-Process -Id $TargetProcessId -ErrorAction SilentlyContinue)) {
        throw "Test PID $TargetProcessId exited before its $Operation dialog was confirmed."
    }
    Start-Sleep -Milliseconds 200
} while ([DateTime]::UtcNow -lt $deadline)
throw "No $Operation certificate dialog appeared for test PID $TargetProcessId within $TimeoutSeconds seconds."
