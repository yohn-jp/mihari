param(
    [ValidateSet('Parent', 'Worker', 'Operator')][string] $Role = 'Parent',
    [ValidateSet('Add', 'Remove')][string] $Operation = 'Add',
    [string] $PublicCertificatePath,
    [string] $Thumbprint,
    [string] $Subject,
    [int] $WorkerProcessId
)

$ErrorActionPreference = 'Stop'

function Test-ProbeRootPresent {
    param([string] $ExpectedThumbprint, [string] $ExpectedSubject)
    $store = [System.Security.Cryptography.X509Certificates.X509Store]::new(
        [System.Security.Cryptography.X509Certificates.StoreName]::Root,
        [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
    )
    try {
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
        $matches = $store.Certificates.Find(
            [System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint,
            $ExpectedThumbprint,
            $false
        )
        foreach ($certificate in $matches) {
            if ($certificate.Subject -ceq $ExpectedSubject) { return $true }
        }
        return $false
    }
    finally {
        $store.Close()
        $store.Dispose()
    }
}

function Start-ProbeProcess {
    param([string] $ChildRole, [string] $ChildOperation, [int] $TargetProcessId)
    $executable = Join-Path $PSHOME 'powershell.exe'
    if ($PSVersionTable.PSEdition -eq 'Core') { $executable = Join-Path $PSHOME 'pwsh.exe' }
    $scriptPath = $PSCommandPath.Replace('"', '""')
    $certificatePath = $PublicCertificatePath.Replace('"', '""')
    $safeSubject = $Subject.Replace('"', '""')
    $arguments = '-NoProfile -NonInteractive -File "{0}" -Role {1} -Operation {2} -PublicCertificatePath "{3}" -Thumbprint {4} -Subject "{5}" -WorkerProcessId {6}' -f
        $scriptPath, $ChildRole, $ChildOperation, $certificatePath, $Thumbprint, $safeSubject, $TargetProcessId
    $info = New-Object System.Diagnostics.ProcessStartInfo
    $info.FileName = $executable
    $info.Arguments = $arguments
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $info
    if (-not $process.Start()) { throw "Could not start trust probe $ChildRole process." }
    return $process
}

function Stop-ProbeProcess {
    param([System.Diagnostics.Process] $Process)
    if ($null -eq $Process) { return }
    try {
        if (-not $Process.HasExited) {
            try { $Process.Kill() }
            catch [System.InvalidOperationException] { } # Process exited after HasExited.
            [void] $Process.WaitForExit(3000)
        }
    }
    finally { $Process.Dispose() }
}

function Invoke-ProbeOperation {
    param([string] $Action)
    Write-Host "[trust-ui-probe] Starting $Action worker."
    $worker = $null
    $operator = $null
    try {
        $worker = Start-ProbeProcess -ChildRole Worker -ChildOperation $Action -TargetProcessId 0
        Start-Sleep -Milliseconds 400
        $operator = Start-ProbeProcess -ChildRole Operator -ChildOperation $Action -TargetProcessId $worker.Id
        if (-not $operator.WaitForExit(10000)) {
            Write-Host "[trust-ui-probe] UI Automation operator timed out for $Action."
            try { $operator.Kill() }
            catch [System.InvalidOperationException] { }
            [void] $operator.WaitForExit(3000)
        }
        $operatorOutput = $operator.StandardOutput.ReadToEnd().Trim()
        $operatorError = $operator.StandardError.ReadToEnd().Trim()
        if ($operatorOutput) { Write-Host $operatorOutput }
        if ($operatorError) { Write-Host "[trust-ui-probe] operator error: $operatorError" }
        if (-not $worker.WaitForExit(2000)) {
            Write-Host "[trust-ui-probe] $Action worker remained blocked after UI Automation."
            try { $worker.Kill() }
            catch [System.InvalidOperationException] { }
            [void] $worker.WaitForExit(3000)
        }
        else {
            Write-Host "[trust-ui-probe] $Action worker exit code: $($worker.ExitCode)."
            $workerOutput = $worker.StandardOutput.ReadToEnd().Trim()
            $workerError = $worker.StandardError.ReadToEnd().Trim()
            if ($workerOutput) { Write-Host $workerOutput }
            if ($workerError) { Write-Host "[trust-ui-probe] worker error: $workerError" }
        }
    }
    finally {
        Stop-ProbeProcess -Process $operator
        Stop-ProbeProcess -Process $worker
    }
}

function Invoke-ProbeManagedUia {
    # UIAutomationClient is the Windows .NET wrapper around the same platform UIA service.
    Add-Type -AssemblyName UIAutomationClient
    $root = [System.Windows.Automation.AutomationElement]::RootElement
    $condition = [System.Windows.Automation.Condition]::TrueCondition
    $deadline = [DateTime]::UtcNow.AddSeconds(8)
    do {
        $windows = $root.FindAll([System.Windows.Automation.TreeScope]::Children, $condition)
        for ($i = 0; $i -lt $windows.Count; $i++) {
            $window = $windows.Item($i)
            try {
                $title = [string] $window.Current.Name
                $processId = [int] $window.Current.ProcessId
            }
            catch { continue }
            if ($processId -ne $WorkerProcessId -and
                $title -notmatch 'Root Certificate Store|Security Warning|Windows Security|Certificate') {
                continue
            }
            Write-Host "[trust-ui-probe] managed candidate title='$title' pid=$processId."
            $elements = $window.FindAll([System.Windows.Automation.TreeScope]::Descendants, $condition)
            $hasMarker = $false
            $yesButton = $null
            for ($j = 0; $j -lt $elements.Count -and $j -lt 250; $j++) {
                $element = $elements.Item($j)
                try {
                    $name = [string] $element.Current.Name
                    $controlType = $element.Current.ControlType
                }
                catch { continue }
                if ($name.Contains($Subject)) { $hasMarker = $true }
                if ($controlType -eq [System.Windows.Automation.ControlType]::Button -and
                    $name -match '^(Yes|&Yes|はい)$') {
                    $yesButton = $element
                }
            }
            if ($null -ne $yesButton -and ($hasMarker -or $processId -eq $WorkerProcessId)) {
                Write-Host "[trust-ui-probe] invoking managed Yes for $Operation (marker=$hasMarker, pid=$processId)."
                $pattern = [System.Windows.Automation.InvokePattern] $yesButton.GetCurrentPattern(
                    [System.Windows.Automation.InvokePattern]::Pattern
                )
                $pattern.Invoke()
                return $true
            }
            Write-Host "[trust-ui-probe] no safe managed Yes target (marker=$hasMarker, button=$($null -ne $yesButton))."
        }
        $stillRunning = Get-Process -Id $WorkerProcessId -ErrorAction SilentlyContinue
        if ($null -eq $stillRunning) { break }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    return $false
}

if ($Role -eq 'Worker') {
    if ($Subject -cnotmatch '^CN=Mihari Ephemeral Diagnostic CA [0-9a-f]{32}$' -or
        $Thumbprint -notmatch '^[0-9a-fA-F]{40}$') {
        throw 'Trust probe worker refused an unmarked root identity.'
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
                    throw 'The public trust probe certificate did not match the expected identity.'
                }
                $store.Add($public)
                Write-Host '[trust-ui-probe] public root add returned.'
            }
            finally { $public.Dispose() }
        }
        else {
            $matches = $store.Certificates.Find(
                [System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint,
                $Thumbprint,
                $false
            )
            foreach ($certificate in $matches) {
                if ($certificate.Subject -ceq $Subject) {
                    $store.Remove($certificate)
                    Write-Host '[trust-ui-probe] exact root remove returned.'
                }
            }
        }
    }
    finally {
        $store.Close()
        $store.Dispose()
    }
    exit 0
}

if ($Role -eq 'Operator') {
    try {
        # CUIAutomation is the Windows platform UI Automation COM implementation.
        $automationType = [type]::GetTypeFromCLSID([guid] 'ff48dba4-60ef-4201-aa87-54103eef594e', $true)
        $automation = [Activator]::CreateInstance($automationType)
        $root = $automation.GetRootElement()
        $condition = $automation.CreateTrueCondition()
        $deadline = [DateTime]::UtcNow.AddSeconds(8)
        $clicked = $false
        do {
            $windows = $root.FindAll(2, $condition) # TreeScope.Children: top-level windows.
            for ($i = 0; $i -lt $windows.Length; $i++) {
                $window = $windows.GetElement($i)
                try {
                    $title = [string] $window.CurrentName
                    $processId = [int] $window.CurrentProcessId
                }
                catch { continue } # A window can close during enumeration.
                if ($processId -ne $WorkerProcessId -and
                    $title -notmatch 'Root Certificate Store|Security Warning|Windows Security|Certificate') {
                    continue
                }
                Write-Host "[trust-ui-probe] candidate dialog title='$title' pid=$processId."
                $elements = $window.FindAll(4, $condition) # TreeScope.Descendants.
                $hasMarker = $false
                $yesButton = $null
                for ($j = 0; $j -lt $elements.Length -and $j -lt 250; $j++) {
                    $element = $elements.GetElement($j)
                    try {
                        $name = [string] $element.CurrentName
                        $controlType = [int] $element.CurrentControlType
                    }
                    catch { continue }
                    if ($name.Contains($Subject)) { $hasMarker = $true }
                    if ($controlType -eq 50000 -and $name -match '^(Yes|&Yes|はい)$') {
                        $yesButton = $element
                    }
                }
                if ($null -ne $yesButton -and ($hasMarker -or $processId -eq $WorkerProcessId)) {
                    Write-Host "[trust-ui-probe] invoking Yes for $Operation (marker=$hasMarker, pid=$processId)."
                    $invoke = $yesButton.GetCurrentPattern(10000) # UIA_InvokePatternId.
                    $invoke.Invoke()
                    $clicked = $true
                    break
                }
                Write-Host "[trust-ui-probe] no safe Yes target (marker=$hasMarker, button=$($null -ne $yesButton))."
            }
            if ($clicked) { break }
            $stillRunning = Get-Process -Id $WorkerProcessId -ErrorAction SilentlyContinue
            if ($null -eq $stillRunning) { break }
            Start-Sleep -Milliseconds 250
        } while ([DateTime]::UtcNow -lt $deadline)
        Write-Host "[trust-ui-probe] UI Automation clicked=$clicked."
        exit 0
    }
    catch {
        Write-Host "[trust-ui-probe] direct UIA COM unavailable: $($_.Exception.GetType().FullName): $($_.Exception.Message)"
        try {
            $managedClicked = Invoke-ProbeManagedUia
            Write-Host "[trust-ui-probe] managed UI Automation clicked=$managedClicked."
            exit 0
        }
        catch {
            Write-Host "[trust-ui-probe] managed UI Automation unavailable: $($_.Exception.GetType().FullName): $($_.Exception.Message)"
            exit 2
        }
    }
}

if ($env:OS -ne 'Windows_NT') { throw 'The trust UI probe requires Windows.' }
. (Join-Path (Split-Path $PSScriptRoot -Parent) 'src/Certificate.ps1')
$probeDirectory = Join-Path ([IO.Path]::GetTempPath()) ('mihari-trust-probe-' + [guid]::NewGuid().ToString('N'))
[void] [IO.Directory]::CreateDirectory($probeDirectory)
$PublicCertificatePath = Join-Path $probeDirectory 'public-ca.cer'
$ca = $null
$cleanupError = $null
try {
    $ca = New-MihariCA -SessionId ([guid]::NewGuid().ToString('N'))
    $Thumbprint = $ca.Thumbprint
    $Subject = $ca.Subject
    [IO.File]::WriteAllBytes(
        $PublicCertificatePath,
        $ca.Certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
    )
    Write-Host "[trust-ui-probe] parent pid=$PID; public CA thumbprint=$Thumbprint; private key stays in parent."
    Invoke-ProbeOperation -Action Add
    $present = Test-ProbeRootPresent -ExpectedThumbprint $Thumbprint -ExpectedSubject $Subject
    Write-Host "[trust-ui-probe] exact public root present after add=$present."
    if (-not $present) { throw 'The protected-root trust prompt was not completed.' }
}
finally {
    if ($null -ne $ca) {
        try {
            if (Test-ProbeRootPresent -ExpectedThumbprint $ca.Thumbprint -ExpectedSubject $ca.Subject) {
                Invoke-ProbeOperation -Action Remove
            }
            if (Test-ProbeRootPresent -ExpectedThumbprint $ca.Thumbprint -ExpectedSubject $ca.Subject) {
                $cleanupError = 'The unique Mihari probe root remains trusted after bounded cleanup.'
            }
        }
        catch { $cleanupError = "Probe root cleanup failed: $($_.Exception.Message)" }
        $ca.Certificate.Dispose()
        $ca.PrivateKey.Dispose()
    }
    try { [IO.Directory]::Delete($probeDirectory, $true) }
    catch { if (-not $cleanupError) { $cleanupError = "Public certificate file cleanup failed: $($_.Exception.Message)" } }
    if ($cleanupError) { throw $cleanupError }
}
