# The foreground listener owns the runspace pool and every accepted socket.
# Connection processing lives in Connection.ps1 and runs in the bounded pool.

function Complete-MihariListenerWorker {
    param(
        [Parameter(Mandatory = $true)]$Session,
        [Parameter(Mandatory = $true)]$Worker
    )

    try {
        $null = $Worker.PowerShell.EndInvoke($Worker.AsyncResult)
        if ($Worker.PowerShell.Streams.Error.Count -gt 0) {
            foreach ($workerError in $Worker.PowerShell.Streams.Error) {
                Write-MihariListenerWorkerFailure -Session $Session -ConnectionId $Worker.ConnectionId -ErrorRecord $workerError
            }
        }
    }
    catch {
        Write-MihariListenerWorkerFailure -Session $Session -ConnectionId $Worker.ConnectionId -ErrorRecord $_
    }
    finally {
        try { $Worker.Client.Close() } catch { Write-Warning ("Mihari client socket cleanup failed: {0}" -f $_.Exception.Message) }
        $Worker.PowerShell.Dispose()
    }
}

function Write-MihariListenerWorkerFailure {
    param(
        [Parameter(Mandatory = $true)]$Session,
        [Parameter(Mandatory = $true)][string]$ConnectionId,
        [Parameter(Mandatory = $true)]$ErrorRecord
    )

    $exception = $ErrorRecord.Exception
    $errorType = 'System.Exception'
    $errorMessage = [string]$ErrorRecord
    if ($null -ne $exception) {
        $errorType = $exception.GetType().FullName
        $errorMessage = $exception.Message
    }

    # The listener must not let a failed worker silently disappear. The event
    # writer supplied by Observation.ps1 serializes writes across runspaces.
    if (Get-Command Write-MihariEvent -ErrorAction SilentlyContinue) {
        try {
            $null = Write-MihariEvent -Session $Session -ConnectionId $ConnectionId -RequestId $null -Stage 'listener.accept' -Outcome 'failed' -ElapsedMs 0 -Data @{
                exception = $exception
                errorType = $errorType
                errorCode = 'worker_failed'
                errorMessage = $errorMessage
            }
            return
        }
        catch {
            Write-Warning 'Mihari worker failure could not be recorded in the event stream.'
        }
    }
    Write-Warning 'Mihari connection worker failed.'
}

function Stop-MihariListener {
    param([Parameter(Mandatory = $true)]$Session)

    if ([string]::IsNullOrWhiteSpace([string]$Session.StopPath)) {
        throw 'Session.StopPath is required to stop the listener.'
    }
    $null = New-Item -ItemType File -Path $Session.StopPath -Force
    if ($null -ne $Session.Cancellation) {
        try { $Session.Cancellation.Cancel() } catch { Write-Warning ("Mihari cancellation failed: {0}" -f $_.Exception.Message) }
    }
    if ($null -ne $Session.Listener) {
        try { $Session.Listener.Stop() } catch { Write-Warning ("Mihari listener stop failed: {0}" -f $_.Exception.Message) }
    }
}

function Start-MihariListener {
    param(
        [Parameter(Mandatory = $true)]$Session,
        [scriptblock]$OnReady
    )

    $port = [int]$Session.Port
    $maxWorkers = [int]$Session.MaxWorkers
    if ($port -lt 0 -or $port -gt 65535) { throw 'Session.Port must be between 0 and 65535.' }
    if ($maxWorkers -lt 1 -or $maxWorkers -gt 256) { throw 'Session.MaxWorkers must be between 1 and 256.' }
    if ([string]::IsNullOrWhiteSpace([string]$Session.StopPath)) { throw 'Session.StopPath is required.' }
    # A stop command can arrive while the session is still starting. In that
    # case the entry point's finally block owns the normal session cleanup.
    if (Test-Path -LiteralPath $Session.StopPath) { return }

    $sourceRoot = [string]$Session.SourceRoot
    if (Test-Path -LiteralPath (Join-Path $sourceRoot 'src') -PathType Container) {
        $sourceRoot = Join-Path $sourceRoot 'src'
    }
    if (-not (Test-Path -LiteralPath (Join-Path $sourceRoot 'Connection.ps1') -PathType Leaf)) {
        throw 'Session.SourceRoot does not contain Connection.ps1.'
    }

    $listener = New-Object System.Net.Sockets.TcpListener -ArgumentList @([System.Net.IPAddress]::Loopback, $port)
    $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $maxWorkers)
    $workers = New-Object System.Collections.ArrayList
    $workerScript = @'
param($WorkerSession, $WorkerClient, $WorkerSourceRoot, $AcceptedMode)
$ErrorActionPreference = 'Stop'
try {
    foreach ($sourceFile in (Get-ChildItem -LiteralPath $WorkerSourceRoot -Filter '*.ps1' -File | Sort-Object Name)) {
        . $sourceFile.FullName
    }
    Handle-MihariConnection -Session $WorkerSession -Client $WorkerClient -AcceptedMode $AcceptedMode
}
finally {
    $WorkerClient.Close()
}
'@

    try {
        $pool.Open()
        $listener.Start([Math]::Max(2, $maxWorkers * 2))
        $actualPort = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
        if ($null -eq $Session.PSObject.Properties['ActualPort']) {
            $Session | Add-Member -NotePropertyName ActualPort -NotePropertyValue $actualPort
        }
        else {
            $Session.ActualPort = $actualPort
        }
        if ($null -eq $Session.PSObject.Properties['Listener']) {
            $Session | Add-Member -NotePropertyName Listener -NotePropertyValue $listener
        }
        else {
            $Session.Listener = $listener
        }
        $Session.ProxyHeartbeatUtc = [DateTime]::UtcNow.ToString('o')
        if ($null -ne $OnReady) { & $OnReady $Session }
        [void](Save-MihariSessionMetadata -Session $Session)

        $lastHeartbeatPersist = [DateTime]::MinValue

        while (-not (Test-Path -LiteralPath $Session.StopPath)) {
            $Session.ProxyHeartbeatUtc = [DateTime]::UtcNow.ToString('o')
            if ($null -ne $Session.ManagementListener -and (Get-Command Invoke-MihariManagementPending -ErrorAction SilentlyContinue)) {
                Invoke-MihariManagementPending -Session $Session
            }
            if (([DateTime]::UtcNow - $lastHeartbeatPersist).TotalSeconds -ge 1) {
                try { [void](Save-MihariSessionMetadata -Session $Session) }
                catch {
                    if ($null -ne $Session.Writer) {
                        $null = Write-MihariEvent -Session $Session -ConnectionId 'session' -Stage 'session.metadata' -Outcome 'failed' -ElapsedMs 0 -Data @{
                            exception = $_.Exception; errorCode = 'metadata_write_failed'
                        }
                    }
                }
                $lastHeartbeatPersist = [DateTime]::UtcNow
            }
            for ($i = $workers.Count - 1; $i -ge 0; $i--) {
                if ($workers[$i].AsyncResult.IsCompleted) {
                    $worker = $workers[$i]
                    $workers.RemoveAt($i)
                    Complete-MihariListenerWorker -Session $Session -Worker $worker
                }
            }

            if ($workers.Count -ge $maxWorkers) {
                Start-Sleep -Milliseconds 25
                continue
            }
            try {
                if (-not $listener.Pending()) {
                    Start-Sleep -Milliseconds 25
                    continue
                }
                $client = $listener.AcceptTcpClient()
                [System.Threading.Monitor]::Enter($Session.StateLock)
                try { $acceptedMode = [string]$Session.Mode }
                finally { [System.Threading.Monitor]::Exit($Session.StateLock) }
            }
            catch {
                # Stop-MihariListener may close the listener while accept is
                # in progress. The stop file distinguishes that from a fault.
                if (Test-Path -LiteralPath $Session.StopPath) { break }
                throw
            }
            $connectionId = [guid]::NewGuid().ToString('N')
            $powerShell = $null
            try {
                $powerShell = [System.Management.Automation.PowerShell]::Create()
                $powerShell.RunspacePool = $pool
                $null = $powerShell.AddScript($workerScript).AddArgument($Session).AddArgument($client).AddArgument($sourceRoot).AddArgument($acceptedMode)
                $asyncResult = $powerShell.BeginInvoke()
                $null = $workers.Add([pscustomobject]@{
                    PowerShell = $powerShell
                    AsyncResult = $asyncResult
                    Client = $client
                    ConnectionId = $connectionId
                })
            }
            catch {
                if ($null -ne $powerShell) { $powerShell.Dispose() }
                $client.Close()
                Write-MihariListenerWorkerFailure -Session $Session -ConnectionId $connectionId -ErrorRecord $_
            }
        }
    }
    finally {
        $listener.Stop()
        foreach ($worker in $workers) {
            try { $worker.Client.Close() } catch { Write-Warning ("Mihari client socket cleanup failed: {0}" -f $_.Exception.Message) }
        }

        $deadline = [DateTime]::UtcNow.AddSeconds(10)
        while ($workers.Count -gt 0 -and [DateTime]::UtcNow -lt $deadline) {
            for ($i = $workers.Count - 1; $i -ge 0; $i--) {
                if ($workers[$i].AsyncResult.IsCompleted) {
                    $worker = $workers[$i]
                    $workers.RemoveAt($i)
                    Complete-MihariListenerWorker -Session $Session -Worker $worker
                }
            }
            if ($workers.Count -gt 0) { Start-Sleep -Milliseconds 25 }
        }
        foreach ($worker in $workers) {
            try { $worker.PowerShell.Stop() } catch { Write-Warning ("Mihari worker stop failed: {0}" -f $_.Exception.Message) }
            $worker.PowerShell.Dispose()
        }
        $pool.Close()
        $pool.Dispose()
    }
}
