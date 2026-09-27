function Get-MihariDefaultOutputRoot {
    param([string]$OutputRoot)

    if (-not [string]::IsNullOrWhiteSpace($OutputRoot)) {
        return [System.IO.Path]::GetFullPath($OutputRoot)
    }

    $localAppData = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
    if ([string]::IsNullOrWhiteSpace($localAppData)) {
        throw 'Mihari requires a user-scoped LocalApplicationData directory.'
    }
    return [System.IO.Path]::GetFullPath((Join-Path (Join-Path $localAppData 'Mihari') 'sessions'))
}

function Get-MihariSessionProcessAlive {
    param($Metadata)

    if ($null -eq $Metadata -or $null -eq $Metadata.processId) { return $false }
    try {
        $process = [System.Diagnostics.Process]::GetProcessById([int]$Metadata.processId)
        try {
            if ($process.HasExited) { return $false }
            if (-not [string]::IsNullOrWhiteSpace([string]$Metadata.processStartTimeUtc)) {
                $expected = [DateTime]::Parse([string]$Metadata.processStartTimeUtc).ToUniversalTime()
                $actual = $process.StartTime.ToUniversalTime()
                if ([Math]::Abs(($actual - $expected).TotalSeconds) -gt 2) { return $false }
            }
            return $true
        }
        finally {
            $process.Dispose()
        }
    }
    catch [System.ArgumentException] {
        return $false
    }
    catch [System.InvalidOperationException] {
        return $false
    }
    catch {
        # If process details cannot be read, treat the owner as alive. Cleanup must
        # prefer leaving a root in place over removing trust from a live session.
        return $true
    }
}

function Read-MihariJsonFile {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    $raw = [System.IO.File]::ReadAllText($Path, [System.Text.Encoding]::UTF8)
    if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
    return ($raw | ConvertFrom-Json -ErrorAction Stop)
}

function Write-MihariJsonFileAtomic {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Value
    )

    $directory = [System.IO.Path]::GetDirectoryName($Path)
    if (-not [System.IO.Directory]::Exists($directory)) {
        [void][System.IO.Directory]::CreateDirectory($directory)
    }
    $temporaryPath = $Path + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
    $backupPath = $Path + '.' + [Guid]::NewGuid().ToString('N') + '.bak'
    $json = ConvertTo-Json -InputObject $Value -Depth 8 -Compress
    $encoding = [System.Text.UTF8Encoding]::new($false)
    try {
        [System.IO.File]::WriteAllText($temporaryPath, $json + [Environment]::NewLine, $encoding)
        if ([System.IO.File]::Exists($Path)) {
            [System.IO.File]::Replace($temporaryPath, $Path, $backupPath)
        }
        else {
            [System.IO.File]::Move($temporaryPath, $Path)
        }
    }
    finally {
        if ([System.IO.File]::Exists($temporaryPath)) {
            [System.IO.File]::Delete($temporaryPath)
        }
        if ([System.IO.File]::Exists($backupPath)) {
            [System.IO.File]::Delete($backupPath)
        }
    }
}

function Get-MihariSafeProxyEndpoint {
    param([string]$Proxy)

    if ([string]::IsNullOrWhiteSpace($Proxy)) { return $null }
    $candidate = $Proxy.Trim()
    if ($candidate -notmatch '^[a-zA-Z][a-zA-Z0-9+.-]*://') {
        $candidate = 'http://' + $candidate
    }
    $uri = $null
    if (-not [Uri]::TryCreate($candidate, [UriKind]::Absolute, [ref]$uri)) {
        return '[configured; endpoint unavailable]'
    }
    if ([string]::IsNullOrWhiteSpace($uri.Host)) { return '[configured; endpoint unavailable]' }
    $proxyHostName = $uri.Host
    if ($proxyHostName.Contains(':') -and -not $proxyHostName.StartsWith('[')) { $proxyHostName = '[' + $proxyHostName + ']' }
    if ($uri.IsDefaultPort) { return $proxyHostName }
    return $proxyHostName + ':' + $uri.Port
}

function Test-MihariSessionCATrust {
    param($Session)

    if ($null -eq $Session.CA) { return $false }
    $store = [System.Security.Cryptography.X509Certificates.X509Store]::new(
        [System.Security.Cryptography.X509Certificates.StoreName]::Root,
        [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
    )
    try {
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
        foreach ($certificate in $store.Certificates) {
            if ($certificate.Thumbprint -eq [string]$Session.CA.Thumbprint -and
                $certificate.Subject -eq [string]$Session.CA.Subject) {
                return $true
            }
        }
        return $false
    }
    finally { $store.Close() }
}

function Set-MihariSessionMode {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Session,
        [Parameter(Mandatory = $true)][ValidateSet('Inspect', 'Tunnel')][string]$Mode
    )

    if ([string]$Session.Status -ne 'running') {
        throw 'Mihari mode can only change while both session listeners are running.'
    }
    [System.Threading.Monitor]::Enter($Session.StateLock)
    try {
        $previous = [string]$Session.Mode
        if ($previous -eq $Mode) { return $previous }
        if ($Mode -eq 'Inspect') {
            $capability = Test-MihariCapability -Mode Inspect
            if (-not $capability.Available) {
                throw ('Mihari Inspect mode is unavailable: {0}' -f $capability.Reason)
            }
            if ($null -eq $Session.CA) {
                $Session.CA = New-MihariCA -SessionId ([string]$Session.Id)
                # Persist exact CA identity before adding public trust.
                [void](Save-MihariSessionMetadata -Session $Session)
            }
            if (-not (Test-MihariSessionCATrust -Session $Session)) {
                $Session.PublicCARoot = Install-MihariCARoot -CA $Session.CA
            }
            if (-not (Test-MihariSessionCATrust -Session $Session)) {
                throw 'The session CA is not trusted; Inspect was not enabled.'
            }
        }
        $Session.Mode = $Mode
        [void](Save-MihariSessionMetadata -Session $Session)
        if ($null -ne $Session.Writer) {
            $null = Write-MihariEvent -Session $Session -ConnectionId 'session' -Stage 'session.mode' -Outcome 'changed' -ElapsedMs 0 -Data @{
                previousMode = $previous; mode = $Mode; caTrusted = (Test-MihariSessionCATrust -Session $Session)
            }
        }
        return $Mode
    }
    finally { [System.Threading.Monitor]::Exit($Session.StateLock) }
}

function Get-MihariSessionMetadataObject {
    param([Parameter(Mandatory = $true)]$Session)

    $caThumbprint = $null
    $caSubject = $null
    if ($null -ne $Session.CA) {
        if ($Session.CA.PSObject.Properties['Thumbprint']) { $caThumbprint = [string]$Session.CA.Thumbprint }
        if ($Session.CA.PSObject.Properties['Subject']) { $caSubject = [string]$Session.CA.Subject }
    }

    $actualPort = $null
    if ($null -ne $Session.ActualPort) { $actualPort = [int]$Session.ActualPort }
    $actualManagementPort = $null
    if ($null -ne $Session.ActualManagementPort) { $actualManagementPort = [int]$Session.ActualManagementPort }
    $proxyEndpoint = $null
    if ($null -ne $actualPort -and $actualPort -gt 0) { $proxyEndpoint = 'http://127.0.0.1:' + $actualPort }
    $uiEndpoint = $null
    if ($null -ne $actualManagementPort -and $actualManagementPort -gt 0) { $uiEndpoint = 'http://127.0.0.1:' + $actualManagementPort + '/' }
    $data = [ordered]@{
        schemaVersion = 1
        sessionId = [string]$Session.Id
        startedAtUtc = [string]$Session.StartedAtUtc
        stoppedAtUtc = $Session.StoppedAtUtc
        processId = [int]$Session.ProcessId
        processStartTimeUtc = [string]$Session.ProcessStartTimeUtc
        mode = [string]$Session.Mode
        status = [string]$Session.Status
        bindAddress = '127.0.0.1'
        port = [int]$Session.Port
        actualPort = $actualPort
        managementPort = [int]$Session.ManagementPort
        actualManagementPort = $actualManagementPort
        proxyEndpoint = $proxyEndpoint
        uiEndpoint = $uiEndpoint
        proxyHeartbeatUtc = $Session.ProxyHeartbeatUtc
        managementHeartbeatUtc = $Session.ManagementHeartbeatUtc
        activeConnections = [int]$Session.ActiveConnectionCount
        outputDirectory = [string]$Session.OutputDirectory
        eventsPath = [string]$Session.EventsPath
        stopPath = [string]$Session.StopPath
        reportJsonPath = [System.IO.Path]::Combine([string]$Session.OutputDirectory, 'report.json')
        reportTextPath = [System.IO.Path]::Combine([string]$Session.OutputDirectory, 'report.txt')
        caThumbprint = $caThumbprint
        caSubject = $caSubject
        caTrusted = $(if ($null -ne $Session.CA) { Test-MihariSessionCATrust -Session $Session } else { $false })
        upstreamProxy = Get-MihariSafeProxyEndpoint -Proxy ([string]$Session.UpstreamProxy)
        upstreamSnapshotCapturedAtUtc = $(if ($null -ne $Session.PlatformProxySnapshot) { [string]$Session.PlatformProxySnapshot.CapturedAtUtc } else { $null })
        maxWorkers = [int]$Session.MaxWorkers
        error = $Session.Error
        managementError = $Session.ManagementError
        cleanupErrors = @($Session.CleanupErrors)
    }
    return $data
}

function Save-MihariSessionMetadata {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Session)

    if ($null -eq $Session -or [string]::IsNullOrWhiteSpace([string]$Session.OutputDirectory)) {
        throw 'A session with an output directory is required.'
    }
    [System.Threading.Monitor]::Enter($Session.StateLock)
    try {
        [System.Threading.Monitor]::Enter($Session.MetadataLock)
        try {
            if ($null -ne $Session.ActualPort -and $null -ne $Session.ActualManagementPort -and [string]$Session.Status -eq 'starting') {
                $Session.Status = 'running'
            }
            $document = Get-MihariSessionMetadataObject -Session $Session
            Write-MihariJsonFileAtomic -Path ([string]$Session.MetadataPath) -Value $document
            Write-MihariJsonFileAtomic -Path ([string]$Session.ActivePath) -Value $document
        }
        finally { [System.Threading.Monitor]::Exit($Session.MetadataLock) }
    }
    finally { [System.Threading.Monitor]::Exit($Session.StateLock) }
    return $document
}

function New-MihariSession {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateSet('Tunnel', 'Inspect')][string]$Mode,
        [Parameter(Mandatory = $true)][ValidateRange(0, 65535)][int]$Port,
        [ValidateRange(0, 65535)][int]$ManagementPort = 0,
        [string]$UpstreamProxy,
        [string]$OutputRoot,
        [ValidateRange(1, 128)][int]$MaxWorkers = 16
    )

    if (-not (Get-Command Test-MihariCapability -ErrorAction SilentlyContinue)) {
        throw 'Mihari compatibility checks are unavailable.'
    }
    $capability = Test-MihariCapability -Mode $Mode
    if (-not $capability.Available) {
        throw ('Mihari {0} mode is unavailable: {1}' -f $Mode, $capability.Reason)
    }

    $root = Get-MihariDefaultOutputRoot -OutputRoot $OutputRoot
    [void][System.IO.Directory]::CreateDirectory($root)
    $activePath = Join-Path $root 'active-session.json'
    $lockPath = Join-Path $root '.session-start.lock'
    $lock = $null
    try {
        $lock = [System.IO.File]::Open($lockPath, [System.IO.FileMode]::OpenOrCreate, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
    }
    catch {
        throw ('Another Mihari session may be starting in output root {0}: {1}' -f $root, $_.Exception.Message)
    }

    try {
        $prior = Read-MihariJsonFile -Path $activePath
        $priorFinished = $null -ne $prior -and (
            [string]$prior.status -like 'stopped*' -or
            [string]$prior.status -eq 'start_failed' -or
            [string]$prior.status -eq 'orphaned_cleaned'
        )
        if ($null -ne $prior -and -not $priorFinished -and (Get-MihariSessionProcessAlive -Metadata $prior)) {
            throw ('Mihari session {0} is still owned by process {1}.' -f $prior.sessionId, $prior.processId)
        }
        if (Get-Command Invoke-MihariCleanup -ErrorAction SilentlyContinue) {
            # Repair only roots whose exact Mihari ownership metadata proves they
            # belong to a previous process. The cleanup function refuses all others.
            $null = Invoke-MihariCleanup -OutputRoot $root
        }

        $id = [Guid]::NewGuid().ToString('N').ToLowerInvariant()
        $outputDirectory = Join-Path $root $id
        [void][System.IO.Directory]::CreateDirectory($outputDirectory)
        $metadataPath = Join-Path $outputDirectory 'session.json'
        $eventsPath = Join-Path $outputDirectory 'events.jsonl'
        $stopPath = Join-Path $outputDirectory 'stop.request'
        $started = [DateTime]::UtcNow.ToString('o')
        $process = [System.Diagnostics.Process]::GetCurrentProcess()
        try { $processStart = $process.StartTime.ToUniversalTime().ToString('o') }
        finally { $process.Dispose() }
        $sessionScriptPath = [string]$MyInvocation.MyCommand.ScriptBlock.File
        if ([string]::IsNullOrWhiteSpace($sessionScriptPath)) {
            throw 'Could not locate Session.ps1 to configure the connection worker source path.'
        }
        $sessionSourceDirectory = Split-Path -Parent $sessionScriptPath
        $sourceRoot = [System.IO.Path]::GetFullPath((Split-Path -Parent $sessionSourceDirectory))
        if (-not (Get-Command New-MihariUpstreamSnapshot -ErrorAction SilentlyContinue)) {
            throw 'The upstream route snapshot function is unavailable.'
        }
        $platformProxySnapshot = New-MihariUpstreamSnapshot

        $session = [pscustomobject]@{
            Id = $id
            Mode = $Mode
            Port = $Port
            ActualPort = $null
            ManagementPort = $ManagementPort
            ActualManagementPort = $null
            OutputDirectory = $outputDirectory
            OutputRoot = $root
            EventsPath = $eventsPath
            StopPath = $stopPath
            MetadataPath = $metadataPath
            ActivePath = $activePath
            SourceRoot = $sourceRoot
            MaxWorkers = $MaxWorkers
            UpstreamProxy = $UpstreamProxy
            PlatformProxySnapshot = $platformProxySnapshot
            Writer = $null
            CA = $null
            PublicCARoot = $null
            LeafCache = [hashtable]::Synchronized(@{})
            Cancellation = New-Object System.Threading.CancellationTokenSource
            StateLock = New-Object System.Object
            MetadataLock = New-Object System.Object
            Listener = $null
            ManagementListener = $null
            ManagementError = $null
            ProxyHeartbeatUtc = $null
            ManagementHeartbeatUtc = $null
            ActiveConnectionCount = 0
            WorkerPool = $null
            ProcessId = [int]$PID
            ProcessStartTimeUtc = $processStart
            StartedAtUtc = $started
            StoppedAtUtc = $null
            Status = 'starting'
            Error = $null
            CleanupErrors = @()
        }

        # Persist ownership metadata before placing any CA in the trust store.
        [void](Save-MihariSessionMetadata -Session $session)
        try {
            if (-not (Get-Command New-MihariEventWriter -ErrorAction SilentlyContinue)) {
                throw 'The observation writer is unavailable.'
            }
            $session.Writer = New-MihariEventWriter -Path $eventsPath

            if ($Mode -eq 'Inspect') {
                if (-not (Get-Command New-MihariCA -ErrorAction SilentlyContinue) -or
                    -not (Get-Command Install-MihariCARoot -ErrorAction SilentlyContinue)) {
                    throw 'Inspect mode requires the Mihari certificate runtime.'
                }
                $session.CA = New-MihariCA -SessionId $id
                # Record exact root identity before installing it so cleanup can
                # still identify the root if the process dies immediately after.
                [void](Save-MihariSessionMetadata -Session $session)
                $session.PublicCARoot = Install-MihariCARoot -CA $session.CA
            }
            if (Get-Command Write-MihariEvent -ErrorAction SilentlyContinue) {
                $null = Write-MihariEvent -Session $session -ConnectionId 'session' -RequestId $null -Stage 'session.lifecycle' -Outcome 'created' -ElapsedMs 0 -Data @{ port = $Port }
            }
            [void](Save-MihariSessionMetadata -Session $session)
            return $session
        }
        catch {
            $creationError = $_
            $session.Status = 'start_failed'
            $session.Error = [ordered]@{ type = $creationError.Exception.GetType().FullName; message = 'Session initialization failed.' }
            try {
                if ($null -ne $session.Writer -and (Get-Command Close-MihariEventWriter -ErrorAction SilentlyContinue)) {
                    Close-MihariEventWriter -Writer $session.Writer
                }
            }
            catch { $session.Error['closeWriter'] = $true }
            try {
                if ($null -ne $session.CA) {
                    if (-not (Get-Command Remove-MihariCARoot -ErrorAction SilentlyContinue)) {
                        throw 'The exact-root CA removal function is unavailable.'
                    }
                    [void](Remove-MihariCARoot -Thumbprint ([string]$session.CA.Thumbprint) -Subject ([string]$session.CA.Subject))
                }
            }
            catch { $session.Error['removeCA'] = $true }
            if ($null -ne $session.CA) {
                try { if ($null -ne $session.CA.Certificate) { $session.CA.Certificate.Dispose() } }
                catch { $session.Error['disposeCertificate'] = $true }
                try { if ($null -ne $session.CA.PrivateKey) { $session.CA.PrivateKey.Dispose() } }
                catch { $session.Error['disposePrivateKey'] = $true }
            }
            try { if ($null -ne $session.PublicCARoot) { $session.PublicCARoot.Dispose() } }
            catch { $session.Error['disposePublicCA'] = $true }
            $session.StoppedAtUtc = [DateTime]::UtcNow.ToString('o')
            try { [void](Save-MihariSessionMetadata -Session $session) }
            catch { $session.Error['persistFailure'] = $true }
            throw $creationError
        }
    }
    finally {
        if ($null -ne $lock) { $lock.Dispose() }
    }
}

function Get-MihariPersistedListenerHealth {
    param(
        $Metadata,
        [string]$PortProperty,
        [string]$HeartbeatProperty
    )

    $port = 0
    $listening = $false
    if ([int]::TryParse([string]$Metadata.$PortProperty, [ref]$port) -and $port -gt 0 -and $port -le 65535) {
        try {
            $endpoints = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetActiveTcpListeners()
            foreach ($endpoint in $endpoints) {
                if ($endpoint.Port -eq $port -and [System.Net.IPAddress]::IsLoopback($endpoint.Address)) {
                    $listening = $true
                    break
                }
            }
        }
        catch {
            $listening = $false
        }
    }
    $heartbeatFresh = $false
    $heartbeat = [string]$Metadata.$HeartbeatProperty
    if (-not [string]::IsNullOrWhiteSpace($heartbeat)) {
        $parsed = [DateTime]::MinValue
        if ([DateTime]::TryParse($heartbeat, [ref]$parsed)) {
            $age = ([DateTime]::UtcNow - $parsed.ToUniversalTime()).TotalSeconds
            $heartbeatFresh = $age -ge -5 -and $age -le 5
        }
    }
    return [pscustomobject]@{
        listening = [bool]$listening
        heartbeatFresh = [bool]$heartbeatFresh
        healthy = [bool]($listening -and $heartbeatFresh)
    }
}

function Get-MihariSessionStatus {
    [CmdletBinding()]
    param([string]$OutputRoot)

    $root = Get-MihariDefaultOutputRoot -OutputRoot $OutputRoot
    $activePath = Join-Path $root 'active-session.json'
    $metadata = Read-MihariJsonFile -Path $activePath
    if ($null -eq $metadata) { return $null }
    $id = [string]$metadata.sessionId
    if ($id -notmatch '^[a-fA-F0-9]{32}$') { return $null }
    $expectedDirectory = [System.IO.Path]::GetFullPath((Join-Path $root $id))
    if ([string]$metadata.outputDirectory -ne $expectedDirectory) { return $null }
    $sessionMetadataPath = Join-Path $expectedDirectory 'session.json'
    $sessionMetadata = Read-MihariJsonFile -Path $sessionMetadataPath
    if ($null -eq $sessionMetadata -or [string]$sessionMetadata.sessionId -ne $id) { return $null }
    $alive = Get-MihariSessionProcessAlive -Metadata $sessionMetadata
    Add-Member -InputObject $sessionMetadata -NotePropertyName processAlive -NotePropertyValue $alive -Force
    $proxyHealth = Get-MihariPersistedListenerHealth -Metadata $sessionMetadata -PortProperty 'actualPort' -HeartbeatProperty 'proxyHeartbeatUtc'
    $managementHealth = Get-MihariPersistedListenerHealth -Metadata $sessionMetadata -PortProperty 'actualManagementPort' -HeartbeatProperty 'managementHeartbeatUtc'
    if (-not [string]::IsNullOrWhiteSpace([string]$sessionMetadata.managementError)) {
        $managementHealth.healthy = $false
    }
    Add-Member -InputObject $sessionMetadata -NotePropertyName proxyHealth -NotePropertyValue $proxyHealth -Force
    Add-Member -InputObject $sessionMetadata -NotePropertyName managementHealth -NotePropertyValue $managementHealth -Force
    $currentStatus = [string]$sessionMetadata.status
    $finished = $currentStatus -like 'stopped*' -or $currentStatus -in @('start_failed', 'orphaned', 'orphaned_cleaned')
    if (-not $alive -and -not $finished) {
        Add-Member -InputObject $sessionMetadata -NotePropertyName effectiveStatus -NotePropertyValue 'orphaned' -Force
    }
    elseif ($alive -and $currentStatus -eq 'running' -and (-not $proxyHealth.healthy -or -not $managementHealth.healthy)) {
        Add-Member -InputObject $sessionMetadata -NotePropertyName effectiveStatus -NotePropertyValue 'unhealthy' -Force
    }
    else {
        Add-Member -InputObject $sessionMetadata -NotePropertyName effectiveStatus -NotePropertyValue ([string]$sessionMetadata.status) -Force
    }
    return $sessionMetadata
}

function Request-MihariSessionStop {
    [CmdletBinding()]
    param([string]$OutputRoot)

    $root = Get-MihariDefaultOutputRoot -OutputRoot $OutputRoot
    $status = Get-MihariSessionStatus -OutputRoot $root
    if ($null -eq $status) {
        return [pscustomobject]@{ requested = $false; reason = 'no_session'; sessionId = $null }
    }
    if (-not $status.processAlive) {
        return [pscustomobject]@{ requested = $false; reason = 'session_process_not_running'; sessionId = [string]$status.sessionId }
    }
    if ([string]$status.status -like 'stopped*' -or [string]$status.status -eq 'start_failed') {
        return [pscustomobject]@{ requested = $false; reason = 'session_already_stopped'; sessionId = [string]$status.sessionId }
    }
    $outputDirectory = [System.IO.Path]::GetFullPath((Join-Path $root ([string]$status.sessionId)))
    $stopPath = Join-Path $outputDirectory 'stop.request'
    $request = [ordered]@{
        schemaVersion = 1
        sessionId = [string]$status.sessionId
        requestedAtUtc = [DateTime]::UtcNow.ToString('o')
        requestedByProcessId = [System.Diagnostics.Process]::GetCurrentProcess().Id
    }
    if (-not [System.IO.File]::Exists($stopPath)) {
        Write-MihariJsonFileAtomic -Path $stopPath -Value $request
    }
    $metadataUpdated = $true
    if ([string]$status.status -notlike 'stopped*' -and [string]$status.status -ne 'start_failed') {
        $persisted = Read-MihariJsonFile -Path (Join-Path $outputDirectory 'session.json')
        if ($null -ne $persisted) {
            $persisted.status = 'stop_requested'
            $persisted | Add-Member -NotePropertyName stopRequestedAtUtc -NotePropertyValue ([string]$request.requestedAtUtc) -Force
            try {
                Write-MihariJsonFileAtomic -Path (Join-Path $outputDirectory 'session.json') -Value $persisted
                Write-MihariJsonFileAtomic -Path (Join-Path $root 'active-session.json') -Value $persisted
            }
            catch { $metadataUpdated = $false }
        }
    }
    return [pscustomobject]@{
        requested = $true
        reason = 'stop_signal_written'
        sessionId = [string]$status.sessionId
        stopPath = $stopPath
        metadataUpdated = $metadataUpdated
    }
}

function Clear-MihariSessionLeafCache {
    param([Parameter(Mandatory = $true)]$Session)

    if (Get-Command Clear-MihariLeafCache -ErrorAction SilentlyContinue) {
        Clear-MihariLeafCache -Session $Session
        return
    }
    if ($null -eq $Session.LeafCache) { return }
    $cache = $Session.LeafCache
    $entries = @()
    [System.Threading.Monitor]::Enter($cache.SyncRoot)
    try {
        foreach ($key in @($cache.Keys)) { $entries += $cache[$key] }
        $cache.Clear()
    }
    finally {
        [System.Threading.Monitor]::Exit($cache.SyncRoot)
    }
    $failures = New-Object System.Collections.ArrayList
    foreach ($entry in $entries) {
        if ($null -eq $entry) { continue }
        if ($null -ne $entry.Certificate) {
            try { $entry.Certificate.Dispose() }
            catch { [void]$failures.Add('leaf_certificate') }
        }
        if ($null -ne $entry.PrivateKey) {
            try { $entry.PrivateKey.Dispose() }
            catch { [void]$failures.Add('leaf_private_key') }
        }
    }
    if ($failures.Count -gt 0) {
        throw ('Failed to dispose {0} cached leaf handles.' -f $failures.Count)
    }
}

function Clear-MihariSessionLeafCacheFallback {
    param([Parameter(Mandatory = $true)]$Session)

    if ($null -eq $Session.LeafCache) { return }
    $cache = $Session.LeafCache
    $entries = @()
    [System.Threading.Monitor]::Enter($cache.SyncRoot)
    try {
        foreach ($key in @($cache.Keys)) { $entries += $cache[$key] }
        $cache.Clear()
    }
    finally {
        [System.Threading.Monitor]::Exit($cache.SyncRoot)
    }
    $failures = New-Object System.Collections.ArrayList
    foreach ($entry in $entries) {
        if ($null -eq $entry) { continue }
        if ($null -ne $entry.Certificate) {
            try { $entry.Certificate.Dispose() }
            catch { [void]$failures.Add('leaf_certificate') }
        }
        if ($null -ne $entry.PrivateKey) {
            try { $entry.PrivateKey.Dispose() }
            catch { [void]$failures.Add('leaf_private_key') }
        }
    }
    if ($failures.Count -gt 0) {
        throw ('Failed to dispose {0} cached leaf handles.' -f $failures.Count)
    }
}

function Stop-MihariSession {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Session)

    $cleanupErrors = New-Object System.Collections.ArrayList
    $report = $null
    $Session.Status = 'stopping'
    try { [void](Save-MihariSessionMetadata -Session $Session) }
    catch { [void]$cleanupErrors.Add('Could not persist stopping state.') }

    try {
        if ($null -ne $Session.Writer -and -not $Session.Writer.Closed -and (Get-Command Write-MihariEvent -ErrorAction SilentlyContinue)) {
            $null = Write-MihariEvent -Session $Session -ConnectionId 'session' -RequestId $null -Stage 'session.lifecycle' -Outcome 'stopping' -ElapsedMs 0 -Data @{}
        }
    }
    catch { [void]$cleanupErrors.Add('Could not record the session stop event.') }

    try {
        if ($null -ne $Session.Cancellation) { $Session.Cancellation.Cancel() }
    }
    catch { [void]$cleanupErrors.Add('Could not signal session cancellation.') }

    try {
        if ($null -ne $Session.Listener -and (Get-Command Stop-MihariListener -ErrorAction SilentlyContinue)) {
            Stop-MihariListener -Session $Session
        }
        elseif ($null -ne $Session.Listener) {
            $Session.Listener.Stop()
        }
    }
    catch { [void]$cleanupErrors.Add('Could not stop the listener cleanly.') }

    try {
        if ($null -ne $Session.ManagementListener -and (Get-Command Stop-MihariManagementListener -ErrorAction SilentlyContinue)) {
            $managementStop = Stop-MihariManagementListener -Session $Session
            if ($null -ne $managementStop -and $null -ne $managementStop.errors) {
                foreach ($managementCleanupError in @($managementStop.errors)) {
                    [void]$cleanupErrors.Add(('Management cleanup: {0}' -f [string]$managementCleanupError))
                }
            }
        }
        elseif ($null -ne $Session.ManagementListener) {
            $Session.ManagementListener.Stop()
        }
    }
    catch { [void]$cleanupErrors.Add('Could not stop the management listener cleanly.') }

    if ($null -ne $Session.WorkerPool) {
        try { $Session.WorkerPool.Close() }
        catch { [void]$cleanupErrors.Add('Could not close the connection worker pool cleanly.') }
        try { $Session.WorkerPool.Dispose() }
        catch { [void]$cleanupErrors.Add('Could not dispose the connection worker pool cleanly.') }
    }

    try {
        if ($null -ne $Session.Writer -and (Get-Command Close-MihariEventWriter -ErrorAction SilentlyContinue)) {
            Close-MihariEventWriter -Writer $Session.Writer
        }
        elseif ($null -ne $Session.Writer) {
            throw 'The event writer close function is unavailable.'
        }
    }
    catch { [void]$cleanupErrors.Add('Could not flush and close the event writer.') }
    finally {
        try { Clear-MihariSessionLeafCache -Session $Session }
        catch {
            # Listener shutdown has completed before Stop-MihariSession is called.
            # Retry disposal entry-by-entry so one bad key handle cannot skip the rest.
            try { Clear-MihariSessionLeafCacheFallback -Session $Session }
            catch { [void]$cleanupErrors.Add('Could not dispose every cached host certificate.') }
        }

        try {
            if ($null -ne $Session.CA) {
                if (-not (Get-Command Remove-MihariCARoot -ErrorAction SilentlyContinue)) {
                    throw 'The exact-root CA removal function is unavailable.'
                }
                [void](Remove-MihariCARoot -Thumbprint ([string]$Session.CA.Thumbprint) -Subject ([string]$Session.CA.Subject))
            }
        }
        catch { [void]$cleanupErrors.Add('Could not remove the exact session CA from CurrentUser\Root.') }

        try {
            if ($null -ne $Session.CA) {
                try { if ($null -ne $Session.CA.Certificate) { $Session.CA.Certificate.Dispose() } }
                catch { [void]$cleanupErrors.Add('Could not dispose the session CA certificate handle.') }
                try { if ($null -ne $Session.CA.PrivateKey) { $Session.CA.PrivateKey.Dispose() } }
                catch { [void]$cleanupErrors.Add('Could not dispose the session CA private key handle.') }
            }
        }
        catch { [void]$cleanupErrors.Add('Could not dispose all session CA material.') }
        try { if ($null -ne $Session.PublicCARoot) { $Session.PublicCARoot.Dispose() } }
        catch { [void]$cleanupErrors.Add('Could not dispose the public CA certificate handle.') }

        try { if ($null -ne $Session.Cancellation) { $Session.Cancellation.Dispose() } }
        catch { [void]$cleanupErrors.Add('Could not dispose session cancellation state.') }

        $Session.StoppedAtUtc = [DateTime]::UtcNow.ToString('o')
        $Session.Status = 'stopped'
        if ($cleanupErrors.Count -gt 0) { $Session.Status = 'stopped_with_cleanup_errors' }
        $Session.CleanupErrors = @($cleanupErrors.ToArray())
        try { [void](Save-MihariSessionMetadata -Session $Session) }
        catch { [void]$cleanupErrors.Add('Could not persist final session state.') }
    }

    try {
        if (-not (Get-Command New-MihariReport -ErrorAction SilentlyContinue)) {
            throw 'The report generator is unavailable.'
        }
        $report = New-MihariReport -EventsPath $Session.EventsPath -OutputDirectory $Session.OutputDirectory
    }
    catch {
        [void]$cleanupErrors.Add('Could not generate the session report; the event log was retained.')
    }
    if ($cleanupErrors.Count -gt 0) {
        $Session.CleanupErrors = @($cleanupErrors.ToArray())
        if ($Session.Status -eq 'stopped') { $Session.Status = 'stopped_with_cleanup_errors' }
        try { [void](Save-MihariSessionMetadata -Session $Session) }
        catch { [void]$cleanupErrors.Add('Could not persist report generation status.') }
    }
    return [pscustomobject]@{
        sessionId = [string]$Session.Id
        status = [string]$Session.Status
        cleanupErrors = @($cleanupErrors.ToArray())
        report = $report
    }
}
