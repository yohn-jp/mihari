function Get-MihariHelpText {
    return @'
Mihari - Windows HTTP(S) diagnostic proxy

Usage:
  .\mihari.ps1 <command> [options]

Commands:
  help      Show this help.
  start     Start a foreground diagnostic session.
  browser   Launch Microsoft Edge through the active Mihari proxy.
  status    Show the latest session and listener health.
  report    Generate report.json and report.txt from the latest session.
  stop      Request the active foreground session to stop.
  cleanup   Remove stale Mihari-owned session CA trust.

Start options:
  -Mode Inspect|Tunnel    Inspect terminates TLS 1.2; Tunnel relays CONNECT.
  -Port <port>            Loopback listener port. Default: 8899. Use 0 for any free port.
  -UiPort <port>          Management UI loopback port. Default: 0 (free port).
  -UpstreamProxy <uri>    Explicit upstream HTTP proxy override.
  -OutputRoot <path>      Session output root.
  -MaxWorkers <count>     Maximum concurrent connection workers. Default: 16.

Other options:
  browser -Url <url>
  report -CompareEventsPath <events.jsonl>

Examples:
  .\mihari.ps1 start
  .\mihari.ps1 start -Mode Tunnel -Port 8899
  .\mihari.ps1 status
  .\mihari.ps1 browser -Url 'https://example.com/'
  .\mihari.ps1 report
  .\mihari.ps1 stop
  .\mihari.ps1 cleanup

start runs in the foreground. Use another PowerShell window for browser, status, report, or stop.
'@
}

function Format-MihariStartMessage {
    param([Parameter(Mandatory = $true)]$Session)

    return ('Mihari {0} session {1} is running.{2}Proxy: http://127.0.0.1:{3}{2}UI:    http://127.0.0.1:{4}/' -f
        $Session.Mode, $Session.Id, [Environment]::NewLine, [int]$Session.ActualPort, [int]$Session.ActualManagementPort)
}

function Format-MihariFinalStop {
    param([Parameter(Mandatory = $true)]$Result)

    $lines = New-Object 'System.Collections.Generic.List[string]'
    $lines.Add(('Mihari session {0} stopped: {1}' -f $Result.sessionId, $Result.status))
    if ($null -ne $Result.report -and $null -ne $Result.report.files) {
        if (-not [string]::IsNullOrWhiteSpace([string]$Result.report.files.text)) {
            $lines.Add(('  Report: {0}' -f $Result.report.files.text))
        }
    }
    $cleanupCount = @($Result.cleanupErrors).Count
    if ($cleanupCount -gt 0) {
        $lines.Add(('  Cleanup warnings: {0}' -f $cleanupCount))
    }
    return ($lines -join [Environment]::NewLine)
}

function Format-MihariStatus {
    param($Metadata)

    if ($null -eq $Metadata) {
        return 'No Mihari session found. Start one with: .\mihari.ps1 start'
    }

    $status = [string]$Metadata.effectiveStatus
    if ([string]::IsNullOrWhiteSpace($status)) { $status = [string]$Metadata.status }

    $lines = New-Object 'System.Collections.Generic.List[string]'
    $lines.Add('Mihari session')
    $lines.Add(('  Status: {0}' -f $status))
    $lines.Add(('  Mode: {0}' -f [string]$Metadata.mode))
    $lines.Add(('  Session: {0}' -f [string]$Metadata.sessionId))
    if ($Metadata.processAlive) {
        $lines.Add(('  PID: {0}' -f [string]$Metadata.processId))
    }

    $proxyEndpoint = [string]$Metadata.proxyEndpoint
    if ([string]::IsNullOrWhiteSpace($proxyEndpoint)) {
        $fallbackPort = 0
        if ([int]::TryParse([string]$Metadata.actualPort, [ref]$fallbackPort) -and $fallbackPort -gt 0) {
            $proxyEndpoint = 'http://127.0.0.1:' + $fallbackPort
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($proxyEndpoint)) {
        if ($null -ne $Metadata.proxyHealth) {
            $proxyState = $(if ($Metadata.proxyHealth.healthy) { 'healthy' } else { 'unhealthy' })
            $lines.Add(('  Proxy: {0} ({1})' -f $proxyEndpoint, $proxyState))
        }
        else { $lines.Add(('  Proxy: {0}' -f $proxyEndpoint)) }
    }
    if (-not [string]::IsNullOrWhiteSpace([string]$Metadata.uiEndpoint)) {
        $managementState = $(if ($Metadata.managementHealth.healthy) { 'healthy' } else { 'unhealthy' })
        $lines.Add(('  UI: {0} ({1})' -f [string]$Metadata.uiEndpoint, $managementState))
    }
    if (-not [string]::IsNullOrWhiteSpace([string]$Metadata.outputDirectory)) {
        $lines.Add(('  Output: {0}' -f [string]$Metadata.outputDirectory))
    }
    return ($lines -join [Environment]::NewLine)
}

function Format-MihariStopResult {
    param([Parameter(Mandatory = $true)]$Result)

    switch ([string]$Result.reason) {
        'no_session' {
            return 'No Mihari session found.'
        }
        'session_process_not_running' {
            return ('Mihari session {0} is not running. Use ".\mihari.ps1 cleanup" to remove stale CA trust if needed.' -f $Result.sessionId)
        }
        'session_already_stopped' {
            return ('Mihari session {0} is already stopped.' -f $Result.sessionId)
        }
        'stop_signal_written' {
            return ('Stop requested for Mihari session {0}.' -f $Result.sessionId)
        }
        default {
            return ('Mihari stop request result: {0}' -f [string]$Result.reason)
        }
    }
}

function Format-MihariBrowserResult {
    param([Parameter(Mandatory = $true)]$Result)

    if ($Result.Success) {
        return ('Started Microsoft Edge through {0} (PID {1}).' -f $Result.ProxyEndpoint, $Result.Pid)
    }
    if (-not [string]::IsNullOrWhiteSpace([string]$Result.Reason)) {
        return [string]$Result.Reason
    }
    return 'Microsoft Edge was not started.'
}

function Format-MihariReportResult {
    param([Parameter(Mandatory = $true)]$Report)

    $findings = @($Report.findings).Count
    $lines = New-Object 'System.Collections.Generic.List[string]'
    $lines.Add(('Mihari report generated. Findings: {0}' -f $findings))
    if ($null -ne $Report.files) {
        if (-not [string]::IsNullOrWhiteSpace([string]$Report.files.text)) {
            $lines.Add(('  Text: {0}' -f $Report.files.text))
        }
        if (-not [string]::IsNullOrWhiteSpace([string]$Report.files.json)) {
            $lines.Add(('  JSON: {0}' -f $Report.files.json))
        }
    }
    return ($lines -join [Environment]::NewLine)
}

function Format-MihariCleanupResult {
    param([Parameter(Mandatory = $true)]$Result)

    return ('Mihari cleanup complete. Removed: {0}; Refused: {1}; Errors: {2}.' -f [int]$Result.removedCount, @($Result.refused).Count, @($Result.errors).Count)
}
