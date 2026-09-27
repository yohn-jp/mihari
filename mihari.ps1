param(
    [Parameter(Position = 0)]
    [ValidateSet('help', 'start', 'browser', 'status', 'report', 'stop', 'cleanup')]
    [string] $Command = 'help',
    [ValidateSet('Inspect', 'Tunnel')]
    [string] $Mode = 'Inspect',
    [ValidateSet('compatibility', 'http2-observe', 'http2-inspect')]
    [string] $Profile = 'compatibility',
    [ValidateSet('reuse', 'close')]
    [string] $HttpConnectionPolicy = 'reuse',
    [int] $Port = 8899,
    [int] $UiPort = 0,
    [string] $UpstreamProxy,
    [string] $OutputRoot,
    [int] $MaxWorkers = 16,
    [string] $Url,
    [string] $CompareEventsPath
)

$ErrorActionPreference = 'Stop'
$sourceRoot = Join-Path $PSScriptRoot 'src'
foreach ($name in @('Compatibility', 'Certificate', 'Observation', 'Http', 'Hpack', 'Http2', 'Http2Tls', 'Upstream', 'Tls', 'Environment', 'Connection', 'Listener', 'Diagnosis', 'Comparison', 'TrafficProjection', 'Case', 'Dependencies', 'Evidence', 'Cleanup', 'Session', 'BrowserObservation', 'Browser', 'ManagementProjection', 'ManagementUi', 'Management', 'ManagementV2', 'Cli')) {
    . (Join-Path $sourceRoot ($name + '.ps1'))
}

switch ($Command) {
    'help' {
        Get-MihariHelpText
        break
    }
    'start' {
        $session = New-MihariSession -Mode $Mode -Profile $Profile -HttpConnectionPolicy $HttpConnectionPolicy -Port $Port -ManagementPort $UiPort -UpstreamProxy $UpstreamProxy -OutputRoot $OutputRoot -MaxWorkers $MaxWorkers
        try {
            Start-MihariListener -Session $session -OnReady {
                param($readySession)
                [void](Start-MihariManagementListener -Session $readySession)
                [void](Save-MihariSessionMetadata -Session $readySession)
                Format-MihariStartMessage -Session $readySession
            }
        }
        finally {
            $final = Stop-MihariSession -Session $session
            Format-MihariFinalStop -Result $final
        }
        break
    }
    'status' {
        $metadata = Get-MihariSessionStatus -OutputRoot $OutputRoot
        Format-MihariStatus -Metadata $metadata
        break
    }
    'stop' {
        $result = Request-MihariSessionStop -OutputRoot $OutputRoot
        Format-MihariStopResult -Result $result
        break
    }
    'browser' {
        $metadata = Get-MihariSessionStatus -OutputRoot $OutputRoot
        if ($null -eq $metadata -or -not $metadata.processAlive -or $metadata.effectiveStatus -ne 'running') {
            throw 'No running Mihari session is available for Edge launch. Start a session and retry.'
        }
        $result = Start-MihariBrowser -SessionMetadata $metadata -Url $Url
        Format-MihariBrowserResult -Result $result
        break
    }
    'report' {
        $metadata = Get-MihariSessionStatus -OutputRoot $OutputRoot
        if ($null -eq $metadata) { throw 'No Mihari session is available to report.' }
        $report = New-MihariReport -EventsPath $metadata.eventsPath -OutputDirectory $metadata.outputDirectory -CompareEventsPath $CompareEventsPath
        Format-MihariReportResult -Report $report
        break
    }
    'cleanup' {
        $result = Invoke-MihariCleanup -OutputRoot $OutputRoot
        Format-MihariCleanupResult -Result $result
        break
    }
}
