param(
    [Parameter(Position = 0)]
    [ValidateSet('start', 'browser', 'status', 'report', 'stop', 'cleanup')]
    [string] $Command = 'status',
    [ValidateSet('Inspect', 'Tunnel')]
    [string] $Mode = 'Inspect',
    [int] $Port = 8899,
    [string] $UpstreamProxy,
    [string] $OutputRoot,
    [int] $MaxWorkers = 16,
    [string] $Url,
    [string] $CompareEventsPath
)

$ErrorActionPreference = 'Stop'
$sourceRoot = Join-Path $PSScriptRoot 'src'
foreach ($name in @('Compatibility', 'Certificate', 'Observation', 'Http', 'Upstream', 'Tls', 'Connection', 'Listener', 'Diagnosis', 'Cleanup', 'Session', 'Browser')) {
    . (Join-Path $sourceRoot ($name + '.ps1'))
}

switch ($Command) {
    'start' {
        $session = New-MihariSession -Mode $Mode -Port $Port -UpstreamProxy $UpstreamProxy -OutputRoot $OutputRoot -MaxWorkers $MaxWorkers
        try {
            Start-MihariListener -Session $session
        }
        finally {
            Stop-MihariSession -Session $session
        }
        break
    }
    'status' {
        Get-MihariSessionStatus -OutputRoot $OutputRoot
        break
    }
    'stop' {
        Request-MihariSessionStop -OutputRoot $OutputRoot
        break
    }
    'browser' {
        $metadata = Get-MihariSessionStatus -OutputRoot $OutputRoot
        if ($null -eq $metadata -or -not $metadata.processAlive -or $metadata.effectiveStatus -ne 'running') {
            throw 'No running Mihari session is available for Edge launch. Start a session and retry.'
        }
        Start-MihariBrowser -SessionMetadata $metadata -Url $Url
        break
    }
    'report' {
        $metadata = Get-MihariSessionStatus -OutputRoot $OutputRoot
        if ($null -eq $metadata) { throw 'No Mihari session is available to report.' }
        New-MihariReport -EventsPath $metadata.eventsPath -OutputDirectory $metadata.outputDirectory -CompareEventsPath $CompareEventsPath
        break
    }
    'cleanup' {
        Invoke-MihariCleanup -OutputRoot $OutputRoot
        break
    }
}
