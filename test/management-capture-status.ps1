$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path $PSScriptRoot -Parent
. (Join-Path $repoRoot 'src/Management.ps1')
. (Join-Path $repoRoot 'src/ManagementUi.ps1')

function Assert-MihariCaptureStatusTest {
    param([bool] $Condition, [string] $Message)
    if (-not $Condition) { throw ('ASSERTION FAILED: ' + $Message) }
}

function Get-MihariCaptureStatusFixture {
    param([Parameter(Mandatory = $true)]$Session, [string]$Path = '/api/status')
    $headers = @{ host = ('127.0.0.1:{0}' -f [int]$Session.ActualManagementPort) }
    $request = [pscustomobject]@{ Method = 'GET'; Path = $Path; Query = ''; Headers = $headers; Body = [byte[]]@() }
    $response = Invoke-MihariManagementApiRequest -Session $Session -Request $request
    $json = [System.Text.UTF8Encoding]::new($false).GetString([byte[]]$response.Body)
    return (ConvertFrom-Json -InputObject $json -ErrorAction Stop)
}

$proxyListener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
$managementListener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
try {
    $proxyListener.Start()
    $managementListener.Start()
    $now = [DateTime]::UtcNow.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
    $proxyPort = ([System.Net.IPEndPoint]$proxyListener.LocalEndpoint).Port
    $managementPort = ([System.Net.IPEndPoint]$managementListener.LocalEndpoint).Port
    $session = [pscustomobject]@{
        Id = 'capture-status-fixture'
        Status = 'running'
        Mode = 'Tunnel'
        Profile = 'compatibility'
        ProfileVersion = 1
        HttpConnectionPolicy = 'persistent'
        ConfigurationRevision = 0
        StartedAtUtc = $now
        ProcessId = $PID
        Listener = $proxyListener
        ManagementListener = $managementListener
        ProxyHeartbeatUtc = $now
        ManagementHeartbeatUtc = $now
        ActualPort = $proxyPort
        ActualManagementPort = $managementPort
        ActiveConnectionCount = 0
        CleanupErrors = @()
        CaptureState = [pscustomobject]@{
            Incomplete = $false
            Reason = $null
            AtUtc = $null
            EvidenceByteLimit = [long]536870912
            QueueCapacity = 8
            QueuePeak = 0
            SaturationCount = [long]0
        }
    }

    $initial = Get-MihariCaptureStatusFixture -Session $session
    Assert-MihariCaptureStatusTest ($initial.effectiveStatus -eq 'running' -and
        $initial.proxyHealth.healthy -and $initial.managementHealth.healthy -and
        $initial.capture.available -and -not $initial.capture.incomplete) 'A complete capture state must not change healthy listener status.'
    $initialHealth = Get-MihariCaptureStatusFixture -Session $session -Path '/api/health'
    Assert-MihariCaptureStatusTest ($initialHealth.healthy) 'Health must be positive only when listeners and capture state are available and complete.'

    $completeCapture = $session.CaptureState
    $session.PSObject.Properties.Remove('CaptureState')
    $legacyStatus = Get-MihariCaptureStatusFixture -Session $session
    $legacyHealth = Get-MihariCaptureStatusFixture -Session $session -Path '/api/health'
    Assert-MihariCaptureStatusTest (-not $legacyStatus.capture.available -and $legacyStatus.effectiveStatus -eq 'running' -and $legacyHealth.healthy) 'Legacy status without a capture-state field must report capture unknown without changing healthy listener state.'
    $session | Add-Member -NotePropertyName CaptureState -NotePropertyValue $completeCapture

    $session.CaptureState.Incomplete = $true
    $session.CaptureState.Reason = 'evidence_limit_reached'
    $session.CaptureState.AtUtc = $now
    $session.CaptureState.EvidenceByteLimit = [long]4096
    $session.CaptureState.QueuePeak = 7
    $session.CaptureState.SaturationCount = [long]2
    $status = Get-MihariCaptureStatusFixture -Session $session
    Assert-MihariCaptureStatusTest ($status.effectiveStatus -eq 'unhealthy' -and
        $status.session.effectiveStatus -eq 'unhealthy') 'Persistent capture loss must mark the live session status unhealthy even when both listeners are healthy.'
    Assert-MihariCaptureStatusTest ($status.capture.incomplete -and
        $status.capture.reason -eq 'evidence_limit_reached' -and
        $status.capture.evidenceByteLimit -eq 4096 -and $status.capture.queueCapacity -eq 8 -and
        $status.capture.queuePeak -eq 7 -and $status.capture.saturationCount -eq 2 -and
        -not [string]::IsNullOrWhiteSpace([string]$status.capture.atUtc)) 'The API must expose only the safe persistent capture state and its measured limits.'
    Assert-MihariCaptureStatusTest (@($status.warnings | Where-Object { $_.code -eq 'capture_incomplete' -and $_.source -eq 'mihari' }).Count -eq 1 -and
        @($status.errors | Where-Object { $_.code -eq 'capture_incomplete' }).Count -eq 1) 'Capture loss must have a stable tool-health warning code separate from observed traffic outcomes.'
    $unhealthyHealth = Get-MihariCaptureStatusFixture -Session $session -Path '/api/health'
    Assert-MihariCaptureStatusTest (-not $unhealthyHealth.healthy -and $unhealthyHealth.status -eq 'unhealthy' -and
        $unhealthyHealth.capture.incomplete -and @($unhealthyHealth.warnings | Where-Object { $_.code -eq 'capture_incomplete' }).Count -eq 1) 'Health must expose capture incompleteness even while listeners remain healthy.'
    $again = Get-MihariCaptureStatusFixture -Session $session
    Assert-MihariCaptureStatusTest ($again.capture.incomplete -and $again.capture.reason -eq 'evidence_limit_reached') 'Capture loss must persist across status refreshes independently of the event window.'

    $html = Get-MihariManagementUiHtml -ControlToken 'capture-status-test-token'
    Assert-MihariCaptureStatusTest ($html.Contains('id="capture-warning"') -and
        $html.Contains('function paintCaptureWarning(data)') -and
        $html.Contains("setAttribute('data-capture-state','incomplete')") -and
        $html.Contains('Evidence capture stopped at the configured byte limit.')) 'Overview must render a persistent capture warning from the status API state.'
    Write-Host 'PASS management-capture-status: API completeness state, unhealthy session state, retained counters, and persistent Overview warning'
}
finally {
    $proxyListener.Stop()
    $managementListener.Stop()
}
