param()

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'TestSupport.ps1')
$repoRoot = Split-Path $PSScriptRoot -Parent
foreach ($name in @('Case', 'Diagnosis', 'TrafficProjection', 'Evidence', 'Management', 'ManagementV2Evidence')) {
    . (Join-Path (Join-Path $repoRoot 'src') ($name + '.ps1'))
}

function New-MihariManagementV2EvidenceTestRequest {
    param(
        [Parameter(Mandatory = $true)][string]$Method,
        [Parameter(Mandatory = $true)][string]$Path,
        [string]$Query = '',
        [AllowNull()][object]$Body
    )
    $bodyBytes = New-Object byte[] 0
    $headers = @{}
    if ($null -ne $Body) {
        $json = ConvertTo-Json -InputObject $Body -Depth 16 -Compress
        $bodyBytes = [System.Text.UTF8Encoding]::new($false).GetBytes($json)
        $headers['content-type'] = 'application/json; charset=utf-8'
    }
    return [pscustomobject]@{ Method = $Method; Path = $Path; Query = $Query; Headers = $headers; Body = $bodyBytes }
}

function ConvertFrom-MihariManagementV2EvidenceTestResponse {
    param([Parameter(Mandatory = $true)]$Response)
    $text = [System.Text.Encoding]::UTF8.GetString([byte[]]$Response.Body)
    return ($text | ConvertFrom-Json -ErrorAction Stop)
}

function Wait-MihariManagementV2EvidenceTestJob {
    param([Parameter(Mandatory = $true)]$Session, [Parameter(Mandatory = $true)][string]$JobId)
    $deadline = [DateTime]::UtcNow.AddSeconds(20)
    do {
        $response = Invoke-MihariManagementV2EvidenceRequest -Session $Session -Request (New-MihariManagementV2EvidenceTestRequest -Method 'GET' -Path ('/api/v2/evidence/jobs/' + $JobId))
        if ($response.StatusCode -ne 200) { throw ('Evidence job polling failed with HTTP {0}.' -f $response.StatusCode) }
        $value = ConvertFrom-MihariManagementV2EvidenceTestResponse -Response $response
        if ($value.state -in @('completed', 'failed', 'cancelled')) { return $value }
        Start-Sleep -Milliseconds 50
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'Evidence management job did not finish within the local test bound.'
}

function Get-MihariManagementV2EvidenceTestZipText {
    param([Parameter(Mandatory = $true)][string]$Path)
    $stream = [System.IO.File]::OpenRead($Path)
    $archive = $null
    $texts = New-Object 'System.Collections.Generic.List[string]'
    try {
        $archive = [System.IO.Compression.ZipArchive]::new($stream, [System.IO.Compression.ZipArchiveMode]::Read, $false)
        foreach ($entry in $archive.Entries) {
            $entryStream = $entry.Open()
            $reader = $null
            try {
                $reader = New-Object System.IO.StreamReader($entryStream, [System.Text.Encoding]::UTF8)
                $texts.Add($reader.ReadToEnd())
            }
            finally {
                if ($null -ne $reader) { $reader.Dispose() }
                else { $entryStream.Dispose() }
            }
        }
    }
    finally {
        if ($null -ne $archive) { $archive.Dispose() }
        $stream.Dispose()
    }
    return ($texts -join "`n")
}

$temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('mihari-management-evidence-test-' + [Guid]::NewGuid().ToString('N'))
[void][System.IO.Directory]::CreateDirectory($temporaryRoot)
$pool = $null
try {
    $sessionId = [Guid]::NewGuid().ToString('N').ToLowerInvariant()
    $sessionDirectory = [System.IO.Path]::Combine($temporaryRoot, $sessionId)
    [void][System.IO.Directory]::CreateDirectory($sessionDirectory)
    $eventsPath = [System.IO.Path]::Combine($sessionDirectory, 'events.jsonl')
    $metadataPath = [System.IO.Path]::Combine($sessionDirectory, 'session.json')
    $metadata = [pscustomobject]@{ schemaVersion = 1; sessionId = $sessionId; outputDirectory = $sessionDirectory }
    [System.IO.File]::WriteAllText($metadataPath, (ConvertTo-Json -InputObject $metadata -Depth 4 -Compress), [System.Text.UTF8Encoding]::new($false))

    $event = [pscustomobject]@{
        schemaVersion = 2; sequence = 1; timestamp = [DateTime]::UtcNow.ToString('o'); eventId = 'event-' + [Guid]::NewGuid().ToString('N')
        sessionId = $sessionId; connectionId = 'connection-' + [Guid]::NewGuid().ToString('N'); requestId = 'request-' + [Guid]::NewGuid().ToString('N')
        mode = 'Inspect'; stage = 'http.response'; outcome = 'observed'; elapsedMs = 7; source = 'proxy'; coverage = 'observed'; transportLeg = 'upstream'
        data = [pscustomobject]@{
            host = 'intranet.corp'; path = '/classified/customer-77?token=EVENT_QUERY_SECRET'; method = 'GET'; statusCode = 403
            authorization = 'Bearer EVENT_AUTH_SECRET'; cookie = 'EVENT_COOKIE_SECRET'; body = 'EVENT_BODY_SECRET'
        }
    }
    $eventLine = ConvertTo-Json -InputObject $event -Depth 16 -Compress
    [System.IO.File]::WriteAllText($eventsPath, $eventLine + "`n", [System.Text.UTF8Encoding]::new($false))

    $case = New-MihariCase -CaseRoot $temporaryRoot -Title 'Flow for https://intranet.corp/private?secret=CASE_QUERY_SECRET' -SessionReferences @($sessionId)
    $null = Add-MihariCaseNote -CaseRoot $temporaryRoot -CaseId $case.caseId -Text 'Bearer CASE_NOTE_TOKEN_SECRET; see C:\Users\alice\private.txt'
    $trial = New-MihariTrial -CaseRoot $temporaryRoot -CaseId $case.caseId -SessionId $sessionId -Profile ([pscustomobject]@{ mode = 'Inspect'; protocol = 'HTTP/1.1'; debuggerAddress = 'PROFILE_DEBUG_SECRET' }) -ConfigurationRevision '1'
    $null = Add-MihariMarker -CaseRoot $temporaryRoot -TrialId $trial.trialId -Boundary 'point' -Label 'Upload started' -Note 'Bearer ANNOTATION_AUTH_SECRET https://intranet.corp/private/path?token=ANNOTATION_QUERY_SECRET'

    $sourceDirectory = Join-Path $repoRoot 'src'
    $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, 3)
    $pool.Open()

    $session = [pscustomobject]@{
        Id = $sessionId; Mode = 'Inspect'; Profile = 'compatibility'; HttpConnectionPolicy = 'reuse'; ConfigurationRevision = 1
        OutputRoot = $temporaryRoot; OutputDirectory = $sessionDirectory; EventsPath = $eventsPath; StateLock = (New-Object System.Object)
        ManagementWorkerPool = $pool; ManagementListener = (New-Object System.Object); SourceRoot = $repoRoot; ManagementSourceRoot = $sourceDirectory
        UpstreamProxy = $null; PlatformProxySnapshot = $null; MaxWorkers = 4; CA = $null; PublicCARoot = $null
    }

    $previewRequest = New-MihariManagementV2EvidenceTestRequest -Method 'GET' -Path '/api/v2/evidence/preview' -Query ('caseId=' + $case.caseId + '&maskHosts=true&maskUsernames=true&maskPaths=true&maskIdentifiers=true')
    $caseSnapshot = Get-MihariCaseStoreSnapshot -CaseRoot $temporaryRoot
    $activeTrialRecords = @($caseSnapshot.Trials | Where-Object { [string]$_.trialId -eq [string]$trial.trialId })
    Assert-MihariTest -Condition ($activeTrialRecords.Count -eq 1) -Message 'The preview fixture must contain its canonical active trial.'
    Assert-MihariTest -Condition ($activeTrialRecords[0].status -eq 'running' -and $null -eq $activeTrialRecords[0].endedAtUtc -and $null -eq $activeTrialRecords[0].endMarkerId) -Message 'The preview fixture must preserve missing completion time and end marker as null.'
    $previewResponse = Invoke-MihariManagementV2EvidenceRequest -Session $session -Request $previewRequest
    $previewErrorCode = 'none'
    if ($previewResponse.StatusCode -ne 200) {
        try {
            $previewErrorCodeCandidate = [string](ConvertFrom-MihariManagementV2EvidenceTestResponse -Response $previewResponse).error
            if ($previewErrorCodeCandidate -match '^[a-z0-9_]{1,80}$') { $previewErrorCode = $previewErrorCodeCandidate }
            else { $previewErrorCode = 'unrecognized' }
        }
        catch { $previewErrorCode = 'unparseable' }
    }
    Assert-MihariTest -Condition ($previewResponse.StatusCode -eq 200) -Message ('The management preview route must handle an active trial and return a redaction preview (HTTP {0}, error code {1}).' -f [int]$previewResponse.StatusCode, $previewErrorCode)
    $preview = ConvertFrom-MihariManagementV2EvidenceTestResponse -Response $previewResponse
    Assert-MihariTest -Condition ($preview.preview.schemaVersion -eq 1 -and $preview.preview.redacted.Count -ge 3) -Message 'The preview route must expose included and redacted bundle categories.'

    $outsidePath = Join-Path ([System.IO.Path]::GetTempPath()) ('mihari-outside-' + [Guid]::NewGuid().ToString('N') + '.zip')
    $outsideResponse = Invoke-MihariManagementV2EvidenceRequest -Session $session -Request (New-MihariManagementV2EvidenceTestRequest -Method 'POST' -Path '/api/v2/evidence/export' -Body ([pscustomobject]@{ caseId = $case.caseId; destinationPath = $outsidePath }))
    Assert-MihariTest -Condition ($outsideResponse.StatusCode -eq 400) -Message 'Export must reject destinations outside the Mihari output root.'

    $exportResponse = Invoke-MihariManagementV2EvidenceRequest -Session $session -Request (New-MihariManagementV2EvidenceTestRequest -Method 'POST' -Path '/api/v2/evidence/export' -Body ([pscustomobject]@{ caseId = $case.caseId; shareProfile = [pscustomobject]@{ maskHosts = $true; maskUsernames = $true; maskPaths = $true; maskIdentifiers = $true } }))
    Assert-MihariTest -Condition ($exportResponse.StatusCode -eq 202) -Message 'Export must return a bounded asynchronous job reference.'
    $accepted = ConvertFrom-MihariManagementV2EvidenceTestResponse -Response $exportResponse
    Assert-MihariTest -Condition ($accepted.state -eq 'accepted' -and $accepted.progress.totalStages -eq 4) -Message 'The export response must report its accepted state and bounded progress stages.'
    $exportJob = Wait-MihariManagementV2EvidenceTestJob -Session $session -JobId ([string]$accepted.jobId)
    Assert-MihariTest -Condition ($exportJob.state -eq 'completed' -and [System.IO.File]::Exists([string]$exportJob.result.destinationPath)) -Message 'The export job must complete into an output-root bundle.'
    $bundleText = Get-MihariManagementV2EvidenceTestZipText -Path ([string]$exportJob.result.destinationPath)
    foreach ($secret in @('CASE_QUERY_SECRET', 'CASE_NOTE_TOKEN_SECRET', 'EVENT_QUERY_SECRET', 'EVENT_AUTH_SECRET', 'EVENT_COOKIE_SECRET', 'EVENT_BODY_SECRET', 'PROFILE_DEBUG_SECRET', 'ANNOTATION_AUTH_SECRET', 'ANNOTATION_QUERY_SECRET', 'intranet.corp', 'classified/customer-77')) {
        Assert-MihariTest -Condition (-not $bundleText.Contains($secret)) -Message ('The management export must remove secret sentinel {0}.' -f $secret)
    }
    Assert-MihariTest -Condition ($null -eq $session.CA -and $null -eq $session.PublicCARoot) -Message 'Evidence preview and export must not create or trust a CA.'

    $importResponse = Invoke-MihariManagementV2EvidenceRequest -Session $session -Request (New-MihariManagementV2EvidenceTestRequest -Method 'POST' -Path '/api/v2/evidence/import' -Body ([pscustomobject]@{ sourcePath = [string]$exportJob.result.destinationPath }))
    Assert-MihariTest -Condition ($importResponse.StatusCode -eq 202) -Message 'Import must validate in a bounded asynchronous job.'
    $importAccepted = ConvertFrom-MihariManagementV2EvidenceTestResponse -Response $importResponse
    $importJob = Wait-MihariManagementV2EvidenceTestJob -Session $session -JobId ([string]$importAccepted.jobId)
    Assert-MihariTest -Condition ($importJob.state -eq 'completed' -and $importJob.result.readOnly -and $importJob.result.reviewId -match '^case-[0-9a-f]{32}$') -Message 'Import must finish with a read-only review reference.'

    $offlineResponse = Invoke-MihariManagementV2EvidenceRequest -Session $session -Request (New-MihariManagementV2EvidenceTestRequest -Method 'GET' -Path ('/api/v2/evidence/offline/' + $importJob.result.reviewId))
    Assert-MihariTest -Condition ($offlineResponse.StatusCode -eq 200) -Message 'The imported review reference must load through the offline route.'
    $offline = ConvertFrom-MihariManagementV2EvidenceTestResponse -Response $offlineResponse
    Assert-MihariTest -Condition ($offline.readOnly -and -not $offline.capabilities.capture -and -not $offline.capabilities.browserLaunch -and -not $offline.capabilities.trustMutation -and $offline.eventCount -eq 1) -Message 'Offline review must be read-only and retain the imported canonical event.'
    Assert-MihariTest -Condition ($null -eq $session.CA -and $null -eq $session.PublicCARoot) -Message 'Offline review must not create or trust a CA.'

    $retentionResponse = Invoke-MihariManagementV2EvidenceRequest -Session $session -Request (New-MihariManagementV2EvidenceTestRequest -Method 'GET' -Path '/api/v2/evidence/retention' -Query ('scope=imports&olderThanUtc=' + [Uri]::EscapeDataString(([DateTime]::UtcNow.AddDays(1).ToString('o')))))
    Assert-MihariTest -Condition ($retentionResponse.StatusCode -eq 200 -and (ConvertFrom-MihariManagementV2EvidenceTestResponse -Response $retentionResponse).eligible.Count -eq 1) -Message 'Retention preview must only expose verified imported evidence candidates.'
    $unconfirmedCleanup = Invoke-MihariManagementV2EvidenceRequest -Session $session -Request (New-MihariManagementV2EvidenceTestRequest -Method 'POST' -Path '/api/v2/evidence/cleanup' -Body ([pscustomobject]@{ scope = 'imports'; olderThanUtc = [DateTime]::UtcNow.AddDays(1).ToString('o') }))
    Assert-MihariTest -Condition ($unconfirmedCleanup.StatusCode -eq 400) -Message 'Evidence cleanup must reject a request without explicit deletion confirmation.'
    $cleanupResponse = Invoke-MihariManagementV2EvidenceRequest -Session $session -Request (New-MihariManagementV2EvidenceTestRequest -Method 'POST' -Path '/api/v2/evidence/cleanup' -Body ([pscustomobject]@{ scope = 'imports'; olderThanUtc = [DateTime]::UtcNow.AddDays(1).ToString('o'); confirmDeletion = $true }))
    Assert-MihariTest -Condition ($cleanupResponse.StatusCode -eq 200 -and (ConvertFrom-MihariManagementV2EvidenceTestResponse -Response $cleanupResponse).deletedCount -eq 1) -Message 'Confirmed import retention must clean only verified case bundles.'

    Write-Host '[management-evidence] preview, bounded export/import jobs, offline review, retention, and privacy passed'
}
finally {
    if ($null -ne $pool) {
        try { $pool.Close() }
        catch { Write-Warning 'The test evidence runspace pool could not be closed cleanly.' }
        try { $pool.Dispose() }
        catch { Write-Warning 'The test evidence runspace pool could not be disposed cleanly.' }
    }
    if ([System.IO.Directory]::Exists($temporaryRoot)) { [System.IO.Directory]::Delete($temporaryRoot, $true) }
}
