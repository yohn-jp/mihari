param()

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'TestSupport.ps1')
$repoRoot = Split-Path $PSScriptRoot -Parent
foreach ($name in @('Observation', 'BrowserObservation', 'Case', 'Diagnosis', 'TrafficProjection', 'Evidence', 'Management', 'ManagementV2', 'ManagementV2Cases', 'ManagementV2Evidence')) {
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
$browserWriter = $null
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

    $browserImportDirectory = Join-Path $temporaryRoot 'browser-import'
    [void][System.IO.Directory]::CreateDirectory($browserImportDirectory)
    $browserEventsPath = Join-Path $browserImportDirectory 'events.jsonl'
    $browserWriter = New-MihariEventWriter -Path $browserEventsPath
    $browserSession = [pscustomobject]@{
        Id = [Guid]::NewGuid().ToString('N').ToLowerInvariant(); Mode = 'Tunnel'; ConfigurationRevision = 1
        Profile = 'compatibility'; HttpConnectionPolicy = 'reuse'; MaxWorkers = 4
        OutputRoot = $temporaryRoot; OutputDirectory = $browserImportDirectory; EventsPath = $browserEventsPath
        Writer = $browserWriter; StateLock = (New-Object System.Object); ManagementWorkerPool = $pool
        ManagementListener = (New-Object System.Object); ManagementSourceRoot = $sourceDirectory
        ActualManagementPort = 49152; ControlToken = 'browser-import-test-control-token'
    }
    $harPath = Join-Path $browserImportDirectory 'input.har'
    $harJson = @'
{"log":{"version":"1.2","entries":[{"startedDateTime":"2026-01-02T03:04:05Z","time":42.5,"request":{"method":"POST","url":"https://alice:password@example.test/api/upload?token=BROWSER_HAR_QUERY_SECRET","headers":[{"name":"Cookie","value":"BROWSER_HAR_COOKIE_SECRET"}],"postData":{"text":"BROWSER_HAR_BODY_SECRET"}},"response":{"status":201,"httpVersion":"h2","content":{"text":"BROWSER_HAR_RESPONSE_SECRET"}}},{"request":{"method":"GET","url":"data:text/plain,unsupported"}}]}}
'@
    [System.IO.File]::WriteAllText($harPath, $harJson, [System.Text.UTF8Encoding]::new($false))
    $netLogPath = Join-Path $browserImportDirectory 'input-netlog.json'
    $netLogJson = @'
{"constants":{"logEventTypes":{"URL_REQUEST_START_JOB":1,"HTTP_TRANSACTION_READ_HEADERS":2}},"events":[{"type":1,"source":{"id":77,"type":31},"params":{"url":"https://bob:password@example.test/api/list?token=BROWSER_NETLOG_QUERY_SECRET","method":"GET","headers":{"Authorization":"BROWSER_NETLOG_AUTH_SECRET"},"request_body":"BROWSER_NETLOG_BODY_SECRET"}},{"type":2,"source":{"id":77,"type":31},"params":{"url":"https://example.test/api/list?token=BROWSER_NETLOG_QUERY_SECRET","status_code":403,"http_version":"h2","response_body":"BROWSER_NETLOG_RESPONSE_SECRET"}},{"type":999,"source":{"id":77,"type":31},"params":{"url":"https://example.test/ignored"}}]}
'@
    [System.IO.File]::WriteAllText($netLogPath, $netLogJson, [System.Text.UTF8Encoding]::new($false))

    $unguardedRequest = New-MihariManagementV2EvidenceTestRequest -Method 'POST' -Path '/api/v2/browser/import' -Body ([pscustomobject]@{ format = 'har'; path = $harPath })
    $unguardedRequest.Headers['host'] = '127.0.0.1:49152'
    $unguardedRequest.Headers['origin'] = 'http://127.0.0.1:49152'
    $unguardedResponse = Invoke-MihariManagementApiRequest -Session $browserSession -Request $unguardedRequest
    Assert-MihariTest -Condition ($unguardedResponse.StatusCode -eq 403 -and (ConvertFrom-MihariManagementV2EvidenceTestResponse -Response $unguardedResponse).error -eq 'invalid_control_token') -Message 'Browser evidence import must require the management control token.'

    $badOriginRequest = New-MihariManagementV2EvidenceTestRequest -Method 'POST' -Path '/api/v2/browser/import' -Body ([pscustomobject]@{ format = 'har'; path = $harPath })
    $badOriginRequest.Headers['host'] = '127.0.0.1:49152'
    $badOriginRequest.Headers['origin'] = 'https://127.0.0.1:49152'
    $badOriginRequest.Headers['x-mihari-control-token'] = $browserSession.ControlToken
    $badOriginResponse = Invoke-MihariManagementApiRequest -Session $browserSession -Request $badOriginRequest
    Assert-MihariTest -Condition ($badOriginResponse.StatusCode -eq 403 -and (ConvertFrom-MihariManagementV2EvidenceTestResponse -Response $badOriginResponse).error -eq 'invalid_local_origin') -Message 'Browser evidence import must reject a non-local management origin.'

    $badHostRequest = New-MihariManagementV2EvidenceTestRequest -Method 'POST' -Path '/api/v2/browser/import' -Body ([pscustomobject]@{ format = 'har'; path = $harPath })
    $badHostRequest.Headers['host'] = 'example.test:49152'
    $badHostRequest.Headers['origin'] = 'http://example.test:49152'
    $badHostRequest.Headers['x-mihari-control-token'] = $browserSession.ControlToken
    $badHostResponse = Invoke-MihariManagementApiRequest -Session $browserSession -Request $badHostRequest
    Assert-MihariTest -Condition ($badHostResponse.StatusCode -eq 403 -and (ConvertFrom-MihariManagementV2EvidenceTestResponse -Response $badHostResponse).error -eq 'invalid_local_origin') -Message 'Browser evidence import must reject a non-loopback management host.'

    $invalidFormatRequest = New-MihariManagementV2EvidenceTestRequest -Method 'POST' -Path '/api/v2/browser/import' -Body ([pscustomobject]@{ format = 'unknown'; path = $harPath })
    $invalidFormatRequest.Headers['host'] = '127.0.0.1:49152'
    $invalidFormatRequest.Headers['origin'] = 'http://127.0.0.1:49152'
    $invalidFormatRequest.Headers['x-mihari-control-token'] = $browserSession.ControlToken
    $invalidFormatResponse = Invoke-MihariManagementApiRequest -Session $browserSession -Request $invalidFormatRequest
    Assert-MihariTest -Condition ($invalidFormatResponse.StatusCode -eq 400 -and (ConvertFrom-MihariManagementV2EvidenceTestResponse -Response $invalidFormatResponse).error -eq 'browser_import_invalid_format') -Message 'Browser evidence import must reject unsupported format names with a fixed error code.'

    $missingSourceRequest = New-MihariManagementV2EvidenceTestRequest -Method 'POST' -Path '/api/v2/browser/import' -Body ([pscustomobject]@{ format = 'har'; path = (Join-Path $browserImportDirectory 'missing.har') })
    $missingSourceRequest.Headers['host'] = '127.0.0.1:49152'
    $missingSourceRequest.Headers['origin'] = 'http://127.0.0.1:49152'
    $missingSourceRequest.Headers['x-mihari-control-token'] = $browserSession.ControlToken
    $missingSourceResponse = Invoke-MihariManagementApiRequest -Session $browserSession -Request $missingSourceRequest
    Assert-MihariTest -Condition ($missingSourceResponse.StatusCode -eq 404 -and (ConvertFrom-MihariManagementV2EvidenceTestResponse -Response $missingSourceResponse).error -eq 'browser_import_source_not_found') -Message 'Browser evidence import must return a fixed missing-file error without exposing the path.'
    $missingSourceResponseText = [System.Text.Encoding]::UTF8.GetString([byte[]]$missingSourceResponse.Body)
    Assert-MihariTest -Condition (-not $missingSourceResponseText.Contains((Join-Path $browserImportDirectory 'missing.har'))) -Message 'Browser import errors must not echo the selected local file path.'

    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
        $networkPath = '\\example.test\share\BROWSER_UNC_PATH_SECRET.har'
        $networkPathRequest = New-MihariManagementV2EvidenceTestRequest -Method 'POST' -Path '/api/v2/browser/import' -Body ([pscustomobject]@{ format = 'har'; path = $networkPath })
        $networkPathRequest.Headers['host'] = '127.0.0.1:49152'
        $networkPathRequest.Headers['origin'] = 'http://127.0.0.1:49152'
        $networkPathRequest.Headers['x-mihari-control-token'] = $browserSession.ControlToken
        $networkPathResponse = Invoke-MihariManagementApiRequest -Session $browserSession -Request $networkPathRequest
        $networkPathResponseText = [System.Text.Encoding]::UTF8.GetString([byte[]]$networkPathResponse.Body)
        Assert-MihariTest -Condition ($networkPathResponse.StatusCode -eq 400 -and (ConvertFrom-MihariManagementV2EvidenceTestResponse -Response $networkPathResponse).error -eq 'browser_import_invalid_input' -and -not $networkPathResponseText.Contains('BROWSER_UNC_PATH_SECRET')) -Message 'Browser import must reject network paths without attempting network file access or echoing them.'
    }

    $harImportRequest = New-MihariManagementV2EvidenceTestRequest -Method 'POST' -Path '/api/v2/browser/import' -Body ([pscustomobject]@{ format = 'har'; path = $harPath })
    $harImportRequest.Headers['host'] = '127.0.0.1:49152'
    $harImportRequest.Headers['origin'] = 'http://127.0.0.1:49152'
    $harImportRequest.Headers['x-mihari-control-token'] = $browserSession.ControlToken
    $harImportResponse = Invoke-MihariManagementApiRequest -Session $browserSession -Request $harImportRequest
    Assert-MihariTest -Condition ($harImportResponse.StatusCode -eq 202) -Message 'HAR import must start as a bounded asynchronous management job.'
    $harAccepted = ConvertFrom-MihariManagementV2EvidenceTestResponse -Response $harImportResponse
    Assert-MihariTest -Condition ($harAccepted.operation -eq 'browser-import' -and $harAccepted.state -eq 'accepted' -and $harAccepted.progress.totalStages -eq 2) -Message 'HAR import must expose its accepted job and bounded progress.'
    $harJob = Wait-MihariManagementV2EvidenceTestJob -Session $browserSession -JobId ([string]$harAccepted.jobId)
    Assert-MihariTest -Condition ($harJob.state -eq 'completed' -and $harJob.result.source -eq 'import' -and $harJob.result.format -eq 'HAR' -and $harJob.result.supported -and $harJob.result.sourceIdentity -match '^[0-9a-f]{32}$' -and $harJob.result.sourceVersion -eq 'har-1.2' -and $harJob.result.importedCount -eq 1 -and $harJob.result.unsupportedCount -eq 1 -and $harJob.result.coverage -eq 'partial') -Message 'HAR job status must report safe source identity/version, import counts, and coverage.'

    $netLogImportRequest = New-MihariManagementV2EvidenceTestRequest -Method 'POST' -Path '/api/v2/browser/import' -Body ([pscustomobject]@{ format = 'netlog'; path = $netLogPath })
    $netLogImportRequest.Headers['host'] = '127.0.0.1:49152'
    $netLogImportRequest.Headers['origin'] = 'http://127.0.0.1:49152'
    $netLogImportRequest.Headers['x-mihari-control-token'] = $browserSession.ControlToken
    $netLogImportResponse = Invoke-MihariManagementApiRequest -Session $browserSession -Request $netLogImportRequest
    Assert-MihariTest -Condition ($netLogImportResponse.StatusCode -eq 202) -Message 'NetLog import must start as a bounded asynchronous management job.'
    $netLogAccepted = ConvertFrom-MihariManagementV2EvidenceTestResponse -Response $netLogImportResponse
    $netLogJob = Wait-MihariManagementV2EvidenceTestJob -Session $browserSession -JobId ([string]$netLogAccepted.jobId)
    Assert-MihariTest -Condition ($netLogJob.state -eq 'completed' -and $netLogJob.result.source -eq 'import' -and $netLogJob.result.format -eq 'Chromium NetLog JSON' -and $netLogJob.result.supported -and $netLogJob.result.sourceIdentity -match '^[0-9a-f]{32}$' -and $netLogJob.result.sourceVersion -eq 'chromium-netlog-json-recognized-events-v1' -and $netLogJob.result.importedCount -eq 2 -and $netLogJob.result.unsupportedCount -eq 1 -and $netLogJob.result.coverage -eq 'partial') -Message 'NetLog job status must report safe source identity/version, import counts, and coverage.'

    $browserEventStream = New-Object System.IO.FileStream($browserEventsPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    try {
        $browserEventReader = New-Object System.IO.StreamReader($browserEventStream, [System.Text.Encoding]::UTF8)
        try { $browserEventText = $browserEventReader.ReadToEnd() }
        finally { $browserEventReader.Dispose() }
    }
    finally { $browserEventStream.Dispose() }
    $browserEvents = @($browserEventText -split '\r?\n' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { ConvertFrom-Json -InputObject $_ })
    Assert-MihariTest -Condition ($browserEvents.Count -eq 3 -and @($browserEvents | Where-Object { $_.source -eq 'import' -and $_.stage -eq 'browser.network.request' }).Count -eq 3) -Message 'Browser import must append sanitized import-provenance facts through the canonical event writer.'
    Assert-MihariTest -Condition ($browserEvents[0].data.path -eq '/api/upload' -and $browserEvents[0].data.protocol -eq 'h2' -and $browserEvents[0].data.statusCode -eq 201 -and $browserEvents[1].data.path -eq '/api/list' -and $null -eq $browserEvents[1].data.statusCode -and $browserEvents[2].data.statusCode -eq 403 -and $browserEvents[2].data.protocol -eq 'h2') -Message 'Browser import must retain observed URL, status, and protocol facts without inventing a response for the NetLog start event.'
    Assert-MihariTest -Condition ($browserEvents[0].sourceIdentity -eq $harJob.result.sourceIdentity -and $browserEvents[0].sourceVersion -eq $harJob.result.sourceVersion) -Message 'Job metadata must use the same import source identity and parser version as canonical facts.'
    $browserImportText = $browserEventText + (ConvertTo-Json -InputObject @($harAccepted, $harJob.result, $netLogJob.result) -Depth 8 -Compress)
    foreach ($secret in @('BROWSER_HAR_QUERY_SECRET', 'BROWSER_HAR_COOKIE_SECRET', 'BROWSER_HAR_BODY_SECRET', 'BROWSER_HAR_RESPONSE_SECRET', 'BROWSER_NETLOG_QUERY_SECRET', 'BROWSER_NETLOG_AUTH_SECRET', 'BROWSER_NETLOG_BODY_SECRET', 'BROWSER_NETLOG_RESPONSE_SECRET', 'browser-import-test-control-token', 'password', $harPath, $netLogPath)) {
        Assert-MihariTest -Condition (-not $browserImportText.Contains($secret)) -Message 'Browser import results and canonical events must exclude raw paths, credentials, queries, and bodies.'
    }

    Write-Host '[management-evidence] preview, bounded export/import jobs, offline review, retention, and privacy passed'
}
finally {
    if ($null -ne $pool) {
        try { $pool.Close() }
        catch { Write-Warning 'The test evidence runspace pool could not be closed cleanly.' }
        try { $pool.Dispose() }
        catch { Write-Warning 'The test evidence runspace pool could not be disposed cleanly.' }
    }
    if ($null -ne $browserWriter) {
        try { Close-MihariEventWriter -Writer $browserWriter }
        catch { Write-Warning 'The test browser import event writer could not be closed cleanly.' }
    }
    if ([System.IO.Directory]::Exists($temporaryRoot)) { [System.IO.Directory]::Delete($temporaryRoot, $true) }
}
