$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path $PSScriptRoot -Parent
. (Join-Path $repoRoot 'src/Upstream.ps1')
. (Join-Path $repoRoot 'src/Environment.ps1')
. (Join-Path $repoRoot 'src/Case.ps1')
. (Join-Path $repoRoot 'src/TrafficProjection.ps1')
. (Join-Path $repoRoot 'src/Dependencies.ps1')
. (Join-Path $repoRoot 'src/Diagnosis.ps1')
. (Join-Path $repoRoot 'src/Comparison.ps1')
. (Join-Path $repoRoot 'src/Management.ps1')
. (Join-Path $repoRoot 'src/ManagementV2.ps1')
. (Join-Path $repoRoot 'src/ManagementV2Cases.ps1')

function Assert-MihariManagementCases {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw ('ASSERTION FAILED: ' + $Message) }
}

function New-MihariManagementCasesRequest {
    param([string]$Method, [string]$Path, [string]$Query, [AllowNull()][object]$Body)

    $bytes = [byte[]]@()
    $headers = @{}
    if ($null -ne $Body) {
        $json = ConvertTo-Json -InputObject $Body -Depth 10 -Compress
        $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes($json)
        $headers['content-type'] = 'application/json; charset=utf-8'
    }
    return [pscustomobject]@{ Method = $Method; Path = $Path; Query = $Query; Headers = $headers; Body = $bytes }
}

function Invoke-MihariManagementCasesRoute {
    param([object]$Session, [string]$Method, [string]$Path, [string]$Query, [AllowNull()][object]$Body)

    $request = New-MihariManagementCasesRequest -Method $Method -Path $Path -Query $Query -Body $Body
    $response = Invoke-MihariManagementV2CaseRequest -Session $Session -Request $request
    if ($null -eq $response) { throw ('The case adapter did not handle ' + $Method + ' ' + $Path) }
    $json = [System.Text.UTF8Encoding]::new($false).GetString([byte[]]$response.Body)
    return [pscustomobject]@{ StatusCode = [int]$response.StatusCode; Value = (ConvertFrom-Json -InputObject $json -ErrorAction Stop) }
}

function Add-MihariManagementCasesFixtureEvent {
    param(
        [string]$EventsPath,
        [string]$SessionId,
        [string]$TrialId,
        [string]$EventId,
        [string]$RequestId,
        [long]$Sequence,
        [string]$Mode
    )

    $event = [ordered]@{
        schemaVersion = 2
        timestamp = [DateTime]::UtcNow.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
        eventId = $EventId
        sequence = $Sequence
        sessionId = $SessionId
        connectionId = ('conn-' + $RequestId)
        requestId = $RequestId
        caseId = $null
        trialId = $TrialId
        configurationRevision = 1
        mode = $Mode
        stage = 'http.response'
        outcome = 'success'
        elapsedMs = 8
        source = 'proxy'
        coverage = 'observed'
        data = [ordered]@{
            scheme = 'https'
            host = 'api.example.test'
            port = 443
            path = '/items?token=fixture-secret'
            method = 'GET'
            protocol = 'http/1.1'
            statusCode = 200
        }
    }
    $line = ConvertTo-Json -InputObject ([pscustomobject]$event) -Depth 10 -Compress
    [System.IO.File]::AppendAllText($EventsPath, $line + [Environment]::NewLine, [System.Text.UTF8Encoding]::new($false))
}

$temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('mihari-management-cases-' + [Guid]::NewGuid().ToString('N'))
[void][System.IO.Directory]::CreateDirectory($temporaryRoot)
$sessionId = [Guid]::NewGuid().ToString('N')
$eventsPath = Join-Path $temporaryRoot 'events.jsonl'
[System.IO.File]::WriteAllText($eventsPath, '', [System.Text.UTF8Encoding]::new($false))
$session = [pscustomobject]@{
    Id = $sessionId
    OutputRoot = $temporaryRoot
    OutputDirectory = $temporaryRoot
    EventsPath = $eventsPath
    TrafficProjection = $null
    TrafficProjectionError = $null
    StateLock = (New-Object System.Object)
    Mode = 'Inspect'
    Profile = 'compatibility'
    ProfileVersion = 1
    HttpConnectionPolicy = 'close'
    ConfigurationRevision = 1
    LocalInspectExclusions = @('excluded.example.test')
}

try {
    $domainEmptyCases = Get-MihariCases -CaseRoot $temporaryRoot
    Assert-MihariManagementCases ($domainEmptyCases.items.Count -eq 0 -and $domainEmptyCases.scopeTotal -eq 0 -and
        $null -ne $domainEmptyCases.PSObject.Properties['nextCursor'] -and $null -ne $domainEmptyCases.PSObject.Properties['revision']) 'The domain case list returns a complete empty-page envelope.'

    $listEmpty = Invoke-MihariManagementCasesRoute -Session $session -Method 'GET' -Path '/api/v2/cases' -Query '' -Body $null
    $emptyResponseDiagnostic = 'status=' + [string]$listEmpty.StatusCode + ' value=' + (ConvertTo-Json -InputObject $listEmpty.Value -Depth 8 -Compress)
    Assert-MihariManagementCases ($listEmpty.StatusCode -eq 200 -and $listEmpty.Value.scopeTotal -eq 0) ('GET cases returns the domain list envelope (' + $emptyResponseDiagnostic + ')')
    Assert-MihariManagementCases ($null -ne $listEmpty.Value.PSObject.Properties['nextCursor'] -and $null -ne $listEmpty.Value.PSObject.Properties['revision']) 'case list cursor and revision are present'

    $createdCaseResponse = Invoke-MihariManagementCasesRoute -Session $session -Method 'POST' -Path '/api/v2/cases' -Query '' -Body ([pscustomobject]@{ title = 'Upload fails' })
    Assert-MihariManagementCases ($createdCaseResponse.StatusCode -eq 200 -and $createdCaseResponse.Value.state -eq 'completed') 'POST cases returns explicit completed state'
    $case = $createdCaseResponse.Value.result
    Assert-MihariManagementCases ($case.title -eq 'Upload fails' -and @($case.sessionReferences) -contains $sessionId) 'case creation associates the active session'

    $beforeStart = Invoke-MihariManagementCasesRoute -Session $session -Method 'POST' -Path '/api/v2/trials' -Query '' -Body ([pscustomobject]@{ caseId = $case.caseId })
    Assert-MihariManagementCases ($beforeStart.StatusCode -eq 200 -and $beforeStart.Value.result.status -eq 'running') 'POST trials starts a running trial'
    $beforeTrial = $beforeStart.Value.result
    Assert-MihariManagementCases ($beforeTrial.profile.mode -eq 'Inspect' -and $beforeTrial.profile.protocolProfile -eq 'compatibility') 'trial captures the active mode and protocol profile'
    Assert-MihariManagementCases ($beforeTrial.profile.configurationRevision -eq '1' -and @($beforeTrial.profile.localInspectionExclusions) -contains 'excluded.example.test') 'trial captures configuration revision and local exclusions'
    $environmentPath = Join-Path $temporaryRoot ([string]$beforeTrial.environmentReference.relativePath)
    Assert-MihariManagementCases ([System.IO.File]::Exists($environmentPath) -and $beforeTrial.environmentReference.snapshotId) 'trial references a persisted read-only environment snapshot'

    $marker = Invoke-MihariManagementCasesRoute -Session $session -Method 'POST' -Path ('/api/v2/trials/' + $beforeTrial.trialId + '/markers') -Query '' -Body ([pscustomobject]@{ boundary = 'point'; label = 'Clicked upload'; note = 'Started the reproduction.' })
    Assert-MihariManagementCases ($marker.StatusCode -eq 200 -and $marker.Value.result.boundary -eq 'point' -and $marker.Value.result.source -eq 'operator') 'POST markers stores an operator marker'
    $markerPage = Invoke-MihariManagementCasesRoute -Session $session -Method 'GET' -Path ('/api/v2/trials/' + $beforeTrial.trialId + '/markers') -Query '' -Body $null
    Assert-MihariManagementCases ($markerPage.StatusCode -eq 200 -and $markerPage.Value.scopeTotal -eq 2) 'GET markers includes the domain-created trial start marker and operator marker'

    $note = Invoke-MihariManagementCasesRoute -Session $session -Method 'POST' -Path ('/api/v2/cases/' + $case.caseId + '/notes') -Query '' -Body ([pscustomobject]@{ text = 'Reproduced from the diagnostic profile.'; trialId = $beforeTrial.trialId })
    Assert-MihariManagementCases ($note.StatusCode -eq 200 -and $note.Value.result.source -eq 'operator') 'POST case notes stores an operator annotation'

    Add-MihariManagementCasesFixtureEvent -EventsPath $eventsPath -SessionId $sessionId -TrialId $beforeTrial.trialId -EventId 'case-event-1' -RequestId 'request-1' -Sequence 1 -Mode 'Inspect'
    Add-MihariManagementCasesFixtureEvent -EventsPath $eventsPath -SessionId $sessionId -TrialId $beforeTrial.trialId -EventId 'case-event-2' -RequestId 'request-2' -Sequence 2 -Mode 'Inspect'
    $beforeComplete = Invoke-MihariManagementCasesRoute -Session $session -Method 'POST' -Path ('/api/v2/trials/' + $beforeTrial.trialId + '/complete') -Query '' -Body ([pscustomobject]@{ businessOutcome = 'failed'; note = 'Upload did not complete.' })
    Assert-MihariManagementCases ($beforeComplete.StatusCode -eq 200 -and $beforeComplete.Value.result.operatorBusinessOutcome -eq 'failed') 'trial completion preserves the operator outcome separately'

    $session.Mode = 'Tunnel'
    $session.ConfigurationRevision = 2
    $afterStart = Invoke-MihariManagementCasesRoute -Session $session -Method 'POST' -Path '/api/v2/trials' -Query '' -Body ([pscustomobject]@{ caseId = $case.caseId })
    Assert-MihariManagementCases ($afterStart.StatusCode -eq 200) 'a second controlled trial can start in the active session'
    $afterTrial = $afterStart.Value.result
    Add-MihariManagementCasesFixtureEvent -EventsPath $eventsPath -SessionId $sessionId -TrialId $afterTrial.trialId -EventId 'case-event-3' -RequestId 'request-3' -Sequence 3 -Mode 'Tunnel'
    Add-MihariManagementCasesFixtureEvent -EventsPath $eventsPath -SessionId $sessionId -TrialId $afterTrial.trialId -EventId 'case-event-4' -RequestId 'request-4' -Sequence 4 -Mode 'Tunnel'
    $afterComplete = Invoke-MihariManagementCasesRoute -Session $session -Method 'POST' -Path ('/api/v2/trials/' + $afterTrial.trialId + '/complete') -Query '' -Body ([pscustomobject]@{ businessOutcome = 'succeeded' })
    Assert-MihariManagementCases ($afterComplete.StatusCode -eq 200 -and $afterComplete.Value.result.operatorBusinessOutcome -eq 'succeeded') 'the second trial records its separate business outcome'

    $trialPage = Invoke-MihariManagementCasesRoute -Session $session -Method 'GET' -Path '/api/v2/trials' -Query ('caseId=' + $case.caseId + '&limit=10') -Body $null
    Assert-MihariManagementCases ($trialPage.StatusCode -eq 200 -and $trialPage.Value.scopeTotal -eq 2 -and $trialPage.Value.items.Count -eq 2) 'GET trials filters on the server and returns the domain envelope'

    $dependencyPage = Invoke-MihariManagementCasesRoute -Session $session -Method 'GET' -Path '/api/v2/dependencies' -Query ('caseId=' + $case.caseId + '&trialId=' + $beforeTrial.trialId) -Body $null
    Assert-MihariManagementCases ($dependencyPage.StatusCode -eq 200 -and $dependencyPage.Value.items.Count -eq 1) 'dependencies use canonical projected events and explicit trial identity'
    $dependency = $dependencyPage.Value.items[0]
    Assert-MihariManagementCases ($dependency.attemptCount -eq 2 -and $dependency.requestKeys.Count -eq 2) 'identical URLs retain distinct request identities inside a dependency summary'
    $dependencyJson = ConvertTo-Json -InputObject $dependencyPage.Value -Depth 12 -Compress
    Assert-MihariManagementCases ($dependencyJson -notmatch 'fixture-secret') 'dependency evidence retains query-value redaction'

    $unconfirmed = Invoke-MihariManagementCasesRoute -Session $session -Method 'POST' -Path ('/api/v2/dependencies/' + $dependency.dependencyId + '/necessity') -Query '' -Body ([pscustomobject]@{ state = 'business_required_confirmed'; confirmBusinessRequired = $false })
    Assert-MihariManagementCases ($unconfirmed.StatusCode -eq 400) 'business necessity requires an explicit positive confirmation'
    $confirmed = Invoke-MihariManagementCasesRoute -Session $session -Method 'POST' -Path ('/api/v2/dependencies/' + $dependency.dependencyId + '/necessity') -Query '' -Body ([pscustomobject]@{ state = 'business_required_confirmed'; confirmBusinessRequired = $true; rationale = 'Required for the upload operation.' })
    Assert-MihariManagementCases ($confirmed.StatusCode -eq 200 -and $confirmed.Value.result.explicitConfirmation) 'necessity confirmation is journaled against projected evidence'

    $proposals = Invoke-MihariManagementCasesRoute -Session $session -Method 'GET' -Path '/api/v2/proposals' -Query ('caseId=' + $case.caseId + '&trialId=' + $beforeTrial.trialId) -Body $null
    Assert-MihariManagementCases ($proposals.StatusCode -eq 200 -and $proposals.Value.items.Count -eq 1) 'proposals are generated from the selected canonical dependency'
    Assert-MihariManagementCases ($proposals.Value.items[0].proposalType -eq 'url_allowlist' -and $proposals.Value.items[0].necessityState -eq 'business_required_confirmed') 'URL proposals retain their distinct type and operator necessity state'
    $broadenedProposals = Invoke-MihariManagementCasesRoute -Session $session -Method 'GET' -Path '/api/v2/proposals' -Query ('caseId=' + $case.caseId + '&trialId=' + $beforeTrial.trialId + '&pathMatch=pathPrefix') -Body $null
    Assert-MihariManagementCases ($broadenedProposals.StatusCode -eq 200 -and $broadenedProposals.Value.items[0].requiresConfirmation -contains 'broadened_path_prefix') 'broadened URL patterns remain suggestions until explicitly confirmed'

    $neutralPolicy = [pscustomobject]@{
        format = 'mihari-neutral-url-policy'
        schemaVersion = 1
        rules = @([pscustomobject]@{
            ruleId = 'upload-api'; host = 'api.example.test'; scheme = 'https'; port = 443
            matchType = 'exact'; path = '/items'; effect = 'allow'; methods = @('GET')
        })
    }
    $policyComparison = Invoke-MihariManagementCasesRoute -Session $session -Method 'POST' -Path '/api/v2/policy/compare' -Query '' -Body ([pscustomobject]@{
        caseId = $case.caseId; trialId = $beforeTrial.trialId; policyDocument = $neutralPolicy
    })
    Assert-MihariManagementCases ($policyComparison.StatusCode -eq 200 -and $policyComparison.Value.items[0].status -eq 'covered') 'policy comparison accepts only the documented neutral format'
    $vendorPolicy = Invoke-MihariManagementCasesRoute -Session $session -Method 'POST' -Path '/api/v2/policy/compare' -Query '' -Body ([pscustomobject]@{
        caseId = $case.caseId; trialId = $beforeTrial.trialId; policyDocument = [pscustomobject]@{ format = 'vendor-specific'; schemaVersion = 1; rules = @() }
    })
    Assert-MihariManagementCases ($vendorPolicy.StatusCode -eq 400) 'vendor policy formats are rejected instead of being interpreted by Mihari'

    $previewRequest = [pscustomobject]@{
        caseId = $case.caseId; trialId = $beforeTrial.trialId; dependencyIds = @($dependency.dependencyId)
        businessAction = 'Upload report'; pathMatch = 'exact'
        reproductionConditions = [pscustomobject]@{ mode = 'Inspect'; cacheState = 'unknown'; secretToken = 'change-request-secret' }
    }
    $preview = Invoke-MihariManagementCasesRoute -Session $session -Method 'POST' -Path '/api/v2/change-requests/preview' -Query '' -Body $previewRequest
    Assert-MihariManagementCases ($preview.StatusCode -eq 200 -and $preview.Value.result.included.proposals -eq 1) 'change-request preview returns a redaction summary and selected proposal count'
    $previewJson = ConvertTo-Json -InputObject $preview.Value -Depth 12 -Compress
    Assert-MihariManagementCases ($previewJson -notmatch 'change-request-secret' -and $previewJson -notmatch 'fixture-secret') 'preview excludes secret-like fields and query values'

    $exportRequest = [pscustomobject]@{}
    foreach ($property in $previewRequest.PSObject.Properties) { $exportRequest | Add-Member -NotePropertyName $property.Name -NotePropertyValue $property.Value }
    $exportRequest | Add-Member -NotePropertyName previewId -NotePropertyValue ([string]$preview.Value.result.previewId)
    $exportRequest | Add-Member -NotePropertyName format -NotePropertyValue 'csv'
    $export = Invoke-MihariManagementCasesRoute -Session $session -Method 'POST' -Path '/api/v2/change-requests/export' -Query '' -Body $exportRequest
    Assert-MihariManagementCases ($export.StatusCode -eq 200 -and $export.Value.result.completed -and $export.Value.result.files.Count -eq 1) 'change-request export requires and completes a current preview'
    Assert-MihariManagementCases ($export.Value.result.files[0].relativePath.StartsWith('change-requests/')) 'exports are stored under the case output root and return only a relative path'
    $exportPath = Join-Path $temporaryRoot ($export.Value.result.files[0].relativePath.Replace('/', [System.IO.Path]::DirectorySeparatorChar))
    $exportText = [System.IO.File]::ReadAllText($exportPath, [System.Text.Encoding]::UTF8)
    Assert-MihariManagementCases ($exportText -notmatch 'change-request-secret' -and $exportText -notmatch 'fixture-secret') 'CSV export excludes secret-like values and query values'

    $resetNecessity = Invoke-MihariManagementCasesRoute -Session $session -Method 'POST' -Path ('/api/v2/dependencies/' + $dependency.dependencyId + '/necessity') -Query '' -Body ([pscustomobject]@{ state = 'necessity_unconfirmed' })
    Assert-MihariManagementCases ($resetNecessity.StatusCode -eq 200) 'the operator can remove a prior necessity confirmation'
    $staleExport = Invoke-MihariManagementCasesRoute -Session $session -Method 'POST' -Path '/api/v2/change-requests/export' -Query '' -Body $exportRequest
    Assert-MihariManagementCases ($staleExport.StatusCode -eq 409 -and $staleExport.Value.error -eq 'preview_stale') 'export rejects proposal changes made after preview'

    $comparison = Invoke-MihariManagementCasesRoute -Session $session -Method 'GET' -Path '/api/v2/comparisons' -Query ('beforeTrialId=' + $beforeTrial.trialId + '&afterTrialId=' + $afterTrial.trialId) -Body $null
    Assert-MihariManagementCases ($comparison.StatusCode -eq 200 -and $comparison.Value.before.trialId -eq $beforeTrial.trialId -and $comparison.Value.after.trialId -eq $afterTrial.trialId) 'comparison uses the actual before/after trial records'
    Assert-MihariManagementCases ($comparison.Value.collectionCoverage.status -eq 'observed') 'comparison reports canonical event collection coverage'
    $modeChanges = @($comparison.Value.changedConditions | Where-Object { $_.name -eq 'mode' })
    Assert-MihariManagementCases ($modeChanges.Count -eq 1 -and [string]$modeChanges[0].before -eq 'Inspect' -and [string]$modeChanges[0].after -eq 'Tunnel') 'comparison exposes the changed diagnostic mode'

    $badQuery = Invoke-MihariManagementCasesRoute -Session $session -Method 'GET' -Path '/api/v2/dependencies' -Query 'host=unvalidated.example' -Body $null
    Assert-MihariManagementCases ($badQuery.StatusCode -eq 400) 'unsupported dependency query fields are rejected'
    Write-Host 'PASS Phase 2 management cases: cases, trials, markers, notes, dependencies, necessity, comparisons'
}
finally {
    if ([System.IO.Directory]::Exists($temporaryRoot)) { [System.IO.Directory]::Delete($temporaryRoot, $true) }
}
