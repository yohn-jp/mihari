$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'TestSupport.ps1')
. (Join-Path (Split-Path $PSScriptRoot -Parent) 'src/Observation.ps1')
. (Join-Path (Split-Path $PSScriptRoot -Parent) 'src/Case.ps1')
. (Join-Path (Split-Path $PSScriptRoot -Parent) 'src/Dependencies.ps1')

function Assert-MihariCaseDependencyThrows {
    param([Parameter(Mandatory = $true)][scriptblock] $Action, [Parameter(Mandatory = $true)][string] $Message)
    $threw = $false
    try { & $Action }
    catch { $threw = $true }
    Assert-MihariTest -Condition $threw -Message $Message
}

function New-MihariCaseDependencyEvent {
    param(
        [Parameter(Mandatory = $true)][string] $EventId,
        [Parameter(Mandatory = $true)][string] $SessionId,
        [string] $RequestId,
        [Parameter(Mandatory = $true)][string] $ConnectionId,
        [Parameter(Mandatory = $true)][long] $Sequence,
        [Parameter(Mandatory = $true)][string] $TrialId,
        [Parameter(Mandatory = $true)][string] $HostName,
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][string] $Method,
        [string] $Stage = 'http.request',
        [string] $Outcome = 'succeeded',
        [int] $StatusCode = 0,
        [string] $Timestamp
    )

    if (-not $Timestamp) { $Timestamp = [DateTime]::UtcNow.ToString('o', [Globalization.CultureInfo]::InvariantCulture) }
    $data = [ordered]@{ scheme = 'https'; host = $HostName; port = 443; path = $Path; method = $Method }
    if ($StatusCode -gt 0) { $data['statusCode'] = $StatusCode }
    return [pscustomobject]@{
        schemaVersion = 2; timestamp = $Timestamp; eventId = $EventId; sequence = $Sequence
        sessionId = $SessionId; connectionId = $ConnectionId; requestId = $RequestId
        caseId = $null; trialId = $TrialId; source = 'proxy'; coverage = 'observed'
        mode = 'Inspect'; stage = $Stage; outcome = $Outcome; elapsedMs = 2
        transportLeg = 'upstream'; data = [pscustomobject]$data
    }
}

$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('mihari-cases-dependencies-' + [Guid]::NewGuid().ToString('N'))
$caseRoot = Join-Path $tempRoot 'cases'
$querySecret = 'CASE_QUERY_SENTINEL_94f03b'
$passwordSecret = 'CASE_PASSWORD_SENTINEL_8431c0'
$cookieSecret = 'CASE_COOKIE_SENTINEL_291bd8'
$proxySecret = 'CASE_PROXY_SENTINEL_1f41d2'
$tokenSecret = 'CASE_TOKEN_SENTINEL_2a7c11'
$localPathSecret = 'C:\Users\internal-user\CASE_LOCAL_PATH_SENTINEL'
$eventTimestamp = [DateTimeOffset]::UtcNow.AddMinutes(-1)
$eventTimestampText = $eventTimestamp.ToString('o', [Globalization.CultureInfo]::InvariantCulture)

try {
    $case = New-MihariCase -CaseRoot $caseRoot -Title ('=HYPERLINK("https://inside.example.test/upload?key=' + $querySecret + '","Upload")')
    Assert-MihariTest -Condition ($case.caseId -match '^case-[0-9a-f]{32}$') -Message 'New cases need opaque, path-safe IDs.'
    Assert-MihariTest -Condition ($case.title -notmatch [regex]::Escape($querySecret)) -Message 'Case titles must redact query values before persistence.'

    $pageOne = Get-MihariCases -CaseRoot $caseRoot -MaximumItems 1
    Assert-MihariTest -Condition ($pageOne.scopeTotal -eq 1 -and $null -eq $pageOne.nextCursor) -Message 'Case list scope totals must be independent of the page size.'

    $profile = [ordered]@{
        mode = 'Inspect'
        protocolProfile = 'compatibility'
        explicitProxy = 'http://operator:' + $proxySecret + '@proxy.example.test/?token=' + $tokenSecret
        password = $passwordSecret
        username = 'enterprise-user-sentinel'
        browserProfilePath = 'C:\Users\internal-user\EdgeProfile'
        headers = @{ Authorization = 'Bearer ' + $passwordSecret; Cookie = $cookieSecret }
        cacheDisabled = $true
    }
    $trial = New-MihariTrial -CaseRoot $caseRoot -CaseId $case.caseId -SessionId 'session-cases-1' -Profile $profile -ConfigurationRevision 'config-r7' -EnvironmentReference ([pscustomobject]@{
            snapshotId = 'environment-1'; capturedAtUtc = $eventTimestampText; relativePath = 'environment/snapshot.json'; sources = @('user_proxy', 'winhttp')
        })
    $profile.mode = 'Tunnel'
    Assert-MihariTest -Condition ($trial.profile.mode -eq 'Inspect') -Message 'A trial profile must be a creation-time immutable snapshot.'
    Assert-MihariTest -Condition ($trial.environmentReference.relativePath -eq 'environment/snapshot.json') -Message 'Trials must retain safe local environment snapshot references.'
    Assert-MihariTest -Condition (-not $trial.profile.Contains('password') -and -not $trial.profile.Contains('username') -and -not $trial.profile.Contains('browserProfilePath') -and -not $trial.profile.Contains('headers')) -Message 'Credential fields, local profile paths, and arbitrary headers must be omitted from trial metadata.'

    $note = Add-MihariCaseNote -CaseRoot $caseRoot -CaseId $case.caseId -TrialId $trial.trialId -Text ('Upload observed at https://inside.example.test/files?token=' + $querySecret + ' password=' + $passwordSecret + ' username=internal-user path=' + $localPathSecret)
    Assert-MihariTest -Condition ($note.text -notmatch [regex]::Escape($querySecret) -and $note.text -notmatch [regex]::Escape($passwordSecret) -and $note.text -notmatch [regex]::Escape($localPathSecret) -and $note.text -notmatch 'username=internal-user') -Message 'Notes must redact credentials, query values, and local file paths before storage.'

    $markerStart = $eventTimestamp.AddSeconds(-10)
    $markerEnd = $eventTimestamp.AddSeconds(10)
    $startMarker = Add-MihariMarker -CaseRoot $caseRoot -TrialId $trial.trialId -Boundary start -Label 'Upload' -TimestampUtc $markerStart
    $endMarker = Add-MihariMarker -CaseRoot $caseRoot -TrialId $trial.trialId -Boundary end -Label 'Upload' -Note 'Done' -TimestampUtc $markerEnd
    Assert-MihariTest -Condition ($startMarker.markerId -ne $endMarker.markerId -and $startMarker.timestamp -eq $startMarker.timestampUtc) -Message 'Operation boundaries need distinct timestamped marker identities.'

    $events = @(
        (New-MihariCaseDependencyEvent -EventId 'event-r1-request' -SessionId $trial.sessionId -RequestId 'request-r1' -ConnectionId 'connection-r1' -Sequence 1 -TrialId $trial.trialId -HostName 'UPLOAD.EXAMPLE.TEST.' -Path ('/files?token=' + $querySecret) -Method POST -Timestamp $eventTimestampText),
        (New-MihariCaseDependencyEvent -EventId 'event-r1-response' -SessionId $trial.sessionId -RequestId 'request-r1' -ConnectionId 'connection-r1' -Sequence 2 -TrialId $trial.trialId -HostName 'upload.example.test' -Path ('/files?token=' + $querySecret) -Method POST -Stage 'upstream.http' -Outcome 'succeeded' -StatusCode 200 -Timestamp $eventTimestampText),
        (New-MihariCaseDependencyEvent -EventId 'event-r2-request' -SessionId $trial.sessionId -RequestId 'request-r2' -ConnectionId 'connection-r2' -Sequence 3 -TrialId $trial.trialId -HostName 'upload.example.test' -Path ('/files?token=' + $querySecret) -Method POST -Timestamp $eventTimestampText),
        (New-MihariCaseDependencyEvent -EventId 'event-r2-response' -SessionId $trial.sessionId -RequestId 'request-r2' -ConnectionId 'connection-r2' -Sequence 4 -TrialId $trial.trialId -HostName 'upload.example.test' -Path ('/files?token=' + $querySecret) -Method POST -Stage 'upstream.http' -Outcome 'succeeded' -StatusCode 200 -Timestamp $eventTimestampText),
        (New-MihariCaseDependencyEvent -EventId 'event-r3' -SessionId $trial.sessionId -RequestId 'request-r3' -ConnectionId 'connection-r3' -Sequence 5 -TrialId $trial.trialId -HostName 'upload.example.test' -Path '/files/42' -Method GET -Timestamp $eventTimestampText),
        (New-MihariCaseDependencyEvent -EventId 'event-r4' -SessionId $trial.sessionId -RequestId 'request-r4' -ConnectionId 'connection-r4' -Sequence 6 -TrialId $trial.trialId -HostName 'upload.example.test' -Path '/filesystem' -Method GET -Timestamp $eventTimestampText)
    )
    $projection = Get-MihariDependencyProjection -Events $events -CaseRoot $caseRoot
    $uploadDependency = @($projection.items | Where-Object { $_.path -eq '/files?token=[REDACTED]' })[0]
    Assert-MihariTest -Condition ($null -ne $uploadDependency -and $uploadDependency.attemptCount -eq 2) -Message 'Two direct request IDs for the same URL must remain two attempts even at the same timestamp.'
    Assert-MihariTest -Condition ($uploadDependency.requestKeys.Count -eq 2 -and $uploadDependency.successfulHttpResponseCount -eq 2) -Message 'Dependency rows need direct request identities and observed HTTP outcome counts.'
    Assert-MihariTest -Condition ($uploadDependency.operationLabel -eq 'Upload' -and $uploadDependency.operationAttribution -eq 'heuristic_marker_window') -Message 'Marker windows may group requests by an explicitly labelled operation only as a heuristic.'
    Assert-MihariTest -Condition ($uploadDependency.businessOutcome -eq 'unknown') -Message 'An HTTP response must not be presented as business success.'
    Assert-MihariTest -Condition ($uploadDependency.path -notmatch [regex]::Escape($querySecret)) -Message 'Dependency paths must not retain query values.'

    $firstDependencyPage = Get-MihariDependencyProjection -Events $events -CaseRoot $caseRoot -MaximumItems 1
    Assert-MihariTest -Condition ($null -ne $firstDependencyPage.nextCursor -and $firstDependencyPage.scopeTotal -gt 1) -Message 'Dependency projections need a stable bounded cursor and full scope total.'
    $secondDependencyPage = Get-MihariDependencyProjection -Events $events -CaseRoot $caseRoot -MaximumItems 1 -Cursor $firstDependencyPage.nextCursor
    Assert-MihariTest -Condition ($secondDependencyPage.items.Count -eq 1 -and $secondDependencyPage.items[0].dependencyId -ne $firstDependencyPage.items[0].dependencyId) -Message 'Dependency cursor paging must not repeat rows.'
    $changedEvents = @($events) + @((New-MihariCaseDependencyEvent -EventId 'event-r5-new' -SessionId $trial.sessionId -RequestId 'request-r5' -ConnectionId 'connection-r5' -Sequence 7 -TrialId $trial.trialId -HostName 'second.example.test' -Path '/new' -Method GET -Timestamp $eventTimestampText))
    Assert-MihariCaseDependencyThrows -Action {
        Get-MihariDependencyProjection -Events $changedEvents -CaseRoot $caseRoot -MaximumItems 1 -Cursor $firstDependencyPage.nextCursor
    } -Message 'A dependency cursor must be invalidated when its source events change.'

    $proxySourceEvent = New-MihariCaseDependencyEvent -EventId 'event-source-proxy' -SessionId 'session-source-scope' -RequestId 'request-reused' -ConnectionId 'connection-proxy' -Sequence 1 -HostName 'upload.example.test' -Path '/same' -Method GET -Timestamp $eventTimestampText
    $windowsSourceEvent = New-MihariCaseDependencyEvent -EventId 'event-source-windows' -SessionId 'session-source-scope' -RequestId 'request-reused' -ConnectionId 'connection-windows' -Sequence 2 -HostName 'upload.example.test' -Path '/same' -Method GET -Timestamp $eventTimestampText
    $windowsSourceEvent.source = 'windows'
    $sharedKeyProjection = Get-MihariDependencyProjection -Events @($proxySourceEvent, $windowsSourceEvent)
    Assert-MihariTest -Condition ($sharedKeyProjection.items[0].attemptCount -eq 1 -and $sharedKeyProjection.items[0].sources.Count -eq 2) -Message 'One session-scoped request ID provides a direct request link while retaining each event source.'
    $wrongSessionTrialReference = New-MihariCaseDependencyEvent -EventId 'event-mismatched-trial-session' -SessionId 'session-other-than-trial' -RequestId 'request-session-check' -ConnectionId 'connection-session-check' -Sequence 1 -TrialId $trial.trialId -HostName 'upload.example.test' -Path '/session-check' -Method GET -Timestamp $eventTimestampText
    $mismatchedTrialProjection = Get-MihariDependencyProjection -Events @($wrongSessionTrialReference) -Trials @((Get-MihariTrial -CaseRoot $caseRoot -TrialId $trial.trialId))
    Assert-MihariTest -Condition ($mismatchedTrialProjection.items[0].trialId -eq $null -and $mismatchedTrialProjection.items[0].trialAttribution -eq 'ambiguous') -Message 'A direct trial ID cannot attach events from another session to the case.'

    $informationalEvent = New-MihariCaseDependencyEvent -EventId 'event-100-continue' -SessionId 'session-info' -RequestId 'request-info' -ConnectionId 'connection-info' -Sequence 1 -TrialId $trial.trialId -HostName 'upload.example.test' -Path '/continue' -Method POST -Stage 'upstream.http' -Outcome 'succeeded' -StatusCode 100 -Timestamp $eventTimestampText
    $informationalProjection = Get-MihariDependencyProjection -Events @($informationalEvent)
    Assert-MihariTest -Condition ($informationalProjection.items[0].successfulHttpResponseCount -eq 0 -and $informationalProjection.items[0].failedHttpResponseCount -eq 0) -Message 'Informational HTTP status codes must not be counted as a final response result.'

    $exactPolicy = [pscustomobject]@{
        schemaVersion = 1; format = 'mihari-neutral-url-policy'
        rules = @([pscustomobject]@{ ruleId = 'exact-files'; host = 'upload.example.test'; scheme = 'https'; port = 443; matchType = 'exact'; path = '/files' })
    }
    $exactComparison = Compare-MihariDependencyPolicy -Dependencies $projection.items -PolicyDocument $exactPolicy
    $exactFilesResult = @($exactComparison.items | Where-Object { $_.dependencyId -eq $uploadDependency.dependencyId })[0]
    $filesChild = @($projection.items | Where-Object { $_.path -eq '/files/42' })[0]
    $filesChildResult = @($exactComparison.items | Where-Object { $_.dependencyId -eq $filesChild.dependencyId })[0]
    Assert-MihariTest -Condition ($exactFilesResult.status -eq 'covered' -and $filesChildResult.status -eq 'uncovered') -Message 'Neutral exact path rules must cover only the exact path.'
    $firstPolicyPage = Compare-MihariDependencyPolicy -Dependencies $projection.items -PolicyDocument $exactPolicy -MaximumItems 1
    Assert-MihariTest -Condition ($null -ne $firstPolicyPage.nextCursor -and $firstPolicyPage.scopeTotal -gt 1) -Message 'Policy comparison needs bounded cursor paging and a full scope total.'
    $secondPolicyPage = Compare-MihariDependencyPolicy -Dependencies $projection.items -PolicyDocument $exactPolicy -MaximumItems 1 -Cursor $firstPolicyPage.nextCursor
    Assert-MihariTest -Condition ($secondPolicyPage.items.Count -eq 1 -and $secondPolicyPage.items[0].dependencyId -ne $firstPolicyPage.items[0].dependencyId) -Message 'Policy cursor paging must not repeat rows.'

    $prefixPolicy = [pscustomobject]@{
        schemaVersion = 1; format = 'mihari-neutral-url-policy'
        rules = @([pscustomobject]@{ ruleId = 'prefix-files'; host = 'upload.example.test'; scheme = 'https'; port = 443; matchType = 'pathPrefix'; path = '/files' })
    }
    $prefixComparison = Compare-MihariDependencyPolicy -Dependencies $projection.items -PolicyDocument $prefixPolicy
    $coveredChild = @($prefixComparison.items | Where-Object { $_.dependencyId -eq $filesChild.dependencyId })[0]
    $filesystem = @($projection.items | Where-Object { $_.path -eq '/filesystem' })[0]
    $notCoveredSibling = @($prefixComparison.items | Where-Object { $_.dependencyId -eq $filesystem.dependencyId })[0]
    Assert-MihariTest -Condition ($coveredChild.status -eq 'covered' -and $notCoveredSibling.status -eq 'uncovered') -Message 'Path-prefix rules must use a segment boundary.'

    $unsupportedPolicy = [pscustomobject]@{ schemaVersion = 1; format = 'vendor-regex'; rules = @(@{ pattern = '.*' }) }
    $unsupportedComparison = Compare-MihariDependencyPolicy -Dependencies @($uploadDependency) -PolicyDocument $unsupportedPolicy
    Assert-MihariTest -Condition (@($unsupportedComparison.items)[0].status -eq 'unknown') -Message 'Unsupported vendor policy semantics must remain unknown.'

    Assert-MihariCaseDependencyThrows -Action {
        Set-MihariDependencyNecessity -CaseRoot $caseRoot -Dependency $filesChild -State business_required_confirmed
    } -Message 'Business necessity cannot be classified without an explicit confirmation action.'
    $confirmed = Set-MihariDependencyNecessity -CaseRoot $caseRoot -Dependency $filesChild -State business_required_confirmed -ConfirmBusinessRequired -Rationale 'Required for the upload workflow.'
    Assert-MihariTest -Condition ($confirmed.explicitConfirmation -eq $true -and $confirmed.evidenceReferences.Count -gt 0) -Message 'Necessity confirmation must persist explicit operator action and event evidence.'
    $confirmedProjection = Get-MihariDependencyProjection -Events $events -CaseRoot $caseRoot
    $confirmedChild = @($confirmedProjection.items | Where-Object { $_.path -eq '/files/42' })[0]
    Assert-MihariTest -Condition ($confirmedChild.necessityState -eq 'business_required_confirmed') -Message 'The dependency projection must replay its latest necessity confirmation.'

    $prefixProposalSet = New-MihariPolicyProposals -Dependencies @($confirmedChild) -PolicyComparison $exactComparison -PathMatch pathPrefix
    $prefixProposal = @($prefixProposalSet.items | Where-Object { $_.proposalType -eq 'url_allowlist' })[0]
    Assert-MihariTest -Condition ($prefixProposal.proposalStatus -eq 'requires_confirmation' -and 'broadened_path_prefix' -in $prefixProposal.requiresConfirmation) -Message 'A path-prefix proposal must remain non-executable until broadening is confirmed.'
    $confirmedPrefixProposal = New-MihariPolicyProposals -Dependencies @($confirmedChild) -PolicyComparison $exactComparison -PathMatch pathPrefix -ConfirmBroadenedPathPrefix
    Assert-MihariTest -Condition (@($confirmedPrefixProposal.items)[0].broadenedPatternConfirmed) -Message 'Explicit prefix confirmation must be retained on the proposal.'
    $firstProposalPage = New-MihariPolicyProposals -Dependencies @($confirmedProjection.items) -PolicyComparison $exactComparison -MaximumItems 1
    Assert-MihariTest -Condition ($null -ne $firstProposalPage.nextCursor -and $firstProposalPage.scopeTotal -gt 1) -Message 'Proposal lists need bounded cursor paging and a full scope total.'
    $secondProposalPage = New-MihariPolicyProposals -Dependencies @($confirmedProjection.items) -PolicyComparison $exactComparison -MaximumItems 1 -Cursor $firstProposalPage.nextCursor
    Assert-MihariTest -Condition ($secondProposalPage.items.Count -eq 1 -and $secondProposalPage.items[0].proposalId -ne $firstProposalPage.items[0].proposalId) -Message 'Proposal cursor paging must not repeat rows.'

    $invalidTlsEvidence = [pscustomobject]@{
        comparisonId = 'comparison-bytes-only'; caseId = $case.caseId; host = 'upload.example.test'
        classification = 'tls_interception_incompatible'; evidenceStrength = 'comparison_supported'
        inspectFailureObserved = $true; tunnelBusinessOutcome = 'unknown'; tunnelBytesRelayed = $true
        sameRoute = $true; sameProtocolPolicy = $true; otherConditionsComparable = $true
        inspectTrialId = 'trial-inspect'; tunnelTrialId = 'trial-tunnel'
        evidenceReferences = @([pscustomobject]@{ sessionId = 's1'; eventId = 'inspect-failed' }, [pscustomobject]@{ sessionId = 's2'; eventId = 'tunnel-bytes' })
    }
    $invalidTlsProposals = New-MihariPolicyProposals -Dependencies @($confirmedProjection.items) -TlsEvidence @($invalidTlsEvidence)
    Assert-MihariTest -Condition (@($invalidTlsProposals.items | Where-Object { $_.proposalType -eq 'tls_inspection_exclusion' }).Count -eq 0) -Message 'Tunnel bytes cannot support a TLS-exclusion proposal without observed business success.'

    $validTlsEvidence = [pscustomobject]@{
        comparisonId = 'comparison-supported'; caseId = $case.caseId; host = 'upload.example.test'
        classification = 'tls_interception_incompatible'; evidenceStrength = 'comparison_supported'
        inspectFailureObserved = $true; tunnelBusinessOutcome = 'succeeded'; sameRoute = $true
        sameProtocolPolicy = $true; otherConditionsComparable = $true; changedConditions = @()
        inspectTrialId = 'trial-inspect'; tunnelTrialId = 'trial-tunnel'
        evidenceReferences = @([pscustomobject]@{ sessionId = 's1'; eventId = 'inspect-failed' }, [pscustomobject]@{ sessionId = 's2'; eventId = 'tunnel-business-success' })
    }
    $validTlsProposals = New-MihariPolicyProposals -Dependencies @($confirmedChild) -TlsEvidence @($validTlsEvidence) -ConfirmTlsExclusionHostScope
    $tlsProposal = @($validTlsProposals.items | Where-Object { $_.proposalType -eq 'tls_inspection_exclusion' } | Select-Object -First 1)
    Assert-MihariTest -Condition ($null -ne $tlsProposal -and $tlsProposal.policyDomain -eq 'mihari-local-inspection' -and $tlsProposal.upstreamRoute -eq 'unchanged' -and $tlsProposal.exactHostScopeConfirmed -and $tlsProposal.proposalStatus -eq 'candidate') -Message 'A supported TLS comparison needs separate explicit exact-host local-exclusion confirmation and cannot change the upstream route.'
    $unconfirmedTlsProposal = New-MihariPolicyProposals -Dependencies @($confirmedChild) -TlsEvidence @($validTlsEvidence)
    Assert-MihariTest -Condition (@($unconfirmedTlsProposal.items)[0].proposalStatus -eq 'requires_confirmation' -and 'exact_host_scope' -in @($unconfirmedTlsProposal.items)[0].requiresConfirmation) -Message 'A host-wide TLS exclusion stays withheld from use until exact-host scope is explicitly confirmed.'

    $allProposals = @($validTlsProposals.items)
    $businessAction = '=HYPERLINK("https://inside.example.test/upload?token=' + $querySecret + '","Upload")'
    $preview = Get-MihariChangeRequestPreview -Case (Get-MihariCase -CaseRoot $caseRoot -CaseId $case.caseId) -Trial (Get-MihariTrial -CaseRoot $caseRoot -TrialId $trial.trialId) -Dependencies @($confirmedProjection.items) -Proposals $allProposals -BusinessAction $businessAction -ReproductionConditions @{ mode = 'Inspect'; password = $passwordSecret; path = '/upload?token=' + $querySecret }
    Assert-MihariTest -Condition ($preview.included.proposals -eq $allProposals.Count -and $preview.redacted.queryValues -eq 'all values') -Message 'The export preview must name included proposals and redactions.'
    $export = Export-MihariChangeRequest -Path (Join-Path $tempRoot 'review.csv') -Format csv -Preview $preview -Case (Get-MihariCase -CaseRoot $caseRoot -CaseId $case.caseId) -Trial (Get-MihariTrial -CaseRoot $caseRoot -TrialId $trial.trialId) -Dependencies @($confirmedProjection.items) -Proposals $allProposals -BusinessAction $businessAction -ReproductionConditions @{ mode = 'Inspect'; password = $passwordSecret; path = '/upload?token=' + $querySecret }
    $csvText = [System.IO.File]::ReadAllText([string]$export.files[0].path, [System.Text.Encoding]::UTF8)
    Assert-MihariTest -Condition ($csvText.Contains('"' + "'" + '=HYPERLINK')) -Message 'CSV cells that could be spreadsheet formulas must be escaped.'
    Assert-MihariTest -Condition ($csvText -match 'tls_inspection_exclusion' -and $csvText -match 'url_allowlist') -Message 'CSV export must retain the separate proposal types.'

    $textPreview = Get-MihariChangeRequestPreview -Case $case -Trial $trial -Dependencies @($confirmedProjection.items) -Proposals $allProposals -BusinessAction $businessAction -ReproductionConditions @{ mode = 'Inspect'; password = $passwordSecret; path = '/upload?token=' + $querySecret }
    $textExport = Export-MihariChangeRequest -Path (Join-Path $tempRoot 'review') -Format all -Preview $textPreview -Case $case -Trial $trial -Dependencies @($confirmedProjection.items) -Proposals $allProposals -BusinessAction $businessAction -ReproductionConditions @{ mode = 'Inspect'; password = $passwordSecret; path = '/upload?token=' + $querySecret }
    $jsonText = [System.IO.File]::ReadAllText([string](@($textExport.files | Where-Object { $_.format -eq 'json' })[0].path), [System.Text.Encoding]::UTF8)
    $reportText = [System.IO.File]::ReadAllText([string](@($textExport.files | Where-Object { $_.format -eq 'text' })[0].path), [System.Text.Encoding]::UTF8)
    Assert-MihariTest -Condition ($reportText -match 'Business action:' -and $reportText -match 'Evidence:' -and $reportText -match 'Unresolved questions:') -Message 'The human report must include the business action, evidence, and unresolved questions.'
    Assert-MihariTest -Condition ($csvText -notmatch [regex]::Escape($querySecret) -and $csvText -notmatch [regex]::Escape($passwordSecret) -and $jsonText -notmatch [regex]::Escape($querySecret) -and $jsonText -notmatch [regex]::Escape($passwordSecret) -and $jsonText -notmatch [regex]::Escape($cookieSecret) -and $reportText -notmatch [regex]::Escape($proxySecret) -and $reportText -notmatch [regex]::Escape($tokenSecret) -and $reportText -notmatch [regex]::Escape($localPathSecret)) -Message 'JSON/CSV/text outputs must not contain credentials, raw query values, or local file paths.'

    $stalePreview = Get-MihariChangeRequestPreview -Case $case -Trial $trial -Proposals $allProposals -BusinessAction $businessAction
    $allProposals[0].rationale = 'Changed after preview'
    Assert-MihariCaseDependencyThrows -Action {
        Export-MihariChangeRequest -Path (Join-Path $tempRoot 'stale.json') -Format json -Preview $stalePreview -Case $case -Trial $trial -Proposals $allProposals -BusinessAction $businessAction
    } -Message 'An export must be rejected if its scope changes after preview.'

    $journalText = [System.IO.File]::ReadAllText((Join-Path $caseRoot 'operator.jsonl'), [System.Text.Encoding]::UTF8)
    foreach ($secret in @($querySecret, $passwordSecret, $cookieSecret, $proxySecret, $tokenSecret, $localPathSecret)) {
        Assert-MihariTest -Condition (-not $journalText.Contains($secret)) -Message 'The operator journal must not persist secret sentinels.'
    }

    $corruptCursorRoot = Join-Path $tempRoot 'paged-cases'
    [void](New-MihariCase -CaseRoot $corruptCursorRoot -Title 'First')
    [void](New-MihariCase -CaseRoot $corruptCursorRoot -Title 'Second')
    $firstPage = Get-MihariCases -CaseRoot $corruptCursorRoot -MaximumItems 1
    Assert-MihariTest -Condition ($null -ne $firstPage.nextCursor -and $firstPage.scopeTotal -eq 2) -Message 'Case pagination must return a stable cursor and full scope total.'
    $secondPage = Get-MihariCases -CaseRoot $corruptCursorRoot -MaximumItems 1 -Cursor $firstPage.nextCursor
    Assert-MihariTest -Condition ($secondPage.items.Count -eq 1 -and $secondPage.items[0].caseId -ne $firstPage.items[0].caseId) -Message 'Stable case pagination must not repeat items.'
    [void](New-MihariCase -CaseRoot $corruptCursorRoot -Title 'Third')
    Assert-MihariCaseDependencyThrows -Action {
        Get-MihariCases -CaseRoot $corruptCursorRoot -MaximumItems 1 -Cursor $firstPage.nextCursor
    } -Message 'A cursor must be invalidated after the operator journal changes.'

    Write-Host 'PASS cases-dependencies: file-backed metadata, immutable trials, marker heuristics, direct request identity, policy comparison, necessity confirmation, safe proposal exports'
}
finally {
    if (Test-Path -LiteralPath $tempRoot) { Remove-Item -LiteralPath $tempRoot -Recurse -Force }
}
