# Case and controlled-trial management routes. These handlers adapt the
# file-backed case journal and canonical traffic projection without rewriting
# captured facts.

function Get-MihariManagementV2CaseRoot {
    param([Parameter(Mandatory = $true)]$Session)

    if ([string]::IsNullOrWhiteSpace([string]$Session.OutputRoot)) {
        throw 'case_store_unavailable'
    }
    return [System.IO.Path]::GetFullPath([string]$Session.OutputRoot)
}

function Get-MihariManagementV2CaseQuery {
    param(
        [AllowNull()][string]$Query,
        [Parameter(Mandatory = $true)][string[]]$AllowedNames
    )

    $values = Get-MihariManagementV2Query -Query $Query
    foreach ($name in $values.Keys) {
        if ($name -notin $AllowedNames) { throw 'unsupported_query_field' }
    }
    return $values
}

function Get-MihariManagementV2CaseLimit {
    param([System.Collections.IDictionary]$Query, [int]$Default = 100)

    if (-not $Query.Contains('limit')) { return $Default }
    if ([string]$Query['limit'] -notmatch '^\d{1,3}$') { throw 'invalid_limit' }
    $limit = [int]$Query['limit']
    if ($limit -lt 1 -or $limit -gt 200) { throw 'invalid_limit' }
    return $limit
}

function Test-MihariManagementV2BodyFields {
    param([Parameter(Mandatory = $true)]$Body, [Parameter(Mandatory = $true)][string[]]$AllowedNames)

    foreach ($property in $Body.PSObject.Properties) {
        if ($property.Name -notin $AllowedNames) { return $false }
    }
    return $true
}

function Read-MihariManagementV2CaseBody {
    param([Parameter(Mandatory = $true)]$Request, [Parameter(Mandatory = $true)][ref]$ErrorResponse)

    $ErrorResponse.Value = $null
    if ($null -eq $Request.Body -or $Request.Body.Length -gt 8192) {
        $ErrorResponse.Value = New-MihariManagementErrorResponse -StatusCode 413 -Code 'request_body_too_large' -Message 'The JSON request body exceeded its limit.'
        return $null
    }
    try { return (Read-MihariManagementJsonBody -Request $Request) }
    catch {
        if ([string]$_.Exception.Message -eq 'unsupported_media_type') {
            $ErrorResponse.Value = New-MihariManagementErrorResponse -StatusCode 415 -Code 'unsupported_media_type' -Message 'Send a UTF-8 application/json request body.'
        }
        else {
            $ErrorResponse.Value = New-MihariManagementErrorResponse -StatusCode 400 -Code 'invalid_json' -Message 'The request body must be a bounded JSON object.'
        }
        return $null
    }
}

function New-MihariManagementV2CompletedResponse {
    param([Parameter(Mandatory = $true)]$Result)

    return (New-MihariManagementJsonResponse -StatusCode 200 -Value ([pscustomobject][ordered]@{
        state = 'completed'
        result = $Result
    }))
}

function Save-MihariManagementV2EnvironmentSnapshot {
    param([Parameter(Mandatory = $true)]$Session, [Parameter(Mandatory = $true)][string]$CaseRoot)

    $snapshot = Get-MihariEnvironmentSnapshot -Session $Session -Destinations @()
    $snapshotId = [string]$snapshot.snapshotId
    if ($snapshotId -notmatch '^[0-9a-fA-F]{32}$') { throw 'environment_snapshot_invalid' }
    $relativePath = Join-Path 'environment' ($snapshotId.ToLowerInvariant() + '.json')
    $directory = Join-Path $CaseRoot 'environment'
    [void][System.IO.Directory]::CreateDirectory($directory)
    $fullPath = [System.IO.Path]::GetFullPath((Join-Path $CaseRoot $relativePath))
    $rootPrefix = [System.IO.Path]::GetFullPath($CaseRoot).TrimEnd([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
    if (-not $fullPath.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) { throw 'environment_snapshot_path_invalid' }
    $json = ConvertTo-Json -InputObject $snapshot -Depth 12 -Compress -ErrorAction Stop
    $encoding = [System.Text.UTF8Encoding]::new($false)
    $bytes = $encoding.GetBytes($json)
    if ($bytes.Length -gt 262144) { throw 'environment_snapshot_too_large' }
    $temporaryPath = $fullPath + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
    try {
        [System.IO.File]::WriteAllText($temporaryPath, $json + [Environment]::NewLine, $encoding)
        if ([System.IO.File]::Exists($fullPath)) { throw 'environment_snapshot_already_exists' }
        [System.IO.File]::Move($temporaryPath, $fullPath)
    }
    finally {
        if ([System.IO.File]::Exists($temporaryPath)) { [System.IO.File]::Delete($temporaryPath) }
    }
    return [pscustomobject][ordered]@{
        snapshotId = $snapshotId
        capturedAtUtc = [string]$snapshot.capturedAtUtc
        relativePath = $relativePath
        sources = $snapshot.sources
    }
}

function New-MihariManagementV2TrialProfile {
    param([Parameter(Mandatory = $true)]$Session)

    return [ordered]@{
        mode = [string]$Session.Mode
        protocolProfile = [string]$Session.Profile
        profileVersion = [int]$Session.ProfileVersion
        httpConnectionPolicy = [string]$Session.HttpConnectionPolicy
        configurationRevision = [string]$Session.ConfigurationRevision
        localInspectionExclusions = @($Session.LocalInspectExclusions | ForEach-Object { [string]$_ } | Sort-Object -Unique)
    }
}

function Get-MihariManagementV2CaseTrafficSnapshot {
    param([Parameter(Mandatory = $true)]$Session)

    try {
        $store = Get-MihariManagementV2TrafficStore -Session $Session
        $null = Update-MihariTrafficProjectionStore -Store $store
        $eventPage = Get-MihariTrafficProjectionEvents -Store $store -AfterOrdinal 0 -Limit 20000
        $events = @($eventPage.events | ForEach-Object { $_.event })
        return [pscustomobject]@{
            Store = $store
            Events = $events
            HasMore = [bool]$eventPage.hasMore
            NextOrdinal = [long]$eventPage.nextOrdinal
            Error = $null
        }
    }
    catch {
        if ($null -ne $Session.PSObject.Properties['TrafficProjectionError']) {
            $Session.TrafficProjectionError = $_.Exception.GetType().FullName
        }
        return [pscustomobject]@{ Store = $null; Events = @(); HasMore = $false; NextOrdinal = 0; Error = $_.Exception.GetType().FullName }
    }
}

function Get-MihariManagementV2DependencyContext {
    param(
        [Parameter(Mandatory = $true)]$Session,
        [string]$CaseId,
        [string]$TrialId
    )

    $caseRoot = Get-MihariManagementV2CaseRoot -Session $Session
    $traffic = Get-MihariManagementV2CaseTrafficSnapshot -Session $Session
    if ($null -ne $traffic.Error) { throw 'traffic_projection_unavailable' }
    $projection = Get-MihariDependencyProjection -Events $traffic.Events -CaseRoot $caseRoot -MaximumItems 200
    $items = @($projection.items)
    if ($CaseId) { $items = @($items | Where-Object { [string]$_.caseId -eq $CaseId }) }
    if ($TrialId) { $items = @($items | Where-Object { [string]$_.trialId -eq $TrialId }) }

    $coverage = [ordered]@{}
    foreach ($property in $projection.coverage.PSObject.Properties) { $coverage[$property.Name] = $property.Value }
    $coverage['eventScanLimit'] = 20000
    $coverage['eventCountScanned'] = [int]$traffic.Events.Count
    $coverage['eventScanTruncated'] = [bool]$traffic.HasMore
    $projectionTruncated = ([int]$projection.scopeTotal -gt @($projection.items).Count)
    $coverage['dependencyResultsTruncated'] = [bool]$projectionTruncated
    if ($traffic.HasMore -or $projectionTruncated) { $coverage['status'] = 'incomplete' }

    if ($CaseId -or $TrialId) {
        $snapshot = Get-MihariCaseStoreSnapshot -CaseRoot $caseRoot
        $selectedTrials = @($snapshot.Trials | Where-Object {
                (-not $CaseId -or [string]$_.caseId -eq $CaseId) -and
                (-not $TrialId -or [string]$_.trialId -eq $TrialId)
            })
        $unavailableSessionIds = @($selectedTrials | Where-Object { [string]$_.sessionId -ne [string]$Session.Id } | ForEach-Object { [string]$_.sessionId } | Sort-Object -Unique)
        if ($unavailableSessionIds.Count -gt 0) {
            $coverage['unavailableSessionCount'] = [int]$unavailableSessionIds.Count
            $coverage['status'] = 'incomplete'
        }
    }

    $scopeTotal = [int]$items.Count
    if (-not $CaseId -and -not $TrialId) { $scopeTotal = [int]$projection.scopeTotal }
    return [pscustomobject][ordered]@{
        items = @($items | Select-Object -First 200)
        nextCursor = $null
        revision = $projection.revision
        ordering = [string]$projection.ordering
        scopeTotal = $scopeTotal
        coverage = [pscustomobject]$coverage
        freshnessUtc = [string]$projection.freshnessUtc
    }
}

function Get-MihariManagementV2TrialEvents {
    param([Parameter(Mandatory = $true)]$Session, [Parameter(Mandatory = $true)]$Trial)

    if ([string]$Trial.sessionId -ne [string]$Session.Id) {
        return [pscustomobject]@{ Events = @(); Available = $false; Truncated = $false; Reason = 'trial_session_not_active' }
    }
    $traffic = Get-MihariManagementV2CaseTrafficSnapshot -Session $Session
    if ($null -ne $traffic.Error) {
        return [pscustomobject]@{ Events = @(); Available = $false; Truncated = $false; Reason = 'traffic_projection_unavailable' }
    }
    return [pscustomobject]@{ Events = @($traffic.Events); Available = $true; Truncated = [bool]$traffic.HasMore; Reason = $null }
}

function Invoke-MihariManagementV2CaseRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Session,
        [Parameter(Mandatory = $true)]$Request
    )

    $method = [string]$Request.Method
    $path = [string]$Request.Path
    $isRoute = ($path -in @('/api/v2/cases', '/api/v2/trials', '/api/v2/dependencies', '/api/v2/comparisons') -or
        $path -match '^/api/v2/trials/trial-[0-9a-fA-F]{32}/(complete|markers)$' -or
        $path -match '^/api/v2/cases/case-[0-9a-fA-F]{32}/notes$' -or
        $path -match '^/api/v2/dependencies/dep-[0-9a-fA-F]{24}/necessity$')
    if (-not $isRoute) { return $null }
    if ($method -notin @('GET', 'POST')) {
        return (New-MihariManagementErrorResponse -StatusCode 405 -Code 'method_not_allowed' -Message 'Only GET and POST are supported for this route.')
    }

    $caseRoot = $null
    try { $caseRoot = Get-MihariManagementV2CaseRoot -Session $Session }
    catch { return (New-MihariManagementErrorResponse -StatusCode 503 -Code 'case_store_unavailable' -Message 'The case metadata store is unavailable.') }

    if ($path -eq '/api/v2/cases' -and $method -eq 'GET') {
        try {
            $query = Get-MihariManagementV2CaseQuery -Query ([string]$Request.Query) -AllowedNames @('cursor', 'limit')
            $limit = Get-MihariManagementV2CaseLimit -Query $query
            $cursor = $null
            if ($query.Contains('cursor')) { $cursor = [string]$query['cursor'] }
            $page = Get-MihariCases -CaseRoot $caseRoot -MaximumItems $limit -Cursor $cursor
            return (New-MihariManagementJsonResponse -StatusCode 200 -Value $page)
        }
        catch {
            if ($_.Exception.Data['mihariCode'] -eq 'cursor_invalidated') {
                return (New-MihariManagementErrorResponse -StatusCode 409 -Code 'cursor_invalidated' -Message 'Case metadata changed; restart paging from the first page.')
            }
            return (New-MihariManagementErrorResponse -StatusCode 400 -Code 'invalid_case_query' -Message 'The case filter, cursor, or page size is invalid.')
        }
    }

    if ($path -eq '/api/v2/cases' -and $method -eq 'POST') {
        $bodyError = $null
        $body = Read-MihariManagementV2CaseBody -Request $Request -ErrorResponse ([ref]$bodyError)
        if ($null -ne $bodyError) { return $bodyError }
        if (-not (Test-MihariManagementV2BodyFields -Body $body -AllowedNames @('title', 'sessionReferences')) -or
            $null -eq $body.PSObject.Properties['title'] -or [string]$body.title -notmatch '\S') {
            return (New-MihariManagementErrorResponse -StatusCode 400 -Code 'invalid_case' -Message 'A case title is required; optional sessionReferences must be a bounded string list.')
        }
        $sessionReferences = @([string]$Session.Id)
        if ($null -ne $body.PSObject.Properties['sessionReferences']) {
            if ($body.sessionReferences -isnot [Array] -or $body.sessionReferences.Count -gt 32) {
                return (New-MihariManagementErrorResponse -StatusCode 400 -Code 'invalid_case' -Message 'sessionReferences must contain at most 32 session IDs.')
            }
            $sessionReferences = @($body.sessionReferences | ForEach-Object { [string]$_ })
            if ($sessionReferences -notcontains [string]$Session.Id) { $sessionReferences += [string]$Session.Id }
        }
        try {
            $result = New-MihariCase -CaseRoot $caseRoot -Title ([string]$body.title) -SessionReferences $sessionReferences
            return (New-MihariManagementV2CompletedResponse -Result $result)
        }
        catch { return (New-MihariManagementErrorResponse -StatusCode 400 -Code 'case_create_failed' -Message 'The case could not be created from the supplied metadata.') }
    }

    if ($path -eq '/api/v2/trials' -and $method -eq 'GET') {
        try {
            $query = Get-MihariManagementV2CaseQuery -Query ([string]$Request.Query) -AllowedNames @('caseId', 'sessionId', 'cursor', 'limit')
            $limit = Get-MihariManagementV2CaseLimit -Query $query
            $parameters = @{ CaseRoot = $caseRoot; MaximumItems = $limit }
            if ($query.Contains('caseId')) { $parameters.CaseId = [string]$query['caseId'] }
            if ($query.Contains('sessionId')) { $parameters.SessionId = [string]$query['sessionId'] }
            if ($query.Contains('cursor')) { $parameters.Cursor = [string]$query['cursor'] }
            $page = Get-MihariTrials @parameters
            return (New-MihariManagementJsonResponse -StatusCode 200 -Value $page)
        }
        catch {
            if ($_.Exception.Data['mihariCode'] -eq 'cursor_invalidated') {
                return (New-MihariManagementErrorResponse -StatusCode 409 -Code 'cursor_invalidated' -Message 'Case metadata changed; restart paging from the first page.')
            }
            return (New-MihariManagementErrorResponse -StatusCode 400 -Code 'invalid_trial_query' -Message 'The case/session filter, cursor, or page size is invalid.')
        }
    }

    if ($path -eq '/api/v2/trials' -and $method -eq 'POST') {
        $bodyError = $null
        $body = Read-MihariManagementV2CaseBody -Request $Request -ErrorResponse ([ref]$bodyError)
        if ($null -ne $bodyError) { return $bodyError }
        if (-not (Test-MihariManagementV2BodyFields -Body $body -AllowedNames @('caseId')) -or
            $null -eq $body.PSObject.Properties['caseId'] -or -not (Test-MihariCaseId -CaseId ([string]$body.caseId))) {
            return (New-MihariManagementErrorResponse -StatusCode 400 -Code 'invalid_trial' -Message 'A valid caseId is required to start a trial.')
        }
        $case = Get-MihariCase -CaseRoot $caseRoot -CaseId ([string]$body.caseId)
        if ($null -eq $case) { return (New-MihariManagementErrorResponse -StatusCode 404 -Code 'case_not_found' -Message 'The requested case does not exist.') }
        try {
            $environmentReference = Save-MihariManagementV2EnvironmentSnapshot -Session $Session -CaseRoot $caseRoot
            $result = New-MihariTrial -CaseRoot $caseRoot -CaseId ([string]$body.caseId) -SessionId ([string]$Session.Id) `
                -Profile (New-MihariManagementV2TrialProfile -Session $Session) `
                -ConfigurationRevision ([string]$Session.ConfigurationRevision) `
                -EnvironmentReference $environmentReference -OutputDirectory $caseRoot
            return (New-MihariManagementV2CompletedResponse -Result $result)
        }
        catch {
            return (New-MihariManagementErrorResponse -StatusCode 503 -Code 'trial_start_failed' -Message 'The trial could not capture its session profile and environment reference.')
        }
    }

    if ($path -match '^/api/v2/trials/(trial-[0-9a-fA-F]{32})/complete$' -and $method -eq 'POST') {
        $trialId = [string]$Matches[1]
        $bodyError = $null
        $body = Read-MihariManagementV2CaseBody -Request $Request -ErrorResponse ([ref]$bodyError)
        if ($null -ne $bodyError) { return $bodyError }
        if (-not (Test-MihariManagementV2BodyFields -Body $body -AllowedNames @('businessOutcome', 'note')) -or
            $null -eq $body.PSObject.Properties['businessOutcome'] -or
            [string]$body.businessOutcome -notin @('succeeded', 'failed', 'not_reproduced', 'unknown')) {
            return (New-MihariManagementErrorResponse -StatusCode 400 -Code 'invalid_trial_outcome' -Message 'businessOutcome must be succeeded, failed, not_reproduced, or unknown.')
        }
        try {
            $trial = Get-MihariTrial -CaseRoot $caseRoot -TrialId $trialId
            if ($null -eq $trial) { return (New-MihariManagementErrorResponse -StatusCode 404 -Code 'trial_not_found' -Message 'The requested trial does not exist.') }
            $note = $null
            if ($null -ne $body.PSObject.Properties['note']) { $note = [string]$body.note }
            $result = Complete-MihariTrial -CaseRoot $caseRoot -TrialId $trialId -OperatorBusinessOutcome ([string]$body.businessOutcome) -Note $note
            return (New-MihariManagementV2CompletedResponse -Result $result)
        }
        catch { return (New-MihariManagementErrorResponse -StatusCode 409 -Code 'trial_complete_failed' -Message 'The trial could not be completed; it may already have ended.') }
    }

    if ($path -match '^/api/v2/trials/(trial-[0-9a-fA-F]{32})/markers$') {
        $trialId = [string]$Matches[1]
        if ($method -eq 'GET') {
            try {
                $trial = Get-MihariTrial -CaseRoot $caseRoot -TrialId $trialId
                if ($null -eq $trial) { return (New-MihariManagementErrorResponse -StatusCode 404 -Code 'trial_not_found' -Message 'The requested trial does not exist.') }
                $query = Get-MihariManagementV2CaseQuery -Query ([string]$Request.Query) -AllowedNames @('cursor', 'limit')
                $limit = Get-MihariManagementV2CaseLimit -Query $query
                $parameters = @{ CaseRoot = $caseRoot; TrialId = $trialId; MaximumItems = $limit }
                if ($query.Contains('cursor')) { $parameters.Cursor = [string]$query['cursor'] }
                $page = Get-MihariMarkers @parameters
                return (New-MihariManagementJsonResponse -StatusCode 200 -Value $page)
            }
            catch {
                if ($_.Exception.Data['mihariCode'] -eq 'cursor_invalidated') {
                    return (New-MihariManagementErrorResponse -StatusCode 409 -Code 'cursor_invalidated' -Message 'Case metadata changed; restart paging from the first page.')
                }
                return (New-MihariManagementErrorResponse -StatusCode 400 -Code 'invalid_marker_query' -Message 'The marker cursor or page size is invalid.')
            }
        }
        $bodyError = $null
        $body = Read-MihariManagementV2CaseBody -Request $Request -ErrorResponse ([ref]$bodyError)
        if ($null -ne $bodyError) { return $bodyError }
        if (-not (Test-MihariManagementV2BodyFields -Body $body -AllowedNames @('boundary', 'label', 'note')) -or
            [string]$body.boundary -notin @('point', 'start', 'end', 'note') -or
            $null -eq $body.PSObject.Properties['label'] -or [string]$body.label -notmatch '\S') {
            return (New-MihariManagementErrorResponse -StatusCode 400 -Code 'invalid_marker' -Message 'A marker boundary and label are required.')
        }
        try {
            $note = $null
            if ($null -ne $body.PSObject.Properties['note']) { $note = [string]$body.note }
            $result = Add-MihariMarker -CaseRoot $caseRoot -TrialId $trialId -Boundary ([string]$body.boundary) -Label ([string]$body.label) -Note $note
            return (New-MihariManagementV2CompletedResponse -Result $result)
        }
        catch { return (New-MihariManagementErrorResponse -StatusCode 404 -Code 'marker_create_failed' -Message 'The marker could not be added to that trial.') }
    }

    if ($path -match '^/api/v2/cases/(case-[0-9a-fA-F]{32})/notes$' -and $method -eq 'POST') {
        $caseId = [string]$Matches[1]
        $bodyError = $null
        $body = Read-MihariManagementV2CaseBody -Request $Request -ErrorResponse ([ref]$bodyError)
        if ($null -ne $bodyError) { return $bodyError }
        if (-not (Test-MihariManagementV2BodyFields -Body $body -AllowedNames @('text', 'trialId')) -or
            $null -eq $body.PSObject.Properties['text'] -or [string]$body.text -notmatch '\S' -or
            ($null -ne $body.PSObject.Properties['trialId'] -and -not (Test-MihariTrialId -TrialId ([string]$body.trialId)))) {
            return (New-MihariManagementErrorResponse -StatusCode 400 -Code 'invalid_case_note' -Message 'A note is required, with an optional valid trialId.')
        }
        try {
            $parameters = @{ CaseRoot = $caseRoot; CaseId = $caseId; Text = [string]$body.text }
            if ($null -ne $body.PSObject.Properties['trialId']) { $parameters.TrialId = [string]$body.trialId }
            $result = Add-MihariCaseNote @parameters
            return (New-MihariManagementV2CompletedResponse -Result $result)
        }
        catch { return (New-MihariManagementErrorResponse -StatusCode 400 -Code 'case_note_failed' -Message 'The note could not be added to the requested case/trial.') }
    }

    if ($path -eq '/api/v2/dependencies' -and $method -eq 'GET') {
        try {
            $query = Get-MihariManagementV2CaseQuery -Query ([string]$Request.Query) -AllowedNames @('caseId', 'trialId')
            if ($query.Contains('caseId') -and -not (Test-MihariCaseId -CaseId ([string]$query['caseId']))) { throw 'invalid_case_id' }
            if ($query.Contains('trialId') -and -not (Test-MihariTrialId -TrialId ([string]$query['trialId']))) { throw 'invalid_trial_id' }
            $parameters = @{ Session = $Session }
            if ($query.Contains('caseId')) { $parameters.CaseId = [string]$query['caseId'] }
            if ($query.Contains('trialId')) { $parameters.TrialId = [string]$query['trialId'] }
            $page = Get-MihariManagementV2DependencyContext @parameters
            return (New-MihariManagementJsonResponse -StatusCode 200 -Value $page)
        }
        catch {
            if ([string]$_.Exception.Message -eq 'traffic_projection_unavailable') {
                return (New-MihariManagementErrorResponse -StatusCode 503 -Code 'traffic_projection_unavailable' -Message 'Canonical traffic evidence could not be projected; the dependency scope is unavailable.')
            }
            return (New-MihariManagementErrorResponse -StatusCode 400 -Code 'invalid_dependency_query' -Message 'The case/trial filter is invalid.')
        }
    }

    if ($path -match '^/api/v2/dependencies/(dep-[0-9a-fA-F]{24})/necessity$' -and $method -eq 'POST') {
        $dependencyId = [string]$Matches[1]
        $bodyError = $null
        $body = Read-MihariManagementV2CaseBody -Request $Request -ErrorResponse ([ref]$bodyError)
        if ($null -ne $bodyError) { return $bodyError }
        if (-not (Test-MihariManagementV2BodyFields -Body $body -AllowedNames @('state', 'confirmBusinessRequired', 'rationale')) -or
            [string]$body.state -notin @('necessity_unconfirmed', 'business_required_confirmed') -or
            ($null -ne $body.PSObject.Properties['confirmBusinessRequired'] -and $body.confirmBusinessRequired -isnot [bool]) -or
            ([string]$body.state -eq 'business_required_confirmed' -and $body.confirmBusinessRequired -ne $true)) {
            return (New-MihariManagementErrorResponse -StatusCode 400 -Code 'invalid_necessity' -Message 'A supported necessity state and explicit business confirmation are required.')
        }
        try {
            $context = Get-MihariManagementV2DependencyContext -Session $Session
            $dependency = @($context.items | Where-Object { [string]$_.dependencyId -eq $dependencyId } | Select-Object -First 1)
            if ($dependency.Count -eq 0) { return (New-MihariManagementErrorResponse -StatusCode 404 -Code 'dependency_not_found' -Message 'The dependency is not in the active canonical evidence scope.') }
            $parameters = @{ CaseRoot = $caseRoot; Dependency = $dependency[0]; State = [string]$body.state }
            if ($body.confirmBusinessRequired -eq $true) { $parameters.ConfirmBusinessRequired = $true }
            if ($null -ne $body.PSObject.Properties['rationale']) { $parameters.Rationale = [string]$body.rationale }
            $result = Set-MihariDependencyNecessity @parameters
            return (New-MihariManagementV2CompletedResponse -Result $result)
        }
        catch {
            return (New-MihariManagementErrorResponse -StatusCode 409 -Code 'necessity_update_failed' -Message 'The necessity state could not be recorded with the current canonical dependency evidence.')
        }
    }

    if ($path -eq '/api/v2/comparisons' -and $method -eq 'GET') {
        try {
            $query = Get-MihariManagementV2CaseQuery -Query ([string]$Request.Query) -AllowedNames @('beforeTrialId', 'afterTrialId')
            if (-not $query.Contains('beforeTrialId') -or -not $query.Contains('afterTrialId') -or
                -not (Test-MihariTrialId -TrialId ([string]$query['beforeTrialId'])) -or
                -not (Test-MihariTrialId -TrialId ([string]$query['afterTrialId']))) { throw 'invalid_trial_ids' }
            if ([string]$query['beforeTrialId'] -eq [string]$query['afterTrialId']) { throw 'same_trial_ids' }
            $beforeTrial = Get-MihariTrial -CaseRoot $caseRoot -TrialId ([string]$query['beforeTrialId'])
            $afterTrial = Get-MihariTrial -CaseRoot $caseRoot -TrialId ([string]$query['afterTrialId'])
            if ($null -eq $beforeTrial -or $null -eq $afterTrial) {
                return (New-MihariManagementErrorResponse -StatusCode 404 -Code 'trial_not_found' -Message 'One or both requested trials do not exist.')
            }
            $beforeSnapshot = Get-MihariManagementV2TrialEvents -Session $Session -Trial $beforeTrial
            $afterSnapshot = $beforeSnapshot
            if ([string]$beforeTrial.sessionId -ne [string]$afterTrial.sessionId) {
                $afterSnapshot = Get-MihariManagementV2TrialEvents -Session $Session -Trial $afterTrial
            }
            $comparison = New-MihariTrialComparison -BeforeTrial $beforeTrial -AfterTrial $afterTrial `
                -BeforeEvents $beforeSnapshot.Events -AfterEvents $afterSnapshot.Events
            $sourceAvailable = ([bool]$beforeSnapshot.Available -and [bool]$afterSnapshot.Available)
            $truncated = ([bool]$beforeSnapshot.Truncated -or [bool]$afterSnapshot.Truncated)
            $comparison | Add-Member -NotePropertyName collectionCoverage -NotePropertyValue ([pscustomobject][ordered]@{
                status = $(if (-not $sourceAvailable) { 'unknown' } elseif ($truncated) { 'truncated' } else { 'observed' })
                beforeSessionAvailable = [bool]$beforeSnapshot.Available
                afterSessionAvailable = [bool]$afterSnapshot.Available
                beforeEventCount = [int]@($beforeSnapshot.Events).Count
                afterEventCount = [int]@($afterSnapshot.Events).Count
                eventScanLimit = 20000
                truncated = $truncated
            })
            if (-not $sourceAvailable -or $truncated) {
                $comparison.comparisonKind = 'incomplete'
                $comparison.evidenceStrength = 'undetermined'
                $comparison.supportedFindings = @()
                $comparison.interpretation = 'Comparison evidence is incomplete because one trial session is outside the active canonical traffic projection or the bounded event read was truncated.'
            }
            return (New-MihariManagementJsonResponse -StatusCode 200 -Value $comparison)
        }
        catch { return (New-MihariManagementErrorResponse -StatusCode 400 -Code 'invalid_comparison_query' -Message 'Supply two distinct valid trial IDs.') }
    }

    return $null
}
