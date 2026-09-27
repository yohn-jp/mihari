# Focused Phase 2 management routes. Domain modules own their data and rules.

function Get-MihariManagementV2Query {
    param([AllowNull()][string]$Query)

    $values = [ordered]@{}
    if ([string]::IsNullOrEmpty($Query)) { return $values }
    if ($Query.Length -gt 4096) { throw 'query_too_large' }
    foreach ($part in ($Query -split '&')) {
        if ([string]::IsNullOrEmpty($part)) { continue }
        $separator = $part.IndexOf('=')
        if ($separator -lt 1) { throw 'invalid_query' }
        $name = [Uri]::UnescapeDataString($part.Substring(0, $separator).Replace('+', ' '))
        $value = [Uri]::UnescapeDataString($part.Substring($separator + 1).Replace('+', ' '))
        if ($name -notmatch '^[A-Za-z][A-Za-z0-9]{0,39}$' -or $value.Length -gt 2048 -or $values.Contains($name)) { throw 'invalid_query' }
        $values[$name] = $value
    }
    return $values
}

function Get-MihariManagementV2TrafficStore {
    param([Parameter(Mandatory = $true)]$Session)

    [System.Threading.Monitor]::Enter($Session.StateLock)
    try {
        if ($null -eq $Session.TrafficProjection) {
            $indexDirectory = Join-Path ([string]$Session.OutputDirectory) 'traffic-index'
            $Session.TrafficProjection = New-MihariTrafficProjectionStore -SessionId ([string]$Session.Id) -EventsPath ([string]$Session.EventsPath) -IndexDirectory $indexDirectory
        }
        return $Session.TrafficProjection
    }
    finally { [System.Threading.Monitor]::Exit($Session.StateLock) }
}

function Invoke-MihariManagementV2TrafficRequest {
    param([Parameter(Mandatory = $true)]$Session, [Parameter(Mandatory = $true)]$Request)

    $path = [string]$Request.Path
    if ([string]$Request.Method -ne 'GET' -or
        ($path -ne '/api/v2/requests' -and $path -notmatch '^/api/v2/requests/[^/]+$')) { return $null }
    try {
        $store = Get-MihariManagementV2TrafficStore -Session $Session
        $null = Update-MihariTrafficProjectionStore -Store $store
        $Session.TrafficProjectionError = $null
    }
    catch {
        if ($null -ne $Session.PSObject.Properties['TrafficProjectionError']) {
            $Session.TrafficProjectionError = $_.Exception.GetType().FullName
        }
        return (New-MihariManagementErrorResponse -StatusCode 503 -Code 'traffic_projection_failed' -Message 'The canonical traffic log could not be projected; capture coverage is incomplete.')
    }
    if ($path -eq '/api/v2/requests') {
        try {
            $query = Get-MihariManagementV2Query -Query ([string]$Request.Query)
            $filters = [ordered]@{}
            foreach ($key in $query.Keys) {
                if ($key -in @('host', 'pathPrefix', 'method', 'status', 'mode', 'protocol', 'stage', 'source', 'fromUtc', 'toUtc', 'preset')) {
                    $filters[$key] = $query[$key]
                }
                elseif ($key -notin @('cursor', 'limit')) { throw 'unsupported_query_field' }
            }
            $limit = 100
            if ($query.Contains('limit')) {
                if ([string]$query.limit -notmatch '^\d{1,3}$') { throw 'invalid_limit' }
                $limit = [int]$query.limit
                if ($limit -lt 1 -or $limit -gt 200) { throw 'invalid_limit' }
            }
            $cursor = $null
            if ($query.Contains('cursor')) { $cursor = [string]$query.cursor }
            $page = Get-MihariTrafficRequests -Store $store -Filters $filters -Cursor $cursor -Limit $limit
            return (New-MihariManagementJsonResponse -StatusCode 200 -Value $page)
        }
        catch {
            if ($_.Exception.Data['mihariCode'] -eq 'cursor_invalidated') {
                return (New-MihariManagementErrorResponse -StatusCode 409 -Code 'cursor_invalidated' -Message 'The canonical log changed; restart paging from the first page.')
            }
            return (New-MihariManagementErrorResponse -StatusCode 400 -Code 'invalid_traffic_query' -Message 'The traffic filter, cursor, or page size is invalid.')
        }
    }
    try {
        $key = [Uri]::UnescapeDataString($path.Substring('/api/v2/requests/'.Length))
        if ($key.Length -lt 1 -or $key.Length -gt 512 -or $key -match '[\x00-\x1f\x7f/#?]') { throw 'invalid_key' }
        $detail = Get-MihariTrafficRequestDetail -Store $store -Key $key
        if ($null -eq $detail) { return (New-MihariManagementErrorResponse -StatusCode 404 -Code 'request_not_found' -Message 'The request key is not in this session.') }
        return (New-MihariManagementJsonResponse -StatusCode 200 -Value $detail)
    }
    catch {
        return (New-MihariManagementErrorResponse -StatusCode 400 -Code 'invalid_request_key' -Message 'The request key is invalid.')
    }
}

function Invoke-MihariManagementV2Request {
    param(
        [Parameter(Mandatory = $true)]$Session,
        [Parameter(Mandatory = $true)]$Request
    )

    $method = [string]$Request.Method
    $path = [string]$Request.Path
    $trafficResponse = Invoke-MihariManagementV2TrafficRequest -Session $Session -Request $Request
    if ($null -ne $trafficResponse) { return $trafficResponse }
    if ($method -eq 'GET' -and $path -eq '/api/v2/capabilities') {
        $environment = Get-MihariEnvironmentCapabilities
        $inspect = Test-MihariCapability -Mode Inspect
        $nativeH2 = 'not_verified_on_this_host'
        if (-not $environment.tlsAlpnProperty) { $nativeH2 = 'unavailable_managed_alpn' }
        elseif (Get-Command Test-MihariHttp2RuntimeCapability -ErrorAction SilentlyContinue) {
            $nativeProbe = Test-MihariHttp2RuntimeCapability
            if (-not $nativeProbe.Available) { $nativeH2 = 'unavailable_managed_alpn' }
        }
        return (New-MihariManagementJsonResponse -StatusCode 200 -Value ([pscustomobject][ordered]@{
            schemaVersion = 2
            profile = [string]$Session.Profile
            mode = [string]$Session.Mode
            httpConnectionPolicy = [string]$Session.HttpConnectionPolicy
            environment = $environment
            http1Inspect = $(if ($inspect.Available) { 'available' } else { 'unavailable' })
            http2Tunnel = 'available_for_trial'
            http2BrowserAssisted = 'unverified'
            http2Inspect = $nativeH2
            limits = [pscustomobject]@{
                maximumWorkers = [int]$Session.MaxWorkers
                maximumPageItems = 200
                maximumApiResponseBytes = 1048576
                maximumManagementBodyBytes = 8192
                maximumManagementHeaderBytes = 16384
                hotRequestRecords = $(if ($null -ne $Session.TrafficProjection) { [int]$Session.TrafficProjection.HotLimit } else { $null })
            }
        }))
    }
    if ($method -eq 'GET' -and $path -eq '/api/v2/environment') {
        try { $snapshot = Get-MihariEnvironmentSnapshot -Session $Session -Destinations @() }
        catch {
            return (New-MihariManagementErrorResponse -StatusCode 503 -Code 'environment_snapshot_failed' -Message 'Mihari could not collect the read-only environment snapshot.')
        }
        return (New-MihariManagementJsonResponse -StatusCode 200 -Value $snapshot)
    }
    if ($method -eq 'GET' -and $path -eq '/api/v2/exclusions') {
        return (New-MihariManagementJsonResponse -StatusCode 200 -Value ([pscustomobject][ordered]@{
            configurationRevision = [int]$Session.ConfigurationRevision
            effectiveFor = 'new_connections'
            items = @($Session.LocalInspectExclusions)
        }))
    }
    if ($method -eq 'POST' -and $path -eq '/api/v2/exclusions') {
        try { $body = Read-MihariManagementJsonBody -Request $Request }
        catch { return (New-MihariManagementErrorResponse -StatusCode 400 -Code 'invalid_json' -Message 'Supply a JSON object with exact host and excluded boolean.') }
        if ($null -eq $body.PSObject.Properties['host'] -or
            $null -eq $body.PSObject.Properties['excluded'] -or
            $body.excluded -isnot [bool]) {
            return (New-MihariManagementErrorResponse -StatusCode 400 -Code 'invalid_exclusion' -Message 'An exact host and excluded boolean are required.')
        }
        try { $result = Set-MihariLocalInspectExclusion -Session $Session -HostName ([string]$body.host) -Excluded ([bool]$body.excluded) }
        catch { return (New-MihariManagementErrorResponse -StatusCode 400 -Code 'invalid_exclusion' -Message 'The exact-host exclusion could not be changed.') }
        return (New-MihariManagementJsonResponse -StatusCode 200 -Value ([pscustomobject]@{ state = 'completed'; result = $result }))
    }
    return $null
}
