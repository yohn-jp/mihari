param()

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'TestSupport.ps1')
$repoRoot = Split-Path $PSScriptRoot -Parent
. (Join-Path $repoRoot 'src/Observation.ps1')
. (Join-Path $repoRoot 'src/Browser.ps1')

function Read-MihariBrowserObservationTestText {
    param([Parameter(Mandatory = $true)][string] $Path)

    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    $reader = $null
    try {
        $reader = [IO.StreamReader]::new($stream, [Text.Encoding]::UTF8, $true)
        return $reader.ReadToEnd()
    }
    finally {
        if ($null -ne $reader) { $reader.Dispose() }
        elseif ($null -ne $stream) { $stream.Dispose() }
    }
}

$temporaryDirectory = Join-Path ([IO.Path]::GetTempPath()) ('mihari-browser-observation-test-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($temporaryDirectory)
$testProfilePath = Join-Path (Join-Path $temporaryDirectory 'Edge Profile') 'Edge-owned-0123456789abcdef0123456789abcdef'
$quotedBrowserCommandLine = '"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" "--user-data-dir={0}" --remote-debugging-port=0' -f $testProfilePath
$quotedProfileValueCommandLine = '"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --user-data-dir="{0}" --remote-debugging-port=0' -f $testProfilePath
$neighboringProfileCommandLine = '"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" "--user-data-dir={0}-other" --remote-debugging-port=0' -f $testProfilePath
Assert-MihariTest -Condition ((Test-MihariBrowserOwnedProfileArgument -CommandLine $quotedBrowserCommandLine -ProfilePath $testProfilePath) -and
    (Test-MihariBrowserOwnedProfileArgument -CommandLine $quotedProfileValueCommandLine -ProfilePath $testProfilePath) -and
    -not (Test-MihariBrowserOwnedProfileArgument -CommandLine $neighboringProfileCommandLine -ProfilePath $testProfilePath)) -Message 'Owned Edge verification must parse quoted profile arguments exactly without accepting a neighboring profile path.'
$writer = $null
try {
    $target = ConvertTo-MihariBrowserSafeTarget -Url 'https://alice:password@example.test/api/upload?token=browser-query-secret&session=browser-query-secret#fragment'
    Assert-MihariTest -Condition ($target.Host -eq 'example.test' -and $target.Scheme -eq 'https' -and $target.Path -eq '/api/upload') -Message 'Browser URLs must retain only scheme, host, port, and path.'
    $targetJson = ConvertTo-Json -InputObject $target -Depth 4 -Compress
    Assert-MihariTest -Condition (-not $targetJson.Contains('alice') -and -not $targetJson.Contains('password') -and -not $targetJson.Contains('browser-query-secret') -and -not $targetJson.Contains('fragment')) -Message 'Browser URL normalization must exclude user info, query values, and fragments.'

    $requestFact = ConvertTo-MihariBrowserRequestFact -SessionId 'session-test' -ProcessId 1234 `
        -TargetId 'raw-target-id' -BrowserRequestId 'raw-request-id' -FrameId 'raw-frame-id' -RedirectIndex 1 `
        -Request ([pscustomobject]@{ url = 'https://alice:password@example.test/api/upload?token=browser-query-secret'; method = 'post' }) `
        -Response ([pscustomobject]@{ status = 200; protocol = 'h2'; connectionId = 42; fromDiskCache = $false; fromServiceWorker = $true }) `
        -InitiatorType 'script' -Outcome 'completed' -ErrorText $null -BlockedReason $null -CorsError $null `
        -StartTimestamp 41.0 -EndTimestamp 41.125 -BrowserConnectionId 42 -FromDiskCache $false -FromServiceWorker $true
    Assert-MihariTest -Condition ($requestFact.ElapsedMs -eq 125 -and $requestFact.Data.protocol -eq 'h2' -and $requestFact.Data.statusCode -eq 200) -Message 'Browser facts must retain the protocol/status and measured request duration.'
    Assert-MihariTest -Condition ($requestFact.Data.fromDiskCache -eq $false -and $requestFact.Data.fromServiceWorker -eq $true -and $requestFact.Data.initiatorType -eq 'script') -Message 'Browser facts must distinguish cache, Service Worker, and initiator evidence.'
    Assert-MihariTest -Condition ($requestFact.Data.browserRedirectIndex -eq 1 -and $requestFact.Data.browserFrameId -match '^bf-' -and $requestFact.Data.browserTargetId -match '^bt-' -and $requestFact.Data.browserRequestId -match '^br-' -and $requestFact.Data.browserConnectionId -match '^bc-') -Message 'Browser IDs must be scoped hashes, with redirect occurrence retained.'
    $requestFactJson = ConvertTo-Json -InputObject $requestFact -Depth 8 -Compress
    Assert-MihariTest -Condition (-not $requestFactJson.Contains('raw-target-id') -and -not $requestFactJson.Contains('raw-request-id') -and -not $requestFactJson.Contains('raw-frame-id') -and -not $requestFactJson.Contains('browser-query-secret') -and -not $requestFactJson.Contains('password')) -Message 'Browser facts must not retain raw CDP IDs or sensitive URL material.'

    $unmeasuredFact = ConvertTo-MihariBrowserRequestFact -SessionId 'session-test' -ProcessId 1234 `
        -TargetId 'target-2' -BrowserRequestId 'request-2' -FrameId $null -RedirectIndex 0 `
        -Request ([pscustomobject]@{ url = 'https://example.test/no-timing'; method = 'GET' }) `
        -Response $null -InitiatorType $null -Outcome 'failed' -ErrorText 'net::ERR_NAME_NOT_RESOLVED' `
        -BlockedReason $null -CorsError $null -StartTimestamp $null -EndTimestamp $null `
        -BrowserConnectionId $null -FromDiskCache $null -FromServiceWorker $null
    Assert-MihariTest -Condition ($null -eq $unmeasuredFact.ElapsedMs -and -not $unmeasuredFact.Data.Contains('browserTimingDurationMs')) -Message 'Missing browser timing must remain unknown and must not be written as zero.'
    Assert-MihariTest -Condition ($unmeasuredFact.Data.browserError -eq 'net::ERR_NAME_NOT_RESOLVED') -Message 'Browser failures must retain only the allowlisted stable error token.'
    $oneSidedTimingFact = ConvertTo-MihariBrowserRequestFact -SessionId 'session-test' -ProcessId 1234 `
        -TargetId 'target-3' -BrowserRequestId 'request-3' -FrameId $null -RedirectIndex 0 `
        -Request ([pscustomobject]@{ url = 'https://example.test/partial-timing'; method = 'GET' }) `
        -Response $null -InitiatorType $null -Outcome 'incomplete' -ErrorText $null `
        -BlockedReason $null -CorsError $null -StartTimestamp 41.0 -EndTimestamp $null `
        -BrowserConnectionId $null -FromDiskCache $null -FromServiceWorker $null
    Assert-MihariTest -Condition ($null -eq $oneSidedTimingFact.ElapsedMs -and
        -not $oneSidedTimingFact.Data.Contains('browserTimingOrigin') -and
        -not $oneSidedTimingFact.Data.Contains('browserTimingStartMs') -and
        -not $oneSidedTimingFact.Data.Contains('browserTimingDurationMs')) -Message 'A single monotonic timestamp must not be promoted into a measured duration or timing pair.'

    $targetSessions = @{}
    $firstTarget = Add-MihariBrowserObserverTarget -TargetSessions $targetSessions -SessionId 'session-1' -TargetId 'target-1' -MaximumTargets 1
    $duplicateTarget = Add-MihariBrowserObserverTarget -TargetSessions $targetSessions -SessionId 'session-1' -TargetId 'target-1' -MaximumTargets 1
    $overflowTarget = Add-MihariBrowserObserverTarget -TargetSessions $targetSessions -SessionId 'session-2' -TargetId 'target-2' -MaximumTargets 1
    Assert-MihariTest -Condition ($firstTarget.Added -and $duplicateTarget.AlreadyTracked -and
        $overflowTarget.Overflow -and $targetSessions.Count -eq 1) -Message 'Browser observer target maps must be bounded and distinguish tracked, duplicate, and overflow admission.'
    $pendingAttempts = @{}
    $firstAttempt = Add-MihariBrowserObserverAttempt -Attempts $pendingAttempts -Key 'target-1/request-1' -Record ([ordered]@{ value = 'first' }) -MaximumAttempts 1
    $redirectAttempt = Add-MihariBrowserObserverAttempt -Attempts $pendingAttempts -Key 'target-1/request-1' -Record ([ordered]@{ value = 'redirect' }) -MaximumAttempts 1
    $overflowAttempt = Add-MihariBrowserObserverAttempt -Attempts $pendingAttempts -Key 'target-1/request-2' -Record ([ordered]@{ value = 'second' }) -MaximumAttempts 1
    Assert-MihariTest -Condition ($firstAttempt.Added -and $redirectAttempt.Added -and
        $pendingAttempts.Count -eq 1 -and $pendingAttempts['target-1/request-1'].value -eq 'redirect' -and
        $overflowAttempt.Overflow) -Message 'Browser pending request maps must stay bounded while allowing redirect replacement.'
    $limitCheckpoints = @(1..8 | Where-Object { Test-MihariBrowserLimitCountCheckpoint -Count $_ })
    Assert-MihariTest -Condition ([string]::Join(',', [string[]]$limitCheckpoints) -eq '1,2,4,8') -Message 'Browser overflow health checkpoints must grow logarithmically rather than emit an event for every dropped item.'

    $writerPath = Join-Path $temporaryDirectory 'browser-events.jsonl'
    $writer = New-MihariEventWriter -Path $writerPath
    $session = [pscustomobject]@{
        Id = 'session-test'
        Mode = 'Tunnel'
        ConfigurationRevision = 4
        Writer = $writer
    }
    $launch = [pscustomobject]@{ SourceIdentity = 'edge-test-source'; ClockId = 'edge-test-clock' }
    Write-MihariBrowserObservationFact -Session $session -Launch $launch -Stage 'browser.network.request' `
        -Outcome $requestFact.Outcome -ConnectionId $requestFact.ConnectionId -RequestId $requestFact.RequestId `
        -ElapsedMs $requestFact.ElapsedMs -Data $requestFact.Data -Coverage $requestFact.Coverage
    Write-MihariBrowserObservationFact -Session $session -Launch $launch -Stage 'browser.network.request' `
        -Outcome $unmeasuredFact.Outcome -ConnectionId $unmeasuredFact.ConnectionId -RequestId $unmeasuredFact.RequestId `
        -ElapsedMs $unmeasuredFact.ElapsedMs -Data $unmeasuredFact.Data -Coverage 'observed'
    $eventText = Read-MihariBrowserObservationTestText -Path $writerPath
    $writtenEvents = @($eventText -split '\r?\n' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { ConvertFrom-Json -InputObject $_ })
    Assert-MihariTest -Condition ($writtenEvents.Count -eq 2 -and $writtenEvents[0].schemaVersion -eq 2 -and $writtenEvents[0].source -eq 'browser' -and $writtenEvents[0].sequence -eq 1) -Message 'Browser producers must write through the canonical sequenced fact writer.'
    Assert-MihariTest -Condition ($null -eq $writtenEvents[1].elapsedMs -and $null -eq $writtenEvents[1].data.PSObject.Properties['browserTimingDurationMs']) -Message 'The canonical event must preserve an unavailable browser duration as null.'
    Assert-MihariTest -Condition (-not $eventText.Contains('browser-query-secret') -and -not $eventText.Contains('password') -and -not $eventText.Contains('raw-request-id')) -Message 'Persisted browser facts must exclude credentials, query values, and raw debugger identifiers.'
    Write-MihariBrowserObservationLimitFact -Session $session -Launch $launch -LimitKind 'target' -DroppedCount 3
    Write-MihariBrowserObservationLimitFact -Session $session -Launch $launch -LimitKind 'request' -DroppedCount 2
    $limitEvents = @((Read-MihariBrowserObservationTestText -Path $writerPath) -split '\r?\n' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { ConvertFrom-Json -InputObject $_ })
    Assert-MihariTest -Condition ($limitEvents.Count -eq 4 -and
        @($limitEvents | Where-Object { $_.stage -eq 'browser.observation' -and $_.outcome -eq 'observer_limit' -and $_.coverage -eq 'truncated' -and $_.data.browserError -eq 'target_limit_reached' -and [long]$_.data.browserDroppedTargetCount -eq 3 }).Count -eq 1 -and
        @($limitEvents | Where-Object { $_.stage -eq 'browser.observation' -and $_.outcome -eq 'observer_limit' -and $_.coverage -eq 'truncated' -and $_.data.browserError -eq 'request_limit_reached' -and [long]$_.data.browserDroppedRequestCount -eq 2 }).Count -eq 1) -Message 'Browser observer overflow must persist explicit truncated tool-health facts and cumulative target/request drop counts.'
    $diagnosticProfilePath = Join-Path $temporaryDirectory 'owned-profile-diagnostic'
    $null = [System.IO.Directory]::CreateDirectory($diagnosticProfilePath)
    $diagnosticMarkerPath = Join-Path $diagnosticProfilePath 'MihariProfileOwner.json'
    $diagnosticMarker = [pscustomobject]@{
        owner = 'Mihari'
        sessionId = 'another-session'
        processId = 4321
        profilePath = $diagnosticProfilePath
        executablePath = 'C:\Program Files\Microsoft\Edge\Application\msedge.exe'
        processStartTimeUtc = '2026-01-02T03:04:05.0000000Z'
    }
    [System.IO.File]::WriteAllText($diagnosticMarkerPath, (ConvertTo-Json -InputObject $diagnosticMarker -Compress), [System.Text.UTF8Encoding]::new($false))
    $diagnosticLaunch = [pscustomobject]@{
        Pid = 4321
        ProfilePath = $diagnosticProfilePath
        Path = [string]$diagnosticMarker.executablePath
        OwnerStartTimeUtc = [string]$diagnosticMarker.processStartTimeUtc
    }
    $ownedProcessVerification = Get-MihariBrowserOwnedProcessVerification -SessionId 'session-test' -Launch $diagnosticLaunch
    Assert-MihariTest -Condition (-not $ownedProcessVerification.Verified -and
        $ownedProcessVerification.FailureDetailCode -eq 'profile_marker_mismatch') -Message 'Owned browser verification must classify marker mismatches with a fixed safe detail code.'
    $observerUnavailable = New-MihariBrowserObservationUnavailableResult -Session $session -Launch $diagnosticLaunch `
        -ErrorCode 'profile_marker_unverified' -FailureDetailCode $ownedProcessVerification.FailureDetailCode
    $observerFailureText = Read-MihariBrowserObservationTestText -Path $writerPath
    $observerFailureEvents = @($observerFailureText -split '\r?\n' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { ConvertFrom-Json -InputObject $_ })
    $observerFailureEvent = @($observerFailureEvents | Where-Object { $_.source -eq 'browser' -and $_.stage -eq 'browser.observation' -and $_.outcome -eq 'unavailable' }) | Select-Object -Last 1
    Assert-MihariTest -Condition ($observerUnavailable.Status -eq 'unavailable' -and $observerUnavailable.ErrorCode -eq 'profile_marker_unverified' -and
        $null -ne $observerFailureEvent -and $observerFailureEvent.coverage -eq 'unknown' -and
        $observerUnavailable.FailureDetailCode -eq 'profile_marker_mismatch' -and
        $observerFailureEvent.data.browserError -eq 'profile_marker_unverified' -and
        $observerFailureEvent.data.errorCode -eq 'profile_marker_mismatch' -and
        -not $observerFailureText.Contains($diagnosticProfilePath)) -Message 'Owned browser observer failure must preserve API-compatible status and expose only a fixed safe verification detail code.'

    $harPath = Join-Path $temporaryDirectory 'input.har'
    $harJson = @'
{"log":{"version":"1.2","entries":[{"startedDateTime":"2026-01-02T03:04:05Z","time":42.5,"request":{"method":"POST","url":"https://alice:password@example.test/api/upload?token=har-secret","headers":[{"name":"Cookie","value":"cookie-secret"}],"postData":{"text":"body-secret"}},"response":{"status":201,"httpVersion":"h2","headers":[{"name":"Set-Cookie","value":"set-cookie-secret"}],"content":{"text":"response-body-secret"}}},{"time":1,"request":{"method":"GET","url":"data:text/plain,unsupported"},"response":{"status":200}}]}}
'@
    [IO.File]::WriteAllText($harPath, $harJson, [Text.Encoding]::UTF8)
    $har = ConvertFrom-MihariHar -Path $harPath
    Assert-MihariTest -Condition ($har.supported -and $har.version -eq '1.2' -and $har.importedCount -eq 1 -and $har.unsupportedCount -eq 1) -Message 'HAR 1.2 import must report recognized and unsupported records.'
    Assert-MihariTest -Condition ($har.records[0].source -eq 'import' -and $har.records[0].sourceVersion -eq 'har-1.2' -and $har.records[0].elapsedMs -eq 43 -and $har.records[0].data.protocol -eq 'h2') -Message 'HAR records must retain source provenance, observed protocol, and measured duration.'
    Assert-MihariTest -Condition ($har.records[0].data.path -eq '/api/upload' -and $null -eq $har.records[0].data.PSObject.Properties['headers'] -and $null -eq $har.records[0].data.PSObject.Properties['body']) -Message 'HAR import must preserve safe URL components only and never retain headers or bodies.'
    $harText = ConvertTo-Json -InputObject $har -Depth 12 -Compress
    foreach ($secret in @('har-secret', 'cookie-secret', 'set-cookie-secret', 'body-secret', 'response-body-secret', 'alice', 'password')) {
        Assert-MihariTest -Condition (-not $harText.Contains($secret)) -Message 'HAR import output must not retain secret URL, header, or body sentinels.'
    }
    $harImport = Import-MihariBrowserEvidence -Session $session -Format har -Path $harPath
    Assert-MihariTest -Condition ($harImport.supported -and $harImport.sourceIdentity -match '^[0-9a-f]{32}$' -and
        $harImport.sourceVersion -eq 'har-1.2' -and $harImport.importedCount -eq 1 -and
        $harImport.unsupportedCount -eq 1 -and $harImport.coverage -eq 'partial') -Message 'Production HAR ingestion must return a bare import identity, source version, safe counts, and partial coverage.'
    $harImportEvents = @((Read-MihariBrowserObservationTestText -Path $writerPath) -split '\r?\n' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { ConvertFrom-Json -InputObject $_ })
    $harImportedEvent = @($harImportEvents | Where-Object { $_.source -eq 'import' -and $_.sourceIdentity -eq $harImport.sourceIdentity -and $_.sourceVersion -eq 'har-1.2' }) | Select-Object -Last 1
    Assert-MihariTest -Condition ($null -ne $harImportedEvent -and $harImportedEvent.stage -eq 'browser.network.request' -and
        $harImportedEvent.outcome -eq 'imported' -and $harImportedEvent.data.host -eq 'example.test' -and
        $harImportedEvent.data.path -eq '/api/upload' -and $harImportedEvent.data.protocol -eq 'h2' -and
        $harImportedEvent.elapsedMs -eq 43) -Message 'Production HAR ingestion must persist the sanitized request fact through the canonical event writer.'
    $harEventText = Read-MihariBrowserObservationTestText -Path $writerPath
    foreach ($secret in @('har-secret', 'cookie-secret', 'set-cookie-secret', 'body-secret', 'response-body-secret', 'password')) {
        Assert-MihariTest -Condition (-not $harEventText.Contains($secret)) -Message 'Persisted HAR facts must exclude raw query, header, body, and user-info sentinels.'
    }

    $unsupportedHarPath = Join-Path $temporaryDirectory 'unsupported.har'
    [IO.File]::WriteAllText($unsupportedHarPath, '{"log":{"version":"1.1","entries":[]}}', [Text.Encoding]::UTF8)
    $unsupportedHar = ConvertFrom-MihariHar -Path $unsupportedHarPath
    Assert-MihariTest -Condition (-not $unsupportedHar.supported -and $unsupportedHar.unsupportedCount -gt 0) -Message 'Unsupported HAR versions must be reported without being parsed as supported evidence.'
    $unsupportedHarImport = Import-MihariBrowserEvidence -Session $session -Format har -Path $unsupportedHarPath
    Assert-MihariTest -Condition (-not $unsupportedHarImport.supported -and $null -eq $unsupportedHarImport.sourceIdentity -and
        $null -eq $unsupportedHarImport.sourceVersion -and $unsupportedHarImport.importedCount -eq 0 -and
        $unsupportedHarImport.coverage -eq 'unsupported') -Message 'Unsupported HAR versions must return explicit unsupported coverage without inventing a source version.'

    $netLogPath = Join-Path $temporaryDirectory 'input-netlog.json'
    $netLogJson = @'
{"constants":{"logEventTypes":{"URL_REQUEST_START_JOB":1,"HTTP_TRANSACTION_READ_HEADERS":2}},"events":[{"type":1,"source":{"id":77,"type":31},"params":{"url":"https://bob:password@example.test/api/list?token=netlog-secret","method":"GET","headers":{"Authorization":"bearer-secret"},"request_body":"body-secret"}},{"type":2,"source":{"id":77,"type":31},"params":{"url":"https://example.test/api/list?token=netlog-secret","status_code":403,"http_version":"h2","response_body":"response-secret"}},{"type":999,"source":{"id":77,"type":31},"params":{"url":"https://example.test/ignored"}}]}
'@
    [IO.File]::WriteAllText($netLogPath, $netLogJson, [Text.Encoding]::UTF8)
    $netLog = ConvertFrom-MihariNetLog -Path $netLogPath
    Assert-MihariTest -Condition ($netLog.supported -and $netLog.importedCount -eq 2 -and $netLog.unsupportedCount -eq 1) -Message 'Chromium NetLog JSON import must report recognized and unsupported event counts.'
    Assert-MihariTest -Condition ($netLog.records[0].source -eq 'import' -and $netLog.records[0].sourceVersion -like 'chromium-netlog-json-*' -and $netLog.records[1].data.statusCode -eq 403 -and $netLog.records[1].data.protocol -eq 'h2') -Message 'NetLog records must retain import provenance and allowlisted response facts.'
    $netLogText = ConvertTo-Json -InputObject $netLog -Depth 12 -Compress
    foreach ($secret in @('netlog-secret', 'bearer-secret', 'body-secret', 'response-secret', 'password', 'Authorization')) {
        Assert-MihariTest -Condition (-not $netLogText.Contains($secret)) -Message 'NetLog import output must not retain raw URLs, credential headers, or bodies.'
    }
    $netLogImport = Import-MihariBrowserEvidence -Session $session -Format netlog -Path $netLogPath
    Assert-MihariTest -Condition ($netLogImport.supported -and $netLogImport.sourceIdentity -match '^[0-9a-f]{32}$' -and
        $netLogImport.sourceVersion -eq 'chromium-netlog-json-recognized-events-v1' -and
        $netLogImport.importedCount -eq 2 -and $netLogImport.unsupportedCount -eq 1 -and
        $netLogImport.coverage -eq 'partial') -Message 'Production NetLog ingestion must report recognized version, counts, and partial coverage.'
    $allImportEvents = @((Read-MihariBrowserObservationTestText -Path $writerPath) -split '\r?\n' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { ConvertFrom-Json -InputObject $_ })
    $netLogImportEvents = @($allImportEvents | Where-Object { $_.source -eq 'import' -and $_.sourceIdentity -eq $netLogImport.sourceIdentity })
    Assert-MihariTest -Condition ($netLogImportEvents.Count -eq 2 -and
        $netLogImportEvents[0].requestId -eq $netLogImportEvents[1].requestId -and
        $netLogImportEvents[1].data.statusCode -eq 403 -and $netLogImportEvents[1].data.protocol -eq 'h2') -Message 'Production NetLog ingestion must persist sanitized events and preserve source request grouping.'
    $allImportText = Read-MihariBrowserObservationTestText -Path $writerPath
    foreach ($secret in @('netlog-secret', 'bearer-secret', 'body-secret', 'response-secret', 'Authorization', 'password')) {
        Assert-MihariTest -Condition (-not $allImportText.Contains($secret)) -Message 'Persisted NetLog facts must exclude raw URL, credential header, and body sentinels.'
    }

    $largeImportPath = Join-Path $temporaryDirectory 'too-large.har'
    [IO.File]::WriteAllText($largeImportPath, (' ' * 1200), [Text.Encoding]::UTF8)
    $sizeRejected = $false
    try { $null = ConvertFrom-MihariHar -Path $largeImportPath -MaximumBytes 1024 }
    catch { $sizeRejected = $true }
    Assert-MihariTest -Condition $sizeRejected -Message 'Browser evidence imports must enforce a finite file size limit before parsing.'

    $missingRejected = $false
    try { $null = Import-MihariBrowserEvidence -Session $session -Format har -Path (Join-Path $temporaryDirectory 'missing.har') }
    catch { $missingRejected = ($_.Exception.Message -eq 'browser_import_source_not_found') }
    Assert-MihariTest -Condition $missingRejected -Message 'Production browser import must return a stable missing-source error.'

    Close-MihariEventWriter -Writer $writer
    $writer = $null
    Write-Host 'PASS browser-observation: owned-profile facts, bounded maps, canonical HAR/NetLog ingestion, scoped IDs, and measured timing'
}
finally {
    if ($null -ne $writer) { Close-MihariEventWriter -Writer $writer }
    Remove-Item -LiteralPath $temporaryDirectory -Recurse -Force -ErrorAction SilentlyContinue
}
