param()

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'TestSupport.ps1')
$repoRoot = Split-Path $PSScriptRoot -Parent
. (Join-Path $repoRoot 'src/Observation.ps1')
. (Join-Path $repoRoot 'src/Browser.ps1')

$temporaryDirectory = Join-Path ([IO.Path]::GetTempPath()) ('mihari-browser-observation-test-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($temporaryDirectory)
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
    $writtenEvents = @([IO.File]::ReadAllLines($writerPath, [Text.Encoding]::UTF8) | ForEach-Object { ConvertFrom-Json -InputObject $_ })
    Assert-MihariTest -Condition ($writtenEvents.Count -eq 2 -and $writtenEvents[0].schemaVersion -eq 2 -and $writtenEvents[0].source -eq 'browser' -and $writtenEvents[0].sequence -eq 1) -Message 'Browser producers must write through the canonical sequenced fact writer.'
    Assert-MihariTest -Condition ($null -eq $writtenEvents[1].elapsedMs -and $null -eq $writtenEvents[1].data.PSObject.Properties['browserTimingDurationMs']) -Message 'The canonical event must preserve an unavailable browser duration as null.'
    $eventText = [IO.File]::ReadAllText($writerPath)
    Assert-MihariTest -Condition (-not $eventText.Contains('browser-query-secret') -and -not $eventText.Contains('password') -and -not $eventText.Contains('raw-request-id')) -Message 'Persisted browser facts must exclude credentials, query values, and raw debugger identifiers.'
    Close-MihariEventWriter -Writer $writer
    $writer = $null

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

    $unsupportedHarPath = Join-Path $temporaryDirectory 'unsupported.har'
    [IO.File]::WriteAllText($unsupportedHarPath, '{"log":{"version":"1.1","entries":[]}}', [Text.Encoding]::UTF8)
    $unsupportedHar = ConvertFrom-MihariHar -Path $unsupportedHarPath
    Assert-MihariTest -Condition (-not $unsupportedHar.supported -and $unsupportedHar.unsupportedCount -gt 0) -Message 'Unsupported HAR versions must be reported without being parsed as supported evidence.'

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

    $largeImportPath = Join-Path $temporaryDirectory 'too-large.har'
    [IO.File]::WriteAllText($largeImportPath, (' ' * 1200), [Text.Encoding]::UTF8)
    $sizeRejected = $false
    try { $null = ConvertFrom-MihariHar -Path $largeImportPath -MaximumBytes 1024 }
    catch { $sizeRejected = $true }
    Assert-MihariTest -Condition $sizeRejected -Message 'Browser evidence imports must enforce a finite file size limit before parsing.'

    Write-Host 'PASS browser-observation: owned-profile facts, privacy-safe HAR/NetLog adapters, scoped IDs, and measured timing'
}
finally {
    if ($null -ne $writer) { Close-MihariEventWriter -Writer $writer }
    Remove-Item -LiteralPath $temporaryDirectory -Recurse -Force -ErrorAction SilentlyContinue
}
