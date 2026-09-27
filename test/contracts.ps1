param()

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'TestSupport.ps1')
$sourceRoot = Join-Path (Split-Path $PSScriptRoot -Parent) 'src'
. (Join-Path $sourceRoot 'Http.ps1')
. (Join-Path $sourceRoot 'Observation.ps1')
. (Join-Path $sourceRoot 'Diagnosis.ps1')
. (Join-Path $sourceRoot 'ManagementProjection.ps1')
. (Join-Path $sourceRoot 'Cli.ps1')

function New-MihariTestMemoryStream {
    param([Parameter(Mandatory = $true)][byte[]] $Bytes)
    $stream = New-Object System.IO.MemoryStream
    $stream.Write($Bytes, 0, $Bytes.Length)
    $stream.Position = 0
    return $stream
}

function ConvertTo-MihariTestBytes {
    param([Parameter(Mandatory = $true)][string] $Text)
    return [System.Text.Encoding]::GetEncoding(28591).GetBytes($Text)
}

function Assert-MihariTestThrows {
    param(
        [Parameter(Mandatory = $true)][scriptblock] $Action,
        [Parameter(Mandatory = $true)][string] $Message
    )
    $threw = $false
    try { & $Action }
    catch { $threw = $true }
    Assert-MihariTest -Condition $threw -Message $Message
}

$wire = ConvertTo-MihariTestBytes -Text (
    "POST http://127.0.0.1:8080/upload?token=secret HTTP/1.1`r`n" +
    "hOsT: 127.0.0.1:8080`r`n" +
    "Content-Length: 3`r`n`r`n"
)
$wire += [byte[]]@(0, 255, 1)
$stream = New-MihariTestMemoryStream -Bytes $wire
try {
    $message = Read-MihariHttpMessage -Stream $stream -Kind Request
    Assert-MihariTest -Condition ($message.Method -eq 'POST') -Message 'HTTP method must parse.'
    Assert-MihariTest -Condition ($message.Host -eq '127.0.0.1' -and $message.Port -eq 8080) -Message 'HTTP authority must parse case-insensitively.'
    Assert-MihariTest -Condition ($message.Body.Length -eq 3 -and $message.Body[0] -eq 0 -and $message.Body[1] -eq 255 -and $message.Body[2] -eq 1) -Message 'Content-Length framing must preserve binary request bodies.'
    $safePath = Get-MihariSafePath -Target $message.Path
    Assert-MihariTest -Condition ($safePath -eq '/upload?token=REDACTED') -Message 'Query values must be redacted while retaining the URL path.'
    Assert-MihariTest -Condition ((Get-MihariSafePath -Target '/upload?raw-secret') -eq '/upload?value=REDACTED') -Message 'Keyless query tokens must be treated as values and redacted.'
}
finally { $stream.Dispose() }

$chunkedWire = ConvertTo-MihariTestBytes -Text (
    "POST /chunked HTTP/1.1`r`nHost: example.test`r`nTransfer-Encoding: chunked`r`n`r`n" +
    "3;kind=raw`r`n"
)
$chunkedWire += [byte[]]@(0, 255, 2)
$chunkedWire += ConvertTo-MihariTestBytes -Text "`r`n0`r`nX-Trailer: allowed`r`n`r`n"
$stream = New-MihariTestMemoryStream -Bytes $chunkedWire
try {
    $message = Read-MihariHttpMessage -Stream $stream -Kind Request
    $expectedBody = [byte[]]@(0x33, 0x3B, 0x6B, 0x69, 0x6E, 0x64, 0x3D, 0x72, 0x61, 0x77, 0x0D, 0x0A, 0, 255, 2, 0x0D, 0x0A, 0x30, 0x0D, 0x0A, 0x58, 0x2D, 0x54, 0x72, 0x61, 0x69, 0x6C, 0x65, 0x72, 0x3A, 0x20, 0x61, 0x6C, 0x6C, 0x6F, 0x77, 0x65, 0x64, 0x0D, 0x0A, 0x0D, 0x0A)
    Assert-MihariTest -Condition ($message.Body.Length -eq $expectedBody.Length) -Message 'Chunked body wire framing length must be retained.'
    for ($index = 0; $index -lt $expectedBody.Length; $index++) {
        Assert-MihariTest -Condition ($message.Body[$index] -eq $expectedBody[$index]) -Message 'Chunked body framing and binary bytes must be preserved.'
    }
}
finally { $stream.Dispose() }

$ambiguous = New-MihariTestMemoryStream -Bytes (ConvertTo-MihariTestBytes -Text "POST / HTTP/1.1`r`nHost: example.test`r`nContent-Length: 1`r`nTransfer-Encoding: chunked`r`n`r`nx")
try { Assert-MihariTestThrows -Action { Read-MihariHttpMessage -Stream $ambiguous -Kind Request } -Message 'Conflicting Transfer-Encoding and Content-Length must be rejected.' }
finally { $ambiguous.Dispose() }

$authority = New-MihariTestMemoryStream -Bytes (ConvertTo-MihariTestBytes -Text "GET http://one.test/path HTTP/1.1`r`nHost: two.test`r`n`r`n")
try { Assert-MihariTestThrows -Action { Read-MihariHttpMessage -Stream $authority -Kind Request } -Message 'Mismatched absolute target and Host must be rejected.' }
finally { $authority.Dispose() }

$hopInput = ConvertTo-MihariTestBytes -Text "GET / HTTP/1.1`r`nHost: example.test`r`nConnection: X-Private-Hop, keep-alive`r`nX-Private-Hop: discard-me`r`nProxy-Connection: keep-alive`r`nX-End-To-End: retain-me`r`n`r`n"
$hopStream = New-MihariTestMemoryStream -Bytes $hopInput
$hopRequest = Read-MihariHttpMessage -Stream $hopStream -Kind Request
$hopStream.Dispose()
$outputStream = New-Object System.IO.MemoryStream
try {
    Write-MihariHttpMessage -Stream $outputStream -Message $hopRequest
    $outgoing = [System.Text.Encoding]::GetEncoding(28591).GetString($outputStream.ToArray())
    Assert-MihariTest -Condition ($outgoing -notmatch '(?im)^X-Private-Hop:|^Proxy-Connection:|^Connection:') -Message 'Hop-by-hop headers named by Connection must be removed.'
    Assert-MihariTest -Condition ($outgoing -match '(?im)^X-End-To-End: retain-me\r?$') -Message 'End-to-end headers must be forwarded.'
}
finally { $outputStream.Dispose() }

$proxyAuthInput = ConvertTo-MihariTestBytes -Text "GET http://example.test/private HTTP/1.1`r`nHost: example.test`r`nProxy-Authorization: Basic proxy-secret`r`n`r`n"
$proxyAuthStream = New-MihariTestMemoryStream -Bytes $proxyAuthInput
try { $proxyAuthRequest = Read-MihariHttpMessage -Stream $proxyAuthStream -Kind Request }
finally { $proxyAuthStream.Dispose() }
foreach ($forwardToExplicitProxy in @($false, $true)) {
    $outputStream = New-Object System.IO.MemoryStream
    try {
        Write-MihariHttpMessage -Stream $outputStream -Message $proxyAuthRequest -ForwardProxyAuthorization:$forwardToExplicitProxy
        $outgoing = [System.Text.Encoding]::GetEncoding(28591).GetString($outputStream.ToArray())
        if ($forwardToExplicitProxy) {
            Assert-MihariTest -Condition ($outgoing -match '(?im)^Proxy-Authorization: Basic proxy-secret\r?$') -Message 'An explicit HTTP proxy must receive the client proxy credential.'
        }
        else {
            Assert-MihariTest -Condition ($outgoing -notmatch '(?im)^Proxy-Authorization:') -Message 'A direct origin must not receive the client proxy credential.'
        }
    }
    finally { $outputStream.Dispose() }
}

$tempDirectory = Join-Path ([IO.Path]::GetTempPath()) ('mihari-contract-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($tempDirectory)
try {
    $eventsPath = Join-Path $tempDirectory 'events.jsonl'
    $writer = New-MihariEventWriter -Path $eventsPath
    $session = [pscustomobject]@{ Id = [guid]::NewGuid().ToString('N'); Mode = 'Inspect'; Writer = $writer }
    Write-MihariEvent -Session $session -ConnectionId 'connection-contract' -RequestId 'request-contract' -Stage 'http.request' -Outcome 'success' -ElapsedMs 12.4 -Data @{
        host = 'example.test'; port = 443; method = 'GET'; path = '/safe/path?token=secret&x=also-secret'
        Authorization = 'Bearer authorization-secret'; Cookie = 'session=cookie-secret'; ProxyAuthorization = 'proxy-secret'
        SetCookie = 'set-cookie-secret'; body = 'body-secret'; arbitraryHeader = 'header-secret'
    } | Out-Null
    Write-MihariEvent -Session $session -ConnectionId 'connection-contract' -RequestId 'request-contract' -Stage 'http.response' -Outcome 'success' -ElapsedMs 20 -Data @{ statusCode = 200 } | Out-Null
    Close-MihariEventWriter -Writer $writer
    $lines = [IO.File]::ReadAllLines($eventsPath)
    Assert-MihariTest -Condition ($lines.Length -eq 2) -Message 'Event writer must emit complete JSONL lines.'
    $serializedEvent = $lines[0]
    foreach ($secret in @('secret', 'authorization-secret', 'cookie-secret', 'proxy-secret', 'set-cookie-secret', 'body-secret', 'header-secret')) {
        Assert-MihariTest -Condition (-not $serializedEvent.Contains($secret)) -Message 'Event JSONL must exclude query, credential, cookie, body, and arbitrary-header values.'
    }
    $event = ConvertFrom-Json -InputObject $serializedEvent
    Assert-MihariTest -Condition ($event.data.path -eq '/safe/path?token=[REDACTED]&x=[REDACTED]') -Message 'Event JSONL must preserve the path and redact query values.'
    Assert-MihariTest -Condition ($event.schemaVersion -eq 2 -and $event.sequence -eq 1 -and $event.source -eq 'proxy' -and $event.coverage -eq 'observed' -and $event.sessionId -eq $session.Id -and $event.connectionId -eq 'connection-contract' -and $event.requestId -eq 'request-contract') -Message 'Event envelope must include versioned order, provenance, coverage, and correlation fields.'
    $secondEvent = ConvertFrom-Json -InputObject $lines[1]
    Assert-MihariTest -Condition ($secondEvent.sequence -eq 2 -and $secondEvent.eventId -ne $event.eventId) -Message 'Writer sequence must advance independently of timestamp ties.'
    $legacyProjection = ConvertTo-MihariManagementEvent -Event ([pscustomobject]@{
        schemaVersion = 1; eventId = 'legacy-1'; sessionId = 'legacy-session'; connectionId = 'legacy-connection'
        stage = 'upstream.tcp'; outcome = 'failed'; data = [pscustomobject]@{ host = 'legacy.test' }
    })
    Assert-MihariTest -Condition ($legacyProjection.source -eq 'proxy' -and $legacyProjection.coverage -eq 'unknown' -and $null -eq $legacyProjection.sequence) -Message 'Legacy schema-v1 events must retain unknown coverage and sequence.'

    $emptyFindings = @(Get-MihariDiagnosis -Events @())
    Assert-MihariTest -Condition ($emptyFindings.Count -eq 0) -Message 'Diagnosis must accept an empty event collection and return no findings.'

    $diagnosticEvents = @(
        [pscustomobject]@{ eventId = 'proxy-407'; sessionId = 's1'; connectionId = 'c1'; requestId = 'r1'; mode = 'Tunnel'; stage = 'upstream.proxy.connect'; outcome = 'rejected'; data = [pscustomobject]@{ routeKind = 'ExplicitProxy'; host = 'blocked.test'; port = 443; proxyStatus = 407 } },
        [pscustomobject]@{ eventId = 'proxy-403'; sessionId = 's1'; connectionId = 'c2'; requestId = 'r2'; mode = 'Tunnel'; stage = 'upstream.proxy.connect'; outcome = 'rejected'; data = [pscustomobject]@{ routeKind = 'ExplicitProxy'; host = 'denied.test'; port = 443; proxyStatus = 403 } },
        [pscustomobject]@{ eventId = 'timeout'; sessionId = 's1'; connectionId = 'c3'; requestId = 'r3'; mode = 'Tunnel'; stage = 'upstream.tcp'; outcome = 'failed'; data = [pscustomobject]@{ routeKind = 'Direct'; host = 'slow.test'; port = 443; errorCode = 'connection_timeout' } },
        [pscustomobject]@{ eventId = 'unsupported'; sessionId = 's1'; connectionId = 'c4'; requestId = 'r4'; mode = 'Inspect'; stage = 'client.tls'; outcome = 'failed'; data = [pscustomobject]@{ host = 'tls13.test'; port = 443; errorCode = 'unsupported_protocol'; unsupportedProtocol = 'TLS 1.3' } }
    )
    $findings = @(Get-MihariDiagnosis -Events $diagnosticEvents)
    $codes = @($findings | ForEach-Object { $_.code })
    Assert-MihariTest -Condition ($codes -contains 'upstream_proxy_auth_required') -Message 'A concrete explicit proxy 407 must support auth-required diagnosis.'
    Assert-MihariTest -Condition ($codes -contains 'upstream_proxy_rejected') -Message 'A concrete explicit proxy 403 must support proxy-rejected diagnosis.'
    Assert-MihariTest -Condition ($codes -contains 'connection_timeout') -Message 'A concrete timeout must support timeout diagnosis.'
    Assert-MihariTest -Condition ($codes -contains 'unsupported_protocol') -Message 'An explicit unsupported protocol fact must support an unsupported-protocol diagnosis.'
    Assert-MihariTest -Condition (@($findings | Where-Object { $_.code -eq 'upstream_proxy_rejected' -and $_.evidenceIds -contains 'proxy-403' }).Count -eq 1) -Message 'Diagnosis must retain evidence event IDs.'
    Assert-MihariTest -Condition (@($findings | Where-Object { $_.code -eq 'upstream_proxy_rejected' -and $_.evidenceIds -contains 'timeout' }).Count -eq 0) -Message 'A timeout must not be described as an upstream proxy rejection.'

    $reportDirectory = Join-Path $tempDirectory 'report'
    $report = New-MihariReport -EventsPath $eventsPath -OutputDirectory $reportDirectory
    Assert-MihariTest -Condition ([IO.File]::Exists((Join-Path $reportDirectory 'report.json'))) -Message 'JSON report must be written.'
    Assert-MihariTest -Condition ([IO.File]::Exists((Join-Path $reportDirectory 'report.txt'))) -Message 'Text report must be written.'
    Assert-MihariTest -Condition ($report.eventCount -eq 2 -and $report.sessionId -eq $session.Id) -Message 'Report must carry event count and session identity.'
    $help = Get-MihariHelpText
    Assert-MihariTest -Condition ($help -match '(?m)^Usage:' -and $help -match '\.\\mihari\.ps1 start' -and $help -match '\.\\mihari\.ps1 status') -Message 'CLI help must expose the primary user workflow.'
    $emptyStatus = Format-MihariStatus -Metadata $null
    Assert-MihariTest -Condition ($emptyStatus -eq 'No Mihari session found. Start one with: .\mihari.ps1 start') -Message 'CLI status must explain the no-session state.'
    $runningStatus = Format-MihariStatus -Metadata ([pscustomobject]@{
        effectiveStatus = 'running'; mode = 'Inspect'; sessionId = 'abc'; processAlive = $true; processId = 1234
        actualPort = 8899; port = 8899; outputDirectory = 'C:\Mihari\sessions\abc'
    })
    Assert-MihariTest -Condition ($runningStatus -match 'Status: running' -and $runningStatus -match 'Proxy: http://127\.0\.0\.1:8899') -Message 'CLI status must expose runtime state and the usable proxy endpoint.'
    $stopText = Format-MihariStopResult -Result ([pscustomobject]@{ requested = $false; reason = 'no_session'; sessionId = $null })
    Assert-MihariTest -Condition ($stopText -eq 'No Mihari session found.') -Message 'CLI stop must explain the no-session state.'
    Write-Host 'PASS contracts: HTTP framing/binary/chunked/authority/hop headers, redaction/JSONL, conservative diagnoses/evidence, reports, CLI UX'
}
finally {
    Remove-Item -LiteralPath $tempDirectory -Recurse -Force -ErrorAction SilentlyContinue
}
