$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'TestSupport.ps1')
if ($env:OS -ne 'Windows_NT') {
    Write-Warning 'Issue #3 management integration requires Windows certificate and listener behavior.'
    return
}
. (Join-Path $PSScriptRoot 'integration.ps1') -LoadHelpersOnly

$repoRoot = Split-Path $PSScriptRoot -Parent
. (Join-Path (Join-Path $repoRoot 'src') 'Session.ps1')

function Invoke-Issue3ManagementRequest {
    param(
        [Parameter(Mandatory = $true)][string]$Endpoint,
        [Parameter(Mandatory = $true)][ValidateSet('GET', 'POST')][string]$Method,
        [AllowNull()][object]$Body,
        [switch]$SkipControlToken
    )

    $request = [System.Net.HttpWebRequest][System.Net.WebRequest]::Create($Endpoint)
    $request.ServicePoint.Expect100Continue = $false
    $request.Method = $Method
    $request.Proxy = $null
    $request.KeepAlive = $false
    $request.Timeout = 7000
    $request.ReadWriteTimeout = 7000
    $request.Accept = 'application/json, text/html;q=0.9, */*;q=0.8'
    if ($Method -eq 'POST' -and -not $SkipControlToken) {
        $authority = ([Uri]$Endpoint).GetLeftPart([UriPartial]::Authority) + '/'
        $page = Invoke-Issue3ManagementRequest -Endpoint $authority -Method GET -Body $null
        $tokenMatch = [regex]::Match([string]$page.Text, 'var CONTROL_TOKEN="(?<token>[A-Za-z0-9_-]+)";')
        Assert-MihariTest -Condition $tokenMatch.Success -Message 'The owned management page must bootstrap an in-memory action token.'
        $request.Headers['X-Mihari-Control-Token'] = $tokenMatch.Groups['token'].Value
    }
    if ($null -ne $Body) {
        $request.ContentType = 'application/json; charset=utf-8'
        $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $Body -Depth 6 -Compress))
        $request.ContentLength = $bodyBytes.Length
        $requestStream = $request.GetRequestStream()
        try { $requestStream.Write($bodyBytes, 0, $bodyBytes.Length) }
        finally { $requestStream.Dispose() }
    }

    $response = $null
    try { $response = $request.GetResponse() }
    catch [System.Net.WebException] {
        if ($null -eq $_.Exception.Response) {
            throw ('Management request {0} {1} failed before an HTTP response: {2}' -f $Method, ([Uri]$Endpoint).AbsolutePath, $_.Exception.Status)
        }
        $response = $_.Exception.Response
    }
    try {
        $reader = [System.IO.StreamReader]::new($response.GetResponseStream(), [System.Text.Encoding]::UTF8)
        try { $content = $reader.ReadToEnd() }
        finally { $reader.Dispose() }
        $json = $null
        if ([string]$response.ContentType -match '(?i)application/(.+\+)?json' -or $content.TrimStart().StartsWith('{') -or $content.TrimStart().StartsWith('[')) {
            try { $json = ConvertFrom-Json -InputObject $content -ErrorAction Stop }
            catch { throw ("Management endpoint returned invalid JSON: {0}" -f $_.Exception.Message) }
        }
        return [pscustomobject]@{
            StatusCode = [int]$response.StatusCode
            ContentType = [string]$response.ContentType
            Text = $content
            Json = $json
        }
    }
    finally { $response.Close() }
}

function Get-Issue3Metadata {
    param([Parameter(Mandatory = $true)][string]$OutputDirectory)
    $path = Join-Path $OutputDirectory 'session.json'
    return (ConvertFrom-Json -InputObject (Read-MihariTestLiveText -Path $path) -ErrorAction Stop)
}

function Wait-Issue3ManagementReady {
    param([Parameter(Mandatory = $true)]$Child, [int]$TimeoutSeconds = 35)
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $activePath = Join-Path $Child.OutputRoot 'active-session.json'
    while ([DateTime]::UtcNow -lt $deadline) {
        if ($Child.Process.HasExited) {
            $Child.Process.WaitForExit()
            throw ("Mihari exited during management startup ({0}). stdout={1} stderr={2}" -f $Child.Process.ExitCode, $Child.Stdout.Result, $Child.Stderr.Result)
        }
        if ([IO.File]::Exists($activePath)) {
            $active = ConvertFrom-Json -InputObject (Read-MihariTestLiveText -Path $activePath) -ErrorAction Stop
            if ($active.outputDirectory -and [IO.File]::Exists((Join-Path ([string]$active.outputDirectory) 'session.json'))) {
                $metadata = Get-Issue3Metadata -OutputDirectory ([string]$active.outputDirectory)
                $managementPort = 0
                if (-not [int]::TryParse([string]$metadata.actualManagementPort, [ref]$managementPort)) {
                    [void][int]::TryParse([string]$metadata.uiPort, [ref]$managementPort)
                }
                if ([string]$metadata.status -eq 'running' -and [int]$metadata.actualPort -gt 0 -and $managementPort -gt 0) {
                    return $metadata
                }
            }
        }
        Start-Sleep -Milliseconds 50
    }
    throw ("Mihari did not publish both listener endpoints within {0}s under {1}." -f $TimeoutSeconds, $Child.OutputRoot)
}

function Test-Issue3TcpEndpoint {
    param([Parameter(Mandatory = $true)][int]$Port, [int]$TimeoutMilliseconds = 1200)
    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $connect = $client.ConnectAsync('127.0.0.1', $Port)
        if (-not $connect.Wait($TimeoutMilliseconds)) { return $false }
        return $client.Connected
    }
    catch { return $false }
    finally { $client.Close() }
}

function Wait-Issue3ApiEvent {
    param(
        [Parameter(Mandatory = $true)][string]$ManagementEndpoint,
        [Parameter(Mandatory = $true)][scriptblock]$Predicate,
        [int]$TimeoutSeconds = 15
    )
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $response = Invoke-Issue3ManagementRequest -Endpoint ($ManagementEndpoint + 'api/events?limit=200') -Method GET -Body $null
        Assert-MihariTest -Condition ($response.StatusCode -eq 200 -and $null -ne $response.Json.events) -Message 'The management events endpoint must return a JSON event collection.'
        foreach ($event in @($response.Json.events)) {
            if (& $Predicate $event) { return $event }
        }
        Start-Sleep -Milliseconds 80
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'The expected management event did not appear before the deadline.'
}

function Assert-Issue3UnhealthyPersistedStatus {
    $root = Join-Path ([IO.Path]::GetTempPath()) ('mihari-issue3-health-' + [guid]::NewGuid().ToString('N'))
    $sessionId = [guid]::NewGuid().ToString('N')
    $sessionDirectory = Join-Path $root $sessionId
    [void][IO.Directory]::CreateDirectory($sessionDirectory)
    $process = [System.Diagnostics.Process]::GetCurrentProcess()
    try { $processStart = $process.StartTime.ToUniversalTime().ToString('o') }
    finally { $process.Dispose() }
    $proxyPort = Get-MihariTestFreePort
    $managementPort = Get-MihariTestFreePort
    while ($managementPort -eq $proxyPort) { $managementPort = Get-MihariTestFreePort }
    $heartbeat = [DateTime]::UtcNow.ToString('o')
    $metadata = [ordered]@{
        schemaVersion = 1
        sessionId = $sessionId
        outputDirectory = [System.IO.Path]::GetFullPath($sessionDirectory)
        status = 'running'
        processId = [int]$PID
        processStartTimeUtc = $processStart
        actualPort = $proxyPort
        actualManagementPort = $managementPort
        proxyHeartbeatUtc = $heartbeat
        managementHeartbeatUtc = $heartbeat
    }
    [IO.File]::WriteAllText((Join-Path $sessionDirectory 'session.json'), (ConvertTo-Json -InputObject $metadata -Depth 5 -Compress))
    [IO.File]::WriteAllText((Join-Path $root 'active-session.json'), (ConvertTo-Json -InputObject $metadata -Depth 5 -Compress))
    try {
        $status = Get-MihariSessionStatus -OutputRoot $root
        Assert-MihariTest -Condition ([bool]$status.processAlive) -Message 'The dead-listener status fixture must keep the owner PID alive.'
        Assert-MihariTest -Condition ($status.effectiveStatus -eq 'unhealthy') -Message 'Status must report unhealthy when owner PID is alive but persisted listeners are closed.'
        Assert-MihariTest -Condition (-not $status.proxyHealth.healthy -and -not $status.managementHealth.healthy) -Message 'Status must expose each failed listener health check.'
    }
    finally { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue }

    $proxyListener = New-MihariTestListener
    $managementListener = New-MihariTestListener
    $rootWithError = Join-Path ([IO.Path]::GetTempPath()) ('mihari-issue3-management-error-' + [guid]::NewGuid().ToString('N'))
    $errorSessionId = [guid]::NewGuid().ToString('N')
    $errorSessionDirectory = Join-Path $rootWithError $errorSessionId
    [void][IO.Directory]::CreateDirectory($errorSessionDirectory)
    $errorMetadata = [ordered]@{
        schemaVersion = 1
        sessionId = $errorSessionId
        outputDirectory = [System.IO.Path]::GetFullPath($errorSessionDirectory)
        status = 'running'
        processId = [int]$PID
        processStartTimeUtc = $processStart
        actualPort = [int]([System.Net.IPEndPoint]$proxyListener.LocalEndpoint).Port
        actualManagementPort = [int]([System.Net.IPEndPoint]$managementListener.LocalEndpoint).Port
        proxyHeartbeatUtc = $heartbeat
        managementHeartbeatUtc = $heartbeat
        managementError = 'management_listener_failed'
    }
    try {
        [IO.File]::WriteAllText((Join-Path $errorSessionDirectory 'session.json'), (ConvertTo-Json -InputObject $errorMetadata -Depth 5 -Compress))
        [IO.File]::WriteAllText((Join-Path $rootWithError 'active-session.json'), (ConvertTo-Json -InputObject $errorMetadata -Depth 5 -Compress))
        $errorStatus = Get-MihariSessionStatus -OutputRoot $rootWithError
        Assert-MihariTest -Condition ([bool]$errorStatus.processAlive -and [bool]$errorStatus.proxyHealth.healthy) -Message 'The persisted management error fixture must retain a live owner and a healthy proxy listener.'
        Assert-MihariTest -Condition ([bool]$errorStatus.managementHealth.listening -and [bool]$errorStatus.managementHealth.heartbeatFresh -and -not [bool]$errorStatus.managementHealth.healthy) -Message 'A persisted management listener error must force its health result unhealthy despite a live socket and fresh heartbeat.'
        Assert-MihariTest -Condition ($errorStatus.effectiveStatus -eq 'unhealthy') -Message 'Status must preserve a persisted management failure even when its socket and heartbeat look healthy.'
    }
    finally {
        $proxyListener.Stop()
        $managementListener.Stop()
        Remove-Item -LiteralPath $rootWithError -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Write-Issue3FixtureResponse {
    param([Parameter(Mandatory = $true)][System.IO.Stream]$Stream)
    $body = 'issue3-body-secret'
    $bodyBytes = [System.Text.Encoding]::ASCII.GetBytes($body)
    $header = "HTTP/1.1 404 Not Found`r`nContent-Length: $($bodyBytes.Length)`r`nSet-Cookie: session=issue3-setcookie-secret`r`nConnection: close`r`n`r`n"
    $headerBytes = [System.Text.Encoding]::ASCII.GetBytes($header)
    $Stream.Write($headerBytes, 0, $headerBytes.Length)
    $Stream.Write($bodyBytes, 0, $bodyBytes.Length)
    $Stream.Flush()
}

$tempRoot = Join-Path ([IO.Path]::GetTempPath()) ('mihari-issue3-management-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($tempRoot)
$fixtureIdentity = $null
$child = $null
$metadata = $null
$findingsChild = $null
$findingsMetadata = $null
$proxyStatusListener = $null
$addOperator = $null
$oldOriginListener = $null
$oldOriginClient = $null
$oldProxyClient = $null
$oldProxyTls = $null
$inspectOriginListener = $null
$inspectOriginClient = $null
$inspectOriginTls = $null
$inspectProxyClient = $null
$inspectProxyTls = $null
$tunnelOriginListener = $null
$tunnelOriginClient = $null
$tunnelOriginTls = $null
$tunnelProxyClient = $null
$tunnelProxyTls = $null
$loopClient = $null
$failures = New-Object 'System.Collections.Generic.List[string]'
try {
    Assert-Issue3UnhealthyPersistedStatus
    $fixtureIdentity = New-MihariTestFixtureTlsIdentity
    $outputRoot = Join-Path $tempRoot 'session'
    $child = Start-MihariTestProcess -Command start -OutputRoot $outputRoot -Mode Tunnel -Port 0
    $metadata = Wait-Issue3ManagementReady -Child $child
    $proxyPort = [int]$metadata.actualPort
    $managementPort = [int]$metadata.actualManagementPort
    $managementEndpoint = [string]$metadata.uiEndpoint
    if ([string]::IsNullOrWhiteSpace($managementEndpoint)) { $managementEndpoint = 'http://127.0.0.1:' + $managementPort + '/' }

    Assert-MihariTest -Condition ($proxyPort -ne $managementPort) -Message 'Proxy and management listeners must use distinct actual ports.'
    Assert-MihariTest -Condition (Test-Issue3TcpEndpoint -Port $proxyPort) -Message 'The published proxy endpoint must accept a loopback TCP connection.'
    Assert-MihariTest -Condition (Test-Issue3TcpEndpoint -Port $managementPort) -Message 'The published management endpoint must accept a loopback TCP connection.'

    $statusResponse = Invoke-Issue3ManagementRequest -Endpoint ($managementEndpoint + 'api/status') -Method GET -Body $null
    $statusErrorCode = $null
    if ($null -ne $statusResponse.Json) {
        $statusErrorCode = [string]$statusResponse.Json.errorCode
        if ([string]::IsNullOrWhiteSpace($statusErrorCode)) { $statusErrorCode = [string]$statusResponse.Json.code }
    }
    if ([string]::IsNullOrWhiteSpace($statusErrorCode)) { $statusErrorCode = '[none]' }
    Assert-MihariTest -Condition ($statusResponse.StatusCode -eq 200 -and $null -ne $statusResponse.Json.session) -Message ('The management status endpoint must return the running session (HTTP {0}, error code {1}).' -f $statusResponse.StatusCode, $statusErrorCode)
    Assert-MihariTest -Condition ($statusResponse.Json.session.sessionId -eq $metadata.sessionId -and $statusResponse.Json.session.status -eq 'running') -Message 'Management status must identify the active session and running state.'
    Assert-MihariTest -Condition ($statusResponse.Json.session.mode -eq 'Tunnel' -and -not [bool]$statusResponse.Json.session.inspectEnabled) -Message 'Initial management status must report Tunnel with Inspect disabled.'
    Assert-MihariTest -Condition ([bool]$statusResponse.Json.proxyHealth.healthy -and [bool]$statusResponse.Json.managementHealth.healthy) -Message 'Management status must report both live listeners healthy.'
    Assert-MihariTest -Condition (-not [string]::IsNullOrWhiteSpace([string]$statusResponse.Json.proxyEndpoint) -and -not [string]::IsNullOrWhiteSpace([string]$statusResponse.Json.managementEndpoint)) -Message 'Management status must expose both actual endpoints.'
    Assert-MihariTest -Condition ($null -ne $statusResponse.Json.upstreamRoute) -Message 'Management status must expose the selected upstream route state.'

    $healthResponse = Invoke-Issue3ManagementRequest -Endpoint ($managementEndpoint + 'api/health') -Method GET -Body $null
    Assert-MihariTest -Condition ($healthResponse.StatusCode -eq 200) -Message 'The management health endpoint must answer successfully.'
    $pageResponse = Invoke-Issue3ManagementRequest -Endpoint $managementEndpoint -Method GET -Body $null
    $untrustedAction = Invoke-Issue3ManagementRequest -Endpoint ($managementEndpoint + 'api/mode') -Method POST -Body @{ mode = 'Tunnel' } -SkipControlToken
    Assert-MihariTest -Condition ($untrustedAction.StatusCode -eq 403 -and $untrustedAction.Json.error -eq 'invalid_control_token') -Message 'Management actions must reject a request without the session control token.'
    Assert-MihariTest -Condition ($pageResponse.StatusCode -eq 200 -and $pageResponse.ContentType -match '(?i)text/html') -Message 'The local management server must serve its HTML page.'
    foreach ($pollEndpoint in @('/api/status', '/api/events', '/api/findings')) {
        Assert-MihariTest -Condition ($pageResponse.Text.Contains($pollEndpoint)) -Message 'The served page must poll current status, event log, and finding data.'
    }
    Assert-MihariTest -Condition ($pageResponse.Text -match '(?is)<style\b' -and $pageResponse.Text -match '(?is)<script\b' -and $pageResponse.Text -match '(?is)setInterval') -Message 'The served management UI must contain its local CSS, JavaScript, and polling loop.'
    Assert-MihariTest -Condition ($pageResponse.Text -match '(?i)/api/mode' -and $pageResponse.Text -match '(?i)/api/browser') -Message 'The served management UI must expose mode and browser actions.'

    $cliStatus = Start-MihariTestProcess -Command status -OutputRoot $outputRoot
    try {
        if (-not $cliStatus.Process.WaitForExit(10000)) { throw 'The CLI status command timed out.' }
        $cliStatus.Process.WaitForExit()
        Assert-MihariTest -Condition ($cliStatus.Process.ExitCode -eq 0) -Message 'The CLI status command must succeed for a healthy session.'
        $cliText = $cliStatus.Stdout.Result
        Assert-MihariTest -Condition ($cliText -match [regex]::Escape("http://127.0.0.1:$proxyPort") -and $cliText -match [regex]::Escape($managementEndpoint.TrimEnd('/'))) -Message 'CLI status must print both actual listener endpoints.'
        Assert-MihariTest -Condition ($cliText -match 'running') -Message 'CLI status must report a live session as running.'
    }
    finally { $cliStatus.Process.Dispose() }

    $initialEvents = Invoke-Issue3ManagementRequest -Endpoint ($managementEndpoint + 'api/events?limit=1') -Method GET -Body $null
    Assert-MihariTest -Condition ($initialEvents.StatusCode -eq 200 -and @($initialEvents.Json.events).Count -le 1) -Message 'The events endpoint must honor its bounded result limit.'

    # Hold a Tunnel CONNECT open while switching the accepted mode to Inspect.
    $oldOriginListener = New-MihariTestListener
    $oldOriginPort = ([System.Net.IPEndPoint]$oldOriginListener.LocalEndpoint).Port
    $oldAccept = $oldOriginListener.AcceptTcpClientAsync()
    $oldProxyClient = [System.Net.Sockets.TcpClient]::new()
    $oldProxyClient.Connect('127.0.0.1', $proxyPort)
    $oldProxyStream = $oldProxyClient.GetStream()
    $oldConnect = [System.Text.Encoding]::ASCII.GetBytes("CONNECT 127.0.0.1:$oldOriginPort HTTP/1.1`r`nHost: 127.0.0.1:$oldOriginPort`r`n`r`n")
    $oldProxyStream.Write($oldConnect, 0, $oldConnect.Length)
    $oldProxyStream.Flush()
    $oldReply = Read-MihariTestHeaderText -Stream $oldProxyStream -Context 'pre-toggle Tunnel CONNECT'
    Assert-MihariTest -Condition ($oldReply.StartsWith('HTTP/1.1 200')) -Message 'A Tunnel CONNECT accepted before the toggle must be established.'
    Assert-MihariTest -Condition ($oldAccept.Wait(15000)) -Message 'The pre-toggle Tunnel connection must reach its local fixture.'
    $oldOriginClient = $oldAccept.Result

    $addOperator = Start-MihariTestRootConfirmation -Operation Add -TargetProcessId $child.Process.Id
    $inspectToggle = Invoke-Issue3ManagementRequest -Endpoint ($managementEndpoint + 'api/mode') -Method POST -Body @{ mode = 'Inspect' }
    Assert-MihariTest -Condition ($inspectToggle.StatusCode -eq 200) -Message 'The management mode action must enable Inspect.'
    Complete-MihariTestRootConfirmation -Operator $addOperator
    Stop-MihariTestRootConfirmation -Operator $addOperator
    $addOperator = $null

    $inspectStatus = Invoke-Issue3ManagementRequest -Endpoint ($managementEndpoint + 'api/status') -Method GET -Body $null
    Assert-MihariTest -Condition ($inspectStatus.Json.session.mode -eq 'Inspect' -and [bool]$inspectStatus.Json.session.inspectEnabled) -Message 'The management status must reflect Inspect after the action.'
    Assert-MihariTest -Condition ([bool]$inspectStatus.Json.ca.trusted -and -not [string]::IsNullOrWhiteSpace([string]$inspectStatus.Json.ca.thumbprint)) -Message 'Inspect must not be enabled until its session CA is trusted.'
    $inspectModeEvent = Wait-Issue3ApiEvent -ManagementEndpoint $managementEndpoint -Predicate { param($event) $event.stage -eq 'session.mode' -and $event.data.mode -eq 'Inspect' }
    Assert-MihariTest -Condition ($inspectModeEvent.data.previousMode -eq 'Tunnel' -and [bool]$inspectModeEvent.data.caTrusted) -Message 'The safe event projection must retain the mode change and the trusted CA fact.'

    $oldProxyClient.Close(); $oldProxyClient = $null
    $oldOriginClient.Close(); $oldOriginClient = $null
    $oldOriginListener.Stop(); $oldOriginListener = $null
    $oldRelay = Wait-Issue3ApiEvent -ManagementEndpoint $managementEndpoint -Predicate { param($event) $event.stage -eq 'tunnel.relay' }
    Assert-MihariTest -Condition ($oldRelay.mode -eq 'Tunnel') -Message 'A Tunnel connection accepted before the mode toggle must retain Tunnel behavior.'

    # New CONNECTs after the toggle use Inspect, expose the HTTP path, and keep
    # credentials, cookies, query values, and response bodies out of the API.
    $inspectOriginListener = New-MihariTestListener
    $inspectOriginPort = ([System.Net.IPEndPoint]$inspectOriginListener.LocalEndpoint).Port
    $inspectAccept = $inspectOriginListener.AcceptTcpClientAsync()
    $inspectProxyClient = [System.Net.Sockets.TcpClient]::new()
    $inspectProxyClient.Connect('127.0.0.1', $proxyPort)
    $inspectProxyStream = $inspectProxyClient.GetStream()
    $inspectConnect = [System.Text.Encoding]::ASCII.GetBytes("CONNECT 127.0.0.1:$inspectOriginPort HTTP/1.1`r`nHost: 127.0.0.1:$inspectOriginPort`r`n`r`n")
    $inspectProxyStream.Write($inspectConnect, 0, $inspectConnect.Length)
    $inspectProxyStream.Flush()
    $inspectReply = Read-MihariTestHeaderText -Stream $inspectProxyStream -Context 'post-toggle Inspect CONNECT'
    Assert-MihariTest -Condition ($inspectReply.StartsWith('HTTP/1.1 200')) -Message 'A new CONNECT after the toggle must be accepted for Inspect.'
    $inspectProxyTls = [System.Net.Security.SslStream]::new($inspectProxyStream, $true)
    $inspectClientAuth = Begin-MihariTestTlsClientAuthentication -Stream $inspectProxyTls -TargetHost '127.0.0.1'
    Complete-MihariTestTlsAuthentication -ClientStream $inspectProxyTls -ClientResult $inspectClientAuth
    Assert-MihariTest -Condition ($inspectProxyTls.SslProtocol -eq [System.Security.Authentication.SslProtocols]::Tls12) -Message 'A post-toggle Inspect connection must terminate TLS 1.2.'
    $inspectRequest = [System.Text.Encoding]::ASCII.GetBytes("GET /management/poll?token=issue3-query-secret HTTP/1.1`r`nHost: 127.0.0.1:$inspectOriginPort`r`nAuthorization: Bearer issue3-auth-secret`r`nCookie: session=issue3-cookie-secret`r`nConnection: close`r`n`r`n")
    $inspectProxyTls.Write($inspectRequest, 0, $inspectRequest.Length)
    $inspectProxyTls.Flush()
    Assert-MihariTest -Condition ($inspectAccept.Wait(15000)) -Message 'A new Inspect connection must reach the local TLS origin.'
    $inspectOriginClient = $inspectAccept.Result
    $inspectOriginTls = [System.Net.Security.SslStream]::new($inspectOriginClient.GetStream(), $true)
    $inspectServerAuth = Begin-MihariTestTlsServerAuthentication -Stream $inspectOriginTls -Certificate $fixtureIdentity.Leaf
    Complete-MihariTestTlsAuthentication -ServerStream $inspectOriginTls -ServerResult $inspectServerAuth
    $inspectOriginRequest = Read-MihariTestHeaderText -Stream $inspectOriginTls -Context 'post-toggle Inspect origin request'
    Assert-MihariTest -Condition ($inspectOriginRequest.StartsWith('GET /management/poll?token=issue3-query-secret HTTP/1.1')) -Message 'Inspect must forward the local request path to the upstream fixture.'
    Assert-MihariTest -Condition ($inspectOriginRequest -match '(?im)^Authorization: Bearer issue3-auth-secret\r?$' -and $inspectOriginRequest -match '(?im)^Cookie: session=issue3-cookie-secret\r?$') -Message 'The local upstream fixture must receive end-to-end credentials for the redaction test.'
    Write-Issue3FixtureResponse -Stream $inspectOriginTls
    $inspectResponse = Read-MihariTestHttpResponse -Stream $inspectProxyTls
    Assert-MihariTest -Condition ($inspectResponse.Headers.StartsWith('HTTP/1.1 404') -and $inspectResponse.Body -eq 'issue3-body-secret') -Message 'Inspect must relay the local fixture response.'
    $inspectProxyTls.Dispose(); $inspectProxyTls = $null
    $inspectOriginTls.Dispose(); $inspectOriginTls = $null
    $inspectProxyClient.Close(); $inspectProxyClient = $null
    $inspectOriginClient.Close(); $inspectOriginClient = $null
    $inspectOriginListener.Stop(); $inspectOriginListener = $null

    $httpEvent = Wait-Issue3ApiEvent -ManagementEndpoint $managementEndpoint -Predicate {
        param($event)
        $event.stage -eq 'http.request' -and [string]$event.data.path -like '/management/poll?token=*'
    }
    Assert-MihariTest -Condition ($httpEvent.mode -eq 'Inspect' -and $httpEvent.data.path -eq '/management/poll?token=[REDACTED]') -Message 'The management event projection must expose Inspect path data with redacted query values.'
    $allEvents = Invoke-Issue3ManagementRequest -Endpoint ($managementEndpoint + 'api/events?limit=200') -Method GET -Body $null
    Assert-MihariTest -Condition ($allEvents.StatusCode -eq 200 -and @($allEvents.Json.events).Count -le 200 -and @($allEvents.Json.events).Count -gt @($initialEvents.Json.events).Count) -Message 'The management event projection must refresh and remain bounded at 200 items.'
    $eventJson = ConvertTo-Json -InputObject $allEvents.Json.events -Depth 12 -Compress
    foreach ($secret in @('issue3-query-secret', 'issue3-auth-secret', 'issue3-cookie-secret', 'issue3-setcookie-secret', 'issue3-body-secret')) {
        Assert-MihariTest -Condition (-not $eventJson.Contains($secret)) -Message 'Management event data must not expose query, credential, cookie, response-cookie, or body secrets.'
    }
    Assert-MihariTest -Condition ($eventJson.Contains('/management/poll?token=[REDACTED]')) -Message 'Management event data must retain the path while redacting its query value.'

    $findingsResponse = Invoke-Issue3ManagementRequest -Endpoint ($managementEndpoint + 'api/findings') -Method GET -Body $null
    $findingError = $(if ($null -ne $findingsResponse.Json) { [string]$findingsResponse.Json.error } else { '[no-json]' })
    $findingCode = $(if ($null -ne $findingsResponse.Json) { [string]$findingsResponse.Json.projectionCode } else { '' })
    $findingType = $(if ($null -ne $findingsResponse.Json) { [string]$findingsResponse.Json.errorType } else { '' })
    Assert-MihariTest -Condition ($findingsResponse.StatusCode -eq 200 -and $null -ne $findingsResponse.Json.findings) -Message ('The management findings endpoint must return canonical findings (HTTP {0}, error {1}, projection {2}, type {3}).' -f $findingsResponse.StatusCode, $findingError, $findingCode, $findingType)
    $findingJson = ConvertTo-Json -InputObject $findingsResponse.Json.findings -Depth 12 -Compress
    foreach ($secret in @('issue3-query-secret', 'issue3-auth-secret', 'issue3-cookie-secret', 'issue3-setcookie-secret', 'issue3-body-secret')) {
        Assert-MihariTest -Condition (-not $findingJson.Contains($secret)) -Message 'Management findings must preserve the event privacy boundary.'
    }

    # The route guard is exercised over the running proxy itself: sending an
    # absolute request back to Mihari must fail as a fact rather than recurse.
    $loopClient = [System.Net.Sockets.TcpClient]::new()
    $loopClient.ReceiveTimeout = 7000
    $loopClient.SendTimeout = 7000
    $loopClient.Connect('127.0.0.1', $proxyPort)
    $loopStream = $loopClient.GetStream()
    $loopStream.ReadTimeout = 7000
    $loopRequest = [System.Text.Encoding]::ASCII.GetBytes("GET http://127.0.0.1:$proxyPort/recursive?token=issue3-loop-secret HTTP/1.1`r`nHost: 127.0.0.1:$proxyPort`r`nConnection: close`r`n`r`n")
    $loopStream.Write($loopRequest, 0, $loopRequest.Length)
    $loopStream.Flush()
    $loopReply = Read-MihariTestHeaderText -Stream $loopStream -Context 'self-reference guard response'
    Assert-MihariTest -Condition ($loopReply.StartsWith('HTTP/1.1 502')) -Message 'A self-referencing request must receive a local upstream failure response without following the route.'
    $loopClient.Close(); $loopClient = $null
    $selfReferenceEvent = Wait-Issue3ApiEvent -ManagementEndpoint $managementEndpoint -Predicate {
        param($event)
        $event.data.errorCode -eq 'upstream_route_self_reference' -or $event.data.mihariErrorCode -eq 'upstream_route_self_reference'
    }
    Assert-MihariTest -Condition ($null -ne $selfReferenceEvent) -Message 'A request targeting Mihari itself must produce an upstream_route_self_reference fact and must not recurse.'

    $tunnelToggle = Invoke-Issue3ManagementRequest -Endpoint ($managementEndpoint + 'api/mode') -Method POST -Body @{ mode = 'Tunnel' }
    Assert-MihariTest -Condition ($tunnelToggle.StatusCode -eq 200) -Message 'The management mode action must switch new connections back to Tunnel.'
    $tunnelStatus = Invoke-Issue3ManagementRequest -Endpoint ($managementEndpoint + 'api/status') -Method GET -Body $null
    Assert-MihariTest -Condition ($tunnelStatus.Json.session.mode -eq 'Tunnel' -and -not [bool]$tunnelStatus.Json.session.inspectEnabled) -Message 'The management status must reflect Tunnel after the second action.'
    Assert-MihariTest -Condition ([bool]$tunnelStatus.Json.ca.trusted) -Message 'The single session CA must remain consistently trusted until normal session cleanup.'
    $tunnelModeEvent = Wait-Issue3ApiEvent -ManagementEndpoint $managementEndpoint -Predicate { param($event) $event.stage -eq 'session.mode' -and $event.data.mode -eq 'Tunnel' }
    Assert-MihariTest -Condition ($tunnelModeEvent.data.previousMode -eq 'Inspect' -and [bool]$tunnelModeEvent.data.caTrusted) -Message 'The safe event projection must retain the return-to-Tunnel transition and session CA trust state.'

    # A subsequent CONNECT now uses Tunnel, so its TLS handshake reaches the
    # fixture unchanged and its relay event is tagged with the accepted mode.
    $tunnelOriginListener = New-MihariTestListener
    $tunnelOriginPort = ([System.Net.IPEndPoint]$tunnelOriginListener.LocalEndpoint).Port
    $tunnelAccept = $tunnelOriginListener.AcceptTcpClientAsync()
    $tunnelProxyClient = [System.Net.Sockets.TcpClient]::new()
    $tunnelProxyClient.Connect('127.0.0.1', $proxyPort)
    $tunnelProxyStream = $tunnelProxyClient.GetStream()
    $tunnelConnect = [System.Text.Encoding]::ASCII.GetBytes("CONNECT 127.0.0.1:$tunnelOriginPort HTTP/1.1`r`nHost: 127.0.0.1:$tunnelOriginPort`r`n`r`n")
    $tunnelProxyStream.Write($tunnelConnect, 0, $tunnelConnect.Length)
    $tunnelProxyStream.Flush()
    $tunnelReply = Read-MihariTestHeaderText -Stream $tunnelProxyStream -Context 'post-toggle Tunnel CONNECT'
    Assert-MihariTest -Condition ($tunnelReply.StartsWith('HTTP/1.1 200')) -Message 'A new CONNECT after switching back must establish a Tunnel.'
    Assert-MihariTest -Condition ($tunnelAccept.Wait(15000)) -Message 'The post-toggle Tunnel must connect to the local TLS fixture.'
    $tunnelOriginClient = $tunnelAccept.Result
    $tunnelOriginTls = [System.Net.Security.SslStream]::new($tunnelOriginClient.GetStream(), $true)
    $tunnelProxyTls = [System.Net.Security.SslStream]::new($tunnelProxyStream, $true)
    $tunnelServerAuth = Begin-MihariTestTlsServerAuthentication -Stream $tunnelOriginTls -Certificate $fixtureIdentity.Leaf
    $tunnelClientAuth = Begin-MihariTestTlsClientAuthentication -Stream $tunnelProxyTls -TargetHost '127.0.0.1'
    Complete-MihariTestTlsAuthentication -ServerStream $tunnelOriginTls -ServerResult $tunnelServerAuth -ClientStream $tunnelProxyTls -ClientResult $tunnelClientAuth
    $tunnelRequest = [System.Text.Encoding]::ASCII.GetBytes("GET /tunnel-after-toggle HTTP/1.1`r`nHost: 127.0.0.1:$tunnelOriginPort`r`nConnection: close`r`n`r`n")
    $tunnelProxyTls.Write($tunnelRequest, 0, $tunnelRequest.Length)
    $tunnelProxyTls.Flush()
    $tunnelOriginRequest = Read-MihariTestHeaderText -Stream $tunnelOriginTls -Context 'post-toggle Tunnel origin request'
    Assert-MihariTest -Condition ($tunnelOriginRequest.StartsWith('GET /tunnel-after-toggle HTTP/1.1')) -Message 'A new Tunnel must relay TLS application bytes without HTTP interception.'
    Write-MihariTestHttpResponse -Stream $tunnelOriginTls
    $tunnelResponse = Read-MihariTestHttpResponse -Stream $tunnelProxyTls
    Assert-MihariTest -Condition ($tunnelResponse.Headers.StartsWith('HTTP/1.1 200')) -Message 'The post-toggle Tunnel must relay its local TLS response.'
    $tunnelProxyTls.Dispose(); $tunnelProxyTls = $null
    $tunnelOriginTls.Dispose(); $tunnelOriginTls = $null
    $tunnelProxyClient.Close(); $tunnelProxyClient = $null
    $tunnelOriginClient.Close(); $tunnelOriginClient = $null
    $tunnelOriginListener.Stop(); $tunnelOriginListener = $null
    $newTunnelEvent = Wait-Issue3ApiEvent -ManagementEndpoint $managementEndpoint -Predicate { param($event) $event.stage -eq 'tunnel.relay' -and $event.data.host -eq '127.0.0.1' -and [int]$event.data.port -eq $tunnelOriginPort }
    Assert-MihariTest -Condition ($newTunnelEvent.mode -eq 'Tunnel') -Message 'A post-toggle Tunnel relay must be tagged with its accepted Tunnel mode.'

    $metadata = Get-Issue3Metadata -OutputDirectory ([string]$metadata.outputDirectory)
    $final = Stop-MihariTestSession -Child $child -Metadata $metadata
    $child.Process.Dispose()
    $child = $null
    Assert-MihariTest -Condition (-not (Test-Issue3TcpEndpoint -Port $proxyPort) -and -not (Test-Issue3TcpEndpoint -Port $managementPort)) -Message 'Normal stop must close both loopback listeners.'
    Assert-MihariTest -Condition (-not [bool]$final.caTrusted) -Message 'Normal stop must persist the session CA as no longer trusted.'

    $statusAfterStop = Start-MihariTestProcess -Command status -OutputRoot $outputRoot
    try {
        if (-not $statusAfterStop.Process.WaitForExit(10000)) { throw 'The stopped CLI status command timed out.' }
        $statusAfterStop.Process.WaitForExit()
        Assert-MihariTest -Condition ($statusAfterStop.Process.ExitCode -eq 0 -and $statusAfterStop.Stdout.Result -match 'stopped') -Message 'CLI status must report the stopped session after listener cleanup.'
    }
    finally { $statusAfterStop.Process.Dispose() }

    # The canonical diagnosis projection must refresh after a concrete local
    # upstream proxy response. This uses a fixture proxy and never the public
    # network, and verifies that findings retain their event evidence IDs.
    $proxyStatusListener = New-MihariTestListener
    $proxyStatusPort = ([System.Net.IPEndPoint]$proxyStatusListener.LocalEndpoint).Port
    $findingsRoot = Join-Path $tempRoot 'findings-session'
    try {
        $findingsChild = Start-MihariTestProcess -Command start -OutputRoot $findingsRoot -Mode Tunnel -Port 0 -UpstreamProxy ('http://127.0.0.1:{0}' -f $proxyStatusPort)
        $findingsMetadata = Wait-Issue3ManagementReady -Child $findingsChild
        [void](Invoke-MihariTestExplicitProxyStatus -ProxyListener $proxyStatusListener -MihariPort ([int]$findingsMetadata.actualPort) -StatusCode 407)
        $proxyEvent = Wait-Issue3ApiEvent -ManagementEndpoint ([string]$findingsMetadata.uiEndpoint) -Predicate { param($event) $event.stage -eq 'upstream.proxy.connect' -and [int]$event.data.proxyStatus -eq 407 }
        $authFinding = $null
        $findingsDeadline = [DateTime]::UtcNow.AddSeconds(12)
        do {
            $updatedFindings = Invoke-Issue3ManagementRequest -Endpoint ([string]$findingsMetadata.uiEndpoint + 'api/findings') -Method GET -Body $null
            Assert-MihariTest -Condition ($updatedFindings.StatusCode -eq 200) -Message 'The second live findings projection must respond successfully.'
            $authFinding = @($updatedFindings.Json.findings | Where-Object { $_.code -eq 'upstream_proxy_auth_required' }) | Select-Object -First 1
            if ($null -ne $authFinding) { break }
            Start-Sleep -Milliseconds 80
        } while ([DateTime]::UtcNow -lt $findingsDeadline)
        Assert-MihariTest -Condition ($null -ne $authFinding -and @($authFinding.evidenceIds) -contains [string]$proxyEvent.eventId) -Message 'A live concrete upstream HTTP 407 must refresh the canonical finding projection with its evidence event ID.'
    }
    finally {
        if ($null -ne $findingsChild) {
            try {
                if (-not $findingsChild.Process.HasExited) {
                    if ($null -ne $findingsMetadata) {
                        $findingsMetadata = Get-Issue3Metadata -OutputDirectory ([string]$findingsMetadata.outputDirectory)
                        [void](Stop-MihariTestSession -Child $findingsChild -Metadata $findingsMetadata)
                    }
                    else {
                        $findingsChild.Process.Kill()
                        [void]$findingsChild.Process.WaitForExit(5000)
                    }
                }
            }
            finally {
                if (-not $findingsChild.Process.HasExited) {
                    try { $findingsChild.Process.Kill(); [void]$findingsChild.Process.WaitForExit(5000) }
                    catch { $failures.Add("Findings child stop after cleanup error failed: $($_.Exception.Message)") }
                }
                if ($findingsChild.Process.HasExited) {
                    $findingsChild.Process.Dispose()
                    $findingsChild = $null
                }
            }
        }
        if ($null -ne $proxyStatusListener) { $proxyStatusListener.Stop(); $proxyStatusListener = $null }
    }
    Write-Host 'PASS issue3-management: dual listeners, live API/UI, event/finding projection and privacy, Inspect/Tunnel toggles, self-reference guard, health, and stop cleanup'
}
catch {
    $failures.Add($_.Exception.Message)
}
finally {
    if ($null -ne $addOperator) {
        try { Stop-MihariTestRootConfirmation -Operator $addOperator }
        catch { $failures.Add("CA-add prompt cleanup failed: $($_.Exception.Message)") }
    }
    foreach ($resourceName in @('oldProxyTls', 'inspectProxyTls', 'inspectOriginTls', 'tunnelProxyTls', 'tunnelOriginTls')) {
        $resource = Get-Variable -Name $resourceName -ValueOnly -ErrorAction SilentlyContinue
        if ($null -ne $resource) {
            try { $resource.Dispose() }
            catch { $failures.Add("$resourceName cleanup failed: $($_.Exception.Message)") }
        }
    }
    foreach ($resourceName in @('oldProxyClient', 'oldOriginClient', 'inspectProxyClient', 'inspectOriginClient', 'tunnelProxyClient', 'tunnelOriginClient', 'loopClient')) {
        $resource = Get-Variable -Name $resourceName -ValueOnly -ErrorAction SilentlyContinue
        if ($null -ne $resource) {
            try { $resource.Close() }
            catch { $failures.Add("$resourceName cleanup failed: $($_.Exception.Message)") }
        }
    }
    foreach ($resourceName in @('oldOriginListener', 'inspectOriginListener', 'tunnelOriginListener')) {
        $resource = Get-Variable -Name $resourceName -ValueOnly -ErrorAction SilentlyContinue
        if ($null -ne $resource) {
            try { $resource.Stop() }
            catch { $failures.Add("$resourceName cleanup failed: $($_.Exception.Message)") }
        }
    }
    if ($null -ne $child) {
        try {
            if (-not $child.Process.HasExited -and $null -ne $metadata) {
                $latest = Get-Issue3Metadata -OutputDirectory ([string]$metadata.outputDirectory)
                [void](Stop-MihariTestSession -Child $child -Metadata $latest)
            }
            elseif (-not $child.Process.HasExited) {
                $child.Process.Kill()
                [void]$child.Process.WaitForExit(5000)
            }
        }
        catch {
            $failures.Add("Mihari child cleanup failed: $($_.Exception.Message)")
            if (-not $child.Process.HasExited) {
                try { $child.Process.Kill(); [void]$child.Process.WaitForExit(5000) }
                catch { $failures.Add("Mihari child force-stop failed: $($_.Exception.Message)") }
            }
        }
        if ($child.Process.HasExited) { $child.Process.Dispose() }
    }
    if ($null -ne $findingsChild) {
        try {
            if (-not $findingsChild.Process.HasExited -and $null -ne $findingsMetadata) {
                $latestFindingsMetadata = Get-Issue3Metadata -OutputDirectory ([string]$findingsMetadata.outputDirectory)
                [void](Stop-MihariTestSession -Child $findingsChild -Metadata $latestFindingsMetadata)
            }
            elseif (-not $findingsChild.Process.HasExited) {
                $findingsChild.Process.Kill()
                [void]$findingsChild.Process.WaitForExit(5000)
            }
        }
        catch {
            $failures.Add("Findings child cleanup failed: $($_.Exception.Message)")
            if (-not $findingsChild.Process.HasExited) {
                try { $findingsChild.Process.Kill(); [void]$findingsChild.Process.WaitForExit(5000) }
                catch { $failures.Add("Findings child force-stop failed: $($_.Exception.Message)") }
            }
        }
        if ($findingsChild.Process.HasExited) { $findingsChild.Process.Dispose() }
    }
    if ($null -ne $proxyStatusListener) { try { $proxyStatusListener.Stop() } catch { $failures.Add("Proxy status listener cleanup failed: $($_.Exception.Message)") } }
    if ($null -ne $fixtureIdentity) {
        try { Remove-MihariTestFixtureTlsIdentity -Identity $fixtureIdentity }
        catch { $failures.Add("Fixture certificate cleanup failed: $($_.Exception.Message)") }
    }
    try { Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction Stop }
    catch { $failures.Add("Temporary test output cleanup failed: $($_.Exception.Message)") }
}
if ($failures.Count -gt 0) { throw ('Issue #3 management verification failed: ' + ($failures -join '; ')) }
