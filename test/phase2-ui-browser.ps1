param()

$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') {
    Write-Warning 'The Phase 2 workbench browser test requires Windows and Microsoft Edge.'
    return
}

. (Join-Path $PSScriptRoot 'TestSupport.ps1')
. (Join-Path $PSScriptRoot 'integration.ps1') -LoadHelpersOnly
. (Join-Path $PSScriptRoot 'issue3-ui-browser.ps1') -LoadHelpersOnly

$repoRoot = Split-Path $PSScriptRoot -Parent
$uiPath = Join-Path (Join-Path $repoRoot 'src') 'ManagementUi.ps1'
$uiBytes = [IO.File]::ReadAllBytes($uiPath)
$nonAsciiUiBytes = @($uiBytes | Where-Object { $_ -gt 127 })
Assert-MihariTest -Condition ($nonAsciiUiBytes.Count -eq 0) -Message 'ManagementUi.ps1 must remain ASCII-only for Windows PowerShell 5.1.'

function Send-Phase2UiOriginResponse {
    param([Parameter(Mandatory = $true)][System.Net.Sockets.TcpListener]$Listener,
        [Parameter(Mandatory = $true)][string]$ExpectedPath,
        [string]$Body = '<!doctype html><link rel="icon" href="data:,"><title>Mihari fixture</title><p>Local browser fixture</p>')
    $accept = $Listener.AcceptTcpClientAsync()
    if (-not $accept.Wait(30000)) { throw 'The local origin did not receive a request through Mihari.' }
    $client = $accept.Result
    try {
        $stream = $client.GetStream()
        $request = Read-MihariTestHeaderText -Stream $stream -Context 'Phase 2 UI local origin request'
        Assert-MihariTest -Condition ($request.StartsWith(('GET {0} HTTP/1.1' -f $ExpectedPath))) -Message 'The browser/proxy request must reach the exact local fixture path.'
        $bodyBytes = [Text.Encoding]::ASCII.GetBytes($Body)
        $headers = [Text.Encoding]::ASCII.GetBytes("HTTP/1.1 200 OK`r`nContent-Type: text/html; charset=utf-8`r`nContent-Length: $($bodyBytes.Length)`r`nConnection: close`r`n`r`n")
        $stream.Write($headers, 0, $headers.Length)
        $stream.Write($bodyBytes, 0, $bodyBytes.Length)
        $stream.Flush()
        return $request
    }
    finally { $client.Close() }
}

function Get-Phase2UiHtml {
    param([Parameter(Mandatory = $true)][string]$Uri)
    $request = [System.Net.HttpWebRequest]::Create($Uri)
    $request.Proxy = $null
    $request.Timeout = 5000
    $response = $request.GetResponse()
    try {
        $reader = [System.IO.StreamReader]::new($response.GetResponseStream(), [System.Text.Encoding]::UTF8)
        try { return $reader.ReadToEnd() }
        finally { $reader.Dispose() }
    }
    finally { $response.Dispose() }
}

function Invoke-Phase2UiProxyGet {
    param([Parameter(Mandatory = $true)][int]$ProxyPort,
        [Parameter(Mandatory = $true)][System.Net.Sockets.TcpListener]$Origin,
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$QueryToken)
    $originPort = ([System.Net.IPEndPoint]$Origin.LocalEndpoint).Port
    $target = 'http://127.0.0.1:{0}{1}?token={2}' -f $originPort, $Path, $QueryToken
    $accept = $Origin.AcceptTcpClientAsync()
    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $client.Connect('127.0.0.1', $ProxyPort)
        $stream = $client.GetStream()
        $request = "GET $target HTTP/1.1`r`nHost: 127.0.0.1:$originPort`r`nConnection: close`r`n`r`n"
        $bytes = [Text.Encoding]::ASCII.GetBytes($request)
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush()
        if (-not $accept.Wait(15000)) { throw 'Mihari did not connect to the local origin for the paused-display fixture.' }
        $originClient = $accept.Result
        try {
            $originStream = $originClient.GetStream()
            $originRequest = Read-MihariTestHeaderText -Stream $originStream -Context 'Paused-display origin request'
            Assert-MihariTest -Condition ($originRequest.StartsWith(('GET {0} HTTP/1.1' -f $Path))) -Message 'The paused-display request must reach the local origin.'
            Write-MihariTestHttpResponse -Stream $originStream -Body 'phase2-ui-ok'
        }
        finally { $originClient.Close() }
        return (Read-MihariTestHttpResponse -Stream $stream)
    }
    finally { $client.Close() }
}

$tempRoot = Join-Path ([IO.Path]::GetTempPath()) ('mihari-phase2-ui-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($tempRoot)
$child = $null
$metadata = $null
$browser = $null
$addOperator = $null
$originListener = $null
$pauseListener = $null
$diagnosticProfile = $null
$cleanupFailure = $null
try {
    $child = Start-MihariTestProcess -Command start -OutputRoot (Join-Path $tempRoot 'session') -Mode Tunnel -Port 0
    $metadata = Wait-MihariTestSession -Child $child
    $managementUrl = 'http://127.0.0.1:{0}/' -f [int]$metadata.actualManagementPort
    $servedHtml = Get-Phase2UiHtml -Uri $managementUrl
    Assert-MihariTest -Condition ($servedHtml -match 'var CONTROL_TOKEN="[A-Za-z0-9_-]+";') -Message 'The served same-origin page must expose the ASCII-safe session token bootstrap expected by its owned controls.'
    $browser = Start-Issue3UiEdge -Uri $managementUrl -ProfilePath (Join-Path $tempRoot 'management-edge')
    $null = Wait-Issue3UiValue -Browser $browser -Expression 'document.getElementById("session-id")?.textContent || ""' -Predicate {
        param($value) [string]$value -eq [string]$metadata.sessionId
    }

    # The protected mode action must work from the served token bootstrap.
    $addOperator = Start-MihariTestRootConfirmation -Operation Add -TargetProcessId $child.Process.Id
    $null = Invoke-Issue3UiEvaluate -Browser $browser -Expression 'document.getElementById("inspect-toggle").click(); true'
    $null = Wait-Issue3UiValue -Browser $browser -Expression 'document.getElementById("mode-state").textContent' -Predicate { param($value) $value -eq 'Inspect' }
    Complete-MihariTestRootConfirmation -Operator $addOperator
    Stop-MihariTestRootConfirmation -Operator $addOperator
    $addOperator = $null
    $null = Invoke-Issue3UiEvaluate -Browser $browser -Expression 'document.getElementById("inspect-toggle").click(); true'
    $null = Wait-Issue3UiValue -Browser $browser -Expression 'document.getElementById("mode-state").textContent' -Predicate { param($value) $value -eq 'Tunnel' }

    # Launch the actual diagnostic Edge from the workbench and serve its request locally.
    $originListener = New-MihariTestListener
    $originPort = ([System.Net.IPEndPoint]$originListener.LocalEndpoint).Port
    $pathPrefix = '/phase2-ui-' + [guid]::NewGuid().ToString('N')
    $firstPath = $pathPrefix + '/browser'
    $queryToken = 'secret-' + [guid]::NewGuid().ToString('N')
    $fixtureUrl = 'http://127.0.0.1:{0}{1}?token={2}' -f $originPort, $firstPath, $queryToken
    $urlJson = ConvertTo-Json -InputObject $fixtureUrl -Compress
    $null = Invoke-Issue3UiEvaluate -Browser $browser -Expression ('document.getElementById("browser-url").value={0}; document.getElementById("launch-browser").click(); true' -f $urlJson)
    $browserOriginRequest = Send-Phase2UiOriginResponse -Listener $originListener -ExpectedPath $firstPath
    Assert-MihariTest -Condition ($browserOriginRequest -match [regex]::Escape(('token={0}' -f $queryToken))) -Message 'The local fixture must receive the browser request with its query value intact on the wire.'
    $launchPath = Join-Path ([string]$metadata.outputDirectory) 'browser-launch.json'
    $launchDeadline = [DateTime]::UtcNow.AddSeconds(10)
    do {
        if ([IO.File]::Exists($launchPath)) { break }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $launchDeadline)
    Assert-MihariTest -Condition ([IO.File]::Exists($launchPath)) -Message 'The visible browser action must use the canonical Mihari Edge launcher.'
    $launch = ConvertFrom-Json -InputObject (Read-MihariTestLiveText -Path $launchPath)
    $diagnosticProfile = [string]$launch.profilePath
    Assert-MihariTest -Condition ([bool]$launch.success -and [string]$launch.proxyEndpoint -eq ('http://127.0.0.1:{0}' -f [int]$metadata.actualPort)) -Message 'The diagnostic browser must use the Mihari loopback proxy.'

    # Exercise real request filters, local saved views, row selection and safe evidence drill-down.
    $pathPrefixJson = ConvertTo-Json -InputObject $pathPrefix -Compress
    $filterExpression = 'document.getElementById("tab-traffic").click(); document.getElementById("filter-host").value="127.0.0.1"; document.getElementById("filter-host").dispatchEvent(new Event("input",{bubbles:true})); document.getElementById("filter-path").value=' + $pathPrefixJson + '; document.getElementById("filter-path").dispatchEvent(new Event("input",{bubbles:true})); true'
    $null = Invoke-Issue3UiEvaluate -Browser $browser -Expression $filterExpression
    $rowText = Wait-Issue3UiValue -Browser $browser -Expression 'document.getElementById("request-rows").textContent' -Predicate {
        param($value) [string]$value -match [regex]::Escape($pathPrefix)
    }
    Assert-MihariTest -Condition ([string]$rowText -notmatch [regex]::Escape($queryToken)) -Message 'Traffic rows must redact query values.'
    $null = Invoke-Issue3UiEvaluate -Browser $browser -Expression 'document.getElementById("saved-view-name").value="Local fixture"; document.getElementById("save-view").click(); true'
    $savedCount = Wait-Issue3UiValue -Browser $browser -Expression 'document.getElementById("saved-views").options.length' -Predicate { param($value) [int]$value -ge 2 }
    Assert-MihariTest -Condition ([int]$savedCount -ge 2) -Message 'The Traffic Inspector must save the current filter set in this browser profile.'
    $null = Invoke-Issue3UiEvaluate -Browser $browser -Expression 'document.getElementById("clear-filters").click(); true'
    $null = Wait-Issue3UiValue -Browser $browser -Expression 'document.getElementById("filter-path").value' -Predicate { param($value) [string]$value -eq '' }
    $null = Invoke-Issue3UiEvaluate -Browser $browser -Expression 'var s=document.getElementById("saved-views"); s.selectedIndex=1; s.dispatchEvent(new Event("change",{bubbles:true})); true'
    $null = Wait-Issue3UiValue -Browser $browser -Expression 'document.getElementById("filter-path").value' -Predicate {
        param($value) [string]$value -eq [string]$pathPrefix
    }
    $null = Wait-Issue3UiValue -Browser $browser -Expression 'document.querySelector("#request-rows .traffic-row[data-request-key]")?.getAttribute("data-request-key") || ""' -Predicate {
        param($value) -not [string]::IsNullOrWhiteSpace([string]$value)
    }
    $requestKey = [string](Invoke-Issue3UiEvaluate -Browser $browser -Expression 'document.querySelector("#request-rows .traffic-row[data-request-key]")?.getAttribute("data-request-key") || ""')
    $null = Invoke-Issue3UiEvaluate -Browser $browser -Expression ('document.querySelector("#request-rows .traffic-row[data-request-key]")?.click(); true')
    $detailText = Wait-Issue3UiValue -Browser $browser -Expression 'document.getElementById("detail-content").textContent' -Predicate {
        param($value) [string]$value -match 'Observed phase timeline' -and [string]$value -match 'Linked evidence'
    }
    Assert-MihariTest -Condition ([string]$detailText -match [regex]::Escape($requestKey) -and [string]$detailText -notmatch [regex]::Escape($queryToken)) -Message 'Selecting an actual request must reveal its safe summary and evidence chain.'
    $detailUri = $managementUrl + 'api/v2/requests/' + [Uri]::EscapeDataString($requestKey)
    $apiDetail = Get-Issue3UiHttpJson -Uri $detailUri
    $apiEvents = @($apiDetail.events)
    Assert-MihariTest -Condition ($apiEvents.Count -gt 0 -and ([string]$detailText).Contains([string]$apiEvents[0].eventId)) -Message 'The selected detail DOM must contain an event ID from the exact detail API response.'
    $null = Invoke-Issue3UiEvaluate -Browser $browser -Expression 'var d=document.querySelector("#detail-content details.evidence-event"); if(d)d.open=true; true'

    # Pause hides new rows without stopping capture, then resume reads the new request.
    $beforeCount = [int](Invoke-Issue3UiEvaluate -Browser $browser -Expression 'document.querySelectorAll("#request-rows .traffic-row[data-request-key]").length')
    $null = Invoke-Issue3UiEvaluate -Browser $browser -Expression 'document.getElementById("traffic-pause").click(); true'
    $null = Wait-Issue3UiValue -Browser $browser -Expression 'document.getElementById("traffic-display-state").textContent' -Predicate { param($value) [string]$value -match 'paused; capture continues' }
    $pauseListener = New-MihariTestListener
    $pausePath = $pathPrefix + '/paused-capture'
    $proxyResponse = Invoke-Phase2UiProxyGet -ProxyPort ([int]$metadata.actualPort) -Origin $pauseListener -Path $pausePath -QueryToken $queryToken
    Assert-MihariTest -Condition ($proxyResponse.Headers.StartsWith('HTTP/1.1 200') -and $proxyResponse.Body -eq 'phase2-ui-ok') -Message 'Capture must continue to forward actual requests while the UI display is paused.'
    $null = Wait-Issue3UiValue -Browser $browser -Expression 'document.getElementById("traffic-display-state").textContent' -Predicate { param($value) [string]$value -match 'paused; capture continues' }
    Start-Sleep -Milliseconds 2800
    $pausedCount = [int](Invoke-Issue3UiEvaluate -Browser $browser -Expression 'document.querySelectorAll("#request-rows .traffic-row[data-request-key]").length')
    Assert-MihariTest -Condition ($pausedCount -eq $beforeCount) -Message 'A captured request must remain out of the rendered list while display is paused.'
    $null = Invoke-Issue3UiEvaluate -Browser $browser -Expression 'document.getElementById("traffic-pause").click(); true'
    $resumedCount = Wait-Issue3UiValue -Browser $browser -Expression 'document.querySelectorAll("#request-rows .traffic-row[data-request-key]").length' -Predicate {
        param($value) [int]$value -gt $beforeCount
    }
    Assert-MihariTest -Condition ([int]$resumedCount -gt $beforeCount) -Message 'Resuming live display must show the request captured while paused.'

    # Prove stale rows remain visible during an API fault, then recover from the real route.
    $null = Invoke-Issue3UiEvaluate -Browser $browser -Expression 'window.__mihariOriginalFetch=window.fetch.bind(window); window.fetch=function(input,init){var u=(typeof input==="string"?input:input.url); if(u.indexOf("/api/v2/requests")===0)return Promise.reject(new Error("local fixture API fault")); return window.__mihariOriginalFetch(input,init);}; document.getElementById("traffic-refresh").click(); true'
    $apiError = Wait-Issue3UiValue -Browser $browser -Expression 'document.getElementById("traffic-error").textContent' -Predicate {
        param($value) [string]$value -match 'stale because the management API failed'
    }
    $staleCount = [int](Invoke-Issue3UiEvaluate -Browser $browser -Expression 'document.querySelectorAll("#request-rows .traffic-row[data-request-key]").length')
    Assert-MihariTest -Condition ($staleCount -eq [int]$resumedCount -and [string]$apiError -match 'local fixture API fault') -Message 'API failure must be visible while retaining the last successful rows.'
    $null = Invoke-Issue3UiEvaluate -Browser $browser -Expression 'window.fetch=window.__mihariOriginalFetch; delete window.__mihariOriginalFetch; document.getElementById("traffic-refresh").click(); true'
    $null = Wait-Issue3UiValue -Browser $browser -Expression 'document.getElementById("traffic-error").className' -Predicate { param($value) [string]$value -notmatch 'visible' }
    $finalState = Invoke-Issue3UiEvaluate -Browser $browser -Expression ('JSON.stringify({rows:document.querySelectorAll("#request-rows .traffic-row[data-request-key]").length,visible:document.getElementById("traffic-view").hidden===false,paused:document.getElementById("traffic-display-state").textContent})')
    $final = ConvertFrom-Json -InputObject ([string]$finalState)
    Assert-MihariTest -Condition ($final.rows -ge 2 -and $final.visible) -Message 'The live Traffic Inspector must recover and render both real local requests in Edge.'
    Write-Host 'PASS phase2-ui-browser: real Edge mode and browser actions, filtered request selection, evidence drill-down, pause/resume capture, query redaction, and API recovery.'
}
finally {
    if ($null -ne $addOperator) { Stop-MihariTestRootConfirmation -Operator $addOperator }
    if ($null -ne $originListener) { $originListener.Stop() }
    if ($null -ne $pauseListener) { $pauseListener.Stop() }
    if ($null -ne $browser) { $browser.Socket.Dispose() }
    foreach ($profile in @($diagnosticProfile, (Join-Path $tempRoot 'management-edge'))) {
        try { Stop-Issue3UiEdgeProfile -ProfilePath $profile }
        catch { $cleanupFailure = $_; Write-Warning ('Edge profile cleanup failed: ' + $_.Exception.Message) }
    }
    if ($null -ne $child -and $null -ne $metadata -and -not $child.Process.HasExited) {
        try {
            $latestMetadata = ConvertFrom-Json -InputObject (Read-MihariTestLiveText -Path (Join-Path ([string]$metadata.outputDirectory) 'session.json'))
            [void](Stop-MihariTestSession -Child $child -Metadata $latestMetadata)
        }
        catch { $cleanupFailure = $_; Write-Warning ('Session cleanup failed: ' + $_.Exception.Message) }
    }
    if ($null -ne $child) {
        if (-not $child.Process.HasExited) { $child.Process.Kill(); [void]$child.Process.WaitForExit(5000) }
        $child.Process.Dispose()
    }
    if (Test-Path -LiteralPath $tempRoot) { Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue }
}
if ($null -ne $cleanupFailure) { throw $cleanupFailure }
