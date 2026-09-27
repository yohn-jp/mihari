param([switch] $LoadHelpersOnly)

$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') {
    Write-Warning 'The Issue #3 browser UI smoke requires Windows and Microsoft Edge.'
    return
}

. (Join-Path $PSScriptRoot 'TestSupport.ps1')
. (Join-Path $PSScriptRoot 'integration.ps1') -LoadHelpersOnly
. (Join-Path (Split-Path $PSScriptRoot -Parent) 'src/Browser.ps1')

$managementUiSourcePath = Join-Path (Join-Path (Split-Path $PSScriptRoot -Parent) 'src') 'ManagementUi.ps1'
$managementUiBytes = [IO.File]::ReadAllBytes($managementUiSourcePath)
$nonAsciiUiBytes = @($managementUiBytes | Where-Object { $_ -gt 127 })
Assert-MihariTest -Condition ($nonAsciiUiBytes.Count -eq 0) -Message 'ManagementUi.ps1 must remain ASCII-only so Windows PowerShell 5.1 cannot reinterpret embedded HTML/JavaScript through the active ANSI code page.'

function Get-Issue3UiHttpJson {
    param([Parameter(Mandatory = $true)][string]$Uri)
    $request = [System.Net.HttpWebRequest]::Create($Uri)
    $request.Proxy = $null
    $request.Timeout = 5000
    $response = $request.GetResponse()
    try {
        $reader = [System.IO.StreamReader]::new($response.GetResponseStream(), [System.Text.Encoding]::UTF8)
        try { return (ConvertFrom-Json -InputObject $reader.ReadToEnd() -ErrorAction Stop) }
        finally { $reader.Dispose() }
    }
    finally { $response.Dispose() }
}

function Read-Issue3UiCdpMessage {
    param([Parameter(Mandatory = $true)][System.Net.WebSockets.ClientWebSocket]$Socket)
    $bytes = New-Object byte[] 8192
    $buffer = [System.ArraySegment[byte]]::new($bytes)
    $stream = New-Object System.IO.MemoryStream
    $cancel = [System.Threading.CancellationTokenSource]::new(10000)
    try {
        do {
            $result = $Socket.ReceiveAsync($buffer, $cancel.Token).GetAwaiter().GetResult()
            if ($result.MessageType -eq [System.Net.WebSockets.WebSocketMessageType]::Close) {
                throw 'Edge closed its DevTools connection before returning a command result.'
            }
            $stream.Write($bytes, 0, $result.Count)
            if ($stream.Length -gt 1048576) { throw 'Edge returned an oversized DevTools message.' }
        } while (-not $result.EndOfMessage)
        return (ConvertFrom-Json -InputObject ([System.Text.Encoding]::UTF8.GetString($stream.ToArray())) -ErrorAction Stop)
    }
    finally {
        $cancel.Dispose()
        $stream.Dispose()
    }
}

function Invoke-Issue3UiEvaluate {
    param([Parameter(Mandatory = $true)]$Browser, [Parameter(Mandatory = $true)][string]$Expression)
    $Browser.NextId++
    $request = ConvertTo-Json -InputObject ([ordered]@{
        id = $Browser.NextId
        method = 'Runtime.evaluate'
        params = @{ expression = $Expression; returnByValue = $true; awaitPromise = $true }
    }) -Compress -Depth 5
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($request)
    $segment = [System.ArraySegment[byte]]::new($bytes)
    $cancel = [System.Threading.CancellationTokenSource]::new(10000)
    try {
        [void]$Browser.Socket.SendAsync($segment, [System.Net.WebSockets.WebSocketMessageType]::Text, $true, $cancel.Token).GetAwaiter().GetResult()
        do {
            $response = Read-Issue3UiCdpMessage -Socket $Browser.Socket
        } while ($null -eq $response.id -or [int]$response.id -ne $Browser.NextId)
        if ($null -ne $response.error) { throw ('Edge DevTools command failed: ' + [string]$response.error.message) }
        if ($null -ne $response.result.exceptionDetails) {
            $detail = [string]$response.result.exceptionDetails.exception.description
            if ([string]::IsNullOrWhiteSpace($detail)) { $detail = [string]$response.result.exceptionDetails.text }
            throw ('Management UI JavaScript failed: ' + $detail)
        }
        return $response.result.result.value
    }
    finally { $cancel.Dispose() }
}

function Wait-Issue3UiValue {
    param([Parameter(Mandatory = $true)]$Browser, [Parameter(Mandatory = $true)][string]$Expression,
        [Parameter(Mandatory = $true)][scriptblock]$Predicate, [int]$TimeoutSeconds = 25)
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $value = Invoke-Issue3UiEvaluate -Browser $Browser -Expression $Expression
        if (& $Predicate $value) { return $value }
        Start-Sleep -Milliseconds 200
    } while ([DateTime]::UtcNow -lt $deadline)
    $lastValue = [string]$value
    if ($lastValue.Length -gt 200) { $lastValue = $lastValue.Substring(0, 200) + '...' }
    throw ('The management UI did not reach the expected DOM state. Last value: ' + $lastValue)
}

function Start-Issue3UiEdge {
    param([Parameter(Mandatory = $true)][string]$Uri, [Parameter(Mandatory = $true)][string]$ProfilePath)
    $edge = Find-MihariEdgeExecutable
    if ([string]::IsNullOrWhiteSpace($edge)) { throw 'Microsoft Edge is required for the real management UI smoke test.' }
    $info = New-Object System.Diagnostics.ProcessStartInfo
    $info.FileName = $edge
    $arguments = @('--headless=new', '--disable-gpu', '--disable-background-networking', '--no-first-run', '--no-default-browser-check',
        '--no-proxy-server', '--remote-debugging-port=0', ('--user-data-dir=' + $ProfilePath), $Uri)
    $info.Arguments = [string]::Join(' ', @($arguments | ForEach-Object { ConvertTo-MihariWindowsArgument -Value $_ }))
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $process = [System.Diagnostics.Process]::Start($info)
    if ($null -eq $process) { throw 'Could not start headless Edge for the management UI smoke test.' }
    $portFile = Join-Path $ProfilePath 'DevToolsActivePort'
    $deadline = [DateTime]::UtcNow.AddSeconds(25)
    $port = 0
    $portReadError = $null
    do {
        if ($process.HasExited) { throw ('Headless Edge exited before exposing DevTools: ' + $process.ExitCode) }
        if ([IO.File]::Exists($portFile)) {
            try {
                $portLines = [IO.File]::ReadAllLines($portFile)
                $candidatePort = 0
                if ($portLines.Length -gt 0 -and [int]::TryParse($portLines[0], [ref]$candidatePort) -and
                    $candidatePort -gt 0 -and $candidatePort -le 65535) {
                    $port = $candidatePort
                    break
                }
            }
            catch {
                $isSharingRace = ($_.Exception -is [IO.IOException] -or $_.Exception.InnerException -is [IO.IOException])
                if (-not $isSharingRace) { throw }
                $portReadError = $_.Exception.GetType().FullName
            }
        }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    if ($port -le 0) {
        if (-not [IO.File]::Exists($portFile)) { throw 'Headless Edge did not expose DevToolsActivePort.' }
        throw ('Headless Edge did not publish a readable positive DevTools port before startup deadline. Last read error type: ' + [string]$portReadError)
    }
    $target = $null
    $targetProbeError = $null
    do {
        if ($process.HasExited) { throw ('Headless Edge exited before exposing its management page: ' + $process.ExitCode) }
        try {
            foreach ($candidate in @(Get-Issue3UiHttpJson -Uri ('http://127.0.0.1:{0}/json/list' -f $port))) {
                if ($candidate.type -eq 'page' -and ([string]$candidate.url).StartsWith($Uri, [System.StringComparison]::OrdinalIgnoreCase)) {
                    $target = $candidate
                    break
                }
            }
        }
        catch {
            $isStartupNetworkRace = ($_.Exception -is [System.Net.WebException] -or $_.Exception.InnerException -is [System.Net.WebException])
            if (-not $isStartupNetworkRace) { throw }
            $targetProbeError = $_.Exception.GetType().FullName
        }
        if ($null -ne $target) { break }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    if ($null -eq $target) { throw ('Headless Edge did not navigate to the Mihari management page before startup deadline. Last probe error type: ' + [string]$targetProbeError) }
    $socket = New-Object System.Net.WebSockets.ClientWebSocket
    $cancel = [System.Threading.CancellationTokenSource]::new(10000)
    try { [void]$socket.ConnectAsync([Uri]$target.webSocketDebuggerUrl, $cancel.Token).GetAwaiter().GetResult() }
    finally { $cancel.Dispose() }
    return [pscustomobject]@{ Process = $process; Socket = $socket; NextId = 0; ProfilePath = $ProfilePath }
}

function Get-Issue3UiEdgeProcesses {
    param([Parameter(Mandatory = $true)][string]$ProfilePath)
    return @(Get-CimInstance -ClassName Win32_Process -Filter "Name = 'msedge.exe'" |
        Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_.CommandLine) -and
            ([string]$_.CommandLine).IndexOf($ProfilePath, [StringComparison]::OrdinalIgnoreCase) -ge 0 })
}

function Stop-Issue3UiEdgeProfile {
    param([string]$ProfilePath)
    if ([string]::IsNullOrWhiteSpace($ProfilePath)) { return }
    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    do {
        $matches = @(Get-Issue3UiEdgeProcesses -ProfilePath $ProfilePath)
        foreach ($item in $matches) {
            try { Stop-Process -Id ([int]$item.ProcessId) -Force -ErrorAction Stop }
            catch {
                # Edge may exit after the CIM snapshot. Only a surviving
                # process with this unique profile needs another attempt.
                $survivors = @(Get-Issue3UiEdgeProcesses -ProfilePath $ProfilePath |
                    Where-Object { [int]$_.ProcessId -eq [int]$item.ProcessId })
                if ($survivors.Count -gt 0) {
                    Write-Verbose ('Retrying cleanup of Edge process {0}.' -f $item.ProcessId)
                }
            }
        }
        if ($matches.Count -eq 0) { break }
        Start-Sleep -Milliseconds 200
    } while ([DateTime]::UtcNow -lt $deadline)
    if (@(Get-Issue3UiEdgeProcesses -ProfilePath $ProfilePath).Count -gt 0) {
        throw 'Edge processes retained the test profile after cleanup.'
    }
    if (Test-Path -LiteralPath $ProfilePath) {
        Remove-Item -LiteralPath $ProfilePath -Recurse -Force -ErrorAction Stop
        if (Test-Path -LiteralPath $ProfilePath) { throw 'The Edge test profile remained after removal.' }
    }
}

if ($LoadHelpersOnly) { return }

$tempRoot = Join-Path ([IO.Path]::GetTempPath()) ('mihari-issue3-ui-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($tempRoot)
$child = $null
$metadata = $null
$browser = $null
$addOperator = $null
$originListener = $null
$originClient = $null
$diagnosticProfile = $null
$findingListener = $null
$findingChild = $null
$findingMetadata = $null
$findingBrowser = $null
$cleanupFailure = $null
try {
    $child = Start-MihariTestProcess -Command start -OutputRoot (Join-Path $tempRoot 'session') -Mode Tunnel -Port 0
    $metadata = Wait-MihariTestSession -Child $child
    $managementUrl = 'http://127.0.0.1:{0}/' -f [int]$metadata.actualManagementPort
    $browser = Start-Issue3UiEdge -Uri $managementUrl -ProfilePath (Join-Path $tempRoot 'management-edge')
    $browserType = 'null'
    if ($null -ne $browser) { $browserType = $browser.GetType().FullName }
    Assert-MihariTest -Condition ($browser -is [pscustomobject] -and $null -ne $browser.PSObject.Properties['NextId']) -Message ('The headless Edge setup must return one browser control context; type={0}, count={1}.' -f $browserType, @($browser).Count)

    $snapshotExpression = 'JSON.stringify({session:document.getElementById("session-id")?.textContent,mode:document.getElementById("mode-state")?.textContent,proxy:document.getElementById("proxy-endpoint")?.textContent,ui:document.getElementById("management-endpoint")?.textContent,updated:document.getElementById("last-updated")?.textContent,events:document.getElementById("event-rows")?.textContent,error:document.getElementById("api-error")?.className})'
    $initialText = Wait-Issue3UiValue -Browser $browser -Expression $snapshotExpression -Predicate {
        param($value) $value -and $value.Contains([string]$metadata.sessionId) -and $value.Contains('Tunnel') -and $value.Contains('Updated ')
    }
    $initial = ConvertFrom-Json -InputObject $initialText
    Assert-MihariTest -Condition ($initial.proxy -match [regex]::Escape([string]$metadata.actualPort) -and
        $initial.ui -match [regex]::Escape([string]$metadata.actualManagementPort) -and $initial.error -notmatch 'visible') -Message 'The live management page must render the actual healthy session and both listener endpoints.'

    # A successful event added after page load must appear without navigation.
    $pollListener = New-MihariTestListener
    $pollPort = ([System.Net.IPEndPoint]$pollListener.LocalEndpoint).Port
    $pollPath = '/ui-poll-' + [guid]::NewGuid().ToString('N')
    $pollAccept = $pollListener.AcceptTcpClientAsync()
    $proxyClient = [System.Net.Sockets.TcpClient]::new()
    try {
        $proxyClient.Connect('127.0.0.1', [int]$metadata.actualPort)
        $proxyStream = $proxyClient.GetStream()
        $requestBytes = [Text.Encoding]::ASCII.GetBytes("GET http://127.0.0.1:$pollPort$pollPath HTTP/1.1`r`nHost: 127.0.0.1:$pollPort`r`nConnection: close`r`n`r`n")
        $proxyStream.Write($requestBytes, 0, $requestBytes.Length)
        $proxyStream.Flush()
        Assert-MihariTest -Condition ($pollAccept.Wait(10000)) -Message 'The polling fixture must accept the request forwarded by Mihari.'
        $pollClient = $pollAccept.Result
        try {
            $pollStream = $pollClient.GetStream()
            $null = Read-MihariTestHeaderText -Stream $pollStream -Context 'UI polling origin request'
            $pollResponse = [Text.Encoding]::ASCII.GetBytes("HTTP/1.1 200 OK`r`nContent-Length: 0`r`nConnection: close`r`n`r`n")
            $pollStream.Write($pollResponse, 0, $pollResponse.Length)
            $pollStream.Flush()
        }
        finally { $pollClient.Close() }
        $null = Read-MihariTestHeaderText -Stream $proxyStream -Context 'UI event fixture'
    }
    finally { $proxyClient.Close(); $pollListener.Stop() }
    $null = Wait-Issue3UiValue -Browser $browser -Expression 'document.getElementById("event-rows").textContent' -Predicate {
        param($value) [string]$value -match [regex]::Escape($pollPath)
    }

    $addOperator = Start-MihariTestRootConfirmation -Operation Add -TargetProcessId $child.Process.Id
    $null = Invoke-Issue3UiEvaluate -Browser $browser -Expression 'document.getElementById("inspect-toggle").click(); true'
    $null = Wait-Issue3UiValue -Browser $browser -Expression 'document.getElementById("mode-state").textContent' -Predicate { param($value) $value -eq 'Inspect' }
    Complete-MihariTestRootConfirmation -Operator $addOperator
    Stop-MihariTestRootConfirmation -Operator $addOperator
    $addOperator = $null
    $inspectStatus = Get-Issue3UiHttpJson -Uri ($managementUrl + 'api/status')
    Assert-MihariTest -Condition ($inspectStatus.session.mode -eq 'Inspect' -and [bool]$inspectStatus.ca.trusted) -Message 'The UI toggle must enable Inspect only after session CA trust is available.'
    $null = Invoke-Issue3UiEvaluate -Browser $browser -Expression 'document.getElementById("inspect-toggle").click(); true'
    $null = Wait-Issue3UiValue -Browser $browser -Expression 'document.getElementById("mode-state").textContent' -Predicate { param($value) $value -eq 'Tunnel' }

    $originListener = New-MihariTestListener
    $originPort = ([System.Net.IPEndPoint]$originListener.LocalEndpoint).Port
    $fixturePath = '/ui-click-' + [guid]::NewGuid().ToString('N')
    $fixtureUrl = 'http://127.0.0.1:{0}{1}' -f $originPort, $fixturePath
    $originAccept = $originListener.AcceptTcpClientAsync()
    $fixtureUrlJson = ConvertTo-Json -InputObject $fixtureUrl -Compress
    $null = Invoke-Issue3UiEvaluate -Browser $browser -Expression ('document.getElementById("browser-url").value={0}; document.getElementById("launch-browser").click(); true' -f $fixtureUrlJson)
    if (-not $originAccept.Wait(30000)) { throw 'The UI-clicked diagnostic Edge did not reach the local fixture through Mihari.' }
    $originClient = $originAccept.Result
    $originStream = $originClient.GetStream()
    $originRequest = Read-MihariTestHeaderText -Stream $originStream -Context 'UI-clicked Edge fixture'
    Assert-MihariTest -Condition ($originRequest.StartsWith(('GET {0} HTTP/1.1' -f $fixturePath))) -Message 'The UI launch button must produce browser traffic at the local fixture.'
    $body = [Text.Encoding]::UTF8.GetBytes('Mihari UI browser fixture')
    $headers = [Text.Encoding]::ASCII.GetBytes("HTTP/1.1 200 OK`r`nContent-Length: $($body.Length)`r`nConnection: close`r`n`r`n")
    $originStream.Write($headers, 0, $headers.Length)
    $originStream.Write($body, 0, $body.Length)
    $originStream.Flush()
    $originClient.Close()
    $originClient = $null
    $originListener.Stop()
    $originListener = $null
    $launchPath = Join-Path ([string]$metadata.outputDirectory) 'browser-launch.json'
    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    do {
        if ([IO.File]::Exists($launchPath)) { break }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    Assert-MihariTest -Condition ([IO.File]::Exists($launchPath)) -Message 'The UI launch must delegate to the canonical browser launcher.'
    $launch = ConvertFrom-Json -InputObject (Read-MihariTestLiveText -Path $launchPath)
    $diagnosticProfile = [string]$launch.profilePath
    Assert-MihariTest -Condition ([bool]$launch.success -and [string]$launch.proxyEndpoint -eq ('http://127.0.0.1:{0}' -f [int]$metadata.actualPort)) -Message 'The UI-clicked Edge must use Mihari as its proxy.'
    # The page's bounded recent table can legitimately evict this request
    # during Edge startup. The earlier unique poll fixture proves DOM updates;
    # confirm this UI-clicked browser request in the canonical event stream.
    $browserRequestSeen = $false
    $deadline = [DateTime]::UtcNow.AddSeconds(15)
    do {
        foreach ($line in (Read-MihariTestCompleteLiveLines -Path ([string]$metadata.eventsPath))) {
            $event = ConvertFrom-Json -InputObject $line -ErrorAction Stop
            if ($event.stage -eq 'proxy.request' -and $event.data.path -eq $fixturePath) {
                $browserRequestSeen = $true
                break
            }
        }
        if ($browserRequestSeen) { break }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    Assert-MihariTest -Condition $browserRequestSeen -Message 'Mihari must record the UI-clicked browser request for the unique local fixture.'

    # A concrete upstream 407 must produce a finding in an already-open page.
    # The separate session keeps the first session's direct local fixtures and
    # its real browser action independent of this explicit-upstream fixture.
    $findingListener = New-MihariTestListener
    $findingProxyPort = ([System.Net.IPEndPoint]$findingListener.LocalEndpoint).Port
    $findingChild = Start-MihariTestProcess -Command start -OutputRoot (Join-Path $tempRoot 'finding-session') -Mode Tunnel -Port 0 -UpstreamProxy ('http://127.0.0.1:{0}' -f $findingProxyPort)
    $findingMetadata = Wait-MihariTestSession -Child $findingChild
    $findingManagementUrl = 'http://127.0.0.1:{0}/' -f [int]$findingMetadata.actualManagementPort
    $findingBrowser = Start-Issue3UiEdge -Uri $findingManagementUrl -ProfilePath (Join-Path $tempRoot 'finding-edge')
    $null = Wait-Issue3UiValue -Browser $findingBrowser -Expression 'document.getElementById("session-id")?.textContent || ""' -Predicate {
        param($value) [string]$value -eq [string]$findingMetadata.sessionId
    }
    $beforeFinding = Invoke-Issue3UiEvaluate -Browser $findingBrowser -Expression 'document.getElementById("finding-rows")?.textContent || ""'
    Assert-MihariTest -Condition ([string]$beforeFinding -notmatch 'upstream_proxy_auth_required') -Message 'The finding must be absent before the fixture emits its upstream 407.'
    [void](Invoke-MihariTestExplicitProxyStatus -ProxyListener $findingListener -MihariPort ([int]$findingMetadata.actualPort) -StatusCode 407)
    $null = Wait-Issue3UiValue -Browser $findingBrowser -Expression 'document.getElementById("finding-rows")?.textContent || ""' -Predicate {
        param($value) [string]$value -match 'upstream_proxy_auth_required'
    }
    Write-Host 'PASS issue3-ui-browser: Edge rendered live status, observations and a 407 finding; both mode clicks and UI-launched proxy traffic worked.'
}
finally {
    if ($null -ne $addOperator) { Stop-MihariTestRootConfirmation -Operator $addOperator }
    if ($null -ne $originClient) { $originClient.Close() }
    if ($null -ne $originListener) { $originListener.Stop() }
    if ($null -ne $browser) { $browser.Socket.Dispose() }
    if ($null -ne $findingBrowser) { $findingBrowser.Socket.Dispose() }
    foreach ($profile in @($diagnosticProfile, (Join-Path $tempRoot 'management-edge'), (Join-Path $tempRoot 'finding-edge'))) {
        try { Stop-Issue3UiEdgeProfile -ProfilePath $profile }
        catch { $cleanupFailure = $_; Write-Warning ('Edge profile cleanup failed: ' + $_.Exception.Message) }
    }
    if ($null -ne $findingChild -and $null -ne $findingMetadata -and -not $findingChild.Process.HasExited) {
        try { [void](Stop-MihariTestSession -Child $findingChild -Metadata $findingMetadata) }
        catch { $cleanupFailure = $_; Write-Warning ('Finding session cleanup failed: ' + $_.Exception.Message) }
    }
    if ($null -ne $findingChild) {
        if (-not $findingChild.Process.HasExited) { $findingChild.Process.Kill(); [void]$findingChild.Process.WaitForExit(5000) }
        $findingChild.Process.Dispose()
    }
    if ($null -ne $findingListener) { $findingListener.Stop() }
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
