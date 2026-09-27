param([switch] $LoadHelpersOnly)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'TestSupport.ps1')
if ($env:OS -ne 'Windows_NT') {
    Write-Warning 'Windows proxy integration tests require Windows; the parse and direct-contract suites remain available.'
    return
}

$repoRoot = Split-Path $PSScriptRoot -Parent
$sourceRoot = Join-Path $repoRoot 'src'
. (Join-Path $sourceRoot 'Certificate.ps1')
. (Join-Path $sourceRoot 'Compatibility.ps1')

function ConvertTo-MihariTestProcessArgument {
    param([Parameter(Mandatory = $true)][string] $Value)
    return '"' + $Value.Replace('"', '\"') + '"'
}

function Start-MihariTestProcess {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('start', 'stop', 'report')][string] $Command,
        [Parameter(Mandatory = $true)][string] $OutputRoot,
        [string] $Mode,
        [string] $UpstreamProxy,
        [int] $Port = 0
    )

    $executableName = 'powershell.exe'
    if ($PSVersionTable.PSEdition -eq 'Core') { $executableName = 'pwsh.exe' }
    $executablePath = Join-Path $PSHOME $executableName
    $arguments = @('-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File',
        (ConvertTo-MihariTestProcessArgument -Value (Join-Path $repoRoot 'mihari.ps1')),
        $Command)
    if ($Command -eq 'start') {
        $arguments += @('-Mode', $Mode, '-Port', [string]$Port)
        if (-not [string]::IsNullOrWhiteSpace($UpstreamProxy)) {
            $arguments += @('-UpstreamProxy', (ConvertTo-MihariTestProcessArgument -Value $UpstreamProxy))
        }
    }
    $arguments += @('-OutputRoot', (ConvertTo-MihariTestProcessArgument -Value $OutputRoot))

    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $executablePath
    $startInfo.Arguments = [string]::Join(' ', $arguments)
    $startInfo.WorkingDirectory = $repoRoot
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $startInfo
    if (-not $process.Start()) { throw ("Could not start Mihari child process: {0}" -f $executablePath) }
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    return [pscustomobject]@{ Process = $process; Stdout = $stdout; Stderr = $stderr; OutputRoot = $OutputRoot }
}

function Wait-MihariTestSession {
    param([Parameter(Mandatory = $true)]$Child, [int]$TimeoutSeconds = 30)
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $activePath = Join-Path $Child.OutputRoot 'active-session.json'
    while ([DateTime]::UtcNow -lt $deadline) {
        if ($Child.Process.HasExited) {
            $Child.Process.WaitForExit()
            throw ("Mihari exited during startup ({0}). stdout={1} stderr={2}" -f $Child.Process.ExitCode, $Child.Stdout.Result, $Child.Stderr.Result)
        }
        if ([IO.File]::Exists($activePath)) {
            $active = ConvertFrom-Json -InputObject (Read-MihariTestLiveText -Path $activePath) -ErrorAction Stop
            $sessionPath = Join-Path ([string]$active.outputDirectory) 'session.json'
            if ([IO.File]::Exists($sessionPath)) {
                $metadata = ConvertFrom-Json -InputObject (Read-MihariTestLiveText -Path $sessionPath) -ErrorAction Stop
                if ($metadata.actualPort -and $metadata.status -eq 'running') { return $metadata }
            }
        }
        Start-Sleep -Milliseconds 50
    }
    throw ("Mihari did not publish running session metadata within {0}s under {1}." -f $TimeoutSeconds, $Child.OutputRoot)
}

function Stop-MihariTestSession {
    param([Parameter(Mandatory = $true)]$Child, [Parameter(Mandatory = $true)]$Metadata)
    $Child | Add-Member -MemberType NoteProperty -Name StopAttempted -Value $true -Force
    $removeOperator = $null
    if ($Metadata.caThumbprint -and
        -not (Test-MihariTestThumbprintAbsent -Thumbprint ([string]$Metadata.caThumbprint))) {
        $removeOperator = Start-MihariTestRootConfirmation -Operation Remove -TargetProcessId $Child.Process.Id
    }
    $stopCli = $null
    try {
        $stopCli = Start-MihariTestProcess -Command stop -OutputRoot $Child.OutputRoot
        if (-not $stopCli.Process.WaitForExit(10000)) {
            throw 'The Mihari stop command did not exit promptly.'
        }
        $stopCli.Process.WaitForExit()
        if ($stopCli.Process.ExitCode -ne 0) {
            throw ("Mihari stop command failed ({0}). stdout={1} stderr={2}" -f $stopCli.Process.ExitCode, $stopCli.Stdout.Result, $stopCli.Stderr.Result)
        }
        if ($null -ne $removeOperator) {
            Complete-MihariTestRootConfirmation -Operator $removeOperator
        }
        if (-not $Child.Process.WaitForExit(15000)) {
            throw 'The foreground Mihari process did not stop after the stop signal.'
        }
        $Child.Process.WaitForExit()
        if ($Child.Process.ExitCode -ne 0) {
            throw ("Mihari exited with {0}. stdout={1} stderr={2}" -f $Child.Process.ExitCode, $Child.Stdout.Result, $Child.Stderr.Result)
        }
        $sessionPath = Join-Path ([string]$Metadata.outputDirectory) 'session.json'
        $final = ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($sessionPath)) -ErrorAction Stop
        Assert-MihariTest -Condition ($final.status -eq 'stopped') -Message 'Normal stop must persist a clean stopped state.'
        Assert-MihariTest -Condition ([IO.File]::Exists([string]$final.eventsPath)) -Message 'Session stop must retain its JSONL events.'
        Assert-MihariTest -Condition ([IO.File]::Exists([string]$final.reportJsonPath) -and [IO.File]::Exists([string]$final.reportTextPath)) -Message 'Session stop must generate JSON and text reports.'
        if ($final.caThumbprint) {
            Assert-MihariTest -Condition (Test-MihariTestThumbprintAbsent -Thumbprint ([string]$final.caThumbprint)) -Message 'Normal stop must remove the session CA from certificate stores.'
        }
        if ($final.caSubject) {
            Assert-MihariTest -Condition (Test-MihariTestNoLeavesForIssuer -IssuerSubject ([string]$final.caSubject)) -Message 'Normal stop must leave no issued leaf certificate in any certificate store.'
        }
        return $final
    }
    finally {
        Stop-MihariTestRootConfirmation -Operator $removeOperator
        if ($null -ne $stopCli) {
            if (-not $stopCli.Process.HasExited) {
                try { $stopCli.Process.Kill(); $stopCli.Process.WaitForExit(5000) }
                catch { Write-Warning ("Mihari stop child cleanup failed: {0}" -f $_.Exception.Message) }
            }
            $stopCli.Process.Dispose()
        }
    }
}

function Invoke-MihariTestReportCommand {
    param([Parameter(Mandatory = $true)][string]$OutputRoot)
    $reportChild = Start-MihariTestProcess -Command report -OutputRoot $OutputRoot
    try {
        if (-not $reportChild.Process.WaitForExit(15000)) {
            throw 'The Mihari report command did not exit promptly.'
        }
        $reportChild.Process.WaitForExit()
        if ($reportChild.Process.ExitCode -ne 0) {
            throw ("Mihari report command failed ({0}). stdout={1} stderr={2}" -f $reportChild.Process.ExitCode, $reportChild.Stdout.Result, $reportChild.Stderr.Result)
        }
    }
    finally {
        if (-not $reportChild.Process.HasExited) {
            try { $reportChild.Process.Kill(); $reportChild.Process.WaitForExit(5000) }
            catch { Write-Warning ("Mihari report child cleanup failed: {0}" -f $_.Exception.Message) }
        }
        if ($reportChild.Process.HasExited) { $reportChild.Process.Dispose() }
    }
}

function New-MihariTestListener {
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $listener.Start()
    return $listener
}

function Read-MihariTestHeaderText {
    param([Parameter(Mandatory = $true)][System.IO.Stream] $Stream, [int]$MaximumBytes = 65536)
    $deadline = [DateTime]::UtcNow.AddSeconds(15)
    $text = New-Object System.Text.StringBuilder
    while ($text.Length -lt $MaximumBytes) {
        $remainingMs = [int][Math]::Max(1, ($deadline - [DateTime]::UtcNow).TotalMilliseconds)
        if ([DateTime]::UtcNow -ge $deadline) { throw 'The fixture HTTP header read exceeded its 15 second deadline.' }
        if ($Stream.CanTimeout) { $Stream.ReadTimeout = $remainingMs }
        $value = $Stream.ReadByte()
        if ($value -lt 0) { throw 'The fixture peer closed before completing an HTTP header.' }
        $character = [char]$value
        [void]$text.Append($character)
        if ($text.Length -ge 4 -and
            $text[$text.Length - 4] -eq [char]13 -and $text[$text.Length - 3] -eq [char]10 -and
            $text[$text.Length - 2] -eq [char]13 -and $text[$text.Length - 1] -eq [char]10) {
            return $text.ToString()
        }
    }
    throw 'The fixture HTTP header exceeded its byte limit.'
}

function Read-MihariTestExactBytes {
    param([Parameter(Mandatory = $true)][System.IO.Stream] $Stream, [Parameter(Mandatory = $true)][int]$Count)
    $deadline = [DateTime]::UtcNow.AddSeconds(15)
    $buffer = New-Object 'byte[]' $Count
    $offset = 0
    while ($offset -lt $Count) {
        $remainingMs = [int][Math]::Max(1, ($deadline - [DateTime]::UtcNow).TotalMilliseconds)
        if ([DateTime]::UtcNow -ge $deadline) { throw 'The fixture HTTP body read exceeded its 15 second deadline.' }
        if ($Stream.CanTimeout) { $Stream.ReadTimeout = $remainingMs }
        $read = $Stream.Read($buffer, $offset, $Count - $offset)
        if ($read -le 0) { throw 'The fixture peer closed before completing an HTTP body.' }
        $offset += $read
    }
    return ,$buffer
}

function Begin-MihariTestTlsServerAuthentication {
    param(
        [Parameter(Mandatory = $true)][System.Net.Security.SslStream]$Stream,
        [Parameter(Mandatory = $true)][System.Security.Cryptography.X509Certificates.X509Certificate]$Certificate
    )
    $Stream.ReadTimeout = 10000
    $Stream.WriteTimeout = 10000
    return $Stream.BeginAuthenticateAsServer(
        $Certificate, $false, [System.Security.Authentication.SslProtocols]::Tls12, $false, $null, $null
    )
}

function Begin-MihariTestTlsClientAuthentication {
    param(
        [Parameter(Mandatory = $true)][System.Net.Security.SslStream]$Stream,
        [Parameter(Mandatory = $true)][string]$TargetHost
    )
    $Stream.ReadTimeout = 10000
    $Stream.WriteTimeout = 10000
    return $Stream.BeginAuthenticateAsClient(
        $TargetHost, $null, [System.Security.Authentication.SslProtocols]::Tls12, $false, $null, $null
    )
}

function Complete-MihariTestTlsAuthentication {
    param(
        [System.Net.Security.SslStream]$ServerStream,
        $ServerResult,
        [System.Net.Security.SslStream]$ClientStream,
        $ClientResult
    )
    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    if ($null -ne $ServerResult -and -not $ServerResult.AsyncWaitHandle.WaitOne(10000)) {
        throw 'The local TLS fixture server handshake timed out.'
    }
    if ($null -ne $ClientResult) {
        $remainingMs = [int][Math]::Max(0, ($deadline - [DateTime]::UtcNow).TotalMilliseconds)
        if (-not $ClientResult.AsyncWaitHandle.WaitOne($remainingMs)) {
            throw 'The TLS client handshake timed out.'
        }
    }
    $handshakeError = $null
    if ($null -ne $ServerResult) {
        try { $ServerStream.EndAuthenticateAsServer($ServerResult) }
        catch { $handshakeError = $_.Exception }
    }
    if ($null -ne $ClientResult) {
        try { $ClientStream.EndAuthenticateAsClient($ClientResult) }
        catch { if ($null -eq $handshakeError) { $handshakeError = $_.Exception } }
    }
    if ($null -ne $handshakeError) { throw $handshakeError }
}

function Write-MihariTestHttpResponse {
    param([Parameter(Mandatory = $true)][System.IO.Stream] $Stream, [string]$Body = 'ok')
    if ($Stream.CanTimeout) { $Stream.WriteTimeout = 10000 }
    $bodyBytes = [System.Text.Encoding]::ASCII.GetBytes($Body)
    $headerBytes = [System.Text.Encoding]::ASCII.GetBytes("HTTP/1.1 200 OK`r`nContent-Length: $($bodyBytes.Length)`r`nConnection: close`r`n`r`n")
    $Stream.Write($headerBytes, 0, $headerBytes.Length)
    $Stream.Write($bodyBytes, 0, $bodyBytes.Length)
    $Stream.Flush()
}

function Invoke-MihariTestExplicitProxyStatus {
    param(
        [Parameter(Mandatory = $true)][System.Net.Sockets.TcpListener]$ProxyListener,
        [Parameter(Mandatory = $true)][int]$MihariPort,
        [Parameter(Mandatory = $true)][int]$StatusCode,
        [string]$ProxyAuthorization
    )
    $proxyAccept = $ProxyListener.AcceptTcpClientAsync()
    $client = [System.Net.Sockets.TcpClient]::new()
    $proxyServer = $null
    try {
        $client.Connect('127.0.0.1', $MihariPort)
        $clientStream = $client.GetStream()
        $requestText = "CONNECT 192.0.2.19:443 HTTP/1.1`r`nHost: 192.0.2.19:443`r`n"
        if (-not [string]::IsNullOrEmpty($ProxyAuthorization)) { $requestText += "Proxy-Authorization: $ProxyAuthorization`r`n" }
        $wire = [System.Text.Encoding]::ASCII.GetBytes($requestText + "`r`n")
        $clientStream.Write($wire, 0, $wire.Length)
        $clientStream.Flush()
        Assert-MihariTest -Condition ($proxyAccept.Wait(15000)) -Message 'Mihari did not connect to the explicit proxy fixture.'
        $proxyServer = $proxyAccept.Result
        $proxyStream = $proxyServer.GetStream()
        $proxyRequest = Read-MihariTestHeaderText -Stream $proxyStream
        Assert-MihariTest -Condition ($proxyRequest.StartsWith('CONNECT 192.0.2.19:443 HTTP/1.1')) -Message 'Explicit proxy CONNECT target must match the requested authority.'
        if (-not [string]::IsNullOrEmpty($ProxyAuthorization)) {
            Assert-MihariTest -Condition ($proxyRequest -match '(?im)^Proxy-Authorization: Basic proxy-secret\r?$') -Message 'Explicit proxy CONNECT must receive the client proxy credential.'
        }
        $reason = 'Proxy Rejected'
        if ($StatusCode -eq 407) { $reason = 'Proxy Authentication Required' }
        $responseText = "HTTP/1.1 $StatusCode $reason`r`nContent-Length: 0`r`nConnection: close`r`n"
        if ($StatusCode -eq 407) { $responseText += "Proxy-Authenticate: Basic realm=`"mihari-test`"`r`n" }
        $responseText += "`r`n"
        $response = [System.Text.Encoding]::ASCII.GetBytes($responseText)
        $proxyStream.Write($response, 0, $response.Length)
        $proxyStream.Flush()
        $clientResponse = Read-MihariTestHeaderText -Stream $clientStream
        Assert-MihariTest -Condition ($clientResponse.StartsWith("HTTP/1.1 $StatusCode")) -Message ("Mihari must preserve the concrete upstream proxy status {0}." -f $StatusCode)
        if ($StatusCode -eq 407) {
            Assert-MihariTest -Condition ($clientResponse -match '(?im)^Proxy-Authenticate: Basic realm="mihari-test"\r?$') -Message 'Mihari must preserve the explicit proxy authentication challenge.'
        }
        return $clientResponse
    }
    finally {
        if ($null -ne $proxyServer) { $proxyServer.Close() }
        $client.Close()
    }
}

function Read-MihariTestHttpResponse {
    param([Parameter(Mandatory = $true)][System.IO.Stream] $Stream)
    $headers = Read-MihariTestHeaderText -Stream $Stream
    $lengthMatch = [regex]::Match($headers, '(?im)^Content-Length:\s*(\d+)\s*$')
    if (-not $lengthMatch.Success) { throw 'Fixture client response has no Content-Length.' }
    $body = Read-MihariTestExactBytes -Stream $Stream -Count ([int]$lengthMatch.Groups[1].Value)
    return [pscustomobject]@{ Headers = $headers; Body = [System.Text.Encoding]::ASCII.GetString($body) }
}

function Wait-MihariTestEvent {
    param([Parameter(Mandatory = $true)][string]$EventsPath, [Parameter(Mandatory = $true)][string]$Stage, [int]$TimeoutSeconds = 10)
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        if ([IO.File]::Exists($EventsPath)) {
            $lines = Read-MihariTestCompleteLiveLines -Path $EventsPath
            foreach ($line in $lines) {
                if ([string]::IsNullOrWhiteSpace($line)) { continue }
                try {
                    $event = ConvertFrom-Json -InputObject $line -ErrorAction Stop
                    if ($event.stage -eq $Stage) { return $event }
                }
                catch { throw ("Invalid or partial JSONL event encountered while waiting: {0}" -f $_.Exception.Message) }
            }
        }
        Start-Sleep -Milliseconds 50
    }
    throw ("No {0} event appeared within {1}s." -f $Stage, $TimeoutSeconds)
}

function New-MihariTestFixtureTlsIdentity {
    $sessionId = [guid]::NewGuid().ToString('N')
    $ca = New-MihariCA -SessionId $sessionId
    $publicRoot = $null
    $leaf = $null
    $session = $null
    $cache = [hashtable]::Synchronized(@{})
    try {
        $publicRoot = Invoke-MihariTestRootConfirmation -Operation Add -Action {
            Install-MihariCARoot -CA $ca
        }
        $session = [pscustomobject]@{ CA = $ca; LeafCache = $cache }
        $leaf = Get-MihariLeaf -Session $session -DestinationHost '127.0.0.1'
        return [pscustomobject]@{ CA = $ca; PublicRoot = $publicRoot; Leaf = $leaf; LeafThumbprint = $leaf.Thumbprint; Session = $session; Thumbprint = $ca.Thumbprint; Subject = $ca.Subject }
    }
    catch {
        $creationError = $_
        $cleanupErrors = New-Object 'System.Collections.Generic.List[string]'
        if ($null -ne $ca) {
            try {
                if (-not (Test-MihariTestThumbprintAbsent -Thumbprint $ca.Thumbprint)) {
                    [void](Invoke-MihariTestRootConfirmation -Operation Remove -Action {
                        Remove-MihariCARoot -Thumbprint $ca.Thumbprint -Subject $ca.Subject
                    })
                }
            }
            catch { $cleanupErrors.Add("fixture root removal: $($_.Exception.Message)") }
        }
        if ($null -ne $leaf -and $null -ne $session) {
            try { Release-MihariLeaf -Session $session -Certificate $leaf }
            catch { $cleanupErrors.Add("fixture leaf release: $($_.Exception.Message)") }
            try { Clear-MihariLeafCache -Session $session }
            catch { $cleanupErrors.Add("fixture leaf disposal: $($_.Exception.Message)") }
        }
        if ($null -ne $publicRoot) {
            try { $publicRoot.Dispose() }
            catch { $cleanupErrors.Add("fixture public root disposal: $($_.Exception.Message)") }
        }
        if ($null -ne $ca) {
            try { $ca.Certificate.Dispose(); $ca.PrivateKey.Dispose() }
            catch { $cleanupErrors.Add("fixture CA key disposal: $($_.Exception.Message)") }
        }
        if ($cleanupErrors.Count -gt 0) {
            throw ("Could not create local TLS fixture ({0}); cleanup errors: {1}" -f $creationError.Exception.Message, ($cleanupErrors -join '; '))
        }
        throw $creationError
    }
}

function Remove-MihariTestFixtureTlsIdentity {
    param([Parameter(Mandatory = $true)]$Identity)
    $failures = New-Object 'System.Collections.Generic.List[string]'
    try { Release-MihariLeaf -Session $Identity.Session -Certificate $Identity.Leaf }
    catch { $failures.Add("fixture leaf release: $($_.Exception.Message)") }
    try { Clear-MihariLeafCache -Session $Identity.Session }
    catch { $failures.Add("fixture leaf disposal: $($_.Exception.Message)") }
    try {
        $removed = Invoke-MihariTestRootConfirmation -Operation Remove -Action {
            Remove-MihariCARoot -Thumbprint $Identity.Thumbprint -Subject $Identity.Subject
        }
        if ($removed -ne 1) { $failures.Add('fixture CA root cleanup did not remove one certificate') }
    }
    catch { $failures.Add("fixture CA root removal: $($_.Exception.Message)") }
    try { $Identity.PublicRoot.Dispose() }
    catch { $failures.Add("fixture public root disposal: $($_.Exception.Message)") }
    try { $Identity.CA.Certificate.Dispose(); $Identity.CA.PrivateKey.Dispose() }
    catch { $failures.Add("fixture CA key disposal: $($_.Exception.Message)") }
    if (-not (Test-MihariTestThumbprintAbsent -Thumbprint $Identity.LeafThumbprint)) {
        $failures.Add('fixture leaf certificate remained in a certificate store')
    }
    if (-not (Test-MihariTestThumbprintAbsent -Thumbprint $Identity.Thumbprint)) {
        $failures.Add('fixture root certificate remained in a certificate store')
    }
    if ($failures.Count -gt 0) { throw ('Fixture certificate cleanup failed: ' + ($failures -join '; ')) }
}

if ($LoadHelpersOnly) { return }

$tempRoot = Join-Path ([IO.Path]::GetTempPath()) ('mihari-integration-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($tempRoot)
$fixtureIdentity = $null
$originListener = $null
$originClient = $null
$originTls = $null
$proxyClient = $null
$proxyTls = $null
$tunnelChild = $null
$inspectChild = $null
$inspectAddOperator = $null
$tunnelMetadata = $null
$inspectMetadata = $null
$proxyStatusChild = $null
$proxyStatusMetadata = $null
$proxyStatusListener = $null
$finalCleanupFailures = New-Object 'System.Collections.Generic.List[string]'
try {
    $fixtureIdentity = New-MihariTestFixtureTlsIdentity

    $tunnelRoot = Join-Path $tempRoot 'tunnel'
    $tunnelChild = Start-MihariTestProcess -Command start -OutputRoot $tunnelRoot -Mode Tunnel -Port 0
    $tunnelMetadata = Wait-MihariTestSession -Child $tunnelChild
    $proxyPort = [int]$tunnelMetadata.actualPort

    # Plain HTTP proxy forwarding against a local raw TCP fixture.
    $originListener = New-MihariTestListener
    $originPort = ([System.Net.IPEndPoint]$originListener.LocalEndpoint).Port
    $acceptTask = $originListener.AcceptTcpClientAsync()
    $proxyClient = [System.Net.Sockets.TcpClient]::new()
    $proxyClient.Connect('127.0.0.1', $proxyPort)
    $proxyStream = $proxyClient.GetStream()
    $requestText = "GET http://127.0.0.1:$originPort/http-proxy/path?token=http-secret HTTP/1.1`r`nHost: 127.0.0.1:$originPort`r`nAuthorization: Bearer auth-secret`r`nCookie: session=cookie-secret`r`nConnection: close`r`n`r`n"
    $requestBytes = [System.Text.Encoding]::ASCII.GetBytes($requestText)
    $proxyStream.Write($requestBytes, 0, $requestBytes.Length)
    $proxyStream.Flush()
    Assert-MihariTest -Condition ($acceptTask.Wait(15000)) -Message 'HTTP proxy did not connect to the local origin fixture.'
    $originClient = $acceptTask.Result
    $originStream = $originClient.GetStream()
    $originRequest = Read-MihariTestHeaderText -Stream $originStream
    Assert-MihariTest -Condition ($originRequest.StartsWith("GET /http-proxy/path?token=http-secret HTTP/1.1")) -Message 'HTTP proxy must forward an origin-form request target and query.'
    Assert-MihariTest -Condition ($originRequest -match '(?im)^Authorization: Bearer auth-secret\r?$' -and $originRequest -match '(?im)^Cookie: session=cookie-secret\r?$') -Message 'HTTP proxy must preserve end-to-end request headers to the local origin.'
    Write-MihariTestHttpResponse -Stream $originStream
    $plainResponse = Read-MihariTestHttpResponse -Stream $proxyStream
    Assert-MihariTest -Condition ($plainResponse.Headers.StartsWith('HTTP/1.1 200') -and $plainResponse.Body -eq 'ok') -Message 'HTTP proxy must relay the local origin response.'
    $proxyClient.Close(); $proxyClient = $null
    $originClient.Close(); $originClient = $null
    $originListener.Stop(); $originListener = $null
    [void](Wait-MihariTestEvent -EventsPath ([string]$tunnelMetadata.eventsPath) -Stage 'upstream.http')

    # CONNECT tunnel preserves and relays an actual TLS 1.2 exchange.
    $originListener = New-MihariTestListener
    $originPort = ([System.Net.IPEndPoint]$originListener.LocalEndpoint).Port
    $acceptTask = $originListener.AcceptTcpClientAsync()
    $proxyClient = [System.Net.Sockets.TcpClient]::new()
    $proxyClient.Connect('127.0.0.1', $proxyPort)
    $proxyStream = $proxyClient.GetStream()
    $connectRequest = [System.Text.Encoding]::ASCII.GetBytes("CONNECT 127.0.0.1:$originPort HTTP/1.1`r`nHost: 127.0.0.1:$originPort`r`n`r`n")
    $proxyStream.Write($connectRequest, 0, $connectRequest.Length)
    $proxyStream.Flush()
    $connectReply = Read-MihariTestHeaderText -Stream $proxyStream
    Assert-MihariTest -Condition ($connectReply.StartsWith('HTTP/1.1 200')) -Message 'Tunnel CONNECT must be acknowledged after the local upstream connects.'
    Assert-MihariTest -Condition ($acceptTask.Wait(15000)) -Message 'Tunnel mode did not connect to the local TLS origin.'
    $originClient = $acceptTask.Result
    $originTls = [System.Net.Security.SslStream]::new($originClient.GetStream(), $true)
    $proxyTls = [System.Net.Security.SslStream]::new($proxyStream, $true)
    $serverAuth = Begin-MihariTestTlsServerAuthentication -Stream $originTls -Certificate $fixtureIdentity.Leaf
    $clientAuth = Begin-MihariTestTlsClientAuthentication -Stream $proxyTls -TargetHost '127.0.0.1'
    Complete-MihariTestTlsAuthentication -ServerStream $originTls -ServerResult $serverAuth -ClientStream $proxyTls -ClientResult $clientAuth
    Assert-MihariTest -Condition ($proxyTls.SslProtocol -eq [System.Security.Authentication.SslProtocols]::Tls12) -Message 'Tunnel must pass a TLS 1.2 client/origin handshake.'
    $tunnelRequest = [System.Text.Encoding]::ASCII.GetBytes("GET /tunnel/probe HTTP/1.1`r`nHost: 127.0.0.1:$originPort`r`nConnection: close`r`n`r`n")
    $proxyTls.Write($tunnelRequest, 0, $tunnelRequest.Length)
    $proxyTls.Flush()
    $originTunnelRequest = Read-MihariTestHeaderText -Stream $originTls
    Assert-MihariTest -Condition ($originTunnelRequest.StartsWith('GET /tunnel/probe HTTP/1.1')) -Message 'Tunnel must relay client TLS application bytes to the origin.'
    Write-MihariTestHttpResponse -Stream $originTls
    $tunnelResponse = Read-MihariTestHttpResponse -Stream $proxyTls
    Assert-MihariTest -Condition ($tunnelResponse.Headers.StartsWith('HTTP/1.1 200') -and $tunnelResponse.Body -eq 'ok') -Message 'Tunnel must relay origin TLS application bytes to the client.'
    $proxyTls.Dispose(); $proxyTls = $null
    $originTls.Dispose(); $originTls = $null
    $proxyClient.Close(); $proxyClient = $null
    $originClient.Close(); $originClient = $null
    $originListener.Stop(); $originListener = $null
    [void](Wait-MihariTestEvent -EventsPath ([string]$tunnelMetadata.eventsPath) -Stage 'tunnel.relay')

    $tunnelFinal = Stop-MihariTestSession -Child $tunnelChild -Metadata $tunnelMetadata
    $tunnelChild.Process.Dispose()
    $tunnelChild = $null
    Invoke-MihariTestReportCommand -OutputRoot $tunnelRoot
    $tunnelLines = [IO.File]::ReadAllLines([string]$tunnelFinal.eventsPath)
    Assert-MihariTest -Condition ($tunnelLines.Length -ge 8) -Message 'HTTP and CONNECT traffic must emit structured observations.'
    foreach ($line in $tunnelLines) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $event = ConvertFrom-Json -InputObject $line -ErrorAction Stop
        Assert-MihariTest -Condition ($event.schemaVersion -eq 1 -and $event.timestamp -and $event.sessionId -and $event.connectionId -and $event.mode -and $event.stage -and $event.outcome -and $null -ne $event.elapsedMs) -Message 'Every JSONL event must have the required schema envelope.'
    }
    $tunnelEventText = [string]::Join("`n", $tunnelLines)
    foreach ($secret in @('http-secret', 'auth-secret', 'cookie-secret')) {
        Assert-MihariTest -Condition (-not $tunnelEventText.Contains($secret)) -Message 'JSONL must not retain HTTP query or credential header values.'
    }

    # Concrete explicit-proxy statuses remain facts and support only their
    # corresponding conservative diagnoses.
    $proxyStatusListener = New-MihariTestListener
    $proxyStatusPort = ([System.Net.IPEndPoint]$proxyStatusListener.LocalEndpoint).Port
    $proxyStatusRoot = Join-Path $tempRoot 'explicit-proxy'
    $proxyStatusChild = Start-MihariTestProcess -Command start -OutputRoot $proxyStatusRoot -Mode Tunnel -Port 0 -UpstreamProxy ("http://127.0.0.1:{0}" -f $proxyStatusPort)
    $proxyStatusMetadata = Wait-MihariTestSession -Child $proxyStatusChild
    [void](Invoke-MihariTestExplicitProxyStatus -ProxyListener $proxyStatusListener -MihariPort ([int]$proxyStatusMetadata.actualPort) -StatusCode 407)
    [void](Wait-MihariTestEvent -EventsPath ([string]$proxyStatusMetadata.eventsPath) -Stage 'upstream.proxy.connect')
    [void](Invoke-MihariTestExplicitProxyStatus -ProxyListener $proxyStatusListener -MihariPort ([int]$proxyStatusMetadata.actualPort) -StatusCode 403 -ProxyAuthorization 'Basic proxy-secret')
    [void](Wait-MihariTestEvent -EventsPath ([string]$proxyStatusMetadata.eventsPath) -Stage 'upstream.proxy.connect')
    $proxyStatusFinal = Stop-MihariTestSession -Child $proxyStatusChild -Metadata $proxyStatusMetadata
    $proxyStatusChild.Process.Dispose()
    $proxyStatusChild = $null
    $proxyEventIds = @{}
    $observedProxyStatuses = New-Object 'System.Collections.Generic.List[int]'
    foreach ($line in [IO.File]::ReadAllLines([string]$proxyStatusFinal.eventsPath)) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        Assert-MihariTest -Condition (-not $line.Contains('proxy-secret')) -Message 'JSONL must not retain an explicit proxy credential.'
        $event = ConvertFrom-Json -InputObject $line -ErrorAction Stop
        if ($event.stage -eq 'upstream.proxy.connect') {
            $observedProxyStatuses.Add([int]$event.data.proxyStatus)
            $proxyEventIds[[string]$event.data.proxyStatus] = [string]$event.eventId
        }
    }
    Assert-MihariTest -Condition ($observedProxyStatuses -contains 407 -and $observedProxyStatuses -contains 403) -Message 'JSONL must preserve the concrete upstream proxy 407 and 403 facts.'
    $proxyReport = ConvertFrom-Json -InputObject ([IO.File]::ReadAllText([string]$proxyStatusFinal.reportJsonPath)) -ErrorAction Stop
    $proxyFindingCodes = @($proxyReport.findings | ForEach-Object { $_.code })
    Assert-MihariTest -Condition ($proxyFindingCodes -contains 'upstream_proxy_auth_required') -Message 'A concrete explicit proxy 407 must appear in the generated diagnosis report.'
    Assert-MihariTest -Condition ($proxyFindingCodes -contains 'upstream_proxy_rejected') -Message 'A concrete explicit proxy 403 must appear in the generated diagnosis report.'
    Assert-MihariTest -Condition (@($proxyReport.findings | Where-Object { $_.code -eq 'upstream_proxy_auth_required' -and $_.evidenceIds -contains $proxyEventIds['407'] }).Count -eq 1) -Message 'The 407 diagnosis must point to its concrete event evidence.'
    Assert-MihariTest -Condition (@($proxyReport.findings | Where-Object { $_.code -eq 'upstream_proxy_rejected' -and $_.evidenceIds -contains $proxyEventIds['403'] }).Count -eq 1) -Message 'The 403 diagnosis must point to its concrete event evidence.'

    # Inspect TLS 1.2 client handshake, upstream validation, and URL-path capture.
    $inspectRoot = Join-Path $tempRoot 'inspect'
    $inspectChild = Start-MihariTestProcess -Command start -OutputRoot $inspectRoot -Mode Inspect -Port 0
    $inspectAddOperator = Start-MihariTestRootConfirmation -Operation Add -TargetProcessId $inspectChild.Process.Id
    $inspectMetadata = Wait-MihariTestSession -Child $inspectChild
    Complete-MihariTestRootConfirmation -Operator $inspectAddOperator
    Stop-MihariTestRootConfirmation -Operator $inspectAddOperator
    $inspectAddOperator = $null
    $proxyPort = [int]$inspectMetadata.actualPort
    $originListener = New-MihariTestListener
    $originPort = ([System.Net.IPEndPoint]$originListener.LocalEndpoint).Port
    $acceptTask = $originListener.AcceptTcpClientAsync()
    $proxyClient = [System.Net.Sockets.TcpClient]::new()
    $proxyClient.Connect('127.0.0.1', $proxyPort)
    $proxyStream = $proxyClient.GetStream()
    $connectRequest = [System.Text.Encoding]::ASCII.GetBytes("CONNECT 127.0.0.1:$originPort HTTP/1.1`r`nHost: 127.0.0.1:$originPort`r`n`r`n")
    $proxyStream.Write($connectRequest, 0, $connectRequest.Length)
    $proxyStream.Flush()
    $connectReply = Read-MihariTestHeaderText -Stream $proxyStream
    Assert-MihariTest -Condition ($connectReply.StartsWith('HTTP/1.1 200')) -Message 'Inspect CONNECT must acknowledge the client TLS endpoint.'
    $proxyTls = [System.Net.Security.SslStream]::new($proxyStream, $true)
    $clientAuth = Begin-MihariTestTlsClientAuthentication -Stream $proxyTls -TargetHost '127.0.0.1'
    Complete-MihariTestTlsAuthentication -ClientStream $proxyTls -ClientResult $clientAuth
    Assert-MihariTest -Condition ($proxyTls.SslProtocol -eq [System.Security.Authentication.SslProtocols]::Tls12) -Message 'Inspect must terminate a TLS 1.2 client connection.'
    $inspectRequest = [System.Text.Encoding]::ASCII.GetBytes("GET /inspect/deep/path?token=inspect-secret HTTP/1.1`r`nHost: 127.0.0.1:$originPort`r`nConnection: close`r`n`r`n")
    $proxyTls.Write($inspectRequest, 0, $inspectRequest.Length)
    $proxyTls.Flush()
    Assert-MihariTest -Condition ($acceptTask.Wait(15000)) -Message 'Inspect mode did not connect to the local TLS origin.'
    $originClient = $acceptTask.Result
    $originTls = [System.Net.Security.SslStream]::new($originClient.GetStream(), $true)
    $serverAuth = Begin-MihariTestTlsServerAuthentication -Stream $originTls -Certificate $fixtureIdentity.Leaf
    Complete-MihariTestTlsAuthentication -ServerStream $originTls -ServerResult $serverAuth
    $originInspectRequest = Read-MihariTestHeaderText -Stream $originTls
    Assert-MihariTest -Condition ($originInspectRequest.StartsWith('GET /inspect/deep/path?token=inspect-secret HTTP/1.1')) -Message 'Inspect must forward the observed URL path to the local origin.'
    Write-MihariTestHttpResponse -Stream $originTls
    $inspectResponse = Read-MihariTestHttpResponse -Stream $proxyTls
    Assert-MihariTest -Condition ($inspectResponse.Headers.StartsWith('HTTP/1.1 200') -and $inspectResponse.Body -eq 'ok') -Message 'Inspect must relay the local upstream HTTPS response.'
    $proxyTls.Dispose(); $proxyTls = $null
    $originTls.Dispose(); $originTls = $null
    $proxyClient.Close(); $proxyClient = $null
    $originClient.Close(); $originClient = $null
    $originListener.Stop(); $originListener = $null
    [void](Wait-MihariTestEvent -EventsPath ([string]$inspectMetadata.eventsPath) -Stage 'upstream.http')

    $inspectEvents = Read-MihariTestCompleteLiveLines -Path ([string]$inspectMetadata.eventsPath)
    $inspectText = [string]::Join("`n", $inspectEvents)
    Assert-MihariTest -Condition ($inspectText.Contains('/inspect/deep/path?token=[REDACTED]')) -Message 'Inspect JSONL must record URL path with the query value redacted.'
    Assert-MihariTest -Condition (-not $inspectText.Contains('inspect-secret')) -Message 'Inspect JSONL must not retain the query value.'
    $pathEvent = $null
    foreach ($line in $inspectEvents) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $event = ConvertFrom-Json -InputObject $line -ErrorAction Stop
        if ($event.stage -eq 'http.request') { $pathEvent = $event; break }
    }
    Assert-MihariTest -Condition ($null -ne $pathEvent -and $pathEvent.data.path -eq '/inspect/deep/path?token=[REDACTED]') -Message 'Inspect must emit a correlated HTTP path observation.'
    $inspectFinal = Stop-MihariTestSession -Child $inspectChild -Metadata $inspectMetadata
    $inspectChild.Process.Dispose()
    $inspectChild = $null
    Invoke-MihariTestReportCommand -OutputRoot $inspectRoot
    Assert-MihariTest -Condition ($inspectFinal.caThumbprint) -Message 'Inspect session must own a session-specific CA.'
    $privateArtifacts = @(Get-ChildItem -LiteralPath $inspectFinal.outputDirectory -File -Recurse | Where-Object { $_.Extension -match '^\.(pfx|p12|key|pem)$' })
    Assert-MihariTest -Condition ($privateArtifacts.Count -eq 0) -Message 'The session output must not persist a CA private key or leaf certificate.'
    Write-Host 'PASS integration: child-process start/stop, local HTTP forwarding, TLS 1.2 CONNECT tunnel, TLS 1.2 Inspect/path redaction, JSONL, reports, CA cleanup'
}
finally {
    Stop-MihariTestRootConfirmation -Operator $inspectAddOperator
    foreach ($item in @(@{ Tls = $originTls }, @{ Tls = $proxyTls })) {
        if ($null -ne $item.Tls) { try { $item.Tls.Dispose() } catch { $finalCleanupFailures.Add("Fixture TLS stream cleanup failed: $($_.Exception.Message)") } }
    }
    if ($null -ne $proxyClient) { try { $proxyClient.Close() } catch { $finalCleanupFailures.Add("Fixture proxy socket cleanup failed: $($_.Exception.Message)") } }
    if ($null -ne $originClient) { try { $originClient.Close() } catch { $finalCleanupFailures.Add("Fixture origin socket cleanup failed: $($_.Exception.Message)") } }
    if ($null -ne $originListener) { try { $originListener.Stop() } catch { $finalCleanupFailures.Add("Fixture listener cleanup failed: $($_.Exception.Message)") } }
    if ($null -ne $proxyStatusListener) { try { $proxyStatusListener.Stop() } catch { $finalCleanupFailures.Add("Explicit proxy fixture cleanup failed: $($_.Exception.Message)") } }
    foreach ($child in @($tunnelChild, $proxyStatusChild, $inspectChild)) {
        if ($null -eq $child) { continue }
        try {
            $active = $null
            $activePath = Join-Path $child.OutputRoot 'active-session.json'
            if ([IO.File]::Exists($activePath)) {
                try { $active = ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($activePath)) }
                catch { $finalCleanupFailures.Add("Could not read session metadata during cleanup: $($_.Exception.Message)") }
            }
            if (-not $child.Process.HasExited) {
                if ($null -ne $active -and -not $child.StopAttempted) {
                    try { Stop-MihariTestSession -Child $child -Metadata $active | Out-Null }
                    catch { $finalCleanupFailures.Add("Mihari integration session cleanup failed: $($_.Exception.Message)") }
                }
                if (-not $child.Process.HasExited) {
                    try { $child.Process.Kill(); $child.Process.WaitForExit(5000) }
                    catch { $finalCleanupFailures.Add("Mihari child process cleanup failed: $($_.Exception.Message)") }
                }
            }
            if ($null -ne $active -and $active.caThumbprint -and $active.caSubject) {
                try {
                    if (-not (Test-MihariTestThumbprintAbsent -Thumbprint ([string]$active.caThumbprint))) {
                        [void](Invoke-MihariTestRootConfirmation -Operation Remove -Action {
                            Remove-MihariCARoot -Thumbprint ([string]$active.caThumbprint) -Subject ([string]$active.caSubject)
                        })
                    }
                }
                catch { $finalCleanupFailures.Add("Could not remove a failed session's exact CA root: $($_.Exception.Message)") }
            }
            if ($child.Process.HasExited) { $child.Process.Dispose() }
        }
        catch { $finalCleanupFailures.Add("Mihari process cleanup failed: $($_.Exception.Message)") }
    }
    if ($null -ne $fixtureIdentity) {
        try { Remove-MihariTestFixtureTlsIdentity -Identity $fixtureIdentity }
        catch { $finalCleanupFailures.Add("Fixture certificate cleanup failed: $($_.Exception.Message)") }
    }
    try { Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction Stop }
    catch { $finalCleanupFailures.Add("Could not remove the temporary integration output: $($_.Exception.Message)") }
}
if ($finalCleanupFailures.Count -gt 0) {
    throw ('Integration test cleanup failed: ' + ($finalCleanupFailures -join '; '))
}
