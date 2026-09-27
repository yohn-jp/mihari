function New-MihariRouteResult {
    param(
        [Parameter(Mandatory = $true)][string]$Kind,
        [AllowNull()][string]$HostName,
        [AllowNull()][Nullable[int]]$Port,
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Reason
    )

    return [pscustomobject]@{
        Kind   = $Kind
        Host   = $HostName
        Port   = $Port
        Source = $Source
        Reason = $Reason
    }
}

function Get-MihariPlatformProxyConfiguration {
    $result = [pscustomobject]@{
        Configured = $false
        PacConfigured = $false
        EnvironmentConfigured = $false
        ErrorType  = $null
    }

    foreach ($name in @('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy')) {
        $value = [Environment]::GetEnvironmentVariable($name)
        if (-not [string]::IsNullOrWhiteSpace($value)) {
            $result.Configured = $true
            $result.EnvironmentConfigured = $true
            return $result
        }
    }

    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        return $result
    }

    $locations = @(
        @{ Root = [Microsoft.Win32.Registry]::CurrentUser; Path = 'Software\Microsoft\Windows\CurrentVersion\Internet Settings'; Policy = $false },
        @{ Root = [Microsoft.Win32.Registry]::CurrentUser; Path = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'; Policy = $true },
        @{ Root = [Microsoft.Win32.Registry]::LocalMachine; Path = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'; Policy = $true }
    )

    foreach ($location in $locations) {
        $key = $null
        try {
            $key = $location.Root.OpenSubKey($location.Path, $false)
            if ($null -eq $key) {
                continue
            }

            $proxyEnabled = $false
            $proxyEnableValue = $key.GetValue('ProxyEnable', $null)
            if ($null -ne $proxyEnableValue) {
                try {
                    $proxyEnabled = ([int]$proxyEnableValue -ne 0)
                }
                catch {
                    $result.ErrorType = $_.Exception.GetType().FullName
                }
            }

            $proxyServer = $key.GetValue('ProxyServer', $null)
            $autoConfigUrl = $key.GetValue('AutoConfigURL', $null)
            $autoDetectValue = $key.GetValue('AutoDetect', $null)
            $autoDetect = $false
            if ($null -ne $autoDetectValue) {
                try {
                    $autoDetect = ([int]$autoDetectValue -ne 0)
                }
                catch {
                    $result.ErrorType = $_.Exception.GetType().FullName
                }
            }

            if ((-not [string]::IsNullOrWhiteSpace([string]$proxyServer)) -and ($proxyEnabled -or $location.Policy)) {
                $result.Configured = $true
            }
            if (-not [string]::IsNullOrWhiteSpace([string]$autoConfigUrl) -or $autoDetect) {
                $result.Configured = $true
                $result.PacConfigured = $true
            }
        }
        catch {
            $result.ErrorType = $_.Exception.GetType().FullName
        }
        finally {
            if ($null -ne $key) {
                $key.Dispose()
            }
        }
    }

    return $result
}

function ConvertTo-MihariProxyEndpoint {
    param(
        [Parameter(Mandatory = $true)][object]$Value,
        [Parameter(Mandatory = $true)][string]$Source
    )

    $hostName = $null
    $port = $null
    if ($Value -is [System.Uri]) {
        $proxyUri = $Value
        if (-not $proxyUri.IsAbsoluteUri) {
            throw [System.ArgumentException]::new('The proxy endpoint must be an absolute URI.')
        }
        if ($proxyUri.Scheme -ne 'http') {
            throw [System.NotSupportedException]::new('Only HTTP explicit proxy endpoints are supported.')
        }
        if (-not [string]::IsNullOrEmpty($proxyUri.UserInfo)) {
            throw [System.ArgumentException]::new('Proxy credentials in the endpoint are not supported.')
        }
        if ($proxyUri.AbsolutePath -ne '/' -or -not [string]::IsNullOrEmpty($proxyUri.Query) -or -not [string]::IsNullOrEmpty($proxyUri.Fragment)) {
            throw [System.ArgumentException]::new('The proxy endpoint must not contain a path, query, or fragment.')
        }
        $hostName = $proxyUri.DnsSafeHost
        $port = $proxyUri.Port
    }
    elseif ($Value -is [System.Collections.IDictionary]) {
        $candidateHost = $Value['Host']
        $candidatePort = $Value['Port']
        if ([string]::IsNullOrWhiteSpace([string]$candidateHost)) {
            throw [System.ArgumentException]::new('An explicit proxy endpoint needs a host.')
        }
        $hostName = [string]$candidateHost
        $parsedPort = 0
        if (-not [int]::TryParse([string]$candidatePort, [ref]$parsedPort)) {
            throw [System.ArgumentException]::new('An explicit proxy endpoint needs a numeric port.')
        }
        $port = $parsedPort
    }
    elseif ($null -ne $Value.PSObject.Properties['Host'] -and $null -ne $Value.PSObject.Properties['Port']) {
        $hostName = [string]$Value.Host
        $parsedPort = 0
        if (-not [int]::TryParse([string]$Value.Port, [ref]$parsedPort)) {
            throw [System.ArgumentException]::new('An explicit proxy endpoint needs a numeric port.')
        }
        $port = $parsedPort
    }
    else {
        $proxyText = [string]$Value
        if ([string]::IsNullOrWhiteSpace($proxyText)) {
            throw [System.ArgumentException]::new('The explicit proxy endpoint is empty.')
        }
        if ($proxyText -notmatch '^[A-Za-z][A-Za-z0-9+.-]*://') {
            $proxyText = 'http://' + $proxyText
        }

        $proxyUri = $null
        if (-not [System.Uri]::TryCreate($proxyText, [System.UriKind]::Absolute, [ref]$proxyUri)) {
            throw [System.ArgumentException]::new('The explicit proxy endpoint is not a valid URI.')
        }
        return ConvertTo-MihariProxyEndpoint -Value $proxyUri -Source $Source
    }

    if ([string]::IsNullOrWhiteSpace($hostName) -or $hostName -match '[\r\n/@?#]') {
        throw [System.ArgumentException]::new('The explicit proxy host is invalid.')
    }
    if ($port -lt 1 -or $port -gt 65535) {
        throw [System.ArgumentOutOfRangeException]::new('Port', 'The explicit proxy port must be between 1 and 65535.')
    }

    return New-MihariRouteResult -Kind 'ExplicitProxy' -HostName $hostName -Port ([Nullable[int]]$port) -Source $Source -Reason ('Using the ' + $Source.ToLowerInvariant() + ' HTTP proxy.')
}

function Resolve-MihariRoute {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][System.Uri]$Uri,
        [AllowNull()][object]$Override
    )

    if (-not $Uri.IsAbsoluteUri -or ($Uri.Scheme -ne 'http' -and $Uri.Scheme -ne 'https')) {
        return New-MihariRouteResult -Kind 'Unsupported' -HostName $Uri.DnsSafeHost -Port ([Nullable[int]]$null) -Source 'None' -Reason 'Only absolute HTTP and HTTPS destination URIs can be routed.'
    }

    if ($null -ne $Override -and -not ($Override -is [string] -and [string]::IsNullOrWhiteSpace($Override))) {
        try {
            $endpointValue = $Override
            if ($Override -is [System.Collections.IDictionary] -and $Override.Contains('Uri')) {
                $endpointValue = $Override['Uri']
            }
            elseif ($Override -isnot [string] -and $Override -isnot [System.Uri] -and $Override -isnot [System.Collections.IDictionary] -and $null -ne $Override.PSObject.Properties['Uri']) {
                $endpointValue = $Override.Uri
            }
            return ConvertTo-MihariProxyEndpoint -Value $endpointValue -Source 'Override'
        }
        catch {
            return New-MihariRouteResult -Kind 'Unsupported' -HostName $null -Port ([Nullable[int]]$null) -Source 'Override' -Reason ('The configured proxy override is unsupported (' + $_.Exception.GetType().FullName + ').')
        }
    }

    $configuration = Get-MihariPlatformProxyConfiguration
    $platformProxy = $null
    try {
        $platformProxy = [System.Net.WebRequest]::DefaultWebProxy
    }
    catch {
        return New-MihariRouteResult -Kind 'Unsupported' -HostName $null -Port ([Nullable[int]]$null) -Source 'Platform' -Reason ('The platform proxy could not be inspected (' + $_.Exception.GetType().FullName + ').')
    }

    if ($null -eq $platformProxy) {
        if ($configuration.Configured -or $configuration.ErrorType) {
            return New-MihariRouteResult -Kind 'Unsupported' -HostName $null -Port ([Nullable[int]]$null) -Source 'Platform' -Reason 'Platform proxy configuration exists but no deterministic route is available.'
        }
        return New-MihariRouteResult -Kind 'Direct' -HostName $Uri.DnsSafeHost -Port ([Nullable[int]]$Uri.Port) -Source 'None' -Reason 'No platform proxy is configured; using the direct network path.'
    }

    $proxyUri = $null
    $isBypassed = $false
    try {
        $proxyUri = $platformProxy.GetProxy($Uri)
        $isBypassed = $platformProxy.IsBypassed($Uri)
    }
    catch {
        return New-MihariRouteResult -Kind 'Unsupported' -HostName $null -Port ([Nullable[int]]$null) -Source 'Platform' -Reason ('Platform proxy resolution failed (' + $_.Exception.GetType().FullName + ').')
    }

    if ($null -eq $proxyUri) {
        if (-not $configuration.Configured -and -not $configuration.ErrorType) {
            return New-MihariRouteResult -Kind 'Direct' -HostName $Uri.DnsSafeHost -Port ([Nullable[int]]$Uri.Port) -Source 'Platform' -Reason 'The platform returned no proxy endpoint and no proxy policy is configured.'
        }
        return New-MihariRouteResult -Kind 'Unsupported' -HostName $null -Port ([Nullable[int]]$null) -Source 'Platform' -Reason 'Platform proxy resolution returned no route.'
    }

    if ($isBypassed -or $proxyUri.Equals($Uri)) {
        if ($configuration.PacConfigured -or $configuration.ErrorType) {
            return New-MihariRouteResult -Kind 'Unsupported' -HostName $null -Port ([Nullable[int]]$null) -Source 'Platform' -Reason 'The platform selected a direct route, but configured proxy policy could not be verified safely.'
        }
        if ($configuration.EnvironmentConfigured) {
            return New-MihariRouteResult -Kind 'Unsupported' -HostName $null -Port ([Nullable[int]]$null) -Source 'Platform' -Reason 'Environment proxy configuration exists, but Mihari cannot prove that the direct platform result is an explicit bypass.'
        }
        return New-MihariRouteResult -Kind 'Direct' -HostName $Uri.DnsSafeHost -Port ([Nullable[int]]$Uri.Port) -Source 'Platform' -Reason 'Platform proxy resolution selected a direct route for this destination.'
    }

    try {
        return ConvertTo-MihariProxyEndpoint -Value $proxyUri -Source 'Platform'
    }
    catch {
        return New-MihariRouteResult -Kind 'Unsupported' -HostName $null -Port ([Nullable[int]]$null) -Source 'Platform' -Reason ('The platform selected a proxy type Mihari cannot honor (' + $_.Exception.GetType().FullName + ').')
    }
}

function Format-MihariAuthority {
    param(
        [Parameter(Mandatory = $true)][string]$HostName,
        [Parameter(Mandatory = $true)][int]$Port
    )

    if ([string]::IsNullOrWhiteSpace($HostName) -or $HostName -match '[\r\n/@?#]') {
        throw [System.ArgumentException]::new('The upstream destination host is invalid.')
    }
    if ($Port -lt 1 -or $Port -gt 65535) {
        throw [System.ArgumentOutOfRangeException]::new('TargetPort', 'The upstream destination port must be between 1 and 65535.')
    }

    $address = $null
    if ([System.Net.IPAddress]::TryParse($HostName, [ref]$address) -and $address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
        return '[' + $address.ToString() + ']:' + $Port
    }
    $asciiHost = $HostName
    if ($HostName.IndexOf(':') -lt 0) {
        try {
            $idn = New-Object System.Globalization.IdnMapping
            $asciiHost = $idn.GetAscii($HostName)
        }
        catch {
            throw [System.ArgumentException]::new('The upstream destination host is not a valid DNS name.')
        }
    }
    return $asciiHost + ':' + $Port
}

function Read-MihariProxyResponse {
    param(
        [Parameter(Mandatory = $true)][System.Net.Sockets.NetworkStream]$Stream,
        [int]$MaximumHeaderBytes = 32768
    )

    $headerBytes = New-Object System.Collections.Generic.List[byte]
    $previous1 = -1
    $previous2 = -1
    $previous3 = -1
    $headerComplete = $false
    while ($headerBytes.Count -lt $MaximumHeaderBytes) {
        $value = $Stream.ReadByte()
        if ($value -lt 0) {
            throw [System.IO.EndOfStreamException]::new('The explicit proxy closed before completing its CONNECT response.')
        }

        $headerBytes.Add([byte]$value)
        if ($previous3 -eq 13 -and $previous2 -eq 10 -and $previous1 -eq 13 -and $value -eq 10) {
            $headerComplete = $true
            break
        }
        $previous3 = $previous2
        $previous2 = $previous1
        $previous1 = $value
    }

    if (-not $headerComplete) {
        throw [System.IO.InvalidDataException]::new('The explicit proxy response headers exceeded the configured limit.')
    }

    $headerText = [System.Text.Encoding]::ASCII.GetString($headerBytes.ToArray())
    $lines = $headerText -split "`r`n"
    if ($lines.Count -lt 2 -or $lines[0] -notmatch '^HTTP/1\.[01][ \t]+([0-9]{3})(?:[ \t]+([^\r\n]*))?$') {
        throw [System.IO.InvalidDataException]::new('The explicit proxy returned an invalid HTTP status line.')
    }

    $statusCode = [int]$Matches[1]
    $reasonPhrase = ''
    if ($Matches.Count -gt 2 -and $null -ne $Matches[2]) {
        $reasonPhrase = [string]$Matches[2]
        $reasonPhrase = ($reasonPhrase -replace '[\x00-\x1f\x7f]', ' ').Trim()
        if ($reasonPhrase.Length -gt 128) {
            $reasonPhrase = $reasonPhrase.Substring(0, 128)
        }
    }

    $proxyAuthenticate = New-Object System.Collections.Generic.List[string]
    for ($lineIndex = 1; $lineIndex -lt $lines.Count; $lineIndex++) {
        $line = [string]$lines[$lineIndex]
        if ($line -match '^Proxy-Authenticate[ \t]*:[ \t]*(.*)$') {
            $challenge = ([string]$Matches[1] -replace '[\x00-\x08\x0a-\x1f\x7f]', ' ').Trim()
            if ($challenge.Length -gt 0) {
                $proxyAuthenticate.Add($challenge)
            }
        }
    }

    return [pscustomobject]@{
        StatusCode        = $statusCode
        ReasonPhrase      = $reasonPhrase
        ProxyAuthenticate = $proxyAuthenticate.ToArray()
    }
}

function Connect-MihariTcpClient {
    param(
        [Parameter(Mandatory = $true)][System.Net.Sockets.TcpClient]$Client,
        [Parameter(Mandatory = $true)][string]$HostName,
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][int]$TimeoutMs
    )

    $pending = $null
    $waitHandle = $null
    try {
        $pending = $Client.BeginConnect($HostName, $Port, $null, $null)
        $waitHandle = $pending.AsyncWaitHandle
        if (-not $waitHandle.WaitOne($TimeoutMs)) {
            throw [System.TimeoutException]::new('The upstream TCP connection timed out.')
        }
        $Client.EndConnect($pending)
    }
    finally {
        if ($null -ne $waitHandle) {
            $waitHandle.Close()
        }
    }
}

function Open-MihariUpstream {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][object]$Route,
        [Parameter(Mandatory = $true)][string]$TargetHost,
        [Parameter(Mandatory = $true)][int]$TargetPort,
        [Parameter(Mandatory = $true)][bool]$Tunnel,
        [AllowNull()][string]$ProxyAuthorization,
        [ValidateRange(100, 120000)][int]$TimeoutMs = 15000
    )

    if ($Route.Kind -eq 'Unsupported') {
        throw [System.NotSupportedException]::new(('The upstream route is unsupported: ' + [string]$Route.Reason))
    }
    if ($Route.Kind -ne 'Direct' -and $Route.Kind -ne 'ExplicitProxy') {
        throw [System.ArgumentException]::new('The upstream route kind must be Direct, ExplicitProxy, or Unsupported.')
    }

    $destinationAuthority = Format-MihariAuthority -HostName $TargetHost -Port $TargetPort
    if ($Route.Kind -eq 'Direct') {
        $connectHost = $TargetHost
        $connectPort = $TargetPort
    }
    else {
        $proxyHost = [string]$Route.Host
        $proxyPort = 0
        if ([string]::IsNullOrWhiteSpace($proxyHost) -or -not [int]::TryParse([string]$Route.Port, [ref]$proxyPort) -or $proxyPort -lt 1 -or $proxyPort -gt 65535) {
            throw [System.ArgumentException]::new('The explicit upstream proxy endpoint is invalid.')
        }
        if ($proxyHost -match '[\r\n/@?#]') {
            throw [System.ArgumentException]::new('The explicit upstream proxy host is invalid.')
        }
        $connectHost = $proxyHost
        $connectPort = $proxyPort
    }

    $client = New-Object System.Net.Sockets.TcpClient
    try {
        Connect-MihariTcpClient -Client $client -HostName $connectHost -Port $connectPort -TimeoutMs $TimeoutMs
        $stream = $client.GetStream()
        $proxyStatus = $null

        if ($Route.Kind -eq 'ExplicitProxy' -and $Tunnel) {
            $client.SendTimeout = $TimeoutMs
            $client.ReceiveTimeout = $TimeoutMs
            $stream.WriteTimeout = $TimeoutMs
            $stream.ReadTimeout = $TimeoutMs
            $connectRequest = 'CONNECT ' + $destinationAuthority + " HTTP/1.1`r`nHost: " + $destinationAuthority + "`r`nProxy-Connection: Keep-Alive`r`n`r`n"
            if (-not [string]::IsNullOrEmpty($ProxyAuthorization)) {
                if ($ProxyAuthorization -match '[\x00-\x1f\x7f]') {
                    throw [System.IO.InvalidDataException]::new('The proxy authorization field contains invalid characters.')
                }
                $connectRequest = 'CONNECT ' + $destinationAuthority + " HTTP/1.1`r`nHost: " + $destinationAuthority + "`r`nProxy-Connection: Keep-Alive`r`nProxy-Authorization: " + $ProxyAuthorization + "`r`n`r`n"
            }
            $requestBytes = [System.Text.Encoding]::ASCII.GetBytes($connectRequest)
            $stream.Write($requestBytes, 0, $requestBytes.Length)
            $stream.Flush()
            $proxyStatus = Read-MihariProxyResponse -Stream $stream
            if ($proxyStatus.StatusCode -ge 200 -and $proxyStatus.StatusCode -lt 300) {
                $client.SendTimeout = 0
                $client.ReceiveTimeout = 0
                $stream.WriteTimeout = 0
                $stream.ReadTimeout = 0
            }
        }

        return [pscustomobject]@{
            Client      = $client
            Stream      = $stream
            ProxyStatus = $proxyStatus
        }
    }
    catch {
        $client.Close()
        throw
    }
}
