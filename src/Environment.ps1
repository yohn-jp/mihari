function Get-MihariEnvironmentHash {
    param([AllowNull()][string]$Value)
    if ([string]::IsNullOrEmpty($Value)) { return $null }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Value)
        return ([System.BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    }
    finally { $sha.Dispose() }
}

function ConvertTo-MihariSafeConfigurationEndpoint {
    param([AllowNull()][string]$Value, [switch]$PacUrl)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    $items = New-Object 'System.Collections.Generic.List[string]'
    foreach ($part in @($Value -split ';')) {
        $candidate = $part.Trim()
        if (-not $candidate) { continue }
        $prefix = ''
        if (-not $PacUrl -and $candidate -match '^(http|https|ftp|socks)=(.*)$') {
            $prefix = $Matches[1].ToLowerInvariant() + '='
            $candidate = $Matches[2]
        }
        $uri = $null
        if ([System.Uri]::TryCreate($candidate, [System.UriKind]::Absolute, [ref]$uri) -and
            $uri.Scheme -in @('http', 'https')) {
            $hostText = $uri.Host
            if ($hostText.IndexOf(':') -ge 0) { $hostText = '[' + $hostText + ']' }
            $safe = $uri.Scheme + '://' + $hostText
            if (-not $uri.IsDefaultPort) { $safe += ':' + $uri.Port }
            if ($PacUrl -and $uri.AbsolutePath -ne '/') { $safe += '/[redacted-path]' }
            $items.Add($prefix + $safe)
        }
        elseif (-not $PacUrl -and $candidate -match '^[a-zA-Z0-9._-]+:[0-9]{1,5}$') {
            $items.Add($prefix + $candidate.ToLowerInvariant())
        }
        else { $items.Add($prefix + '[configured; endpoint redacted]') }
        if ($items.Count -ge 8) { break }
    }
    return ($items.ToArray() -join ';')
}

function Get-MihariEnvironmentRegistrySource {
    param(
        [Parameter(Mandatory=$true)][Microsoft.Win32.RegistryKey]$Root,
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][string[]]$Names,
        [Parameter(Mandatory=$true)][string]$Source
    )
    $key = $null
    $values = [ordered]@{}
    try {
        $key = $Root.OpenSubKey($Path, $false)
        if ($null -eq $key) {
            return [pscustomobject]@{ source = $Source; coverage = 'observed'; configured = $false; values = $values; errorType = $null }
        }
        foreach ($name in $Names) {
            $value = $key.GetValue($name, $null)
            if ($null -eq $value) { continue }
            if ($name -in @('ProxyServer', 'ProxyPacUrl')) {
                $safeEndpoint = ConvertTo-MihariSafeConfigurationEndpoint -Value ([string]$value) -PacUrl:($name -eq 'ProxyPacUrl')
                $values[$name] = [pscustomobject]@{
                    endpoint = $safeEndpoint
                    sha256 = Get-MihariEnvironmentHash -Value $safeEndpoint
                }
            }
            elseif ($name -eq 'AutoConfigURL') {
                $safeEndpoint = ConvertTo-MihariSafeConfigurationEndpoint -Value ([string]$value) -PacUrl
                $values[$name] = [pscustomobject]@{
                    endpoint = $safeEndpoint
                    sha256 = Get-MihariEnvironmentHash -Value $safeEndpoint
                }
            }
            elseif ($name -eq 'ProxyBypassList') {
                $values[$name] = [pscustomobject]@{ configured = $true; sha256 = Get-MihariEnvironmentHash -Value ([string]$value) }
            }
            elseif ($value -is [byte[]]) {
                $values[$name] = [pscustomobject]@{ configured = $true; sha256 = Get-MihariEnvironmentHash -Value ([Convert]::ToBase64String($value)) }
            }
            elseif ($name -in @('ProxyEnable', 'AutoDetect', 'QuicAllowed')) {
                $values[$name] = [string]$value
            }
            elseif ($name -eq 'ProxyMode') {
                $mode = ([string]$value).ToLowerInvariant()
                if ($mode -in @('direct', 'auto_detect', 'pac_script', 'fixed_servers', 'system')) { $values[$name] = $mode }
                else { $values[$name] = 'configured_unknown_value' }
            }
            elseif ($name -eq 'DnsOverHttpsMode') {
                $mode = ([string]$value).ToLowerInvariant()
                if ($mode -in @('off', 'automatic', 'secure')) { $values[$name] = $mode }
                else { $values[$name] = 'configured_unknown_value' }
            }
            else {
                $values[$name] = [pscustomobject]@{ configured = $true; sha256 = Get-MihariEnvironmentHash -Value ([string]$value) }
            }
        }
        return [pscustomobject]@{ source = $Source; coverage = 'observed'; configured = ($values.Count -gt 0); values = $values; errorType = $null }
    }
    catch [System.Security.SecurityException] {
        return [pscustomobject]@{ source = $Source; coverage = 'permission_denied'; configured = $null; values = $values; errorType = $_.Exception.GetType().FullName }
    }
    catch [System.UnauthorizedAccessException] {
        return [pscustomobject]@{ source = $Source; coverage = 'permission_denied'; configured = $null; values = $values; errorType = $_.Exception.GetType().FullName }
    }
    catch {
        return [pscustomobject]@{ source = $Source; coverage = 'unknown'; configured = $null; values = $values; errorType = $_.Exception.GetType().FullName }
    }
    finally { if ($null -ne $key) { $key.Dispose() } }
}

function Get-MihariEnvironmentNetworkInterfaces {
    $items = New-Object 'System.Collections.Generic.List[object]'
    try {
        foreach ($adapter in @([System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() | Sort-Object -Property Id)) {
            if ($items.Count -ge 64) { break }
            $properties = $adapter.GetIPProperties()
            $addresses = @($properties.UnicastAddresses | Select-Object -First 16 | ForEach-Object { $_.Address.ToString() })
            $dns = @($properties.DnsAddresses | Select-Object -First 16 | ForEach-Object { $_.ToString() })
            $gateways = @($properties.GatewayAddresses | Select-Object -First 16 | ForEach-Object { $_.Address.ToString() })
            $items.Add([pscustomobject]@{
                id = [string]$adapter.Id
                name = [string]$adapter.Name
                type = $adapter.NetworkInterfaceType.ToString()
                status = $adapter.OperationalStatus.ToString()
                addresses = $addresses
                configuredDns = $dns
                gateways = $gateways
                vpnIndicator = ($adapter.NetworkInterfaceType.ToString() -in @('Ppp', 'Tunnel'))
            })
        }
        return [pscustomobject]@{ source = 'windows.network_interfaces'; coverage = $(if ($items.Count -ge 64) { 'truncated' } else { 'observed' }); items = $items.ToArray(); errorType = $null }
    }
    catch {
        return [pscustomobject]@{ source = 'windows.network_interfaces'; coverage = 'unknown'; items = @(); errorType = $_.Exception.GetType().FullName }
    }
}

function Get-MihariEnvironmentCapabilities {
    $isWindows = ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT)
    $sslType = [System.Net.Security.SslStream]
    return [pscustomobject]@{
        capturedAtUtc = [DateTime]::UtcNow.ToString('o')
        source = 'mihari.runtime_probe'
        powershellVersion = [string]$PSVersionTable.PSVersion
        clrVersion = [string][Environment]::Version
        osVersion = [string][Environment]::OSVersion.Version
        windows = $isWindows
        tlsAlpnProperty = ($null -ne $sslType.GetProperty('NegotiatedApplicationProtocol'))
        tlsCipherSuiteProperty = ($null -ne $sslType.GetProperty('NegotiatedCipherSuite'))
        nativeH2Inspect = 'unproven'
        winHttpEffectiveSettings = 'unavailable'
        routeTable = 'unavailable'
        clientCertificateRequest = 'unavailable'
    }
}

function Get-MihariEnvironmentSnapshot {
    [CmdletBinding()]
    param(
        [AllowNull()][object]$Session,
        [AllowNull()][System.Uri[]]$Destinations
    )
    $isWindows = ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT)
    $captured = [DateTime]::UtcNow.ToString('o')
    $environmentVariables = [ordered]@{}
    foreach ($name in @('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY', 'http_proxy', 'https_proxy', 'all_proxy', 'no_proxy')) {
        $value = [Environment]::GetEnvironmentVariable($name)
        if ([string]::IsNullOrWhiteSpace($value)) { continue }
        if ($name -match 'NO_PROXY') {
            $environmentVariables[$name] = [pscustomobject]@{ configured = $true; sha256 = Get-MihariEnvironmentHash -Value $value }
        }
        else {
            $safeEndpoint = ConvertTo-MihariSafeConfigurationEndpoint -Value $value
            $environmentVariables[$name] = [pscustomobject]@{ endpoint = $safeEndpoint; sha256 = Get-MihariEnvironmentHash -Value $safeEndpoint }
        }
    }
    $internet = [pscustomobject]@{ source = 'windows.internet_settings.current_user'; coverage = 'unsupported'; configured = $null; values = @{}; errorType = $null }
    $winHttp = [pscustomobject]@{ source = 'windows.winhttp.registry'; coverage = 'unsupported'; configured = $null; values = @{}; errorType = $null; effectiveSettings = 'unavailable' }
    $browserUser = [pscustomobject]@{ source = 'windows.edge_policy.current_user'; coverage = 'unsupported'; configured = $null; values = @{}; errorType = $null }
    $browserMachine = [pscustomobject]@{ source = 'windows.edge_policy.local_machine'; coverage = 'unsupported'; configured = $null; values = @{}; errorType = $null }
    if ($isWindows) {
        $internet = Get-MihariEnvironmentRegistrySource -Root ([Microsoft.Win32.Registry]::CurrentUser) -Path 'Software\Microsoft\Windows\CurrentVersion\Internet Settings' -Names @('ProxyEnable', 'ProxyServer', 'AutoConfigURL', 'AutoDetect') -Source 'windows.internet_settings.current_user'
        $winHttp = Get-MihariEnvironmentRegistrySource -Root ([Microsoft.Win32.Registry]::LocalMachine) -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections' -Names @('WinHttpSettings') -Source 'windows.winhttp.registry'
        $winHttp | Add-Member -NotePropertyName effectiveSettings -NotePropertyValue 'unavailable'
        $policyNames = @('ProxyMode', 'ProxyServer', 'ProxyPacUrl', 'ProxyBypassList', 'QuicAllowed', 'DnsOverHttpsMode')
        $browserUser = Get-MihariEnvironmentRegistrySource -Root ([Microsoft.Win32.Registry]::CurrentUser) -Path 'SOFTWARE\Policies\Microsoft\Edge' -Names $policyNames -Source 'windows.edge_policy.current_user'
        $browserMachine = Get-MihariEnvironmentRegistrySource -Root ([Microsoft.Win32.Registry]::LocalMachine) -Path 'SOFTWARE\Policies\Microsoft\Edge' -Names $policyNames -Source 'windows.edge_policy.local_machine'
    }
    $override = $null
    $platform = $null
    $proxyPort = 0
    if ($null -ne $Session) {
        $override = [string]$Session.UpstreamProxy
        $platform = $Session.PlatformProxySnapshot
        $proxyPort = [int]$Session.ActualPort
    }
    $resolution = New-Object 'System.Collections.Generic.List[object]'
    if ($null -ne $Destinations) {
        foreach ($destination in @($Destinations | Select-Object -First 16)) {
            if ($null -eq $destination -or -not $destination.IsAbsoluteUri -or $destination.Scheme -notin @('http', 'https')) { continue }
            $start = [DateTime]::UtcNow
            try {
                $route = Resolve-MihariRoute -Uri $destination -Override $override -PlatformSnapshot $platform -MihariProxyPort $proxyPort
                $resolution.Add([pscustomobject]@{
                    source = [string]$route.Source
                    evaluatedAtUtc = $start.ToString('o')
                    destination = ($destination.Scheme + '://' + $destination.Authority)
                    selection = [string]$route.Kind
                    proxyEndpoint = $(if ($route.Kind -eq 'ExplicitProxy') { [string]$route.Host + ':' + [string]$route.Port } else { $null })
                    errorCode = [string]$route.ErrorCode
                    coverage = $(if ($route.Kind -eq 'Unsupported') { 'unknown' } else { 'observed' })
                })
            }
            catch {
                $resolution.Add([pscustomobject]@{ source = 'platform'; evaluatedAtUtc = $start.ToString('o'); destination = ($destination.Scheme + '://' + $destination.Authority); selection = 'Unknown'; proxyEndpoint = $null; errorCode = $_.Exception.GetType().FullName; coverage = 'unknown' })
            }
        }
    }
    return [pscustomobject]@{
        schemaVersion = 1
        snapshotId = [Guid]::NewGuid().ToString('N')
        capturedAtUtc = $captured
        sources = [pscustomobject]@{
            internetSettings = $internet
            winHttp = $winHttp
            environmentVariables = [pscustomobject]@{ source = 'process.environment'; coverage = 'observed'; values = $environmentVariables }
            browserPolicyUser = $browserUser
            browserPolicyMachine = $browserMachine
            mihariOverride = [pscustomobject]@{ source = 'mihari.session'; coverage = $(if ($null -eq $Session) { 'unknown' } else { 'observed' }); endpoint = ConvertTo-MihariSafeConfigurationEndpoint -Value $override; configured = (-not [string]::IsNullOrWhiteSpace($override)) }
            platformResolver = [pscustomobject]@{ source = 'dotnet.default_web_proxy'; coverage = $(if ($null -eq $platform) { 'unknown' } elseif ($platform.ErrorType) { 'unknown' } else { 'observed' }); capturedAtUtc = $(if ($null -ne $platform) { $platform.CapturedAtUtc } else { $null }); pacConfigured = $(if ($null -ne $platform) { $platform.Configuration.PacConfigured } else { $null }); errorType = $(if ($null -ne $platform) { $platform.ErrorType } else { $null }) }
            pacResolution = [pscustomobject]@{ source = 'dotnet.default_web_proxy'; retrieval = 'not_performed'; resolver = 'Resolve-MihariRoute'; evaluations = $resolution.ToArray() }
            networkInterfaces = Get-MihariEnvironmentNetworkInterfaces
            routes = [pscustomobject]@{ source = 'windows.route_table'; coverage = 'unavailable'; reason = 'No managed route-table reader is available in the supported runtime.' }
            vpn = [pscustomobject]@{ source = 'windows.network_interfaces'; coverage = 'partial'; reason = 'Only PPP and tunnel interface types are visible; other VPN implementations may not be identifiable.' }
        }
    }
}

function Test-MihariLocalInspectExclusion {
    param([Parameter(Mandatory=$true)][string]$HostName, [AllowNull()][string[]]$ExcludedHosts)
    if ($null -eq $ExcludedHosts -or $ExcludedHosts.Count -eq 0) { return $false }
    $normalized = (ConvertTo-MihariCertificateHost -DestinationHost $HostName).Name
    foreach ($entry in $ExcludedHosts) {
        if ([string]::IsNullOrWhiteSpace($entry)) { continue }
        try {
            $candidate = (ConvertTo-MihariCertificateHost -DestinationHost $entry).Name
            if ([string]::Equals($normalized, $candidate, [StringComparison]::OrdinalIgnoreCase)) { return $true }
        }
        catch { continue }
    }
    return $false
}
