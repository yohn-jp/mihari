param()

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path $PSScriptRoot -Parent
. (Join-Path $repoRoot 'src/Upstream.ps1')

function Assert-MihariUpstreamTest {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Message
    )
    if (-not $Condition) { throw ('ASSERTION FAILED: ' + $Message) }
}

function New-MihariTestPlatformSnapshot {
    param(
        [AllowNull()][object]$Proxy,
        [bool]$Configured = $false
    )

    return [pscustomobject]@{
        PlatformProxy = $Proxy
        Configuration = [pscustomobject]@{
            Configured = $Configured
            PacConfigured = $false
            EnvironmentConfigured = $false
            ErrorType = $null
        }
        CapturedAtUtc = [DateTime]::UtcNow.ToString('o')
        ErrorType = $null
    }
}

$proxyPort = 18899
$target = New-Object System.Uri -ArgumentList 'https://fixture.invalid/resource'
$originalPlatformProxy = [System.Net.WebRequest]::DefaultWebProxy

try {
    # The session captures the existing enterprise resolver before Edge starts.
    # Simulate a later process-default change to Mihari's injected endpoint and
    # prove route selection continues to use the captured resolver.
    $enterpriseProxy = New-Object System.Net.WebProxy -ArgumentList 'http://enterprise-proxy.invalid:8080'
    [System.Net.WebRequest]::DefaultWebProxy = $enterpriseProxy
    $snapshot = New-MihariUpstreamSnapshot
    $browserProxy = New-Object System.Net.WebProxy -ArgumentList ('http://127.0.0.1:{0}' -f $proxyPort)
    [System.Net.WebRequest]::DefaultWebProxy = $browserProxy

    $route = Resolve-MihariRoute -Uri $target -PlatformSnapshot $snapshot -MihariProxyPort $proxyPort
    Assert-MihariUpstreamTest -Condition ($route.Kind -eq 'ExplicitProxy' -and $route.Host -eq 'enterprise-proxy.invalid' -and [int]$route.Port -eq 8080) `
        -Message 'A session must retain the platform proxy captured before browser launch.'

    $selfRoutes = @(
        Resolve-MihariRoute -Uri $target -Override ('http://127.0.0.1:{0}' -f $proxyPort) -PlatformSnapshot $snapshot -MihariProxyPort $proxyPort
        Resolve-MihariRoute -Uri $target -Override ('http://localhost:{0}' -f $proxyPort) -PlatformSnapshot $snapshot -MihariProxyPort $proxyPort
        Resolve-MihariRoute -Uri $target -Override ('http://[::1]:{0}' -f $proxyPort) -PlatformSnapshot $snapshot -MihariProxyPort $proxyPort
        Resolve-MihariRoute -Uri $target -PlatformSnapshot (New-MihariTestPlatformSnapshot -Proxy $browserProxy -Configured $true) -MihariProxyPort $proxyPort
    )
    foreach ($selfRoute in $selfRoutes) {
        Assert-MihariUpstreamTest -Condition ($selfRoute.Kind -eq 'Unsupported' -and $selfRoute.ErrorCode -eq 'upstream_route_self_reference') `
            -Message 'A platform or explicit upstream route resolving to Mihari loopback must be rejected with the stable self-reference code.'
    }

    # A browser can ask its configured proxy to fetch an absolute URI pointing
    # at the same listener. Even a platform-direct result must be stopped.
    $directSnapshot = New-MihariTestPlatformSnapshot -Proxy $null
    $selfTarget = New-Object System.Uri -ArgumentList ('http://127.0.0.1:{0}/' -f $proxyPort)
    $directSelfRoute = Resolve-MihariRoute -Uri $selfTarget -PlatformSnapshot $directSnapshot -MihariProxyPort $proxyPort
    Assert-MihariUpstreamTest -Condition ($directSelfRoute.Kind -eq 'Unsupported' -and $directSelfRoute.ErrorCode -eq 'upstream_route_self_reference') `
        -Message 'A direct destination matching Mihari loopback must be rejected before opening an upstream socket.'

    # DNS names under localhost are guaranteed loopback aliases by the host
    # naming convention, and exercise the non-literal alias path without any
    # external DNS dependency.
    $localhostAlias = Resolve-MihariRoute -Uri $target -Override ('http://mihari.localhost:{0}' -f $proxyPort) -PlatformSnapshot $snapshot -MihariProxyPort $proxyPort
    Assert-MihariUpstreamTest -Condition ($localhostAlias.Kind -eq 'Unsupported' -and $localhostAlias.ErrorCode -eq 'upstream_route_self_reference') `
        -Message 'A .localhost alias on Mihari’s listener port must be treated as self-reference.'

    Write-Host 'PASS upstream snapshot and self-reference guards'
}
finally {
    [System.Net.WebRequest]::DefaultWebProxy = $originalPlatformProxy
}
