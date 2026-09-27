param()

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'TestSupport.ps1')
$sourceRoot = Join-Path (Split-Path $PSScriptRoot -Parent) 'src'
. (Join-Path $sourceRoot 'Diagnosis.ps1')
. (Join-Path $sourceRoot 'Comparison.ps1')

$repeatedEvents = New-Object 'System.Collections.Generic.List[object]'
for ($index = 1; $index -le 220; $index++) {
    $timestamp = ([DateTimeOffset]::UtcNow.AddSeconds($index)).ToString('o', [Globalization.CultureInfo]::InvariantCulture)
    $repeatedEvents.Add([pscustomobject][ordered]@{
        schemaVersion = 2
        eventId = ('proxy-407-{0:D3}' -f $index)
        sequence = $index
        timestamp = $timestamp
        sessionId = 'findings-session'
        connectionId = ('connection-{0:D3}' -f $index)
        requestId = ('request-{0:D3}' -f $index)
        source = 'proxy'
        mode = 'Tunnel'
        stage = 'upstream.proxy.connect'
        outcome = 'rejected'
        elapsedMs = 12
        data = [pscustomobject][ordered]@{
            routeKind = 'ExplicitProxy'
            host = 'blocked.test'
            port = 443
            path = '/upload?token=secret-value'
            proxyStatus = 407
        }
    })
}

$findings = @(Get-MihariSessionFindings -Events @($repeatedEvents.ToArray()))
$finding = @($findings | Where-Object { $_.code -eq 'upstream_proxy_auth_required' }) | Select-Object -First 1
Assert-MihariTest -Condition ($null -ne $finding) -Message 'Repeated proxy failures must produce a grouped finding.'
Assert-MihariTest -Condition ($finding.occurrenceCount -eq 220 -and $finding.evidenceRefs.Count -eq 220) -Message 'Session findings must preserve all occurrences and references beyond the UI hot window.'
Assert-MihariTest -Condition ($finding.ruleVersion -eq 'mihari-diagnosis/1' -and $finding.findingId -match '^finding-[0-9a-f]{32}$') -Message 'Grouped findings must have a stable rule version and identity.'
Assert-MihariTest -Condition ($finding.evidenceRefs[0].sessionId -eq 'findings-session' -and $finding.evidenceRefs[0].eventId -like 'proxy-407-*') -Message 'Evidence references must include both session and event identity.'
Assert-MihariTest -Condition ($finding.classification -eq 'proxy_authentication' -and $finding.evidenceStrength -eq 'direct_observation' -and -not [string]::IsNullOrWhiteSpace($finding.nextCheck)) -Message 'Findings must expose classification, evidence strength, and a next check.'
Assert-MihariTest -Condition (-not ($finding | ConvertTo-Json -Depth 20 -Compress).Contains('secret-value')) -Message 'Finding evidence must redact query values.'

$replayOrder = @($repeatedEvents.ToArray())
[array]::Reverse($replayOrder)
$reorderedFinding = @((Get-MihariDiagnosis -Events $replayOrder) | Where-Object { $_.code -eq 'upstream_proxy_auth_required' }) | Select-Object -First 1
Assert-MihariTest -Condition ($reorderedFinding.findingId -eq $finding.findingId) -Message 'Finding identity must not depend on event replay order.'

$nextEvent = [pscustomobject][ordered]@{
    schemaVersion = 2; eventId = 'proxy-407-221'; sequence = 221
    timestamp = ([DateTimeOffset]::UtcNow.AddMinutes(1)).ToString('o', [Globalization.CultureInfo]::InvariantCulture)
    sessionId = 'findings-session'; connectionId = 'connection-221'; requestId = 'request-221'
    source = 'proxy'; mode = 'Tunnel'; stage = 'upstream.proxy.connect'; outcome = 'rejected'; elapsedMs = 12
    data = [pscustomobject]@{ routeKind = 'ExplicitProxy'; host = 'blocked.test'; port = 443; path = '/upload?token=another-secret'; proxyStatus = 407 }
}
$incremented = @(Get-MihariSessionFindings -Events @($nextEvent) -PreviousFindings @($findings))
$retained = @($incremented | Where-Object { $_.findingId -eq $finding.findingId }) | Select-Object -First 1
Assert-MihariTest -Condition ($retained.occurrenceCount -eq 221 -and $retained.evidenceRefs.Count -eq 221) -Message 'Incremental replay must append only new evidence and preserve prior references.'
$agedOut = @(Get-MihariSessionFindings -Events @() -PreviousFindings @($incremented))
$stillOpen = @($agedOut | Where-Object { $_.findingId -eq $finding.findingId }) | Select-Object -First 1
Assert-MihariTest -Condition ($null -ne $stillOpen -and $stillOpen.resolutionState -eq 'open' -and $stillOpen.occurrenceCount -eq 221) -Message 'An absent finding in a later event window must remain open and retain its evidence.'

$resolution = [pscustomobject]@{
    positive = $true
    kind = 'successful_comparable_trial'
    observedAt = ([DateTimeOffset]::UtcNow.AddMinutes(2)).ToString('o', [Globalization.CultureInfo]::InvariantCulture)
    evidenceRefs = @([pscustomobject]@{ sessionId = 'findings-session'; eventId = 'verified-recovery' })
}
$resolved = Set-MihariFindingResolution -Finding $stillOpen -ResolutionEvidence $resolution
Assert-MihariTest -Condition ($resolved.resolutionState -eq 'resolved' -and $resolved.resolutionEvidence.Count -eq 1) -Message 'Only explicit positive evidence may resolve a finding.'
$reopened = @(Get-MihariSessionFindings -Events @([pscustomobject]@{
    eventId = 'proxy-407-222'; timestamp = ([DateTimeOffset]::UtcNow.AddMinutes(3)).ToString('o', [Globalization.CultureInfo]::InvariantCulture)
    sessionId = 'findings-session'; connectionId = 'connection-222'; requestId = 'request-222'; mode = 'Tunnel'
    stage = 'upstream.proxy.connect'; outcome = 'rejected'; data = [pscustomobject]@{ routeKind = 'ExplicitProxy'; host = 'blocked.test'; port = 443; path = '/upload?token=latest-secret'; proxyStatus = 407 }
}) -PreviousFindings @($resolved))
$reopenedFinding = @($reopened | Where-Object { $_.findingId -eq $finding.findingId }) | Select-Object -First 1
Assert-MihariTest -Condition ($reopenedFinding.resolutionState -eq 'reopened') -Message 'New failure evidence after a verified resolution must reopen the same finding.'

$invalidResolution = [pscustomobject]@{
    positive = $false; kind = 'operator_verified'; observedAt = '2026-01-01T00:00:00Z'
    evidenceRefs = @([pscustomobject]@{ sessionId = 'findings-session'; eventId = 'no-proof' })
}
$invalidResolutionRejected = $false
try { [void](Set-MihariFindingResolution -Finding $stillOpen -ResolutionEvidence $invalidResolution) }
catch { $invalidResolutionRejected = $true }
Assert-MihariTest -Condition $invalidResolutionRejected -Message 'Negative or unsupported resolution evidence must not resolve a finding.'

$beforeTrial = [pscustomobject][ordered]@{
    trialId = 'trial-inspect'; caseId = 'case-1'; sessionId = 'session-inspect'; coverage = 'observed'; mode = 'Inspect'
    protocolProfile = 'compatibility'; proxyAuthState = 'anonymous'; cacheState = 'fresh'; loginState = 'signed-in'
    browserVersion = 'Edge-test'; browserProfileId = 'diagnostic-profile'; configurationRevision = 'revision-1'
    networkFingerprint = 'network-1'; upstreamFingerprint = 'route-1'; effectiveProxyRoute = 'Direct'; localInspectionExclusions = @()
}
$afterTrial = [pscustomobject][ordered]@{
    trialId = 'trial-tunnel'; caseId = 'case-1'; sessionId = 'session-tunnel'; coverage = 'observed'; mode = 'Tunnel'
    protocolProfile = 'compatibility'; proxyAuthState = 'anonymous'; cacheState = 'fresh'; loginState = 'signed-in'
    browserVersion = 'Edge-test'; browserProfileId = 'diagnostic-profile'; configurationRevision = 'revision-1'
    networkFingerprint = 'network-1'; upstreamFingerprint = 'route-1'; effectiveProxyRoute = 'Direct'; localInspectionExclusions = @()
}
$inspectEvent = [pscustomobject][ordered]@{
    eventId = 'inspect-failure'; sessionId = 'session-inspect'; trialId = 'trial-inspect'; caseId = 'case-1'; requestId = 'inspect-request'
    source = 'proxy'; coverage = 'observed'; mode = 'Inspect'; stage = 'client.tls'; outcome = 'failed'; timestamp = '2026-01-01T00:00:00Z'
    data = [pscustomobject]@{ host = 'service.test'; port = 443; method = 'GET'; path = '/login?state=secret' }
}
$tunnelEvent = [pscustomobject][ordered]@{
    eventId = 'tunnel-relay'; sessionId = 'session-tunnel'; trialId = 'trial-tunnel'; caseId = 'case-1'; requestId = 'tunnel-request'
    source = 'proxy'; coverage = 'observed'; mode = 'Tunnel'; stage = 'tunnel.relay'; outcome = 'connected'; timestamp = '2026-01-01T00:01:00Z'
    data = [pscustomobject]@{ host = 'service.test'; port = 443; method = 'GET'; path = '/login?state=other-secret'; protocol = 'h2' }
}
$comparison = New-MihariTrialComparison -BeforeTrial $beforeTrial -AfterTrial $afterTrial -BeforeEvents @($inspectEvent) -AfterEvents @($tunnelEvent)
Assert-MihariTest -Condition ($comparison.comparisonKind -eq 'single_recorded_condition_change' -and $comparison.changedConditions.Count -eq 1 -and $comparison.changedConditions[0].name -eq 'mode') -Message 'Matching explicit trial conditions must identify the single changed mode.'
Assert-MihariTest -Condition ($comparison.destinationChanges.Count -eq 1 -and $comparison.destinationChanges[0].matchKind -eq 'heuristic') -Message 'Cross-trial URL similarity must remain a heuristic match.'
Assert-MihariTest -Condition ($comparison.supportedFindings.Count -eq 1 -and $comparison.supportedFindings[0].code -eq 'tls_interception_incompatible') -Message 'A matching Inspect TLS failure and Tunnel relay may support an interception-stage finding.'
Assert-MihariTest -Condition ($comparison.supportedFindings[0].evidenceRefs.Count -eq 2 -and $comparison.supportedFindings[0].limitations -match 'does not prove application success') -Message 'The comparison finding must link both event references and keep tunnel application outcome unknown.'
Assert-MihariTest -Condition ($comparison.destinationChanges[0].after[0].outcome -eq 'transport_only' -and $comparison.destinationChanges[0].after[0].applicationOutcome -eq 'unknown') -Message 'Tunnel relay evidence must not become HTTP or application success.'
Assert-MihariTest -Condition (-not ($comparison | ConvertTo-Json -Depth 30 -Compress).Contains('other-secret')) -Message 'Comparison evidence must redact URL query values.'

$secondTunnelEvent = [pscustomobject][ordered]@{
    eventId = 'tunnel-relay-second'; sessionId = 'session-tunnel'; trialId = 'trial-tunnel'; caseId = 'case-1'; requestId = 'tunnel-request-second'
    source = 'proxy'; coverage = 'observed'; mode = 'Tunnel'; stage = 'tunnel.relay'; outcome = 'connected'; timestamp = '2026-01-01T00:01:01Z'
    data = [pscustomobject]@{ host = 'service.test'; port = 443; method = 'GET'; path = '/login?state=second-secret'; protocol = 'h2' }
}
$ambiguousComparison = New-MihariTrialComparison -BeforeTrial $beforeTrial -AfterTrial $afterTrial -BeforeEvents @($inspectEvent) -AfterEvents @($tunnelEvent, $secondTunnelEvent)
Assert-MihariTest -Condition ($ambiguousComparison.uncertainMatches.Count -eq 1 -and $ambiguousComparison.destinationChanges[0].after.Count -eq 2 -and $ambiguousComparison.destinationChanges[0].ambiguous) -Message 'Identical concurrent destinations must remain separate attempts with an explicit ambiguous match.'

$changedProtocolTrial = [pscustomobject]@{}
foreach ($property in $afterTrial.PSObject.Properties) { $changedProtocolTrial | Add-Member -MemberType NoteProperty -Name $property.Name -Value $property.Value }
$changedProtocolTrial.protocolProfile = 'http2-observe'
$nonComparable = New-MihariTrialComparison -BeforeTrial $beforeTrial -AfterTrial $changedProtocolTrial -BeforeEvents @($inspectEvent) -AfterEvents @($tunnelEvent)
Assert-MihariTest -Condition ($nonComparable.comparisonKind -eq 'observational' -and $nonComparable.changedConditions.Count -eq 2 -and $nonComparable.supportedFindings.Count -eq 0) -Message 'A changed protocol profile must prevent a one-variable Inspect/Tunnel conclusion.'

$legacyTlsEvents = @(
    [pscustomobject]@{ eventId = 'legacy-inspect-failure'; sessionId = 'legacy-session'; connectionId = 'legacy-inspect'; mode = 'Inspect'; stage = 'client.tls'; outcome = 'failed'; data = [pscustomobject]@{ host = 'service.test'; port = 443 } },
    [pscustomobject]@{ eventId = 'legacy-tunnel-relay'; sessionId = 'legacy-session'; connectionId = 'legacy-tunnel'; mode = 'Tunnel'; stage = 'tunnel.relay'; outcome = 'connected'; data = [pscustomobject]@{ host = 'service.test'; port = 443 } }
)
$legacyTlsCodes = @((Get-MihariDiagnosis -Events $legacyTlsEvents) | ForEach-Object { $_.code })
Assert-MihariTest -Condition ($legacyTlsCodes -contains 'client_tls_interception_failed' -and $legacyTlsCodes -notcontains 'tls_interception_incompatible') -Message 'Legacy TLS and opaque Tunnel facts without trial conditions must not imply an interception comparison.'

$opaqueOnly = New-MihariTrialComparison -BeforeTrial $afterTrial -AfterTrial $afterTrial -BeforeEvents @($tunnelEvent) -AfterEvents @($tunnelEvent)
Assert-MihariTest -Condition ($opaqueOnly.supportedFindings.Count -eq 0 -and $opaqueOnly.destinationChanges[0].after[0].applicationOutcome -eq 'unknown') -Message 'Opaque Tunnel bytes alone must never establish application success.'

Write-Host 'PASS findings-comparison: stable findings, incremental retention, evidence-backed resolution, controlled trial comparison, heuristic matching, and opaque tunnel limits'
