function Get-MihariComparisonProperty {
    param(
        [Parameter(Mandatory = $true)][object] $Trial,
        [Parameter(Mandatory = $true)][string[]] $Names
    )

    $targets = @($Trial)
    foreach ($containerName in @('profile', 'configuration', 'environment', 'browser', 'network')) {
        $container = Get-MihariMemberValue -InputObject $Trial -Names @($containerName)
        if ($null -ne $container) { $targets += $container }
    }
    foreach ($target in $targets) {
        foreach ($name in $Names) {
            $value = $null
            if ($target -is [System.Collections.IDictionary]) {
                foreach ($key in $target.Keys) {
                    if ([string]::Equals([string]$key, $name, [StringComparison]::OrdinalIgnoreCase)) {
                        $value = $target[$key]
                        break
                    }
                }
            }
            else {
                $property = $target.PSObject.Properties[$name]
                if ($null -ne $property) { $value = $property.Value }
            }
            if ($null -eq $value) { continue }
            if ($value -is [System.Array] -or $value -is [System.Collections.IList]) { return ,$value }
            return $value
        }
    }
    return $null
}

function ConvertTo-MihariComparisonValue {
    param([Parameter(Mandatory = $false)][object] $Value)

    if ($null -eq $Value) { return $null }
    if ($Value -is [System.Collections.IDictionary] -or $Value -is [pscustomobject]) {
        return $null
    }
    if ($Value -is [System.Array] -or $Value -is [System.Collections.IList]) {
        if ($Value.Count -eq 0) { return '[none]' }
        $items = New-Object 'System.Collections.Generic.List[string]'
        $unsupportedItems = $false
        foreach ($item in $Value) {
            if ($null -eq $item) { continue }
            if ($item -is [System.Collections.IDictionary] -or $item -is [pscustomobject]) { $unsupportedItems = $true; continue }
            $safeItem = ConvertTo-MihariDiagnosisSafeText -Value $item
            if ($null -ne $safeItem -and -not $items.Contains($safeItem)) { $items.Add($safeItem) }
            if ($items.Count -ge 40) { break }
        }
        $orderedItems = @($items.ToArray() | Sort-Object -Unique)
        if ($unsupportedItems) { return $null }
        if ($orderedItems.Count -eq 0) { return '[none]' }
        return [string]::Join(',', $orderedItems)
    }
    return ConvertTo-MihariDiagnosisSafeText -Value $Value
}

function Get-MihariTrialConditions {
    param([Parameter(Mandatory = $true)][object] $Trial)

    $specifications = @(
        @{ name = 'mode'; aliases = @('mode', 'effectiveMode') },
        @{ name = 'protocolProfile'; aliases = @('protocolProfile', 'profileName') },
        @{ name = 'proxyAuthState'; aliases = @('proxyAuthState', 'authenticationState', 'authState') },
        @{ name = 'cacheState'; aliases = @('cacheState', 'cacheCondition') },
        @{ name = 'loginState'; aliases = @('loginState') },
        @{ name = 'browserVersion'; aliases = @('browserVersion') },
        @{ name = 'browserProfileId'; aliases = @('browserProfileId', 'ownedProfileId') },
        @{ name = 'configurationRevision'; aliases = @('configurationRevision') },
        @{ name = 'networkFingerprint'; aliases = @('networkFingerprint', 'environmentFingerprint') },
        @{ name = 'upstreamFingerprint'; aliases = @('upstreamFingerprint', 'routeFingerprint') },
        @{ name = 'effectiveProxyRoute'; aliases = @('effectiveProxyRoute', 'routeKind') },
        @{ name = 'localInspectionExclusions'; aliases = @('localInspectionExclusions', 'inspectionExclusions') }
    )
    $conditions = [ordered]@{}
    foreach ($specification in $specifications) {
        $value = Get-MihariComparisonProperty -Trial $Trial -Names $specification.aliases
        $conditions[$specification.name] = ConvertTo-MihariComparisonValue -Value $value
    }
    return [pscustomobject]$conditions
}

function Get-MihariComparisonEventObservations {
    param([Parameter(Mandatory = $false)][AllowEmptyCollection()][object[]] $Events = @())

    $observations = New-Object 'System.Collections.Generic.List[object]'
    $eventCounter = 0
    foreach ($event in $Events) {
        if ($null -eq $event) { continue }
        $eventCounter++
        $data = Get-MihariEventData -Event $event
        $hostName = ConvertTo-MihariDiagnosisSafeText -Value (Get-MihariEventValue -Event $event -Data $data -Names @('destinationHost', 'host', 'hostname', 'targetHost'))
        if ($null -eq $hostName) { continue }
        $port = ConvertTo-MihariDiagnosisSafeText -Value (Get-MihariEventValue -Event $event -Data $data -Names @('destinationPort', 'port', 'targetPort'))
        $method = ConvertTo-MihariDiagnosisSafeText -Value (Get-MihariEventValue -Event $event -Data $data -Names @('method', 'httpMethod'))
        if ($null -ne $method) { $method = $method.ToUpperInvariant() }
        $path = ConvertTo-MihariPath -Value (Get-MihariEventValue -Event $event -Data $data -Names @('path', 'requestPath', 'urlPath'))
        $stage = ConvertTo-MihariDiagnosisSafeText -Value (Get-MihariEventValue -Event $event -Data $data -Names @('stage'))
        $outcome = ConvertTo-MihariDiagnosisSafeText -Value (Get-MihariEventValue -Event $event -Data $data -Names @('outcome'))
        $mode = ConvertTo-MihariDiagnosisSafeText -Value (Get-MihariEventValue -Event $event -Data $data -Names @('mode'))
        $sessionId = ConvertTo-MihariDiagnosisSafeText -Value (Get-MihariEventValue -Event $event -Data $data -Names @('sessionId'))
        $eventId = ConvertTo-MihariDiagnosisSafeText -Value (Get-MihariEventValue -Event $event -Data $data -Names @('eventId', 'id'))
        if ($null -eq $eventId) { $eventId = 'comparison-event-' + $eventCounter.ToString('D6', [Globalization.CultureInfo]::InvariantCulture) }
        $requestId = ConvertTo-MihariDiagnosisSafeText -Value (Get-MihariEventValue -Event $event -Data $data -Names @('requestId'))
        $connectionId = ConvertTo-MihariDiagnosisSafeText -Value (Get-MihariEventValue -Event $event -Data $data -Names @('connectionId'))
        $statusValue = Get-MihariEventValue -Event $event -Data $data -Names @('statusCode', 'httpStatusCode', 'responseStatusCode')
        $status = $null
        if ($null -ne $statusValue -and [string]$statusValue -match '^([1-5][0-9][0-9])$') { $status = [int]$Matches[1] }
        $protocol = ConvertTo-MihariDiagnosisSafeText -Value (Get-MihariEventValue -Event $event -Data $data -Names @('observedProtocol', 'negotiatedProtocol', 'httpVersion', 'protocol'))
        $source = ConvertTo-MihariDiagnosisSafeText -Value (Get-MihariEventValue -Event $event -Data $data -Names @('source'))
        $errorCode = ConvertTo-MihariDiagnosisSafeText -Value (Get-MihariEventValue -Event $event -Data $data -Names @('mihariErrorCode', 'errorCode'))
        $coverage = ConvertTo-MihariDiagnosisSafeText -Value (Get-MihariEventValue -Event $event -Data $data -Names @('coverage'))
        $timestamp = ConvertTo-MihariDiagnosisSafeText -Value (Get-MihariEventValue -Event $event -Data $data -Names @('timestamp'))
        $isFailed = Test-MihariFailedOutcome -Record ([pscustomobject]@{ Outcome = $outcome })
        $stageToken = ''
        if ($null -ne $stage) { $stageToken = ($stage -replace '[^A-Za-z]', '').ToLowerInvariant() }
        $modeToken = ''
        if ($null -ne $mode) { $modeToken = ($mode -replace '[^A-Za-z]', '').ToLowerInvariant() }
        $isTunnelRelay = $modeToken -eq 'tunnel' -and $stageToken -match 'tunnelrelay|tunnelcomplete|connectioncomplete|connectionclosed' -and (Test-MihariSuccessfulOutcome -Record ([pscustomobject]@{ Outcome = $outcome }))
        $attemptOutcome = 'unknown'
        if ($null -ne $status) { $attemptOutcome = 'http_response' }
        elseif ($isFailed) { $attemptOutcome = 'failed' }
        elseif ($isTunnelRelay) { $attemptOutcome = 'transport_only' }
        $safeHost = $hostName.ToLowerInvariant()
        $signaturePort = 'unknown'
        if ($null -ne $port) { $signaturePort = $port }
        $signatureMethod = 'unknown'
        if ($null -ne $method) { $signatureMethod = $method }
        $signaturePath = 'unknown'
        if ($null -ne $path) { $signaturePath = $path }
        $signature = $safeHost + ':' + $signaturePort + '|' + $signatureMethod + '|' + $signaturePath
        if ($null -eq $method -and $null -eq $path -and $null -ne $sessionId -and $null -ne $connectionId) {
            $attemptKey = [string]$sessionId + ':connection:' + $connectionId
        }
        elseif ($null -ne $sessionId -and $null -ne $requestId) {
            $attemptKey = $sessionId + ':request:' + $requestId
        }
        elseif ($null -ne $sessionId -and $null -ne $eventId) {
            $attemptKey = $sessionId + ':event:' + $eventId
        }
        else {
            $attemptKey = 'anonymous-event:' + $eventCounter.ToString([Globalization.CultureInfo]::InvariantCulture)
        }
        $reference = [pscustomobject][ordered]@{ sessionId = $sessionId; eventId = $eventId }
        $observations.Add([pscustomobject][ordered]@{
            attemptKey = $attemptKey
            signature = $signature
            host = $hostName
            port = $port
            method = $method
            path = $path
            mode = $mode
            stage = $stage
            outcome = $attemptOutcome
            statusCode = $status
            observedProtocol = $protocol
            source = $source
            errorCode = $errorCode
            coverage = $coverage
            timestamp = $timestamp
            evidenceRefs = @($reference)
        })
    }

    $attempts = New-Object 'System.Collections.Generic.List[object]'
    $attemptIndex = @{}
    foreach ($observation in $observations) {
        if (-not $attemptIndex.ContainsKey($observation.attemptKey)) {
            $attempt = [pscustomobject][ordered]@{
                attemptKey = $observation.attemptKey
                signature = $observation.signature
                host = $observation.host
                port = $observation.port
                method = $observation.method
                path = $observation.path
                mode = $observation.mode
                outcome = $observation.outcome
                applicationOutcome = 'unknown'
                statusCode = $observation.statusCode
                observedProtocol = $observation.observedProtocol
                coverage = $observation.coverage
                stages = @()
                errorCodes = @()
                evidenceRefs = @()
            }
            $attemptIndex[$observation.attemptKey] = $attempt
            $attempts.Add($attempt)
        }
        $attempt = $attemptIndex[$observation.attemptKey]
        if ($observation.outcome -eq 'http_response') {
            $attempt.outcome = 'http_response'
            $attempt.statusCode = $observation.statusCode
        }
        elseif ($observation.outcome -eq 'failed' -and $attempt.outcome -ne 'http_response') { $attempt.outcome = 'failed' }
        elseif ($observation.outcome -eq 'transport_only' -and $attempt.outcome -eq 'unknown') { $attempt.outcome = 'transport_only' }
        if ($null -eq $attempt.observedProtocol -and $null -ne $observation.observedProtocol) { $attempt.observedProtocol = $observation.observedProtocol }
        if ($null -eq $attempt.mode -and $null -ne $observation.mode) { $attempt.mode = $observation.mode }
        if ([string]::IsNullOrWhiteSpace([string]$attempt.method) -and $null -ne $observation.method) { $attempt.method = $observation.method }
        if ([string]::IsNullOrWhiteSpace([string]$attempt.path) -and $null -ne $observation.path) { $attempt.path = $observation.path }
        if ($attempt.signature -match '\|\|$' -and $observation.signature -notmatch '\|\|$') { $attempt.signature = $observation.signature }
        if ($observation.coverage -in @('lost', 'truncated', 'unsupported', 'permission_denied')) { $attempt.coverage = $observation.coverage }
        $stages = New-Object 'System.Collections.Generic.List[string]'
        foreach ($value in @($attempt.stages)) { if (-not $stages.Contains([string]$value)) { $stages.Add([string]$value) } }
        if ($null -ne $observation.stage -and -not $stages.Contains([string]$observation.stage)) { $stages.Add([string]$observation.stage) }
        $attempt.stages = @($stages.ToArray())
        $errorCodes = New-Object 'System.Collections.Generic.List[string]'
        foreach ($value in @($attempt.errorCodes)) { if (-not $errorCodes.Contains([string]$value)) { $errorCodes.Add([string]$value) } }
        if ($null -ne $observation.errorCode -and -not $errorCodes.Contains([string]$observation.errorCode)) { $errorCodes.Add([string]$observation.errorCode) }
        $attempt.errorCodes = @($errorCodes.ToArray())
        $references = New-Object 'System.Collections.Generic.List[object]'
        $referenceKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
        foreach ($reference in @($attempt.evidenceRefs)) {
            $key = Get-MihariFindingReferenceKey -Reference $reference
            if ($referenceKeys.Add($key)) { $references.Add($reference) }
        }
        foreach ($reference in @($observation.evidenceRefs)) {
            $key = Get-MihariFindingReferenceKey -Reference $reference
            if ($referenceKeys.Add($key)) { $references.Add($reference) }
        }
        $attempt.evidenceRefs = @($references.ToArray())
    }
    return @($attempts.ToArray())
}

function Get-MihariTrialCoverage {
    param(
        [Parameter(Mandatory = $false)][object] $Trial,
        [Parameter(Mandatory = $false)][AllowEmptyCollection()][object[]] $Events = @(),
        [Parameter(Mandatory = $false)][AllowEmptyCollection()][object[]] $Attempts = @()
    )
    if ($Events.Count -eq 0) { return 'unknown' }
    $trialCoverage = $null
    if ($null -ne $Trial) { $trialCoverage = ConvertTo-MihariDiagnosisSafeText -Value (Get-MihariMemberValue -InputObject $Trial -Names @('coverage', 'coverageState')) }
    if ($trialCoverage -in @('lost', 'truncated', 'unsupported', 'permission_denied')) { return 'incomplete' }
    foreach ($attempt in $Attempts) {
        if ($attempt.coverage -in @('lost', 'truncated', 'unsupported', 'permission_denied')) { return 'incomplete' }
    }
    foreach ($event in $Events) {
        $coverage = ConvertTo-MihariDiagnosisSafeText -Value (Get-MihariEventValue -Event $event -Data (Get-MihariEventData -Event $event) -Names @('coverage'))
        if ($coverage -in @('lost', 'truncated', 'unsupported', 'permission_denied')) { return 'incomplete' }
    }
    if ($trialCoverage -eq 'observed') { return 'observed' }
    $hasObservedCoverage = $false
    foreach ($event in $Events) {
        $coverage = ConvertTo-MihariDiagnosisSafeText -Value (Get-MihariEventValue -Event $event -Data (Get-MihariEventData -Event $event) -Names @('coverage'))
        if ($coverage -eq 'observed') { $hasObservedCoverage = $true; continue }
        if ($null -eq $coverage -or $coverage -eq 'unknown') { return 'unknown' }
    }
    if ($hasObservedCoverage) { return 'observed' }
    return 'unknown'
}

function New-MihariTrialComparison {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][object] $BeforeTrial,
        [Parameter(Mandatory = $true)][object] $AfterTrial,
        [Parameter(Mandatory = $false)][AllowEmptyCollection()][object[]] $BeforeEvents = @(),
        [Parameter(Mandatory = $false)][AllowEmptyCollection()][object[]] $AfterEvents = @()
    )

    $beforeId = ConvertTo-MihariDiagnosisSafeText -Value (Get-MihariMemberValue -InputObject $BeforeTrial -Names @('trialId', 'id'))
    $afterId = ConvertTo-MihariDiagnosisSafeText -Value (Get-MihariMemberValue -InputObject $AfterTrial -Names @('trialId', 'id'))
    $beforeSessionId = ConvertTo-MihariDiagnosisSafeText -Value (Get-MihariMemberValue -InputObject $BeforeTrial -Names @('sessionId'))
    $afterSessionId = ConvertTo-MihariDiagnosisSafeText -Value (Get-MihariMemberValue -InputObject $AfterTrial -Names @('sessionId'))
    $beforeCaseId = ConvertTo-MihariDiagnosisSafeText -Value (Get-MihariMemberValue -InputObject $BeforeTrial -Names @('caseId'))
    $afterCaseId = ConvertTo-MihariDiagnosisSafeText -Value (Get-MihariMemberValue -InputObject $AfterTrial -Names @('caseId'))
    $beforeConditions = Get-MihariTrialConditions -Trial $BeforeTrial
    $afterConditions = Get-MihariTrialConditions -Trial $AfterTrial
    $changedConditions = New-Object 'System.Collections.Generic.List[object]'
    $unchangedConditions = New-Object 'System.Collections.Generic.List[string]'
    $unknownConditions = New-Object 'System.Collections.Generic.List[string]'
    $revisionChange = $null
    foreach ($conditionName in $beforeConditions.PSObject.Properties.Name) {
        $beforeValue = [string]$beforeConditions.$conditionName
        $afterValue = [string]$afterConditions.$conditionName
        if ($conditionName -eq 'configurationRevision') {
            if (-not [string]::IsNullOrWhiteSpace($beforeValue) -and -not [string]::IsNullOrWhiteSpace($afterValue) -and
                -not [string]::Equals($beforeValue, $afterValue, [System.StringComparison]::Ordinal)) {
                $revisionChange = [pscustomobject][ordered]@{ before = $beforeValue; after = $afterValue }
            }
            continue
        }
        if ([string]::IsNullOrWhiteSpace($beforeValue) -or [string]::IsNullOrWhiteSpace($afterValue)) {
            $unknownConditions.Add($conditionName)
        }
        elseif (-not [string]::Equals($beforeValue, $afterValue, [System.StringComparison]::Ordinal)) {
            $changedConditions.Add([pscustomobject][ordered]@{ name = $conditionName; before = $beforeValue; after = $afterValue })
        }
        else { $unchangedConditions.Add($conditionName) }
    }

    $beforeAttempts = @(Get-MihariComparisonEventObservations -Events $BeforeEvents)
    $afterAttempts = @(Get-MihariComparisonEventObservations -Events $AfterEvents)
    $beforeCoverage = Get-MihariTrialCoverage -Trial $BeforeTrial -Events $BeforeEvents -Attempts $beforeAttempts
    $afterCoverage = Get-MihariTrialCoverage -Trial $AfterTrial -Events $AfterEvents -Attempts $afterAttempts
    $beforeBySignature = [System.Collections.Hashtable]::new([System.StringComparer]::Ordinal)
    $afterBySignature = [System.Collections.Hashtable]::new([System.StringComparer]::Ordinal)
    foreach ($attempt in $beforeAttempts) {
        if (-not $beforeBySignature.ContainsKey($attempt.signature)) { $beforeBySignature[$attempt.signature] = New-Object 'System.Collections.Generic.List[object]' }
        $beforeBySignature[$attempt.signature].Add($attempt)
    }
    foreach ($attempt in $afterAttempts) {
        if (-not $afterBySignature.ContainsKey($attempt.signature)) { $afterBySignature[$attempt.signature] = New-Object 'System.Collections.Generic.List[object]' }
        $afterBySignature[$attempt.signature].Add($attempt)
    }
    $signatures = New-Object 'System.Collections.Generic.List[string]'
    foreach ($signature in $beforeBySignature.Keys) { if (-not $signatures.Contains([string]$signature)) { $signatures.Add([string]$signature) } }
    foreach ($signature in $afterBySignature.Keys) { if (-not $signatures.Contains([string]$signature)) { $signatures.Add([string]$signature) } }

    if ($beforeCaseId -ne $afterCaseId -or $null -eq $beforeCaseId -or $null -eq $afterCaseId) {
        $unknownConditions.Add('caseIdentity')
    }
    $comparisonKind = 'observational'
    $interpretation = 'Observed trial differences are descriptive. Recorded conditions or evidence coverage do not support a one-variable comparison.'
    if ($beforeCoverage -eq 'observed' -and $afterCoverage -eq 'observed' -and $changedConditions.Count -eq 1 -and $unknownConditions.Count -eq 0 -and $beforeCaseId -eq $afterCaseId) {
        $comparisonKind = 'single_recorded_condition_change'
        $interpretation = 'One recorded condition changed while all listed conditions remained comparable; destination matches are heuristic and do not prove request identity or a cause.'
    }
    elseif ($beforeCoverage -eq 'incomplete' -or $afterCoverage -eq 'incomplete' -or $beforeCoverage -eq 'unknown' -or $afterCoverage -eq 'unknown') {
        $comparisonKind = 'incomplete'
        $interpretation = 'Trial evidence coverage is incomplete or unknown, so differences and missing destinations require cautious review.'
    }

    $destinationChanges = New-Object 'System.Collections.Generic.List[object]'
    $addedDestinations = New-Object 'System.Collections.Generic.List[object]'
    $removedDestinations = New-Object 'System.Collections.Generic.List[object]'
    $uncertainMatches = New-Object 'System.Collections.Generic.List[object]'
    $supportedFindings = New-Object 'System.Collections.Generic.List[object]'
    foreach ($signature in $signatures) {
        $beforeMatches = @()
        $afterMatches = @()
        if ($beforeBySignature.ContainsKey($signature)) { $beforeMatches = @($beforeBySignature[$signature].ToArray()) }
        if ($afterBySignature.ContainsKey($signature)) { $afterMatches = @($afterBySignature[$signature].ToArray()) }
        if ($beforeMatches.Count -eq 0) {
            foreach ($attempt in $afterMatches) { $addedDestinations.Add($attempt) }
            continue
        }
        if ($afterMatches.Count -eq 0) {
            foreach ($attempt in $beforeMatches) { $removedDestinations.Add($attempt) }
            continue
        }
        $allReferences = New-Object 'System.Collections.Generic.List[object]'
        foreach ($attempt in @($beforeMatches) + @($afterMatches)) {
            foreach ($reference in @($attempt.evidenceRefs)) { $allReferences.Add($reference) }
        }
        $ambiguous = ($beforeMatches.Count -gt 1 -or $afterMatches.Count -gt 1)
        $beforeOutcomeSet = @($beforeMatches | ForEach-Object { [string]$_.outcome } | Sort-Object -Unique)
        $afterOutcomeSet = @($afterMatches | ForEach-Object { [string]$_.outcome } | Sort-Object -Unique)
        $outcomeRelation = 'unknown'
        if (@($beforeOutcomeSet | Where-Object { $_ -ne 'unknown' }).Count -gt 0 -and @($afterOutcomeSet | Where-Object { $_ -ne 'unknown' }).Count -gt 0) {
            if ([string]::Join(',', $beforeOutcomeSet) -eq [string]::Join(',', $afterOutcomeSet)) { $outcomeRelation = 'same_observed_outcome' }
            else { $outcomeRelation = 'different_observed_outcome' }
        }
        $change = [pscustomobject][ordered]@{
            signature = $signature
            matchKind = 'heuristic'
            ambiguous = [bool]$ambiguous
            ambiguity = 'The destination, method, and redacted path match; distinct cross-trial requests cannot be proven from these fields alone.'
            before = @($beforeMatches)
            after = @($afterMatches)
            outcomeRelation = $outcomeRelation
            evidenceRefs = @($allReferences.ToArray())
        }
        $destinationChanges.Add($change)
        if ($ambiguous) { $uncertainMatches.Add($change) }

        $beforeMode = ([string]$beforeConditions.mode).ToLowerInvariant()
        $afterMode = ([string]$afterConditions.mode).ToLowerInvariant()
        if ($comparisonKind -eq 'single_recorded_condition_change' -and
            (($beforeMode -eq 'inspect' -and $afterMode -eq 'tunnel') -or ($beforeMode -eq 'tunnel' -and $afterMode -eq 'inspect'))) {
            $allMatches = @($beforeMatches) + @($afterMatches)
            $inspectAttempts = @($allMatches | Where-Object {
                ([string]$_.mode).ToLowerInvariant() -eq 'inspect' -and $_.outcome -eq 'failed' -and
                (@($_.stages | Where-Object { ([string]$_ -replace '[^A-Za-z]', '').ToLowerInvariant() -match 'clienttls|tlsclient|inspecttlsclient' }).Count -gt 0)
            })
            $tunnelAttempts = @($allMatches | Where-Object {
                ([string]$_.mode).ToLowerInvariant() -eq 'tunnel' -and $_.outcome -eq 'transport_only' -and
                (@($_.stages | Where-Object { ([string]$_ -replace '[^A-Za-z]', '').ToLowerInvariant() -match 'tunnelrelay|tunnelcomplete|connectioncomplete|connectionclosed' }).Count -gt 0)
            })
            if ($inspectAttempts.Count -gt 0 -and $tunnelAttempts.Count -gt 0) {
                $tlsEvidenceRefs = New-Object 'System.Collections.Generic.List[object]'
                $tlsReferenceKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
                foreach ($attempt in @($inspectAttempts) + @($tunnelAttempts)) {
                    foreach ($reference in @($attempt.evidenceRefs)) {
                        if ($tlsReferenceKeys.Add((Get-MihariFindingReferenceKey -Reference $reference))) { $tlsEvidenceRefs.Add($reference) }
                    }
                }
                $tlsFindingId = Get-MihariStableFindingId -Identity ([pscustomobject][ordered]@{
                    ruleVersion = 'mihari-comparison/1'
                    code = 'tls_interception_incompatible'
                    beforeTrialId = $beforeId
                    afterTrialId = $afterId
                    destination = $signature
                })
                $tlsEvidenceIds = @($tlsEvidenceRefs.ToArray() | ForEach-Object { [string]$_.eventId } | Select-Object -Unique)
                $supportedFindings.Add([pscustomobject][ordered]@{
                    findingId = $tlsFindingId
                    code = 'tls_interception_incompatible'
                    summary = 'Inspect client TLS failed while the comparable Tunnel relay completed for ' + $beforeMatches[0].host + ':' + $beforeMatches[0].port + '.'
                    scope = 'host'
                    classification = 'interception_compatibility'
                    evidenceStrength = 'comparison_supported'
                    ruleVersion = 'mihari-comparison/1'
                    evidenceRefs = @($tlsEvidenceRefs.ToArray())
                    evidenceIds = $tlsEvidenceIds
                    interpretation = 'The client-facing TLS handshake failed during Inspect while a condition-matched Tunnel relay completed. This supports a difference at the interception stage.'
                    limitations = 'Tunnel relay activity does not prove application success. This does not distinguish certificate pinning, mTLS, or another client/application behavior.'
                    nextCheck = 'Collect browser request and initiator evidence from a comparable trial before identifying the application-level impact.'
                })
            }
        }
    }

    if ($uncertainMatches.Count -gt 0 -and $comparisonKind -eq 'single_recorded_condition_change') {
        $interpretation += ' Multiple attempts share a destination signature, so individual outcomes remain ambiguously matched.'
    }

    $evidenceStrength = 'undetermined'
    if ($comparisonKind -eq 'single_recorded_condition_change') { $evidenceStrength = 'comparison_supported' }

    $comparisonHashId = Get-MihariStableFindingId -Identity ([pscustomobject][ordered]@{ beforeTrialId = $beforeId; beforeSessionId = $beforeSessionId; afterTrialId = $afterId; afterSessionId = $afterSessionId })
    return [pscustomobject][ordered]@{
        schemaVersion = 1
        comparisonId = 'comparison-' + $comparisonHashId.Substring(8)
        before = [pscustomobject][ordered]@{ trialId = $beforeId; sessionId = $beforeSessionId; caseId = $beforeCaseId; conditions = $beforeConditions; coverage = $beforeCoverage; attemptCount = $beforeAttempts.Count }
        after = [pscustomobject][ordered]@{ trialId = $afterId; sessionId = $afterSessionId; caseId = $afterCaseId; conditions = $afterConditions; coverage = $afterCoverage; attemptCount = $afterAttempts.Count }
        changedConditions = @($changedConditions.ToArray())
        unchangedConditions = @($unchangedConditions.ToArray())
        unknownConditions = @($unknownConditions.ToArray() | Select-Object -Unique)
        configurationRevisionChange = $revisionChange
        addedDestinations = @($addedDestinations.ToArray())
        removedDestinations = @($removedDestinations.ToArray())
        destinationChanges = @($destinationChanges.ToArray())
        uncertainMatches = @($uncertainMatches.ToArray())
        supportedFindings = @($supportedFindings.ToArray())
        comparisonKind = $comparisonKind
        evidenceStrength = $evidenceStrength
        interpretation = $interpretation
        limitations = 'HTTP status is endpoint-visible response evidence, not proof of business success. Tunnel bytes prove transport activity only. URL and method similarity creates a heuristic edge; it does not merge request identities.'
        ruleVersion = 'mihari-comparison/1'
    }
}
