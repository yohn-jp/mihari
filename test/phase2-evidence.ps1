param()

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'TestSupport.ps1')
$evidenceSourceRoot = Join-Path (Split-Path $PSScriptRoot -Parent) 'src'
. (Join-Path $evidenceSourceRoot 'Evidence.ps1')
. (Join-Path $evidenceSourceRoot 'Diagnosis.ps1')

$compressionAssembly = Ensure-MihariEvidenceCompression
Assert-MihariTest -Condition ($null -ne $compressionAssembly.GetType('System.IO.Compression.ZipArchive', $false)) -Message 'The current PowerShell runtime must load its platform ZIP archive API.'

function New-MihariEvidenceTestZip {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Files, [string]$SymlinkEntry)
    $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
    $archive = $null
    try {
        $archive = [System.IO.Compression.ZipArchive]::new($stream, [System.IO.Compression.ZipArchiveMode]::Create, $true)
        foreach ($name in $Files.Keys) {
            $entry = $archive.CreateEntry([string]$name, [System.IO.Compression.CompressionLevel]::Optimal)
            if ($name -eq $SymlinkEntry) { $entry.ExternalAttributes = -1610612736 }
            $entryStream = $entry.Open()
            try {
                $bytes = [byte[]]$Files[$name]
                $entryStream.Write($bytes, 0, $bytes.Length)
            }
            finally { $entryStream.Dispose() }
        }
    }
    finally {
        if ($null -ne $archive) { $archive.Dispose() }
        $stream.Dispose()
    }
}

function ConvertTo-MihariEvidenceTestBytes {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Text)
    return ,([System.Text.UTF8Encoding]::new($false).GetBytes($Text))
}

function Get-MihariEvidenceTestZipText {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][string]$EntryName)
    $stream = [System.IO.File]::OpenRead($Path)
    $archive = $null
    $reader = $null
    try {
        $archive = [System.IO.Compression.ZipArchive]::new($stream, [System.IO.Compression.ZipArchiveMode]::Read, $false)
        $entry = $archive.GetEntry($EntryName)
        if ($null -eq $entry) { throw ('Missing zip entry {0}.' -f $EntryName) }
        $reader = New-Object System.IO.StreamReader($entry.Open(), [System.Text.Encoding]::UTF8)
        return $reader.ReadToEnd()
    }
    finally {
        if ($null -ne $reader) { $reader.Dispose() }
        if ($null -ne $archive) { $archive.Dispose() }
        $stream.Dispose()
    }
}

$temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('mihari-evidence-test-' + [Guid]::NewGuid().ToString('N'))
[void][System.IO.Directory]::CreateDirectory($temporaryRoot)
try {
    $bundlePath = Join-Path $temporaryRoot 'case.mihari.zip'
    $case = [pscustomobject]@{
        caseId = 'CASE_SECRET_483'
        title = 'Login flow for https://intranet.corp/users/alice?ticket=CASE_QUERY_SECRET'
        notes = 'Bearer CASE_NOTE_TOKEN_SECRET; open https://intranet.corp/classified/customer-77?lookup=CASE_PATH_QUERY_SECRET'
        sessionRefs = @('SESSION_SECRET_123')
        trialRefs = @('TRIAL_SECRET_456')
        ignored = 'CASE_IGNORED_SECRET'
    }
    $firstEvent = [pscustomobject]@{
        schemaVersion = 2; sequence = 1; timestamp = '2026-01-01T00:00:00Z'; eventId = 'EVENT_SECRET_1'
        sessionId = 'SESSION_SECRET_123'; connectionId = 'CONNECTION_SECRET_1'; requestId = 'REQUEST_SECRET_1'
        mode = 'Inspect'; stage = 'upstream.proxy.connect'; outcome = 'rejected'; elapsedMs = 3; source = 'proxy'; coverage = 'observed';
        transportLeg = 'client'; data = [pscustomobject]@{
            host = 'intranet.corp'; path = '/classified/customer-77'; url = 'https://intranet.corp/classified/customer-77?ticket=EVENT_QUERY_SECRET'
            method = 'GET'; routeKind = 'ExplicitProxy'; explicitProxy = $true; proxyStatus = 407
            authorization = 'Bearer EVENT_AUTH_SECRET'; cookie = 'EVENT_COOKIE_SECRET'; body = 'EVENT_BODY_SECRET'
            debuggerAddress = 'http://127.0.0.1:9222/json/version'; secret = 'EVENT_SECRET_FIELD'; username = 'alice'
            reason = 'Bearer EVENT_ERROR_TOKEN_SECRET at C:\Users\alice\private\error.txt'
        }
        credentialBlob = 'EVENT_TOP_SECRET'
    }
    $secondEvent = [pscustomobject]@{
        schemaVersion = 2; sequence = 2; timestamp = '2026-01-01T00:00:03Z'; eventId = 'EVENT_SECRET_2'
        sessionId = 'SESSION_SECRET_123'; connectionId = 'CONNECTION_SECRET_2'; requestId = 'REQUEST_SECRET_2'
        mode = 'Inspect'; stage = 'http.response'; outcome = 'observed'; elapsedMs = 5; source = 'proxy'; coverage = 'observed';
        transportLeg = 'upstream'; data = [pscustomobject]@{ host = 'intranet.corp'; path = '/classified/customer-77'; method = 'GET'; statusCode = 200 }
    }
    $annotation = [pscustomobject]@{ markerId = 'MARKER_SECRET_1'; trialId = 'TRIAL_SECRET_456'; timestamp = '2026-01-01T00:00:01Z'; label = 'Upload'; note = 'path https://intranet.corp/private/upload?secret=ANNOTATION_QUERY_SECRET' }
    $trial = [pscustomobject]@{ trialId = 'TRIAL_SECRET_456'; caseId = 'CASE_SECRET_483'; sessionId = 'SESSION_SECRET_123'; startedAtUtc = '2026-01-01T00:00:00Z'; businessOutcome = 'Upload succeeded'; profile = [pscustomobject]@{ mode = 'Inspect'; protocol = 'HTTP/1.1'; debuggerAddress = 'PROFILE_DEBUG_SECRET' } }
    $finding = [pscustomobject]@{ findingId = 'FINDING_SECRET_1'; ruleVersion = 'rules-1'; classification = 'upstream_proxy_rejected'; summary = 'Observed'; limitations = 'No appliance rule attribution'; evidenceIds = @('EVENT_SECRET_1') }
    $result = [pscustomobject]@{ ruleVersion = 'rules-1'; generatedAtUtc = '2026-01-01T00:00:02Z'; findings = @($finding); debuggerUrl = 'RESULT_DEBUG_SECRET' }
    $preview = New-MihariEvidenceBundlePreview -Case $case -Trials @($trial) -Events @($firstEvent, $secondEvent) -Annotations @($annotation) -Findings @($finding) -OriginalResult $result -DiagnosticProfile ([pscustomobject]@{ mode = 'Inspect'; tlsVersion = 'TLS 1.2'; debuggerAddress = 'PROFILE_DEBUG_SECRET' }) -EnvironmentSnapshots @([pscustomobject]@{ runtime = 'PowerShell'; proxyHost = 'proxy.corp'; browserVersion = 'Edge 1'; apiToken = 'ENV_SECRET_TOKEN' }) -CaptureCoverage ([pscustomobject]@{ coverage = 'observed'; body = 'COVERAGE_BODY_SECRET' }) -RuleVersion 'rules-1' -ApplicationRevision 'commit-abc'
    Assert-MihariTest -Condition ($preview.schemaVersion -eq 1 -and @($preview.included).Count -ge 4) -Message 'The export preview must enumerate versioned bundle files and records.'
    Assert-MihariTest -Condition (@($preview.redacted).Count -ge 3 -and $preview.warning -match 'do not prove authorship') -Message 'The preview must state redaction categories and the limit of hashes.'

    $export = Export-MihariEvidenceBundle -DestinationPath $bundlePath -Case $case -Trials @($trial) -Events @($firstEvent, $secondEvent) -Annotations @($annotation) -Findings @($finding) -OriginalResult $result -DiagnosticProfile ([pscustomobject]@{ mode = 'Inspect'; tlsVersion = 'TLS 1.2'; debuggerAddress = 'PROFILE_DEBUG_SECRET' }) -EnvironmentSnapshots @([pscustomobject]@{ runtime = 'PowerShell'; proxyHost = 'proxy.corp'; browserVersion = 'Edge 1'; apiToken = 'ENV_SECRET_TOKEN' }) -CaptureCoverage ([pscustomobject]@{ coverage = 'observed'; body = 'COVERAGE_BODY_SECRET' }) -RuleVersion 'rules-1' -ApplicationRevision 'commit-abc'
    Assert-MihariTest -Condition ([IO.File]::Exists($bundlePath) -and $export.sha256 -match '^[0-9a-f]{64}$') -Message 'Export must create a bundle with a SHA-256 summary.'
    $combined = (Get-MihariEvidenceTestZipText -Path $bundlePath -EntryName 'manifest.json') + (Get-MihariEvidenceTestZipText -Path $bundlePath -EntryName 'events.jsonl') + (Get-MihariEvidenceTestZipText -Path $bundlePath -EntryName 'annotations.jsonl') + (Get-MihariEvidenceTestZipText -Path $bundlePath -EntryName 'environment.json') + (Get-MihariEvidenceTestZipText -Path $bundlePath -EntryName 'original-result.json')
    foreach ($secret in @('CASE_QUERY_SECRET', 'CASE_NOTE_TOKEN_SECRET', 'CASE_PATH_QUERY_SECRET', 'EVENT_QUERY_SECRET', 'EVENT_AUTH_SECRET', 'EVENT_COOKIE_SECRET', 'EVENT_BODY_SECRET', 'EVENT_SECRET_FIELD', 'EVENT_TOP_SECRET', 'EVENT_ERROR_TOKEN_SECRET', 'PROFILE_DEBUG_SECRET', 'ENV_SECRET_TOKEN', 'COVERAGE_BODY_SECRET', 'ANNOTATION_QUERY_SECRET', 'RESULT_DEBUG_SECRET', 'intranet.corp', 'classified/customer-77')) {
        Assert-MihariTest -Condition (-not $combined.Contains($secret)) -Message ('Evidence export must redact secret sentinel {0}.' -f $secret)
    }
    Assert-MihariTest -Condition ($combined.Contains('[REDACTED]')) -Message 'Query values and credential-like text must leave an explicit redaction marker.'

    $importRoot = Join-Path $temporaryRoot 'imports'
    $imported = Import-MihariEvidenceBundle -ArchivePath $bundlePath -DestinationDirectory $importRoot
    Assert-MihariTest -Condition ($imported.success -and $imported.sourceHashVerified -and $imported.importedEventCount -eq 2) -Message 'Import must validate and round-trip safe event records.'
    $offline = Read-MihariOfflineEvidenceCase -CaseDirectory $imported.caseDirectory
    Assert-MihariTest -Condition ($offline.readOnly -and -not $offline.capabilities.capture -and -not $offline.capabilities.browserLaunch -and -not $offline.capabilities.trustMutation) -Message 'Offline review must expose read-only capabilities only.'
    Assert-MihariTest -Condition ($offline.events.Count -eq 2 -and $offline.events[0].data.host -eq $offline.events[1].data.host) -Message 'Pseudonyms must remain stable within an imported case.'
    Assert-MihariTest -Condition ($offline.events[0].sessionId -eq $offline.manifest.case.sessionRefs[0] -and $offline.events[0].eventId -eq $offline.findings[0].evidenceRefs[0].eventId) -Message 'Pseudonymized cross-record references must remain joinable.'
    Assert-MihariTest -Condition ($null -ne $offline.originalResult -and $offline.originalResult.findings.Count -eq 1) -Message 'Import must preserve the original diagnosis result.'
    $reanalyzed = New-MihariOfflineReanalysisRecord -OfflineCase $offline -RuleVersion 'rules-2' -Findings @($finding)
    Assert-MihariTest -Condition ($reanalyzed.originalResultPreserved -and $reanalyzed.originalResult.ruleVersion -eq 'rules-1' -and $reanalyzed.ruleVersion -eq 'rules-2') -Message 'Offline reanalysis must record its rule version and preserve the original result.'

    $script:offlineSideEffectCalls = 0
    function New-MihariSession { $script:offlineSideEffectCalls++; throw 'Offline review must not create a session.' }
    function New-MihariCA { $script:offlineSideEffectCalls++; throw 'Offline review must not create a CA.' }
    function Install-MihariCARoot { $script:offlineSideEffectCalls++; throw 'Offline review must not install CA trust.' }
    function Start-MihariListener { $script:offlineSideEffectCalls++; throw 'Offline review must not bind a proxy listener.' }
    function Start-MihariManagementListener { $script:offlineSideEffectCalls++; throw 'Offline review must not bind a management listener.' }
    function Start-MihariBrowser { $script:offlineSideEffectCalls++; throw 'Offline review must not start a browser.' }
    function Set-MihariSessionMode { $script:offlineSideEffectCalls++; throw 'Offline review must not mutate a session.' }
    $offlineReview = Open-MihariOfflineEvidenceReview -CaseDirectory $imported.caseDirectory -RuleVersion 'rules-2' -MaximumEvidenceBytes 8388608 -MaximumEvents 20
    Assert-MihariTest -Condition ($offlineReview.readOnly -and $offlineReview.reanalysis.findings.Count -eq 1 -and $offlineReview.reanalysis.findings[0].code -eq 'upstream_proxy_auth_required') -Message 'Offline reanalysis must use the canonical diagnosis rules over the saved case.'
    Assert-MihariTest -Condition ($offlineReview.reanalysis.findings[0].evidenceRefs[0].eventId -eq $offline.events[0].eventId) -Message 'Offline reanalysis evidence references must still drill down to the saved pseudonymized event.'
    Assert-MihariTest -Condition ($offlineReview.reanalysis.originalResult.ruleVersion -eq 'rules-1' -and $offlineReview.reanalysis.ruleVersion -eq 'rules-2') -Message 'Offline reanalysis must preserve the original result alongside its new rule version.'
    $offlineReviewJsonBytes = [System.Text.Encoding]::UTF8.GetByteCount((ConvertTo-Json -InputObject $offlineReview -Depth 32 -Compress))
    Assert-MihariTest -Condition ($offlineReview.limits.evidenceBytesRead -le $offlineReview.limits.maximumEvidenceBytes -and $offlineReview.limits.resultBytes -eq $offlineReviewJsonBytes -and $offlineReview.limits.resultBytes -le $offlineReview.limits.maximumResultBytes) -Message 'Offline review must report measured evidence and response bounds.'
    Assert-MihariTest -Condition ($script:offlineSideEffectCalls -eq 0) -Message 'Offline loading and reanalysis must not create sessions, listeners, browsers, or CA trust.'
    Assert-MihariTestThrows -Action { Open-MihariOfflineEvidenceReview -CaseDirectory $imported.caseDirectory -RuleVersion 'rules-2' -MaximumEvents 1 } -Message 'Offline reanalysis must enforce the event-count bound.'
    Assert-MihariTestThrows -Action { Open-MihariOfflineEvidenceReview -CaseDirectory $imported.caseDirectory -RuleVersion 'rules-2' -MaximumEvidenceBytes 1024 } -Message 'Offline reanalysis must enforce the evidence byte bound.'

    $badHashPath = Join-Path $temporaryRoot 'bad-hash.zip'
    $sourceFiles = @{}
    $stream = [IO.File]::OpenRead($bundlePath)
    $archive = [System.IO.Compression.ZipArchive]::new($stream, [System.IO.Compression.ZipArchiveMode]::Read, $false)
    try {
        foreach ($entry in $archive.Entries) {
            $entryStream = $entry.Open()
            $memory = New-Object IO.MemoryStream
            try { $entryStream.CopyTo($memory); $sourceFiles[$entry.FullName] = $memory.ToArray() }
            finally { $entryStream.Dispose(); $memory.Dispose() }
        }
    }
    finally { $archive.Dispose(); $stream.Dispose() }
    $changedEvents = [System.Text.Encoding]::UTF8.GetString([byte[]]$sourceFiles['events.jsonl']).Replace('observed', 'changed')
    $sourceFiles['events.jsonl'] = ConvertTo-MihariEvidenceTestBytes -Text $changedEvents
    New-MihariEvidenceTestZip -Path $badHashPath -Files $sourceFiles
    Assert-MihariTestThrows -Action { Import-MihariEvidenceBundle -ArchivePath $badHashPath -DestinationDirectory (Join-Path $temporaryRoot 'bad-hash-import') } -Message 'Import must reject a modified file whose manifest hash no longer matches.'

    $unknownBundle = New-MihariEvidenceBundleContent -Case $case -Events @($firstEvent) -RuleVersion 'rules-1'
    $unknownFiles = @{}
    foreach ($name in $unknownBundle.Files.Keys) { $unknownFiles[$name] = [byte[]]$unknownBundle.Files[$name] }
    $unknownEvent = '{"schemaVersion":99,"source":"future","eventId":"DO_NOT_EXECUTE"}'
    $eventText = [System.Text.Encoding]::UTF8.GetString([byte[]]$unknownFiles['events.jsonl']) + $unknownEvent + "`n"
    $unknownFiles['events.jsonl'] = ConvertTo-MihariEvidenceTestBytes -Text $eventText
    $unknownManifest = ConvertFrom-MihariEvidenceJsonBytes -Bytes ([byte[]]$unknownFiles['manifest.json']) -Name 'manifest.json'
    foreach ($record in $unknownManifest.files) {
        if ($record.path -eq 'events.jsonl') {
            $record.bytes = ([byte[]]$unknownFiles['events.jsonl']).Length
            $record.sha256 = (Get-MihariEvidenceSha256Bytes -Bytes ([byte[]]$unknownFiles['events.jsonl']))
            $record.recordCount = 2
        }
    }
    $unknownFiles['manifest.json'] = ConvertTo-MihariEvidenceJsonBytes -Value $unknownManifest
    $unknownPath = Join-Path $temporaryRoot 'unknown-record.zip'
    New-MihariEvidenceTestZip -Path $unknownPath -Files $unknownFiles
    $unknownImport = Import-MihariEvidenceBundle -ArchivePath $unknownPath -DestinationDirectory (Join-Path $temporaryRoot 'unknown-import')
    Assert-MihariTest -Condition ($unknownImport.unknownRecordCount -eq 1 -and $unknownImport.importedEventCount -eq 1) -Message 'Unknown schema records must be reported and excluded from accepted facts.'
    $unknownOffline = Read-MihariOfflineEvidenceCase -CaseDirectory $unknownImport.caseDirectory
    Assert-MihariTest -Condition ($unknownOffline.importReport.unknownRecords[0].reason -eq 'unknown_schema') -Message 'The offline import report must retain a safe unknown-schema reason.'

    $traversalPath = Join-Path $temporaryRoot 'traversal.zip'
    New-MihariEvidenceTestZip -Path $traversalPath -Files @{ '../escape.txt' = (ConvertTo-MihariEvidenceTestBytes -Text 'no') }
    Assert-MihariTestThrows -Action { Import-MihariEvidenceBundle -ArchivePath $traversalPath -DestinationDirectory (Join-Path $temporaryRoot 'traversal-import') } -Message 'Import must reject archive traversal paths.'
    $symlinkPath = Join-Path $temporaryRoot 'symlink.zip'
    New-MihariEvidenceTestZip -Path $symlinkPath -Files @{ 'events.jsonl' = (ConvertTo-MihariEvidenceTestBytes -Text '') } -SymlinkEntry 'events.jsonl'
    Assert-MihariTestThrows -Action { Import-MihariEvidenceBundle -ArchivePath $symlinkPath -DestinationDirectory (Join-Path $temporaryRoot 'symlink-import') } -Message 'Import must reject archive symlink entries.'
    $bombPath = Join-Path $temporaryRoot 'bomb.zip'
    $bombBytes = New-Object byte[] 2097152
    New-MihariEvidenceTestZip -Path $bombPath -Files @{ 'events.jsonl' = $bombBytes }
    Assert-MihariTestThrows -Action { Import-MihariEvidenceBundle -ArchivePath $bombPath -DestinationDirectory (Join-Path $temporaryRoot 'bomb-import') -MaximumEntryBytes 3145728 -MaximumExpandedBytes 3145728 } -Message 'Import must reject a decompression bomb ratio before saving its output.'

    $formula = ConvertTo-MihariSafeCsvCell -Value '  =HYPERLINK("https://evil.test","open")'
    Assert-MihariTest -Condition ($formula.StartsWith('"''  =') -and $formula.Contains('""https://evil.test""')) -Message 'CSV output must neutralize formula-like cells and escape embedded quotes.'
    foreach ($formulaPrefix in @('=1+1', '+SUM(A1:A2)', '-1+1', '@SUM(A1:A2)', "`t=1+1")) {
        $safeCell = ConvertTo-MihariSafeCsvCell -Value $formulaPrefix
        Assert-MihariTest -Condition ($safeCell.StartsWith('"''')) -Message ('CSV formula prefix must be escaped: {0}' -f $formulaPrefix)
    }

    $localManifestPath = Join-Path $imported.caseDirectory 'manifest.json'
    $localManifest = ConvertFrom-MihariEvidenceJsonBytes -Bytes ([IO.File]::ReadAllBytes($localManifestPath)) -Name 'manifest.json'
    $localManifest.createdAtUtc = '2000-01-01T00:00:00Z'
    [IO.File]::WriteAllBytes($localManifestPath, (ConvertTo-MihariEvidenceJsonBytes -Value $localManifest))
    $unrelatedDirectory = Join-Path $importRoot 'user-data'
    [void][IO.Directory]::CreateDirectory($unrelatedDirectory)
    [IO.File]::WriteAllText((Join-Path $unrelatedDirectory 'notes.txt'), 'leave me alone')
    $plan = Get-MihariEvidenceRetentionPlan -RootPath $importRoot -OlderThanUtc ([DateTime]::Parse('2020-01-01T00:00:00Z').ToUniversalTime())
    Assert-MihariTest -Condition (@($plan.eligible).Count -eq 1 -and @($plan.refused | Where-Object { $_.reason -eq 'no_mihari_manifest' }).Count -eq 1) -Message 'Retention must target verified Mihari cases and refuse unmarked directories.'
    Assert-MihariTestThrows -Action { Invoke-MihariEvidenceRetentionCleanup -RootPath $importRoot -OlderThanUtc ([DateTime]::Parse('2020-01-01T00:00:00Z').ToUniversalTime()) } -Message 'Retention deletion must require explicit confirmation.'
    $cleanup = Invoke-MihariEvidenceRetentionCleanup -RootPath $importRoot -OlderThanUtc ([DateTime]::Parse('2020-01-01T00:00:00Z').ToUniversalTime()) -ConfirmDeletion
    Assert-MihariTest -Condition ($cleanup.deleted.Count -eq 1 -and [IO.Directory]::Exists($unrelatedDirectory)) -Message 'Confirmed retention must remove only old verified cases.'

    $distributionRoot = Join-Path $temporaryRoot 'distribution'
    [void][IO.Directory]::CreateDirectory((Join-Path $distributionRoot 'src'))
    [IO.File]::WriteAllText((Join-Path $distributionRoot 'mihari.ps1'), 'entry')
    [IO.File]::WriteAllText((Join-Path $distributionRoot 'src/Evidence.ps1'), 'source')
    $distributionPath = Join-Path $distributionRoot 'distribution-manifest.json'
    $distributionManifest = New-MihariDistributionManifest -RootPath $distributionRoot -OutputPath $distributionPath -ApplicationRevision 'test' -CommitId 'abc123'
    $verify = Test-MihariDistributionManifest -RootPath $distributionRoot -ManifestPath $distributionPath
    Assert-MihariTest -Condition ($verify.valid -and $verify.checkedFiles -eq 2 -and -not $verify.authenticityVerified) -Message 'Distribution manifests must verify SHA-256 inventory while making no authenticity claim.'
    [IO.File]::AppendAllText((Join-Path $distributionRoot 'src/Evidence.ps1'), 'changed')
    $modified = Test-MihariDistributionManifest -RootPath $distributionRoot -ManifestPath $distributionPath
    Assert-MihariTest -Condition (-not $modified.valid -and $modified.errors -contains 'hash_or_length_mismatch') -Message 'Distribution verification must detect post-manifest file changes.'

    Write-Host '[evidence] portable bundle, privacy, import bounds, offline review, retention, CSV, and distribution manifest passed'
}
finally {
    if ([System.IO.Directory]::Exists($temporaryRoot)) { [System.IO.Directory]::Delete($temporaryRoot, $true) }
}
