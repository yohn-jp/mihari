# Distribution and optional enterprise signing

Mihari distribution verification uses a SHA-256 inventory. The inventory detects
files changed after it was generated; it does not identify the publisher or prove
that a package came from a trusted build. Mihari does not create a signing key or
require an operator to enroll a certificate.

## Create and verify an inventory

Stage the release in a clean directory. Exclude session output, case bundles,
browser profiles, temporary key files, private keys, debugger controls, and other
runtime state. `src/Evidence.ps1` rejects common key/debugger artifacts and
reparse points when it generates a manifest.

```powershell
. .\src\Evidence.ps1
$manifest = New-MihariDistributionManifest `
    -RootPath .\release `
    -OutputPath .\release\distribution-manifest.json `
    -ApplicationRevision '2.0.0' `
    -CommitId '0123456789abcdef'

$check = Test-MihariDistributionManifest `
    -RootPath .\release `
    -ManifestPath .\release\distribution-manifest.json
if (-not $check.valid) { throw ('Distribution files failed verification: ' + ($check.errors -join ', ')) }
```

The manifest lists each packaged relative path, byte length, and SHA-256 digest.
Keep it beside the package or in the organization's trusted release record.
Verify the inventory after transfer and before running scripts. Protect the
manifest itself through the organization's release channel; a party able to
replace both files and the inventory can recompute the hashes.

## Optional code signing

An enterprise can sign release PowerShell scripts or a release catalog with an
organization-controlled Authenticode certificate under its existing approval
and key-protection process. Sign the final files first, then generate the SHA-256
inventory so the listed hashes cover the signed bytes. Verify signatures with
Windows Authenticode policy and verify the inventory independently. A locally
generated self-signed certificate is not a Mihari publisher identity. Mihari
does not request trust enrollment, alter certificate stores for distribution,
or require signing for runtime use.

## Case evidence bundles

Portable case bundles have a separate versioned manifest and per-file SHA-256
digests. Their hashes are modification checks only; they are not signatures,
proof of authorship, or evidence that the original acquisition was complete.
Preview the included records and redactions before sharing a bundle. Query
values are redacted; share-time pseudonyms can consistently mask hostnames,
usernames, paths, and identifiers within one bundle. Secret-bearing paths in
free text should be reviewed in the preview before distribution.

Import treats the archive as untrusted data. Mihari accepts only recognized
flat bundle paths and bounded JSON/JSONL records, checks every declared hash,
and sanitizes supported records into a new local case. Unsupported schema or
source records appear in the import report with their line and reason; their raw
contents are not retained. Offline review is read-only and does not start a
proxy, launch a browser, or create certificate trust.

## Retention

Review cleanup candidates before confirming deletion. Retention walks only the
immediate child case directories below the selected root, checks their Mihari
bundle marker and listed file hashes, and refuses unknown files and reparse
points. Deletion requires the explicit `-ConfirmDeletion` switch.

```powershell
$cutoff = [DateTime]::UtcNow.AddDays(-90)
$plan = Get-MihariEvidenceRetentionPlan -RootPath $caseRoot -OlderThanUtc $cutoff
$plan.eligible | Format-Table bundleId, createdAtUtc, path

# Run only after the operator has reviewed the plan.
$result = Invoke-MihariEvidenceRetentionCleanup `
    -RootPath $caseRoot -OlderThanUtc $cutoff -ConfirmDeletion
```

## Offline review

The application loads `Evidence.ps1` and the existing `Diagnosis.ps1` rules before
calling `Open-MihariOfflineEvidenceReview`. The helper checks a locally imported
case directory's file hashes and schema, applies the same diagnosis rules, and
returns a new rule-versioned result beside the original result. These checks do
not authenticate the source bundle. It has finite evidence-byte, event-count,
and serialized-result limits. It does not call session, listener, browser, or
certificate-trust operations.

```powershell
$review = Open-MihariOfflineEvidenceReview `
    -CaseDirectory $savedCaseDirectory `
    -RuleVersion 'mihari-rules-2026-09' `
    -MaximumEvidenceBytes 16777216 `
    -MaximumEvents 10000 `
    -MaximumResultBytes 4194304
```
