function Invoke-MihariCleanup {
    [CmdletBinding()]
    param([string]$OutputRoot)

    $root = Get-MihariDefaultOutputRoot -OutputRoot $OutputRoot
    $removed = New-Object System.Collections.ArrayList
    $refused = New-Object System.Collections.ArrayList
    $errors = New-Object System.Collections.ArrayList
    if (-not [System.IO.Directory]::Exists($root)) {
        return [pscustomobject]@{
            removed = @()
            refused = @()
            errors = @()
            removedCount = 0
        }
    }

    $store = $null
    $certificates = $null
    try {
        $store = [System.Security.Cryptography.X509Certificates.X509Store]::new(
            [System.Security.Cryptography.X509Certificates.StoreName]::Root,
            [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
        )
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        $certificates = $store.Certificates
    }
    catch {
        [void]$errors.Add([pscustomobject]@{
            operation = 'open_current_user_root'
            errorType = $_.Exception.GetType().FullName
        })
        if ($null -ne $store) {
            try { $store.Close() }
            catch { [void]$errors.Add([pscustomobject]@{ operation = 'close_current_user_root'; errorType = $_.Exception.GetType().FullName }) }
        }
        return [pscustomobject]@{
            removed = @($removed.ToArray())
            refused = @($refused.ToArray())
            errors = @($errors.ToArray())
            removedCount = $removed.Count
        }
    }

    try {
        foreach ($certificate in $certificates) {
            $subject = [string]$certificate.Subject
            if ($subject -cnotmatch '^CN=Mihari Ephemeral Diagnostic CA ') { continue }

            $thumbprint = [string]$certificate.Thumbprint
            $sessionId = $null
            if ($subject -cmatch '^CN=Mihari Ephemeral Diagnostic CA ([0-9a-f]{32})$') {
                $sessionId = $matches[1]
            }
            if ([string]::IsNullOrWhiteSpace($sessionId)) {
                [void]$refused.Add([pscustomobject]@{
                    subject = $subject
                    thumbprint = $thumbprint
                    reason = 'subject_does_not_match_the_exact_Mihari_session_CA_format'
                })
                continue
            }

            $owned = $false
            if (Get-Command Test-MihariCAOwnership -ErrorAction SilentlyContinue) {
                try { $owned = [bool](Test-MihariCAOwnership -Certificate $certificate -Thumbprint $thumbprint) }
                catch { $owned = $false }
            }
            if (-not $owned) {
                [void]$refused.Add([pscustomobject]@{
                    sessionId = $sessionId
                    subject = $subject
                    thumbprint = $thumbprint
                    reason = 'certificate_ownership_markers_failed'
                })
                continue
            }

            $sessionDirectory = [System.IO.Path]::GetFullPath((Join-Path $root $sessionId))
            $metadataPath = Join-Path $sessionDirectory 'session.json'
            $metadata = $null
            try { $metadata = Read-MihariJsonFile -Path $metadataPath }
            catch {
                [void]$refused.Add([pscustomobject]@{
                    sessionId = $sessionId
                    subject = $subject
                    thumbprint = $thumbprint
                    reason = 'session_metadata_unreadable'
                })
                continue
            }
            if ($null -eq $metadata -or [string]$metadata.sessionId -cne $sessionId) {
                [void]$refused.Add([pscustomobject]@{
                    sessionId = $sessionId
                    subject = $subject
                    thumbprint = $thumbprint
                    reason = 'matching_session_metadata_missing'
                })
                continue
            }

            $metadataDirectory = $null
            try { $metadataDirectory = [System.IO.Path]::GetFullPath([string]$metadata.outputDirectory) }
            catch { $metadataDirectory = $null }
            if ($null -eq $metadataDirectory -or
                -not [StringComparer]::OrdinalIgnoreCase.Equals($metadataDirectory, $sessionDirectory) -or
                [string]$metadata.caSubject -cne $subject -or
                ([string]$metadata.caThumbprint).Replace(' ', '') -ine $thumbprint) {
                [void]$refused.Add([pscustomobject]@{
                    sessionId = $sessionId
                    subject = $subject
                    thumbprint = $thumbprint
                    reason = 'session_metadata_does_not_match_certificate_identity'
                })
                continue
            }

            $processAlive = Get-MihariSessionProcessAlive -Metadata $metadata
            $sessionStatus = [string]$metadata.status
            $finished = $sessionStatus -like 'stopped*' -or $sessionStatus -eq 'start_failed' -or $sessionStatus -eq 'orphaned_cleaned'
            if ($processAlive -and -not $finished) {
                [void]$refused.Add([pscustomobject]@{
                    sessionId = $sessionId
                    subject = $subject
                    thumbprint = $thumbprint
                    reason = 'session_process_is_still_running'
                })
                continue
            }

            try {
                $count = [int](Remove-MihariCARoot -Thumbprint $thumbprint -Subject $subject)
                if ($count -ne 1) {
                    [void]$refused.Add([pscustomobject]@{
                        sessionId = $sessionId
                        subject = $subject
                        thumbprint = $thumbprint
                        reason = 'exact_root_was_not_removed_or_was_no_longer_present'
                    })
                    continue
                }
                [void]$removed.Add([pscustomobject]@{
                    sessionId = $sessionId
                    subject = $subject
                    thumbprint = $thumbprint
                })
            }
            catch {
                [void]$errors.Add([pscustomobject]@{
                    sessionId = $sessionId
                    operation = 'remove_exact_session_root'
                    errorType = $_.Exception.GetType().FullName
                })
                continue
            }

            if (-not $processAlive -and -not $finished) {
                $metadata.status = 'orphaned_cleaned'
                if ([string]::IsNullOrWhiteSpace([string]$metadata.stoppedAtUtc)) {
                    $metadata.stoppedAtUtc = [DateTime]::UtcNow.ToString('o')
                }
                $metadata | Add-Member -NotePropertyName caCleanup -NotePropertyValue 'removed_by_cleanup' -Force
                try {
                    Write-MihariJsonFileAtomic -Path $metadataPath -Value $metadata
                    $activePath = Join-Path $root 'active-session.json'
                    $active = Read-MihariJsonFile -Path $activePath
                    if ($null -ne $active -and [string]$active.sessionId -ceq $sessionId) {
                        Write-MihariJsonFileAtomic -Path $activePath -Value $metadata
                    }
                }
                catch {
                    [void]$errors.Add([pscustomobject]@{
                        sessionId = $sessionId
                        operation = 'record_stale_session_cleanup'
                        errorType = $_.Exception.GetType().FullName
                    })
                }
            }
        }
    }
    finally {
        if ($null -ne $certificates) {
            foreach ($certificate in $certificates) {
                try { $certificate.Dispose() }
                catch { [void]$errors.Add([pscustomobject]@{ operation = 'dispose_enumerated_certificate'; errorType = $_.Exception.GetType().FullName }) }
            }
        }
        if ($null -ne $store) {
            try { $store.Close() }
            catch { [void]$errors.Add([pscustomobject]@{ operation = 'close_current_user_root'; errorType = $_.Exception.GetType().FullName }) }
        }
    }

    return [pscustomobject]@{
        removed = @($removed.ToArray())
        refused = @($refused.ToArray())
        errors = @($errors.ToArray())
        removedCount = $removed.Count
    }
}
