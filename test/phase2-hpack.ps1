$ErrorActionPreference = 'Stop'
$sourcePath = Join-Path (Split-Path -Parent $PSScriptRoot) 'src/Hpack.ps1'
. $sourcePath

function Assert-Hpack {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Message
    )
    if (-not $Condition) {
        throw $Message
    }
}

function Convert-HpackHexToBytes {
    param([Parameter(Mandatory = $true)][string]$Hex)
    $parts = @($Hex -split '\s+' | Where-Object { $_ })
    $bytes = [byte[]]::new($parts.Count)
    for ($index = 0; $index -lt $parts.Count; $index++) {
        $bytes[$index] = [byte]::Parse(
            $parts[$index],
            [System.Globalization.NumberStyles]::HexNumber,
            [System.Globalization.CultureInfo]::InvariantCulture)
    }
    return ,$bytes
}

function Assert-HpackHeaders {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Actual,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Expected,
        [Parameter(Mandatory = $true)][string]$Message
    )
    if ($Actual.Count -ne $Expected.Count) {
        throw ($Message + ': unexpected field count.')
    }
    for ($index = 0; $index -lt $Expected.Count; $index++) {
        if ($Actual[$index].name -cne $Expected[$index].name -or
            $Actual[$index].value -cne $Expected[$index].value) {
            throw ($Message + ': ordered field mismatch.')
        }
    }
}

function Assert-HpackRejected {
    param(
        [Parameter(Mandatory = $true)][scriptblock]$Action,
        [Parameter(Mandatory = $true)][string]$Message
    )
    $rejected = $false
    try {
        & $Action
    }
    catch {
        $rejected = $true
    }
    if (-not $rejected) {
        throw ($Message + ': malformed input was accepted.')
    }
}

try {
    $context = New-MihariHpackContext -MaxTableSize 4096
    Assert-Hpack -Condition ($context.StaticTable.Count -eq 61) -Message 'RFC static table length'
    Assert-Hpack -Condition ($context.MaxHeaderListBytes -eq 65536 -and $context.MaxHeaderCount -eq 128) -Message 'Finite decoded header limits'

    # RFC 7541 Appendix C.4.1: Huffman-coded request and dynamic authority entry.
    $firstRequest = Convert-HpackHexToBytes '82 86 84 41 8c f1 e3 c2 e5 f2 3a 6b a0 ab 90 f4 ff'
    $firstHeaders = Decode-MihariHpackBlock -Context $context -Bytes $firstRequest
    Assert-HpackHeaders -Actual $firstHeaders -Expected @(
        [pscustomobject]@{ name = ':method'; value = 'GET' }
        [pscustomobject]@{ name = ':scheme'; value = 'http' }
        [pscustomobject]@{ name = ':path'; value = '/' }
        [pscustomobject]@{ name = ':authority'; value = 'www.example.com' }
    ) -Message 'RFC Huffman request one'
    Assert-Hpack -Condition ($context.DynamicTable.Count -eq 1 -and $context.DynamicTable[0].name -eq ':authority') -Message 'Dynamic table insertion'

    # RFC 7541 Appendix C.4.2: dynamic index plus Huffman value on the same context.
    $secondRequest = Convert-HpackHexToBytes '82 86 84 be 58 86 a8 eb 10 64 9c bf'
    $secondHeaders = Decode-MihariHpackBlock -Context $context -Bytes $secondRequest
    Assert-Hpack -Condition ($secondHeaders.Count -eq 5) -Message 'Single context retains dynamic entries across blocks'
    Assert-Hpack -Condition ($secondHeaders[3].name -eq ':authority' -and $secondHeaders[3].value -eq 'www.example.com') -Message 'Dynamic table index resolves'

    # RFC 7541 Appendix C.2.1 and C.2.2 exercise literal insertion and non-indexed fields.
    $literalContext = New-MihariHpackContext -MaxTableSize 4096
    $literalBlock = Convert-HpackHexToBytes '40 0a 63 75 73 74 6f 6d 2d 6b 65 79 0d 63 75 73 74 6f 6d 2d 68 65 61 64 65 72'
    $literalHeaders = Decode-MihariHpackBlock -Context $literalContext -Bytes $literalBlock
    Assert-Hpack -Condition ($literalHeaders.Count -eq 1 -and $literalHeaders[0].name -eq 'custom-key' -and $literalHeaders[0].value -eq 'custom-header') -Message 'Literal incremental indexing'
    $nonIndexed = Convert-HpackHexToBytes '04 0c 2f 73 61 6d 70 6c 65 2f 70 61 74 68'
    $nonIndexedHeaders = Decode-MihariHpackBlock -Context $literalContext -Bytes $nonIndexed
    Assert-Hpack -Condition ($nonIndexedHeaders[0].name -eq ':path' -and $literalContext.DynamicTable.Count -eq 1) -Message 'Literal without indexing preserves table'

    # Encoding follows the same RFC vectors and decodes back to the same ordered fields.
    $encodeContext = New-MihariHpackContext -MaxTableSize 4096
    $decodeContext = New-MihariHpackContext -MaxTableSize 4096
    $requestHeaders = @(
        [pscustomobject]@{ name = ':method'; value = 'GET' }
        [pscustomobject]@{ name = ':scheme'; value = 'http' }
        [pscustomobject]@{ name = ':path'; value = '/' }
        [pscustomobject]@{ name = ':authority'; value = 'www.example.com' }
    )
    $encodedFirst = Encode-MihariHpackBlock -Context $encodeContext -Headers $requestHeaders
    $expectedFirst = Convert-HpackHexToBytes '82 86 84 41 8c f1 e3 c2 e5 f2 3a 6b a0 ab 90 f4 ff'
    Assert-Hpack -Condition ([Convert]::ToBase64String($encodedFirst) -ceq [Convert]::ToBase64String($expectedFirst)) -Message 'RFC Huffman encoder vector one'
    Assert-HpackHeaders -Actual (Decode-MihariHpackBlock -Context $decodeContext -Bytes $encodedFirst) -Expected $requestHeaders -Message 'Encoder request round trip'

    $requestHeadersTwo = @(
        [pscustomobject]@{ name = ':method'; value = 'GET' }
        [pscustomobject]@{ name = ':scheme'; value = 'http' }
        [pscustomobject]@{ name = ':path'; value = '/' }
        [pscustomobject]@{ name = ':authority'; value = 'www.example.com' }
        [pscustomobject]@{ name = 'cache-control'; value = 'no-cache' }
    )
    $encodedSecond = Encode-MihariHpackBlock -Context $encodeContext -Headers $requestHeadersTwo
    $expectedSecond = Convert-HpackHexToBytes '82 86 84 be 58 86 a8 eb 10 64 9c bf'
    Assert-Hpack -Condition ([Convert]::ToBase64String($encodedSecond) -ceq [Convert]::ToBase64String($expectedSecond)) -Message 'RFC Huffman encoder vector two'
    Assert-HpackHeaders -Actual (Decode-MihariHpackBlock -Context $decodeContext -Bytes $encodedSecond) -Expected $requestHeadersTwo -Message 'Dynamic encoder state persists across blocks'

    $sensitiveContext = New-MihariHpackContext -MaxTableSize 4096
    $sensitiveHeaders = @([pscustomobject]@{ name = 'authorization'; value = 'Bearer example' })
    $sensitiveBlock = Encode-MihariHpackBlock -Context $sensitiveContext -Headers $sensitiveHeaders
    Assert-Hpack -Condition (($sensitiveBlock[0] -band 240) -eq 16) -Message 'Sensitive field uses never-indexed representation'
    Assert-Hpack -Condition ($sensitiveContext.DynamicTable.Count -eq 0) -Message 'Sensitive field is not retained in dynamic table'
    Assert-HpackHeaders -Actual (Decode-MihariHpackBlock -Context (New-MihariHpackContext -MaxTableSize 4096) -Bytes $sensitiveBlock) -Expected $sensitiveHeaders -Message 'Sensitive field round trip'

    # Empty and duplicate lists/fields preserve ordered-array behavior.
    $empty = Decode-MihariHpackBlock -Context (New-MihariHpackContext -MaxTableSize 0) -Bytes ([byte[]]::new(0))
    Assert-Hpack -Condition ($empty.Count -eq 0) -Message 'Empty decoded block returns an empty array'
    $duplicates = @(
        [pscustomobject]@{ name = 'x-repeat'; value = 'same' }
        [pscustomobject]@{ name = 'x-repeat'; value = 'same' }
    )
    $duplicateEncoded = Encode-MihariHpackBlock -Context (New-MihariHpackContext -MaxTableSize 0) -Headers $duplicates
    $duplicateDecoded = Decode-MihariHpackBlock -Context (New-MihariHpackContext -MaxTableSize 0) -Bytes $duplicateEncoded
    Assert-HpackHeaders -Actual $duplicateDecoded -Expected $duplicates -Message 'Duplicate fields remain distinct and ordered'

    # A lowered peer limit requires a leading size update and evicts entries.
    $lowered = New-MihariHpackContext -MaxTableSize 4096
    $null = Decode-MihariHpackBlock -Context $lowered -Bytes $firstRequest
    $lowered.MaxTableSize = 0
    Assert-HpackRejected -Action {
        $null = Decode-MihariHpackBlock -Context $lowered -Bytes (Convert-HpackHexToBytes '82')
    } -Message 'Lowered table limit without update'
    $updated = New-MihariHpackContext -MaxTableSize 4096
    $null = Decode-MihariHpackBlock -Context $updated -Bytes $firstRequest
    $updated.MaxTableSize = 0
    $null = Decode-MihariHpackBlock -Context $updated -Bytes (Convert-HpackHexToBytes '20')
    Assert-Hpack -Condition ($updated.DynamicTable.Count -eq 0 -and $updated.CurrentTableMaxSize -eq 0) -Message 'Table size update clears dynamic state'

    # Malformed indexes, integer overflows, bad Huffman padding/EOS, and misplaced updates fail closed.
    Assert-HpackRejected -Action {
        $null = Decode-MihariHpackBlock -Context (New-MihariHpackContext -MaxTableSize 4096) -Bytes (Convert-HpackHexToBytes '80')
    } -Message 'Index zero'
    Assert-HpackRejected -Action {
        $null = Decode-MihariHpackBlock -Context (New-MihariHpackContext -MaxTableSize 4096) -Bytes (Convert-HpackHexToBytes 'ff ff ff ff ff ff ff ff ff')
    } -Message 'Integer overflow'
    Assert-HpackRejected -Action {
        $null = Decode-MihariHpackBlock -Context (New-MihariHpackContext -MaxTableSize 4096) -Bytes (Convert-HpackHexToBytes '01 81 00')
    } -Message 'Bad Huffman padding'
    Assert-HpackRejected -Action {
        $null = Decode-MihariHpackBlock -Context (New-MihariHpackContext -MaxTableSize 4096) -Bytes (Convert-HpackHexToBytes '01 84 ff ff ff ff')
    } -Message 'Huffman EOS'
    Assert-HpackRejected -Action {
        $null = Decode-MihariHpackBlock -Context (New-MihariHpackContext -MaxTableSize 4096) -Bytes (Convert-HpackHexToBytes '82 20')
    } -Message 'Table update after a header'
    Assert-HpackRejected -Action {
        $null = Decode-MihariHpackBlock -Context (New-MihariHpackContext -MaxTableSize 0) -Bytes (Convert-HpackHexToBytes '21')
    } -Message 'Table update above configured limit'
    Assert-HpackRejected -Action {
        $null = Decode-MihariHpackBlock -Context (New-MihariHpackContext -MaxTableSize 4096) -Bytes (Convert-HpackHexToBytes '00 01 ff 00')
    } -Message 'Invalid UTF-8 is rejected without lossy replacement'

    $manyFields = [byte[]]::new(129)
    for ($index = 0; $index -lt $manyFields.Length; $index++) { $manyFields[$index] = 130 }
    Assert-HpackRejected -Action {
        $null = Decode-MihariHpackBlock -Context (New-MihariHpackContext -MaxTableSize 0) -Bytes $manyFields
    } -Message 'Decoded field-count limit'

    Write-Host 'PASS phase2-hpack'
}
catch {
    [Console]::Error.WriteLine(('FAIL phase2-hpack: ' + $_.Exception.Message))
    exit 1
}
