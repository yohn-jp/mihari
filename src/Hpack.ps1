function New-MihariHpackHuffmanTable {
    param()

    # RFC 7541 Appendix B. Codes are listed by symbol number; lengths include EOS.
    $codeText = '1ff8,7fffd8,fffffe2,fffffe3,fffffe4,fffffe5,fffffe6,fffffe7,fffffe8,ffffea,3ffffffc,fffffe9,fffffea,3ffffffd,fffffeb,fffffec,fffffed,fffffee,fffffef,ffffff0,ffffff1,ffffff2,3ffffffe,ffffff3,ffffff4,ffffff5,ffffff6,ffffff7,ffffff8,ffffff9,ffffffa,ffffffb,14,3f8,3f9,ffa,1ff9,15,f8,7fa,3fa,3fb,f9,7fb,fa,16,17,18,0,1,2,19,1a,1b,1c,1d,1e,1f,5c,fb,7ffc,20,ffb,3fc,1ffa,21,5d,5e,5f,60,61,62,63,64,65,66,67,68,69,6a,6b,6c,6d,6e,6f,70,71,72,fc,73,fd,1ffb,7fff0,1ffc,3ffc,22,7ffd,3,23,4,24,5,25,26,27,6,74,75,28,29,2a,7,2b,76,2c,8,9,2d,77,78,79,7a,7b,7ffe,7fc,3ffd,1ffd,ffffffc,fffe6,3fffd2,fffe7,fffe8,3fffd3,3fffd4,3fffd5,7fffd9,3fffd6,7fffda,7fffdb,7fffdc,7fffdd,7fffde,ffffeb,7fffdf,ffffec,ffffed,3fffd7,7fffe0,ffffee,7fffe1,7fffe2,7fffe3,7fffe4,1fffdc,3fffd8,7fffe5,3fffd9,7fffe6,7fffe7,ffffef,3fffda,1fffdd,fffe9,3fffdb,3fffdc,7fffe8,7fffe9,1fffde,7fffea,3fffdd,3fffde,fffff0,1fffdf,3fffdf,7fffeb,7fffec,1fffe0,1fffe1,3fffe0,1fffe2,7fffed,3fffe1,7fffee,7fffef,fffea,3fffe2,3fffe3,3fffe4,7ffff0,3fffe5,3fffe6,7ffff1,3ffffe0,3ffffe1,fffeb,7fff1,3fffe7,7ffff2,3fffe8,1ffffec,3ffffe2,3ffffe3,3ffffe4,7ffffde,7ffffdf,3ffffe5,fffff1,1ffffed,7fff2,1fffe3,3ffffe6,7ffffe0,7ffffe1,3ffffe7,7ffffe2,fffff2,1fffe4,1fffe5,3ffffe8,3ffffe9,ffffffd,7ffffe3,7ffffe4,7ffffe5,fffec,fffff3,fffed,1fffe6,3fffe9,1fffe7,1fffe8,7ffff3,3fffea,3fffeb,1ffffee,1ffffef,fffff4,fffff5,3ffffea,7ffff4,3ffffeb,7ffffe6,3ffffec,3ffffed,7ffffe7,7ffffe8,7ffffe9,7ffffea,7ffffeb,ffffffe,7ffffec,7ffffed,7ffffee,7ffffef,7fffff0,3ffffee,3fffffff'
    $lengthText = '13,23,28,28,28,28,28,28,28,24,30,28,28,30,28,28,28,28,28,28,28,28,30,28,28,28,28,28,28,28,28,28,6,10,10,12,13,6,8,11,10,10,8,11,8,6,6,6,5,5,5,6,6,6,6,6,6,6,7,8,15,6,12,10,13,6,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,8,7,8,13,19,13,14,6,15,5,6,5,6,5,6,6,6,5,7,7,6,6,6,5,6,7,6,5,5,6,7,7,7,7,7,15,11,14,13,28,20,22,20,20,22,22,22,23,22,23,23,23,23,23,24,23,24,24,22,23,24,23,23,23,23,21,22,23,22,23,23,24,22,21,20,22,22,23,23,21,23,22,22,24,21,22,23,23,21,21,22,21,23,22,23,23,20,22,22,22,23,22,22,23,26,26,20,19,22,23,22,25,26,26,26,27,27,26,24,25,19,21,26,27,27,26,27,24,21,21,26,26,28,27,27,27,20,24,20,21,22,21,21,23,22,22,25,25,24,24,26,23,26,27,26,26,27,27,27,27,27,28,27,27,27,27,27,26,30'
    $codeParts = $codeText.Split(',')
    $lengthParts = $lengthText.Split(',')
    if ($codeParts.Length -ne 257 -or $lengthParts.Length -ne 257) {
        throw [System.InvalidOperationException]::new('The HPACK Huffman table is incomplete.')
    }

    $codes = [uint32[]]::new(257)
    $lengths = [byte[]]::new(257)
    $nodes = New-Object 'System.Collections.Generic.List[object]'
    $root = [int[]]::new(3)
    $root[0] = -1
    $root[1] = -1
    $root[2] = -1
    $nodes.Add($root)

    for ($symbol = 0; $symbol -lt 257; $symbol++) {
        $codes[$symbol] = [System.UInt32]::Parse(
            $codeParts[$symbol],
            [System.Globalization.NumberStyles]::HexNumber,
            [System.Globalization.CultureInfo]::InvariantCulture)
        $lengths[$symbol] = [byte]::Parse($lengthParts[$symbol], [System.Globalization.CultureInfo]::InvariantCulture)
        $nodeIndex = 0
        for ($bitIndex = ([int]$lengths[$symbol] - 1); $bitIndex -ge 0; $bitIndex--) {
            $bit = [int](($codes[$symbol] -shr $bitIndex) -band 1)
            $node = $nodes[$nodeIndex]
            $childIndex = $node[$bit]
            if ($childIndex -lt 0) {
                $childIndex = $nodes.Count
                $child = [int[]]::new(3)
                $child[0] = -1
                $child[1] = -1
                $child[2] = -1
                $nodes.Add($child)
                $node[$bit] = $childIndex
            }
            $nodeIndex = $childIndex
            if ($bitIndex -eq 0) {
                $terminal = $nodes[$nodeIndex]
                if ($terminal[2] -ge 0 -or $terminal[0] -ge 0 -or $terminal[1] -ge 0) {
                    throw [System.InvalidOperationException]::new('The HPACK Huffman table has an invalid prefix.')
                }
                $terminal[2] = $symbol
            }
        }
    }

    return [pscustomobject]@{
        Codes = $codes
        Lengths = $lengths
        Nodes = $nodes
    }
}

function New-MihariHpackContext {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateRange(0, 65536)]
        [int]$MaxTableSize
    )

    $staticRows = @(
        ':authority|'
        ':method|GET'
        ':method|POST'
        ':path|/'
        ':path|/index.html'
        ':scheme|http'
        ':scheme|https'
        ':status|200'
        ':status|204'
        ':status|206'
        ':status|304'
        ':status|400'
        ':status|404'
        ':status|500'
        'accept-charset|'
        'accept-encoding|gzip, deflate'
        'accept-language|'
        'accept-ranges|'
        'accept|'
        'access-control-allow-origin|'
        'age|'
        'allow|'
        'authorization|'
        'cache-control|'
        'content-disposition|'
        'content-encoding|'
        'content-language|'
        'content-length|'
        'content-location|'
        'content-range|'
        'content-type|'
        'cookie|'
        'date|'
        'etag|'
        'expect|'
        'expires|'
        'from|'
        'host|'
        'if-match|'
        'if-modified-since|'
        'if-none-match|'
        'if-range|'
        'if-unmodified-since|'
        'last-modified|'
        'link|'
        'location|'
        'max-forwards|'
        'proxy-authenticate|'
        'proxy-authorization|'
        'range|'
        'referer|'
        'refresh|'
        'retry-after|'
        'server|'
        'set-cookie|'
        'strict-transport-security|'
        'transfer-encoding|'
        'user-agent|'
        'vary|'
        'via|'
        'www-authenticate|'
    )
    $static = New-Object 'System.Collections.Generic.List[object]'
    foreach ($row in $staticRows) {
        $separatorIndex = $row.IndexOf('|')
        $static.Add([pscustomobject]@{
            name = $row.Substring(0, $separatorIndex)
            value = $row.Substring($separatorIndex + 1)
        })
    }

    $huffman = New-MihariHpackHuffmanTable
    return [pscustomobject]@{
        MaxTableSize = [int]$MaxTableSize
        CurrentTableMaxSize = [int]$MaxTableSize
        DynamicTableSize = [long]0
        DynamicTable = (New-Object 'System.Collections.Generic.List[object]')
        StaticTable = $static
        HuffmanCodes = $huffman.Codes
        HuffmanLengths = $huffman.Lengths
        HuffmanNodes = $huffman.Nodes
        MaxHeaderListBytes = [int]65536
        MaxHeaderCount = [int]128
        IsFailed = $false
    }
}

function Read-MihariHpackInteger {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [Parameter(Mandatory = $true)][int]$Index,
        [Parameter(Mandatory = $true)][ValidateRange(1, 8)][int]$PrefixBits
    )

    if ($Index -lt 0 -or $Index -ge $Bytes.Length) {
        throw [System.IO.InvalidDataException]::new('HPACK integer is truncated.')
    }
    $mask = (1 -shl $PrefixBits) - 1
    [long]$value = [int]$Bytes[$Index] -band $mask
    $Index++
    if ($value -lt $mask) {
        return [pscustomobject]@{ Value = $value; Next = $Index }
    }

    $shift = 0
    while ($true) {
        if ($Index -ge $Bytes.Length -or $shift -gt 28) {
            throw [System.IO.InvalidDataException]::new('HPACK integer is truncated or too large.')
        }
        [long]$next = $Bytes[$Index]
        $Index++
        [long]$chunk = $next -band 127
        if ($chunk -gt ([long]2147483647 -shr $shift)) {
            throw [System.IO.InvalidDataException]::new('HPACK integer is too large.')
        }
        $value += ($chunk -shl $shift)
        if ($value -gt 2147483647) {
            throw [System.IO.InvalidDataException]::new('HPACK integer is too large.')
        }
        if (($next -band 128) -eq 0) {
            return [pscustomobject]@{ Value = $value; Next = $Index }
        }
        $shift += 7
    }
}

function Write-MihariHpackInteger {
    param(
        [Parameter(Mandatory = $true)][System.Collections.Generic.List[byte]]$Output,
        [Parameter(Mandatory = $true)][long]$Value,
        [Parameter(Mandatory = $true)][ValidateRange(1, 8)][int]$PrefixBits,
        [Parameter(Mandatory = $true)][int]$HighBits
    )

    if ($Value -lt 0 -or $Value -gt 2147483647) {
        throw [System.ArgumentOutOfRangeException]::new('Value')
    }
    $mask = (1 -shl $PrefixBits) - 1
    if ($Value -lt $mask) {
        $Output.Add([byte]($HighBits -bor [int]$Value))
        return
    }
    $Output.Add([byte]($HighBits -bor $mask))
    $remaining = $Value - $mask
    while ($remaining -ge 128) {
        $Output.Add([byte](($remaining -band 127) -bor 128))
        $remaining = [long][Math]::Floor($remaining / 128)
    }
    $Output.Add([byte]$remaining)
}

function Get-MihariHpackEntry {
    param(
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][long]$Index
    )

    if ($Index -le 0) {
        throw [System.IO.InvalidDataException]::new('HPACK index is invalid.')
    }
    if ($Index -le $Context.StaticTable.Count) {
        return $Context.StaticTable[[int]($Index - 1)]
    }
    $dynamicIndex = [int]($Index - $Context.StaticTable.Count - 1)
    if ($dynamicIndex -lt 0 -or $dynamicIndex -ge $Context.DynamicTable.Count) {
        throw [System.IO.InvalidDataException]::new('HPACK index is outside the available table.')
    }
    return $Context.DynamicTable[$dynamicIndex]
}

function Add-MihariHpackDynamicEntry {
    param(
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value
    )

    $utf8 = [System.Text.UTF8Encoding]::new($false, $true)
    [long]$entrySize = 32 + $utf8.GetByteCount($Name) + $utf8.GetByteCount($Value)
    if ($entrySize -gt $Context.CurrentTableMaxSize) {
        $Context.DynamicTable.Clear()
        $Context.DynamicTableSize = [long]0
        return
    }
    $Context.DynamicTable.Insert(0, [pscustomobject]@{ name = $Name; value = $Value; size = $entrySize })
    $Context.DynamicTableSize += $entrySize
    while ($Context.DynamicTableSize -gt $Context.CurrentTableMaxSize -and $Context.DynamicTable.Count -gt 0) {
        $lastIndex = $Context.DynamicTable.Count - 1
        $oldest = $Context.DynamicTable[$lastIndex]
        $Context.DynamicTableSize -= [long]$oldest.size
        $Context.DynamicTable.RemoveAt($lastIndex)
    }
}

function Read-MihariHpackString {
    param(
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [Parameter(Mandatory = $true)][int]$Index,
        [Parameter(Mandatory = $true)][int]$MaximumOutputBytes
    )

    $huffman = (($Bytes[$Index] -band 128) -ne 0)
    $length = Read-MihariHpackInteger -Bytes $Bytes -Index $Index -PrefixBits 7
    $encodedLength = [long]$length.Value
    $Index = [int]$length.Next
    if ($encodedLength -gt $Bytes.Length - $Index -or $encodedLength -gt 65536) {
        throw [System.IO.InvalidDataException]::new('HPACK string length is invalid.')
    }
    $encoded = [byte[]]::new([int]$encodedLength)
    if ($encodedLength -gt 0) {
        [Array]::Copy($Bytes, $Index, $encoded, 0, [int]$encodedLength)
    }
    $Index += [int]$encodedLength

    if ($huffman) {
        $decoded = Read-MihariHpackHuffmanString -Context $Context -Bytes $encoded -MaximumOutputBytes $MaximumOutputBytes
    }
    else {
        if ($encoded.Length -gt $MaximumOutputBytes) {
            throw [System.IO.InvalidDataException]::new('HPACK string exceeds the header-list limit.')
        }
        $decoded = $encoded
    }

    try {
        $text = [System.Text.UTF8Encoding]::new($false, $true).GetString($decoded)
    }
    catch {
        throw [System.IO.InvalidDataException]::new('HPACK string is not valid UTF-8.')
    }
    return [pscustomobject]@{ Value = $text; Next = $Index; OctetLength = $decoded.Length }
}

function Read-MihariHpackHuffmanString {
    param(
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$Bytes,
        [Parameter(Mandatory = $true)][int]$MaximumOutputBytes
    )

    $decoded = New-Object 'System.Collections.Generic.List[byte]'
    $nodeIndex = 0
    $pendingCount = 0
    $pendingValue = 0
    foreach ($octet in $Bytes) {
        for ($bitIndex = 7; $bitIndex -ge 0; $bitIndex--) {
            $bit = [int](($octet -shr $bitIndex) -band 1)
            $pendingCount++
            $pendingValue = ($pendingValue * 2) + $bit
            $node = $Context.HuffmanNodes[$nodeIndex]
            $nodeIndex = $node[$bit]
            if ($nodeIndex -lt 0) {
                throw [System.IO.InvalidDataException]::new('HPACK Huffman code is invalid.')
            }
            $terminal = $Context.HuffmanNodes[$nodeIndex]
            if ($terminal[2] -ge 0) {
                if ($terminal[2] -eq 256) {
                    throw [System.IO.InvalidDataException]::new('HPACK Huffman string contains EOS.')
                }
                if ($decoded.Count -ge $MaximumOutputBytes) {
                    throw [System.IO.InvalidDataException]::new('HPACK Huffman string exceeds the header-list limit.')
                }
                $decoded.Add([byte]$terminal[2])
                $nodeIndex = 0
                $pendingCount = 0
                $pendingValue = 0
            }
        }
    }

    if ($nodeIndex -ne 0) {
        if ($pendingCount -gt 7) {
            throw [System.IO.InvalidDataException]::new('HPACK Huffman padding is invalid.')
        }
        $expectedPadding = (1 -shl $pendingCount) - 1
        if ($pendingValue -ne $expectedPadding) {
            throw [System.IO.InvalidDataException]::new('HPACK Huffman padding is invalid.')
        }
    }
    return ,($decoded.ToArray())
}

function Find-MihariHpackFullIndex {
    param(
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value
    )

    for ($index = 0; $index -lt $Context.StaticTable.Count; $index++) {
        $entry = $Context.StaticTable[$index]
        if ($entry.name -ceq $Name -and $entry.value -ceq $Value) {
            return $index + 1
        }
    }
    for ($index = 0; $index -lt $Context.DynamicTable.Count; $index++) {
        $entry = $Context.DynamicTable[$index]
        if ($entry.name -ceq $Name -and $entry.value -ceq $Value) {
            return $Context.StaticTable.Count + $index + 1
        }
    }
    return 0
}

function Find-MihariHpackNameIndex {
    param(
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][string]$Name
    )

    for ($index = 0; $index -lt $Context.StaticTable.Count; $index++) {
        if ($Context.StaticTable[$index].name -ceq $Name) {
            return $index + 1
        }
    }
    for ($index = 0; $index -lt $Context.DynamicTable.Count; $index++) {
        if ($Context.DynamicTable[$index].name -ceq $Name) {
            return $Context.StaticTable.Count + $index + 1
        }
    }
    return 0
}

function Write-MihariHpackHuffmanString {
    param(
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][System.Collections.Generic.List[byte]]$Output,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$Bytes
    )

    [long]$bitCount = 0
    foreach ($octet in $Bytes) {
        $bitCount += [long]$Context.HuffmanLengths[[int]$octet]
    }
    $encodedLength = [int][Math]::Ceiling($bitCount / 8.0)
    if ($encodedLength -ge $Bytes.Length) {
        Write-MihariHpackInteger -Output $Output -Value $Bytes.Length -PrefixBits 7 -HighBits 0
        foreach ($octet in $Bytes) { $Output.Add([byte]$octet) }
        return
    }

    Write-MihariHpackInteger -Output $Output -Value $encodedLength -PrefixBits 7 -HighBits 128
    [byte]$current = 0
    $currentBits = 0
    foreach ($octet in $Bytes) {
        $symbol = [int]$octet
        $code = [long]$Context.HuffmanCodes[$symbol]
        $codeLength = [int]$Context.HuffmanLengths[$symbol]
        for ($bitIndex = $codeLength - 1; $bitIndex -ge 0; $bitIndex--) {
            $current = [byte](($current -shl 1) -bor [int](($code -shr $bitIndex) -band 1))
            $currentBits++
            if ($currentBits -eq 8) {
                $Output.Add($current)
                $current = [byte]0
                $currentBits = 0
            }
        }
    }
    if ($currentBits -gt 0) {
        while ($currentBits -lt 8) {
            $current = [byte](($current -shl 1) -bor 1)
            $currentBits++
        }
        $Output.Add($current)
    }
}

function Write-MihariHpackString {
    param(
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][System.Collections.Generic.List[byte]]$Output,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value
    )

    try {
        $bytes = [System.Text.UTF8Encoding]::new($false, $true).GetBytes($Value)
    }
    catch {
        throw [System.ArgumentException]::new('An HPACK string must contain valid Unicode.')
    }
    Write-MihariHpackHuffmanString -Context $Context -Output $Output -Bytes $bytes
}

function Set-MihariHpackTableLimit {
    param(
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][int]$Size
    )

    if ($Size -lt 0 -or $Size -gt $Context.MaxTableSize) {
        throw [System.IO.InvalidDataException]::new('HPACK dynamic table size update exceeds its configured limit.')
    }
    $Context.CurrentTableMaxSize = $Size
    while ($Context.DynamicTableSize -gt $Context.CurrentTableMaxSize -and $Context.DynamicTable.Count -gt 0) {
        $lastIndex = $Context.DynamicTable.Count - 1
        $oldest = $Context.DynamicTable[$lastIndex]
        $Context.DynamicTableSize -= [long]$oldest.size
        $Context.DynamicTable.RemoveAt($lastIndex)
    }
}

function Decode-MihariHpackBlock {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$Bytes
    )

    if ($null -eq $Context -or $null -eq $Context.DynamicTable -or $Context.IsFailed) {
        throw [System.InvalidOperationException]::new('The HPACK context is unavailable.')
    }
    if ($Context.MaxTableSize -lt 0 -or $Context.MaxTableSize -gt 65536) {
        throw [System.InvalidOperationException]::new('The HPACK context table limit is invalid.')
    }
    if ($Context.MaxHeaderListBytes -lt 0 -or $Context.MaxHeaderListBytes -gt 65536 -or
        $Context.MaxHeaderCount -lt 0 -or $Context.MaxHeaderCount -gt 128) {
        throw [System.InvalidOperationException]::new('The HPACK header limits are invalid.')
    }
    if ($Bytes.Length -gt 65536) {
        $Context.IsFailed = $true
        throw [System.IO.InvalidDataException]::new('The HPACK header block exceeds the configured limit.')
    }

    try {
        $headers = New-Object 'System.Collections.Generic.List[object]'
        [long]$headerListBytes = 0
        $index = 0
        $sawHeader = $false
        $needsTableUpdate = ([int]$Context.CurrentTableMaxSize -gt [int]$Context.MaxTableSize)
        while ($index -lt $Bytes.Length) {
            $first = [int]$Bytes[$index]
            if (($first -band 128) -ne 0) {
                if ($needsTableUpdate) {
                    throw [System.IO.InvalidDataException]::new('HPACK table size update is required.')
                }
                $sawHeader = $true
                $decodedIndex = Read-MihariHpackInteger -Bytes $Bytes -Index $index -PrefixBits 7
                $index = [int]$decodedIndex.Next
                $field = Get-MihariHpackEntry -Context $Context -Index $decodedIndex.Value
                $name = [string]$field.name
                $value = [string]$field.value
            }
            elseif (($first -band 64) -ne 0) {
                if ($needsTableUpdate) {
                    throw [System.IO.InvalidDataException]::new('HPACK table size update is required.')
                }
                $sawHeader = $true
                $nameInteger = Read-MihariHpackInteger -Bytes $Bytes -Index $index -PrefixBits 6
                $index = [int]$nameInteger.Next
                if ($nameInteger.Value -eq 0) {
                    $nameString = Read-MihariHpackString -Context $Context -Bytes $Bytes -Index $index -MaximumOutputBytes $Context.MaxHeaderListBytes
                    $name = [string]$nameString.Value
                    $index = [int]$nameString.Next
                }
                else {
                    $nameEntry = Get-MihariHpackEntry -Context $Context -Index $nameInteger.Value
                    $name = [string]$nameEntry.name
                }
                $valueString = Read-MihariHpackString -Context $Context -Bytes $Bytes -Index $index -MaximumOutputBytes $Context.MaxHeaderListBytes
                $value = [string]$valueString.Value
                $index = [int]$valueString.Next
                Add-MihariHpackDynamicEntry -Context $Context -Name $name -Value $value
            }
            elseif (($first -band 32) -ne 0) {
                if ($sawHeader) {
                    throw [System.IO.InvalidDataException]::new('HPACK table size update is not at the start of the block.')
                }
                $sizeInteger = Read-MihariHpackInteger -Bytes $Bytes -Index $index -PrefixBits 5
                $index = [int]$sizeInteger.Next
                if ($sizeInteger.Value -gt $Context.MaxTableSize) {
                    throw [System.IO.InvalidDataException]::new('HPACK dynamic table size update exceeds its configured limit.')
                }
                Set-MihariHpackTableLimit -Context $Context -Size ([int]$sizeInteger.Value)
                $needsTableUpdate = $false
                continue
            }
            else {
                if ($needsTableUpdate) {
                    throw [System.IO.InvalidDataException]::new('HPACK table size update is required.')
                }
                $sawHeader = $true
                $nameInteger = Read-MihariHpackInteger -Bytes $Bytes -Index $index -PrefixBits 4
                $index = [int]$nameInteger.Next
                if ($nameInteger.Value -eq 0) {
                    $nameString = Read-MihariHpackString -Context $Context -Bytes $Bytes -Index $index -MaximumOutputBytes $Context.MaxHeaderListBytes
                    $name = [string]$nameString.Value
                    $index = [int]$nameString.Next
                }
                else {
                    $nameEntry = Get-MihariHpackEntry -Context $Context -Index $nameInteger.Value
                    $name = [string]$nameEntry.name
                }
                $valueString = Read-MihariHpackString -Context $Context -Bytes $Bytes -Index $index -MaximumOutputBytes $Context.MaxHeaderListBytes
                $value = [string]$valueString.Value
                $index = [int]$valueString.Next
            }

            if ($headers.Count -ge $Context.MaxHeaderCount) {
                throw [System.IO.InvalidDataException]::new('HPACK header field count exceeds the configured limit.')
            }
            $nameOctets = [System.Text.UTF8Encoding]::new($false, $true).GetByteCount($name)
            $valueOctets = [System.Text.UTF8Encoding]::new($false, $true).GetByteCount($value)
            $headerListBytes += 32 + $nameOctets + $valueOctets
            if ($headerListBytes -gt $Context.MaxHeaderListBytes) {
                throw [System.IO.InvalidDataException]::new('HPACK header list exceeds the configured limit.')
            }
            $headers.Add([pscustomobject]@{ name = $name; value = $value })
        }
        return ,($headers.ToArray())
    }
    catch {
        $Context.IsFailed = $true
        throw [System.IO.InvalidDataException]::new('HPACK header block is invalid or exceeds a configured limit.')
    }
}

function Encode-MihariHpackBlock {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Headers
    )

    if ($null -eq $Context -or $null -eq $Context.DynamicTable -or $Context.IsFailed) {
        throw [System.InvalidOperationException]::new('The HPACK context is unavailable.')
    }
    if ($Context.MaxTableSize -lt 0 -or $Context.MaxTableSize -gt 65536) {
        throw [System.InvalidOperationException]::new('The HPACK context table limit is invalid.')
    }
    if ($Context.MaxHeaderListBytes -lt 0 -or $Context.MaxHeaderListBytes -gt 65536 -or
        $Context.MaxHeaderCount -lt 0 -or $Context.MaxHeaderCount -gt 128) {
        throw [System.InvalidOperationException]::new('The HPACK header limits are invalid.')
    }
    if ($Headers.Count -gt $Context.MaxHeaderCount) {
        throw [System.ArgumentOutOfRangeException]::new('Headers')
    }
    $output = New-Object 'System.Collections.Generic.List[byte]'
    if ($Context.CurrentTableMaxSize -ne $Context.MaxTableSize) {
        Write-MihariHpackInteger -Output $output -Value $Context.MaxTableSize -PrefixBits 5 -HighBits 32
        Set-MihariHpackTableLimit -Context $Context -Size $Context.MaxTableSize
    }
    [long]$headerListBytes = 0
    $sensitiveNames = @('authorization', 'proxy-authorization', 'cookie', 'set-cookie')
    foreach ($header in $Headers) {
        if ($null -eq $header) {
            throw [System.ArgumentException]::new('Header entries cannot be null.')
        }
        $name = [string]$header.name
        $value = [string]$header.value
        if ([string]::IsNullOrEmpty($name) -or $null -eq $header.value) {
            throw [System.ArgumentException]::new('Header names and values must be present.')
        }
        try {
            $nameBytes = [System.Text.UTF8Encoding]::new($false, $true).GetBytes($name)
            $valueBytes = [System.Text.UTF8Encoding]::new($false, $true).GetBytes($value)
        }
        catch {
            throw [System.ArgumentException]::new('Header strings must contain valid Unicode.')
        }
        $headerListBytes += 32 + $nameBytes.Length + $valueBytes.Length
        if ($headerListBytes -gt $Context.MaxHeaderListBytes) {
            throw [System.ArgumentOutOfRangeException]::new('Headers')
        }
        $isSensitive = $sensitiveNames -contains $name
        $fullIndex = 0
        if (-not $isSensitive) {
            $fullIndex = Find-MihariHpackFullIndex -Context $Context -Name $name -Value $value
        }
        if ($fullIndex -gt 0) {
            Write-MihariHpackInteger -Output $output -Value $fullIndex -PrefixBits 7 -HighBits 128
            continue
        }

        if ($isSensitive) {
            $prefix = 4
            $highBits = 16
        }
        else {
            $prefix = 6
            $highBits = 64
        }
        $nameIndex = Find-MihariHpackNameIndex -Context $Context -Name $name
        Write-MihariHpackInteger -Output $output -Value $nameIndex -PrefixBits $prefix -HighBits $highBits
        if ($nameIndex -eq 0) {
            Write-MihariHpackString -Context $Context -Output $output -Value $name
        }
        Write-MihariHpackString -Context $Context -Output $output -Value $value
        if (-not $isSensitive) {
            Add-MihariHpackDynamicEntry -Context $Context -Name $name -Value $value
        }
        if ($output.Count -gt 65536) {
            throw [System.ArgumentOutOfRangeException]::new('Headers')
        }
    }
    return ,($output.ToArray())
}
