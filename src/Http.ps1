function Read-MihariHttpHeaderBlock {
    param(
        [Parameter(Mandatory = $true)][System.IO.Stream]$Stream,
        [int]$MaximumBytes = 65536,
        [int]$DeadlineMs = 30000,
        [Nullable[byte]]$InitialByte
    )

    $bytes = New-Object 'System.Collections.Generic.List[byte]'
    $previous = -1
    if ($null -ne $InitialByte) {
        $bytes.Add([byte]$InitialByte)
        $previous = [int]$InitialByte
    }
    $clock = [System.Diagnostics.Stopwatch]::StartNew()
    $originalTimeout = $null
    if ($Stream.CanTimeout) { $originalTimeout = $Stream.ReadTimeout }
    try {
    while ($bytes.Count -lt $MaximumBytes) {
        $remainingMs = $DeadlineMs - [int]$clock.ElapsedMilliseconds
        if ($remainingMs -le 0) {
            throw [System.TimeoutException]::new('The HTTP header deadline expired.')
        }
        if ($Stream.CanTimeout) { $Stream.ReadTimeout = $remainingMs }
        $next = $Stream.ReadByte()
        if ($next -lt 0) {
            if ($bytes.Count -eq 0) { return $null }
            throw [System.IO.EndOfStreamException]::new('The HTTP header ended before CRLF-CRLF.')
        }

        if ($next -eq 10 -and $previous -ne 13) {
            throw [System.IO.InvalidDataException]::new('HTTP headers must use CRLF line endings.')
        }
        if ($previous -eq 13 -and $next -ne 10) {
            throw [System.IO.InvalidDataException]::new('HTTP headers must use CRLF line endings.')
        }

        $bytes.Add([byte]$next)
        $count = $bytes.Count
        if ($count -ge 4 -and
            $bytes[$count - 4] -eq 13 -and $bytes[$count - 3] -eq 10 -and
            $bytes[$count - 2] -eq 13 -and $bytes[$count - 1] -eq 10) {
            return ,($bytes.ToArray())
        }
        $previous = $next
    }

    throw [System.IO.InvalidDataException]::new("The HTTP header block exceeds the $MaximumBytes byte limit.")
    }
    finally {
        if ($null -ne $originalTimeout) { $Stream.ReadTimeout = $originalTimeout }
    }
}

function Read-MihariHttpLine {
    param(
        [Parameter(Mandatory = $true)][System.IO.Stream]$Stream,
        [int]$MaximumBytes = 8192,
        [int]$DeadlineMs = 30000
    )

    $bytes = New-Object 'System.Collections.Generic.List[byte]'
    $previous = -1
    $clock = [System.Diagnostics.Stopwatch]::StartNew()
    $originalTimeout = $null
    if ($Stream.CanTimeout) { $originalTimeout = $Stream.ReadTimeout }
    try {
    while ($bytes.Count -lt $MaximumBytes) {
        $remainingMs = $DeadlineMs - [int]$clock.ElapsedMilliseconds
        if ($remainingMs -le 0) {
            throw [System.TimeoutException]::new('The HTTP chunk line deadline expired.')
        }
        if ($Stream.CanTimeout) { $Stream.ReadTimeout = $remainingMs }
        $next = $Stream.ReadByte()
        if ($next -lt 0) {
            throw [System.IO.EndOfStreamException]::new('The HTTP chunk framing ended before CRLF.')
        }
        if ($next -eq 10) {
            if ($previous -ne 13) {
                throw [System.IO.InvalidDataException]::new('HTTP chunk framing must use CRLF line endings.')
            }
            $bytes.Add([byte]$next)
            $wire = $bytes.ToArray()
            $text = [System.Text.Encoding]::GetEncoding(28591).GetString($wire, 0, $wire.Length - 2)
            return [pscustomobject]@{ Bytes = $wire; Text = $text }
        }
        if ($previous -eq 13) {
            throw [System.IO.InvalidDataException]::new('HTTP chunk framing must use CRLF line endings.')
        }
        $bytes.Add([byte]$next)
        $previous = $next
    }
    throw [System.IO.InvalidDataException]::new("An HTTP chunk line exceeds the $MaximumBytes byte limit.")
    }
    finally {
        if ($null -ne $originalTimeout) { $Stream.ReadTimeout = $originalTimeout }
    }
}

function Read-MihariExactToStream {
    param(
        [Parameter(Mandatory = $true)][System.IO.Stream]$Source,
        [Parameter(Mandatory = $true)][System.IO.Stream]$Destination,
        [Parameter(Mandatory = $true)][long]$Length
    )

    $buffer = [byte[]]::new(8192)
    $remaining = $Length
    while ($remaining -gt 0) {
        $wanted = [int][Math]::Min([long]$buffer.Length, $remaining)
        $read = $Source.Read($buffer, 0, $wanted)
        if ($read -le 0) {
            throw [System.IO.EndOfStreamException]::new('The HTTP body ended before its declared framing length.')
        }
        $Destination.Write($buffer, 0, $read)
        $remaining -= $read
    }
}

function Read-MihariHttpBody {
    param(
        [Parameter(Mandatory = $true)][System.IO.Stream]$Stream,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Headers,
        [Parameter(Mandatory = $true)][ValidateSet('Request', 'Response')][string]$Kind,
        [int]$StatusCode,
        [string]$RequestMethod
    )

    $maximumBodyBytes = 33554432
    $body = New-Object System.IO.MemoryStream
    try {
        $transferEncoding = $null
        if ($Headers.Contains('Transfer-Encoding')) {
            $transferEncoding = [string]$Headers['Transfer-Encoding']
        }
        $contentLength = $null
        if ($Headers.Contains('Content-Length')) {
            $contentLength = [string]$Headers['Content-Length']
        }

        if ($Kind -eq 'Response' -and
            (($RequestMethod -and $RequestMethod -ieq 'HEAD') -or
             ($StatusCode -ge 100 -and $StatusCode -lt 200) -or
             $StatusCode -eq 204 -or $StatusCode -eq 304)) {
            if ($StatusCode -eq 101) {
                throw [System.NotSupportedException]::new('HTTP protocol upgrades are outside Mihari HTTP/1.1 support.')
            }
            return ,([byte[]]@())
        }

        if ($transferEncoding -and $contentLength) {
            throw [System.IO.InvalidDataException]::new('A message cannot contain both Transfer-Encoding and Content-Length.')
        }

        if ($transferEncoding) {
            $codings = @($transferEncoding.Split(',') | ForEach-Object { $_.Trim() })
            if ($codings.Count -ne 1 -or $codings[0] -ine 'chunked') {
                throw [System.NotSupportedException]::new('Unsupported HTTP transfer coding.')
            }

            $wireLength = [long]0
            while ($true) {
                $chunkLine = Read-MihariHttpLine -Stream $Stream
                $sizeText = $chunkLine.Text
                if ($sizeText -notmatch '^[0-9A-Fa-f]+(?:;[^\r\n]*)?$') {
                    throw [System.IO.InvalidDataException]::new('The HTTP chunk size line is malformed.')
                }
                $hexSize = ($sizeText -split ';', 2)[0]
                $chunkSize = [long]0
                $parsed = [long]::TryParse($hexSize, [System.Globalization.NumberStyles]::AllowHexSpecifier,
                    [System.Globalization.CultureInfo]::InvariantCulture, [ref]$chunkSize)
                if (-not $parsed -or $chunkSize -lt 0) {
                    throw [System.IO.InvalidDataException]::new('The HTTP chunk size is outside the supported range.')
                }

                $body.Write($chunkLine.Bytes, 0, $chunkLine.Bytes.Length)
                $wireLength += $chunkLine.Bytes.Length
                if ($wireLength -gt ($maximumBodyBytes + 65536)) {
                    throw [System.IO.InvalidDataException]::new("The HTTP body exceeds the $maximumBodyBytes byte limit.")
                }

                if ($chunkSize -eq 0) {
                    $trailerBytes = 0
                    while ($true) {
                        $trailer = Read-MihariHttpLine -Stream $Stream
                        $trailerBytes += $trailer.Bytes.Length
                        if (($wireLength + $trailerBytes) -gt ($maximumBodyBytes + 65536)) {
                            throw [System.IO.InvalidDataException]::new('The HTTP chunk trailers exceed the message size limit.')
                        }
                        if ($trailer.Text.Length -eq 0) {
                            $body.Write($trailer.Bytes, 0, $trailer.Bytes.Length)
                            break
                        }
                        if ($trailer.Text -match '^[ \t]' -or $trailer.Text -notmatch '^([^:]+):[ \t]*(.*)$') {
                            throw [System.IO.InvalidDataException]::new('An HTTP chunk trailer field is malformed.')
                        }
                        $trailerName = $matches[1]
                        $trailerValue = $matches[2]
                        if ($trailerName -notmatch '^[!#$%&''*+\-.^_`|~0-9A-Za-z]+$' -or
                            $trailerValue -match '[\x00-\x08\x0A-\x1F\x7F]') {
                            throw [System.IO.InvalidDataException]::new('An HTTP chunk trailer field contains invalid characters.')
                        }
                        $body.Write($trailer.Bytes, 0, $trailer.Bytes.Length)
                    }
                    break
                }

                if ($chunkSize -gt $maximumBodyBytes -or ($body.Length + $chunkSize) -gt ($maximumBodyBytes + 65536)) {
                    throw [System.IO.InvalidDataException]::new("The HTTP body exceeds the $maximumBodyBytes byte limit.")
                }
                Read-MihariExactToStream -Source $Stream -Destination $body -Length $chunkSize
                $wireLength += $chunkSize
                $delimiter = [byte[]]::new(2)
                $delimiterRead = 0
                while ($delimiterRead -lt 2) {
                    $count = $Stream.Read($delimiter, $delimiterRead, 2 - $delimiterRead)
                    if ($count -le 0) {
                        throw [System.IO.EndOfStreamException]::new('The HTTP chunk data ended before its CRLF delimiter.')
                    }
                    $delimiterRead += $count
                }
                if ($delimiter[0] -ne 13 -or $delimiter[1] -ne 10) {
                    throw [System.IO.InvalidDataException]::new('The HTTP chunk data is not followed by CRLF.')
                }
                $body.Write($delimiter, 0, 2)
                $wireLength += 2
            }
            return ,($body.ToArray())
        }

        if ($contentLength) {
            $lengthParts = @($contentLength.Split(',') | ForEach-Object { $_.Trim() })
            if ($lengthParts.Count -eq 0 -or $lengthParts[0] -notmatch '^[0-9]+$') {
                throw [System.IO.InvalidDataException]::new('The HTTP Content-Length field is malformed.')
            }
            foreach ($part in $lengthParts) {
                if ($part -ne $lengthParts[0]) {
                    throw [System.IO.InvalidDataException]::new('Conflicting HTTP Content-Length values are ambiguous.')
                }
            }
            $length = [long]0
            if (-not [long]::TryParse($lengthParts[0], [System.Globalization.NumberStyles]::None,
                [System.Globalization.CultureInfo]::InvariantCulture, [ref]$length) -or $length -gt $maximumBodyBytes) {
                throw [System.IO.InvalidDataException]::new("The HTTP Content-Length exceeds the $maximumBodyBytes byte limit or is invalid.")
            }
            Read-MihariExactToStream -Source $Stream -Destination $body -Length $length
            return ,($body.ToArray())
        }

        if ($Kind -eq 'Request') {
            return ,([byte[]]@())
        }

        $buffer = [byte[]]::new(8192)
        while ($true) {
            $read = $Stream.Read($buffer, 0, $buffer.Length)
            if ($read -le 0) { break }
            if (($body.Length + $read) -gt $maximumBodyBytes) {
                throw [System.IO.InvalidDataException]::new("The HTTP body exceeds the $maximumBodyBytes byte limit.")
            }
            $body.Write($buffer, 0, $read)
        }
        return ,($body.ToArray())
    }
    finally {
        $body.Dispose()
    }
}

function Read-MihariHttpMessage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][System.IO.Stream]$Stream,
        [Parameter(Mandatory = $true)][ValidateSet('Request', 'Response')][string]$Kind,
        [string]$RequestMethod,
        [switch]$HeadersOnly,
        [Nullable[byte]]$InitialByte
    )

    $readArguments = @{ Stream = $Stream }
    if ($PSBoundParameters.ContainsKey('InitialByte')) { $readArguments.InitialByte = $InitialByte }
    $rawHeaderBlock = Read-MihariHttpHeaderBlock @readArguments
    if ($null -eq $rawHeaderBlock) { return $null }

    $encoding = [System.Text.Encoding]::GetEncoding(28591)
    $headerText = $encoding.GetString($rawHeaderBlock)
    $lines = [System.Text.RegularExpressions.Regex]::Split($headerText, "`r`n")
    if ($lines.Count -lt 3 -or $lines[$lines.Count - 1] -ne '' -or $lines[$lines.Count - 2] -ne '') {
        throw [System.IO.InvalidDataException]::new('The HTTP header block is malformed.')
    }
    $startLine = $lines[0]
    if ($startLine.Length -gt 8192) {
        throw [System.IO.InvalidDataException]::new('The HTTP start line exceeds the 8192 character limit.')
    }

    $method = $null
    $target = $null
    $statusCode = $null
    $reason = $null
    $version = $null
    if ($Kind -eq 'Request') {
        if ($startLine -match '^PRI \* HTTP/2\.0$') {
            throw [System.NotSupportedException]::new('HTTP/2 is outside Mihari HTTP/1.1 support.')
        }
        $requestMatch = [System.Text.RegularExpressions.Regex]::Match($startLine,
            '^([!#$%&''*+\-.^_`|~0-9A-Za-z]+) ([^ \t]+) (HTTP/1\.[01])$')
        if (-not $requestMatch.Success) {
            if ($startLine -match '^.+ HTTP/[2-9](?:\.[0-9]+)?$') {
                throw [System.NotSupportedException]::new('Only HTTP/1.x requests are supported.')
            }
            throw [System.IO.InvalidDataException]::new('The HTTP request line is malformed or uses an unsupported version.')
        }
        $method = $requestMatch.Groups[1].Value
        $target = $requestMatch.Groups[2].Value
        $version = $requestMatch.Groups[3].Value
        if ($target.Length -gt 8192 -or $target -match '[\x00-\x20\x7F]') {
            throw [System.IO.InvalidDataException]::new('The HTTP request target contains invalid characters or exceeds the size limit.')
        }
    }
    else {
        $responseMatch = [System.Text.RegularExpressions.Regex]::Match($startLine,
            '^(HTTP/1\.[01]) ([0-9]{3})(?: ([^\x00-\x1F\x7F]*))?$')
        if (-not $responseMatch.Success) {
            throw [System.IO.InvalidDataException]::new('The HTTP response line is malformed or uses an unsupported version.')
        }
        $version = $responseMatch.Groups[1].Value
        $statusCode = [int]$responseMatch.Groups[2].Value
        $reason = $responseMatch.Groups[3].Value
    }

    $headers = New-Object 'System.Collections.Hashtable' ([System.StringComparer]::OrdinalIgnoreCase)
    for ($index = 1; $index -lt ($lines.Count - 2); $index++) {
        $line = $lines[$index]
        if ($line -match '^[ \t]') {
            throw [System.IO.InvalidDataException]::new('Obsolete folded HTTP header lines are not supported.')
        }
        $colon = $line.IndexOf(':')
        if ($colon -le 0) {
            throw [System.IO.InvalidDataException]::new('An HTTP header field is malformed.')
        }
        $name = $line.Substring(0, $colon)
        $value = $line.Substring($colon + 1) -replace '^[ \t]+|[ \t]+$', ''
        if ($name -notmatch '^[!#$%&''*+\-.^_`|~0-9A-Za-z]+$' -or
            $value -match '[\x00-\x08\x0A-\x1F\x7F]') {
            throw [System.IO.InvalidDataException]::new('An HTTP header field contains invalid characters.')
        }

        if ($headers.Contains($name)) {
            if ($name -ieq 'Host' -or $name -ieq 'Authorization' -or $name -ieq 'Proxy-Authorization') {
                throw [System.IO.InvalidDataException]::new('A singleton HTTP header field appears more than once.')
            }
            if ($name -ieq 'Set-Cookie') {
                $headers[$name] = [string[]](@($headers[$name]) + @($value))
            }
            elseif ($name -ieq 'Cookie') {
                $headers[$name] = [string]$headers[$name] + '; ' + $value
            }
            else {
                $headers[$name] = [string]$headers[$name] + ', ' + $value
            }
        }
        else {
            $headers[$name] = $value
        }
    }

    if ($headers.Contains('Connection')) {
        foreach ($connectionToken in ([string]$headers['Connection']).Split(',')) {
            $connectionName = $connectionToken.Trim()
            if ($connectionName -notmatch '^[!#$%&''*+\-.^_`|~0-9A-Za-z]+$') {
                throw [System.IO.InvalidDataException]::new('The Connection header contains a malformed field name.')
            }
            if ($connectionName -ieq 'Host' -or $connectionName -ieq 'Content-Length' -or
                $connectionName -ieq 'Transfer-Encoding' -or $connectionName -ieq 'Trailer') {
                throw [System.IO.InvalidDataException]::new('Connection cannot nominate a framing or routing header.')
            }
            if ($Kind -eq 'Request' -and $connectionName -ieq 'Upgrade' -and -not $HeadersOnly) {
                throw [System.NotSupportedException]::new('HTTP protocol upgrades are outside Mihari HTTP/1.1 support.')
            }
        }
    }
    if ($Kind -eq 'Request' -and $headers.Contains('Upgrade') -and -not $HeadersOnly) {
        throw [System.NotSupportedException]::new('HTTP protocol upgrades are outside Mihari HTTP/1.1 support.')
    }

    if ($Kind -eq 'Request' -and $headers.Contains('Expect') -and -not $HeadersOnly) {
        throw [System.NotSupportedException]::new('HTTP Expect extensions, including 100-continue, are not supported.')
    }

    $body = [byte[]]@()
    if (-not $HeadersOnly) {
        $body = Read-MihariHttpBody -Stream $Stream -Headers $headers -Kind $Kind `
            -StatusCode $(if ($null -eq $statusCode) { 0 } else { $statusCode }) -RequestMethod $RequestMethod
    }
    $message = [pscustomobject]@{
        Method = $method
        Target = $target
        Version = $version
        StatusCode = $statusCode
        Reason = $reason
        Headers = $headers
        RawHeaders = [byte[]]$rawHeaderBlock
        Body = [byte[]]$body
        Host = $null
        Port = $null
        Path = $null
        Scheme = $null
    }
    if ($Kind -eq 'Request') {
        $resolved = Get-MihariTarget -Message $message
        $message.Host = $resolved.Host
        $message.Port = $resolved.Port
        $message.Path = $resolved.Path
        $message.Scheme = $resolved.Scheme
    }
    return $message
}

function Read-MihariHttpHead {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][System.IO.Stream]$Stream,
        [Parameter(Mandatory = $true)][ValidateSet('Request', 'Response')][string]$Kind,
        [string]$RequestMethod,
        [Nullable[byte]]$InitialByte
    )
    $readArguments = @{ Stream = $Stream; Kind = $Kind; RequestMethod = $RequestMethod; HeadersOnly = $true }
    if ($PSBoundParameters.ContainsKey('InitialByte')) { $readArguments.InitialByte = $InitialByte }
    return Read-MihariHttpMessage @readArguments
}

function ConvertTo-MihariAuthority {
    param(
        [Parameter(Mandatory = $true)][string]$Authority,
        [int]$DefaultPort = 0,
        [switch]$RequirePort
    )

    $value = $Authority.Trim()
    if ($value.Length -eq 0 -or $value -match '[\x00-\x20\x7F/@?#,]') {
        throw [System.IO.InvalidDataException]::new('The HTTP authority is malformed.')
    }

    $hostName = $null
    $portText = $null
    $isIpv6 = $false
    if ($value.StartsWith('[')) {
        $match = [System.Text.RegularExpressions.Regex]::Match($value,
            '^\[(?<host>[^\]]+)\](?::(?<port>[0-9]+))?$')
        if (-not $match.Success) {
            throw [System.IO.InvalidDataException]::new('The bracketed HTTP authority is malformed.')
        }
        $hostName = $match.Groups['host'].Value
        $isIpv6 = $true
        if ($match.Groups['port'].Success) { $portText = $match.Groups['port'].Value }
        $parsedAddress = $null
        if ($hostName.Contains('%') -or -not [System.Net.IPAddress]::TryParse($hostName, [ref]$parsedAddress) -or
            $parsedAddress.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
            throw [System.IO.InvalidDataException]::new('The IPv6 host is invalid or scoped.')
        }
        $hostName = $parsedAddress.ToString().ToLowerInvariant()
    }
    else {
        $colonCount = ([regex]::Matches($value, ':')).Count
        if ($colonCount -gt 1) {
            throw [System.IO.InvalidDataException]::new('IPv6 authorities must bracket the host.')
        }
        if ($colonCount -eq 1) {
            $colon = $value.LastIndexOf(':')
            $hostName = $value.Substring(0, $colon)
            $portText = $value.Substring($colon + 1)
        }
        else {
            $hostName = $value
        }
        if ($hostName.Length -eq 0) {
            throw [System.IO.InvalidDataException]::new('The HTTP authority has no host.')
        }
        $address = $null
        if ([System.Net.IPAddress]::TryParse($hostName, [ref]$address)) {
            if ($address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
                throw [System.IO.InvalidDataException]::new('IPv6 authorities must bracket the host.')
            }
            $hostName = $address.ToString()
        }
        elseif ([System.Uri]::CheckHostName($hostName) -ne [System.UriHostNameType]::Dns) {
            throw [System.IO.InvalidDataException]::new('The DNS host is invalid.')
        }
        else {
            try {
                $idn = New-Object System.Globalization.IdnMapping
                $hostName = $idn.GetAscii($hostName).ToLowerInvariant()
            }
            catch {
                throw [System.IO.InvalidDataException]::new('The DNS host is invalid.')
            }
        }
    }

    if ($null -ne $portText) {
        if ($portText -notmatch '^[0-9]{1,5}$') {
            throw [System.IO.InvalidDataException]::new('The port in the HTTP authority is invalid.')
        }
        $port = [int]$portText
        if ($port -lt 1 -or $port -gt 65535) {
            throw [System.IO.InvalidDataException]::new('The port in the HTTP authority is outside 1..65535.')
        }
        $explicitPort = $true
    }
    else {
        if ($RequirePort -or $DefaultPort -lt 1 -or $DefaultPort -gt 65535) {
            throw [System.IO.InvalidDataException]::new('The HTTP authority must include a port.')
        }
        $port = $DefaultPort
        $explicitPort = $false
    }

    if ($isIpv6) { $formattedHost = '[' + $hostName + ']' } else { $formattedHost = $hostName }
    $formattedAuthority = $formattedHost + ':' + $port.ToString([System.Globalization.CultureInfo]::InvariantCulture)
    return [pscustomobject]@{
        Host = $hostName
        Port = $port
        ExplicitPort = $explicitPort
        Authority = $formattedAuthority
    }
}

function ConvertTo-MihariConnectAuthority {
    param(
        [Parameter(Mandatory = $true)][string]$HostName,
        [Parameter(Mandatory = $true)][int]$DefaultPort
    )

    $authorityText = $HostName.Trim()
    if (-not $authorityText.StartsWith('[')) {
        $address = $null
        if ([System.Net.IPAddress]::TryParse($authorityText, [ref]$address) -and
            $address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
            $authorityText = '[' + $address.ToString() + ']'
        }
    }
    return ConvertTo-MihariAuthority -Authority $authorityText -DefaultPort $DefaultPort
}

function Format-MihariUriHost {
    param([Parameter(Mandatory = $true)][string]$HostName)
    if ($HostName.Contains(':')) { return '[' + $HostName + ']' }
    return $HostName
}

function Get-MihariHeaderText {
    param(
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Headers,
        [Parameter(Mandatory = $true)][string]$Name
    )
    if (-not $Headers.Contains($Name)) { return $null }
    $value = $Headers[$Name]
    if ($value -is [System.Array] -or $value -is [System.Collections.IList]) {
        if ($value.Count -ne 1) {
            throw [System.IO.InvalidDataException]::new('Multiple values make HTTP authority ambiguous.')
        }
        return [string]$value[0]
    }
    return [string]$value
}

function Get-MihariTarget {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Message,
        [string]$ConnectHost,
        [Nullable[int]]$ConnectPort
    )

    $method = [string]$Message.Method
    $requestTarget = [string]$Message.Target
    $headers = $Message.Headers
    if ($null -eq $headers) {
        $headers = New-Object 'System.Collections.Hashtable' ([System.StringComparer]::OrdinalIgnoreCase)
    }
    $hostHeader = Get-MihariHeaderText -Headers $headers -Name 'Host'

    if ($method -ieq 'CONNECT') {
        $authority = ConvertTo-MihariAuthority -Authority $requestTarget -RequirePort
        if ($hostHeader) {
            $headerAuthority = ConvertTo-MihariAuthority -Authority $hostHeader -DefaultPort $authority.Port
            if ($headerAuthority.Host -ine $authority.Host -or $headerAuthority.Port -ne $authority.Port) {
                throw [System.IO.InvalidDataException]::new('The CONNECT request target and Host field disagree.')
            }
        }
        if ($ConnectHost) {
            $expectedPort = 443
            if ($null -ne $ConnectPort) { $expectedPort = [int]$ConnectPort }
            $expected = ConvertTo-MihariConnectAuthority -HostName $ConnectHost -DefaultPort $expectedPort
            if ($expected.Host -ine $authority.Host -or $expected.Port -ne $authority.Port) {
                throw [System.IO.InvalidDataException]::new('The CONNECT target does not match its enclosing CONNECT authority.')
            }
        }
        return [pscustomobject]@{
            Host = $authority.Host; Port = $authority.Port; Scheme = 'https';
            Path = ''; OriginTarget = ''; UpstreamTarget = $authority.Authority;
            AbsoluteTarget = ''
        }
    }

    if ($requestTarget -match '^https?://') {
        if ($requestTarget.Contains('#')) {
            throw [System.IO.InvalidDataException]::new('An HTTP request target must not contain a fragment.')
        }
        $absoluteMatch = [System.Text.RegularExpressions.Regex]::Match($requestTarget,
            '^(?<scheme>https?)://(?<authority>[^/?#]+)(?<path>/[^?#]*)?(?<query>\?[^#]*)?$',
            [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        if (-not $absoluteMatch.Success) {
            throw [System.IO.InvalidDataException]::new('The absolute HTTP request target is malformed.')
        }
        $scheme = $absoluteMatch.Groups['scheme'].Value.ToLowerInvariant()
        $defaultPort = 80
        if ($scheme -eq 'https') { $defaultPort = 443 }
        $authority = ConvertTo-MihariAuthority -Authority $absoluteMatch.Groups['authority'].Value -DefaultPort $defaultPort
        $pathPart = $absoluteMatch.Groups['path'].Value
        if (-not $pathPart) { $pathPart = '/' }
        $originTarget = $pathPart + $absoluteMatch.Groups['query'].Value

        if ($hostHeader) {
            $headerAuthority = ConvertTo-MihariAuthority -Authority $hostHeader -DefaultPort $defaultPort
            if ($headerAuthority.Host -ine $authority.Host -or $headerAuthority.Port -ne $authority.Port) {
                throw [System.IO.InvalidDataException]::new('The absolute request target and Host field disagree.')
            }
        }
        else {
            throw [System.IO.InvalidDataException]::new('An HTTP/1.1 request requires a Host field.')
        }

        if ($ConnectHost) {
            if ($scheme -ne 'https') {
                throw [System.IO.InvalidDataException]::new('A decrypted TLS request must use the HTTPS scheme.')
            }
            $expectedPort = 443
            if ($null -ne $ConnectPort) { $expectedPort = [int]$ConnectPort }
            $expected = ConvertTo-MihariConnectAuthority -HostName $ConnectHost -DefaultPort $expectedPort
            if ($expected.Host -ine $authority.Host -or $expected.Port -ne $authority.Port) {
                throw [System.IO.InvalidDataException]::new('The absolute request target does not match its enclosing CONNECT authority.')
            }
            if ($hostHeader) {
                $headerAuthority = ConvertTo-MihariAuthority -Authority $hostHeader -DefaultPort $expectedPort
                if ($headerAuthority.Host -ine $expected.Host -or $headerAuthority.Port -ne $expected.Port) {
                    throw [System.IO.InvalidDataException]::new('The Host field does not match its enclosing CONNECT authority.')
                }
            }
            $scheme = 'https'
            $authority = $expected
            $upstreamTarget = $originTarget
        }
        else {
            $upstreamTarget = $requestTarget
        }
        $absoluteTarget = $scheme + '://' + (Format-MihariUriHost -HostName $authority.Host)
        if ($authority.Port -ne $defaultPort) { $absoluteTarget += ':' + $authority.Port }
        $absoluteTarget += $originTarget
        return [pscustomobject]@{
            Host = $authority.Host; Port = $authority.Port; Scheme = $scheme;
            Path = $originTarget; OriginTarget = $originTarget; UpstreamTarget = $upstreamTarget;
            AbsoluteTarget = $absoluteTarget
        }
    }

    if ($requestTarget -eq '*') {
        if ($method -ine 'OPTIONS') {
            throw [System.IO.InvalidDataException]::new('The asterisk request target is valid only for OPTIONS.')
        }
        $path = '*'
    }
    elseif ($requestTarget.StartsWith('/')) {
        if ($requestTarget.Contains('#') -or $requestTarget -match '[\x00-\x20\x7F]') {
            throw [System.IO.InvalidDataException]::new('The origin-form request target contains invalid characters.')
        }
        $path = $requestTarget
    }
    else {
        throw [System.IO.InvalidDataException]::new('Only origin-form, absolute-form, and CONNECT authority-form request targets are supported.')
    }

    if ($ConnectHost) {
        $expectedPort = 443
        if ($null -ne $ConnectPort) { $expectedPort = [int]$ConnectPort }
        $expected = ConvertTo-MihariConnectAuthority -HostName $ConnectHost -DefaultPort $expectedPort
        if (-not $hostHeader) {
            throw [System.IO.InvalidDataException]::new('A decrypted HTTP/1.1 request requires a Host field.')
        }
        $actual = ConvertTo-MihariAuthority -Authority $hostHeader -DefaultPort $expectedPort
        if ($actual.Host -ine $expected.Host -or $actual.Port -ne $expected.Port) {
            throw [System.IO.InvalidDataException]::new('The Host field does not match its enclosing CONNECT authority.')
        }
        return [pscustomobject]@{
            Host = $expected.Host; Port = $expected.Port; Scheme = 'https';
            Path = $path; OriginTarget = $path; UpstreamTarget = $path;
            AbsoluteTarget = ('https://' + (Format-MihariUriHost -HostName $expected.Host) + $(if ($expected.Port -ne 443) { ':' + $expected.Port } else { '' }) + $path)
        }
    }

    if (-not $hostHeader) {
        throw [System.IO.InvalidDataException]::new('An HTTP/1.1 request requires a Host field.')
    }
    $authority = ConvertTo-MihariAuthority -Authority $hostHeader -DefaultPort 80
    $absoluteTarget = 'http://' + (Format-MihariUriHost -HostName $authority.Host)
    if ($authority.Port -ne 80) { $absoluteTarget += ':' + $authority.Port }
    $absoluteTarget += $path
    return [pscustomobject]@{
        Host = $authority.Host; Port = $authority.Port; Scheme = 'http';
        Path = $path; OriginTarget = $path; UpstreamTarget = $path;
        AbsoluteTarget = $absoluteTarget
    }
}

function Get-MihariSafePath {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Target)

    $path = $Target
    if ($Target -match '^https?://') {
        $match = [System.Text.RegularExpressions.Regex]::Match($Target,
            '^https?://[^/?#]+(?<path>/[^?#]*)?(?<query>\?[^#]*)?(?:#.*)?$',
            [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        if (-not $match.Success) { return '/' }
        $path = $match.Groups['path'].Value
        if (-not $path) { $path = '/' }
        $path += $match.Groups['query'].Value
    }
    if ($path -eq '*' -or $path.Length -eq 0) { return $path }
    $queryIndex = $path.IndexOf('?')
    if ($queryIndex -lt 0) { return $path }
    $prefix = $path.Substring(0, $queryIndex)
    $query = $path.Substring($queryIndex + 1)
    $parts = $query.Split([char]'&')
    $safeParts = New-Object 'System.Collections.Generic.List[string]'
    foreach ($part in $parts) {
        $equals = $part.IndexOf('=')
        if ($equals -lt 0) {
            $safeParts.Add('value=REDACTED')
        }
        else {
            $safeParts.Add($part.Substring(0, $equals) + '=REDACTED')
        }
    }
    return $prefix + '?' + [string]::Join('&', $safeParts.ToArray())
}

function Write-MihariHttpMessage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][System.IO.Stream]$Stream,
        [Parameter(Mandatory = $true)]$Message,
        [string]$RequestTarget,
        [switch]$CloseConnection,
        [switch]$PreserveProxyAuthenticate,
        [switch]$ForwardProxyAuthorization,
        [switch]$HeadersOnly,
        [switch]$UpgradeWebSocket
    )

    $encoding = [System.Text.Encoding]::GetEncoding(28591)
    if ($Message.Method) {
        $target = [string]$Message.Target
        if ($PSBoundParameters.ContainsKey('RequestTarget')) { $target = $RequestTarget }
        if (-not $target -or $target -match '[\x00-\x20\x7F]') {
            throw [System.IO.InvalidDataException]::new('The outgoing HTTP request target is invalid.')
        }
        $startLine = [string]$Message.Method + ' ' + $target + ' ' + [string]$Message.Version + "`r`n"
    }
    else {
        $statusCode = [int]$Message.StatusCode
        $reason = [string]$Message.Reason
        if ($statusCode -lt 100 -or $statusCode -gt 999 -or $reason -match '[\r\n]') {
            throw [System.IO.InvalidDataException]::new('The outgoing HTTP status line is invalid.')
        }
        $startLine = [string]$Message.Version + ' ' + $statusCode.ToString('000')
        if ($reason) { $startLine += ' ' + $reason }
        $startLine += "`r`n"
    }
    $startBytes = $encoding.GetBytes($startLine)
    $Stream.Write($startBytes, 0, $startBytes.Length)

    $headers = $Message.Headers
    if ($null -eq $headers) {
        $headers = New-Object 'System.Collections.Hashtable' ([System.StringComparer]::OrdinalIgnoreCase)
    }
    $drop = New-Object 'System.Collections.Hashtable' ([System.StringComparer]::OrdinalIgnoreCase)
    $drop['Connection'] = $true
    $drop['Keep-Alive'] = $true
    $drop['Proxy-Connection'] = $true
    if (-not $ForwardProxyAuthorization) { $drop['Proxy-Authorization'] = $true }
    if (-not $PreserveProxyAuthenticate) { $drop['Proxy-Authenticate'] = $true }
    if (-not $UpgradeWebSocket) { $drop['Upgrade'] = $true }
    $drop['TE'] = $true
    if ($headers.Contains('Connection')) {
        foreach ($token in ([string]$headers['Connection']).Split(',')) {
            $name = $token.Trim()
            if ($name -match '^[!#$%&''*+\-.^_`|~0-9A-Za-z]+$' -and
                -not ($UpgradeWebSocket -and $name -ieq 'Upgrade')) { $drop[$name] = $true }
        }
    }

    $headerNames = New-Object System.Collections.ArrayList
    foreach ($headerName in $headers.Keys) {
        $name = [string]$headerName
        if ($name -notmatch '^[!#$%&''*+\-.^_`|~0-9A-Za-z]+$') {
            throw [System.IO.InvalidDataException]::new('An outgoing HTTP header name is invalid.')
        }
        if (-not $drop.Contains($name)) { [void]$headerNames.Add($name) }
    }
    $headerNames.Sort([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($name in $headerNames) {
        $values = @($headers[[string]$name])
        foreach ($value in $values) {
            $textValue = [string]$value
            if ($textValue -match '[\x00-\x08\x0A-\x1F\x7F]') {
                throw [System.IO.InvalidDataException]::new('An outgoing HTTP header contains invalid characters.')
            }
            $lineBytes = $encoding.GetBytes([string]$name + ': ' + $textValue + "`r`n")
            $Stream.Write($lineBytes, 0, $lineBytes.Length)
        }
    }
    if ($CloseConnection) {
        $connectionClose = $encoding.GetBytes("Connection: close`r`n")
        $Stream.Write($connectionClose, 0, $connectionClose.Length)
    }
    elseif ($UpgradeWebSocket) {
        $upgradeConnection = $encoding.GetBytes("Connection: Upgrade`r`n")
        $Stream.Write($upgradeConnection, 0, $upgradeConnection.Length)
    }
    $headerTerminator = $encoding.GetBytes("`r`n")
    $Stream.Write($headerTerminator, 0, $headerTerminator.Length)

    $body = [byte[]]@()
    if ($null -ne $Message.Body) { $body = [byte[]]$Message.Body }
    if (-not $HeadersOnly -and $body.Length -gt 0) { $Stream.Write($body, 0, $body.Length) }
}

function Write-MihariHttpHead {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][System.IO.Stream]$Stream,
        [Parameter(Mandatory = $true)]$Message,
        [string]$RequestTarget,
        [switch]$CloseConnection,
        [switch]$PreserveProxyAuthenticate,
        [switch]$ForwardProxyAuthorization,
        [switch]$UpgradeWebSocket
    )
    $arguments = @{
        Stream = $Stream; Message = $Message; HeadersOnly = $true
        CloseConnection = $CloseConnection
        PreserveProxyAuthenticate = $PreserveProxyAuthenticate
        ForwardProxyAuthorization = $ForwardProxyAuthorization
        UpgradeWebSocket = $UpgradeWebSocket
    }
    if ($PSBoundParameters.ContainsKey('RequestTarget')) { $arguments.RequestTarget = $RequestTarget }
    Write-MihariHttpMessage @arguments
}

# Framing is decided before any body byte is forwarded. This keeps a malformed
# length/coding combination from becoming a request smuggling ambiguity.
function Get-MihariHttpBodyFraming {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Message,
        [Parameter(Mandatory = $true)][ValidateSet('Request', 'Response')][string]$Kind,
        [string]$RequestMethod
    )
    $headers = $Message.Headers
    $transferEncoding = Get-MihariHeaderText -Headers $headers -Name 'Transfer-Encoding'
    $contentLength = Get-MihariHeaderText -Headers $headers -Name 'Content-Length'
    if ($transferEncoding -and $contentLength) {
        throw [System.IO.InvalidDataException]::new('A message cannot contain both Transfer-Encoding and Content-Length.')
    }
    if ($Kind -eq 'Response') {
        $status = [int]$Message.StatusCode
        if ($RequestMethod -ieq 'HEAD' -or ($status -ge 100 -and $status -lt 200) -or
            $status -eq 204 -or $status -eq 205 -or $status -eq 304 -or
            ($RequestMethod -ieq 'CONNECT' -and $status -ge 200 -and $status -lt 300)) {
            return [pscustomobject]@{ Kind = 'None'; Length = [long]0; Reusable = ($status -ne 101) }
        }
    }
    if ($transferEncoding) {
        if ($Message.Version -ne 'HTTP/1.1') {
            throw [System.IO.InvalidDataException]::new('HTTP/1.0 cannot use chunked transfer coding.')
        }
        $codings = @($transferEncoding.Split(',') | ForEach-Object { $_.Trim() })
        if ($codings.Count -ne 1 -or $codings[0] -ine 'chunked') {
            throw [System.NotSupportedException]::new('Unsupported HTTP transfer coding.')
        }
        return [pscustomobject]@{ Kind = 'Chunked'; Length = $null; Reusable = $true }
    }
    if ($contentLength) {
        $parts = @($contentLength.Split(',') | ForEach-Object { $_.Trim() })
        if ($parts.Count -eq 0 -or $parts[0] -notmatch '^[0-9]+$') {
            throw [System.IO.InvalidDataException]::new('The HTTP Content-Length field is malformed.')
        }
        foreach ($part in $parts) {
            if ($part -ne $parts[0]) {
                throw [System.IO.InvalidDataException]::new('Conflicting HTTP Content-Length values are ambiguous.')
            }
        }
        $length = [long]0
        if (-not [long]::TryParse($parts[0], [System.Globalization.NumberStyles]::None,
            [System.Globalization.CultureInfo]::InvariantCulture, [ref]$length)) {
            throw [System.IO.InvalidDataException]::new('The HTTP Content-Length is outside the supported range.')
        }
        return [pscustomobject]@{ Kind = 'ContentLength'; Length = $length; Reusable = $true }
    }
    if ($Kind -eq 'Request') {
        return [pscustomobject]@{ Kind = 'None'; Length = [long]0; Reusable = $true }
    }
    return [pscustomobject]@{ Kind = 'CloseDelimited'; Length = $null; Reusable = $false }
}

function Copy-MihariHttpBody {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][System.IO.Stream]$Source,
        [Parameter(Mandatory = $true)][System.IO.Stream]$Destination,
        [Parameter(Mandatory = $true)]$Framing,
        $Session
    )
    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    [long]$bytes = 0
    [long]$writeMs = 0
    $firstByteMs = $null
    $buffer = [byte[]]::new(16384)
    $lineDeadlineMs = 30000
    if ($Source.CanTimeout -and $Source.ReadTimeout -gt $lineDeadlineMs) {
        $lineDeadlineMs = $Source.ReadTimeout
    }
    $copyExact = {
        param([long]$Count)
        [long]$remaining = $Count
        while ($remaining -gt 0) {
            if ($null -ne $Session -and (Test-MihariConnectionStopping -Session $Session)) {
                throw [System.OperationCanceledException]::new('The Mihari session stopped during body relay.')
            }
            $wanted = [int][Math]::Min([long]$buffer.Length, $remaining)
            $read = $Source.Read($buffer, 0, $wanted)
            if ($read -le 0) {
                throw [System.IO.EndOfStreamException]::new('The HTTP body ended before its declared framing length.')
            }
            if ($null -eq $firstByteMs) { $firstByteMs = $timer.ElapsedMilliseconds }
            $beforeWrite = $timer.ElapsedMilliseconds
            $Destination.Write($buffer, 0, $read)
            $writeMs += ($timer.ElapsedMilliseconds - $beforeWrite)
            $bytes += $read
            $remaining -= $read
        }
    }
    switch ([string]$Framing.Kind) {
        'None' { break }
        'ContentLength' { . $copyExact ([long]$Framing.Length); break }
        'CloseDelimited' {
            while ($true) {
                if ($null -ne $Session -and (Test-MihariConnectionStopping -Session $Session)) {
                    throw [System.OperationCanceledException]::new('The Mihari session stopped during body relay.')
                }
                $read = $Source.Read($buffer, 0, $buffer.Length)
                if ($read -le 0) { break }
                if ($null -eq $firstByteMs) { $firstByteMs = $timer.ElapsedMilliseconds }
                $beforeWrite = $timer.ElapsedMilliseconds
                $Destination.Write($buffer, 0, $read)
                $writeMs += ($timer.ElapsedMilliseconds - $beforeWrite)
                $bytes += $read
            }
            break
        }
        'Chunked' {
            while ($true) {
                $line = Read-MihariHttpLine -Stream $Source -DeadlineMs $lineDeadlineMs
                if ($line.Text -notmatch '^[0-9A-Fa-f]+(?:;[\x20-\x7E]*)?$') {
                    throw [System.IO.InvalidDataException]::new('The HTTP chunk size line is malformed.')
                }
                $sizeText = ($line.Text -split ';', 2)[0]
                [long]$size = 0
                if (-not [long]::TryParse($sizeText, [System.Globalization.NumberStyles]::AllowHexSpecifier,
                    [System.Globalization.CultureInfo]::InvariantCulture, [ref]$size) -or $size -lt 0) {
                    throw [System.IO.InvalidDataException]::new('The HTTP chunk size is outside the supported range.')
                }
                if ($null -eq $firstByteMs) { $firstByteMs = $timer.ElapsedMilliseconds }
                $beforeWrite = $timer.ElapsedMilliseconds
                $Destination.Write($line.Bytes, 0, $line.Bytes.Length)
                $writeMs += ($timer.ElapsedMilliseconds - $beforeWrite)
                $bytes += $line.Bytes.Length
                if ($size -eq 0) {
                    $trailerBytes = 0
                    while ($true) {
                        $trailer = Read-MihariHttpLine -Stream $Source -DeadlineMs $lineDeadlineMs
                        $trailerBytes += $trailer.Bytes.Length
                        if ($trailerBytes -gt 65536) {
                            throw [System.IO.InvalidDataException]::new('The HTTP chunk trailers exceed the 65536 byte limit.')
                        }
                        if ($trailer.Text.Length -gt 0) {
                            if ($trailer.Text -match '^[ \t]' -or
                                $trailer.Text -notmatch '^([!#$%&''*+\-.^_`|~0-9A-Za-z]+):[ \t]*([^\x00-\x08\x0A-\x1F\x7F]*)$') {
                                throw [System.IO.InvalidDataException]::new('An HTTP chunk trailer field is malformed.')
                            }
                            if ($matches[1] -match '^(?:Host|Content-Length|Transfer-Encoding|Trailer|Connection|Proxy-Connection|Keep-Alive|TE|Upgrade|Authorization|Proxy-Authorization|Cookie|Set-Cookie)$') {
                                throw [System.IO.InvalidDataException]::new('A forbidden HTTP framing or routing trailer was received.')
                            }
                        }
                        $beforeWrite = $timer.ElapsedMilliseconds
                        $Destination.Write($trailer.Bytes, 0, $trailer.Bytes.Length)
                        $writeMs += ($timer.ElapsedMilliseconds - $beforeWrite)
                        $bytes += $trailer.Bytes.Length
                        if ($trailer.Text.Length -eq 0) { break }
                    }
                    break
                }
                . $copyExact $size
                $delimiter = [byte[]]::new(2)
                $offset = 0
                while ($offset -lt 2) {
                    $read = $Source.Read($delimiter, $offset, 2 - $offset)
                    if ($read -le 0) { throw [System.IO.EndOfStreamException]::new('The HTTP chunk data ended before CRLF.') }
                    $offset += $read
                }
                if ($delimiter[0] -ne 13 -or $delimiter[1] -ne 10) {
                    throw [System.IO.InvalidDataException]::new('The HTTP chunk data is not followed by CRLF.')
                }
                $beforeWrite = $timer.ElapsedMilliseconds
                $Destination.Write($delimiter, 0, 2)
                $writeMs += ($timer.ElapsedMilliseconds - $beforeWrite)
                $bytes += 2
            }
            break
        }
        default { throw [System.IO.InvalidDataException]::new('Unknown HTTP body framing.') }
    }
    $timer.Stop()
    $lastByteMs = $null
    if ($bytes -gt 0) { $lastByteMs = $timer.ElapsedMilliseconds }
    return [pscustomobject]@{
        Bytes = $bytes; FirstByteMs = $firstByteMs; LastByteMs = $lastByteMs
        ForwardWriteMs = $writeMs; Framing = [string]$Framing.Kind
    }
}

function Test-MihariHttpKeepAlive {
    param([Parameter(Mandatory = $true)]$Message)
    $connection = Get-MihariHeaderText -Headers $Message.Headers -Name 'Connection'
    $tokens = @()
    if ($connection) { $tokens = @($connection.Split(',') | ForEach-Object { $_.Trim().ToLowerInvariant() }) }
    if ($tokens -contains 'close') { return $false }
    if ([string]$Message.Version -eq 'HTTP/1.0') { return ($tokens -contains 'keep-alive') }
    return $true
}

function Test-MihariWebSocketRequest {
    param([Parameter(Mandatory = $true)]$Message)
    $upgrade = Get-MihariHeaderText -Headers $Message.Headers -Name 'Upgrade'
    if (-not $upgrade) { return $false }
    $connection = Get-MihariHeaderText -Headers $Message.Headers -Name 'Connection'
    if ($Message.Method -ine 'GET' -or $upgrade -ine 'websocket' -or
        -not $connection -or @($connection.Split(',') | ForEach-Object { $_.Trim().ToLowerInvariant() }) -notcontains 'upgrade') {
        throw [System.NotSupportedException]::new('Only a valid WebSocket HTTP/1.1 upgrade is supported.')
    }
    $key = Get-MihariHeaderText -Headers $Message.Headers -Name 'Sec-WebSocket-Key'
    $version = Get-MihariHeaderText -Headers $Message.Headers -Name 'Sec-WebSocket-Version'
    $keyBytes = $null
    try { $keyBytes = [Convert]::FromBase64String($key) }
    catch { throw [System.IO.InvalidDataException]::new('The WebSocket key is malformed.') }
    if ($null -eq $keyBytes -or $keyBytes.Length -ne 16 -or $version -ne '13') {
        throw [System.IO.InvalidDataException]::new('The WebSocket key or version is invalid.')
    }
    return $true
}

function Test-MihariWebSocketResponse {
    param(
        [Parameter(Mandatory = $true)]$Message,
        $Request
    )
    if ([int]$Message.StatusCode -ne 101) { return $false }
    $upgrade = Get-MihariHeaderText -Headers $Message.Headers -Name 'Upgrade'
    $connection = Get-MihariHeaderText -Headers $Message.Headers -Name 'Connection'
    if ($upgrade -ine 'websocket' -or -not $connection -or
        @($connection.Split(',') | ForEach-Object { $_.Trim().ToLowerInvariant() }) -notcontains 'upgrade') {
        throw [System.IO.InvalidDataException]::new('The upstream WebSocket upgrade response is malformed.')
    }
    if ($null -ne $Request) {
        $requestKey = Get-MihariHeaderText -Headers $Request.Headers -Name 'Sec-WebSocket-Key'
        $actualAccept = Get-MihariHeaderText -Headers $Message.Headers -Name 'Sec-WebSocket-Accept'
        $sha1 = [System.Security.Cryptography.SHA1]::Create()
        try {
            $inputBytes = [System.Text.Encoding]::ASCII.GetBytes($requestKey + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11')
            $expectedAccept = [Convert]::ToBase64String($sha1.ComputeHash($inputBytes))
        }
        finally { $sha1.Dispose() }
        if (-not [string]::Equals([string]$actualAccept, $expectedAccept, [System.StringComparison]::Ordinal)) {
            throw [System.IO.InvalidDataException]::new('The upstream WebSocket accept value does not match the request.')
        }
    }
    return $true
}
