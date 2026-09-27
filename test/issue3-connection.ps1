param()

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'TestSupport.ps1')
$sourceRoot = Join-Path (Split-Path $PSScriptRoot -Parent) 'src'
. (Join-Path $sourceRoot 'Http.ps1')
. (Join-Path $sourceRoot 'Observation.ps1')
. (Join-Path $sourceRoot 'Connection.ps1')

$tempRoot = Join-Path ([IO.Path]::GetTempPath()) ('mihari-connection-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($tempRoot)
$eventsPath = Join-Path $tempRoot 'events.jsonl'
$listener = $null
$client = $null
$accepted = $null
$writer = $null
try {
    $writer = New-MihariEventWriter -Path $eventsPath
    $session = [pscustomobject]@{
        Id = [guid]::NewGuid().ToString('N')
        Mode = 'Inspect'
        Writer = $writer
    }
    $listener = New-Object System.Net.Sockets.TcpListener -ArgumentList @([System.Net.IPAddress]::Loopback, 0)
    $listener.Start()
    $port = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
    $client = New-Object System.Net.Sockets.TcpClient
    $client.Connect('127.0.0.1', $port)
    $accepted = $listener.AcceptTcpClient()
    $client.Close()
    $client = $null

    # The listener accepted this socket in Tunnel mode. Simulate the UI
    # switching the mutable session state before its worker starts.
    Handle-MihariConnection -Session $session -Client $accepted -AcceptedMode Tunnel
    $accepted = $null
    Close-MihariEventWriter -Writer $writer

    $events = @([IO.File]::ReadAllLines($eventsPath) | ForEach-Object { ConvertFrom-Json -InputObject $_ -ErrorAction Stop })
    Assert-MihariTest -Condition ($events.Count -eq 2) -Message 'A client EOF before any request must have acceptance and terminal cleanup facts.'
    Assert-MihariTest -Condition ($events[0].stage -eq 'listener.accept' -and $events[1].stage -eq 'connection.cleanup') -Message 'The terminal connection fact must follow acceptance.'
    Assert-MihariTest -Condition ($events[0].connectionId -eq $events[1].connectionId -and $events[0].connectionId) -Message 'The terminal fact must correlate to the accepted connection.'
    Assert-MihariTest -Condition ($events[0].mode -eq 'Tunnel' -and $events[1].mode -eq 'Tunnel') -Message 'A later mode toggle must not relabel an accepted connection.'
    Assert-MihariTest -Condition ($events[1].outcome -eq 'success' -and $null -eq $events[1].requestId) -Message 'A clean EOF must finish successfully without inventing a request.'
    Write-Host 'PASS issue3-connection: EOF terminal fact and immutable accepted mode'
}
finally {
    if ($null -ne $accepted) { $accepted.Close() }
    if ($null -ne $client) { $client.Close() }
    if ($null -ne $listener) { $listener.Stop() }
    if ($null -ne $writer -and -not $writer.Closed) { Close-MihariEventWriter -Writer $writer }
    if ([IO.Directory]::Exists($tempRoot)) { [IO.Directory]::Delete($tempRoot, $true) }
}
