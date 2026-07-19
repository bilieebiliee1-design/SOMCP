param(
    [string]$Url = 'http://127.0.0.1:8000/mcp',
    [string]$SoName = 'libxvcowre.so'
)

$ErrorActionPreference = 'Stop'
$script:nextId = 1
$results = [ordered]@{}

function Convert-McpResponse {
    param($Content)
    $Content = @($Content) -join "`n"
    $trimmed = $Content.Trim()
    $dataLines = @($Content -split "`r?`n" | Where-Object { $_.TrimStart().StartsWith('data:') })
    if ($dataLines.Count -gt 0) {
        $data = ($dataLines | ForEach-Object { $_.TrimStart().Substring(5).TrimStart() }) -join "`n"
        return $data | ConvertFrom-Json
    }
    return $Content | ConvertFrom-Json
}

function Invoke-McpTool {
    param([string]$Name, [hashtable]$Arguments = @{}, [int]$TimeoutSec = 90)
    $body = @{ jsonrpc = '2.0'; id = $script:nextId++; method = 'tools/call'; params = @{ name = $Name; arguments = $Arguments } } | ConvertTo-Json -Depth 50
    $raw = & curl.exe -sS --max-time $TimeoutSec -X POST $Url -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' --data-binary $body
    if ($LASTEXITCODE -ne 0) { throw "curl failed for ${Name} with exit code $LASTEXITCODE" }
    $resp = Convert-McpResponse $raw
    if ($resp.error) { throw "JSON-RPC error for ${Name}: $($resp.error | ConvertTo-Json -Compress -Depth 20)" }
    $text = @($resp.result.content)[0].text
    return $text | ConvertFrom-Json
}

function Assert-Ok {
    param([string]$Name, $Value)
    if ($Value.ok -eq $false) { throw "$Name failed: $($Value | ConvertTo-Json -Compress -Depth 50)" }
    $results[$Name] = $Value
    Write-Host "$Name => OK"
}

Assert-Ok 'health' (Invoke-McpTool meta_info @{ action = 'health' })
Assert-Ok 'open' (Invoke-McpTool so_open @{ path = $SoName; temporary = $true })
$wid = $results.open.workspaceId
if (-not $wid) { throw 'open did not return workspaceId' }

Assert-Ok 'bytes_spaced' (Invoke-McpTool search_bytes @{ workspaceId = $wid; pattern = '5F 24 03 D5'; fromVa = '0x1fc544'; toVa = '0x1fc600' })
Assert-Ok 'bytes_compact' (Invoke-McpTool search_bytes @{ workspaceId = $wid; pattern = '5F2403D5'; fromVa = '0x1fc544'; toVa = '0x1fc600' })
Assert-Ok 'bytes_wildcard' (Invoke-McpTool search_bytes @{ workspaceId = $wid; pattern = '5F 24 ?? D5'; fromVa = '0x1fc544'; toVa = '0x1fc600' })
Assert-Ok 'strings_regex' (Invoke-McpTool search_strings @{ workspaceId = $wid; prefix = 'JNI.*Load'; regex = $true; limit = 5 })

foreach ($key in @('bytes_spaced', 'bytes_compact', 'bytes_wildcard')) {
    $value = $results[$key]
    if ($value.backend -ne 'rizin') { throw "$key did not use rizin backend" }
    if (-not $value.hits -or @($value.hits).Count -lt 1) { throw "$key returned no hits" }
    $hit = @($value.hits)[0]
    if (-not $hit.hexAddr -or -not $hit.fileOffset -or -not $hit.section) { throw "$key hit is missing address enrichment" }
}

if ($results.strings_regex.matchMode -ne 'regex') { throw 'strings_regex did not report regex matchMode' }
if (-not $results.strings_regex.items -or @($results.strings_regex.items).Count -lt 1) { throw 'strings_regex returned no items' }

$out = Join-Path $PSScriptRoot 'mcp-search-regression-results.json'
($results | ConvertTo-Json -Depth 100) | Set-Content -LiteralPath $out -Encoding UTF8
Write-Host "Saved $out"
