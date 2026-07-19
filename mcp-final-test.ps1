param(
    [string]$Url = 'https://paths-recycling-cellular-detroit.trycloudflare.com/mcp'
)

$ErrorActionPreference = 'Stop'
$results = [ordered]@{}
$script:nextId = 1

function Convert-McpResponse {
    param([string]$Content)
    $trimmed = $Content.Trim()
    if ($trimmed.StartsWith('event:') -or $trimmed.StartsWith('data:')) {
        $data = ($Content -split "`r?`n" | Where-Object { $_.StartsWith('data:') } | ForEach-Object { $_.Substring(5).TrimStart() }) -join "`n"
        return $data | ConvertFrom-Json -Depth 100
    }
    return $Content | ConvertFrom-Json -Depth 100
}

function Invoke-McpTool {
    param([string]$Name, [hashtable]$Arguments = @{}, [int]$TimeoutSec = 90)
    $body = @{ jsonrpc = '2.0'; id = $script:nextId++; method = 'tools/call'; params = @{ name = $Name; arguments = $Arguments } } | ConvertTo-Json -Depth 50
    $raw = Invoke-WebRequest -Uri $Url -Method Post -ContentType 'application/json' -Headers @{ Accept = 'application/json, text/event-stream' } -Body $body -TimeoutSec $TimeoutSec
    $resp = Convert-McpResponse $raw.Content
    if ($resp.error) { return [pscustomobject]@{ ok = $false; jsonRpcError = $resp.error } }
    if (-not $resp.result -or -not $resp.result.content) { return [pscustomobject]@{ ok = $false; malformedResponse = $resp } }
    $content = @($resp.result.content)
    if ($content.Count -eq 0 -or -not $content[0].text) { return [pscustomobject]@{ ok = $false; malformedContent = $resp.result } }
    $text = $content[0].text
    try { return $text | ConvertFrom-Json -Depth 100 } catch { return $text }
}

function Invoke-McpList {
    $body = @{ jsonrpc = '2.0'; id = $script:nextId++; method = 'tools/list'; params = @{} } | ConvertTo-Json -Depth 20
    $raw = Invoke-WebRequest -Uri $Url -Method Post -ContentType 'application/json' -Headers @{ Accept = 'application/json, text/event-stream' } -Body $body -TimeoutSec 60
    return Convert-McpResponse $raw.Content
}

function Save-Step($key, $value) {
    $results[$key] = $value
    $status = if ($value -is [string]) { 'TEXT' } elseif ($value.ok -eq $false) { 'ERR' } else { 'OK' }
    Write-Host "$key => $status"
}

Save-Step 'tools_list' (Invoke-McpList)
Save-Step 'health' (Invoke-McpTool meta_info @{ action = 'health' })
Save-Step 'help' (Invoke-McpTool meta_info @{ action = 'help' })
Save-Step 'tools_meta' (Invoke-McpTool meta_info @{ action = 'tools' })
Save-Step 'describe_all' (Invoke-McpTool meta_info @{ action = 'describe'; tools = @(
    'so_open','so_close','analyze_elf','analyze_functions','analyze_cfg','analyze_crypto','analyze_xrefs','analyze_esil',
    'search_bytes','search_strings','read_disasm','read_hexdump','edit_hex','edit_asm','edit_symbol','edit_fix_sections',
    'emulate_call','emulate_dump','diff_so','session_open','session_history','session_audit','build_so','system_control','meta_info'
) })
Save-Step 'system_status' (Invoke-McpTool system_control @{ action = 'status'; probe = $false })
Save-Step 'so_list' (Invoke-McpTool so_open @{ action = 'list'; limit = 200 })

$items = @()
if ($results.so_list.items) { $items = @($results.so_list.items) }
elseif ($results.so_list.files) { $items = @($results.so_list.files) }

$targets = @()
foreach ($name in @('libjiagu.so', 'libxvcowre.so')) {
    $hit = $items | Where-Object { ($_.name -eq $name) -or ($_.path -like "*$name") -or ($_.filePath -like "*$name") } | Select-Object -First 1
    if ($hit) { $targets += $hit }
}

$workspaceSummaries = @()
foreach ($target in $targets) {
    $path = if ($target.path) { $target.path } elseif ($target.filePath) { $target.filePath } elseif ($target.openPath) { $target.openPath } else { '' }
    $name = if ($target.name) { $target.name } else { Split-Path $path -Leaf }
    Save-Step "open_$name" (Invoke-McpTool so_open @{ path = $path; temporary = $true })
    $open = $results["open_$name"]
    $wid = if ($open.workspaceId) { $open.workspaceId } elseif ($open.workspace -and $open.workspace.id) { $open.workspace.id } else { '' }
    if (-not $wid) { continue }
    $workspaceSummaries += @{ name = $name; workspaceId = $wid; path = $path }

    Save-Step "${name}_elf_stats" (Invoke-McpTool analyze_elf @{ workspaceId = $wid; view = 'stats' })
    Save-Step "${name}_sections" (Invoke-McpTool analyze_elf @{ workspaceId = $wid; view = 'list'; subView = 'sections'; limit = 40 })
    Save-Step "${name}_symbols" (Invoke-McpTool analyze_elf @{ workspaceId = $wid; view = 'list'; subView = 'symbols'; limit = 20 })
    Save-Step "${name}_dynsyms" (Invoke-McpTool analyze_elf @{ workspaceId = $wid; view = 'list'; subView = 'dynsyms'; limit = 20 })
    Save-Step "${name}_strings" (Invoke-McpTool search_strings @{ workspaceId = $wid; limit = 20 })
    Save-Step "${name}_crypto" (Invoke-McpTool analyze_crypto @{ workspaceId = $wid })
    Save-Step "${name}_functions" (Invoke-McpTool analyze_functions @{ workspaceId = $wid })

    $funcs = @()
    if ($results["${name}_functions"].functions) { $funcs = @($results["${name}_functions"].functions) }
    elseif ($results["${name}_functions"] -is [array]) { $funcs = @($results["${name}_functions"]) }
    $fn = $funcs | Where-Object { $_.name -and $_.name -notmatch '^sym\.imp\.' } | Select-Object -First 1
    $locator = if ($fn.locator) { $fn.locator } elseif ($fn.name) { $fn.name } else { '' }
    $textSec = $results["${name}_sections"].items | Where-Object { $_.name -eq '.text' } | Select-Object -First 1
    if ($locator) {
        Save-Step "${name}_disasm" (Invoke-McpTool read_disasm @{ workspaceId = $wid; locator = $locator; limit = 20; maxBytes = 1024 })
        Save-Step "${name}_cfg" (Invoke-McpTool analyze_cfg @{ workspaceId = $wid; locator = $locator })
        Save-Step "${name}_xrefs" (Invoke-McpTool analyze_xrefs @{ workspaceId = $wid; locator = $locator; direction = 'both'; limit = 20 })
        Save-Step "${name}_esil" (Invoke-McpTool analyze_esil @{ workspaceId = $wid; locator = $locator; stepCount = 3 })
    } elseif ($textSec -and $textSec.virtualAddr) {
        Save-Step "${name}_disasm_addr" (Invoke-McpTool read_disasm @{ workspaceId = $wid; addr = $textSec.virtualAddr; limit = 20; maxBytes = 1024 })
    }

    Save-Step "${name}_session_open" (Invoke-McpTool session_open @{ workspaceId = $wid })
    $sid = $results["${name}_session_open"].editSessionId
    if ($sid) {
        Save-Step "${name}_snapshot" (Invoke-McpTool session_history @{ action = 'snapshot'; workspaceId = $wid; editSessionId = $sid; label = 'final-test' })
        if ($textSec) {
            Save-Step "${name}_hex_dryrun" (Invoke-McpTool edit_hex @{ workspaceId = $wid; editSessionId = $sid; locator = '.text'; dryRun = $true; edits = @(@{ byteOffset = 0; newHex = '00' }) })
        }
        if ($locator) {
            Save-Step "${name}_asm_dryrun" (Invoke-McpTool edit_asm @{ workspaceId = $wid; editSessionId = $sid; locator = $locator; dryRun = $true; edits = @(@{ instructionIndex = 0; writeAsm = 'nop' }) })
        }
        Save-Step "${name}_check" (Invoke-McpTool session_history @{ action = 'check'; workspaceId = $wid; editSessionId = $sid })
        Save-Step "${name}_audit" (Invoke-McpTool session_audit @{ action = 'audit'; workspaceId = $wid; editSessionId = $sid })
        Save-Step "${name}_build_dry_list" (Invoke-McpTool build_so @{ action = 'list'; prefix = $name; limit = 20 })
    }
}

$results['workspaceSummaries'] = $workspaceSummaries
$out = Join-Path $PSScriptRoot 'mcp-final-test-results.json'
($results | ConvertTo-Json -Depth 100) | Set-Content -LiteralPath $out -Encoding UTF8
Write-Host "Saved $out"
