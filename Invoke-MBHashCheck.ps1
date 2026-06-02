#Requires -Version 5.1
<#
.SYNOPSIS
    ZavetSec - MalwareBazaar Hash Checker
    Bulk hash triage against MalwareBazaar (abuse.ch) with ThreatFox C2
    enrichment and GeoIP. Free key at auth.abuse.ch.

.DESCRIPTION
    Checks MD5/SHA1/SHA256 hashes against the MalwareBazaar API, enriches
    confirmed hits with ThreatFox IOC intelligence (C2 IPs / domains) and
    GeoIP data (ip-api.com). Outputs to console and a self-contained
    dark-themed HTML report. Requires a free Auth-Key from auth.abuse.ch.

.PARAMETER ApiKey
    MalwareBazaar / ThreatFox Auth-Key (free at auth.abuse.ch). Prompted if omitted.

.PARAMETER HashFile
    Path to a text file containing hashes (one per line, # comments allowed)

.PARAMETER Hashes
    Array of hashes to check

.PARAMETER ScanDirectory
    Scan all files in a directory and compute their SHA256 automatically.
    Combine with -Recurse to include subdirectories.

.PARAMETER Recurse
    Recurse into subdirectories when using -ScanDirectory.

.PARAMETER OutputDir
    Directory for the HTML report (default: current directory)

.PARAMETER MaxRetries
    Number of retry attempts on transient errors (default: 3).

.PARAMETER RetryDelaySeconds
    Seconds to wait between retries (default: 5).

.PARAMETER Quiet
    Suppress NOT_FOUND output - show only MALICIOUS / ERROR results in console.

.PARAMETER PassThru
    Return result objects to the pipeline for further scripting.

.EXAMPLE
    .\Invoke-MBHashCheck.ps1 -ApiKey "YOUR_KEY" -HashFile "hashes.txt"

.EXAMPLE
    .\Invoke-MBHashCheck.ps1 -ApiKey "YOUR_KEY" -ScanDirectory "C:\Suspicious" -Recurse -Quiet

.EXAMPLE
    .\Invoke-MBHashCheck.ps1 -ApiKey "YOUR_KEY" -HashFile "iocs.txt" -PassThru |
        Where-Object Status -eq "MALICIOUS" | Export-Csv hits.csv -NoTypeInformation

.EXAMPLE
    .\Invoke-MBHashCheck.ps1   # interactive: prompts for key, then file path or manual entry

.NOTES
    ZavetSec | MalwareBazaar API: https://bazaar.abuse.ch/api/ | ThreatFox: https://threatfox.abuse.ch
    Supports MD5, SHA1, SHA256.
    NOT IN DB does not mean clean - MalwareBazaar only contains known malware samples.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ApiKey = "",

    [Parameter(Mandatory = $false)]
    [string]$HashFile = "",

    [Parameter(Mandatory = $false)]
    [string[]]$Hashes = @(),

    [Parameter(Mandatory = $false)]
    [string]$ScanDirectory = "",

    [Parameter(Mandatory = $false)]
    [switch]$Recurse,

    [Parameter(Mandatory = $false)]
    [string]$OutputDir = (Get-Location).Path,

    [Parameter(Mandatory = $false)]
    [int]$MaxRetries = 3,

    [Parameter(Mandatory = $false)]
    [int]$RetryDelaySeconds = 5,

    [Parameter(Mandatory = $false)]
    [switch]$Quiet,

    [Parameter(Mandatory = $false)]
    [switch]$PassThru
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Force TLS 1.2 - abuse.ch refuses older protocols, and PS 5.1 on older
# Windows (2012R2 / 2016) may not negotiate it by default.
try {
    [Net.ServicePointManager]::SecurityProtocol = `
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch { }

# ============================================================
# CONST
# ============================================================
$SCRIPT_VERSION = "2.1"
$MB_API_URL     = "https://mb-api.abuse.ch/api/v1/"
$TF_API_URL     = "https://threatfox-api.abuse.ch/api/v1/"
$GEOIP_URL      = "http://ip-api.com/json"
$DELAY_MS       = 1000   # 1 sec between MB requests - being polite
$GEOIP_DELAY_MS = 1500   # ip-api free tier = 45 req/min -> >=1334ms apart
$UA             = "ZavetSec-MBHashCheck/$SCRIPT_VERSION (github.com/zavetsec)"

# ip-api free tier is rate limited (45/min). If we hit 429 we stop trying
# GeoIP for the rest of the run instead of silently failing every call.
$script:GeoIPDisabled = $false

# ============================================================
# HELPERS
# ============================================================
function Write-Banner {
    # Single-quoted here-string: backticks and $ are literal here, so the
    # ASCII art is not mangled by PowerShell escape processing.
    $banner = @'
 ______               _    _____           
|___  /              | |  / ____|          
   / / __ ___   _____| |_| (___   ___  ___ 
  / / / _` \ \ / / _ \ __|\___ \ / _ \/ __|
 / /_| (_| |\ V /  __/ |_ ____) |  __/ (__ 
/_____\__,_| \_/ \___|\__|_____/ \___|\___|
'@
    Write-Host $banner -ForegroundColor Cyan
    Write-Host "   ZavetSec - MalwareBazaar Hash Checker v$SCRIPT_VERSION" -ForegroundColor Cyan
    Write-Host "   MalwareBazaar + ThreatFox + GeoIP | Free key: auth.abuse.ch" -ForegroundColor Cyan
    Write-Host ("-" * 54) -ForegroundColor DarkGray
}

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $ts = Get-Date -Format "HH:mm:ss"
    $color = switch ($Level) {
        "INFO"    { "Gray" }
        "OK"      { "Green" }
        "WARN"    { "Yellow" }
        "ERROR"   { "Red" }
        "HEAD"    { "Cyan" }
        default   { "Gray" }
    }
    Write-Host "[$ts] " -ForegroundColor DarkGray -NoNewline
    Write-Host "[$Level] " -ForegroundColor $color -NoNewline
    Write-Host $Message -ForegroundColor White
}

function Test-HashFormat {
    param([string]$Hash)
    return ($Hash -match '^[A-Fa-f0-9]{32}$') -or
           ($Hash -match '^[A-Fa-f0-9]{40}$') -or
           ($Hash -match '^[A-Fa-f0-9]{64}$')
}

function Get-HashType {
    param([string]$Hash)
    switch ($Hash.Length) {
        32 { return "MD5" }
        40 { return "SHA1" }
        64 { return "SHA256" }
        default { return "UNKNOWN" }
    }
}

# Safe property extraction - PSObject.Properties avoids StrictMode errors.
function Get-Prop {
    param($obj, [string]$name, [string]$default = "N/A")
    $p = $obj.PSObject.Properties[$name]
    if ($p -and $null -ne $p.Value -and "$($p.Value)" -ne "") { return "$($p.Value)" }
    return $default
}

# Extract HTTP status code from an error record (works on PS 5.1 WebException
# and PS 7 HttpResponseException). Returns 0 when there is no HTTP response.
function Get-HttpStatus {
    param($ErrorRecord)
    $sc = 0
    try {
        $resp = $ErrorRecord.Exception.PSObject.Properties["Response"]
        if ($resp -and $resp.Value) {
            $scp = $resp.Value.PSObject.Properties["StatusCode"]
            if ($scp -and $null -ne $scp.Value) { $sc = [int]$scp.Value }
        }
    } catch { $sc = 0 }
    return $sc
}

# HTML-escape any value that originates from an API (file names, tags,
# signatures, ThreatFox fields etc. are attacker-influenced). Self-contained.
function ConvertTo-HtmlSafe {
    param($Text)
    if ($null -eq $Text) { return "" }
    $s = [string]$Text
    $s = $s -replace '&', '&amp;'
    $s = $s -replace '<', '&lt;'
    $s = $s -replace '>', '&gt;'
    $s = $s -replace '"', '&quot;'
    $s = $s -replace "'", '&#39;'
    return $s
}

# Load and validate hashes from a text file into the target list (dedup).
# Returns the number of valid hashes added.
function Import-HashFile {
    param(
        [string]$Path,
        [System.Collections.Generic.List[string]]$Target
    )
    $added = 0
    $lines = Get-Content -LiteralPath $Path -ErrorAction Stop |
        Where-Object { $_.Trim() -ne "" -and $_ -notmatch "^\s*#" }
    foreach ($line in $lines) {
        $h = $line.Trim().ToLower()
        if (Test-HashFormat $h) {
            if (-not $Target.Contains($h)) { $Target.Add($h); $added++ }
        }
        else {
            Write-Log "Skipping invalid hash: $h" "WARN"
        }
    }
    return $added
}

# ============================================================
# MB API CALL
# ============================================================
function Invoke-MBLookup {
    param([string]$Hash, [string]$Key, [int]$Retries = 3, [int]$RetryDelay = 5)

    $result = [PSCustomObject]@{
        Hash         = $Hash
        HashType     = Get-HashType $Hash
        Status       = "UNKNOWN"
        FileName     = "N/A"
        FileType     = "N/A"
        FileSize     = "N/A"
        MimeType     = "N/A"
        Signer       = "N/A"
        Tags         = "N/A"
        Signature    = "N/A"
        Reporter     = "N/A"
        FirstSeen    = "N/A"
        LastSeen     = "N/A"
        DeliveryMethod = "N/A"
        Intelligence = "N/A"
        MBLink       = "https://bazaar.abuse.ch/browse.php?search=sha256%3A$Hash"
        SHA256       = "N/A"
        MD5          = "N/A"
        SHA1         = "N/A"
        TFIOCs       = @()
        TFEnriched   = $false
        Error        = ""
    }

    # --- Request with retry. Nothing throws out of this function: every
    #     failure path returns a populated $result so the run continues. ---
    $response = $null
    $attempt  = 0
    while ($true) {
        $attempt++
        try {
            $body = @{ query = "get_info"; hash = $Hash }
            $headers = @{ "Auth-Key" = $Key; "User-Agent" = $UA }
            $response = Invoke-RestMethod `
                -Uri $MB_API_URL -Method POST -Body $body -Headers $headers -ErrorAction Stop
            break
        }
        catch {
            $sc = Get-HttpStatus $_

            # 401 / 403 -> bad or missing Auth-Key: fatal for the whole run
            if ($sc -eq 401 -or $sc -eq 403) {
                $result.Status = "AUTH_ERROR"
                $result.Error  = "Auth-Key rejected (HTTP $sc)"
                return $result
            }
            # 429 or 5xx or transient network error -> retry
            $retryable = ($sc -eq 429) -or ($sc -ge 500) -or ($sc -eq 0)
            if ($retryable -and $attempt -le $Retries) {
                Start-Sleep -Seconds $RetryDelay
                continue
            }
            # give up gracefully
            $result.Status = "ERROR"
            $result.Error  = "Request failed (HTTP $sc): $($_.Exception.Message)"
            return $result
        }
    }

    try {
        $qs = Get-Prop $response "query_status" ""

        switch ($qs) {
            { $_ -in @("unknown_auth_key", "unauthenticated", "auth_required") } {
                $result.Status = "AUTH_ERROR"
                $result.Error  = "Auth-Key invalid or missing ($qs)"
                return $result
            }
            { $_ -in @("illegal_hash", "no_hash", "illegal_sha256_hash") } {
                $result.Status = "ERROR"
                $result.Error  = "Malformed hash rejected by API ($qs)"
                return $result
            }
            { $_ -in @("hash_not_found", "no_results") } {
                $result.Status = "NOT_FOUND"
                $result.Error  = "Not in MalwareBazaar database"
                return $result
            }
        }

        if ($qs -ne "ok" -or -not $response.data) {
            $result.Status = "ERROR"
            $result.Error  = "Unexpected response: $qs"
            return $result
        }

        # data can be array or single object depending on PS JSON deserializer
        if ($response.data -is [System.Array]) { $d = $response.data[0] }
        else { $d = $response.data }
        if (-not $d) {
            $result.Status = "NOT_FOUND"
            $result.Error  = "Empty data in response"
            return $result
        }

        $result.Status    = "MALICIOUS"
        $result.SHA256    = Get-Prop $d "sha256_hash"
        $result.MD5       = Get-Prop $d "md5_hash"
        $result.SHA1      = Get-Prop $d "sha1_hash"
        $result.FileName  = Get-Prop $d "file_name"
        $result.FileType  = Get-Prop $d "file_type"
        $result.MimeType  = Get-Prop $d "mime_type"
        $result.Reporter  = Get-Prop $d "reporter"
        $result.FirstSeen = Get-Prop $d "first_seen"
        $result.LastSeen  = Get-Prop $d "last_seen"
        $result.Signature = Get-Prop $d "signature"

        # Fallback 1: popular_threat_classification -> suggested_threat_label
        if ($result.Signature -eq "N/A") {
            $ptcProp = $d.PSObject.Properties["popular_threat_classification"]
            if ($ptcProp -and $ptcProp.Value) {
                $lblProp = $ptcProp.Value.PSObject.Properties["suggested_threat_label"]
                if ($lblProp -and $lblProp.Value) { $result.Signature = "$($lblProp.Value)" }
            }
        }
        # Fallback 2: first YARA rule name
        if ($result.Signature -eq "N/A") {
            $yaraProp = $d.PSObject.Properties["yara_rules"]
            if ($yaraProp -and $yaraProp.Value) {
                $yaraArr = @($yaraProp.Value)
                if ($yaraArr.Count -gt 0) {
                    $rnProp = $yaraArr[0].PSObject.Properties["rule_name"]
                    if ($rnProp -and $rnProp.Value) { $result.Signature = "$($rnProp.Value)" }
                }
            }
        }
        $result.DeliveryMethod = Get-Prop $d "delivery_method"

        $fsProp = $d.PSObject.Properties["file_size"]
        if ($fsProp -and $fsProp.Value) {
            $kb = [math]::Round([double]$fsProp.Value / 1KB, 1)
            $result.FileSize = "$kb KB ($($fsProp.Value) bytes)"
        }

        $tagsProp = $d.PSObject.Properties["tags"]
        if ($tagsProp -and $tagsProp.Value) {
            $tagArr = @($tagsProp.Value)
            if ($tagArr.Count -gt 0) { $result.Tags = $tagArr -join ", " }
        }
        # Fallback: vendor_intel -> ANY.RUN -> malware_family
        if ($result.Tags -eq "N/A") {
            $viProp = $d.PSObject.Properties["vendor_intel"]
            if ($viProp -and $viProp.Value) {
                $arProp = $viProp.Value.PSObject.Properties["ANY.RUN"]
                if ($arProp -and $arProp.Value) {
                    $arArr = @($arProp.Value)
                    if ($arArr.Count -gt 0) {
                        $tagsParsed = $arArr | ForEach-Object {
                            $tProp = $_.PSObject.Properties["malware_family"]
                            if ($tProp -and $tProp.Value) { "$($tProp.Value)" }
                        } | Where-Object { $_ }
                        if ($tagsParsed) { $result.Tags = ($tagsParsed | Select-Object -Unique) -join ", " }
                    }
                }
            }
        }

        $csProp = $d.PSObject.Properties["code_sign"]
        if ($csProp -and $csProp.Value) {
            $csArr = @($csProp.Value)
            if ($csArr.Count -gt 0) {
                $cnProp = $csArr[0].PSObject.Properties["subject_cn"]
                if ($cnProp) { $result.Signer = "$($cnProp.Value)" }
            }
        }

        $intelParts = @()
        $intelProp = $d.PSObject.Properties["intelligence"]
        if ($intelProp -and $intelProp.Value) {
            $intel = $intelProp.Value
            $cavProp = $intel.PSObject.Properties["clamav"]
            if ($cavProp -and $cavProp.Value) {
                $cavArr = @($cavProp.Value)
                if ($cavArr.Count -gt 0) { $intelParts += "ClamAV: " + ($cavArr -join ", ") }
            }
            $dlProp = $intel.PSObject.Properties["downloads"]
            if ($dlProp -and $dlProp.Value) { $intelParts += "Downloads: $($dlProp.Value)" }
            $ulProp = $intel.PSObject.Properties["uploads"]
            if ($ulProp -and $ulProp.Value) { $intelParts += "Uploads: $($ulProp.Value)" }
        }
        if ($intelParts.Count -gt 0) { $result.Intelligence = $intelParts -join " | " }

        if ($result.SHA256 -ne "N/A") {
            $result.MBLink = "https://bazaar.abuse.ch/sample/$($result.SHA256)/"
        }
    }
    catch {
        $result.Status = "ERROR"
        $result.Error  = $_.Exception.Message
    }

    return $result
}

# ============================================================
# THREATFOX IOC LOOKUP + GeoIP ENRICHMENT
# ============================================================
function Invoke-ThreatFoxLookup {
    param([string]$Hash, [string]$Key)

    $tfResult = [PSCustomObject]@{
        Found = $false
        IOCs  = [System.Collections.Generic.List[object]]::new()
        Error = ""
    }

    try {
        $tfBody = @{ query = "search_hash"; hash = $Hash } | ConvertTo-Json -Compress
        $tfHeaders = @{
            "Auth-Key"     = $Key
            "Content-Type" = "application/json"
            "User-Agent"   = $UA
        }
        $tfResp = Invoke-RestMethod `
            -Uri $TF_API_URL -Method POST -Body $tfBody -Headers $tfHeaders -ErrorAction Stop

        $qs = Get-Prop $tfResp "query_status" ""
        if ($qs -ne "ok") { return $tfResult }

        $dataProp = $tfResp.PSObject.Properties["data"]
        if (-not $dataProp -or -not $dataProp.Value) { return $tfResult }
        $dataArr = @($dataProp.Value)
        if ($dataArr.Count -eq 0) { return $tfResult }

        $tfResult.Found = $true
        $seen = [System.Collections.Generic.HashSet[string]]::new()

        foreach ($ioc in $dataArr) {
            $iocStr  = Get-Prop $ioc "ioc"
            $typeStr = Get-Prop $ioc "ioc_type"
            $ttStr   = Get-Prop $ioc "threat_type"
            $malStr  = Get-Prop $ioc "malware_printable"
            $confStr = Get-Prop $ioc "confidence_level" "0"
            $fsStr   = Get-Prop $ioc "first_seen"
            $repStr  = Get-Prop $ioc "reporter"

            if (-not $seen.Add($iocStr)) { continue }   # dedup

            $entry = [PSCustomObject]@{
                IOC        = $iocStr
                IOCType    = $typeStr
                ThreatType = $ttStr
                Malware    = $malStr
                Confidence = $confStr
                FirstSeen  = $fsStr
                Reporter   = $repStr
                GeoCountry = "N/A"
                GeoCC      = "N/A"
                GeoCity    = "N/A"
                ASN        = "N/A"
                ISP        = "N/A"
                TFLink     = "https://threatfox.abuse.ch/browse.php?search=ioc%3A$iocStr"
            }

            # GeoIP only for IP-type IOCs, and only while not rate-limited
            $isIP = ($typeStr -in @("ip:port", "ip")) -or ($iocStr -match '^\d{1,3}(\.\d{1,3}){3}')
            if ($isIP -and -not $script:GeoIPDisabled) {
                $cleanIP = ($iocStr -replace ':\d+$', '').Trim()
                try {
                    $geo = Invoke-RestMethod `
                        -Uri "$GEOIP_URL/$cleanIP`?fields=status,country,countryCode,city,isp,as" `
                        -Method GET -ErrorAction Stop
                    if ((Get-Prop $geo "status" "") -eq "success") {
                        $entry.GeoCountry = Get-Prop $geo "country"
                        $entry.GeoCC      = Get-Prop $geo "countryCode"
                        $entry.GeoCity    = Get-Prop $geo "city"
                        $entry.ISP        = Get-Prop $geo "isp"
                        $entry.ASN        = Get-Prop $geo "as"
                    }
                    Start-Sleep -Milliseconds $GEOIP_DELAY_MS
                }
                catch {
                    if ((Get-HttpStatus $_) -eq 429) {
                        $script:GeoIPDisabled = $true
                        Write-Log "ip-api rate limit hit (45/min) - GeoIP disabled for the rest of this run." "WARN"
                    }
                }
            }

            $tfResult.IOCs.Add($entry)
        }
    }
    catch {
        $tfResult.Error = $_.Exception.Message
    }

    return $tfResult
}

# ============================================================
# HTML REPORT
# ============================================================
function New-HtmlReport {
    param([array]$Results, [string]$OutputPath)

    $malCount  = @($Results | Where-Object { $_.Status -eq "MALICIOUS" }).Count
    $nfCount   = @($Results | Where-Object { $_.Status -eq "NOT_FOUND" }).Count
    $errCount  = @($Results | Where-Object { $_.Status -eq "ERROR" -or $_.Status -eq "AUTH_ERROR" }).Count
    $total     = @($Results).Count
    $reportTs  = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    $rowsHtml = ""
    foreach ($r in $Results) {
        $statusClass = switch ($r.Status) {
            "MALICIOUS" { "status-mal" }
            "NOT_FOUND" { "status-nf" }
            default     { "status-err" }
        }
        $badge = switch ($r.Status) {
            "MALICIOUS" { "<span class='badge badge-mal'>&#9888; MALICIOUS</span>" }
            "NOT_FOUND" { "<span class='badge badge-nf'>&#63; NOT IN DB</span>" }
            default     { "<span class='badge badge-err'>&#33; ERROR</span>" }
        }

        # All API-derived values are HTML-escaped before insertion.
        $eHash      = ConvertTo-HtmlSafe $r.Hash
        $eHashType  = ConvertTo-HtmlSafe $r.HashType
        $eFileName  = ConvertTo-HtmlSafe $r.FileName
        $eFileType  = ConvertTo-HtmlSafe $r.FileType
        $eFileSize  = ConvertTo-HtmlSafe $r.FileSize
        $eFirstSeen = ConvertTo-HtmlSafe $r.FirstSeen
        $eSHA256    = ConvertTo-HtmlSafe $r.SHA256
        $eSHA1      = ConvertTo-HtmlSafe $r.SHA1
        $eMD5       = ConvertTo-HtmlSafe $r.MD5
        $eMBLink    = ConvertTo-HtmlSafe $r.MBLink

        $shortHash = if ($r.Hash.Length -ge 16) {
            $r.Hash.Substring(0,8) + "..." + $r.Hash.Substring($r.Hash.Length - 8)
        } else { $r.Hash }
        $shortHash = ConvertTo-HtmlSafe $shortHash

        $tagsHtml = ""
        if ($r.Tags -ne "N/A") {
            $tagItems = $r.Tags -split ", " | ForEach-Object { "<span class='tag'>$(ConvertTo-HtmlSafe $_)</span>" }
            $tagsHtml = $tagItems -join " "
        } else { $tagsHtml = "<span class='dim'>-</span>" }

        $hashesDetail = ""
        if ($r.Status -eq "MALICIOUS") {
            $hashesDetail = @"
<details>
<summary class='sum-hashes'>All Hashes</summary>
<div class='hash-detail'>
  <span class='hl'>SHA256:</span> <span class='hv'>$eSHA256</span><br>
  <span class='hl'>SHA1:</span>   <span class='hv'>$eSHA1</span><br>
  <span class='hl'>MD5:</span>    <span class='hv'>$eMD5</span>
</div>
</details>
"@
        }

        $intelDisp = if ($r.Intelligence -ne "N/A") { ConvertTo-HtmlSafe $r.Intelligence } else { "<span class='dim'>-</span>" }
        $sigDisp   = if ($r.Signature -ne "N/A") { "<span class='sig'>$(ConvertTo-HtmlSafe $r.Signature)</span>" } else { "<span class='dim'>-</span>" }
        $errDisp   = if ($r.Error) { "<span class='err-msg'>$(ConvertTo-HtmlSafe $r.Error)</span>" } else { "" }

        $rowsHtml += @"
        <tr class="$statusClass">
            <td class="hash-cell">
                <a href="$eMBLink" target="_blank" class="vt-link" title="$eHash">$shortHash</a>
                <span class="htag">$eHashType</span>
                $hashesDetail
            </td>
            <td>$badge$errDisp</td>
            <td>
                <span class="fname">$eFileName</span><br>
                <span class="dim small">$eFileType &nbsp;|&nbsp; $eFileSize</span>
            </td>
            <td>$sigDisp</td>
            <td>$tagsHtml</td>
            <td><span class="dim small">$eFirstSeen</span></td>
            <td class="intel-cell">$intelDisp</td>
        </tr>
"@
    }

    $html = @"
<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<title>ZavetSec - MalwareBazaar Report</title>
<style>
:root {
  --bg:     #090b0f;
  --bg2:    #0d1017;
  --bg3:    #131820;
  --border: #1c2333;
  --text:   #e6edf3;
  --dim:    #8b949e;
  --accent: #79c0ff;
  --mal:    #ff6b6b;
  --nf:     #8b949e;
  --warn:   #f0c050;
  --green:  #56d364;
  --font:   'Consolas','Courier New',monospace;
}
*{box-sizing:border-box;margin:0;padding:0;}
body{background:var(--bg);color:var(--text);font-family:var(--font);font-size:13px;line-height:1.5;}

.header{background:var(--bg2);border-bottom:2px solid #e5534b33;padding:22px 30px;}
.logo{
  font-size:22px;font-weight:900;letter-spacing:4px;margin-bottom:4px;
  color:#ffd700;
  text-shadow:0 0 8px #ffd70099, 0 0 18px #ffaa0066, 0 0 32px #ff880033;
  font-family:'Consolas','Courier New',monospace;
}
.logo em{color:#ff6b35;font-style:normal;font-weight:900;
  text-shadow:0 0 8px #ff6b3599, 0 0 18px #ff440066;}
.powered{color:var(--dim);font-size:10px;margin-bottom:8px;}
.meta{color:var(--dim);font-size:11px;}
.meta strong{color:var(--text);}

.statsbar{display:flex;gap:10px;padding:14px 30px;background:var(--bg2);border-bottom:1px solid var(--border);flex-wrap:wrap;}
.sc{background:var(--bg3);border:1px solid var(--border);border-radius:6px;padding:10px 18px;text-align:center;min-width:90px;}
.sc .n{font-size:26px;font-weight:bold;}
.sc .l{font-size:10px;color:var(--dim);text-transform:uppercase;letter-spacing:1px;}
.n-mal{color:var(--mal);}
.n-nf{color:var(--nf);}
.n-total{color:var(--accent);}
.n-warn{color:var(--warn);}

.container{padding:22px 30px;}
.sec-title{color:var(--accent);font-size:11px;text-transform:uppercase;letter-spacing:2px;margin-bottom:12px;padding-bottom:6px;border-bottom:1px solid var(--border);}

.notice{background:#daaa3f18;border:1px solid #daaa3f44;border-radius:6px;padding:10px 16px;margin-bottom:16px;color:var(--warn);font-size:12px;}
.notice strong{color:#f0c050;}

table{width:100%;border-collapse:collapse;background:var(--bg2);border-radius:8px;overflow:hidden;border:1px solid var(--border);}
thead tr{background:var(--bg3);border-bottom:2px solid var(--border);}
th{padding:9px 12px;text-align:left;color:var(--dim);font-size:10px;text-transform:uppercase;letter-spacing:1px;font-weight:normal;}
td{padding:9px 12px;border-bottom:1px solid var(--border);vertical-align:top;}
tr:last-child td{border-bottom:none;}
tr:hover td{background:rgba(83,155,245,0.03);}

.status-mal td{border-left:3px solid var(--mal);}
.status-nf  td{border-left:3px solid #333a47;}
.status-err td{border-left:3px solid var(--warn);}

.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:bold;letter-spacing:.5px;}
.badge-mal{background:rgba(229,83,75,.15);color:var(--mal);border:1px solid rgba(229,83,75,.3);}
.badge-nf{background:rgba(99,110,123,.12);color:var(--nf);border:1px solid rgba(99,110,123,.25);}
.badge-err{background:rgba(218,170,63,.12);color:var(--warn);border:1px solid rgba(218,170,63,.25);}

.hash-cell{font-family:monospace;font-size:12px;}
.vt-link{color:var(--accent);text-decoration:none;}
.vt-link:hover{text-decoration:underline;}
.htag{display:inline-block;background:var(--bg3);border:1px solid var(--border);border-radius:3px;padding:0 4px;font-size:10px;color:var(--dim);margin-left:6px;}
.fname{color:var(--text);}
.sig{color:var(--warn);font-size:11px;}
.err-msg{color:var(--dim);font-size:11px;display:block;margin-top:2px;}
.dim{color:var(--dim);}
.small{font-size:11px;}
.intel-cell{color:var(--dim);font-size:11px;max-width:200px;}

.tag{display:inline-block;background:rgba(229,83,75,.12);border:1px solid rgba(229,83,75,.2);border-radius:3px;padding:1px 6px;font-size:10px;color:#e5534b88;margin:1px;}

details summary.sum-hashes{cursor:pointer;color:var(--accent);font-size:10px;margin-top:4px;user-select:none;}
.hash-detail{margin-top:5px;background:var(--bg3);border:1px solid var(--border);border-radius:4px;padding:7px;font-size:10px;}
.hl{color:var(--dim);}
.hv{color:var(--text);word-break:break-all;}

.filter-bar{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:12px;}
.fbtn{background:var(--bg3);border:1px solid var(--border);border-radius:4px;color:var(--dim);padding:4px 12px;font-family:var(--font);font-size:11px;cursor:pointer;transition:all .15s;}
.fbtn:hover,.fbtn.active{border-color:var(--accent);color:var(--accent);background:rgba(83,155,245,.07);}
#srch{background:var(--bg3);border:1px solid var(--border);border-radius:4px;color:var(--text);padding:4px 10px;font-family:var(--font);font-size:11px;width:220px;}
#srch:focus{outline:none;border-color:var(--accent);}

.footer{padding:14px 30px;border-top:1px solid var(--border);color:var(--dim);font-size:10px;text-align:center;}
.footer a{color:var(--accent);text-decoration:none;}
</style>
</head>
<body>

<div class="header">
  <div class="logo">ZAVET<em>SEC</em></div>
  <div class="powered">MalwareBazaar Hash Checker &mdash; abuse.ch API &mdash; Auth-Key required &mdash; free at auth.abuse.ch &nbsp;|&nbsp; <a href="https://github.com/zavetsec" target="_blank" style="color:var(--dim);text-decoration:none;opacity:0.6;">github.com/zavetsec</a></div>
  <div class="meta">
    Generated: <strong>$reportTs</strong> &nbsp;|&nbsp;
    Total hashes: <strong>$total</strong> &nbsp;|&nbsp;
    Source: <strong>MalwareBazaar + ThreatFox (abuse.ch)</strong>
  </div>
</div>

<div class="statsbar">
  <div class="sc"><div class="n n-total">$total</div><div class="l">Total</div></div>
  <div class="sc"><div class="n n-mal">$malCount</div><div class="l">Malicious</div></div>
  <div class="sc"><div class="n n-nf">$nfCount</div><div class="l">Not in DB</div></div>
  <div class="sc"><div class="n n-warn">$errCount</div><div class="l">Errors</div></div>
</div>

<div class="container">
  <div class="notice">
    <strong>&#9888; Note:</strong>
    NOT IN DB means the hash was not found in MalwareBazaar &mdash; this does not mean the file is clean.
    MalwareBazaar only indexes known malware samples. Cross-reference with additional threat intelligence sources for a complete picture.
  </div>

  <div class="sec-title">Hash Analysis Results &mdash; MalwareBazaar</div>

  <div class="filter-bar">
    <button class="fbtn active" onclick="ft('ALL')">All ($total)</button>
    <button class="fbtn" onclick="ft('mal')">&#9888; Malicious ($malCount)</button>
    <button class="fbtn" onclick="ft('nf')">? Not in DB ($nfCount)</button>
    <input type="text" id="srch" placeholder="Search hash / filename..." oninput="fs()">
  </div>

  <table id="ht">
    <thead>
      <tr>
        <th>Hash</th>
        <th>Verdict</th>
        <th>File Info</th>
        <th>Signature</th>
        <th>Tags</th>
        <th>First Seen</th>
        <th>Intel</th>
      </tr>
    </thead>
    <tbody id="tb">
$rowsHtml
    </tbody>
  </table>

  <div id="tfSection" style="display:none; margin-top:28px;">
    <div class="sec-title">ThreatFox IOC Intelligence &mdash; C2 / Payload Indicators</div>
    <table id="tfTable">
      <thead>
        <tr>
          <th>IOC</th>
          <th>Type</th>
          <th>Threat</th>
          <th>Malware</th>
          <th>Confidence</th>
          <th>Geo / ASN</th>
          <th>First Seen</th>
          <th>Reporter</th>
        </tr>
      </thead>
      <tbody id="tfBody">
      </tbody>
    </table>
  </div>
</div>

<div class="footer">
  <a href="https://github.com/zavetsec" target="_blank" class="vt-link" style="color:#ffd700;opacity:0.7;font-weight:bold;text-shadow:0 0 6px #ffd70044;">ZavetSec</a>
  &mdash; MalwareBazaar Hash Checker v$SCRIPT_VERSION &nbsp;|&nbsp;
  <a href="https://bazaar.abuse.ch" target="_blank">bazaar.abuse.ch</a> &nbsp;|&nbsp;
  Data provided by <a href="https://abuse.ch" target="_blank">abuse.ch</a>
</div>

PLACEHOLDER_JS
</body>
</html>
"@

    $jsBlock = @'
<script>
var rows=null;
function gr(){if(!rows)rows=Array.from(document.querySelectorAll('#tb tr'));return rows;}
function ft(s){
  document.querySelectorAll('.fbtn').forEach(function(b){b.classList.remove('active');});
  event.target.classList.add('active');
  var q=document.getElementById('srch').value.toLowerCase();
  gr().forEach(function(r){
    var ms=(s==='ALL')||r.classList.contains('status-'+s);
    var mq=!q||r.textContent.toLowerCase().includes(q);
    r.style.display=(ms&&mq)?'':'none';
  });
}
function fs(){
  var q=document.getElementById('srch').value.toLowerCase();
  gr().forEach(function(r){r.style.display=(!q||r.textContent.toLowerCase().includes(q))?'':'none';});
}
// ThreatFox IOC data injected by PowerShell (string fields are HTML-escaped server-side)
var tfData = TF_DATA_PLACEHOLDER;
(function(){
  if(!tfData||!tfData.length){return;}
  document.getElementById('tfSection').style.display='block';
  var body=document.getElementById('tfBody');
  tfData.forEach(function(r){
    var iocCell;
    var isIP=r.ioc_type==='ip:port'||r.ioc_type==='ip';
    var cleanIP=r.ioc.replace(/:\d+$/,'');
    if(isIP){
      iocCell='<a href="https://www.shodan.io/host/'+encodeURIComponent(cleanIP)+'" target="_blank" class="vt-link">'+r.ioc+'</a>';
    } else if(r.ioc_type==='domain'||r.ioc_type==='url'){
      iocCell='<a href="'+r.tf_link+'" target="_blank" class="vt-link">'+r.ioc+'</a>';
    } else {
      iocCell=r.ioc;
    }
    var flag='';
    if(r.geo_cc&&r.geo_cc!='N/A'&&/^[a-zA-Z]{2}$/.test(r.geo_cc)){
      flag='<img src="https://flagcdn.com/16x12/'+r.geo_cc.toLowerCase()+'.png" style="margin-right:5px;vertical-align:middle;">';
    }
    var geo=r.geo_country!='N/A'?flag+r.geo_country+(r.geo_city!='N/A'?', '+r.geo_city:''):'<span class="dim">-</span>';
    var confColor=r.confidence>=75?'var(--mal)':r.confidence>=50?'var(--warn)':'var(--dim)';
    var tr=document.createElement('tr');
    tr.innerHTML='<td class="hash-cell">'+iocCell+'</td>'
      +'<td><span class="htag">'+r.ioc_type+'</span></td>'
      +'<td class="dim small">'+r.threat_type+'</td>'
      +'<td><span class="sig">'+r.malware+'</span></td>'
      +'<td style="color:'+confColor+';font-weight:bold;">'+r.confidence+'%</td>'
      +'<td class="dim small">'+geo+(r.asn!='N/A'?'<br>'+r.asn:'')+'</td>'
      +'<td class="dim small">'+r.first_seen+'</td>'
      +'<td class="dim small">'+r.reporter+'</td>';
    body.appendChild(tr);
  });
})();
</script>
'@

    $html = $html.Replace('PLACEHOLDER_JS', $jsBlock)

    # --- Build ThreatFox IOC JSON via ConvertTo-Json (handles quotes,
    #     backslashes, control chars). String fields are HTML-escaped so they
    #     are safe when the JS injects them via innerHTML. ---
    $tfObjects = [System.Collections.Generic.List[object]]::new()
    foreach ($r in $Results) {
        if ($r.TFIOCs -and @($r.TFIOCs).Count -gt 0) {
            foreach ($ioc in @($r.TFIOCs)) {
                $conf = 0
                if ("$($ioc.Confidence)" -match '^\d+$') { $conf = [int]$ioc.Confidence }
                $tfObjects.Add([ordered]@{
                    ioc         = (ConvertTo-HtmlSafe $ioc.IOC)
                    ioc_type    = (ConvertTo-HtmlSafe $ioc.IOCType)
                    threat_type = (ConvertTo-HtmlSafe $ioc.ThreatType)
                    malware     = (ConvertTo-HtmlSafe $ioc.Malware)
                    confidence  = $conf
                    geo_country = (ConvertTo-HtmlSafe $ioc.GeoCountry)
                    geo_cc      = (ConvertTo-HtmlSafe $ioc.GeoCC)
                    geo_city    = (ConvertTo-HtmlSafe $ioc.GeoCity)
                    asn         = (ConvertTo-HtmlSafe $ioc.ASN)
                    isp         = (ConvertTo-HtmlSafe $ioc.ISP)
                    first_seen  = (ConvertTo-HtmlSafe $ioc.FirstSeen)
                    reporter    = (ConvertTo-HtmlSafe $ioc.Reporter)
                    tf_link     = (ConvertTo-HtmlSafe $ioc.TFLink)
                })
            }
        }
    }

    if ($tfObjects.Count -gt 0) {
        $tfJson = ConvertTo-Json -InputObject $tfObjects.ToArray() -Depth 4 -Compress
        if ($tfJson -notmatch '^\s*\[') { $tfJson = "[$tfJson]" }   # single item -> wrap as array
    } else {
        $tfJson = "[]"
    }
    # Neutralize any literal </script> that could close the script tag early.
    $tfJson = $tfJson -replace '</', '<\/'

    $html = $html.Replace('TF_DATA_PLACEHOLDER', $tfJson)

    # UTF-8 without BOM. Out-File -Encoding UTF8 on Windows PowerShell 5.1
    # prepends a BOM and can mangle non-ASCII in here-strings.
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($OutputPath, $html, $utf8NoBom)
}

# ============================================================
# MAIN
# ============================================================

Write-Banner

# --- API Key ---
if (-not $ApiKey) {
    Write-Host ""
    Write-Host "  MalwareBazaar Auth-Key required (free)." -ForegroundColor Yellow
    Write-Host "  Get your key at: https://auth.abuse.ch  (sign in with GitHub / Google / LinkedIn)" -ForegroundColor DarkGray
    Write-Host ""
    $ApiKey = Read-Host "  Enter Auth-Key"
    if (-not $ApiKey) {
        Write-Log "Auth-Key not provided. Exiting." "ERROR"
        exit 1
    }
}

# --- Collect hashes ---
$hashList = [System.Collections.Generic.List[string]]::new()

foreach ($h in $Hashes) {
    $h = $h.Trim().ToLower()
    if ($h -and (Test-HashFormat $h)) {
        if (-not $hashList.Contains($h)) { $hashList.Add($h) }
    }
}

if ($HashFile) {
    if (-not (Test-Path -LiteralPath $HashFile)) {
        Write-Log "Hash file not found: $HashFile" "ERROR"
        exit 1
    }
    [void](Import-HashFile -Path $HashFile -Target $hashList)
}

# From directory scan
if ($ScanDirectory) {
    if (-not (Test-Path -LiteralPath $ScanDirectory)) {
        Write-Log "Directory not found: $ScanDirectory" "ERROR"
        exit 1
    }
    $getParams = @{ Path = $ScanDirectory; File = $true }
    if ($Recurse) { $getParams['Recurse'] = $true }
    $files = Get-ChildItem @getParams -ErrorAction SilentlyContinue
    Write-Log "Hashing $(@($files).Count) file(s) in: $ScanDirectory" "INFO"
    foreach ($f in $files) {
        try {
            $sha = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256 -ErrorAction Stop).Hash.ToLower()
            if (-not $hashList.Contains($sha)) {
                $hashList.Add($sha)
                Write-Log "Hashed: $($f.Name) -> $sha" "OK"
            }
        }
        catch {
            Write-Log "Cannot hash: $($f.FullName) - $($_.Exception.Message)" "WARN"
        }
    }
}

# --- Interactive input (nothing provided on the command line) ---
if ($hashList.Count -eq 0) {
    Write-Host ""
    Write-Host "  No hashes provided. Choose an input method:" -ForegroundColor Cyan
    Write-Host "    1) Load from a text file (.txt, one hash per line)" -ForegroundColor DarkGray
    Write-Host "    2) Type hashes manually" -ForegroundColor DarkGray
    Write-Host ""

    $fp = Read-Host "  Path to hash file (.txt), or press Enter to type manually"
    if ($fp) {
        $fp = $fp.Trim().Trim('"').Trim("'")   # strip drag-and-drop quotes
        if (Test-Path -LiteralPath $fp) {
            $n = Import-HashFile -Path $fp -Target $hashList
            Write-Log "Loaded $n valid hash(es) from file." "OK"
        }
        else {
            Write-Log "File not found: $fp" "ERROR"
        }
    }
}

# Still nothing -> manual entry loop
if ($hashList.Count -eq 0) {
    Write-Host ""
    Write-Host "  Enter hashes to check (MD5 / SHA1 / SHA256)." -ForegroundColor Cyan
    Write-Host "  One hash per line. Press Enter on empty line when done." -ForegroundColor DarkGray
    Write-Host ""
    while ($true) {
        $inp = Read-Host "  Hash"
        if (-not $inp) { break }
        $inp = $inp.Trim().ToLower()
        if (Test-HashFormat $inp) {
            if (-not $hashList.Contains($inp)) {
                $hashList.Add($inp)
                Write-Log "Added: $inp ($(Get-HashType $inp))" "OK"
            }
        }
        else { Write-Log "Invalid format: $inp" "WARN" }
    }
}

if ($hashList.Count -eq 0) {
    Write-Log "No hashes to check." "WARN"
    exit 0
}

Write-Host ""
Write-Log "Loaded $($hashList.Count) hash(es) for analysis." "HEAD"
Write-Log "Source: MalwareBazaar + ThreatFox (abuse.ch) | Auth-Key: ....$($ApiKey.Substring([Math]::Max(0,$ApiKey.Length-4)))" "INFO"
Write-Host ("-" * 54) -ForegroundColor DarkGray
Write-Host ""

# --- Process ---
$results = [System.Collections.Generic.List[object]]::new()
$idx = 0

foreach ($hash in $hashList) {
    $idx++
    $pct = [int](($idx / $hashList.Count) * 100)
    Write-Progress -Activity "MalwareBazaar Lookup" `
                   -Status "[$idx/$($hashList.Count)] $hash" `
                   -PercentComplete $pct

    Write-Host "  [$idx/$($hashList.Count)] " -ForegroundColor DarkGray -NoNewline
    Write-Host "$hash " -ForegroundColor White -NoNewline
    Write-Host "($(Get-HashType $hash))" -ForegroundColor DarkGray -NoNewline
    Write-Host " ... " -NoNewline

    $res = Invoke-MBLookup -Hash $hash -Key $ApiKey -Retries $MaxRetries -RetryDelay $RetryDelaySeconds

    # A bad Auth-Key affects every request - stop now and still write a report.
    if ($res.Status -eq "AUTH_ERROR") {
        $results.Add($res)
        if ($PassThru) { Write-Output $res }
        Write-Host "[AUTH_ERROR]" -ForegroundColor Red
        Write-Host ""
        Write-Log "Auth-Key rejected: $($res.Error)" "ERROR"
        Write-Log "Get a valid free key at https://auth.abuse.ch and retry." "WARN"
        break
    }

    # ThreatFox IOC lookup for MALICIOUS hits
    if ($res.Status -eq "MALICIOUS") {
        Write-Host "  [TF] " -ForegroundColor DarkMagenta -NoNewline
        Write-Host "Querying ThreatFox for related IOCs..." -ForegroundColor Gray
        $tfHash = if ($res.SHA256 -ne "N/A") { $res.SHA256 }
                  elseif ($res.MD5 -ne "N/A")  { $res.MD5 }
                  elseif ($res.SHA1 -ne "N/A") { $res.SHA1 }
                  else                          { $res.Hash }
        $tfResult = Invoke-ThreatFoxLookup -Hash $tfHash -Key $ApiKey
        if (-not $tfResult.Found -and $res.Hash -ne $tfHash) {
            $tfResult = Invoke-ThreatFoxLookup -Hash $res.Hash -Key $ApiKey
        }
        if ($tfResult.Found -and $tfResult.IOCs.Count -gt 0) {
            $res.TFIOCs     = @($tfResult.IOCs)
            $res.TFEnriched = $true
            $ipCount  = @($tfResult.IOCs | Where-Object { $_.IOCType -in @("ip:port","ip") }).Count
            $domCount = @($tfResult.IOCs | Where-Object { $_.IOCType -eq "domain" }).Count
            Write-Host "      Found $($tfResult.IOCs.Count) IOC(s)" -ForegroundColor DarkMagenta -NoNewline
            if ($ipCount -gt 0)  { Write-Host " | $ipCount IP/port" -ForegroundColor DarkMagenta -NoNewline }
            if ($domCount -gt 0) { Write-Host " | $domCount domain" -ForegroundColor DarkMagenta -NoNewline }
            Write-Host ""
        } elseif ($tfResult.Error) {
            Write-Host "      ThreatFox error: $($tfResult.Error)" -ForegroundColor DarkGray
        } else {
            Write-Host "      No IOCs found in ThreatFox" -ForegroundColor DarkGray
        }
    }

    $results.Add($res)
    if ($PassThru) { Write-Output $res }

    $col = switch ($res.Status) {
        "MALICIOUS" { "Red" }
        "NOT_FOUND" { "DarkGray" }
        default     { "Yellow" }
    }

    if (-not ($Quiet -and $res.Status -notin @("MALICIOUS","ERROR"))) {
        Write-Host "[$($res.Status)]" -ForegroundColor $col -NoNewline
        if ($res.Status -eq "MALICIOUS") {
            if ($res.Signature -ne "N/A") {
                Write-Host "  $($res.Signature)" -ForegroundColor Red -NoNewline
                if ($res.Tags -ne "N/A" -and $res.Tags -ne $res.Signature) {
                    $filteredTags = ($res.Tags -split ", " | Where-Object { $_ -ne $res.Signature }) -join ", "
                    if ($filteredTags) {
                        Write-Host "  | $filteredTags" -ForegroundColor DarkGray -NoNewline
                    }
                }
            } elseif ($res.Tags -ne "N/A") {
                Write-Host "  $($res.Tags)" -ForegroundColor DarkGray -NoNewline
            }
        }
        elseif ($res.Error) {
            Write-Host "  $($res.Error)" -ForegroundColor DarkGray -NoNewline
        }
        Write-Host ""
    }

    if ($idx -lt $hashList.Count) { Start-Sleep -Milliseconds $DELAY_MS }
}

Write-Progress -Activity "MalwareBazaar Lookup" -Completed

# --- Summary ---
Write-Host ""
Write-Host ("-" * 54) -ForegroundColor DarkGray
$malC  = @($results | Where-Object { $_.Status -eq "MALICIOUS" }).Count
$nfC   = @($results | Where-Object { $_.Status -eq "NOT_FOUND" }).Count
$errC  = @($results | Where-Object { $_.Status -eq "ERROR" -or $_.Status -eq "AUTH_ERROR" }).Count
$total = @($results).Count

$tfCount    = @($results | Where-Object { $_.TFEnriched -eq $true }).Count
$tfIOCTotal = ($results | ForEach-Object { if ($_.TFIOCs) { @($_.TFIOCs).Count } else { 0 } } | Measure-Object -Sum).Sum

Write-Log "Analysis complete." "HEAD"
Write-Host "  Total:          " -NoNewline; Write-Host $total      -ForegroundColor Cyan
Write-Host "  MALICIOUS:      " -NoNewline; Write-Host $malC       -ForegroundColor Red
Write-Host "  NOT IN DB:      " -NoNewline; Write-Host $nfC        -ForegroundColor DarkGray
Write-Host "  Errors:         " -NoNewline; Write-Host $errC       -ForegroundColor Yellow
Write-Host "  ThreatFox hits: " -NoNewline; Write-Host $tfCount    -ForegroundColor Magenta
Write-Host "  TF IOCs total:  " -NoNewline; Write-Host $tfIOCTotal -ForegroundColor Magenta
Write-Host ""
Write-Host "  [!] NOT IN DB != CLEAN  MalwareBazaar indexes known malware only." -ForegroundColor Yellow
Write-Host "      Cross-reference with additional threat intelligence sources for full coverage." -ForegroundColor DarkGray
Write-Host ""

# --- HTML Report ---
$ts   = Get-Date -Format "yyyyMMdd_HHmmss"
$path = Join-Path $OutputDir "MB_HashReport_$ts.html"

try {
    New-HtmlReport -Results $results -OutputPath $path
    Write-Log "HTML report saved: $path" "OK"
}
catch {
    Write-Log "Failed to save report: $($_.Exception.Message)" "ERROR"
}
Write-Host ""

if ($PassThru) { $results }
