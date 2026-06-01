#Requires -Version 5.1
<#
.SYNOPSIS
    ZavetSec Express Triage v1.4 - Zero-dependency DFIR for live Windows systems.
.DESCRIPTION
    Collects high-value forensic artifacts. No external tools required.

    Modules:
      [1]  System baseline       - OS, domain, uptime, hotfixes, installed software
      [2]  Running processes     - hashes, signatures, parent chains, masquerade check
      [3]  Network state         - TCP/UDP, DNS cache, ARP, named pipes (C2 detection)
      [4]  Persistence           - Run keys, Winlogon, IFEO, LSA SSP, tasks, services, WMI
      [5]  User accounts         - local users/groups, sessions, Kerberos tickets
      [6]  PowerShell artifacts  - history all users, language mode
      [7]  Event logs            - targeted IDs as CSV + raw EVTX (FULL: all winevt logs)
      [8]  Prefetch              - execution evidence, 30+ known attacker tools flagged
      [9]  File activity         - LNK recent files (pure .NET binary parse, no COM)
      [10] Registry forensics    - UserAssist (ROT13 decoded), MUICache, TypedURLs
      [11] Credential security   - WDigest, Credential Guard, LSA PPL
      [12] Configuration         - hosts file, firewall in/out rules, ADS scan
      [13] Shadow copies         - VSS enumeration (absence = ransomware IOC T1490)
      [14] Browser history       - 16 browsers, all users, CSV output
      [15] BITS jobs             - stealthy download detection (T1197)
      [16] Clipboard             - text capture, credential pattern detection
      [17] Metadata & summary    - highlights CSV/JSON, file manifest, ZIP
      [18] HTML report          - triage_report.html with findings, system info, network, threats

    Output: <OutputDir>\<hostname>_<timestamp>.zip

    Reading collected files:
      CSV         - Excel or LibreOffice Calc
      JSON        - Notepad / VS Code / browser
      TXT         - Notepad
      EVTX        - double-click in Windows Event Viewer
                    or: Chainsaw / Hayabusa for batch Sigma analysis
      SQLite DB   - optional: DB Browser for SQLite https://sqlitebrowser.org

.PARAMETER OutputDir
    Where to save the ZIP. Default = script directory.
.PARAMETER Mode
    LITE (skip raw EVTX copy) or FULL (default, copy all winevt logs).
.PARAMETER SkipHashing
    Skip SHA256 + Authenticode on process/service binaries for a fast snapshot.
    Use when speed matters more than binary integrity verification.
.EXAMPLE
    .\Invoke-ZavetSecTriage.ps1
    .\Invoke-ZavetSecTriage.ps1 -OutputDir C:\DFIR
    .\Invoke-ZavetSecTriage.ps1 -SkipHashing        # fast snapshot, no hashing
.NOTES
    Version   : 1.4
    Requires  : PowerShell 5.1+, local Administrator rights
    Encoding  : ASCII-safe (PS 5.1 compatible, no non-ASCII chars)
    External  : none required. sqlite3.exe optional for full browser parse.
    Changelog : 1.4 - per-path hash/sig caching (major speedup on busy hosts),
                      -SkipHashing switch, null-safe event Message extraction,
                      SKIP_LARGE binaries now surfaced as highlights,
                      HTML report long-cell tooltip + click-to-expand.
#>

[CmdletBinding()]
param(
    [string]$OutputDir = $(if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }),
    [ValidateSet('LITE','FULL')]
    [string]$Mode = 'FULL',
    [switch]$SkipHashing   # skip SHA256/Authenticode on process binaries for a fast snapshot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'SilentlyContinue'

# -------------------------------------------------------
# ADMIN CHECK
# -------------------------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# -------------------------------------------------------
# GLOBALS
# -------------------------------------------------------
$global:Highlights    = [System.Collections.Generic.List[PSCustomObject]]::new()
$global:HighlightSeen = [System.Collections.Generic.HashSet[string]]::new()
$global:StartTime     = Get-Date
$global:PhaseCount   = 0
$global:TotalPhases  = 18
$hostname            = $env:COMPUTERNAME
$timestamp           = Get-Date -Format 'yyyyMMdd_HHmmss'
$triageRoot          = Join-Path $env:TEMP "ZS_${hostname}_${timestamp}"
$null                = New-Item -ItemType Directory -Path $triageRoot -Force

foreach ($d in @('System','Processes','Network','Persistence',
                 'Logs','Users','Forensics','Config','Registry')) {
    $null = New-Item -ItemType Directory -Path (Join-Path $triageRoot $d) -Force
}

# -------------------------------------------------------
# HELPERS
# -------------------------------------------------------
function Write-Phase {
    param([string]$T)
    $global:PhaseCount++
    Write-Host ''
    Write-Host "  [*] [$global:PhaseCount/$global:TotalPhases] $T" -ForegroundColor Cyan
}
function Write-OK   { param([string]$M); Write-Host "  [+] $M" -ForegroundColor Green }
function Write-Warn { param([string]$M); Write-Host "  [!] $M" -ForegroundColor Yellow }
function Write-Info { param([string]$M); Write-Host "  [-] $M" -ForegroundColor DarkGray }

function Save-Text {
    param([string]$Path, [string]$Content)
    try { [System.IO.File]::WriteAllText($Path, $Content, [System.Text.Encoding]::UTF8) } catch {}
}
function Save-Json {
    param([string]$Path, $Data)
    try {
        $json = $Data | ConvertTo-Json -Depth 8
        [System.IO.File]::WriteAllText($Path, $json, [System.Text.Encoding]::UTF8)
    } catch {}
}
function Save-Csv {
    param([string]$Path, $Data)
    if ($null -eq $Data) { return }
    # Note: do NOT skip empty collections - we WANT empty CSVs (with headers if possible)
    # so analysts can see "this phase ran but found nothing" vs "phase was skipped".
    try { $Data | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8 -Force } catch {}
}

function Copy-LockedFile {
    param([string]$Src, [string]$Dst)
    try {
        $s = [System.IO.File]::Open($Src,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::ReadWrite)
        $d = [System.IO.File]::Create($Dst)
        $s.CopyTo($d); $s.Close(); $d.Close()
        return $true
    } catch { return $false }
}

function Copy-ViaVSS {
    param([string]$FilePath, [string]$Dst)
    try {
        $shadows = Get-WmiObject Win32_ShadowCopy -EA Stop |
            Sort-Object InstallDate -Descending
        foreach ($sh in $shadows) {
            $relPath    = $FilePath -replace '^[A-Za-z]:\\', '\'
            $shadowPath = "$($sh.DeviceObject)$relPath"
            try {
                Copy-Item -LiteralPath $shadowPath -Destination $Dst -Force -EA Stop
                return $true
            } catch {}
        }
    } catch {}
    return $false
}

function Get-FileSHA256 {
    param([string]$FilePath, [long]$MaxBytes = 524288000)  # 500MB cap
    try {
        $fi = Get-Item -LiteralPath $FilePath -Force -EA Stop
        if ($fi.Length -gt $MaxBytes) { return 'SKIP_LARGE' }
        return (Get-FileHash -LiteralPath $FilePath -Algorithm SHA256 -EA Stop).Hash
    } catch { return 'N/A' }
}

function Get-FileSignature {
    param([string]$FilePath)
    try {
        $sig = Get-AuthenticodeSignature -FilePath $FilePath -EA Stop
        return $sig.Status.ToString()
    } catch { return 'N/A' }
}

function Add-Highlight {
    param(
        [string]$Category,
        [string]$Severity,
        [string]$Description,
        [string]$Detail = '',
        [string]$Mitre  = ''
    )
    # Dedupe: skip if identical (Category|Severity|Description|Detail) already added.
    # Use explicit $null comparison — PowerShell coerces some collections to bool
    # by their .Count, which would re-create the HashSet on every call.
    if ($null -eq $global:HighlightSeen) {
        $global:HighlightSeen = [System.Collections.Generic.HashSet[string]]::new()
    }
    $key = "$Category|$Severity|$Description|$Detail"
    if (-not $global:HighlightSeen.Add($key)) { return }

    $global:Highlights.Add([PSCustomObject]@{
        Category    = $Category
        Severity    = $Severity
        Description = $Description
        Detail      = $Detail
        Mitre       = $Mitre
        Time        = (Get-Date -Format 'HH:mm:ss')
    })
}

# Pure .NET LNK binary parser - no COM, no Shell.Application
# Supports LocalBasePath (ANSI) and LocalBasePathUnicode (UTF-16)
function Get-LnkTarget {
    param([string]$LnkPath)
    try {
        $bytes = [System.IO.File]::ReadAllBytes($LnkPath)
        if ($bytes.Length -lt 76) { return '' }
        if ($bytes[0] -ne 0x4C -or $bytes[1] -ne 0x00) { return '' }
        $flags  = [BitConverter]::ToUInt32($bytes, 20)
        $offset = 76
        if ($flags -band 0x01) {
            $idListSize = [BitConverter]::ToUInt16($bytes, $offset)
            $offset += 2 + $idListSize
        }
        if ($flags -band 0x02) {
            if ($offset + 36 -gt $bytes.Length) { return '' }
            $liSize           = [BitConverter]::ToUInt32($bytes, $offset)
            $liHeaderSize     = [BitConverter]::ToUInt32($bytes, $offset + 4)
            $liFlags          = [BitConverter]::ToUInt32($bytes, $offset + 8)
            $localBase        = [BitConverter]::ToUInt32($bytes, $offset + 16)
            $localBaseUnicode = if ($liHeaderSize -ge 36) {
                [BitConverter]::ToUInt32($bytes, $offset + 32)
            } else { 0 }

            # Prefer Unicode path when present (handles non-ASCII like Cyrillic)
            if ($localBaseUnicode -gt 0) {
                $strStart = $offset + $localBaseUnicode
                if ($strStart -lt $bytes.Length) {
                    $end = $strStart
                    while ($end + 1 -lt $bytes.Length -and
                           -not ($bytes[$end] -eq 0 -and $bytes[$end+1] -eq 0)) {
                        $end += 2
                    }
                    $len = $end - $strStart
                    if ($len -gt 0) {
                        $str = [System.Text.Encoding]::Unicode.GetString($bytes, $strStart, $len)
                        if ($str.Length -gt 2) { return $str }
                    }
                }
            }

            # Fallback: ANSI LocalBasePath - decode via system default code page (handles legacy locales)
            if (($liFlags -band 0x01) -and $localBase -gt 0) {
                $strStart = $offset + $localBase
                if ($strStart -lt $bytes.Length) {
                    $end = $strStart
                    while ($end -lt $bytes.Length -and $bytes[$end] -ne 0) { $end++ }
                    $len = $end - $strStart
                    if ($len -gt 0) {
                        try {
                            $str = [System.Text.Encoding]::Default.GetString($bytes, $strStart, $len)
                        } catch {
                            $str = [System.Text.Encoding]::ASCII.GetString($bytes, $strStart, $len)
                        }
                        if ($str.Length -gt 2) { return $str }
                    }
                }
            }
        }
    } catch {}
    return ''
}

# -------------------------------------------------------
# DETECTION PATTERNS
# -------------------------------------------------------
$suspCmdPatterns = @(
    '-encodedcommand', '-enc ', '-nop ', '-noprofile',
    'frombase64string', 'downloadstring', 'downloadfile',
    'iex ', 'invoke-expression', 'invoke-webrequest',
    'bypass', 'certutil.*-decode', 'certutil.*-urlcache',
    'bitsadmin.*/transfer', 'mshta.*http',
    'regsvr32.*/u.*/s.*/i', 'rundll32.*javascript',
    'wmic.*/node:', 'net.*user.*/add',
    'net.*localgroup.*administrators',
    'sc.*create.*binpath', 'schtasks.*/create',
    'powershell.*-w.*hidden', 'start-process.*hidden'
)

$hiRiskDirs = @(
    "$env:TEMP\", "$env:APPDATA\", "$env:LOCALAPPDATA\Temp\",
    'C:\Users\Public\', 'C:\ProgramData\Temp\', 'C:\Windows\Temp\',
    'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\'
)

# Named pipe patterns - known C2 frameworks
# NOTE: mojo.* and chrome.* = Chromium IPC - excluded (false positive)
$c2PipePatterns = @(
    'msagent_', 'postex_', 'msse-', 'status_[0-9]',
    'ntsvcs[0-9]', 'wkssvc[0-9]', 'isapi[0-9]', 'netsvc[0-9]',
    'gecko[0-9]', 'PSHost\.[0-9]+\.[0-9]+\.',
    'MSSE-[0-9]+-server', 'postex_ssh_[0-9]+'
)

# Known attacker tools flagged in Prefetch automatically
$knownAttackerTools = @(
    'MIMIKATZ', 'MIMI', 'PROCDUMP', 'PROCESSHACKER', 'PCHUNTER',
    'WCESVR', 'GSECDUMP', 'FGDUMP', 'PWDUMP', 'XORDUMP',
    'PSEXEC', 'PSEXESVC', 'PAEXEC', 'REMCOM', 'CRACKMAPEXEC',
    'COBALT', 'BEACON', 'COBALTSTRIKE', 'CS_BEACON',
    'METERPRETER', 'METASPLOIT', 'MSFRPC',
    'NMAP', 'MASSCAN', 'ZMAP', 'ANGRYIPSCAN', 'RUSTSCAN',
    'NETCAT', 'NC64', 'NCAT', 'SOCAT',
    'REGEORG', 'CHISEL', 'LIGOLO', 'FRPC', 'GOPROXY',
    'RUBEUS', 'KEKEO', 'IMPACKET', 'SECRETSDUMP',
    'LAZAGNE', 'NIRSOFT', 'WEBBROWSERPASSVIEW', 'CREDENTIALSFILEVIEW',
    'NBTSCAN', 'BLOODHOUND', 'SHARPHOUND', 'ADRECON',
    'RCLONE', 'MEGACMD', 'WINSCP', 'FILEZILLA',
    'TIGHTVNC', 'ULTRAVNC', 'REALVNC', 'ANYDESK',
    'ADVANCED_IP_SCANNER', 'SOFTPERFECT',
    'ADEXPLORER', 'LDAPADMIN',
    'CERTUTIL', 'MSHTA', 'REGSVR32', 'INSTALLUTIL', 'REGASM',
    'SEATBELT', 'WINPEAS', 'LINPEAS', 'POWERUP', 'POWERVIEW',
    'INVOKE-MIMIKATZ', 'INVOKE-OBFUSCATION'
)

# -------------------------------------------------------
# BANNER
# -------------------------------------------------------
Clear-Host
Write-Host ''
Write-Host '     ____                  _    ____            ' -ForegroundColor DarkCyan
Write-Host '    |_  /__ ___ _____ ___ | |_ / __/__ ___     ' -ForegroundColor Cyan
Write-Host '     / // _` \ V / -_)  _||  _\__ \/ -_) _|    ' -ForegroundColor Cyan
Write-Host '    /___\__,_|\_/\___\__| |_| |___/\___\__|    ' -ForegroundColor DarkCyan
Write-Host ''
Write-Host '    +--------------------------------------------+' -ForegroundColor DarkGray
Write-Host '    |  E X P R E S S   T R I A G E   v 1 . 1   |' -ForegroundColor White
Write-Host '    |  DFIR  //  Zero Dependencies  //  PS 5.1  |' -ForegroundColor Gray
Write-Host '    +--------------------------------------------+' -ForegroundColor DarkGray
Write-Host ''
Write-Host "    [>] Target   : $hostname" -ForegroundColor Green
Write-Host "    [>] User     : $($env:USERNAME)" -ForegroundColor Green
Write-Host "    [>] Output   : $OutputDir" -ForegroundColor Green
Write-Host "    [>] Started  : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Green
Write-Host ''
Write-Host '    [!] Run as Administrator for full artifact coverage' -ForegroundColor Yellow
Write-Host ''

# Collection parameters
$EventLogCount = 500
$DaysBack      = 7
$CopyRawEvtx   = ($Mode -eq 'FULL')

# -------------------------------------------------------
# 1. SYSTEM BASELINE
# -------------------------------------------------------
Write-Phase 'System Baseline'

$wmiOS = Get-WmiObject Win32_OperatingSystem
$wmiCS = Get-WmiObject Win32_ComputerSystem

$sysInfo = [ordered]@{
    Hostname       = $hostname
    CollectionTime = $global:StartTime.ToString('yyyy-MM-dd HH:mm:ss')
    CollectedBy    = $env:USERNAME
    RunAsAdmin     = $isAdmin
    OS             = $wmiOS.Caption
    OSVersion      = $wmiOS.Version
    OSBuild        = $wmiOS.BuildNumber
    Architecture   = $wmiOS.OSArchitecture
    Domain         = $wmiCS.Domain
    PartOfDomain   = $wmiCS.PartOfDomain
    LastBootTime   = $wmiOS.ConvertToDateTime($wmiOS.LastBootUpTime).ToString('yyyy-MM-dd HH:mm:ss')
    InstallDate    = $wmiOS.ConvertToDateTime($wmiOS.InstallDate).ToString('yyyy-MM-dd HH:mm:ss')
    UptimeHours    = [Math]::Round(((Get-Date) - $wmiOS.ConvertToDateTime($wmiOS.LastBootUpTime)).TotalHours, 1)
    TotalRAM_GB    = [Math]::Round($wmiCS.TotalPhysicalMemory / 1GB, 2)
    LogicalCPUs    = $wmiCS.NumberOfLogicalProcessors
    TimeZone       = (Get-TimeZone).Id
    PSVersion      = $PSVersionTable.PSVersion.ToString()
}
Save-Json "$triageRoot\System\sysinfo.json" $sysInfo

$hotfixes = Get-WmiObject Win32_QuickFixEngineering |
    Sort-Object InstalledOn -Descending | Select-Object -First 20 |
    Select-Object HotFixID, Description, InstalledOn
Save-Csv "$triageRoot\System\hotfixes_last20.csv" $hotfixes

$software = @(Get-ItemProperty `
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' |
    Where-Object { $_.DisplayName } |
    Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
    Sort-Object DisplayName)
Save-Csv "$triageRoot\System\installed_software.csv" $software

$ratKeywords = @('anydesk','teamviewer','ngrok','cloudflared','radmin',
                 'netsupport','screenconnect','remotepc','splashtop','rustdesk',
                 'ultraviewer','ammyy','supremo','dameware')
foreach ($sw in $software) {
    if ($sw.DisplayName) {
        $swLower = $sw.DisplayName.ToLower()
        foreach ($kw in $ratKeywords) {
            if ($swLower -match $kw) {
                Add-Highlight 'System' 'MEDIUM' "Remote access tool installed: $($sw.DisplayName)" "Publisher=$($sw.Publisher) InstallDate=$($sw.InstallDate)" 'T1219'
                break
            }
        }
    }
}

Write-OK "OS=$($sysInfo.OS) | Build=$($sysInfo.OSBuild) | Uptime=$($sysInfo.UptimeHours)h | Admin=$isAdmin | SW=$($software.Count)"

# -------------------------------------------------------
# 2. RUNNING PROCESSES
# -------------------------------------------------------
Write-Phase 'Running Processes'

$wmiProcs = Get-WmiObject Win32_Process

# Performance: dedupe expensive hash/signature work by executable path. A host can run
# the same binary in dozens of processes (svchost.exe x50); without caching that means
# 50 redundant SHA256 reads + 50 Authenticode/CRL lookups. We compute once per unique
# path and reuse, which on a busy host (RDS/terminal server) cuts the process phase from
# minutes to seconds. -SkipHashing bypasses it entirely for an instant snapshot.
$hashCache = @{}   # path(lowercase) -> @{ Hash=...; Sig=... }
$largeSkipped = [System.Collections.Generic.HashSet[string]]::new()

function Get-PathHashSig {
    param([string]$Path)
    if ($SkipHashing) { return @{ Hash = 'SKIPPED'; Sig = 'SKIPPED' } }
    $ck = $Path.ToLower()
    if ($hashCache.ContainsKey($ck)) { return $hashCache[$ck] }
    $h = Get-FileSHA256 $Path
    $s = Get-FileSignature $Path
    $entry = @{ Hash = $h; Sig = $s }
    $hashCache[$ck] = $entry
    return $entry
}

$procData = foreach ($p in ($wmiProcs | Sort-Object ProcessId)) {
    $path    = $p.ExecutablePath
    $cmdLine = if ($p.CommandLine) { $p.CommandLine } else { '' }
    if ($path -and (Test-Path $path -EA SilentlyContinue)) {
        $hs    = Get-PathHashSig $path
        $hash  = $hs.Hash
        $sigSt = $hs.Sig
    } else {
        $hash  = 'N/A'
        $sigSt = 'N/A'
    }

    # A binary too large to hash leaves an unverifiable blind spot - surface it once per
    # path so a swapped-out large executable doesn't slip through silently (point 4).
    if ($hash -eq 'SKIP_LARGE' -and $largeSkipped.Add($path.ToLower())) {
        Add-Highlight 'Processes' 'MEDIUM' "Binary too large to hash (unverified): $($p.Name)" "Path=$path - exceeds hash size cap, integrity not checked" 'T1036'
    }

    $isSusp = $false; $suspReason = ''; $mitre = ''

    if ($path) {
        foreach ($d in $hiRiskDirs) {
            if ($path -like "$d*") {
                $isSusp     = $true
                $suspReason = "Binary in high-risk dir: $path"
                $mitre      = 'T1059'
                break
            }
        }
    }
    # Signature check: NotSigned alone is NOT suspicious (many legit dev/portable builds
    # are unsigned - Chromium portable, custom internal tools, etc.). Only flag actual
    # tampering indicators: HashMismatch (binary modified after signing) and NotTrusted
    # (signer chain broken / revoked).
    if (-not $isSusp -and $sigSt -in @('HashMismatch','NotTrusted')) {
        $isSusp     = $true
        $suspReason = "Signature anomaly: $sigSt"
        $mitre      = 'T1036.001'
    }
    if (-not $isSusp -and $cmdLine) {
        foreach ($pat in $suspCmdPatterns) {
            if ($cmdLine -match $pat) {
                $isSusp     = $true
                $suspReason = "Suspicious cmdline: $pat"
                $mitre      = 'T1059.001'
                break
            }
        }
    }

    # Each entry: array of legitimate prefix paths (case-insensitive).
    # Includes both System32 (64-bit) and SysWOW64 (32-bit redirector) where relevant.
    $legitPaths = @{
        'svchost.exe'   = @('C:\Windows\System32\','C:\Windows\SysWOW64\')
        'lsass.exe'     = @('C:\Windows\System32\')
        'csrss.exe'     = @('C:\Windows\System32\')
        'services.exe'  = @('C:\Windows\System32\')
        'winlogon.exe'  = @('C:\Windows\System32\')
        'explorer.exe'  = @('C:\Windows\','C:\Windows\SysWOW64\')
        'taskhostw.exe' = @('C:\Windows\System32\')
        'taskhost.exe'  = @('C:\Windows\System32\','C:\Windows\SysWOW64\')   # legacy Win7/2008R2
        'taskhostex.exe'= @('C:\Windows\System32\')                           # Win8/2012
        'smss.exe'      = @('C:\Windows\System32\')
        'wininit.exe'   = @('C:\Windows\System32\')
        'spoolsv.exe'   = @('C:\Windows\System32\','C:\Windows\SysWOW64\')
        'dllhost.exe'   = @('C:\Windows\System32\','C:\Windows\SysWOW64\')
        'conhost.exe'   = @('C:\Windows\System32\')
    }
    $pnameLower = $p.Name.ToLower()
    if (-not $isSusp -and $path -and $legitPaths.ContainsKey($pnameLower)) {
        $matched = $false
        foreach ($lp in $legitPaths[$pnameLower]) {
            if ($path.StartsWith($lp, [System.StringComparison]::OrdinalIgnoreCase)) {
                $matched = $true; break
            }
        }
        if (-not $matched) {
            $isSusp     = $true
            $suspReason = "Masquerade: $($p.Name) from $path"
            $mitre      = 'T1036.005'
        }
    }

    $ownerInfo = try { $p.GetOwner() } catch { $null }
    $owner = if ($ownerInfo -and $ownerInfo.ReturnValue -eq 0) {
        "$($ownerInfo.Domain)\$($ownerInfo.User)"
    } else { '' }

    if ($isSusp) {
        $cmdShort = if ($cmdLine.Length -gt 120) { $cmdLine.Substring(0,120) } else { $cmdLine }
        Add-Highlight 'Processes' 'HIGH' "Suspicious process: $($p.Name) PID=$($p.ProcessId)" "$suspReason | CMD=$cmdShort" $mitre
    }

    [PSCustomObject]@{
        PID          = $p.ProcessId
        PPID         = $p.ParentProcessId
        Name         = $p.Name
        Path         = $path
        CommandLine  = if ($cmdLine.Length -gt 300) { $cmdLine.Substring(0,300) } else { $cmdLine }
        SHA256       = $hash
        Signature    = $sigSt
        Owner        = $owner
        Handles      = $p.HandleCount
        WorkingSetMB = [Math]::Round($p.WorkingSetSize / 1MB, 1)
        CreationDate = $p.CreationDate
        Suspicious   = $isSusp
        SuspReason   = $suspReason
        Mitre        = $mitre
    }
}

Save-Csv  "$triageRoot\Processes\processes.csv"  $procData
Save-Json "$triageRoot\Processes\processes.json" ($procData | Select-Object -First 300)

$suspCount = ($procData | Where-Object { $_.Suspicious }).Count
Write-OK "Processes=$($procData.Count) | Suspicious=$suspCount"

# -------------------------------------------------------
# 3. NETWORK STATE
# -------------------------------------------------------
Write-Phase 'Network State'

$netConns = Get-NetTCPConnection -EA SilentlyContinue | ForEach-Object {
    $conn    = $_
    $proc    = $procData | Where-Object { $_.PID -eq $conn.OwningProcess } | Select-Object -First 1
    $remHost = ''
    if ($conn.RemoteAddress -and
        $conn.RemoteAddress -notin @('0.0.0.0','::','127.0.0.1','::1')) {
        try { $remHost = [System.Net.Dns]::GetHostEntry($conn.RemoteAddress).HostName } catch {}
    }
    $isExt = $conn.RemoteAddress -and
             $conn.RemoteAddress -notin @('0.0.0.0','::','127.0.0.1','::1','') -and
             $conn.RemoteAddress -notmatch '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|169\.254\.)'

    [PSCustomObject]@{
        State         = $conn.State
        LocalAddress  = $conn.LocalAddress
        LocalPort     = $conn.LocalPort
        RemoteAddress = $conn.RemoteAddress
        RemotePort    = $conn.RemotePort
        RemoteHost    = $remHost
        PID           = $conn.OwningProcess
        ProcessName   = if ($proc) { $proc.Name } else { '' }
        ProcessPath   = if ($proc) { $proc.Path } else { '' }
        IsExternal    = $isExt
    }
}

$established = @($netConns | Where-Object { $_.State -eq 'Established' })
$listening   = @($netConns | Where-Object { $_.State -eq 'Listen' })
$external    = @($netConns | Where-Object { $_.IsExternal })

Save-Csv "$triageRoot\Network\tcp_connections.csv" $netConns
Save-Csv "$triageRoot\Network\tcp_established.csv" $established
Save-Csv "$triageRoot\Network\tcp_listening.csv"   $listening

$udpConns = Get-NetUDPEndpoint -EA SilentlyContinue | ForEach-Object {
    $ep   = $_
    $proc = $procData | Where-Object { $_.PID -eq $ep.OwningProcess } | Select-Object -First 1
    [PSCustomObject]@{
        LocalAddress = $ep.LocalAddress
        LocalPort    = $ep.LocalPort
        PID          = $ep.OwningProcess
        ProcessName  = if ($proc) { $proc.Name } else { '' }
        ProcessPath  = if ($proc) { $proc.Path } else { '' }
    }
}
Save-Csv "$triageRoot\Network\udp_endpoints.csv" $udpConns

$suspNetProcs = @('powershell','powershell_ise','cmd','wscript','cscript',
    'mshta','rundll32','regsvr32','certutil','bitsadmin','msiexec',
    'schtasks','wmic','curl','wget','bcdedit','regasm','installutil')
foreach ($c in ($external | Where-Object { $_.State -eq 'Established' })) {
    $pn = ($c.ProcessName -replace '\.exe$','').ToLower()
    if ($pn -in $suspNetProcs) {
        Add-Highlight 'Network' 'HIGH' "Suspicious external connection: $($c.ProcessName) -> $($c.RemoteAddress):$($c.RemotePort)" "PID=$($c.PID) Host=$($c.RemoteHost)" 'T1071'
    }
}

$namedPipes = [System.Collections.Generic.List[PSCustomObject]]::new()
try {
    # Build PID->Path/Name lookups from already-collected process data
    $pidPathMap = @{}
    $pidNameMap = @{}
    foreach ($pd in $procData) {
        if ($pd.PID) {
            if ($pd.Path) { $pidPathMap[[int]$pd.PID] = $pd.Path }
            if ($pd.Name) { $pidNameMap[[int]$pd.PID] = $pd.Name }
        }
    }

    # P/Invoke: GetNamedPipeServerProcessId requires opening a handle to the pipe.
    # Available on Vista+. Returns owner PID of the server end of the pipe.
    $pipeApiAvailable = $false
    try {
        if (-not ('ZS.PipeApi' -as [type])) {
            Add-Type -ErrorAction Stop -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
namespace ZS {
  public static class PipeApi {
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern SafeFileHandle CreateFileW(
        string lpFileName, uint dwDesiredAccess, uint dwShareMode,
        IntPtr lpSecurityAttributes, uint dwCreationDisposition,
        uint dwFlagsAndAttributes, IntPtr hTemplateFile);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool GetNamedPipeServerProcessId(SafeFileHandle h, out uint pid);
    public static uint GetOwnerPid(string pipeName) {
        // 0x80000000 = GENERIC_READ, 3 = OPEN_EXISTING
        // Share = READ|WRITE|DELETE so we don't disturb the pipe
        SafeFileHandle h = CreateFileW(@"\\.\pipe\" + pipeName, 0x80000000, 7,
                                       IntPtr.Zero, 3, 0, IntPtr.Zero);
        if (h.IsInvalid) { return 0; }
        uint pid = 0;
        try { if (!GetNamedPipeServerProcessId(h, out pid)) pid = 0; }
        finally { h.Close(); }
        return pid;
    }
  }
}
'@
        }
        $pipeApiAvailable = $true
    } catch {
        $pipeApiAvailable = $false
    }

    # Enumerate pipes via Get-ChildItem.
    # NOTE: trailing \* is required - without it PS treats the path as a file, not a dir.
    $pipeNames = [System.Collections.Generic.List[string]]::new()
    try {
        Get-ChildItem '\\.\pipe\*' -EA Stop | ForEach-Object {
            if ($_.Name -and $_.Name.Trim()) { $pipeNames.Add($_.Name.Trim()) }
        }
    } catch {}

    # Fallback via .NET if Get-ChildItem fails (rare, but seen on hardened hosts)
    if ($pipeNames.Count -eq 0) {
        try {
            [System.IO.Directory]::GetFiles('\\.\pipe\') | ForEach-Object {
                $leaf = $_ -replace '^.*\\', ''
                if ($leaf -and $leaf.Trim()) { $pipeNames.Add($leaf.Trim()) }
            }
        } catch {}
    }

    # Deduplicate
    $pipeNames = @($pipeNames | Sort-Object -Unique)

    foreach ($pipeName in $pipeNames) {
        if ([string]::IsNullOrWhiteSpace($pipeName)) { continue }

        $isSusp = $false
        foreach ($pat in $c2PipePatterns) {
            if ($pipeName -match $pat) { $isSusp = $true; break }
        }

        # Resolve owner PID via P/Invoke (best-effort; returns 0 on failure)
        $ownerPid = 0
        if ($pipeApiAvailable) {
            try { $ownerPid = [int]([ZS.PipeApi]::GetOwnerPid($pipeName)) } catch { $ownerPid = 0 }
        }

        # Resolve process path and name from already-collected data
        $ownerPath = ''
        $ownerName = ''
        if ($ownerPid -gt 0) {
            if ($pidPathMap.ContainsKey($ownerPid)) { $ownerPath = $pidPathMap[$ownerPid] }
            if ($pidNameMap.ContainsKey($ownerPid)) { $ownerName = $pidNameMap[$ownerPid] }
            if (-not $ownerPath -and -not $ownerName) { $ownerName = "PID:$ownerPid" }
        }

        $namedPipes.Add([PSCustomObject]@{
            PipeName    = $pipeName
            OwnerPID    = if ($ownerPid -gt 0) { $ownerPid } else { '' }
            ProcessName = $ownerName
            ProcessPath = $ownerPath
            Suspicious  = $isSusp
        })
        if ($isSusp) {
            Add-Highlight 'Network' 'CRITICAL' "Suspicious named pipe (C2 indicator): $pipeName" `
                "PID=$ownerPid Process=$ownerName Path=$ownerPath" 'T1071.001'
        }
    }
} catch {}
Save-Csv "$triageRoot\Network\named_pipes.csv" $namedPipes

$dnsCache = Get-DnsClientCache -EA SilentlyContinue |
    Select-Object Entry, RecordName, RecordType, Data, TimeToLive
Save-Csv "$triageRoot\Network\dns_cache.csv" $dnsCache

Save-Text "$triageRoot\Network\arp_table.txt"   ((& arp -a 2>$null) -join "`n")
Save-Text "$triageRoot\Network\route_table.txt" ((& route print 2>$null) -join "`n")

$adapters = Get-NetAdapter -EA SilentlyContinue |
    Select-Object Name, Status, MacAddress, LinkSpeed, InterfaceDescription
Save-Csv "$triageRoot\Network\adapters.csv" $adapters
$ipConf = Get-NetIPAddress -EA SilentlyContinue |
    Select-Object InterfaceAlias, AddressFamily, IPAddress, PrefixLength
Save-Csv "$triageRoot\Network\ip_addresses.csv" $ipConf

Write-OK "TCP=$($netConns.Count) (estab=$($established.Count) listen=$($listening.Count) ext=$($external.Count)) | Pipes=$($namedPipes.Count)"

# -------------------------------------------------------
# 4. PERSISTENCE
# -------------------------------------------------------
Write-Phase 'Persistence & Autoruns'

$persistItems = [System.Collections.Generic.List[PSCustomObject]]::new()

function Test-PersistValue {
    param([string]$Val, [string]$KeyPath, [string]$ValName)
    $isSusp = $false; $mitre = ''
    foreach ($d in $hiRiskDirs) {
        if ($Val -like "$d*") { $isSusp = $true; $mitre = 'T1547.001'; break }
    }
    if (-not $isSusp) {
        foreach ($pat in $suspCmdPatterns) {
            if ($Val -match $pat) { $isSusp = $true; $mitre = 'T1059'; break }
        }
    }
    if ($isSusp) {
        $vShort = if ($Val.Length -gt 100) { $Val.Substring(0,100) } else { $Val }
        Add-Highlight 'Persistence' 'HIGH' "Suspicious autorun: $ValName" "Key=$KeyPath Val=$vShort" $mitre
    }
    return $isSusp
}

$runKeys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
)
foreach ($key in $runKeys) {
    try {
        $props = Get-ItemProperty -Path $key -EA Stop
        $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
            $v = $_.Value
            if (-not $v) { return }
            $vs  = if ($v.ToString().Length -gt 300) { $v.ToString().Substring(0,300) } else { $v.ToString() }
            $isS = Test-PersistValue $v $key $_.Name
            $persistItems.Add([PSCustomObject]@{
                Source='RunKey'; Location=$key; Name=$_.Name; Value=$vs; Suspicious=$isS
            })
        }
    } catch {}
}

$wlKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
try {
    $wl = Get-ItemProperty -Path $wlKey -EA Stop
    foreach ($vn in @('Shell','Userinit','AppSetup','GinaDLL','TaskMan')) {
        $v = $wl.$vn
        if ($v) {
            $isSusp = $false
            if ($vn -eq 'Shell'    -and $v -ne 'explorer.exe')           { $isSusp = $true }
            if ($vn -eq 'Userinit' -and $v -notmatch 'userinit\.exe,?$') { $isSusp = $true }
            if ($vn -eq 'GinaDLL')                                        { $isSusp = $true }
            $persistItems.Add([PSCustomObject]@{
                Source='Winlogon'; Location=$wlKey; Name=$vn; Value=$v; Suspicious=$isSusp
            })
            if ($isSusp) {
                Add-Highlight 'Persistence' 'CRITICAL' "Winlogon hijack: $vn = $v" "Key=$wlKey" 'T1547.004'
            }
        }
    }
} catch {}

$ifeoKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
try {
    Get-ChildItem $ifeoKey -EA Stop | ForEach-Object {
        $debugger = (Get-ItemProperty -Path $_.PSPath -EA SilentlyContinue).Debugger
        if ($debugger) {
            $persistItems.Add([PSCustomObject]@{
                Source='IFEO_Debugger'; Location=$_.PSPath; Name='Debugger'; Value=$debugger; Suspicious=$true
            })
            Add-Highlight 'Persistence' 'HIGH' "IFEO debugger hijack: $($_.PSChildName) -> $debugger" "Key=$($_.PSPath)" 'T1546.012'
        }
    }
} catch {}

$appInitKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppInitDLLs'
try {
    $appInit = (Get-ItemProperty -Path $appInitKey -EA Stop).AppInit_DLLs
    if ($appInit -and $appInit.Trim() -ne '') {
        $persistItems.Add([PSCustomObject]@{
            Source='AppInitDLL'; Location=$appInitKey; Name='AppInit_DLLs'; Value=$appInit; Suspicious=$true
        })
        Add-Highlight 'Persistence' 'HIGH' "AppInit_DLLs set: $appInit" '' 'T1546.010'
    }
} catch {}

$lsaKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
try {
    $lsaProps = Get-ItemProperty -Path $lsaKey -EA Stop
    $secPkgs  = $lsaProps.'Security Packages'
    $legitSSP = @('kerberos','msv1_0','schannel','wdigest','tspkg','pku2u','cloudap','')
    if ($secPkgs) {
        $pkgList = if ($secPkgs -is [array]) { $secPkgs } else { $secPkgs -split '\s+' }
        foreach ($pkg in $pkgList) {
            $pkgTrimmed = $pkg.Trim()
            if (-not $pkgTrimmed -or $pkgTrimmed -eq '""') { continue }
            if ($pkgTrimmed.ToLower() -notin $legitSSP) {
                $persistItems.Add([PSCustomObject]@{
                    Source='LSA_SSP'; Location=$lsaKey; Name='Security Packages'; Value=$pkgTrimmed; Suspicious=$true
                })
                Add-Highlight 'Persistence' 'CRITICAL' "Non-standard LSA Security Package: $pkgTrimmed" "Key=$lsaKey" 'T1547.005'
            }
        }
    }
} catch {}

$sessMgrKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
try {
    $bootExec = (Get-ItemProperty -Path $sessMgrKey -EA Stop).BootExecute
    $legitBE  = @('autocheck autochk *')
    foreach ($be in $bootExec) {
        if ($be.Trim() -and $be.Trim().ToLower() -notin $legitBE) {
            $persistItems.Add([PSCustomObject]@{
                Source='BootExecute'; Location=$sessMgrKey; Name='BootExecute'; Value=$be; Suspicious=$true
            })
            Add-Highlight 'Persistence' 'CRITICAL' "Non-standard BootExecute: $be" "Key=$sessMgrKey" 'T1547.001'
        }
    }
} catch {}

$comHijackCount = 0
$comHijackSusp  = 0
foreach ($base in @('HKCU:\SOFTWARE\Classes\CLSID','HKCU:\SOFTWARE\Classes\Wow6432Node\CLSID')) {
    try {
        Get-ChildItem -Path $base -EA Stop | ForEach-Object {
            $clsid = $_.PSChildName
            $ip    = "$($_.PSPath)\InprocServer32"
            $dll   = try { (Get-ItemProperty -Path $ip -EA Stop).'(default)' } catch { $null }
            if ($dll) {
                $comHijackCount++
                # Real hijacks point to user-writable / unusual locations.
                # DLLs under System32, SysWOW64, or Program Files are legitimate
                # AppX/UWP-style HKCU registrations and not actionable as IOCs.
                $dllExpanded = [Environment]::ExpandEnvironmentVariables($dll)
                $isLegitPath = $dllExpanded -match '^(?i)("?)(C:\\Windows\\(System32|SysWOW64|WinSxS)\\|C:\\Program Files( \(x86\))?\\)'
                $isSusp      = -not $isLegitPath
                $persistItems.Add([PSCustomObject]@{
                    Source='COM_Hijack'; Location=$ip; Name=$clsid; Value=$dll; Suspicious=$isSusp
                })
                if ($isSusp) {
                    $comHijackSusp++
                    if ($comHijackSusp -le 5) {
                        Add-Highlight 'Persistence' 'HIGH' "COM hijack HKCU: $clsid -> $dll" "Path=$ip" 'T1546.015'
                    }
                }
            }
        }
    } catch {}
}
if ($comHijackSusp -gt 5) {
    Add-Highlight 'Persistence' 'HIGH' "COM hijack entries in HKCU (non-system paths): $comHijackSusp total" "Only first 5 logged individually" 'T1546.015'
}

foreach ($sp in @(
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup')) {
    if (Test-Path $sp) {
        Get-ChildItem -Path $sp -File -Recurse -EA SilentlyContinue | ForEach-Object {
            $ext    = $_.Extension.ToLower()
            $isSusp = $ext -in @('.exe','.dll','.ps1','.bat','.vbs','.js','.hta','.scr','.pif','.cmd')
            $persistItems.Add([PSCustomObject]@{
                Source='StartupFolder'; Location=$sp; Name=$_.Name; Value=$_.FullName; Suspicious=$isSusp
            })
            if ($isSusp) {
                Add-Highlight 'Persistence' 'MEDIUM' "Executable in startup folder: $($_.Name)" "Path=$($_.FullName)" 'T1547.001'
            }
        }
    }
}
Save-Csv "$triageRoot\Persistence\autoruns.csv" $persistItems

function ConvertTo-TaskObject {
    param($t, [string]$Action, [string]$TaskPath, [string]$State, [string]$Author,
          [string]$LastRunTime, [string]$NextRunTime)
    $isSusp  = $false
    $legitTP = @('\Microsoft\','\Google\','\Adobe\','\Mozilla\','\Kaspersky\','\UserGate\','\ESET\','\Windows\','\Intel\','\Zoom\','\Dropbox\')
    $inLegit = $false
    foreach ($lp in $legitTP) { if ($TaskPath -like "$lp*") { $inLegit = $true; break } }
    foreach ($pat in $suspCmdPatterns) { if ($Action -match $pat) { $isSusp = $true; break } }
    if (-not $inLegit -and $Action -match '\\(Temp|Tmp|AppData|ProgramData\\Temp)\\') { $isSusp = $true }
    if ($isSusp) {
        $actShort = if ($Action.Length -gt 150) { $Action.Substring(0,150) } else { $Action }
        $tname = if ($t -and $t.TaskName) { $t.TaskName } else { Split-Path $TaskPath -Leaf }
        Add-Highlight 'Persistence' 'HIGH' "Suspicious scheduled task: $tname" "Path=$TaskPath Action=$actShort" 'T1053.005'
    }
    [PSCustomObject]@{
        TaskName    = if ($t -and $t.TaskName) { $t.TaskName } else { Split-Path $TaskPath -Leaf }
        TaskPath    = $TaskPath
        State       = $State
        Author      = $Author
        Action      = if ($Action.Length -gt 300) { $Action.Substring(0,300) } else { $Action }
        LastRunTime = $LastRunTime
        NextRunTime = $NextRunTime
        Suspicious  = $isSusp
    }
}

# Primary: Get-ScheduledTask (ScheduledTasks module, PS 3.0+)
$rawTasks = @(Get-ScheduledTask -EA SilentlyContinue)

$tasks = [System.Collections.Generic.List[PSCustomObject]]::new()

if ($rawTasks.Count -gt 0) {
    foreach ($t in $rawTasks) {
        try {
            $info     = Get-ScheduledTaskInfo -TaskName $t.TaskName -TaskPath $t.TaskPath -EA SilentlyContinue
            $action   = if ($t.Actions) {
                ($t.Actions | ForEach-Object {
                    $exe = if ($_.Execute)   { $_.Execute }   else { '' }
                    $arg = if ($_.Arguments) { $_.Arguments } else { '' }
                    "$exe $arg".Trim()
                }) -join ' | '
            } else { '' }
            $stateStr = try { [string]$t.State } catch { '' }
            $author   = try { if ($t.Author) { [string]$t.Author } else { '' } } catch { '' }
            $lastRun  = try { if ($info -and $info.LastRunTime) { $info.LastRunTime.ToString() } else { '' } } catch { '' }
            $nextRun  = try { if ($info -and $info.NextRunTime) { $info.NextRunTime.ToString() } else { '' } } catch { '' }
            $tasks.Add((ConvertTo-TaskObject $t $action $t.TaskPath $stateStr $author $lastRun $nextRun))
        } catch {}
    }
} else {
    # Fallback: COM Schedule.Service — works even when ScheduledTasks module is unavailable
    Write-Warn "Get-ScheduledTask returned 0 results, trying COM fallback"
    try {
        $sched = New-Object -ComObject Schedule.Service -EA Stop
        $sched.Connect()
        $stack = [System.Collections.Stack]::new()
        $stack.Push($sched.GetFolder('\'))
        while ($stack.Count -gt 0) {
            $folder = $stack.Pop()
            foreach ($sub in @($folder.GetFolders(0))) { $stack.Push($sub) }
            foreach ($task in @($folder.GetTasks(1))) {   # 1 = include hidden
                try {
                    $defXml  = [xml]$task.Xml
                    $nsMgr   = New-Object System.Xml.XmlNamespaceManager($defXml.NameTable)
                    $nsMgr.AddNamespace('t','http://schemas.microsoft.com/windows/2004/02/mit/task')
                    $exec    = $defXml.SelectSingleNode('//t:Exec', $nsMgr)
                    $exePath = if ($exec) { $exec.Command } else { '' }
                    $execArgs = if ($exec) { $exec.Arguments } else { '' }
                    $action  = "$exePath $execArgs".Trim()
                    $author  = try { $defXml.Task.RegistrationInfo.Author } catch { '' }
                    $stateMap = @{ 0='Unknown'; 1='Disabled'; 2='Queued'; 3='Ready'; 4='Running' }
                    $stateStr = if ($stateMap.ContainsKey($task.State)) { $stateMap[$task.State] } else { $task.State.ToString() }
                    $lastRun  = try { $task.LastRunTime.ToString() } catch { '' }
                    $nextRun  = try { $task.NextRunTime.ToString() } catch { '' }
                    $tasks.Add((ConvertTo-TaskObject $null $action $task.Path $stateStr $author $lastRun $nextRun))
                } catch {}
            }
        }
    } catch {
        Write-Warn "COM Schedule.Service fallback also failed: $_"
    }
}

if ($tasks.Count -eq 0) {
    Write-Warn "scheduled_tasks.csv: no tasks collected (0 results from both methods)"
}

$taskCsv = "$triageRoot\Persistence\scheduled_tasks.csv"
try {
    if ($tasks.Count -gt 0) {
        $tasks | Export-Csv -Path $taskCsv -NoTypeInformation -Encoding UTF8 -Force
    } else {
        # Write header-only CSV so the file is never 0 bytes
        [PSCustomObject]@{TaskName='';TaskPath='';State='';Author='';Action='';LastRunTime='';NextRunTime='';Suspicious=''} |
            Export-Csv -Path $taskCsv -NoTypeInformation -Encoding UTF8 -Force
    }
} catch { Save-Csv $taskCsv $tasks }

$services = Get-WmiObject Win32_Service | ForEach-Object {
    $svc  = $_
    $path = $svc.PathName
    $exe  = if ($path) { ($path -replace '"','') -split ' ' | Select-Object -First 1 } else { '' }
    # Reuse the process-phase cache: most service binaries (svchost.exe, etc.) are already
    # hashed. -SkipHashing is honored transparently via Get-PathHashSig.
    $hash = if ($exe -and (Test-Path $exe -EA SilentlyContinue)) { (Get-PathHashSig $exe).Hash } else { 'N/A' }
    $isSusp = $false
    if ($path) {
        foreach ($d in $hiRiskDirs) { if ($path -like "$d*") { $isSusp = $true; break } }
        if (-not $isSusp) {
            foreach ($pat in $suspCmdPatterns) { if ($path -match $pat) { $isSusp = $true; break } }
        }
    }
    if ($isSusp) {
        Add-Highlight 'Persistence' 'HIGH' "Suspicious service: $($svc.Name)" "Path=$path State=$($svc.State)" 'T1543.003'
    }
    [PSCustomObject]@{
        Name        = $svc.Name
        DisplayName = $svc.DisplayName
        State       = $svc.State
        StartMode   = $svc.StartMode
        PathName    = $path
        StartName   = $svc.StartName
        SHA256      = $hash
        Suspicious  = $isSusp
    }
}
Save-Csv "$triageRoot\Persistence\services.csv" $services

$wmiFilters   = @(Get-WmiObject -Namespace 'root\subscription' -Class '__EventFilter'   -EA SilentlyContinue)
$wmiConsumers = @(Get-WmiObject -Namespace 'root\subscription' -Class '__EventConsumer' -EA SilentlyContinue)
$wmiBindings  = @(Get-WmiObject -Namespace 'root\subscription' -Class '__FilterToConsumerBinding' -EA SilentlyContinue)
Save-Json "$triageRoot\Persistence\wmi_subscriptions.json" @{
    Filters   = ($wmiFilters   | Select-Object Name, Query, QueryLanguage)
    Consumers = ($wmiConsumers | Select-Object Name, ScriptText, CommandLineTemplate, ExecutablePath)
    Bindings  = ($wmiBindings  | Select-Object Filter, Consumer)
}

# Filter out known-legitimate Windows default WMI subscriptions before alerting.
# These ship with Windows and Microsoft products - flagging them is pure noise.
$legitWmiNames = @(
    'SCM Event Log Filter','SCM Event Log Consumer',         # Service Control Manager (built-in)
    'BVTFilter','BVTConsumer',                               # Build Verification Test (Win debug)
    'NETeQoSEvent_*'                                          # Network QoS
)
$suspWmiFilters = @($wmiFilters | Where-Object {
    $n = $_.Name
    $isLegit = $false
    foreach ($lp in $legitWmiNames) {
        if ($n -like $lp) { $isLegit = $true; break }
    }
    -not $isLegit
})
$wmiFilterCount = $wmiFilters.Count
$suspWmiCount   = $suspWmiFilters.Count
if ($suspWmiCount -gt 0) {
    $names = ($suspWmiFilters | Select-Object -ExpandProperty Name) -join ', '
    Add-Highlight 'Persistence' 'CRITICAL' "Non-default WMI event subscription(s): $suspWmiCount" "Names: $names - review wmi_subscriptions.json" 'T1546.003'
}

Write-OK "Autoruns=$($persistItems.Count) | Tasks=$($tasks.Count) | Services=$($services.Count) | WMI=$wmiFilterCount(susp=$suspWmiCount) | COM=$comHijackCount(susp=$comHijackSusp)"

# -------------------------------------------------------
# 5. USER ACCOUNTS & SESSIONS
# -------------------------------------------------------
Write-Phase 'User Accounts & Sessions'

# Get-LocalUser - safe, fast
$localUsers = @(Get-LocalUser -EA SilentlyContinue | ForEach-Object {
    [PSCustomObject]@{
        Name             = $_.Name
        Enabled          = $_.Enabled
        LastLogon        = $_.LastLogon
        PasswordLastSet  = $_.PasswordLastSet
        PasswordExpires  = $_.PasswordExpires
        PasswordRequired = $_.PasswordRequired
        Description      = $_.Description
        SID              = $_.SID.Value
    }
})
Save-Csv "$triageRoot\Users\local_users.csv" $localUsers

# Win32_UserAccount - can hang on domain-joined systems, use timeout
try {
    $wuJob  = Start-Job { Get-WmiObject Win32_UserAccount -EA SilentlyContinue |
                          Where-Object { $_.Name -match '\$' -and $_.LocalAccount -eq $true } }
    $dollarAccts = $wuJob | Wait-Job -Timeout 10 | Receive-Job
    Remove-Job $wuJob -Force -EA SilentlyContinue
    if ($dollarAccts) {
        $names = ($dollarAccts | Select-Object -ExpandProperty Name) -join ', '
        Add-Highlight 'Users' 'HIGH' "Dollar-sign local accounts: $names" "May be backdoor accounts" 'T1136.001'
    }
} catch {}

$recentEnabled = $localUsers | Where-Object {
    $_.Enabled -eq $true -and $_.PasswordLastSet -ne $null -and
    $_.PasswordLastSet -gt (Get-Date).AddDays(-$DaysBack)
}
foreach ($u in $recentEnabled) {
    Add-Highlight 'Users' 'MEDIUM' "Account with recent password change: $($u.Name)" "PasswordLastSet=$($u.PasswordLastSet)" 'T1136.001'
}

# Get-LocalGroup + Get-LocalGroupMember - wrap entire block in job with timeout
try {
    $lgJob = Start-Job {
        Get-LocalGroup -EA SilentlyContinue | ForEach-Object {
            $g = $_
            $members = try {
                (Get-LocalGroupMember -Group $g.Name -EA Stop |
                 Select-Object -ExpandProperty Name) -join ', '
            } catch { '' }
            [PSCustomObject]@{ Group=$g.Name; Description=$g.Description; Members=$members }
        }
    }
    $localGroups = $lgJob | Wait-Job -Timeout 15 | Receive-Job
    Remove-Job $lgJob -Force -EA SilentlyContinue
} catch { $localGroups = $null }
Save-Csv "$triageRoot\Users\local_groups.csv" $localGroups

# query user - timeout 8 sec
try {
    $quJob = Start-Job { & query user 2>$null }
    $quOut = $quJob | Wait-Job -Timeout 8 | Receive-Job
    Remove-Job $quJob -Force -EA SilentlyContinue
    Save-Text "$triageRoot\Users\logon_sessions.txt" ($quOut -join "`n")
} catch {
    Save-Text "$triageRoot\Users\logon_sessions.txt" "query user: timeout or not available"
}

# klist - timeout 8 sec
try {
    $klJob = Start-Job { & klist 2>$null }
    $klistOut = $klJob | Wait-Job -Timeout 8 | Receive-Job
    Remove-Job $klJob -Force -EA SilentlyContinue
    Save-Text "$triageRoot\Users\kerberos_tickets.txt" ($klistOut -join "`n")
    if ($klistOut) {
        $klistStr = $klistOut -join ' '
        if ($klistStr -match '(10 years|3650 days|golden|20[3-9][0-9])') {
            Add-Highlight 'Users' 'CRITICAL' "Possible Golden/Silver Ticket in Kerberos cache" "klist output contains suspicious validity period" 'T1558.001'
        }
    }
} catch {
    Save-Text "$triageRoot\Users\kerberos_tickets.txt" "klist: timeout or not available"
}

Write-OK "Users=$($localUsers.Count) | Groups=$($localGroups.Count)"

# -------------------------------------------------------
# 6. POWERSHELL ARTIFACTS
# -------------------------------------------------------
Write-Phase 'PowerShell Artifacts'

$psHistCount = 0
Get-ChildItem 'C:\Users' -Directory -EA SilentlyContinue | ForEach-Object {
    $histPath = "$($_.FullName)\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    if (Test-Path $histPath) {
        $content = Get-Content $histPath -EA SilentlyContinue | Select-Object -Last 1000
        $safe    = $_.Name -replace '[^\w\-]','_'
        $content | Out-File -FilePath "$triageRoot\Users\ps_history_$safe.txt" -Encoding UTF8 -Force
        $psHistCount++
        foreach ($line in $content) {
            foreach ($pat in $suspCmdPatterns) {
                if ($line -match $pat) {
                    $lineShort = if ($line.Length -gt 100) { $line.Substring(0,100) } else { $line }
                    Add-Highlight 'PowerShell' 'HIGH' "Suspicious PS history [$($_.Name)]: $lineShort" "Pattern=$pat" 'T1059.001'
                    break
                }
            }
        }
    }
}
$clmStatus = $ExecutionContext.SessionState.LanguageMode
Save-Text "$triageRoot\Users\ps_language_mode.txt" "LanguageMode: $clmStatus"
Write-OK "PS history files=$psHistCount | LanguageMode=$clmStatus"

# -------------------------------------------------------
# 7. EVENT LOGS
# -------------------------------------------------------
Write-Phase 'Event Logs'

$logSpecs = @(
    @{ Name='Security';    IDs=@(4624,4625,4648,4672,4688,4698,4699,4700,4720,4722,4726,4732,4740,4756,1102,7045) }
    @{ Name='System';      IDs=@(7036,7045,7034,1074,6005,6006) }
    @{ Name='Application'; IDs=@(1000,1001,1002) }
    @{ Name='Microsoft-Windows-PowerShell/Operational';                              IDs=@(4103,4104,4105,4106) }
    @{ Name='Microsoft-Windows-TaskScheduler/Operational';                           IDs=@(106,140,141,200,201) }
    @{ Name='Microsoft-Windows-WMI-Activity/Operational';                            IDs=@(5857,5858,5860,5861) }
    @{ Name='Microsoft-Windows-TerminalServices-LocalSessionManager/Operational';    IDs=@(21,22,23,24,25) }
    @{ Name='Microsoft-Windows-Bits-Client/Operational';                             IDs=@(3,59,60,61) }
    @{ Name='Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational';         IDs=@(131,140) }
    @{ Name='Microsoft-Windows-DNS-Client/Operational';                              IDs=@(3006,3010) }
    @{ Name='Microsoft-Windows-Sysmon/Operational';                                  IDs=@(1,2,3,5,6,7,8,10,11,12,13,17,18,22,23,25) }
    @{ Name='Microsoft-Windows-AppLocker/EXE and DLL';                               IDs=@(8003,8004,8006,8007) }
    @{ Name='Microsoft-Windows-Windows Defender/Operational';                        IDs=@(1006,1007,1008,1013,1116,1117,1118,1119,5001,5004,5007,5010,5012) }
)

$startTime = (Get-Date).AddDays(-$DaysBack)
$csvEventCount = 0
foreach ($spec in $logSpecs) {
    try {
        $filter = @{ LogName=$spec.Name; Id=$spec.IDs; StartTime=$startTime }
        $evts   = Get-WinEvent -FilterHashtable $filter -MaxEvents $EventLogCount -EA Stop |
            Select-Object TimeCreated, Id, LevelDisplayName, ProviderName,
                @{N='Message';E={
                    # $_.Message can be $null (event with no message template / missing
                    # provider DLL). Under StrictMode .Length on $null throws and kills the
                    # whole channel's pipeline, losing every event. Coerce to string first.
                    $m = if ($null -eq $_.Message) { '' } else { [string]$_.Message }
                    if ($m.Length -gt 500) { $m.Substring(0,500) } else { $m }
                }}
        $safe   = $spec.Name -replace '[/\\]','-'
        Save-Csv "$triageRoot\Logs\evtx_$safe.csv" $evts
        $csvEventCount += $evts.Count
        Write-OK "Log '$($spec.Name)': $($evts.Count) events"
    } catch {
        $fqeid = $_.FullyQualifiedErrorId
        if ($fqeid -match 'NoMatchingEventsFound' -or $_.Exception.Message -match 'No events') {
            Write-Info "Log '$($spec.Name)': no events in last $DaysBack days"
        } elseif ($_.Exception.Message -match 'not found') {
            Write-Info "Log '$($spec.Name)': channel not present on this system"
        } else {
            Write-Warn "Log '$($spec.Name)': $($_.Exception.Message)"
        }
    }
}
Write-OK "CSV event extraction complete: $csvEventCount total events"

# Raw EVTX copies
if ($CopyRawEvtx) {
    $winevtDir  = 'C:\Windows\System32\winevt\Logs'
    $evtxFiles  = Get-ChildItem -Path $winevtDir -Filter '*.evtx' -EA SilentlyContinue
    $evtxTotal  = if ($evtxFiles) { ($evtxFiles | Measure-Object).Count } else { 0 }
    $evtxCopied = 0
    $evtxFailed = 0
    Write-OK "FULL mode: copying ALL $evtxTotal *.evtx files from winevt\Logs..."
    foreach ($evtxFile in $evtxFiles) {
        $dest = "$triageRoot\Logs\$($evtxFile.Name)"
        Write-Info "  Copying EVTX: $($evtxFile.Name)"
        if     (Copy-LockedFile $evtxFile.FullName $dest) { $evtxCopied++ }
        elseif (Copy-ViaVSS     $evtxFile.FullName $dest) { $evtxCopied++ }
        else                                              { $evtxFailed++ }
    }
    Write-OK "Raw EVTX: copied=$evtxCopied failed=$evtxFailed (total=$evtxTotal)"
    Write-OK "Open .evtx files: double-click in Windows Event Viewer"
    Write-OK "Batch analysis: Chainsaw 'chainsaw hunt Logs\ --sigma rules\ --mapping mapping.yml'"
    Write-OK "               Hayabusa 'hayabusa csv-timeline -d Logs\ -o timeline.csv'"
} else {
    Write-Info "Raw EVTX: skipped (LITE mode) - use FULL mode to collect all winevt logs"
}

# -------------------------------------------------------
# 8. PREFETCH
# -------------------------------------------------------
Write-Phase 'Prefetch (Execution Evidence)'

$pfPath = 'C:\Windows\Prefetch'
if (Test-Path $pfPath) {
    # Try Get-ChildItem first, fall back to cmd dir if access denied
    $pfRaw = @(Get-ChildItem -Path $pfPath -Filter '*.pf' -Force -EA SilentlyContinue |
               Sort-Object LastWriteTime -Descending)
    if ($pfRaw.Count -eq 0) {
        # Fallback: use cmd dir to get file list, then access via .NET
        $dirOut = & cmd /c "dir /b /o-d `"$pfPath\*.pf`" 2>nul"
        $pfRaw  = @($dirOut | Where-Object { $_ -match '\.pf$' } | ForEach-Object {
            $fp = Join-Path $pfPath $_
            try { Get-Item -LiteralPath $fp -Force -EA Stop } catch { $null }
        } | Where-Object { $_ })
    }
    Write-Info "Prefetch folder: $($pfRaw.Count) .pf files found"
    if ($pfRaw.Count -gt 0) {
        $pfList = [System.Collections.Generic.List[PSCustomObject]]::new()
        foreach ($pf in $pfRaw) {
            $appName    = $pf.BaseName -replace '-[A-F0-9]{8}$',''
            $isAttacker = $false
            foreach ($tool in $knownAttackerTools) {
                if ($appName -match $tool) { $isAttacker = $true; break }
            }
            if ($isAttacker) {
                Add-Highlight 'Forensics' 'CRITICAL' "Known attacker tool in prefetch: $appName" "LastRun=$($pf.LastWriteTime) File=$($pf.Name)" 'T1059'
            }
            $pfList.Add([PSCustomObject]@{
                AppName     = $appName
                LastRun     = $pf.LastWriteTime
                SizeKB      = [Math]::Round($pf.Length / 1KB, 1)
                FileName    = $pf.Name
                KnownThreat = $isAttacker
            })
        }
        $pfList | Export-Csv -Path "$triageRoot\Forensics\prefetch.csv" -NoTypeInformation -Encoding UTF8 -Force
        $threatCount = ($pfList | Where-Object { $_.KnownThreat }).Count
        Write-OK "Prefetch=$($pfList.Count) entries | Known threats=$threatCount"
    } else {
        Write-Warn "Prefetch: folder exists but no .pf files readable"
    }
} else {
    Write-Info "Prefetch not found - likely disabled"
}

# -------------------------------------------------------
# 9. FILE ACTIVITY (LNK)
# -------------------------------------------------------
Write-Phase 'File Activity (Recent LNK)'

$allLnk = [System.Collections.Generic.List[PSCustomObject]]::new()
Get-ChildItem 'C:\Users' -Directory -EA SilentlyContinue | ForEach-Object {
    $uName   = $_.Name
    $recentP = "$($_.FullName)\AppData\Roaming\Microsoft\Windows\Recent"
    if (Test-Path $recentP) {
        Get-ChildItem -Path $recentP -Filter '*.lnk' -EA SilentlyContinue |
            Sort-Object LastWriteTime -Descending | Select-Object -First 200 | ForEach-Object {
                $target = Get-LnkTarget $_.FullName
                $isSusp = $false
                if ($target) {
                    foreach ($d in $hiRiskDirs) { if ($target -like "$d*") { $isSusp = $true; break } }
                    if ($target -match '^\\\\') { $isSusp = $true }
                }
                $allLnk.Add([PSCustomObject]@{
                    User         = $uName
                    LinkName     = $_.Name
                    TargetPath   = $target
                    LastAccessed = $_.LastWriteTime
                    Created      = $_.CreationTime
                    Suspicious   = $isSusp
                })
                if ($isSusp -and $target) {
                    Add-Highlight 'FileActivity' 'MEDIUM' "Suspicious LNK target: $($_.Name)" "Target=$target User=$uName" 'T1547.009'
                }
            }
    }
}
Save-Csv "$triageRoot\Forensics\lnk_recent.csv" $allLnk
Write-OK "LNK=$($allLnk.Count) | Suspicious=$(($allLnk | Where-Object {$_.Suspicious}).Count)"

# -------------------------------------------------------
# 10. REGISTRY FORENSICS
# -------------------------------------------------------
Write-Phase 'Registry Forensics (UserAssist / MUICache / TypedURLs)'

$regForensics = [System.Collections.Generic.List[PSCustomObject]]::new()
Get-ChildItem 'C:\Users' -Directory -EA SilentlyContinue | ForEach-Object {
    $uName = $_.Name
    $sid   = try {
        (New-Object System.Security.Principal.NTAccount($uName)).Translate(
            [System.Security.Principal.SecurityIdentifier]).Value
    } catch { $null }
    if (-not $sid) { return }
    $hkuBase = "Registry::HKEY_USERS\$sid"

    # UserAssist (ROT13 decoded)
    $uaKeys = Get-ChildItem "$hkuBase\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist" -EA SilentlyContinue
    foreach ($uak in $uaKeys) {
        $countKey = "$($uak.PSPath)\Count"
        try {
            $uaProps = Get-ItemProperty -Path $countKey -EA Stop
            $uaProps.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
                $decoded = $_.Name.ToCharArray() | ForEach-Object {
                    $c = [int]$_
                    if    ($c -ge 65 -and $c -le 90)  { [char](($c - 65 + 13) % 26 + 65) }
                    elseif($c -ge 97 -and $c -le 122) { [char](($c - 97 + 13) % 26 + 97) }
                    else  { $_ }
                }
                $decodedStr = -join $decoded
                $regForensics.Add([PSCustomObject]@{
                    User=$uName; Category='UserAssist'; Key=$decodedStr; Value=$_.Value
                })
                foreach ($d in $hiRiskDirs) {
                    if ($decodedStr -like "$d*") {
                        Add-Highlight 'Registry' 'HIGH' "UserAssist: execution from risky dir: $decodedStr" "User=$uName" 'T1204.002'
                        break
                    }
                }
            }
        } catch {}
    }

    # MUICache
    $muiKey = "$hkuBase\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache"
    try {
        $muiProps = Get-ItemProperty -Path $muiKey -EA Stop
        $muiProps.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
            if ($_.Name -match '\\') {
                $regForensics.Add([PSCustomObject]@{
                    User=$uName; Category='MUICache'; Key=$_.Name; Value=$_.Value
                })
            }
        }
    } catch {}

    # TypedURLs
    $urlKey = "$hkuBase\SOFTWARE\Microsoft\Internet Explorer\TypedURLs"
    try {
        $urlProps = Get-ItemProperty -Path $urlKey -EA Stop
        $urlProps.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
            $regForensics.Add([PSCustomObject]@{
                User=$uName; Category='TypedURL'; Key=$_.Name; Value=$_.Value
            })
        }
    } catch {}

    # RecentDocs
    $rdKey = "$hkuBase\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"
    try {
        Get-ChildItem -Path $rdKey -EA Stop | ForEach-Object {
            $regForensics.Add([PSCustomObject]@{
                User=$uName; Category="RecentDocs_$($_.PSChildName)"; Key=$_.PSChildName; Value='[binary list]'
            })
        }
    } catch {}
}
$ua  = @($regForensics | Where-Object { $_.Category -eq 'UserAssist' })
$mui = @($regForensics | Where-Object { $_.Category -eq 'MUICache' })
$url = @($regForensics | Where-Object { $_.Category -eq 'TypedURL' })
$rd  = @($regForensics | Where-Object { $_.Category -like 'RecentDocs*' })
if ($ua)  { Save-Csv "$triageRoot\Registry\userassist.csv"  $ua  }
if ($mui) { Save-Csv "$triageRoot\Registry\muicache.csv"    $mui }
if ($url) { Save-Csv "$triageRoot\Registry\typedurls.csv"   $url }
if ($rd)  { Save-Csv "$triageRoot\Registry\recentdocs.csv"  $rd  }
Write-OK "Registry forensics: UserAssist=$($ua.Count) MUICache=$($mui.Count) TypedURLs=$($url.Count) RecentDocs=$($rd.Count)"

# -------------------------------------------------------
# 11. CREDENTIAL SECURITY
# -------------------------------------------------------
Write-Phase 'Credential / LSA Security'

$credInfo = [ordered]@{}
try {
    $wdigest = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -EA Stop).UseLogonCredential
    $credInfo['WDigest_UseLogonCredential'] = $wdigest
    if ($wdigest -eq 1) {
        Add-Highlight 'Credentials' 'CRITICAL' 'WDigest plaintext caching ENABLED' 'UseLogonCredential=1 - plaintext creds in LSASS memory' 'T1003.001'
    }
} catch { $credInfo['WDigest_UseLogonCredential'] = 'N/A' }

try {
    $devGuard = Get-WmiObject -Namespace 'root\Microsoft\Windows\DeviceGuard' -Class Win32_DeviceGuard -EA Stop
    $credInfo['CredentialGuard_Running']    = $devGuard.SecurityServicesRunning -contains 1
    $credInfo['CredentialGuard_Configured'] = $devGuard.SecurityServicesConfigured -contains 1
    if (-not ($devGuard.SecurityServicesRunning -contains 1)) {
        Add-Highlight 'Credentials' 'MEDIUM' 'Credential Guard not running' 'LSASS not isolated in VSM' 'T1003.001'
    }
} catch { $credInfo['CredentialGuard_Running'] = 'N/A' }

try {
    $ppl = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -EA Stop).RunAsPPL
    $credInfo['LSA_RunAsPPL'] = $ppl
    if ($ppl -ne 1) {
        Add-Highlight 'Credentials' 'MEDIUM' 'LSA Protection (PPL) not enabled' 'LSASS unprotected from memory read' 'T1003.001'
    }
} catch { $credInfo['LSA_RunAsPPL'] = 'N/A' }

Save-Json "$triageRoot\Forensics\credential_security.json" $credInfo
Write-OK "WDigest=$($credInfo['WDigest_UseLogonCredential']) | PPL=$($credInfo['LSA_RunAsPPL']) | CredGuard=$($credInfo['CredentialGuard_Running'])"

# -------------------------------------------------------
# 12. CONFIGURATION
# -------------------------------------------------------
Write-Phase 'Configuration (Hosts / Firewall / ADS)'

$hostsPath    = 'C:\Windows\System32\drivers\etc\hosts'
$hostsContent = Get-Content $hostsPath -EA SilentlyContinue
Save-Text "$triageRoot\Config\hosts_file.txt" ($hostsContent -join "`n")

$hostsAbnormal = @($hostsContent | Where-Object {
    $_ -notmatch '^\s*#' -and $_ -match '\S' -and
    $_ -notmatch '(127\.0\.0\.1\s+localhost|::1\s+localhost|0\.0\.0\.0\s+0\.0\.0\.0)'
})
if ($hostsAbnormal.Count -gt 0) {
    $avDomains = @('kaspersky','windowsupdate','microsoft','update\.','antivirus','mcafee','symantec','eset','avp\.','sophosupd','malwarebytes','defender')
    foreach ($line in $hostsAbnormal) {
        foreach ($av in $avDomains) {
            if ($line -match $av) {
                Add-Highlight 'Config' 'HIGH' "Hosts redirects AV/update domain: $($line.Trim())" "File=$hostsPath" 'T1562.001'
            }
        }
    }
    if ($hostsAbnormal.Count -gt 3) {
        Add-Highlight 'Config' 'MEDIUM' "Hosts has $($hostsAbnormal.Count) non-standard entries" (($hostsAbnormal | Select-Object -First 5) -join ' | ') 'T1565.001'
    }
}

$fwProfiles = Get-NetFirewallProfile -EA SilentlyContinue |
    Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction
Save-Csv "$triageRoot\Config\firewall_profiles.csv" $fwProfiles
foreach ($fp in $fwProfiles) {
    if ($fp.Enabled -eq $false) {
        Add-Highlight 'Config' 'HIGH' "Firewall profile disabled: $($fp.Name)" '' 'T1562.004'
    }
}

$fwInbound = @(Get-NetFirewallRule -EA SilentlyContinue |
    Where-Object { $_.Enabled -eq $true -and $_.Direction -eq 'Inbound' } |
    Select-Object -First 200 | ForEach-Object {
        $r = $_
        $portFilter = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $r -EA SilentlyContinue
        [PSCustomObject]@{
            Name      = $r.DisplayName
            Action    = $r.Action.ToString()
            Profile   = $r.Profile
            Protocol  = if ($portFilter) { $portFilter.Protocol } else { '' }
            LocalPort = if ($portFilter) { $portFilter.LocalPort } else { '' }
            Program   = (Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $r -EA SilentlyContinue).Program
        }
    })
Save-Csv "$triageRoot\Config\firewall_rules_inbound.csv" $fwInbound

$fwOutbound = @(Get-NetFirewallRule -EA SilentlyContinue |
    Where-Object { $_.Enabled -eq $true -and $_.Direction -eq 'Outbound' } |
    Select-Object -First 200 | ForEach-Object {
        $r = $_
        $portFilter = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $r -EA SilentlyContinue
        [PSCustomObject]@{
            Name       = $r.DisplayName
            Action     = $r.Action.ToString()
            Profile    = $r.Profile
            Protocol   = if ($portFilter) { $portFilter.Protocol } else { '' }
            RemotePort = if ($portFilter) { $portFilter.RemotePort } else { '' }
            Program    = (Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $r -EA SilentlyContinue).Program
        }
    })
Save-Csv "$triageRoot\Config\firewall_rules_outbound.csv" $fwOutbound

$adsScanDirs = @("$env:TEMP", 'C:\Users\Public', "$env:APPDATA")
$adsResults  = [System.Collections.Generic.List[PSCustomObject]]::new()
foreach ($scanDir in $adsScanDirs) {
    if (-not (Test-Path $scanDir)) { continue }
    try {
        # -File replaces "Where { -not PSIsContainer }" and skips dirs at the source
        # Stop after 500 files per scan dir (don't enumerate the whole tree first)
        $count = 0
        Get-ChildItem -Path $scanDir -Recurse -File -Force -EA SilentlyContinue | ForEach-Object {
            if ($count -ge 500) { return }
            $count++
            $streams = Get-Item -LiteralPath $_.FullName -Stream * -EA SilentlyContinue |
                Where-Object { $_.Stream -ne ':$DATA' -and $_.Stream -ne 'Zone.Identifier' }
            foreach ($stream in $streams) {
                $adsResults.Add([PSCustomObject]@{
                    FilePath   = $_.FullName
                    StreamName = $stream.Stream
                    SizeBytes  = $stream.Length
                })
                Add-Highlight 'Config' 'HIGH' "ADS found: $($_.FullName):$($stream.Stream)" "Size=$($stream.Length) bytes" 'T1564.004'
            }
        }
    } catch {}
}
if ($adsResults.Count -gt 0) { Save-Csv "$triageRoot\Config\ads_scan.csv" $adsResults }
Write-OK "Hosts abnormal=$($hostsAbnormal.Count) | FW inbound=$($fwInbound.Count) | FW outbound block=$($fwOutbound.Count) | ADS=$($adsResults.Count)"

# -------------------------------------------------------
# 13. SHADOW COPIES
# -------------------------------------------------------
Write-Phase 'Shadow Copies (VSS)'

$vss = Get-WmiObject Win32_ShadowCopy -EA SilentlyContinue |
    Select-Object ID, VolumeName, DeviceObject, InstallDate, Accessible
Save-Csv "$triageRoot\Forensics\shadow_copies.csv" $vss
$vssCount = if ($vss) { ($vss | Measure-Object).Count } else { 0 }
if ($vssCount -eq 0) {
    Add-Highlight 'Forensics' 'HIGH' 'No VSS shadow copies found' 'Possible ransomware deleted backups (vssadmin delete shadows)' 'T1490'
    Write-Warn "No shadow copies found - possible T1490"
} else {
    Write-OK "Shadow copies=$vssCount"
}

# -------------------------------------------------------
# 14. BROWSER HISTORY
# -------------------------------------------------------
Write-Phase 'Browser History (All Users / 16 Browsers)'

$systemAccounts = @('Public','Default','Default User','All Users','defaultuser0','desktop.ini')

$userProfiles2 = [System.Collections.Generic.List[PSCustomObject]]::new()
$regPL = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
Get-ChildItem $regPL -EA SilentlyContinue | ForEach-Object {
    $pp = (Get-ItemProperty $_.PSPath -EA SilentlyContinue).ProfileImagePath
    if (-not $pp) { return }
    $un = Split-Path $pp -Leaf
    if ($systemAccounts -contains $un) { return }
    if ($un -match '^(SYSTEM|NETWORK SERVICE|LOCAL SERVICE)$') { return }
    if (Test-Path $pp) {
        $userProfiles2.Add([PSCustomObject]@{
            UserName    = $un
            ProfilePath = $pp
            Local       = "$pp\AppData\Local"
            Roaming     = "$pp\AppData\Roaming"
        })
    }
}
if ($userProfiles2.Count -eq 0) {
    Get-ChildItem 'C:\Users' -Directory -EA SilentlyContinue | ForEach-Object {
        if ($systemAccounts -contains $_.Name) { return }
        $loc = "$($_.FullName)\AppData\Local"
        if (Test-Path $loc) {
            $userProfiles2.Add([PSCustomObject]@{
                UserName    = $_.Name
                ProfilePath = $_.FullName
                Local       = $loc
                Roaming     = "$($_.FullName)\AppData\Roaming"
            })
        }
    }
}

# sqlite3.exe optional - full SQL parse with titles/visit counts/timestamps
$sqlite3Path = $null
$sq3Candidates = @(
    (Join-Path $PSScriptRoot 'sqlite3.exe'),
    (Join-Path $PSScriptRoot 'sqlite3\sqlite3.exe')
)
$sq3FromPath = (Get-Command 'sqlite3.exe' -EA SilentlyContinue).Source
if ($sq3FromPath) { $sq3Candidates += $sq3FromPath }
foreach ($c in $sq3Candidates) {
    if ($c -and (Test-Path $c)) { $sqlite3Path = $c; break }
}
if ($sqlite3Path) {
    Write-OK "sqlite3.exe found: full SQL parse enabled (URL + Title + Visits + Timestamp)"
} else {
    Write-Info "sqlite3.exe not found - regex fallback (URLs only, no titles/counts)"
    Write-Info "Optional: https://sqlite.org/download.html -> sqlite-tools-win-x64-*.zip"
}

function Invoke-Sqlite3 {
    param([string]$DbPath, [string]$Query)
    if (-not $script:sqlite3Path) { return $null }
    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName               = $script:sqlite3Path
        $psi.Arguments              = "`"$DbPath`" `"$Query`""
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError  = $true
        $psi.UseShellExecute        = $false
        $psi.CreateNoWindow         = $true
        $psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
        $proc = [System.Diagnostics.Process]::Start($psi)
        $out  = $proc.StandardOutput.ReadToEnd()
        $proc.WaitForExit()
        return ($out -split "`n" | Where-Object { $_ -ne '' })
    } catch { return $null }
}

function Copy-BrowserDb {
    param([string]$Source)
    if (-not (Test-Path $Source)) { return $null }
    $tmp = [System.IO.Path]::GetTempFileName() + '.db'
    try {
        $s = [System.IO.File]::Open($Source,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::ReadWrite)
        $buf = New-Object byte[] $s.Length
        $null = $s.Read($buf, 0, $buf.Length)
        $s.Close()
        [System.IO.File]::WriteAllBytes($tmp, $buf)
        if ((Get-Item $tmp -EA SilentlyContinue).Length -gt 0) { return $tmp }
    } catch {}
    try {
        $shadows = Get-WmiObject Win32_ShadowCopy -EA Stop | Sort-Object InstallDate -Descending
        foreach ($sh in $shadows) {
            $rel  = $Source -replace '^[A-Za-z]:\\', '\'
            $sp   = "$($sh.DeviceObject)$rel"
            try {
                $sbuf = [System.IO.File]::ReadAllBytes($sp)
                [System.IO.File]::WriteAllBytes($tmp, $sbuf)
                if ((Get-Item $tmp -EA SilentlyContinue).Length -gt 0) { return $tmp }
            } catch {}
        }
    } catch {}
    Remove-Item $tmp -Force -EA SilentlyContinue
    return $null
}

function Get-ChromiumHistory {
    param([string]$ProfilePath, [string]$BrowserName, [string]$UserName, [int]$Limit)
    $tmp = Copy-BrowserDb "$ProfilePath\History"
    if (-not $tmp) { return @() }
    $records = [System.Collections.Generic.List[PSCustomObject]]::new()
    try {
        if ($script:sqlite3Path) {
            $q    = "SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT $Limit;"
            $rows = Invoke-Sqlite3 $tmp $q
            foreach ($row in $rows) {
                if ([string]::IsNullOrWhiteSpace($row)) { continue }
                $p  = $row -split '\|'
                if ($p.Count -lt 2) { continue }
                $ts = if ($p.Count -ge 4 -and $p[3]) { try { [int64]$p[3] } catch { 0 } } else { 0 }
                $dt = if ($ts -gt 0) {
                    try { [datetime]::FromFileTimeUtc(($ts - 11644473600000000) * 10).ToString('yyyy-MM-dd HH:mm:ss') } catch { '' }
                } else { '' }
                $records.Add([PSCustomObject]@{
                    User      = $UserName
                    Browser   = $BrowserName
                    URL       = $p[0]
                    Title     = if ($p.Count -ge 2 -and $p[1]) { $p[1] } else { '' }
                    Visits    = if ($p.Count -ge 3) { try { [int]$p[2] } catch { 1 } } else { 1 }
                    LastVisit = $dt
                    Domain    = try { ([System.Uri]$p[0]).Host } catch { 'unknown' }
                })
            }
        }
        if ($records.Count -eq 0) {
            $dbInfo = Get-Item $tmp -EA SilentlyContinue
            if ($dbInfo -and $dbInfo.Length -gt 100MB) {
                # Skip regex fallback for huge DBs to avoid OOM
                return $records
            }
            $content    = [System.IO.File]::ReadAllText($tmp, [System.Text.Encoding]::Latin1)
            $urlMatches = [regex]::Matches($content, 'https?://[^\x00-\x1F\x7F"<> ]{5,500}')
            $seen = @{}
            foreach ($m in $urlMatches) {
                $url = $m.Value.TrimEnd(([char[]]".,;)" + [char]39 + [char]34 + [char]92))
                if ($seen[$url] -or $records.Count -ge $Limit) { continue }
                $seen[$url] = $true
                $records.Add([PSCustomObject]@{
                    User      = $UserName
                    Browser   = $BrowserName
                    URL       = $url
                    Title     = ''
                    Visits    = 1
                    LastVisit = ''
                    Domain    = try { ([System.Uri]$url).Host } catch { 'unknown' }
                })
            }
        }
    } finally { Remove-Item $tmp -Force -EA SilentlyContinue }
    return $records
}

function Get-FirefoxHistory {
    param([string]$ProfilePath, [string]$BrowserName, [string]$UserName, [int]$Limit)
    $tmp = Copy-BrowserDb "$ProfilePath\places.sqlite"
    if (-not $tmp) { return @() }
    $records = [System.Collections.Generic.List[PSCustomObject]]::new()
    try {
        if ($script:sqlite3Path) {
            $q    = "SELECT p.url, COALESCE(p.title,''), p.visit_count, MAX(h.visit_date) FROM moz_places p LEFT JOIN moz_historyvisits h ON p.id=h.place_id WHERE p.hidden=0 GROUP BY p.id ORDER BY MAX(h.visit_date) DESC LIMIT $Limit;"
            $rows = Invoke-Sqlite3 $tmp $q
            foreach ($row in $rows) {
                if ([string]::IsNullOrWhiteSpace($row)) { continue }
                $p  = $row -split '\|'
                if ($p.Count -lt 1) { continue }
                $ts = if ($p.Count -ge 4 -and $p[3]) { try { [int64]$p[3] } catch { 0 } } else { 0 }
                $dt = if ($ts -gt 0) {
                    try {
                        $epoch = [datetime]::new(1970,1,1,0,0,0,[System.DateTimeKind]::Utc)
                        $epoch.AddTicks($ts * 10).ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss')
                    } catch { '' }
                } else { '' }
                $records.Add([PSCustomObject]@{
                    User      = $UserName
                    Browser   = $BrowserName
                    URL       = $p[0]
                    Title     = if ($p.Count -ge 2) { $p[1] } else { '' }
                    Visits    = if ($p.Count -ge 3) { try { [int]$p[2] } catch { 1 } } else { 1 }
                    LastVisit = $dt
                    Domain    = try { ([System.Uri]$p[0]).Host } catch { 'unknown' }
                })
            }
        }
        if ($records.Count -eq 0) {
            $dbInfo = Get-Item $tmp -EA SilentlyContinue
            if ($dbInfo -and $dbInfo.Length -gt 100MB) {
                return $records
            }
            $content    = [System.IO.File]::ReadAllText($tmp, [System.Text.Encoding]::Latin1)
            $urlMatches = [regex]::Matches($content, 'https?://[^\x00-\x1F\x7F"<> ]{5,500}')
            $seen = @{}
            foreach ($m in $urlMatches) {
                $url = $m.Value.TrimEnd(([char[]]".,;)" + [char]39 + [char]34 + [char]92))
                if ($seen[$url] -or $records.Count -ge $Limit) { continue }
                $seen[$url] = $true
                $records.Add([PSCustomObject]@{
                    User      = $UserName
                    Browser   = $BrowserName
                    URL       = $url
                    Title     = ''
                    Visits    = 1
                    LastVisit = ''
                    Domain    = try { ([System.Uri]$url).Host } catch { 'unknown' }
                })
            }
        }
    } finally { Remove-Item $tmp -Force -EA SilentlyContinue }
    return $records
}

$browserDefs = @(
    @{ Name='Chromium';        Type='Chromium'; Paths=@('{L}\Chromium\User Data\Default','{L}\Chromium\User Data\Profile 1') }
    @{ Name='Google Chrome';   Type='Chromium'; Paths=@('{L}\Google\Chrome\User Data\Default','{L}\Google\Chrome\User Data\Profile 1','{L}\Google\Chrome\User Data\Profile 2') }
    @{ Name='Microsoft Edge';  Type='Chromium'; Paths=@('{L}\Microsoft\Edge\User Data\Default','{L}\Microsoft\Edge\User Data\Profile 1') }
    @{ Name='Brave';           Type='Chromium'; Paths=@('{L}\BraveSoftware\Brave-Browser\User Data\Default') }
    @{ Name='Yandex Browser';  Type='Chromium'; Paths=@('{L}\Yandex\YandexBrowser\User Data\Default') }
    @{ Name='Opera';           Type='Chromium'; Paths=@('{R}\Opera Software\Opera Stable') }
    @{ Name='Opera GX';        Type='Chromium'; Paths=@('{R}\Opera Software\Opera GX Stable') }
    @{ Name='Vivaldi';         Type='Chromium'; Paths=@('{L}\Vivaldi\User Data\Default') }
    @{ Name='Epic Browser';    Type='Chromium'; Paths=@('{L}\Epic Privacy Browser\User Data\Default') }
    @{ Name='Comodo Dragon';   Type='Chromium'; Paths=@('{L}\Comodo\Dragon\User Data\Default') }
    @{ Name='Mozilla Firefox'; Type='Firefox';  Paths=@('{R}\Mozilla\Firefox\Profiles') }
    @{ Name='Thunderbird';     Type='Firefox';  Paths=@('{R}\Thunderbird\Profiles') }
    @{ Name='Tor Browser';     Type='Firefox';  Paths=@('{R}\Tor Browser\Browser\TorBrowser\Data\Browser\profile.default','{H}\Desktop\Tor Browser\Browser\TorBrowser\Data\Browser\profile.default') }
    @{ Name='Waterfox';        Type='Firefox';  Paths=@('{R}\Waterfox\Profiles') }
    @{ Name='LibreWolf';       Type='Firefox';  Paths=@('{R}\LibreWolf\Profiles') }
    @{ Name='Pale Moon';       Type='Firefox';  Paths=@('{R}\Moonchild Productions\Pale Moon\Profiles') }
)

$allBrowserRecords = [System.Collections.Generic.List[PSCustomObject]]::new()
$bHistLimit        = 5000
$rawDbCount        = 0

foreach ($up in $userProfiles2) {
    foreach ($def in $browserDefs) {
        $resolvedPaths = $def.Paths | ForEach-Object {
            $_ -replace '\{L\}', $up.Local `
               -replace '\{R\}', $up.Roaming `
               -replace '\{H\}', $up.ProfilePath
        }
        if ($def.Type -eq 'Firefox') {
            foreach ($basePath in $resolvedPaths) {
                if (-not (Test-Path $basePath)) { continue }
                $profileDirs = if ($basePath -match 'Profiles$') {
                    Get-ChildItem $basePath -Directory -EA SilentlyContinue
                } else {
                    @([System.IO.DirectoryInfo]::new($basePath))
                }
                foreach ($pd in $profileDirs) {
                    $recs = Get-FirefoxHistory $pd.FullName $def.Name $up.UserName $bHistLimit
                    if ($recs.Count -gt 0) {
                        foreach ($r in $recs) { $allBrowserRecords.Add($r) }
                        Write-OK "Browser: $($up.UserName)\$($def.Name)\$($pd.Name) -> $($recs.Count) records"
                    }
                }
            }
        } else {
            foreach ($bp in $resolvedPaths) {
                if (-not (Test-Path $bp)) { continue }
                $recs = Get-ChromiumHistory $bp $def.Name $up.UserName $bHistLimit
                if ($recs.Count -gt 0) {
                    foreach ($r in $recs) { $allBrowserRecords.Add($r) }
                    Write-OK "Browser: $($up.UserName)\$($def.Name) -> $($recs.Count) records"
                }
            }
        }
    }

    # Raw SQLite DB copies disabled - CSV only output
    # To enable raw DB copies, uncomment the block below and set $CopyBrowserRawDB = $true
}

if ($allBrowserRecords.Count -gt 0) {
    Save-Csv "$triageRoot\Forensics\browser_history_all.csv" $allBrowserRecords
    $suspBrowserDomains = @(
        'ngrok','tunnel\.','serveo\.','localhost\.run','playit\.gg','cloudflared',
        'pastebin','paste\.ee','hastebin','dpaste','ghostbin',
        'temp-mail','guerrillamail','mailnull','sharklasers',
        'anonfile','gofile','transfer\.sh','bashupload','wetransfer',
        '\.onion\.'
    )
    # Aggregate matches per (User, Browser, Domain) so we get one alert with a hit count
    # instead of one alert per visit (which spams highlights).
    $suspHits = @{}
    foreach ($rec in $allBrowserRecords) {
        foreach ($sd in $suspBrowserDomains) {
            if ($rec.Domain -match $sd) {
                $key = "$($rec.User)|$($rec.Browser)|$($rec.Domain)"
                if (-not $suspHits.ContainsKey($key)) {
                    $suspHits[$key] = [PSCustomObject]@{
                        User    = $rec.User
                        Browser = $rec.Browser
                        Domain  = $rec.Domain
                        Hits    = 0
                    }
                }
                $suspHits[$key].Hits++
                break
            }
        }
    }
    foreach ($h in $suspHits.Values) {
        Add-Highlight 'Browser' 'MEDIUM' "Suspicious domain in browser history: $($h.Domain)" "User=$($h.User) Browser=$($h.Browser) Hits=$($h.Hits)" 'T1071.001'
    }
    Write-OK "browser_history_all.csv: $($allBrowserRecords.Count) records | suspicious domain hits: $($suspHits.Count)"
}
Write-OK "Browser total: $($allBrowserRecords.Count) records (CSV only)"

# -------------------------------------------------------
# 15. BITS JOBS
# -------------------------------------------------------
Write-Phase 'BITS Transfer Jobs'

try {
    $bitsJobs = Get-BitsTransfer -AllUsers -EA Stop | ForEach-Object {
        $job     = $_
        $fileUrl = ''; $fileDst = ''
        try {
            $files   = Get-BitsTransfer -JobId $job.JobId -EA SilentlyContinue | Select-Object -ExpandProperty FileList
            $fileUrl = if ($files) { ($files | Select-Object -ExpandProperty RemoteName -EA SilentlyContinue) -join '; ' } else { '' }
            $fileDst = if ($files) { ($files | Select-Object -ExpandProperty LocalName  -EA SilentlyContinue) -join '; ' } else { '' }
        } catch {}
        $isSusp = $false
        if ($fileUrl -and $fileUrl -notmatch '(microsoft|windows|update|msftconnecttest)') { $isSusp = $true }
        if ($fileDst -and $fileDst -match '(Temp|AppData|ProgramData|Public)')             { $isSusp = $true }
        if ($isSusp) {
            Add-Highlight 'Forensics' 'HIGH' "Suspicious BITS job: $($job.DisplayName)" "URL=$fileUrl Dst=$fileDst" 'T1197'
        }
        [PSCustomObject]@{
            JobName   = $job.DisplayName
            State     = $job.JobState
            Owner     = $job.OwnerAccount
            Created   = $job.CreationTime
            Modified  = $job.ModificationTime
            SourceURL = $fileUrl
            DestPath  = $fileDst
            Suspicious= $isSusp
        }
    }
    if ($bitsJobs.Count -gt 0) { Save-Csv "$triageRoot\Forensics\bits_jobs.csv" $bitsJobs }
    Write-OK "BITS jobs=$($bitsJobs.Count)"
} catch {
    Write-Info 'BITS: no jobs or service not running'
}

# -------------------------------------------------------
# 16. CLIPBOARD
# -------------------------------------------------------
Write-Phase 'Clipboard'

try {
    Add-Type -AssemblyName System.Windows.Forms
    $clip = [System.Windows.Forms.Clipboard]::GetText()
    if ($clip -and $clip.Length -gt 0) {
        Save-Text "$triageRoot\Forensics\clipboard.txt" $clip
        if ($clip -match '(password|passwd|secret|token|apikey|BEGIN.*PRIVATE|ssh-rsa|AWS|access_key|Authorization)') {
            Add-Highlight 'Forensics' 'HIGH' 'Clipboard: potentially sensitive data' "Length=$($clip.Length) chars - review clipboard.txt" 'T1552'
        }
        Write-OK "Clipboard=$($clip.Length) chars captured"
    } else {
        Write-Info 'Clipboard: empty'
    }
} catch { Write-Warn "Clipboard read error: $_" }

# -------------------------------------------------------
# 17. METADATA, MANIFEST & SUMMARY
# -------------------------------------------------------
Write-Phase 'Metadata & File Manifest'

$duration = ((Get-Date) - $global:StartTime).ToString("m'm 's's'")
$critHL   = ($global:Highlights | Where-Object { $_.Severity -eq 'CRITICAL' }).Count
$highHL   = ($global:Highlights | Where-Object { $_.Severity -eq 'HIGH'     }).Count
$medHL    = ($global:Highlights | Where-Object { $_.Severity -eq 'MEDIUM'   }).Count
$totalHL  = $global:Highlights.Count

$riskLevel = if     ($critHL -gt 0)                   { 'CRITICAL' }
             elseif ($highHL -gt 5)                   { 'HIGH' }
             elseif ($highHL -gt 0 -or $medHL -gt 8)  { 'MEDIUM' }
             else                                     { 'LOW' }

# File manifest with sizes
$manifest = Get-ChildItem -Path $triageRoot -Recurse -File -EA SilentlyContinue |
    Sort-Object FullName | ForEach-Object {
        [PSCustomObject]@{
            Path   = $_.FullName.Replace($triageRoot, '').TrimStart('\/')
            SizeKB = [Math]::Round($_.Length / 1KB, 1)
            SizeMB = [Math]::Round($_.Length / 1MB, 3)
        }
    }
$manifestTotal = if ($manifest) {
    [Math]::Round(($manifest | Measure-Object SizeKB -Sum).Sum / 1024, 2)
} else { 0 }
Save-Csv "$triageRoot\triage_manifest.csv" $manifest

$meta = [ordered]@{
    TriageVersion  = '1.3'
    Tool           = 'ZavetSec Express Triage v1.4'
    Hostname       = $hostname
    CollectionTime = $global:StartTime.ToString('yyyy-MM-dd HH:mm:ss')
    Duration       = $duration
    CollectedBy    = $env:USERNAME
    RunAsAdmin     = $isAdmin
    PSVersion      = $PSVersionTable.PSVersion.ToString()
    OS             = $wmiOS.Caption
    OSBuild        = $wmiOS.BuildNumber
    Mode           = $Mode
    EventLogDays   = $DaysBack
    RiskLevel      = $riskLevel
    Highlights     = [ordered]@{ Critical=$critHL; High=$highHL; Medium=$medHL; Total=$totalHL }
    Files          = [ordered]@{ Count=($manifest | Measure-Object).Count; TotalMB=$manifestTotal }
}
Save-Json "$triageRoot\triage_metadata.json" $meta
Save-Csv  "$triageRoot\Forensics\triage_highlights.csv"  $global:Highlights
Save-Json "$triageRoot\Forensics\triage_highlights.json" $global:Highlights

Write-OK "Files collected: $(($manifest | Measure-Object).Count) | Total: $manifestTotal MB"
Write-OK "Highlights: CRITICAL=$critHL HIGH=$highHL MEDIUM=$medHL Total=$totalHL"

# -------------------------------------------------------
# HASH EXPORT
# -------------------------------------------------------
# Consolidate all SHA256 hashes from processes and services into two files:
#   hashes.txt   - plain list of unique hashes (one per line) for bulk VT / MISP lookup
#   hashes.csv   - SHA256, FileName, FilePath, Source, Suspicious for analyst review

$hashMap = [System.Collections.Generic.Dictionary[string,PSCustomObject]]::new()

# Source 1: running processes
foreach ($p in $procData) {
    if ($p.SHA256 -and $p.SHA256 -ne 'N/A' -and $p.SHA256.Length -eq 64) {
        if (-not $hashMap.ContainsKey($p.SHA256)) {
            $hashMap[$p.SHA256] = [PSCustomObject]@{
                SHA256     = $p.SHA256
                FileName   = $p.Name
                FilePath   = $p.Path
                Source     = 'Process'
                Suspicious = $p.Suspicious
            }
        } elseif ($p.Suspicious -and -not $hashMap[$p.SHA256].Suspicious) {
            # Promote to suspicious if any instance is flagged
            $hashMap[$p.SHA256] = [PSCustomObject]@{
                SHA256     = $p.SHA256
                FileName   = $p.Name
                FilePath   = $p.Path
                Source     = 'Process'
                Suspicious = $true
            }
        }
    }
}

# Source 2: services
foreach ($svc in $services) {
    if ($svc.SHA256 -and $svc.SHA256 -ne 'N/A' -and $svc.SHA256.Length -eq 64) {
        if (-not $hashMap.ContainsKey($svc.SHA256)) {
            $hashMap[$svc.SHA256] = [PSCustomObject]@{
                SHA256     = $svc.SHA256
                FileName   = Split-Path $svc.PathName -Leaf -EA SilentlyContinue
                FilePath   = $svc.PathName
                Source     = 'Service'
                Suspicious = $svc.Suspicious
            }
        }
    }
}

if ($hashMap.Count -gt 0) {
    # Plain list - one hash per line, deduplicated, sorted
    $plainList = ($hashMap.Keys | Sort-Object) -join "`n"
    [System.IO.File]::WriteAllText("$triageRoot\Forensics\hashes.txt", $plainList, [System.Text.Encoding]::ASCII)

    # CSV with context
    $hashMap.Values |
        Sort-Object @{E={switch($_.Suspicious){$true{0}default{1}}}}, SHA256 |
        Export-Csv -Path "$triageRoot\Forensics\hashes.csv" -NoTypeInformation -Encoding ASCII -Force

    $suspHashes = ($hashMap.Values | Where-Object { $_.Suspicious }).Count
    Write-OK "Hash export: $($hashMap.Count) unique hashes | Suspicious=$suspHashes -> Forensics\hashes.txt + hashes.csv"
} else {
    Write-Info "Hash export: no valid SHA256 hashes collected"
}

# -------------------------------------------------------
# HTML REPORT
# -------------------------------------------------------
Write-Phase 'Generating HTML Triage Report'

function ConvertTo-HtmlTable {
    param($Data, [int]$MaxRows = 500)
    if (-not $Data) { return '<p class="empty">No data</p>' }
    $rows = @($Data)
    if ($rows.Count -eq 0) { return '<p class="empty">No data</p>' }
    $totalRows = $rows.Count                       # capture BEFORE capping (was reporting capped count)
    $truncated = $totalRows -gt $MaxRows
    $rows = $rows | Select-Object -First $MaxRows
    $headers = $rows[0].PSObject.Properties.Name
    $sb = [System.Text.StringBuilder]::new()
    $null = $sb.Append('<div class="tbl-wrap"><table>')
    $null = $sb.Append('<thead><tr>')
    foreach ($h in $headers) { $null = $sb.Append("<th>$h</th>") }
    $null = $sb.Append('</tr></thead><tbody>')
    foreach ($row in $rows) {
        $null = $sb.Append('<tr>')
        foreach ($h in $headers) {
            $val  = $row.$h
            $raw  = if ($null -eq $val) { '' } else { $val.ToString() }
            $cell = if ($raw -eq '') { '' } else { [System.Web.HttpUtility]::HtmlEncode($raw) }

            $classes = [System.Collections.Generic.List[string]]::new()
            if ($h -in @('Suspicious','KnownThreat') -and $val -eq $true) { $classes.Add('bad') }
            if ($h -eq 'Severity') {
                switch ($val) { 'CRITICAL'{$classes.Add('crit')} 'HIGH'{$classes.Add('high')} 'MEDIUM'{$classes.Add('med')} }
            }
            if ($h -eq 'Action') {
                switch ($val) { 'Block'{$classes.Add('bad')} 'Allow'{$classes.Add('ok')} }
            }
            if ($h -eq 'IsExternal' -and $val -eq $true) { $classes.Add('warn') }

            # Long cells get the full (HTML-encoded) value in a title attribute so the
            # native tooltip shows complete data on hover, and class 'long' so a single
            # click expands the cell inline (selectable/copyable). HtmlEncode also escapes
            # double-quotes to &quot;, so reusing $cell inside title="..." is safe.
            $titleAttr = ''
            if ($raw.Length -gt 45) {
                $classes.Add('long')
                $titleAttr = " title=`"$cell`""
            }

            $clsAttr = if ($classes.Count -gt 0) { " class=`"$($classes -join ' ')`"" } else { '' }
            $null = $sb.Append("<td$clsAttr$titleAttr>$cell</td>")
        }
        $null = $sb.Append('</tr>')
    }
    $null = $sb.Append('</tbody></table>')
    if ($truncated) { $null = $sb.Append("<p class='trunc'>Showing first $MaxRows of $totalRows records &mdash; full data in the CSV/JSON exports</p>") }
    $null = $sb.Append('</div>')
    return $sb.ToString()
}

Add-Type -AssemblyName System.Web -EA SilentlyContinue

$riskColor = switch ($riskLevel) {
    'CRITICAL' { '#ff2244' }
    'HIGH'     { '#ff6600' }
    'MEDIUM'   { '#ffaa00' }
    default    { '#00ff88' }
}

# Build external connections list for report (single pass, used multiple times)
$extConns = @($netConns | Where-Object { $_.IsExternal -and $_.State -eq 'Established' } |
    Select-Object ProcessName, ProcessPath, LocalAddress, LocalPort, RemoteAddress, RemotePort, RemoteHost, PID)

# Collect system disk info
$diskInfo = Get-WmiObject Win32_LogicalDisk -EA SilentlyContinue |
    Where-Object { $_.DriveType -eq 3 } | ForEach-Object {
        [PSCustomObject]@{
            Drive    = $_.DeviceID
            Label    = $_.VolumeName
            TotalGB  = [Math]::Round($_.Size / 1GB, 1)
            FreeGB   = [Math]::Round($_.FreeSpace / 1GB, 1)
            UsedPct  = if ($_.Size -gt 0) { [Math]::Round(100 - ($_.FreeSpace / $_.Size * 100), 1) } else { 0 }
        }
    }

# Suspicious processes for quick view
$suspProcs = $procData | Where-Object { $_.Suspicious } |
    Select-Object PID, PPID, Name, Path, SuspReason, Mitre, SHA256, Signature

# Top highlights
$topHL = $global:Highlights | Sort-Object @{E={switch($_.Severity){'CRITICAL'{0}'HIGH'{1}'MEDIUM'{2}default{3}}}} |
    Select-Object -First 50

# Network summary stats
$extEstab  = $extConns.Count
$listenCnt = ($netConns | Where-Object { $_.State -eq 'Listen' }).Count
$udpCnt    = if ($udpConns) { @($udpConns).Count } else { 0 }


# MITRE ATT&CK techniques seen
$mitreList = $global:Highlights | Where-Object { $_.Mitre } |
    Group-Object Mitre | Sort-Object Count -Descending | ForEach-Object {
        [PSCustomObject]@{ Technique=$_.Name; Count=$_.Count; Examples=(($_.Group | Select-Object -First 2 | ForEach-Object {$_.Description}) -join ' | ') }
    }

# Build HTML highlight badges
$hlBadges = ($global:Highlights | Group-Object Category | Sort-Object Name | ForEach-Object {
    $cat   = $_.Name
    $cCrit = ($_.Group | Where-Object {$_.Severity -eq 'CRITICAL'}).Count
    $cHigh = ($_.Group | Where-Object {$_.Severity -eq 'HIGH'}).Count
    $cMed  = ($_.Group | Where-Object {$_.Severity -eq 'MEDIUM'}).Count
    "<div class='cat-badge'><span class='cat-name'>$cat</span>" +
    $(if($cCrit -gt 0){"<span class='sev-crit'>CRIT:$cCrit</span>"}else{''}) +
    $(if($cHigh -gt 0){"<span class='sev-high'>HIGH:$cHigh</span>"}else{''}) +
    $(if($cMed  -gt 0){"<span class='sev-med'>MED:$cMed</span>"}else{''}) +
    "</div>"
}) -join "`n"

# Browser history top domains
$topDomains = if ($allBrowserRecords.Count -gt 0) {
    $allBrowserRecords | Where-Object { $_.Domain -and $_.Domain -ne 'unknown' } |
        Group-Object Domain | Sort-Object Count -Descending | Select-Object -First 20 |
        ForEach-Object { [PSCustomObject]@{ Domain=$_.Name; Visits=$_.Count } }
} else { $null }

$htmlCollectionTime = $global:StartTime.ToString('yyyy-MM-dd HH:mm:ss')
$htmlNow            = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')

# Disk bar helper
function Get-DiskBar {
    param([double]$Pct)
    $color = if ($Pct -gt 90) { '#ff2244' } elseif ($Pct -gt 70) { '#ffaa00' } else { '#00c875' }
    "<div class='disk-bar-bg'><div class='disk-bar-fill' style='width:$([Math]::Round($Pct,0))%;background:$color'></div><span class='disk-pct'>$Pct%</span></div>"
}

$diskRows = if ($diskInfo) {
    ($diskInfo | ForEach-Object {
        "<tr><td>$($_.Drive)</td><td>$($_.Label)</td><td>$($_.TotalGB) GB</td><td>$($_.FreeGB) GB</td><td>$(Get-DiskBar $_.UsedPct)</td></tr>"
    }) -join ''
} else { '<tr><td colspan="5" class="empty">No disk info</td></tr>' }

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Triage Report - $hostname</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;700&family=Rajdhani:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
:root {
  --bg:        #0a0d10;
  --bg2:       #0d1117;
  --bg3:       #111820;
  --bg4:       #161d27;
  --border:    #1a2332;
  --border2:   #243040;
  --accent:    #00ff88;
  --accent2:   #00cc6a;
  --accent3:   #00ff8844;
  --red:       #ff3355;
  --orange:    #ff7700;
  --yellow:    #ffc400;
  --purple:    #cc44ff;
  --blue:      #3388ff;
  --text:      #b0bec8;
  --text2:     #6a7f8e;
  --text3:     #3d5060;
  --font:      'JetBrains Mono', 'Consolas', monospace;
  --font-ui:   'Rajdhani', 'Consolas', monospace;
}
@keyframes scanline {
  0%   { transform:translateY(-100%); }
  100% { transform:translateY(100vh); }
}
@keyframes glow-pulse {
  0%,100% { opacity:.5; }
  50%      { opacity:1; }
}
@keyframes dot-blink {
  0%,100% { opacity:1; }
  50%      { opacity:.2; }
}
@keyframes fade-in {
  from { opacity:0; transform:translateY(6px); }
  to   { opacity:1; transform:translateY(0); }
}

* { box-sizing:border-box; margin:0; padding:0; }
html { scroll-behavior:smooth; }
body {
  background:var(--bg);
  color:var(--text);
  font-family:var(--font);
  font-size:13px;
  line-height:1.6;
  min-height:100vh;
  overflow-x:hidden;
}
a { color:var(--accent); text-decoration:none; transition:opacity .15s; }
a:hover { opacity:.75; }

/* ── SCANLINE OVERLAY ─────────────────────────────────── */
body::before {
  content:'';
  position:fixed; top:0; left:0; right:0; bottom:0;
  background:repeating-linear-gradient(
    0deg,
    transparent,
    transparent 3px,
    rgba(0,255,136,.012) 3px,
    rgba(0,255,136,.012) 4px
  );
  pointer-events:none;
  z-index:9999;
}
/* ── RADIAL GLOW ──────────────────────────────────────── */
body::after {
  content:'';
  position:fixed; top:-20%; left:50%; transform:translateX(-50%);
  width:900px; height:500px;
  background:radial-gradient(ellipse at center, rgba(0,255,136,.045) 0%, transparent 70%);
  pointer-events:none;
  z-index:0;
  animation:glow-pulse 4s ease-in-out infinite;
}

/* ── HEADER ───────────────────────────────────────────── */
.header {
  position:relative; overflow:hidden;
  background:linear-gradient(180deg, #0d1520 0%, var(--bg) 100%);
  border-bottom:1px solid var(--border2);
  padding:32px 40px 24px;
  z-index:1;
}
.header-corner-tl, .header-corner-tr, .header-corner-bl, .header-corner-br {
  position:absolute; width:20px; height:20px;
  border-color:var(--accent); border-style:solid; opacity:.4;
}
.header-corner-tl { top:12px; left:12px; border-width:2px 0 0 2px; }
.header-corner-tr { top:12px; right:12px; border-width:2px 2px 0 0; }
.header-corner-bl { bottom:12px; left:12px; border-width:0 0 2px 2px; }
.header-corner-br { bottom:12px; right:12px; border-width:0 2px 2px 0; }

.header-grid { display:flex; justify-content:space-between; align-items:flex-start; flex-wrap:wrap; gap:20px; position:relative; z-index:1; }

.header-brand { display:flex; align-items:center; gap:14px; }
.brand-icon {
  width:44px; height:44px;
  border:1.5px solid var(--accent);
  display:flex; align-items:center; justify-content:center;
  font-size:20px; color:var(--accent);
  box-shadow:0 0 18px var(--accent3), inset 0 0 10px rgba(0,255,136,.08);
  flex-shrink:0;
}
.header-title h1 {
  font-family:var(--font-ui);
  font-size:26px; font-weight:700;
  color:var(--accent);
  letter-spacing:4px;
  text-transform:uppercase;
  text-shadow:0 0 20px rgba(0,255,136,.5);
}
.header-title .sub {
  color:var(--text3);
  font-size:10px;
  letter-spacing:3px;
  margin-top:3px;
  text-transform:uppercase;
}
.header-title .sub .dot {
  display:inline-block;
  width:5px; height:5px;
  background:var(--accent);
  border-radius:50%;
  margin:0 6px;
  vertical-align:middle;
  animation:dot-blink 1.6s ease-in-out infinite;
}

.risk-badge {
  padding:12px 28px;
  border:1.5px solid $riskColor;
  color:$riskColor;
  font-family:var(--font-ui);
  font-size:22px; font-weight:700;
  letter-spacing:5px;
  text-shadow:0 0 16px ${riskColor}99;
  box-shadow:0 0 24px ${riskColor}44, inset 0 0 12px ${riskColor}11;
  text-transform:uppercase;
  position:relative;
}
.risk-badge::before {
  content:'RISK LEVEL';
  position:absolute; top:-8px; left:50%; transform:translateX(-50%);
  font-size:9px; letter-spacing:2px;
  background:var(--bg);
  padding:0 6px;
  color:var(--text3);
}

.header-meta {
  display:flex; gap:0; flex-wrap:wrap;
  margin-top:18px;
  border:1px solid var(--border);
  background:var(--bg2);
  position:relative; z-index:1;
}
.meta-item {
  color:var(--text3);
  font-size:10px;
  letter-spacing:1px;
  text-transform:uppercase;
  padding:7px 18px;
  border-right:1px solid var(--border);
  white-space:nowrap;
}
.meta-item:last-child { border-right:none; }
.meta-item span { color:var(--accent); font-weight:500; }

/* ── SUMMARY CARDS ────────────────────────────────────── */
.summary-strip {
  display:flex; gap:0;
  padding:0 40px;
  background:var(--bg2);
  border-bottom:1px solid var(--border2);
  flex-wrap:wrap;
  position:relative; z-index:1;
}
.scard {
  flex:1; min-width:120px;
  padding:18px 20px 16px;
  border-right:1px solid var(--border);
  border-bottom:none;
  position:relative;
  transition:background .15s;
}
.scard:last-child { border-right:none; }
.scard::after {
  content:'';
  position:absolute; bottom:0; left:0; right:0; height:2px;
  background:transparent;
  transition:background .15s;
}
.scard:hover { background:var(--bg3); }
.scard .sc-val {
  font-family:var(--font-ui);
  font-size:32px; font-weight:700;
  line-height:1;
  letter-spacing:-1px;
}
.scard .sc-lbl {
  color:var(--text3);
  font-size:9px;
  letter-spacing:2px;
  text-transform:uppercase;
  margin-top:5px;
}
.scard.crit::after { background:var(--red); }
.scard.high::after { background:var(--orange); }
.scard.med::after  { background:var(--yellow); }
.scard.info::after { background:var(--accent); }
.scard.crit .sc-val { color:var(--red); text-shadow:0 0 16px #ff335566; }
.scard.high .sc-val { color:var(--orange); text-shadow:0 0 16px #ff770066; }
.scard.med  .sc-val { color:var(--yellow); text-shadow:0 0 16px #ffc40066; }
.scard.info .sc-val { color:var(--accent); text-shadow:0 0 16px rgba(0,255,136,.4); }

/* ── NAV ──────────────────────────────────────────────── */
.nav {
  background:var(--bg);
  border-bottom:1px solid var(--border2);
  padding:0 40px;
  display:flex; gap:0;
  overflow-x:auto;
  position:sticky; top:0;
  z-index:100;
}
.nav::after {
  content:'';
  position:absolute; bottom:0; left:0; right:0; height:1px;
  background:linear-gradient(90deg, transparent, var(--accent2), transparent);
  opacity:.3;
}
.nav a {
  color:var(--text3);
  padding:12px 18px;
  font-size:10px;
  letter-spacing:2px;
  text-transform:uppercase;
  border-bottom:2px solid transparent;
  white-space:nowrap;
  transition:color .15s, border-color .15s;
  font-family:var(--font-ui);
  font-weight:600;
}
.nav a:hover { color:var(--accent); border-color:var(--accent); opacity:1; }

/* ── LAYOUT ───────────────────────────────────────────── */
.main { max-width:1600px; margin:0 auto; padding:32px 40px 64px; position:relative; z-index:1; }
.section { margin-bottom:40px; animation:fade-in .3s ease both; }

.section-hdr {
  display:flex; align-items:center; gap:12px;
  margin-bottom:16px;
  padding-bottom:10px;
  border-bottom:1px solid var(--border);
  position:relative;
}
.section-hdr::after {
  content:'';
  position:absolute; bottom:-1px; left:0; width:60px; height:1px;
  background:var(--accent);
}
.section-num {
  font-family:var(--font-ui);
  font-size:10px; font-weight:700;
  color:var(--accent);
  background:var(--bg3);
  border:1px solid var(--border2);
  padding:2px 7px;
  letter-spacing:1px;
}
.section-hdr h2 {
  font-family:var(--font-ui);
  font-size:14px;
  letter-spacing:3px;
  text-transform:uppercase;
  color:var(--text);
  font-weight:600;
}
.section-hdr .badge {
  background:var(--bg3);
  color:var(--text3);
  font-size:10px;
  padding:2px 8px;
  border:1px solid var(--border2);
  letter-spacing:1px;
  margin-left:auto;
}

/* ── SYSINFO GRID ─────────────────────────────────────── */
.sysinfo-grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(260px,1fr)); gap:8px; }
.si-item {
  background:var(--bg2);
  border:1px solid var(--border);
  border-left:2px solid var(--border2);
  padding:10px 14px;
  transition:border-left-color .15s, background .15s;
}
.si-item:hover { border-left-color:var(--accent); background:var(--bg3); }
.si-key { color:var(--text3); font-size:9px; letter-spacing:2px; text-transform:uppercase; }
.si-val { color:var(--text); margin-top:3px; word-break:break-all; font-size:12px; }

/* ── CATEGORY BADGES ──────────────────────────────────── */
.cat-grid { display:flex; flex-wrap:wrap; gap:6px; margin-bottom:14px; }
.cat-badge {
  background:var(--bg2);
  border:1px solid var(--border2);
  padding:5px 10px;
  display:flex; align-items:center; gap:7px;
  font-size:11px;
  transition:border-color .15s;
}
.cat-badge:hover { border-color:var(--accent); }
.cat-name { color:var(--text2); font-family:var(--font-ui); letter-spacing:.5px; }
.sev-crit { background:#ff335522; color:var(--red);    padding:2px 7px; font-size:9px; font-weight:700; letter-spacing:1px; text-transform:uppercase; border:1px solid #ff335544; }
.sev-high { background:#ff770022; color:var(--orange); padding:2px 7px; font-size:9px; font-weight:700; letter-spacing:1px; text-transform:uppercase; border:1px solid #ff770044; }
.sev-med  { background:#ffc40022; color:var(--yellow); padding:2px 7px; font-size:9px; font-weight:700; letter-spacing:1px; text-transform:uppercase; border:1px solid #ffc40044; }

/* ── TABLES ───────────────────────────────────────────── */
.tbl-wrap { overflow-x:auto; border:1px solid var(--border); }
table { width:100%; border-collapse:collapse; font-size:12px; }
thead tr { background:var(--bg3); }
th {
  padding:8px 12px;
  text-align:left;
  color:var(--accent);
  font-size:9px;
  letter-spacing:2px;
  text-transform:uppercase;
  border-bottom:1px solid var(--border2);
  white-space:nowrap;
  font-family:var(--font-ui);
  font-weight:600;
}
td {
  padding:6px 12px;
  border-bottom:1px solid var(--border);
  color:var(--text);
  max-width:400px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;
}
tbody tr:hover td { background:rgba(0,255,136,.03); }
td.long { cursor:pointer; }
td.long.td-expanded { max-width:none; white-space:normal; word-break:break-all; overflow:visible; background:rgba(0,255,136,.05); }
td.bad  { color:var(--red);    background:rgba(255,51,85,.08);  }
td.crit { color:var(--red);    background:rgba(255,51,85,.08);  font-weight:600; }
td.high { color:var(--orange); background:rgba(255,119,0,.08);  font-weight:600; }
td.med  { color:var(--yellow); background:rgba(255,196,0,.06); }
td.ok   { color:var(--accent); background:rgba(0,255,136,.06); }
td.warn { color:var(--yellow); }
.empty  { color:var(--text3); font-style:italic; padding:10px 12px; display:block; }
.trunc  { color:var(--text3); font-size:10px; padding:6px 12px; display:block; }

/* ── DISK BARS ────────────────────────────────────────── */
.disk-bar-bg {
  background:var(--bg4);
  border:1px solid var(--border);
  height:14px;
  position:relative;
  min-width:120px;
  overflow:hidden;
}
.disk-bar-fill { position:absolute; top:0; left:0; height:100%; transition:width .4s; }
.disk-pct { position:absolute; right:5px; top:0; font-size:9px; line-height:14px; color:#fff; mix-blend-mode:difference; }

/* ── MITRE TAGS ───────────────────────────────────────── */
.mitre-grid { display:flex; flex-wrap:wrap; gap:6px; }
.mitre-tag {
  background:var(--bg3);
  border:1px solid #cc44ff44;
  color:var(--purple);
  padding:5px 12px;
  font-size:11px;
  box-shadow:0 0 8px #cc44ff18;
  transition:border-color .15s, box-shadow .15s;
  font-family:var(--font-ui);
  letter-spacing:.5px;
}
.mitre-tag:hover { border-color:var(--purple); box-shadow:0 0 14px #cc44ff44; }
.mitre-tag .mitre-cnt { color:var(--text3); margin-left:5px; font-size:10px; }

/* ── NEXT STEPS ───────────────────────────────────────── */
.steps { list-style:none; counter-reset:steps; }
.steps li {
  counter-increment:steps;
  padding:10px 0 10px 44px;
  position:relative;
  border-bottom:1px solid var(--border);
  color:var(--text);
  transition:background .1s;
}
.steps li:hover { background:var(--bg2); }
.steps li::before {
  content:counter(steps);
  position:absolute; left:0; top:8px;
  color:var(--accent);
  font-weight:700;
  font-size:10px;
  background:var(--bg3);
  width:26px; height:26px;
  display:flex; align-items:center; justify-content:center;
  border:1px solid var(--accent);
  font-family:var(--font-ui);
  letter-spacing:0;
}
.steps li .cmd {
  display:inline-block;
  background:var(--bg3);
  color:var(--accent);
  border:1px solid var(--border2);
  padding:2px 10px;
  font-size:11px;
  margin-top:3px;
  font-family:var(--font);
}

/* ── TABS ─────────────────────────────────────────────── */
.tabs {
  display:flex; gap:0;
  border-bottom:1px solid var(--border2);
  margin-bottom:0;
  background:var(--bg2);
}
.tab-btn {
  background:transparent;
  border:none;
  color:var(--text3);
  padding:9px 18px;
  cursor:pointer;
  font-family:var(--font-ui);
  font-size:10px;
  letter-spacing:2px;
  text-transform:uppercase;
  border-bottom:2px solid transparent;
  transition:all .15s;
  font-weight:600;
}
.tab-btn.active { color:var(--accent); border-color:var(--accent); background:rgba(0,255,136,.04); }
.tab-btn:hover  { color:var(--text); }
.tab-pane       { display:none; padding-top:12px; }
.tab-pane.active { display:block; }

/* ── ALERT BOX ────────────────────────────────────────── */
.alert-box {
  border-left:3px solid var(--red);
  background:rgba(255,51,85,.06);
  padding:10px 16px;
  margin-bottom:12px;
  font-size:12px;
  color:var(--text2);
}
.alert-box.warn { border-color:var(--yellow); background:rgba(255,196,0,.06); }
.alert-box.info { border-color:var(--accent); background:rgba(0,255,136,.04); }

/* ── FOOTER ───────────────────────────────────────────── */
.footer {
  border-top:1px solid var(--border2);
  padding:16px 40px;
  color:var(--text3);
  font-size:10px;
  display:flex;
  justify-content:space-between;
  align-items:center;
  background:var(--bg2);
  position:relative; z-index:1;
  letter-spacing:1px;
}
.footer-brand { color:var(--accent); font-family:var(--font-ui); font-weight:700; letter-spacing:3px; }
</style>
</head>
<body>

<div class="header">
  <div class="header-corner-tl"></div>
  <div class="header-corner-tr"></div>
  <div class="header-corner-bl"></div>
  <div class="header-corner-br"></div>
  <div class="header-grid">
    <div class="header-brand">
      <div class="brand-icon">&#9670;</div>
      <div class="header-title">
        <h1>Triage Report</h1>
        <div class="sub">ZavetSec Express Triage v1.4 <span class="dot"></span> DFIR <span class="dot"></span> Zero Dependencies</div>
      </div>
    </div>
    <div class="risk-badge">$riskLevel</div>
  </div>
  <div class="header-meta">
    <div class="meta-item">HOST <span>$hostname</span></div>
    <div class="meta-item">OS <span>$($sysInfo.OS)</span></div>
    <div class="meta-item">BUILD <span>$($sysInfo.OSBuild)</span></div>
    <div class="meta-item">DOMAIN <span>$($sysInfo.Domain)</span></div>
    <div class="meta-item">COLLECTED <span>$htmlCollectionTime</span></div>
    <div class="meta-item">DURATION <span>$duration</span></div>
    <div class="meta-item">ADMIN <span>$isAdmin</span></div>
    <div class="meta-item">OPERATOR <span>$($sysInfo.CollectedBy)</span></div>
  </div>
</div>

<div class="summary-strip">
  <div class="scard crit"><div class="sc-val">$critHL</div><div class="sc-lbl">Critical</div></div>
  <div class="scard high"><div class="sc-val">$highHL</div><div class="sc-lbl">High</div></div>
  <div class="scard med"><div class="sc-val">$medHL</div><div class="sc-lbl">Medium</div></div>
  <div class="scard info"><div class="sc-val">$totalHL</div><div class="sc-lbl">Total Findings</div></div>
  <div class="scard info"><div class="sc-val">$($procData.Count)</div><div class="sc-lbl">Processes</div></div>
  <div class="scard info"><div class="sc-val">$extEstab</div><div class="sc-lbl">Ext Conns</div></div>
  <div class="scard info"><div class="sc-val">$(($manifest | Measure-Object).Count)</div><div class="sc-lbl">Artifacts</div></div>
  <div class="scard info"><div class="sc-val">$manifestTotal MB</div><div class="sc-lbl">Total Size</div></div>
</div>

<nav class="nav">
  <a href="#highlights">&#9632; Findings</a>
  <a href="#sysinfo">&#9632; System</a>
  <a href="#processes">&#9632; Processes</a>
  <a href="#network">&#9632; Network</a>
  <a href="#persistence">&#9632; Persistence</a>
  <a href="#mitre">&#9632; MITRE</a>
  <a href="#nextsteps">&#9632; Next Steps</a>
</nav>

<div class="main">

<!-- FINDINGS -->
<div class="section" id="highlights">
  <div class="section-hdr">
    <span class="section-num">01</span>
    <h2>Threat Findings</h2>
    <span class="badge">$totalHL TOTAL</span>
  </div>
  <div class="cat-grid">
$hlBadges
  </div>
  $(ConvertTo-HtmlTable $topHL 50)
</div>

<!-- SYSTEM INFO -->
<div class="section" id="sysinfo">
  <div class="section-hdr">
    <span class="section-num">02</span>
    <h2>System Information</h2>
  </div>
  <div class="sysinfo-grid">
    <div class="si-item"><div class="si-key">Hostname</div><div class="si-val">$hostname</div></div>
    <div class="si-item"><div class="si-key">Operating System</div><div class="si-val">$($sysInfo.OS)</div></div>
    <div class="si-item"><div class="si-key">OS Version / Build</div><div class="si-val">$($sysInfo.OSVersion) / $($sysInfo.OSBuild)</div></div>
    <div class="si-item"><div class="si-key">Architecture</div><div class="si-val">$($sysInfo.Architecture)</div></div>
    <div class="si-item"><div class="si-key">Domain</div><div class="si-val">$($sysInfo.Domain) (joined: $($sysInfo.PartOfDomain))</div></div>
    <div class="si-item"><div class="si-key">Last Boot</div><div class="si-val">$($sysInfo.LastBootTime) ($($sysInfo.UptimeHours)h uptime)</div></div>
    <div class="si-item"><div class="si-key">RAM</div><div class="si-val">$($sysInfo.TotalRAM_GB) GB</div></div>
    <div class="si-item"><div class="si-key">Logical CPUs</div><div class="si-val">$($sysInfo.LogicalCPUs)</div></div>
    <div class="si-item"><div class="si-key">Time Zone</div><div class="si-val">$($sysInfo.TimeZone)</div></div>
    <div class="si-item"><div class="si-key">PowerShell Version</div><div class="si-val">$($sysInfo.PSVersion)</div></div>
    <div class="si-item"><div class="si-key">Run As Admin</div><div class="si-val">$isAdmin</div></div>
    <div class="si-item"><div class="si-key">Collection Time</div><div class="si-val">$htmlCollectionTime</div></div>
  </div>
  <br>
  <table>
    <thead><tr><th>Drive</th><th>Label</th><th>Total</th><th>Free</th><th>Used</th></tr></thead>
    <tbody>$diskRows</tbody>
  </table>
</div>

<!-- PROCESSES -->
<div class="section" id="processes">
  <div class="section-hdr">
    <span class="section-num">03</span>
    <h2>Processes</h2>
    <span class="badge">$($procData.Count) TOTAL / $($suspProcs.Count) SUSPICIOUS</span>
  </div>
  <div class="tabs">
    <button class="tab-btn active" onclick="showTab(this,'susp-procs')">Suspicious</button>
    <button class="tab-btn" onclick="showTab(this,'all-procs')">All Processes</button>
  </div>
  <div id="susp-procs" class="tab-pane active">
    $(if ($suspProcs.Count -gt 0) { ConvertTo-HtmlTable $suspProcs 100 } else { '<p class="empty">No suspicious processes detected</p>' })
  </div>
  <div id="all-procs" class="tab-pane">
    $(ConvertTo-HtmlTable ($procData | Select-Object PID,PPID,Name,Path,Owner,WorkingSetMB,Suspicious,Mitre) 300)
  </div>
</div>

<!-- NETWORK -->
<div class="section" id="network">
  <div class="section-hdr">
    <span class="section-num">04</span>
    <h2>Network</h2>
    <span class="badge">ESTAB: $($established.Count) / LISTEN: $listenCnt / EXT: $extEstab / UDP: $udpCnt</span>
  </div>
  <div class="tabs">
    <button class="tab-btn active" onclick="showTab(this,'net-ext')">External Connections</button>
    <button class="tab-btn" onclick="showTab(this,'net-all')">All TCP</button>
    <button class="tab-btn" onclick="showTab(this,'net-listen')">Listening</button>
    <button class="tab-btn" onclick="showTab(this,'net-pipes')">Named Pipes</button>
  </div>
  <div id="net-ext" class="tab-pane active">
    $(if ($extConns.Count -gt 0) { ConvertTo-HtmlTable $extConns 200 } else { '<p class="empty">No established external connections</p>' })
  </div>
  <div id="net-all" class="tab-pane">
    $(ConvertTo-HtmlTable ($netConns | Select-Object State,LocalAddress,LocalPort,RemoteAddress,RemotePort,RemoteHost,ProcessName,ProcessPath,IsExternal) 300)
  </div>
  <div id="net-listen" class="tab-pane">
    $(ConvertTo-HtmlTable ($listening | Select-Object LocalAddress,LocalPort,ProcessName,ProcessPath,PID) 200)
  </div>
  <div id="net-pipes" class="tab-pane">
    $(ConvertTo-HtmlTable ($namedPipes | Select-Object PipeName,OwnerPID,ProcessName,ProcessPath,Suspicious) 300)
  </div>
</div>

<!-- PERSISTENCE -->
<div class="section" id="persistence">
  <div class="section-hdr">
    <span class="section-num">05</span>
    <h2>Persistence</h2>
    <span class="badge">AUTORUNS: $($persistItems.Count) / TASKS: $($tasks.Count) / SERVICES: $($services.Count)</span>
  </div>
  <div class="tabs">
    <button class="tab-btn active" onclick="showTab(this,'pers-auto')">Autoruns</button>
    <button class="tab-btn" onclick="showTab(this,'pers-tasks')">Scheduled Tasks</button>
    <button class="tab-btn" onclick="showTab(this,'pers-svc')">Services</button>
  </div>
  <div id="pers-auto" class="tab-pane active">
    $(ConvertTo-HtmlTable ($persistItems | Select-Object Source,Location,Name,Value,Suspicious) 200)
  </div>
  <div id="pers-tasks" class="tab-pane">
    $(ConvertTo-HtmlTable ($tasks | Select-Object TaskName,TaskPath,State,Author,Action,Suspicious) 200)
  </div>
  <div id="pers-svc" class="tab-pane">
    $(ConvertTo-HtmlTable ($services | Where-Object {$_.Suspicious -or $_.State -eq 'Running'} | Select-Object Name,DisplayName,State,StartMode,PathName,StartName,Suspicious) 200)
  </div>
</div>


<!-- MITRE ATT&CK -->
<div class="section" id="mitre">
  <div class="section-hdr">
    <span class="section-num">06</span>
    <h2>MITRE ATT&amp;CK</h2>
    <span class="badge">$($mitreList.Count) TECHNIQUES</span>
  </div>
  <div class="mitre-grid">
$(($mitreList | ForEach-Object { "    <div class='mitre-tag'><a href='https://attack.mitre.org/techniques/$($_.Technique -replace '\.','/') ' target='_blank'>$($_.Technique)</a><span class='mitre-cnt'>x$($_.Count)</span></div>" }) -join "`n")
  </div>
  <br>
  $(ConvertTo-HtmlTable $mitreList 50)
</div>


<!-- NEXT STEPS -->
<div class="section" id="nextsteps">
  <div class="section-hdr">
    <span class="section-num">07</span>
    <h2>Recommended Next Steps</h2>
  </div>
  <ol class="steps">
    <li>Review <strong>Forensics\triage_highlights.csv</strong> - sort by Severity column, focus CRITICAL/HIGH first</li>
    <li>Filter suspicious processes: <span class="cmd">Processes\processes.csv</span> - column Suspicious=True</li>
    <li>Examine external connections: <span class="cmd">Network\tcp_connections.csv</span> - column IsExternal=True</li>
    <li>Check browser history for C2/exfil domains: <span class="cmd">Forensics\browser_history_all.csv</span></li>
    <li>Review persistence mechanisms: <span class="cmd">Persistence\autoruns.csv</span> + <span class="cmd">scheduled_tasks.csv</span></li>
    <li>Run Sigma rules against collected EVTX: <span class="cmd">chainsaw hunt Logs\ --sigma rules\ --mapping mapping.yml</span></li>
    <li>Run Hayabusa timeline: <span class="cmd">hayabusa csv-timeline -d Logs\ -o timeline.csv</span></li>
    <li>Check firewall rules for unexpected Allow entries: <span class="cmd">Config\firewall_rules_inbound.csv</span></li>
    <li>Verify no shadow copies were deleted (T1490): <span class="cmd">Forensics\shadow_copies.csv</span></li>
    <li>If Tor Browser or tunneling tools found - isolate host immediately</li>
  </ol>
</div>

</div><!-- /main -->

<div class="footer">
  <span><span class="footer-brand">&#9670; ZAVETSEC</span> &nbsp;&nbsp; Express Triage v1.4 &nbsp;|&nbsp; Host: $hostname &nbsp;|&nbsp; Collected: $htmlCollectionTime</span>
  <span>Generated: $htmlNow &nbsp;|&nbsp; <a href="https://github.com/zavetsec/" target="_blank">github.com/zavetsec</a></span>
</div>

<script>
function showTab(btn, id) {
  var section = btn.closest('.section');
  section.querySelectorAll('.tab-btn').forEach(function(b){ b.classList.remove('active'); });
  section.querySelectorAll('.tab-pane').forEach(function(p){ p.classList.remove('active'); });
  btn.classList.add('active');
  var pane = document.getElementById(id);
  if (pane) pane.classList.add('active');
}

// Click a truncated cell to expand it inline (full value is also in the native
// hover tooltip via the title attribute). Click again to collapse.
document.addEventListener('click', function(e){
  var td = e.target.closest && e.target.closest('td.long');
  if (td) td.classList.toggle('td-expanded');
});
</script>
</body>
</html>
"@

$reportPath = "$triageRoot\triage_report.html"
try {
    [System.IO.File]::WriteAllText($reportPath, $html, [System.Text.Encoding]::UTF8)
    Write-OK "HTML report: triage_report.html"
} catch {
    Write-Warn "HTML report failed: $_"
}

# -------------------------------------------------------
# ZIP PACKAGING
# -------------------------------------------------------
Write-Host ''
Write-Host "  [*] Packaging ZIP" -ForegroundColor Cyan

$zipName = "TRG_${hostname}_${timestamp}.zip"
$zipPath = Join-Path $OutputDir $zipName

try {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::CreateFromDirectory($triageRoot, $zipPath)
    $zipMB = [Math]::Round((Get-Item $zipPath).Length / 1MB, 2)
    Write-OK "ZIP created: $zipName ($zipMB MB)"
} catch {
    Write-Warn "ZIP failed: $_ | Files remain at: $triageRoot"
    $zipMB = 0
}
try { Remove-Item -Path $triageRoot -Recurse -Force -EA SilentlyContinue } catch {}

# -------------------------------------------------------
# FINAL SUMMARY
# -------------------------------------------------------
$rlc      = switch ($riskLevel) { 'CRITICAL'{'Red'}'HIGH'{'Red'}'MEDIUM'{'Yellow'}default{'Yellow'} }
$mitreSet = ($global:Highlights | Where-Object { $_.Mitre } |
    Select-Object -ExpandProperty Mitre -Unique | Sort-Object) -join ', '

Write-Host ''
Write-Host '    +---------------------------------------------------+' -ForegroundColor DarkCyan
Write-Host '    |        C O L L E C T I O N   D O N E            |' -ForegroundColor Cyan
Write-Host '    +---------------------------------------------------+' -ForegroundColor DarkCyan
Write-Host ''
Write-Host "    [>] Host      : $hostname"   -ForegroundColor Green
Write-Host "    [>] Mode      : $Mode"       -ForegroundColor $(if($Mode -eq 'LITE'){'Cyan'}else{'Green'})
Write-Host "    [>] Hashing   : $(if($SkipHashing){'SKIPPED'}else{"ON ($($hashCache.Count) unique binaries)"})" -ForegroundColor $(if($SkipHashing){'Yellow'}else{'Green'})
Write-Host "    [>] Admin     : $isAdmin"    -ForegroundColor $(if($isAdmin){'Green'}else{'Red'})
Write-Host "    [>] Duration  : $duration"   -ForegroundColor Green
Write-Host "    [>] ZIP       : $zipPath"    -ForegroundColor Green
Write-Host "    [>] Size      : $zipMB MB"   -ForegroundColor Green
Write-Host ''
Write-Host "    [!] CRITICAL  : $critHL"     -ForegroundColor $(if($critHL -gt 0){'Red'}else{'Yellow'})
Write-Host "    [!] HIGH      : $highHL"     -ForegroundColor $(if($highHL -gt 0){'Red'}else{'Yellow'})
Write-Host "    [-] MEDIUM    : $medHL"      -ForegroundColor $(if($medHL  -gt 0){'Yellow'}else{'Yellow'})
Write-Host "    [-] Total HL  : $totalHL"    -ForegroundColor White
Write-Host "    [>] Risk      : $riskLevel"  -ForegroundColor $rlc

if ($totalHL -gt 0) {
    Write-Host ''
    Write-Host '    Top findings:' -ForegroundColor DarkGray
    $global:Highlights |
        Sort-Object @{E={switch($_.Severity){'CRITICAL'{0}'HIGH'{1}'MEDIUM'{2}default{3}}}} |
        Select-Object -First 10 | ForEach-Object {
            $hc  = switch ($_.Severity) { 'CRITICAL'{'Red'}'HIGH'{'Red'}default{'Yellow'} }
            $mit = if ($_.Mitre) { " [$($_.Mitre)]" } else { '' }
            $dsc = if ($_.Description -and $_.Description.Length -gt 70) { $_.Description.Substring(0,70) } else { [string]$_.Description }
            Write-Host "      [$($_.Severity)]$mit $dsc" -ForegroundColor $hc
        }
}

if ($mitreSet) {
    Write-Host ''
    Write-Host "    MITRE: $mitreSet" -ForegroundColor DarkMagenta
}
Write-Host ''
Write-Host '    Next steps:' -ForegroundColor DarkGray
Write-Host "      1. Open ZIP and review Forensics\triage_highlights.csv (sort by Severity)" -ForegroundColor DarkGray
Write-Host "      2. Check Processes\processes.csv - filter Suspicious=True" -ForegroundColor DarkGray
Write-Host "      3. Check Network\tcp_connections.csv - filter IsExternal=True" -ForegroundColor DarkGray
Write-Host "      4. Check Forensics\browser_history_all.csv in Excel" -ForegroundColor DarkGray
Write-Host "      5. Run Chainsaw/Hayabusa against Logs\ for Sigma: chainsaw hunt Logs\ --sigma rules\" -ForegroundColor DarkGray
Write-Host ''
