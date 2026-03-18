#Requires -Version 5.1
<#
.SYNOPSIS
    ZavetSec Express Triage v1.0 - Zero-dependency DFIR for live Windows systems.
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
      [14] Browser history       - 16 browsers, all users, CSV + raw DB copies
      [15] BITS jobs             - stealthy download detection (T1197)
      [16] Clipboard             - text capture, credential pattern detection
      [17] Metadata & summary    - highlights CSV/JSON, file manifest, ZIP

    Output: <OutputDir>\ZavetSec_<hostname>_<timestamp>.zip

    Reading collected files:
      CSV         - Excel or LibreOffice Calc
      JSON        - Notepad / VS Code / browser
      TXT         - Notepad
      EVTX        - double-click in Windows Event Viewer
                    or: Chainsaw / Hayabusa for batch Sigma analysis
      SQLite DB   - DB Browser for SQLite (optional, for RawDB files)
                    https://sqlitebrowser.org

.PARAMETER OutputDir
    Where to save the ZIP. Default = script directory.
.EXAMPLE
    .\Invoke-ZavetSecTriage.ps1
    .\Invoke-ZavetSecTriage.ps1 -OutputDir C:\DFIR
.NOTES
    Version   : 1.0
    Requires  : PowerShell 5.1+, local Administrator rights
    Encoding  : ASCII-safe (PS 5.1 compatible, no non-ASCII chars)
    External  : none required. sqlite3.exe optional for full browser parse.
#>

[CmdletBinding()]
param(
    [string]$OutputDir = $(if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path })
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
$global:Highlights   = [System.Collections.Generic.List[PSCustomObject]]::new()
$global:StartTime    = Get-Date
$global:PhaseCount   = 0
$global:TotalPhases  = 17
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
function Write-OK   { param([string]$M); Write-Host "  [+] $M" -ForegroundColor Yellow }
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
    param([string]$FilePath)
    try { return (Get-FileHash -Path $FilePath -Algorithm SHA256 -EA Stop).Hash }
    catch { return 'N/A' }
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
            $liFlags   = [BitConverter]::ToUInt32($bytes, $offset + 4)
            $localBase = [BitConverter]::ToUInt32($bytes, $offset + 16)
            if ($liFlags -band 0x01) {
                $strStart = $offset + $localBase
                $str = ''
                for ($i = $strStart; $i -lt $bytes.Length -and $bytes[$i] -ne 0; $i++) {
                    $str += [char]$bytes[$i]
                }
                if ($str.Length -gt 2) { return $str }
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
# -------------------------------------------------------
# BANNER
# -------------------------------------------------------
Write-Host ''
Write-Host '     ____                  _    ____            ' -ForegroundColor DarkCyan
Write-Host '    |_  /__ ___ _____ ___ | |_ / __/__ ___     ' -ForegroundColor Cyan
Write-Host '     / // _` \ V / -_)  _||  _\__ \/ -_) _|    ' -ForegroundColor Cyan
Write-Host '    /___\__,_|\_/\___\__| |_| |___/\___\__|    ' -ForegroundColor DarkCyan
Write-Host ''
Write-Host '    +--------------------------------------------+' -ForegroundColor DarkGray
Write-Host '    |  E X P R E S S   T R I A G E   v 1 . 0   |' -ForegroundColor White
Write-Host '    |  DFIR  //  Zero Dependencies  //  PS 5.1  |' -ForegroundColor Gray
Write-Host '    +--------------------------------------------+' -ForegroundColor DarkGray
Write-Host ''
Write-Host "    [>] Target   : $hostname" -ForegroundColor Yellow
Write-Host "    [>] User     : $($env:USERNAME)" -ForegroundColor Yellow
Write-Host "    [>] Output   : $OutputDir" -ForegroundColor Yellow
Write-Host "    [>] Started  : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Yellow
Write-Host ''
Write-Host '    [!] Run as Administrator for full artifact coverage' -ForegroundColor Yellow
Write-Host ''

# Collection parameters
$EventLogCount = 500
$DaysBack      = 7
$CopyRawEvtx   = $true

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

$software = Get-ItemProperty `
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' |
    Where-Object { $_.DisplayName } |
    Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
    Sort-Object DisplayName
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
$procData = foreach ($p in ($wmiProcs | Sort-Object ProcessId)) {
    $path    = $p.ExecutablePath
    $cmdLine = if ($p.CommandLine) { $p.CommandLine } else { '' }
    $hash    = if ($path -and (Test-Path $path -EA SilentlyContinue)) { Get-FileSHA256 $path } else { 'N/A' }
    $sigSt   = if ($path -and (Test-Path $path -EA SilentlyContinue)) { Get-FileSignature $path } else { 'N/A' }

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
    if (-not $isSusp -and $sigSt -notin @('Valid','N/A','') -and $sigSt -ne '') {
        $isSusp     = $true
        $suspReason = "Invalid/unsigned: $sigSt"
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

    $legitPaths = @{
        'svchost.exe'  = 'C:\Windows\System32\'
        'lsass.exe'    = 'C:\Windows\System32\'
        'csrss.exe'    = 'C:\Windows\System32\'
        'services.exe' = 'C:\Windows\System32\'
        'winlogon.exe' = 'C:\Windows\System32\'
        'explorer.exe' = 'C:\Windows\'
        'taskhostw.exe'= 'C:\Windows\System32\'
        'smss.exe'     = 'C:\Windows\System32\'
        'wininit.exe'  = 'C:\Windows\System32\'
        'spoolsv.exe'  = 'C:\Windows\System32\'
    }
    $pnameLower = $p.Name.ToLower()
    if (-not $isSusp -and $path -and $legitPaths.ContainsKey($pnameLower)) {
        if (-not $path.StartsWith($legitPaths[$pnameLower], [System.StringComparison]::OrdinalIgnoreCase)) {
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

$established = $netConns | Where-Object { $_.State -eq 'Established' }
$listening   = $netConns | Where-Object { $_.State -eq 'Listen' }
$external    = $netConns | Where-Object { $_.IsExternal }

Save-Csv "$triageRoot\Network\tcp_connections.csv" $netConns
Save-Csv "$triageRoot\Network\tcp_established.csv" $established
Save-Csv "$triageRoot\Network\tcp_listening.csv"   $listening

$udpConns = Get-NetUDPEndpoint -EA SilentlyContinue |
    Select-Object LocalAddress, LocalPort, OwningProcess
Save-Csv "$triageRoot\Network\udp_endpoints.csv" $udpConns

$suspNetProcs = @('powershell','powershell_ise','cmd','wscript','cscript',
    'mshta','rundll32','regsvr32','certutil','bitsadmin','msiexec',
    'schtasks','wmic','curl','wget','bcedit','regasm','installutil')
foreach ($c in ($external | Where-Object { $_.State -eq 'Established' })) {
    $pn = ($c.ProcessName -replace '\.exe$','').ToLower()
    if ($pn -in $suspNetProcs) {
        Add-Highlight 'Network' 'HIGH' "Suspicious external connection: $($c.ProcessName) -> $($c.RemoteAddress):$($c.RemotePort)" "PID=$($c.PID) Host=$($c.RemoteHost)" 'T1071'
    }
}

$namedPipes = [System.Collections.Generic.List[PSCustomObject]]::new()
try {
    $pipeDir = [System.IO.Directory]::GetFiles('\\.\pipe\')
    foreach ($pipe in $pipeDir) {
        $pipeName = Split-Path $pipe -Leaf
        $isSusp   = $false
        foreach ($pat in $c2PipePatterns) {
            if ($pipeName -match $pat) { $isSusp = $true; break }
        }
        $namedPipes.Add([PSCustomObject]@{ PipeName=$pipeName; FullPath=$pipe; Suspicious=$isSusp })
        if ($isSusp) {
            Add-Highlight 'Network' 'CRITICAL' "Suspicious named pipe (C2 indicator): $pipeName" "Known C2 framework pipe pattern" 'T1071.001'
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
foreach ($base in @('HKCU:\SOFTWARE\Classes\CLSID','HKCU:\SOFTWARE\Classes\Wow6432Node\CLSID')) {
    try {
        Get-ChildItem -Path $base -EA Stop | ForEach-Object {
            $clsid = $_.PSChildName
            $ip    = "$($_.PSPath)\InprocServer32"
            $dll   = try { (Get-ItemProperty -Path $ip -EA Stop).'(default)' } catch { $null }
            if ($dll) {
                $comHijackCount++
                $persistItems.Add([PSCustomObject]@{
                    Source='COM_Hijack'; Location=$ip; Name=$clsid; Value=$dll; Suspicious=$true
                })
                if ($comHijackCount -le 5) {
                    Add-Highlight 'Persistence' 'HIGH' "COM hijack HKCU: $clsid -> $dll" "Path=$ip" 'T1546.015'
                }
            }
        }
    } catch {}
}
if ($comHijackCount -gt 5) {
    Add-Highlight 'Persistence' 'HIGH' "COM hijack entries in HKCU: $comHijackCount total" "Only first 5 logged individually" 'T1546.015'
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

$tasks = Get-ScheduledTask -EA SilentlyContinue | ForEach-Object {
    $t      = $_
    $info   = Get-ScheduledTaskInfo -TaskName $t.TaskName -TaskPath $t.TaskPath -EA SilentlyContinue
    $action = if ($t.Actions) {
        ($t.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' | '
    } else { '' }
    $isSusp  = $false
    $legitTP = @('\Microsoft\','\Google\','\Adobe\','\Mozilla\','\Kaspersky\','\UserGate\','\ESET\','\Windows\','\Intel\','\Zoom\','\Dropbox\')
    $inLegit = $false
    foreach ($lp in $legitTP) { if ($t.TaskPath -like "$lp*") { $inLegit = $true; break } }
    foreach ($pat in $suspCmdPatterns) { if ($action -match $pat) { $isSusp = $true; break } }
    if (-not $inLegit -and $action -match '\\(Temp|Tmp|AppData|ProgramData\\Temp)\\') { $isSusp = $true }
    if ($isSusp) {
        $actShort = if ($action.Length -gt 150) { $action.Substring(0,150) } else { $action }
        Add-Highlight 'Persistence' 'HIGH' "Suspicious scheduled task: $($t.TaskName)" "Path=$($t.TaskPath) Action=$actShort" 'T1053.005'
    }
    [PSCustomObject]@{
        TaskName    = $t.TaskName
        TaskPath    = $t.TaskPath
        State       = $t.State
        Author      = $t.Author
        Action      = if ($action.Length -gt 300) { $action.Substring(0,300) } else { $action }
        LastRunTime = if ($info) { $info.LastRunTime } else { '' }
        NextRunTime = if ($info) { $info.NextRunTime } else { '' }
        Suspicious  = $isSusp
    }
}
Save-Csv "$triageRoot\Persistence\scheduled_tasks.csv" $tasks

$services = Get-WmiObject Win32_Service | ForEach-Object {
    $svc  = $_
    $path = $svc.PathName
    $exe  = if ($path) { ($path -replace '"','') -split ' ' | Select-Object -First 1 } else { '' }
    $hash = if ($exe -and (Test-Path $exe -EA SilentlyContinue)) { Get-FileSHA256 $exe } else { 'N/A' }
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

$wmiFilters   = Get-WmiObject -Namespace 'root\subscription' -Class '__EventFilter'   -EA SilentlyContinue
$wmiConsumers = Get-WmiObject -Namespace 'root\subscription' -Class '__EventConsumer' -EA SilentlyContinue
$wmiBindings  = Get-WmiObject -Namespace 'root\subscription' -Class '__FilterToConsumerBinding' -EA SilentlyContinue
Save-Json "$triageRoot\Persistence\wmi_subscriptions.json" @{
    Filters   = ($wmiFilters   | Select-Object Name, Query, QueryLanguage)
    Consumers = ($wmiConsumers | Select-Object Name, ScriptText, CommandLineTemplate, ExecutablePath)
    Bindings  = ($wmiBindings  | Select-Object Filter, Consumer)
}
$wmiFilterCount = if ($wmiFilters) { ($wmiFilters | Measure-Object).Count } else { 0 }
if ($wmiFilterCount -gt 0) {
    Add-Highlight 'Persistence' 'CRITICAL' "WMI event subscriptions: $wmiFilterCount filters found" "WMI persistence - strong IOC" 'T1546.003'
}

Write-OK "Autoruns=$($persistItems.Count) | Tasks=$($tasks.Count) | Services=$($services.Count) | WMI=$wmiFilterCount | COM=$comHijackCount"

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
                @{N='Message';E={ if ($_.Message.Length -gt 500) { $_.Message.Substring(0,500) } else { $_.Message } }}
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
$ua  = $regForensics | Where-Object { $_.Category -eq 'UserAssist' }
$mui = $regForensics | Where-Object { $_.Category -eq 'MUICache' }
$url = $regForensics | Where-Object { $_.Category -eq 'TypedURL' }
$rd  = $regForensics | Where-Object { $_.Category -like 'RecentDocs*' }
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

$hostsAbnormal = $hostsContent | Where-Object {
    $_ -notmatch '^\s*#' -and $_ -match '\S' -and
    $_ -notmatch '(127\.0\.0\.1\s+localhost|::1\s+localhost|0\.0\.0\.0\s+0\.0\.0\.0)'
}
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

$fwInbound = Get-NetFirewallRule -EA SilentlyContinue |
    Where-Object { $_.Enabled -eq $true -and $_.Direction -eq 'Inbound' -and $_.Action -eq 'Allow' } |
    Select-Object -First 200 | ForEach-Object {
        $r = $_
        $portFilter = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $r -EA SilentlyContinue
        [PSCustomObject]@{
            Name      = $r.DisplayName
            Profile   = $r.Profile
            Protocol  = if ($portFilter) { $portFilter.Protocol } else { '' }
            LocalPort = if ($portFilter) { $portFilter.LocalPort } else { '' }
            Program   = (Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $r -EA SilentlyContinue).Program
        }
    }
Save-Csv "$triageRoot\Config\firewall_rules_inbound.csv" $fwInbound

$fwOutbound = Get-NetFirewallRule -EA SilentlyContinue |
    Where-Object { $_.Enabled -eq $true -and $_.Direction -eq 'Outbound' -and $_.Action -eq 'Block' } |
    Select-Object -First 200 | ForEach-Object {
        $r = $_
        $portFilter = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $r -EA SilentlyContinue
        [PSCustomObject]@{
            Name       = $r.DisplayName
            Profile    = $r.Profile
            Protocol   = if ($portFilter) { $portFilter.Protocol } else { '' }
            RemotePort = if ($portFilter) { $portFilter.RemotePort } else { '' }
            Program    = (Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $r -EA SilentlyContinue).Program
        }
    }
Save-Csv "$triageRoot\Config\firewall_rules_outbound.csv" $fwOutbound

$adsScanDirs = @("$env:TEMP", 'C:\Users\Public', "$env:APPDATA")
$adsResults  = [System.Collections.Generic.List[PSCustomObject]]::new()
foreach ($scanDir in $adsScanDirs) {
    if (-not (Test-Path $scanDir)) { continue }
    try {
        Get-ChildItem -Path $scanDir -Recurse -EA SilentlyContinue |
            Where-Object { -not $_.PSIsContainer } | Select-Object -First 500 | ForEach-Object {
                $streams = Get-Item -Path $_.FullName -Stream * -EA SilentlyContinue |
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

    # Raw SQLite DB copies
    $rawDir = "$triageRoot\Forensics\Browser_$($up.UserName -replace '[^\w\-]','_')\RawDB"
    $chromiumRawDefs = @(
        @{ N='Chrome';  P="$($up.Local)\Google\Chrome\User Data\Default" }
        @{ N='Edge';    P="$($up.Local)\Microsoft\Edge\User Data\Default" }
        @{ N='Brave';   P="$($up.Local)\BraveSoftware\Brave-Browser\User Data\Default" }
        @{ N='Yandex';  P="$($up.Local)\Yandex\YandexBrowser\User Data\Default" }
        @{ N='Vivaldi'; P="$($up.Local)\Vivaldi\User Data\Default" }
        @{ N='Opera';   P="$($up.Roaming)\Opera Software\Opera Stable" }
    )
    foreach ($cb in $chromiumRawDefs) {
        if (-not (Test-Path $cb.P)) { continue }
        foreach ($dbf in @('History','Cookies','Login Data','Web Data')) {
            $src = "$($cb.P)\$dbf"
            if (-not (Test-Path $src)) { continue }
            $null = New-Item -ItemType Directory -Path $rawDir -Force
            $dst  = "$rawDir\$($cb.N)_$($dbf -replace ' ','_')"
            if (Copy-LockedFile $src $dst) { $rawDbCount++ }
        }
    }
    $ffBase = "$($up.Roaming)\Mozilla\Firefox\Profiles"
    if (Test-Path $ffBase) {
        Get-ChildItem $ffBase -Directory -EA SilentlyContinue | Select-Object -First 3 | ForEach-Object {
            $ffRawDir = "$rawDir\FF_$($_.Name)"
            foreach ($dbf in @('places.sqlite','cookies.sqlite','logins.json')) {
                $src = "$($_.FullName)\$dbf"
                if (-not (Test-Path $src)) { continue }
                $null = New-Item -ItemType Directory -Path $ffRawDir -Force
                if (Copy-LockedFile $src "$ffRawDir\$dbf") { $rawDbCount++ }
            }
        }
    }
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
    foreach ($rec in $allBrowserRecords) {
        foreach ($sd in $suspBrowserDomains) {
            if ($rec.Domain -match $sd) {
                Add-Highlight 'Browser' 'MEDIUM' "Suspicious domain in browser history: $($rec.Domain)" "User=$($rec.User) Browser=$($rec.Browser)" 'T1071.001'
                break
            }
        }
    }
    Write-OK "browser_history_all.csv: $($allBrowserRecords.Count) records"
}
Write-OK "Browser total: $($allBrowserRecords.Count) records | Raw DB files: $rawDbCount"

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
    TriageVersion  = '1.0'
    Tool           = 'ZavetSec Express Triage'
    Hostname       = $hostname
    CollectionTime = $global:StartTime.ToString('yyyy-MM-dd HH:mm:ss')
    Duration       = $duration
    CollectedBy    = $env:USERNAME
    RunAsAdmin     = $isAdmin
    PSVersion      = $PSVersionTable.PSVersion.ToString()
    OS             = $wmiOS.Caption
    OSBuild        = $wmiOS.BuildNumber
    Mode           = 'FULL'
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
# ZIP PACKAGING
# -------------------------------------------------------
Write-Phase 'Packaging ZIP'
$global:PhaseCount-- # packaging is not a real phase in the 17-count

$zipName = "ZavetSec_${hostname}_${timestamp}.zip"
$zipPath = Join-Path $OutputDir $zipName

try {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::CreateFromDirectory($triageRoot, $zipPath)
    $zipMB = [Math]::Round((Get-Item $zipPath).Length / 1MB, 2)
    Write-OK "ZIP created: $zipName ($zipMB MB)"
} catch {
    Write-Warn "ZIP failed: $_ | Files remain at: $triageRoot"
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
Write-Host "    [>] Host      : $hostname"   -ForegroundColor Gray
Write-Host "    [>] Mode      : $Mode"       -ForegroundColor $(if($Mode -eq 'LITE'){'Cyan'}else{'Yellow'})
Write-Host "    [>] Admin     : $isAdmin"    -ForegroundColor $(if($isAdmin){'Yellow'}else{'Red'})
Write-Host "    [>] Duration  : $duration"   -ForegroundColor Gray
Write-Host "    [>] ZIP       : $zipPath"    -ForegroundColor Cyan
Write-Host "    [>] Size      : $zipMB MB"   -ForegroundColor DarkGray
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
            $dsc = if ($_.Description.Length -gt 70) { $_.Description.Substring(0,70) } else { $_.Description }
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
