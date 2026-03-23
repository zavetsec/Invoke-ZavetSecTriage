<div align="center">

```
     ____                  _    ____
    |_  /__ ___ _____ ___ | |_ / __/__ ___
     / // _` \ V / -_)  _||  _\__ \/ -_) _|
    /___\__,_|\_/\___\__| |_| |___/\___\__|

    EXPRESS TRIAGE v1.1  //  DFIR  //  PowerShell 5.1
```

**Live Windows forensics. Drop, run, ZIP. No setup. No install. No excuses.**

[![PowerShell 5.1](https://img.shields.io/badge/PowerShell-5.1%2B-blue?logo=powershell&logoColor=white)](https://github.com/PowerShell/PowerShell)
[![Platform](https://img.shields.io/badge/Platform-Windows%208.1%2B-0078d4?logo=windows)](https://microsoft.com/windows)
[![Requires](https://img.shields.io/badge/Requires-Administrator-critical)](.)
[![Dependencies](https://img.shields.io/badge/Dependencies-Zero-brightgreen)](.)
[![License](https://img.shields.io/badge/License-MIT-30d158)](LICENSE)
[![Version](https://img.shields.io/badge/Version-1.1-ff6b00)](CHANGELOG.md)
[![Stars](https://img.shields.io/github/stars/zavetsec/Invoke-ZavetSecTriage?style=flat-square)](https://github.com/zavetsec/Invoke-ZavetSecTriage/stargazers)

</div>

---

> **TL;DR** — Drop the script on a Windows host, run as Administrator. **3–5 minutes. ~20 MB ZIP. One HTML report. One decision.** No setup. No internet. No dependencies. No persistent footprint.

---

## The situation

It's 2 AM. You get the call — host is acting weird, possible compromise. You need to know what's running, what's persisting, what's phoning home. **Right now.**

You don't have time to install agents. You can't push an EDR. The SIEM doesn't cover this box.

Drop `Invoke-ZavetSecTriage.ps1`. Run as Admin. Walk away for 3 minutes. Come back to a ZIP with everything you need — running processes with hashes, network connections, autoruns, scheduled tasks, event logs, PowerShell history, browser history, loaded drivers, named pipes. Flagged by severity. Mapped to MITRE ATT&CK.

That's what this tool is for.

**Design priorities:** speed over completeness, breadth over depth, zero friction over configurability. The goal is signal in under 5 minutes on an unknown host — not a replacement for full forensic acquisition.

---

## Who this is for

- **Incident responders** working live compromised hosts with no pre-deployed tooling
- **Consultants** doing rapid onsite triage with no access to client infrastructure
- **Blue teams** with EDR gaps — specific hosts not covered, agent not deployed, legacy systems
- **SOC analysts** who need a shareable evidence package fast — one ZIP, one HTML, done

---

## Quick start

```powershell
# One-liner — download and run directly (run as Administrator)
powershell -ep bypass -c "iwr https://raw.githubusercontent.com/zavetsec/Invoke-ZavetSecTriage/main/Invoke-ZavetSecTriage.ps1 -OutFile $env:TEMP\triage.ps1; & $env:TEMP\triage.ps1"
```

```powershell
# Run as Administrator — local collection
.\Invoke-ZavetSecTriage.ps1

# Specify output directory
.\Invoke-ZavetSecTriage.ps1 -OutputDir C:\DFIR

# Remote via PsExec — runs as SYSTEM, no interaction required
psexec \\TARGET -s -d powershell.exe -NonInteractive -WindowStyle Hidden `
    -ExecutionPolicy Bypass -File "\\share\Invoke-ZavetSecTriage.ps1" `
    -OutputDir "\\share\output"
```

Output: `<hostname>_<timestamp>.zip` in the specified directory.

---

## What you get in one run

```
HOSTNAME_20260319_091103.zip
├── triage_report.html              ← open this first
├── triage_metadata.json            ← collection summary, risk level
├── Processes\
│   └── processes.csv               ← SHA256, signature, Suspicious column
├── Network\
│   ├── tcp_connections.csv         ← IsExternal flag, ProcessPath
│   ├── named_pipes.csv             ← OwnerPID + C2 pattern matches
│   └── dns_cache.csv
├── Persistence\
│   ├── autoruns.csv                ← Run keys, Winlogon, IFEO, COM…
│   ├── scheduled_tasks.csv
│   └── services.csv
├── Users\
│   ├── kerberos_tickets.txt
│   └── ps_history_<user>.txt
├── Logs\
│   ├── evtx_Security.csv
│   └── *.evtx                      ← raw copies for Chainsaw / Hayabusa
├── Forensics\
│   ├── triage_highlights.csv       ← CRITICAL/HIGH/MEDIUM findings, MITRE-tagged
│   ├── hashes.txt                  ← SHA256 list → pipe to Invoke-MBHashCheck
│   ├── browser_history_all.csv
│   ├── shadow_copies.csv
│   └── prefetch.csv                ← attacker tool names flagged
└── Config\
    ├── firewall_rules_inbound.csv
    └── ads_scan.csv
```

**18 collection modules. One pass. One ZIP.**

---

## Triage workflow — where to start

```
1. triage_report.html                  → open in browser, check risk banner
2. Forensics\triage_highlights.csv     → sort Severity DESC — start at CRITICAL
3. Processes\processes.csv             → filter Suspicious = True, check SHA256
4. Forensics\hashes.txt                → bulk lookup: Invoke-MBHashCheck / VT / MISP
5. Network\tcp_connections.csv         → filter IsExternal = True + State = Established
6. Persistence\autoruns.csv            → unknown entries in Temp / AppData
7. Persistence\scheduled_tasks.csv     → non-Microsoft task paths and authors
8. Logs\ (Chainsaw or Hayabusa)        → Sigma rules against raw EVTX
9. Forensics\shadow_copies.csv         → empty = ransomware VSS wipe (T1490)
10. Forensics\prefetch.csv             → filter KnownThreat = True
```

---

## Real IR scenarios

### Ransomware — patient zero triage
RDP access, 10 minutes before the cable gets pulled.

```
Forensics\shadow_copies.csv      → empty? vssadmin already ran (T1490)
Forensics\prefetch.csv           → Rclone? Cobalt Strike loader?
Network\tcp_connections.csv      → IsExternal + Established → C2 still active?
Persistence\scheduled_tasks.csv  → dropper persistence before encryption?
Logs\evtx_Security.csv           → EID 4688 process creation timeline
```

### Suspicious user / insider threat

```
Users\kerberos_tickets.txt           → unusual service names, abnormal validity
Users\ps_history_<user>.txt          → net use / copy / xcopy to network paths?
Forensics\lnk_recent.csv             → recently opened files, share paths
Forensics\browser_history_all.csv    → cloud upload, webmail, exfil sites
```

### Unknown initial access — alert fired, unclear source

```
Forensics\triage_highlights.csv  → sort CRITICAL→HIGH, read top 10
Processes\processes.csv          → unsigned binaries in Temp / AppData
Network\named_pipes.csv          → Suspicious = True → C2 framework pipe?
Persistence\autoruns.csv         → entries outside known software vendors
```

---

## Console output

```
[+] Phase 1/17: Running Processes
    [OK] 142 processes collected | Suspicious=3
[+] Phase 2/17: Network Connections
    [OK] TCP: 47 connections | External=12 | Suspicious=1
[+] Phase 3/17: Named Pipes
    [WARN] Suspicious pipe: \\.\pipe\mojo.5688.8052.183894939787788877
...
[+] Phase 17/17: Metadata & File Manifest
    [OK] Files collected: 84 | Total: 18.4 MB
    [OK] Highlights: CRITICAL=0 HIGH=2 MEDIUM=5 Total=7
[OK] ZIP: HOST01_20260318_143022.zip (18.4 MB)
[OK] HTML report: triage_report.html
```

`[OK]` green · `[WARN]` yellow · `[-]` gray.

---

## HTML triage report

Self-contained `.html` — opens in any browser, no internet required.

- **Risk banner** — CRITICAL / HIGH / MEDIUM / LOW based on finding count
- **Findings table** — severity, MITRE technique ID, description, remediation hint
- **Tabbed sections** per collection module — raw data on demand
- **Recommended next steps** — investigation workflow built-in
- **Timestamps, hostname, collector** — chain of custody basics in the footer

Hand it to a customer. Drop it in a ticket. Open it on an airgapped analyst machine.

> 📸 **Screenshot:**

<img width="1893" height="905" alt="image" src="https://github.com/user-attachments/assets/85ae3568-aac1-4c11-aa3d-2349b0d36f5c" />


---

## ⚡ When Velociraptor is too heavy

| | Invoke-ZavetSecTriage | KAPE | Velociraptor | CyberTriage |
|---|---|---|---|---|
| **External dependencies** | **None** | Collectors + targets | Agent + server | Agent + license |
| **Offline operation** | ✅ | ✅ | ❌ | ❌ |
| **Single-file deployment** | ✅ | ❌ | ❌ | ❌ |
| **Live HTML report** | ✅ | ❌ | ✅ | ✅ |
| **PsExec / SYSTEM-compatible** | ✅ | ⚠️ | ❌ | ❌ |
| **Setup time** | **0 min** | 30+ min | Hours | Hours |
| **Cost** | **Free** | Free | Free / Paid | Paid |

Those tools are excellent — for prepared environments. This is what you run when neither is available.

---

## DFIR pipeline — triage → hash check → verdict

```powershell
# Step 1 — collect
.\Invoke-ZavetSecTriage.ps1 -OutputDir "C:\IR\HOST01"

# Step 2 — bulk hash check against MalwareBazaar + ThreatFox
.\Invoke-MBHashCheck.ps1 `
    -ApiKey "YOUR_KEY" `
    -HashFile "C:\IR\HOST01\Forensics\hashes.txt" `
    -Quiet -OutputDir "C:\IR\HOST01"

# Step 3 — instant verdict
$hits = .\Invoke-MBHashCheck.ps1 -ApiKey $key -HashFile "$out\Forensics\hashes.txt" -PassThru |
    Where-Object Status -eq "MALICIOUS"

if ($hits) {
    Write-Host "COMPROMISE CONFIRMED: $($hits.Count) malicious process(es)" -ForegroundColor Red
    $hits | Select-Object Hash, Signature, Tags, TFIOCs | Format-Table
}
```

"Unknown host" → "confirmed malware family + C2 IPs" in ~8 minutes.

> `Invoke-ZavetSecTriage` + `Invoke-MBHashCheck` = the **ZavetSec DFIR pipeline**. Both PS 5.1, zero-dep, dark HTML reports, PsExec-compatible. Built to work together.

---

## MITRE ATT&CK coverage

Findings are automatically tagged and surfaced in `triage_highlights.csv` and the HTML report.

| Tactic | Techniques |
|---|---|
| Persistence | T1053.005, T1547.001, T1547.004, T1547.005, T1546.003, T1546.010, T1546.012, T1546.015 |
| Credential Access | T1003.001, T1552, T1558.001 |
| Defense Evasion | T1036.001, T1036.005, T1197, T1490, T1562.001, T1562.004, T1564.004 |
| Execution | T1059, T1059.001 |
| C2 / Exfiltration | T1071, T1071.001 |
| Remote Access | T1219 |

---

## When NOT to use this tool

Being explicit about limitations is more useful than overpromising:

- **Stealth assessments** — WMI queries + named pipe enumeration triggers behavioral EDR alerts. Not a covert tool.
- **Full forensic preservation** — no memory images, no disk images. Use WinPmem / FTK Imager for that.
- **Memory-resident threats** — reflective DLLs and process hollowing without on-disk artifacts are not directly detected.
- **Fleet-scale triage** — one host at a time. For 100+ hosts simultaneously, use Velociraptor.
- **Legal chain of custody** — first-pass triage, not forensically sound acquisition.

---

## Performance & footprint

| Metric | Typical value |
|---|---|
| Runtime | 3–5 minutes on a modern workstation |
| Peak RAM | < 150 MB |
| Archive size | 15–40 MB (no raw EVTX copy: 3–8 MB) |
| Disk writes | One temp folder in `%TEMP%`, removed on completion |
| System calls | Read-only — no registry writes, no service install, no process injection |

---

## Requirements

| | |
|---|---|
| PowerShell | 5.1+ (built into Windows 8.1 / Server 2012 R2+) |
| Privileges | Local Administrator |
| Internet | Not required |
| Install | None |
| Optional | `sqlite3.exe` alongside script — enables full browser history with titles + timestamps |

---

## Tested environments

| OS | Domain-joined | Workgroup |
|---|---|---|
| Windows 11 Pro 23H2 | ✅ | ✅ |
| Windows 11 Pro 21H2 | ✅ | ✅ |
| Windows 10 Pro 22H2 | ✅ | ✅ |
| Windows 10 LTSC 2019 | ✅ | ✅ |
| Windows Server 2022 (Core + Desktop) | ✅ | ✅ |
| Windows Server 2019 | ✅ | ✅ |
| Windows Server 2016 | ✅ | ✅ |

Modules that depend on features absent on older builds degrade silently — collection continues.

---

## Part of the ZavetSec DFIR toolkit

Designed to work together during live IR engagements. Each tool is independent — use any one standalone, or chain them as a pipeline.

| Tool | What it does |
|---|---|
| **Invoke-ZavetSecTriage** | Live artifact collection — 18 modules, MITRE-tagged findings, HTML report |
| **[Invoke-MBHashCheck](https://github.com/zavetsec/Invoke-MBHashCheck)** | Bulk hash triage — MalwareBazaar + ThreatFox C2 enrichment + GeoIP |
| **[ZavetSecHardeningBaseline](https://github.com/zavetsec/ZavetSecHardeningBaseline)** | 60+ hardening checks — CIS/STIG aligned, JSON rollback, compliance report |

All three: PS 5.1, zero dependencies, self-contained HTML reports, PsExec-compatible.

---

## Changelog

### v1.1
- Interactive HTML triage report — dark theme, tabbed views, MITRE links
- Named pipe C2 pattern detection (Cobalt Strike, Sliver, Havoc, Brute Ratel)
- `hashes.txt` / `hashes.csv` export for direct pipeline to `Invoke-MBHashCheck`
- Firewall collection: `Action` column (Allow/Block), all enabled rules in both directions
- UDP endpoints: `ProcessName` and `ProcessPath` columns added
- Console output: `[OK]` green · `[WARN]` yellow · `[-]` gray
- MITRE technique IDs on all highlight findings

### v1.0
- Initial release — 17 collection modules

---

## Roadmap

- [ ] `LITE` mode — skip raw EVTX for faster, smaller output
- [ ] Amcache / ShimCache module — additional execution evidence
- [ ] MFT timeline sampling — recent file creations in high-risk directories
- [ ] Expandable IOC lists — external config file for pipe patterns, attacker tools, domains
- [ ] JSON-only output mode — for SIEM ingestion pipelines

---

## Contributing

Most useful contributions:
- **New attacker tool names** for Prefetch flagging (`$knownAttackerTools`)
- **New C2 named pipe patterns** — Sliver, Havoc, Brute Ratel signatures
- **Bug reports** on specific Windows versions or domain configurations
- **False positives** — legitimate software triggering `Suspicious = True`

Keep changes PS 5.1 compatible and zero-dependency. Open an issue or PR.

---

## License

MIT — free to use, modify, distribute.

---

<div align="center">

**[ZavetSec](https://github.com/zavetsec)** — built for field DFIR, not demos

*⭐ Star the repo to help other responders find it.*

</div>
