<div align="center">

# Invoke-ZavetSecTriage

**Live Windows forensics. No setup. No install. Just run.**

[![PowerShell 5.1](https://img.shields.io/badge/PowerShell-5.1%2B-blue?logo=powershell&logoColor=white)](https://github.com/PowerShell/PowerShell)
[![Platform](https://img.shields.io/badge/Platform-Windows%208.1%2B-0078d4?logo=windows)](https://microsoft.com/windows)
[![Requires](https://img.shields.io/badge/Requires-Administrator-critical)](.)
[![Dependencies](https://img.shields.io/badge/Dependencies-Zero-brightgreen)](.)
[![License](https://img.shields.io/badge/License-MIT-30d158)](LICENSE)
[![Version](https://img.shields.io/badge/Version-1.1-ff6b00)](CHANGELOG.md)

</div>

---

> **TL;DR** — Drop the script on a Windows host, run as Administrator. **3–5 minutes. ~20 MB ZIP. One HTML report. Fast initial decision.** No setup. No internet. No dependencies. No persistent footprint.
>
> *Designed for the first 5 minutes of an incident — not the full investigation.*

---

## About

Built by a DFIR practitioner with hands-on experience across SOC operations, incident response, and threat hunting. Every design decision in this tool comes from real triage work on real hosts — not from a lab.

The goal was simple: a single script that collects everything an analyst needs in the first five minutes of an incident, with zero preconditions. No agents. No servers. No prior setup. Just PowerShell, which is already on the machine.

Tested across enterprise environments (domain-joined and workgroup), live IR engagements, and EDR-gap scenarios where no pre-deployed tooling was available.

*Built for signal over noise in time-constrained investigations.*

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
# Download first, verify hash, then run — recommended in sensitive environments
iwr https://raw.githubusercontent.com/zavetsec/Invoke-ZavetSecTriage/main/Invoke-ZavetSecTriage.ps1 `
    -OutFile "$env:TEMP\triage.ps1"

# Compare output with the published hash in CHECKSUMS.txt before proceeding
Get-FileHash "$env:TEMP\triage.ps1" -Algorithm SHA256

& "$env:TEMP\triage.ps1"
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

> ⚠️ **Security note:** In regulated or high-sensitivity environments, download the script to an offline staging machine first, verify the SHA256 hash against `CHECKSUMS.txt`, then deploy from an internal share. Do not execute remote scripts directly in environments where living-off-the-land execution is monitored or restricted.

Output: `TRG_<hostname>_<timestamp>.zip` in the specified directory.

<img width="955" height="494" alt="image" src="https://github.com/user-attachments/assets/9768cd2e-62ea-48f3-8f7e-59a3fc7d6302" />

---

## What you get in one run

```
TRG_HOSTNAME_20260319_091103.zip
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

<details>
<summary><strong>Ransomware — patient zero triage</strong></summary>

RDP access, 10 minutes before the cable gets pulled.

```
Forensics\shadow_copies.csv      → empty? vssadmin already ran (T1490)
Forensics\prefetch.csv           → Rclone? Cobalt Strike loader?
Network\tcp_connections.csv      → IsExternal + Established → C2 still active?
Persistence\scheduled_tasks.csv  → dropper persistence before encryption?
Logs\evtx_Security.csv           → EID 4688 process creation timeline
```
</details>

<details>
<summary><strong>Suspicious user / insider threat</strong></summary>

```
Users\kerberos_tickets.txt           → unusual service names, abnormal validity
Users\ps_history_<user>.txt          → net use / copy / xcopy to network paths?
Forensics\lnk_recent.csv             → recently opened files, share paths
Forensics\browser_history_all.csv    → cloud upload, webmail, exfil sites
```
</details>

<details>
<summary><strong>Unknown initial access — alert fired, unclear source</strong></summary>

```
Forensics\triage_highlights.csv  → sort CRITICAL→HIGH, read top 10
Processes\processes.csv          → unsigned binaries in Temp / AppData
Network\named_pipes.csv          → Suspicious = True → C2 framework pipe?
Persistence\autoruns.csv         → entries outside known software vendors
```
</details>

---

## Detection logic

Understanding how findings are generated helps you calibrate what to trust and what to investigate further.

### `Suspicious = True` on processes

A process is flagged when one or more of the following apply:

- Binary path is in a high-risk location: `%TEMP%`, `%APPDATA%`, `%PUBLIC%`, `C:\ProgramData`, `C:\Users\*\Downloads`
- Binary is unsigned or signature validation fails
- Process name matches a known attacker tool list (Mimikatz, Cobalt Strike loader names, common RAT names, recon utilities)
- Parent/child relationship is anomalous (e.g. `Word.exe` → `powershell.exe`, `svchost.exe` spawning from unusual path)

### Severity levels

| Level | Assigned when |
|---|---|
| **CRITICAL** | Known malware name in Prefetch or process list, VSS empty (ransomware indicator), active C2 pipe pattern matched |
| **HIGH** | Unsigned binary in high-risk path, external connection from non-browser process, suspicious scheduled task with encoded command |
| **MEDIUM** | Autorun entry outside known software vendors, unusual named pipe, encoded PowerShell in history |
| **LOW** | Informational findings — non-default firewall rules, ADS present, non-standard service recovery action |

### Named pipe C2 detection

Pipe names are matched against known patterns for Cobalt Strike (`postex_*`, `msagent_*`), Sliver, Havoc, and Brute Ratel. Pattern list is static — custom C2 profiles with renamed pipes will not be detected. See `$suspiciousPipes` in the script to extend.

### False positives

Detection is intentionally broad — the goal is triage signal, not precision. Expect noise from:

- Security software (AV, EDR agents) running from non-standard paths
- Developer tools (unsigned build artifacts, test binaries in `%TEMP%`)
- IT management agents with encoded command-line arguments

Every `Suspicious = True` entry is a lead to investigate, not a confirmed finding. The tool surfaces candidates — the analyst makes the call.

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
[OK] ZIP: TRG_HOST01_20260318_143022.zip (18.4 MB)
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

> 📸 **Screenshot — overview and risk banner:**

<img width="1328" height="906" alt="image" src="https://github.com/user-attachments/assets/e33b54d8-e7b8-4f44-9e3a-366e8f2a03b6" />

---

## How it compares

Velociraptor and KAPE are both solid tools — widely used in professional IR engagements for good reason. Velociraptor has an offline collector mode that runs without a server and collects in a few minutes. KAPE is fast, scriptable, and battle-tested. Neither is a bad choice.

But both come with a hidden cost: **you need to know them before the incident hits.** Velociraptor's offline collector requires building a custom collection binary ahead of time — selecting artifacts, generating a config, compiling the executable via the server GUI or CLI. It's not complicated if you've done it before. If you haven't, you'll spend 30–60 minutes reading docs under pressure. KAPE has its own module and target ecosystem, sync logic, and output processing workflow that takes real time to get comfortable with. Both tools reward preparation. Neither forgives showing up cold.

This script has no learning curve. It's PowerShell — built into every Windows machine since 2009. If you can open an elevated prompt, you can run a triage. There's nothing to pre-build, nothing to configure, no documentation to read mid-incident.

| | Invoke-ZavetSecTriage | KAPE | Velociraptor Offline |
|---|---|---|---|
| **What you need on the target** | PowerShell 5.1 (built-in) | Collector binary + targets | Pre-built offline collector binary |
| **Pre-configuration required** | None | Targets/modules selection | Build collector config on another machine first |
| **Offline operation** | ✅ | ✅ | ✅ |
| **Immediate HTML report** | ✅ | ❌ (post-process in KAPE GUI) | ❌ (process via server or Hunt Manager) |
| **PsExec / SYSTEM-compatible** | ✅ | ⚠️ | ⚠️ |
| **Time to first result** | 3–5 min | 10–25 min | 10–20 min |
| **Cost** | Free | Free | Free / Enterprise paid |

Use Velociraptor when you had time to pre-build a collector before the incident. Use KAPE when your binary kit is staged and you know the module layout by heart.

**Use this when neither is staged, the clock is running, and PowerShell is all you have.**

---

## Remote execution via PsExec

Running via PsExec is supported and tested, but be aware of what it leaves behind:

| Artifact | Detail |
|---|---|
| **Windows Event Log** | EID 7045 (service install) on the target — PsExec registers a temporary service |
| **Registry** | `HKLM\SYSTEM\CurrentControlSet\Services\PSEXESVC` — removed after session, but logged |
| **Network share access** | SMB connection from your IP to `ADMIN$` is logged (EID 5140) |
| **Script output** | Written to `-OutputDir` — ensure share permissions allow SYSTEM write access |

If PsExec artifacts are a concern for your engagement, copy the script to the target manually and execute via WMI or a scheduled task instead.

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

**Example finding from `triage_highlights.csv`:**

```
Severity  : HIGH
Technique : T1053.005
Title     : Suspicious scheduled task — encoded command
Detail    : Task "\Microsoft\Windows\UpdateCheck" runs powershell.exe -EncodedCommand <base64>
            Author: WORKGROUP\SYSTEM | Path outside Windows\System32
Remediation: Decode command, check creation time against breach window, remove if unauthorized
```

---

## When NOT to use this tool

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

## Part of the ZavetSec toolkit

This script is part of a broader open-source SOC and DFIR toolkit built around one philosophy: **zero dependencies, zero setup, immediate output.**

Every tool in the toolkit runs on stock Windows infrastructure — PowerShell 5.1, no agents, no servers, no internet required. Each one produces a self-contained dark-themed HTML report you can open anywhere and hand to anyone. All tools are PS 5.1 compatible, PsExec/SYSTEM-friendly, and designed to work standalone or chain into a pipeline.

The toolkit spans the full incident response and security operations workflow: live host triage and artifact collection, bulk threat intelligence enrichment, infrastructure hardening audits, network reconnaissance and asset discovery, lateral movement detection, and passive OSINT collection. Built for field use — not lab demos, not prepared environments.

**[github.com/zavetsec](https://github.com/zavetsec)**

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
