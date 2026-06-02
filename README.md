<div align="center">

```
 ______               _    _____           
|___  /              | |  / ____|          
   / / __ ___   _____| |_| (___   ___  ___ 
  / / / _` \ \ / / _ \ __|\___ \ / _ \/ __|
 / /_| (_| |\ V /  __/ |_ ____) |  __/ (__ 
/_____\__,_| \_/ \___|\__|_____/ \___|\___|
```

**Bulk hash triage — MalwareBazaar + ThreatFox + GeoIP**  
*Dozens of hashes. Minutes. One HTML report. No SIEM. No install.*

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue?logo=powershell&logoColor=white)](https://github.com/PowerShell/PowerShell)
[![Platform](https://img.shields.io/badge/Platform-Windows-0078d4?logo=windows)](https://microsoft.com/windows)
[![License](https://img.shields.io/badge/License-MIT-brightgreen)](LICENSE)
[![MalwareBazaar](https://img.shields.io/badge/API-MalwareBazaar-orange)](https://bazaar.abuse.ch)
[![ThreatFox](https://img.shields.io/badge/API-ThreatFox-red)](https://threatfox.abuse.ch)
<!-- Uncomment after publishing the first GitHub Release:
[![GitHub release](https://img.shields.io/github/v/release/zavetsec/Invoke-MBHashCheck)](https://github.com/zavetsec/Invoke-MBHashCheck/releases)
-->

</div>

# Invoke-MBHashCheck

**Bulk malware hash triage for incident responders.** PowerShell tool to bulk-check MD5, SHA1 and SHA256 hashes against MalwareBazaar, enrich confirmed hits with ThreatFox IOC intelligence and GeoIP, and generate self-contained HTML reports.

---

> **TL;DR** — Give it a list of hashes. It checks MalwareBazaar, enriches confirmed hits with ThreatFox C2 intel + GeoIP, and outputs a filterable, self-contained HTML report. Free API. No install. Runs on built-in PowerShell.
>
> ```powershell
> .\Invoke-MBHashCheck.ps1 -ApiKey "YOUR_KEY" -HashFile "hashes.txt"
> ```

---

## Contents

- [Features](#features)
- [Quick start](#quick-start)
- [The problem](#the-problem)
- [What it does](#what-it-does)
- [Console output](#console-output)
- [HTML report](#html-report)
- [Why not just VirusTotal?](#why-not-just-virustotal)
- [Usage](#usage)
- [Parameters](#parameters)
- [Hash file format](#hash-file-format)
- [Understanding results](#understanding-results)
- [Antivirus false positives](#antivirus-false-positives)
- [Requirements](#requirements)
- [ZavetSec DFIR toolkit](#part-of-the-zavetsec-dfir-toolkit)
- [Roadmap](#roadmap)
- [Changelog](#changelog)

---

## Features

- Bulk MD5 / SHA1 / SHA256 lookup against MalwareBazaar
- ThreatFox IOC correlation on confirmed hits (C2 IPs / domains)
- GeoIP enrichment for IP-type IOCs (country, city, ASN, Shodan link)
- Self-contained dark-themed HTML report — opens offline, no server
- Multiple inputs: file, inline array, directory scan, interactive prompt
- Pipeline support (`-PassThru`) for CSV export and automation
- Resilient: TLS 1.2, retries with backoff, graceful auth/network failure
- Report-side HTML escaping of all API-derived fields
- PowerShell 5.1+ compatible — zero dependencies, no install

---

## The problem

You have a pile of suspicious file hashes from a compromised host. You need to know which ones are confirmed malware, what families they belong to, and whether any known C2 infrastructure is associated.

Manual approach:

1. Open MalwareBazaar — paste hash — wait
2. Open ThreatFox — paste hash — wait
3. Look up the C2 IP geolocation — wait
4. Take notes in a ticket
5. Repeat for every remaining hash

**With dozens of hashes this takes hours. This tool does it in minutes, automatically.**

---

## What it does

```
Hash list (file / directory scan / inline / interactive)
            │
            ▼
    ┌─────────────────┐
    │  MalwareBazaar  │  ──►  MALICIOUS  ──►   ┌──────────────────┐
    │   get_info API  │                        │  ThreatFox       │
    └─────────────────┘                        │  search_hash API │
            │                                  └──────┬───────────┘
            ├── NOT_FOUND                             │ C2 IPs / Domains
            └── ERROR / AUTH_ERROR                    ▼
                                              ┌──────────────────┐
                                              │  ip-api.com      │
                                              │  GeoIP (free)    │
                                              └──────┬───────────┘
                                                     │
                                                     ▼
                                        Self-contained HTML Report
                                        + Console output
```

**Result:** one HTML file you can open, filter, search, and drop into a ticket.

---

## Quick start

```powershell
# 1. Get your free key at https://auth.abuse.ch (GitHub / Google / LinkedIn login)

# 2. Run against your hash list
.\Invoke-MBHashCheck.ps1 -ApiKey "YOUR_KEY" -HashFile "hashes.txt"

# 3. Open the generated HTML report
```

Run it with no parameters and it goes interactive — it prompts for the Auth-Key, then offers to load a `.txt` file (paste or drag-and-drop the path) or to type hashes in by hand.

---

## Console output

```
 ______               _    _____
|___  /              | |  / ____|
   / / __ ___   _____| |_| (___   ___  ___
  / / / _` \ \ / / _ \ __|\___ \ / _ \/ __|
 / /_| (_| |\ V /  __/ |_ ____) |  __/ (__
/_____\__,_| \_/ \___|\__|_____/ \___|\___|
   ZavetSec - MalwareBazaar Hash Checker v2.1
   MalwareBazaar + ThreatFox + GeoIP | Free key: auth.abuse.ch
------------------------------------------------------

[10:29:01] [HEAD] Loaded 5 hash(es) for analysis.
[10:29:01] [INFO] Source: MalwareBazaar + ThreatFox (abuse.ch) | Auth-Key: ....e043

  [1/5] 00f32286...93a730af (SHA256) ... [NOT_FOUND]  Not in MalwareBazaar database
  [2/5] 0235838b...40d744be (SHA256) ... [NOT_FOUND]  Not in MalwareBazaar database
  [3/5] 07bfae03...dfc6d5e4 (SHA256) ... [NOT_FOUND]  Not in MalwareBazaar database
  [4/5] ed01ebfb...080e41aa (SHA256) ... [MALICIOUS]  WannaCry
  [TF] Querying ThreatFox for related IOCs...
      No IOCs found in ThreatFox
  [5/5] 0a093c05...5f380a19 (SHA256) ... [NOT_FOUND]  Not in MalwareBazaar database

------------------------------------------------------
[10:29:05] [HEAD] Analysis complete.
  Total:          5
  MALICIOUS:      1
  NOT IN DB:      4
  Errors:         0
  ThreatFox hits: 0
  TF IOCs total:  0

[10:29:05] [OK] HTML report saved: .\MB_HashReport_20260602_102905.html
```

> `-Quiet` suppresses NOT_FOUND rows in the console. `-PassThru` pipes result objects into further automation.

---

## HTML report

<img width="1919" height="938" alt="mbcheck" src="https://github.com/user-attachments/assets/9af3395a-ac05-4602-9c2a-9b4ae62d3306" />

Self-contained `.html` — no server, no internet required to open. Dark terminal theme, UTF-8 (no BOM).

**Summary header:** Total · Malicious · Not in DB · Errors

**Hash table columns:** Hash (clickable → MalwareBazaar sample page) · Verdict badge · File name / type / size · Signature · Tags · First seen · Intel (ClamAV detections + download/upload counts)

**ThreatFox section** *(shown only when hash-linked IOCs exist)*: IOC · Type · Threat · Malware family · Confidence % · Country flag + city · ASN · Shodan link for IPs

**Filters:** All / Malicious / Not in DB  
**Search:** instant full-text across all rows

> All API-derived fields (file names, tags, signatures, ThreatFox values) are HTML-escaped before rendering, so a hostile sample name cannot inject markup into the report.

Drop it in a ticket. Email it. Open it on an airgapped analyst machine.

---

## Why not just VirusTotal?

VirusTotal is excellent for deep single-file analysis. This tool solves a different problem: **bulk triage with C2 context during incident response.** It is designed for incident-response triage, not malware reverse engineering.

| | MalwareBazaar GUI | VirusTotal GUI | **Invoke-MBHashCheck** |
|---|---|---|---|
| **Bulk (dozens of hashes)** | Hours | Manual workflow | Minutes |
| **Output format** | Browser notes | Browser notes | Filterable HTML |
| **C2 enrichment** | No | No | Automatic (ThreatFox) |
| **GeoIP on C2 IPs** | No | No | Yes |
| **Automatable** | No | No | Yes (`-PassThru`) |
| **Free** | Yes | Freemium | Yes |
| **Offline report** | No | No | Yes |

---

## Usage

```powershell
# Bulk check from file
.\Invoke-MBHashCheck.ps1 -ApiKey "YOUR_KEY" -HashFile "hashes.txt"

# Auto-hash all files in a directory
.\Invoke-MBHashCheck.ps1 -ApiKey "YOUR_KEY" -ScanDirectory "C:\Suspicious" -Recurse

# Single / multiple hashes inline
.\Invoke-MBHashCheck.ps1 -ApiKey "YOUR_KEY" -Hashes "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"

# Quiet mode — MALICIOUS / ERROR only in console
.\Invoke-MBHashCheck.ps1 -ApiKey "YOUR_KEY" -HashFile "hashes.txt" -Quiet

# Pipeline — export MALICIOUS hits to CSV
.\Invoke-MBHashCheck.ps1 -ApiKey "YOUR_KEY" -HashFile "hashes.txt" -PassThru |
    Where-Object Status -eq "MALICIOUS" |
    Select-Object Hash, Signature, Tags, FirstSeen |
    Export-Csv hits.csv -NoTypeInformation

# Custom output folder + retry tuning
.\Invoke-MBHashCheck.ps1 -ApiKey "YOUR_KEY" -HashFile "hashes.txt" `
    -OutputDir "C:\Reports" -MaxRetries 5 -RetryDelaySeconds 10

# Fully interactive (prompts for key, then file path or manual entry)
.\Invoke-MBHashCheck.ps1
```

---

## Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-ApiKey` | String | prompted | MalwareBazaar / ThreatFox Auth-Key (free). Prompted if omitted. |
| `-HashFile` | String | — | Path to a text file, one hash per line (`#` comments allowed) |
| `-Hashes` | String[] | — | Hashes passed directly as an array |
| `-ScanDirectory` | String | — | Directory to auto-hash (SHA256) before lookup |
| `-Recurse` | Switch | off | Recurse into subdirectories with `-ScanDirectory` |
| `-OutputDir` | String | current dir | Where to save the HTML report |
| `-MaxRetries` | Int | 3 | Retry attempts on transient errors (HTTP 429 / 5xx / network) |
| `-RetryDelaySeconds` | Int | 5 | Seconds between retries |
| `-Quiet` | Switch | off | Show only MALICIOUS / ERROR in console |
| `-PassThru` | Switch | off | Emit result objects to the pipeline |

---

## Hash file format

Plain text, one hash per line. Comments (`#`) and blank lines are ignored. MD5, SHA1, SHA256 — mix freely. Invalid lines are skipped with a warning. Duplicates are removed automatically.

```text
# Ransomware samples
ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa

# Stealers
5dd92be22d005624d865ddf07402eb852426fc97baa52bbc58316690d41adb74

# MD5 is fine too
84c82835a5d21bbcf75a61706d8ab549
```

---

## Understanding results

| Status | Meaning |
|---|---|
| `MALICIOUS` | Confirmed in MalwareBazaar — known malware |
| `NOT_FOUND` | Not in MalwareBazaar — **does not mean clean** |
| `ERROR` | API or network error after retries — see detail column |
| `AUTH_ERROR` | Auth-Key rejected — the run stops, a report is still written |

> **NOT_FOUND ≠ Clean.** MalwareBazaar only indexes confirmed malware samples that have been submitted. A file absent from the database may still be malicious. Cross-reference with additional sources.

**ThreatFox enrichment** fires on MALICIOUS hits when the hash was explicitly submitted to ThreatFox as an IOC by a researcher. In practice most hashes return "No IOCs found" — this is expected and correct. Hash-type IOCs are rare in ThreatFox; when present they provide C2 IPs/domains with confidence level and GeoIP. Note: ThreatFox expires IOCs older than 6 months, so older samples may not return results.

**GeoIP** uses the free `ip-api.com` tier (45 requests/min). The tool paces requests to stay under that limit; if it is hit anyway, GeoIP is disabled for the rest of the run and a warning is logged — MalwareBazaar/ThreatFox data is unaffected.

---

## Antivirus false positives

**Your AV may flag or quarantine this script. It is a false positive.** This is normal and expected for DFIR / blue-team tooling.

Behavioural engines (Kaspersky, Defender, etc.) flag the script because — by design — it does the same *kinds* of things malware does: PowerShell making outbound API calls with a custom User-Agent, querying IP geolocation, recursively hashing files on disk (`-ScanDirectory`), and generating HTML with embedded data. The heuristic sees the *behaviour*, not the intent, and raises a generic verdict such as `HEUR:Trojan.Script.Generic` or `PDM:Trojan.Win32.Generic`. The script does nothing malicious — it reads hashes, calls public abuse.ch APIs, and writes a report.

**How to confirm it really is a false positive:**

- Check the exact verdict in your AV's quarantine log. `HEUR:`, `Generic`, `PDM:` prefixes indicate heuristic detection — almost always a false positive.
- Upload the file to [VirusTotal](https://www.virustotal.com). A couple of heuristic hits out of 70+ engines = false positive. If many named engines agree on a specific malware family, stop and re-download a clean copy from this repo.
- Verify integrity against the published hash (see below).

**Add it to your AV exclusions:**

*Kaspersky*
1. Quarantine → restore the file.
2. Settings → **Threats and Exclusions** → **Manage exclusions** → **Add**.
3. Add the full path to `Invoke-MBHashCheck.ps1` (or the ZavetSec folder). Optionally add the verdict name to the trusted list.

*Microsoft Defender*
```powershell
Add-MpPreference -ExclusionPath "C:\Tools\ZavetSec\Invoke-MBHashCheck.ps1"
```

**Optional — sign the script (recommended for distribution):**
```powershell
$cert = New-SelfSignedCertificate -Subject "CN=ZavetSec Code Signing" `
    -Type CodeSigningCert -CertStoreLocation Cert:\CurrentUser\My
Set-AuthenticodeSignature -FilePath .\Invoke-MBHashCheck.ps1 -Certificate $cert
```
Add the certificate to **Trusted Publishers**. This reduces prompts and also satisfies PowerShell's execution policy.

**Report the false positive** so it stops triggering for everyone: submit the file to [opentip.kaspersky.com](https://opentip.kaspersky.com) (or your vendor's FP submission form). Vendors typically clear generic verdicts within a few days.

---

## Requirements

| | |
|---|---|
| PowerShell | 5.1+ (built into Windows 10+); also runs on PowerShell 7 |
| API key | Free at [auth.abuse.ch](https://auth.abuse.ch) — GitHub / Google / LinkedIn login |
| Internet | `mb-api.abuse.ch`, `threatfox-api.abuse.ch`, `ip-api.com` |
| TLS | TLS 1.2 forced at startup (for older Windows / PS 5.1) |
| Install | None |

---

## Part of the ZavetSec DFIR toolkit

Designed to work together during live IR engagements. Each tool is independent — use any one standalone, or chain them.

| Tool | What it does |
|---|---|
| **Invoke-ZavetSecTriage** | Live artifact collection — MITRE-tagged findings, HTML report |
| **Invoke-MBHashCheck** | Bulk hash triage — MalwareBazaar + ThreatFox C2 enrichment + GeoIP |
| **ZavetSecHardeningBaseline** | Windows hardening checks — JSON rollback, compliance report |

All: PS 5.1, zero dependencies, self-contained HTML reports.

### Pipeline example — triage → verdict

```powershell
$key = "YOUR_KEY"
$out = "C:\IR\WORKSTATION-042"

# 1. Collect running-process hashes from a suspect host
.\Invoke-ZavetSecTriage.ps1 -OutputDir $out

# 2. Check them, keep only confirmed malware
$hits = .\Invoke-MBHashCheck.ps1 -ApiKey $key `
    -HashFile "$out\Forensics\hashes.txt" -PassThru -Quiet |
    Where-Object Status -eq "MALICIOUS"

if ($hits) {
    Write-Host "COMPROMISE CONFIRMED: $($hits.Count) malicious process(es)" -ForegroundColor Red
    $hits | Select-Object Hash, Signature, Tags | Format-Table
} else {
    Write-Host "No known malware in running processes" -ForegroundColor Green
}
```

---

## Roadmap

- [ ] VirusTotal fallback for NOT_FOUND hashes
- [ ] JSON / CSV output alongside HTML
- [ ] Local cache — skip re-querying known hashes
- [ ] Sigma rule export from confirmed hits
- [ ] MISP push integration

---

## Changelog

**v2.1**
- HTML-escaping of all API-derived fields (report-side injection hardening)
- ThreatFox JSON built via `ConvertTo-Json` (correct escaping); `</script>` neutralized
- Graceful failure handling — bad key / network errors no longer abort the run; a report is always written
- TLS 1.2 forced at startup; UTF-8 (no BOM) report output
- ip-api rate-limit handling (paced + auto-disable on 429)
- Interactive `.txt` file-path prompt; clean ASCII banner

**v2.0**
- ThreatFox IOC enrichment + GeoIP
- `-ScanDirectory` / `-Recurse`, `-Quiet`, `-MaxRetries`, `-RetryDelaySeconds`, `-PassThru`

**v1.0** — initial MalwareBazaar hash lookup + HTML report

---

## Contributing

```bash
git clone https://github.com/zavetsec/Invoke-MBHashCheck
cd Invoke-MBHashCheck

# Lint before submitting
Invoke-ScriptAnalyzer -Path .\Invoke-MBHashCheck.ps1 -Severity Warning,Error
```

Issues and feature requests → open an issue.

---

## License

MIT — free to use, modify, distribute. Attribution appreciated.

---

<div align="center">

**ZavetSec** · Powered by [abuse.ch](https://abuse.ch) (MalwareBazaar + ThreatFox)

*Free API key: [auth.abuse.ch](https://auth.abuse.ch)*

*⭐ Star the repo to help other responders find it.*

</div>
