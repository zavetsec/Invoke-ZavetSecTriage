# ZavetSec Triage

```
     ____                  _    ____
    |_  /__ ___ _____ ___ | |_ / __/__ ___
     / // _` \ V / -_)  _||  _\__ \/ -_) _|
    /___\__,_|\_/\___\__| |_| |___/\___\__|

    EXPRESS TRIAGE v1.0  //  DFIR  //  PowerShell 5.1
```

> Zero-dependency live forensics for Windows. One script. No installation. No traces.

---

## What it does

Collects 17 categories of forensic artifacts from a live Windows system and packages everything into a single ZIP. Runs entirely in PowerShell 5.1 with no external tools required.

| # | Module | Key artifacts |
|---|--------|--------------|
| 1 | System Baseline | OS, domain, uptime, hotfixes, installed software |
| 2 | Running Processes | SHA256 hashes, signatures, parent chains, masquerade detection |
| 3 | Network State | TCP/UDP connections, DNS cache, ARP table, named pipes (C2) |
| 4 | Persistence | Run keys, Winlogon, IFEO, LSA SSP, scheduled tasks, services, WMI |
| 5 | User Accounts | Local users/groups, active sessions, Kerberos tickets |
| 6 | PowerShell Artifacts | History (all users), language mode |
| 7 | Event Logs | Targeted Event IDs as CSV + raw EVTX export |
| 8 | Prefetch | Execution evidence, 30+ attacker tools flagged automatically |
| 9 | File Activity | LNK recent files (pure .NET parser, no COM) |
| 10 | Registry Forensics | UserAssist (ROT13 decoded), MUICache, TypedURLs |
| 11 | Credential Security | WDigest, Credential Guard, LSA PPL status |
| 12 | Configuration | Hosts file, firewall rules (in/out), ADS scan |
| 13 | Shadow Copies | VSS enumeration — absence flagged as T1490 (ransomware IOC) |
| 14 | Browser History | 16 browsers, all users, CSV + raw SQLite DB copies |
| 15 | BITS Jobs | Stealthy download detection (T1197) |
| 16 | Clipboard | Text capture, credential pattern detection |
| 17 | Metadata & Summary | Highlights CSV/JSON, file manifest, final ZIP |

---

## Usage

```powershell
# Local - run as Administrator
.\Invoke-ZavetSecTriage.ps1

# Custom output directory
.\Invoke-ZavetSecTriage.ps1 -OutputDir C:\DFIR

# Remote via PsExec (silent, runs as SYSTEM)
psexec \\TARGET -s -d powershell.exe -NonInteractive -WindowStyle Hidden `
    -ExecutionPolicy Bypass -File "\\share\Invoke-ZavetSecTriage.ps1" `
    -OutputDir "\\share\output"
```

**Output:** `ZavetSec_<hostname>_<timestamp>.zip`

---

## Requirements

- PowerShell 5.1+
- Local Administrator rights (recommended — some modules degrade without)
- No internet access required
- No external binaries required
- `sqlite3.exe` optional — enables full browser history parsing

---

## Reading the output

| Format | Tool |
|--------|------|
| `.csv` | Excel, LibreOffice Calc |
| `.json` | VS Code, any browser |
| `.evtx` | Windows Event Viewer, Chainsaw, Hayabusa |
| `.db` (SQLite) | DB Browser for SQLite |

Sigma-based batch analysis of collected logs:
```
chainsaw hunt Logs\ --sigma rules\ --mapping mapping.yml
hayabusa csv-timeline -d Logs\ -o timeline.csv
```

---

## Recommendations

### Viewing CSV output
For the best analysis experience, use **Timeline Explorer** by Eric Zimmerman (SANS / ex-FBI)
instead of Excel — it was built specifically for DFIR CSV workflows.

- Fast filtering and multi-column search across large files
- Color-coded rows, column pinning, tag/bookmark rows during investigation
- Handles large CSVs (100k+ rows) without freezing
- Dark mode included

Download: https://www.sans.org/tools/timeline-explorer/

### Analyzing collected EVTX logs
**Chainsaw** and **Hayabusa** allow batch Sigma rule scanning against the collected `Logs\` folder:
```
chainsaw hunt Logs\ --sigma rules\ --mapping mapping.yml
hayabusa csv-timeline -d Logs\ -o timeline.csv
```

The resulting timeline CSV can be opened directly in Timeline Explorer for unified analysis.

- Chainsaw: https://github.com/WithSecureLabs/chainsaw
- Hayabusa: https://github.com/Yamato-Security/hayabusa

### Browser SQLite databases
Raw `.db` files in `Forensics\Browser_<user>\` can be examined with
**DB Browser for SQLite** — free, cross-platform, supports deleted record recovery.

Download: https://sqlitebrowser.org

---

## MITRE ATT&CK coverage

Script auto-flags findings with ATT&CK technique IDs. Coverage includes persistence (T1053, T1547, T1546), credential access (T1552, T1003), defense evasion (T1197, T1490), discovery, and lateral movement indicators.

---

## Screenshot

<img width="945" height="443" alt="image" src="https://github.com/user-attachments/assets/96235df3-3ee6-43f8-880e-80ba98b78b4e" />

---

## License

MIT — see [LICENSE](LICENSE)

---

*ZavetSec — built for field DFIR, not demos.*
