ZavetSec Triage v1.1
====================
DFIR Express Triage for live Windows systems.
Zero dependencies. No installation. PowerShell 5.1.

WHAT IT DOES
------------
Collects forensic artifacts from a running Windows host and packages
them into a timestamped ZIP with an HTML triage report. All 18
collection modules run in a single pass. No external tools, no internet
access, no traces left on disk beyond the output ZIP.

WHAT'S NEW IN v1.1
------------------
- HTML report (triage_report.html) in archive root — open in any browser,
  dark theme, tabbed views, severity-colored findings, MITRE ATT&CK tags
- Firewall rules now include Action column (Allow/Block); all rules
  collected regardless of action, not just Allow-inbound/Block-outbound
- Named pipes enriched with OwnerPID, ProcessName, ProcessPath columns
- UDP endpoints enriched with ProcessName and ProcessPath columns
- Browser history: raw SQLite DB copies removed, CSV output only
- Scheduled tasks: fixed BOM encoding issue (pi symbol in Excel)
- Archive renamed: <hostname>_<timestamp>.zip (no ZavetSec_ prefix)
- Console output: [+] success = green, [!] warnings = yellow, [-] info = gray

REQUIREMENTS
------------
- PowerShell 5.1+
- Local Administrator rights (strongly recommended)
- sqlite3.exe optional — enables full browser history with titles,
  visit counts and timestamps instead of URL-only regex fallback

USAGE
-----
Local (run PowerShell as Administrator):

    .\Invoke-ZavetSecTriage.ps1
    .\Invoke-ZavetSecTriage.ps1 -OutputDir C:\DFIR

Remote via PsExec (silent, no user interaction):

    psexec \\TARGET -s -d powershell.exe -NonInteractive -WindowStyle Hidden
        -ExecutionPolicy Bypass -File "\\share\Invoke-ZavetSecTriage.ps1"
        -OutputDir "\\share\output"

    -s  runs as SYSTEM (full access, no password needed)
    -d  detached — does not wait for completion

OUTPUT
------
File: <hostname>_<timestamp>.zip

Structure inside ZIP:
    triage_report.html     - interactive HTML report, start here
    triage_metadata.json   - collection summary and risk level
    System\          - OS info, hotfixes, installed software
    Processes\       - process list with hashes and signatures
    Network\         - TCP/UDP connections with process paths,
                       DNS cache, ARP table, named pipes with owners
    Persistence\     - autorun keys, tasks, services, WMI subscriptions
    Users\           - accounts, sessions, Kerberos tickets, PS history
    Logs\            - event log CSVs and raw EVTX files
    Forensics\       - prefetch, browser history CSV, BITS, clipboard,
                       LNK files, shadow copies, credential info,
                       highlights (all findings in one place)
    Config\          - hosts file, firewall rules with Action column,
                       ADS scan
    Registry\        - UserAssist, MUICache, TypedURLs, RecentDocs

READING THE OUTPUT
------------------
HTML    - any browser, open triage_report.html directly
CSV     - Excel or LibreOffice Calc
JSON    - VS Code, Notepad, any browser
EVTX    - Windows Event Viewer
          Chainsaw: chainsaw hunt Logs\ --sigma rules\
          Hayabusa: hayabusa csv-timeline -d Logs\ -o tl.csv

START WITH
----------
1. triage_report.html                - visual overview, open in browser
2. Forensics\triage_highlights.csv   - sort by Severity column
3. Processes\processes.csv           - filter Suspicious = True
4. Network\tcp_connections.csv       - filter IsExternal = True and State = Established
5. Persistence\autoruns.csv          - check for unknown entries
