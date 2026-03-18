ZavetSec Triage v1.0
====================
DFIR Express Triage for live Windows systems.
Zero dependencies. No installation. PowerShell 5.1.

WHAT IT DOES
------------
Collects forensic artifacts from a running Windows host and packages
them into a timestamped ZIP. All 17 collection modules run in a single
pass. No external tools, no internet access, no traces left on disk
beyond the output ZIP.

REQUIREMENTS
------------
- PowerShell 5.1+
- Local Administrator rights (strongly recommended)
- sqlite3.exe optional — enables full browser DB parsing

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
File: ZavetSec_<hostname>_<timestamp>.zip

Structure inside ZIP:
    System\          - OS info, hotfixes, installed software
    Processes\       - process list with hashes and signatures
    Network\         - connections, DNS cache, ARP, named pipes
    Persistence\     - autorun keys, tasks, services, WMI subscriptions
    Users\           - accounts, sessions, Kerberos tickets
    Logs\            - event log CSVs and raw EVTX files
    Forensics\       - prefetch, browser history, BITS, clipboard,
                       LNK files, registry artifacts, highlights
    Config\          - hosts file, firewall rules, ADS scan
    triage_metadata.json   - collection summary and risk level
    triage_highlights.csv  - all flagged findings sorted by severity

READING THE OUTPUT
------------------
CSV     - Excel or LibreOffice Calc
JSON    - VS Code, Notepad, any browser
EVTX    - Windows Event Viewer
          Chainsaw: chainsaw hunt Logs\ --sigma rules\
          Hayabusa: hayabusa csv-timeline -d Logs\ -o tl.csv
SQLite  - DB Browser for SQLite (sqlitebrowser.org)

START WITH
----------
1. Forensics\triage_highlights.csv   -- sort by Severity
2. Processes\processes.csv           -- filter Suspicious = True
3. Network\tcp_connections.csv       -- filter IsExternal = True
4. Forensics\browser_history_all.csv -- open in Excel
