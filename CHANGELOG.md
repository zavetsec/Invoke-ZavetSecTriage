# Changelog

All notable changes to Invoke-MBHashCheck are documented here.
Format based on [Keep a Changelog](https://keepachangelog.com/).

## [2.1]

### Security
- HTML-escape all API-derived fields (file names, tags, signatures, ThreatFox values) before rendering into the report, preventing markup injection from hostile sample names.
- Build the ThreatFox JSON via `ConvertTo-Json` instead of manual string concatenation, ensuring correct escaping of quotes, backslashes and control characters.
- Neutralize any literal `</script>` in injected data so it cannot close the script block early.

### Added
- Interactive `.txt` file-path prompt when no hashes are supplied (paste or drag-and-drop the path; Enter falls through to manual entry).

### Changed
- Force TLS 1.2 at startup for older Windows / PowerShell 5.1.
- Write the report as UTF-8 without BOM via `System.IO.File::WriteAllText` (avoids BOM and non-ASCII mangling from `Out-File -Encoding UTF8`).
- Clean ASCII banner (no escape-character artifacts).

### Fixed
- A rejected Auth-Key or network error no longer aborts the whole run; every failure path returns a populated result and a report is always written.
- GeoIP requests are paced under the ip-api free-tier limit (45/min) and auto-disable on HTTP 429 with a logged warning instead of failing silently.
- Default missing ThreatFox `confidence_level` to `0` and guard the integer cast, preventing malformed report JSON.
- Replaced a no-op quote-escaping routine that could break the ThreatFox table.

## [2.0]

### Added
- ThreatFox IOC enrichment (`search_hash`) on MALICIOUS hits — C2 IPs / domains with confidence level.
- GeoIP enrichment for IP-type IOCs (country, city, ASN, ISP, Shodan link).
- `-ScanDirectory` / `-Recurse` to auto-hash files in a directory.
- `-Quiet`, `-MaxRetries`, `-RetryDelaySeconds`, `-PassThru` parameters.
- Signature fallbacks (popular_threat_classification, first YARA rule) and tag fallback (vendor_intel / ANY.RUN).
- Extended console summary (ThreatFox hits, total IOCs) and progress bar.

## [1.0]

### Added
- Initial release: MalwareBazaar `get_info` hash lookup for MD5 / SHA1 / SHA256.
- Dark-themed self-contained HTML report with filtering and search.
- File, inline, and interactive hash input.
