# Changelog

## v0.2.0 — 2026-05-10

### Added
- **`clawkit logscan`** — New log forensics scanner command (separate from `logs`):
  - Parses Apache, syslog, and JSON-lines log formats with auto-detection
  - Anomaly detection: error rate spikes, unusual IPs, suspicious paths, traffic spikes
  - HTML report with warnings, spikes, suspicious paths, and top sources
  - Rich terminal output with emoji indicators
- .github/workflows/ci.yml — GitHub Actions CI (pytest on Python 3.10-3.12)
- .gitattributes — Text/binary file handling configuration
- CONTRIBUTING.md — Contribution guide
- SECURITY.md — Security policy

### Changed
- README updated with new logscan examples, 9-tool table, badges
- CLI and pyproject.toml updated to reflect 9 tools

## v0.1.0 — 2026-05-10

Initial release — merge 8 focused CLI tools into one unified toolkit.

### Tools merged

| Command | Origin | Description |
|---------|--------|-------------|
| `clawkit scan` | sift | Duplicate file finder by content hash |
| `clawkit dotenv` | dotenv | .env file validation, merge, diff, template |
| `clawkit integrity` | warden | SHA256-based file integrity monitoring |
| `clawkit audit` | perm | SUID binaries, world-readable secrets, weak perms |
| `clawkit markdown` | mark | TOC, lint, check-links, format, stats |
| `clawkit data` | tally | Tabular data CLI: select, filter, group, join, stats |
| `clawkit logs` | logsmith | Log file parsing, analysis, search, HTML reports |
| `clawkit secrets` | vault | Secret scanner — 20+ patterns, entropy detection |

### Features
- Zero external dependencies (stdlib-only Python 3.8+)
- HTML reports with dark-mode CSS
- Consistent CLI argument patterns across all commands
- CI/CD ready (SARIF support for secrets scanner)
