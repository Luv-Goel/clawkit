# Changelog

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
