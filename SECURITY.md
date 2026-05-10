# Security Policy

## Supported Versions

| Version | Supported          |
|---------|-------------------|
| 0.1.x   | ✅ Active         |

## Reporting a Vulnerability

If you discover a security vulnerability in clawkit, please report it privately.

**Do not** open a public issue. Instead, email the maintainer directly or use GitHub's private vulnerability reporting feature.

### What to include

- Description of the vulnerability
- Steps to reproduce
- Affected version(s)
- Potential impact
- Any suggested fix (if available)

### Response

You can expect an acknowledgement within 48 hours, and a detailed response within 7 days. We'll keep you informed of progress toward a fix.

## Security Practices

- **Zero dependencies** — reduces supply-chain risk.
- **No network calls** — clawkit operates entirely locally.
- **No telemetry** — no data is sent anywhere.
- **SARIF output** — the secrets scanner supports standard SARIF format for CI/CD integration.
