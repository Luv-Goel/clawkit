"""clawkit audit — Security permissions auditor (perm)."""

import os
import sys
import stat
from ..utils.html import report_header, report_footer


def register(sub):
    p = sub.add_parser("audit", help="Security permissions auditor", description="Find SUID binaries, world-readable secrets, weak permissions")
    p.add_argument("paths", nargs="*", default=["/"], help="Directories to audit")
    p.add_argument("--report", "-o", help="HTML report output")
    return p


def run(args):
    findings = []
    for path in args.paths:
        if os.path.isdir(path):
            findings.extend(_audit(path))
    findings.sort(key=lambda x: x["severity"], reverse=True)
    for f in findings:
        sev = {"critical": "🔴", "high": "🟡", "medium": "🟠", "low": "ℹ️"}.get(f["severity"], "•")
        print(f"  {sev} [{f['severity'].upper()}] {f['file']}: {f['reason']}")
    print(f"\n  Total findings: {len(findings)}")
    if args.report:
        _report_html(findings, args.report)
        print(f"[OK] Report: {args.report}", file=sys.stderr)


SECRET_EXTS = {".pem", ".key", ".pgp", ".gpg", ".id_rsa", ".env", ".credentials"}
SECRET_NAMES = {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "known_hosts", ".netrc"}


def _audit(root):
    findings = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if not d.startswith(".") or d in (".ssh", ".aws", ".config", ".gnupg")]
        try:
            st = os.stat(dirpath)
            if st.st_mode & stat.S_IWOTH:
                findings.append({"file": dirpath, "reason": "World-writable directory", "severity": "medium"})
        except OSError:
            pass
        for fn in filenames:
            path = os.path.join(dirpath, fn)
            try:
                st = os.stat(path)
                mode = st.st_mode
                # SUID/SGID
                if mode & stat.S_ISUID:
                    findings.append({"file": path, "reason": "SUID binary", "severity": "high"})
                if mode & stat.S_ISGID:
                    findings.append({"file": path, "reason": "SGID binary", "severity": "high"})
                # World-readable secrets
                ext = os.path.splitext(fn)[1].lower()
                name = os.path.splitext(fn)[0].lower()
                if ext in SECRET_EXTS or fn.lower() in SECRET_NAMES:
                    if mode & stat.S_IROTH:
                        findings.append({"file": path, "reason": f"World-readable secret file ({ext or name})", "severity": "critical"})
                # World-writable files
                if mode & stat.S_IWOTH:
                    findings.append({"file": path, "reason": "World-writable file", "severity": "high"})
            except OSError:
                pass
    return findings


def _report_html(findings, output):
    rows = ""
    for f in findings:
        color = {"critical": "#f87171", "high": "#fbbf24", "medium": "#fb923c", "low": "#94a3b8"}[f["severity"]]
        rows += f"<tr><td><span style='color:{color}'>{f['severity'].upper()}</span></td><td>{f['file']}</td><td>{f['reason']}</td></tr>\n"
    html = report_header("Security Audit Report", "Perm — Security Permissions Auditor")
    html += f"""<div class="grid">
<div class="stat"><div class="stat-value">{len(findings)}</div><div class="stat-label">Total Findings</div></div>
<div class="stat"><div class="stat-value" style="color:#f87171">{sum(1 for f in findings if f['severity']=='critical')}</div><div class="stat-label">Critical</div></div>
<div class="stat"><div class="stat-value" style="color:#fbbf24">{sum(1 for f in findings if f['severity']=='high')}</div><div class="stat-label">High</div></div>
</div>
<table><thead><tr><th>Severity</th><th>File</th><th>Issue</th></tr></thead><tbody>{rows}</tbody></table>"""
    html += report_footer()
    with open(output, "w", encoding="utf-8") as f:
        f.write(html)
