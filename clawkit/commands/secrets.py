"""clawkit secrets — Code secret scanner (vault)."""

import os
import sys
import re
import json
import math
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from ..utils.html import report_header, report_footer


def register(sub):
    p = sub.add_parser("secrets", help="Secret scanner", description="Find hardcoded credentials, tokens, API keys, and secrets in code")
    p.add_argument("path", nargs="?", default=".", help="Directory to scan")
    p.add_argument("--format", choices=["text", "json", "sarif", "html"], default="text", help="Output format")
    p.add_argument("--output", "-o", help="Output file")
    p.add_argument("--include-tests", action="store_true", help="Include test files")
    p.add_argument("--entropy-threshold", type=float, default=4.5, help="Entropy threshold (default: 4.5)")
    p.add_argument("--threads", type=int, default=0, help="Worker threads (default: CPU count)")
    return p


def run(args):
    if not os.path.isdir(args.path):
        print(f"[ERR] Directory not found: {args.path}", file=sys.stderr)
        sys.exit(1)

    findings = _scan(args.path, args.include_tests, args.entropy_threshold, args.threads or None)

    if args.format == "text":
        _text_output(findings)
    elif args.format == "json":
        _json_output(findings, args.output)
    elif args.format == "sarif":
        _sarif_output(findings, args.output)
    elif args.format == "html":
        _html_output(findings, args.output)


PATTERNS = [
    ("AWS Access Key", r"AKIA[0-9A-Z]{16}", "critical"),
    ("AWS Secret Key", r"(?i)aws(.{0,20})?(?-i)['\"][0-9a-zA-Z/+]{40}['\"]", "critical"),
    ("GitHub Token", r"(?i)(github|gh)[_-]?pat[_-]?[a-z0-9]{36,}", "high"),
    ("GitLab Token", r"glpat-[0-9a-zA-Z\-_]{20,}", "high"),
    ("Stripe Live", r"sk_live_[0-9a-zA-Z]{24,}", "critical"),
    ("Stripe Test", r"sk_test_[0-9a-zA-Z]{24,}", "medium"),
    ("Discord Token", r"[mN][a-zA-Z0-9_-]{23,28}\.[a-zA-Z0-9_-]{6,7}\.[a-zA-Z0-9_-]{27,}", "high"),
    ("Slack Token", r"(xox[baprs]-[0-9a-zA-Z\-]{10,})", "high"),
    ("Telegram Bot Token", r"[0-9]{8,10}:[a-zA-Z0-9_-]{35}", "high"),
    ("Private Key", r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "critical"),
    ("PGP Private Key", r"-----BEGIN PGP PRIVATE KEY BLOCK-----", "critical"),
    ("Password in Config", r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"][^'\"]+['\"]", "high"),
    ("API Key", r"(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"][a-z0-9]{16,}['\"]", "high"),
    ("Database URL", r"(?i)(postgres|mysql|mongodb|redis)://\S+:\S+@", "critical"),
    ("Bearer Token", r"Bearer\s+[a-zA-Z0-9\-_.]{20,}", "high"),
    ("JWT Token", r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}", "medium"),
]

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", ".eggs", "dist", "build", ".gitlab", ".svn"}
SKIP_EXTS = {".pyc", ".o", ".so", ".dll", ".dylib", ".exe", ".jpg", ".png", ".gif", ".ico", ".svg", ".woff", ".woff2", ".eot", ".ttf"}
TEST_PATTERNS = re.compile(r"(test_|_test|spec_|_spec|fixture|mock|stub)", re.IGNORECASE)


def _entropy(s):
    if not s:
        return 0
    prob = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in prob)


def _scan_file(path, patterns, entropy_threshold):
    findings = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except:
        return findings

    for i, line in enumerate(lines, 1):
        for name, pattern, severity in patterns:
            for m in re.finditer(pattern, line):
                matched = m.group()
                score = _entropy(matched)
                if score >= entropy_threshold or severity in ("critical",):
                    findings.append({
                        "file": path, "line": i,
                        "pattern": name, "match": matched,
                        "severity": severity, "entropy": round(score, 2),
                        "context": line.strip()[:120],
                    })
    return findings


def _scan(root, include_tests, entropy_threshold, threads):
    patterns = PATTERNS
    files = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        if not include_tests and TEST_PATTERNS.search(dirpath):
            continue
        for fn in filenames:
            ext = os.path.splitext(fn)[1].lower()
            if ext in SKIP_EXTS:
                continue
            path = os.path.join(dirpath, fn)
            files.append(path)

    all_findings = []
    worker_count = threads or os.cpu_count() or 4
    with ThreadPoolExecutor(max_workers=worker_count) as ex:
        results = ex.map(lambda f: _scan_file(f, patterns, entropy_threshold), files)
        for r in results:
            all_findings.extend(r)

    all_findings.sort(key=lambda x: {"critical": 0, "high": 1, "medium": 2}.get(x["severity"], 3))
    return all_findings


def _text_output(findings):
    if not findings:
        print("  [OK] No secrets found.")
        return
    for f in findings:
        sev = {"critical": "🔴", "high": "🟡", "medium": "🟠"}.get(f["severity"], "•")
        print(f"  {sev} [{f['severity'].upper()}] {f['file']}:{f['line']}")
        print(f"    Pattern: {f['pattern']}")
        print(f"    Context: {f['context']}")
        print()
    print(f"  Total: {len(findings)} findings")
    severity_counts = Counter(f["severity"] for f in findings)
    for sev in ["critical", "high", "medium"]:
        if sev in severity_counts:
            print(f"    {sev}: {severity_counts[sev]}")


def _json_output(findings, output):
    data = {"findings": findings, "total": len(findings)}
    if output:
        with open(output, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        print(f"[OK] JSON report: {output}")
    else:
        print(json.dumps(data, indent=2))


def _sarif_output(findings, output):
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "clawkit secrets", "version": "0.1.0"}}, "results": []}],
    }
    for f in findings:
        sarif["runs"][0]["results"].append({
            "ruleId": f["pattern"],
            "level": "error" if f["severity"] == "critical" else "warning",
            "message": {"text": f"{f['pattern']} found in {f['file']}:{f['line']}"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f["file"]},
                          "region": {"startLine": f["line"]}}}],
        })
    if output:
        with open(output, "w", encoding="utf-8") as f:
            json.dump(sarif, f, indent=2)
        print(f"[OK] SARIF report: {output}")
    else:
        print(json.dumps(sarif, indent=2))


def _html_output(findings, output):
    if not output:
        print("[ERR] --output required for HTML format", file=sys.stderr)
        return
    rows = ""
    sev_colors = {"critical": "#f87171", "high": "#fbbf24", "medium": "#fb923c"}
    for f in findings:
        color = sev_colors.get(f["severity"], "#94a3b8")
        rows += f"<tr><td><span style='color:{color}'>{f['severity'].upper()}</span></td><td>{f['pattern']}</td><td>{f['file']}:{f['line']}</td><td><code>{f['context'][:80]}</code></td></tr>\n"
    html = report_header("Secret Scan Report", "Vault — Code Secret Scanner")
    html += f"""<div class="grid">
<div class="stat"><div class="stat-value">{len(findings)}</div><div class="stat-label">Total Findings</div></div>
<div class="stat"><div class="stat-value" style="color:{sev_colors['critical']}">{sum(1 for f in findings if f['severity']=='critical')}</div><div class="stat-label">Critical</div></div>
<div class="stat"><div class="stat-value" style="color:{sev_colors['high']}">{sum(1 for f in findings if f['severity']=='high')}</div><div class="stat-label">High</div></div>
</div>
<table><thead><tr><th>Severity</th><th>Pattern</th><th>Location</th><th>Context</th></tr></thead><tbody>{rows}</tbody></table>"""
    html += report_footer()
    with open(output, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"[OK] HTML report: {output}")


from collections import Counter
