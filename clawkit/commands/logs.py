"""clawkit logs — Log file forensics (logsmith)."""

import os
import sys
import re
import json
from collections import Counter, defaultdict
from datetime import datetime
from ..utils.html import report_header, report_footer


def register(sub):
    p = sub.add_parser("logs", help="Log file forensics", description="Parse, analyze, search, and report on log files")
    p.add_argument("action", choices=["parse", "stats", "anomalies", "search", "top", "timeline", "report"], help="Action")
    p.add_argument("file", help="Log file")
    p.add_argument("--pattern", help="Search pattern (regex)")
    p.add_argument("--field", default="ip", help="Field for top-N analysis")
    p.add_argument("--limit", type=int, default=10, help="Row limit")
    p.add_argument("--output", "-o", help="Output file")
    return p


def run(args):
    if not os.path.exists(args.file):
        print(f"[ERR] File not found: {args.file}", file=sys.stderr)
        sys.exit(1)
    with open(args.file, encoding="utf-8", errors="replace") as f:
        raw = f.read()
    entries = _parse(raw)
    if args.action == "parse":
        for e in entries[:args.limit]:
            print(f"  [{e.get('timestamp','?')}] {e.get('ip','?'):15s} {e.get('method','?'):6s} {e.get('path','?'):50s} {e.get('status','?')}")
    elif args.action == "stats":
        _stats(entries)
    elif args.action == "anomalies":
        _anomalies(entries)
    elif args.action == "search":
        _search(entries, args.pattern)
    elif args.action == "top":
        _top(entries, args.field, args.limit)
    elif args.action == "timeline":
        _timeline(entries)
    elif args.action == "report":
        _report_html(entries, args.output)


APACHE_RE = re.compile(
    r'(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+\S+"\s+(\d+)\s+(\S+)'
)
SYSLOG_RE = re.compile(
    r'(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S+)\[(.+?)\]:\s+(.*)'
)


def _parse(raw):
    entries = []
    for line in raw.splitlines():
        m = APACHE_RE.match(line)
        if m:
            entries.append({
                "ip": m.group(1), "timestamp": m.group(2),
                "method": m.group(3), "path": m.group(4),
                "status": int(m.group(5)), "bytes": m.group(6),
            })
            continue
        m = SYSLOG_RE.match(line)
        if m:
            entries.append({
                "timestamp": m.group(1), "host": m.group(2),
                "app": m.group(3), "pid": m.group(4),
                "message": m.group(5),
            })
    return entries


def _stats(entries):
    if not entries:
        print("  [OK] No entries parsed.")
        return
    ips = Counter(e.get("ip", "") for e in entries if "ip" in e)
    statuses = Counter(e.get("status") for e in entries if "status" in e)
    methods = Counter(e.get("method", "") for e in entries if "method" in e)
    print(f"  Total entries: {len(entries)}")
    print(f"  Unique IPs: {len(ips)}")
    print(f"  Methods: {dict(methods)}")
    print(f"  Statuses: {dict(statuses)}")
    if ips:
        print(f"  Top IP: {ips.most_common(1)[0][0]} ({ips.most_common(1)[0][1]} hits)")


def _anomalies(entries):
    statuses = Counter(e.get("status") for e in entries if "status" in e)
    total = sum(statuses.values())
    errors = sum(v for k, v in statuses.items() if k >= 400)
    error_rate = errors / total * 100 if total else 0
    print(f"  Error rate (4xx+): {error_rate:.1f}% ({errors}/{total})")
    if error_rate > 10:
        print("  ⚠️  High error rate detected!")
    # Spike detection
    if entries:
        print(f"  Total unique IPs hitting 5xx: {sum(1 for e in entries if e.get('status',0) >= 500)}")


def _search(entries, pattern):
    if not pattern:
        print("[ERR] --pattern required", file=sys.stderr)
        return
    regex = re.compile(pattern, re.IGNORECASE)
    found = 0
    for e in entries:
        for v in e.values():
            if isinstance(v, str) and regex.search(v):
                print(f"  {e.get('timestamp','?')} {e.get('ip','?'):15s} {e.get('method','?'):6s} {e.get('path','?')[:60]}")
                found += 1
                break
    print(f"\n  Found: {found} entries")


def _top(entries, field, limit):
    vals = Counter(e.get(field, "") for e in entries if field in e)
    for val, count in vals.most_common(limit):
        print(f"  {val:30s} {count}")


def _timeline(entries):
    timestamps = [e.get("timestamp", "") for e in entries if e.get("timestamp")]
    if not timestamps:
        print("  [WARN] No timestamps found.")
        return
    print(f"  Range: {timestamps[0]} — {timestamps[-1]}")
    print(f"  Entries: {len(timestamps)}")
    # Group by hour
    hour_counts = Counter()
    for ts in timestamps:
        try:
            dt = datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S")
            hour_counts[dt.strftime("%Y-%m-%d %H:00")] += 1
        except:
            pass
    for hour, count in sorted(hour_counts.items()):
        bar = "█" * min(count, 50)
        print(f"  {hour} | {bar} {count}")


def _report_html(entries, output):
    if not output:
        print("[ERR] --output required for report", file=sys.stderr)
        return
    total = len(entries)
    ips = Counter(e.get("ip", "") for e in entries if "ip" in e)
    statuses = Counter(e.get("status") for e in entries if "status" in e)
    errors = sum(1 for e in entries if e.get("status", 0) >= 400)

    rows = ""
    for e in entries[:200]:
        rows += f"<tr><td>{e.get('timestamp','')}</td><td>{e.get('ip','')}</td><td>{e.get('method','')}</td><td>{e.get('path','')[:50]}</td><td>{e.get('status','')}</td></tr>\n"

    html = report_header("Log Analysis Report", "Logsmith — Log Forensics")
    html += f"""<div class="grid">
<div class="stat"><div class="stat-value">{total}</div><div class="stat-label">Total Entries</div></div>
<div class="stat"><div class="stat-value">{len(ips)}</div><div class="stat-label">Unique IPs</div></div>
<div class="stat"><div class="stat-value">{errors}</div><div class="stat-label">Errors (4xx+)</div></div>
</div>
<table><thead><tr><th>Timestamp</th><th>IP</th><th>Method</th><th>Path</th><th>Status</th></tr></thead><tbody>{rows}</tbody></table>"""
    html += report_footer()
    with open(output, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"[OK] Report: {output}")
