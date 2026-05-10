"""clawkit logscan — Log forensics scanner.

Parses common log formats (Apache, syslog, JSON-lines) and detects
anomalies: error spikes, unusual IPs, abnormal patterns.
"""

import os
import sys
import re
import json
import argparse
from collections import Counter, defaultdict
from datetime import datetime
from ..utils.html import report_header, report_footer


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

def register(sub):
    p = sub.add_parser(
        "logscan",
        help="Log forensics scanner",
        description="Parse common log formats (Apache, syslog, JSON) and detect anomalies.",
        formatter_class=lambda prog: argparse.RawDescriptionHelpFormatter(prog, max_help_position=40),
        epilog=(
            "Examples:\n"
            "  clawkit logscan access.log\n"
            "  clawkit logscan access.log --format apache\n"
            "  clawkit logscan syslog.log --format syslog --anomalies\n"
            "  clawkit logscan app.json --format json --output report.html\n"
        ),
    )
    p.add_argument("file", help="Log file to scan")
    p.add_argument("--format", choices=["auto", "apache", "syslog", "json"], default="auto",
                   help="Log format (default: auto-detect)")
    p.add_argument("--anomalies", action="store_true",
                   help="Run anomaly detection and print results")
    p.add_argument("--output", "-o", metavar="FILE",
                   help="Write HTML report to FILE")
    p.add_argument("--limit", type=int, default=50,
                   help="Max anomalous entries to show (default: 50)")
    return p


def run(args):
    if not os.path.exists(args.file):
        print(f"[ERR] File not found: {args.file}", file=sys.stderr)
        sys.exit(1)

    raw = _read_file(args.file)
    fmt = args.format if args.format != "auto" else _detect_format(raw, args.file)
    entries = _parse(raw, fmt)

    if not entries:
        print("  [OK] No entries parsed.")
        sys.exit(0)

    # Always show summary
    _summary(entries, fmt)

    # Anomaly detection (always runs, shows if --anomalies or if issues found)
    anomalies = _detect_anomalies(entries, fmt)
    if args.anomalies or anomalies["error_rate"] > 10 or anomalies["spike_count"] > 0:
        _print_anomalies(anomalies, args.limit)

    # HTML report
    if args.output:
        _write_report(entries, anomalies, fmt, args.output)
        print(f"[OK] Report: {args.output}")


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

APACHE_RE = re.compile(
    r'(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+\S+"\s+(\d+)\s+(\S+)'
)
SYSLOG_RE = re.compile(
    r'(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S+)\[([^\]]+)?\]:\s+(.*)'
)


def _read_file(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        return f.read()


def _detect_format(raw, path):
    """Auto-detect log format from content and/or file extension."""
    ext = os.path.splitext(path)[1].lower()
    if ext == ".json":
        return "json"

    lines = [l for l in raw.splitlines() if l.strip()][:50]

    # Try Apache first (most common)
    apache_hits = sum(1 for l in lines if APACHE_RE.match(l))
    if apache_hits >= len(lines) * 0.5:
        return "apache"

    # Try syslog
    syslog_hits = sum(1 for l in lines if SYSLOG_RE.match(l))
    if syslog_hits >= len(lines) * 0.5:
        return "syslog"

    # Try JSON
    json_hits = 0
    for l in lines:
        if l.strip().startswith("{"):
            try:
                json.loads(l)
                json_hits += 1
            except json.JSONDecodeError:
                pass
    if json_hits >= len(lines) * 0.5:
        return "json"

    return "apache"  # fallback


def _parse(raw, fmt):
    if fmt == "apache":
        return _parse_apache(raw)
    elif fmt == "syslog":
        return _parse_syslog(raw)
    elif fmt == "json":
        return _parse_json(raw)
    return []


def _parse_apache(raw):
    entries = []
    for line in raw.splitlines():
        m = APACHE_RE.match(line)
        if m:
            entries.append({
                "ip": m.group(1),
                "timestamp": m.group(2),
                "method": m.group(3),
                "path": m.group(4),
                "status": int(m.group(5)),
                "bytes": m.group(6),
                "_fmt": "apache",
            })
    return entries


def _parse_syslog(raw):
    entries = []
    for line in raw.splitlines():
        m = SYSLOG_RE.match(line)
        if m:
            pid = m.group(4) if m.group(4) else ""
            entries.append({
                "timestamp": m.group(1),
                "host": m.group(2),
                "app": m.group(3),
                "pid": pid,
                "message": m.group(5),
                "_fmt": "syslog",
            })
    return entries


def _parse_json(raw):
    entries = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            obj["_fmt"] = "json"
            entries.append(obj)
    return entries


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

def _summary(entries, fmt):
    total = len(entries)
    print(f"  Format: {fmt}")
    print(f"  Entries: {total}")

    if fmt == "apache":
        ips = Counter(e.get("ip", "") for e in entries)
        statuses = Counter(e.get("status") for e in entries)
        methods = Counter(e.get("method", "") for e in entries)
        print(f"  Unique IPs: {len(ips)}")
        print(f"  Methods: {', '.join(f'{k}={v}' for k, v in methods.most_common())}")
        print(f"  Status codes: {', '.join(f'{k}={v}' for k, v in sorted(statuses.items()))}")

    elif fmt == "syslog":
        apps = Counter(e.get("app", "") for e in entries)
        hosts = Counter(e.get("host", "") for e in entries)
        print(f"  Unique hosts: {len(hosts)}")
        print(f"  Applications: {', '.join(a for a, _ in apps.most_common(5))}")

    elif fmt == "json":
        keys = Counter()
        for e in entries:
            for k in e:
                if not k.startswith("_"):
                    keys[k] += 1
        print(f"  JSON keys found: {', '.join(k for k, _ in keys.most_common(8))}")


# ---------------------------------------------------------------------------
# Anomaly detection
# ---------------------------------------------------------------------------

def _detect_anomalies(entries, fmt):
    result = {
        "total": len(entries),
        "fmt": fmt,
        "error_rate": 0.0,
        "errors_4xx": 0,
        "errors_5xx": 0,
        "spike_count": 0,
        "spike_info": [],
        "top_ips": [],
        "unusual_ips": [],
        "suspicious_paths": [],
        "error_entries": [],
        "warnings": [],
    }

    if fmt == "apache":
        result = _detect_apache_anomalies(entries, result)
    elif fmt == "syslog":
        result = _detect_syslog_anomalies(entries, result)
    elif fmt == "json":
        result = _detect_json_anomalies(entries, result)

    return result


def _detect_apache_anomalies(entries, result):
    total = len(entries)
    statuses = Counter(e.get("status") for e in entries)
    ips_counter = Counter(e.get("ip", "") for e in entries)
    paths_counter = Counter(e.get("path", "") for e in entries)

    errors_4xx = sum(v for k, v in statuses.items() if 400 <= k < 500)
    errors_5xx = sum(v for k, v in statuses.items() if k >= 500)
    error_rate = (errors_4xx + errors_5xx) / total * 100 if total else 0

    result["error_rate"] = round(error_rate, 1)
    result["errors_4xx"] = errors_4xx
    result["errors_5xx"] = errors_5xx

    if error_rate > 10:
        result["warnings"].append(f"High error rate: {error_rate:.1f}% ({errors_4xx + errors_5xx}/{total})")
    if errors_5xx > total * 0.05:
        result["warnings"].append(f"Elevated 5xx rate: {errors_5xx} ({errors_5xx/total*100:.1f}%)")

    # Top IPs
    result["top_ips"] = ips_counter.most_common(10)

    # Unusual IPs (single-hit IPs that hit error endpoints)
    single_hit_ips = {ip for ip, c in ips_counter.items() if c == 1}
    unusual = []
    for e in entries:
        if e.get("ip") in single_hit_ips and e.get("status", 0) >= 404:
            unusual.append({"ip": e.get("ip"), "path": e.get("path"), "status": e.get("status")})
    result["unusual_ips"] = unusual[:20]

    # Suspicious paths (probing paths like /admin, /wp-admin, etc.)
    suspicious_patterns = re.compile(
        r'(/admin|/wp-admin|/wp-login|\.env|/config|/backup|/sql|/phpmyadmin|/shell|/cmd)', re.I
    )
    suspicious = []
    for e in entries:
        path = e.get("path", "")
        if suspicious_patterns.search(path):
            suspicious.append({"ip": e.get("ip"), "path": path, "status": e.get("status")})
    result["suspicious_paths"] = suspicious[:20]

    # Spike detection by hour
    hour_entries = defaultdict(list)
    for e in entries:
        ts = e.get("timestamp", "")
        try:
            dt = datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S")
            hour_entries[dt.strftime("%Y-%m-%d %H:00")].append(e)
        except (ValueError, IndexError):
            pass

    if hour_entries:
        hours_sorted = sorted(hour_entries.items())
        counts = [len(v) for _, v in hours_sorted]
        avg = sum(counts) / len(counts) if counts else 0
        spike_info = []
        for hour_label, entries_list in hours_sorted:
            c = len(entries_list)
            if avg > 0 and c > avg * 3 and c >= 10:
                spike_info.append({"hour": hour_label, "count": c, "avg": round(avg, 1)})
                result["spike_count"] += 1
        result["spike_info"] = spike_info[:10]

    # Collect error entries for report
    result["error_entries"] = [e for e in entries if e.get("status", 0) >= 400][:100]

    return result


def _detect_syslog_anomalies(entries, result):
    levels = Counter()
    apps = Counter()
    error_messages = []

    for e in entries:
        msg = e.get("message", "")
        # Detect log levels
        level_match = re.match(r"<(\w+)>", msg) or re.search(r"\b(ERROR|WARN|FATAL|CRIT|ALERT|EMERG)\b", msg, re.I)
        if level_match:
            levels[level_match.group(1).upper()] += 1
        apps[e.get("app", "")] += 1

        if re.search(r"\b(error|fail|fatal|critical|denied|refused|timeout)\b", msg, re.I):
            error_messages.append(e)

    total = result["total"]
    error_count = sum(levels.get(lv, 0) for lv in ("ERROR", "FATAL", "CRIT", "ALERT", "EMERG"))
    result["error_rate"] = round(error_count / total * 100, 1) if total else 0
    result["warnings"].extend([f"{lv}: {c}" for lv, c in levels.most_common()])
    result["top_ips"] = apps.most_common(10)
    result["error_entries"] = error_messages[:100]

    if error_count > total * 0.1:
        result["warnings"].append(f"High error log density: {error_count}/{total}")

    return result


def _detect_json_anomalies(entries, result):
    # Try to find common fields
    level_field = None
    status_field = None
    ip_field = None

    key_samples = defaultdict(set)
    for e in entries[:200]:
        for k, v in e.items():
            if isinstance(v, str) and len(v) < 100:
                key_samples[k].add(v)

    # Heuristic field detection
    for k in list(entries[0].keys()) if entries else []:
        kl = k.lower()
        if any(x in kl for x in ("level", "severity", "loglevel", "log.level")):
            level_field = k
        if any(x in kl for x in ("status", "status_code", "http_status")):
            status_field = k
        if any(x in kl for x in ("ip", "remote_addr", "client_ip", "src_ip")):
            ip_field = k

    # Level-based error detection
    if level_field:
        level_counter = Counter()
        for e in entries:
            level_counter[e.get(level_field, "?")] += 1
        error_levels = {l for l in level_counter if l.upper() in ("ERROR", "FATAL", "CRITICAL", "CRIT")}
        error_count = sum(level_counter[l] for l in error_levels)
        result["error_rate"] = round(error_count / len(entries) * 100, 1) if entries else 0
        if error_count:
            result["warnings"].append(f"Error levels: {', '.join(f'{l}={c}' for l, c in level_counter.most_common())}")

    # Status-based error detection
    if status_field:
        error_entries = [e for e in entries if isinstance(e.get(status_field), (int, str))]
        error_entries_num = []
        for e in error_entries:
            try:
                s = int(e.get(status_field, 0))
                if s >= 400:
                    error_entries_num.append(e)
            except (ValueError, TypeError):
                pass
        if error_entries:
            result["error_rate"] = round(len(error_entries_num) / len(error_entries) * 100, 1)
        result["error_entries"] = error_entries_num[:100]

    # IP-based anomalies
    if ip_field:
        ips = Counter(e.get(ip_field, "") for e in entries if e.get(ip_field))
        result["top_ips"] = ips.most_common(10)

    return result


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def _print_anomalies(anomalies, limit):
    print()
    print("=" * 56)
    print("  Anomaly Detection Report")
    print("=" * 56)

    if anomalies["warnings"]:
        print()
        print("  ⚠️  Warnings:")
        for w in anomalies["warnings"]:
            print(f"    ⚠️  {w}")

    if anomalies["error_rate"] > 0:
        sev = "HIGH" if anomalies["error_rate"] > 10 else ("MODERATE" if anomalies["error_rate"] > 5 else "LOW")
        print(f"  Error rate: {anomalies['error_rate']:.1f}% ({sev})")

    if anomalies.get("spike_info"):
        print()
        print(f"  📊 Traffic spikes ({anomalies['spike_count']} detected):")
        for s in anomalies["spike_info"][:5]:
            print(f"    {s['hour']}: {s['count']} entries (avg: {s['avg']})")

    if anomalies.get("suspicious_paths"):
        print()
        print("  🚨 Suspicious paths:")
        for s in anomalies["suspicious_paths"][:limit]:
            print(f"    {s['ip']:15s} → {s['path'][:60]} [{s['status']}]")

    if anomalies.get("unusual_ips"):
        print()
        print("  👤 Unusual IPs (single-hit, error responses):")
        for u in anomalies["unusual_ips"][:limit]:
            print(f"    {u['ip']:15s} → {u['path'][:60]} [{u['status']}]")

    if anomalies.get("top_ips") and anomalies["fmt"] != "syslog":
        print()
        print("  🔝 Top sources:")
        for ip, count in anomalies["top_ips"][:10]:
            print(f"    {ip:20s} {count}")

    if anomalies.get("error_entries"):
        print()
        print(f"  ❌ Error entries (showing first {min(limit, len(anomalies['error_entries']))}):")
        for e in anomalies["error_entries"][:limit]:
            if anomalies["fmt"] == "apache":
                print(f"    {e.get('timestamp','?'):20s} {e.get('ip','?'):15s} {e.get('method','?'):6s} {e.get('path','?')[:50]} [{e.get('status','?')}]")
            elif anomalies["fmt"] == "syslog":
                print(f"    {e.get('timestamp','?'):15s} {e.get('app','?'):10s} {e.get('message','?')[:70]}")
            elif anomalies["fmt"] == "json":
                print(f"    {str(e)[:100]}")


# ---------------------------------------------------------------------------
# HTML Report
# ---------------------------------------------------------------------------

def _write_report(entries, anomalies, fmt, output_path):
    total = len(entries)
    total_errors = anomalies.get("errors_4xx", 0) + anomalies.get("errors_5xx", 0)
    error_rate = anomalies["error_rate"]

    # Stats grid values
    if fmt == "apache":
        ips = Counter(e.get("ip", "") for e in entries)
        stat2_label = "Unique IPs"
        stat2_value = len(ips)
        stat3_label = "Errors (4xx+5xx)"
        stat3_value = total_errors
    elif fmt == "syslog":
        apps = Counter(e.get("app", "") for e in entries)
        stat2_label = "Applications"
        stat2_value = len(apps)
        stat3_label = "Error-level messages"
        stat3_value = len(anomalies.get("error_entries", []))
    else:
        stat2_label = "Anomalies"
        stat2_value = anomalies["spike_count"]
        stat3_label = "Warnings"
        stat3_value = len(anomalies.get("warnings", []))

    rows = ""
    for e in entries[:200]:
        if fmt == "apache":
            rows += (
                f"<tr>"
                f"<td>{e.get('timestamp', '')}</td>"
                f"<td>{e.get('ip', '')}</td>"
                f"<td>{e.get('method', '')}</td>"
                f"<td>{e.get('path', '')[:60]}</td>"
                f"<td>{e.get('status', '')}</td>"
                f"</tr>\n"
            )
        elif fmt == "syslog":
            rows += (
                f"<tr>"
                f"<td>{e.get('timestamp', '')}</td>"
                f"<td>{e.get('host', '')}</td>"
                f"<td>{e.get('app', '')}</td>"
                f"<td>{e.get('message', '')[:80]}</td>"
                f"</tr>\n"
            )
        else:
            rows += (
                f"<tr>"
                f"<td>{str(e).get('timestamp', '') if isinstance(e, dict) else ''}</td>"
                f"<td colspan='3'>{str(e)[:120]}</td>"
                f"</tr>\n"
            )

    # Warnings section
    warnings_html = ""
    if anomalies.get("warnings"):
        warnings_html = '<div class="card"><h2>⚠️ Warnings</h2><ul>'
        for w in anomalies["warnings"]:
            warnings_html += f"<li>{w}</li>"
        warnings_html += "</ul></div>"

    # Suspicious paths
    suspicious_html = ""
    if anomalies.get("suspicious_paths"):
        suspicious_html = '<div class="card"><h2>🚨 Suspicious Paths</h2><table><thead><tr><th>IP</th><th>Path</th><th>Status</th></tr></thead><tbody>'
        for s in anomalies["suspicious_paths"][:20]:
            suspicious_html += f"<tr><td>{s['ip']}</td><td>{s['path'][:60]}</td><td>{s['status']}</td></tr>\n"
        suspicious_html += "</tbody></table></div>"

    # Spikes
    spikes_html = ""
    if anomalies.get("spike_info"):
        spikes_html = '<div class="card"><h2>📊 Traffic Spikes</h2><table><thead><tr><th>Hour</th><th>Count</th><th>Avg</th></tr></thead><tbody>'
        for s in anomalies["spike_info"]:
            spikes_html += f"<tr><td>{s['hour']}</td><td>{s['count']}</td><td>{s['avg']}</td></tr>\n"
        spikes_html += "</tbody></table></div>"

    # IPs table
    ips_html = ""
    if anomalies.get("top_ips"):
        ips_html = '<div class="card"><h2>🔝 Top Sources</h2><table><thead><tr><th>Source</th><th>Count</th></tr></thead><tbody>'
        for ip, count in anomalies["top_ips"][:20]:
            ips_html += f"<tr><td>{ip}</td><td>{count}</td></tr>\n"
        ips_html += "</tbody></table></div>"

    html = report_header("Log Forensics Scan Report", "Clawkit — Log Scan")
    html += f"""<div class="grid grid-4">
<div class="stat"><div class="stat-value">{total}</div><div class="stat-label">Total Entries</div></div>
<div class="stat"><div class="stat-value">{stat2_value}</div><div class="stat-label">{stat2_label}</div></div>
<div class="stat"><div class="stat-value">{stat3_value}</div><div class="stat-label">{stat3_label}</div></div>
<div class="stat"><div class="stat-value">{error_rate}%</div><div class="stat-label">Error Rate</div></div>
</div>"""
    html += warnings_html
    html += spikes_html
    html += suspicious_html
    html += ips_html
    html += f"""<div class="card"><h2>📋 Log Entries</h2>
<table><thead><tr>
"""
    if fmt == "apache":
        html += "<th>Timestamp</th><th>IP</th><th>Method</th><th>Path</th><th>Status</th>"
    elif fmt == "syslog":
        html += "<th>Timestamp</th><th>Host</th><th>App</th><th>Message</th>"
    else:
        html += "<th colspan='4'>Entry</th>"
    html += f"""</tr></thead><tbody>{rows}</tbody></table></div>"""
    html += report_footer()

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
