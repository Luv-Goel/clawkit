"""clawkit integrity — File integrity monitor (warden)."""

import os
import sys
import hashlib
import json
from ..utils.html import report_header, report_footer

MANIFEST = "warden.manifest.json"
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv"}


def register(sub):
    p = sub.add_parser("integrity", help="File integrity monitor", description="SHA256-based file integrity monitoring (tripwire-lite)")
    p.add_argument("action", choices=["init", "check", "update", "report"], help="Action")
    p.add_argument("path", nargs="?", default=".", help="Directory to monitor")
    return p


def run(args):
    if not os.path.isdir(args.path):
        print(f"[ERR] Directory not found: {args.path}", file=sys.stderr)
        sys.exit(1)
    if args.action == "init":
        _init(args.path)
    elif args.action == "check":
        _check(args.path)
    elif args.action == "update":
        _update(args.path)
    elif args.action == "report":
        _report(args.path)


def _hash_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def _scan_dir(root):
    manifest = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            if fn == MANIFEST:
                continue
            path = os.path.join(dirpath, fn)
            try:
                rel = os.path.relpath(path, root)
                manifest[rel] = _hash_file(path)
            except OSError:
                pass
    return manifest


def _init(root):
    manifest = _scan_dir(root)
    mpath = os.path.join(root, MANIFEST)
    with open(mpath, "w") as f:
        json.dump(manifest, f, indent=2)
    print(f"[OK] Manifest created: {mpath} ({len(manifest)} files)")


def _check(root):
    mpath = os.path.join(root, MANIFEST)
    if not os.path.exists(mpath):
        print(f"[ERR] No manifest found at {mpath}. Run 'clawkit integrity init' first.", file=sys.stderr)
        sys.exit(1)
    with open(mpath) as f:
        stored = json.load(f)
    current = _scan_dir(root)
    changes = {"added": [], "removed": [], "modified": []}
    for path, h in current.items():
        if path not in stored:
            changes["added"].append(path)
        elif stored[path] != h:
            changes["modified"].append(path)
    for path in stored:
        if path not in current:
            changes["removed"].append(path)
    if any(changes.values()):
        for f in changes["added"]:
            print(f"  + {f}")
        for f in changes["removed"]:
            print(f"  - {f}")
        for f in changes["modified"]:
            print(f"  ~ {f}")
        print(f"\n  Changes: +{len(changes['added'])} / -{len(changes['removed'])} / ~{len(changes['modified'])}")
    else:
        print("  [OK] All files intact.")


def _update(root):
    mpath = os.path.join(root, MANIFEST)
    if not os.path.exists(mpath):
        print(f"[ERR] No manifest found. Run 'clawkit integrity init' first.", file=sys.stderr)
        sys.exit(1)
    _init(root)


def _report(root):
    mpath = os.path.join(root, MANIFEST)
    if not os.path.exists(mpath):
        print(f"[ERR] No manifest found.", file=sys.stderr)
        sys.exit(1)
    with open(mpath) as f:
        stored = json.load(f)
    current = _scan_dir(root)
    changes = {"added": [], "removed": [], "modified": []}
    for path, h in current.items():
        if path not in stored:
            changes["added"].append(path)
        elif stored[path] != h:
            changes["modified"].append(path)
    for path in stored:
        if path not in current:
            changes["removed"].append(path)

    rows = ""
    for path in changes["added"]:
        rows += f"<tr style='color:#4ade80'><td>+</td><td>{path}</td><td>NEW</td></tr>\n"
    for path in changes["removed"]:
        rows += f"<tr style='color:#f87171'><td>-</td><td>{path}</td><td>DELETED</td></tr>\n"
    for path in changes["modified"]:
        rows += f"<tr style='color:#fbbf24'><td>~</td><td>{path}</td><td>MODIFIED</td></tr>\n"

    html = report_header("Integrity Report", "Warden — File Integrity Monitor")
    html += f"""<div class="grid">
<div class="stat"><div class="stat-value">{len(stored)}</div><div class="stat-label">Tracked Files</div></div>
<div class="stat"><div class="stat-value" style="color:#4ade80">{len(changes['added'])}</div><div class="stat-label">Added</div></div>
<div class="stat"><div class="stat-value" style="color:#f87171">{len(changes['removed'])}</div><div class="stat-label">Removed</div></div>
<div class="stat"><div class="stat-value" style="color:#fbbf24">{len(changes['modified'])}</div><div class="stat-label">Modified</div></div>
</div>
<table><thead><tr><th>Change</th><th>File</th><th>Status</th></tr></thead><tbody>{rows}</tbody></table>"""
    html += report_footer()
    out = os.path.join(root, "integrity-report.html")
    with open(out, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"[OK] Report: {out}")
