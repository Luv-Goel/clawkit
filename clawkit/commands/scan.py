"""clawkit scan — Duplicate file finder (sift)."""

import os
import sys
import hashlib
import fnmatch
from collections import defaultdict
from ..utils.html import report_header, report_footer

SKIP_DIRS = {".git", ".svn", "__pycache__", "node_modules", ".venv", ".eggs", "dist", "build"}
SKIP_EXTS = {".pyc", ".o", ".so", ".dll", ".dylib", ".exe"}


def register(sub):
    p = sub.add_parser("scan", help="Duplicate file finder", description="Find duplicate files by content hash")
    p.add_argument("path", nargs="?", default=".", help="Directory to scan")
    p.add_argument("--min-size", type=int, default=0, help="Minimum file size in bytes")
    p.add_argument("--exclude", action="append", default=[], help="Exclude pattern (fnmatch)")
    p.add_argument("--report", metavar="FILE", help="Generate HTML report")
    p.add_argument("--dedupe", choices=["dry-run", "execute"], help="Deduplicate mode")
    return p


def run(args):
    if not os.path.isdir(args.path):
        print(f"[ERR] Directory not found: {args.path}", file=sys.stderr)
        sys.exit(1)

    duplicates = _scan(args.path, args.min_size, args.exclude)

    if args.dedupe:
        _dedupe(duplicates, args.dedupe == "execute")
    else:
        print(_format(duplicates))
        if args.report:
            _report(duplicates, args.report)
            print(f"[OK] Report: {args.report}", file=sys.stderr)


def _hash_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _scan(root, min_size=0, exclude_patterns=None):
    exclude = exclude_patterns or []

    def is_excluded(name):
        for pat in exclude:
            if fnmatch.fnmatch(name, pat):
                return True
        return False

    by_size = defaultdict(list)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            if is_excluded(fn):
                continue
            path = os.path.join(dirpath, fn)
            ext = os.path.splitext(fn)[1].lower()
            if ext in SKIP_EXTS:
                continue
            try:
                size = os.path.getsize(path)
                if size >= min_size:
                    by_size[size].append(path)
            except OSError:
                pass

    by_hash = defaultdict(list)
    for size, paths in by_size.items():
        if len(paths) < 2:
            continue
        for path in paths:
            try:
                by_hash[_hash_file(path)].append({"path": path, "size": size})
            except OSError:
                pass

    duplicates = {}
    for file_hash, files in by_hash.items():
        if len(files) >= 2:
            duplicates[file_hash] = {
                "hash": file_hash, "size": files[0]["size"],
                "total_size": files[0]["size"] * len(files),
                "wasted_size": files[0]["size"] * (len(files) - 1),
                "files": [f["path"] for f in files], "count": len(files),
            }
    return duplicates


def _format(duplicates, max_groups=50):
    if not duplicates:
        return "  [OK] No duplicates found."
    sorted_groups = sorted(duplicates.values(), key=lambda g: g["wasted_size"], reverse=True)
    total_wasted = sum(g["wasted_size"] for g in sorted_groups)
    lines = ["=" * 56, "  Duplicate File Scan", "=" * 56]
    lines.append(f"  Duplicate groups: {len(sorted_groups)}")
    lines.append(f"  Total wasted space: {total_wasted:,} bytes ({total_wasted/1024/1024:.1f} MB)\n")
    for g in sorted_groups[:max_groups]:
        lines.append(f"  [{g['hash'][:12]}...] {g['size']:,} bytes x {g['count']}")
        lines.append(f"    Wasted: {g['wasted_size']:,} bytes")
        for path in g['files']:
            lines.append(f"      {path}")
        lines.append("")
    if len(sorted_groups) > max_groups:
        lines.append(f"  ... and {len(sorted_groups) - max_groups} more groups")
    return "\n".join(lines)


def _report(duplicates, output_path):
    sorted_groups = sorted(duplicates.values(), key=lambda g: g["wasted_size"], reverse=True)
    total_wasted = sum(g["wasted_size"] for g in sorted_groups)
    rows = ""
    for g in sorted_groups[:100]:
        files_html = "<br>".join(g['files'][:5])
        if len(g['files']) > 5:
            files_html += f"<br>... +{len(g['files'])-5} more"
        rows += f"<tr><td><code>{g['hash'][:12]}...</code></td><td>{g['count']}</td><td>{g['size']:,}</td><td>{g['wasted_size']:,}</td><td style='font-size:0.8rem'>{files_html}</td></tr>\n"
    html = report_header("Duplicate File Report", "Sift — Duplicate File Finder")
    html += f"""<div class="grid">
<div class="stat"><div class="stat-value">{len(sorted_groups)}</div><div class="stat-label">Duplicate Groups</div></div>
<div class="stat"><div class="stat-value">{sum(g['count']-1 for g in sorted_groups)}</div><div class="stat-label">Duplicate Files</div></div>
<div class="stat"><div class="stat-value">{total_wasted/1024/1024:.1f} MB</div><div class="stat-label">Wasted Space</div></div>
</div>
<table><thead><tr><th>Hash</th><th>Copies</th><th>Size</th><th>Wasted</th><th>Locations</th></tr></thead><tbody>{rows}</tbody></table>"""
    html += report_footer()
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)


def _dedupe(duplicates, execute=False):
    total_freed = 0
    total_removed = 0
    for h, group in sorted(duplicates.items(), key=lambda x: x[1]["wasted_size"], reverse=True):
        for dup in group["files"][1:]:
            total_freed += group["size"]
            total_removed += 1
            if execute:
                try:
                    os.remove(dup)
                    print(f"  Removed: {dup}")
                except OSError as e:
                    print(f"  [ERR] Could not remove {dup}: {e}", file=sys.stderr)
            else:
                print(f"  Would remove: {dup}")
    if not execute:
        print(f"\n[Dry Run] Would free {total_freed:,} bytes across {total_removed} files")
    else:
        print(f"\n[OK] Freed {total_freed:,} bytes across {total_removed} files")
