"""clawkit dotenv — .env file toolkit."""

import os
import sys
import re


def register(sub):
    p = sub.add_parser("dotenv", help=".env file toolkit", description="Load, validate, merge, diff, template, sort .env files")
    p.add_argument("action", choices=["load", "check", "merge", "diff", "template", "sort"], help="Action")
    p.add_argument("files", nargs="+", help=".env file(s)")
    p.add_argument("--output", "-o", help="Output file")
    p.add_argument("--against", help="Reference file (for check)")
    return p


def run(args):
    if args.action == "load":
        _load(args.files[0])
    elif args.action == "check":
        _check(args.files[0], args.against)
    elif args.action == "merge":
        _merge(args.files, args.output)
    elif args.action == "diff":
        _diff(args.files[0], args.files[1])
    elif args.action == "template":
        _template(args.files[0], args.output)
    elif args.action == "sort":
        _sort(args.files[0], args.output)


def _parse(text):
    vars = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip().strip("'\"").strip()
        vars[key] = val
    return vars


def _load(path):
    if not os.path.exists(path):
        print(f"[ERR] File not found: {path}", file=sys.stderr)
        sys.exit(1)
    with open(path) as f:
        vars = _parse(f.read())
    for k, v in vars.items():
        print(f"{k}={v}")


def _check(path, against=None):
    if not os.path.exists(path):
        print(f"[ERR] File not found: {path}", file=sys.stderr)
        sys.exit(1)
    with open(path) as f:
        content = f.read()
    vars = _parse(content)
    errors = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            errors.append(f"Invalid syntax: {line}")
    if against and os.path.exists(against):
        with open(against) as f:
            schema = _parse(f.read())
        for k in schema:
            if k not in vars:
                errors.append(f"Missing variable: {k}")
    if errors:
        for e in errors:
            print(f"  [WARN] {e}")
    else:
        print("  [OK] No issues found.")


def _merge(files, output):
    merged = {}
    for f in files:
        if os.path.exists(f):
            with open(f) as fh:
                merged.update(_parse(fh.read()))
    out_lines = [f"{k}={v}" for k, v in sorted(merged.items())]
    output_text = "\n".join(out_lines)
    if output:
        with open(output, "w") as f:
            f.write(output_text)
        print(f"[OK] Merged {len(files)} files -> {output}")
    else:
        print(output_text)


def _diff(a, b):
    if not os.path.exists(a) or not os.path.exists(b):
        print("[ERR] Both files must exist", file=sys.stderr)
        sys.exit(1)
    with open(a) as f:
        va = _parse(f.read())
    with open(b) as f:
        vb = _parse(f.read())
    all_keys = set(va) | set(vb)
    added = sorted(set(vb) - set(va))
    removed = sorted(set(va) - set(vb))
    changed = sorted(k for k in all_keys if k in va and k in vb and va[k] != vb[k])
    for k in added:
        print(f"  + {k}={vb[k]}")
    for k in removed:
        print(f"  - {k}={va[k]}")
    for k in changed:
        print(f"  ~ {k}: {va[k]} -> {vb[k]}")
    if not (added or removed or changed):
        print("  [OK] Files are identical.")


def _template(path, output):
    if not os.path.exists(path):
        print(f"[ERR] File not found: {path}", file=sys.stderr)
        sys.exit(1)
    with open(path) as f:
        content = f.read()
    vars = _parse(content)
    result = re.sub(r"\{\{(\w+)\}\}", lambda m: vars.get(m.group(1), m.group(0)), content)
    if output:
        with open(output, "w") as f:
            f.write(result)
        print(f"[OK] Template rendered -> {output}")
    else:
        print(result)


def _sort(path, output):
    if not os.path.exists(path):
        print(f"[ERR] File not found: {path}", file=sys.stderr)
        sys.exit(1)
    with open(path) as f:
        content = f.read()
    vars = _parse(content)
    lines = [f"{k}={v}" for k, v in sorted(vars.items())]
    result = "\n".join(lines)
    if output:
        with open(output, "w") as f:
            f.write(result)
        print(f"[OK] Sorted -> {output}")
    else:
        print(result)
