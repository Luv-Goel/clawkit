"""clawkit data — Tabular data CLI (tally)."""

import os
import sys
import json
import csv
import io
from collections import defaultdict


def register(sub):
    p = sub.add_parser("data", help="Tabular data CLI", description="Select, filter, sort, group, join, stats for CSV/TSV/JSON data")
    p.add_argument("action", choices=["select", "filter", "sort", "head", "sample", "group", "join", "stats", "validate"], help="Action")
    p.add_argument("file", help="Data file (CSV/TSV/JSON)")
    p.add_argument("--columns", help="Column selection (comma-separated)")
    p.add_argument("--query", help="Filter expression (e.g. 'age > 25')")
    p.add_argument("--by", help="Column to sort/group by")
    p.add_argument("--desc", action="store_true", help="Descending sort")
    p.add_argument("--agg", help="Aggregation (e.g. 'avg(salary),count(*)')")
    p.add_argument("--file2", help="Second file for join")
    p.add_argument("--on", help="Join key column")
    p.add_argument("--limit", type=int, default=10, help="Row limit")
    p.add_argument("--format", choices=["table", "csv", "json"], default="table", help="Output format")
    p.add_argument("--schema", help="JSON schema for validation")
    return p


def run(args):
    if not os.path.exists(args.file):
        print(f"[ERR] File not found: {args.file}", file=sys.stderr)
        sys.exit(1)
    records = _load(args.file)
    if args.action == "select":
        _select(records, args.columns, args.format)
    elif args.action == "filter":
        _filter(records, args.query, args.format)
    elif args.action == "sort":
        _sort(records, args.by, args.desc, args.format)
    elif args.action == "head":
        _head(records, args.limit, args.format)
    elif args.action == "sample":
        _sample(records, args.limit, args.format)
    elif args.action == "group":
        _group(records, args.by, args.agg, args.format)
    elif args.action == "join":
        if not args.file2 or not args.on:
            print("[ERR] join requires --file2 and --on", file=sys.stderr)
            sys.exit(1)
        records2 = _load(args.file2)
        _join(records, records2, args.on, args.format)
    elif args.action == "stats":
        _stats(records, args.columns)
    elif args.action == "validate":
        schema = json.loads(args.schema) if args.schema else {}
        _validate(records, schema)


def _load(path):
    ext = os.path.splitext(path)[1].lower()
    if ext == ".json":
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else [data]
    delim = "\t" if ext == ".tsv" else ","
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        return list(reader)


def _format_output(records, fmt="table"):
    if not records:
        print("  [OK] No records.")
        return
    if fmt == "json":
        print(json.dumps(records, indent=2))
    elif fmt == "csv":
        keys = list(records[0].keys())
        w = csv.writer(sys.stdout)
        w.writerow(keys)
        for r in records:
            w.writerow([r.get(k, "") for k in keys])
    else:
        keys = list(records[0].keys())
        col_widths = {k: max(len(k), max((len(str(r.get(k, ""))) for r in records), default=0)) for k in keys}
        sep = "+".join("-" * (w + 2) for w in col_widths.values())
        header = "| " + " | ".join(k.ljust(col_widths[k]) for k in keys) + " |"
        print(sep)
        print(header)
        print(sep)
        for r in records:
            row = "| " + " | ".join(str(r.get(k, "")).ljust(col_widths[k]) for k in keys) + " |"
            print(row)
        print(sep)
        print(f"  ({len(records)} rows)")


def _select(records, columns, fmt):
    if not columns:
        _format_output(records, fmt)
        return
    cols = [c.strip() for c in columns.split(",")]
    result = [{k: r[k] for k in cols if k in r} for r in records]
    _format_output(result, fmt)


def _filter(records, query, fmt):
    if not query:
        _format_output(records, fmt)
        return
    result = []
    for r in records:
        try:
            if eval(query, {"__builtins__": {}}, {k: _to_num(v) for k, v in r.items()}):
                result.append(r)
        except:
            pass
    _format_output(result, fmt)


def _to_num(v):
    try:
        return int(v)
    except:
        try:
            return float(v)
        except:
            return v


def _sort(records, by, desc, fmt):
    if not by:
        _format_output(records, fmt)
        return
    result = sorted(records, key=lambda r: _to_num(r.get(by, "")), reverse=desc)
    _format_output(result, fmt)


def _head(records, limit, fmt):
    _format_output(records[:limit], fmt)


def _sample(records, limit, fmt):
    import random
    result = random.sample(records, min(limit, len(records)))
    _format_output(result, fmt)


def _group(records, by, agg, fmt):
    if not by:
        print("[ERR] --by is required for group", file=sys.stderr)
        return
    groups = defaultdict(list)
    for r in records:
        groups[r.get(by, "")].append(r)
    if agg:
        result = []
        for key, group in groups.items():
            row = {by: key}
            for ag in agg.split(","):
                ag = ag.strip()
                if ag.startswith("avg("):
                    col = ag[4:-1]
                    vals = [_to_num(r.get(col, 0)) for r in group]
                    row[f"avg({col})"] = sum(vals) / len(vals) if vals else 0
                elif ag.startswith("count("):
                    row[ag] = len(group)
                elif ag.startswith("sum("):
                    col = ag[4:-1]
                    row[ag] = sum(_to_num(r.get(col, 0)) for r in group)
                elif ag.startswith("min("):
                    col = ag[4:-1]
                    row[ag] = min(_to_num(r.get(col, 0)) for r in group)
                elif ag.startswith("max("):
                    col = ag[4:-1]
                    row[ag] = max(_to_num(r.get(col, 0)) for r in group)
            result.append(row)
        _format_output(result, fmt)
    else:
        for key, group in groups.items():
            print(f"\n  [{key}] ({len(group)} rows)")
            _format_output(group[:5], fmt)


def _join(records1, records2, on, fmt):
    result = []
    for r1 in records1:
        k1 = r1.get(on, "")
        for r2 in records2:
            k2 = r2.get(on, "")
            if k1 == k2:
                merged = {**r1, **r2}
                result.append(merged)
    _format_output(result, fmt)


def _stats(records, column=None):
    if not records:
        return
    keys = [column] if column else list(records[0].keys())
    for k in keys:
        vals = [_to_num(r.get(k, 0)) for r in records if _to_num(r.get(k, 0)) != r.get(k, 0) or True]
        nums = [v for v in [_to_num(r.get(k, 0)) for r in records] if isinstance(v, (int, float))]
        if nums:
            print(f"  {k}:")
            print(f"    count: {len(nums)}")
            print(f"    mean:  {sum(nums)/len(nums):.2f}")
            print(f"    min:   {min(nums)}")
            print(f"    max:   {max(nums)}")
            print(f"    range: {max(nums)-min(nums)}")
        else:
            unique = set(str(r.get(k, "")) for r in records)
            print(f"  {k}: {len(unique)} unique values")


def _validate(records, schema):
    errors = 0
    for i, r in enumerate(records):
        for field, ftype in schema.items():
            val = r.get(field, "")
            if ftype == "int":
                try:
                    int(val)
                except:
                    print(f"  row {i+1}: {field} expected int, got '{val}'")
                    errors += 1
            elif ftype == "float":
                try:
                    float(val)
                except:
                    print(f"  row {i+1}: {field} expected float, got '{val}'")
                    errors += 1
            elif ftype == "str":
                if not isinstance(val, str):
                    print(f"  row {i+1}: {field} expected str")
                    errors += 1
    if errors == 0:
        print(f"  [OK] {len(records)} rows validated successfully.")
    else:
        print(f"  [WARN] {errors} validation errors.")
