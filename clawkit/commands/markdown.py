"""clawkit markdown — Markdown toolkit (mark)."""

import os
import sys
import re


def register(sub):
    p = sub.add_parser("markdown", help="Markdown toolkit", description="Generate TOC, lint, check links, format, stats for markdown files")
    p.add_argument("action", choices=["toc", "lint", "check-links", "format", "stats", "merge"], help="Action")
    p.add_argument("files", nargs="+", help="Markdown file(s)")
    p.add_argument("--output", "-o", help="Output file")
    return p


def run(args):
    if args.action == "toc":
        for f in args.files:
            _toc(f)
    elif args.action == "lint":
        for f in args.files:
            _lint(f)
    elif args.action == "check-links":
        for f in args.files:
            _check_links(f)
    elif args.action == "format":
        _format(args.files[0], args.output)
    elif args.action == "stats":
        for f in args.files:
            _stats(f)
    elif args.action == "merge":
        _merge(args.files, args.output)


def _read(path):
    if not os.path.exists(path):
        print(f"[ERR] File not found: {path}", file=sys.stderr)
        sys.exit(1)
    with open(path, encoding="utf-8") as f:
        return f.read()


def _toc(path):
    content = _read(path)
    headings = re.findall(r"^(#{1,6})\s+(.+?)$", content, re.MULTILINE)
    for hashes, title in headings:
        level = len(hashes) - 1
        slug = title.lower().replace(" ", "-").replace("`", "").replace("(", "").replace(")", "").replace(".", "")
        slug = re.sub(r"[^a-z0-9\-]", "", slug)
        indent = "  " * level
        print(f"{indent}- [{title}](#{slug})")


def _lint(path):
    content = _read(path)
    issues = []
    for i, line in enumerate(content.splitlines(), 1):
        # Trailing whitespace
        if line.rstrip() != line and line.strip():
            issues.append((i, "Trailing whitespace"))
        # Multiple spaces after list marker
        if re.match(r"^(\s*[-*+]|\s*\d+\.)\s{3,}", line):
            issues.append((i, "Too many spaces after list marker"))
        # Hard tabs
        if "\t" in line:
            issues.append((i, "Hard tab character"))
        # Broken link syntax
        if re.search(r"\[.*\]\((.*\s.*)\)", line):
            issues.append((i, "Space in URL"))
    if issues:
        for line, msg in issues:
            print(f"  {path}:{line} — {msg}")
    else:
        print(f"  [OK] No issues in {path}")


def _check_links(path):
    content = _read(path)
    links = re.findall(r"\[([^\]]+)\]\(([^)]+)\)", content)
    broken = 0
    for text, url in links:
        if url.startswith("http"):
            print(f"  [SKIP] {url} (external)")
        elif url.startswith("#"):
            anchor = url[1:]
            if anchor not in content:
                print(f"  [BROKEN] #{anchor} (anchor not found)")
                broken += 1
        else:
            base = os.path.dirname(path)
            target = os.path.join(base, url) if base else url
            if not os.path.exists(target):
                print(f"  [BROKEN] {url} (file not found)")
                broken += 1
    if broken == 0:
        print(f"  [OK] All local links valid in {path}")


def _format(path, output):
    content = _read(path)
    lines = content.splitlines()
    formatted = []
    for line in lines:
        line = line.rstrip()
        if line.startswith("#"):
            line = line.rstrip()
        formatted.append(line)
    result = "\n".join(formatted) + "\n"
    if output:
        with open(output, "w", encoding="utf-8") as f:
            f.write(result)
        print(f"[OK] Formatted -> {output}")
    else:
        print(result)


def _stats(path):
    content = _read(path)
    words = len(content.split())
    chars = len(content)
    lines = content.count("\n") + 1
    headings = len(re.findall(r"^#{1,6}\s", content, re.MULTILINE))
    links = len(re.findall(r"\[([^\]]+)\]", content))
    code_blocks = len(re.findall(r"```", content)) // 2
    reading_time_min = max(1, round(words / 200))
    print(f"  File: {path}")
    print(f"  Words: {words:,}")
    print(f"  Characters: {chars:,}")
    print(f"  Lines: {lines:,}")
    print(f"  Headings: {headings}")
    print(f"  Links: {links}")
    print(f"  Code blocks: {code_blocks}")
    print(f"  Reading time: ~{reading_time_min} min")


def _merge(files, output):
    merged = []
    for f in files:
        merged.append(_read(f))
    result = "\n\n---\n\n".join(merged)
    if output:
        with open(output, "w", encoding="utf-8") as fh:
            fh.write(result)
        print(f"[OK] Merged {len(files)} files -> {output}")
    else:
        print(result)
