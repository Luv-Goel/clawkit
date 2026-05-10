"""clawkit — Unified CLI entry point."""

import argparse
import sys
from . import __version__
from .commands import scan, dotenv, integrity, audit, markdown, data, logs, secrets


COMMANDS = {
    "scan": scan,
    "dotenv": dotenv,
    "integrity": integrity,
    "audit": audit,
    "markdown": markdown,
    "data": data,
    "logs": logs,
    "secrets": secrets,
}


def main():
    parser = argparse.ArgumentParser(
        prog="clawkit",
        description="Unified DevOps CLI toolkit — 8 tools in one.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Commands:
  scan        Duplicate file finder (sift)
  dotenv      .env file toolkit
  integrity   File integrity monitor (warden)
  audit       Security permissions auditor (perm)
  markdown    Markdown toolkit (mark)
  data        Tabular data CLI (tally)
  logs        Log file forensics (logsmith)
  secrets     Code secret scanner (vault)

Use 'clawkit <command> --help' for detailed help on each command.
        """,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    for name, mod in COMMANDS.items():
        mod.register(sub)

    args = parser.parse_args()
    mod = COMMANDS[args.command]
    mod.run(args)


if __name__ == "__main__":
    main()
