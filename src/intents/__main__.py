import argparse
import asyncio
import json
import logging
import sys

from config.config import get_config
from intents.labels import run_label
from intents.review import run_review
from intents.sessions import run_sessions
from pkg.setup_logging import setup_logging

logger = logging.getLogger("cortex_xsiam_mcp.intents")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m intents",
        description="Pilot: label what the authors of past XQL queries were trying to achieve. Started by an operator.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    sessions = commands.add_parser("sessions", help="Read the query history into sessions. Calls no model.")
    sessions.add_argument("--days", type=int, required=True, help="Days of query history to read. Fixed by the first run.")
    sessions.add_argument("--max-units", type=float, required=True, help="Compute units this invocation may spend.")
    label = commands.add_parser("label", help="Send sessions to the configured provider and validate the replies.")
    label.add_argument("--max-sessions", type=int, default=50, help="Sessions to send in this invocation (default 50).")
    label.add_argument("--min-steps", type=int, default=2, help="Skip sessions with fewer steps than this (default 2).")
    label.add_argument("--dry-run", action="store_true", help="Write the prompts to intents/dry_run.json and send nothing.")
    commands.add_parser("review", help="Write intents/review.csv and report precision from the verdicts in it.")
    args = parser.parse_args(argv)
    setup_logging(get_config())
    try:
        if args.command == "sessions":
            report = asyncio.run(run_sessions(args.days, args.max_units))
        elif args.command == "label":
            report = asyncio.run(run_label(args.max_sessions, args.min_steps, dry_run=args.dry_run))
        else:
            report = run_review()
    except Exception as e:
        logger.error("Intent pilot %s failed: %s", args.command, type(e).__name__)
        print(json.dumps({"command": args.command, "error": type(e).__name__}), file=sys.stderr)
        return 2
    print(json.dumps(report, sort_keys=True, default=str))
    return 1 if report.get("stopped") is not None or report.get("refused") is not None else 0


if __name__ == "__main__":
    raise SystemExit(main())
