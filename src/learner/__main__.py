import argparse
import asyncio
import json
import logging
import sys

from config.config import get_config
from pkg.setup_logging import setup_logging
from usecase import learner

logger = logging.getLogger("cortex_xsiam_mcp.learner")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m learner",
        description="Fold the learning journal into tier-1 fact files and run scheduled learning jobs (UTC).",
    )
    parser.add_argument(
        "command",
        nargs="?",
        default="tick",
        choices=(*learner.COMMANDS, "backfill"),
        help="tick (default, run every few minutes), nightly, weekly, canary (on deploy), status, or backfill (once).",
    )
    parser.add_argument("--days", type=int, help="backfill only: days of query history to read. Fixed by the first run.")
    parser.add_argument("--max-units", type=float, help="backfill only: compute units this invocation may spend.")
    args = parser.parse_args(argv)
    backfill = args.command == "backfill"
    if backfill and (args.days is None or args.max_units is None):
        parser.error("backfill requires --days and --max-units")
    if not backfill and (args.days is not None or args.max_units is not None):
        parser.error("--days and --max-units apply only to backfill")
    setup_logging(get_config())
    try:
        report = asyncio.run(learner.run_backfill(args.days, args.max_units) if backfill else learner.run(args.command))
    except Exception as e:
        logger.error("Learner %s failed: %s", args.command, type(e).__name__)
        print(json.dumps({"command": args.command, "error": type(e).__name__}), file=sys.stderr)
        return 2
    print(json.dumps(report, sort_keys=True, default=str))
    failed = report.get("stopped") is not None if backfill else args.command == "canary" and report.get("ok") is False
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
