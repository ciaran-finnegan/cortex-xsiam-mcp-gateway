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
        choices=learner.COMMANDS,
        help="tick (default, run every few minutes), nightly, weekly, canary (on deploy), or status.",
    )
    args = parser.parse_args(argv)
    setup_logging(get_config())
    try:
        report = asyncio.run(learner.run(args.command))
    except Exception as e:
        logger.error("Learner %s failed: %s", args.command, type(e).__name__)
        print(json.dumps({"command": args.command, "error": type(e).__name__}), file=sys.stderr)
        return 2
    print(json.dumps(report, sort_keys=True, default=str))
    return 1 if args.command == "canary" and report.get("ok") is False else 0


if __name__ == "__main__":
    raise SystemExit(main())
