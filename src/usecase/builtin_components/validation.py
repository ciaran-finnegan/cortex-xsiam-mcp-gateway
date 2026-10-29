import logging
from typing import Annotated, Any

from fastmcp import Context, FastMCP
from pydantic import Field

from usecase.base_module import BaseModule
from usecase.identity import resolve_mcp_context
from usecase.xql_validation import validate_query

logger = logging.getLogger(__name__)


async def validate_xql(
    ctx: Context,
    query: Annotated[str, Field(description="Raw XQL to check. It is not run unless probe is true.")],
    timeframe: Annotated[
        dict | None,
        Field(
            description=(
                "Window the query will run over: {'from_ms': <epoch ms>, 'to_ms': <epoch ms>} or "
                "{'relative_ms': <ms>}. The XSIAM API keys from, to and relativeTime are also accepted."
            )
        ),
    ] = None,
    probe: Annotated[
        bool,
        Field(
            description=(
                "After the static checks pass, run the query over one hour with '| limit 1' and report success "
                "or the classified error. Costs about a thousandth of a query unit. Requires the raw-XQL grant."
            )
        ),
    ] = False,
) -> dict[str, Any]:
    """
    Check raw XQL before it spends quota, and return the problems found with deterministic fixes.

    Checks: comments stripped; a terminal '| limit N'; the dataset exists and dataset policy allows it;
    field names in filter, fields, alter, comp ... by, sort and dedup stages exist in the discovered
    schema; '=' or '!=' on an enum-backed field (suggests contains); contains on an IPv4 or IPv6 literal
    (suggests in); a missing or over-long timeframe. Returns ok, problems (code, severity, message,
    field, suggestion, docs), corrected_query built only by fixed rewrites, and a cost estimate when the
    cost guard is installed.

    The query itself never runs unless probe is true. Field discovery samples the dataset at most once
    an hour. Each problem's docs URL is a page on the vendor's public Cortex documentation site; clients
    connected to the Cortex documentation MCP server should fetch that page rather than rely on the
    summary. The gateway itself never contacts the documentation site.
    """
    principal = resolve_mcp_context(ctx)
    try:
        return await validate_query(ctx, principal, query, timeframe=timeframe, probe=probe)
    except ValueError as e:
        return {"success": False, "executed": False, "error": str(e)}
    except Exception as e:
        logger.exception("XQL validation failed: %s", type(e).__name__)
        return {"success": False, "executed": False, "error": f"XQL validation failed: {type(e).__name__}"}


class XQLValidationModule(BaseModule):
    def register_tools(self):
        self._add_tool(validate_xql)

    def register_resources(self):
        pass

    def __init__(self, mcp: FastMCP):
        super().__init__(mcp)
