import logging
from typing import Annotated, Any

from fastmcp import Context, FastMCP
from pydantic import Field

from entities.exceptions import (
    PAPIAuthenticationError,
    PAPIClientError,
    PAPIClientRequestError,
    PAPIConnectionError,
    PAPIResponseError,
    PAPIServerError,
)
from usecase.base_module import BaseModule
from usecase.dataset_catalogue import (
    DEFAULT_FIND_RESULTS,
    MAX_FIND_RESULTS,
    MAX_TOPIC_CHARS,
    CatalogueError,
    DatasetDomain,
    EntityType,
    get_catalogue,
    search_catalogue,
)
from usecase.fetcher import get_fetcher
from usecase.identity import resolve_mcp_context
from usecase.log_policy import ALL_DATASETS, authorize_dataset
from usecase.xql_discovery import parse_dataset_reply

logger = logging.getLogger(__name__)

_PAPI_ERRORS = (
    PAPIConnectionError,
    PAPIAuthenticationError,
    PAPIServerError,
    PAPIClientRequestError,
    PAPIResponseError,
    PAPIClientError,
)

_GUIDANCE = (
    "Pick one dataset, then call discover_log_fields to confirm the candidate field names before query_dataset. "
    "Catalogue field names are candidates, not guarantees. When query_hint is aggregate_first, answer with an "
    "aggregate and a bounded timeframe before requesting rows."
)


async def _allowed_dataset_names(ctx: Context, principal) -> tuple[list[str], str, str | None]:
    """Return dataset names the principal may query, the source used, and an optional warning.

    Dataset policy is applied here, before any catalogue lookup, so catalogue text is never
    returned for a dataset the principal cannot query.
    """
    try:
        fetcher = await get_fetcher(ctx)
        response_data = await fetcher.send_request("/xql/get_datasets", data={"request_data": {}})
        names = [record["dataset_name"] for record in parse_dataset_reply(response_data)]
        source, warning = "xsiam_api", None
    except (*_PAPI_ERRORS, ValueError) as e:
        logger.warning("find_datasets could not list XSIAM datasets; using policy names: %s", type(e).__name__)
        decision = authorize_dataset(principal, ALL_DATASETS)
        names = [name for name in decision.allowed_datasets if name != ALL_DATASETS]
        source = "dataset_policy_fallback"
        warning = "XSIAM dataset listing is unavailable; results are limited to dataset names written in policy."
    return [name for name in names if authorize_dataset(principal, name).allowed], source, warning


async def find_datasets(
    ctx: Context,
    topic: Annotated[
        str | None,
        Field(
            description="Plain words for what the user is asking about, for example 'firewall traffic', 'sign-in failures', or 'aws audit'.",
            max_length=MAX_TOPIC_CHARS,
        ),
    ] = None,
    domain: Annotated[DatasetDomain | None, Field(description="Optional exact catalogue domain filter.")] = None,
    entity_type: Annotated[
        EntityType | None,
        Field(description="Only return datasets with a known field for this kind of entity, and list those fields."),
    ] = None,
    max_results: Annotated[int, Field(description=f"Maximum datasets to return. Capped at {MAX_FIND_RESULTS}.")] = DEFAULT_FIND_RESULTS,
    offset: Annotated[int, Field(description="Matches to skip. Pass the returned next_offset to read the next page.")] = 0,
) -> dict[str, Any]:
    """Find datasets the current principal may query by topic, domain, or the kind of entity they can identify."""
    try:
        principal = resolve_mcp_context(ctx)
        catalogue = get_catalogue()
        allowed_names, source, warning = await _allowed_dataset_names(ctx, principal)
        result = search_catalogue(
            allowed_names,
            topic=topic,
            domain=domain,
            entity_type=entity_type,
            max_results=max_results,
            offset=offset,
            catalogue=catalogue,
        )
        response: dict[str, Any] = {
            "success": True,
            "source": source,
            "allowed_dataset_count": len(allowed_names),
            **result,
            "content_trust": "authored_catalogue",
            "guidance": _GUIDANCE,
        }
        if warning:
            response["warning"] = warning
        return response
    except CatalogueError as e:
        logger.error("Dataset catalogue is invalid: %s", e)
        return {"success": False, "error": "Dataset catalogue is misconfigured; contact the gateway operator."}
    except ValueError as e:
        return {"success": False, "error": str(e)}
    except Exception as e:
        logger.exception("find_datasets failed: %s", type(e).__name__)
        return {"success": False, "error": f"Dataset search failed: {type(e).__name__}"}


class DatasetCatalogueModule(BaseModule):
    """Topic and entity based dataset selection backed by the authored catalogue."""

    def register_tools(self):
        self._add_tool(find_datasets)

    def register_resources(self):
        pass

    def __init__(self, mcp: FastMCP):
        super().__init__(mcp)
