import logging
from typing import Annotated, Any

from fastmcp import Context, FastMCP
from pydantic import Field

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
from usecase.helper_runtime import allowed_dataset_names
from usecase.identity import resolve_mcp_context

logger = logging.getLogger(__name__)

_GUIDANCE = (
    "Pick one dataset, then call discover_log_fields to confirm the candidate field names before query_dataset. "
    "Catalogue field names are candidates, not guarantees. When query_hint is aggregate_first, answer with an "
    "aggregate and a bounded timeframe before requesting rows."
)


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
        allowed_names, source, warning = await allowed_dataset_names(ctx, principal)
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
