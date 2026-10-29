"""Links into the vendor's public Cortex documentation for agent-facing XQL guidance.

The gateway only returns these URLs; it never fetches the documentation site. Clients that also
connect the documentation MCP server (``CORTEX_DOCS_MCP_URL``) can fetch a page themselves.
Paths come from ``https://cortex-docs.paloaltonetworks.com/llms.txt``; appending ``.md`` to any
URL returns a Markdown copy of the page.
"""

CORTEX_DOCS_BASE_URL = "https://cortex-docs.paloaltonetworks.com"
CORTEX_DOCS_MCP_URL = f"{CORTEX_DOCS_BASE_URL}/~gitbook/mcp"

_STAGES = "/xql-command-reference-guide/readme/stages"
_XQL = "/cortex-xsiam/reference-and-developer-docs/cortex-agentix-xql"
_BUILD = f"{_XQL}/build-xql-queries/how-to-build-xql-queries"

XQL_DOCS: dict[str, str] = {
    name: CORTEX_DOCS_BASE_URL + path
    for name, path in {
        "language_structure": f"{_XQL}/get-started-with-xql/xql-language-structure",
        "supported_operators": f"{_XQL}/get-started-with-xql/supported-operators",
        "datasets_and_presets": f"{_XQL}/get-started-with-xql/datasets-and-presets",
        "best_practices": f"{_BUILD}/xql-query-best-practices",
        "expected_results": f"{_BUILD}/expected-results-when-querying-fields",
        "stage_alter": f"{_STAGES}/alter",
        "stage_bin": f"{_STAGES}/bin",
        "stage_comp": f"{_STAGES}/comp",
        "stage_dataset": f"{_STAGES}/dataset",
        "stage_dedup": f"{_STAGES}/dedup",
        "stage_fields": f"{_STAGES}/fields",
        "stage_filter": f"{_STAGES}/filter",
        "stage_limit": f"{_STAGES}/limit",
        "stage_sort": f"{_STAGES}/sort",
        "schema_reference": "/xql-schema-reference",
        "xql_query_api": "/xsiam-api/cortex-platform/xql-query",
    }.items()
}

# One page per get_xql_help topic. Topics without an entry fall back to the language overview.
XQL_HELP_TOPIC_DOCS: dict[str, str] = {
    "workflow": XQL_DOCS["best_practices"],
    "filters": XQL_DOCS["stage_filter"],
    "aggregations": XQL_DOCS["stage_comp"],
    "top_values": XQL_DOCS["stage_comp"],
    "time_trends": XQL_DOCS["stage_bin"],
    "pagination": XQL_DOCS["stage_sort"],
    "raw_xql": XQL_DOCS["language_structure"],
}

# One page per validate_xql problem code and per classified XSIAM error class.
XQL_PROBLEM_DOCS: dict[str, str] = {
    "query_invalid": XQL_DOCS["language_structure"],
    "missing_limit": XQL_DOCS["stage_limit"],
    "limit_invalid": XQL_DOCS["stage_limit"],
    "limit_clamped": XQL_DOCS["stage_limit"],
    "no_dataset": XQL_DOCS["stage_dataset"],
    "dataset_unresolved": XQL_DOCS["datasets_and_presets"],
    "dataset_not_allowed": XQL_DOCS["datasets_and_presets"],
    "unknown_dataset": XQL_DOCS["datasets_and_presets"],
    "unknown_field": XQL_DOCS["schema_reference"],
    "field_check_skipped": XQL_DOCS["expected_results"],
    "enum_equality": XQL_DOCS["supported_operators"],
    "contains_on_address": XQL_DOCS["supported_operators"],
    "timeframe_missing": XQL_DOCS["xql_query_api"],
    "timeframe_invalid": XQL_DOCS["xql_query_api"],
    "timeframe_too_long": XQL_DOCS["best_practices"],
    "timeframe_exceeds_mode_window": XQL_DOCS["best_practices"],
    "config_timeframe": XQL_DOCS["best_practices"],
    "syntax_error": XQL_DOCS["language_structure"],
    "type_mismatch": XQL_DOCS["supported_operators"],
    "probe_failed": XQL_DOCS["language_structure"],
}

DOCS_GUIDANCE = (
    "Each docs URL is a page on the vendor's public Cortex documentation site. Clients connected to the "
    f"Cortex documentation MCP server ({CORTEX_DOCS_MCP_URL}) should fetch that page rather than rely on this "
    "summary; append .md to a URL for Markdown. The gateway itself never contacts the documentation site."
)


def help_topic_docs(topic: str) -> str:
    return XQL_HELP_TOPIC_DOCS.get(topic, XQL_DOCS["language_structure"])


def problem_docs(code: str) -> str:
    return XQL_PROBLEM_DOCS.get(code, XQL_DOCS["language_structure"])
