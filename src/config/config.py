from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from pkg.util import REMOTE_DIR


class Settings(BaseSettings):
    """
    A simple, flat configuration model using Pydantic.
    It loads settings from environment variables.
    """

    # --- Server Settings ---
    mcp_transport: str = Field("stdio", validation_alias="MCP_TRANSPORT")
    mcp_host: str = Field("0.0.0.0", validation_alias="MCP_HOST")
    mcp_port: int = Field(8080, validation_alias="MCP_PORT")
    mcp_path: str = Field("/api/v1/stream/mcp", validation_alias="MCP_PATH")
    allow_unauthenticated_http: bool = Field(
        False,
        validation_alias="MCP_ALLOW_UNAUTHENTICATED_HTTP",
    )
    elicitation_enabled: bool = Field(False, validation_alias="MCP_ELICITATION_ENABLED")
    write_tools_enabled: bool = Field(False, validation_alias="MCP_WRITE_TOOLS_ENABLED")
    isolate_endpoint_tool_enabled: bool = Field(False, validation_alias="MCP_ISOLATE_ENDPOINT_TOOL_ENABLED")
    http_response_error_message_max_size: int = Field(1000, validation_alias="CORTEX_MCP_RESPONSE_ERROR_MAX_SIZE")

    # --- PAPI Settings ---
    papi_url_env_key: str = Field("", validation_alias="CORTEX_MCP_PAPI_URL")
    papi_auth_header_key: str = Field("", validation_alias="CORTEX_MCP_PAPI_AUTH_HEADER")
    papi_auth_id_key: str = Field("", validation_alias="CORTEX_MCP_PAPI_AUTH_ID")

    max_objects_to_retrieve: int = Field(50, validation_alias="MAX_OBJECTS_TO_RETRIEVE")

    # --- Log Settings ---
    log_enable_uvicorn_access_logs: bool = Field(True, validation_alias="LOG_ENABLE_UVICORN_ACCESS_LOGS")
    log_level: str = Field("INFO", validation_alias="LOG_LEVEL")

    # --- Log Search Authorization Settings ---
    log_search_default_principal_id: str = Field("service-account", validation_alias="LOG_SEARCH_DEFAULT_PRINCIPAL_ID")
    log_search_default_groups: str = Field("", validation_alias="LOG_SEARCH_DEFAULT_GROUPS")
    log_search_dataset_policy: str = Field(
        '{"Security": ["*"], "SOC": ["xdr_data"], "Tier1": ["xdr_data"]}',
        validation_alias="LOG_SEARCH_DATASET_POLICY",
    )
    raw_xql_privileged_groups: str = Field(
        "Security,Admin",
        validation_alias="RAW_XQL_PRIVILEGED_GROUPS",
    )
    tool_access_policy: str = Field(
        (
            '{"Admin":["*"],"Security":["*"],'
            '"SOC":["get_log_search_guidance","list_log_datasets","discover_log_fields","search_logs",'
            '"get_dataset_query_guidance","get_xql_help","query_dataset","continue_dataset_query",'
            '"get_xql_query_quota","get_cases","get_issues"],'
            '"Tier1":["get_log_search_guidance","list_log_datasets","discover_log_fields","search_logs",'
            '"get_dataset_query_guidance","get_xql_help","query_dataset","continue_dataset_query",'
            '"get_xql_query_quota","get_cases","get_issues"]}'
        ),
        validation_alias="TOOL_ACCESS_POLICY",
    )

    # --- Incoming Identity Settings ---
    identity_auth_mode: str = Field("none", validation_alias="MCP_IDENTITY_AUTH_MODE")
    entra_tenant_id: str = Field("", validation_alias="ENTRA_TENANT_ID")
    entra_issuer: str = Field("", validation_alias="ENTRA_ISSUER")
    entra_audience: str = Field("", validation_alias="ENTRA_AUDIENCE")
    entra_jwks_uri: str = Field("", validation_alias="ENTRA_JWKS_URI")
    entra_jwt_public_key: str = Field("", validation_alias="ENTRA_JWT_PUBLIC_KEY")
    entra_jwt_algorithm: str = Field("RS256", validation_alias="ENTRA_JWT_ALGORITHM")
    entra_required_scopes: str = Field("", validation_alias="ENTRA_REQUIRED_SCOPES")
    entra_principal_claims: str = Field(
        "preferred_username,upn,email,oid,sub",
        validation_alias="ENTRA_PRINCIPAL_CLAIMS",
    )
    entra_groups_claim: str = Field("groups", validation_alias="ENTRA_GROUPS_CLAIM")
    entra_roles_claim: str = Field("roles", validation_alias="ENTRA_ROLES_CLAIM")

    # --- Optional Trusted AI Gateway Identity Settings ---
    gateway_shared_secret: str = Field("", validation_alias="MCP_GATEWAY_SHARED_SECRET")
    gateway_allowed_issuers: str = Field("", validation_alias="MCP_GATEWAY_ALLOWED_ISSUERS")
    gateway_max_clock_skew_seconds: int = Field(
        300,
        validation_alias="MCP_GATEWAY_MAX_CLOCK_SKEW_SECONDS",
    )
    gateway_nonce_cache_size: int = Field(
        10000,
        ge=1,
        validation_alias="MCP_GATEWAY_NONCE_CACHE_SIZE",
    )
    gateway_principal_header: str = Field(
        "X-MCP-Gateway-Principal",
        validation_alias="MCP_GATEWAY_PRINCIPAL_HEADER",
    )
    gateway_groups_header: str = Field(
        "X-MCP-Gateway-Groups",
        validation_alias="MCP_GATEWAY_GROUPS_HEADER",
    )
    gateway_roles_header: str = Field(
        "X-MCP-Gateway-Roles",
        validation_alias="MCP_GATEWAY_ROLES_HEADER",
    )
    gateway_issuer_header: str = Field(
        "X-MCP-Gateway-Issuer",
        validation_alias="MCP_GATEWAY_ISSUER_HEADER",
    )
    gateway_timestamp_header: str = Field(
        "X-MCP-Gateway-Timestamp",
        validation_alias="MCP_GATEWAY_TIMESTAMP_HEADER",
    )
    gateway_nonce_header: str = Field(
        "X-MCP-Gateway-Nonce",
        validation_alias="MCP_GATEWAY_NONCE_HEADER",
    )
    gateway_signature_header: str = Field(
        "X-MCP-Gateway-Signature",
        validation_alias="MCP_GATEWAY_SIGNATURE_HEADER",
    )

    # --- XSIAM Credential Broker Settings ---
    xsiam_credential_broker_enabled: bool = Field(
        False,
        validation_alias="XSIAM_CREDENTIAL_BROKER_ENABLED",
    )
    xsiam_credential_profiles: str = Field(
        "{}",
        validation_alias="XSIAM_CREDENTIAL_PROFILES",
    )

    # --- Structured Dataset Query Settings ---
    dataset_query_max_rows: int = Field(
        100,
        ge=1,
        le=1000,
        validation_alias="DATASET_QUERY_MAX_ROWS",
    )
    dataset_query_max_fields: int = Field(25, validation_alias="DATASET_QUERY_MAX_FIELDS")
    dataset_query_max_filters: int = Field(20, validation_alias="DATASET_QUERY_MAX_FILTERS")
    dataset_query_max_metrics: int = Field(8, validation_alias="DATASET_QUERY_MAX_METRICS")
    dataset_query_max_group_fields: int = Field(5, validation_alias="DATASET_QUERY_MAX_GROUP_FIELDS")
    dataset_query_max_response_bytes: int = Field(
        65536,
        validation_alias="DATASET_QUERY_MAX_RESPONSE_BYTES",
    )
    dataset_query_max_cell_chars: int = Field(
        2048,
        validation_alias="DATASET_QUERY_MAX_CELL_CHARS",
    )
    dataset_query_max_timeframe_ms: int = Field(
        2592000000,
        validation_alias="DATASET_QUERY_MAX_TIMEFRAME_MS",
    )
    dataset_query_cursor_secret: str = Field(
        "",
        validation_alias="DATASET_QUERY_CURSOR_SECRET",
    )
    dataset_query_cursor_ttl_seconds: int = Field(
        900,
        validation_alias="DATASET_QUERY_CURSOR_TTL_SECONDS",
    )
    xql_max_concurrent_queries: int = Field(
        4,
        validation_alias="XQL_MAX_CONCURRENT_QUERIES",
    )
    xql_max_query_chars: int = Field(
        32768,
        validation_alias="XQL_MAX_QUERY_CHARS",
    )

    # --- Audit Settings ---
    audit_log_enabled: bool = Field(True, validation_alias="AUDIT_LOG_ENABLED")
    audit_log_emit_start_events: bool = Field(True, validation_alias="AUDIT_LOG_EMIT_START_EVENTS")
    audit_log_include_query_text: bool = Field(False, validation_alias="AUDIT_LOG_INCLUDE_QUERY_TEXT")
    audit_log_fail_closed: bool = Field(False, validation_alias="AUDIT_LOG_FAIL_CLOSED")
    audit_log_xsiam_http_collector_enabled: bool = Field(
        False,
        validation_alias="AUDIT_LOG_XSIAM_HTTP_COLLECTOR_ENABLED",
    )
    audit_log_xsiam_http_collector_url: str = Field(
        "",
        validation_alias="AUDIT_LOG_XSIAM_HTTP_COLLECTOR_URL",
    )
    audit_log_xsiam_http_collector_api_key: str = Field(
        "",
        validation_alias="AUDIT_LOG_XSIAM_HTTP_COLLECTOR_API_KEY",
    )
    audit_log_xsiam_http_collector_timeout_seconds: int = Field(
        10,
        validation_alias="AUDIT_LOG_XSIAM_HTTP_COLLECTOR_TIMEOUT_SECONDS",
    )

    # This configuration tells Pydantic to:
    # 1. Load variables from a file named '.env' (for local development).
    # 2. Ignore any extra environment variables that aren't defined in this class.
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # --- Update Settings ---
    update_folder: str = Field(REMOTE_DIR.as_posix(), validation_alias="CORTEX_MCP_UPDATE_FOLDER")


# Global config instance
config = Settings()

def reload_config():
    """Reload the global config instance"""
    global config
    config = Settings()
    return config

def get_config():
    """Get the current config instance"""
    return config
