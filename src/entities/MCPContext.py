from dataclasses import dataclass


@dataclass
class MCPContext:
    auth_headers: dict[str, str]
    principal_id: str = "service-account"
    groups: tuple[str, ...] = ()
    auth_source: str = "local-default"
    tenant_id: str | None = None
