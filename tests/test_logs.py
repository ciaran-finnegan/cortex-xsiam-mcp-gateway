import pytest

from entities.MCPContext import MCPContext
from usecase.log_policy import DatasetAuthorizationError, ensure_dataset_authorized
from usecase.xql_builder import build_structured_xql


def test_build_structured_xql_with_filters_fields_and_limit():
    query = build_structured_xql(
        dataset="xdr_data",
        filters=[
            {"field": "event_type", "operator": "contains", "value": "authentication"},
            {"field": "severity", "operator": "in", "value": ["high", "critical"]},
        ],
        fields=["event_id", "event_type", "severity"],
        limit=250,
    )

    assert query == (
        'dataset = xdr_data | filter event_type contains "authentication" '
        '| filter severity in ("high", "critical") | fields event_id, event_type, severity | limit 250'
    )


def test_build_structured_xql_caps_limit_at_xsiam_api_limit():
    query = build_structured_xql("xdr_data", limit=5000)

    assert query.endswith("| limit 1000")


def test_build_structured_xql_rejects_unsafe_identifiers():
    with pytest.raises(ValueError, match="Invalid dataset"):
        build_structured_xql("xdr_data | alter")


def test_dataset_policy_allows_security_group_all_datasets(monkeypatch):
    from config.config import get_config

    monkeypatch.setattr(get_config(), "log_search_dataset_policy", '{"Security": ["*"], "Tier1": ["xdr_data"]}')
    context = MCPContext(auth_headers={}, principal_id="analyst@example.com", groups=("Security",))

    decision = ensure_dataset_authorized(context, "custom_cloud_dataset")

    assert decision.allowed is True
    assert decision.matched_group == "Security"


def test_dataset_policy_denies_unassigned_dataset(monkeypatch):
    from config.config import get_config

    monkeypatch.setattr(get_config(), "log_search_dataset_policy", '{"Tier1": ["xdr_data"]}')
    context = MCPContext(auth_headers={}, principal_id="tier1@example.com", groups=("Tier1",))

    with pytest.raises(DatasetAuthorizationError):
        ensure_dataset_authorized(context, "custom_cloud_dataset")
