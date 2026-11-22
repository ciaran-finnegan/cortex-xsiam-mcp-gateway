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


def test_build_structured_xql_backtick_quotes_reserved_word_fields():
    query = build_structured_xql(
        dataset="identity_audit_raw",
        filters=[{"field": "target", "operator": "not_contains", "value": "svc"}],
        fields=["action", "target", "Limit"],
        limit=5,
    )

    assert query == (
        'dataset = identity_audit_raw | filter not (`target` contains "svc") | fields action, `target`, `Limit` | limit 5'
    )


@pytest.mark.parametrize("name", ["target`", "`target`", "target` | fields `x"])
def test_build_structured_xql_rejects_a_backtick_in_a_field_name(name):
    with pytest.raises(ValueError, match="Invalid"):
        build_structured_xql("identity_audit_raw", fields=[name])
    with pytest.raises(ValueError, match="Invalid"):
        build_structured_xql("identity_audit_raw", filters=[{"field": name, "operator": "eq", "value": "x"}], fields=["action"])


def test_reserved_word_list_holds_only_lowercase_identifiers():
    from usecase.xql_builder import SAFE_IDENTIFIER_RE, XQL_RESERVED_WORDS

    assert {"target", "limit", "sort", "filter", "fields", "tag", "top", "view", "table", "null"} <= XQL_RESERVED_WORDS
    assert all(word == word.lower() and SAFE_IDENTIFIER_RE.match(word) for word in XQL_RESERVED_WORDS)
