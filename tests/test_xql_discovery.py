from entities.MCPContext import MCPContext
from usecase.xql_discovery import (
    build_field_discovery_xql,
    extract_xql_rows,
    filter_authorized_dataset_records,
    filter_field_catalog,
    infer_field_catalog,
    normalize_dataset_record,
    policy_dataset_records,
)


def test_build_field_discovery_xql_caps_sample_size():
    assert build_field_discovery_xql("xdr_data", 500) == "dataset = xdr_data | limit 100"


def test_normalize_dataset_record_accepts_api_display_keys():
    normalized = normalize_dataset_record(
        {
            "Dataset Name": "xdr_data ",
            "Type": "SYSTEM",
            "Log Update Type": "LOGS",
            "Default Query Target": "FALSE",
            "Total Size Stored": 100000,
        }
    )

    assert normalized == {
        "dataset_name": "xdr_data",
        "type": "SYSTEM",
        "log_update_type": "LOGS",
        "default_query_target": "FALSE",
    }


def test_filter_authorized_dataset_records_caps_and_filters(monkeypatch):
    from config.config import get_config

    monkeypatch.setattr(
        get_config(),
        "log_search_dataset_policy",
        '{"Tier1": ["xdr_data", "auth_logs", "cloud_audit_logs"]}',
    )
    context = MCPContext(auth_headers={}, principal_id="tier1@example.com", groups=("Tier1",))
    records = [
        {"dataset_name": "xdr_data"},
        {"dataset_name": "auth_logs"},
        {"dataset_name": "cloud_audit_logs"},
        {"dataset_name": "secret_admin_logs"},
    ]

    allowed, truncated = filter_authorized_dataset_records(records, context, name_contains="logs", max_datasets=1)

    assert [record["dataset_name"] for record in allowed] == ["auth_logs"]
    assert truncated is True


def test_policy_dataset_records_uses_configured_dataset_policy(monkeypatch):
    from config.config import get_config

    monkeypatch.setattr(get_config(), "log_search_dataset_policy", '{"Tier1": ["xdr_data", "auth_logs"]}')
    context = MCPContext(auth_headers={}, principal_id="tier1@example.com", groups=("Tier1",))

    records, truncated = policy_dataset_records(context)

    assert [record["dataset_name"] for record in records] == ["auth_logs", "xdr_data"]
    assert truncated is False


def test_extract_xql_rows_accepts_nested_reply_results():
    rows = extract_xql_rows(
        {
            "reply": {
                "status": "SUCCESS",
                "results": [
                    {"event_id": "1", "severity": "high"},
                    {"event_id": "2", "severity": "low"},
                ],
            }
        }
    )

    assert rows == [
        {"event_id": "1", "severity": "high"},
        {"event_id": "2", "severity": "low"},
    ]


def test_infer_and_filter_field_catalog_does_not_return_values():
    catalog = infer_field_catalog(
        [
            {"event_id": "1", "severity": "high", "success": False},
            {"event_id": "2", "severity": "low", "success": True, "attempts": 3},
        ]
    )

    filtered, truncated = filter_field_catalog(catalog, max_fields=2)

    assert filtered == [
        {"name": "attempts", "type": "integer", "observed_count": 1},
        {"name": "event_id", "type": "string", "observed_count": 2},
    ]
    assert truncated is True
    assert "sample_values" not in filtered[0]
