import pytest

from usecase.dataset_query import DatasetQueryPlan, QueryFilter, build_dataset_xql
from usecase.xql_builder import enforce_terminal_xql_limit, strip_xql_comments


@pytest.mark.parametrize(
    "query",
    [
        "dataset = xdr_data | fields _time // | limit 5",
        "dataset = xdr_data | fields _time\n// | limit 5",
        "dataset = xdr_data | fields _time /* | limit 5 */",
        "dataset = xdr_data | fields _time /* note */ // | limit 5",
    ],
)
def test_limit_written_only_inside_a_comment_does_not_satisfy_the_terminal_limit(query):
    with pytest.raises(ValueError, match="must end with a numeric"):
        enforce_terminal_xql_limit(query, 100)


def test_real_terminal_limit_is_clamped_and_comments_are_removed_before_submission():
    query = (
        "config timeframe = 1d //Set the timeframe\n"
        "| dataset = xdr_data //Use endpoint telemetry\n"
        "| filter agent_hostname = \"wks-1234\" /* the host */\n"
        "| limit 5000 // cap"
    )

    bounded = enforce_terminal_xql_limit(query, 100)

    assert bounded.endswith("| limit 100")
    assert "//" not in bounded and "/*" not in bounded and "Set the timeframe" not in bounded
    assert 'agent_hostname = "wks-1234"' in bounded


def test_comment_markers_inside_string_literals_are_preserved():
    query = 'dataset = web_raw | filter url = "https://example.com/a" and note = """x // y /* z */""" | limit 10'

    assert strip_xql_comments(query) == query
    assert enforce_terminal_xql_limit(query, 100).endswith("| limit 10")


def test_escaped_quote_does_not_end_the_string_early():
    query = 'dataset = t | filter a = "he said \\"hi\\" // still string" | limit 3 // | limit 999999'

    bounded = enforce_terminal_xql_limit(query, 100)

    assert '// still string"' in bounded and bounded.endswith("| limit 3")


def test_limit_inside_a_string_literal_is_not_a_terminal_limit():
    with pytest.raises(ValueError):
        enforce_terminal_xql_limit('dataset = t | filter a = "x | limit 5"', 100)


def test_unterminated_block_comment_is_rejected():
    with pytest.raises(ValueError, match="unterminated"):
        enforce_terminal_xql_limit("dataset = t /* never closed | limit 5", 100)


def test_enum_filters_compile_to_enum_members():
    single = build_dataset_xql(
        DatasetQueryPlan(
            dataset="xdr_data",
            fields=["agent_hostname"],
            filters=[QueryFilter(field="event_type", operator="eq", value="PROCESS", value_type="enum")],
            limit=5,
        )
    ).xql
    many = build_dataset_xql(
        DatasetQueryPlan(
            dataset="xdr_data",
            fields=["agent_hostname"],
            filters=[QueryFilter(field="event_type", operator="not_in", value=["NETWORK", "FILE"], value_type="enum")],
            limit=5,
        )
    ).xql

    assert "event_type = ENUM.PROCESS" in single and '"PROCESS"' not in single
    assert "not (event_type in (ENUM.NETWORK, ENUM.FILE))" in many


@pytest.mark.parametrize(
    "operator, value",
    [
        ("eq", "PROCESS) or (1 = 1"),
        ("eq", "process"),
        ("eq", "ENUM.PROCESS"),
        ("eq", 7),
        ("in", ["PROCESS", "x | limit 1"]),
        ("contains", "PROCESS"),
        ("gt", "PROCESS"),
        ("eq", "A" * 200),
    ],
)
def test_enum_filters_reject_anything_but_bare_uppercase_members(operator, value):
    with pytest.raises(ValueError):
        QueryFilter(field="event_type", operator=operator, value=value, value_type="enum")
