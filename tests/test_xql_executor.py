import asyncio

import pytest

from config.config import get_config
from usecase import xql_executor


class SequenceFetcher:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.requests = []

    async def send_request(self, path, data):
        self.requests.append((path, data))
        return next(self.responses)


@pytest.mark.asyncio
async def test_xql_executor_preserves_synchronous_start_results(monkeypatch):
    fetcher = SequenceFetcher(
        [{"reply": {"status": "SUCCESS", "results": {"data": [{"total": 1}]}}}]
    )

    async def fake_get_fetcher(ctx):
        return fetcher

    monkeypatch.setattr(xql_executor, "get_fetcher", fake_get_fetcher)
    response = await xql_executor.run_xql_query(None, "dataset = sample | comp count()", 1)

    assert response["reply"]["results"]["data"] == [{"total": 1}]
    assert response["query_id"] is None
    assert response["poll_attempts"] == 0
    assert len(fetcher.requests) == 1


@pytest.mark.asyncio
async def test_xql_executor_polls_pending_query_to_success_and_caps_limit(monkeypatch):
    fetcher = SequenceFetcher(
        [
            {"reply": {"query_id": "query-1"}},
            {"reply": {"status": "PENDING"}},
            {"reply": {"status": "SUCCESS", "results": {"data": [{"total": 1}]}}},
        ]
    )

    async def fake_get_fetcher(ctx):
        return fetcher

    monkeypatch.setattr(xql_executor, "get_fetcher", fake_get_fetcher)
    response = await xql_executor.run_xql_query(None, "dataset = sample | limit 1", 5000, poll_interval_seconds=0)

    assert response["query_id"] == "query-1"
    assert response["poll_attempts"] == 2
    assert fetcher.requests[1][1]["request_data"]["limit"] == 1000


@pytest.mark.asyncio
async def test_xql_executor_rejects_oversized_query_before_fetcher_creation(monkeypatch):
    monkeypatch.setattr(get_config(), "xql_max_query_chars", 10)

    async def fail_get_fetcher(ctx):
        raise AssertionError("oversized query must not create a fetcher")

    monkeypatch.setattr(xql_executor, "get_fetcher", fail_get_fetcher)
    with pytest.raises(ValueError, match="exceeds the configured"):
        await xql_executor.run_xql_query(None, "dataset = sample", 1)


@pytest.mark.asyncio
async def test_xql_executor_returns_bounded_failure_without_query_text(monkeypatch):
    upstream_error = 'invalid field in dataset = sensitive | filter user = "private"'
    fetcher = SequenceFetcher(
        [
            {"reply": "query-2"},
            {"reply": {"status": "FAILED", "error_message": upstream_error}},
        ]
    )

    async def fake_get_fetcher(ctx):
        return fetcher

    monkeypatch.setattr(xql_executor, "get_fetcher", fake_get_fetcher)
    response = await xql_executor.run_xql_query(None, "dataset = sensitive", 10, poll_interval_seconds=0)

    assert response == {
        "query_id": "query-2",
        "poll_attempts": 1,
        "error": "XQL query failed",
        "xsiam_status": "FAILED",
        "error_reference_sha256": response["error_reference_sha256"],
    }
    assert len(response["error_reference_sha256"]) == 64
    assert upstream_error not in str(response)


@pytest.mark.asyncio
async def test_xql_executor_sanitizes_synchronous_failure(monkeypatch):
    upstream_error = 'failed query echoed dataset = sensitive | limit 1'
    fetcher = SequenceFetcher(
        [{"reply": {"status": "ERROR", "error": upstream_error}}]
    )

    async def fake_get_fetcher(ctx):
        return fetcher

    monkeypatch.setattr(xql_executor, "get_fetcher", fake_get_fetcher)
    response = await xql_executor.run_xql_query(None, "dataset = sample | limit 1", 1)

    assert response["error"] == "XQL query failed"
    assert response["xsiam_status"] == "ERROR"
    assert response["poll_attempts"] == 0
    assert len(response["error_reference_sha256"]) == 64
    assert upstream_error not in str(response)
    assert len(fetcher.requests) == 1


@pytest.mark.asyncio
async def test_xql_executor_times_out_without_unbounded_polling(monkeypatch):
    fetcher = SequenceFetcher([{"reply": "query-3"}])
    clock = iter([0.0, 2.0])

    async def fake_get_fetcher(ctx):
        return fetcher

    monkeypatch.setattr(xql_executor, "get_fetcher", fake_get_fetcher)
    monkeypatch.setattr(xql_executor, "_monotonic", lambda: next(clock))
    response = await xql_executor.run_xql_query(None, "dataset = sample", 10, timeout_seconds=1)

    assert response["query_id"] == "query-3"
    assert response["poll_attempts"] == 0
    assert "timed out" in response["error"]


@pytest.mark.asyncio
async def test_xql_executor_never_exceeds_xsiam_concurrency_limit(monkeypatch):
    monkeypatch.setattr(get_config(), "xql_max_concurrent_queries", 20)
    release = asyncio.Event()
    saturated = asyncio.Event()
    active = 0
    maximum = 0
    next_id = 0

    class BlockingFetcher:
        async def send_request(self, path, data):
            nonlocal active, maximum, next_id
            if path.endswith("start_xql_query/"):
                next_id += 1
                query_id = f"query-{next_id}"
                active += 1
                maximum = max(maximum, active)
                if active == 4:
                    saturated.set()
                await release.wait()
                return {"reply": query_id}
            active -= 1
            return {"reply": {"status": "SUCCESS", "results": {"data": []}}}

    fetcher = BlockingFetcher()

    async def fake_get_fetcher(ctx):
        return fetcher

    monkeypatch.setattr(xql_executor, "get_fetcher", fake_get_fetcher)
    tasks = [
        asyncio.create_task(xql_executor.run_xql_query(None, "dataset = sample", 1, poll_interval_seconds=0))
        for _ in range(6)
    ]
    await asyncio.wait_for(saturated.wait(), timeout=1)
    assert maximum == 4
    release.set()
    responses = await asyncio.gather(*tasks)

    assert all(response.get("error") is None for response in responses)
