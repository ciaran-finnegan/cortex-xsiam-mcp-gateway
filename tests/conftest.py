import pytest


def pytest_addoption(parser):
    parser.addoption(
        "--run-live",
        action="store_true",
        default=False,
        help="Run tests that call an explicitly configured Cortex XSIAM service.",
    )


def pytest_collection_modifyitems(config, items):
    if config.getoption("--run-live"):
        return
    skip_live = pytest.mark.skip(reason="requires explicit --run-live opt-in")
    for item in items:
        if "live" in item.keywords:
            item.add_marker(skip_live)


@pytest.fixture(autouse=True)
def _reset_cost_guard_state(monkeypatch):
    from usecase import cost_guard

    async def no_quota_api(ctx):
        raise RuntimeError("the XSIAM quota API is not called in unit tests")

    # The guard reads /xql/get_quota through the real fetcher when it has no quota reading.
    monkeypatch.setattr(cost_guard, "_fetch_quota_reply", no_quota_api)
    cost_guard.reset_state()
    yield
    cost_guard.reset_state()
