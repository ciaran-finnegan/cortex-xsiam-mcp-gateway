import json
from datetime import UTC, datetime

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
def _reset_learning_state():
    from usecase import learned_store, learning_journal, learning_observers

    learned_store.reset_state()
    learning_observers.reset_state()
    learning_journal.reset_state()
    yield
    learned_store.reset_state()
    learning_observers.reset_state()
    learning_journal.reset_state()


@pytest.fixture
def pack(tmp_path, monkeypatch):
    from config.config import get_config

    root = tmp_path / "tenant-pack"
    monkeypatch.setattr(get_config(), "tenant_pack_dir", str(root))
    monkeypatch.setattr(get_config(), "learning_enabled", True)
    return root


@pytest.fixture
def audit_events(monkeypatch):
    from usecase import learner
    from usecase.builtin_components import learning as learning_tools

    events = []

    async def capture(event):
        events.append(json.loads(json.dumps(event, default=str)))

    for module in (learner, learning_tools):
        monkeypatch.setattr(module, "emit_audit_event", capture)
    return events


@pytest.fixture
def clock(monkeypatch):
    from usecase import learned_store

    state = {"now": datetime(2026, 10, 1, tzinfo=UTC)}
    monkeypatch.setattr(learned_store, "now_utc", lambda: state["now"])
    return state
