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
def _clear_field_catalog():
    from usecase.field_catalog import clear_observed_fields

    clear_observed_fields()
    yield
    clear_observed_fields()
