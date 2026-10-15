import os
import pytest

# Ensure all tests testing 'import httplib2' execute against modern_httplib2
import modern_httplib2.auto  # noqa: F401


@pytest.fixture(autouse=True)
def _clean_proxy_env(monkeypatch):
    """Ensure ambient proxy environment variables do not interfere with local test servers."""
    for var in (
        "http_proxy",
        "https_proxy",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "all_proxy",
        "ALL_PROXY",
        "no_proxy",
        "NO_PROXY",
    ):
        monkeypatch.delenv(var, raising=False)
