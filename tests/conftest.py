"""Shared offline setup; domain-specific fixtures stay next to their tests."""

import os
from collections.abc import Callable
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def clean_dynaconf_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in os.environ:
        if name.startswith("DYNACONF_") or name.endswith("_FOR_DYNACONF"):
            monkeypatch.delenv(name)


@pytest.fixture(autouse=True)
def clean_network_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "no_proxy",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "REQUESTS_CA_BUNDLE",
        "CURL_CA_BUNDLE",
    ):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def config_file(tmp_path: Path) -> Callable[..., Path]:
    def write(text: str, name: str = "consumer.yaml") -> Path:
        path = tmp_path / name
        path.write_text(text, encoding="utf-8")
        return path

    return write
