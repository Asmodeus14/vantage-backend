from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.analysis.base import RuleContext
from app.analysis.engine import build_facts
from app.config import Settings, get_settings
from app.ingest.snapshot import Snapshot

# Everything a developer might have in a real `.env` that would change what a
# test observes. Tests assert on behaviour with a feature *off*, so inheriting a
# configured value silently rewrites the assertion.
_AMBIENT = (
    "GEMINI_API_KEY",
    "DATABASE_URL",
    "GITHUB_TOKEN",
    "GITHUB_CLIENT_ID",
    "INTERNAL_API_SECRET",
    "TOKEN_ENCRYPTION_KEY",
)


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch):
    """Run every test against an unconfigured service.

    `Settings` reads `.env`, so without this the suite depends on whoever's
    machine it runs on: configuring GitHub sign-in locally made four tests fail
    that had nothing to do with the change. Empty strings rather than deletion,
    because pydantic-settings falls back to the `.env` file when a variable is
    merely absent from the environment — only an explicit empty value overrides
    it.
    """
    for name in _AMBIENT:
        monkeypatch.setenv(name, "")

    # The settings object is cached for the process; both sides of the test
    # need to see the cleared environment.
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def make_project(tmp_path: Path):
    """Materialise a dict of {relative path: contents} as a real directory."""

    def _make(files: dict[str, str | dict]) -> Path:
        root = tmp_path / "project"
        root.mkdir(exist_ok=True)
        for relative, content in files.items():
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(content, (dict, list)):
                target.write_text(json.dumps(content, indent=2), encoding="utf-8")
            else:
                target.write_text(content, encoding="utf-8")
        return root

    return _make


@pytest.fixture
def make_context(make_project):
    """Build a RuleContext over a synthetic project."""

    def _make(files: dict[str, str | dict], *, http=None, **settings_kwargs) -> RuleContext:
        root = make_project(files)
        snapshot = Snapshot.build(root)
        settings = Settings(database_url=None, gemini_api_key=None, **settings_kwargs)
        return RuleContext(
            snapshot=snapshot,
            facts=build_facts(snapshot),
            settings=settings,
            http=http,
        )

    return _make
