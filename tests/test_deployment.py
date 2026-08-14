"""Deployment invariants that the code alone cannot express.

`render.yaml` and `app/analysis/runner.py` have a dependency on each other that
neither file can enforce, and it produced a real bug: the deploy ran uvicorn
with `--workers 2` while job state lived in a module-level dict.

Starting an analysis and streaming its progress are two separate HTTP
connections. Uvicorn's workers share one listening socket, so the second
connection goes to whichever process is free rather than the one holding the
job. About half of all analyses therefore reported

    "That analysis is no longer available."

from `/api/analyze/{job_id}/events`, while the analysis ran fine in the other
process and its report landed in the database. The user simply never saw it
happen, and nothing in either file looked wrong on its own.

So the pairing is asserted here. These tests are cheap and they fail loudly the
moment someone changes one side without the other.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from app.analysis.runner import JobManager

RENDER_YAML = Path(__file__).resolve().parent.parent / "render.yaml"


@pytest.fixture(scope="module")
def start_command() -> str:
    text = RENDER_YAML.read_text(encoding="utf-8")
    match = re.search(r"^\s*startCommand:\s*(.+)$", text, re.MULTILINE)
    assert match, "render.yaml has no startCommand"
    return match.group(1)


def test_job_state_is_per_process():
    """The premise everything below rests on.

    If this ever stops being true — because jobs moved to Postgres or Redis —
    the worker constraint can be lifted, and this test failing is the prompt to
    go and lift it.
    """
    worker_a, worker_b = JobManager(), JobManager()
    job = worker_a.create()

    assert worker_a.get(job.id) is not None
    assert worker_b.get(job.id) is None, (
        "JobManager now shares state across instances — the single-worker "
        "constraint in render.yaml can be revisited."
    )


def test_the_deploy_runs_a_single_worker(start_command):
    """Because job state is per-process. See the module docstring."""
    match = re.search(r"--workers[= ](\d+)", start_command)
    assert match, f"no explicit --workers in: {start_command}"
    assert match.group(1) == "1", (
        f"render.yaml runs {match.group(1)} workers while job state is "
        "per-process; the progress stream will miss roughly "
        f"{100 - 100 // int(match.group(1))}% of analyses"
    )


def test_every_environment_specific_setting_is_declared_in_the_blueprint():
    """A setting whose default only makes sense on a laptop has to be declared.

    `APP_BASE_URL` defaults to `http://localhost:3000`. It was added for the
    pull request comment and never added here, so in production the comment
    would have embedded a localhost link into someone's pull request — working
    perfectly in every test and being useless to every reader.

    The rule is mechanical on purpose: a default of `None` gates a feature off,
    and a default pointing at localhost is a development convenience. Either
    way the deployed service needs to be told, so the blueprint must name it.
    Values may still be `sync: false` — the point is that the variable is
    *declared*, not that its value lives in the file.
    """
    from app.config import Settings

    text = RENDER_YAML.read_text(encoding="utf-8")
    declared = set(re.findall(r"-\s*key:\s*([A-Z_0-9]+)", text))

    needs_declaring = {
        name.upper()
        for name, field in Settings.model_fields.items()
        if field.default is None
        or (isinstance(field.default, str) and "localhost" in field.default)
    }

    missing = sorted(needs_declaring - declared)
    assert not missing, (
        "environment-specific settings absent from render.yaml, so the "
        f"deployed service silently uses a development default: {missing}"
    )


def test_migrations_run_before_the_server_starts(start_command):
    """A server that boots before its schema is migrated serves errors from a
    table that is about to exist."""
    assert "app.migrate" in start_command
    assert start_command.index("app.migrate") < start_command.index("uvicorn")


def test_the_health_check_path_is_one_that_exists(start_command):
    """Render restarts the service when the health check fails, so a typo here
    is an unbootable deploy that looks like a crash loop."""
    from app.main import app

    text = RENDER_YAML.read_text(encoding="utf-8")
    match = re.search(r"^\s*healthCheckPath:\s*(\S+)$", text, re.MULTILINE)
    assert match, "render.yaml has no healthCheckPath"

    paths = {route.path for route in app.routes}
    assert match.group(1) in paths, (
        f"healthCheckPath {match.group(1)} is not a route this app serves"
    )
