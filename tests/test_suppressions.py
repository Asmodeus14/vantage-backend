"""Accepting findings, and the rules about who may.

A scanner reporting the same forty-seven unchanging lows on every run teaches
people to stop reading the list. These tests are mostly about making sure the
escape hatch cannot be used to hide something from someone who should see it.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.auth.dependencies import current_user
from app.auth.store import AuthenticatedUser
from app.config import Settings, get_settings
from app.main import app
from app.routers import health as health_module
from app.schemas import Category, Confidence, Severity
from app.store import InMemoryReportStore
from app.suppressions import (
    InMemorySuppressionStore,
    new_suppression,
    reset_suppression_store,
)

from tests.test_api_flow import make_finding, make_report


def user(user_id: str = "u1") -> AuthenticatedUser:
    return AuthenticatedUser(
        id=user_id,
        github_id=1,
        login="octocat",
        name="Octo",
        avatar_url=None,
        scopes=("read:user",),
        _token_ciphertext="",
    )


@pytest.fixture
def api(monkeypatch):
    """A client whose report and suppression stores are in memory.

    Yields a helper so a test can choose who is signed in, per request.
    """
    reports = InMemoryReportStore()
    suppressions = InMemorySuppressionStore()

    app.dependency_overrides[get_settings] = lambda: Settings(
        database_url=None, gemini_api_key=None
    )

    async def fake_probe():
        return False, "No DATABASE_URL configured."

    monkeypatch.setattr(health_module, "probe_database", fake_probe)
    health_module._db_cache = None

    for module in ("app.routers.reports", "app.analysis.runner"):
        monkeypatch.setattr(f"{module}.get_store", lambda: reports)
    monkeypatch.setattr(
        "app.routers.reports.get_suppression_store", lambda: suppressions
    )

    def sign_in(as_user: AuthenticatedUser | None) -> None:
        app.dependency_overrides[current_user] = lambda: as_user

    sign_in(None)

    class Api:
        reports = None
        suppressions = None

    helper = Api()
    helper.reports = reports
    helper.suppressions = suppressions
    helper.sign_in = sign_in
    yield helper

    app.dependency_overrides.clear()
    health_module._db_cache = None
    reset_suppression_store()


def report_with(*findings, report_id: str = "r1", repository: str | None = "a/b"):
    report = make_report(report_id, repository=repository)
    report.findings = list(findings)
    return report


def located(fingerprint: str, finding_id: str, **kwargs):
    finding = make_finding(id=finding_id, **kwargs)
    finding.fingerprint = fingerprint
    return finding


# --------------------------------------------------------------------------
# Reading
# --------------------------------------------------------------------------

async def test_a_suppressed_finding_is_marked_not_removed(api):
    """Removing it would make `suppressed_count` unverifiable and turn
    "show suppressed" into a second round-trip."""
    await api.reports.save(
        report_with(located("fp1", "f1"), located("fp2", "f2")), owner_id="u1"
    )
    await api.suppressions.add(
        "u1", "a/b", new_suppression(fingerprint="fp1", reason="test fixture",
                                     title="t", rule_id="r")
    )

    with TestClient(app) as client:
        body = client.get("/api/reports/r1").json()

    assert body["suppressed_count"] == 1
    assert len(body["findings"]) == 2
    marked = {f["id"]: f for f in body["findings"]}
    assert marked["f1"]["suppressed"] is True
    assert marked["f1"]["suppression_reason"] == "test fixture"
    assert marked["f2"]["suppressed"] is False


async def test_the_score_is_recomputed_without_suppressed_findings(api):
    critical = located("fp1", "f1", severity=Severity.CRITICAL,
                       category=Category.SECURITY)
    await api.reports.save(report_with(critical), owner_id="u1")

    with TestClient(app) as client:
        before = client.get("/api/reports/r1").json()
        assert before["effective_score"] is None, "nothing suppressed yet"

        await api.suppressions.add(
            "u1", "a/b",
            new_suppression(fingerprint="fp1", reason="", title="t", rule_id="r"),
        )
        after = client.get("/api/reports/r1").json()

    # `score` is what the analysis produced and must never change.
    assert after["score"] == before["score"]
    assert after["effective_score"]["value"] > after["score"]["value"]


async def test_the_owners_suppressions_apply_to_everyone_reading_the_link(api):
    """A shared report has to mean one thing. Filtering per viewer means two
    people discussing the same URL see different reports."""
    await api.reports.save(report_with(located("fp1", "f1")), owner_id="u1")
    await api.suppressions.add(
        "u1", "a/b",
        new_suppression(fingerprint="fp1", reason="", title="t", rule_id="r"),
    )

    with TestClient(app) as client:
        api.sign_in(None)
        anonymous = client.get("/api/reports/r1").json()
        api.sign_in(user("u2"))
        stranger = client.get("/api/reports/r1").json()

    assert anonymous["suppressed_count"] == 1
    assert stranger["suppressed_count"] == 1


async def test_an_anonymous_report_has_no_suppressions_to_apply(api):
    """There is no owner whose judgement it could be."""
    await api.reports.save(report_with(located("fp1", "f1")))
    await api.suppressions.add(
        "u1", "a/b",
        new_suppression(fingerprint="fp1", reason="", title="t", rule_id="r"),
    )

    with TestClient(app) as client:
        body = client.get("/api/reports/r1").json()

    assert body["suppressed_count"] == 0
    assert body["findings"][0]["suppressed"] is False


# --------------------------------------------------------------------------
# Writing
# --------------------------------------------------------------------------

async def test_accepting_a_finding_persists_it_against_the_repository(api):
    """Keyed on the repository, not the report, so it survives the next run."""
    await api.reports.save(report_with(located("fp1", "f1")), owner_id="u1")

    with TestClient(app) as client:
        api.sign_in(user("u1"))
        response = client.put(
            "/api/reports/r1/findings/f1/suppression", json={"reason": "known"}
        )

    assert response.status_code == 204
    stored = await api.suppressions.list("u1", "a/b")
    assert [s.fingerprint for s in stored] == ["fp1"]
    assert stored[0].reason == "known"


async def test_a_suppression_carries_forward_to_the_next_analysis(api):
    """The whole point. A new report of the same repository inherits it."""
    await api.reports.save(report_with(located("fp1", "f1")), owner_id="u1")
    with TestClient(app) as client:
        api.sign_in(user("u1"))
        client.put("/api/reports/r1/findings/f1/suppression", json={"reason": "x"})

        # A later analysis of the same repository, with the same problem in it.
        await api.reports.save(
            report_with(located("fp1", "f9"), report_id="r2"), owner_id="u1"
        )
        body = client.get("/api/reports/r2").json()

    assert body["suppressed_count"] == 1


async def test_unsuppressing_restores_the_finding_without_reanalysing(api):
    await api.reports.save(report_with(located("fp1", "f1")), owner_id="u1")

    with TestClient(app) as client:
        api.sign_in(user("u1"))
        client.put("/api/reports/r1/findings/f1/suppression", json={"reason": "x"})
        assert client.get("/api/reports/r1").json()["suppressed_count"] == 1

        assert client.delete(
            "/api/reports/r1/findings/f1/suppression"
        ).status_code == 204
        restored = client.get("/api/reports/r1").json()

    assert restored["suppressed_count"] == 0
    assert restored["effective_score"] is None


async def test_history_shows_the_same_score_as_the_report_it_links_to(api):
    """The listing is built from indexed columns and never reads the payload, so
    the adjusted score has to be cached there. Without this, History said 72 and
    the report it linked to said 84."""
    critical = located("fp1", "f1", severity=Severity.CRITICAL,
                       category=Category.SECURITY)
    await api.reports.save(report_with(critical), owner_id="u1")

    with TestClient(app) as client:
        api.sign_in(user("u1"))
        client.put("/api/reports/r1/findings/f1/suppression", json={"reason": "x"})

        page = client.get("/api/reports/r1").json()
        listing = client.get("/api/reports").json()

    assert listing[0]["effective_score"] == page["effective_score"]["value"]
    assert listing[0]["suppressed_count"] == 1
    # The analysed score is still reported alongside, unchanged.
    assert listing[0]["score"] == page["score"]["value"]


async def test_accepting_updates_every_past_report_of_that_repository(api):
    """A suppression applies to the repository, not to one analysis, so an
    older report containing the same problem has to move too."""
    await api.reports.save(report_with(located("fp1", "f1")), owner_id="u1")
    await api.reports.save(
        report_with(located("fp1", "f9"), report_id="r2"), owner_id="u1"
    )

    with TestClient(app) as client:
        api.sign_in(user("u1"))
        client.put("/api/reports/r2/findings/f9/suppression", json={"reason": "x"})
        listing = client.get("/api/reports").json()

    assert {row["id"]: row["suppressed_count"] for row in listing} == {"r1": 1, "r2": 1}


async def test_restoring_clears_the_cached_score_everywhere(api):
    await api.reports.save(report_with(located("fp1", "f1")), owner_id="u1")

    with TestClient(app) as client:
        api.sign_in(user("u1"))
        client.put("/api/reports/r1/findings/f1/suppression", json={"reason": "x"})
        assert client.get("/api/reports").json()[0]["effective_score"] is not None

        client.delete("/api/reports/r1/findings/f1/suppression")
        listing = client.get("/api/reports").json()

    assert listing[0]["effective_score"] is None
    assert listing[0]["suppressed_count"] == 0


async def test_the_score_refresh_writes_once_not_once_per_report(api, monkeypatch):
    """A suppression applies to every report of a repository. Writing inside the
    loop meant one network round-trip each, and on a managed database that is
    tens of milliseconds apiece — one click could block for seconds."""
    for index in range(8):
        await api.reports.save(
            report_with(located("fp1", f"f{index}"), report_id=f"r{index}"),
            owner_id="u1",
        )

    calls: list[int] = []
    original = api.reports.set_effective_scores

    async def counting(updates):
        calls.append(len(updates))
        await original(updates)

    monkeypatch.setattr(api.reports, "set_effective_scores", counting)

    with TestClient(app) as client:
        api.sign_in(user("u1"))
        client.put("/api/reports/r0/findings/f0/suppression", json={"reason": "x"})

    assert calls == [8], "eight reports, one batched write"


async def test_accepting_twice_updates_the_reason_rather_than_duplicating(api):
    await api.reports.save(report_with(located("fp1", "f1")), owner_id="u1")

    with TestClient(app) as client:
        api.sign_in(user("u1"))
        client.put("/api/reports/r1/findings/f1/suppression", json={"reason": "first"})
        client.put("/api/reports/r1/findings/f1/suppression", json={"reason": "second"})

    stored = await api.suppressions.list("u1", "a/b")
    assert len(stored) == 1
    assert stored[0].reason == "second"


# --------------------------------------------------------------------------
# Who may
# --------------------------------------------------------------------------

async def test_a_stranger_holding_the_link_cannot_accept_findings(api):
    """The id is a read capability. It must not become an edit capability."""
    await api.reports.save(report_with(located("fp1", "f1")), owner_id="u1")

    with TestClient(app) as client:
        api.sign_in(user("u2"))
        response = client.put(
            "/api/reports/r1/findings/f1/suppression", json={"reason": "hide this"}
        )

    assert response.status_code == 403
    assert await api.suppressions.list("u2", "a/b") == []


async def test_signing_out_is_not_a_way_to_accept_findings(api):
    await api.reports.save(report_with(located("fp1", "f1")), owner_id="u1")

    with TestClient(app) as client:
        api.sign_in(None)
        response = client.put(
            "/api/reports/r1/findings/f1/suppression", json={"reason": "x"}
        )

    assert response.status_code == 403


async def test_an_anonymous_report_cannot_have_findings_accepted(api):
    """No owner to attribute the judgement to."""
    await api.reports.save(report_with(located("fp1", "f1")))

    with TestClient(app) as client:
        api.sign_in(user("u1"))
        response = client.put(
            "/api/reports/r1/findings/f1/suppression", json={"reason": "x"}
        )

    assert response.status_code == 403


async def test_upload_findings_cannot_be_accepted(api):
    """An acceptance carries forward to the same repository. An upload has no
    stable identity to carry it to."""
    await api.reports.save(
        report_with(located("fp1", "f1"), repository=None), owner_id="u1"
    )

    with TestClient(app) as client:
        api.sign_in(user("u1"))
        response = client.put(
            "/api/reports/r1/findings/f1/suppression", json={"reason": "x"}
        )

    assert response.status_code == 403
    assert "upload" in response.json()["message"].lower()


async def test_a_finding_without_a_fingerprint_is_refused_with_a_reason(api):
    """Pre-diffing reports. An acceptance keyed on an empty fingerprint would
    match every other legacy finding on the next run."""
    legacy = make_finding(id="f1")  # fingerprint defaults to ""
    await api.reports.save(report_with(legacy), owner_id="u1")

    with TestClient(app) as client:
        api.sign_in(user("u1"))
        response = client.put(
            "/api/reports/r1/findings/f1/suppression", json={"reason": "x"}
        )

    assert response.status_code == 403
    assert "re-analyse" in response.json()["detail"].lower()


async def test_accepting_an_unknown_finding_is_a_404_not_a_silent_success(api):
    await api.reports.save(report_with(located("fp1", "f1")), owner_id="u1")

    with TestClient(app) as client:
        api.sign_in(user("u1"))
        response = client.put(
            "/api/reports/r1/findings/nope/suppression", json={"reason": "x"}
        )

    assert response.status_code == 404


async def test_the_reason_is_capped_rather_than_stored_unbounded(api):
    await api.reports.save(report_with(located("fp1", "f1")), owner_id="u1")

    with TestClient(app) as client:
        api.sign_in(user("u1"))
        response = client.put(
            "/api/reports/r1/findings/f1/suppression", json={"reason": "x" * 5000}
        )

    assert response.status_code == 422, "the schema should reject it outright"
