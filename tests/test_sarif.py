"""SARIF 2.1.0 export.

Validated against the OASIS schema itself, vendored at
`tests/fixtures/sarif-schema-2.1.0.json`, rather than against a hand-written
idea of what SARIF looks like. The schema sets `additionalProperties: false`
almost everywhere, so a misspelled or misplaced property fails here instead of
being silently ignored by an importer — which is the failure mode that makes
"we export SARIF" untrue in practice.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from jsonschema import Draft7Validator

from app.export.sarif import SARIF_VERSION, to_sarif
from app.schemas import (
    Category,
    Confidence,
    Finding,
    IngestStats,
    ProjectInfo,
    Report,
    Score,
    Severity,
    SeverityCounts,
    SourceInfo,
    SourceKind,
)

SCHEMA_PATH = Path(__file__).parent / "fixtures" / "sarif-schema-2.1.0.json"


@pytest.fixture(scope="module")
def validator() -> Draft7Validator:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    return Draft7Validator(schema)


def assert_valid(validator: Draft7Validator, document: dict) -> None:
    errors = sorted(validator.iter_errors(document), key=lambda e: list(e.path))
    if errors:
        detail = "\n".join(
            f"  at {'/'.join(str(p) for p in e.path) or '<root>'}: {e.message}"
            for e in errors[:8]
        )
        raise AssertionError(f"SARIF failed schema validation:\n{detail}")


def finding(**overrides) -> Finding:
    base = {
        "id": "abc123",
        "fingerprint": "fp0123456789",
        "rule_id": "security/sql-injection",
        "title": "SQL statement assembled from an interpolated value",
        "description": "A SQL statement is built by string interpolation.",
        "category": Category.SECURITY,
        "severity": Severity.CRITICAL,
        "confidence": Confidence.HIGH,
        "file": "api/users.js",
        "line": 12,
        "end_line": 12,
        "snippet": "db.query(`SELECT * FROM users WHERE id = ${req.query.id}`)",
        "snippet_start_line": 10,
        "remediation": "Use a bound parameter.",
        "references": ["https://cwe.mitre.org/data/definitions/89.html"],
        "priority": 100,
    }
    return Finding(**{**base, **overrides})


def report(findings: list[Finding], **overrides) -> Report:
    base = {
        "id": "r123456789",
        "created_at": datetime.now(UTC),
        "duration_seconds": 2.5,
        "source": SourceInfo(
            kind=SourceKind.REPOSITORY,
            repository="acme/app",
            ref="main",
            commit="661317e6f91fe7c90306c2c48ea9354562ee9146",
            url="https://github.com/acme/app",
        ),
        "project": ProjectInfo(analysed_files=40, total_lines=4000),
        "score": Score(value=72, grade="C", categories=[], summary="s"),
        "severity_counts": SeverityCounts(),
        "findings": findings,
        "ingest": IngestStats(),
    }
    return Report(**{**base, **overrides})


# --------------------------------------------------------------------------
# Schema conformance
# --------------------------------------------------------------------------

def test_a_typical_report_validates(validator):
    assert_valid(validator, to_sarif(report([finding()])))


def test_an_empty_report_validates(validator):
    """A clean run still has to produce a valid log — an importer that receives
    nothing cannot tell "no findings" from "the export broke"."""
    document = to_sarif(report([]))
    assert_valid(validator, document)
    assert document["runs"][0]["results"] == []
    assert document["runs"][0]["tool"]["driver"]["rules"] == []


def test_every_category_severity_and_confidence_combination_validates(validator):
    """Guards the three lookup tables. A category added without a tag entry, or
    a severity without a `security-severity`, raises a KeyError here rather
    than in production."""
    findings = [
        finding(
            id=f"{c.value}-{s.value}-{f.value}",
            category=c,
            severity=s,
            confidence=f,
            rule_id=f"{c.value}/rule",
        )
        for c in Category
        for s in Severity
        for f in Confidence
    ]
    assert_valid(validator, to_sarif(report(findings)))


def test_upload_report_without_repository_validates(validator):
    """Uploads have no repository URL, so `versionControlProvenance` must be
    omitted rather than emitted empty."""
    document = to_sarif(
        report(
            [finding()],
            source=SourceInfo(kind=SourceKind.UPLOAD, filename="app.zip"),
        )
    )
    assert_valid(validator, document)
    assert "versionControlProvenance" not in document["runs"][0]


def test_project_wide_finding_has_no_invented_location(validator):
    """"No test framework configured" has no location. Inventing line 1 of the
    repository root would be a lie a consumer cannot detect."""
    document = to_sarif(
        report([finding(file=None, line=None, end_line=None, snippet=None)])
    )
    assert_valid(validator, document)
    assert "locations" not in document["runs"][0]["results"][0]


# --------------------------------------------------------------------------
# The mappings that carry the value
# --------------------------------------------------------------------------

def test_vantage_fingerprint_is_exported_as_a_partial_fingerprint():
    """The mapping that makes cross-run identity work in the consumer.

    Vantage already computes a deliberately stable identity — `long-file` keys
    on the file, `known-vulnerability` on the package name so it survives a
    version bump. Handing it over means an importer inherits that stability
    instead of re-deriving a worse one from line numbers.
    """
    document = to_sarif(report([finding(fingerprint="deadbeef1234")]))
    result = document["runs"][0]["results"][0]
    assert result["partialFingerprints"] == {"vantageFingerprint/v1": "deadbeef1234"}


def test_reports_predating_fingerprints_omit_the_property(validator):
    document = to_sarif(report([finding(fingerprint="")]))
    assert_valid(validator, document)
    assert "partialFingerprints" not in document["runs"][0]["results"][0]


def test_suppressed_findings_are_exported_marked_not_dropped(validator):
    """Dropping them would be the same failure as hiding them in the UI: the
    counts stop reconciling and the consumer treats an accepted finding as new.
    """
    document = to_sarif(
        report(
            [
                finding(
                    suppressed=True,
                    suppression_reason="Query is built from a constant allowlist.",
                )
            ]
        )
    )
    assert_valid(validator, document)
    result = document["runs"][0]["results"][0]
    assert result["suppressions"][0]["kind"] == "external"
    assert "allowlist" in result["suppressions"][0]["justification"]


def test_severity_maps_onto_both_level_and_security_severity():
    """SARIF has three levels and Vantage has five severities, so `level`
    alone cannot rank. `security-severity` carries the full ordering, and code
    scanning reads it as a *string*."""
    document = to_sarif(
        report(
            [
                finding(id="a", severity=Severity.CRITICAL, rule_id="x/critical"),
                finding(id="b", severity=Severity.MEDIUM, rule_id="x/medium"),
                finding(id="c", severity=Severity.INFO, rule_id="x/info"),
            ]
        )
    )
    levels = [r["level"] for r in document["runs"][0]["results"]]
    assert levels == ["error", "warning", "note"]

    rules = document["runs"][0]["tool"]["driver"]["rules"]
    scores = [r["properties"]["security-severity"] for r in rules]
    assert scores == ["9.5", "5.0", "1.0"]
    assert all(isinstance(s, str) for s in scores)


def test_rules_are_deduplicated_and_indices_point_at_them():
    """`ruleIndex` is an index into `tool.driver.rules`. Off-by-one here
    silently attributes every finding to the wrong rule."""
    document = to_sarif(
        report(
            [
                finding(id="1", rule_id="security/sql-injection", file="a.js"),
                finding(id="2", rule_id="security/sql-injection", file="b.js"),
                finding(id="3", rule_id="security/ssrf", file="c.js"),
            ]
        )
    )
    run = document["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    assert [r["id"] for r in rules] == ["security/sql-injection", "security/ssrf"]

    for result in run["results"]:
        assert rules[result["ruleIndex"]]["id"] == result["ruleId"]


def test_remediation_becomes_rule_help():
    document = to_sarif(report([finding(remediation="Use a bound parameter.")]))
    rule = document["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["help"]["text"] == "Use a bound parameter."
    assert rule["helpUri"].startswith("https://cwe.mitre.org/")


def test_a_branch_alone_is_not_recorded_as_a_revision(validator):
    """A branch is a moving target. Recording it as `revisionId` would let a
    consumer believe it can reproduce a run that it cannot."""
    document = to_sarif(
        report(
            [finding()],
            source=SourceInfo(
                kind=SourceKind.REPOSITORY,
                repository="acme/app",
                ref="main",
                commit=None,
                url="https://github.com/acme/app",
            ),
        )
    )
    assert_valid(validator, document)
    provenance = document["runs"][0]["versionControlProvenance"][0]
    assert "revisionId" not in provenance
    assert provenance["branch"] == "main"


def test_truncation_is_declared(validator):
    """A consumer importing a capped run and treating it as exhaustive will
    report findings as resolved when they were only cut off."""
    document = to_sarif(report([finding()], truncated=True))
    assert_valid(validator, document)
    assert document["runs"][0]["properties"]["vantage-truncated"] is True


def test_version_and_schema_are_declared():
    document = to_sarif(report([]))
    assert document["version"] == SARIF_VERSION == "2.1.0"
    assert document["$schema"].endswith("sarif-schema-2.1.0.json")


# --------------------------------------------------------------------------
# The endpoint
# --------------------------------------------------------------------------

@pytest.fixture
def api(monkeypatch):
    """The API with an in-memory store, off the network and off the database.

    Mirrors the fixture in `test_api_flow.py` rather than importing it: that
    one is `autouse=True` in its own module, and lifting it into `conftest`
    would silently apply this monkeypatching to every test in the suite.
    """
    from app.config import Settings, get_settings
    from app.main import app
    from app.store import InMemoryReportStore, reset_store

    app.dependency_overrides[get_settings] = lambda: Settings(
        database_url=None, gemini_api_key=None
    )
    store = InMemoryReportStore()
    monkeypatch.setattr("app.store._store", store)
    monkeypatch.setattr("app.routers.reports.get_store", lambda: store)
    yield app, store
    app.dependency_overrides.clear()
    reset_store()


def test_sarif_endpoint_serves_a_downloadable_file(api):
    """The point of this route is a file that goes into another tool, so the
    content type and the filename are part of the contract, not decoration."""
    import asyncio

    from fastapi.testclient import TestClient

    app_, store = api
    stored = report([finding()])
    # `asyncio.run` rather than poking at the loop policy: the store is
    # in-memory, so this needs a loop only to await a coroutine.
    asyncio.run(store.save(stored))

    with TestClient(app_) as client:
        response = client.get(f"/api/reports/{stored.id}/sarif")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/sarif+json")
    assert f'filename="{stored.id}.vantage.sarif"' in (
        response.headers["content-disposition"]
    )

    document = response.json()
    assert document["version"] == "2.1.0"
    assert document["runs"][0]["results"][0]["ruleId"] == "security/sql-injection"
    assert document["runs"][0]["automationDetails"]["id"] == f"vantage/{stored.id}"


def test_sarif_endpoint_404s_for_an_unknown_report(api):
    from fastapi.testclient import TestClient

    app_, _ = api
    with TestClient(app_) as client:
        response = client.get("/api/reports/does-not-exist/sarif")

    assert response.status_code == 404
    assert response.json()["code"] == "report_not_found"
