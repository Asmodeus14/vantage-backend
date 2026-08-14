"""Finding identity across reports, and the report-to-report comparison.

The point of a fingerprint is that it survives edits that do not change the
underlying problem. Most of these tests are therefore phrased as "make this
edit, assert the finding is still the same finding".
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from app.analysis.base import ProjectFacts, RuleContext
from app.analysis.diffing import compare, is_comparable
from app.analysis.runner import AnalysisRunner
from app.analysis.scoring import compute_score, severity_counts
from app.config import Settings
from app.ingest.snapshot import Snapshot
from app.schemas import (
    Category,
    Confidence,
    Finding,
    Report,
    Severity,
    SourceInfo,
    SourceKind,
)
from app.store import InMemoryReportStore


@pytest.fixture
def ctx() -> RuleContext:
    return RuleContext(
        snapshot=Snapshot(root=Path(".")), facts=ProjectFacts(), settings=Settings()
    )


def build(ctx: RuleContext, **kwargs) -> Finding:
    defaults = {
        "rule_id": "test/rule",
        "title": "Something is wrong",
        "description": "d",
        "category": Category.QUALITY,
        "severity": Severity.MEDIUM,
        "confidence": Confidence.HIGH,
    }
    defaults.update(kwargs)
    return ctx.finding(**defaults)


# --------------------------------------------------------------------------
# Fingerprints
# --------------------------------------------------------------------------

def test_fingerprint_ignores_the_title(ctx):
    """`quality/long-file` puts the line count in its title, so a title-keyed
    identity made every edit look like one problem fixed and another found."""
    before = build(ctx, file="a.ts", line=1, title="a.ts is 1,050 lines long", key="a.ts")
    after = build(ctx, file="a.ts", line=1, title="a.ts is 1,051 lines long", key="a.ts")

    assert before.fingerprint == after.fingerprint
    # `id` still distinguishes them — it is a within-report handle, and the AI
    # action cache depends on it changing when the text does.
    assert before.id != after.id


def test_a_keyed_finding_survives_moving_down_the_file(ctx):
    """Inserting an import above a finding must not resolve and recreate it."""
    before = build(ctx, file="a.ts", line=10, key="a.ts|handleSubmit")
    after = build(ctx, file="a.ts", line=48, key="a.ts|handleSubmit")
    assert before.fingerprint == after.fingerprint


def test_an_unkeyed_finding_does_move_with_its_line(ctx):
    """Documented limitation, asserted so it stays a decision rather than a bug.

    Rules like `react/array-index-key` emit several findings per file with
    nothing to tell them apart but position.
    """
    before = build(ctx, file="a.ts", line=10)
    after = build(ctx, file="a.ts", line=48)
    assert before.fingerprint != after.fingerprint


def test_the_same_key_in_different_files_is_a_different_finding(ctx):
    """`render` exists in most React codebases; the path must qualify it."""
    a = build(ctx, file="a.ts", line=1, key="a.ts|render")
    b = build(ctx, file="b.ts", line=1, key="b.ts|render")
    assert a.fingerprint != b.fingerprint


def test_an_empty_key_drops_the_location_entirely(ctx):
    """`quality/todo-markers` anchors to the first marker it happened to find.
    That file changes when an unrelated file gains a TODO."""
    before = build(ctx, file="a.ts", line=3, key="")
    after = build(ctx, file="zzz.ts", line=99, key="")
    assert before.fingerprint == after.fingerprint


def test_different_rules_never_share_a_fingerprint(ctx):
    a = build(ctx, rule_id="quality/long-file", file="a.ts", key="a.ts")
    b = build(ctx, rule_id="quality/deep-nesting", file="a.ts", key="a.ts")
    assert a.fingerprint != b.fingerprint


# --------------------------------------------------------------------------
# Comparison
# --------------------------------------------------------------------------

def make_report(
    report_id: str,
    findings: list[Finding],
    *,
    repository: str | None = "acme/app",
    rule_ids: list[str] | None = None,
    minutes_ago: int = 0,
    truncated: bool = False,
) -> Report:
    return Report(
        id=report_id,
        created_at=datetime.now(UTC) - timedelta(minutes=minutes_ago),
        duration_seconds=1.0,
        source=SourceInfo(
            kind=SourceKind.UPLOAD if repository is None else SourceKind.REPOSITORY,
            repository=repository,
        ),
        project={},
        score=compute_score(findings, 10),
        severity_counts=severity_counts(findings),
        findings=findings,
        ingest={},
        rule_ids=rule_ids if rule_ids is not None else ["test/rule"],
        truncated=truncated,
    )


def test_compare_splits_new_resolved_and_unchanged(ctx):
    kept = build(ctx, file="a.ts", key="kept")
    gone = build(ctx, file="b.ts", key="gone", title="Fixed at last")
    fresh = build(ctx, file="c.ts", key="fresh")

    delta = compare(
        make_report("r2", [kept, fresh]),
        make_report("r1", [kept, gone], minutes_ago=60),
    )

    assert delta.new == [fresh.fingerprint]
    assert [r.fingerprint for r in delta.resolved] == [gone.fingerprint]
    assert delta.unchanged == 1
    assert delta.previous_report_id == "r1"


def test_resolved_findings_carry_their_own_details(ctx):
    """They are absent from `Report.findings` by definition, so a fingerprint
    alone would leave the UI with nothing to render."""
    gone = build(
        ctx, file="b.ts", key="gone", title="Secret committed", severity=Severity.CRITICAL
    )
    delta = compare(make_report("r2", []), make_report("r1", [gone], minutes_ago=60))

    assert len(delta.resolved) == 1
    assert delta.resolved[0].title == "Secret committed"
    assert delta.resolved[0].file == "b.ts"
    assert delta.resolved[0].severity is Severity.CRITICAL


def test_a_rule_added_since_the_last_run_is_named(ctx):
    """Its findings are all technically new even if the code never changed —
    the UI has to be able to caption that, so the set is recorded."""
    finding = build(ctx, rule_id="security/new-rule", file="a.ts", key="x")
    delta = compare(
        make_report("r2", [finding], rule_ids=["test/rule", "security/new-rule"]),
        make_report("r1", [], rule_ids=["test/rule"], minutes_ago=60),
    )
    assert delta.new_rules == ["security/new-rule"]
    assert delta.new == [finding.fingerprint]


def test_a_rule_that_ran_clean_last_time_is_not_called_new(ctx):
    """This is why the rule-id set is stored rather than derived from findings:
    a clean run leaves no finding to derive it from."""
    finding = build(ctx, rule_id="test/rule", file="a.ts", key="x")
    delta = compare(
        make_report("r2", [finding], rule_ids=["test/rule"]),
        make_report("r1", [], rule_ids=["test/rule"], minutes_ago=60),
    )
    assert delta.new_rules == []


def test_legacy_findings_without_a_fingerprint_are_skipped(ctx):
    """Reports written before diffing existed have empty fingerprints. Matching
    on those would make every one of them equal to every other."""
    old_a = Finding(
        id="1", rule_id="r", title="A", description="d",
        category=Category.QUALITY, severity=Severity.LOW,
    )
    old_b = Finding(
        id="2", rule_id="r", title="B", description="d",
        category=Category.QUALITY, severity=Severity.LOW,
    )
    assert old_a.fingerprint == old_b.fingerprint == ""

    delta = compare(
        make_report("r2", [old_a]), make_report("r1", [old_b], minutes_ago=60)
    )
    assert delta.new == []
    assert delta.resolved == []
    assert delta.unchanged == 0


# --------------------------------------------------------------------------
# Which reports may be compared at all
# --------------------------------------------------------------------------

def test_uploads_are_never_compared(ctx):
    """Two ZIPs with the same name may be unrelated projects."""
    upload = make_report("r2", [], repository=None)
    assert not is_comparable(upload, make_report("r1", [], minutes_ago=60))
    assert not is_comparable(make_report("r2", []), upload)


def test_different_repositories_are_never_compared(ctx):
    assert not is_comparable(
        make_report("r2", [], repository="acme/app"),
        make_report("r1", [], repository="acme/other", minutes_ago=60),
    )


def test_a_truncated_report_is_not_compared(ctx):
    """Everything past the findings cap was never written down, so it would
    read as resolved."""
    assert not is_comparable(
        make_report("r2", []),
        make_report("r1", [], minutes_ago=60, truncated=True),
    )
    assert not is_comparable(
        make_report("r2", [], truncated=True), make_report("r1", [], minutes_ago=60)
    )


def test_a_report_is_not_compared_against_itself(ctx):
    report = make_report("r1", [])
    assert not is_comparable(report, report)


def test_two_comparable_repository_reports_are_comparable(ctx):
    assert is_comparable(
        make_report("r2", [build(ctx, file="a.ts", key="x")]),
        make_report("r1", [build(ctx, file="a.ts", key="y")], minutes_ago=60),
    )


# --------------------------------------------------------------------------
# Runner wiring
# --------------------------------------------------------------------------

@pytest.fixture
def store(monkeypatch) -> InMemoryReportStore:
    instance = InMemoryReportStore()
    monkeypatch.setattr("app.analysis.runner.get_store", lambda: instance)
    return instance


async def test_the_runner_finds_and_compares_the_previous_report(ctx, store):
    kept = build(ctx, file="a.ts", key="kept")
    gone = build(ctx, file="b.ts", key="gone")
    fresh = build(ctx, file="c.ts", key="fresh")

    await store.save(make_report("r1", [kept, gone], minutes_ago=60))
    runner = AnalysisRunner(Settings())

    delta = await runner._delta(make_report("r2", [kept, fresh]))

    assert delta is not None
    assert delta.previous_report_id == "r1"
    assert delta.new == [fresh.fingerprint]
    assert [r.fingerprint for r in delta.resolved] == [gone.fingerprint]


async def test_the_first_analysis_of_a_repository_has_no_delta(ctx, store):
    runner = AnalysisRunner(Settings())
    assert await runner._delta(make_report("r1", [build(ctx, key="x")])) is None


async def test_an_upload_is_never_diffed(ctx, store):
    """It has no repository to look one up by, so the store is never asked."""
    await store.save(make_report("r1", [build(ctx, key="x")], minutes_ago=60))
    runner = AnalysisRunner(Settings())
    assert await runner._delta(make_report("r2", [], repository=None)) is None


async def test_a_signed_in_run_is_not_compared_against_an_anonymous_one(ctx, store):
    """Ownership is the boundary. Crossing it would put findings from someone
    else's analysis into this report's resolved list."""
    await store.save(make_report("anon", [build(ctx, key="x")], minutes_ago=60))
    runner = AnalysisRunner(Settings())

    assert await runner._delta(make_report("r2", []), owner_id="u1") is None
    # ...and the same run signed out does find it.
    assert await runner._delta(make_report("r2", [])) is not None


async def test_a_store_failure_loses_the_comparison_not_the_report(ctx, store):
    """Enrichment must never fail an analysis — the findings are the product."""

    async def explode(*args, **kwargs):
        raise RuntimeError("database is on fire")

    store.latest_for = explode  # type: ignore[method-assign]
    runner = AnalysisRunner(Settings())

    assert await runner._delta(make_report("r2", [build(ctx, key="x")])) is None


# --------------------------------------------------------------------------
# Reopened: fixed once, and back
# --------------------------------------------------------------------------

def _finding(ctx: RuleContext, key: str) -> Finding:
    """A finding whose fingerprint is stable across reports."""
    return build(ctx, rule_id="security/sql-injection", file="api/users.js", key=key)


def test_a_returning_finding_is_reopened_not_new(ctx):
    """The distinction the whole feature exists for.

    "You introduced this" and "the fix for this did not hold" call for
    different reactions, and reporting both as `new` loses the more
    interesting of the two.
    """
    problem = _finding(ctx, "leak-1")

    oldest = make_report("r1", [problem], minutes_ago=30)   # present
    previous = make_report("r2", [], minutes_ago=20)        # fixed
    current = make_report("r3", [problem], minutes_ago=10)  # back

    delta = compare(current, previous, [oldest])

    assert delta.reopened == [problem.fingerprint]
    assert delta.new == []
    assert delta.unchanged == 0


def test_new_and_reopened_are_disjoint(ctx):
    returning = _finding(ctx, "old-problem")
    fresh = build(ctx, rule_id="security/ssrf", file="api/proxy.js", key="brand-new")

    oldest = make_report("r1", [returning], minutes_ago=30)
    previous = make_report("r2", [], minutes_ago=20)
    current = make_report("r3", [returning, fresh], minutes_ago=10)

    delta = compare(current, previous, [oldest])

    assert delta.reopened == [returning.fingerprint]
    assert delta.new == [fresh.fingerprint]
    assert not set(delta.new) & set(delta.reopened)


def test_without_history_a_returning_finding_reads_as_new(ctx):
    """`earlier` is optional, and its absence must not invent a regression.

    Reports written before reopening was tracked carry no history, and "new" is
    the honest answer when you cannot see far enough back to know otherwise.
    """
    problem = _finding(ctx, "leak-1")
    previous = make_report("r2", [], minutes_ago=20)
    current = make_report("r3", [problem], minutes_ago=10)

    delta = compare(current, previous)

    assert delta.new == [problem.fingerprint]
    assert delta.reopened == []


def test_a_finding_that_never_went_away_is_unchanged_not_reopened(ctx):
    """Present throughout. The window must not turn continuity into a
    regression."""
    problem = _finding(ctx, "always-here")

    oldest = make_report("r1", [problem], minutes_ago=30)
    previous = make_report("r2", [problem], minutes_ago=20)
    current = make_report("r3", [problem], minutes_ago=10)

    delta = compare(current, previous, [oldest])

    assert delta.unchanged == 1
    assert delta.reopened == []
    assert delta.new == []


def test_reopening_is_detected_several_analyses_later(ctx):
    """Fixed once, clean for a while, then regressed — the realistic shape."""
    problem = _finding(ctx, "regression")

    history = [
        make_report("r5", [], minutes_ago=20),
        make_report("r4", [], minutes_ago=30),
        make_report("r3", [], minutes_ago=40),
        make_report("r2", [problem], minutes_ago=50),
        make_report("r1", [problem], minutes_ago=60),
    ]
    current = make_report("r6", [problem], minutes_ago=10)

    delta = compare(current, history[0], history[1:])

    assert delta.reopened == [problem.fingerprint]
    assert delta.new == []


def test_resolved_still_reported_alongside_reopened(ctx):
    """The three states have to coexist without stealing from each other."""
    returning = _finding(ctx, "returning")
    going = build(ctx, rule_id="quality/long-file", file="big.ts", key="going")

    oldest = make_report("r1", [returning], minutes_ago=30)
    previous = make_report("r2", [going], minutes_ago=20)
    current = make_report("r3", [returning], minutes_ago=10)

    delta = compare(current, previous, [oldest])

    assert delta.reopened == [returning.fingerprint]
    assert [r.fingerprint for r in delta.resolved] == [going.fingerprint]
    assert delta.new == []
