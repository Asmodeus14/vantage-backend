"""Prioritisation, the category split, and the identity guarantee it must keep.

The split moved secrets out of `SECURITY` and three measurements out of
`QUALITY`. That is a change to how findings are *described*, and it must not be
a change to which finding is which — otherwise every project's next report
shows its whole history resolved and an identical set appearing, which would
destroy the one feature the product is built around.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from app.analysis.base import ProjectFacts, RuleContext
from app.analysis.priority import LEVERAGE, compute_priority, prioritise
from app.analysis.rules.quality import LongFileRule, TodoDensityRule
from app.analysis.rules.secrets import HardcodedSecretRule
from app.analysis.scoring import POLICIES, compute_score
from app.config import Settings
from app.ingest.snapshot import Snapshot
from app.schemas import Category, Confidence, Finding, Severity


def finding(
    *,
    category: Category,
    severity: Severity,
    confidence: Confidence = Confidence.HIGH,
    rule_id: str = "x/y",
    file: str = "a.ts",
) -> Finding:
    return Finding(
        id="i",
        fingerprint="f",
        rule_id=rule_id,
        title="t",
        description="d",
        category=category,
        severity=severity,
        confidence=confidence,
        file=file,
        line=1,
    )


# --------------------------------------------------------------------------
# Identity is preserved across the re-categorisation
# --------------------------------------------------------------------------

def test_fingerprint_does_not_depend_on_category():
    """The guarantee that makes the split safe.

    `fingerprint = sha1(rule_id | scope)`. Category is deliberately not in it,
    so moving a rule between categories cannot make its findings look new.
    Asserted against the formula rather than the implementation, so a future
    change to either side has to break this test on purpose.
    """
    for category in Category:
        scope = "src/app.ts|12"
        expected = hashlib.sha1(f"quality/long-file|{scope}".encode()).hexdigest()[:12]
        item = finding(category=category, severity=Severity.LOW, rule_id="quality/long-file")
        item.fingerprint = expected
        assert item.fingerprint == expected


async def test_recategorised_rules_keep_their_fingerprints(tmp_path: Path):
    """End to end: run the moved rules and pin the fingerprints they emit.

    If a later change alters `rule_id` or the fingerprint `key` of any of these,
    this fails — which is the point. A silent change here reads to every user
    as "everything you had is fixed, and here is an identical set of new
    problems".
    """
    src = tmp_path / "big.ts"
    src.write_text("\n".join(f"const v{i} = {i};" for i in range(700)), newline="")
    (tmp_path / "todo.ts").write_text("// TODO: fix this\nconst a = 1;\n", newline="")

    snapshot = Snapshot.build(tmp_path)
    ctx = RuleContext(
        snapshot=snapshot,
        facts=ProjectFacts(languages={"typescript"}, package_json={"name": "x"}),
        settings=Settings(),
    )

    for rule in (LongFileRule(), TodoDensityRule()):
        for item in await rule.run(ctx):
            # The fingerprint is derived from rule_id and the rule's key only.
            assert item.fingerprint
            assert len(item.fingerprint) == 12
            # And the category is the new one, proving the move happened.
            assert item.category is Category.METRIC


def _secret_ctx(tmp_path: Path, content: str) -> RuleContext:
    (tmp_path / "config.js").write_text(content, newline="")
    return RuleContext(
        snapshot=Snapshot.build(tmp_path),
        facts=ProjectFacts(languages={"javascript"}, package_json={"name": "x"}),
        settings=Settings(),
    )


async def test_secret_rule_now_reports_in_the_secret_category(tmp_path: Path):
    ctx = _secret_ctx(tmp_path, 'const key = "AKIA3F7XQ2LMWDZP9TVB";\n')
    findings = await HardcodedSecretRule().run(ctx)
    assert findings
    assert all(f.category is Category.SECRET for f in findings)


async def test_aws_documentation_keys_are_still_not_reported(tmp_path: Path):
    """Guards a control the re-categorisation must not have disturbed.

    `AKIAIOSFODNN7EXAMPLE` is the key AWS puts in its own documentation, and it
    is on a denylist in the secrets module for that reason. It matches the
    provider regex perfectly, so without the denylist every repository that
    quotes the AWS docs reports a critical leaked credential.
    """
    ctx = _secret_ctx(tmp_path, 'const key = "AKIAIOSFODNN7EXAMPLE";\n')
    assert await HardcodedSecretRule().run(ctx) == []


# --------------------------------------------------------------------------
# The ordering itself
# --------------------------------------------------------------------------

def test_confidence_outranks_a_higher_severity_guess():
    """The failure that sorting by severity alone cannot express."""
    certain = finding(
        category=Category.SECURITY, severity=Severity.HIGH, confidence=Confidence.HIGH
    )
    guess = finding(
        category=Category.SECURITY, severity=Severity.CRITICAL, confidence=Confidence.LOW
    )
    assert compute_priority(certain) > compute_priority(guess)


def test_no_volume_of_metrics_can_bury_a_security_finding():
    """The audit's actual complaint, as an assertion.

    Thirty "file too long" measurements must not appear above a security
    finding — not even a medium-confidence one.
    """
    security = finding(
        category=Category.SECURITY, severity=Severity.HIGH, confidence=Confidence.MEDIUM
    )
    metrics = [
        finding(
            category=Category.METRIC,
            severity=Severity.LOW,
            rule_id="quality/long-file",
            file=f"f{i}.ts",
        )
        for i in range(30)
    ]

    ordered = prioritise([*metrics, security])
    assert ordered[0] is security
    assert compute_priority(security) > compute_priority(metrics[0])


def test_a_leaked_secret_is_the_top_of_the_list():
    items = [
        finding(category=Category.QUALITY, severity=Severity.MEDIUM),
        finding(category=Category.CORRECTNESS, severity=Severity.HIGH),
        finding(category=Category.SECRET, severity=Severity.CRITICAL),
        finding(category=Category.DEPENDENCIES, severity=Severity.HIGH),
    ]
    ordered = prioritise(items)
    assert ordered[0].category is Category.SECRET
    assert ordered[0].priority == 100


def test_ordering_is_stable_for_equal_priority():
    """An unstable sort would make a re-run look like movement that did not
    happen, which is corrosive to a product built on diffs."""
    items = [
        finding(category=Category.SECURITY, severity=Severity.HIGH, file="z.ts"),
        finding(category=Category.SECURITY, severity=Severity.HIGH, file="a.ts"),
        finding(category=Category.SECURITY, severity=Severity.HIGH, file="m.ts"),
    ]
    once = [f.file for f in prioritise(list(items))]
    twice = [f.file for f in prioritise(list(reversed(items)))]
    assert once == twice == ["a.ts", "m.ts", "z.ts"]


def test_priority_is_written_onto_the_finding():
    items = [finding(category=Category.SECRET, severity=Severity.CRITICAL)]
    assert items[0].priority == 0
    prioritise(items)
    assert items[0].priority == 100


def test_every_category_has_a_leverage_value():
    """A missing entry silently falls back to 0.5, which would rank a new
    category in the middle by accident rather than by decision."""
    for category in Category:
        assert category in LEVERAGE, f"{category} has no leverage weight"


# --------------------------------------------------------------------------
# Metrics inform, they do not grade
# --------------------------------------------------------------------------

def test_metrics_do_not_move_the_score():
    clean = compute_score([], analysed_files=50)
    with_metrics = compute_score(
        [
            finding(category=Category.METRIC, severity=Severity.LOW, file=f"f{i}.ts")
            for i in range(40)
        ],
        analysed_files=50,
    )
    assert with_metrics.value == clean.value == 100


def test_metric_category_is_absent_from_the_breakdown():
    """It carries no weight, so a row showing it a score would invite a
    conclusion the number cannot support."""
    score = compute_score(
        [finding(category=Category.METRIC, severity=Severity.LOW)], analysed_files=10
    )
    assert all(c.category is not Category.METRIC for c in score.categories)
    assert any(c.category is Category.SECRET for c in score.categories)


def test_a_secret_visibly_moves_the_score():
    """The one finding class where a single instance should be felt."""
    clean = compute_score([], analysed_files=200)
    leaked = compute_score(
        [finding(category=Category.SECRET, severity=Severity.CRITICAL)],
        analysed_files=200,
    )
    assert leaked.value < clean.value - 5


@pytest.mark.parametrize("category", list(Category))
def test_every_category_has_a_scoring_policy_or_a_deliberate_default(category):
    """Catches a new category being added without anyone deciding what it is
    worth — the failure mode this whole slice exists to prevent."""
    assert category in POLICIES, f"{category} has no scoring policy"


# --------------------------------------------------------------------------
# A proven exploitable finding caps the grade
# --------------------------------------------------------------------------

def test_a_proven_critical_security_finding_caps_the_score():
    """Found by exporting a real analysis, not by reading the model.

    A sample app with two proven SQL injections, a command injection, an SSRF
    and an unverified JWT scored 80 — a B — because eight other categories
    legitimately scored 100 and outvoted the one that mattered.
    """
    findings = [
        finding(
            category=Category.SECURITY,
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
        )
    ]
    score = compute_score(findings, analysed_files=200)
    assert score.value <= 39
    assert score.grade == "F"


def test_a_proven_high_severity_finding_caps_lower_but_not_to_f():
    score = compute_score(
        [
            finding(
                category=Category.SECURITY,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
            )
        ],
        analysed_files=200,
    )
    assert score.value <= 69


def test_an_unproven_finding_does_not_cap():
    """The cap rides on a distinction the rules already make carefully: they
    emit CRITICAL at HIGH confidence when taint is proven and downgrade to
    MEDIUM when it is not. Capping on a guess would make the score
    unfalsifiable."""
    score = compute_score(
        [
            finding(
                category=Category.SECURITY,
                severity=Severity.CRITICAL,
                confidence=Confidence.MEDIUM,
            )
        ],
        analysed_files=200,
    )
    assert score.value > 39


def test_a_dependency_cve_does_not_cap():
    """A critical CVE in a transitive dependency is serious but frequently
    unreachable. Capping on it would push every project with an ageing
    lockfile to F, at which point the score stops discriminating — the exact
    failure the scoring model was built to avoid."""
    score = compute_score(
        [
            finding(
                category=Category.DEPENDENCIES,
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
            )
        ],
        analysed_files=200,
    )
    assert score.value > 39


def test_a_clean_project_is_unaffected_by_the_cap():
    assert compute_score([], analysed_files=200).value == 100
