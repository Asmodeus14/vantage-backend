"""Finding priority — the answer to "what should I fix first?".

Sorting by severity alone gets this wrong in both directions. It puts a
low-confidence guess above a certainty one step below it, and it puts "this
file is long" — reported at LOW, but reported *often* — in the same ranking as
a leaked credential, so a large repository buries its real findings under its
own volume.

Priority multiplies three things the report already knows:

    severity   how bad it is if real
    confidence how sure the rule is that it is real
    leverage   how much the reader can do about it right now

**Leverage is the part that is not already on the finding**, and it is the part
that makes the ordering useful. A committed AWS key and a 1,200-line file can
both be true statements about a codebase; only one of them is work. Leverage
encodes that difference once, here, rather than leaving every consumer to
rediscover it.

The result is a 0-100 integer stored on the finding, so the ordering is
computed once on the server and the UI does not reimplement — and disagree
with — it.

Deliberately *not* multiplied in: how many other findings share the rule, and
how recently the finding appeared. Both are real signals and both belong to the
report rather than the finding, so folding them in here would make a finding's
priority depend on its neighbours and change under filtering.
"""

from __future__ import annotations

from app.schemas import Category, Confidence, Finding, Severity

# Shared with scoring: the same severity ladder should not be defined twice
# with different numbers.
SEVERITY_WEIGHT: dict[Severity, float] = {
    Severity.CRITICAL: 10.0,
    Severity.HIGH: 6.0,
    Severity.MEDIUM: 3.0,
    Severity.LOW: 1.0,
    Severity.INFO: 0.25,
}

CONFIDENCE_FACTOR: dict[Confidence, float] = {
    Confidence.HIGH: 1.0,
    Confidence.MEDIUM: 0.55,
    Confidence.LOW: 0.25,
}

# How actionable a category is, not how serious. Serious is `severity`.
#
# The spread is wide on purpose. A MEDIUM-confidence security finding
# (6 x 0.55 x 1.0 = 3.30) must outrank a HIGH-confidence long-file metric
# (1 x 1.0 x 0.1 = 0.10) by enough that no amount of the latter can bury the
# former — which is the failure the audit described.
LEVERAGE: dict[Category, float] = {
    Category.SECRET: 1.0,        # already leaked; rotate it today
    Category.SECURITY: 1.0,      # exploitable, and the fix is local
    Category.DEPENDENCIES: 0.85,  # real, but the fix is a version bump
    Category.CORRECTNESS: 0.75,  # a bug, though not necessarily reachable
    Category.PERFORMANCE: 0.45,
    Category.CONFIGURATION: 0.40,
    Category.TESTING: 0.35,
    Category.QUALITY: 0.30,
    Category.METRIC: 0.10,       # a measurement; there is nothing to fix
}

DEFAULT_LEVERAGE = 0.50

# 10.0 x 1.0 x 1.0 — a CRITICAL, HIGH-confidence secret or security finding.
_MAX_RAW = 10.0


def raw_priority(finding: Finding) -> float:
    return (
        SEVERITY_WEIGHT[finding.severity]
        * CONFIDENCE_FACTOR[finding.confidence]
        * LEVERAGE.get(finding.category, DEFAULT_LEVERAGE)
    )


def compute_priority(finding: Finding) -> int:
    """0-100. 100 is "stop reading and fix this"."""
    return round(min(100.0, raw_priority(finding) / _MAX_RAW * 100.0))


def prioritise(findings: list[Finding]) -> list[Finding]:
    """Set `priority` on every finding and return them worst-first.

    Ties break on severity, then on file path, so the order is stable across
    runs — an unstable list would make the diff between two reports look like
    movement that did not happen.
    """
    for finding in findings:
        finding.priority = compute_priority(finding)

    severity_rank = list(Severity)
    return sorted(
        findings,
        key=lambda f: (
            -f.priority,
            severity_rank.index(f.severity),
            f.file or "",
            f.line or 0,
            f.rule_id,
        ),
    )
