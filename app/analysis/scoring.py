"""Health scoring.

v2 used ``100 - 10*high - 5*medium - 2*low``. That has two problems: it reaches
zero after ten high-severity findings regardless of project size, so every
large codebase scores 0 and the number stops discriminating; and it explains
nothing, so the UI could only display a bare figure.

This model instead:

* weights findings by severity **and confidence**, so a low-confidence heuristic
  hit costs less than a confirmed CVE;
* normalises by project size for categories where volume scales with the
  codebase (quality), while keeping absolute counts for categories where it
  does not (one leaked credential is equally bad in any repo);
* uses a saturating curve, so the score degrades smoothly and never collapses
  to zero from a handful of findings;
* returns a per-category breakdown so the UI can show *why*.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.schemas import (
    Category,
    CategoryScore,
    Confidence,
    Finding,
    Score,
    Severity,
    SeverityCounts,
)

SEVERITY_WEIGHT: dict[Severity, float] = {
    Severity.CRITICAL: 10.0,
    Severity.HIGH: 6.0,
    Severity.MEDIUM: 3.0,
    Severity.LOW: 1.0,
    Severity.INFO: 0.25,
}

CONFIDENCE_FACTOR: dict[Confidence, float] = {
    Confidence.HIGH: 1.0,
    Confidence.MEDIUM: 0.7,
    Confidence.LOW: 0.4,
}


@dataclass(frozen=True)
class CategoryPolicy:
    weight: float          # contribution to the overall score
    sensitivity: float     # how fast the score falls as penalty accumulates
    size_normalised: bool  # divide penalty by project size?


# Security and dependency issues are judged on absolute count. Quality and
# testing scale with the codebase, so they are normalised by size.
POLICIES: dict[Category, CategoryPolicy] = {
    # A committed credential is an incident rather than a weakness, and is the
    # one finding class where a single instance should visibly move the score.
    Category.SECRET: CategoryPolicy(weight=3.0, sensitivity=0.60, size_normalised=False),
    Category.SECURITY: CategoryPolicy(weight=3.0, sensitivity=0.30, size_normalised=False),
    Category.DEPENDENCIES: CategoryPolicy(weight=2.0, sensitivity=0.18, size_normalised=False),
    Category.CORRECTNESS: CategoryPolicy(weight=2.0, sensitivity=0.12, size_normalised=True),
    Category.TESTING: CategoryPolicy(weight=1.5, sensitivity=0.35, size_normalised=False),
    Category.CONFIGURATION: CategoryPolicy(weight=1.0, sensitivity=0.30, size_normalised=False),
    Category.PERFORMANCE: CategoryPolicy(weight=1.0, sensitivity=0.15, size_normalised=True),
    Category.QUALITY: CategoryPolicy(weight=1.0, sensitivity=0.10, size_normalised=True),
    # Weight 0: metrics are measurements, not defects. A 1,200-line file is a
    # fact about the codebase, not a thing that is wrong with it, and grading
    # on it means a large project can never score well no matter how carefully
    # it is written. They are still computed and still shown — `weight=0` keeps
    # them out of the average without hiding them.
    Category.METRIC: CategoryPolicy(weight=0.0, sensitivity=0.10, size_normalised=True),
}

DEFAULT_POLICY = CategoryPolicy(weight=1.0, sensitivity=0.15, size_normalised=True)


def finding_penalty(finding: Finding) -> float:
    return SEVERITY_WEIGHT[finding.severity] * CONFIDENCE_FACTOR[finding.confidence]


def _size_divisor(analysed_files: int) -> float:
    """Sub-linear normalisation.

    Dividing by file count outright would make large projects nearly immune to
    quality findings. The square root keeps larger codebases meaningfully
    accountable while not punishing them for existing.
    """
    return max(1.0, (max(analysed_files, 1)) ** 0.5)


def category_score(
    findings: list[Finding], category: Category, analysed_files: int
) -> CategoryScore:
    policy = POLICIES.get(category, DEFAULT_POLICY)
    relevant = [f for f in findings if f.category == category]

    penalty = sum(finding_penalty(f) for f in relevant)
    if policy.size_normalised:
        penalty /= _size_divisor(analysed_files)

    # Saturating: score = 100 / (1 + k·penalty). Never negative, never exactly
    # zero, and each additional finding costs less than the last.
    value = 100.0 / (1.0 + policy.sensitivity * penalty)

    return CategoryScore(
        category=category,
        score=round(max(0.0, min(100.0, value))),
        findings=len(relevant),
        weight=policy.weight,
    )


# A weighted average across categories describes how *broadly* a codebase is
# in good shape. It is a poor description of how *dangerous* it is, and the two
# get confused because they share a number.
#
# Measured on a sample app with two proven SQL injections, a command injection,
# an SSRF and an unverified JWT: it scored 80, a B. Not a bug in the average —
# eight other categories legitimately scored 100 and outvoted the one that
# mattered. But a product whose whole claim is "tells you what needs your
# attention" cannot hand that codebase a B.
#
# So the average is a ceiling, not the answer. A proven, exploitable finding in
# first-party code caps the grade regardless of how clean everything else is.
SEVERITY_CAP: dict[Severity, int] = {
    Severity.CRITICAL: 39,  # F
    Severity.HIGH: 69,      # D
}

# Only these cap. A critical CVE in a transitive dependency is serious but
# frequently unreachable, and capping on it would push every project with an
# ageing lockfile to F — at which point the score stops discriminating, which
# is the exact failure the current model was built to avoid.
CAPPING_CATEGORIES = frozenset({Category.SECURITY, Category.SECRET})


def _cap(findings: list[Finding]) -> int:
    """The lowest ceiling any single finding imposes.

    Confidence-gated: only findings the rules are sure about cap the score.
    The security rules emit CRITICAL at HIGH confidence exactly when taint is
    proven and downgrade to MEDIUM when it is not, so this rides on a
    distinction that is already made carefully rather than inventing one.
    """
    ceiling = 100
    for finding in findings:
        if finding.category not in CAPPING_CATEGORIES:
            continue
        if finding.confidence is not Confidence.HIGH:
            continue
        ceiling = min(ceiling, SEVERITY_CAP.get(finding.severity, 100))
    return ceiling


def grade_for(value: int) -> str:
    if value >= 90:
        return "A"
    if value >= 80:
        return "B"
    if value >= 70:
        return "C"
    if value >= 60:
        return "D"
    return "F"


def severity_counts(findings: list[Finding]) -> SeverityCounts:
    counts = SeverityCounts()
    for finding in findings:
        setattr(counts, finding.severity.value, getattr(counts, finding.severity.value) + 1)
    return counts


# Categories where a finding is work someone can do, as opposed to a
# measurement or a judgement about style. The summary names one of these or it
# names nothing.
ACTIONABLE = frozenset(
    {Category.SECRET, Category.SECURITY, Category.DEPENDENCIES, Category.CORRECTNESS}
)


def _decapitalise(title: str) -> str:
    """Lower the first letter, unless it begins an acronym.

    Rule titles start capitalised because they are titles. Dropping one into
    mid-sentence needs it lowered — except that several begin with an acronym,
    and a naive `title[0].lower()` produced "aWS access key ID committed to the
    repository" and "sQL statement assembled from an interpolated value".

    A second uppercase character means the first belongs to a word like AWS,
    SQL, JWT or MD5, which keeps its case.
    """
    if len(title) < 2 or title[1].isupper():
        return title
    return title[0].lower() + title[1:]


def _lead_finding(findings: list[Finding]) -> Finding | None:
    """The one thing to do first, or nothing worth naming.

    Confidence-gated: naming a finding puts it in the report header, the pull
    request comment and the social preview card, and doing that for something
    the rules are unsure about would be the loudest possible place to be wrong.
    """
    candidates = [
        f
        for f in findings
        if f.category in ACTIONABLE
        and f.confidence is Confidence.HIGH
        and f.severity in {Severity.CRITICAL, Severity.HIGH}
        and not f.suppressed
    ]
    return max(candidates, key=lambda f: f.priority, default=None)


def _summarise(
    value: int,
    categories: list[CategoryScore],
    counts: SeverityCounts,
    findings: list[Finding],
) -> str:
    """One sentence, and it has to earn its place.

    This used to end with "Dependencies is the weakest area (65/100 across 1
    finding)". That is a property of the scoring model, not an instruction —
    it tells a reader which bucket the arithmetic disliked, not what to do. The
    sentence is read in three places that all want the same thing: the report
    header, the pull request comment, and the `og:description` of a shared
    link.

    So it names the work when there is work, and says so plainly when there is
    not. What it must never do is claim safety: "nothing blocking found" is
    defensible from a rule set with documented limits, "your app is secure" is
    not, and no wording here should imply the second.
    """
    if counts.total == 0:
        return "No issues detected across the rules that applied to this project."

    lead = _lead_finding(findings)

    if lead is not None:
        others = sum(
            1
            for f in findings
            if f is not lead
            and f.category in ACTIONABLE
            and f.confidence is Confidence.HIGH
            and f.severity in {Severity.CRITICAL, Severity.HIGH}
            and not f.suppressed
        )
        where = f" in {lead.file}" if lead.file else ""
        tail = (
            f", then {others} other issue{'s' if others != 1 else ''} of the same kind"
            if others
            else ""
        )
        return f"Start with {_decapitalise(lead.title)}{where}{tail}."

    # Nothing proven and serious. Say what was found rather than what the
    # scoring model thought of it.
    blocking = counts.critical + counts.high
    if blocking:
        return (
            f"{blocking} finding{'s' if blocking != 1 else ''} of high severity, "
            f"{'none of them confirmed' if blocking != 1 else 'not confirmed'} — "
            "worth reviewing before acting."
        )
    return (
        f"Nothing blocking found. {counts.total} lower-severity "
        f"finding{'s' if counts.total != 1 else ''} to look at when convenient."
    )
    return f"{lead}."


def compute_score(findings: list[Finding], analysed_files: int) -> Score:
    present = [c for c in Category if any(f.category == c for f in findings)]
    # Include categories with no findings so the UI can show a full picture,
    # but not ones that carry no weight: a breakdown row saying "Metric 45/100"
    # next to a score it contributed nothing to is a number that invites a
    # conclusion it cannot support.
    categories = [
        category_score(findings, c, analysed_files)
        for c in Category
        if POLICIES.get(c, DEFAULT_POLICY).weight > 0
    ]

    total_weight = sum(POLICIES.get(c.category, DEFAULT_POLICY).weight for c in categories)
    weighted = sum(
        c.score * POLICIES.get(c.category, DEFAULT_POLICY).weight for c in categories
    )
    value = round(weighted / total_weight) if total_weight else 100
    # The average is the ceiling, not the answer.
    value = min(value, _cap(findings))

    counts = severity_counts(findings)
    scored = [c for c in categories if c.category in present] or categories

    return Score(
        value=max(0, min(100, value)),
        grade=grade_for(value),
        categories=categories,
        summary=_summarise(value, scored, counts, findings),
    )
