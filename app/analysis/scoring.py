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

from app.schemas import Category, CategoryScore, Confidence, Finding, Score, SeverityCounts, Severity

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
    Category.SECURITY: CategoryPolicy(weight=3.0, sensitivity=0.30, size_normalised=False),
    Category.DEPENDENCIES: CategoryPolicy(weight=2.0, sensitivity=0.18, size_normalised=False),
    Category.CORRECTNESS: CategoryPolicy(weight=2.0, sensitivity=0.12, size_normalised=True),
    Category.TESTING: CategoryPolicy(weight=1.5, sensitivity=0.35, size_normalised=False),
    Category.CONFIGURATION: CategoryPolicy(weight=1.0, sensitivity=0.30, size_normalised=False),
    Category.PERFORMANCE: CategoryPolicy(weight=1.0, sensitivity=0.15, size_normalised=True),
    Category.QUALITY: CategoryPolicy(weight=1.0, sensitivity=0.10, size_normalised=True),
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
        score=int(round(max(0.0, min(100.0, value)))),
        findings=len(relevant),
        weight=policy.weight,
    )


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


def _summarise(value: int, categories: list[CategoryScore], counts: SeverityCounts) -> str:
    if counts.total == 0:
        return "No issues detected across the rules that applied to this project."

    weakest = min(categories, key=lambda c: c.score) if categories else None
    blocking = counts.critical + counts.high

    if blocking:
        lead = (
            f"{blocking} issue{'s' if blocking != 1 else ''} "
            f"need{'' if blocking != 1 else 's'} attention first"
        )
    else:
        lead = "No critical or high-severity issues"

    if weakest and weakest.findings:
        return (
            f"{lead}. {weakest.category.value.title()} is the weakest area "
            f"({weakest.score}/100 across {weakest.findings} finding"
            f"{'s' if weakest.findings != 1 else ''})."
        )
    return f"{lead}."


def compute_score(findings: list[Finding], analysed_files: int) -> Score:
    present = [c for c in Category if any(f.category == c for f in findings)]
    # Include categories with no findings so the UI can show a full picture.
    categories = [category_score(findings, c, analysed_files) for c in Category]

    total_weight = sum(POLICIES.get(c.category, DEFAULT_POLICY).weight for c in categories)
    weighted = sum(
        c.score * POLICIES.get(c.category, DEFAULT_POLICY).weight for c in categories
    )
    value = int(round(weighted / total_weight)) if total_weight else 100

    counts = severity_counts(findings)
    scored = [c for c in categories if c.category in present] or categories

    return Score(
        value=max(0, min(100, value)),
        grade=grade_for(value),
        categories=categories,
        summary=_summarise(value, scored, counts),
    )
