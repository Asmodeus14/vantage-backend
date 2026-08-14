"""The pull request comment.

A developer's review happens in the pull request, not in a dashboard they have
to remember to open. This renders one comment — and the endpoint that posts it
edits that same comment in place on every re-run rather than adding another, so
a branch pushed twelve times has one Vantage comment at the end of it and not
twelve.

The comment leads with **what changed**, not with the full finding list. A PR
author already knows the repository has debt; what they need to know is whether
*this branch* added to it. That is the one thing Vantage knows and a
first-time scanner does not, so it is the thing the comment is built around.

Everything else is a link. A comment that reproduces the whole report is a
comment people collapse.
"""

from __future__ import annotations

from app.schemas import Finding, Report, Severity

# Lets the poster find its own previous comment and edit it instead of adding
# a new one. Invisible in rendered markdown.
MARKER = "<!-- vantage:report -->"

# Enough to act on, few enough to read without collapsing the comment.
MAX_LISTED = 10

SEVERITY_MARK: dict[Severity, str] = {
    Severity.CRITICAL: "critical",
    Severity.HIGH: "high",
    Severity.MEDIUM: "medium",
    Severity.LOW: "low",
    Severity.INFO: "info",
}


def _location(file: str | None, line: int | None = None) -> str:
    if not file:
        return "—"
    return f"`{file}:{line}`" if line else f"`{file}`"


def _finding_row(finding: Finding) -> str:
    return (
        f"| {SEVERITY_MARK[finding.severity]} "
        f"| {finding.title} "
        f"| {_location(finding.file, finding.line)} |"
    )


def render_comment(report: Report, *, report_url: str, head_sha: str | None = None) -> str:
    """Markdown for one consolidated PR comment."""
    lines: list[str] = [MARKER]

    title = report.source.repository or report.source.filename or "Analysis"
    heading = f"### Vantage — `{title}`"
    if head_sha:
        heading += f" @ `{head_sha[:7]}`"
    lines.append(heading)
    lines.append("")

    score = report.effective_score or report.score
    delta = report.delta

    if delta is None:
        # First analysis of this repository. Saying "0 new" would be false —
        # everything is new — and saying nothing changed would be worse.
        lines.append(
            f"**{len(report.findings)} findings** · Score **{score.value}** "
            f"({score.grade})"
        )
        lines.append("")
        lines.append(
            "_First analysis of this repository, so there is nothing to compare "
            "against yet. Re-run after merging to see what a branch changes._"
        )
    else:
        lines.append(
            f"**{len(delta.new)} new · {len(delta.resolved)} resolved · "
            f"{delta.unchanged} unchanged** · Score **{score.value}** ({score.grade})"
        )

    lines.append("")

    # --- New -------------------------------------------------------------
    if delta and delta.new:
        new_prints = set(delta.new)
        # Already ordered worst-first by the runner, so this needs no sort of
        # its own — and must not have one, or the comment and the report page
        # would disagree about what matters.
        new_findings = [f for f in report.findings if f.fingerprint in new_prints]

        lines.append(f"#### New in this branch ({len(new_findings)})")
        lines.append("")
        lines.append("| | Finding | Location |")
        lines.append("|---|---|---|")
        for finding in new_findings[:MAX_LISTED]:
            lines.append(_finding_row(finding))
        lines.append("")
        if len(new_findings) > MAX_LISTED:
            lines.append(
                f"_…and {len(new_findings) - MAX_LISTED} more. "
                f"[See all in the report]({report_url}?tab=findings&new=1)._"
            )
            lines.append("")

    # --- Resolved --------------------------------------------------------
    if delta and delta.resolved:
        lines.append(f"#### Resolved ({len(delta.resolved)})")
        lines.append("")
        for resolved in delta.resolved[:MAX_LISTED]:
            lines.append(
                f"- {SEVERITY_MARK[resolved.severity]} {resolved.title} "
                f"— {_location(resolved.file)}"
            )
        if len(delta.resolved) > MAX_LISTED:
            lines.append(f"- _…and {len(delta.resolved) - MAX_LISTED} more_")
        lines.append("")

    # --- Caveats ---------------------------------------------------------
    if delta and delta.new_rules:
        # Otherwise "12 new findings" reads as a regression the author caused,
        # when some of it is a rule that did not exist last time.
        lines.append(
            f"> Some of these come from {len(delta.new_rules)} rule"
            f"{'s' if len(delta.new_rules) != 1 else ''} added since the previous "
            "analysis, not from this branch."
        )
        lines.append("")

    if report.truncated:
        lines.append(
            "> The finding list was capped, so this comparison is not "
            "exhaustive."
        )
        lines.append("")

    lines.append(f"[Full report →]({report_url})")

    return "\n".join(lines)
