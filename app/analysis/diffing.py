"""Comparing a report against the previous analysis of the same repository.

The question a maintainer actually has is not "how many problems are there" but
"did this get better". That needs findings to have an identity that survives an
edit, which is :attr:`Finding.fingerprint`, and a previous report to compare
against, which is chosen here.

The comparison is computed once, when the report is created, and stored on it.
Deriving it on read would mean the answer drifted as newer reports arrived: a
report someone bookmarked would quietly begin describing a different comparison
than the one it was created with.
"""

from __future__ import annotations

from app.schemas import FindingDelta, Report, ResolvedFinding


def compare(current: Report, previous: Report) -> FindingDelta:
    """What changed between two reports of the same repository.

    Both sides are matched on fingerprint alone. A finding whose fingerprint is
    empty — every report written before diffing existed — is skipped rather than
    grouped under a shared empty key, which would have made them all match each
    other.
    """
    previous_prints = {f.fingerprint for f in previous.findings if f.fingerprint}
    current_prints = {f.fingerprint for f in current.findings if f.fingerprint}

    # Rules that ran this time but not last. Their findings are all new by the
    # fingerprint test even when the code is untouched, so the UI needs to be
    # able to say so.
    new_rules = sorted(set(current.rule_ids) - set(previous.rule_ids))

    resolved: list[ResolvedFinding] = []
    seen: set[str] = set()
    for finding in previous.findings:
        if not finding.fingerprint or finding.fingerprint in current_prints:
            continue
        if finding.fingerprint in seen:
            continue
        seen.add(finding.fingerprint)
        resolved.append(
            ResolvedFinding(
                fingerprint=finding.fingerprint,
                rule_id=finding.rule_id,
                title=finding.title,
                file=finding.file,
                severity=finding.severity,
            )
        )

    return FindingDelta(
        previous_report_id=previous.id,
        previous_created_at=previous.created_at,
        new=sorted(current_prints - previous_prints),
        resolved=resolved,
        unchanged=len(current_prints & previous_prints),
        new_rules=new_rules,
    )


def is_comparable(current: Report, previous: Report) -> bool:
    """Whether two reports describe the same thing closely enough to diff.

    Deliberately strict. A misleading comparison is worse than none, because
    the whole point is to be trusted about what changed.
    """
    # Uploads have no stable identity — two ZIPs with the same filename may be
    # unrelated projects — so only repository-to-repository is compared.
    if not current.source.repository or not previous.source.repository:
        return False
    if current.source.repository != previous.source.repository:
        return False
    if previous.id == current.id:
        return False
    # A truncated report is missing findings that were never written down, so
    # everything past the cap would read as resolved.
    if previous.truncated or current.truncated:
        return False
    # Nothing on the previous side to match against.
    return any(f.fingerprint for f in previous.findings) or not previous.findings
