"""SARIF 2.1.0 export.

Findings that cannot leave the tool that produced them are worth less than
findings that can. SARIF is the format GitHub code scanning, VS Code, Azure
DevOps and most review tooling already read, so exporting it is the difference
between Vantage being a place you visit and Vantage being something in a
workflow you already have.

Two mappings carry most of the value and neither is obvious from the spec:

**`partialFingerprints`.** SARIF consumers use these to recognise the same
result across runs — it is how GitHub avoids closing and reopening an alert
every time a file shifts by a line. Vantage already computes exactly that
identity for its own diffing, and it is deliberately more stable than location:
`quality/long-file` keys on the file, `dep/known-vulnerability` on the package
name so it survives a version bump. Handing it over means an importer inherits
the stability rather than re-deriving a worse version from line numbers.

**`suppressions`.** A finding the owner has accepted is not absent from the
export — it is present and marked suppressed, which is what SARIF models. An
importer then shows it as dismissed rather than as a new problem, and the
counts still reconcile with the report. Dropping them would be the same failure
as hiding them in the UI.

`security-severity` and `precision` are GitHub-specific property extensions.
They are how the security alert ranking and the false-positive triage in code
scanning work, and both are read from `properties` rather than from `level` —
without them every finding lands in the same undifferentiated bucket.
"""

from __future__ import annotations

from typing import Any

from app.schemas import Category, Confidence, Finding, Report, Severity

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
    "Schemata/sarif-schema-2.1.0.json"
)

TOOL_NAME = "Vantage"
INFORMATION_URI = "https://github.com/Asmodeus14/Vantage"

# SARIF has three meaningful levels, and Vantage has five severities. Mapping
# is lossy in one direction only: `security-severity` below carries the full
# ordering for consumers that rank on it.
LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

# GitHub code scanning reads this to sort and to decide what blocks a PR. The
# numbers are CVSS-shaped because that is what it expects; the string type is
# also what it expects, and a float here is silently ignored.
SECURITY_SEVERITY: dict[Severity, str] = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "3.0",
    Severity.INFO: "1.0",
}

# `precision` is the vocabulary code scanning uses for "how much should I trust
# this", which is exactly what Confidence means.
PRECISION: dict[Confidence, str] = {
    Confidence.HIGH: "high",
    Confidence.MEDIUM: "medium",
    Confidence.LOW: "low",
}

# Tags are free-form and are what most importers group and filter on.
CATEGORY_TAGS: dict[Category, list[str]] = {
    Category.SECRET: ["security", "secret"],
    Category.SECURITY: ["security"],
    Category.DEPENDENCIES: ["security", "dependency"],
    Category.CORRECTNESS: ["correctness"],
    Category.PERFORMANCE: ["performance"],
    Category.CONFIGURATION: ["configuration"],
    Category.TESTING: ["testing"],
    Category.QUALITY: ["maintainability"],
    Category.METRIC: ["maintainability", "metric"],
}


def _rule_descriptor(finding: Finding) -> dict[str, Any]:
    """One `reportingDescriptor` per rule.

    Built from the first finding each rule produced. Rule-level text has to be
    general — the specifics belong on the result — so the help text carries the
    remediation, which is the same for every instance of a rule.
    """
    descriptor: dict[str, Any] = {
        "id": finding.rule_id,
        "name": finding.rule_id.replace("/", "-"),
        "shortDescription": {"text": finding.title},
        "fullDescription": {"text": finding.description},
        "defaultConfiguration": {"level": LEVEL[finding.severity]},
        "properties": {
            "tags": CATEGORY_TAGS.get(finding.category, [finding.category.value]),
            "security-severity": SECURITY_SEVERITY[finding.severity],
            "precision": PRECISION[finding.confidence],
            "vantage-category": finding.category.value,
        },
    }
    if finding.remediation:
        descriptor["help"] = {"text": finding.remediation}
    # A rule may cite several references; SARIF has room for exactly one URI,
    # so the first is used and the rest ride along on the result.
    if finding.references:
        descriptor["helpUri"] = finding.references[0]
    return descriptor


def _location(finding: Finding) -> list[dict[str, Any]]:
    """Physical location, or nothing.

    Project-wide findings — "no test framework configured" — genuinely have no
    location. SARIF permits a result with no locations, and inventing one
    (line 1 of the repository root) would be a lie a consumer cannot detect.
    """
    if not finding.file:
        return []

    region: dict[str, Any] = {}
    if finding.line:
        region["startLine"] = finding.line
        if finding.end_line and finding.end_line >= finding.line:
            region["endLine"] = finding.end_line
    if finding.snippet:
        region["snippet"] = {"text": finding.snippet}

    physical: dict[str, Any] = {
        # `uriBaseId` keeps the path repository-relative, which is what lets an
        # importer match it against a checkout rather than a temp directory.
        "artifactLocation": {"uri": finding.file, "uriBaseId": "%SRCROOT%"},
    }
    if region:
        physical["region"] = region
    return [{"physicalLocation": physical}]


def _result(finding: Finding, rule_index: int) -> dict[str, Any]:
    result: dict[str, Any] = {
        "ruleId": finding.rule_id,
        "ruleIndex": rule_index,
        "level": LEVEL[finding.severity],
        # The message is the specific instance, not the rule's general text.
        "message": {"text": f"{finding.title}. {finding.description}"},
        "properties": {
            "vantage-category": finding.category.value,
            "vantage-confidence": finding.confidence.value,
            "vantage-severity": finding.severity.value,
            "vantage-priority": finding.priority,
        },
    }

    locations = _location(finding)
    if locations:
        result["locations"] = locations

    if finding.fingerprint:
        # Versioned: if the fingerprint scheme ever changes, a consumer can
        # tell the two apart instead of silently treating them as one identity.
        result["partialFingerprints"] = {"vantageFingerprint/v1": finding.fingerprint}

    if finding.suppressed:
        result["suppressions"] = [
            {
                "kind": "external",
                "justification": finding.suppression_reason
                or "Accepted by the report owner in Vantage.",
            }
        ]

    return result


def to_sarif(report: Report) -> dict[str, Any]:
    """Convert a report to a SARIF 2.1.0 log."""
    # Rules are deduplicated and indexed; `ruleIndex` must point into this list.
    rule_index: dict[str, int] = {}
    rules: list[dict[str, Any]] = []
    for finding in report.findings:
        if finding.rule_id not in rule_index:
            rule_index[finding.rule_id] = len(rules)
            rules.append(_rule_descriptor(finding))

    results = [_result(f, rule_index[f.rule_id]) for f in report.findings]

    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": TOOL_NAME,
                "informationUri": INFORMATION_URI,
                "rules": rules,
            }
        },
        "results": results,
        # Ties the export back to the analysis it came from, so a consumer
        # importing several runs can tell them apart.
        "automationDetails": {"id": f"vantage/{report.id}"},
        "columnKind": "unicodeCodePoints",
    }

    if report.source.repository and report.source.url:
        provenance: dict[str, Any] = {"repositoryUri": report.source.url}
        # Only a resolved commit is provenance. A branch name is a moving
        # target, and recording it as `revisionId` would let a consumer believe
        # it can reproduce this run when it cannot.
        if report.source.commit:
            provenance["revisionId"] = report.source.commit
        if report.source.ref:
            provenance["branch"] = report.source.ref
        run["versionControlProvenance"] = [provenance]

    if report.truncated:
        # Say so in the export too. A consumer that imports a capped run and
        # treats it as complete will report findings as resolved when they were
        # only cut off.
        run["properties"] = {
            "vantage-truncated": True,
            "vantage-truncated-note": (
                "The finding list was capped; this run is not exhaustive."
            ),
        }

    return {"$schema": SARIF_SCHEMA, "version": SARIF_VERSION, "runs": [run]}
