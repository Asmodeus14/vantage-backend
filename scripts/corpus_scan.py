"""Run the rule set over a corpus of checked-out repositories.

Written for one question the test suite cannot answer: **does a scan of a
normal application return anything worth reading?**

The security rules were validated against a deliberately vulnerable app written
to trigger them (11/11) and against `expressjs/express`, `psf/requests` and
Vantage itself (0 findings across ~360 files). Both samples are misleading in
opposite directions — one was built to be caught, the others are hardened
libraries that have had years of review. Neither says anything about the code
the product is actually for.

So the corpus is deliberately two halves:

* **Deliberately vulnerable applications** measure *recall*. Their flaws are
  known and documented, so a miss is a miss rather than an opinion.
* **Ordinary applications** measure *noise*. Every security finding here has
  to be read by hand and judged, because a false positive on real code is what
  makes people stop trusting a scanner.

Usage::

    python -m scripts.corpus_scan <corpus-dir> [--json out.json]

Each immediate subdirectory of ``corpus-dir`` is treated as one repository.
Offline: `osv_enabled=False` and `http=None`, so no rule reaches the network
and the numbers are reproducible.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from collections import Counter
from pathlib import Path

import app.analysis.rules  # noqa: F401  — registers every rule
from app.analysis.base import ProjectFacts, RuleContext, all_rules
from app.analysis.engine import build_facts
from app.analysis.priority import prioritise
from app.analysis.scoring import compute_score
from app.config import Settings
from app.ingest.snapshot import Snapshot
from app.schemas import Category, Finding

# Categories worth a human verdict. Everything else is a measurement or a
# style note, and reading five hundred of those by hand teaches nothing.
JUDGED = {Category.SECURITY, Category.SECRET}


def settings() -> Settings:
    """Offline, and deliberately not reading anyone's `.env`.

    `Settings` has `env_file=".env"` relative to the process working directory,
    so scanning a checkout that contains one would silently ingest it. That is
    a real hazard here — several corpus repositories ship an example `.env`.
    """
    return Settings(_env_file=None, osv_enabled=False)


async def scan(root: Path) -> tuple[list[Finding], int]:
    snapshot = Snapshot.build(root)
    facts: ProjectFacts = build_facts(snapshot)
    # `http=None` means the OSV rule declines in `applies()` rather than
    # timing out — see `dependencies.KnownVulnerabilityRule.applies`.
    ctx = RuleContext(snapshot=snapshot, facts=facts, settings=settings(), http=None)

    findings: list[Finding] = []
    for rule in all_rules():
        if not rule.applies(ctx):
            continue
        try:
            findings.extend(await rule.run(ctx))
        except Exception as exc:  # pragma: no cover - a rule crash is a result
            print(f"    !! {rule.id} raised {type(exc).__name__}: {exc}", file=sys.stderr)
    return prioritise(findings), len(snapshot.analysable())


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("corpus", type=Path)
    parser.add_argument("--json", type=Path, default=None)
    args = parser.parse_args()

    repositories = sorted(p for p in args.corpus.iterdir() if p.is_dir())
    results: list[dict] = []

    for root in repositories:
        findings, analysed = await scan(root)
        score = compute_score(findings, analysed)
        judged = [f for f in findings if f.category in JUDGED]

        results.append(
            {
                "repository": root.name,
                "analysed_files": analysed,
                "findings": len(findings),
                "score": score.value,
                "grade": score.grade,
                "by_category": dict(Counter(f.category.value for f in findings)),
                "by_rule": dict(Counter(f.rule_id for f in findings)),
                "judged": [
                    {
                        "rule_id": f.rule_id,
                        "severity": f.severity.value,
                        "confidence": f.confidence.value,
                        "priority": f.priority,
                        "file": f.file,
                        "line": f.line,
                        "title": f.title,
                    }
                    for f in judged
                ],
            }
        )

        print(
            f"{root.name:38} {analysed:5} files  {len(findings):4} findings  "
            f"{score.value:3} {score.grade}   security/secret: {len(judged)}"
        )

    if args.json:
        args.json.write_text(json.dumps(results, indent=2), encoding="utf-8")
        print(f"\nwrote {args.json}")


if __name__ == "__main__":
    asyncio.run(main())
