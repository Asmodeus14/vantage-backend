"""Code quality metrics.

v2 computed "complexity" as ``content.count('if ') + content.count('for ') …``
over the raw file, so keywords inside comments and string literals counted, and
the score scaled with file length rather than structure. These rules measure
per-construct over source with comments and strings blanked out, and report the
specific location rather than a whole-file number.
"""

from __future__ import annotations

import re

from app.analysis.base import RuleContext, register, strip_comments_and_strings
from app.schemas import Category, Confidence, Finding, Severity

LONG_FILE_LINES = 600
VERY_LONG_FILE_LINES = 1000
LONG_FUNCTION_LINES = 80
DEEP_NESTING = 5
MAX_FINDINGS_PER_RULE = 40

FUNCTION_START = re.compile(
    r"""^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?
        (?:function\s+(?P<fn>[A-Za-z_$][\w$]*)
         |(?:const|let|var)\s+(?P<const>[A-Za-z_$][\w$]*)\s*=\s*
            (?:async\s+)?(?:function\b|\([^)]*\)\s*=>|[A-Za-z_$][\w$]*\s*=>)
         |def\s+(?P<py>[A-Za-z_][\w]*)\s*\()""",
    re.VERBOSE,
)

TODO_MARKER = re.compile(r"\b(TODO|FIXME|HACK|XXX)\b[:\s]", re.IGNORECASE)


@register
class LongFileRule:
    id = "quality/long-file"
    name = "Very long file"
    category = Category.QUALITY

    def applies(self, ctx: RuleContext) -> bool:
        return True

    async def run(self, ctx: RuleContext) -> list[Finding]:
        findings: list[Finding] = []
        candidates = sorted(
            (f for f in ctx.snapshot.analysable() if f.line_count() > LONG_FILE_LINES),
            key=lambda f: f.line_count(),
            reverse=True,
        )
        for source in candidates[:MAX_FINDINGS_PER_RULE]:
            count = source.line_count()
            severity = Severity.MEDIUM if count > VERY_LONG_FILE_LINES else Severity.LOW
            findings.append(
                ctx.finding(
                    rule_id=self.id,
                    title=f"{source.name} is {count:,} lines long",
                    description=(
                        f"Files above roughly {LONG_FILE_LINES} lines tend to "
                        f"hold several unrelated responsibilities, which makes "
                        f"them harder to test in isolation and a frequent "
                        f"source of merge conflicts."
                    ),
                    category=Category.QUALITY,
                    severity=severity,
                    confidence=Confidence.HIGH,
                    file=source.path,
                    line=1,
                    remediation=(
                        "Extract cohesive groups of functions into modules "
                        "organised around a single responsibility."
                    ),
                )
            )
        return findings


@register
class LongFunctionRule:
    id = "quality/long-function"
    name = "Long function"
    category = Category.QUALITY

    def applies(self, ctx: RuleContext) -> bool:
        return True

    async def run(self, ctx: RuleContext) -> list[Finding]:
        findings: list[Finding] = []

        for source in ctx.snapshot.by_language(
            "javascript", "typescript", "python", "go", "java", "ruby"
        ):
            if len(findings) >= MAX_FINDINGS_PER_RULE:
                break
            text = source.text()
            if not text:
                continue
            lines = strip_comments_and_strings(text, source.language).splitlines()

            for start, line in enumerate(lines):
                match = FUNCTION_START.match(line)
                if not match:
                    continue
                name = match.group("fn") or match.group("const") or match.group("py")
                if not name:
                    continue
                end = _function_end(lines, start, source.language)
                length = end - start
                if length < LONG_FUNCTION_LINES:
                    continue
                findings.append(
                    ctx.finding(
                        rule_id=self.id,
                        title=f"{name}() spans {length} lines",
                        description=(
                            f"A function this long usually has several distinct "
                            f"jobs and many branches, which makes each path hard "
                            f"to cover with tests."
                        ),
                        category=Category.QUALITY,
                        severity=Severity.LOW,
                        confidence=Confidence.MEDIUM,
                        file=source.path,
                        line=start + 1,
                        end_line=end,
                        remediation="Extract the distinct steps into named helpers.",
                    )
                )
        return findings


def _function_end(lines: list[str], start: int, language: str | None) -> int:
    """Find a function's last line by brace depth, or indentation for Python."""
    if language == "python":
        base = len(lines[start]) - len(lines[start].lstrip())
        for index in range(start + 1, len(lines)):
            stripped = lines[index].strip()
            if not stripped:
                continue
            indent = len(lines[index]) - len(lines[index].lstrip())
            if indent <= base:
                return index
        return len(lines)

    depth = 0
    opened = False
    for index in range(start, len(lines)):
        depth += lines[index].count("{") - lines[index].count("}")
        if "{" in lines[index]:
            opened = True
        if opened and depth <= 0:
            return index + 1
    return len(lines)


@register
class DeepNestingRule:
    id = "quality/deep-nesting"
    name = "Deeply nested control flow"
    category = Category.QUALITY

    def applies(self, ctx: RuleContext) -> bool:
        return True

    async def run(self, ctx: RuleContext) -> list[Finding]:
        findings: list[Finding] = []

        for source in ctx.snapshot.by_language("javascript", "typescript", "go", "java"):
            if len(findings) >= MAX_FINDINGS_PER_RULE:
                break
            text = source.text()
            if not text:
                continue
            lines = strip_comments_and_strings(text, source.language).splitlines()

            depth = 0
            worst = 0
            worst_line = 0
            for number, line in enumerate(lines, start=1):
                depth += line.count("{") - line.count("}")
                if depth > worst:
                    worst, worst_line = depth, number

            if worst >= DEEP_NESTING:
                findings.append(
                    ctx.finding(
                        rule_id=self.id,
                        title=f"{source.name} nests {worst} levels deep",
                        description=(
                            "Deep nesting forces a reader to hold several "
                            "conditions in mind at once and is strongly "
                            "correlated with defect density."
                        ),
                        category=Category.QUALITY,
                        severity=Severity.LOW,
                        confidence=Confidence.MEDIUM,
                        file=source.path,
                        line=worst_line,
                        remediation=(
                            "Use early returns and guard clauses, or extract "
                            "inner blocks into their own functions."
                        ),
                    )
                )
        return findings


@register
class TodoDensityRule:
    id = "quality/todo-markers"
    name = "Unresolved TODO markers"
    category = Category.QUALITY

    def applies(self, ctx: RuleContext) -> bool:
        return True

    async def run(self, ctx: RuleContext) -> list[Finding]:
        hits: list[tuple[str, int, str]] = []
        for source in ctx.snapshot.analysable():
            for number, line in enumerate(source.lines(), start=1):
                if TODO_MARKER.search(line):
                    hits.append((source.path, number, line.strip()[:120]))

        if len(hits) < 10:
            return []  # a handful of TODOs is normal and not worth reporting

        path, line, _ = hits[0]
        return [
            ctx.finding(
                rule_id=self.id,
                title=f"{len(hits)} unresolved TODO/FIXME markers",
                description=(
                    f"The codebase contains {len(hits)} TODO, FIXME, HACK or XXX "
                    f"markers across {len({h[0] for h in hits})} files. Markers "
                    f"that accumulate stop being read."
                ),
                category=Category.QUALITY,
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                file=path,
                line=line,
                remediation=(
                    "Convert the ones that matter into tracked issues and "
                    "delete the rest."
                ),
            )
        ]
