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

# Braces that represent a branch a reader must hold in mind, as opposed to an
# object literal, a JSX interpolation or a plain function body.
CONTROL_FLOW = re.compile(
    r"\b(?:if|else|for|while|switch|case|try|catch|finally|do)\b"
)

# A line that is JSX markup rather than logic: an opening or closing tag, a bare
# attribute, or the punctuation that closes an element.
MARKUP_LINE = re.compile(
    r"""^(?:
        </?[A-Za-z][\w.]*      # <div  </div  <Button
      | /?>                    # />  >
      | \{?\s*[A-Za-z_$][\w$]*=  # className=  key=
      | [)}\]>;,\s]*$          # closing punctuation only
    )""",
    re.VERBOSE,
)


def _logic_lines(body: list[str]) -> int:
    """Lines in ``body`` that are code rather than markup or blank.

    JSX is a template, not control flow. A component that is long because it
    renders a lot is a different thing from a function that is long because it
    branches a lot, and only the second is what this rule is about.
    """
    count = 0
    for line in body:
        stripped = line.strip()
        if not stripped:
            continue
        if MARKUP_LINE.match(stripped):
            continue
        count += 1
    return count


@register
class LongFileRule:
    id = "quality/long-file"
    name = "Very long file"
    category = Category.METRIC

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
                    # One per file, and the length is in the title — so the file
                    # alone is the identity. Keyed on `line` this would resolve
                    # and reappear on every edit.
                    key=source.path,
                    title=f"{source.name} is {count:,} lines long",
                    references=["https://refactoring.com/catalog/extractClass.html"],
                    description=(
                        f"Files above roughly {LONG_FILE_LINES} lines tend to "
                        f"hold several unrelated responsibilities, which makes "
                        f"them harder to test in isolation and a frequent "
                        f"source of merge conflicts."
                    ),
                    category=Category.METRIC,
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

                # Measure the logic, not the markup.
                #
                # A React component is mostly JSX. Counting those lines reported
                # 24 components on a real frontend, each carrying a rationale
                # about branches being hard to cover with tests — true of a long
                # function, false of a long template. The measurement was right
                # and the explanation was wrong, which costs a reader's trust
                # just as fast as a false positive.
                logic = _logic_lines(lines[start:end])
                if logic < LONG_FUNCTION_LINES:
                    continue
                markup = length - logic
                findings.append(
                    ctx.finding(
                        rule_id=self.id,
                        # The function's name outlives both its length and its
                    # position. Qualified by path, since the same name recurs
                    # across files.
                    key=f"{source.path}|{name}",
                    title=f"{name}() spans {length} lines",
                    references=["https://refactoring.com/catalog/extractFunction.html"],
                        description=(
                            "A function this long usually has several distinct "
                            "jobs and many branches, which makes each path hard "
                            "to cover with tests."
                            + (
                                f" {logic} of these lines are logic; the other "
                                f"{markup} are markup, which is not counted "
                                f"towards the threshold."
                                if markup > 0
                                else ""
                            )
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
    category = Category.METRIC

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

            # Only braces opened by control flow count.
            #
            # Raw brace depth measured punctuation, not nesting. In JSX every
            # `className={…}`, every `key={…}` and every `{items.map(…)}` is a
            # brace, so a flat component read as deeply nested — measured on a
            # real frontend, all eleven findings were markup, and the rule's own
            # description ("hold several conditions in mind at once") was false
            # for every one of them.
            stack: list[bool] = []
            worst = 0
            worst_line = 0
            for number, line in enumerate(lines, start=1):
                control = bool(CONTROL_FLOW.search(line))
                for char in line:
                    if char == "{":
                        stack.append(control)
                    elif char == "}" and stack:
                        stack.pop()
                depth = sum(stack)
                if depth > worst:
                    worst, worst_line = depth, number

            if worst >= DEEP_NESTING:
                findings.append(
                    ctx.finding(
                        rule_id=self.id,
                        # One per file; `worst_line` moves as the deepest block
                        # moves, without the file becoming a different problem.
                        key=source.path,
                        title=f"{source.name} nests {worst} levels deep",
                        references=["https://refactoring.com/catalog/replaceNestedConditionalWithGuardClauses.html"],
                        description=(
                            "Deep nesting forces a reader to hold several "
                            "conditions in mind at once and is strongly "
                            "correlated with defect density."
                        ),
                        category=Category.METRIC,
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
    category = Category.METRIC

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
                # Project-wide and singular, but anchored at the first marker
                # found — a location that moves whenever an unrelated file gains
                # a TODO. Empty key: the rule identifies it on its own.
                key="",
                title=f"{len(hits)} unresolved TODO/FIXME markers",
                description=(
                    f"The codebase contains {len(hits)} TODO, FIXME, HACK or XXX "
                    f"markers across {len({h[0] for h in hits})} files. Markers "
                    f"that accumulate stop being read."
                ),
                category=Category.METRIC,
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
