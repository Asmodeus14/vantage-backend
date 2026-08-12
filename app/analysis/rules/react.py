"""React and JSX correctness rules.

v2's only React check tested whether a file contained ``.map(`` and did not
contain the substring ``key=`` anywhere — so a single keyed list elsewhere in
the file suppressed every other occurrence, and a ``key=`` inside a comment
counted. These rules operate per call site, over source with comments and
string literals blanked out.
"""

from __future__ import annotations

import re

from app.analysis.base import RuleContext, iter_code_lines, register, strip_comments_and_strings
from app.schemas import Category, Confidence, Finding, Severity

JSX_LANGUAGES = ("javascript", "typescript")

# `.map(` returning JSX on the same or next few lines.
MAP_CALL = re.compile(r"\.map\s*\(\s*\(?\s*[A-Za-z_$][\w$]*\s*(?:,\s*[A-Za-z_$][\w$]*\s*)?\)?\s*=>")
KEY_PROP = re.compile(r"\bkey\s*=")
DANGEROUS_HTML = re.compile(r"dangerouslySetInnerHTML")
ARRAY_INDEX_KEY = re.compile(r"\bkey\s*=\s*\{\s*(?:index|idx|i)\s*\}")


def _is_jsx_file(source) -> bool:
    if source.language not in JSX_LANGUAGES:
        return False
    if source.path.endswith((".jsx", ".tsx")):
        return True
    text = source.text() or ""
    return "React" in text or "from 'react'" in text or 'from "react"' in text


@register
class MissingKeyRule:
    id = "react/missing-list-key"
    name = "List rendering without a key"
    category = Category.CORRECTNESS

    def applies(self, ctx: RuleContext) -> bool:
        return ctx.facts.is_react

    async def run(self, ctx: RuleContext) -> list[Finding]:
        findings: list[Finding] = []

        for source in ctx.snapshot.by_language(*JSX_LANGUAGES):
            if not _is_jsx_file(source):
                continue
            text = source.text()
            if not text:
                continue
            cleaned = strip_comments_and_strings(text, source.language).splitlines()

            for index, line in enumerate(cleaned):
                if not MAP_CALL.search(line):
                    continue
                # A key may appear on the same line or in the returned element
                # a few lines below; inspect the local window only.
                window = "\n".join(cleaned[index : index + 6])
                if "<" not in window:
                    continue  # not rendering JSX
                if KEY_PROP.search(window):
                    continue

                findings.append(
                    ctx.finding(
                        rule_id=self.id,
                        title="List rendered with .map() has no key prop",
                        description=(
                            "React uses the key prop to match elements across "
                            "renders. Without it, React falls back to index "
                            "matching, which can preserve state on the wrong "
                            "item when the list is reordered, inserted into or "
                            "filtered."
                        ),
                        category=Category.CORRECTNESS,
                        severity=Severity.MEDIUM,
                        confidence=Confidence.MEDIUM,
                        file=source.path,
                        line=index + 1,
                        remediation=(
                            "Give each element a key that is stable and unique "
                            "for that item, such as a database id."
                        ),
                        references=["https://react.dev/learn/rendering-lists"],
                    )
                )
        return findings


@register
class ArrayIndexKeyRule:
    id = "react/array-index-key"
    name = "Array index used as key"
    category = Category.CORRECTNESS

    def applies(self, ctx: RuleContext) -> bool:
        return ctx.facts.is_react

    async def run(self, ctx: RuleContext) -> list[Finding]:
        findings: list[Finding] = []
        for source in ctx.snapshot.by_language(*JSX_LANGUAGES):
            if not _is_jsx_file(source):
                continue
            for number, line in iter_code_lines(source):
                if ARRAY_INDEX_KEY.search(line):
                    findings.append(
                        ctx.finding(
                            rule_id=self.id,
                            title="Array index used as a React key",
                            description=(
                                "An index key changes meaning whenever the list "
                                "is reordered or an item is inserted, which "
                                "makes React reuse the wrong DOM node and can "
                                "leave stale state in inputs."
                            ),
                            category=Category.CORRECTNESS,
                            severity=Severity.LOW,
                            confidence=Confidence.MEDIUM,
                            file=source.path,
                            line=number,
                            remediation="Key by a stable identifier from the item itself.",
                        )
                    )
        return findings


@register
class DangerouslySetInnerHtmlRule:
    id = "react/dangerously-set-inner-html"
    name = "dangerouslySetInnerHTML usage"
    category = Category.SECURITY

    def applies(self, ctx: RuleContext) -> bool:
        return ctx.facts.is_react

    async def run(self, ctx: RuleContext) -> list[Finding]:
        findings: list[Finding] = []
        for source in ctx.snapshot.by_language(*JSX_LANGUAGES):
            for number, line in iter_code_lines(source):
                if not DANGEROUS_HTML.search(line):
                    continue
                findings.append(
                    ctx.finding(
                        rule_id=self.id,
                        title="dangerouslySetInnerHTML bypasses React's escaping",
                        description=(
                            "React escapes interpolated values by default; this "
                            "API opts out. If the HTML derives from user input "
                            "or a third-party response and is not sanitised, "
                            "this is a cross-site scripting vector."
                        ),
                        category=Category.SECURITY,
                        severity=Severity.MEDIUM,
                        # Legitimate when the input is trusted or sanitised, so
                        # this is flagged for review rather than asserted.
                        confidence=Confidence.LOW,
                        file=source.path,
                        line=number,
                        remediation=(
                            "Render text as children where possible. If HTML is "
                            "required, sanitise it with a library such as "
                            "DOMPurify immediately before rendering."
                        ),
                        references=["https://react.dev/reference/react-dom/components/common"],
                    )
                )
        return findings
