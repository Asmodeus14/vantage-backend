"""Rule interface and shared helpers.

Every rule is a small, independently testable unit that receives a read-only
:class:`~app.ingest.snapshot.Snapshot` and returns findings. Rules declare which
projects they apply to, so a Python repository is never told it is missing
ESLint — a specific complaint about v2, which ran all checks unconditionally.

Findings are created through :meth:`RuleContext.finding`, which populates the
source snippet from the snapshot. That keeps "every finding knows where it is"
a property of the framework rather than something each rule must remember.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from app.config import Settings
from app.ingest.snapshot import Snapshot, SourceFile
from app.schemas import Category, Confidence, Finding, Severity

if TYPE_CHECKING:  # pragma: no cover
    import httpx


@dataclass
class ProjectFacts:
    """Cheap, shared detection results computed once before rules run.

    Rules use these to decide applicability instead of re-scanning the tree.
    """

    package_json: dict | None = None
    package_managers: set[str] = field(default_factory=set)
    frameworks: set[str] = field(default_factory=set)
    languages: set[str] = field(default_factory=set)
    has_typescript: bool = False
    has_tests: bool = False
    has_ci: bool = False
    has_lockfile: bool = False
    entry_points: list[str] = field(default_factory=list)

    @property
    def is_node(self) -> bool:
        return self.package_json is not None

    @property
    def is_python(self) -> bool:
        return "python" in self.languages

    @property
    def is_react(self) -> bool:
        return bool({"react", "next", "remix", "gatsby"} & self.frameworks)


@dataclass
class RuleContext:
    snapshot: Snapshot
    facts: ProjectFacts
    settings: Settings
    http: httpx.AsyncClient | None = None

    def finding(
        self,
        *,
        rule_id: str,
        title: str,
        description: str,
        category: Category,
        severity: Severity,
        confidence: Confidence = Confidence.HIGH,
        file: str | None = None,
        line: int | None = None,
        end_line: int | None = None,
        snippet: str | None = None,
        remediation: str | None = None,
        references: list[str] | None = None,
        key: str | None = None,
    ) -> Finding:
        """Build a finding, filling in the snippet from the snapshot.

        ``key`` is the rule's own answer to "which problem is this, as distinct
        from the others I report", and only affects :attr:`Finding.fingerprint`.
        No single formula works across rule families, so the rule decides, and
        when it supplies a key that key is the *whole* discriminator — file
        included, or deliberately not:

        - ``None`` (default) — fall back to ``file`` and ``line``. Correct for
          rules emitting several findings per file with nothing else to tell
          them apart, such as ``react/array-index-key``. Inserting code above
          one of these does make it read as resolved-plus-new; that is accepted
          and documented rather than papered over.
        - ``source.path`` — the file alone identifies it, as for
          ``quality/long-file``, whose line is always 1 and whose title carries
          a changing measurement.
        - ``""`` — the rule identifies it, with no location at all. For
          project-wide findings like ``quality/todo-markers``, which anchors
          itself to the first marker it happened to find; that file changes
          when an unrelated file gains a TODO, so including it would be wrong.
        - anything else — a discriminator that outlives the details, such as
          the package name for ``dep/known-vulnerability``, which must survive
          a version bump.
        """
        snippet_start_line: int | None = None
        if snippet is None and file and line:
            source = self.snapshot.get(file)
            if source is not None:
                extracted = source.snippet(line)
                if extracted is not None:
                    snippet, snippet_start_line = extracted

        # Deterministic id: stable across re-runs of the same project, so the
        # UI can keep a selection across a refresh and AI results can be cached.
        digest = hashlib.sha1(
            f"{rule_id}|{file or ''}|{line or 0}|{title}".encode()
        ).hexdigest()[:12]

        # Identity across reports. `title` is never part of it: several rules
        # put a measurement there — `quality/long-file` says "…is 1,050 lines
        # long" — so one added line would read as a problem resolved and another
        # appearing. Location is part of it only when the rule has nothing
        # better to offer.
        scope = key if key is not None else f"{file or ''}|{line or 0}"
        fingerprint = hashlib.sha1(f"{rule_id}|{scope}".encode()).hexdigest()[:12]

        return Finding(
            id=digest,
            fingerprint=fingerprint,
            rule_id=rule_id,
            title=title,
            description=description,
            category=category,
            severity=severity,
            confidence=confidence,
            file=file,
            line=line,
            end_line=end_line or line,
            snippet=snippet,
            snippet_start_line=snippet_start_line,
            remediation=remediation,
            references=references or [],
        )


@runtime_checkable
class Rule(Protocol):
    id: str
    name: str
    category: Category

    def applies(self, ctx: RuleContext) -> bool:
        """Whether this rule is meaningful for the project at hand."""
        ...

    async def run(self, ctx: RuleContext) -> list[Finding]: ...


_REGISTRY: list[Rule] = []


def register(rule_cls: type) -> type:
    """Class decorator adding a rule to the default registry."""
    _REGISTRY.append(rule_cls())
    return rule_cls


def all_rules() -> list[Rule]:
    return list(_REGISTRY)


# --------------------------------------------------------------------------
# Shared source helpers
# --------------------------------------------------------------------------

def strip_comments_and_strings(text: str, language: str | None) -> str:
    """Blank out comment and string content, preserving line structure.

    v2 computed complexity with ``content.count('if ')``, which counted matches
    inside comments and string literals. Rules that scan for code constructs run
    over this instead, so line numbers still line up with the original file.
    """
    if language in {"python", "ruby", "shell"}:
        line_comment, block = "#", None
    else:
        line_comment, block = "//", ("/*", "*/")

    out: list[str] = []
    in_block = False
    quote: str | None = None

    for raw_line in text.splitlines():
        buffer: list[str] = []
        i = 0
        while i < len(raw_line):
            rest = raw_line[i:]

            if in_block:
                assert block is not None
                if rest.startswith(block[1]):
                    in_block = False
                    buffer.append("  ")
                    i += 2
                else:
                    buffer.append(" ")
                    i += 1
                continue

            if quote is not None:
                if rest[0] == "\\":
                    buffer.append("  ")
                    i += 2
                    continue
                if rest.startswith(quote):
                    buffer.append(rest[0])
                    quote = None
                    i += 1
                    continue
                buffer.append(" ")
                i += 1
                continue

            if block and rest.startswith(block[0]):
                in_block = True
                buffer.append("  ")
                i += 2
                continue
            if rest.startswith(line_comment):
                buffer.append(" " * len(rest))
                break
            if rest[0] in "\"'`":
                quote = rest[0]
                buffer.append(rest[0])
                i += 1
                continue

            buffer.append(rest[0])
            i += 1

        out.append("".join(buffer))

    return "\n".join(out)


def line_of_offset(text: str, offset: int) -> int:
    """1-indexed line number containing ``offset``."""
    return text.count("\n", 0, offset) + 1


def iter_code_lines(source: SourceFile) -> list[tuple[int, str]]:
    """(1-indexed line number, code with comments/strings blanked)."""
    text = source.text()
    if not text:
        return []
    cleaned = strip_comments_and_strings(text, source.language)
    return list(enumerate(cleaned.splitlines(), start=1))
