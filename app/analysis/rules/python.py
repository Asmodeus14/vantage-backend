"""Python rules.

The rule engine was JS/TS-weighted: a Python project got structural metrics and
secret scanning and nothing else. This is the second ecosystem, and it is the
shape any third one should follow — declare applicability honestly in
``applies``, and let the shared machinery do the rest.

Dependencies are handled by extending the existing OSV rule rather than adding
a parallel one. The advisory lookup, severity mapping, transitive downgrade and
per-package fingerprinting are all ecosystem-agnostic already; only the manifest
parsing differs.
"""

from __future__ import annotations

import re
import tomllib
from typing import Any

from app.analysis.base import RuleContext, iter_code_lines, register
from app.schemas import Category, Confidence, Finding, Severity

MAX_FINDINGS_PER_RULE = 25

# --------------------------------------------------------------------------
# Manifests
# --------------------------------------------------------------------------

# `package[extra]==1.2.3 ; python_version < "3.9"` — name, then everything else.
_REQUIREMENT = re.compile(
    r"^\s*(?P<name>[A-Za-z0-9._-]+)\s*(?:\[[^\]]*\])?\s*(?P<spec>[^;#]*)"
)
_EXACT = re.compile(r"^==\s*(?P<version>\d+(?:\.\d+)*(?:\.[A-Za-z0-9]+)?)$")


def normalise_name(name: str) -> str:
    """PEP 503 normalisation.

    ``Flask_SQLAlchemy``, ``flask-sqlalchemy`` and ``Flask.SQLAlchemy`` are one
    project, and OSV indexes the normalised form. Without this, half of a
    requirements file silently matches no advisory.
    """
    return re.sub(r"[-_.]+", "-", name).lower()


def exact_version(spec: str) -> str | None:
    """A pinned version, or ``None``.

    Deliberately strict, mirroring the npm side: only ``==`` is a fact. A range
    would have to be resolved against the index to mean anything, and guessing
    at it would produce advisories for versions nobody installed.
    """
    match = _EXACT.match(spec.strip().replace(" ", ""))
    return match.group("version") if match else None


def parse_requirements(text: str) -> dict[str, str]:
    """``{normalised name: spec}`` from a requirements file."""
    found: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        # Options (-r, -e, --index-url), comments and blanks.
        if not line or line.startswith(("#", "-")):
            continue
        match = _REQUIREMENT.match(line)
        if not match:
            continue
        name = match.group("name")
        if not name or name.lower() in {"python", "python_version"}:
            continue
        found[normalise_name(name)] = (match.group("spec") or "").strip()
    return found


def parse_pyproject(text: str) -> dict[str, str]:
    """PEP 621 ``[project]`` and Poetry ``[tool.poetry]``, both."""
    try:
        data: dict[str, Any] = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError):
        return {}

    found: dict[str, str] = {}

    for entry in (data.get("project") or {}).get("dependencies") or []:
        if isinstance(entry, str):
            found.update(parse_requirements(entry))

    optional = (data.get("project") or {}).get("optional-dependencies") or {}
    for group in optional.values():
        for entry in group if isinstance(group, list) else []:
            if isinstance(entry, str):
                found.update(parse_requirements(entry))

    poetry = ((data.get("tool") or {}).get("poetry") or {}).get("dependencies") or {}
    for name, spec in poetry.items():
        if name.lower() == "python":
            continue
        # Poetry allows a table: {version = "^1.0", optional = true}.
        if isinstance(spec, dict):
            spec = spec.get("version", "")
        if not isinstance(spec, str):
            continue
        # Poetry's `1.2.3` means exactly that; `^`/`~` do not.
        pinned = spec.strip()
        found[normalise_name(name)] = (
            f"=={pinned}" if re.fullmatch(r"\d+(\.\d+)*", pinned) else pinned
        )

    return found


def parse_poetry_lock(text: str) -> dict[str, str]:
    """Exact installed versions from ``poetry.lock``.

    Worth its own parser: a lockfile is the only place many Python projects
    record an exact version at all. Their ``pyproject.toml`` says ``^2.31``,
    which cannot be resolved without the index, so without this they would get
    no dependency scanning whatsoever.
    """
    try:
        data: dict[str, Any] = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError):
        return {}

    found: dict[str, str] = {}
    for package in data.get("package") or []:
        if not isinstance(package, dict):
            continue
        name, version = package.get("name"), package.get("version")
        if isinstance(name, str) and isinstance(version, str):
            found[normalise_name(name)] = version
    return found


def collect_python_dependencies(ctx: RuleContext) -> list[tuple[str, str, str | None]]:
    """``(name, spec, exact_version | None)`` across every Python manifest.

    Order is precedence, weakest first: a declared range loses to a pin, and a
    pin loses to a lockfile, because the lockfile is what actually installs.
    """
    declared: dict[str, str] = {}

    for source in ctx.snapshot.by_name("pyproject.toml"):
        text = source.text()
        if text:
            declared.update(parse_pyproject(text))

    for source in ctx.snapshot.files:
        name = source.name.lower()
        if not (name.startswith("requirements") and name.endswith(".txt")):
            continue
        text = source.text()
        if text:
            declared.update(parse_requirements(text))

    resolved: dict[str, str] = {}
    for source in ctx.snapshot.by_name("poetry.lock"):
        text = source.text()
        if text:
            resolved.update(parse_poetry_lock(text))

    names = set(declared) | set(resolved)
    return [
        (
            name,
            declared.get(name, "(from lockfile)"),
            resolved.get(name) or exact_version(declared.get(name, "")),
        )
        for name in sorted(names)
    ]


def python_manifest_path(ctx: RuleContext) -> str | None:
    for candidate in ("requirements.txt", "pyproject.toml"):
        found = ctx.snapshot.by_name(candidate)
        if found:
            return found[0].path
    return None


# --------------------------------------------------------------------------
# Correctness
# --------------------------------------------------------------------------

_TEST_PATH = re.compile(r"(^|/)(tests?|testing)/|(^|/)(test_[^/]+|[^/]+_test)\.py$")


def is_test_file(path: str) -> bool:
    return bool(_TEST_PATH.search(path))


def _python_sources(ctx: RuleContext, *, skip_tests: bool = False):
    """Python files, optionally excluding tests.

    Tests are excluded from the *security* rules and only those. A test suite
    exercises `pickle.loads` and shells out on purpose — measured on `psf/requests`,
    every one of the seven deserialisation findings was a test deliberately
    testing deserialisation. Seven unactionable findings is how a rule teaches
    people to skip its whole category.

    Correctness rules keep scanning tests, because a mutable default argument is
    a bug wherever it is, and a test that fails for its own reasons is worse than
    one that does not exist.
    """
    return [
        s
        for s in ctx.snapshot.analysable()
        if s.language == "python" and not (skip_tests and is_test_file(s.path))
    ]


_DEF = re.compile(r"\bdef\s+(?P<name>\w+)\s*\(")
# `=[`, `={`, `=list()`, `=dict()`, `=set()` — a fresh object made once, at
# definition time, and then shared by every call.
_MUTABLE_DEFAULT = re.compile(r"=\s*(?:\[|\{|(?:list|dict|set)\s*\(\s*\))")


@register
class MutableDefaultArgumentRule:
    id = "python/mutable-default-argument"
    name = "Mutable default argument"
    category = Category.CORRECTNESS

    def applies(self, ctx: RuleContext) -> bool:
        return ctx.facts.is_python

    async def run(self, ctx: RuleContext) -> list[Finding]:
        findings: list[Finding] = []

        for source in _python_sources(ctx):
            if len(findings) >= MAX_FINDINGS_PER_RULE:
                break
            lines = iter_code_lines(source)

            for index, (number, line) in enumerate(lines):
                match = _DEF.search(line)
                if not match:
                    continue

                # A signature can wrap. Gather it by paren depth rather than
                # assuming one line, which is where a naive version misses the
                # formatted-with-black case entirely.
                signature = line[match.end() - 1 :]
                depth = signature.count("(") - signature.count(")")
                cursor = index
                while depth > 0 and cursor + 1 < len(lines) and cursor - index < 20:
                    cursor += 1
                    nxt = lines[cursor][1]
                    signature += nxt
                    depth += nxt.count("(") - nxt.count(")")

                if not _MUTABLE_DEFAULT.search(signature):
                    continue

                findings.append(
                    ctx.finding(
                        rule_id=self.id,
                        key=f"{source.path}|{match.group('name')}",
                        title=f"{match.group('name')}() has a mutable default argument",
                        description=(
                            "A default value is evaluated once, when the "
                            "function is defined — not on each call. Every "
                            "call that relies on the default therefore shares "
                            "one list or dict, so a mutation in one call is "
                            "visible in the next."
                        ),
                        category=Category.CORRECTNESS,
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        file=source.path,
                        line=number,
                        remediation=(
                            "Default to None and build the value inside the "
                            "function: `def f(items=None): items = items or []`."
                        ),
                        references=[
                            "https://docs.python.org/3/reference/compound_stmts.html#function-definitions"
                        ],
                    )
                )
        return findings


_BARE_EXCEPT = re.compile(r"^\s*except\s*:")


@register
class BareExceptRule:
    id = "python/bare-except"
    name = "Bare except"
    category = Category.CORRECTNESS

    def applies(self, ctx: RuleContext) -> bool:
        return ctx.facts.is_python

    async def run(self, ctx: RuleContext) -> list[Finding]:
        findings: list[Finding] = []

        for source in _python_sources(ctx):
            if len(findings) >= MAX_FINDINGS_PER_RULE:
                break
            for number, line in iter_code_lines(source):
                if not _BARE_EXCEPT.match(line):
                    continue
                findings.append(
                    ctx.finding(
                        rule_id=self.id,
                        title="Bare `except:` catches everything",
                        references=["https://peps.python.org/pep-0008/#programming-recommendations"],
                        description=(
                            "A bare except also catches KeyboardInterrupt and "
                            "SystemExit, so it swallows Ctrl-C and a request to "
                            "shut down. It hides the failures you did not "
                            "anticipate, which are the ones worth seeing."
                        ),
                        category=Category.CORRECTNESS,
                        severity=Severity.LOW,
                        confidence=Confidence.HIGH,
                        file=source.path,
                        line=number,
                        remediation=(
                            "Catch `Exception` to keep interrupts working, or "
                            "name the exceptions you actually expect."
                        ),
                    )
                )
        return findings


_SHELL_TRUE = re.compile(r"\bshell\s*=\s*True\b")
_SUBPROCESS = re.compile(r"\b(?:subprocess\.\w+|os\.(?:system|popen))\s*\(")


@register
class ShellInjectionSurfaceRule:
    id = "python/subprocess-shell"
    name = "Shell invoked from Python"
    category = Category.SECURITY

    def applies(self, ctx: RuleContext) -> bool:
        return ctx.facts.is_python

    async def run(self, ctx: RuleContext) -> list[Finding]:
        findings: list[Finding] = []

        for source in _python_sources(ctx, skip_tests=True):
            if len(findings) >= MAX_FINDINGS_PER_RULE:
                break
            for number, line in iter_code_lines(source):
                shell_true = _SHELL_TRUE.search(line)
                os_call = re.search(r"\bos\.(?:system|popen)\s*\(", line)
                if not shell_true and not os_call:
                    continue
                # `shell=True` on its own line belongs to a call above it; a
                # subprocess call without it is fine and not reported.
                if shell_true and not _SUBPROCESS.search(line):
                    continue

                findings.append(
                    ctx.finding(
                        rule_id=self.id,
                        title="Command executed through a shell",
                        description=(
                            "Running a command through a shell means any "
                            "interpolated value is shell syntax. A filename "
                            "containing `; rm -rf` stops being a filename. "
                            "Flagged for review — it is only a vulnerability "
                            "if any part of the command comes from input."
                        ),
                        category=Category.SECURITY,
                        severity=Severity.MEDIUM,
                        confidence=Confidence.MEDIUM,
                        file=source.path,
                        line=number,
                        remediation=(
                            "Pass a list of arguments and drop `shell=True`: "
                            "`subprocess.run([\"git\", \"clone\", url])`. The "
                            "arguments are then never parsed as shell syntax."
                        ),
                        references=[
                            "https://docs.python.org/3/library/subprocess.html#security-considerations"
                        ],
                    )
                )
        return findings


_UNSAFE_LOADS = (
    (re.compile(r"\byaml\.load\s*\("), "yaml.load", "Loader="),
    (re.compile(r"\bpickle\.loads?\s*\("), "pickle.load", None),
    (re.compile(r"\bmarshal\.loads?\s*\("), "marshal.load", None),
)


@register
class UnsafeDeserialisationRule:
    id = "python/unsafe-deserialisation"
    name = "Unsafe deserialisation"
    category = Category.SECURITY

    def applies(self, ctx: RuleContext) -> bool:
        return ctx.facts.is_python

    async def run(self, ctx: RuleContext) -> list[Finding]:
        findings: list[Finding] = []

        for source in _python_sources(ctx, skip_tests=True):
            if len(findings) >= MAX_FINDINGS_PER_RULE:
                break
            for number, line in iter_code_lines(source):
                for pattern, label, safe_marker in _UNSAFE_LOADS:
                    if not pattern.search(line):
                        continue
                    # `yaml.load(f, Loader=SafeLoader)` is the fixed form.
                    if safe_marker and safe_marker in line:
                        continue

                    findings.append(
                        ctx.finding(
                            rule_id=self.id,
                            key=f"{source.path}|{label}|{number}",
                            title=f"{label} can execute arbitrary code",
                            description=(
                                f"{label} reconstructs arbitrary objects, which "
                                "means a crafted payload runs code as it is "
                                "read. This is only safe when the data can "
                                "never come from anywhere untrusted — including "
                                "a file someone else can write."
                            ),
                            category=Category.SECURITY,
                            severity=Severity.HIGH,
                            confidence=Confidence.MEDIUM,
                            file=source.path,
                            line=number,
                            remediation=(
                                "Use `yaml.safe_load` for YAML, and JSON rather "
                                "than pickle for data that crosses a trust "
                                "boundary."
                            ),
                            references=[
                                "https://docs.python.org/3/library/pickle.html"
                            ],
                        )
                    )
                    break
        return findings
