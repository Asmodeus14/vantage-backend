"""Dependency analysis backed by real vulnerability data.

v2 shipped an eight-entry dict mapping package name to a version-range *string*,
then reported a finding whenever the name appeared — without ever comparing the
installed version against the range. Any project depending on ``react`` was told
it was vulnerable to a flaw fixed in 16.14, including projects on React 19.

This queries OSV.dev (free, no API key, maintained by Google's OSS security
team) with the *resolved* version from the lockfile, so range matching is done
against real advisory data by the people who publish it.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from typing import Any

from app.analysis.base import RuleContext, register
from app.analysis.rules.python import (
    collect_python_dependencies,
    normalise_name,
    python_manifest_path,
)
from app.ingest.snapshot import SourceFile
from app.schemas import Category, Confidence, DependencyInfo, Finding, Severity

logger = logging.getLogger(__name__)

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{vuln_id}"

# Bound the work for very large dependency trees.
MAX_PACKAGES_QUERIED = 400
MAX_VULN_DETAILS = 40

_VERSION_TOKEN = re.compile(r"(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)")

# OSV severity strings vary by advisory source; normalise onto our scale.
_SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


def parse_package_json(source: SourceFile) -> dict[str, Any] | None:
    text = source.text()
    if not text:
        return None
    try:
        data = json.loads(text)
        return data if isinstance(data, dict) else None
    except json.JSONDecodeError:
        return None


def resolved_versions_from_lockfile(snapshot) -> dict[str, str]:
    """Exact installed versions, keyed by package name.

    Supports npm lockfile v1 (``dependencies``) and v2/v3 (``packages``).
    """
    resolved: dict[str, str] = {}
    for lock in snapshot.by_name("package-lock.json"):
        text = lock.text()
        if not text:
            continue
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            continue

        # v2/v3: {"packages": {"node_modules/lodash": {"version": "4.17.21"}}}
        for path, meta in (data.get("packages") or {}).items():
            if not path or not isinstance(meta, dict):
                continue
            marker = "node_modules/"
            if marker in path:
                name = path[path.rindex(marker) + len(marker):]
                version = meta.get("version")
                if name and isinstance(version, str):
                    resolved.setdefault(name, version)

        # v1: {"dependencies": {"lodash": {"version": "4.17.21", ...}}}
        def walk(node: dict[str, Any]) -> None:
            for name, meta in (node.get("dependencies") or {}).items():
                if isinstance(meta, dict):
                    version = meta.get("version")
                    if isinstance(version, str):
                        resolved.setdefault(name, version)
                    walk(meta)

        walk(data)
    return resolved


def coerce_version(spec: str) -> str | None:
    """Best-effort exact version from a range spec, for lockfile-less projects.

    Deliberately conservative: anything that isn't a plain ``x.y.z`` after
    stripping a leading range operator is skipped rather than guessed at.
    """
    spec = spec.strip()
    if spec.startswith(("npm:", "file:", "link:", "workspace:", "git+", "http")):
        return None
    match = _VERSION_TOKEN.search(spec)
    return match.group(1) if match else None


def _highest_severity(vuln: dict[str, Any]) -> Severity:
    """Pick the strongest severity label an advisory carries."""
    ranked = [Severity.INFO]

    for entry in vuln.get("severity") or []:
        label = str(entry.get("type", "")).upper()
        if label in _SEVERITY_MAP:
            ranked.append(_SEVERITY_MAP[label])

    ecosystem = (vuln.get("database_specific") or {}).get("severity")
    if isinstance(ecosystem, str) and ecosystem.upper() in _SEVERITY_MAP:
        ranked.append(_SEVERITY_MAP[ecosystem.upper()])

    for affected in vuln.get("affected") or []:
        specific = (affected.get("database_specific") or {}).get("severity")
        if isinstance(specific, str) and specific.upper() in _SEVERITY_MAP:
            ranked.append(_SEVERITY_MAP[specific.upper()])

    order = [
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFO,
    ]
    for level in order:
        if level in ranked:
            return level
    return Severity.MEDIUM


_SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]


def _downgrade(severity: Severity) -> Severity:
    index = _SEVERITY_ORDER.index(severity)
    return _SEVERITY_ORDER[min(index + 1, len(_SEVERITY_ORDER) - 1)]


def _cve_ids(vuln: dict[str, Any]) -> list[str]:
    aliases = [a for a in (vuln.get("aliases") or []) if str(a).startswith("CVE-")]
    return aliases or [vuln.get("id", "")]


def _join_summaries(summaries: list[str], limit: int = 400) -> str:
    """Render several advisory summaries as distinct sentences.

    OSV summaries are unpunctuated titles. Joined with a bare space they ran
    together into one unreadable sentence, so each is terminated before
    joining, and truncation falls on a word boundary rather than mid-word.
    """
    sentences = [
        text if text.endswith((".", "!", "?")) else f"{text}."
        for text in (summary.strip() for summary in summaries)
        if text
    ]
    joined = " ".join(sentences)
    if len(joined) <= limit:
        return joined
    return joined[:limit].rsplit(" ", 1)[0].rstrip(",;:") + "…"


@register
class KnownVulnerabilityRule:
    """Cross-references resolved dependency versions against OSV.dev."""

    id = "dep/known-vulnerability"
    name = "Known vulnerable dependencies"
    category = Category.DEPENDENCIES

    def applies(self, ctx: RuleContext) -> bool:
        has_manifest = ctx.facts.is_node or "pip" in ctx.facts.package_managers
        return has_manifest and ctx.settings.osv_enabled and ctx.http is not None

    async def run(self, ctx: RuleContext) -> list[Finding]:
        manifests = ctx.snapshot.by_name("package.json")
        python_manifest = python_manifest_path(ctx)
        if not manifests and not python_manifest:
            return []

        resolved = resolved_versions_from_lockfile(ctx.snapshot)
        direct = collect_dependencies(ctx, resolved) if manifests else []

        # Python packages join the same batch. Everything downstream — the
        # severity mapping, the per-package fingerprint, the UI — is already
        # ecosystem-agnostic, so a second parallel rule would only duplicate it.
        direct += [
            ResolvedDependency(
                name=name,
                version_spec=spec or "(unpinned)",
                resolved_version=version,
                ecosystem="PyPI",
                is_dev=False,
                from_lockfile=False,
            )
            for name, spec, version in collect_python_dependencies(ctx)
        ]
        direct_names = {d.name for d in direct}

        # Transitive packages come only from the lockfile. They are real risk
        # (npm audit reports them) but the user cannot bump them directly, so
        # they are reported more conservatively — see below.
        transitive = [
            ResolvedDependency(
                name=name,
                version_spec="(transitive)",
                resolved_version=version,
                ecosystem="npm",
                is_dev=False,
                from_lockfile=True,
            )
            for name, version in resolved.items()
            if name not in direct_names
        ]

        queryable = [d for d in direct if d.resolved_version]
        budget = max(0, MAX_PACKAGES_QUERIED - len(queryable))
        queryable += transitive[:budget]
        if not queryable:
            return []

        try:
            vuln_ids = await self._query_batch(ctx, queryable)
        except Exception as exc:
            # A vulnerability-feed outage must not fail the whole analysis.
            logger.warning("OSV batch query failed: %s", exc)
            return []

        details = await self._fetch_details(ctx, vuln_ids)
        # Per ecosystem: a finding about `requests` must point at
        # requirements.txt, not at a package.json that may not even exist.
        manifest_for = {
            "npm": manifests[0].path if manifests else None,
            "PyPI": python_manifest,
        }
        findings: list[Finding] = []

        for package, ids in vuln_ids.items():
            if not ids:
                continue
            info = next((d for d in queryable if d.name == package), None)
            if info is None:
                continue
            info.vulnerabilities = list(ids)
            is_direct = package in direct_names
            declared_in = manifest_for.get(info.ecosystem)

            # One finding per package, listing every advisory against it.
            # Emitting one per CVE produced several findings with identical
            # titles, which read as duplicates in the UI.
            advisories = [details.get(v) for v in ids[:8]]
            severities = [
                _highest_severity(v) for v in advisories if v is not None
            ] or [Severity.MEDIUM]
            severity = min(severities, key=lambda s: _SEVERITY_ORDER.index(s))

            if not is_direct:
                # Only surface transitive issues that are serious, and rank them
                # one step below an equivalent direct dependency.
                if severity not in (Severity.CRITICAL, Severity.HIGH):
                    continue
                severity = _downgrade(severity)

            aliases: list[str] = []
            fixed: str | None = None
            summaries: list[str] = []
            for vuln in advisories:
                if vuln is None:
                    continue
                aliases.extend(a for a in _cve_ids(vuln) if a not in aliases)
                summary = (vuln.get("summary") or "").strip()
                if summary and summary not in summaries:
                    summaries.append(summary)
                fixed = fixed or _first_fixed_version(vuln)

            count = len(ids)
            label = "vulnerability" if count == 1 else "vulnerabilities"
            origin = "" if is_direct else " (pulled in transitively)"

            findings.append(
                ctx.finding(
                    rule_id=self.id,
                    # The package, not the version — a bump that does not clear
                    # the advisory is the same unfixed problem, and the title
                    # carries both the version and the advisory count.
                    key=package,
                    title=(
                        f"{package}@{info.resolved_version} has {count} known {label}"
                    ),
                    description=(
                        f"{', '.join(aliases[:6]) or ', '.join(ids[:3])}"
                        f"{origin}. "
                        + (
                            _join_summaries(summaries[:3])
                            or "See the advisories for detail."
                        )
                    ),
                    category=Category.DEPENDENCIES,
                    severity=severity,
                    confidence=(
                        Confidence.HIGH if info.from_lockfile else Confidence.MEDIUM
                    ),
                    file=declared_in if is_direct else None,
                    line=(
                        _manifest_line(ctx, declared_in, package)
                        if is_direct and declared_in
                        else None
                    ),
                    remediation=(
                        f"Upgrade {package} to {fixed} or later."
                        if fixed and is_direct
                        else (
                            f"{package} is a transitive dependency. Run "
                            f"`npm audit fix`, or bump the direct dependency "
                            f"that requires it."
                            if not is_direct
                            else f"Review the advisories and upgrade {package}."
                        )
                    ),
                    references=[
                        f"https://osv.dev/vulnerability/{v}" for v in ids[:8]
                    ],
                )
            )

        return findings

    async def _query_batch(
        self, ctx: RuleContext, dependencies: list[ResolvedDependency]
    ) -> dict[str, list[str]]:
        assert ctx.http is not None
        payload = {
            "queries": [
                {
                    # From the dependency, not hardcoded: OSV keys advisories by
                    # ecosystem, and asking it about `requests` on npm returns
                    # nothing rather than an error — a silent miss, which is the
                    # worst way for a security check to be wrong.
                    "package": {"name": d.name, "ecosystem": d.ecosystem},
                    "version": d.resolved_version,
                }
                for d in dependencies
            ]
        }
        response = await ctx.http.post(
            OSV_BATCH_URL, json=payload, timeout=ctx.settings.osv_timeout_seconds
        )
        response.raise_for_status()
        results = response.json().get("results", [])

        # OSV returns one result per query, in order. If it ever returned
        # fewer, `zip` would silently drop the tail — packages reported as clean
        # because nothing asked about them, which is the worst way for a
        # security check to be wrong. Not `strict=True`: raising here loses
        # every finding in the batch, and a partial answer that says so is
        # better than none.
        if len(results) != len(dependencies):
            logger.warning(
                "OSV returned %d results for %d queries; %d package(s) unchecked",
                len(results), len(dependencies), len(dependencies) - len(results),
            )
        out: dict[str, list[str]] = {}
        for dependency, result in zip(dependencies, results, strict=False):
            vulns = result.get("vulns") or []
            out[dependency.name] = [v["id"] for v in vulns if "id" in v]
        return out

    async def _fetch_details(
        self, ctx: RuleContext, vuln_ids: dict[str, list[str]]
    ) -> dict[str, dict[str, Any]]:
        assert ctx.http is not None
        unique: list[str] = []
        for ids in vuln_ids.values():
            for vuln_id in ids[:5]:
                if vuln_id not in unique:
                    unique.append(vuln_id)
        unique = unique[:MAX_VULN_DETAILS]

        async def fetch(vuln_id: str) -> tuple[str, dict[str, Any] | None]:
            try:
                response = await ctx.http.get(
                    OSV_VULN_URL.format(vuln_id=vuln_id),
                    timeout=ctx.settings.osv_timeout_seconds,
                )
                response.raise_for_status()
                return vuln_id, response.json()
            except Exception:
                return vuln_id, None

        pairs = await asyncio.gather(*(fetch(v) for v in unique))
        return {k: v for k, v in pairs if v is not None}


def _first_fixed_version(vuln: dict[str, Any]) -> str | None:
    for affected in vuln.get("affected") or []:
        for rng in affected.get("ranges") or []:
            for event in rng.get("events") or []:
                if "fixed" in event:
                    return str(event["fixed"])
    return None


def _manifest_line(ctx: RuleContext, manifest_path: str | None, package: str) -> int | None:
    """Locate the dependency's declaration line so the UI can jump to it.

    Matches the package only in *key* position. A substring search matched
    `"dev": "vite"` inside `scripts` and reported the wrong line.
    """
    if manifest_path is None:
        return None
    source = ctx.snapshot.get(manifest_path)
    if source is None:
        return None

    # Requirements files and pyproject are not JSON, and the key-position logic
    # below would find nothing in them. Match the normalised name instead, since
    # `Flask-SQLAlchemy` and `flask_sqlalchemy` are the same package and the
    # advisory always names the normalised form.
    if not manifest_path.endswith(".json"):
        for number, line in enumerate(source.lines(), start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            match = re.match(r"^[\"'\s]*([A-Za-z0-9._-]+)", stripped)
            if match and normalise_name(match.group(1)) == package:
                return number
        return None

    key = f'"{package}":'
    in_dependencies = False
    fallback: int | None = None

    for number, line in enumerate(source.lines(), start=1):
        stripped = line.strip()

        if stripped.startswith('"') and stripped.rstrip().endswith("{"):
            section = stripped.split('"')[1] if '"' in stripped else ""
            in_dependencies = "ependencies" in section  # dependencies, devDependencies, peer…
            continue

        if stripped.startswith(key):
            if in_dependencies:
                return number
            fallback = fallback or number

    return fallback


class ResolvedDependency(DependencyInfo):
    from_lockfile: bool = False


def collect_dependencies(
    ctx: RuleContext, resolved: dict[str, str]
) -> list[ResolvedDependency]:
    """Flatten every manifest's dependencies, preferring lockfile versions."""
    out: dict[str, ResolvedDependency] = {}

    for manifest in ctx.snapshot.by_name("package.json"):
        data = parse_package_json(manifest)
        if not data:
            continue
        for key, is_dev in (("dependencies", False), ("devDependencies", True)):
            for name, spec in (data.get(key) or {}).items():
                if not isinstance(spec, str) or name in out:
                    continue
                lockfile_version = resolved.get(name)
                out[name] = ResolvedDependency(
                    name=name,
                    version_spec=spec,
                    resolved_version=lockfile_version or coerce_version(spec),
                    ecosystem="npm",
                    is_dev=is_dev,
                    from_lockfile=lockfile_version is not None,
                )
    return list(out.values())


@register
class MissingLockfileRule:
    id = "dep/no-lockfile"
    name = "No dependency lockfile"
    category = Category.DEPENDENCIES

    def applies(self, ctx: RuleContext) -> bool:
        return ctx.facts.is_node

    async def run(self, ctx: RuleContext) -> list[Finding]:
        if ctx.facts.has_lockfile:
            return []
        manifests = ctx.snapshot.by_name("package.json")
        return [
            ctx.finding(
                rule_id=self.id,
                title="No dependency lockfile committed",
                references=["https://docs.npmjs.com/cli/v10/configuring-npm/package-lock-json"],
                description=(
                    "Without a lockfile, installs resolve version ranges "
                    "differently over time and across machines, so builds are "
                    "not reproducible and vulnerability scanning cannot "
                    "determine which versions are actually installed."
                ),
                category=Category.DEPENDENCIES,
                severity=Severity.MEDIUM,
                file=manifests[0].path if manifests else None,
                line=1 if manifests else None,
                remediation=(
                    "Run your package manager's install and commit the "
                    "resulting package-lock.json, yarn.lock or pnpm-lock.yaml."
                ),
            )
        ]


@register
class ReactVersionMismatchRule:
    """Ported from v2, which compared version *strings* for equality."""

    id = "dep/react-dom-mismatch"
    name = "React and ReactDOM version mismatch"
    category = Category.DEPENDENCIES

    def applies(self, ctx: RuleContext) -> bool:
        return ctx.facts.is_node

    async def run(self, ctx: RuleContext) -> list[Finding]:
        findings: list[Finding] = []
        resolved = resolved_versions_from_lockfile(ctx.snapshot)

        for manifest in ctx.snapshot.by_name("package.json"):
            data = parse_package_json(manifest)
            if not data:
                continue
            deps = {**(data.get("dependencies") or {}), **(data.get("devDependencies") or {})}
            if "react" not in deps or "react-dom" not in deps:
                continue

            # Compare resolved majors rather than raw spec strings: "^19.1.1"
            # and "19.1.2" are compatible, and v2 would have flagged them.
            react_v = resolved.get("react") or coerce_version(deps["react"])
            dom_v = resolved.get("react-dom") or coerce_version(deps["react-dom"])
            if not react_v or not dom_v:
                continue
            if react_v.split(".")[0] == dom_v.split(".")[0]:
                continue

            findings.append(
                ctx.finding(
                    rule_id=self.id,
                    title="react and react-dom are on different major versions",
                    references=["https://react.dev/versions"],
                    description=(
                        f"react resolves to {react_v} but react-dom resolves to "
                        f"{dom_v}. These packages share internal APIs and must "
                        f"be kept on the same major version."
                    ),
                    category=Category.DEPENDENCIES,
                    severity=Severity.HIGH,
                    file=manifest.path,
                    line=_manifest_line(ctx, manifest.path, "react-dom"),
                    remediation=f"Align both packages, e.g. install react-dom@{react_v}.",
                )
            )
        return findings
