"""Analysis orchestration.

Builds shared project facts once, runs every applicable rule, and reports real
progress as it goes. Progress is emitted through a callback so the SSE endpoint
can stream genuine per-rule state — replacing v2's progress bar, which was a
static element hardcoded to 100% width.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections.abc import Awaitable, Callable
from pathlib import PurePosixPath

import httpx

import app.analysis.rules  # noqa: F401  - registers every rule
from app.analysis.base import ProjectFacts, RuleContext, all_rules
from app.analysis.rules.dependencies import (
    collect_dependencies,
    parse_package_json,
    resolved_versions_from_lockfile,
)
from app.analysis.scoring import compute_score, finding_penalty, severity_counts
from app.config import Settings
from app.ingest.filter import ANALYSABLE_LANGUAGES
from app.ingest.snapshot import Snapshot
from app.schemas import (
    AnalysisStage,
    DependencyInfo,
    Finding,
    LanguageStat,
    ProgressEvent,
    ProjectInfo,
)

logger = logging.getLogger(__name__)

ProgressCallback = Callable[[ProgressEvent], Awaitable[None]]

TEST_INDICATORS = (".test.", ".spec.", "_test.", "test_", "__tests__")
CI_MARKERS = (
    ".github/workflows", ".gitlab-ci.yml", ".circleci", "azure-pipelines.yml",
    "jenkinsfile", ".travis.yml", "bitbucket-pipelines.yml",
)
LOCKFILES = ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
             "Pipfile.lock", "Cargo.lock", "go.sum", "composer.lock")

FRAMEWORK_PACKAGES = {
    "next": "next", "react": "react", "vue": "vue", "nuxt": "nuxt",
    "svelte": "svelte", "@sveltejs/kit": "sveltekit", "@angular/core": "angular",
    "express": "express", "fastify": "fastify", "@nestjs/core": "nestjs",
    "remix": "remix", "gatsby": "gatsby", "astro": "astro", "vite": "vite",
    "webpack": "webpack", "electron": "electron", "react-native": "react-native",
}


async def _noop(event: ProgressEvent) -> None:
    return None


def build_facts(snapshot: Snapshot) -> ProjectFacts:
    """Detect everything rules need to decide applicability, once."""
    facts = ProjectFacts()

    manifests = snapshot.by_name("package.json")
    root_manifest = None
    if manifests:
        # Prefer the shallowest manifest as the project root.
        root = min(manifests, key=lambda f: len(PurePosixPath(f.path).parts))
        root_manifest = parse_package_json(root)
        facts.package_json = root_manifest

    for source in snapshot.files:
        if source.language:
            facts.languages.add(source.language)

        lowered = source.path.lower()
        if any(marker in lowered for marker in TEST_INDICATORS):
            facts.has_tests = True
        if any(marker in lowered for marker in CI_MARKERS):
            facts.has_ci = True
        if source.name in LOCKFILES:
            facts.has_lockfile = True

    facts.has_typescript = bool(snapshot.by_name("tsconfig.json")) or "typescript" in facts.languages

    if root_manifest:
        facts.package_managers.add("npm")
        deps = {
            **(root_manifest.get("dependencies") or {}),
            **(root_manifest.get("devDependencies") or {}),
        }
        for package, label in FRAMEWORK_PACKAGES.items():
            if package in deps:
                facts.frameworks.add(label)
        scripts = root_manifest.get("scripts") or {}
        if any(k in scripts for k in ("test", "test:unit", "vitest", "jest")):
            facts.has_tests = facts.has_tests or True

    if snapshot.by_name("yarn.lock"):
        facts.package_managers.add("yarn")
    if snapshot.by_name("pnpm-lock.yaml"):
        facts.package_managers.add("pnpm")
    if snapshot.by_name("requirements.txt", "pyproject.toml", "Pipfile"):
        facts.package_managers.add("pip")
    if snapshot.by_name("go.mod"):
        facts.package_managers.add("go")
    if snapshot.by_name("Cargo.toml"):
        facts.package_managers.add("cargo")

    facts.entry_points = _entry_points(snapshot, root_manifest)
    return facts


def _entry_points(snapshot: Snapshot, manifest: dict | None) -> list[str]:
    candidates: list[str] = []
    if manifest:
        for key in ("main", "module", "browser"):
            value = manifest.get(key)
            if isinstance(value, str):
                candidates.append(value.lstrip("./"))

    common = (
        "src/main.tsx", "src/main.ts", "src/main.jsx", "src/main.js",
        "src/index.tsx", "src/index.ts", "src/index.js", "src/app.tsx",
        "app/page.tsx", "app/layout.tsx", "pages/index.tsx", "pages/_app.tsx",
        "main.py", "app.py", "manage.py", "main.go", "src/main.rs", "index.js",
    )
    for path in common:
        if snapshot.get(path):
            candidates.append(path)

    seen: list[str] = []
    for path in candidates:
        if path not in seen and snapshot.get(path):
            seen.append(path)
    return seen[:8]


def build_project_info(snapshot: Snapshot, facts: ProjectFacts) -> ProjectInfo:
    analysable = snapshot.analysable()

    per_language: dict[str, tuple[int, int]] = {}
    for source in analysable:
        if not source.language:
            continue
        files, lines = per_language.get(source.language, (0, 0))
        per_language[source.language] = (files + 1, lines + source.line_count())

    total_lines = sum(lines for _, lines in per_language.values()) or 1
    languages = sorted(
        (
            LanguageStat(
                language=language,
                files=files,
                lines=lines,
                share=round(lines / total_lines, 4),
            )
            for language, (files, lines) in per_language.items()
        ),
        key=lambda s: s.lines,
        reverse=True,
    )

    manifest = facts.package_json or {}
    return ProjectInfo(
        name=manifest.get("name"),
        description=manifest.get("description"),
        languages=languages[:12],
        frameworks=sorted(facts.frameworks),
        package_managers=sorted(facts.package_managers),
        entry_points=facts.entry_points,
        total_files=len(snapshot.files),
        analysed_files=len(analysable),
        total_lines=sum(lines for _, lines in per_language.values()),
        has_tests=facts.has_tests,
        has_ci=facts.has_ci,
        has_lockfile=facts.has_lockfile,
    )


class AnalysisEngine:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    async def analyse(
        self,
        snapshot: Snapshot,
        *,
        progress: ProgressCallback | None = None,
    ) -> tuple[list[Finding], ProjectInfo, list[DependencyInfo], float, list[str]]:
        """Findings, project info, dependencies, elapsed seconds, rules run.

        The rule-id list includes rules that found nothing. Report diffing needs
        it to distinguish "this rule is new" from "this rule ran clean last
        time", which cannot be recovered from the findings alone.
        """
        emit = progress or _noop
        started = time.monotonic()

        await emit(
            ProgressEvent(
                stage=AnalysisStage.INDEXING,
                message=f"Indexed {len(snapshot.files):,} files",
                completed=0,
                total=0,
            )
        )

        facts = build_facts(snapshot)
        project = build_project_info(snapshot, facts)

        async with httpx.AsyncClient(
            headers={"User-Agent": "Vantage/3.0 (+https://github.com/Asmodeus14)"},
            follow_redirects=True,
        ) as http:
            ctx = RuleContext(
                snapshot=snapshot, facts=facts, settings=self.settings, http=http
            )

            applicable = [rule for rule in all_rules() if rule.applies(ctx)]
            total = len(applicable)
            findings: list[Finding] = []

            for index, rule in enumerate(applicable, start=1):
                await emit(
                    ProgressEvent(
                        stage=AnalysisStage.ANALYSING,
                        message=rule.name,
                        completed=index,
                        total=total,
                    )
                )
                try:
                    produced = await asyncio.wait_for(
                        rule.run(ctx), timeout=self.settings.osv_timeout_seconds + 30
                    )
                    findings.extend(produced)
                except asyncio.TimeoutError:
                    logger.warning("Rule %s timed out", rule.id)
                except Exception:
                    # One failing rule must not lose the entire analysis.
                    logger.exception("Rule %s raised", rule.id)

            dependencies = self._dependencies(ctx, findings)

        findings = self._prioritise(findings)
        duration = time.monotonic() - started
        return findings, project, dependencies, duration, [r.id for r in applicable]

    def _dependencies(self, ctx: RuleContext, findings: list[Finding]) -> list[DependencyInfo]:
        if not ctx.facts.is_node:
            return []
        resolved = resolved_versions_from_lockfile(ctx.snapshot)
        collected = collect_dependencies(ctx, resolved)

        vulnerable: dict[str, list[str]] = {}
        for finding in findings:
            if finding.rule_id != "dep/known-vulnerability":
                continue
            package = finding.title.split("@")[0]
            ids = [r.rsplit("/", 1)[-1] for r in finding.references if "osv.dev" in r]
            vulnerable.setdefault(package, []).extend(ids)

        out: list[DependencyInfo] = []
        for dependency in collected:
            out.append(
                DependencyInfo(
                    name=dependency.name,
                    version_spec=dependency.version_spec,
                    resolved_version=dependency.resolved_version,
                    ecosystem=dependency.ecosystem,
                    is_dev=dependency.is_dev,
                    vulnerabilities=sorted(set(vulnerable.get(dependency.name, []))),
                )
            )
        return sorted(out, key=lambda d: (not d.vulnerabilities, d.name))

    def _prioritise(self, findings: list[Finding]) -> list[Finding]:
        """Most actionable first: penalty desc, then located before unlocated."""
        return sorted(
            findings,
            key=lambda f: (-finding_penalty(f), f.file is None, f.file or "", f.line or 0),
        )


__all__ = [
    "AnalysisEngine",
    "build_facts",
    "build_project_info",
    "compute_score",
    "severity_counts",
]
