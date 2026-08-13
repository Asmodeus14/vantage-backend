"""Project configuration and hygiene checks.

Every rule here declares an ``applies()`` gate. v2 ran all of these
unconditionally, so a Python or Go repository was told it was missing ESLint
and a Vite config.
"""

from __future__ import annotations

from app.analysis.base import RuleContext, register
from app.schemas import Category, Confidence, Finding, Severity

ESLINT_CONFIGS = (
    ".eslintrc", ".eslintrc.js", ".eslintrc.cjs", ".eslintrc.json",
    ".eslintrc.yml", ".eslintrc.yaml", "eslint.config.js", "eslint.config.mjs",
    "eslint.config.ts", "biome.json", "biome.jsonc",
)

CI_PATHS = (".github/workflows", ".gitlab-ci.yml", ".circleci", "azure-pipelines.yml",
            "Jenkinsfile", ".travis.yml", "bitbucket-pipelines.yml")

TEST_INDICATORS = (
    ".test.", ".spec.", "_test.", "test_", "/tests/", "/test/", "__tests__",
)


@register
class NoLinterRule:
    id = "config/no-linter"
    name = "No linter configured"
    category = Category.CONFIGURATION

    def applies(self, ctx: RuleContext) -> bool:
        # Both ecosystems that have a rule pack. The Node-only gate was correct
        # while the engine was JS-only, and became a blind spot the moment
        # Python rules shipped: this API's own repository has no linter at all
        # and was never told so, because the check did not apply to it.
        return ctx.facts.is_node or ctx.facts.is_python

    async def run(self, ctx: RuleContext) -> list[Finding]:
        if not ctx.facts.is_node:
            return self._python(ctx)
        if ctx.snapshot.exists(*ESLINT_CONFIGS):
            return []
        manifests = ctx.snapshot.by_name("package.json")
        return [
            ctx.finding(
                rule_id=self.id,
                title="No ESLint or Biome configuration found",
                description=(
                    "A linter catches an entire class of defect — unused "
                    "variables, unreachable code, misused hooks — before review. "
                    "No configuration file was found in the project."
                ),
                category=Category.CONFIGURATION,
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                file=manifests[0].path if manifests else None,
                line=1 if manifests else None,
                remediation="Run `npm init @eslint/config`, or adopt Biome for a faster single-binary setup.",
                references=["https://eslint.org/docs/latest/use/getting-started"],
            )
        ]

    def _python(self, ctx: RuleContext) -> list[Finding]:
        """Ruff, flake8 or pylint — configured anywhere they are usually put."""
        # A dedicated config file is proof on its own.
        if ctx.snapshot.exists(".ruff.toml", "ruff.toml", ".flake8", ".pylintrc"):
            return []

        # `setup.cfg` and `tox.ini` exist in most projects for other reasons, so
        # their presence proves nothing — the section inside them does.
        #
        # Formatters are deliberately not accepted here. black and isort make
        # code consistent; neither catches an unused import or a shadowed name,
        # which is what this rule is about.
        for name in ("pyproject.toml", "setup.cfg", "tox.ini"):
            for source in ctx.snapshot.by_name(name):
                text = (source.text() or "").lower()
                if any(
                    marker in text
                    for marker in ("[tool.ruff", "[flake8]", "[tool.pylint", "[pylint")
                ):
                    return []

        manifests = ctx.snapshot.by_name("pyproject.toml", "setup.cfg")
        return [
            ctx.finding(
                rule_id=self.id,
                title="No Python linter configured",
                description=(
                    "A linter catches an entire class of defect — unused imports, "
                    "shadowed names, unreachable code — before review. No ruff, "
                    "flake8 or pylint configuration was found."
                ),
                category=Category.CONFIGURATION,
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                file=manifests[0].path if manifests else None,
                line=1 if manifests else None,
                remediation=(
                    "Add a `[tool.ruff]` section to pyproject.toml. Ruff is a "
                    "single binary and covers most of flake8 and isort."
                ),
                references=["https://docs.astral.sh/ruff/"],
            )
        ]


@register
class NoTestsRule:
    id = "config/no-tests"
    name = "No automated tests"
    category = Category.TESTING

    def applies(self, ctx: RuleContext) -> bool:
        return True

    async def run(self, ctx: RuleContext) -> list[Finding]:
        if ctx.facts.has_tests:
            return []
        return [
            ctx.finding(
                rule_id=self.id,
                title="No test files found",
                description=(
                    "No files matching common test conventions were found. "
                    "Without tests, every change is verified by hand and "
                    "regressions surface in production rather than in CI."
                ),
                category=Category.TESTING,
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                remediation=(
                    "Add a test runner (Vitest and pytest are good defaults) "
                    "and start with the highest-risk module rather than aiming "
                    "for a coverage percentage."
                ),
            )
        ]


@register
class NoCiRule:
    id = "config/no-ci"
    name = "No continuous integration"
    category = Category.CONFIGURATION

    def applies(self, ctx: RuleContext) -> bool:
        return True

    async def run(self, ctx: RuleContext) -> list[Finding]:
        if ctx.facts.has_ci:
            return []
        return [
            ctx.finding(
                rule_id=self.id,
                title="No CI pipeline configured",
                description=(
                    "No CI configuration was found. Tests and linting that only "
                    "run locally get skipped under deadline pressure."
                ),
                category=Category.CONFIGURATION,
                severity=Severity.LOW,
                confidence=Confidence.MEDIUM,
                remediation=(
                    "Add a GitHub Actions workflow running install, lint, "
                    "typecheck and test on pull requests."
                ),
            )
        ]


@register
class NoTypeScriptStrictRule:
    id = "config/ts-not-strict"
    name = "TypeScript strict mode disabled"
    category = Category.CONFIGURATION

    def applies(self, ctx: RuleContext) -> bool:
        return ctx.facts.has_typescript

    async def run(self, ctx: RuleContext) -> list[Finding]:
        findings: list[Finding] = []
        for config in ctx.snapshot.by_name("tsconfig.json"):
            text = config.text()
            if not text:
                continue
            # Deliberately textual: tsconfig.json permits comments and trailing
            # commas, so json.loads would reject valid files.
            if '"strict"' in text and '"strict": true' not in text.replace("'", '"'):
                line = next(
                    (n for n, l in enumerate(config.lines(), 1) if '"strict"' in l), 1
                )
                findings.append(
                    ctx.finding(
                        rule_id=self.id,
                        title="TypeScript strict mode is disabled",
                        description=(
                            "With strict off, null and undefined are assignable "
                            "everywhere and implicit any is permitted, which "
                            "removes most of the guarantees TypeScript exists "
                            "to provide."
                        ),
                        category=Category.CONFIGURATION,
                        severity=Severity.MEDIUM,
                        file=config.path,
                        line=line,
                        remediation=(
                            'Set "strict": true and fix errors incrementally, '
                            "enabling strictNullChecks first."
                        ),
                    )
                )
            elif '"strict"' not in text:
                findings.append(
                    ctx.finding(
                        rule_id=self.id,
                        title="TypeScript strict mode is not enabled",
                        description=(
                            "tsconfig.json does not set `strict`, so it "
                            "defaults to false and most type guarantees are off."
                        ),
                        category=Category.CONFIGURATION,
                        severity=Severity.MEDIUM,
                        file=config.path,
                        line=1,
                        remediation='Add "strict": true to compilerOptions.',
                    )
                )
        return findings


@register
class NoReadmeRule:
    id = "config/no-readme"
    name = "No README"
    category = Category.CONFIGURATION

    def applies(self, ctx: RuleContext) -> bool:
        return True

    async def run(self, ctx: RuleContext) -> list[Finding]:
        readmes = [f for f in ctx.snapshot.files if f.name.lower().startswith("readme")]
        if readmes:
            return []
        return [
            ctx.finding(
                rule_id=self.id,
                title="No README found",
                description=(
                    "A README is the first thing a new contributor reads. "
                    "Without it, setup knowledge lives only in people's heads."
                ),
                category=Category.CONFIGURATION,
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                remediation="Add a README covering what the project does, how to run it, and how to test it.",
            )
        ]
