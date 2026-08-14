"""Every finding, from every rule, has to answer the same four questions.

    What is wrong?      title
    Why does it matter? description
    Where is it?        file/line, or nothing when it is genuinely project-wide
    How do I fix it?    remediation, and somewhere to read more

The nine security rules were written to that standard. The twenty-one that
came before were not held to it, and the difference showed: they carried
remediation but mostly no reference, and their advice was a sentence where the
newer ones show the actual change.

This is a contract over the *registry*, not a list of per-rule assertions. A
rule added next year is covered by it without anyone remembering to come back
here — which is the only version of this that survives contact with a codebase
that keeps growing.
"""

from __future__ import annotations

import pytest

import app.analysis.rules  # noqa: F401  — importing registers every rule
from app.analysis.base import ProjectFacts, RuleContext, all_rules
from app.config import Settings
from app.ingest.snapshot import Snapshot
from app.schemas import Category, Finding

# A project built to trip as many rules as possible in one pass: no lockfile,
# no linter, no tests, no CI, no README, non-strict TypeScript, a long deeply
# nested file, React anti-patterns, and Python correctness problems.
FIXTURE: dict[str, str] = {
    "package.json": '{"name":"demo","dependencies":{"react":"^18.0.0","react-dom":"^17.0.0"}}',
    "tsconfig.json": '{"compilerOptions":{"strict":false,"target":"es2020"}}',
    "src/list.tsx": (
        "export function List({ items, html }) {\n"
        "  return (\n"
        "    <div>\n"
        "      {items.map((item, i) => (\n"
        "        <li key={i}>{item.name}</li>\n"
        "      ))}\n"
        "      <span dangerouslySetInnerHTML={{ __html: html }} />\n"
        "    </div>\n"
        "  );\n"
        "}\n"
    ),
    "src/big.ts": (
        "// TODO: split this up\n"
        "// FIXME: and this\n"
        + "\n".join(f"export const value{i} = {i};" for i in range(700))
        + "\n\nexport function tangled(a, b, c, d) {\n"
        + "  if (a) {\n    if (b) {\n      if (c) {\n        if (d) {\n"
        + "          return 1;\n        }\n      }\n    }\n  }\n"
        + "\n".join(f"  const step{i} = {i};" for i in range(90))
        + "\n  return 0;\n}\n"
    ),
    "app/service.py": (
        "def collect(items=[]):\n"
        "    try:\n"
        "        items.append(1)\n"
        "    except:\n"
        "        pass\n"
        "    return items\n"
    ),
    # Deep nesting and markers get their own file. `big.ts` is already long
    # enough to trip the file-length rule, and piling everything into it made
    # it unclear which rule a failure belonged to.
    "src/nested.ts": (
        "\n".join(f"// TODO: item {i}" for i in range(12))
        + "\n\nexport function deep(a, b, c, d, e) {\n"
        + "  if (a) {\n    for (const x of b) {\n      while (c) {\n"
        + "        if (d) {\n          try {\n            if (e) {\n"
        + "              return x;\n"
        + "            }\n          } catch (err) {}\n        }\n"
        + "      }\n    }\n  }\n  return null;\n}\n"
    ),
    # Trips the security pack too, so the contract covers those rules rather
    # than only the ones about project hygiene.
    "src/vuln.js": (
        "const crypto = require('crypto');\n"
        "app.get('/u', async (req, res) => {\n"
        "  const rows = await db.query(`SELECT * FROM u WHERE id = ${req.query.id}`);\n"
        "  exec(`cat /logs/${req.query.name}`);\n"
        "  fs.readFile(path.join(R, req.query.file), cb);\n"
        "  await fetch(req.query.url);\n"
        "  const passwordHash = crypto.createHash('md5').update(req.body.p).digest('hex');\n"
        "  const sessionToken = Math.random().toString(36);\n"
        "  const claims = jwt.decode(req.headers.authorization);\n"
        "  res.json({ rows, claims, sessionToken, passwordHash });\n"
        "});\n"
    ),
    "app/danger.py": (
        "import pickle, subprocess\n"
        "def load(blob, name):\n"
        "    subprocess.run(f'ls {name}', shell=True)\n"
        "    return pickle.loads(blob)\n"
    ),
    "config/keys.js": 'module.exports = { awsKey: "AKIA3F7XQ2LMWDZP9TVB" };\n',
}

# Rules whose findings genuinely have no location: they are statements about
# the project, not about a line. Listed explicitly so a rule that simply forgot
# to record where it looked cannot hide among them.
PROJECT_WIDE = {
    "config/no-linter",
    "config/no-tests",
    "config/no-ci",
    "config/no-readme",
    "config/ts-not-strict",
    "dep/no-lockfile",
    "dep/react-dom-mismatch",
    "quality/todo-markers",
}


@pytest.fixture(scope="module")
def findings(tmp_path_factory) -> list[Finding]:
    root = tmp_path_factory.mktemp("contract")
    for name, content in FIXTURE.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, newline="")

    snapshot = Snapshot.build(root)
    ctx = RuleContext(
        snapshot=snapshot,
        facts=ProjectFacts(
            languages={"typescript", "javascript", "python"},
            package_json={"name": "demo", "dependencies": {"react": "^18.0.0"}},
            frameworks={"react"},
            package_managers={"npm"},
            has_typescript=True,
            has_tests=False,
            has_ci=False,
            has_lockfile=False,
        ),
        settings=Settings(),
    )

    import asyncio

    async def run_all() -> list[Finding]:
        out: list[Finding] = []
        for rule in all_rules():
            # `applies` is the rule's own judgement; a rule that declines is not
            # a rule that failed.
            if not rule.applies(ctx):
                continue
            try:
                out.extend(await rule.run(ctx))
            except Exception as exc:  # pragma: no cover - surfaced as a failure
                raise AssertionError(f"{rule.id} raised {type(exc).__name__}: {exc}") from exc
        return out

    return asyncio.run(run_all())


def test_the_fixture_actually_exercises_a_broad_set_of_rules(findings):
    """Guards every other test in this file from being vacuous.

    A contract asserted over an empty list passes perfectly.
    """
    fired = {f.rule_id for f in findings}
    assert len(fired) >= 10, f"fixture only tripped {len(fired)} rules: {sorted(fired)}"


def test_every_finding_explains_why_it_matters(findings):
    for finding in findings:
        assert finding.description, f"{finding.rule_id} has no description"
        assert finding.description != finding.title, (
            f"{finding.rule_id} restates its title instead of explaining it"
        )
        # Short enough to be a label rather than an explanation.
        assert len(finding.description) >= 60, (
            f"{finding.rule_id} explains itself in {len(finding.description)} chars: "
            f"{finding.description!r}"
        )


def test_every_finding_says_how_to_fix_it(findings):
    for finding in findings:
        assert finding.remediation, f"{finding.rule_id} has no remediation"
        assert len(finding.remediation) >= 30, (
            f"{finding.rule_id} remediation is too thin: {finding.remediation!r}"
        )


# Findings with no canonical source to cite, and no honest way to invent one.
# "You have twelve TODO markers" is an observation about this repository, not a
# claim about software engineering that someone else has written down. Forcing
# a URL here would produce a citation that does not support the finding, which
# is worse for the reader than no citation at all.
#
# Deliberately a short, named list rather than a relaxed assertion: adding to it
# should require saying why.
NO_CANONICAL_REFERENCE = {"quality/todo-markers"}


def test_every_finding_points_somewhere_to_read_more(findings):
    """The gap between the newer rules and the older ones.

    A reference is what lets someone disagree with a finding on the merits
    rather than on trust, and it is the cheapest thing a rule can offer.
    """
    missing = sorted(
        {
            f.rule_id
            for f in findings
            if not f.references and f.rule_id not in NO_CANONICAL_REFERENCE
        }
    )
    assert not missing, f"rules with no reference: {missing}"


def test_the_reference_exemption_list_stays_honest(findings):
    """An exemption that is no longer needed is an exemption that will hide the
    next rule that forgets."""
    fired = {f.rule_id for f in findings}
    for rule_id in NO_CANONICAL_REFERENCE:
        if rule_id not in fired:
            continue
        has_refs = any(f.references for f in findings if f.rule_id == rule_id)
        assert not has_refs, (
            f"{rule_id} now has references and should leave the exemption list"
        )


def test_every_finding_is_anchored_unless_it_is_project_wide(findings):
    for finding in findings:
        if finding.rule_id in PROJECT_WIDE:
            continue
        assert finding.file, f"{finding.rule_id} reported no file"
        assert finding.line, f"{finding.rule_id} reported no line"


def test_every_finding_has_a_usable_fingerprint(findings):
    for finding in findings:
        assert finding.fingerprint, f"{finding.rule_id} has no fingerprint"
        assert len(finding.fingerprint) == 12


def test_metrics_are_the_only_findings_that_cannot_be_acted_on(findings):
    """`METRIC` is the category for measurements. Anything else claiming to be
    one is miscategorised, and would be filtered out of the default view for
    the wrong reason."""
    for finding in findings:
        if finding.category is Category.METRIC:
            assert finding.rule_id.startswith("quality/"), (
                f"{finding.rule_id} is a metric but not a quality measurement"
            )
