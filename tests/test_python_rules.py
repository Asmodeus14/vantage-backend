"""The Python rule pack, and Python dependency parsing.

Each rule is tested against code that should fire it *and* against code that
should not. The second half is what decides whether a rule is signal or noise,
and noise is what makes people stop reading findings.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.analysis.base import ProjectFacts, RuleContext
from app.analysis.rules.python import (
    BareExceptRule,
    MutableDefaultArgumentRule,
    ShellInjectionSurfaceRule,
    UnsafeDeserialisationRule,
    collect_python_dependencies,
    exact_version,
    normalise_name,
    parse_poetry_lock,
    parse_pyproject,
    parse_requirements,
)
from app.config import Settings
from app.ingest.snapshot import Snapshot


def build(tmp_path: Path, files: dict[str, str]) -> RuleContext:
    for name, content in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, newline="")
    snapshot = Snapshot.build(tmp_path)
    facts = ProjectFacts(languages={"python"}, package_managers={"pip"})
    return RuleContext(snapshot=snapshot, facts=facts, settings=Settings())


async def run(rule, tmp_path: Path, files: dict[str, str]):
    return await rule.run(build(tmp_path, files))


# --------------------------------------------------------------------------
# Manifest parsing
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "raw,expected",
    [
        ("Flask_SQLAlchemy", "flask-sqlalchemy"),
        ("flask.sqlalchemy", "flask-sqlalchemy"),
        ("FLASK-SQLALCHEMY", "flask-sqlalchemy"),
    ],
)
def test_package_names_are_normalised(raw, expected):
    """PEP 503. OSV indexes the normalised form, so without this half a
    requirements file silently matches no advisory at all."""
    assert normalise_name(raw) == expected


def test_requirements_parsing_handles_what_real_files_contain():
    text = """
# a comment
-r base.txt
--index-url https://example.invalid

Django==4.2.1
requests>=2.0
celery[redis]==5.3.0
uvicorn==0.23.2 ; python_version >= "3.8"
"""
    found = parse_requirements(text)
    assert found["django"] == "==4.2.1"
    assert found["requests"] == ">=2.0"
    assert found["celery"] == "==5.3.0", "extras must not become part of the name"
    assert found["uvicorn"] == "==0.23.2", "an environment marker is not a version"
    # Options and comments are not packages.
    assert "-r" not in found and "base.txt" not in found


@pytest.mark.parametrize(
    "spec,expected",
    [
        ("==4.2.1", "4.2.1"),
        ("== 4.2.1", "4.2.1"),
        (">=2.0", None),
        ("^1.0", None),
        ("~=1.4", None),
        ("", None),
    ],
)
def test_only_a_pin_counts_as_a_resolved_version(spec, expected):
    """Mirrors the npm side: a range would have to be resolved against the index
    to mean anything, and guessing produces advisories for versions nobody
    installed."""
    assert exact_version(spec) == expected


def test_pyproject_covers_both_pep_621_and_poetry():
    text = """
[project]
dependencies = ["httpx==0.25.0", "pydantic>=2"]

[project.optional-dependencies]
dev = ["pytest==7.4.0"]

[tool.poetry.dependencies]
python = "^3.12"
requests = "2.31.0"
rich = { version = "^13.0", optional = true }
"""
    found = parse_pyproject(text)
    assert found["httpx"] == "==0.25.0"
    assert found["pytest"] == "==7.4.0", "optional groups still ship"
    # Poetry's bare `2.31.0` means exactly that; `^13.0` does not.
    assert exact_version(found["requests"]) == "2.31.0"
    assert exact_version(found["rich"]) is None
    assert "python" not in found, "the interpreter is not a package"


def test_malformed_pyproject_yields_nothing_rather_than_raising():
    """One bad manifest must not take down an analysis."""
    assert parse_pyproject("this is not [ valid toml") == {}


def test_a_pin_beats_a_range_from_another_manifest(tmp_path):
    ctx = build(
        tmp_path,
        {
            "pyproject.toml": '[project]\ndependencies = ["django>=4"]\n',
            "requirements.txt": "django==4.2.1\n",
        },
    )
    found = {name: version for name, _, version in collect_python_dependencies(ctx)}
    assert found["django"] == "4.2.1", "the pinned file is what actually installs"


# --------------------------------------------------------------------------
# Mutable default arguments
# --------------------------------------------------------------------------

async def test_a_mutable_default_is_reported(tmp_path):
    findings = await run(
        MutableDefaultArgumentRule(),
        tmp_path,
        {"app.py": "def collect(items=[]):\n    return items\n"},
    )
    assert len(findings) == 1
    assert "collect()" in findings[0].title


async def test_a_wrapped_signature_is_still_read(tmp_path):
    """A naive line-at-a-time version misses everything formatted by black."""
    findings = await run(
        MutableDefaultArgumentRule(),
        tmp_path,
        {
            "app.py": (
                "def collect(\n"
                "    name: str,\n"
                "    items: list = [],\n"
                ") -> list:\n"
                "    return items\n"
            )
        },
    )
    assert len(findings) == 1


@pytest.mark.parametrize(
    "code",
    [
        "def f(items=None):\n    return items or []\n",
        "def f(count=0, name='x'):\n    return count\n",
        "def f(items: list | None = None):\n    return items\n",
        # A list *inside the body* is fine — it is rebuilt on every call.
        "def f():\n    items = []\n    return items\n",
    ],
)
async def test_correct_code_is_left_alone(tmp_path, code):
    assert await run(MutableDefaultArgumentRule(), tmp_path, {"a.py": code}) == []


async def test_the_finding_is_keyed_on_the_function_not_the_line(tmp_path):
    """So adding an import above it does not read as resolved-plus-new."""
    one = await run(
        MutableDefaultArgumentRule(), tmp_path / "a", {"app.py": "def f(x=[]):\n    pass\n"}
    )
    two = await run(
        MutableDefaultArgumentRule(),
        tmp_path / "b",
        {"app.py": "import os\nimport sys\n\n\ndef f(x=[]):\n    pass\n"},
    )
    assert one[0].line != two[0].line
    assert one[0].fingerprint == two[0].fingerprint


# --------------------------------------------------------------------------
# Bare except
# --------------------------------------------------------------------------

async def test_a_bare_except_is_reported(tmp_path):
    findings = await run(
        BareExceptRule(),
        tmp_path,
        {"a.py": "try:\n    go()\nexcept:\n    pass\n"},
    )
    assert len(findings) == 1


@pytest.mark.parametrize(
    "code",
    [
        "try:\n    go()\nexcept Exception:\n    pass\n",
        "try:\n    go()\nexcept (ValueError, KeyError):\n    pass\n",
        "try:\n    go()\nexcept OSError as exc:\n    raise\n",
    ],
)
async def test_a_named_except_is_not_reported(tmp_path, code):
    assert await run(BareExceptRule(), tmp_path, {"a.py": code}) == []


# --------------------------------------------------------------------------
# Shell
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "code",
    [
        'subprocess.run(f"git clone {url}", shell=True)\n',
        'subprocess.call("ls " + path, shell=True)\n',
        'os.system(f"rm {path}")\n',
    ],
)
async def test_shell_execution_is_flagged(tmp_path, code):
    assert len(await run(ShellInjectionSurfaceRule(), tmp_path, {"a.py": code})) == 1


@pytest.mark.parametrize(
    "code",
    [
        'subprocess.run(["git", "clone", url])\n',
        'subprocess.run(["ls", path], capture_output=True)\n',
        # A comment mentioning it is not a call. `iter_code_lines` blanks
        # comments and string bodies before any rule sees them.
        '# never use shell=True here\nsubprocess.run(["ls"])\n',
        'message = "pass shell=True to reproduce"\n',
    ],
)
async def test_safe_subprocess_use_is_not_flagged(tmp_path, code):
    assert await run(ShellInjectionSurfaceRule(), tmp_path, {"a.py": code}) == []


# --------------------------------------------------------------------------
# Deserialisation
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "code",
    [
        "data = yaml.load(handle)\n",
        "obj = pickle.loads(payload)\n",
        "obj = marshal.loads(payload)\n",
    ],
)
async def test_unsafe_deserialisation_is_flagged(tmp_path, code):
    findings = await run(UnsafeDeserialisationRule(), tmp_path, {"a.py": code})
    assert len(findings) == 1
    assert findings[0].severity.value == "high"


@pytest.mark.parametrize(
    "code",
    [
        "data = yaml.safe_load(handle)\n",
        "data = yaml.load(handle, Loader=yaml.SafeLoader)\n",
        "data = json.loads(payload)\n",
    ],
)
async def test_the_safe_forms_are_not_flagged(tmp_path, code):
    assert await run(UnsafeDeserialisationRule(), tmp_path, {"a.py": code}) == []


async def test_security_rules_skip_tests_because_tests_do_this_on_purpose(tmp_path):
    """Measured on psf/requests: all seven deserialisation findings were tests
    deliberately testing deserialisation. Seven unactionable findings is how a
    rule teaches people to skip its entire category."""
    files = {
        "app/service.py": "obj = pickle.loads(payload)\n",
        "tests/test_service.py": "obj = pickle.loads(payload)\n",
        "app/thing_test.py": "obj = pickle.loads(payload)\n",
    }
    findings = await run(UnsafeDeserialisationRule(), tmp_path, files)
    assert [f.file for f in findings] == ["app/service.py"]


async def test_correctness_rules_still_scan_tests(tmp_path):
    """A mutable default argument is a bug wherever it is, and a test that fails
    for its own reasons is worse than one that does not exist."""
    findings = await run(
        MutableDefaultArgumentRule(),
        tmp_path,
        {"tests/test_thing.py": "def helper(acc=[]):\n    return acc\n"},
    )
    assert len(findings) == 1


def test_a_lockfile_beats_an_unresolvable_range(tmp_path):
    """Most Python projects declare ranges, so without lockfile support they
    would get no dependency scanning at all."""
    ctx = build(
        tmp_path,
        {
            "pyproject.toml": (
                "[tool.poetry.dependencies]\npython = \"^3.12\"\nrequests = \"^2.31\"\n"
            ),
            "poetry.lock": (
                '[[package]]\nname = "requests"\nversion = "2.31.0"\n\n'
                '[[package]]\nname = "Jinja2"\nversion = "3.1.2"\n'
            ),
        },
    )
    found = {name: version for name, _, version in collect_python_dependencies(ctx)}
    assert found["requests"] == "2.31.0", "the caret range alone resolves to nothing"
    # Present only in the lockfile, and normalised on the way in.
    assert found["jinja2"] == "3.1.2"


def test_a_malformed_lockfile_yields_nothing_rather_than_raising():
    assert parse_poetry_lock("[[package]\nbroken") == {}


async def test_osv_is_asked_about_each_package_in_its_own_ecosystem():
    """The query used to hardcode `npm`. Asking OSV about `requests` on npm
    returns nothing rather than an error — a silent miss, which is the worst way
    for a security check to be wrong."""
    from app.analysis.rules.dependencies import KnownVulnerabilityRule, ResolvedDependency

    captured: dict = {}

    class FakeResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {"results": [{"vulns": []}, {"vulns": []}]}

    class FakeHttp:
        async def post(self, url, json, timeout):
            captured["payload"] = json
            return FakeResponse()

    ctx = RuleContext(
        snapshot=Snapshot(root=Path(".")),
        facts=ProjectFacts(),
        settings=Settings(),
        http=FakeHttp(),
    )
    await KnownVulnerabilityRule()._query_batch(
        ctx,
        [
            ResolvedDependency(
                name="lodash", version_spec="4.17.20", resolved_version="4.17.20",
                ecosystem="npm",
            ),
            ResolvedDependency(
                name="requests", version_spec="==2.19.0", resolved_version="2.19.0",
                ecosystem="PyPI",
            ),
        ],
    )

    ecosystems = [q["package"]["ecosystem"] for q in captured["payload"]["queries"]]
    assert ecosystems == ["npm", "PyPI"]


# --------------------------------------------------------------------------
# Applicability
# --------------------------------------------------------------------------

def test_python_rules_stay_out_of_a_javascript_project(tmp_path):
    """The complaint that shaped this engine: the version it replaced ran every
    check unconditionally, so a Python project was told it lacked ESLint."""
    (tmp_path / "index.js").write_text("const a = 1;\n", newline="")
    ctx = RuleContext(
        snapshot=Snapshot.build(tmp_path),
        facts=ProjectFacts(languages={"javascript"}),
        settings=Settings(),
    )
    for rule in (
        MutableDefaultArgumentRule(),
        BareExceptRule(),
        ShellInjectionSurfaceRule(),
        UnsafeDeserialisationRule(),
    ):
        assert rule.applies(ctx) is False, rule.id
