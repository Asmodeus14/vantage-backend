"""Rule behaviour, including regressions against v2's specific defects."""

from __future__ import annotations

import httpx
import pytest
import respx

from app.analysis.base import strip_comments_and_strings
from app.analysis.rules.configuration import NoLinterRule, NoTypeScriptStrictRule
from app.analysis.rules.dependencies import (
    KnownVulnerabilityRule,
    ReactVersionMismatchRule,
    coerce_version,
    resolved_versions_from_lockfile,
)
from app.analysis.rules.quality import LongFileRule
from app.analysis.rules.react import MissingKeyRule
from app.analysis.rules.secrets import (
    EnvNotIgnoredRule,
    HardcodedSecretRule,
    redact,
    shannon_entropy,
)
from app.schemas import Severity

REACT_PKG = {
    "name": "demo",
    "dependencies": {"react": "^19.1.1", "react-dom": "^19.1.1"},
}


# --------------------------------------------------------------------------
# Comment/string stripping — v2 counted keywords inside comments and literals
# --------------------------------------------------------------------------

def test_strip_removes_line_comments_but_keeps_line_numbers():
    source = "const a = 1;\n// if (x) { for (y) }\nconst b = 2;"
    cleaned = strip_comments_and_strings(source, "javascript")
    assert len(cleaned.splitlines()) == 3
    assert "if (" not in cleaned
    assert "const b = 2;" in cleaned


def test_strip_removes_string_contents():
    source = 'const msg = "if you see this, for real";'
    cleaned = strip_comments_and_strings(source, "javascript")
    assert "if you see this" not in cleaned
    assert cleaned.startswith("const msg = ")


def test_strip_handles_block_comments_across_lines():
    source = "a();\n/* if (x) {\n   for (y) {} \n} */\nb();"
    cleaned = strip_comments_and_strings(source, "javascript")
    assert len(cleaned.splitlines()) == 5
    assert "if (x)" not in cleaned
    assert "b();" in cleaned


def test_strip_uses_hash_comments_for_python():
    cleaned = strip_comments_and_strings("x = 1  # if for while", "python")
    assert "if for while" not in cleaned
    assert "x = 1" in cleaned


# --------------------------------------------------------------------------
# React rules — v2 checked `key=` anywhere in the whole file
# --------------------------------------------------------------------------

async def test_missing_key_is_detected_per_call_site(make_context):
    ctx = make_context(
        {
            "package.json": REACT_PKG,
            "src/List.jsx": (
                "export function List({items}) {\n"
                "  return <ul>{items.map((item) => <li>{item.name}</li>)}</ul>;\n"
                "}\n"
            ),
        }
    )
    findings = await MissingKeyRule().run(ctx)
    assert len(findings) == 1
    assert findings[0].line == 2
    assert findings[0].file == "src/List.jsx"


async def test_keyed_list_produces_no_finding(make_context):
    ctx = make_context(
        {
            "package.json": REACT_PKG,
            "src/List.jsx": (
                "export function List({items}) {\n"
                "  return <ul>{items.map((item) => <li key={item.id}>{item.name}</li>)}</ul>;\n"
                "}\n"
            ),
        }
    )
    assert await MissingKeyRule().run(ctx) == []


async def test_key_elsewhere_in_file_does_not_mask_a_real_miss(make_context):
    """The exact v2 false-negative: one keyed list suppressed all others."""
    ctx = make_context(
        {
            "package.json": REACT_PKG,
            "src/Two.jsx": (
                "export function Two({a, b}) {\n"
                "  return (<>\n"
                "    <ul>{a.map((x) => <li key={x.id}>{x.n}</li>)}</ul>\n"
                "    <ol>{b.map((y) => <li>{y.n}</li>)}</ol>\n"
                "  </>);\n"
                "}\n"
            ),
        }
    )
    findings = await MissingKeyRule().run(ctx)
    assert len(findings) == 1, "the unkeyed list must still be reported"
    assert findings[0].line == 4


async def test_key_in_a_comment_does_not_suppress(make_context):
    ctx = make_context(
        {
            "package.json": REACT_PKG,
            "src/C.jsx": (
                "// remember to add key={item.id} here\n"
                "export const C = ({items}) => <ul>{items.map((i) => <li>{i.n}</li>)}</ul>;\n"
            ),
        }
    )
    findings = await MissingKeyRule().run(ctx)
    assert len(findings) == 1


async def test_react_rules_do_not_run_on_non_react_projects(make_context):
    ctx = make_context({"main.py": "print('hello')\n"})
    assert MissingKeyRule().applies(ctx) is False


# --------------------------------------------------------------------------
# Configuration gating — v2 told Python projects they needed ESLint
# --------------------------------------------------------------------------

async def test_linter_rule_skips_python_projects(make_context):
    ctx = make_context({"main.py": "print(1)\n", "requirements.txt": "flask\n"})
    assert NoLinterRule().applies(ctx) is False


async def test_linter_rule_fires_for_node_without_config(make_context):
    ctx = make_context({"package.json": {"name": "x"}, "src/a.js": "let a = 1;\n"})
    rule = NoLinterRule()
    assert rule.applies(ctx) is True
    assert len(await rule.run(ctx)) == 1


async def test_linter_rule_recognises_flat_config(make_context):
    ctx = make_context(
        {"package.json": {"name": "x"}, "eslint.config.js": "export default [];\n"}
    )
    assert await NoLinterRule().run(ctx) == []


async def test_typescript_strict_detected(make_context):
    ctx = make_context(
        {
            "package.json": {"name": "x"},
            "tsconfig.json": '{"compilerOptions": {"strict": false}}',
            "src/a.ts": "export const a = 1;\n",
        }
    )
    findings = await NoTypeScriptStrictRule().run(ctx)
    assert len(findings) == 1
    assert "strict" in findings[0].title.lower()


async def test_typescript_strict_true_passes(make_context):
    ctx = make_context(
        {
            "package.json": {"name": "x"},
            "tsconfig.json": '{"compilerOptions": {"strict": true}}',
            "src/a.ts": "export const a = 1;\n",
        }
    )
    assert await NoTypeScriptStrictRule().run(ctx) == []


# --------------------------------------------------------------------------
# Secrets
# --------------------------------------------------------------------------

def test_entropy_separates_random_from_prose():
    assert shannon_entropy("aG7$kL9#pQ2@xR4vB8nM") > 3.6
    assert shannon_entropy("aaaaaaaaaaaaaaaaaaaa") < 1.0


def test_redact_never_reveals_the_value():
    secret = "AKIAIOSFODNN7EXAMPLE"
    out = redact(secret)
    assert secret not in out
    assert out.startswith("AKI")


async def test_aws_key_in_source_is_found_and_redacted(make_context):
    key = "AKIA2E4Z7QK3MNBVCXZL"
    ctx = make_context({"src/config.js": f'const k = "{key}";\n'})
    findings = await HardcodedSecretRule().run(ctx)
    assert len(findings) == 1
    assert findings[0].line == 1
    assert findings[0].severity is Severity.CRITICAL
    assert key not in findings[0].description, "the value must never be echoed"


async def test_aws_documentation_key_is_not_reported(make_context):
    """AWS publishes this key in its own docs; it is not a leak."""
    ctx = make_context({"README.md": "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"})
    assert await HardcodedSecretRule().run(ctx) == []


def test_placeholder_check_does_not_swallow_keys_starting_with_a():
    """Regression: a bare 'a' alternative matched every value beginning with A."""
    from app.analysis.rules.secrets import _is_placeholder

    assert _is_placeholder("AKIA2E4Z7QK3MNBVCXZL") is False
    assert _is_placeholder("aG7kL9pQ2xR4vB8nM1zW") is False
    assert _is_placeholder("your-api-key") is True
    assert _is_placeholder("<YOUR_TOKEN>") is True
    assert _is_placeholder("changeme") is True


async def test_example_files_are_ignored(make_context):
    ctx = make_context({".env.example": "GITHUB_TOKEN=ghp_" + "a" * 36 + "\n"})
    assert await HardcodedSecretRule().run(ctx) == []


async def test_placeholder_values_are_ignored(make_context):
    ctx = make_context(
        {"src/c.js": 'const apiKey = "your-api-key-here-placeholder";\n'}
    )
    assert await HardcodedSecretRule().run(ctx) == []


async def test_secrets_are_found_outside_env_files(make_context):
    """v2 only scanned .env*, missing the case that actually matters."""
    ctx = make_context({"src/deep/nested/service.ts": 'const t = "ghp_' + "b" * 36 + '";\n'})
    findings = await HardcodedSecretRule().run(ctx)
    assert len(findings) == 1
    assert findings[0].file == "src/deep/nested/service.ts"


async def test_env_not_ignored_is_reported(make_context):
    ctx = make_context({".env": "API_KEY=x\n", ".gitignore": "node_modules\n"})
    findings = await EnvNotIgnoredRule().run(ctx)
    assert len(findings) == 1


async def test_env_covered_by_gitignore_is_fine(make_context):
    ctx = make_context({".env": "API_KEY=x\n", ".gitignore": "node_modules\n.env\n"})
    assert await EnvNotIgnoredRule().run(ctx) == []


# --------------------------------------------------------------------------
# Dependencies
# --------------------------------------------------------------------------

def test_coerce_version_extracts_from_range_specs():
    assert coerce_version("^4.17.21") == "4.17.21"
    assert coerce_version("~1.2.3") == "1.2.3"
    assert coerce_version(">=2.0.0") == "2.0.0"
    assert coerce_version("workspace:*") is None
    assert coerce_version("github:foo/bar") is None


def test_lockfile_v3_versions_are_resolved(make_context):
    ctx = make_context(
        {
            "package.json": {"name": "x", "dependencies": {"lodash": "^4.17.0"}},
            "package-lock.json": {
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "x"},
                    "node_modules/lodash": {"version": "4.17.15"},
                },
            },
        }
    )
    resolved = resolved_versions_from_lockfile(ctx.snapshot)
    assert resolved["lodash"] == "4.17.15"


async def test_react_mismatch_ignores_compatible_patch_versions(make_context):
    """v2 compared spec strings, so ^19.1.1 vs 19.1.2 was a false positive."""
    ctx = make_context(
        {
            "package.json": {
                "name": "x",
                "dependencies": {"react": "^19.1.1", "react-dom": "19.1.2"},
            }
        }
    )
    assert await ReactVersionMismatchRule().run(ctx) == []


async def test_react_mismatch_flags_different_majors(make_context):
    ctx = make_context(
        {
            "package.json": {
                "name": "x",
                "dependencies": {"react": "^19.1.1", "react-dom": "^18.2.0"},
            }
        }
    )
    findings = await ReactVersionMismatchRule().run(ctx)
    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH


@respx.mock
async def test_vulnerability_rule_uses_resolved_version_not_package_name(make_context):
    """The core v2 bug: `react` was flagged purely for being named `react`."""
    respx.post("https://api.osv.dev/v1/querybatch").mock(
        return_value=httpx.Response(200, json={"results": [{}, {}]})
    )

    async with httpx.AsyncClient() as client:
        ctx = make_context(
            {
                "package.json": {
                    "name": "x",
                    "dependencies": {"react": "^19.1.1", "react-dom": "^19.1.1"},
                },
            },
            http=client,
        )
        findings = await KnownVulnerabilityRule().run(ctx)

    assert findings == [], "a non-vulnerable version must produce no finding"

    request = respx.calls.last.request
    import json as _json

    payload = _json.loads(request.content)
    versions = {q["package"]["name"]: q["version"] for q in payload["queries"]}
    assert versions["react"] == "19.1.1", "OSV must be queried with a concrete version"


@respx.mock
async def test_vulnerability_rule_groups_advisories_per_package(make_context):
    """Emitting one finding per CVE produced apparent duplicates in the UI."""
    respx.post("https://api.osv.dev/v1/querybatch").mock(
        return_value=httpx.Response(
            200,
            json={"results": [{"vulns": [{"id": "GHSA-aaa"}, {"id": "GHSA-bbb"}]}]},
        )
    )
    for vuln_id in ("GHSA-aaa", "GHSA-bbb"):
        respx.get(f"https://api.osv.dev/v1/vulns/{vuln_id}").mock(
            return_value=httpx.Response(
                200,
                json={
                    "id": vuln_id,
                    "aliases": [f"CVE-2021-{vuln_id[-3:]}"],
                    "summary": "Prototype pollution",
                    "severity": [{"type": "HIGH"}],
                    "affected": [{"ranges": [{"events": [{"fixed": "4.17.21"}]}]}],
                },
            )
        )

    async with httpx.AsyncClient() as client:
        ctx = make_context(
            {"package.json": {"name": "x", "dependencies": {"lodash": "4.17.15"}}},
            http=client,
        )
        findings = await KnownVulnerabilityRule().run(ctx)

    assert len(findings) == 1, "one finding per package, not per advisory"
    finding = findings[0]
    assert "2 known vulnerabilities" in finding.title
    assert finding.file == "package.json"
    assert finding.line is not None, "must anchor to the manifest line"
    assert len(finding.references) == 2
    assert "4.17.21" in (finding.remediation or "")


@respx.mock
async def test_osv_outage_does_not_fail_the_analysis(make_context):
    respx.post("https://api.osv.dev/v1/querybatch").mock(
        return_value=httpx.Response(503)
    )
    async with httpx.AsyncClient() as client:
        ctx = make_context(
            {"package.json": {"name": "x", "dependencies": {"lodash": "4.17.15"}}},
            http=client,
        )
        assert await KnownVulnerabilityRule().run(ctx) == []


# --------------------------------------------------------------------------
# Quality
# --------------------------------------------------------------------------

async def test_long_file_reports_actual_line_count(make_context):
    ctx = make_context({"src/big.js": "\n".join(f"const v{i} = {i};" for i in range(700))})
    findings = await LongFileRule().run(ctx)
    assert len(findings) == 1
    assert "700" in findings[0].title


async def test_short_file_is_not_reported(make_context):
    ctx = make_context({"src/small.js": "const a = 1;\n"})
    assert await LongFileRule().run(ctx) == []
