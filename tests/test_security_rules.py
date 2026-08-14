"""The security rule pack.

Every rule is tested against code that should fire it *and* against code that
should not. The negative cases are the point: these rules exist to be believed,
and a security category that cries wolf is one people filter out permanently.

Where a rule deliberately reports at MEDIUM confidence rather than staying
silent, that grading is asserted too — "we found evidence but cannot prove
reachability" is a distinct answer from both "vulnerable" and "fine", and the
report surfaces the three differently.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.analysis.base import ProjectFacts, RuleContext
from app.analysis.rules.security import (
    CodeInjectionRule,
    CommandInjectionRule,
    InsecureRandomRule,
    JwtUnverifiedRule,
    PathTraversalRule,
    PermissiveCorsRule,
    SqlInjectionRule,
    SsrfRule,
    WeakHashRule,
    is_built,
    is_test_path,
    is_vendored,
    tainted,
)
from app.config import Settings
from app.ingest.snapshot import Snapshot
from app.schemas import Category, Confidence, Severity


def build(tmp_path: Path, files: dict[str, str]) -> RuleContext:
    for name, content in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, newline="")
    snapshot = Snapshot.build(tmp_path)
    facts = ProjectFacts(
        languages={"python", "javascript", "typescript"},
        package_json={"name": "x"},
        package_managers={"npm"},
    )
    return RuleContext(snapshot=snapshot, facts=facts, settings=Settings())


async def run(rule, tmp_path: Path, files: dict[str, str]):
    return await rule.run(build(tmp_path, files))


# --------------------------------------------------------------------------
# The taint-lite primitives everything else is built on
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "expr",
    [
        'q = `SELECT * FROM t WHERE id = ${id}`',
        'q = "SELECT * FROM t WHERE id = " + id',
        'q = f"SELECT * FROM t WHERE id = {id}"',
        'q = "SELECT * FROM t WHERE id = %s" % id',
        'q = "SELECT {}".format(id)',
    ],
)
def test_is_built_recognises_every_interpolation_form(expr):
    assert is_built(expr) is True


def test_is_built_rejects_a_plain_literal():
    """A constant statement is not a finding however dangerous the sink."""
    assert is_built('db.query("SELECT * FROM users")') is False


@pytest.mark.parametrize(
    "expr",
    [
        "req.query.id",
        "req.body.name",
        "request.args.get('q')",
        "request.GET['q']",
        "ctx.query.page",
        "searchParams.get('id')",
        "event.queryStringParameters",
    ],
)
def test_tainted_recognises_framework_request_accessors(expr):
    assert tainted(expr) is True


def test_tainted_does_not_fire_on_an_ordinary_variable():
    """The list is closed on purpose — being right when it fires is the
    difference between HIGH and MEDIUM confidence downstream."""
    assert tainted("const id = computeId(user)") is False


@pytest.mark.parametrize(
    "path",
    ["tests/test_x.py", "src/foo.test.ts", "__tests__/a.js", "spec/b.js", "app/x_test.py"],
)
def test_test_files_are_excluded(path):
    assert is_test_path(path) is True


def test_source_files_are_not_mistaken_for_tests():
    assert is_test_path("src/latest/contest.ts") is False


# --------------------------------------------------------------------------
# SQL injection
# --------------------------------------------------------------------------

async def test_sql_injection_is_critical_when_the_value_comes_from_the_request(tmp_path):
    findings = await run(
        SqlInjectionRule(),
        tmp_path,
        {
            "api/users.js": """
export async function handler(req, res) {
  const rows = await db.query(`SELECT * FROM users WHERE id = ${req.query.id}`);
  res.json(rows);
}
""",
        },
    )
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity is Severity.CRITICAL
    assert finding.confidence is Confidence.HIGH
    assert finding.category is Category.SECURITY
    assert finding.file == "api/users.js"
    assert finding.remediation and "bound parameter" in finding.remediation
    # The description must say *why*, not merely name the class.
    assert "structure" in finding.description


async def test_sql_injection_survives_the_assign_then_execute_shape(tmp_path):
    """The most common real-world form, and the one that got away.

    Found by scanning a sample app rather than by unit test: the statement is
    built into a variable on one line and executed on the next. The SQL keyword
    lives inside a template literal — blanked by `iter_code_lines` — and the
    sink is outside a forward-only window, so the original rule saw neither.
    """
    findings = await run(
        SqlInjectionRule(),
        tmp_path,
        {
            "h.js": (
                "const sql =\n"
                "  `SELECT id, email FROM users WHERE id = ${req.query.id}`;\n"
                "const rows = await db.query(sql);\n"
            )
        },
    )
    assert len(findings) == 1
    assert findings[0].confidence is Confidence.HIGH


async def test_sql_taint_is_not_borrowed_from_a_neighbouring_line(tmp_path):
    """Grading reads the statement, not the window.

    The window has to be wide enough to find the sink on an adjacent line,
    which means it also spans unrelated code. If confidence were graded over
    the whole window, an unrelated `req.query` three lines up would promote
    unproven evidence to a CRITICAL finding.
    """
    findings = await run(
        SqlInjectionRule(),
        tmp_path,
        {
            "h.js": (
                "const name = req.query.name;\n"
                "log(name);\n"
                "\n"
                "const sql = `SELECT * FROM audit WHERE actor = ${INTERNAL_ACTOR}`;\n"
                "await db.query(sql);\n"
            )
        },
    )
    assert len(findings) == 1
    assert findings[0].confidence is Confidence.MEDIUM
    assert findings[0].severity is Severity.MEDIUM


async def test_sql_injection_downgrades_when_the_source_is_unknown(tmp_path):
    """Real evidence, unproven reachability. Reported, but not as a
    vulnerability — this is the grading that keeps the category trustworthy."""
    findings = await run(
        SqlInjectionRule(),
        tmp_path,
        {"db.py": 'cur.execute("SELECT * FROM t WHERE id = %s" % internal_id)\n'},
    )
    assert len(findings) == 1
    assert findings[0].confidence is Confidence.MEDIUM
    assert findings[0].severity is Severity.MEDIUM


async def test_parameterised_query_is_not_flagged(tmp_path):
    findings = await run(
        SqlInjectionRule(),
        tmp_path,
        {
            "db.py": 'cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))\n',
            "q.js": 'db.query("SELECT * FROM users WHERE id = $1", [id]);\n',
        },
    )
    assert findings == []


async def test_constant_sql_is_not_flagged(tmp_path):
    findings = await run(
        SqlInjectionRule(),
        tmp_path,
        {"db.js": 'const all = await db.query("SELECT id, name FROM users");\n'},
    )
    assert findings == []


# --------------------------------------------------------------------------
# Command injection
# --------------------------------------------------------------------------

async def test_command_injection_fires_on_interpolated_exec(tmp_path):
    findings = await run(
        CommandInjectionRule(),
        tmp_path,
        {"git.js": "exec(`git show ${req.params.ref}`, cb);\n"},
    )
    assert len(findings) == 1
    assert findings[0].confidence is Confidence.HIGH
    assert findings[0].severity is Severity.CRITICAL
    assert "execFile" in (findings[0].remediation or "")


async def test_execfile_with_an_argument_array_is_not_flagged(tmp_path):
    """No shell means interpolation is not shell syntax. This is the fix the
    rule recommends, so flagging it would be actively misleading."""
    findings = await run(
        CommandInjectionRule(),
        tmp_path,
        {"git.js": "execFile('git', ['show', req.params.ref], cb);\n"},
    )
    assert findings == []


async def test_spawn_with_shell_true_is_still_flagged(tmp_path):
    findings = await run(
        CommandInjectionRule(),
        tmp_path,
        {"g.js": "spawn(`git show ${req.params.ref}`, { shell: true });\n"},
    )
    assert len(findings) == 1


async def test_constant_command_is_not_flagged(tmp_path):
    findings = await run(
        CommandInjectionRule(),
        tmp_path,
        {"build.js": "exec('npm run build', cb);\n"},
    )
    assert findings == []


# --------------------------------------------------------------------------
# Code injection
# --------------------------------------------------------------------------

async def test_eval_of_request_data_is_critical(tmp_path):
    findings = await run(
        CodeInjectionRule(),
        tmp_path,
        {"calc.js": "const out = eval(`compute(${req.body.expr})`);\n"},
    )
    assert len(findings) == 1
    assert findings[0].severity is Severity.CRITICAL
    assert findings[0].confidence is Confidence.HIGH


async def test_eval_of_a_constructed_but_untraced_string_is_downgraded(tmp_path):
    findings = await run(
        CodeInjectionRule(),
        tmp_path,
        {"m.py": 'exec("value = %s" % computed)\n'},
    )
    assert len(findings) == 1
    assert findings[0].confidence is Confidence.MEDIUM


async def test_eval_of_a_literal_is_not_reported_by_this_rule(tmp_path):
    findings = await run(
        CodeInjectionRule(),
        tmp_path,
        {"m.py": 'exec("import os")\n'},
    )
    assert findings == []


# --------------------------------------------------------------------------
# Path traversal
# --------------------------------------------------------------------------

async def test_path_traversal_fires_on_unconstrained_request_path(tmp_path):
    findings = await run(
        PathTraversalRule(),
        tmp_path,
        {"files.js": "fs.readFile(path.join(ROOT, req.query.name), cb);\n"},
    )
    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH
    assert "etc/passwd" in findings[0].description


async def test_containment_check_clears_the_traversal_finding(tmp_path):
    findings = await run(
        PathTraversalRule(),
        tmp_path,
        {
            "files.js": (
                "const full = path.resolve(ROOT, req.query.name);\n"
                "if (!full.startsWith(ROOT)) throw new Error('nope');\n"
                "fs.readFile(full, cb);\n"
            )
        },
    )
    assert findings == []


async def test_filesystem_read_of_a_constant_is_not_flagged(tmp_path):
    findings = await run(
        PathTraversalRule(),
        tmp_path,
        {"cfg.js": "fs.readFileSync('./config.json');\n"},
    )
    assert findings == []


# --------------------------------------------------------------------------
# SSRF
# --------------------------------------------------------------------------

async def test_ssrf_fires_when_the_caller_chooses_the_host(tmp_path):
    findings = await run(
        SsrfRule(),
        tmp_path,
        {"proxy.py": "resp = requests.get(request.args['url'])\n"},
    )
    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH
    assert "metadata" in findings[0].description


async def test_outbound_request_to_a_fixed_url_is_not_flagged(tmp_path):
    findings = await run(
        SsrfRule(),
        tmp_path,
        {"api.js": "const r = await fetch('https://api.example.com/v1/status');\n"},
    )
    assert findings == []


# --------------------------------------------------------------------------
# Weak hashing
# --------------------------------------------------------------------------

async def test_md5_for_passwords_is_flagged(tmp_path):
    findings = await run(
        WeakHashRule(),
        tmp_path,
        {"auth.py": "password_hash = hashlib.md5(password.encode()).hexdigest()\n"},
    )
    assert len(findings) == 1
    assert "MD5" in findings[0].title
    assert "argon2" in (findings[0].remediation or "")


async def test_md5_in_javascript_is_flagged_when_the_purpose_is_security(tmp_path):
    """Guards the negative test below from being vacuous.

    The algorithm name is inside a string literal, and the first version of
    this rule scanned comment/string-blanked source — so `createHash('md5')`
    read as `createHash('')` and never matched. The cache-key test passed for
    the wrong reason: not because the purpose check cleared it, but because
    nothing matched at all. This asserts the JS branch can fire.
    """
    findings = await run(
        WeakHashRule(),
        tmp_path,
        {"auth.js": "const passwordHash = createHash('sha1').update(pw).digest('hex');\n"},
    )
    assert len(findings) == 1
    assert "SHA1" in findings[0].title


async def test_md5_as_a_cache_key_is_not_flagged(tmp_path):
    """Hashing is only weak relative to its purpose. Flagging ETags is how a
    rule earns a permanent filter."""
    findings = await run(
        WeakHashRule(),
        tmp_path,
        {"cache.js": "const etag = createHash('md5').update(body).digest('hex');\n"},
    )
    assert findings == []


# --------------------------------------------------------------------------
# Insecure randomness
# --------------------------------------------------------------------------

async def test_math_random_for_a_token_is_flagged(tmp_path):
    findings = await run(
        InsecureRandomRule(),
        tmp_path,
        {"session.js": "const sessionToken = Math.random().toString(36);\n"},
    )
    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH
    assert "randomBytes" in (findings[0].remediation or "")


async def test_math_random_for_something_harmless_is_not_flagged(tmp_path):
    findings = await run(
        InsecureRandomRule(),
        tmp_path,
        {"ui.js": "const jitter = Math.random() * 100;\n"},
    )
    assert findings == []


# --------------------------------------------------------------------------
# CORS
# --------------------------------------------------------------------------

async def test_wildcard_cors_with_credentials_is_flagged(tmp_path):
    findings = await run(
        PermissiveCorsRule(),
        tmp_path,
        {
            "server.js": (
                "app.use(cors({\n"
                "  origin: '*',\n"
                "  credentials: true,\n"
                "}));\n"
            )
        },
    )
    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH


async def test_wildcard_cors_without_credentials_is_a_deliberate_public_api(tmp_path):
    findings = await run(
        PermissiveCorsRule(),
        tmp_path,
        {"server.js": "app.use(cors({ origin: '*' }));\n"},
    )
    assert findings == []


# --------------------------------------------------------------------------
# JWT
# --------------------------------------------------------------------------

async def test_unverified_jwt_decode_is_critical(tmp_path):
    findings = await run(
        JwtUnverifiedRule(),
        tmp_path,
        {"auth.js": "const claims = jwt.decode(token);\nreq.user = claims.sub;\n"},
    )
    assert len(findings) == 1
    assert findings[0].severity is Severity.CRITICAL
    assert "base64" in findings[0].description


async def test_verify_false_is_flagged(tmp_path):
    findings = await run(
        JwtUnverifiedRule(),
        tmp_path,
        {"auth.py": "claims = jwt.decode(token, options={'verify_signature': False})\n"},
    )
    assert len(findings) == 1


async def test_pyjwt_decode_with_an_algorithm_list_is_verification(tmp_path):
    """`jwt.decode(token, key, algorithms=[...])` in PyJWT *does* verify. This
    is the single most likely false positive for this rule."""
    findings = await run(
        JwtUnverifiedRule(),
        tmp_path,
        {"auth.py": "claims = jwt.decode(token, key, algorithms=['HS256'])\n"},
    )
    assert findings == []


# --------------------------------------------------------------------------
# Cross-cutting guarantees
# --------------------------------------------------------------------------

async def test_no_security_rule_reports_inside_test_files(tmp_path):
    """A test suite exercises dangerous functions deliberately. The Python
    pack learned this on `psf/requests`; the same applies to both ecosystems."""
    files = {
        "__tests__/injection.test.js": "exec(`rm -rf ${req.query.path}`);\n",
        "tests/test_sql.py": 'cur.execute("SELECT * FROM t WHERE id = %s" % req.args["id"])\n',
    }
    for rule in (SqlInjectionRule(), CommandInjectionRule(), CodeInjectionRule()):
        assert await run(rule, tmp_path, files) == []


async def test_every_finding_carries_remediation_and_a_reference(tmp_path):
    """The brief's bar: what is wrong, why it matters, where, and how to fix
    it. A finding without remediation fails that on the last two counts."""
    findings = await run(
        SqlInjectionRule(),
        tmp_path,
        {"a.js": "db.query(`SELECT * FROM t WHERE id = ${req.query.id}`);\n"},
    )
    assert findings
    for finding in findings:
        assert finding.remediation
        assert finding.references
        assert finding.fingerprint
        assert finding.description != finding.title


# --------------------------------------------------------------------------
# False positives found by scanning a corpus of real applications
# --------------------------------------------------------------------------

def test_urlopen_is_not_a_request_source():
    """`urllib.request.urlopen` contains the substring `request.url`.

    Without a trailing word boundary the taint check matched it, and
    `flask_security`'s HaveIBeenPwned lookup — a constant URL with a hash
    appended — was reported as an SSRF. Found by scanning real applications,
    not by a test.
    """
    assert tainted("with urllib.request.urlopen(req) as f:") is False
    assert tainted("req = urllib.request.Request(URL + sha1[:5])") is False
    # Still catches the accessor it was written for.
    assert tainted("const target = req.url") is True
    assert tainted("fetch(request.url)") is True


async def test_verify_false_outside_jwt_is_not_a_jwt_finding(tmp_path):
    """`verify=False` is a keyword argument shared by half of Python.

    `EmailValidation(verify=False)` in `flask_security` was reported as an
    unverified JWT. `requests.get(url, verify=False)` would have been too —
    that one is a real problem, but a different one, and mislabelling it is how
    a rule teaches people to distrust it.
    """
    findings = await run(
        JwtUnverifiedRule(),
        tmp_path,
        {
            "forms.py": "EmailValidation(verify=False)\n",
            "client.py": "resp = requests.get(url, verify=False)\n",
        },
    )
    assert findings == []


async def test_verify_false_with_jwt_in_view_is_still_caught(tmp_path):
    findings = await run(
        JwtUnverifiedRule(),
        tmp_path,
        {"auth.py": "import jwt\nclaims = jwt.decode(token, verify=False)\n"},
    )
    assert len(findings) == 1


@pytest.mark.parametrize(
    "path",
    [
        "static/rest_framework/docs/js/highlight.pack.js",
        "vendor/jquery.js",
        "node_modules/lib/index.js",
        "dist/app.bundle.js",
        "public/js/analytics.min.js",
        "src/vendor/chart.js",
    ],
)
def test_vendored_and_built_files_are_out_of_scope(path):
    """Not ours to fix, and usually minified.

    `payatu/Tiredful-API` reported a SQL injection in a vendored syntax
    highlighter, and it led the report summary. Editing a vendored bundle is
    not a fix — the actionable version of that problem is a dependency finding
    about the package.
    """
    assert is_vendored(path) is True


@pytest.mark.parametrize(
    "path",
    ["src/api/users.js", "app/routes/static_pages.py", "lib/distance.ts", "app/public_api.py"],
)
def test_ordinary_source_is_not_mistaken_for_vendored(path):
    """The markers are path segments and suffixes, not substrings — `distance`
    must not match `dist`, nor `public_api` match `public`."""
    assert is_vendored(path) is False


async def test_a_vulnerability_in_a_vendored_bundle_is_not_reported(tmp_path):
    findings = await run(
        SqlInjectionRule(),
        tmp_path,
        {
            "static/js/highlight.pack.js": (
                "const sql = `SELECT * FROM t WHERE id = ${req.query.id}`;\n"
                "db.query(sql);\n"
            ),
            "src/api/users.js": (
                "const sql = `SELECT * FROM t WHERE id = ${req.query.id}`;\n"
                "db.query(sql);\n"
            ),
        },
    )
    assert [f.file for f in findings] == ["src/api/users.js"]


async def test_taint_assigned_a_few_lines_above_is_followed(tmp_path):
    """The commonest real shape, missed until a corpus scan found it.

    `payatu/Tiredful-API` — deliberately vulnerable — assigns
    `month_requested = request.data['month']` and interpolates it into a raw
    query three lines later. Grading on the statement alone reported it at
    MEDIUM, so it did not cap the score of a knowingly-vulnerable app.
    """
    findings = await run(
        SqlInjectionRule(),
        tmp_path,
        {
            "views.py": (
                "def get_activity(request):\n"
                "    month_requested = request.data['month']\n"
                "    try:\n"
                "        rows = Tracker.objects.raw(\n"
                "            'Select * from health_tracker where month=%s' % month_requested)\n"
            )
        },
    )
    assert len(findings) == 1
    assert findings[0].confidence is Confidence.HIGH
    assert findings[0].severity is Severity.CRITICAL


async def test_an_unrelated_tainted_variable_does_not_escalate(tmp_path):
    """The name has to match.

    This is why the fix is a narrower question rather than a wider window: a
    `req.query` on a neighbouring line, assigned to a variable this statement
    never uses, must still leave the finding at MEDIUM.
    """
    findings = await run(
        SqlInjectionRule(),
        tmp_path,
        {
            "h.js": (
                "const name = req.query.name;\n"
                "log(name);\n"
                "const sql = `SELECT * FROM audit WHERE actor = ${INTERNAL_ACTOR}`;\n"
                "await db.query(sql);\n"
            )
        },
    )
    assert len(findings) == 1
    assert findings[0].confidence is Confidence.MEDIUM


async def test_a_locally_assigned_constant_does_not_escalate(tmp_path):
    findings = await run(
        SqlInjectionRule(),
        tmp_path,
        {
            "h.js": (
                "const actor = 'system';\n"
                "const sql = `SELECT * FROM audit WHERE actor = ${actor}`;\n"
                "await db.query(sql);\n"
            )
        },
    )
    assert len(findings) == 1
    assert findings[0].confidence is Confidence.MEDIUM
