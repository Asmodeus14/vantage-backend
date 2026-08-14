"""Secret detection.

v2 only looked inside ``.env*`` files, which is where secrets are *supposed* to
live — the interesting case is a credential committed into source. This scans
every readable text file, anchors each hit to a line, and never echoes the
secret value back in the finding.
"""

from __future__ import annotations

import math
import re
from pathlib import PurePosixPath

from app.analysis.base import RuleContext, register
from app.schemas import Category, Confidence, Finding, Severity

# High-confidence provider tokens: the shape alone is near-conclusive.
PROVIDER_PATTERNS: list[tuple[str, re.Pattern[str], Severity]] = [
    ("AWS access key ID", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), Severity.CRITICAL),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), Severity.CRITICAL),
    ("Slack token", re.compile(r"\bxox[abprs]-[0-9A-Za-z-]{10,}\b"), Severity.CRITICAL),
    ("Stripe secret key", re.compile(r"\bsk_(?:live|test)_[0-9A-Za-z]{16,}\b"), Severity.CRITICAL),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), Severity.HIGH),
    ("OpenAI API key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"), Severity.CRITICAL),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"), Severity.CRITICAL),
    ("JSON Web Token", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), Severity.HIGH),
    ("Postgres connection string", re.compile(r"\bpostgres(?:ql)?(?:\+\w+)?://[^\s:@]+:[^\s:@]+@[^\s/]+"), Severity.CRITICAL),
    ("MongoDB connection string", re.compile(r"\bmongodb(?:\+srv)?://[^\s:@]+:[^\s:@]+@[^\s/]+"), Severity.CRITICAL),
]

# Generic "NAME = value" assignments, confirmed by an entropy check.
ASSIGNMENT = re.compile(
    r"""(?P<key>[A-Za-z0-9_.\-]*(?:secret|token|passwd|password|api[_-]?key|
        access[_-]?key|private[_-]?key|client[_-]?secret|auth)[A-Za-z0-9_.\-]*)
        \s*[:=]\s*
        (?P<quote>["'`]?)(?P<value>[^\s"'`,;)]{12,120})(?P=quote)""",
    re.IGNORECASE | re.VERBOSE,
)

# Files where an unquoted `KEY=value` really is a value, not an expression.
ENV_FILE = re.compile(
    r"(^|/)(\.env[\w.-]*|[\w.-]*\.(?:env|properties|ini|cfg|conf|toml))$",
    re.IGNORECASE,
)

# A right-hand side that is code rather than a literal: a call, an attribute
# lookup, an index, a comparison.
#
# This is what separates `token = "ghp_realsecret..."` from
# `token = secrets.token_urlsafe(32)`. Measured on real repositories, the
# unquoted form was almost entirely the second kind: `self.api_key`,
# `github_token_for(user, settings)`, `get_auth_from_url(proxy)`. Twenty-eight
# findings on `psf/requests`, essentially all of them code.
CODE_EXPRESSION = re.compile(r"[(\[\]{}]|\.\w|==|!=|\+|\bor\b|\band\b|\bif\b")

# Interpolation and masking syntax — the whole value must be one of these.
PLACEHOLDER_TEMPLATE = re.compile(
    r"^(?:x{3,}|\*{3,}|\.{3,}|-{3,}|<[^>]*>|\$\{[^}]*\}|\{\{[^}]*\}\}|"
    r"%[A-Za-z_]+%|null|none|undefined|true|false|localhost|changeme)$",
    re.IGNORECASE,
)

# Words that mark a value as illustrative wherever they appear within it.
# NB: these must be whole-ish tokens. An earlier version listed bare "a" and
# "the" as prefixes, which — anchored with match() and IGNORECASE — silently
# discarded every value beginning with "a", including real AKIA… AWS keys.
PLACEHOLDER_WORD = re.compile(
    r"(?:change[-_]?me|replace[-_]?me|your[-_]?|my[-_]?secret|placeholder|"
    r"example|sample|dummy|fake|insert[-_]?here|todo|xxxxx|"
    # Connection strings in documentation. `postgres://user:pass@host/db` has
    # the exact shape of a real one, which is the point of writing it that way
    # — and reporting a README's own example as a leaked credential is how a
    # security rule loses its reader.
    r"user:pass|username:password|user:password|<user>|<password>|"
    r"user:secret|admin:admin|root:root)",
    re.IGNORECASE,
)

# Credentials published in vendor documentation. Their shape is valid, so the
# provider patterns match them, but they are not leaks.
KNOWN_DOCUMENTATION_VALUES = frozenset(
    {
        "AKIAIOSFODNN7EXAMPLE",
        "AKIAI44QH8DHBEXAMPLE",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    }
)

# Files where a high-entropy string is expected and uninteresting.
NOISY_NAMES = frozenset(
    {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "cargo.lock"}
)
NOISY_SUFFIXES = (".lock", ".snap", ".map", ".svg", ".csv", ".tsv")

ENTROPY_THRESHOLD = 3.6
MAX_FINDINGS = 60


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(value)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def redact(value: str) -> str:
    """Show only enough to locate the value; never the value itself."""
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:3]}{'*' * 8}{value[-2:]} ({len(value)} chars)"


def _is_placeholder(value: str) -> bool:
    """Whether a value is illustrative rather than a real credential."""
    stripped = value.strip()
    if PLACEHOLDER_TEMPLATE.fullmatch(stripped):
        return True
    return bool(PLACEHOLDER_WORD.search(stripped))


# `postgres://user:pass@host/db`. A connection string with placeholder
# credentials in it, which is how every project documents its own DATABASE_URL.
#
# Narrow on purpose. The general placeholder word list is deliberately not
# applied to provider-shaped matches, because it would discard a real key
# containing a word like "test" — but `user:pass@` cannot be a real credential
# pair, so it can be excluded without that risk.
_DOCUMENTED_CREDENTIALS = re.compile(
    r"//(?:user|username|admin|root|<[^>]+>)"
    r":(?:pass|password|secret|admin|root|<[^>]+>)@",
    re.IGNORECASE,
)


def _is_documentation_value(value: str) -> bool:
    stripped = value.strip()
    if stripped in KNOWN_DOCUMENTATION_VALUES:
        return True
    return bool(_DOCUMENTED_CREDENTIALS.search(stripped))


# A certificate or key living under a test-fixture path, which is a thing
# projects commit on purpose to exercise TLS. Narrow by design: it needs *both*
# a fixture-shaped path and a key-shaped artefact, so a real credential that
# merely happens to sit in a tests directory is untouched.
_FIXTURE_PATH = re.compile(
    r"(^|/)(tests?|testing|__tests__|spec|fixtures?|testdata|certs?|"
    r"test[-_]?certs?)(/|$)",
    re.IGNORECASE,
)
_KEY_ARTEFACT = re.compile(r"\.(key|pem|crt|cer|p12|pfx)$", re.IGNORECASE)


def _is_test_fixture_key(path: str, label: str) -> bool:
    if "private key" not in label.lower():
        return False
    return bool(_FIXTURE_PATH.search(path) and _KEY_ARTEFACT.search(path))


@register
class HardcodedSecretRule:
    id = "security/hardcoded-secret"
    name = "Hardcoded secret"
    category = Category.SECRET

    def applies(self, ctx: RuleContext) -> bool:
        return True

    async def run(self, ctx: RuleContext) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[tuple[str, int]] = set()

        for source in ctx.snapshot.files:
            if len(findings) >= MAX_FINDINGS:
                break
            name = source.name.lower()
            if name in NOISY_NAMES or name.endswith(NOISY_SUFFIXES):
                continue
            # A committed example file is documentation, not a leak.
            if name.endswith((".example", ".sample")) or ".example." in name:
                continue

            lines = source.lines()
            if not lines:
                continue

            for number, line in enumerate(lines, start=1):
                if len(line) > 500:  # minified or generated
                    continue

                matched = False
                for label, pattern, severity in PROVIDER_PATTERNS:
                    match = pattern.search(line)
                    if not match:
                        continue
                    value = match.group(0)
                    # A provider-shaped token is conclusive on its own, so only
                    # an explicit documentation value is excluded here. Applying
                    # the general placeholder heuristic would discard real keys
                    # that happen to contain a word like "test".
                    if _is_documentation_value(value):
                        continue
                    key = (source.path, number)
                    if key in seen:
                        continue
                    seen.add(key)
                    # A TLS key under a test-fixture path is a test certificate.
                    #
                    # Measured on `psf/requests`: four private keys in
                    # `tests/certs/` — expired CA, server, client — scored the
                    # project an F, because a HIGH-confidence critical caps the
                    # grade. Committing throwaway certificates to exercise TLS
                    # is what every HTTP library does, so that reading is wrong
                    # in the way that matters: it is confident, severe, and
                    # about a file the maintainers put there deliberately.
                    #
                    # Still reported, and still critical if it turns out to be
                    # real — only the confidence drops, which keeps it out of
                    # the default view and out of the score cap. A credential
                    # that is genuinely leaked in a test directory is a real
                    # leak, so dropping it entirely would be the worse error.
                    confidence = (
                        Confidence.MEDIUM
                        if _is_test_fixture_key(source.path, label)
                        else Confidence.HIGH
                    )
                    findings.append(
                        self._finding(ctx, source.path, number, label, value, severity,
                                      confidence)
                    )
                    matched = True
                    break

                if matched:
                    continue

                assignment = ASSIGNMENT.search(line)
                if not assignment:
                    continue
                value = assignment.group("value")

                # A hardcoded credential is a *literal*. Without a quote this
                # matched any expression assigned to a credential-shaped name,
                # which is how `secrets.token_urlsafe(32)` and `self.api_key`
                # were reported as secrets. Env-style files are the real
                # exception: there `KEY=value` is genuinely a value.
                quoted = bool(assignment.group("quote"))
                if not quoted and not ENV_FILE.search(source.path):
                    continue
                # Even quoted, a call inside an f-string is still code.
                if CODE_EXPRESSION.search(value):
                    continue

                if _is_placeholder(value) or shannon_entropy(value) < ENTROPY_THRESHOLD:
                    continue
                key = (source.path, number)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(
                    self._finding(
                        ctx,
                        source.path,
                        number,
                        f"credential assigned to '{assignment.group('key')}'",
                        value,
                        Severity.HIGH,
                        # Entropy heuristics do produce false positives; say so
                        # rather than presenting a guess as a certainty.
                        Confidence.MEDIUM,
                    )
                )

        return findings

    def _finding(
        self,
        ctx: RuleContext,
        path: str,
        line: int,
        label: str,
        value: str,
        severity: Severity,
        confidence: Confidence,
    ) -> Finding:
        return ctx.finding(
            rule_id=self.id,
            # The credential itself is the identity, so it survives being moved
            # within the file — and two different keys in one file stay two
            # findings. `redact` is used rather than the raw value: it is
            # already shown in the description, so the fingerprint reveals
            # nothing that is not public. A rotated-but-still-committed value
            # therefore reads as resolved-plus-new, which is the right emphasis.
            key=f"{path}|{label}|{redact(value)}",
            title=f"Possible {label} committed to the repository",
            description=(
                f"A value matching {label} appears at {path}:{line}. "
                f"Detected value: {redact(value)}. Anything committed to git "
                f"remains recoverable from history even after being deleted."
            ),
            category=Category.SECRET,
            severity=severity,
            confidence=confidence,
            file=path,
            line=line,
            remediation=(
                "Revoke and rotate this credential, then load it from an "
                "environment variable. Removing the line is not sufficient — "
                "the value stays in git history until it is purged."
            ),
            references=["https://docs.github.com/code-security/secret-scanning"],
        )


@register
class EnvNotIgnoredRule:
    id = "security/env-not-ignored"
    name = ".env is not gitignored"
    category = Category.SECRET

    def applies(self, ctx: RuleContext) -> bool:
        return True

    async def run(self, ctx: RuleContext) -> list[Finding]:
        env_files = [
            f
            for f in ctx.snapshot.files
            if f.name.startswith(".env")
            and not f.name.endswith((".example", ".sample", ".template"))
        ]
        if not env_files:
            return []

        ignore_files = ctx.snapshot.by_name(".gitignore")
        ignored_patterns: set[str] = set()
        for ignore in ignore_files:
            for line in ignore.lines():
                stripped = line.strip()
                if stripped and not stripped.startswith("#"):
                    ignored_patterns.add(stripped.rstrip("/"))

        findings: list[Finding] = []
        for env_file in env_files:
            name = PurePosixPath(env_file.path).name
            covered = any(
                pattern in {name, ".env", ".env*", "*.env"} or
                (pattern.endswith("*") and name.startswith(pattern[:-1]))
                for pattern in ignored_patterns
            )
            if covered:
                continue
            findings.append(
                ctx.finding(
                    rule_id=self.id,
                    title=f"{name} is present but not covered by .gitignore",
                    description=(
                        f"{env_file.path} exists in the analysed tree and no "
                        f".gitignore rule appears to exclude it. Environment "
                        f"files routinely hold credentials."
                    ),
                    category=Category.SECRET,
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    file=env_file.path,
                    line=1,
                    remediation=(
                        "Add `.env` to .gitignore, commit a `.env.example` with "
                        "placeholder values instead, and rotate anything that "
                        "was already pushed."
                    ),
                )
            )
        return findings
