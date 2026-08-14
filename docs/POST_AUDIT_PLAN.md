# Post-audit plan

Written after reading both repositories end to end, not from the audit summary.
Where the audit and the code disagree, this document follows the code.

---

## 1. Current strengths

These are load-bearing and must not be rewritten.

**The rule framework is better than the rule set.** `RuleContext.finding()`
(`app/analysis/base.py`) centralises snippet extraction, the stable `id`, and
the cross-report `fingerprint`. The `key` parameter — the rule's own answer to
"which problem is this, as distinct from the others I report" — is a genuinely
good piece of design. Its docstring reasons through four separate cases,
including one it accepts as imperfect and documents rather than papering over.

**`applies(ctx)` gating.** Every rule declares whether it is meaningful for the
project at hand, computed once into `ProjectFacts`. A Python repository is never
told it is missing ESLint. Most scanners get this wrong.

**`strip_comments_and_strings()`.** Rules scan code with comments and string
literals blanked, preserving line structure. This single helper removes an
entire class of false positive that regex scanners normally ship with.

**The secrets module already does the hard part.** `app/analysis/rules/secrets.py`
carries provider patterns, a Shannon-entropy gate, placeholder/template
detection, and `CODE_EXPRESSION` — which separates `token = "ghp_real..."` from
`token = secrets.token_urlsafe(32)`. Its comment records the measurement that
motivated it: twenty-eight findings on `psf/requests`, essentially all of them
code rather than credentials. That is real false-positive engineering.

**`Confidence` and `Category` already exist** in `app/schemas.py`. The audit
recommended adding them. They are there and unused.

**Diffing, fingerprints, and suppressions all work** and are covered by 314 and
418 lines of tests respectively.

**Security controls** — archive containment, path traversal, prompt-injection
fencing, ownership checks — are tested (`test_archive_safety.py`,
`test_prompts.py`, `test_auth.py`). Nothing here touches them.

---

## 2. Confirmed weaknesses

Verified by reading, with counts.

### 2.1 The rule set is thin, and thinnest exactly where it matters

**21 rules total.** By prefix:

| prefix | count | rules |
|---|---|---|
| `config/` | 5 | no-ci, no-linter, no-readme, no-tests, ts-not-strict |
| `quality/` | 4 | deep-nesting, long-file, long-function, todo-markers |
| `python/` | 4 | bare-except, mutable-default-argument, subprocess-shell, unsafe-deserialisation |
| `dep/` | 3 | known-vulnerability, no-lockfile, react-dom-mismatch |
| `react/` | 3 | array-index-key, dangerously-set-inner-html, missing-list-key |
| **`security/`** | **2** | env-not-ignored, hardcoded-secret |

Two security rules, one of which is "you did not gitignore `.env`". There is no
SQL injection, command injection in JS, path traversal, SSRF, `eval`/`exec`,
XSS sink, weak hashing, insecure randomness, permissive CORS, or JWT rule.

This — not the architecture — is why the audit concluded the findings do not
justify the UI. It is the whole of P0.

### 2.2 Nothing is prioritised

`findings-panel.tsx` sorts by `compareSeverity` then filename. `Confidence`
exists on every finding and is used by nothing: not the ordering, not the
filters, not the UI. A `MEDIUM`-confidence guess outranks a `HIGH`-confidence
certainty if its severity is one step higher.

### 2.3 Structural metrics compete with real findings

`quality/long-file`, `quality/deep-nesting` and `quality/todo-markers` are
emitted into the same list as `security/hardcoded-secret`. On a large repository
these dominate by count. The audit's complaint — thirty "file too long" warnings
before a real security issue — is reproducible.

`Category` has no value that means "this is a measurement, not a defect".

### 2.4 No SARIF

Nothing in either repository mentions it. Findings cannot leave the product.

### 2.5 No PR workflow

`app/ingest/github.py` is read-only: `fetch_repository`, `parse_repository_url`,
credential building. Auth is a user OAuth token with user-granted scopes. There
is no GitHub App, no check-run, no PR context, no installation token path.

### 2.6 Per-finding history is report-level only

`FindingDelta` lives on the report and lists fingerprints. An individual
`Finding` has no `first_seen`, `last_seen`, or `status`, so the UI cannot say
"this has been here for four scans" without recomputing across reports.

---

## 3. Planned changes

Ordered by the brief's priority, sliced so each lands complete.

### Slice 1 — P0: security and correctness rules

Add rules only where a **high-confidence, low-false-positive** signal is
actually available from single-file analysis. Each new rule ships with positive
*and* negative tests in the same commit.

Target set (JS/TS and Python, the two languages the engine actually understands):

- `security/sql-injection` — string-concatenated SQL reaching a query sink
- `security/command-injection` — `child_process.exec` / `os.system` with an
  interpolated argument
- `security/code-injection` — `eval`, `new Function`, `exec`, `compile`
- `security/path-traversal` — request-derived value reaching `fs`/`open`
- `security/ssrf` — request-derived value reaching an HTTP client
- `security/weak-hash` — MD5/SHA1 used for passwords or signatures
- `security/insecure-random` — `Math.random()` / `random` for tokens/secrets
- `security/permissive-cors` — `Access-Control-Allow-Origin: *` with credentials
- `security/jwt-unverified` — `jwt.decode` without verification / `verify=False`
- `security/unsafe-deserialisation` (JS) — `node-serialize`, `vm.runInNewContext`

**The discipline that makes this different from "add 100 mediocre rules":** a
rule that cannot distinguish a literal from a variable does not ship. Where
taint cannot be established from one file, the finding is emitted at
`Confidence.MEDIUM` and is therefore not surfaced by default (see slice 2).

### Slice 2 — P0: prioritisation and the metric split

- Add `Category.SECRET` and `Category.METRIC`.
- Move `quality/long-file`, `quality/deep-nesting`, `quality/todo-markers` to
  `METRIC`; move secret findings to `SECRET`.
- Add a `priority` derived on the backend from severity × confidence ×
  category weight, so the ordering is computed once and the UI does not
  reimplement it.
- Default the findings list to high-confidence, non-metric findings, with the
  hidden count visible and one click away. Never silently drop anything.

### Slice 3 — P1: actionable findings

Every new rule must answer what/why/where/how. `remediation` is already on the
model and already rendered; the gap is that rules do not populate it richly.
Evidence comes from the existing snippet machinery.

### Slice 4 — P2: SARIF export

`GET /api/reports/{id}/sarif` returning SARIF 2.1.0, validated against the
schema in tests. Downloadable from the report page.

### Slice 5 — P1: GitHub PR workflow

Deliberately last among the implementation slices and explicitly scoped to a
vertical slice: analyse a PR head, compare against its base, post **one**
consolidated check-run. Requires a GitHub App, which is new infrastructure and
new secrets — see migration.

---

## 4. Architectural impact

Small, by intent.

- `Category` gains two members. Pydantic validates old rows against the new
  enum only if existing values remain, which they do — nothing is renamed.
- `Finding` gains `priority: int`, defaulted, so old payloads validate.
- The rule registry, `applies()` gating, `RuleContext.finding()` and the
  fingerprint scheme are unchanged. New rules are new modules registered in
  `app/analysis/rules/__init__.py` — the one step that is easy to forget and
  silently does nothing.
- No new services, no queue, no cache layer.

---

## 5. Migration requirements

**None for slices 1–4.** `payload` is JSONB and every added field is defaulted,
which is the same backward-compatibility path already used for
`files_with_findings` and `delta`. Reports written before this change validate
and render.

The one real constraint: **`fingerprint` must not change for existing rules.**
Re-categorising a rule changes `category`, not `rule_id` or `key`, so
fingerprints are stable and no historical report will show a wave of spurious
"resolved" findings. This is verified by a test, not by inspection.

Slice 5 needs a `github_installations` table and two new secrets. Deferred until
the slice is actually started.

---

## 6. Test requirements

Non-negotiable, per the brief:

- Every new rule: at least one positive and one negative case. The negative
  cases are the point — they are what stops this becoming a noise generator.
- A regression test asserting fingerprints are unchanged for the rules being
  re-categorised.
- Prioritisation: ordering is asserted directly, including that a
  high-confidence medium outranks a low-confidence high.
- SARIF: schema-validated, not merely shape-asserted.
- Existing security tests must pass untouched.

---

## 7. What this plan deliberately does not do

- No rewrite of the rule engine. It is better than the rules running on it.
- No language expansion. JS/TS and Python are what the engine actually
  understands; adding a third would produce superficial coverage, which the
  brief explicitly rejects. Positioning is corrected instead (Option B).
- No Redis, queue, or worker infrastructure.
- No per-finding `first_seen`/`last_seen` yet — it is derivable from the
  existing report history, and adding columns before the UI needs them is
  speculative.
