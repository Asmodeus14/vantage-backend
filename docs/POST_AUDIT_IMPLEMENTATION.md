# Post-audit implementation

What shipped, why, and what did not. Companion to `POST_AUDIT_PLAN.md`, which
was written first and is unedited — the two disagree in places, and where they
do, this one is the record of what actually happened.

---

## What the auditors found

That the engineering was strong and the product was thin: *"a promising scanner
with memory whose detection depth and workflow integration are not yet strong
enough to replace tools developers already use."* The headline instruction was
**make the findings worth the UI**.

Reading both repositories first changed the diagnosis in a way worth recording,
because three of the recommendations were already implemented:

- **`Confidence` and `Category` already existed** on every finding. The
  recommendation was to add them. They were there, and used by nothing.
- **The fingerprint design was already good** — `RuleContext.finding()`'s `key`
  parameter reasons through four cases in its docstring, including one it
  accepts as imperfect and documents rather than papering over.
- **The secrets module already had measured false-positive controls**, with a
  comment recording the measurement that motivated them: 28 findings on
  `psf/requests`, essentially all of them code rather than credentials.

The real gap was narrower and more specific than "detection depth": **21 rules,
of which two were `security/`** — one of them "you did not gitignore `.env`" —
and **nothing anywhere used confidence to decide what to show first**.

---

## What we changed

### 1. Nine security rules with taint-lite grading

`security/` went from 2 rules to 11; the engine from 21 to 30. SQL injection,
command injection, code injection, path traversal, SSRF, weak hashing, insecure
randomness, permissive CORS, unverified JWT — JS/TS and Python.

**Why it matters:** this is the whole of "make the findings worth the UI". A
scanner that cannot find injection is not a scanner anyone keeps.

**How it avoids becoming noise.** Every rule answers two questions separately:
is a dangerous sink present, and does a request-derived value reach it. A sink
alone is `MEDIUM` — real evidence, unproven reachability, and *not surfaced by
default*. A sink reached from a closed list of framework request accessors is
`HIGH`. A plain literal is not a finding at all.

Measured rather than asserted:

| | |
|---|---|
| Sample vulnerable app (Express + Flask) | **11/11** expected findings |
| `vantage-backend`, 75 source files | **0** findings |
| `vantage-frontend`, 94 source files | **0** findings |

Both real repositories do auth, subprocess execution, outbound HTTP and crypto
— where a naive rule set generates its noise.

### 2. Prioritisation

`priority = severity x confidence x leverage`, 0-100, computed on the server so
no consumer can disagree with the ranking. Leverage is the input that was not
already on the finding: how much the reader can *act* on the category. A
committed AWS key and a 1,200-line file are both true statements about a
codebase; only one is work.

### 3. The category split

`SECRET` out of `SECURITY`, `METRIC` out of `QUALITY`. Metrics are weighted
**zero** in the score and excluded from the breakdown — a large project should
not be gradeable down for being large. `quality/long-function` deliberately
stayed in `QUALITY`: a long function can be extracted, so it is work; a long
*file* is a measurement.

The UI defaults metrics out of view on exactly the terms accepted findings
already use: count always on screen, one click away, and shown regardless when
the category is asked for explicitly.

### 4. A proven exploitable finding caps the grade

Found by exporting a real analysis, not by reading the model. The sample app —
two proven SQL injections, command injection, SSRF, unverified JWT — scored
**80, a B**. Not a bug in the average: eight other categories legitimately
scored 100 and outvoted the one that mattered. A weighted average describes how
*broadly* a codebase is healthy and is a poor description of how *dangerous* it
is, and the two get confused because they share a number.

The average is now a ceiling. **80 (B) → 39 (F).** Confidence-gated, and
security/secrets only — a critical CVE in a transitive dependency is frequently
unreachable, and capping on it would push every project with an ageing lockfile
to F, at which point the score stops discriminating.

### 5. SARIF 2.1.0 export

`GET /api/reports/{id}/sarif`. Two mappings carry the value: `partialFingerprints`,
which is how a consumer recognises the same result across runs — Vantage's
identity is deliberately *more* stable than location, so an importer inherits
that rather than re-deriving a worse one from line numbers — and `suppressions`,
so an accepted finding is exported marked rather than dropped.

Validated against the OASIS schema itself, vendored so the suite stays offline.
It sets `additionalProperties: false` almost everywhere, so a misplaced property
fails the build instead of being silently ignored by an importer — the failure
mode that makes "we export SARIF" untrue in practice.

### 6. One pull request comment

The comment leads with **what changed**, not the finding list. A PR author
already knows the repository has debt; what they need is whether *this branch*
added to it. Re-runs edit the same comment in place, so a branch pushed twelve
times ends with one comment.

Built on the OAuth token the user already granted rather than a GitHub App —
see "what we deliberately did not build".

### 7. Honest positioning

The product said "point it at a repository and it tells you what is wrong".
True of two ecosystems, an overstatement everywhere else. It now names its
scope, and distinguishes the narrow part (rules: JS/TS/Python) from the part
that genuinely is universal (secrets, dependency advisories).

---

## Architecture changes

Deliberately small. No new services, no queue, no cache, no rewrite.

- `Category` gained two members; nothing renamed, so stored reports validate.
- `Finding` gained `priority`, defaulted.
- Two new modules: `app/analysis/priority.py`, `app/export/`.
- `app/ingest/pull_request.py` extends the existing GitHub layer.

**No migration.** `payload` is JSONB and every added field is defaulted — the
same backward-compatibility path already used for `delta`.

**The guarantee that made the split safe:** `fingerprint = sha1(rule_id | scope)`
— category is not in it. Had it been, every project's next report would have
shown its entire history resolved and an identical set appearing, destroying
the one feature the product is built around. Two tests pin this.

---

## Security considerations

Nothing in the praised set was touched: archive containment, path traversal
protection, prompt-injection fencing, ownership checks, source pinning. Their
tests pass unmodified.

Added surface, and what constrains it:

- **`/sarif`** matches `get_report`'s exposure exactly and deliberately. An
  ownership check there would protect nothing — the same content is served as
  JSON one route up — and would only make the export inconsistent with the page.
- **`/pull-request-comment`** requires sign-in and posts on the user's own
  token. GitHub, not this endpoint, decides whether they may write. Only
  comments the account itself wrote are edited, so two people cannot fight over
  one comment.
- **The report link inside the comment is built server-side.** A caller able to
  supply it could have Vantage post a link to anywhere into someone's pull
  request.

One control was *discovered* rather than added, and now has a test:
`AKIAIOSFODNN7EXAMPLE` — the key AWS puts in its own documentation — is
denylisted in the secrets module. It matches the provider regex perfectly, so
without the denylist every repository quoting the AWS docs reports a critical
leak.

---

## Tests added

Backend **337 → 454**. Frontend **140 → 144**.

| suite | what it protects |
|---|---|
| `test_security_rules.py` (50) | every rule fires *and* stays silent; the silences are the point |
| `test_priority.py` (27) | ordering, the metric split, the score cap, and fingerprint stability |
| `test_sarif.py` (16) | conformance to the real OASIS schema, every category x severity x confidence |
| `test_pull_request.py` (22) | URL parsing, head-SHA resolution, comment content, exactly-one-comment |

Two defects were found by **measurement rather than by test**, and both now
have regression tests:

1. **Three rules were silently dead.** `iter_code_lines` blanks string
   *contents*, so any rule whose signal lives inside a literal — `origin: '*'`,
   `createHash('md5')` — could never match. Worse, the weak-hash negative test
   was passing *for the wrong reason*: nothing matched at all, so the purpose
   check was never exercised. There is now a test guarding that test.
2. **The commonest SQL shape escaped** — built into a variable, executed on the
   next line. Fixed with a bidirectional window; confidence is graded on the
   statement alone so an unrelated `req.query` three lines up cannot promote
   MEDIUM evidence to CRITICAL.

---

## Remaining limitations

Stated plainly, because a scanner that overstates its reach is worse than one
with a documented edge.

- **No cross-file taint tracking.** A value tainted in one module and used in
  another is not detected. The module says so in its docstring and the finding
  text says so to the reader.
- **Backend latency is now attributed, and half of it is gone.** With the
  service's own hostname available it resolved cleanly: **one database query
  costs ~1.35s**, it never warms across repeated requests, and the Vercel proxy
  contributes nothing (direct and proxied calls land within 20ms).

      /api/ping           0 queries    0.41s   <- pure round trip to Render
      /api/reports        1 query      1.8s
      /api/reports/{id}   2 queries    3.1s

  Latency tracks the query *count*, which made the count the thing to attack.
  `get_report` read the same row twice — `get()` then `owner_of()`, the first
  already holding the `owner_id` it discarded. One round trip now, measured in
  production at **3.1s → 1.64s**.

  **Why a single query costs 1.35s is still open**, and it is the largest
  remaining number in the system. It is per-query rather than
  per-connection-burst, which points at the Render↔Neon link rather than at
  anything in this repository — most likely the two are in different regions.
  Checkable in the two dashboards, and if they differ, moving one is worth more
  than any further query tuning.
- **`PostgresReportStore.list` over-fetches** the full payload per row while
  three comments in that file claim it does not. Left alone: there is no
  Postgres-backed test, so the change would ship blind to the only environment
  that runs it.
- **Older rules are not as actionable as the new ones.** The nine security
  rules carry evidence, specific remediation and a reference. The original 21
  mostly carry a sentence.
- **Scores shift once.** Metrics no longer subtract, secrets are weighted
  separately, and the cap applies. Stored reports keep their stored score, so
  trend lines step at the deploy boundary rather than being rewritten.
- **`/api/health` reports `environment: development` in production**, while
  `render.yaml` sets production.

---

## What we deliberately did not build

**A GitHub App.** Only an App can create a check run, which is better than a
comment. It needs a registration, a webhook endpoint, an installation-token
flow and three deployment secrets — and the webhook path depends on job
persistence that does not exist: a free-tier instance that sleeps drops an
in-flight analysis with nothing to resume from, long after GitHub's 10-second
acknowledgement has closed. Building the webhook before the persistence would
produce a check that silently fails. The upgrade is additive: `upsert_comment`
is the only piece a check run replaces.

**More languages.** The brief offered expand-or-position. The engine genuinely
understands two ecosystems; a third would be superficial parser support, which
the brief explicitly rejects. Positioning was corrected instead.

**More rules.** Nine was where the evidence ran out. A tenth rule that cannot
distinguish a literal from user input costs more than it returns, because the
category it lands in is one people either trust or filter out permanently.

**A `browserslist` narrowing** (from the earlier performance work) — tried,
measured as a no-op, reverted. Recorded here because the reverting is the
finding.

**Per-finding `first_seen`/`last_seen`.** Derivable from existing report
history; adding columns before the UI needs them is speculative.
