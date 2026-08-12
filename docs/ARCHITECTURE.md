# Architecture — API

FastAPI + Python 3.12, deployed to Render, backed by Neon Postgres. The web
client is a separate repository with its own deploy pipeline; see
[`vantage-frontend/docs/ARCHITECTURE.md`](https://github.com/Asmodeus14/vantage-frontend/blob/master/docs/ARCHITECTURE.md)
for the browser side.

They stayed separate because they already were, with their own remotes and
pipelines. Merging them into a monorepo would have cost a day and bought
nothing.

---

## Module layout

```
app/
  main.py           FastAPI app, lifespan, CORS, error handlers
  config.py         pydantic-settings — the only place env vars are read
  schemas.py        Pydantic models: the API contract
  errors.py         Domain exceptions, each with an HTTP status and stable code
  db.py             SQLAlchemy 2.0 async engine (lazy; no connection at import)
  store.py          ReportStore protocol + Postgres and in-memory implementations
  limiter.py        Shared rate limiter (its own module, to avoid a circular import)
  migrate.py        Deploy-time migration entrypoint; always exits 0

  ingest/
    github.py       Repo URL parsing, tarball fetch with a streaming size cap
    history.py      Commit activity and per-file churn, from the REST API
    archive.py      Containment policy for ZIP and tar (see Security)
    filter.py       What is worth reading and analysing
    snapshot.py     Indexed, read-only view of the extracted tree

  analysis/
    base.py         Rule protocol, RuleContext, comment/string stripping
    engine.py       Detects project facts once, runs applicable rules
    scoring.py      Weighted, saturating score with per-category breakdown
    runner.py       Job lifecycle and progress emission
    rules/          One module per rule family

  ai/
    provider.py     LLMProvider protocol, circuit breaker, NullProvider
    gemini.py       google-genai implementation
    prompts.py      Prompt assembly, injection defences, output validation

  auth/
    dependencies.py current_user / require_user / require_internal_caller
    models.py       users, sessions
    store.py        Account upsert, session lifecycle
    tokens.py       Fernet encryption of stored GitHub tokens

  routers/          health.py  auth.py  analyze.py  reports.py  ai.py

alembic/            Migrations. 0001 baseline (inspector-guarded), 0002 auth
```

---

## The rule engine

A rule declares `id`, `name`, `category`, an `applies(ctx)` gate and an async
`run(ctx)`. The gate is why a Python project is never told it is missing ESLint.

`RuleContext.finding()` is the only way findings are constructed, and it
populates the source snippet from the snapshot. "Every finding knows where it
is" is therefore a property of the framework rather than something each rule has
to remember.

The snapshot is built once and shared, so the tree is walked and each file read
at most once.

**Rules that scan for code constructs run over source with comments and string
literals blanked out**, with line structure preserved so line numbers still
match the original file. Counting `if ` in raw text — as the previous version
did — counts matches inside comments and strings.

A rule module that is not imported in `app/analysis/rules/__init__.py` never
runs. Registration is an import-time side effect of the `@register` decorator,
so adding a file is not enough.

---

## Progress

`POST` starts a job and returns an id immediately; the client attaches to an SSE
stream. The job's event list is the single source of truth and subscribers read
it **by index**, so a client attaching mid-run replays history and then
continues without receiving anything twice.

Jobs live in the process. That is correct for one web instance; more would need
the queue moved out of process.

---

## Persistence

`ReportStore` has two implementations. Postgres is used when `DATABASE_URL` is
set, otherwise a bounded in-memory LRU. The in-memory mode is a working
fallback, not a stub, and the degradation is reported by `/api/health` and shown
in the UI.

Indexed columns (`created_at`, `repository`, `owner_id`, score, grade) exist so
listing never deserialises the JSON payload.

**Alembic owns the schema on Postgres.** `create_all` still runs for SQLite and
the no-database path, but is skipped entirely for Postgres — letting both manage
the schema would race, with `create_all` creating a table that a pending
revision is about to create itself.

The baseline revision is inspector-guarded: it does nothing when `reports`
already exists, which is what makes `alembic upgrade head` safe against a
database created by the earlier `create_all` era.

---

## Commit history

`ingest/history.py` reads commit activity from the GitHub REST API. It cannot
come from the analysed snapshot — GitHub's tarballs contain no `.git`, and
`ingest/filter.py` drops `.git` from uploads.

Churn is bounded by the report, not by the repository: only files that carry a
finding are queried, capped at 25, ordered worst-first. Each file costs one
request, read as a page count out of the `Link: rel="last"` header rather than
by paging its history. That still means 25 requests against a 60-per-hour
unauthenticated budget, which is the strongest practical argument for
configuring `GITHUB_TOKEN` — or signing in.

Enrichment is best-effort by construction. A rate limit, an outage, or GitHub
answering `202` while it computes its statistics all produce a `partial` result
carrying the reason verbatim — never a failed analysis, and never a quietly
shorter list.

Hitting the 25-file cap is **not** a failure and does not set `partial`; the
report carries `files_with_findings` so the UI can state the cap as a footnote
instead of a warning.

---

## Sign-in

Optional. Everything works signed out; sign-in adds ownership, the user's own
GitHub rate limit, and optional private-repository access.

### This API never sets a cookie

The OAuth dance happens on the frontend server, which owns the client secret and
sets a **first-party** cookie. This API's half is narrower: exchange a GitHub
token for an opaque session, and resolve `Authorization: Bearer <session>` on
subsequent requests.

That split is deliberate. In production the two live on different sites (Vercel
and Render), so a cookie set here would be third-party — blocked outright by
Safari and by Firefox in strict mode. It would pass every test in Chrome and
then fail for a large share of users. Consequently CORS keeps
`allow_credentials=False`.

### Secrets

`INTERNAL_API_SECRET` authenticates the frontend *server*, not a user, and
guards `POST /api/auth/session`. It is compared with `hmac.compare_digest`.

`TOKEN_ENCRYPTION_KEY` is a Fernet key encrypting stored GitHub tokens at rest —
a stored OAuth token is a live credential for someone's account, so a database
leak would otherwise be strictly worse than a leak of our own data. It is
deliberately a separate setting from any session secret so the two rotate
independently; a rotation makes stored tokens unreadable, which degrades to
"sign in again" rather than an error.

`GITHUB_CLIENT_SECRET` is **not read here at all**. See the split-secret table
in the README.

### Sessions

Opaque random tokens, stored only as SHA-256. A database leak does not hand over
live sessions. Revocable, and the lookup is one indexed primary-key read —
cheaper than the JWT machinery it replaces.

`github_id` is `BigInteger`: GitHub ids are already past 2³¹.

### Ownership

| Report | Reachable by id | Appears in the listing | Deletable |
|---|---|---|---|
| Anonymous | yes | only when signed out | no |
| Owned | yes | for its owner only | by its owner |

`owner_id` is nullable and every row predating sign-in is null. Those reports
keep working — unguessable id, shareable link — they are simply never
enumerated. Backfilling them to a placeholder owner would either hide them or
hand them to the wrong person.

`list(owner_id=None)` means *no owner*, not *any owner*. That distinction is the
whole fix: `GET /api/reports` previously handed every caller the index of
everyone's analyses.

---

## Security

### Archive extraction

One containment policy for both formats rather than trusting per-format stdlib
behaviour. Verified experimentally on CPython 3.12:

- `zipfile.extract()` strips `..` itself, so ZIP was never traversable.
- `tarfile.extractall()` with the default filter **does** allow `../../x` to
  escape; only `filter="data"` refuses it. Tar is the primary ingestion path.

`resolve_member_path()` is the single chokepoint for untrusted paths and returns
`None` for anything escaping the root. Symlinks, hardlinks and special files are
refused outright, so the extracted tree contains only regular files and
directories — meaning no later path resolution can be redirected out of it.
Size, file-count and compression limits are enforced *during* streaming, so a
bomb is aborted partway rather than written out and measured afterwards.

Refused entries are counted and surfaced in the report rather than silently
dropped.

### AI

Two separate threats, defended separately.

**The endpoint as a free model proxy.** The client sends a report id, a finding
id and one value from a closed enum. There is no free-text parameter. Prompts
are assembled server-side from stored analysis data, results are cached per
(finding, action), and the route is rate limited.

**Injection from analysed code.** Untrusted source is fenced with a per-request
random sentinel, so injected text cannot guess the closing delimiter. The system
prompt states the fenced block is data to analyse and must not be obeyed. Output
is format-validated — a response that ignores the required shape is rejected
rather than displayed. Proposed fixes are diffs a human reviews; Vantage never
writes to a working tree, which is the backstop that stops a successful
injection becoming code execution.

### Provider resilience

No network calls at import or startup. `status()` is local and never performs
I/O — the previous version called the model on every health check while the
frontend polled it, which exhausted the quota. A 429 opens a circuit breaker
that closes itself after a cooldown, instead of latching the feature off for the
process lifetime.

---

## Notable constraints

- **Jobs are in-process.** Horizontal scaling needs an external queue.
- **Source is discarded after analysis.** Findings keep a ±3-line snippet, so
  *Propose fix* has only that context and will honestly return
  `INSUFFICIENT_CONTEXT` for whole-file findings.
- **Rate limiting is per-IP and in-memory.** It resets on restart and is
  per-instance.
- **`duration_seconds` is stored as an `Integer`.** Sub-second analyses round to
  0 on Postgres but not in memory, so the two store implementations disagree.
