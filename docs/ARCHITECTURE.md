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

## Finding identity

"Is it getting better?" is the question a maintainer actually has, and a total
count cannot answer it. That needs findings to be recognisable across runs.

`Finding.id` cannot do this. It is `sha1(rule_id|file|line|title)`, and **both
`line` and `title` move without the problem moving** — inserting an import
shifts every line below it, and `quality/long-file` puts the measurement in the
title (`"response.js is 1,169 lines long"`). Measured against real data,
express 4.18.0 → 4.19.0 changed the title of 7 surviving findings and the line
of 4 more, so an id-based comparison would have reported 12 resolved and 12 new
where the true answer is 1 and 1.

So findings also carry a `fingerprint`, and **no single formula produces it** —
the rule supplies the discriminator through `key=` on `RuleContext.finding()`:

| `key` | Identity is | Used by |
|---|---|---|
| omitted | file **and** line | `react/*` — several per file, nothing else to tell them apart |
| `source.path` | the file | `quality/long-file`, `quality/deep-nesting` |
| `f"{path}\|{name}"` | the named thing in that file | `quality/long-function` |
| the package name | the package, not its version | `dep/known-vulnerability` |
| `""` | the rule alone, no location | `quality/todo-markers`, which anchors to whichever marker it found first |

`title` is never part of it.

The comparison itself lives in `analysis/diffing.py` and runs **at analysis
time**, in the runner, not on read. Deriving it on read would let the answer
drift as newer reports arrived, so a report someone bookmarked would quietly
start describing a different comparison than the one it was created with.

`is_comparable` is deliberately strict, because a misleading comparison is
worse than none: uploads are excluded (two ZIPs of the same name may be
unrelated projects), so are different repositories, a report against itself, and
either side being `truncated` — everything past the findings cap was never
written down and would read as resolved.

The previous report is looked up with `ReportStore.latest_for`, **scoped by
owner on the same terms as `list`**: `None` means *no owner*, not *any owner*.
Without that, a signed-in user's report would be compared against a stranger's
run of the same project, and the resolved list would name findings from it.

Two things this deliberately does not do. A **renamed file** reads as wholly
resolved plus wholly new; rename detection is out of scope. And a **rule added
between runs** makes all of its findings "new", which is true and misleading at
once — so `Report.rule_ids` records every rule that ran, *including those that
found nothing*, and `FindingDelta.new_rules` lets the UI caption it. The set has
to be stored rather than derived from findings: a rule that ran clean leaves
nothing to derive it from, and would be indistinguishable from one that did not
run.

No migration was needed. `payload` is JSONB and both fields are defaulted
Pydantic fields, so older rows validate unchanged — their findings simply have
an empty fingerprint, which `compare` skips rather than treating as a shared key
that makes every legacy finding equal to every other.

---

## Reading source after the fact

Findings record a file and a line, and until the file viewer there was nothing
behind that coordinate — the analysed tree is deleted as soon as a run finishes.
`app/source/` gives it back, for the viewer and eventually for AI actions that
need more than the ±3 lines a finding carries.

**One interface, two implementations**, chosen by `provider_for(report)`:

| Source | Provider | Why |
|---|---|---|
| Repository | `GitHubSourceProvider` | Re-fetched, **pinned to the analysed commit**. Costs nothing to keep and cannot drift. |
| Upload | `StoredSourceProvider` | The client sent bytes once; there is no URL that would produce them again. |

The split is real and unavoidable, so it is confined to this package —
everything above asks a `SourceProvider` and never learns which kind it holds.
That containment is the entire reason the hybrid is affordable; without it, two
code paths would leak into the viewer, into *Propose fix*, and into every
future feature that reads source.

Pinning to the commit is not an optimisation. A finding says line 47, and line
47 only means anything against the tree that was analysed; reading the branch
head would quietly show the wrong line as soon as anyone pushed. A report with
no recorded commit is refused with a sentence saying to re-analyse, rather than
silently showing today's code.

**Stored blobs are bounded**: 8MB gzipped and 2,000 files per report, analysable
files first, so what gets dropped when a budget runs out is a lockfile rather
than the module someone is trying to read. One row per file rather than one
archive per report, because the viewer opens a single file at a time and
decompressing a whole project to read a 40-line module is a cost that only
appears under load. Deleting a report deletes its blobs — there is no cascade,
deliberately, so the obligation stays visible in the router.

`safe_path` normalises before either provider sees a path. It arrives from a URL
and is interpolated into a GitHub URL in one implementation and a SQL parameter
in the other; `..` is refused once, here, rather than being relied upon to be
harmless twice.

Every failure raises `SourceUnavailable` carrying prose. The repository went
private, the commit was force-pushed away, the upload predates blob storage —
each is a different situation with a different remedy, and "unavailable" tells
nobody anything they can act on.

### The AI router reads through it too

`_wider_source` gives the model a `MAX_CONTEXT_LINES` window of the real file
instead of the finding's ±3-line snippet. Three lines rarely contain the
imports, the surrounding function and the conventions a correct patch has to
match, which is why *Propose fix* so often refused.

The window is **centred on the finding**, not taken from the top of the file:
`clamp_context` truncates from the start, so a window that overflowed would
lose the very lines the finding points at.

Best-effort. A rate-limited GitHub or a deleted repository falls back to the
snippet rather than failing the action, and `AIActionResponse.context` says
which happened — it reads "lines 1–99" or "lines 8–14 (snippet only)", because
a UI claiming context the model never saw is worse than no label.

**This does not make every finding fixable, and should not be described as if
it did.** `quality/long-file` on a 1,187-line file still answers
`INSUFFICIENT_CONTEXT`, correctly: you cannot split a file you have seen an
eighth of. That is not a context bug — "split this file" is not a diff-shaped
answer, and raising the cap would inflate cost and dilute attention for every
other action to chase a case that would still fail.

---

## Accepted findings

A scanner reporting the same forty-seven unchanging low-severity findings on
every run teaches people to stop reading the list, which quietly removes the
value of the two that mattered. `suppressions.py` is the escape hatch, and it
only became possible once fingerprints were stable — a suppression keyed on
anything volatile would silently lapse on the next run.

The key is `(owner_id, repository, fingerprint)`:

- **Fingerprint, not report id.** A suppression is a statement about a problem,
  not about one analysis of it, so it carries forward to every future run.
- **Per repository.** "This hardcoded key is a test fixture" is true of one
  project, not of every project the account analyses.
- **Requires an account.** An unattributable judgement cannot be reviewed or
  revoked by whoever has to live with it. Uploads are refused for the same
  reason the diff refuses them: no stable identity to carry the acceptance to.

Applied when a report is **read**, so removing a suppression restores the
finding immediately rather than needing a re-analysis. Findings are *marked*,
never dropped — removing them would leave `suppressed_count` unverifiable and
turn "show accepted" into a second round-trip.

### Whose suppressions, and what happens to the score

Reading a report applies its **owner's** suppressions, for every viewer.
Filtering per viewer would mean two people discussing the same URL are looking
at different reports, which is worse than the mild oddity of seeing someone
else's judgement. Changing them still requires *being* that owner, so the
unguessable id stays a read capability and never becomes an edit one.

`score` is always what the analysis produced and never changes. `effective_score`
is it recomputed with accepted findings excluded, present only when some are.
Both are sent, and the UI leads with the effective one while keeping the
original on screen — a score that silently absorbed its own exceptions would be
unfalsifiable.

Because the *owner's* suppressions apply for everyone, the effective score is
still the same number for every viewer at any given moment. It moves over time
as the owner accepts and restores, which is the trade accepted when choosing to
let suppressions affect the score at all.

`can_suppress` is the one field on a report that varies by caller. It exists so
the UI can omit an action that would only ever be refused.

### Keeping History honest

A listing is built entirely from indexed columns and never deserialises
`payload` — that is what keeps it cheap — so it cannot recompute anything. Left
alone, History and the trend chart showed the score *as analysed* while the
report page they link to showed it adjusted, and one report displayed two
different numbers depending on where you looked at it.

So `reports.effective_score` and `reports.suppressed_count` are cached columns,
refreshed by `_refresh_effective_scores` whenever a suppression changes. It is a
fan-out write — a suppression applies to the repository, so accepting a finding
changes every past report that contained it — bounded by `reports_for`'s limit,
because an account with a thousand analyses of one project should not turn one
click into a thousand updates.

Deliberately a write-time cost: listings are frequent, suppression changes are
not. Both paths measure a report through the same `_mark`, so they cannot
disagree about what "accepted" means, and if a refresh fails the cache goes
stale while the report pages stay correct — they compute the value directly.

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

### Upload tickets

One request cannot carry a session: a ZIP upload posts **directly** to this API
to clear the frontend's serverless body cap, so the HttpOnly, first-party
session cookie never reaches it. Every signed-in user's upload was therefore
recorded as anonymous and never appeared in their own History.

`auth/tickets.py` closes that without widening anything else. The browser asks
the *frontend* — which can read the cookie — for a ticket, and attaches it to
the upload as a form field.

**A ticket, not the session token.** Handing the session to JavaScript would
undo the whole reason the cookie is HttpOnly. A ticket says one thing, "this is
user X", and expires in ten minutes.

**Fernet, so it is stateless.** Fernet carries its own timestamp, so expiry
needs no storage — the same reasoning as the OAuth `state`, and for the same
reason: Render runs more than one worker, so a nonce table would have to be
shared to be worth anything. The cost is that a ticket is replayable within its
lifetime; someone who intercepted one could attribute *their* upload to *your*
account for a few minutes. That is a nuisance, not a disclosure — it reads
nothing — and it is the same exposure the upload request already has.

**The payload is prefixed** (`upload:`), because stored GitHub tokens use the
same cipher. Without it, a leaked token ciphertext would redeem as a user id.

An unusable ticket is treated as *no* ticket. Refusing an archive someone spent
a minute uploading, because a credential expired while they were choosing a
file, is a worse answer than attributing it anonymously.

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
