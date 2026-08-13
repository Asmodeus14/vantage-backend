# Vantage — API

Static analysis for repositories. Fetches a GitHub repository (or accepts a ZIP),
runs a rule engine over it, and returns a scored report where every finding is
anchored to a file and line.

FastAPI · Python 3.12 · SQLAlchemy 2 (async) · Postgres.

The web client lives in a sibling repository,
[`vantage-frontend`](https://github.com/Asmodeus14/Vantage).

---

## The rules

Every rule declares which projects it applies to, so a Python repository is
never told it is missing ESLint — a specific complaint about the version this
replaced, which ran every check unconditionally.

| Rule | What it catches |
|---|---|
| `dep/known-vulnerability` | Resolves versions and queries **OSV.dev** per ecosystem. Direct and transitive, grouped per package with real CVE/GHSA ids. Transitive advisories are reported only at high/critical and downgraded one level, because you cannot bump them directly. |
| `dep/react-dom-mismatch` | Compares resolved majors, not spec strings. |
| `dep/no-lockfile` | Non-reproducible installs. |
| `security/hardcoded-secret` | Provider-shaped tokens (AWS, GitHub, Stripe, Slack, private keys, JWTs, DB URLs) plus entropy-checked assignments. Values are redacted before they are stored or shown. |
| `security/env-not-ignored` | `.env` present and not covered by `.gitignore`. |
| `react/missing-list-key` | `.map()` rendering JSX with no `key`, evaluated per call site. |
| `react/array-index-key` | An index key changes meaning whenever the list reorders. |
| `react/dangerously-set-inner-html` | XSS surface, flagged for review. |
| `python/mutable-default-argument` | `def f(items=[])` — evaluated once, then shared by every call. Reads wrapped signatures by paren depth, so code formatted by black is not missed. |
| `python/bare-except` | `except:` also swallows `KeyboardInterrupt` and `SystemExit`. |
| `python/subprocess-shell` | `shell=True` and `os.system` — an interpolated value becomes shell syntax. |
| `python/unsafe-deserialisation` | `pickle.loads`, `yaml.load` without a `Loader`, `marshal.loads`. |
| `quality/long-file`, `quality/long-function`, `quality/deep-nesting`, `quality/todo-markers` | Structural metrics measured over source with comments and string literals blanked, so `if` inside a comment does not count. |
| `config/*` | Linter, tests, CI, TypeScript `strict`, README — each gated on the detected stack. |

Every finding carries a **confidence** level; a heuristic match says so rather
than presenting a guess as a certainty.

The **security** rules skip test files. A suite exercising `pickle.loads` on
purpose is not a vulnerability, and measured on `psf/requests` all seven
deserialisation findings were tests testing deserialisation — seven
unactionable findings is how a check teaches people to ignore its whole
category. Correctness rules still scan tests, because a mutable default
argument is a bug wherever it is.

**Dependency scanning needs an exact version.** npm reads the lockfile; Python
reads `poetry.lock`, or `==` pins in `requirements.txt` / `pyproject.toml`. A
project declaring only ranges gets its dependencies listed but not scanned — a
range cannot be resolved without the index, and guessing would report
advisories for versions nobody installed.

Adding one is the most common contribution: see
[CONTRIBUTING.md](CONTRIBUTING.md#adding-a-rule).

---

## Running locally

Requires **Python 3.12+**.

```bash
python -m venv menv
menv/Scripts/activate            # Linux/macOS: source menv/bin/activate
pip install -r requirements.txt
cp .env.example .env             # every variable is optional — see below
python -m uvicorn app.main:app --reload --port 5000
```

Interactive API docs at <http://127.0.0.1:5000/docs>.

**If you set `DATABASE_URL`, apply migrations first:**

```bash
python -m app.migrate            # or: alembic upgrade head
```

Alembic owns the schema on Postgres. `create_all` still runs for SQLite and for
the no-database path, but never for Postgres — letting both manage the schema
would race, with `create_all` creating a table a pending revision is about to
create itself.

### It runs with no configuration at all

Every external dependency is optional, and each absence is reported by
`/api/health` rather than hidden:

| Missing | Effect |
|---|---|
| `GEMINI_API_KEY` | Analysis is unaffected. AI actions are disabled **with the reason shown**. No canned text is ever substituted for a model response. |
| `DATABASE_URL` | Reports are held in a bounded in-memory LRU and lost on restart. This is a working fallback, not a stub. |
| `GITHUB_TOKEN` | Anonymous GitHub access: 60 requests/hour. Commit-history enrichment spends one request per file carrying a finding, so a couple of analyses can exhaust it — the Activity panel then degrades to `partial` and says why. |
| Sign-in variables | Sign-in is reported unconfigured, naming exactly which variables are missing. Public repositories still analyse. |

---

## Configuration

All of it is read in `app/config.py` and nowhere else — no other module calls
`os.getenv`. Defaults shown are the code's own.

### Core

| Variable | Default | Notes |
|---|---|---|
| `ENVIRONMENT` | `development` | `development` \| `production` |
| `LOG_LEVEL` | `INFO` | |
| `CORS_ORIGINS` | `http://localhost:3000,…` | Comma-separated. Kept as a string deliberately: pydantic-settings parses list-typed env vars as JSON, which is a persistently surprising failure mode. |
| `DATABASE_URL` | — | Postgres via **asyncpg**: `postgresql+asyncpg://user:pass@host/db` |

### AI

| Variable | Default | Notes |
|---|---|---|
| `GEMINI_API_KEY` | — | From [AI Studio](https://aistudio.google.com/apikey) |
| `GEMINI_MODEL` | `gemini-3.6-flash` | Free-tier quota is **per model**, not per key. On repeated 429s, switching model is usually faster than waiting for the reset. |
| `AI_TIMEOUT_SECONDS` | `90.0` | Current flash models reason before answering; 30s was measured to be too tight. |
| `AI_CIRCUIT_FAILURE_THRESHOLD` | `3` | Consecutive failures before the circuit opens. |
| `AI_CIRCUIT_COOLDOWN_SECONDS` | `120.0` | How long it stays open. |

### GitHub

| Variable | Default | Notes |
|---|---|---|
| `GITHUB_TOKEN` | — | 60 → 5000 requests/hour, and reaches private repositories. |
| `GITHUB_TIMEOUT_SECONDS` | `60.0` | |

### Sign-in

Optional as a group; all three are required together, plus `DATABASE_URL`.
See [Sign-in](#sign-in) for what each one is for and why the client secret is
absent from this list.

| Variable | Notes |
|---|---|
| `GITHUB_CLIENT_ID` | From your OAuth App. Must match the frontend's value. |
| `INTERNAL_API_SECRET` | Authenticates the *frontend server* to this API. Not a user credential. **Must match the frontend exactly.** |
| `TOKEN_ENCRYPTION_KEY` | Fernet key encrypting stored GitHub tokens at rest. Generate with `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` |
| `SESSION_TTL_DAYS` | Default `30`. |

### Limits and analysis

| Variable | Default |
|---|---|
| `MAX_ARCHIVE_BYTES` | `262144000` (250 MB) |
| `MAX_EXTRACTED_BYTES` | `524288000` (500 MB) |
| `MAX_FILE_BYTES` | `8388608` (8 MB) |
| `MAX_FILE_COUNT` | `30000` |
| `MAX_COMPRESSION_RATIO` | `20.0` |
| `MAX_PATH_DEPTH` | `24` |
| `ANALYSIS_TIMEOUT_SECONDS` | `180.0` |
| `MAX_FINDINGS` | `500` |
| `OSV_ENABLED` | `true` — setting this false **disables vulnerability scanning entirely** |
| `OSV_TIMEOUT_SECONDS` | `30.0` |

---

## API

Full schema at `/docs`. Summary:

| Method | Path | Notes |
|---|---|---|
| `GET` | `/api/health` | Readiness. Never calls the model. Reports AI, database, schema and sign-in state. |
| `GET` | `/api/ping` | Liveness. Touches nothing — see [Keeping a free instance awake](#keeping-a-free-instance-awake). |
| `POST` | `/api/analyze/repository` | Returns `{job_id}` immediately (202). Rate limited 20/hr. |
| `POST` | `/api/analyze/upload` | Multipart ZIP. 10/hr. |
| `GET` | `/api/analyze/{job_id}/events` | Server-Sent Events: real per-stage progress. |
| `GET` | `/api/analyze/{job_id}` | Polling fallback. |
| `GET` | `/api/reports` | `?limit=`, `?repository=`. **Scoped to the caller** — see [Ownership](#ownership). |
| `GET` | `/api/reports/{id}` | Anyone holding the id may read it. Applies the **owner's** accepted findings, so a shared link means one thing to everyone. |
| `PUT` | `/api/reports/{id}/findings/{finding_id}/suppression` | Accept a finding for every analysis of that repository. Owner only; idempotent. |
| `DELETE` | `/api/reports/{id}/findings/{finding_id}/suppression` | Restore it. Takes effect on the next read, with no re-analysis. |
| `GET` | `/api/reports/{id}/suppressions` | What **the caller** has accepted for this repository. |
| `GET` | `/api/reports/{id}/files` | The file tree, with per-file finding counts. |
| `GET` | `/api/reports/{id}/file?path=` | One file's text, with the findings that point into it. |
| `DELETE` | `/api/reports/{id}` | Owner only. |
| `POST` | `/api/reports/{id}/findings/{finding_id}/ai` | Closed action enum. 30/hr. |
| `GET` | `/api/auth/status` | Whether sign-in can be offered, and why not. |
| `POST` | `/api/auth/session` | Server-to-server; guarded by `INTERNAL_API_SECRET`. |
| `GET` | `/api/auth/me` | Current user. |
| `POST` | `/api/auth/upload-ticket` | Short-lived credential so a direct upload can be attributed. Requires a session. |
| `POST` | `/api/auth/logout` | Ends this session. Idempotent. |
| `POST` | `/api/auth/logout-everywhere` | Ends all sessions for the account. |

---

## Sign-in

Optional. It buys three things: reports become owned, so the history listing
stops showing every caller the index of everyone's analyses; analyses spend the
signed-in user's 5000/hour GitHub budget instead of the server's shared 60; and
private repositories become analysable if the user separately grants `repo`.

### The split-secret contract

The two halves hold **different** secrets, and getting this wrong is the most
likely deployment mistake:

| Secret | Backend | Frontend |
|---|---|---|
| `GITHUB_CLIENT_ID` | ✓ | ✓ (same value) |
| `GITHUB_CLIENT_SECRET` | ✗ — deliberately never read here | ✓ |
| `INTERNAL_API_SECRET` | ✓ | ✓ (**must match**) |
| `TOKEN_ENCRYPTION_KEY` | ✓ | ✗ |
| `SESSION_SECRET` | ✗ | ✓ |

The OAuth code exchange happens on the frontend server, so the client secret
never needs to exist here. This API never sets a cookie — it receives a session
token as `Authorization: Bearer` and resolves it. The reason is in the
frontend's architecture notes: a cookie set by this API would be third-party in
production and blocked outright by Safari and Firefox strict mode.

If only one side is configured, `/api/auth/status` and the frontend's
`/api/auth/me` both report unconfigured, so a sign-in button is never offered
for a flow that would fail at the last step.

### Ownership

| Report | Reachable by id | Appears in the listing | Deletable |
|---|---|---|---|
| Anonymous | yes | only when signed out | no |
| Owned | yes | for its owner only | by its owner |

Report ids are `secrets.token_urlsafe(9)`, so "reachable by id" is an
unguessable capability rather than an open door — that is what makes a report
link shareable. *Listing* is the part that has to be scoped.

Anonymous reports cannot be deleted through the API at all: there is no account
to authorise against, and allowing it would turn an unguessable id into a
destructive capability held by anyone it was ever shared with.

---

## Testing

```bash
python -m pytest -q                              # 310 tests
python -m pytest --collect-only -q | tail -1     # current count
```

The suite runs against an **unconfigured** service: `tests/conftest.py` has an
autouse fixture that blanks the six ambient environment variables and clears the
settings cache. Without it the suite depends on whose machine it runs on —
configuring GitHub sign-in locally once made four unrelated tests fail.

Coverage worth knowing about:

- `test_archive_safety.py` — path traversal for **ZIP and tar**, symlinks and
  special files, decompression bombs, size/count/depth caps
- `test_prompts.py` — sentinel fencing, injection containment, output validation
- `test_ai_provider.py` — circuit breaker semantics, no I/O at construction
- `test_auth.py` — the ownership matrix, token encryption, key rotation
- `test_history.py` — the `Link: rel="last"` page-count trick, GitHub's
  `202`-while-computing response, rate-limit degradation

---

## Deployment

`render.yaml` is committed. The start command runs migrations before uvicorn and
**always exits 0** — a bad revision leaves the previous schema serving rather
than stopping the service booting, and `/api/health` reports
`database.migrations: behind` so the degradation is visible rather than silent.

Set in the dashboard (all marked `sync: false`): `GEMINI_API_KEY`,
`DATABASE_URL`, `GITHUB_TOKEN`, `CORS_ORIGINS`, `GITHUB_CLIENT_ID`,
`INTERNAL_API_SECRET`, `TOKEN_ENCRYPTION_KEY`.

Free tiers sleep when idle. The client reports a waking backend rather than
appearing hung.

### Keeping a free instance awake

Render's free tier spins a service down after ~15 minutes of inactivity, and the
cold start that follows is around a minute. An uptime monitor (UptimeRobot or
similar) pinging every 10 minutes prevents it.

**Point it at `/api/ping`, not `/api/health`.** Health is the obvious choice and
it is a trap: it probes the database on a 15-second cache, so a ping every few
minutes always misses the cache and issues a real query. Your database then
never auto-suspends either — and on a plan billed by compute time, keeping it
awake around the clock is the expensive half of the mistake. `/api/ping` touches
nothing.

Two things worth knowing before you set this up:

- Render's free allowance is roughly 750 instance-hours per month against 730
  hours in a month. One always-on service just fits, with nothing spare for a
  second.
- A monitor on `/api/ping` reports liveness only. It will keep saying "up" for a
  service whose database has been unreachable for a week. If you want alerting
  rather than just keep-alive, watch `/api/health` **as a separate, less
  frequent check** and alert on `status: "degraded"`.

---

## Documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — module layout, the rule
  engine, persistence, and the security model
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — setup, adding a rule, writing a
  migration, and the conventions
- [`SECURITY.md`](SECURITY.md) — how to report a vulnerability, and what is
  already defended
- [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md)

## Licence

[MIT](LICENSE).
