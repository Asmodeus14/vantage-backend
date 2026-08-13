# Contributing

## Getting it running

Requires **Python 3.12+**.

```bash
python -m venv menv
menv/Scripts/activate            # Linux/macOS: source menv/bin/activate
pip install -r requirements.txt
cp .env.example .env             # every variable is optional
python -m uvicorn app.main:app --reload --port 5000
```

API docs at <http://127.0.0.1:5000/docs>.

**Nothing needs configuring to develop.** No API key, no database. Each absence
is reported by `/api/health` rather than crashing, so if something seems off,
check there first.

With `DATABASE_URL` set, apply migrations before starting:

```bash
python -m app.migrate            # or: alembic upgrade head
```

## Tests

```bash
python -m pytest -q
python -m pytest --collect-only -q | tail -1     # current count
```

The suite runs against a deliberately **unconfigured** service: an autouse
fixture in `tests/conftest.py` blanks ambient environment variables and clears
the settings cache. Without it, results depend on whose machine it runs on —
configuring sign-in locally once made four unrelated tests fail.

Two API tests start a real analysis in a background task and reach GitHub and
OSV. They pass, but they make the suite slower and weather-dependent.

## Adding a rule

This is the most common contribution.

1. Write it in `app/analysis/rules/`, as a class with `id`, `name`, `category`,
   `applies(ctx)` and `async run(ctx)`.
2. **Register it in `app/analysis/rules/__init__.py`.** A rule module that is
   not imported there never runs, and nothing will tell you.
3. Gate it properly in `applies`. A Python project should never be told it is
   missing ESLint — that was a specific complaint about the version this
   replaced, which ran every check unconditionally.
4. Build findings through `ctx.finding()`, never by constructing `Finding`
   directly. It fills in the snippet and both identities.
5. **Pass `key=`** if your rule's title contains a measurement, or if it emits
   one finding per file. See the identity table in
   [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md#finding-identity). Getting this
   wrong means the finding churns between runs and any suppression of it
   silently lapses.
6. Set `confidence` honestly. A heuristic match says so rather than presenting a
   guess as a certainty.

Add tests in `tests/test_rules.py`. Assert on behaviour — that the rule fires on
the shape it should and stays quiet on the shape it should not — rather than on
exact wording.

## Changing the schema

Alembic owns the schema on Postgres.

```bash
alembic revision -m "what it does"
```

Write the migration by hand rather than autogenerating it: the revisions in this
repository carry the reasoning for the change, and that is most of their value
when someone reads them in a year. Both `upgrade()` and `downgrade()`.

`create_all` still runs for SQLite and the no-database path but never for
Postgres — letting both manage the schema would race.

## Conventions

- **Comments explain why, not what.** The code says what it does. A comment
  earns its place by recording a decision, a constraint, or a bug that is not
  visible from the code.
- **Type annotations everywhere**, including return types.
- **Errors are structured.** Raise a `VantageError` subclass with a `message`
  and a `detail`; the handler turns it into `{code, message, detail}`. Never
  leak a stack trace to a client.
- **Degrade honestly.** If something optional is unavailable, say which thing
  and why, in words fit for a user. Never substitute a canned response for a
  real one — particularly for AI output.
- Line length 90ish. British spelling in prose; American in identifiers where
  an ecosystem expects it (`color` in CSS-adjacent code, `analyse` elsewhere).

## Security

If you have found a vulnerability, **do not open an issue** — see
[SECURITY.md](SECURITY.md).

If you are changing archive extraction, the AI prompt assembly, or anything that
interpolates a caller-supplied path, say so in the pull request. Those three
have tests specifically because they are where a mistake is expensive.

## Pull requests

- One change per pull request.
- Tests for new behaviour, and a test that fails before the fix for a bug.
- Update the documentation in the same pull request. `docs/ARCHITECTURE.md`
  carries the reasoning; the README carries the surface.
- The full suite must pass.
