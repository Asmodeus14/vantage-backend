## What and why

<!-- What changes, and what problem it solves. The "why" is the part that is
     hard to recover later. -->

## Checks

- [ ] `python -m pytest -q` passes
- [ ] Tests cover the new behaviour — and for a bug, a test that failed before
- [ ] Documentation updated in this PR (`docs/ARCHITECTURE.md` for reasoning,
      `README.md` for surface)

## If this adds a rule

- [ ] Registered in `app/analysis/rules/__init__.py` — a module not imported
      there never runs, and nothing will tell you
- [ ] `applies(ctx)` gates it on the right stack
- [ ] `key=` passed if the title carries a measurement, or it emits one finding
      per file (see the identity table in `docs/ARCHITECTURE.md`)
- [ ] `confidence` set honestly

## If this changes the schema

- [ ] Alembic revision written by hand, with `upgrade()` and `downgrade()`
- [ ] The docstring says *why*, not only what

## If this touches security

Archive extraction, prompt assembly, or anything interpolating a
caller-supplied path — say so here, and say what you checked.
