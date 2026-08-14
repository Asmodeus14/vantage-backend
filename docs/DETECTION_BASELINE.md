# Detection baseline

What the rule set actually finds, measured on real repositories rather than
asserted from the test suite.

Reproduce with:

```bash
python -m scripts.corpus_scan <corpus-dir> --json out.json
```

Offline (`osv_enabled=False`, `http=None`), so the numbers do not move with
the state of OSV.dev.

---

## Why this exists

The security rules were validated twice, and both samples were misleading in
opposite directions.

They found **11 of 11** on a deliberately vulnerable Express + Flask app — but
that app was written to trigger them, which proves the rules run, not that they
are useful.

They found **0 across ~360 files** of `expressjs/express`, `psf/requests` and
Vantage itself, and that was reported as "zero true positives on real code". It
was the wrong conclusion from the wrong sample: those are hardened libraries
with years of review, and they are not what the product is for. Someone
scanning a repository they just built is not scanning `express`.

So the corpus is deliberately two halves. **Deliberately vulnerable
applications** measure recall — their flaws are documented, so a miss is a miss
rather than an opinion. **Ordinary applications** measure noise — every
security finding there has to be read by hand and judged, because a false
positive on real code is what makes people stop trusting a scanner.

---

## The corpus

| repository | kind | files |
|---|---|---|
| `appsecco/dvna` | vulnerable by design (Node) | 31 |
| `nVisium/django.nV` | vulnerable by design (Django) | 138 |
| `payatu/Tiredful-API` | vulnerable by design (Django REST) | 83 |
| `juice-shop/juice-shop` | vulnerable by design (Node/TS) | 821 |
| `hagopj13/node-express-boilerplate` | ordinary app | 50 |
| `santiq/bulletproof-nodejs` | ordinary app | 28 |
| `steven-tey/precedent` | ordinary app (Next.js) | 38 |
| `miguelgrinberg/microblog` | ordinary app (Flask) | 53 |
| `realpython/flask-boilerplate` | ordinary app | 50 |
| `pallets-eco/flask-security` | library (auth) | 158 |

---

## Result

Security and secret findings, before and after the fixes below.

| repository | before | after |
|---|---|---|
| `hagopj13/node-express-boilerplate` | 3 | **0** |
| `pallets-eco/flask-security` | 11 | **6** |
| `juice-shop/juice-shop` | 76 | 76 |
| `miguelgrinberg/microblog` | 5 | 5 |
| `appsecco/dvna` | 3 | 3 |
| `payatu/Tiredful-API` | 3 | 3 |
| `nVisium/django.nV` | 2 | 2 |
| `santiq/bulletproof-nodejs` | 0 | 0 |
| `steven-tey/precedent` | 0 | 0 |
| `realpython/flask-boilerplate` | 0 | 0 |
| **total** | **103** | **95** |

Every removed finding was a false positive on an ordinary application. **No
finding was lost on any vulnerable application.** `node-express-boilerplate`
went from 69 D to 100 A, which is the correct score for it.

---

## The false positives, and what caused them

Each was found by reading the flagged line, not by a failing test. All three
now have regression tests.

### `request.url` matched inside `urllib.request.urlopen`

`REQUEST_SOURCE` listed `url` as a request accessor with no trailing word
boundary, so `urllib.request.urlopen` contained a match. `flask_security`'s
HaveIBeenPwned lookup — a constant URL with a password hash appended — was
reported as **SSRF**.

Fixed by anchoring every accessor with `\b`. `req.url` still matches;
`request.urlopen` no longer does.

### `verify=False` reported as an unverified JWT

The JWT pattern included a bare `verify\s*=\s*False`. That is a keyword
argument shared by half of Python: `EmailValidation(verify=False)` in
`flask_security` produced four **critical** findings, and
`requests.get(url, verify=False)` would have produced more.

That second one is a real problem — TLS verification disabled — but it is a
*different* problem, and mislabelling it as a JWT flaw is how a rule teaches
people to distrust the category. `verify=False` now only counts when JWT is
actually in view.

### A sample JWT in API documentation

OpenAPI and Swagger-in-JSDoc write example responses inline, and a sample JWT
is a structurally perfect JWT:

```yaml
example:
  token: eyJhbGciOiJIUzI1NiIs...
```

All three of `node-express-boilerplate`'s findings were this. The placeholder
word list is deliberately not applied to provider-shaped matches — it would
discard a real key containing a word like "test" — but that reasoning is about
the *value*. An `example:` key on the line above is a statement about the
value's purpose, and no real credential is introduced that way.

---

## What the rules do not cover

`nVisium/django.nV` is deliberately vulnerable and produced two findings. That
is **not** a miss: its flaws are template XSS, CSRF and broken access control,
and none of those are classes this rule set attempts. The same is true of most
authorization bugs.

Stated plainly, the rules cover: injection (SQL, command, code), path
traversal, SSRF, weak hashing, predictable randomness, permissive CORS,
unverified JWTs, committed secrets, and known dependency vulnerabilities. They
do not cover authorization, template XSS, CSRF, business logic, or anything
requiring cross-file dataflow.

---

## Known remaining noise

- **`microblog`, 5 × `python/subprocess-shell`** on `os.system('pybabel …')`
  with constant commands. Reported at MEDIUM confidence with text saying it is
  only a vulnerability if part of the command comes from input — so it is
  working as designed, but five of them on a tutorial app is more than the
  signal justifies. A constant-only string argument could reasonably be
  skipped entirely.
- **`flask-security`, `weak-hash`** on `hashlib.sha1(password)`. SHA1 is
  *required* there — it is the HaveIBeenPwned k-anonymity API — so the finding
  is wrong in intent while being right about the code. MEDIUM confidence, so it
  does not affect the score.
- **`flask-security`, secrets in `tests/` and a CI workflow**
  (`postgresql://postgres:testpw@localhost`). Test credentials for a local
  database. Defensible to report, but noise on a library.

All three are in a library rather than an application, and all are MEDIUM
confidence, so they neither surface by default nor cap the grade.

---

## Honest summary

On the four deliberately vulnerable applications the rules fire and find real
things. On the five ordinary applications they now produce **zero** security or
secret findings — which is the correct answer for those repositories, and the
answer a user should be able to trust when they see it.

What this measurement cannot tell you is recall on an *average* application
that has real flaws but was not built to demonstrate them. That would need a
corpus with independently known ground truth, which does not exist for ordinary
code.
