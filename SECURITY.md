# Security policy

Vantage reads code it does not trust and hands parts of it to a language model.
Both of those are attack surfaces, and they are treated as such in the design
rather than assumed benign.

## Reporting a vulnerability

**Please do not open a public issue.**

Use GitHub's private vulnerability reporting — the **Security** tab on this
repository, then *Report a vulnerability*. If that is unavailable, email
<singhabhay3145@gmail.com> with `SECURITY` in the subject.

Please include what you need to demonstrate it: the affected endpoint or
module, the steps, and what an attacker gains. A proof of concept against your
own instance is more useful than a description.

This is a personal project, not a funded one. Expect an acknowledgement within
a few days and a fix timeline that depends on severity. There is no bounty.

**Please do not test against the hosted instance.** Run it locally — it works
with no configuration at all. Testing against the public deployment affects a
shared rate limit and a shared database.

## Supported versions

The `master` branch. This project has not cut tagged releases, so there is no
older version receiving backports.

## What is already defended, and how

Understanding this may save you a report, or point you at something real.

### Untrusted archives

Extraction applies **one containment policy to both ZIP and tar** rather than
relying on per-format stdlib behaviour. Verified on Python 3.12:
`tarfile.extractall()` with the default filter *does* permit `../../x` to
escape, and tar is the primary ingestion path for repositories.

Refused: path traversal, absolute paths, symlinks and other special file types.
Enforced *during* streaming, not after: total extracted bytes, per-file bytes,
file count, compression ratio, and path depth.

### Untrusted source reaching a model

The analysed code is hostile input to the prompt, and is treated that way:

- Source is fenced with a **per-request random sentinel** and the model is
  instructed not to follow instructions found inside it.
- Output is **format-validated** against the action before it is shown; a
  response that breaks shape is discarded rather than rendered.
- Proposed fixes are **diffs a human reviews**. Vantage never writes to a
  working tree, which is the backstop that stops a successful injection
  becoming code execution.

### The AI endpoint is not a model proxy

The client sends a report id, a finding id, and one value from a closed enum.
There is **no free-text parameter** — prompts are assembled server-side from
stored analysis. This is deliberate and should stay true of any new AI feature.

### Secrets

Detected credentials are **redacted before they are stored or displayed**
(`security/hardcoded-secret` reports `abc********yz (40 chars)`, never the
value). Stored GitHub tokens are encrypted at rest with Fernet, under a key
that exists only in the environment. Sessions are stored as SHA-256 hashes, so
a database leak is not directly account takeover.

### Report access

Report ids are `secrets.token_urlsafe(9)` — an unguessable capability, which is
what makes a report link shareable. Listing is scoped to the owner; deletion
requires ownership, and anonymous reports cannot be deleted through the API at
all because there is no account to authorise against.

### Path handling

Any path arriving from a URL is normalised by `app/source/providers.py::safe_path`
before either source provider sees it, because one interpolates into a GitHub
URL and the other into a SQL parameter.

## Known and accepted

Reporting these is not necessary; they are documented decisions.

- **Upload tickets are replayable within their ten-minute lifetime.** They are
  stateless Fernet tokens because Render runs more than one worker. An
  intercepted ticket lets someone attribute *their* upload to *your* account
  briefly. It reads nothing.
- **Rate limiting is per-IP and in memory.** It resets on restart and is
  per-instance.
- **Analysis jobs live in the web process.** A second instance would not find
  another's job.

## Running your own instance

Every external dependency is optional and each absence is reported by
`/api/health`. If you are testing, that is the fastest way to confirm what is
actually configured.
