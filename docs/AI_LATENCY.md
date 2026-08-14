# AI latency and model routing

Why the AI actions default to `gemini-3.5-flash-lite` with `gemini-3.6-flash`
behind it, measured rather than assumed.

---

## What prompted this

Production logged a `503 Service Unavailable` from
`generativelanguage.googleapis.com`, and separately a successful AI action that
took **42 seconds** end to end. The obvious reading — "the model is slow, move
to a newer one" — turned out to be wrong in both halves.

## Newer is not faster

Same prompt, three runs each, non-streaming:

| model | runs | median |
|---|---|---|
| `gemini-3.6-flash` | 8.65s, 5.66s, 98.77s | 8.65s |
| `gemini-3.7-flash` | 24.07s, 88.58s, 18.37s | 24.07s |

`3.7-flash` is slower for this workload. There is no "Gemini 7"; `3.7-flash` is
the newest model the key can reach.

The more useful reading is the **spread**. Identical prompt, identical model:
5.66s, 7.12s, 8.65s, 98.77s, 118.30s, and one hard timeout. That is not a model
characteristic — it is provider weather, and it is the same weather that
produced the 503. No choice of model makes an unstable upstream stable.

Two of those observations exceeded the then-configured 90s timeout, so the
timeout was not hypothetical.

## Time to first token, streamed

| model | first token (median) | full (median) | observed range | failures |
|---|---|---|---|---|
| `gemini-3.6-flash` | 5.20s | 5.91s | 4.26–6.41s | 1 timeout in 4 |
| **`gemini-3.5-flash-lite`** | **1.15s** | **1.47s** | **1.04–1.21s** | none |
| `gemini-3.1-flash-lite` | 7.35s | 9.26s | 1.04–14.54s | none |

`3.5-flash-lite` is ~4.5× faster to first token, and the only model measured
that day that never failed and held a 0.17s spread across four runs. Stability
mattered more than the median.

## Quality, on the real prompts

The hypothesis was that a lite model would hold up on `EXPLAIN` (prose) and fall
down on `PROPOSE_FIX` and `GENERATE_TEST`, which must emit correct code. It did
not.

| action | `3.5-flash-lite` | `3.6-flash` |
|---|---|---|
| `EXPLAIN` | 2.02s — accurate, named `' OR 1=1 --`, correct Sequelize remediation | 17.03s — comparable |
| `PROPOSE_FIX` | 1.34s — `INSUFFICIENT_CONTEXT` | 503 Service Unavailable |
| `GENERATE_TEST` | 2.20s — well-formed Jest test with mocks | 41.66s — `INSUFFICIENT_CONTEXT` |

Both models correctly refused on a deliberately truncated snippet, so the
prompt-injection and insufficient-context guards survive the swap.

**Limits of this measurement.** One finding, one language, one run per action —
n=1, and not enough to claim the result generalises. The one behavioural
difference worth noting is that on incomplete context `3.6-flash` refused where
`3.5-flash-lite` generated. Refusing is arguably the safer default, which is a
reason to keep the larger model reachable rather than delete it.

## Why route at all

Not quality tiering — **failure**. Across one testing session the fallback model
returned 503 twice and timed out three times, while the primary never failed. A
different model is frequently a different capacity pool, so a 503 on one is not
a 503 on the next.

The policy, in `GeminiProvider`:

- **Transient** (5xx, timeout, unknown) → try the next model.
- **Fatal** (401/403 auth, 429 quota) → do not try the next model. It is the
  same key; the second request would fail identically and spend quota doing it.
- **Model** (404) → mark unreachable, try the next, and remember it so a
  misconfigured entry costs one request per process rather than one per call.
  If *every* model is unreachable that is a configuration error which will not
  heal on its own, so it latches.

**The circuit breaker counts chains, not models.** One model failing is a
routing event; if a flaky primary counted towards the breaker, the circuit would
open on a chain that is still serving perfectly from its fallback.

## Timeouts

Per attempt, not per request:

- `ai_primary_timeout_seconds` — 15s. flash-lite's slowest measured response was
  2.2s, so this is ~7× headroom. It fails fast so the fallback fires while the
  user is still waiting.
- `ai_timeout_seconds` — 45s, and also a ceiling: the primary is
  `min(primary, ceiling)`, so lowering the ceiling tightens every attempt rather
  than meaning something different depending on position. 45s because a
  *successful* `3.6-flash` call was observed at 41.66s.

Worst case is 60s against the previous single-attempt 90s.

## Automatic function calling

The SDK enables AFC by default, which logged this on **every** call:

```
AFC is enabled with max remote calls: 10.
WARNING  Direct use of automatic function calling (AFC) ... is not recommended
```

Vantage declares no tools and sends a plain string prompt, so AFC did nothing
except emit that warning and leave tool-invocation machinery enabled in a path
that deliberately treats model input as untrusted. Now explicitly disabled.

## A configuration trap

`model_chain` de-duplicates. Setting `GEMINI_MODEL` to the same value as the
only entry in `GEMINI_FALLBACK_MODELS` therefore collapses the chain to one
model and disables routing entirely. That is correct behaviour — the operator
asked for that model — but losing redundancy silently is not, so the provider
logs a warning when it happens.

## Reproducing

The measurements above are ad-hoc scripts against the live API, not a committed
harness — they cost real quota and their numbers move with Google's load. The
routing *behaviour*, which is what has to stay correct, is covered by tests in
`tests/test_ai_provider.py` under "Model routing".
