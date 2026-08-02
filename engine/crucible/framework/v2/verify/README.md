# verify/ — the deterministic oracle-verification layer

Prove, don't guess.

A finding is confirmed when a **real signal fires**, not when a model says
"confirm". This layer is the KEYSTONE: it replaces the critique gate as the
confirmation authority. The critique agent (URK `critique`) reasons about a
claim; this layer *decides* it — from evidence, deterministically,
reproducibly, offline.

## The contract

```
OracleVerifier.confirm(finding_context) -> VerificationResult
```

`confirmed` is `True` **iff at least one oracle fired at or above
`HIGH_CONFIDENCE` (0.7)** over already-collected data. No oracle, no
confirmation. An absent input does not pass — it skips. There is no path
through this layer that confirms a finding on assertion alone.

Everything here is:

- **pure** — the oracles do no I/O, no clock, no randomness;
- **deterministic** — same inputs, same verdict, every run;
- **offline** — no network, except the OOB receiver, which binds
  `127.0.0.1` only and merely *listens*.

## The five oracles (`oracles.py`)

Each takes OBSERVED data — responses/state/output someone else already
collected — and returns an `OracleSignal(fired, kind, confidence, evidence,
observed)`.

| Oracle | Confirms | Signal |
|---|---|---|
| `differential_response_oracle(baseline, mutated, discriminator)` | boolean- / time-based blind (SQLi, auth) | responses distinguishable (status/length/lexical/latency/marker) |
| `achieved_state_oracle(expected_state, observed_state)` | IDOR / BOLA / mass-assignment / privesc | a state the attacker should not reach became observable |
| `side_effect_oracle(marker, observed_sink)` | XSS / SSTI / path-traversal / error-based | a unique canary reached a sink it should never touch |
| `sanitizer_signal_oracle(process_output)` | memory-corruption / crash | ASAN/UBSAN/MSAN/TSAN, panic, abort, traceback markers |
| `oob_callback_oracle(hits, expected_token)` | SSRF / blind XXE / OOB SQLi / deserialization | an inbound interaction carried the finding's REGISTERED per-finding token (fail-closed without it) |

Confidence inside an oracle combines corroborating dimensions with a
noisy-OR and is clamped to 0.99 — a deterministic oracle never claims
certainty it cannot have.

## The out-of-band receiver (`oob.py`)

The local collaborator for blind signals. A stdlib `http.server` bound to
`127.0.0.1:0` (ephemeral port) that mints unique tokens and records inbound
hits. Localhost only, by construction — it refuses any non-loopback bind and
performs no external egress.

```python
from framework.v2.verify import OOBReceiver, oob_callback_oracle

with OOBReceiver() as oob:
    token, url = oob.register_token()     # hand `url` to a probe
    # ... something blind fetches `url` ...
    signal = oob_callback_oracle(oob.poll(token), token)   # the callback must carry the registered token
    assert signal.fired
```

The token rides the first path segment
(`http://127.0.0.1:<port>/<token>/...`), which also models a DNS-style
callback with the token as the interacting label — kept on loopback.

## Wiring a finding

`confirm` reads these context keys (all optional; a missing input skips its
oracle):

| key(s) | oracle |
|---|---|
| `bug_class` | selects the oracle set |
| `baseline`, `mutated`, `discriminator` | differential |
| `expected_state`, `observed_state` | achieved-state |
| `marker`, `observed_sink` | side-effect |
| `process_output` | sanitizer |
| `oob_hits` | oob-callback |

```python
from framework.v2.verify import OracleVerifier

result = OracleVerifier().confirm({
    "bug_class": "idor",
    "expected_state": {"owner": "victim", "readable": True},
    "observed_state": {"owner": "victim", "readable": True, "id": 42},
})
result.confirmed   # True — achieved_state fired at 0.9
result.rationale   # plain-language account, for the finding file
```

`bug_class -> oracle` mapping lives in `BUG_CLASS_ORACLES` (with aliases via
`normalize_bug_class`). An unknown class falls back to *every* oracle and
runs only those the context has inputs for — unknown bug, still no free pass.

## Integration (follow-up)

This ships as a standalone layer with its tests. Making it the confirmation
authority in the MAO/ACP loop — routing every finding through `confirm`
before it is written to `findings/NNN-*.md`, and demoting the critique gate
to advisory — is the next wire-up. The layer and its contract are stable;
the integration is additive.
