# The Verifiable-Fact program — a remediation is a FACT, not a status field

This is the subsystem that extends VIGIL's one idea — *only a deterministic oracle mints a FACT* — from **"this
bug is real"** to **"this bug is really fixed."** A remediation stops being a field you trust and becomes a
**portable object whose truth a third party re-derives by re-execution**: witnessed, time-anchored, continuously
re-proven, and — for out-of-band classes — self-authenticating. If you change anything here you are changing what
"remediated" *means* for the whole platform — and, more than anywhere else in the tree, the rule is: **never
claim more than the deterministic layer enforces.** The honesty *is* the product.

Companion prose: [`verify-and-oracles.md`](./verify-and-oracles.md) (the oracle authority this builds on) and
[`proof-studio.md`](./proof-studio.md) (the positive FACT pipeline). The design specs are checked into
[`docs/proof-carrying-finding/`](../../docs/proof-carrying-finding/): `REMEDIATION-SEMANTICS.md`, `PROTOCOL.md`,
`WITNESS-TRUST.md`, `TRUST-GRADIENT.md`, and the design-first `DIFFERENTIAL-REMEDIATION.md`.

Program status: **18 implementation PRs `#186–#202` merged + CI-green**, plus a design-first spec `#203`. Every
crypto/composition slice was built → adversarially red-penned with runnable PoCs → fixed to convergence →
merged. The red-pen caught a real defect on nearly every slice — including honesty overclaims in the docs
themselves — which is exactly why this page can be trusted to state limits, not just capabilities.

---

## 1. What it is / its job

`vigil remediate --prove` re-drives the **original** retained exploit live against the patched target, re-fires
the **original** oracle over the fresh wire bytes, and emits **one signed, cross-bound certificate** whose verdict
is *earned by re-execution*, never asserted. The contract in one sentence: a fix is `REMEDIATED` only when the
original exploit oracle goes **silent** across the protocol-required trials **and** every control is satisfied —
otherwise the certificate honestly says why not.

- Entry point: `integration/vigil_integration/cli.py` (`_cmd_remediate`), driver
  `integration/vigil_integration/remediation/prove_driver.py`.
- It loads a **provenance-grounded** finding (a signed spine/envelope, never raw JSON) and reconstructs the
  retained exploit request; it **refuses** (fail-closed) if the request side was not retained.
- FATAL-2 safe: the driver's module scope is stdlib + `vigil_core` only; `framework.v2` imports are function-local.
- Determinism: the driver supplies `now` / `run_id` / the nonces; there is no wallclock or rng in the signed math.

---

## 2. The four states — and why REFUSED ≠ INCONCLUSIVE

| State | Meaning |
|---|---|
| **REMEDIATED** | the exploit provably no longer reproduces — earned by oracle **silence** across the required trials, all controls satisfied |
| **STILL_VULNERABLE** | the original oracle **fired** over fresh evidence — the bug reproduces right now |
| **INCONCLUSIVE** | testing *happened* but the negative claim was **not earned** (a control failed, freshness fell short, the target went unreachable) |
| **REFUSED** | testing **must not begin** (out of scope, expired/insufficient capability, a non-certifiable oracle family) |

The `REFUSED` vs `INCONCLUSIVE` split is load-bearing: the certificate is *signed*, so an `INCONCLUSIVE` reason
can never be stripped and re-read as success, and a `REFUSED` ("must not test") is never confused with a tested
"claim not earned."

Silence is only a fix when it is **controlled** (`remediation/remediation_cert.py`, controls per
`REMEDIATION-SEMANTICS.md`): a **positive-control twin must still FIRE** on the known-vulnerable bytes (the
harness is alive), the target must have **answered** this run (liveness), across a **per-oracle-family repeat
policy**. Certifiability is a **fail-closed allowlist** of deterministic-per-observation oracle kinds derived
from the authoritative verifier taxonomy — timing / race / credential-stuffing / prompt-injection / unknown
classes are `REFUSED`, never silently "remediated." (History lesson: the allowlist replaced an early *blocklist*
that failed unsafe — for a security gate, an allowlist beats a blocklist.)

---

## 3. The freshness gradient F0–F4 — and the asymmetry that keeps it honest

Every certificate records how fresh its evidence is (`Freshness`, `prove_driver.py`):

- **F0** a fresh client challenge exists · **F1** the target echoed it (responsive) · **F2** the fresh challenge
  came back *through the vulnerable sink's own channel* · **F3** structurally bound · **F4** an independent
  collector / the target key signed the nonce-bound observation.

The verdict-dependent asymmetry is **fundamental**, and stating it plainly is the point:

- **STILL_VULNERABLE reaches genuine F2.** With a `payload_template` the run challenge rides the exploit payload;
  the driver credits F2 only when the trial **FIRES** *and* the challenge is reflected **in the datastore-error
  line the oracle matched** (`_challenge_in_firing_signature`, which calls the `error_signature` oracle itself to
  locate the match — never a duplicated signature list — then checks same-line containment). That is *as
  attributable as the error-signature oracle's own firing* — **not** byte-unforgeable (a producer that fabricates
  the origin's bytes is the OOB Tier-2 / zkTLS frontier). A static banner + a separate-line reflection does **not**
  earn F2 (capped to F1).
- **REMEDIATED is capped at F1.** A fixed sink emits no signature, so a nonce in a *silent* response got there by
  reflection — which an echoing app or an interposing edge can fake. Sink-traversal is *unprovable once the sink
  is gone*, so a verifier that sets `minimum_freshness_level >= F2` for a remediation gets `INCONCLUSIVE`, never a
  falsely-strong `REMEDIATED@F2`.

> **Design-history note (why this matters).** #192 originally credited `F2_PATH_TRAVERSED` to a *silent* verdict
> from a merely-reflected nonce. VF-1a.3 (#202) fixed that overclaim: reflection is not sink-traversal. The
> deeper lesson the red-pen named — recorded so it isn't relearned — is **a positional fact (bytes present
> somewhere) is not a causal proof (the sink processed it); dress it as one and it forges.**

---

## 4. The live re-drive adapter + the live positive control

`remediation/live_adapter.py` (`LiveHttpAdapter`) is the first real live-re-execution producer: it re-drives the
original exploit through CRUCIBLE's gated `HttpExecutor` (charter/scope/kill-switch/budget — the gate is
enforced, never bypassed), captures the fresh response bytes, and turns them into the exact `oracle_context` the
original oracle re-fires over. The **positive control is a real gated fetch this run** (VF-1a.3) — a benign,
metacharacter-free marker through the same injectable parameter — so the control genuinely exercises the live
channel instead of asserting liveness from retained bytes; it still returns the retained firing context for the
harness-capability check. `injectable_param_live` is recorded as **informational only** (a reflected marker could
be the app *or* an echoing edge — it never gates a verdict).

Target identity is bound (`framework/v2/verify/tls.py`): for an HTTPS target the cert carries the observed
**TLS SPKI** sha256, so a target presenting a different key is refused (anti-transplant); for a plain-HTTP target
the binding honestly degrades to the host string (an SPKI is never fabricated).

---

## 5. Continuously re-proven, witnessed, and time-bounded

- **Continuous Attestation Log** (`remediation/attestation_log.py` + `vigil_core/highwater.py`): each re-proof
  tick is appended to a signed hash-chain guarded by a durable **anti-rollback high-water floor** (entry-count
  primary guard), yielding a monotonic series `present → proven-fixed → still-proven / regressed`. A full
  truncation of the log is caught by the floor (an empty log + a floor > 0 is a rollback, not "clean").
- **Witnessed, no-later-than-T checkpoint** (`remediation/attestation_witness.py`): a strict-majority,
  split-view-resistant witness quorum co-signs the series head with a median observed time under a distinct domain
  tag. The time bound is honestly *strictly weaker* than non-equivocation — it is over the **presented signing
  quorum** (a producer curates which sigs a verifier sees), raisable toward the full roster via
  `min_distinct_signers`. Built atop the merged transparency primitives (`transparency.py`, `scitt.py`).

---

## 6. The dishonest-producer tier — self-authenticating OOB proofs

For classes whose exploitation produces an **out-of-band callback** (SSRF, blind XXE, OOB-SQLi), the proof
survives a producer that fabricates everything it can (`framework/v2/verify/oob.py`, `oracles.py`):

- the target emits a **per-finding secret token** it could only send by *actually executing* the payload;
- the oracle fires **only** on a registered-token match (constant-time), enforced live *and* on offline
  re-verification;
- the callback is witnessed by an **independent, receipt-signing collector** whose signature over
  `{token, client_ip, received_at, method, path}` is checked against a collector key **pinned out-of-band**.

Honest limit (in the code): the collector's *independence from the producer* is a deployment assumption; a
collector key read from the producer-controlled context proves nothing — the pin must come out-of-band.

---

## 7. Re-derivable with ZERO VIGIL code

[`docs/proof-carrying-finding/verify_vf.py`](../../docs/proof-carrying-finding/verify_vf.py) is a **standalone**
verifier: Python stdlib + one Ed25519 library, and `--prove-standalone` asserts no VIGIL module is even
importable. It re-derives the whole lifecycle offline — the remediation certificate, the attestation series
(chain + anti-rollback), the witnessed no-later-than-T checkpoint — against **out-of-band-pinned** trust roots,
with byte-parity to the real serializer, and a single flipped byte anywhere flips it to NOT SOUND. Documented
boundary: it checks signatures/binding/structure/chain/quorum; it **never re-fires the oracle** (that one layer
honestly needs VIGIL), and no standalone output ever prints "remediated/silent."

The end-to-end demonstration is `integration/tests/test_vf_end_to_end.py` (#201): vulnerable →
`STILL_VULNERABLE`, patched → `REMEDIATED`, re-proved, a 2-of-3 witness quorum → no-later-than-T, then the
standalone verifier confirms the whole bundle and **rejects every tamper**.

---

## 8. The trust gradient — stated on the tin

[`docs/proof-carrying-finding/TRUST-GRADIENT.md`](../../docs/proof-carrying-finding/TRUST-GRADIENT.md) is the
honesty capstone — exactly how much you can trust a remediation proof, and against whom:

- **Tier 1 — against an HONEST producer** (the flagship): re-derived by re-execution, controlled, live-vs-real,
  target-bound (HTTPS-strong / HTTP host-only), authorized, continuously re-proven, witnessed + time-bounded,
  third-party-re-derivable with zero VIGIL code, genuine F2 for the firing case. Honest limits stated inline
  (F1-not-F2 for a remediation; local floor; the witness clock is over the presented quorum; the standalone
  verifier never re-fires the oracle).
- **Tier 2 — against a DISHONEST producer** (OOB-observable classes only): the token + independent signed
  collector receipt of §6.
- **Deferred frontier — never claimed active**: general byte-authenticity vs a malicious producer
  (zkTLS/TLSNotary), an external RFC3161/OpenTimestamps time anchor, and — for the SILENT case — a matched-decoy
  differential to tell a payload-discriminating WAF / request-echoing edge from a real fix (below).

---

## 9. Differential remediation — design-first, deferred (NOT built)

[`docs/proof-carrying-finding/DIFFERENTIAL-REMEDIATION.md`](../../docs/proof-carrying-finding/DIFFERENTIAL-REMEDIATION.md)
(#203) is a **reviewed design with no implementation** — the plan to *narrow* the silent-case interposer residual
with a **matched-decoy differential**: a metacharacter-identical, *data-dependent* boolean true/false pair a
content WAF cannot treat differently, judged by the existing `boolean_inference_oracle`, plus a mandatory
baseline WAF-closure test and a decisive-SPRT-refute requirement.

It was landed spec-first *precisely so the design could be adversarially reviewed before any code* — and that
review earned its keep: it found a false-`REMEDIATED` hole (an in-flight **sanitizing** WAF that escapes quotes
lets the probe reach the origin as inert data → looks fixed) and that a boolean differential is **never
interposer-unforgeable** over plaintext HTTP (the probes are always lexically separable). So the claims were
narrowed to exactly what holds:

- it closes only a **blocking** payload-discriminating WAF (→ `INCONCLUSIVE`, not a false `REMEDIATED`);
- its `STILL_VULNERABLE` is a **safe over-approximation**, not an unforgeable proof (a forged firing only
  over-reports, never mints a false fix);
- a **sanitizing** WAF, a **param-stripping edge**, a structurally-matched 200 block page, and producer
  byte-forgery are all **disclosed residuals**.

**Implementation is deferred** (operator decision, 2026-08): the honest gain is narrow and the residual is
already disclosed in `TRUST-GRADIENT.md`; the spec captures the design for whenever a blocking-WAF-fronted origin
enters the threat model.

---

## 10. Invariants (do not violate)

1. **Oracle authority** — only a fired/silent *oracle* over target-produced bytes decides a verdict; the driver
   only sequences, the adapter only arranges probes.
2. **Never overclaim** — every certificate field, docstring, and doc line must be enforced by the deterministic
   layer. A universal property claim must carry the protocol/transport precondition the code actually requires
   (the #201 SPKI lesson); an inline comment on the code counts as a claim (the #202 lesson).
3. **Fail-closed** — any unbuildable/undelivered/ambiguous evidence → `INCONCLUSIVE`/`REFUSED`, never
   `REMEDIATED`.
4. **Determinism + FATAL-2** — no wallclock/rng in signed math; `framework.v2` imports stay function-local.
5. **Provenance in, provenance out** — a finding enters only via a signed spine/envelope; a remediation leaves
   only as a signed, cross-bound, re-verifiable certificate.
