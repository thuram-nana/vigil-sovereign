# Remediation & Security-State Semantics (VF design spec, draft v0.1)

> Status: **DRAFT — design, not a guarantee.** A novel *trustless* attestation protocol is exactly where
> "don't roll your own" applies. This document specifies the intended semantics + controls so they can be
> adversarially reviewed and independently implemented; every guarantee below ships **with its assumptions on
> the tin**. Real-world reliance warrants external cryptographic/security review.

This spec defines what a VIGIL **RemediationCertificate** and **Continuous Attestation Log** actually *mean*,
and the controls that make a *negative* security claim ("this exploit no longer works") sound rather than a
false negative. It complements `SPEC.md` (the positive proof-carrying finding).

## 1. Why a negative proof is hard

A positive proof is self-evidencing: the exploit fired, here are the bytes, re-fire the oracle. A **negative**
proof — "the oracle went **silent**" — is not, because silence has many causes that are *not* "fixed":

| Silence cause | Not a fix | Control that catches it | Live-tier status |
|---|---|---|---|
| the target was down / unreachable | ✗ | **liveness** — the target must have answered THIS run | caught (the trial's live answer, F1) |
| a stale benign response was replayed | ✗ | **freshness** — a fresh nonce echoed by the target | caught at F1 (nonce echoed) |
| the endpoint moved / was deleted | ✗ | **scope-equivalence** — same surface (method/param) | partial (surface rides on the cert) |
| the exploit is flaky (fires 1-in-N) | ✗ | **repetition** — N consistent silences | caught (per-family repeat policy) |
| the oracle body changed | ✗ | **oracle-version pin** (from the positive proof) | caught |
| a **WAF/edge blocked the probe** while still answering / **an interposing edge reflects the nonce** | ✗ | **LIVE positive control** — a benign probe demonstrating the exploit's parameter still reaches the app's processing path | **NOT yet caught — the F1 limit** (see below) |

Without these, "silent" means only "we did not observe it here, now" — the classic false negative. A sound
RemediationCertificate therefore carries, and a verifier re-checks, **all** of the applicable controls.

**HONEST F1 limit (the live tier, VF-1a.2).** The live adapter's positive control re-uses the RETAINED
original firing bytes — it proves only that the oracle is still *capable of firing* (the harness is not
broken), NOT that the *live observation channel* is intact right now. And the freshness nonce rides a
**separate** query param, so an echo establishes only that the target is **responsive (F1)**, not that the
**vulnerable code path** was exercised. Consequently a WAF/edge that blocks the exploit while still echoing the
nonce — or a down origin behind a reflecting gateway — can yield **REMEDIATED@F1**. Distinguishing that
requires **F2 (the nonce carried through the exploit path) + a LIVE positive control**, the disclosed VF-1a.3
follow-up. A verifier that needs it sets `policy.minimum_freshness_level >= F2`; the current adapter cannot
meet it and returns **INCONCLUSIVE** rather than a falsely-strong REMEDIATED. This is the trust gradient made
enforceable — not hidden.

## 2. The controls (implemented vs driver-populated vs spec-only)

| Control | Meaning | Status |
|---|---|---|
| **silence** | the oracle re-fires over the patched context and does NOT confirm | **implemented** (`_is_silent`, enforced at mint + re-checked at verify) |
| **positive control (twin)** | the SAME oracle DOES re-fire over a known-vulnerable reference (the pre-fix build / a twin) — proving the harness is *capable of firing now*, so silence is meaningful | **implemented** (`_fires`, enforced at mint + re-checked at verify). NOTE: the live tier's control is the RETAINED firing bytes (harness-capability only) — a **LIVE** positive control that proves the live channel/app-path is intact is the VF-1a.3 follow-up |
| **liveness** | the target answered THIS run (not a replay of retained bytes) | **implemented live (F1)** — the exploit trial must return a real answer AND echo the run nonce (`live_adapter`); a down/refused trial ⇒ INCONCLUSIVE |
| **scope-equivalence** | the re-drive hit the SAME surface + oracle family as the original finding | **partial** — oracle-family is pinned (`fix_oracle` channel-pin); `surface`/`probe_digest` ride on the cert; cryptographically tying the re-driven probe back to the ORIGINAL finding (vs a malicious producer) stays the deferred frontier |
| **freshness** | silence observed against a FRESH request bound to a verifier nonce echoed by the target | **implemented at F1** (nonce echoed = target responsive); **F2** (nonce through the exploit path) / **F3** (bound to exploit evidence) / **F4** (independent collector) are the graded follow-ups — the cert records the achieved level and a verifier can require a floor |
| **repetition** | N consistent silences (defeats a flaky exploit reading as silent once) | **spec-only** — `controls.repeats` reserved; populated by the live driver |

Everything in the certificate — both contexts *and* the `controls` block — is covered by one whole-cert
Ed25519 signature, so **no control can be stripped or downgraded** without breaking authenticity.

## 3. Formal state semantics

A **subject** is `(target-identity, exploit-class, surface)`. Its state is a labelled transition system:

```
            EXPLOITABLE@T ──(controlled silence proof)──► REMEDIATED@T'
                 ▲                                             │
                 │                                             │(oracle re-fires)
       (oracle fires)                                          ▼
   UNKNOWN ──────┘                                        REGRESSED@T''
      │                                                        │
      └──────────── INDETERMINATE@T (could not test) ◄─────────┘
```

Rules (the honest core):
1. **`REMEDIATED` is only reachable from `EXPLOITABLE`.** Certifying "fixed" for something never shown present
   is vacuous — the certificate references the positive proof (`original_finding_cert_digest`) it remediates.
2. **`REMEDIATED@T'` is a POINT observation, never durative.** It asserts "silent, with controls, *at T'*". It
   does **not** assert "not exploitable during any interval." A continuous claim is only a **sequence** of
   point observations `{T₁ … Tₙ}`; **the gaps between samples are explicitly NOT covered** (the vuln could
   reappear and vanish between samples). This "gaps-not-covered" axiom is load-bearing honesty.
3. **A missing sample is `INDETERMINATE`, never silently "still fixed".** A tick that cannot reach the target,
   or whose positive control does not fire, records `INDETERMINATE@T` — it does not extend a `REMEDIATED` run.
4. **Every transition is evidence-typed.** `→REMEDIATED` requires a controlled silence proof; `→REGRESSED`
   requires a positive re-fire; `→INDETERMINATE` requires (and records) the failed control. No transition is
   asserted; each carries its re-executable evidence.

The **Continuous Attestation Log** (VF-1b) is a monotonic, hash-chained, anti-rollback sequence of these
transitions. Its honest reading: *"re-proven `<state>` at each of {T₁ … Tₙ}; no claim about the gaps,"* and a
suppressed or reordered entry is detectable (chain + high-water), a post-dated one bounded by the witness time.

## 4. Trust gradient (each tier states its assumptions)

| Tier | What the verifier does | Guarantee | Trusts |
|---|---|---|---|
| **Replay** | re-fires the oracle over the retained bytes, offline | the oracle fires/silent over *these signed bytes*, with controls | that the producer captured honestly (byte authenticity) |
| **Live re-verify** | re-drives the exploit against the live target under a scoped, owner-signed capability | the state holds against the *real target now* | the owner's target-identity attestation |
| **Witnessed + continuous** | + a witness quorum countersigns the series head with observed time | non-equivocation + "no-later-than T" + gap/rollback detection | ≥1 honest, independent, correctly-clocked witness |

## 5. What this does NOT prove (honest scope)

- **Not "the system is secure."** Only that a *specific, previously-demonstrated* exploit does/does-not
  reproduce, with controls. Absence of *all* vulnerabilities is never claimed.
- **Not proof against a malicious producer for arbitrary classes.** Replay-tier byte authenticity is trusted;
  the general defense is the zkTLS/TLSNotary frontier (honestly deferred). The out-of-band path (VF-2) is the
  one class where a target-emitted secret-token callback defeats a dishonest producer.
- **Not continuous coverage.** Point samples only; gaps explicitly uncovered (§3.2).

## 6. Open design work (tracked, not yet done)

The security protocol (freshness/binding/downgrade-resistance), the target-identity model (owner-attested,
policy-over-certs, time-varying), the delegable/scoped/revocable re-verification capability, the witness threat
model (independence/collusion/clock assumptions + external-anchor fallback), and the adversarial
**conformance corpus** (MUST-ACCEPT / MUST-REJECT vectors) + differential testing across the VIGIL and
VIGIL-free verifiers + verifier fuzzing — are specified in the VF plan and land as their own reviewed slices.
This document + the controlled certificate (`remediation_cert.py`) are the first of those.
