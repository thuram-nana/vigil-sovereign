# The Verifiable-Fact trust gradient — stated on the tin

> This document states, explicitly and without overclaim, **exactly how much you can trust a VIGIL
> remediation proof, and against whom.** The honesty *is* the product: a verdict never claims more than the
> deterministic layer enforces. Every guarantee below names the code that enforces it and the assumption or
> attacker that breaks it. It is the companion to `SPEC.md` (positive proof), `REMEDIATION-SEMANTICS.md` (the
> negative proof + state machine), `PROTOCOL.md` (parties/modes/binding), and `WITNESS-TRUST.md` (the witness).

A VIGIL remediation claim is a **portable object whose truth a third party re-derives by re-execution** —
never an assertion you must trust. But *re-derivable by whom, and surviving which adversary?* That is a
gradient, not a yes/no. There are three tiers.

---

## Tier 1 — against an HONEST producer (the flagship)

The producer runs VIGIL correctly and does not forge its own signed artifacts. Under that assumption, a
`REMEDIATED` verdict is **not a claim — it is re-derivable evidence**, and it holds these properties, each
enforced by merged, adversarially-reviewed code:

| Property | What it means | Enforced by |
|---|---|---|
| **Re-derived by re-execution** | the ORIGINAL exploit oracle re-fires over the retained/fresh bytes and must go SILENT — silence is *earned*, never asserted | `remediation_cert.py` (`_is_silent`/`_fires`); `prove_driver.verify_prove_certificate` re-executes the embedded cert |
| **Controlled** | silence ≠ "didn't reach": the SAME oracle must still FIRE on a positive-control twin, the target must have ANSWERED (liveness), across a per-oracle-family repeat policy; only families where silence-across-N is a *sound* negative (deterministic per-observation) can be certified — timing/race/unknown are refused | negative-proof controls (#187); the fail-closed certifiability allowlist (#192) |
| **Portable + tamper-evident** | the whole cert is one m-of-n-signed object; a single flipped byte flips verification | `_cert_signing_bytes` whole-cert Ed25519; the conformance corpus (#189) |
| **Against a REAL target, freshly** | the exploit is re-driven LIVE through the gated executor, not re-judged offline | `LiveHttpAdapter` + gated `HttpExecutor` (#193); `vigil remediate --prove` (#194) |
| **Bound to THE target** | the cert carries the target's OBSERVED TLS SPKI; a target presenting a different key is REFUSED — the cert is not transplantable | `verify/tls.py` `tls_spki_sha256` + `identity_matches` (#197) |
| **Authorized** | the re-verification itself is legal: an owner-minted, scoped, windowed, revocable, attenuable capability with wielder proof-of-possession | `vigil_core/capability.py` (#190) |
| **Continuously re-proven** | a signed, hash-chained, anti-rollback series of re-proof ticks — `present → proven-fixed → still-proven / regressed` — so a finding is "as of the last re-proof," not "as of the report date" | `attestation_log.py` + `vigil_core/highwater.py` (#198) |
| **Witnessed + time-bounded** | a strict-majority INDEPENDENT witness quorum co-signs the series head with a no-later-than-T median time (non-equivocation) | `attestation_witness.py` (#199) |
| **Re-derivable with ZERO VIGIL code** | a third party re-checks the whole lifecycle offline with stdlib + one Ed25519 lib | `docs/proof-carrying-finding/verify_vf.py` (#200) |

**Tier-1 honest limits (do not read past them):**

- **Freshness is F1, not F2, for the current live adapter.** The freshness nonce rides a *separate* query
  param, so an echo proves the target is *responsive* (F1), NOT that the *vulnerable code path* ran (F2). An
  interposing edge / WAF block page / down-origin gateway that reflects the nonce can therefore yield
  `REMEDIATED@F1`. A verifier that needs the exploit path exercised sets
  `policy.minimum_freshness_level >= F2`, which the current adapter honestly cannot meet → `INCONCLUSIVE`
  (never a falsely-strong `REMEDIATED`). Closing this (a LIVE positive control + nonce-through-the-exploit-path)
  is the disclosed VF-1a.3 follow-up.
- **The durable attestation floor is LOCAL.** A same-host attacker with the owner's UID who rewrites the tick
  log, the head, AND the floor together defeats the *local* `verify_log`. The sound guarantee holds against an
  attacker who cannot touch the floor, and against an out-of-band verifier that retained a newer floor — and
  the Tier-1 witness (below) closes even the same-host case out-of-band.
- **The witnessed time bound is over the PRESENTED signing quorum, not the roster,** and is *strictly weaker*
  than non-equivocation: a dishonest producer curating which sigs the verifier sees can shift T with a roster
  minority. Demand the full roster (`min_distinct_signers → n`) or use the external anchor (deferred) for a
  hard time claim.
- **The standalone verifier checks signatures/binding/structure/chain/quorum — it NEVER re-fires the oracle.**
  Re-execution needs the oracle bodies (VIGIL). So a *governance-signed* `REMEDIATED` whose embedded context
  would not actually re-fire silent is accepted standalone but rejected by VIGIL; the standalone verdict
  attests *authenticity + binding*, and says so — it never prints "remediated/silent".

---

## Tier 2 — against a DISHONEST producer (scoped to out-of-band-observable classes)

For classes where exploitation produces an **out-of-band callback** — SSRF, blind XXE, OOB-SQLi,
deserialization gadgets — the proof survives a producer who fabricates everything it can. The target emits a
**per-finding secret token** it could only send by *actually executing* the payload, and:

- the oracle fires ONLY when a callback carried that **registered token** (constant-time), enforced live AND on
  offline re-verification — a fabricated/unrelated callback does not confirm (`oob_callback_oracle`, #195); and
- the callback is witnessed by an **INDEPENDENT, receipt-signing collector** whose signature over
  `{token, client_ip, received_at, method, path}` is checked against a collector public key **pinned
  out-of-band** — a producer who does not hold the collector's private key cannot forge a receipt that
  verifies under the pinned key (`oob.py` + the F4 oracle gate, #196).

**Tier-2 honest limit:** the collector's *independence from the producer* is a deployment assumption (distinct
keys ≠ distinct operators); if the producer runs the collector, it is theater. The pinned key must come
out-of-band; a collector key read from the producer-controlled context proves nothing.

---

## The deferred frontier — NEVER claimed active

These are honestly out of scope today; VIGIL does not claim them:

- **General byte-authenticity vs a malicious producer for arbitrary (non-OOB) classes.** For a class with no
  out-of-band channel, a fully-dishonest producer that fabricates the retained bytes is the TLSNotary / DECO /
  zkTLS frontier. VIGIL's Tier-2 covers only OOB-observable classes; everything else rests on Tier-1's
  honest-producer assumption (re-derivable, but by a party who trusts the producer's capture).
- **A hard, external time anchor.** An RFC3161 TSA / OpenTimestamps proof over the checkpoint hash would give a
  single trusted "no-later-than T" independent of witness honesty. It is a designed, deferred hook
  (`WITNESS-TRUST.md` §5); until built, the time bound is the quorum-median described above.
- **F2+ freshness in the live adapter** (nonce through the exploit path + a live positive control) — the
  VF-1a.3 follow-up noted under Tier 1.

---

## How to check all of this yourself

The whole lifecycle — `vulnerable → proven-fixed → still-proven, witnessed (no-later-than T)` — is walked, and
every tamper rejected, in one runnable test: `integration/tests/test_vf_end_to_end.py`. It ends by handing every
artifact to the **standalone** verifier (`verify_vf.py`), which re-derives the claim with **zero VIGIL code**
against out-of-band-pinned trust roots. Run `verify_vf.py verify --prove-standalone <bundle>` to confirm, in a
clean interpreter, that no VIGIL module is even importable — then that the bundle is SOUND, and that a single
flipped byte flips it to NOT SOUND. That is the whole point: you do not have to trust VIGIL to check a VIGIL
proof — except for the one layer (oracle re-execution) that is honestly labelled as needing it.
