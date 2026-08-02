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
| **Bound to THE target** (SPKI-strong for HTTPS; host-only for HTTP) | for an **HTTPS** target the cert carries the target's OBSERVED TLS SPKI, and a target presenting a different key is REFUSED — not transplantable. For a plain-**HTTP** target the binding honestly degrades to the observed host string (an SPKI is never fabricated), which is transplantable across any target answering at that host — see the limit below | `verify/tls.py` `tls_spki_sha256` + `identity_matches` (#197); `LiveHttpAdapter.identity_sample` (#193) |
| **Authorized** | the re-verification itself is legal: an owner-minted, scoped, windowed, revocable, attenuable capability with wielder proof-of-possession | `vigil_core/capability.py` (#190) |
| **Continuously re-proven** | a signed, hash-chained, anti-rollback series of re-proof ticks — `present → proven-fixed → still-proven / regressed` — so a finding is "as of the last re-proof," not "as of the report date" | `attestation_log.py` + `vigil_core/highwater.py` (#198) |
| **Witnessed + time-bounded** | a strict-majority INDEPENDENT witness quorum co-signs the series head with a no-later-than-T median time (non-equivocation) | `attestation_witness.py` (#199) |
| **Re-derivable with ZERO VIGIL code** | a third party re-checks the whole lifecycle offline with stdlib + one Ed25519 lib | `docs/proof-carrying-finding/verify_vf.py` (#200) |

**Tier-1 honest limits (do not read past them):**

- **Freshness is asymmetric between the two verdicts, and the asymmetry is FUNDAMENTAL (VF-1a.3).** For a
  **STILL_VULNERABLE** finding the adapter reaches **genuine F2**: with a `payload_template` the fresh challenge
  rides the exploit payload and comes back INSIDE the sink's firing signature (e.g. a DB error wrapping the
  nonce) — unforgeable proof the vulnerable path ran this run (`live_adapter.py` + the driver's
  `fired ∧ challenge-in-judged-bytes` gate, #202). For a **REMEDIATED** finding F2 is *unattainable*: a fixed
  sink produces no signature, so a nonce in a silent response got there by *reflection*, which an echoing app or
  an interposing edge can fake — the driver therefore caps a silent verdict at **F1** and an F2-demanding
  verifier of a remediation gets `INCONCLUSIVE` (never a falsely-strong `REMEDIATED@F2`). The remediation's
  liveness is strengthened by a **LIVE positive control** (a real gated fetch this run, not just retained
  bytes); with `policy.require_injectable_param_live` it also rules out a **param-stripping edge / down-origin
  gateway** (the control sends a benign marker through the injectable param and requires the app to reflect it).
  **Residual, disclosed:** the F1 remediation still does not distinguish a *payload-discriminating WAF* (blocks
  the exploit's metacharacters, passes the benign marker) from a real fix — that needs a matched-decoy
  differential or the OOB Tier-2, both deferred.
- **Target-binding is TLS-SPKI-strong only for HTTPS; a plain-HTTP target binds host-only.** The strong,
  non-transplantable form of "bound to THE target" (the SPKI row above) requires an HTTPS handshake:
  `identity_sample` records `tls_spki_sha256` *only* when the scheme is `https`, and for an HTTP target (or a
  transport-layer handshake failure) it honestly degrades to `{"host": …}` — a producer-observed host string, no
  SPKI ever fabricated (`live_adapter.py` `identity_sample`, #193). Against an HTTP target a `REMEDIATED` verdict
  is therefore transplantable onto any target answering at the same host, because `identity_matches` has only the
  host to check. **The end-to-end demo runs over HTTP loopback (`http://127.0.0.1`), so it exercises host-only
  binding and never calls `tls_spki_sha256`.** For a non-transplantable cert, verify against an HTTPS target so
  the SPKI is captured and pinned; full channel-binding of the judged bytes to the key holder is the deferred
  stronger frontier noted below.
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
- **Distinguishing a payload-discriminating WAF from a real fix for the SILENT case.** VF-1a.3 delivered
  genuine F2 for the firing case, a live positive control, and (opt-in) the param-stripping/down-origin closure;
  what remains is telling a WAF that blocks the exploit's metacharacters (while passing a benign marker) apart
  from a genuine remediation. That needs a matched-decoy differential (a metachar-identical-but-null control) or
  the OOB Tier-2 — deferred, and honestly reported as the F1-remediation residual under Tier 1.

---

## How to check all of this yourself

The whole lifecycle — `vulnerable → proven-fixed → still-proven, witnessed (no-later-than T)` — is walked, and
every tamper rejected, in one runnable test: `integration/tests/test_vf_end_to_end.py`. It ends by handing every
artifact to the **standalone** verifier (`verify_vf.py`), which re-derives the claim with **zero VIGIL code**
against out-of-band-pinned trust roots. Run `verify_vf.py verify --prove-standalone <bundle>` to confirm, in a
clean interpreter, that no VIGIL module is even importable — then that the bundle is SOUND, and that a single
flipped byte flips it to NOT SOUND. That is the whole point: you do not have to trust VIGIL to check a VIGIL
proof — except for the one layer (oracle re-execution) that is honestly labelled as needing it.
