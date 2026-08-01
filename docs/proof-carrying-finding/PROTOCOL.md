# Verifiable Security Attestation — Protocol (design spec, draft v0.1)

> Status: **DRAFT — design, not a guarantee.** Designing a novel *trustless* attestation protocol is the
> textbook case of "don't roll your own." This specifies intended message flow, freshness, binding, and
> downgrade-resistance so they can be adversarially reviewed and independently implemented **before** the
> live driver is built on them. Every guarantee states its assumptions (§6). External review is warranted
> before real-world reliance.

Companion to `SPEC.md` (positive proof-carrying finding) and `REMEDIATION-SEMANTICS.md` (negative proof +
state machine). This document defines the *interaction* between mutually-distrusting parties.

## 1. Parties and trust

| Party | Role | Trusted by V? |
|---|---|---|
| **P** — Producer | runs VIGIL; keyless offense + the governance signer (sovereign) | **No** — V re-derives every verdict |
| **O** — Owner | controls target S; holds the owner/governance key; authorizes engagements + re-verification; the accountable party | for its *own* identity/authorization only (§6) |
| **V** — Verifier | third party (regulator / insurer / customer / court) | — (this is the party we design *for*) |
| **W** — Witnesses | independent parties countersigning the transparency log | conditionally: ≥1 honest, independent, clocked (§6) |
| **C** — OOB collector | observes target-emitted callbacks; signs `{token, source_ip, time}` receipts | conditionally: independent of P (VF-2) |
| **S** — Target | the system under test; identity is **owner-attested** (§4) | — |

## 2. Objects and the binding chain

Every object's signature covers the **digest(s) of the object(s) it depends on**, so parts cannot be mixed
across runs/targets/authorizations (a proof from run A cannot ride an authorization from run B or an identity
from target C):

```
IdentityAttestation        (O-signed)  : engagement E → acceptable target-identity policy
        ▲ digest
Authorization/Capability   (O-signed)  : scope, class-allowlist, non-destructive, window, rate, revocation-id
        ▲ digest                         ─ references IdentityAttestation
Proof                      (gov-signed): finding cert OR RemediationCertificate (with its controls)
        ▲ digest                         ─ references Authorization + IdentityAttestation (+ V's nonce, live)
SeriesHead                 (chained)   : monotonic, anti-rollback ─ references prior head + the proofs
        ▲ digest
Checkpoint                 (W-cosigned): carries witness-observed time ─ references SeriesHead
```

## 3. Modes (the trust gradient, as message flows)

**Mode R — Replay (non-interactive, offline, bearer).** V holds the bundle; re-fires each oracle over the
retained bytes, re-checks the negative-proof controls, the signatures, and the chain. *No target, no
authorization, no freshness.* Guarantee: the oracle fires/silent over **these signed bytes** with controls —
trusts P's capture honesty (byte authenticity).

**Mode L — Live re-verify (interactive).** V (or its agent), holding a scoped re-verification Capability from
O, sends a **fresh nonce**; the re-drive must carry that nonce **echoed by S** into the captured bytes (§5);
V re-fires the oracle, checks the nonce is present and the capability window covers it. Guarantee: the state
holds against the **real S, now** — trusts O's identity attestation, not P.

**Mode W — Witnessed + continuous.** As R or L, plus a witness quorum countersigns the `SeriesHead` with
observed time; V checks the quorum, split-view resistance, the "no-later-than-T" bound, and gap/rollback.
Guarantee: non-equivocation + time-bounded + gap-detectable.

## 4. Identity (owner-attested, policy-over-certs, time-varying)

`IdentityAttestation` (O-signed) binds engagement E to an **acceptable-identity policy**, not a single byte,
because identity legitimately evolves (cert rotation, redeploys): e.g. *"any leaf chaining to O's pinned CA
for host H"*, or a commit/artifact-digest set, or a cloud resource-id. Each live sample carries an
**identity proof** (the observed TLS SPKI / commit / resource-id) that MUST satisfy the policy. This defeats
the target-swap ("point the attestation at a fixed lookalike") because the identity is bound to O's policy and
checked per sample — at the cost of trusting O about O's *own* system (§6).

## 5. Freshness / anti-replay (Mode L)

Each live verification carries a fresh nonce `N` (from V, or a monotonic beacon). `N` MUST appear **inside the
target-produced bytes** — the canonical binding is the OOB token `= H(N ‖ finding_ref)` that only S can emit by
actually executing the payload (VF-2), or a reflected request marker for reflection-class oracles. A proof
whose echoed nonce ≠ V's challenge is **rejected** — so a replayed old benign (or malicious) response cannot
satisfy a live check.

## 6. Downgrade resistance

Every proof states its own **mode + provenance inside the signed bytes** (so it cannot be relabelled upward).
V's policy pins the **minimum acceptable mode**; a Mode-R proof presented where Mode-L was required is
rejected. This prevents an adversary (or a lazy producer) from substituting a cheap replay for a demanded live
re-verification.

## 7. Authorization / capability model

O mints a **re-verification Capability**: `{engagement, identity_policy_digest, class_allowlist,
non_destructive=true, not_before, not_after, rate_limit, revocation_id, audience}`, O-signed and
**attenuable** (V may narrow, never widen — macaroon/biscuit-style). Mode R needs **no** capability (no
traffic); Mode L **requires** one, so third-party re-verification (which re-runs an exploit) is itself
authorized and legal. Revocation = short TTL + a revocation-id list the executor checks + the kill-switch.

## 8. Security considerations (assumptions + what breaks)

- **Byte authenticity.** Mode R trusts P's capture. Mode L trusts O's identity attestation + the nonce-echo.
  General (non-OOB, non-live) byte authenticity **vs a malicious P** is **out of scope** — the zkTLS/TLSNotary
  frontier, honestly deferred. VF-2's witnessed OOB callback is the one class that defeats a dishonest P.
- **Witness independence.** Split-view resistance needs a strict majority of **distinct, independent, honest**
  witnesses. If P runs all of W, it is theater — W must be operated by mutually-distrusting parties (O, V, a
  neutral, a public log). Stated, not assumed.
- **Time.** "No-later-than T" assumes ≥1 honest, correctly-clocked witness; it is **weaker** than an RFC3161
  TSA or a chain anchor (fallback: an RFC3161/OpenTimestamps proof over the checkpoint hash — the designed,
  deferred hook).
- **Identity.** Owner-attested ⇒ O could misattest its **own** system — but that is self-defeating for O, the
  accountable party (an insurer/regulator holds O to the attestation regardless).
- **Revocation liveness.** A capability spent within its window before revocation propagates is a known gap →
  short TTLs.

## 9. Relationship to what is built

Implemented today: the controlled RemediationCertificate (Mode-R negative proof + §2 controls), its offline
re-execution verifier, the adversarial **conformance corpus** pinning every MUST-REJECT over that verifier
(`integration/tests/test_remediation_conformance.py`), the signed hash-chain + anti-rollback (`SeriesHead`
substrate), the witnessed log primitive (`transparency.py`, not yet wired to findings), and — new — the
**`IdentityAttestation` + `Capability` objects** of §4/§7 as pure `vigil_core` signed data
(`packages/core/vigil_core/vigil_core/capability.py`): owner-attested acceptable-identity policy
(`identity_matches` = conjunctive over dimensions, any-of within), and an owner-minted, scoped, windowed,
revocable, biscuit-style **narrow-only attenuable** re-verification capability, bound to an identity by digest,
with the one-call `authorize_reverification` gate. **Not yet built** (each its own reviewed slice): the Mode-L
nonce/freshness driver that carries a live `identity_sample` + V's nonce into the re-drive (§5), wiring the
witnessed checkpoint + observed-time (§3 Mode W / §8 time), and extending the VIGIL-free verifier to re-derive
the identity/capability chain offline.
