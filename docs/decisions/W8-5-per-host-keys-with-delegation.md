# W8-5 — Shared owner key across HA passives: the residual, and per-host keys with delegation evaluated

Issue: [#471](https://github.com/thuram-nana/vigil-sovereign/issues/471) ·
Milestone: W8 — HIGH AVAILABILITY.
Interacts with [W8-2](https://github.com/thuram-nana/vigil-sovereign/issues/468) (passive fencing
detection SLA), [W9-1 #434](https://github.com/thuram-nana/vigil-sovereign/issues/434) (owner-key
succession), and [W9-5 #438](https://github.com/thuram-nana/vigil-sovereign/issues/438) (per-host
co-signer enrolment for the destruction quorum).

## The residual (stated plainly)

The HA profile makes the sovereign spine's *failover* safe (an anti-rollback-witnessed-floor interlock,
`docs/architecture/HA-PROFILE.md` §3) and its read/proxy tier horizontally scalable (§1). But the writer
itself is single-owner-signed, and **for a passive to become a valid writer it must hold the owner signing
key.** Concretely, the spine head is signed by a **single owner key at a 1-of-1 trust root**
(`apps/sigil/sigil/spine/checkpoint.py` `trust_root` → `sign_head`/`verify_head`), so **every passive holds
the SAME owner signing key, and every host that holds it can sign a fork.**

That is a genuine contradiction between the HA story and the key story: the more passives you keep hot for
availability, the more hosts hold a key that can sign the exact "same height, different head" fork the floor
and witness quorum exist to *reject* (§2). HA of the writer widens the owner key's blast radius. This
document records that residual and evaluates the obvious mitigation — **per-host keys with delegation** —
against the delegation/succession machinery already in the tree, and records the decision.

## What "per-host keys with delegation" would mean here

Instead of copying the raw owner private key onto every passive, each passive host would hold its **own**
key pair and an **owner-signed delegation** bounding what that key may sign. A compromised passive would then
leak only its delegated authority, not the owner key — narrowing the blast radius. The question W8-5 must
answer honestly is: *can that be built by reusing the existing machinery, cleanly, without half-building a
new trust model?* Three primitives already exist and were each evaluated.

### Primitive 1 — owner-key succession (W9-1 #434, `governor/key_history.py`)

`build_succession` maintains an append-only, cross-signed owner-key **history** with **seq-windowed epochs**:
exactly **one** key is authoritative for any spine `seq`. It is a *succession* (linear rotation of the single
owner key), and it is **fail-closed on a FORK** — two validly cross-signed successors of the live key raise
`SuccessionError`, and every consumer treats that as DENY.

Per-host keys are a **fan-out** (multiple keys concurrently authoritative), which is precisely the ambiguity
succession is designed to reject. You cannot host N concurrent per-host signers inside a machine whose
invariant is "one authoritative key per seq" without breaking that invariant — and the invariant is the
anti-fork property, not an incidental limitation. **Succession cannot carry per-host head keys.**

### Primitive 2 — per-host co-signer enrolment + multi-signer (W9-5 #438, `destruction_gate.py`)

This is the *closest* existing template: CSR-style per-host key generation (the private key is generated on,
and never leaves, the signer's own host — `build_enrollment`), owner-bound m-of-n assembly on a separate box
(`assemble_authority`), and per-host detached signing — **with the exact negative control W8-5's AC3 names**:
a signer outside the quorum, a forged proof-of-possession, a duplicate-pubkey collapse, or an owner-absent
roster is **refused** (`test_cosigner_enrollment.py`). But it governs the **destruction quorum** — a distinct
signing surface. It is **not wired to the spine head**, and it verifies an *m-of-n* authority. Reusing it for
the head means **raising the head trust root from 1-of-1 to m-of-n** — a head-trust-model change, evaluated
below, not a drop-in reuse.

### Primitive 3 — owner-root delegation certificate (S4, `vigil_core/delegation.py`)

`DelegationCert` is an owner-signed, **role/scope/expiry-bounded** delegation of a TrustRoot, verified with
`vigil_core` alone and crossing the offense↔sovereign boundary as inert data (the owner private key stays
sovereign-side; the delegate never holds it). `verify_delegation` **already** enforces "a signer may sign only
what it is delegated": a wrong-owner, wrong-role, out-of-scope, or expired delegation is refused fail-closed
(the AC3 negative control, proved for this surface in `test_delegation.py` and re-asserted in this issue's
own suite). But its surface is the **offense governance / offense-spine** identity, tagged with a **separate
domain** (`vigil-delegation-v1`) deliberately kept away from the spine head-signing bytes; it is **not** wired
into `checkpoint.trust_root` / `verify_head`; and it is a **bearer cert with no pre-expiry revocation** — its
own docstring states `not_after` is its only bound.

## The decision: DEFER per-host head-signing delegation; document and register the residual

<!-- CLAIM:W8-5 -->
> **Registered claim (W0-3 #398, id `W8-5`):** Every HA passive that can become the sovereign spine writer holds the SAME single owner signing key: the spine head is signed at a 1-of-1 owner trust root (`checkpoint.trust_root` yields `threshold=1` with one owner authorizer), so a passive holding only its own per-host key is NOT a valid writer and every host that holds the owner key can sign a fork; per-host keys with delegation were evaluated (against W9-1 #434 succession, W9-5 #438 co-signer enrolment, and the S4 delegation cert) and deliberately NOT implemented for the head surface, because a delegated per-host head signer would still emit a second same-height owner-authorized head (the exact fork the single-writer doctrine detects and rejects) and admitting one would require changing the head trust model from 1-of-1 to m-of-n rather than reusing the existing offense-plane delegation machinery — the residual is recorded rather than half-built.

We **do not** implement per-host head delegation in this issue. The decision is deliberate, and the reasons
are recorded so a future edit does not silently re-open it:

1. **It would not resolve the contradiction it appears to.** The residual's subject is the **write-authority
   surface** — the head. A per-host key delegated to sign heads can still sign a head at a given height. If
   two passives are hot, two per-host keys can each advance and sign a head at the **same** `entry_count` =
   the "same height, different head" fork (§2) the floor + witness quorum exist to reject. Delegation changes
   *which* key signs; it does **not** make concurrent writers safe. Single-writer is **product doctrine**
   (§2), not a key-management gap, so per-host keys do not shrink the write-availability blast radius.

2. **It is a head-trust-model change, not a clean reuse.** Admitting a delegated per-host head signer means
   wiring a delegation into `checkpoint.trust_root` / `classify_head` / `verify_head` — a new head-verification
   surface. Done soundly it is exactly #438's m-of-n co-signer model *raised onto the head* (1-of-1 → m-of-n),
   which is its own design (fork semantics under multiple valid signers, roster provisioning, quorum sizing),
   not a drop-in of existing code. Building a *partial* version of that would be the "half-built delegation
   system" the issue's own guidance forbids.

3. **The bearer-cert has no revocation, which is a regression on this surface.** `DelegationCert` cannot be
   revoked before `not_after`. The owner key already has a stronger recovery for the same threat — succession
   `rotate` (seq-windowed retirement) and `re_genesis` (compromise reset). A per-host delegation would trade
   that down for an un-revocable window, on the highest-value surface in the system.

4. **The real benefit is narrower and already served.** What per-host keys *would* buy is a narrower
   **cross-surface** blast radius — a stolen passive key that could sign only heads, not succession /
   re-genesis / destruction / capability / evidence. That is real but **partial**, and today it is served by
   tight owner-key custody + a **small** passive fleet + `re_genesis` on suspected compromise (all shipped).
   The honest posture is a small hot-passive count, not a false sense of per-host isolation on a surface that
   still forks.

**If** the product ever raises the head trust root to a genuine **m-of-n multi-signer head** (the #438
destruction-quorum model lifted onto the head), per-host head keys become sound and #438's per-host co-signer
enrolment is the template to reuse. Until that trust-model change is designed and accepted, per-host head
delegation stays **evaluated-and-deferred**, recorded here.

## This claim is TRUE of the code as of W8-5

- **The head is single-owner, 1-of-1.** `checkpoint.trust_root` returns
  `TrustRoot(threshold=1, authorizers=[AuthorizerKey(..., name="owner", ...)])`; `checkpoint.checkpoint`
  signs with a single `signers=[(OWNER_KEY_ID, priv)]`; `_owner_keys` reads a single `owner.priv` per host.
- **A passive's own per-host key is NOT accepted by the head path.** `verify_head` of an owner-signed head
  against a trust root built from a *different* (per-host) key fails ("0 valid distinct signature(s)") — there
  is no per-host-delegation admission in `classify_head` / `verify_head`. So the concession ("every passive
  must hold the owner key") is a property of the code, not just a doc sentence.
- **The delegation machinery we evaluated bounds a signer to its grant.** `verify_delegation` returns the
  delegated root in-grant and **refuses** an out-of-scope, out-of-role, or expired delegation — the AC3
  negative control — but for the **offense** surface, tagged `vigil-delegation-v1`, not the head.

Pinned by `apps/sigil/tests/test_ha_shared_owner_key_residual.py` (runs in the required **SIGIL governor
gates (P7 — offense gate + authn)** CI job, which executes the whole `apps/sigil/tests/` directory):

- a test that **FAILS on a tree without this change** — the sharpened concession + decision sentences do not
  exist in `HA-PROFILE.md` and this decision record does not exist pre-W8-5, so the doc assertions fail there;
- a **code-truth** test — an owner-signed head verifies under the 1-of-1 owner root, and a passive's own
  per-host key root does NOT verify it (so the concession is true of the head path, not just documented);
- a live **`trust_root` is 1-of-1** test (single owner authorizer);
- a **negative control that proves the code-truth check is not a no-op** — a synthetic 2-of-2 head root (two
  distinct per-host keys, i.e. what a *silently-introduced* per-host multi-key head would look like) makes the
  "single-owner head root" predicate return **False**, so the predicate would catch such a regression;
- a **delegation-machinery negative control** asserted in the same run — `verify_delegation` refuses an
  out-of-scope / out-of-role / expired grant (a host signing outside its delegation is refused), on the
  offense surface it actually governs.

## Honest scope (do not overclaim)

- This issue **documents and defers**; it does **not** ship per-host head delegation. AC3 ("a per-host key
  can sign only what it is delegated, with a negative control") is gated in the issue on *"IF delegation is
  implemented"* — it is not, for the head, so the AC3 assertion here is against the **existing offense-plane**
  delegation machinery that would be the reuse candidate, clearly labelled as such.
- The all-keys-compromised case (an attacker holding the owner key, on any hot passive) is **not** closed by
  anything in this issue and cannot be closed by code — it is the irreducible custody limit the HA profile
  states throughout (§3, §4). Per-host keys would narrow, not close, its cross-surface reach — and not at all
  on the head surface.

## Registration

Register the claim id `W8-5` in `docs/claims/registry.json`, matching the guard's schema
(`enforced_by` → `apps/sigil/sigil/spine/checkpoint.py:trust_root`, `proved_by` →
`apps/sigil/tests/test_ha_shared_owner_key_residual.py`). The registered-claim marker sits at the
Registered-claim block above; `HA-PROFILE.md` §4 states the same concession in prose and links here.
