# VIGIL — as-built reference

The authoritative map of what is **merged and green** on `main`, the security properties each
piece actually enforces (stated honestly — conditional where the guarantee is conditional), and
what remains blocked on infrastructure. Companion to [PLAN.md](PLAN.md) (the design) and
[CONTINUATION.md](CONTINUATION.md) (resume-here). When this doc and the code disagree, the code and
its tests win — update this doc.

> One rule underpins everything: **a claim is a FACT only when a deterministic oracle fires over
> data a real target produced.** The LLM proposes; the oracle confirms; the signature attests; the
> gates constrain. Nothing else promotes a claim to a fact.

---

## 1. Architecture in one paragraph

One monorepo, one CLI, one signed spine, **two isolated process/trust domains** joined only by an
inert, signed, no-code data seam. `packages/core/vigil_core` is the shared Ed25519 signed
hash-chain substrate (imports neither `framework.*` nor `strix.*`, so `assert_no_offense()` stays
sound). **env-sovereign** = `vigil_core` + SIGIL (offense-free by construction). **env-offense** =
`vigil_core` + CRUCIBLE + Strix + the gateway. Findings cross the seam as inert signed JSON. The two
FATAL flaws the design exists to fix — unbounded sandbox egress (P6) and a defeated offense-free
boundary (P3/P5/P7) — are closed.

---

## 2. What is merged (core: P0–P10 + I1; this program: I2, I4-slice, SCITT, wiring)

| Area | Module(s) | What it enforces |
|------|-----------|------------------|
| Shared crypto core | `packages/core/vigil_core` | Ed25519 sign/verify, m-of-n `verify_threshold`, canonical JSON + domain-separated evidence bytes (`crucible-evidence-v1\0`, unchanged = signature-compatible). **Rejects non-canonical (y≥p) and low-order Ed25519 public keys** at `load_public_key` — closes a keyless forgery (`R=identity,S=0` verifies for any message) against *every* threshold check. |
| Host egress gate (P6) | `gateway/vigil_gateway` | Deny-default nftables + L7 scope-proxy on the sandbox's own docker net; the sandbox's only route out is the charter-scoped proxy. Metadata/RFC1918/link-local + IPv4-mapped/6to4/NAT64 unwrap, DNS-rebinding + TOCTOU safe. NET_ADMIN dropped. |
| Inert seam (P5) | `integration/vigil_integration/inert_finding.py`, `offense_worker.py` | Findings cross as validated, signature-checked inert data; the offense worker holds **no owner key**. |
| WARDEN tool gate (P7) | `warden_gate.py`, `apps/sigil/sigil/governor/*` | Tool-class tier gate (raise-only A2 floor → auto/queue/deny); offense-gate open is owner-signed, charter-bound, auto-expiring, anti-replay. |
| Conjunctive governance (P7 + I4 wiring) | `conjunctive_gate.py` | Every target-touching action passes **CRUCIBLE-authority AND WARDEN**; a **destructive** action additionally passes the **threshold-destruction** conjunct. First failure wins; any error is a DENY. |
| Oracle confirmation (P9) | `oracle_adapter.py` | An LLM-proposed finding becomes a signed FACT only if CRUCIBLE's deterministic oracle **fires** over the retained context AND the class is oracle-mapped; else an honest labelled **lead**. |
| Sovereign ingest (P10) | `apps/sigil/sigil/inbound/finding_receiver.py` | Two-anchor: verify the CRUCIBLE m-of-n governance signature, then append `kind="finding"` to the owner-signed spine. Loads no offense engine. |
| I1 — challenge oracles | `challenge_oracle.py` | Per-run randomized challenge (nonce/canary/OOB-token/value-control) makes replay/hallucination **structurally** impossible; kernel-minted `Verified\|Abstain` HMAC an LLM cannot forge. |
| I2 — transparency log | `transparency.py` | Witnessed, split-view-resistant checkpoint chain over the signed spine head (details §4). |
| I4-slice — threshold destruction | `destruction_gate.py` | m-of-n, owner-mandatory, action-bound, dead-man's-switch, single-use authorization for irreversible actions (details §3). |
| SCITT/OpenVEX certs | `scitt.py` | Offline-verifiable-forever finding certificates: OpenVEX vocab + DSSE m-of-n + RFC-6962 Merkle inclusion receipt anchored to an I2 witnessed checkpoint (details §5). |

---

## 3. The threshold-destruction gate (`destruction_gate.py`)

The last line before an autonomous, prompt-injectable worker performs an **irreversible** action.
On top of the conjunctive gate, a destructive/high-blast action requires a quorum-signed
`DestructionAuthorization`, fail-closed on:

1. **m-of-n threshold** via `verify_threshold` (distinct trusted authorizers). This is the RFC-9591
   *m-of-n authorization property*; true FROST single-signature aggregation is a deferred size
   refinement, not a security change.
2. **Mandatory owner** — the mandatory signer set is bound into an **immutable** deployment-time
   `DestructionAuthority(trust_root, mandatory_signer_ids)`, *not* a per-call string. A
   worker+policy quorum without the owner authorizes nothing (the worker is itself a registered
   authorizer, so a free `owner_key_id` would let it self-authorize).
3. **Action binding** — the authorization names the exact `(engagement, target, blast_class,
   action_id)`. `action_id`→command binding lives with the signer (the gate never sees the command).
4. **Dead-man's-switch** — a policy-capped validity window; a long-lived pre-signed *sleeper* is void.
5. **Single-use** — one nonce, `is_consumed` **required** (no fail-open default); the caller commits
   consumption atomically to the spine.

Wired into `conjunctive_gate.build_offense_gate`, which cross-binds `(slug, target_url)` to the
quorum-signed action's target/engagement (else DENY).

---

## 4. The transparency log (`transparency.py`)

A third party can trust the log **without trusting its operator**.

- **Checkpoint** = a public, domain-separated (`vigil-transparency-checkpoint-v1\0`) summary of the
  signed spine head (`last_seq`, absolute `entry_count`, `head_hash`, `cumulative_merkle_root`) +
  link to the prior checkpoint.
- **`consistent` / `Witness.cosign`** — a witness countersigns a checkpoint only after verifying it
  is an append-only extension of its own tracked tip; it refuses (raises) on any inconsistency, so
  an honest witness never equivocates.
- **Split-view resistance is CONDITIONAL** (this is the honest framing): it holds only under a
  **strict majority of DISTINCT, canonical keys** (`2·threshold > n`, `is_split_view_resistant`).
  Below that (incl. the blessed `threshold==1` with n>1) two disjoint quorums can each sign a
  different fork with no witness equivocating — only detection + per-witness non-equivocation remain.
  `verify_witnessed` proves a quorum signed; `verify_split_view_resistant` additionally proves the
  set is strict-majority-of-distinct-keys.
- **`is_split`** keys on `head_hash` (a fork = a *different head* at the same size). A same-head
  `merkle_root` difference is a prune-boundary difference, authenticated by the signed head/archive —
  not a fork this primitive adjudicates.
- **`CheckpointEmitter`** turns a stream of signed heads into a linked, witness-countersigned chain:
  idempotent on unchanged position, atomically gathers only the willing witnesses (a dissenter is
  skipped, never bricks the chain), dedups by key_id. The caller checks quorum and halts on a
  dissenting quorum.

Deferred: OpenTimestamps Bitcoin anchoring of a checkpoint hash (needs a live calendar server).

---

## 5. Offline-verifiable certificates (`scitt.py`)

An oracle-confirmed finding → a certificate a client / regulator / court verifies **offline and
forever**:

- **OpenVEX** finding vocabulary (portable). Honesty invariant: a confirmed finding is `affected`;
  a lead is `under_investigation` — never asserted affected.
- **DSSE Signed Statement** — m-of-n governance signature over the OpenVEX payload via the DSSE PAE,
  domain-separated from raw evidence signatures.
- **RFC-6962 Merkle transparency log** + **Receipt** with a real inclusion proof. `verify_receipt`
  requires a caller-**pinned** `expected_root` (a receipt carries its own root — pinning is what
  makes inclusion mean "in *the* log"). `verify_anchored_receipt` pins that root to an I2
  witnessed checkpoint.
- **Bridge:** `mint_finding_statement` (pure) and `oracle_adapter.certify_to_scitt` connect the P9
  confirmed-fact pipeline to a registered, offline-verifiable statement (a lead is refused).

Deferred: full COSE_Sign1/CBOR encoding; a dedicated SCITT-registrar receipt (this uses the
governance root + I2 witnesses, which is stronger).

---

## 6. End-to-end pipeline (all merged)

```
propose (Claude+Strix)
  → oracle-confirm (P9, oracle FIRES or it stays a lead)
  → sign proof-carrying certificate (m-of-n governance root)
  → SCITT statement  (OpenVEX + DSSE, offline-verifiable)          [certify_to_scitt]
  → transparency log (RFC-6962 Merkle) + inclusion receipt         [StatementLog]
  → witnessed checkpoint chain (split-view-resistant)              [CheckpointEmitter]
  → inert signed JSON crosses the seam → owner-signed spine (P10)  [finding_receiver]

governance on every target-touching action:
  CRUCIBLE authority  AND  WARDEN tier  AND  (if destructive) m-of-n threshold-destruction
```

---

## 7. Review discipline

Every merge went through: build production code → **independent red-pen** in an isolated clone →
fix → **adversarial re-check on the fixed branch** → PR → all CI green → merge. The re-check on the
fixed branch is load-bearing — it repeatedly surfaced the *next* defect one level deeper (e.g. the
I2 chain: conditional-majority → distinct-key → base64-malleable → **low-order keyless forgery**;
the emitter chain: no-progress false-fork → non-atomic brick → **honest-prune false is_split**).
CI = 6 jobs: `vigil_core`, `CRUCIBLE-core`, `gateway`, `integration` (two runs: sovereign, then the
framework-dependent oracle-adapter in its own process), `strix`, `sigil-governor`.

---

## 8. Blocked on infrastructure (the headline moonshot)

Not fakeable without the environment; awaiting the owner's setup:

- **I3 — Claude-Agent-SDK-native agent body.** Port Strix's Kali execution (welded to
  `openai-agents`) to the Claude Agent SDK, re-exposing Kali tools as in-process MCP servers.
  Needs `claude-agent-sdk` + a live Kali container. (A multi-week sandbox-layer rebuild.)
- **I4-TEE — attested sovereign agent.** Intel TDX / AMD SEV-SNP + Anthropic Confidential Inference,
  attestation-gated key release. Needs TEE hardware. (The threshold-destruction *governance* half of
  I4 is done, §3.)
- **I5 — AIxCC binary / auto-patch tier.** LLM-guided fuzzing + concolic/SMT (angr/Z3) +
  sanitizer-oracle + patch re-verification. Needs Z3/angr + fuzzing infra. (Study ToB "Buttercup".)

Also deferred (need a live target/service): P9 live scope-gated re-drive + the extended Strix
finding contract; OpenTimestamps anchoring.
