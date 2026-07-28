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

## 2.1 This session's merges (UI wiring, dossier, report how-to, graph store, moonshot scaffolds)

Merged and green on `main` in the current program (see `git log` and `docs/DEFERRED-INFRA.md`):

| Area | Module(s) | What it is |
|------|-----------|------------|
| Embedded graph store (G1) | `engine/crucible/framework/v2/graph/store.py` | `EmbeddedGraphStore` — a file-backed, **one-way** projection of the append-only spine into nodes/edges (canonical JSON, no wallclock/RNG, byte-identical out for identical events in). No promote/grant/tier surface: a partition is disposable state, never an authority. `Neo4jGraphStore` sits behind the same interface as a `[SCAFFOLD]` (every method raises) — only the live external service is deferred. |
| Moonshot scaffolds (X1/X2/X3) | `framework/v2/attest/provider.py`, `remediation_binary/tier.py`, `agent_body/interface.py` | `SoftwareAttestationProvider` (a working Ed25519/TPM quote proving integrity + origin, `hardware_backed=False`; SEV-SNP/TDX stubs raise — hardware-gated); `SanitizerSilenceTier` (crash-confirm + `remediated_if_silent` fix-by-oracle-silence over the **existing** sanitizer oracle work; `synthesize_patch` raises — research-gated); `AgentBody` (an interface-only contract, gate-before-execute structurally enforced — research-gated). Honest status matrix in `docs/DEFERRED-INFRA.md`. |
| Report how-to (R1) | `engine/crucible/framework/v2/report/howto.py`, `export.py` | A deterministic per-finding **"how to verify / test / patch"** block (a pure function of the graded finding — no traffic, no RNG). A FACT points at the real re-executable `python3 -m framework.v2 verify` over its retained `reverifiable.json`; a LEAD says "how to CONFIRM" and never implies proof. Woven into the report **and** the SARIF 2.1.0 / structured-JSON export (a LEAD capped at `note` so it never blocks a CI gate). |
| One-click dossier (R2/R3) | `report/dossier.py`, `integration/vigil_integration/cli.py` (`vigil dossier`), `framework/v2/console/server.py` (`POST /api/dossier/<run>/build`, `GET /api/dossier/<run>.zip`) | Compiles a whole run into ONE self-contained, tamper-evident `.zip` (reusing the report renderers + lazily the proof bundle) with an out-of-band-pinnable fingerprint. The GET route **streams a pre-built** file only (building is the CSRF-guarded POST); a bad run id fails closed. This is the **first real client download**. Red-pen fixes on merge: stop an evidence-symlink exfil; scrub secrets inside lists. |
| UI wiring (U0/U1/U2) | `packages/vigil-ui/app.js`, `console/server.py` | New-Assessment **cloud/K8s posture launch** (`actions.launch_cloud`); the **actionable Fixes** screen ("Apply fix (gated)" → `actions.apply_fix` shells `vigil patch`, never `--open-pr`, with an honest provenance pre-check so it's never inert-misleading); the Knowledge screen's **"Pull now"** one-shot feed refresh + **"Draft skills (deep-learn)"** (`/api/knowledge/<slug>/deeplearn`). |
| Live L1 error-based SQLi | `framework/v2/verify/oracles.py` (`error_signature_oracle`, `ERROR_SIGNATURE`) | `error_based_sqli` routes to the `error_signature` oracle first; over the loopback app it minted a real FACT **re-verified 3/3 offline with no Caido/Docker** (the first-party executor captured the datastore-error bytes). `targets/testphp/charter.md` provisions the byte-identical **external** run (needs network egress). |

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

## 8. Moonshots — now SCAFFOLDED (not merely blocked)

Each moonshot now has a **built, tested interface** with a working software fallback/narrow path;
only the hardware/research frontier behind it is stubbed (the stub raises — no capability is
overclaimed). The honest per-item activation runbook is [`DEFERRED-INFRA.md`](DEFERRED-INFRA.md).

- **Agent body (X3, was I3).** `agent_body/interface.py` — an interface-only `AgentBody` contract
  that formalizes `think → propose → gate → execute → learn` and structurally enforces
  gate-before-execute (`execute` unreachable unless the gate authorized). The production Strix
  tool-runtime is named as one implementation. **`[SCAFFOLD — research-gated]`**: a next-gen body
  (e.g. porting Strix's Kali execution to the Claude Agent SDK with in-process MCP servers) still
  needs `claude-agent-sdk` + a live Kali container.
- **Attestation (X1, was I4-TEE).** `attest/provider.py` — `SoftwareAttestationProvider` works today
  (Ed25519 quote proving integrity + origin; `hardware_backed=False` always; a software key is
  readable, so a real trust decision still pins the signer out-of-band). **`[hardware-gated]`**:
  `SevSnpAttestationProvider` / `TdxAttestationProvider` raise until confidential-computing silicon +
  Confidential Inference are present. (The threshold-destruction *governance* half of I4 is done, §3.)
- **Binary / memory-safety auto-patch (X2, was I5).** `remediation_binary/tier.py` —
  `SanitizerSilenceTier` drives the **existing** `sanitizer_signal_oracle` to `confirm_crash` and to
  earn `remediated_if_silent` (the A6a "proven by oracle silence, never asserted" pattern). **`[research-gated]`**:
  `synthesize_patch` raises and `SymbolicCrashRepairTier` is a full stub — the generative localise-and-patch
  step (a CRS: LLM-guided fuzzing + concolic/SMT, angr/Z3) is unbuilt. (Study ToB "Buttercup".)

Also still deferred (need a live target/external service): a running **external** Neo4j/OTLP service
(the embedded file-backed graph store, §2.1, is built); the live-API-key Claude think-step (keyless
replay used today); a live **external**, network-egress engagement + the extended Strix finding
contract (the loopback live-fire already executed real tools and minted + re-verified a real FACT —
`targets/testphp/charter.md` provisions the external run); a per-action cryptographic approval token;
OpenTimestamps anchoring.
