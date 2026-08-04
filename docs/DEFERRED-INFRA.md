# Deferred infrastructure + moonshots — activation runbook

This document tracks the operator's **deferred infrastructure and moonshots**: capabilities where the
*software layer* is built and tested now, but full activation waits on external infrastructure, hardware,
or research. Each section states — honestly — what is **[BUILT]** today, what remains gated, and the exact
steps to activate when the missing piece lands.

Status tags used below:

| Tag | Meaning |
|-----|---------|
| `[BUILT]` | Runs today. Software layer + a working fallback path, with tests. |
| `[SCAFFOLD]` | Interface/contract only. Compiles, is tested for shape, but wires no runtime. |
| `[hardware-gated]` | Blocked on physical hardware (confidential-computing silicon). Stub raises. |
| `[research-gated]` | Blocked on an unbuilt research engine (a CRS / next-gen body). Stub raises. |

**Invariants that hold across every item here** (do not relax on activation):
- **Determinism** — the projection/quote-body layers use no wallclock and no RNG on the hot path.
- **Oracle authority** — nothing in these modules mints a fact, promotes a lead, or grants a tier. X2
  proves a fix **by oracle silence only**, never by assertion.
- **FATAL-2 (offense side)** — these modules import nothing sovereign; they live under the offense engine.
- **Honesty** — the software fallbacks are labelled as fallbacks; the hardware/research parts are stubs
  that raise `NotImplementedError`. No capability is overclaimed.

---

## G1 — embedded graph store (spine projection)

**Module:** `engine/crucible/framework/v2/graph/store.py`
**Tests:** `framework/v2/graph/tests/test_store.py`

### [BUILT] now
An embedded, **file-backed** graph store (`EmbeddedGraphStore`) that needs no external database. It
projects the append-only event spine (`agents/blackboard.py`'s `BlackboardEventRow` shape) into
nodes/edges via `project_from_spine(events, partition=...)`:
- Nodes for events + the agents that posted them; edges for `parent` / `supersedes` / `posted`.
- **One-way projection** — a pure function of the passed event list. Same events in → byte-identical
  partition file out (canonical JSON, sorted). No wallclock, no RNG.
- **Never read back into an authority.** The store has no promote/grant/tier/authorize method, by design.
  A partition is rebuildable, disposable state; dropping it loses no authority (the spine is untouched).
- **Per-session partitions** — mirrors `console/sessions.py`'s per-session model; partitions are isolated.

Use it today via `open_graph_store(base_dir)`.

### [BUILT client body — deploy-gated] a running property-graph database (Neo4j) — H2
`Neo4jGraphStore` is now a **real, reviewable client body** behind the **same interface** (TRUTHENOVATION
H2). `project_from_spine` / `nodes` / `edges` / `drop_partition` / `partitions` issue idempotent
`MERGE` / `DETACH DELETE` Cypher over the SAME pure `project_events` core the embedded store uses, scoped by
a per-partition label (module-level `_tx_rebuild` / `_tx_nodes` / `_tx_edges` transaction bodies). Its
SHAPE is covered over a fake driver in `framework/v2/graph/tests/test_neo4j_client_body.py`; the pure
projection stays covered by the embedded test.

**What is still gated (the honest *deploy* residual):** the `neo4j` driver package and a running Neo4j
service are **both ABSENT** in this environment. Constructing a LIVE store (no injected driver) imports
`neo4j` lazily and raises a clear `NotImplementedError` until installed; the live parity test
(`test_live_neo4j_round_trip`) is behind a **LOUD skip**.

**Activate (deploy) when a Neo4j — or bolt-compatible — service is provisioned:**
1. Provision Neo4j; export `NEO4J_URI` / `NEO4J_AUTH`.
2. `pip install neo4j` into the offense venv.
3. `open_graph_store` stays the default (embedded); switch a call site to
   `Neo4jGraphStore(os.environ["NEO4J_URI"], auth=(...))` — no other call-site edits. Set `NEO4J_URI` and
   run the loud-skipped `test_live_neo4j_round_trip` to confirm on-service parity.
4. The one-way invariant is unchanged: still projection-only, still no authority surface, still never
   touches the spine (`drop_partition` is `MATCH (n:`part_<partition>`) DETACH DELETE n`).

---

## X1 — attestation interface + software/TPM fallback

**Module:** `engine/crucible/framework/v2/attest/provider.py`
**Tests:** `framework/v2/attest/tests/test_provider.py`

### [BUILT] now
`SoftwareAttestationProvider` — a pure-software Ed25519 signer (via `vigil_core.crypto`) that produces a
signed `AttestationQuote` over a payload's digest and verifies it. Runs anywhere, no special hardware.

**Honest scope:** the software quote proves **integrity** (a changed payload fails `verify`) and
**origin** (a valid signature = the key-holder produced it). It does **NOT** prove **hardware
confidentiality or platform state** — there is no TEE measurement. A software key is readable by anyone
with host access; `verify` only establishes internal consistency + origin. A real trust decision still
requires pinning the signer key **out-of-band** (same discipline as `evidence.certify` trust-root
fingerprints). The quote's `hardware_backed` field is always `False` for this backend.

### [hardware-gated] gated: confidential-computing hardware
`SevSnpAttestationProvider` (AMD SEV-SNP) and `TdxAttestationProvider` (Intel TDX) exist behind the same
interface; constructing either raises `NotImplementedError`.

**Activate when confidential-computing hardware is available:**
1. Run inside an SEV-SNP guest (or TDX TD) on capable silicon.
2. Obtain the signed hardware report (SEV-SNP: `/dev/sev-guest` ioctl; TDX: TDREPORT → QE quote), placing
   the payload digest in `REPORT_DATA` / `REPORTDATA`.
3. Implement `attest` to return a quote carrying the report + cert chain (VCEK for SNP; DCAP/QVL for TDX).
4. Implement `verify` to check the report signature against the vendor root and match the digest.
5. Set `hardware_backed=True` **only** when a genuine hardware report verifies — never for the software
   path.

---

## X2 — binary / memory-safety auto-patch tier

**Module:** `engine/crucible/framework/v2/remediation_binary/tier.py`
**Tests:** `framework/v2/remediation_binary/tests/test_tier.py`

### [BUILT] now — one working narrow path
`SanitizerSilenceTier` drives the **existing** `verify.oracles.sanitizer_signal_oracle` (it does not
reimplement crash detection) to:
- `confirm_crash(crash)` — confirm a captured crash's signature (ASAN/UBSAN/MSAN/TSAN, glibc abort,
  Rust/Go panic, signal, Python traceback).
- `remediated_if_silent(before, after)` — the **A6a "earned by oracle silence"** pattern. Returns `True`
  **only** when the sanitizer oracle **fired** on the pre-fix output and goes **silent** on the post-fix
  output. A crash that never reproduced before the fix returns `False` (nothing to earn); a crash still
  firing after returns `False`. **A fix is proven by silence, never asserted.**

### [BUILT — narrow] a REAL ASan-grounded crash-confirm + pattern patch-synthesis + fix-by-silence (R3)
`remediation_binary/asan_repair.py` (TRUTHENOVATION R3, #231) wires the end-to-end loop over the present
toolchain (`gcc -fsanitize=address`): compile → run a crashing input → crash-confirm via the existing
`sanitizer_signal_oracle` → **pattern-synthesise** a patch → recompile → accept ONLY on sanitizer SILENCE
(`remediated_if_silent`) AND functional preservation. The synthesiser is real for ONE narrow class —
unbounded `strcpy(dst, src)` into a fixed `char dst[N]` → bounded `strncpy(dst, src, N-1); dst[N-1]='\0'`.
An unrecognised class returns `SYNTHESIS_UNAVAILABLE` — the crash is confirmed but **no patch is fabricated**.

### [research-gated] gated: GENERAL automated patch synthesis (a cyber-reasoning system)
The **general** generative step — localise an ARBITRARY faulting instruction by symbolic/concolic execution
and emit a patch — is **not built** (the engine, e.g. angr, is **absent from this environment**).
`SanitizerSilenceTier.synthesize_patch` raises `NotImplementedError` (its interface is output-based, distinct
from the source-based narrow synthesiser above), and `SymbolicCrashRepairTier` is a full stub behind the same
interface.

**Activate when the CRS/symbolic engine lands:**
1. Integrate a symbolic/concolic engine (e.g. angr) + a fuzzer harness for the target binary.
2. Implement `synthesize_patch` to localise the fault and emit a candidate diff.
3. Re-run the target under sanitizers on the candidate and gate acceptance on
   `SanitizerSilenceTier().remediated_if_silent(before, after)` — silence, never assertion. The oracle
   stays the sole authority for "is it fixed".

---

## X3 — pluggable agent-body interface

**Module:** `engine/crucible/framework/v2/agent_body/interface.py`
**Tests:** `framework/v2/agent_body/tests/test_interface.py`

### [SCAFFOLD — research-gated] now
An **interface only** — no behaviour change, no runtime wired. `AgentBody` (abstract) formalizes the
`think → propose → gate → execute → learn` loop and the contract a next-gen body must satisfy:
1. **Nothing self-authorizes** — every proposed action passes the conjunctive gate before execution. The
   concrete `run_cycle` template method enforces this structurally: `execute` is unreachable unless
   `gate` returned `authorized=True`.
2. **The oracle is the sole authority** — a body proposes and acts; it never mints a fact, promotes a
   lead, or grants a tier. Learning may re-rank/defer only.
3. **Fail-closed** — an absent/ambiguous gate decision is a DENY (`GateDecision()` defaults to denied).

The current production body (the Strix-based tool-runtime) is named as **one implementation** of this
contract; it already routes actions through the conjunctive gate.

**Activate when a next-gen body is built:**
1. Subclass `AgentBody`; implement `think/propose/gate/execute/learn`.
2. In `gate`, delegate to the **actual** gate-of-record (never decide authorization in the body).
3. Keep `run_cycle` (or, if overriding, preserve gate-before-execute) so the invariant is inherited.
4. Do not add any fact-minting / tier-granting to the body — the oracle remains sole authority.

---

## H3 — field record (recall on diverse real targets)

**Runbook:** `docs/H3-FIELD-RECORD-RUNBOOK.md`
**Harness:** `engine/crucible/framework/v2/eval/recall_baseline.py` (+ `eval/gate.py`, CI-gated)

### [BUILT] now — the mechanism, NOT the record
The M1 recall harness measures the **deterministic scanner's** recall/precision/FN on a **planted loopback
corpus** — a signed, byte-reproducible, offline-verifiable accuracy-core baseline with a recall-floor gate.
The accrual runbook defines the exact bar an engagement must clear to count as a field-record entry
(authorized + in-scope, real external target, oracle-confirmed, independently re-verifiable via an H4
package, misses counted, PII-minimized).

### [social-gated] the field record itself
A genuine field record — VIGIL finding real bugs on **diverse authorized real targets** — **accrues only
over real authorized engagements**. It is **not manufacturable in a lab**, and this repo does **not** claim
one exists. Until entries accrue, the honest state is: deterministic-scanner recall is MEASURED (M1) on a
*planted* corpus; LLM-`engage` recall on diverse real targets is the **open piece**. Accrue entries per the
runbook; state the field record and the planted-corpus number **separately** (they measure different
things); never word an accruing record as completeness.

---

## H4 — reproducible external-audit package

**Module:** `engine/crucible/framework/v2/evidence/audit_package.py`
(standalone verifier: `evidence/audit_offline_verifier.py`, shipped as `verify_offline.py`)
**Tests:** `framework/v2/evidence/tests/test_audit_package.py`

### [BUILT] now
`build_audit_package` / `write_package` assemble a **self-contained** external-audit package from
oracle-confirmed findings, reusing the evidence layer verbatim (`build_certificate` / `sign_certificate` /
`build_chain` / `sign_head`) — no new crypto. The package bundles the signed evidence
(`evidence-bundle.json` + `contexts.json` + `trust-root.json` + `TRUST-ROOT-FINGERPRINT.txt` +
`reverifiable.json`), the raw executor-captured `evidence/` tree, the scope/charter, a runbook
(`RUNBOOK.md`), and a **standalone `verify_offline.py`** that imports **nothing from `framework`/`vigil`**
(stdlib + `cryptography` only). An external team re-verifies OFFLINE:

    python3 verify_offline.py --package . --trust-root-fingerprint <fingerprint pinned OUT-OF-BAND>

Exit 0 iff every certificate is authentic (m-of-n Ed25519), bound (oracle_context ↔ digest), its raw
artifacts re-hash, and the chain anchors the exact certificate set. A single flipped byte anywhere → NOT
SOUND (the tests exercise flipped signature, altered oracle_context, mutated artifact, deleted chain entry,
wrong fingerprint pin).

### the honest residual
1. **Reproduction is deploy-external, not standalone.** `verify_offline.py` proves authenticity + binding +
   integrity + chain with **no VIGIL runtime**; it does NOT re-fire the oracle to re-derive each verdict
   (that needs the oracle's code — the open-source VIGIL verifier `python3 -m framework.v2 evidence verify`,
   documented as Step 2 in the package runbook). So after Step 1 you still trust the signer's honesty about
   each verdict; Step 2 removes that.
2. **The audit itself needs an external team.** We **prepare** a reproducible package; VIGIL cannot **be**
   the independent third party. That conclusion is the auditor's to write.
