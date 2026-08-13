# Inventory C — Architecture and Parts

**Status:** technical inventory for downstream writers. Not lay-reader prose.
**Method:** every entry below was read from source under `/home/kali/vigil` in this pass. Paths are
repo-relative. Where a statement comes from a project doc rather than from code I read, it is tagged
`[doc-claim]`. Where I did not verify something, it is tagged `[NOT VERIFIED]`.
**Repo state at inventory time:** branch `main`, HEAD **`1487e03a`** ("Merge pull request #293 from
thuram-nana/e4-tier2-verb-grant"). A second worktree at `/home/kali/vigil-wt-a14` holds branch
`a14-supply-chain` with today's in-flight supply-chain work (§1.11).

> **Note for writers on numbers.** Several counts in `README.md` / `docs/FEATURES.md` are stale at this
> commit (README says CRUCIBLE has "25+ subcommands" — the dispatch table has **31**; FEATURES.md says
> `OracleKind` has 32 members — the code has **38**). Take counts from this file or re-derive them, not
> from the marketing docs.

---

## 1. The named components

### 1.0 One-line map

| Name | What it is for | Where it lives |
|---|---|---|
| **VIGIL** | The whole monorepo/product: one control plane over two isolated trust domains | `/home/kali/vigil` (repo root) |
| **vigil_core** | Shared signed-integrity substrate both halves stand on | `packages/core/vigil_core/vigil_core/` |
| **CRUCIBLE** | The offensive engine (prove-don't-guess scanner/engagement engine) | `engine/crucible/` (Python package `framework.v2`) |
| **AEGIS** | The defensive dual — the same oracle core pointed inward | `engine/crucible/framework/v2/aegis/` + `.../defender/` + `integration/vigil_integration/detection/` |
| **SIGIL** | The sovereign / personal assistant side, offense-free by construction | `apps/sigil/` (Python package `sigil`) + Rust kernel `apps/sigil/kernel/` |
| **STRIX** | Vendored third-party agentic pentest tool (Apache-2.0), used as a proposing agent | `vendor/strix/` |
| **integration** | The "fusion body": reasoning loop, gates, oracle bridge, live engine, the `vigil` CLI | `integration/vigil_integration/` |
| **gateway** | Host egress gate (deny-by-default firewall + scope-checking proxy) | `gateway/vigil_gateway/` |
| **UI** | The unified no-build web UI assets | `packages/vigil-ui/` |
| **formal** | TLA⁺ machine-checked models of the four core invariants | `formal/` |

Other top-level dirs verified present: `docs/`, `envs/`, `infra/`, `knowledge/`, `targets/`, `tools/`,
`scratch-demo/`, `vendor/hexstrike-ai/`, `bootstrap.sh`, `docker-compose.yml`, `Makefile`,
`LICENSE` + `LICENSE-COMMERCIAL.md`, `.venv-offense/`, `.venv-sovereign/`.

---

### 1.1 VIGIL — the whole

VIGIL is a single git monorepo containing both an offensive security engine and a personal AI
assistant, deliberately split into **two isolated Python environments** that never share an
interpreter (§2). Its stated governing rule, repeated in code docstrings and `README.md`:

> The AI and every tool only PROPOSE. Only a deterministic oracle mints a signed FACT. Only the
> conjunctive gate authorizes an action. Only the egress gate lets a packet leave.

**Command surface.** One super-CLI, `vigil`, plus per-subsystem consoles. Verified from each
`pyproject.toml` `[project.scripts]` block:

| Console script | Entry point | Package |
|---|---|---|
| `vigil` | `vigil_integration.cli:main` | `integration/` |
| `sigil` | `sigil.cli:main` | `apps/sigil/` |
| `crucible` | `framework.v2.__main__:main` | `engine/crucible/` |
| `aegis` | `framework.v2.aegis.cli:main` | `engine/crucible/` |
| `vigil-gateway` | `vigil_gateway.cli:main` | `gateway/` |
| `strix` | `strix.interface.main:main` | `vendor/strix/` (third party) |

`vigil` native subcommands — **33 parsers**, mechanically extracted from `add_parser(...)` in
`integration/vigil_integration/cli.py`:
`engage`, `engage-instruct`, `ledger`, `verify-ledger`, `verify`, `provision`, `identity`, `patch`,
`remediate`, `reprove`, `witness`, `provision-destruction`, `authorize-destruction`, `approve`,
`provision-authority`, `list`, `sign`, `proof-export`, `dossier`, `detect`, `up`, `services`
(`up`/`status`/`down`/`render`), `doctor`, `telemetry`, `down`, `knowledge`, `learn-drain`,
`terminal`, `sandbox`.

`vigil` also **passthrough-dispatches** to the other consoles via
`integration/vigil_integration/dispatch.py`. Its `_ENV` table is the routing authority, read verbatim:

```python
_ENV = {
    "sigil":    ("sovereign", "sigil"),
    "crucible": ("offense",   "crucible"),        # the raw CRUCIBLE arsenal
    "aegis":    ("offense",   "aegis"),           # the defensive dual
    "strix":    ("offense",   "strix"),           # the agent body
    "gateway":  ("offense",   "vigil-gateway"),   # the host egress gate
}
```

`dispatch.py` is pure stdlib and exec-only — it imports neither `framework`/`strix` nor `sigil`,
resolves a *hardcoded* verb→environment map, then `subprocess.run`s the console script inside the
correct venv. This is how one command surface exists without ever co-loading the two trust domains.

CRUCIBLE's own dispatch table (`engine/crucible/framework/v2/__main__.py::_DISPATCH`) has **31**
subcommands: `intake, memory, intel, knowledge, kernel, entitlement, eval, improve, defender,
analysis, authority, socialdefense, scan, engage, plan, verify, plan-integrity, drift, capabilities,
aegis, evidence, report, attack-paths, collaborator, benchmark, calibration, console, mcp, api,
imports, status`. Its own docstring states the design rule: "Subcommands are registered explicitly
here so the operator sees the full surface in one read… the dispatch table is the contract."

`sigil` subcommands (from `apps/sigil/sigil/cli.py`): `doctor, vault, kernel, backup, restore,
ingest, index, sign, search, graph, consolidate, warden-anchor-set, warden-anchor-get, agents,
voice, warden, capability, gesture-nav, delegate-offense, audit, dashboard, budget, verify, status,
settings, inbound, knowledge, owner-pubkey, floor, spine, checkpoint, serve, host, mesh, bridge,
scrape`.

---

### 1.2 vigil_core — the shared signed core

**Location:** `packages/core/vigil_core/vigil_core/`
**Purpose:** the shared, tamper-evident integrity substrate for the monorepo — the single source of
truth for the signed hash-chain, canonical JSON, Ed25519 (+ m-of-n threshold) crypto, and the
trust-root / chain models. It is dependency-minimal (`cryptography` + `pydantic`) and
**namespace-pure**: it imports no `framework.*`, `strix.*`, or `sigil.*`. That purity is what lets
the sovereign side share it without importing offense code.

Module inventory (19 modules, all present; purpose from each docstring):

| Module | Purpose |
|---|---|
| `chain.py` | Tamper-evident hash-linked spine chain; each `ChainEntry` hashes `(seq, prev_hash, cert_digest)`; a `SignedChainHead` anchors the log with a monotonic `last_seq` anti-rollback. Vendored verbatim from CRUCIBLE `evidence/chain.py`. |
| `crypto.py` | Ed25519 primitives + m-of-n threshold verify (pyca `cryptography`). Signing helpers are provisioning-only; **the runtime only ever verifies.** |
| `canonical.py` | Deterministic canonical bytes + digests for spine integrity (byte-stable JSON). |
| `models.py` | Shared types: `ChainEntry`, `SignedChainHead`, `TrustRoot`, `AuthorizerKey`, `Signature`, `KeyPair`, `IntegrityError`. |
| `gate.py` | **The ONE authorization-gate composition of record** (unification S6) — see below. |
| `warden_tiers.py` | **The ONE WARDEN classifier of record** — a byte-faithful Python port of the Rust kernel classifier (`apps/sigil/kernel/src/tiers.rs`), pinned to shared golden vectors. |
| `warden_golden.json` | The shared golden classification vectors that keep Rust and Python from drifting. |
| `spine_domains.py` | Registry of VIGIL's signed spine/log domains — see §3.1. |
| `keystore.py` | The one load-or-create implementation for persisted Ed25519 keypairs — `0600`, AEAD-sealed at rest when a vault is supplied, weak-key rejection, **fail-closed on a sealed-but-unopenable file** (never silently mints a new divergent identity). |
| `vault.py` | At-rest sealing of secret files under a TPM-sealed KEK (audit item G1). Shared by both envs; opt-in and non-bricking. |
| `sealing.py` | Pure AEAD (ChaCha20-Poly1305) seal/open of a byte blob given a 32-byte KEK. Holds no key custody, does no I/O. |
| `kek.py` | TPM-sealed custody of the key-encryption-key. Sealed blob is useless on another machine. |
| `highwater.py` | Durable file-backed anti-rollback high-water floor. |
| `delegation.py` | Owner-root identity delegation (unification S4) — cryptographically ties a governance root to the OWNER, closing the free-floating-key gap in the two-anchor finding seam. |
| `capability.py` | Owner-attested target IDENTITY + an attenuable re-verification CAPABILITY object, verifiable offline with `vigil_core` alone. |

**`gate.py` — the gate of record**, read verbatim from its docstring:

> Every action-bearing edge in BOTH engines authorizes through the same pure, fail-closed conjunction:
> an action ALLOWs only if the domain authority is in-envelope AND the WARDEN tool tier auto-approves
> AND (for a destructive/high-blast action) an owner-inclusive m-of-n threshold authorization is
> present. First failure wins; ANY error in ANY conjunct is a DENY (never caught-and-continued); only
> an explicit WARDEN `"auto"` may open the gate, so a new/unexpected outcome can never silently ALLOW.

Its pinned fail-closed invariants (per `tests/test_gate.py`): a raised conjunct → DENY; a **strict
`authorized is True` identity check** on the destructive conjunct (a truthy-but-not-`True` value must
NOT open an irreversible action); an unrecognised WARDEN outcome → DENY; a missing destruction gate on
a destructive action → DENY. The core imports nothing but stdlib, "so it is a leaf both envs load and
it can never drag `framework`/`strix` into the owner-key process."

---

### 1.3 CRUCIBLE — the offensive engine

**Location:** `engine/crucible/`, importable as `framework.v2`.
**What it is for:** crawl/probe an authorized target, attack inputs with real payloads, and call
something a vulnerability **only when a deterministic oracle fires** over bytes the real target
produced; then reason over proven facts to build attack paths and emit tamper-evident evidence.
Its Claude-operated persona is **OBSIDIAN** (doctrine in `engine/crucible/framework/cognitive/`).

Top-level docs present in `engine/crucible/`: `README.md`, `HOW-TO-START.md`, `AUTONOMY-CHARTER.md`,
`DISCLAIMER.md`, `ENGAGEMENT-LIFECYCLE.md`, `FORGE.md`, `SOVEREIGNTY-THREAT-MODEL.md`,
`V2-LIMITATIONS.md`, `V2-MANIFEST.md`, `SYSTEM-STATE.md`, `USAGE-GUIDE.md`, `ROADMAP-FLAGSHIP.md`,
`ROADMAP-BACKLOG.md`, `SECURITY.md`.

`framework/v2/` subsystem inventory (directories verified by listing):

| Subsystem | Role |
|---|---|
| `verify/` | **The deterministic oracle layer** — the only thing that can turn a claim into a fact. ~40 modules incl. `oracles.py`, `verifier.py`, `confirmation.py`, `reverify.py`, `replay_harness.py`, `coverage_oracle.py`, `plan_integrity.py`, `oob.py`, `collaborator.py`, plus posture/capture oracles (`cloud_posture`, `k8s_posture`, `k8s_workload_posture`, `k8s_rbac_grant`, `cicd_posture`, `mesh_posture`, `mobile_posture`, `identity_posture`, `email_auth`, `tls`, `weak_crypto`, `jwt_forgery`, `saml_forgery`, `policy_path`, `reachability`, `reachability_cloud`, `secret_capture`, `imds_capture`, `iam_escalation_capture`, `gcp_impersonation_capture`, `drift`, `poc_translate`, `oracle_version`). |
| `veracity/` | **The anti-hallucination firewall** — `firewall.py`, `claims.py`, `adapters.py`, `consistency.py`, `tokens.py`. Re-executes a claim's cited proof at every boundary. Can **only demote**, never promote. |
| `scanner/` | The active scanning arsenal (~45 modules): `engine.py`, `crawler.py`, `browser*`/`cdp.py`, `checks.py`, `graphql.py`, `jwt.py`, `race.py`, `sso.py`, `domxss.py`, `bizlogic.py`, `access_control.py`, `coverage.py`, `learning.py`, `self_improve.py`, `benchmark.py`, `library.py`, `js_lex.py`, `quantum_era.py`, `nuclei_compile.py`, etc. |
| `agents/` | **MAO — the multi-agent orchestration layer** + the append-only blackboard/event spine. §3, §4. |
| `evidence/` | Tamper-evident evidence + certificates: `chain.py`, `canonical.py`, `certify.py`, `manifest.py`, `pcf.py` (proof-carrying finding), `poc.py`, `audit_package.py`, `audit_offline_verifier.py`. |
| `worldmodel/` | **WMS — the world-model substrate** (persistent typed attack graph). §3.2. |
| `memory/` | **MLS — the memory & learning substrate** (cross-engagement priors). §5.1. |
| `intel/` | Intelligence engine: collectors, entity resolution, fusion, inference, promotion, VOI planner, `vulnfeed.py`, `from_sbom.py`. |
| `sensors/` | Universal sensors/collectors: `nmap.py`, `tls_cert.py`, `tshark.py`, `sbom.py`, `cloud.py`/`cloud_live.py`, `azure_live.py`, `gcp_live.py`, `k8s_live.py`/`k8s_runtime.py`, `cicd.py`, `mesh.py`, `identity.py`, `email_auth.py`, `mobile.py`, `android_manifest.py`, `fuzz.py`, `web_scanner.py`. |
| `aegis/` | The embeddable defensive dual (§1.4). |
| `defender/` | Detection engineering: Sigma-style `rules.py`, `sigma.py`, `logsource.py`, `telemetry.py`, `efficacy.py`, `gap_report.py`, `posture.py`, `scoring.py`. |
| `calibration/` | Calibrated exploitability scoring + outcome ledger + reward bus (§5.3). |
| `confidence/` | Belief/decision engine (`engine.py`, `decision.py`). |
| `planner/` | Goal tree, budget, pruner, watchdog, resume, seed. |
| `graph/` | Embedded **file-backed** graph store (`store.py`) — a one-way spine projection with no promote/grant/tier/authorize method by design; `Neo4jGraphStore` behind the same interface. |
| `report/` | `generate.py`, `dossier.py`, `export.py`, `howto.py` (per-finding how-to-verify), `priority.py`, `standards.py`, `grounding.py`, `push.py`. |
| `console/` | The read-only ops console + **session registry** (`sessions.py`), `chat.py`, `actions.py`, `api.py`, `server.py`. |
| `eval/` | Benchmarks + regression + recall baseline + corpora. |
| `improve/` | Self-improvement proposals + **merge gate** (§5.4). |
| `knowledge/` + `knowledge_engine/` | Knowledge catalog; deep-learn, evolve, proposals, retrieve. |
| `entitlement/` | Capability/entitlement crypto + trust root. |
| `attest/`, `authority/` | Attestation providers; authority envelope. |
| `analysis/`, `intake/`, `intruder/`, `repeater/`, `imports/`, `kernel/`, `mcp/`, `api/`, `plugins/`, `tools/`, `socialdefense/`, `remediation_binary/`, `agent_body/`, `common/`, `docs/`, `tests/` | Supporting subsystems (each verified present as a directory). |

**Oracle kinds — 38, mechanically extracted from `verify/models.py::OracleKind` with an AST parse:**

```
DIFFERENTIAL_RESPONSE ACHIEVED_STATE SIDE_EFFECT OOB_CALLBACK SANITIZER_SIGNAL TIMING
BOOLEAN_INFERENCE REFLECTION_CONTEXT EVALUATION ERROR_SIGNATURE DOM_EXECUTION
SERVICE_REACHABILITY TLS_WEAKNESS VERSION_RANGE POLICY_PATH            ← the 15 offensive core
PROMPT_INJECTION SYSTEM_PROMPT_DISCLOSURE AUTOMATED_ACCESS CREDENTIAL_STUFFING   ← AEGIS defensive
SQL_INJECTION_BREAKOUT COMMAND_INJECTION_BREAKOUT NOSQL_INJECTION_BREAKOUT       ← request-side parse-proof
K8S_POSTURE K8S_WORKLOAD_POSTURE SSO_ASSERTION_FORGERY SAML_STRUCTURAL_FORGERY
CLOUD_POSTURE MESH_POSTURE CICD_POSTURE MOBILE_POSTURE EMAIL_AUTH_POSTURE
IDENTITY_POSTURE ACTIVE_EXPOSURE
IMDS_CREDENTIAL_CAPTURE SECRET_CREDENTIAL_VALIDITY GCP_SA_IMPERSONATION
IAM_ESCALATION_PRIMITIVE K8S_RBAC_VERB_GRANT                            ← the E-series (§1.10)
```

Load-bearing structural detail, stated repeatedly in comments in `verify/models.py` and
`verify/verifier.py`: the frozen "unknown-class fallback" set `_ALL_ORACLES` stays **exactly 15** — every
later additive kind is reachable **only** via an explicit `BUG_CLASS_ORACLES` row keyed on a context
field that no scan/engage/benchmark finding carries. So appending an oracle kind can never widen what
an unclassified finding may be confirmed by, and none of the posture/E-series oracles can fire
accidentally on a normal web scan.

---

### 1.4 AEGIS — the defensive side

AEGIS is not a separate app; it is the same prove-don't-guess core pointed **inward** at the
operator's own systems. It exists in three places:

1. **`engine/crucible/framework/v2/aegis/`** — the embeddable AI-attack-detection library. Modules:
   `pipeline.py`, `guard.py`, `gateway.py`, `middleware.py`, `integrate.py`, `boundary.py`,
   `sensors.py`, `actor_graph.py`, `oob_correlator.py`, `rampart.py`, `registry.py`,
   `response_policy.py`, `inspect.py`, `models.py`, `cli.py`, `demo_app.py`, `Dockerfile`, plus
   `AEGIS-DESIGN.md` and `QUICKSTART.md`.
   As-built pipeline (`AEGIS-DESIGN.md` §2):
   `raw telemetry → boundary.ingest → sensors.observations → actor_graph.observe →
   OracleVerifier.confirm → veracity.admit → confidence.assess_finding → Verdict`.
   Two enforced invariants: `decision == "confirmed"` ⇔ a certificate exists; and
   `provenance == "grounded:…"` ⇒ an oracle fired **and** `admit()` re-admitted it as a fact.
   Confirmed classes in the MVP: `system_prompt_disclosure`, `prompt_injection`, `automated_access`,
   `credential_stuffing`. Everything else is LEAD-only or roadmap.
   **Honesty detail carried in the design doc itself:** `decision="clear"` means "no oracle fired and
   signals below band" — "which is *not* 'safe', and is documented as such."
   Reuse discipline is explicit: `verify/` never imports `aegis/`; the new oracle bodies live in
   `verify/oracles.py` to avoid an import cycle.

2. **`engine/crucible/framework/v2/defender/`** — detection engineering (Sigma-style ruleset
   matching, log-source modelling, efficacy + gap reporting). `defender/rules.py` disclaims modelling
   any specific SIEM product: the built-in ruleset is "a sensible baseline of well-known detections,
   not a claim to model any specific product."

3. **`integration/vigil_integration/detection/`** — the **Detection Mirror**. Modules: `base.py`,
   `recon.py`, `injection.py`, `credential.py`, `logs.py`, `telemetry.py`, `certificate.py`,
   `registry.py`. Verified constraints, from the package docstring:
   - A detection is a FACT only when the oracle fires over retained telemetry **and** a signed
     `DetectionCertificate` re-verifies offline (signature + evidence digest + a live oracle **re-run**
     over the embedded evidence — "proof by re-execution, not string trust"). Anything softer is a
     LEAD, "never a silent block."
   - Every oracle ships a **benign twin** (a legitimate look-alike) that MUST NOT fire. "A benign twin
     that fires is a BLOCK."
   - Oracles are pure/deterministic (windows come from the records' own ts/seq — no clock/RNG), total
     on malformed telemetry, and secret-free (evidence scrubbed before it enters a signed certificate).
   - Planes covered: **EDGE** (recon + injection over access/flow logs) and **AUTH TELEMETRY**
     (credential over `auth.log`). **The egress, directory, cloud and session planes are honest
     LEAD-only stubs** — "no ingested telemetry, no proof, stated plainly." This is in code, not just docs.

---

### 1.5 SIGIL — the sovereign / personal side

**Location:** `apps/sigil/` (package `sigil`), plus a **Rust kernel** at `apps/sigil/kernel/`.
**Purpose:** an offense-free, local-first personal assistant that remembers the operator's working
history on a signed append-only spine and can act on files, terminal, screen, web and the owner's own
accounts — every action WARDEN-tiered.

Package subsystems (verified by listing `apps/sigil/sigil/`):
`agents/`, `bridge/`, `consolidate/`, `gesture/`, `governor/`, `graph/`, `inbound/`, `ingest/`,
`knowledge/`, `mcp/`, `mesh/`, `perception/`, `platform/`, `reuse/`, `scrape/`, `spine/`, `ui/`,
`vectors/`, `voice/`, plus `audit.py`, `backup.py`, `config.py`, `dashboard.py`, `obs.py`, `cli.py`.

**The Rust WARDEN kernel** — `apps/sigil/kernel/src/` contains 11 files:
`main.rs`, `lib.rs`, `tiers.rs` (the classifier of record), `warden.rs`, `router.rs` (the T0 request
router), `actionlog.rs` (the hash-chained Ed25519-signed action log), `anchor.rs`, `cascade.rs`,
`crypto.rs`, `memory.rs`, `registry.rs`. CI runs `cargo test` on it as the `warden-kernel` job
("chain/head/anti-rollback/tiers/router/registry/crypto + A10 durability").

Key modules read:

- **`sigil/reuse/__init__.py`** — re-exports `vigil_core` primitives and defines the sovereignty guard
  `assert_no_offense()`. Denylist `_OFFENSE_NAMESPACES = ("framework", "strix")`; it scans `sys.modules`
  and raises `RuntimeError("SIGIL sovereignty violation: …")`. A fail-closed tripwire, explicitly *not*
  the primary defense (the primary defense is that the packages are not installed — §2).
- **`sigil/spine/`** — the sovereign append-only record: `store.py`, `models.py`, `envelope.py`,
  `merkle.py`, `manifest.py`, `checkpoint.py`, `snapshot.py`, `floor.py` (anti-rollback), `tail.py`,
  `verify.py`, `witness.py`, `prune.py`, `atomicio.py`, `migrate_runner.py`.
- **`sigil/governor/`** — the authenticated governor: `core.py`, `authn.py`, `capability.py`,
  `promotion.py`, `budget.py`, `killswitch.py`, `identity.py`, `integrity.py`, `offense_gate.py`.
- **`sigil/consolidate/`** — memory consolidation behind a "serve-the-quote" grounding gate.
- **`sigil/graph/`** — `schema.py`, `rebuild.py`, `query.py` (graph rebuilt from the spine).
- **`sigil/inbound/spool_watcher.py`, `finding_receiver.py`** — the sovereign ingest of offense
  findings (§2.3).
- **`sigil/knowledge/learn_grant.py`** — the sovereign producer of the learn-grant seam (§5.5).

`[doc-claim]` `apps/sigil/README.md` reports phases 0–9 complete and merged with Linux as the proven
path; full-duplex voice, on-device perception (VLM advisory, OCR authoritative), gesture control, a
local web cockpit, 8 read-only cited MCP memory tools, and a phone companion over WireGuard where the
phone holds only its own device key. I verified the *directories* for voice/perception/gesture/mcp/
bridge/ui exist; I did not exercise them. `[NOT VERIFIED: runtime behaviour of voice/perception/gesture]`

---

### 1.6 STRIX — the vendored agentic pentest tool

**Location:** `vendor/strix/` — a vendored copy of the open-source Strix project (Apache-2.0; its own
`LICENSE` and `NOTICE` retained in-tree).
**Structure verified:** `strix/{agents,config,core,interface,report,runtime,skills,telemetry,tools,utils}`,
plus `benchmarks/`, `containers/`, `docs/`, `scripts/`, `tests/`, and a VIGIL-added `tests_vigil/`.

**Its role inside VIGIL:** it is *one of the proposing agents*. It runs on the offense side only, and
its outputs must survive the oracle like anything else. Integration points read:
- `integration/vigil_integration/warden_gate.py` — "the offense-side Strix hook adapter"; the boundary
  test asserts it imports the agents SDK, `framework`, `strix` and the live wiring **lazily**.
- `integration/vigil_integration/proof/bootstrap.py` — "the Strix `proof_sink` installer".
- `vendor/strix/strix/core/runner.py` carries a FATAL-2 comment about the sovereign never loading it,
  and honours `VIGIL_WARDEN_STRIX_GATE` — the opt-in WARDEN gate over Strix's arbitrary
  `exec_command` shell. **Gateable, not gated by default** (`docs/AS-BUILT.md`, T3).

`[doc-claim]` `README.md` + `gateway/README.md`: the Strix sandbox's `NET_ADMIN` capability is dropped
so it cannot rewrite its own firewall, `STRIX_DOCKER_SANDBOX_NETWORK` pins it to the gateway's internal
network, and `NET_RAW` is **retained by default** (needed for `nmap -sS`), droppable via
`STRIX_SANDBOX_NET_CAPS=""`.

**hexstrike-ai** (`vendor/hexstrike-ai/`) is a *second* vendored upstream, deliberately
**NON-RUNNABLE**: pinned at commit `d689933f`, MIT, with `hexstrike_server.py.reference` /
`hexstrike_mcp.py.reference` suffixed so Python cannot import them. `UPSTREAM.md` states why: the
upstream server is "a complete, self-contained offensive execution framework… Running them would
bypass VIGIL's conjunctive gate, egress gate, and charter scope entirely." Only its *decision model*
is reused, as a clean-room reimplementation in `integration/vigil_integration/brains/hexstrike_brain.py`.

---

### 1.7 integration — the fusion body and live engine

**Location:** `integration/vigil_integration/`. The largest connective layer; installed in **both** venvs.

| Area | Files | Role |
|---|---|---|
| Reasoning loop | `agent/react.py`, `phases.py`, `cognition.py`, `checkpoint.py`, `state.py`, `targets.py` | Fail-closed ReAct interposition (§4.3). |
| Input safety | `safety/hard_guardrail.py`, `llm_intake.py`, `prompt_safety.py`, `url_guard.py` | Untrusted-input boundary, non-disableable hard block, fail-closed parse, SSRF pre-filter. |
| Tool boundary | `tools/governance.py`, `tools/mcp_registry.py` | Phase→tier→gate subordination; least-privilege MCP registry. |
| Gates | `conjunctive_gate.py`, `warden_gate.py`, `destruction_gate.py`, `challenge_oracle.py` | §4.5. |
| Truth bridge | `oracle_adapter.py` | Where a proposal becomes a signed FACT — only if the bug class is oracle-mapped **and** the oracle fires over retained evidence. The **only sanctioned mint path**. |
| Inert seam | `offense_worker.py`, `inert_finding.py`, `finding_spool.py` | §2.3. |
| Parallel agents | `fireteam/` | §4.4. |
| Graph memory | `graph/model.py`, `projector.py`, `query.py` | Attack-chain graph rebuilt from the record; authorizes nothing. |
| History compaction | `chainast/` | Append-only conversation summarisation; a summary is always labelled a summary. |
| LLM red-teaming | `gauntlet/` | Drives external tools at an AI target; **a judgment by another AI is always a LEAD**. |
| Sandboxed FS/jobs | `fsjob/` | Race-free path confinement, reversible signed file changes, hardened archive extraction. |
| Remediation | `remediation/` (incl. `fix_oracle.py`, `reprove.py`, `prove_driver.py`), `autopatch/` | Gated auto-fix; "remediated" signed only after the original exploit oracle re-fires and goes **silent**. |
| Observability | `observability/`, `telemetry.py` | Emit-only; reports, never gates. |
| Knowledge/budget | `kb/corpus.py`, `kb/skills.py`, `kb/budget.py`, `knowledge_sync.py` | Corpus wrapped as untrusted; skills loader behind a path-traversal guard, grants no privilege; spend meter that can only defer. |
| Attestation | `attestation/{identity,ledger,anchor,models}.py` | The who/when/what usage record, minted before anything runs. |
| Detection Mirror | `detection/` | §1.4. |
| Proof-of-Posture | `posture/` | The signed **Certificate of Non-Exploitability** (§1.8). |
| Proof Studio | `proof/{engine,run,bootstrap,bundle,sink,minimize,content_gate}.py` | PoC → oracle-confirmed, offline-verifiable bundle. |
| Offline certificates | `transparency.py`, `scitt.py`, `witness_service.py`, `channel_binding.py`, `time_anchor.py` | Witnessed transparency log; OpenVEX + DSSE m-of-n + Merkle inclusion receipts; RFC5705 channel binding; RFC3161 time anchoring. |
| Brains | `brains/{hexstrike_brain,hexstrike_body,engine_think}.py` | Pluggable **propose-only** reasoning cores. |
| Live engine | `live/` (43 modules) | The unified running loop (below). |
| CLI | `cli.py`, `dispatch.py`, `doctor.py`, `services.py`, `uiproxy.py` | The `vigil` command + super-CLI routing + UI reverse-proxy. |

**The brain slot** (`brains/__init__.py`, verbatim): "A brain is PROPOSE-ONLY: given a target profile
it emits a proposed tool list + parameters + an ordered attack chain, as LEADs. It computes no facts,
self-authorizes nothing, touches no network. … a finding becomes a FACT solely when a deterministic
VIGIL oracle fires. The brain never reaches that path."

**The live layer** (`integration/vigil_integration/live/`, 43 modules) includes `engine.py` (the
unified attestation-first loop), `wiring.py` (the factory binding it to real gates/oracle/spine),
`executor.py` (target-pinned tool executor + the governed local terminal), `graph_neo4j.py` +
`graph_driver.py`, `gauntlet_subproc.py`, `otel_export.py`, `think_claude.py` (the live Claude step,
key-gated with a keyless replay fallback), `spine_vigilcore.py`/`spine_identity.py`/`spine_verify.py`,
`approval_broker.py` + `approval_token.py` + `nonce_ledger.py` (per-action approvals with single-use
`O_EXCL` nonces), `sandbox_exec.py`, `external_tool.py`, `tool_manifest.py`, `conformance.py`,
`dns_pin.py`, `cloud_scope.py`, `destruction_provision.py`, `governance_identity.py`,
`observation.py`, `verdict.py`, `web_redrive.py`, `body_decode.py`, `safe_parse.py`, `sbom.py`,
`cloud_benchmark.py`, `cloud_live_posture.py`, `codefix_runner.py`, `iac_posture.py`,
`mesh_cicd_posture.py`, `k8s_posture.py`, plus the six E-series verifiers/runners (§1.10).

`live/graph_driver.py` is a good example of the project's honesty posture in code — its docstring
commits to **"Honest omission / fail-closed"**: if the Neo4j vars are unset, the host unreachable, or
credentials rejected, it returns `None` and the projection is simply omitted — "it never fakes a
connection."

---

### 1.8 Proof-of-Posture (the signed negative)

**Location:** `integration/vigil_integration/posture/certificate.py` (+ siblings).
A `PostureCertificate` ("Certificate of Non-Exploitability") is a projection of a coverage certificate
(`framework/v2/verify/coverage_oracle.py`) bound to a target, carrying its coverage denominator and an
honest residual. Read verbatim, the load-bearing rule:

> a claim is CLOSED iff, for its `(surface, param, class)`, at least one probe's coverage verdict is
> `clean` AND that clean probe names a non-empty `oracle_kinds_run` (the conclusive oracle(s) that
> adjudicated it) AND no probe fired. … a `clean` row with an EMPTY `oracle_kinds_run` is a tampered /
> forged coverage certificate and is refused. **UNPROVEN never counts as CLOSED — that is the
> difference between a sound negative and an omniscience lie.**

Deterministic (no wallclock/rng/host:port in the signed bytes); freshness (RFC3161) and witness
co-signatures are **sidecars** added at the bundle layer, never inside the signed bytes, so two scans
of one app produce byte-identical certificates. Imports only `vigil_core` + stdlib; the m-of-n signing
envelope is imported function-locally (FATAL-2 clean).

---

### 1.9 gateway — the egress gate

**Location:** `gateway/vigil_gateway/` — `nftables.py`, `proxy.py`, `denylist.py`, `docker.py`,
`scope_source.py`, `config.py`, `cli.py`. Two layers over one scope:

| Layer | Module | Enforces |
|---|---|---|
| L3/L4 deny-default firewall | `nftables.py` | From the sandbox, DROP everything except the gateway proxy + gateway DNS; hard-drop metadata/link-local/reserved on the forward hook and the gateway's own output; governs by **input interface** when `sandbox_iface` is set (spoof-proof), else by source subnet. |
| L7 forward proxy | `proxy.py` | Per connection: host must be in charter scope; resolve once; **refuse if any resolved IP is on the denylist** (DNS-rebinding defence); pin the exact validated IP (TOCTOU-safe). |

Scope is **CRUCIBLE's**, reused not reinvented (`scope_source.py` → `host_matches_scope` /
`parse_scope`). `denylist.py` is the single source of truth for both layers and covers IPv4-mapped /
6to4 / NAT64 **and** IPv4-compatible `::/96` IPv6 forms, so neither `::ffff:169.254.169.254` nor
`::169.254.169.254` slips past. The strongest topology puts the sandbox on a Docker network with
`internal: true`. The problem this closes is named **FATAL-1** (unbounded sandbox egress). `[doc-claim
on the nft/proxy specifics — `gateway/README.md`; the modules are verified present.]`

---

### 1.10 The E-series — cloud and Kubernetes exploitation confirmations (COMPLETE)

Six achieved-effect capabilities, all merged and wired end to end at this commit. Each has: a
deterministic oracle in `framework/v2/verify/`, its own `OracleKind`, a sovereign-safe
admission/certificate producer in `integration/vigil_integration/live/`, a registered evidence branch
in `docs/capability-matrix/evidence-branches.json`, and offline fixture tests in `integration/tests/`.

| # | Capability | Oracle kind | Oracle module | Producer | Evidence branch |
|---|---|---|---|---|---|
| E1 | Instance-metadata (IMDS) **credential capture** | `imds_credential_capture` | `verify/imds_capture.py` | `live/imds_verify.py` + `live/imds_runner.py` | `cloud_exploit.imds.credential_capture` |
| E5 | **Exposed-secret validity** | `secret_credential_validity` | `verify/secret_capture.py` | `live/secret_verify.py` | `cloud_exploit.secret.credential_validity` |
| E3 | **GCP service-account impersonation** | `gcp_sa_impersonation` | `verify/gcp_impersonation_capture.py` | `live/gcp_impersonation_verify.py` | `cloud_exploit.gcp.sa_impersonation` |
| E2 | **IAM privilege escalation** (achieved strict gain, not reachability) | `iam_escalation_primitive` | `verify/iam_escalation_capture.py` | `live/iam_escalation_verify.py` | `cloud_exploit.iam.privilege_escalation` |
| E4 T1 | **K8s RBAC — anonymous-privileged binding** | `k8s_workload_posture` | `verify/k8s_workload_posture.py` | `live/k8s_rbac_verify.py` | `k8s_exploit.rbac.anonymous_privileged_binding` |
| E4 T2 | **K8s RBAC — dangerous-verb / default-SA grant** | `k8s_rbac_verb_grant` | `verify/k8s_rbac_grant.py` | `live/k8s_rbac_grant_verify.py` | `k8s_exploit.rbac.dangerous_verb_grant` |

All six branches declare `fact_capable: true`, `clean_capable: false`, `target_clean_capable: false`
with a stated downgrade rationale, and **no `blocking_work`** (nothing is left un-built).
`clean_capable: false` is the honest half: one capture cannot prove that no capturable credential
exists.

**The honest live-fire status, quoted verbatim from the E1 evidence branch** (the same shape appears on
E2/E3/E4/E5 and in each producer's module docstring):

> The retained capture is SECRET-SAFE — the credential's secret material is redacted to a presence
> marker — so the FACT re-verifies offline with no live secret; the confirming call is the WARDEN-gated
> runner's RETAINED evidence re-derived by VIGIL's own oracle, never the runner's say-so.
> **Real-transport LIVE-FIRE (the runner against a real metadata endpoint) is deferred on an
> operator-provisioned lab credential; the runner and this admission / certificate / world-model wiring
> are complete and fixture-proven offline.**

Two further structural facts writers must not drop:

- **Nothing on the scan/engage/benchmark path can mint an E-series finding.** Each producer's docstring
  says so explicitly ("INERT on scan/engage"), because the kinds are kept out of the frozen
  `_ALL_ORACLES` fallback and are reachable only through an explicit context key. The capability fires
  **only** when the producer is called deliberately over a gated runner capture.
- **A sovereign `live/*` module must never call `build_certificate`/`confirm_and_certify` directly** —
  the only sanctioned mint path is `oracle_adapter.certify_admitted`.
- E2 (IAM privilege escalation) is *deliberately* offline-only even in principle: its branch note says
  live-fire "is deliberately **not** part of this branch — a defensive verification oracle never
  executes the escalation." It re-derives the gain over the operator's own retained policy.

---

### 1.11 Build and release safeguards (supply chain) — delivered today

Pre-existing on `main`:

- `engine/crucible/bin/verify-supply-chain.sh` — three checks, non-zero on any failure:
  (1) `requirements.in` resolves cleanly (pip-compile dry run); (2) `requirements.lock.txt` is up to
  date with `requirements.in` (`pip-compile --check`); (3) `sbom.json` is a valid **CycloneDX**
  document and matches the lock. Its own comment states the policy: "A lock-file drift means an
  unreviewed dependency change has been merged — fail the pipeline rather than ship." Build-time
  tooling (`pip-tools`, `cyclonedx-bom`) is deliberately kept out of the runtime spec so the deployed
  attack surface is not expanded.
- `engine/crucible/framework/v2/requirements.lock.txt` and `framework/v2/sbom.json` are committed.
- `integration/vigil_integration/live/sbom.py` + `integration/tests/test_sbom.py` — the **product-side**
  SBOM/dependency-CVE capability (the `VERSION_RANGE` fact family): VIGIL parses the target's own
  manifest, looks the version up in a pinned vendored OSV snapshot
  (`docs/capability-matrix/osv-snapshot.json`), and mints a signed FACT **only** when its own
  `version_in_affected` re-derivation proves the version falls in an advisory's affected range. "A
  grype/syft/trivy/osv-scanner run is only a PROPOSER of where to look — its CVE match never [mints]."

**In flight today (branch `a14-supply-chain`, worktree `/home/kali/vigil-wt-a14`; NOT yet merged to
`main` at inventory time):**

- **Dependency hash-locking for the sovereign env** — new `infra/supply-chain/sovereign.in`, the source
  spec for a `--generate-hashes` lock installed with `pip install --require-hashes -r
  infra/supply-chain/sovereign.lock.txt`. It carries the FATAL-2 rule in its own header: "nothing here
  may drag in `framework.*` (CRUCIBLE) or `strix.*`; that absence is what makes
  `sigil.reuse.assert_no_offense()` hold by construction."
- **Container base-image digest pinning** — new `infra/supply-chain/image_pins.py` (stdlib-only
  inventory/checker/drift reporter) + `resolve-image-digests.sh`; six Dockerfiles / compose files
  changed to `FROM python:3.13-slim@sha256:…`. Rationale in the diff: "A tag is a mutable pointer…
  A digest is content-addressed: it either matches or the pull fails." `--drift` (the only networked
  mode) is **advisory by design** and exits 0, because upstream retagging is not the fault of the PR
  under test.
- A missing runtime dependency (`packaging`, used by the `VERSION_RANGE` family) is added to
  `requirements.in` — it was declared by two `pyproject.toml`s but absent from the spec, so "it was the
  one runtime dep the lock could never pin."
- The branch's comments reference an **"A14 supply-chain gate" CI job**
  (`.github/workflows/supply-chain.yml`) and a `docs/SUPPLY-CHAIN.md`. **Neither file existed in the
  working tree when I read it**, and the **vulnerability gate that blocks on CRITICAL** was likewise
  not yet present. `[NOT VERIFIED — part of the same delivery; writers must re-check before publishing
  any claim about the CI gate or the CRITICAL block.]`

CI today is a single workflow, `.github/workflows/ci.yml`, whose jobs include: `vigil-core`,
`crucible-core`, `gateway`, `integration` (the two-env boundary), `strix-vigil`, `sigil-governor`,
`formal-verification` (TLC), and `warden-kernel` (cargo).

---

## 2. The two-environment separation (FATAL-2)

### 2.1 What is kept apart from what

Authoritative declaration, read from the **root `pyproject.toml`** (`[tool.vigil.environments]`):

```toml
[tool.vigil.environments.sovereign]
members = ["packages/core/vigil_core", "apps/sigil", "integration"]
forbids = ["framework", "strix"]

[tool.vigil.environments.offense]
members = ["packages/core/vigil_core", "engine/crucible", "vendor/strix", "gateway", "integration"]
owner_key = false   # the offense worker runs with NO owner signing key (keyless trust domain)
```

`envs/README.md` restates it operationally:

| Env | Venv | Members | Rule |
|---|---|---|---|
| **env-sovereign** | `.venv-sovereign` | `vigil_core` + `apps/sigil` + `integration` | MUST NOT contain `framework.*` (CRUCIBLE) or `strix.*`. That absence makes `assert_no_offense()` hold **by construction**. |
| **env-offense** | `.venv-offense` | `vigil_core` + `engine/crucible` + `vendor/strix` + `gateway` + `integration` | Runs the offense engine as a **keyless** process (no owner key). |

Both venvs exist on this machine. `envs/build_envs.sh` builds both (prefers `uv`, falls back to
venv+pip) and then verifies the boundary; `envs/sovereign.txt` / `envs/offense.txt` hold the member
sets. The README explains why a single uv workspace is *not* used for the real environments: "a single
uv workspace resolves to one shared environment — which is exactly what the boundary forbids."

`integration` is installed in **both** environments. That is why so many integration modules are
required to import `framework` **lazily** (the probe list in §2.2).

**Why this matters for safety** — stated in `knowledge/kb/two-env-boundary.md`:

> the sovereign plane holds the owner key; loading attacker-adjacent offense code into that address
> space would put the key one memory-safety bug away from an offense worker. Keeping them in separate
> interpreters makes the boundary a property of the OS process, not of careful coding.

and:

> The whole reason offense is keyless and sovereign holds the key is so that a compromised offense
> worker can *produce evidence* but can never *authorize an action* or *touch the owner's data core*.

### 2.2 How the boundary is proven

`integration/tests/test_two_env_boundary.py` (read in full). Its own docstring states the boundary is
**structural** and proven at two levels, and explains why an earlier weaker version was not a proof:

> The earlier version of this test scrubbed only PYTHONPATH and ran under the ambient interpreter —
> which is NOT a proof: in a correctly-built env-offense, `engine/crucible` and `vendor/strix` are
> editable-installed, so their `.pth` files import `framework`/`strix` at startup regardless of
> PYTHONPATH, and the "sovereign" assertion would flip red (red-pen P5 BLOCK-1). The boundary is a
> property of *which packages are installed* …

Three tests:

1. **`test_no_sovereign_member_declares_offense_dependency`** — always runs, no external state. Parses
   each sovereign member's `pyproject.toml` and asserts none declares a dependency matching
   `("crucible", "framework", "strix")`. `_dep_names()` deliberately also collects
   `optional-dependencies`, PEP-735 `dependency-groups`, **and** `build-system.requires` — "an offense
   package smuggled in as a build/group requirement must not evade the check." The member list is read
   from the root `pyproject.toml` so the test cannot silently drift from the declared boundary.
2. **`test_real_sovereign_venv_cannot_reach_offense`** — builds an **actual** venv with only
   `vigil_core` + `integration` installed (crucible and strix deliberately absent), then runs a probe
   subprocess in it. Skipped only if a venv/pip build is impossible (offline).
3. **`test_guard_is_not_vacuous_negative_control`** — puts `engine/crucible` on the path, actually
   **loads** `framework.v2.common.ethics`, and asserts `assert_no_offense()` **fires**. Without this the
   guard could be trivially passing.

The probe (`_PROBE`) asserts:
- `framework`, `framework.v2`, `framework.v2.common.ethics`, `strix`, `strix.agents` are all
  **unimportable** (status must be `"blocked"`);
- `assert_no_offense()` does not raise in a genuinely sovereign env;
- a long explicit list of integration modules imports cleanly **and leaves `framework` out of
  `sys.modules`** — i.e. each imports the offense engine lazily. The modules asserted lazy at this
  commit: `inert_finding`, `learn_drain`, `proof.engine`, `proof.run`, `proof.bootstrap`,
  `proof.bundle`, `remediation.fix_oracle`, `warden_gate`, `live.approval_broker`,
  `live.cloud_live_posture`, **`live.imds_verify`, `live.secret_verify`,
  `live.iam_escalation_verify`, `live.k8s_rbac_verify`, `live.gcp_impersonation_verify`,
  `live.k8s_rbac_grant_verify`** (all six E-series producers), `live.cloud_benchmark`; plus
  `sigil.knowledge.learn_grant` (the sovereign producer) must stay offense-free;
- `warden_gate` additionally must not import the `agents` (openai-agents) SDK, `strix`, or
  `vigil_integration.live.wiring` at module scope.

The probe pins `cwd` to a clean temp dir because "Python puts cwd on `sys.path[0]`" — noting the
ambiguity would "fail-safe — it would raise, never falsely pass — but pinning removes [it]."

**Formal model.** `formal/boundary/Boundary.tla` machine-checks the boundary with TLC (invariants
`BoundaryHolds`, `InertSeam`): "offense and sovereign code never co-load; offense never holds the owner
key; the seam is inert." Each spec has a companion `X_broken.tla` — identical except the one
load-bearing guard is removed — which TLC must report as **violating**, so `check.sh` is red both when
an invariant regresses *and* when a mutant stops being caught (a vacuous check). CI runs it as the
`formal-verification` job. `formal/README.md` states the honest scope plainly: "**model-level assurance
that faithfully abstracts the enforcing code — not a code-extraction proof.**"
`[NOT VERIFIED: I did not run `formal/check.sh` in this pass.]`

### 2.3 Why it matters for safety — the inert seam

The two halves are joined by exactly one channel, designed so a fully compromised offense agent cannot
inject anything *trusted* into the sovereign core. Read from `knowledge/kb/two-env-boundary.md` §2 and
the modules themselves:

- **`offense_worker.py`** — the **keyless** offense-side worker; it refuses an owner key at
  construction, so it can only *package* a confirmed finding into a signed data envelope.
- **`finding_spool.py::spool_envelope()`** — takes a pre-built envelope **`str`** (refuses any non-`str`
  live object), writes it `0600` via `mkstemp` + atomic `os.replace` into a `0700` `incoming/` dir with
  a content-addressed name `sha256(envelope)[:32].json` (idempotent re-spool). Imports stdlib +
  `inert_finding` only.
- **`inert_finding.py`** — the receiving-side validator: parsed with **`json.loads` ONLY — never
  pickle/eval/yaml**, size-bounded to `MAX_ENVELOPE_BYTES = 256*1024`, strict top-level allowlist, then
  anchor-1 signature verified with **`vigil_core.verify_threshold` — no `framework` import**. Importable
  in *both* venvs by construction.
- **`apps/sigil/sigil/inbound/spool_watcher.py::SpoolWatcher.drain()`** — claims each file by atomic
  rename into `working/` *before* reading; reads it as a bounded **regular** UTF-8 file
  (`O_NOFOLLOW`+`O_NONBLOCK`, `S_ISREG`, size cap — so a planted symlink/FIFO/device/non-UTF-8 blob
  cannot hang or crash ingest); dedups on the sha256 of the **actual bytes** (not the producer
  filename); routes by `kind` to an **owner-delegated** `FindingReceiver`; moves the file to
  `processed/` on success or `rejected/` (with a `.reason` sidecar) on **any** failure. A missing
  delegation for the file's kind is itself a refusal.
- **`apps/sigil/sigil/inbound/finding_receiver.py`** — the **two-anchor trust model**: first the
  finding's m-of-n governance signature is verified using only the shared core; *then* the record is
  appended under the owner-signed spine.
- `vigil_core/delegation.py` closes the residual hole: without it the governance root would be a
  free-floating key with no cryptographic tie to the owner.

**Fail-closed at every seam step**, per the KB: the producer refuses a non-`str`, empty, oversized or
non-JSON envelope; the watcher refuses a non-regular file, an oversized/non-UTF-8 blob, a missing or
**expired** delegation (checked against a **local** clock, never the envelope), a failed signature, or
an out-of-scope engagement.

**The safety argument in one line:** the offense half holds no owner key and cannot be imported into
the half that does; findings cross as signed inert bytes, never as running code.

---

## 3. The event spine, the world model, and sessions

### 3.1 The event spine / blackboard

**Primary implementation:** `engine/crucible/framework/v2/agents/blackboard.py` + `schema.sql`, with
cryptographic tamper-evidence in `agents/spine_chain.py`.

- **Storage:** SQLite at `framework/v2/.blackboard/store.sqlite` (gitignored), path from
  `blackboard_path()`.
- **Append-only at three levels:**
  1. SQL triggers `bb_events_no_update` and `bb_events_no_delete` refuse direct `UPDATE`/`DELETE`.
  2. The Python API exposes no mutating operation other than `post()` and the supersession helper —
     there is no `update` or `delete`.
  3. Revision is done by **appending** a new row whose `supersedes_id` points at the old one. Reads
     exclude superseded rows by default; `include_superseded=True` shows history. The new row inherits
     `parent_id` from the superseded row, so provenance chains survive edits.
- **Provenance:** every event carries `parent_id`, so a confirmed Finding walks back
  `Result → Action → Plan → Hypothesis → Observation`. Enforced at both the Pydantic and SQL layers.
- **Event kinds:** eight typed kinds in `agents/models.py` (`PAYLOAD_BY_KIND`, `ALL_EVENT_KINDS`);
  later waves add `reflection`, `refusal` and `reward` events (verified in `reflection.py`,
  `cognitive_refusal.py`, `calibration/reward_bus.py`).
- **`events.id` is monotonic and never re-used.**

**`agents/spine_chain.py`** adds the cryptographic layer on top:
- A hash-linked, governance-signed chain over the event log, so tampering that **bypasses** the triggers
  (a raw DB edit, a swapped file) is still detectable.
- It reuses `evidence/chain.py` primitives verbatim — "no new integrity scheme."
- It is **purely additive**: no schema change, no change to `post()`; the chain is built on demand, so
  an unsigned spine behaves exactly as before. **Signing is provisioning-only; the runtime only verifies.**
- `event_digest()` covers identity + content (`engagement_id`, kind, agent, payload, `parent_id`,
  `supersedes_id`) but deliberately **not** the wallclock `posted_at` — so the chain is stable and
  replay-safe. `engagement_id` is bound in so a signed head cannot be replayed onto a look-alike log.
- **Fail-closed on truncation:** `_events()` pages to exhaustion and raises `SpineChainError` rather
  than "anchor/verify a truncated log."

**Several spines, not one.** `vigil_core/spine_domains.py` is "the one registry of VIGIL's signed
spine/log domains", and is unusually candid about the limits:
- Segments: the **sovereign** personal record (owner-key-signed head + anti-rollback floor); the
  **offense finding anchor-1** (m-of-n governance signature, owner-delegated); the **offense engagement
  spine** (checkpoints, exec records, detection certificates); the **offense usage-attestation ledger**
  (operator key); and the **CRUCIBLE blackboard chain** (a DB projection).
- The offense spine and usage ledger sign a raw chain-link hash (no domain-tag prefix); the sovereign
  segments each use a **distinct domain-separation prefix**, so a signature under one can never replay
  as another.
- `owner_rooted` states whether a verify path **exists today** that chains a segment back to the owner.
  "Delegate-ABILITY alone is NOT enough": only `offense-finding-anchor1` is `owner_rooted=True` among
  the offense segments, because a real consumer exists. "this module does not pretend the tie is
  enforced before it is."
- The blackboard chain's persist/offline-verify path has an explicitly **honest scope**: a run refused
  at the attest-first gate posts nothing → the segment is honestly `UNVERIFIABLE` (never a fake
  "verified"); and the chain proves integrity/order/owner-root of the events the run **posted**, "NOT a
  re-verification of a finding's oracle proof."

### 3.2 The world model / knowledge graph

**`engine/crucible/framework/v2/worldmodel/`** — "WMS, the World-Model Substrate". One persistent,
typed attack graph that survives restart and answers *"given what we have observed, what is now
reachable, and by what explainable route?"*
Modules: `models.py`, `graph.py`, `store.py`, `query.py`, `pathsearch.py`, `attack_paths.py`,
`attacker.py`, `derivation.py`, `impact.py`, `spine_projector.py`.

Schema (from `worldmodel/README.md`):

```
NodeKind:  HOST · SERVICE · ENDPOINT · WEBAPP · DATASTORE · CLOUD_RESOURCE ·
           NETWORK_SEGMENT · PRINCIPAL · CREDENTIAL · SESSION · CONTROL · FINDING
EdgeKind:  REACHABLE_FROM · TRUSTS_FOR · HAS_GRANT · MEMBER_OF · CAN_ASSUME ·
           VALID_ON · AUTHENTICATES_TO · SESSION_ON · CONTROL_PROTECTS · EVIDENCES
```

- **Bespoke and deliberately small**, because no off-the-shelf schema spans web + identity + cloud
  *and* carries per-fact provenance/confidence. The motivating chain: an `ENDPOINT` leaks a
  `CREDENTIAL` that is `VALID_ON` a `PRINCIPAL` that `CAN_ASSUME` a `CLOUD_RESOURCE` fronting a
  `DATASTORE`.
- **Two non-negotiables:**
  1. **Every fact carries provenance + confidence.** `provenance` is the id of the event/observation
     that asserted it; `confidence ∈ [0,1]`. `Path.min_confidence` (a path is only as strong as its
     weakest edge) and `Path.provenance_chain` make an attack path auditable rather than asserted.
  2. **Time is a monotonic sequence int, never a wallclock.** Callers pass their own counter as
     `first_seen`/`last_seen`. "The graph never reads the clock, so upsert-merge, ordering, and every
     query are deterministic and replayable."
- **Upsert-merge:** `add_node`/`add_edge` are idempotent; attrs overlay; confidence reconciles to the
  **max** (re-observing never lowers belief, and the higher-confidence assertion donates its
  provenance); the seen-window widens (`first_seen = min`, `last_seen = max`).

**Two graph *stores*, distinct from the world model:**
- `framework/v2/graph/store.py` — an **embedded, file-backed** store needing no external database.
  Per `docs/DEFERRED-INFRA.md` §G1: nodes for events + posting agents; edges for
  `parent`/`supersedes`/`posted`; **one-way projection** (a pure function of the passed event list;
  same events in → byte-identical partition file out, canonical JSON, sorted, no wallclock, no RNG);
  **never read back into an authority** — "The store has no promote/grant/tier/authorize method, by
  design"; per-session partitions.
- `Neo4jGraphStore` (same interface) + `live/graph_neo4j.py`/`graph_driver.py` — a **real, reviewable
  client body** whose *deployment* is the honest residual: the `neo4j` driver package and a running
  service are both absent here, so constructing a live store raises a clear `NotImplementedError` and
  the live parity test is behind a **loud skip**. `[built client body; not live-deployed]`

`integration/vigil_integration/graph/` is the offense-body's own attack-chain graph memory
(`model.py`, `projector.py`, `query.py`) — rebuilt from the record, keeping confirmed facts and leads
strictly separate, and authorizing nothing.

### 3.3 How sessions work

**Implementation:** `engine/crucible/framework/v2/console/sessions.py`. Consumed by
`vigil dossier --session` in `integration/vigil_integration/cli.py` (~lines 1151–1183), which calls
`sessions.get_session`, `sessions.session_graph`, and `sessions.open_threads`.

- **What a session is:** "A 'session' used to be only a chat transcript. This promotes it to a durable,
  renamable, deletable object the operator manages: a named container linking the runs (and the chat
  transcript) of one line of work."
- **Persistence:** `<VIGIL_LIVE_DIR>/sessions/<id>/session.json`, dir `0700`, file `0600`, atomic
  tmp+rename. `VIGIL_LIVE_DIR` defaults to `.vigil-live`.
- **Record shape:** `id, name, kind, run_ids, slug, connections, deleted, created_seq, updated_seq,
  created_ts, updated_ts`. Kinds are `("engagement", "chat", "mixed")`. Caps: `_MAX_ID = 128`,
  `_MAX_NAME = 200`, `_MAX_LIST = 500`.
- **Ordering coordinate:** a **monotonic per-registry `seq`**, not a wallclock. A separate wallclock
  `updated_ts` exists **only** to drive UI sort.
- **Per-session graph:** every session owns a graph **partition** keyed by its id, materialised by the
  default embedded file-backed `graph.store`, as "a PURE, ONE-WAY projection of the append-only signed
  spine of the session's engagement(s)". `project_session_graph` rebuilds it from spine events only, so
  the same spine yields a **byte-identical** partition. Neo4j is an optional backend behind the same
  interface whose sealed password reaches the plane only via the sovereign check-secret broker, and is
  never required.
  The load-bearing invariant, verbatim: "NOTHING here is EVER read back into a tier / grant /
  authorization / FACT — the store structurally exposes no such surface; this module only PROJECTS
  (write) and READS nodes/edges for the UI/handoff. A partition is rebuildable, disposable state:
  dropping it loses no authority (the spine, the sole authority, is untouched)."
- **Authority:** "the registry mints NO facts, reads NO tier/grant, and authorizes nothing. Creating /
  renaming / deleting a session changes no finding and no gate."
- **Deletion is fail-safe:** SOFT = tombstone (retains chat transcript, linked run metas, and always the
  append-only signed spine); HARD = additionally removes the registry entry and drops the rebuildable
  graph partition — "but never touches the spine or a FACT."
- **Concurrency:** the console runs on a `ThreadingHTTPServer`, so every registry mutation is serialised
  under a reentrant lock; each atomic write uses a unique `mkstemp` temp.
- **Session connections:** `connect_session` / `connections_of` — a session's *consented* connected
  session ids (read-time partition union, provenance-tagged, per ADR 0001).
- **`open_threads(sid)`** returns unfinished lines of work, explicitly **advisory**.

Design authority: `knowledge/decisions/0001-knowledge-and-embodiment-program.md` (ADR 0001, status
**Accepted**) specifies the session registry (F2), the per-session graph partition keyed by session id
(F3) and session-connect (F4), and records the invariant that "the per-session graph and
session-connect are **projection-only** (never a source of truth, never a shared live handle across the
boundary, never a read-back of a grant/tier)."

A separate, unrelated notion of "session" exists at `knowledge/sessions/` — redacted **build**-session
transcripts written by `vigil knowledge sync`, with mandatory redaction before commit and explicit
operator-gated pushing; "no agent or automation ever pushes."

---

## 4. Agent types

### 4.1 Offense-side: CRUCIBLE MAO agents (`engine/crucible/framework/v2/agents/`)

The layer is called **MAO** (Multi-Agent Orchestration). All agents communicate **only** through the
append-only blackboard, gated by typed event-kind contracts in `models.py`. Base class `Agent` (ABC) in
`base.py` with `should_run()` + `step()` + cursor helpers; `coordinator.py` boots agents, schedules
ticks, and terminates on quiet / wall-clock / external stop.

Pipeline (from `agents/README.md`):
`recon-agent → observation → hypothesis-agent → hypothesis (≥5 per observation, doctrine) →
exploit-agent → plan/action/result/finding(pending) → critique-agent → critique + supersede(finding) →
reporter-agent → targets/<slug>/reports/technical.md`, with `memory-agent` mirroring to MLS.

| Agent | What it does | What it is allowed to do |
|---|---|---|
| `recon_agent.py` | Probes paths via the intake Fetcher; posts `Observation` events. | **Does not exploit.** Budgeted; fixture-replay mode available. |
| `hypothesis_agent.py` | Watches for new Observations; calls `URK.hypothesize()`; posts **≥5 hypotheses per observation** (doctrine forcing function). | Posts hypotheses only. Confirms nothing. |
| `exploit_agent.py` | Claims open hypotheses; posts Plan → `executor.execute()` → Action → Result → (if confirmed) Finding with `critique_status='pending'`; supersedes the hypothesis `confirmed\|refuted`. | **Never calls tools directly** — it accepts an injected `Executor` (protocol in `executor_proto.py`). |
| `critique_agent.py` | Adversarial review of **every** Finding before promotion; walks provenance; supersedes the Finding with a critique status. | **Non-optional** per FORGE PROTOCOL §3.4 — "the guard against confident hallucination". Findings flagged `objections` / `more_evidence_needed` stay on the blackboard and **do not appear in the report**. |
| `reporter_agent.py` | Renders `technical.md` from **confirmed** findings only. | Does not promote findings the critique-agent flagged. |
| `memory_agent.py` | Mirrors blackboard events to the MLS recorder (engagement start/end, hypotheses with status, confirmed findings, action/result → payloads with outcome, refuted hypotheses → dead_ends). | Write-through to memory only; keeps a per-event-id cursor so a re-run after a kill does not double-write. |
| `chain_synthesizer.py` | Neurosymbolic multi-hop exploit-chain synthesis. | Only an oracle-confirmed hop asserts its edge into the world model; unproven hops remain hypotheses. |
| `critics.py` | A **panel** of differentiated deterministic critic lenses (replay-safe, no LLM cost, no egress); disagreement is itself signal; aggregation abstains on disagreement. | Verdict type is `endorse \| object \| abstain` — **never `confirm`**. "Critics can only advise, gate HARDER (object), or abstain; they can NEVER promote a finding to a fact." |
| `reflection.py` | In-loop metacognitive reflection over the reasoning trace; posts `reflection` events that re-orient the next tick; deduped. | "strictly re-rank / defer, **NEVER gate or skip an attack surface** (coverage doctrine) and never touch the oracle path." Deterministic — no LLM, no wallclock/global-rng; a pure function of the spine. |
| `cognitive_refusal.py` | An explicit "refuse to CONCLUDE" decision + one typed `refusal` event, so hard gates and epistemic abstains land on the same immutable stream. | "This only ever DEMOTES / routes-to-needs-evidence. It never promotes, never gates a surface, and it is fail-closed by construction." Reuses the veracity firewall rather than reinventing grounding. |
| `scope_gate.py` | Pre-flight `validate_action()` — charter signature + scope + destructive classifier, as a structured `ScopeDecision`. | Refusal becomes a `ScopeViolation` blackboard event rather than a crash. |
| `egress_guard.py` | Runtime egress allowlist for sovereign-mode httpx. | Deny-by-default at the library layer (belt-and-braces). |
| `spine_chain.py` / `spine_sink.py` / `spine_credit.py` | Cryptographic chain over the spine; event sink; reward crediting. | Signing is provisioning-only; runtime verifies. |
| Executors | `executor_proto.py` (`Executor` protocol + `DeterministicExecutor`), `realistic_executor.py`, `http_executor.py`, `oracle_probe_executor.py`. | `HttpExecutor` "never auto-claims `success=True`; the exploit-agent decides." |

**`HttpExecutor`'s six safety gates** (from `agents/README.md`) — each called per action, none
bypassable without a code change; if any refuses, the request never goes out and a refusal
`ExecutionOutcome` is returned for the blackboard:
1. charter file present; 2. charter **signature** (a non-placeholder operator name — "UTI's draft
charter is not enough"); 3. **scope** match against the charter's §2 table (literal hosts and
`*.suffix`); 4. **destructive-action confirmation** (POST/PUT/DELETE/PATCH and destructive path tokens
prompt on stderr with a 30-second timeout — **default-deny on no answer or non-TTY stdin**);
5. per-engagement **request budget** (default 100); 6. posture-aware **rate limit + UA** (TEST 5 req/s
identifiable UA; AUDIT 1 req/s; EMULATE 0.2 req/s + jitter, realistic browser UA), read from charter §7.
Plus full evidence capture of every request/response.

### 4.2 Sovereign-side: SIGIL agent mesh (`apps/sigil/sigil/agents/`)

Every SIGIL agent has a **ceiling** in the WARDEN tier system and emits `Proposal`s carrying a tier
(`apps/sigil/sigil/agents/base.py`):

```
class Tier(IntEnum):
    A0 = 0   # observe / answer
    A1 = 1   # reversible internal act (write a report/brief/event) — the AUTO bar
    A2 = 2   # external-visible / semi-reversible (send, calendar write) — QUEUED
    A3 = 3   # destructive / financial / security — explicit, never auto

AUTO_BAR = Tier.A1   # A0/A1 auto-apply; A2/A3 queue for human approval
```

A proposal auto-applies only if it is **at or below the auto bar AND at or below the agent's own
ceiling**. Default `Agent.ceiling` is `Tier.A1`.

| Agent | Mandate | Ceiling / hard limits |
|---|---|---|
| **ARCHIVIST** (`archivist.py`) | The world model: ingest, consolidate nightly, keep the graph true. | Ceiling **A1**. "deletion of source records is A3 and effectively never." |
| **SENTINEL** (`sentinel.py`) | Perception & monitoring: see everything, report only what matters. Pluggable watchers (spine + local system built in; IMAP IDLE / CalDAV / uptime optional). | Ceiling **A1** — writes only event records. Applies a **salience threshold** and an **alert budget** (at most N events per run, highest salience first; the rest suppressed and counted) because "the failure mode is NOISE". |
| **STEWARD** (`steward.py`) | Personal operations: the morning brief, the commitment ledger, recurring admin. | Ceiling **A2** (calendar writes queue until trust promotes them). "Every line is cited to a spine seq." |
| **ENVOY** (`envoy.py`) | Communications: triage inbound, **DRAFT** outbound, track open loops. | Ceiling **A2 HARD, and NO PROMOTION PATH** — "enforced STRUCTURALLY: ENVOY has no method that transmits anything… There is deliberately no `send()`." Writes `draft` records with `status: awaiting-approval`. |
| **ARTIFICER** (`artificer.py`) | Engineering: drives headless Claude Code against a repo to own a coding task end to end. | Ceiling **A2**. "**ARTIFICER NEVER pushes**" — `git push` to a protected branch, deploys and dependency additions are A3. It **runs the tests BEFORE claiming done**; "a failing change is reported, not shipped." Output is a local branch + plain-language diff summary, queued for review. |
| **SCHOLAR** (`scholar.py`) | Research & analysis: long-horizon research, sourced synthesis. | Ceiling **A1** (research never touches external state). Epistemics gate: every claim carries a source **and a verbatim quote**; "a claim that does NOT verify against its cited source is DEMOTED (not asserted)" — the serve-the-quote gate. |
| **BASTION** (`bastion.py`) | Defensive posture over the owner's **OWN** infrastructure only: TLS cert expiry, dependency CVE exposure, uptime — all **observational**. | Ceiling **A1**. "There is NO exploit, no port sweep, no third-party target": it iterates an **allowlisted asset inventory**, and any target not in that allowlist is REFUSED and logged as a `refusal` record — "own systems only" is a **structural property, not a promise**. A dependency is flagged **only** when its parsed version **provably** falls in an advisory's affected range; "an unparseable version is a non-assessment, never a fabricated CVE." |
| **OPERATOR** (`operator.py`) | Opens folders/files and runs terminal commands on request, transactionally. | Ceiling **A2**. **PLAN → PREVIEW → APPROVE → EXECUTE → VERIFY → ROLLBACK/UNDO.** Tier is **derived, never declared** (each step's tool token classified by the fail-closed Rust `KernelClassifier`) and **re-derived from the hash-bound preview at execute** (never a trusted field). Two scope rings: reads/writes must resolve inside the READ ring; a write auto-applies (A1) only inside the narrower AUTO-WRITE ring, else A2. **Empty rings = deny-all.** PREVIEW mutates nothing; the approval BINDS to the previewed content hash and the Operator re-previews and aborts on mismatch (anti-TOCTOU). The executable plan lives in a `0700` journal, **not** the spine — "no file bytes leak into immutable memory; the spine record carries only hashes." EXECUTE journals a pre-image before each mutating step, applies atomically, restores the original mode, and verifies by re-reading the post-image hash. UNDO is hash-bound and single-shot. |
| **DELEGATE** (`actor.py`) | Owner-consented identity/account manager + web actor: manages the owner's own credentials and, with per-action owner approval, creates accounts / logs in / fills forms / submits. | Ceiling **A2** and in `NO_PROMOTION_AGENTS`. Every account/login/submit/purchase is **A3** — explicit, per-action, owner-signed, no promotion. Offense-free by construction: **no `as_identity`/impersonate parameter exists** (fields resolve only from the owner's own vault); a detected block (CAPTCHA/403/429) **STOPS** and is surfaced as a positive control, and there is **no browser-escalation code path at all** (HTTP-only), so "use a browser to beat a block" is structurally unreachable. **One approval authorises exactly one action** (single-shot per step), so an approval can never be replayed into repeated POSTs. Per-service creation cap enforced at preview **and** re-checked at execute. |

Supporting modules: `base.py`, `runner.py` (orchestrates the mesh; `morning()` produces the brief),
`approvals.py`, `kernel_classify.py` (the Rust-oracle tier classifier binding), `actor_gate.py` /
`actor_scope.py`, `operator_scope.py`, `sources.py`, `vault.py`, `web_engine.py`.

**`vault.py` (CredentialVault)** — the owner's own per-service credentials, preserving the
`SecretStore` invariant verbatim: "Secrets NEVER enter the append-only spine, a log, or a network
payload." A `VaultRecord` has **no `password` field** — only a `password_ref` (an OS-keyring key name).
The password resolves from the keyring **only at execute time, into a local variable**. `version` bumps
on every edit and **binds** an approval; the spine binds by `service+vault_ref+version` — "deliberately
NOT a hash of the value (hashing a low-entropy identity field onto an append-only log is itself a weak-
preimage leak)." Its own honest caveat: a password rotated **out-of-band** directly in the keyring does
not bump `version`, so rotation should go through `set_record`.

**The structural no-promotion list**, verified in `apps/sigil/sigil/governor/promotion.py:19`:

```python
NO_PROMOTION_AGENTS = frozenset({"ENVOY", "DELEGATE"})   # outbound + account actions stay human-gated forever
```

It is checked in `is_promoted` **and** deliberately mirrored in `state_all` (an in-code comment marks
the mirror as intentional).

### 4.3 The fusion-body reasoning agent (`integration/vigil_integration/agent/`)

`agent/react.py` — "the sovereign ReAct interposition". Its docstring names the trust model it exists
to *forbid*: an upstream loop "acts on the LLM's say-so, persisting the assertion as a finding. That is
precisely the trust model VIGIL forbids."

- **`parse_decision`** — the raw LLM response is parsed **fail-closed** into a typed `LLMDecision` and
  downgraded to the safest action on any malformation ("a broken `deploy_fireteam` never becomes a
  deploy; a total parse failure pauses for a human"). The result is a **non-authoritative PROPOSAL**.
- **`classify_edge` / `authorize_edge`** — **every** action-bearing edge routes through the injected
  conjunctive gate (WARDEN tier ∧ CRUCIBLE authority ∧ m-of-n) at the phase's tier (A3 + threshold for
  destructive); a phase escalation or fireteam deploy additionally requires the signed human-approval
  leg. Inert actions (`ask_user`/`complete`/`switch_skill`) touch no target and pass. A
  structurally-invalid edge is **DENIED fail-closed**.
- **`intake_result`** — the LLM's `output_analysis` claims become **LEADs, never facts**. An
  `exploit_succeeded` claim triggers the injected deterministic **oracle** to re-fire over the retained
  raw output; only an oracle confirmation (a signed evidence ref) produces a FACT.
- Gate and oracle are **injected callables**, so the keystone is testable without the live
  kernel/framework; import-clean (pydantic + `.state`/`.phases` + safety; no framework/strix).

Siblings: `agent/phases.py` (recon → exploitation → post-exploitation mapped onto WARDEN tiers),
`agent/cognition.py` (non-authoritative cognition governors — stall/loop detectors and an honesty
auditor that may **re-rank or defer**, never decide a finding is true), `agent/checkpoint.py`
(snapshots the run into the signed spine so it can be rebuilt and re-verified), `agent/state.py`,
`agent/targets.py`.

### 4.4 Fireteam — governed parallel specialists (`integration/vigil_integration/fireteam/`)

From the package docstring — the guarantees the package exists to enforce, "all fail-closed and
testable with injected callables":

- a member carries a **capped WARDEN tier that can never be A3**; `_strip_forbidden_actions`
  structurally removes `deploy_fireteam` / `transition_phase` / egress from a member's decision;
- a member **cannot self-escalate** its tier or self-authorize a dangerous tool — an over-cap or
  destructive tool becomes a **QUEUED escalation** resolved only by an injected signed operator
  approval (`ConfirmationRegistry`), "never auto";
- a per-member **credit + deadline** bounds each run deterministically (injected sequence, no wallclock);
- **all member spine writes serialize behind ONE writer** (`SingleWriterSpineQueue`) so the append-only
  signed chain is never interleaved; records are secret-redacted;
- `collect` rolls up member findings as **LEADs** and promotes **only oracle-reconfirmed FACTs**;
- import-clean: pydantic + stdlib; no framework/strix/network.

`orchestrator.py` adds: a malformed/oversized/mutex-violating plan is **REFUSED, never partially
spawned**; a runner that crashes yields an ERROR member result so "one bad member never crashes the
wave or aborts its siblings"; members keep plan order with `seq = seq_start + index` (no wallclock/RNG),
so the whole run is reproducible.

### 4.5 The gatekeepers (not agents, but they bound every agent)

| Gate | File | What it enforces |
|---|---|---|
| **WARDEN classifier** | Rust `apps/sigil/kernel/src/tiers.rs` + `vigil_core/warden_tiers.py` (byte-faithful port, shared golden vectors in `warden_golden.json` loaded by *both* the Python tests and the Rust unit test) | Classifies every action into A0–A3, **danger-first**, with **anything unknown falling to the strictest tier (A3)**. |
| **WARDEN offense gate** | `integration/vigil_integration/warden_gate.py` | Raises every offensive tool to a tier **above** the auto-approve line, so an autonomous agent can never fire an offensive tool by itself — it always queues. Offense-gate open is owner-signed, charter-bound, auto-expiring, anti-replay (`docs/AS-BUILT.md` §2). |
| **Conjunctive gate** | `integration/vigil_integration/conjunctive_gate.py`, composed on `vigil_core/gate.py` | Authority ∧ WARDEN tier ∧ (destructive ⇒ owner-inclusive m-of-n). **First failure wins; any error in any conjunct is a DENY**; only an explicit WARDEN `"auto"` passes. |
| **Egress gate** | `gateway/` | §1.9. |
| **Destruction gate** | `integration/vigil_integration/destruction_gate.py` | m-of-n threshold approval with a mandatory owner signer fixed at deployment, action-binding, a dead-man's-switch window, and single-use tokens (`docs/AS-BUILT.md` §2). |
| **Challenge oracles** | `integration/vigil_integration/challenge_oracle.py` | A fresh per-run randomized challenge (nonce / canary / OOB token / value control) makes replay/hallucination "structurally impossible"; kernel-minted `Verified\|Abstain` HMAC an LLM cannot forge (`docs/AS-BUILT.md` §2). |
| **Per-action approval** | `live/approval_token.py`, `live/approval_broker.py`, `live/nonce_ledger.py` | Single-use `O_EXCL` nonce, action-bound, owner-signed, expiry-checked. Per-action owner approval is **the default offense authority** (`docs/AS-BUILT.md`, #178). |
| **Sovereignty guard** | `apps/sigil/sigil/reuse/assert_no_offense()` | Refuses to run if any `framework.*`/`strix.*` module is loaded in a SIGIL process. |
| **Hard guardrail** | `integration/vigil_integration/safety/hard_guardrail.py` | Non-disableable categorical target refusal. `[doc-claim on the category list; file verified present.]` |
| **Scope gate (external tools)** | `live/external_tool.py` `ScopeGate` | Composes the gateway L3/L4 denylist with the charter scope **before any traffic**; an out-of-scope / IMDS / unauthorised target is refused and **the tool is never launched**. |

---

## 5. How the system learns — and the strict limits on learning

There are **five** distinct learning mechanisms. Every one is constrained so that learning can change
*effort ordering, priors, confidence display and drafted proposals* — and can **never** decide that
something is true, grant authority, or apply itself.

### 5.1 Cross-engagement memory (MLS) — `framework/v2/memory/`

"Persistent priors substrate. Every engagement writes to it; every new engagement queries it."

- **Storage:** SQLite at `framework/v2/.memory/store.sqlite` (gitignored); schema-of-record
  `memory/schema.sql` (version 1). Tables: `engagements`, `findings`, `hypotheses`, `payloads`,
  `dead_ends`, `archetype_priors`, `playbook_outcomes`, `schema_meta`.
- **Embeddings:** `LexicalEmbedder` always available (a **256-dim feature-hashing TF vectorizer**);
  `SentenceTransformerEmbedder` upgrades if `sentence-transformers` is importable; selected by
  `CRUCIBLE_EMBEDDER`.
  **Honest limitation stated in the README itself:** "The lexical default … finds engagements with
  overlapping vocabulary — *not* semantic neighbours. This is documented in `V2-LIMITATIONS.md` and is
  the right default for an offline-first framework."
- **API:** `recorder` (write), `recall` (`similar_targets`, `winning_hypotheses`, `payload_priors`),
  `priors`, `postmortem`, `fleet`, `migrate`. CLI: `python3 -m framework.v2 memory status|similar|priors|seed`.
- Fed by `agents/memory_agent.py`.

### 5.2 The check-ordering bandit — `framework/v2/scanner/learning.py`

A **contextual bandit** that learns which arm (a check / bug class / `(bug_class, payload_family)`) is
most likely to land an oracle-confirmed hit "on targets that look like this one".

- **Algorithm:** Thompson sampling over per-`(context, arm)` Beta posteriors, `Beta(1,1)` prior;
  `alpha` = oracle-confirmed hits + 1, `beta` = misses + 1; `select` draws one sample per candidate arm
  and returns the max. "exploration/exploitation with no tuned epsilon."
- **Determinism:** every draw comes from an **injected** `random.Random` — no module global, no
  wallclock; given the same posteriors and rng, `select` is replayable.
- **Isolation:** "Contexts are independent: learning on one target archetype never moves another's
  posteriors." Posteriors serialise to plain sorted JSON for warm-start.
- **The limit:** the reward signal is check *productivity*. Per `calibration/reward_bus.py` this is
  "legitimate because the bandit **ORDERS effort** — it never gates a surface or promotes a finding."

### 5.3 Calibration + the outcome ledger — `framework/v2/calibration/`

"This is what replaces the hardcoded `1.0`."

- **Contract:** `fit(ledger.pairs()) -> Calibrator`;
  `Calibrator.calibrate(raw_score, oracle_confirmed) -> probability in [0, 0.999]`.
  **It is never `1.0`** — probabilities clamp to `MAX_PROB = 0.999`: "a detector never claims certainty
  it cannot have."
- **Learned, never hardcoded:** isotonic regression (pure-Python Pool-Adjacent-Violators — no sklearn,
  no numpy). Even the boost an oracle-confirmed finding gets is the *empirically measured* rate. "If
  confirmed findings historically turned out to be false positives, that learned prior shrinks and
  confirmation stops meaning certainty."
- **Identity fallback under sparse data:** with fewer than `MIN_LABELS` (8) non-DISPUTED outcomes the
  fit degrades to a passthrough (`method == "identity"`). "We do not invent reliability we have not
  measured."
- **Deterministic:** the ledger orders by a caller-supplied monotonic **sequence int, never a
  wallclock**; every fit and metric is byte-stable and replayable.
- **Ground-truth labels:** `EXPLOITABLE`→1.0, `REMEDIATED`→1.0, `FALSE_POSITIVE`→0.0, and **`DISPUTED`
  is excluded from every fit and metric** — "We do not guess ground truth we do not have."
- **Oracle prior:** `P(exploitable | oracle_confirmed)` learned empirically, combined by noisy-OR and
  capped at `MAX_PROB`; with too few confirmed outcomes **no prior is learned and confirmation grants no
  boost** — "honest silence over an invented number."
- Other modules: `conformal.py`, `meta_monitor.py`, `report.py` (ECE/Brier/reliability bins —
  `[doc-claim, AS-BUILT]` display-only, never promotes), `ledger.py`, `reward_bus.py`.

**`calibration/reward_bus.py` — the single reward fan-out**, and the strongest anti-circularity
statement in the codebase, read verbatim:

> The CALIBRATION LABEL is NON-CIRCULAR — `outcome_label` resolves EXPLOITABLE only on genuine
> cross-oracle corroboration (>=2 distinct oracle kinds firing); everything else is DISPUTED (excluded
> from every calibrator fit). **A silent oracle is NEVER auto-labelled FALSE_POSITIVE — that would be
> the oracle judging itself.** … The BANDIT reward is check PRODUCTIVITY …, which is legitimate because
> the bandit ORDERS effort — it never gates a surface or promotes a finding. **LLM/critic signals never
> enter this path.**

`_CORROBORATION_MIN = 2` is a real module constant, and the docstring notes that real
EXPLOITABLE/FALSE_POSITIVE labels "come only from an INDEPENDENT adjudicator (eval corpus / operator)".
The three sinks fed are the bandit, the calibration ledger, and the memory priors — plus a `reward`
event on the spine.

### 5.4 Self-improvement proposals — `improve/`, `scanner/self_improve.py`, `knowledge_engine/evolve.py`

All three **propose; none applies.**

- **`scanner/self_improve.py`** mines three real, computable shortfalls: a **missing check** (a bug class
  the verify layer routes to an oracle but that no check produces), **low recall** (benchmark ground
  truth shows the scanner missing a class), and **low confirm-rate** (findings that resolved mostly
  not-exploitable in an `OutcomeLedger`). `draft_proposals` turns each into a `CapabilityProposal`; the
  suggested `oracle_kind` is taken from the verifier's own routing table "so a proposal never suggests
  an oracle the system cannot actually run for that class." Explicitly: "**It proposes; it never
  self-applies.**"
- **`improve/merge_gate.py`** is where deployment is held. A proposal MAY be merged only when **all
  three** hold: (1) the deployment holds the `SELF_IMPROVEMENT_MERGE` capability; (2) the candidate
  build's regression verdict passed; (3) at least the trust root's **threshold of governance authorisers
  signed the proposal's content digest**. It returns a `MergeDecision` and **does not touch the working
  tree** — "authorisation and application are separate, deliberately. A human (or a controlled deploy
  step) applies a proposal the gate authorised. **An uncertifiable, unattributable, self-mutating
  offensive tool is exactly what this gate exists to prevent.**"
- **`knowledge_engine/evolve.py`** — "the HONEST, BOUNDED self-evolve loop (K5)", with an unusually
  explicit self-description: a deterministic scan over **disclosed** vulnerability leads into a horizon
  of `CapabilityGap`s + coverage-gap synthesis; those become **DRAFT** proposals; "It **NEVER** merges or
  applies anything — `improve.merge_gate.evaluate_merge` … is the separate, human-applied gate, and K5
  does not call it." Predictions are recorded into a slug-scoped `OutcomeLedger` on propose; the outcome
  is recorded later by a real engagement firing or not firing the mapped oracle.
  Its explicit non-claims: "it does not forecast undiscovered CVEs, prove any vuln exists, fire an
  oracle, mint a FACT, or self-apply a change. 'Studied everything in scope' means 'drafted everything
  for the disclosed leads', not 'the system is complete'. **'Gets smarter' = better-calibrated priors +
  more PROPOSED coverage, never self-applied canon.**" All clocks are injected.

### 5.5 The learn-grant seam — sovereign → offense knowledge transfer

The only path by which the sovereign side can cause the offense side to learn. Both halves read:

- **Producer: `apps/sigil/sigil/knowledge/learn_grant.py`.** When the owner **approves** a queued
  `knowledge.learn_proposal`, this signs an **inert `learn_grant` envelope** and writes it to a
  filesystem spool. "the owner-signed APPROVAL is the sole trust operation; this only WITNESSES it and
  hands the offense side a signed pointer." Fail-closed and gated every round: it exports nothing unless
  the sovereign kill-switch is RELEASED **and** the `autolearn` capability latch is ENABLED. Idempotent
  (a marker under `<spool>/exported/`). Imports no `framework`/`strix`.
- **Consumer: `integration/vigil_integration/learn_drain.py`.** Drains `<spool>/incoming/*.json`,
  verifies each grant under the **owner's public key**, re-derives the full lead **from the offense's OWN
  intel** by `(slug, vuln_id)`, and runs K3 `deep_learn` — "which writes advisory FIND/DETECT/PREVENT
  skills, maps DETECT only onto **EXISTING** oracle kinds, **mints NO fact and bumps no priors.**"
  Invariants: FATAL-2 lazy import of `framework`; verification uses `vigil_core` only; "**the ONLY
  private key material anywhere is the OWNER's, held sovereign-side; this side holds only the owner
  PUBLIC key.**" Fail-closed: a bad/absent signature, wrong pubkey, non-bounded-regular-UTF-8 file, or
  any error → the file moves to `rejected/` and **nothing is learned**. A per-slug offense kill-switch
  **defers** a grant (moved back to `incoming/` to retry after release), "never silently drops it."
  `_MAX_BYTES = 256 * 1024`; the signed core is reconstructed from the fixed tuple
  `("schema","kind","slug","vuln_id","approval_seq")` before verifying, "so a hostile extra envelope
  field [cannot ride] inside the signed bytes."
  Threat bound, stated plainly: "a tampered seam can at most cause an advisory skill for a CVE already
  in the offense's scope."

### 5.6 The runtime doctrine that governs all of it

`engine/crucible/framework/cognitive/metacognition.md` — "IN FORCE on every reasoning call, above any
single task… When a task instruction conflicts with it, this doctrine wins; when in doubt, stop and
ask." Six numbered rules, read in full:

1. **Prove, don't guess — the oracle is the sole authority.** "A claim is a FACT only when a
   deterministic oracle has fired to confirm it. You ADVISE; the oracle CONFIRMS. Never label anything
   'confirmed' on your own confidence, an LLM vote, a critic's endorsement, or a plausible story."
2. **Reflect in the loop.** OODA cycles; re-orient by **RE-RANKING or DEFERRING** — "never by skipping
   an authorized attack surface. Coverage is mandatory; a surface is deprioritised, never silently
   dropped."
3. **Submit to the critics.** Adversarial critique from several angles; "A single well-founded objection
   demotes the claim. When the critics disagree, do not force a verdict: ABSTAIN and route to
   needs-evidence rather than assert through the disagreement."
4. **Refuse honestly.** "Refusals are EVIDENCE — record them, never hide them. Hard limits — scope,
   authorization, destruction, real user data — are inviolable and are never relaxed to make progress."
5. **Vote against yourself.** Prefer answers stable across independent attempts; disagreement **lowers**
   confidence or triggers abstention. "It may never raise confidence, and it never overrides an oracle."
6. **Learn, don't fabricate.** "Never fabricate a confidence, a coverage guarantee, or a corroboration
   you do not have. **A number you did not measure is not evidence.**"

### 5.7 Summary: what learning is NOT allowed to do

| Prohibition | Enforced/stated in |
|---|---|
| Learning may not promote a claim to a FACT. | `veracity/firewall.py` ("only ever DEMOTES or abstains… can NEVER promote a claim the oracle refused"), `oracle_adapter.py`, `agent/react.py`, `metacognition.md` §1 |
| The bandit may not gate a surface or promote a finding — it only orders effort. | `calibration/reward_bus.py` |
| Reflection may not gate or skip an attack surface — only re-rank/defer. | `agents/reflection.py`, `metacognition.md` §2 |
| A silent oracle may not be auto-labelled FALSE_POSITIVE. | `calibration/reward_bus.py` (`_CORROBORATION_MIN = 2`; else DISPUTED) |
| LLM / critic signals may not enter the reward path. | `calibration/reward_bus.py` |
| Critics may object or abstain but may **never** confirm. | `agents/critics.py` (the verdict type itself) |
| Cognitive refusal only demotes / routes to needs-evidence; never promotes, never gates a surface. | `agents/cognitive_refusal.py` |
| Calibrated confidence may never reach 1.0, and with <8 labels degrades to identity. | `calibration/README.md` (`MAX_PROB=0.999`, `MIN_LABELS=8`) |
| Self-improvement may not self-apply; a merge needs capability + green eval + threshold governance signatures, and even then only *authorises* — a human applies. | `improve/merge_gate.py` |
| The self-evolve loop drafts only; never merges, never mints a fact, never fires an oracle, never forecasts undisclosed CVEs. | `knowledge_engine/evolve.py` |
| Cross-plane learning grants mint no fact and bump no priors, map DETECT only onto existing oracle kinds, and are gated on kill-switch RELEASED + `autolearn` latch ENABLED. | `learn_drain.py`, `learn_grant.py` |
| A graph partition / session registry may never be read back into a tier, grant, authorization or FACT — the store exposes no such surface. | `console/sessions.py`, `graph/store.py` (per `DEFERRED-INFRA.md` §G1) |
| Fireteam members may not self-escalate tier or self-authorize a dangerous tool; caps can never be A3. | `fireteam/__init__.py` |
| The world model never reads the clock; memory/calibration order by injected monotonic seq. | `worldmodel/README.md`, `calibration/README.md` |
| Learned knowledge is leads/skills/priors, never oracle-confirmed facts; any framework change requires operator **accept**; activate/deactivate + **stop** always honored. | ADR 0001, "Locked operator decisions" |
| Observability reports; it never gates. | `README.md` §the-parts (`observability/`) — `[doc-claim]`, module verified present |

---

## 6. Honest-status notes for downstream writers

Where the difference between "built", "built but not exercised against a live third party", and
"planned" matters most.

1. **The E-series is complete and wired end to end; what remains is real-world live fire.** All six
   capabilities (§1.10) have oracle + producer + evidence branch + offline fixture proof, and none
   carries `blocking_work`. Every one of them states, in the code and in the registry, that
   **real-transport live fire against a real third-party cloud account / cluster is deferred on an
   operator-provisioned credential**. That is a deliberate design position, not an unfinished feature:
   the detection logic, evidence handling, certificates and safety gates are built and proven; only
   pointing them at a live third-party account is pending. E2 (IAM privilege escalation) is
   *permanently* offline-by-design — "a defensive verification oracle never executes the escalation."
2. **The live end-to-end validation to date was on a purpose-built loopback target on `127.0.0.1`**,
   plus one external run against the vendor-published `testasp.vulnweb.com` (2 oracle-confirmed FACTs,
   re-verified offline 2/2, a tampered byte rejected). `[doc-claim — I read the claim in
   `docs/AS-BUILT.md` and `targets/testasp/charter.md` §7, not the run.]`
3. **LEAD-only *by design*** (an honesty choice, not a gap): detection planes whose logs do not exist
   (egress/command-and-control, directory/identity graph, cloud/CloudTrail, session-phishing); any
   judgment made by another AI (`gauntlet/`); the cognition governors; timing-only `request_smuggling`
   observations (capped at LEAD by audit A12 / #269).
4. **Built but awaiting external infrastructure:** a running Neo4j (client body built, driver + service
   absent → live constructor raises, parity test loud-skipped); the OTLP collector; confidential-
   computing hardware for a real TEE (SEV-SNP/TDX stubs **raise**; a software/TPM Ed25519 quote works
   with `hardware_backed=False`).
5. **Scaffolded, honestly stubbed:** `agent_body/interface.py`; the binary/memory-safety auto-patch tier
   (crash-confirm and fix-by-oracle-silence work; **patch synthesis is research-gated**).
   `docs/DEFERRED-INFRA.md` defines the tag vocabulary: `[BUILT]`, `[SCAFFOLD]`, `[hardware-gated]`,
   `[research-gated]`, and states the invariants that must not be relaxed on activation (determinism,
   oracle authority, FATAL-2, honesty).
6. **A conditional guarantee stated as conditional:** the transparency log's resistance to equivocation
   is **prevented only when a strict majority of distinct witnesses co-sign**; below that it remains
   *detectable* but not prevented. `[doc-claim, README; `transparency.py` verified present.]`
7. **Supply-chain hardening is landing today and is partly in-flight** — see §1.11 for exactly which
   pieces are on `main`, which are in the `a14-supply-chain` worktree, and which (the CI gate file and
   the CRITICAL-blocking vulnerability gate) I could not yet see in the tree.
8. **The claim-discipline doctrine is two-directional and machine-enforced.** `docs/CLAIM-DISCIPLINE.md`
   opens with "**This document raises the system; it does not lower the claim**", and names the failure
   mode it exists to prevent: "the failure mode of every 'do not overclaim' rule is a ratchet: each
   inconvenient capability gets quietly redefined as out of scope, every sentence stays technically
   true, and the product becomes honest about doing less and less." The two enforcement directions are
   equal partners: (1) never assert what is not established; (2) **never leave a capability unbuilt by
   narrowing the claim** — the gap becomes named `blocking_work` in the registry.
   It is enforced by `engine/crucible/framework/v2/scanner/tests/test_claim_discipline.py`, and the doc
   is explicit about the **limits of that enforcement**: it is "a registry lint plus runtime admission
   tests, which is narrower than 'the codebase obeys this'… It does **not** statically prove that every
   code path routes through admission" — that rests on adversarial human review and is marked
   `[REVIEW]`. Rules not enforced by a test must carry a `[REVIEW]` marker; "Adding prose here without
   either an enforcement test or a `[REVIEW]` marker is itself an overclaim about this document."
   The registry is `docs/capability-matrix/evidence-branches.json` (`schema:
   vigil-evidence-branches/1`), **26 branches** at this commit, each declaring `fact_capable` and
   `clean_capable` separately from `target_fact_capable`/`target_clean_capable`.
9. **Numbers I did not independently verify** `[doc-claim / NOT VERIFIED]`: "260+ features" and the UI
   screen count in `README.md`/`docs/FEATURES.md`; the "35–90% industry false-positive rates" and the
   curl bug-bounty anecdote (attributed in-README to `docs/research/FRONTIER.md`); the benchmark
   scoreline "11|0|0"; test counts; `apps/sigil/README.md`'s "phases 0–9 complete"; the spine's "43k+
   records".

---

## 7. Loose ends / gaps in this inventory

- I did not read `docs/FEATURES.md` (the exhaustive per-feature catalog) or `docs/AS-BUILT-LIVE.md` in
  full; a writer needing per-feature detail should go there — but see the stale-count warning at the top.
- I did not read the Rust kernel sources themselves, only enumerated them and read the CI job that
  tests them.
- `framework/v2/agents/tier3_validation.py`, `intruder/`, `repeater/`, `socialdefense/`,
  `remediation_binary/`, `plugins/`, `api/`, `mcp/` were confirmed present but not read.
- I did not run any test suite, `formal/check.sh`, or any CLI in this pass — everything above is static
  reading, except mechanical extractions (AST parse of `OracleKind`, regex extraction of `add_parser`
  names, JSON load of the evidence-branch registry).
- The `a14-supply-chain` worktree was read at one moment in time while work was in progress; its
  contents may have advanced since.
