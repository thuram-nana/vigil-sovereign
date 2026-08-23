# VIGIL — as-built reference

The authoritative map of what is **merged and green** on `main`, the security properties each
piece actually enforces (stated honestly — conditional where the guarantee is conditional), and
what remains blocked on infrastructure. Companion to [PLAN.md](PLAN.md) (the design),
[CONTINUATION.md](CONTINUATION.md) (resume-here), and **[FEATURES.md](FEATURES.md) — the exhaustive
per-feature catalog (260+ features, every one with its `file:line` and how it works; the count is a pre-2026-08 lower bound — the audit-hardening A-series, the UI-completeness program, and the E1 IMDS wiring add more, catalogued in `docs/FEATURES.md` §7 and the README status table)**. This doc is the
*status map*; FEATURES.md is the *complete inventory*. When this doc and the code disagree, the code and
its tests win — update this doc.

> One rule underpins everything: **a claim is a FACT only when a deterministic oracle fires over
> data a real target produced.** The LLM proposes; the oracle confirms; the signature attests; the
> gates constrain. Nothing else promotes a claim to a fact.

## What's assured now (2026-07 hardening program — merged & CI-green on `main`)

Every item below merged only after adversarial red-pen + all required CI jobs green. Branch protection on
`main` is live, and its exact shape matters more than the slogan:

| Protection | State today |
|---|---|
| Required status checks | **14**, all of them: `A14 supply-chain gate` · `CRUCIBLE core on vigil_core` · `CRUCIBLE eval + benchmark corpus` · `formal (TLA+ core-invariant model check, F1)` · `gateway egress gate (P6)` · `integration two-env boundary (P5)` · `livefire smoke (per-PR subset)` · `loopback engagement (end-to-end + offline re-verify)` · `SIGIL governor gates (P7 — offense gate + authn)` · `SIGIL lint (ruff blocking + mypy can-complete)` · `strix Claude-runtime (P8)` · `the briefing explains every agent and capability` · `vigil_core — shared integrity substrate` · `WARDEN Rust kernel (A10 durability)`. The committed source of truth is [`.github/required-status-checks.txt`](../.github/required-status-checks.txt); the offline test `docs/tests/test_required_checks_canonical.py` and the live-reality workflow `.github/workflows/branch-protection-verify.yml` both key on it, so this table cannot drift from the settings again. |
| Branch must be up to date before merge | **required** (`strict: true`) — a PR must be rebased on the current `main`, so a check cannot pass against stale code |
| Force-push to `main` | blocked |
| Branch deletion | blocked |
| Administrator enforcement | **off** (`enforce_admins: false`) — the repository owner keeps an explicit admin override |
| Accuracy gate | rides **inside** `CRUCIBLE core` (required). `test_recall_baseline` + `test_gate` re-derive the committed accuracy core byte-identically, verify its Ed25519 signature against a source-pinned trust root, and assert recall 1.0 / precision 1.0 / fp 0 / fn 0. The full corpus/soak `CRUCIBLE eval + benchmark corpus` is now **also** a required check — so the accuracy measurement is gated from both sides. Keeping the decisive assertions inside the already-required `CRUCIBLE core` is what makes an accuracy regression unmergeable **in code**, independently of any branch-protection setting a person could change |
| Required reviews | **none** — `required_pull_request_reviews` is not set. A code-owner/approving-review gate is a deliberate, scheduled handoff, **not** a shipped control; do not read this table as claiming review is enforced |
| Signed commits | **not required** by the settings — also a planned handoff, not live |

So the honest form of the claim is: **a pull request cannot merge without those 14 checks green, on a branch up to date with `main` — unless the
repository owner uses their admin override.** For every ordinary contributor, and for every automated agent
in this repo, the gate is unconditional. For the owner it is a deliberate, attributable act rather than an
impossibility. Anyone with read access can re-derive this in one command — it now succeeds (the API returned 404 until protection was enabled):
`gh api repos/thuram-nana/vigil-sovereign/branches/main/protection`. Expect `required_status_checks.contexts` to hold the 14 names above (compare it against `.github/required-status-checks.txt`), `required_status_checks.strict = true`, `enforce_admins.enabled = false`, `allow_force_pushes.enabled = false` and `allow_deletions.enabled = false`.

- **Per-action owner approval is the default offense authority** (#178). A queued offense action, and the
  vendored agent's arbitrary shell (`exec_command`/`write_stdin`, gated by default — and **fail-closed since
  #296**: a wiring failure raises `WardenGateUnavailable` and stops the run rather than continuing ungated),
  runs only on a
  single-use, action-bound, owner-signed token (`vigil approve`); no authority / no token ⇒ blocked.
- **Every finding tells you how to re-verify it** (#179), on all five surfaces (report · SARIF/JSON ·
  signed certificate · proof bundle `HOW-TO-VERIFY.md` · UI drawer); per-session graph as a real
  spine-projection backend; `dossier --session` handoff; Inbox/assurance/feed UI.
- **The live claims match the on-disk spine** (#180): a loopback `error_signature` SQLi FACT re-verified
  3/3 offline, and an external `testasp.vulnweb.com` run that minted 4 cert-backed FACTs through the full
  gate (destructive probes default-denied) onto the signed spine.
- **A finding is independently verifiable without trusting or running VIGIL** (#181): an open
  proof-carrying-finding spec + JSON Schemas + a **standalone VIGIL-free verifier**
  (`docs/proof-carrying-finding/`), with canonical-bytes parity proven and tamper rejection.
- **Falsifiable, tamper-evident benchmark** (#182): `make bench` → a signed scorecard (precision/recall/FPR
  with safe negative controls; m-of-n Ed25519 + out-of-band fingerprint pin).
- **Attack-path + chokepoint triage** (#181): `vigil crucible attack-paths <slug>` — shortest paths, the ranked
  chokepoint ("which one fix breaks the most attack paths"), blast radius, and a what-if, over a pure
  spine→world-model projection.
- **Confidence calibration** (#183, `vigil crucible calibration report`: ECE/Brier/reliability bins — display-only, never
  promotes) and **coverage-guided, oracle-gated, non-evasive discovery** (#183, `scanner/coverage.py`:
  re-ranks effort, never gates a surface out, never confirms without an oracle).

**Honestly not-yet / gated** (capabilities present; refinement or external dependency remains): the
cross-engagement meta-learning *auto-loop* + `engage --learn` (its primitives — OutcomeLedger, memory
priors, bandit seeding, postmortem — exist and are used; the auto-seed/persist convenience is the last
wire); the Assurance reliability-diagram panel (lands once the OODA loop writes a per-engagement outcome
ledger); and the genuinely external/hardware-gated items — a real TEE (silicon), the live Claude-API step
(needs a provisioned key), and a full binary cyber-reasoning auto-repair engine (research) — all shipped as
honestly-labelled scaffold + software fallback + activation runbook, never claimed as active.

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
| I1 — challenge oracles | `challenge_oracle.py` | Per-run randomized challenge (nonce/canary/OOB-token/value-control) makes replay/hallucination **structurally** impossible — **scoped to** the bug classes `BUG_CLASS_CHALLENGE` maps to a challenge kind; `oracle_for()` returns `None` for any other class, which therefore rests on deterministic oracle re-execution rather than on a challenge. Kernel-minted `Verified\|Abstain` HMAC an LLM cannot forge. |
| I2 — transparency log | `transparency.py` | Witnessed, split-view-resistant checkpoint chain over the signed spine head (details §4). |
| I4-slice — threshold destruction | `destruction_gate.py` | m-of-n, owner-mandatory, action-bound, dead-man's-switch, single-use authorization for irreversible actions (details §3). |
| SCITT/OpenVEX certs | `scitt.py` | Offline-verifiable-forever finding certificates: OpenVEX vocab + DSSE m-of-n + RFC-6962 Merkle inclusion receipt anchored to an I2 witnessed checkpoint (details §5). |

---

## 2.1 This session's merges (UI wiring, dossier, report how-to, graph store, moonshot scaffolds)

Merged and green on `main` in the current program (see `git log` and `docs/DEFERRED-INFRA.md`):

| Area | Module(s) | What it is |
|------|-----------|------------|
| Embedded graph store (G1) | `engine/crucible/framework/v2/graph/store.py` | `EmbeddedGraphStore` — a file-backed, **one-way** projection of the append-only spine into nodes/edges (canonical JSON, no wallclock/RNG, byte-identical out for identical events in). No promote/grant/tier surface: a partition is disposable state, never an authority. `Neo4jGraphStore` sits behind the same interface as a **real client body** (its methods issue MERGE/read Cypher through an injected or lazily-imported driver); only **construction** raises, and only when no driver is injected and the `neo4j` package is absent — the live external service is what is deferred, not the client code. |
| Moonshot scaffolds (X1/X2/X3) | `framework/v2/attest/provider.py`, `remediation_binary/tier.py`, `agent_body/interface.py` | `SoftwareAttestationProvider` (a working Ed25519/TPM quote proving integrity + origin, `hardware_backed=False`; SEV-SNP/TDX stubs raise — hardware-gated); `SanitizerSilenceTier` (crash-confirm + `remediated_if_silent` fix-by-oracle-silence over the **existing** sanitizer oracle work; `synthesize_patch` raises — research-gated); `AgentBody` (an interface-only contract, gate-before-execute structurally enforced — research-gated). Honest status matrix in `docs/DEFERRED-INFRA.md`. |
| Report how-to (R1) | `engine/crucible/framework/v2/report/howto.py`, `export.py` | A deterministic per-finding **"how to verify / test / patch"** block (a pure function of the graded finding — no traffic, no RNG). A FACT points at the real re-executable `python3 -m framework.v2 verify` over its retained `reverifiable.json`; a LEAD says "how to CONFIRM" and never implies proof. Woven into the report **and** the SARIF 2.1.0 / structured-JSON export (a LEAD capped at `note` so it never blocks a CI gate). |
| One-click dossier (R2/R3) | `report/dossier.py`, `integration/vigil_integration/cli.py` (`vigil dossier`), `framework/v2/console/server.py` (`POST /api/dossier/<run>/build`, `GET /api/dossier/<run>.zip`) | Compiles a whole run into ONE self-contained, tamper-evident `.zip` (reusing the report renderers + lazily the proof bundle) with an out-of-band-pinnable fingerprint. The GET route **streams a pre-built** file only (building is the CSRF-guarded POST); a bad run id fails closed. This is the **first real client download**. Red-pen fixes on merge: stop an evidence-symlink exfil; scrub secrets inside lists. |
| UI wiring (U0/U1/U2) | `packages/vigil-ui/app.js`, `console/server.py` | New-Assessment **cloud/K8s posture launch** (`actions.launch_cloud`); the **actionable Fixes** screen ("Apply fix (gated)" → `actions.apply_fix` shells `vigil patch`, never `--open-pr`, with an honest provenance pre-check so it's never inert-misleading); the Knowledge screen's **"Pull now"** one-shot feed refresh + **"Draft skills (deep-learn)"** (`/api/knowledge/<slug>/deeplearn`). |
| Live L1 error-based SQLi | `framework/v2/verify/oracles.py` (`error_signature_oracle`, `ERROR_SIGNATURE`) | `error_based_sqli` routes to the `error_signature` oracle first; over the loopback app it minted a real FACT **re-verified 3/3 offline with no Caido/Docker** (the first-party executor captured the datastore-error bytes). |
| Live L2 **external** FACT (2026-07-29, re-corroborated 2026-07-30) | `targets/testasp/charter.md` §7 | The byte-identical external run is **DONE and re-corroborated**: a fresh chartered run against the vendor-published `testasp.vulnweb.com` on 2026-07-30 ran live through the full gate chain (every destructive probe **default-denied**, no TTY) and minted **2 oracle-confirmed, certificate-backed findings** onto the signed spine (`.blackboard/store.sqlite`, `--spine`): `boolean_sqli` (`differential_response`, 0.99) + `open_redirect` (`achieved_state`, 0.90). The **signed spine carries these FACTs** (resolving an earlier per-run `telemetry.json` that showed only a refusal — a destructive-edges-denied view, not the confirmed edge plane). Two `request_smuggling` timing detections (CL.TE / TE.TE) were also observed but are **UNCONFIRMED LEADs**, capped at LEAD per audit **A12 (#269)** — timing alone is a hypothesis, not proof, so they are **not** FACTs and are **not** carried as confirmations on the spine. The self-contained **3/3 offline re-verify** is demonstrated on-box by the loopback L1 FACT (`AS-BUILT-LIVE.md` §L1); this external run is corroborated by minting through the full gate + a tampered-baseline byte rejected (`[BAD] CLAIM-MISMATCH`). Demonstrated live **and** external. |
| Governed local Terminal + AI chatbot (T2) | `integration/vigil_integration/live/executor.py` (`execute_terminal`, `_TERMINAL_ALLOWLIST`/`_FIND_SAFE_PREDICATES`/`_TERMINAL_BARE_ONLY`/`_TERMINAL_METACHARS`), `live/wiring.py` (`build_terminal_runtime`), `cli.py` (`_cmd_terminal` → `vigil terminal`), `framework/v2/console/actions.py` (`terminal_propose`/`terminal_dryrun`/`terminal_run`/`terminal_history`), `console/server.py` (`/api/terminal/*`), `packages/vigil-ui/app.js` (`renderTerminal`) | A **local-only** inspection shell where **the AI proposes; the allowlist + WARDEN gate + owner approval decide**. Every command is parsed with **no shell** (argv list, `shell=False`; any shell metacharacter refuses the whole command), **allowlist-validated** to local read/print binaries only (`ls cat head tail wc stat pwd whoami id uname echo df du ps uptime grep cut tr`; `find` via a read-only *predicate* allowlist — exec/write predicates refused by omission; `date`/`hostname` **bare-only**), classified **WARDEN A2 → QUEUES** under the A1 ceiling (never auto), and — on the operator's Run/`--approve` — run and written as a **signed, redacted `ExecRecord`** on the spine (no signer ⇒ refuse before running). It can **neither egress, write files, nor spawn an interpreter — by construction** (no such binary is on the allowlist; the test suite's hostile red-pen battery — network binaries, interpreters, writers, metacharacters, unsafe `find` predicates, and coreutils option-abbreviation bypasses such as `sort --compress=curl` / `--out=` — is refused across the board). The chatbot (`terminal_propose`) has Claude return **one** candidate string that is re-parsed + allowlist-checked exactly like a typed command (a hallucinated/injected off-allowlist command is refused, never run); no `ANTHROPIC_API_KEY` ⇒ an honest "add a key or type a command directly" — the direct terminal needs no LLM. The console's `_TERM_*` allowlist is an **advisory mirror** for the dryrun badge only; the authoritative check is inside `vigil terminal` at run time (the offense console must not import the executor — FATAL-2). |
| Strix shell gate (T3) — **on by default, fail-closed** | `integration/vigil_integration/warden_gate.py` (`attach_from_env`, `WardenGateUnavailable`), `vendor/strix/strix/core/runner.py` (`VIGIL_WARDEN_STRIX_GATE`) | The vendored Strix agent's arbitrary `exec_command`/`write_stdin` shell is WARDEN-gated. **This row previously said "gateable, not gated by default"; that was stale from #157 and is corrected here.** T3 landed it as opt-in; **#178 made it ON BY DEFAULT** (no opt-in required) and **#296 made it FAIL-CLOSED**: `attach_from_env` raises `WardenGateUnavailable` on any wiring failure instead of returning ungated hooks, and the runner narrowed its `except` to `ImportError`, so a governed run **stops** rather than silently proceeding with an unguarded shell. Exactly two paths run ungated, and both are deliberate: the **explicit opt-out** `VIGIL_WARDEN_STRIX_GATE` ∈ {`0`,`off`,`false`,`no`}, and a **bare vendored Strix checkout** with no `vigil_integration` importable (the `ImportError` path — nothing to govern, vendor stays byte-identical). |

---

## 2.2 Later merges this program (live model, per-action token, sandbox, telemetry, inbox)

| Area | Module(s) | What it is |
|------|-----------|------------|
| Live-key Claude think-step (M1) | `integration/vigil_integration/live/think_claude.py` | Binds the F2 ReAct think-step to a **real** Claude Messages call (`anthropic` SDK, `claude-opus-5`, `thinking:{type:"adaptive"}`, streaming via `.get_final_message()`) when an API key is present; **falls back to the injected keyless replay** when none is (tests stay hermetic). Untrusted target text is nonce-boundary wrapped; secrets are F3-redacted before the prompt; the reply is parsed **fail-closed** (garbage → the safest `ASK_USER`). The model **only proposes** — the decision still clears the conjunctive gate and the oracle still judges the bytes, so a hallucinated context can never mint a FACT. The key is never logged, spined, or echoed. |
| Per-action approval token (M2) | `integration/vigil_integration/live/approval_token.py`, consumed in `live/wiring.py` (`_approval_gate`) | Replaces the *standing* `--approve-offense` flag with a **single-use, action-bound, owner-signed** token over canonical `{tool_name, target, action_digest, nonce, not_after}`: the gate verifies the owner signature against the **pinned** governance pubkey (key_id must match), checks the action binding, enforces expiry, and **burns the nonce atomically** (the LAP-3b `O_EXCL` ledger). A replayed / rebound / expired token is refused. Standing approval remains available as an explicit lower-assurance mode. |
| Kernel-isolated `sandbox.exec` | `integration/vigil_integration/live/sandbox_exec.py`, `live/executor.py` (`execute_sandbox`), `cli.py` (`vigil sandbox`) | A gated exec runner that runs an allowlisted command inside **bwrap** with `--unshare-all` (`_BWRAP_BASE_FLAGS`, `sandbox_exec.py:57` — unshares net/pid/ipc/uts/cgroup/user; the **network** unshare is the load-bearing one for the egress floor: no IP, no abstract unix sockets) and a **minimal RO allowlist** bind — never `--ro-bind / /`, which carries host `/run` **pathname** sockets (docker.sock, D-Bus) into the sandbox: the merge-blocking red-pen finding. Same gate chain as the terminal (WARDEN A3 via a danger token → queue for owner approval → signed, redacted `ExecRecord`); `SandboxUnavailable`/`ValueError` → DENY; no signer ⇒ refuse before running. |
| Live telemetry-collector sidecar (G2) | `integration/vigil_integration/telemetry.py`, `uiproxy.py`, `cli.py` (`vigil telemetry`, `vigil up --with-telemetry`), `console/api.py` (`/api/telemetry`) | A pids-tracked sidecar that tails the signed spine and materializes a live assurance/metrics snapshot (`collect_snapshot` — a **pure** spine→metrics projection, no wallclock/RNG, byte-identical out for identical events in). Opt-in, loopback-bound, no egress. Fail-soft: no spine → an honest empty snapshot. |
| Agent inbox (U3) | `console/api.py` (`inbox`), `console/server.py` (`/api/inbox/`) | A read-only **endpoint** (`GET /api/inbox/<slug>`) over the `agent_message` spine kind (sender/recipient/topic/body/refs). **Load-bearing honesty:** a message is structurally **not evidence** — no fact-building path reads it; it is advisory coordination only. **The endpoint is built and routed; no UI screen consumes it yet** (routed-but-orphaned, like `/api/telemetry` — surfacing them in the UI is a follow-up). |

---

## 2.3 The 2026-08 merges (E-series cloud/K8s exploitation, A14 supply chain, sovereignty, CI)

This section exists because a readiness audit found the "authoritative map of what is merged" silent on
everything merged in this program — an agency asking *"show me your supply-chain hardening"* was handed
`AS-BUILT.md` and found zero hits. Every row below is merged on `main`.

| Area | PR | Module(s) | What it is |
|------|----|-----------|------------|
| **A14 — supply-chain hardening** | #294 | `.github/workflows/supply-chain.yml`, `infra/supply-chain/{sovereign.in,sovereign.lock.txt,image_pins.py,resolve-image-digests.sh}`, `engine/crucible/framework/v2/requirements.lock.txt`, `.trivyignore`, `docs/SUPPLY-CHAIN.md` | Base images **digest-pinned**; **two real hash-locked dependency locks** (one per environment) whose installability is proven in CI; an **SBOM**; and a **blocking CVE gate** — `trivy fs --severity HIGH,CRITICAL --exit-code 1` over the locks (raised from CRITICAL-only to HIGH+CRITICAL in **W3-9 (#432)** once the vendored `aiohttp`/`pyasn1`/`cryptography` HIGH backlog was cleared). The gate carries a **negative control** that runs the blocking configuration against a known-CRITICAL fixture *and* a HIGH-only fixture (fail-at-HIGH, pass-at-CRITICAL) and hard-fails if either comes out wrong, so "the gate can fire, and fires on a HIGH" is demonstrated rather than asserted. Honest scope is published in `docs/SUPPLY-CHAIN.md` §6 (MEDIUM and below are advisory; non-Python ecosystems are scanned, not locked; hashes are not signatures). |
| **Dependency CVE remediation** | #295 | `envs/*.txt`, `infra/supply-chain/sovereign.in`, both locks | `cryptography` upgraded past **CVE-2026-69247 (HIGH)** in **both** environments and re-locked. The first CVE the A14 gate surfaced, fixed rather than `.trivyignore`d. |
| **Strix shell gate fails CLOSED** | #296 | `integration/vigil_integration/warden_gate.py`, `vendor/strix/strix/core/runner.py` | `attach_from_env` raises `WardenGateUnavailable` instead of returning ungated hooks; the runner narrowed its `except` to `ImportError`. Detail in the T3 row of §2.1 — the most dangerous surface in the system now **stops** rather than continuing unguarded. |
| **Sovereignty governs LLM egress** | #300 | `integration/vigil_integration/live/{think_claude.py,codefix_runner.py}`, `engine/crucible/framework/v2/console/actions.py`, `kernel/sovereignty.py`, `kernel/backends/anthropic.py`, `bootstrap.sh`, `apps/sigil/sigil/ui/settings.py` | The four-tier ladder was documented and enforced at backend construction, but the model calls `vigil engage` actually makes went around it — `cli.py → wiring.py → live/think_claude.py` read `ANTHROPIC_API_KEY` and built an `anthropic.Anthropic` client with **zero** references to sovereignty anywhere in `integration/`. Every model-egress site — the engage think step (key path *and* injected-client path), the auto-patch coder whose prompt carries real repo source, and the cockpit's terminal router — now routes through the **same** `kernel.sovereignty` decision (`current().assert_permitted(name)`). Fail-closed throughout: the check precedes the SDK import and client construction, an un-evaluable policy refuses, an unknown backend classifies `cloud_only`, and an escaping error is a refusal. The tier vars are on the offense-child env allowlist (without them an operator's `AIR_GAPPED` choice was dropped on the way to the children), exposed in Settings and written into the generated `sigil.env`. **The default tier is still `PERMISSIVE`** — the ladder now binds, but you must choose your rung. |
| **CI covers the module the product is named for** | #299 | `.github/workflows/ci.yml`, `framework/v2/planner/tests/test_full_integration.py` | `veracity`, `kernel`, `planner`, `sensors`, `eval`, `defender`, `memory` and `analysis` were absent from CI's explicit path list — including the **anti-hallucination firewall**. Now covered, and the flagship URL→attack-tree→agent-mesh→report end-to-end test (which was RED against a pre-hardening expectation) is repaired. Adds the `CRUCIBLE eval + benchmark corpus` job — advisory when #299 introduced it, and since promoted to one of the **14 required** checks (see the protection table at the top of this file). |
| **E1 — IMDS credential capture** | #286 | `verify/oracles.py:imds_credential_capture_oracle`, `live/imds_runner.py`, `live/imds_verify.py` | Achieved-effect FACT: a credential retrieved from an instance-metadata endpoint **plus** a confirming `sts:GetCallerIdentity` / GCP `tokeninfo` call that authenticated with the *same* credential, bound by a shared fingerprint. The retained capture is **secret-safe** (secret material redacted to a presence marker), so the FACT re-verifies offline with no live secret. |
| **E5 — exposed-secret validity** | #288, #289 | `verify/oracles.py:exposed_secret_validity_oracle`, `verify/secret_capture.py`, `live/secret_verify.py` | Proves an exposed credential is **valid**, not merely present. Source-semantics are deliberately **inverted** vs E1: the exposure source is evidence but is *not* a firing gate, and the anti-laundering gate is the per-TYPE confirming-endpoint allow-list — so an attacker-controlled "confirming" endpoint cannot mint a FACT. |
| **E3 — GCP service-account impersonation** | #291 | `verify/oracles.py:gcp_sa_impersonation_oracle`, `verify/gcp_impersonation_capture.py`, `live/gcp_impersonation_verify.py` | A principal minted a short-lived token **as** a named target service account and a confirming call **echoed that identity** at an allow-listed Google introspection endpoint. The anti-laundering gate is entirely on the confirming-call side: an echo of a *different* SA cannot mint. |
| **E2 — IAM privilege escalation** | #292 | `verify/oracles.py:iam_escalation_oracle`, `verify/iam_escalation_capture.py`, `live/iam_escalation_verify.py` | The **achieved-escalation (strict-gain) dual** of the reachability half: an explicit differential of two BFS closures proves the retained configuration *unconditionally permits* an escalation primitive from a fixed, auditable set that **strictly increases** what the base principal can reach. Fail-closed by construction — a Condition, a `NotAction`, an explicit Deny, a restricting boundary/SCP or a non-covering Resource wildcard contributes **no** edge. **VIGIL never executes the escalation**: it proves the grant path exists and does not use it. That is a design commitment, not a missing feature. |
| **E4 — Kubernetes RBAC** | #290, #293 | `verify/oracles.py:{k8s_workload_posture_oracle,k8s_rbac_verb_grant_oracle}`, `verify/k8s_rbac_grant.py`, `live/{k8s_rbac_verify.py,k8s_rbac_grant_verify.py}` | Two branches: an **anonymous-privileged binding** (TIER-1, the binding alone) and a **dangerous-VERB / default-SA verb grant** (TIER-2, rule-parsing). |
| **E4 live-fire against a REAL cluster** | #297 | `tools/livefire/k8s_rbac_livefire.{sh,py}` | The K8s branches are **no longer fixture-only**. The harness stands up a real single-node k3s cluster **VIGIL itself creates and owns** (throwaway, loopback-only, destroyed afterwards), plants known-dangerous *and* known-benign RBAC, captures what the real API server returns, and adjudicates those real bytes through the production path (oracle → admission → certificate → offline re-verify). Anonymous→cluster-admin CONFIRMED with an offline-re-verifying certificate; anonymous→view and named-user→cluster-admin correctly **not** confirmed. It **exits non-zero on any deviation** — a live-fire script that only prints is a demo, not a proof — and refuses to conclude anything while the cluster's role controller is still populating built-in roles (a race the harness caught on its own first run). What it does **not** cover is stated in the registry: a scope-gated *enumeration* runner that discovers bindings cluster-wide, and a managed control plane (EKS/GKE/AKS). |

**Live-fire status across the E-series, stated plainly:** E4's Kubernetes branches are live-fire proven
(#297). **E1, E2, E3 and E5 are fixture-proven, not live-fired** — the runner, admission, certificate and
world-model wiring are complete and proven offline, and real-transport live-fire is deferred on an
operator-provisioned lab credential. **No live cloud FACT has been claimed and none exists in the evidence
store.** The deferral, its provisioning steps and its pass criteria are in
[`docs/DEFERRED-INFRA.md`](DEFERRED-INFRA.md) §E; the per-branch statement is in
`docs/capability-matrix/evidence-branches.json`.

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
6. **Production multi-signer default (W9-5)** — under `VIGIL_POSTURE=production` the authorization path
   REQUIRES a genuine multi-signer quorum (threshold ≥ 2 with ≥ threshold distinct keys) and refuses a
   1-of-1 / pubkey-collapsed authority, fail-closed at both `DestructionAuthority` construction and the
   decision. Co-signer keys are provisioned per-host: `vigil enroll-cosigner` generates each key on its own
   host and emits a PUBLIC enrolment request with a proof-of-possession; `vigil assemble-destruction` builds
   the trust root from public material only (no private key on the minting box). See
   `docs/decisions/W9-5-cosigner-provisioning-multisigner-default.md`.

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
CI = 12 jobs in `ci.yml` (`vigil-core`, `briefing-completeness`, `crucible-core`, `crucible-eval`,
`loopback-engagement`, `gateway`, `integration` — two runs: sovereign, then the framework-dependent
oracle-adapter in its own process — `strix-vigil`, `sigil-governor`, `sigil-lint`, `formal-verification`,
`warden-kernel`), plus the `supply-chain` and `livefire` jobs in their own workflows. The full set of
required status checks is enumerated in the protection table at the top of this file and in the committed
source of truth [`.github/required-status-checks.txt`](../.github/required-status-checks.txt).

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
  The **auto-detect selector** `open_attestation_provider()` (+ `detect_tee()`, PR #156) is the
  "activates on hardware" seam: it probes for a TEE guest device (`/dev/sev-guest`, `/dev/tdx[_-]guest`;
  `VIGIL_TEE_BACKEND` overrides) and returns the hardware backend **only if it is both detected and
  implemented**, else falls back to `SoftwareAttestationProvider` with a note saying exactly why — so on
  any Linux PC today it runs software, and the day a hardware backend stops raising it activates
  automatically on that silicon. **Never raises** (fail-soft to software).
- **Binary / memory-safety auto-patch (X2, was I5).** `remediation_binary/tier.py` —
  `SanitizerSilenceTier` drives the **existing** `sanitizer_signal_oracle` to `confirm_crash` and to
  earn `remediated_if_silent` (the A6a "proven by oracle silence, never asserted" pattern). **`[research-gated]`**:
  `synthesize_patch` raises and `SymbolicCrashRepairTier` is a full stub — the generative localise-and-patch
  step (a CRS: LLM-guided fuzzing + concolic/SMT, angr/Z3) is unbuilt. (Study ToB "Buttercup".)

**Now built (was deferred):** the live-API-key Claude think-step (`integration/vigil_integration/live/think_claude.py`,
M1 — a real key-gated `claude-opus-5` call with adaptive thinking + streaming, keyless-replay fallback; the model still
only *proposes*, the oracle judges the bytes); the per-action **cryptographic approval token**
(`integration/vigil_integration/live/approval_token.py`, M2 — single-use `O_EXCL` nonce, action-bound, owner-signed,
expiry-checked; consumed inside the conjunctive gate); the live **telemetry-collector sidecar**
(`integration/vigil_integration/telemetry.py`, G2 — `vigil up --with-telemetry`); the **bwrap-isolated `sandbox.exec`
runner** (`integration/vigil_integration/live/sandbox_exec.py`, `--unshare-net` + minimal RO allowlist); the live
**external**, network-egress engagement (§2.1 Live L2 — done against `testasp.vulnweb.com`, 2/2 re-verified).

Still deferred (need a live external service / silicon): a running **external** Neo4j/OTLP service
(the embedded file-backed graph store, §2.1, is built); the extended Strix finding contract; confidential-computing
hardware; OpenTimestamps anchoring.
