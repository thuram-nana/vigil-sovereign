# VIGIL — Continuation / Resume Doc (durable handoff)

> **Read this FIRST when resuming — local or cloud.** It is the single source of truth for *where the build
> is, how to run it, what's next, and the standard every phase must meet.* The approved architecture + phase
> specs are in [`docs/PLAN.md`](PLAN.md); the frontier research + the 1-of-1 differentiators are in
> [`docs/research/FRONTIER.md`](research/FRONTIER.md). Nothing about this project lives only in a chat
> session — it lives here, in git, and in the maintainer's Claude memory.

## What VIGIL is (one paragraph)
Fuse three of the owner's systems into ONE Claude-powered monorepo and push each layer past the state of the
art: **SIGIL** (sovereign Ed25519 signed-hash-chain spine + Rust WARDEN fail-closed governance; offense-free
personal orchestrator), **CRUCIBLE+AEGIS** (oracle-authority offensive engine + defensive dual; veracity
firewall + PCF certs + charter/ROE), and **Strix** (autonomous AI-hacker: agent loop + hardened Kali Docker
sandbox + Caido proxy + skills). The 1-of-1 thesis (validated by research): *an autonomous agent whose every
finding is deterministically ORACLE-CONFIRMED (no hallucinated findings), cryptographically SIGNED into a
witnessed tamper-evident transparency log (provable, offline-verifiable evidence), and hard-GOVERNED by a
fail-closed WARDEN + charter gate — that also runs the owner's personal life under the same sovereign spine.*
No competitor holds more than two of {oracle-confirmed · signed-provenance · hard-syscall-scope · sovereign ·
full-lifecycle-Claude}; fusing all five is unclaimed ground.

## THE STANDARD (non-negotiable, every phase)
1. **Production-grade only. NO scaffolds, stubs, demos, placeholder, or fake code.** Enterprise standard.
2. **Everything in this one repo** (`/home/kali/vigil` locally; `github.com/thuram-nana/vigil-sovereign`).
3. **Always green.** Each phase ends with all relevant test suites passing; never merge red.
4. **Build → adversarial dual-review → re-check on the fixed code → all-checks-green → PR → merge.** Every
   security-relevant change goes through a red-pen + independent sweep + a re-check that catches fixes'
   own defects. This discipline caught a real defect in *every* slice of the prior hard-prune program and
   in *every* fusion phase so far — keep it.
5. **Model + effort:** Opus 4.8, **ultracode / xhigh reasoning, Workflows for the heavy lifting** (fan-out
   builders + adversarial verifiers + synthesis). Never trust an LLM for a security verdict — the oracle
   decides (see FRONTIER.md).
6. **Never merge on GitHub unless all checks pass** (CI: `.github/workflows/ci.yml`). Use branches + PRs.
7. **The two FATAL flaws must be fixed before any *fused offense run*:** the sandbox egress gate (P6) and
   the offense-free process boundary (P5/P7). Do not run the fused offensive agent until both exist.

## STATE — what is DONE (all green, on `main`)
| Phase | Commit | What | Verified |
|---|---|---|---|
| P1 | `cb8ccd2..b4c1f19` | Monorepo scaffold; subtree-imported SIGIL, CRUCIBLE+AEGIS, Strix (**full history**); stripped cruft | 3 members present |
| P0 | `adef3ec` | Strix sovereign subtraction: deleted `posthog`/`scarf` phone-home → real local `telemetry/sink.py`; stripped OpenRouter attribution; `STRIX_LLM=anthropic/claude-opus-4-8`; telemetry off; Apache `NOTICE` | compile-clean |
| P2 | `17b5540` | `packages/core/vigil_core` — shared signature-safe integrity core (SIGIL's v2 Merkle-prune chain = source of truth) | **7 migration-safety tests** (v1 signs byte-identical, domain tag unchanged, threshold, tamper) |
| P3 | `21af4e9` | SIGIL adopts `vigil_core` (`reuse/` → re-export, no duplicate primitives); `assert_no_offense()` widened to bar `framework.*` AND `strix.*` | **full SIGIL Python suite green** through vigil_core |
| P4 | (post-P3) | **CRUCIBLE adopts `vigil_core`** (evidence/{canonical,chain} + entitlement/crypto → re-export; 5 shared model classes imported from vigil_core; `EntitlementError(CrucibleError, IntegrityError)`) — the make-or-break | **CRUCIBLE evidence/entitlement + broader core (~650 tests) green**; every signature re-verifies |

## STATE — what is NEXT (build in this order; each independently green)
See `docs/PLAN.md` §5–§10 + §I for full specs. Summary + gates:
- **P5 — Two-environment build boundary + inert-data channel.** `uv` workspace (or two venvs): **env-sovereign**
  (`vigil_core` + `apps/sigil`, NEITHER `framework` NOR `strix` installed → `assert_no_offense` holds
  structurally) and **env-offense** (`vigil_core` + `engine/crucible` + `vendor/strix`). Two locks. The offense
  worker gets an engagement-scoped store handle ONLY and **no owner key**. Gate: both envs build; sovereign
  env cannot import offense; offense env runs.
- **P6 — HARD EGRESS GATE (FATAL-1, highest security ROI, parallelizable).** Put the Strix Kali container on an
  internal-only docker network whose ONLY route out is a host-side **deny-default nftables gateway** keyed to
  the charter scope (`engine/crucible/framework/v2/common/ethics.py:parse_scope`) + a filtering forward-proxy
  that calls `agents/scope_gate.py:validate_action(url)` per request and DROPs off-scope before the wire.
  **Drop `NET_ADMIN`** (a container with it can rewrite its own firewall); keep `NET_RAW` only if SYN scans
  are needed. Caido stays *capture*, never a boundary. `gateway/` dir. Gate (red-team test that MUST pass
  before any offense): from inside the sandbox, 169.254.169.254 / the operator LAN / an off-scope host are
  DROPPED at the host gateway.
- **P7 — Unified spine/killswitch/TWO-ANCHOR TrustRoot + WARDEN tool gate + offense-worker trust domain
  (FATAL-2 + confused-deputy).** One signed spine as the single log; one spine-backed owner-signed-release
  killswitch. `assert_offense_gated()` = an A3, owner-signed, spine-logged, auto-expiring transition bound to
  one verified charter (mirror killswitch release semantics). WARDEN sets the FLOOR (offense exec ≥ A2, never
  auto-A0) + a coarse destructive-verb block, gates the semantic host-side tools (`repeat_request`→A2,
  `scope_rules`→A2/A3) via a `WardenGateHooks(RunHooks)` on the SDK `on_tool_start/end` seam; exec_command's
  TARGET authz is delegated to the P6 gateway (WARDEN classifies by tool NAME, not target). Two-anchor trust:
  CRUCIBLE m-of-n governance root signs the finding EvidenceCertificate; owner Ed25519 signs the spine head.
- **P8 — Claude runtime hardening.** Live-fire ONE real Claude scan turn to resolve the 3 LiteLLM seams:
  (a) `Reasoning(effort=)` 400 vs silent-drop, (b) prompt-cache `cache_read`>0, (c) `strix/report/dedupe.py`
  Responses-shaped `ResponseOutputMessage` text extraction returns empty on Claude → add a fallback.
  **Budget-meter fix (HIGH):** add an Anthropic price table so `get_total_llm_cost` is nonzero (else the budget
  governor silently disarms on Claude); assert cost increments after turn 1.
- **P9 — Oracle confirmation pipeline (the no-hallucinated-findings headline), ONE bug class at a time.** Build
  `integration/OracleConfirmationAdapter` (model on `engine/crucible/framework/v2/agents/oracle_probe_executor.py`):
  re-drive a scope-gated baseline+probe pair → build `FindingContext` → `OracleVerifier.confirm` → on confirm
  `evidence/certify.py:build/sign_certificate`. Extend Strix `tools/reporting/tool.py:create_vulnerability_report`
  to carry `{bug_class|cwe, injection_point, baseline_request_id, probe_request_id}` + a CWE→canonical-bug_class
  map. **Honesty invariant: only oracle-mappable classes (`BUG_CLASS_ORACLES`: sqli/xss/idor/ssrf/rce/lfi…)
  become signed FACTS; everything else is a labelled lead** (claiming every finding is a signed fact would be
  the hallucination the system exists to kill).
- **P10 — Spine-sign confirmed findings via the inert-data seam.** Confirmed `SignedEvidence` crosses to
  env-sovereign as **inert JSON** → `sigil/spine/store.py:append(kind="finding", payload=<SignedEvidence>)`
  WITHOUT importing `framework.*` (preserves `assert_no_offense`). Two-anchor (P7).
- **I1–I5 — Moonshot (all committed, phased):** I1 per-run randomized-challenge oracles for every finding class
  (generalize DARPA CGC Type-1/2) + kernel-minted `Verified|Abstain` epistemics (EG-VAR); I2 witnessed
  transparency log (Trillian Tessera / C2SP `tlog-tiles` + `tlog-witness` quorum + OpenTimestamps) + SCITT/
  OpenVEX certs; I3 Claude-Agent-SDK-native agent body (Kali tools → in-process MCP servers; a multi-week
  sandbox rewrite — Strix is welded to `openai-agents` SandboxAgent/Shell/Filesystem); I4 TEE attestation
  (Intel TDX / AMD SEV-SNP; Anthropic Confidential Inference) + FROST m-of-n threshold-gated destruction; I5
  AIxCC binary/memory-safety tier + autonomous auto-patching (LLM+fuzzing+concolic/SMT+sanitizer-oracle+patch
  re-verify; study Trail of Bits **Buttercup**, open-source). See FRONTIER.md for the exact techniques + sources.
- **Deferred (unrelated, resumable):** SIGIL hard-prune Slice E (prune cutover) + the live-93MB-spine migration
  in `apps/sigil` — the Slice A–D Merkle-prune work is *directly reused* as the I2 transparency-log substrate.

## HOW TO BUILD + TEST (exact, reproducible)
Local envs already created; a fresh clone recreates them thus:
```
# env-sovereign (vigil_core + sigil) — the personal, offense-free side
python3 -m venv .venv-sovereign && . .venv-sovereign/bin/activate
pip install -e packages/core/vigil_core && pip install -e apps/sigil   # builds the Rust WARDEN kernel (needs a Rust toolchain)
#   vigil_core migration-safety:  PYTHONPATH=packages/core/vigil_core python -m pytest packages/core/vigil_core/tests -q
#   SIGIL suite (temp home):       SIGIL_HOME=$(mktemp -d) PYTHONPATH=apps/sigil python -m pytest apps/sigil/tests -q

# env-offense (vigil_core + crucible + strix) — the autonomous offense side (NO owner key at runtime)
python3 -m venv .venv-offense && . .venv-offense/bin/activate
pip install -e packages/core/vigil_core "pydantic>=2.10,<3" structlog httpx requests PyYAML beautifulsoup4 \
  Jinja2 "cryptography>=42" packaging pytest pytest-httpserver pytest-asyncio
#   CRUCIBLE core:  cd engine/crucible && PYTHONPATH=. python -m pytest framework/v2/{evidence,entitlement,common,verify,confidence,worldmodel,calibration,authority} -q
#   (Strix full deps: openai-agents[litellm], docker, textual, caido-sdk-client — install to run its suite / a live scan)
```
CI runs the two integrity gates on every push/PR (`.github/workflows/ci.yml`): `vigil_core` migration-safety +
CRUCIBLE core on `vigil_core`. **Do not merge a PR with red CI.**

## THE AUTONOMOUS-BUILD PROTOCOL (for any agent continuing this)
For each phase P<n> / I<n>:
1. Branch `phase/<name>` off `main`.
2. Read `docs/PLAN.md` (the spec) + `docs/research/FRONTIER.md` (the technique + sources) for that phase.
3. Build it **production-grade** (no stubs). Reuse existing functions/patterns; grep before writing new code.
4. **Adversarial dual-review** (Workflow: 2+ red-pen lenses + independent verification of each objection),
   then a **re-check on the fixed code** (fixes introduce defects — this catches them). Fix every CONFIRMED
   finding. This is mandatory for anything touching crypto, governance, scope, the spine, or the oracle.
5. Run all relevant suites → **green**. ruff + mypy clean where configured.
6. Commit (end message with `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`), push,
   open a PR. **Merge only when CI + review are green.**
7. Update this file's STATE table + the todo, and this repo's memory pointer.
The orchestrator (main Claude session, Opus 4.8, ultracode-xhigh) oversees: assigns phases to builder agents,
reviews their PRs against the 1-of-1 standard, and merges. Sequential deps: P5→P7→P9→P10; P6 + P8 parallelize;
I1–I5 after the P-core. Fan out with Workflows; keep tightly-coupled reasoning single-agent.

## KEY FACTS a resuming agent must not re-derive
- The `crucible-evidence-v1\x00` signing domain tag is unchanged and load-bearing — never change it (breaks
  every signature). `vigil_core`'s v2 `SignedChainHead` signs a v1 head byte-identically (version-conditional
  `_head_payload`). All 5 shared model classes are now single-sourced from `vigil_core`.
- Strix's model layer is already provider-agnostic (`StrixProvider→LiteLLM`); `anthropic/claude-opus-4-8` is
  the default. The agent framework is `openai-agents` (its SandboxAgent/Shell/Filesystem drive the Kali
  container) — the Claude-Agent-SDK port (I3) is a real sandbox rewrite, not a config swap.
- Strix scope is prompt-level only + the container holds `NET_ADMIN`/`NET_RAW` — the P6 host-side egress gate
  is what makes it safe; do not run fused offense before it.
- `gh` on this machine authenticates as `thuram-nana` (mislabeled "Water-Hacker" in `gh auth status`).
