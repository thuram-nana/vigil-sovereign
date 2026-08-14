---
name: vigil-live-program
description: VIGIL-LIVE — wired every phase to its live sidecar + unified engine + live validation; MERGED
metadata: 
  node_type: memory
  type: project
  originSessionId: 7758e121-f349-47d5-886b-6bb5a1d60e27
  modified: 2026-07-21T22:37:03.976Z
---

VIGIL-LIVE (§12 of the fusion plan, repo thuram-nana/vigil-sovereign at /home/kali/vigil) — take the
slice-1 fused phases (F0–F12+F2b, injected seams) LIVE and unify them into ONE system. **WHOLE PROGRAM
MERGED** across PR #29 + PR #30; all CI green. Builds on [[vigil-fusion-redamon-pentagi]].

**PR #29 (branch vigil-live-fleet, 9 parallel fleet streams, +358 tests → 905):**
- WS-0 substrate: `infra/loopback/vulnapp.py` (genuine controlled SQLi/XSS/traversal target on
  127.0.0.1:18080 writing CLF access+auth logs), `targets/loopback/charter.md`, OTel sidecar config.
- WS-6 usage-attestation ledger (`attestation/`) — the DEEP CORE: every run mints a mandatory signed
  append-only `usage_attestation` spine record (operator identity + TPM-anchored time + what);
  fail-closed (no attestation → no run). Red-pen HIGH fixed: `verify_ledger` total on malformed sig.
- WS-1 six live binders (`live/`): executor (loopback-pinned Kali subprocess), graph_neo4j (FACT-only
  projection), gauntlet_subproc (garak/PyRIT, oracle_kind routing), otel_export, think_claude
  (proposal-only, key-gated+replay), spine_vigilcore (real signed spine).
- WS-4 Detection Mirror (`detection/`) — AEGIS doc mined: 11 edge oracles (recon+injection+credential),
  each with a passing benign twin + signed PCF cert. Red-pen HIGH fixed: cmd-injection benign twin
  fired on a bare field value → require genuine command structure.
- WS-3 phase 32 AIxCC auto-patch (`autopatch/`): finding→patch→gated PR→fix-verify oracle; timeout→REJECT.

**PR #30 (branch vigil-live-engine, +22 tests → 922):**
- WS-2 unified engine `live/engine.py` + factory `live/wiring.py` + `vigil` CLI (`cli.py`,
  console_script). ONE attestation-first OODA loop wiring the F2 ReAct core through the REAL seams (no
  thunks): attest→think→parse-fail-closed→gate→execute→oracle-refire→sign-FACT/else-LEAD→project→govern→
  observe→checkpoint→loop, then Detection Mirror. Every seam injected (unit-testable); build_engine binds
  the real machinery, graceful-degrade to fail-closed. CLI: `engage`, `ledger who|when`, `verify-ledger`,
  `provision`.
- WS-5 live validation: a real `vigil engage http://127.0.0.1:18080` produced — attestation minted, 2
  tools ran through the full gate chain (owner-approved), 1 oracle-confirmed signed SQLi FACT
  (boolean_inference), 7 signed Detection-Mirror FACTs over the app's OWN logs (dual certs), 2 signed
  spine checkpoints, a who/when-queryable chain-verified TPM-anchored usage ledger. `docs/AS-BUILT-LIVE.md`
  = honest live vs LEAD-only vs deferred.

**KEY LIVE-WIRING LESSONS (recipe in engine/crucible):**
- The REAL gate `conjunctive_gate.build_offense_gate(slug, trust_root, classify, ceiling)` needs a signed
  CRUCIBLE authority on disk at `paths.authority_path(slug)` under CRUCIBLE_ROOT (default engine/crucible;
  override via env). Provision via `authority_from_scope(slug, ["127.0.0.1"], ...)` +
  `sign_authority(doc, {key_id: priv})` [DICT] + `save_signed_authority`. Scope must be LITERAL host (no
  CIDR — `host_matches_scope` has no CIDR). `authority_from_charter("loopback")` FAILS (heading mismatch).
- The REAL oracle `oracle_adapter.confirm_and_certify(finding, engagement_slug, signers)` — `signers` is
  `list[(key_id, priv_b64)]` [LIST-OF-TUPLES, different container from authority's dict]. Fires over
  `finding['oracle_context']`; boolean-SQLi = `probe_rounds:[{true,false_a,false_b}]` (true differs, falses
  agree). Same TrustRoot/keypair for the gate authority AND cert verify.
- **WARDEN structurally forbids an autonomous agent from auto-firing an offense tool**: `AUTO iff tier ≤
  AUTO_BAR(A1) AND ≤ ceiling`, but offense tools FLOOR at A2 → they ALWAYS queue for owner approval. The
  correct model is approve-then-run: WARDEN "queue" = needs the owner's signed approval (the human leg);
  the engine, given `owner_approves_offense` (CLI `--approve-offense`), upgrades the in-envelope queue to
  allow while PRESERVING CRUCIBLE scope denials (`_approval_gate`). The `vigil engage` invocation against
  one's own chartered loopback IS that standing approval.
- The usage ledger is its OWN append-only hash-chain: each engagement must CONTINUE it from the current
  head (read_ledger → next_seq/prev_hash), NOT restart at seq 0/GENESIS (that breaks the chain).
- SnapshotRecord's hash field is `.hash` (not record_hash). Detection FACT needs a cert `signer` +
  `verify_key` wired (else all detections are LEADs).
- Two-env: `framework.*` (offense) can't co-load with sigil.governor (sovereign). test_engine_live.py
  runs in CI's offense process `PYTHONPATH=integration:engine/crucible:gateway` (gateway needed — executor
  imports vigil_gateway.denylist at module top); importorskip framework → skips in the main/sovereign
  process. CI runs NO ruff. Live-Claude tests use `pytest.importorskip("anthropic")` (SDK absent in CI).
  Local `.venv-offense` needs a `vigil_gateway.pth` (gateway not editable-installed; hatchling absent
  offline so `pip install -e` fails — drop a `.pth` with the gateway dir).

Architecture diagram: `docs/architecture/vigil-architecture.html` (Artifact fb4d3c7d) — dark enterprise,
8 Mermaid layers + 118 cards; operator asked twice for bigger diagram text → Mermaid init fontSize 48px
(theme:base custom palette kept; natural-size SVG + forced light text fill).
