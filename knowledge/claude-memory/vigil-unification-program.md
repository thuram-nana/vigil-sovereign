---
name: vigil-unification-program
description: "Unify AEGIS+SIGIL+CRUCIBLE+VIGIL into ONE system in /home/kali/vigil — one control plane over TWO isolated processes (two-env boundary = LOCKED safety invariant). ENTIRE PROGRAM COMPLETE (13 PRs #45-#57): W0 UI + S1 super-CLI + S2 WARDEN-classifier + S3 detection-vocab + S4 owner-root delegation + S5 (stable spine id + `vigil verify`) + S6 gate-of-record + S7 (a stable governance key, b owner-tie delegation ceremony, c detection FACTs cross the ONE inert seam + multi-segment transparency) + S8 whole-control-plane boundary guard + entrypoint reconciliation. NOTHING remains. core-to-core-in-one-process stays the owner-LOCKED FATAL-2 refusal."
metadata:
  node_type: memory
  type: project
  originSessionId: 7758e121-f349-47d5-886b-6bb5a1d60e27
  modified: 2026-07-25T15:06:08.076Z
---

Owner directive (2026-07-24): make **AEGIS + SIGIL + CRUCIBLE + VIGIL** work as "1 unified system,
end-to-end, core-to-core" (explicitly NOT vigil-apex or other systems), find where the goal FAILS, do
every fix+integration; PLUS a SIGIL UI section to disable gesture control / voice control / both. Repo
`/home/kali/vigil` (remote `thuram-nana/vigil-sovereign`). Plan approved (ExitPlanMode) at
`/home/kali/.claude/plans/parsed-popping-lemur.md`. Related: [[vigil-fusion-redamon-pentagi]]
[[vigil-audit-hardening-program]] [[vigil-live-program]] [[vigil-fusion-program]].

**WHERE THE GOAL "FAILS" (the key finding) — and the DECIDED model.** The offense (CRUCIBLE/Strix) and
sovereign (SIGIL) halves are deliberately in SEPARATE OS PROCESSES: offense runs KEYLESS (can import
`framework`/`strix`), sovereign HOLDS the owner key + is offense-free-by-construction (`assert_no_offense`).
A single interpreter that both holds the owner key AND can import framework/strix is a confused-deputy =
owner-LOCKED FATAL-2 ("unsafe and won't boot", docs/PLAN.md §12.1). So "core-to-core in one process" is
REFUSED for safety. **Operator CONFIRMED (AskUserQuestion):** deliver "one system" = ONE control plane +
CLI + spine-view + gate + identity-hierarchy ACROSS two isolated processes, preserving the wall + the ONE
inert signed-finding seam (`inert_finding.py`→`finding_receiver.py`, JSON-only, two-anchor). Scope = FULL
8-slice program; gesture/voice UI FIRST.

**CURRENT STATE (verified by 3 Explore agents + git):** ONE shared `packages/core/vigil_core`
(chain/crypto/canonical/models/sealing/vault/kek) IS fused. Above it, ISOLATED: ~8 entrypoints (`vigil`,
`sigil`, `crucible`, `aegis`, `strix`, `vigil-gateway` + module mains), TWO rival engage loops
(integration `live/engine.py` vs `engine/crucible/framework/v2/engage.py`), ≥5 spines/logs each w/ own
trust root, 5 identities, 5 gates, DUPLICATED WARDEN tiers (Rust `apps/sigil/kernel/src/tiers.rs` vs Python
`integration/.../warden_gate.py`+`live/wiring.py:default_classify`), TWO detection surfaces
(`framework.v2.aegis` present-but-UNWIRED-to-vigil vs `integration/.../detection` wired-but-with-its-OWN
`DetectionOracle`/`DetectionCertificate` instead of CRUCIBLE `OracleKind`/`EvidenceCertificate`). `vigil
engage` unifies the OFFENSE side only. FUSION F0-F12 + VIGIL-LIVE WS1/2/5/6 (incl. `c99f678` "the unified
engine + `vigil` CLI") are MERGED (README accurate; CONTINUATION.md STATE table STALE).

**INVARIANTS to preserve every slice (non-goals):** two processes/venvs forever; offense keyless
(`pyproject [tool.vigil.environments.offense] owner_key=false`); no module co-loads framework/strix AND the
owner key; `integration/tests/test_two_env_boundary.py` + `assert_no_offense` stay green; the seam stays
inert JSON two-anchor; don't collapse the 5 gates into one in-process gate holding the key. Already-unified
(don't redo): vigil_core (byte-identical v1 `crucible-evidence-v1\x00`), the seam, the `vigil engage` loop,
the pure `conjunctive_decide` core, the AEGIS additive-append pattern (`aegis/registry.py`), transparency/
SCITT/witness.

**8 SLICES (build→red-pen→re-check→PR→CI green→merge each; boundary test green throughout):** S1 super-CLI
dispatcher (new `integration/.../dispatch.py`, pure-stdlib EXEC-ONLY, static VERB_ENV table routing
sovereign verbs→`.venv-sovereign` / offense verbs→`.venv-offense`; retire the 2nd engage loop to `vigil
crucible engage`). S2 one WARDEN classifier of record (new pure-Python `vigil_core/warden_tiers.py`
byte-faithful port of tiers.rs, both envs consult it). S3 fold Detection Mirror onto CRUCIBLE OracleKind/
EvidenceCertificate + wire AEGIS-the-app under `vigil detect`/`vigil aegis`. S4 owner-root DELEGATION
(`vigil_core/delegation.py`; offense governance key must be owner-DELEGATED not free `root0`). S5 one
spine-VIEW (`vigil_core/spine_domains.py` registry; retire ephemeral per-run spine keypair for a stable
owner-delegated offense spine id; `vigil verify` walks all segments). S6 promote `conjunctive_decide` to
THE gate of record (framework `gated_fetch`/`scope_gate` + SIGIL Governor delegate to it). S7 extend the
inert seam to carry the unified detection cert + transparency over the multi-segment view. S8 control-plane
hardening + boundary regression guard.

**W0 — gesture/voice disable capability + UI. MERGED (PR #45 @1c612ec).** New
`apps/sigil/sigil/governor/capability.py` `CapabilityGate` mirrors the kill switch: owner-signed append-only
spine record, ASYMMETRIC (default ENABLED; ANY `state:"disabled"` takes effect even unsigned = SAFE
direction; only OWNER-SIGNED `state:"enabled"` re-enables; read error → DISABLED fail-closed). `capability`
in the signed core `_CORE=("signal","capability","state")` under distinct `signal="governor.capability"` →
per-capability + cross-signal domain separation; change-token cache + a `capability_latch` SNAPSHOT FOLD
(prune fail-safety, like the kill switch). Enforced beside the existing kill-switch check (no reorder):
gesture at `SessionGate.handle()/arm()/arm_by_device()` + `gesture/run.py:run_gesture` entry guard; voice at
`voice/dispatch.py:KernelDispatch.send()` gated ONLY on `voice_channel=True` (so cockpit `/api/ask` +
phone `relay` stay ungated — they build a default KernelDispatch) + `voice/run.py:run_mic` entry guard. UI:
"Capabilities · settings" section in the glass cockpit (`ui/static/index.html`+`app.js`, state chip+toggle+
"Disable both"), owner-signed via the existing `ui/actions.py` broker (server signs, browser never holds
key), `capabilities` field on the read plane (`dashboard.py:snapshot`). CLI `sigil capability
status|gesture|voice|both on|off`. Bridge/phone toggle DEFERRED (enable stays owner-signed desktop-only).
24 tests + full sigil regression + two-env boundary green; independent red-pen PASS (live break-harness:
stolen-sig cross-capability replay, stale-cache-after-disable, fold equivalence, all-four-gesture-paths,
voice channel-scoping — every property held, no BLOCK). LESSON: model a new governed toggle on the
kill-switch latch (asymmetric owner-signed spine record + change-token cache + snapshot fold), NOT a bare
`sigil.env` flag (unsigned/attacker-writable = the G2 hole); scope a shared choke-point (KernelDispatch)
narrowly (voice_channel flag) so disabling one capability doesn't break sibling callers.

**S1 — control-plane super-CLI. MERGED (PR #46 @b9d6a95).** New `integration/vigil_integration/dispatch.py`
(PURE STDLIB, EXEC-ONLY): a static hardcoded `_ENV` verb→(environment,script) table routes `vigil sigil…`→
`.venv-sovereign/bin/sigil`, `vigil {crucible,aegis,strix,gateway}…`→`.venv-offense/bin/…`. Routing is by
construction (table = sole authority) so an offense verb can NEVER resolve into the sovereign venv. Imports
no subsystem; `subprocess.run`s the script (list form, no shell) with PYTHONPATH/PYTHONHOME SCRUBBED from
the child env (so a parent's cross-domain path can't inject the other domain across the exec). `cli.main`
intercepts passthrough verbs BEFORE argparse; native verbs (engage/ledger/verify-ledger/provision)
unchanged; `vigil engage` stays THE engage, raw CRUCIBLE = `vigil crucible engage`. Red-pen: BOUNDARY HELD
under 10 axes (the PYTHONPATH scrub is the one load-bearing route; user/system-site off by venv config;
VIGIL_ROOT can't flip the trust-domain label). 2 LOW fixed (corrupt-venv shebang → clean 127 not traceback;
comment reword). 7 tests + 934 integration + two-env boundary green.

**S2 — one WARDEN classifier of record. MERGED (PR #47 @ee1d9c8).** New pure-stdlib
`packages/core/vigil_core/vigil_core/warden_tiers.py` = BYTE-FAITHFUL port of the Rust kernel classifier
(`apps/sigil/kernel/src/tiers.rs`): token sets + danger-first algo + ascii-lower + HID tables. BOTH the Rust
classifier and the Python port are pinned to ONE shared golden (`vigil_core/warden_golden.json`), loaded by
BOTH the Rust unit test (`matches_shared_golden_vectors`) AND the Python test → can't drift. Offense
`live/wiring.py:default_classify` now derives DANGER from the shared `has_danger_token` (git.push→A3 like the
kernel, closing the old recon→A1/else→A2 drift) with ZERO gate-outcome change (dangerous was A2→queue, now
A3→queue under the A1 ceiling; only the label corrected). **Red-pen found a REAL BLOCK via a full-codepoint
Python-vs-Rust diff: the C0 separators U+001C..1F — Python `\s` splits on them, Rust `char::is_whitespace()`
did NOT — so `read.log\x1cdelete` was A0 (AUTO-RUN) on the Rust sovereign kernel vs A3 in Python, uncaught by
the all-printable-ASCII golden.** FIXED fail-safe: Rust tokenizer now also splits on U+001C..1F (danger
exposure is MONOTONE — every dictionary token is delimiter-free, so a danger token can't be split
apart/hidden) + golden boundary vectors. Re-check re-ran the full-codepoint diff on the FIXED code: divergence
set EMPTY (1,112,064 codepoints agree), additive-only, no realistic name affected. 23 tests + cargo 9/9 green.
LESSON: a shared golden of PRINTABLE-ASCII vectors does NOT guard the TOKENIZER BOUNDARY — a port bug on
control/unicode separators is invisible to it; pin the boundary with control-char vectors. Rust `cargo test`
runs LOCALLY not in CI (cargo 1.95 on-box); the golden's Python side IS CI-enforced (vigil-core job).

**S3 — one detection vocabulary + `vigil detect`. MERGED (PR #48 @fa53771).** KEY FINDING (via Explore):
the plan's "fold detection onto CRUCIBLE OracleKind" is UNSOUND — the Detection Mirror
(`integration/.../detection/`) is a genuinely SEPARATE oracle framework (own DetectionOracle + LOG re-run
+ DetectionCertificate), NOT a reuse of CRUCIBLE `oracles.py` like AEGIS-the-app; a detection OracleKind
member would be a BODYLESS kind the verifier can't fire (weakening oracle authority). Operator CHOSE the
honest fold (AskUserQuestion). Shipped: `detection/registry.py` DECLARED `DETECTION_BUG_CLASSES` +
`verify_registration()` (defensive analogue of aegis registry — closes the vocabulary, no hallucinated
class) + `vigil detect --access-log/--auth-log/--conn-log` (surfaces the mirror standalone; cert-re-verified
FACTs; framework-FREE, boundary-clean; DISTINCT from `vigil aegis detect`). NO bodyless OracleKind — a
CI-enforced guard test asserts CRUCIBLE `_ALL_ORACLES` stays 15. Cert m-of-n fold DEFERRED (single-key→
governance trust-model change). Red-pen: 1 LOW honesty BLOCK — docstring claimed all injection classes
"share CRUCIBLE names"; TRUE for sqli/xss/path_traversal but FALSE for crlf_injection (no CRUCIBLE class) +
cmd_injection (CRUCIBLE uses `command_injection`); fixed + the split is now TESTED. AEGIS-the-app already
reachable via S1's `vigil aegis`. LESSON: don't force a "unification" that adds bodyless authority tokens —
verify the shared-vocabulary claim against the REAL registry, don't assume name matches.

**S4 — owner-root delegation. MERGED (PR #49 @e6451d1).** New `packages/core/vigil_core/vigil_core/delegation.py`
(pure vigil_core, both-env importable): `DelegationCert` = OWNER-signed authorization of an offense-governance
`TrustRoot`, bounded by role/scope/expiry, over a domain-separated canonical core (NEW tag
`vigil-delegation-v1\x00` → ZERO v1 signing-byte drift). `sign_delegation`/`verify_delegation` fail-closed on
wrong-owner/role/scope/expired/unsigned/malformed/bad-threshold/dup-key_id/dup-pubkey/bad-schema/non-canonical
authorizer key. `governor/identity.py:delegate_offense_governance()` issues (owner-side).
`FindingReceiver.from_delegation()` DERIVES the trusted governance root from the owner-signed delegation (instead
of a handed-in root) AND carries the delegated scope so `ingest()` BINDS each finding's own signed
`engagement_slug` to it. Raw `__init__`/`ingest_finding` remain the low-level, explicitly UN-owner-tied primitives
(no production caller; daemon wiring must use `from_delegation`). Dual review (crypto-notary + red-pen) + adversarial
re-check on the fixed branch. **Red-pen caught 2 real ones the build missed: BLOCK-1 = honesty overclaim (docstring
said S4 "closes" the free-floating-root hole "only if delegated" but the raw path stayed live+un-owner-tied → the
deterministic layer did NOT enforce the universal claim); HIGH-1 = real confinement hole (scope gated only receiver
construction, NOT the finding's own engagement_slug → any valid in-scope delegation could LAUNDER findings under an
arbitrary engagement label into VEX/report attribution).** Both fixed (honest docstrings; engagement_slug scope
binding, negative-control mutation-tested). Crypto-notary MED = dup-pubkey quorum inflation (verify_threshold counts
distinct key_ids, so 2 authorizers sharing 1 pubkey = 1 keyholder satisfies m-of-n). **KEY LESSON: "guard the whole
class at one shared helper" only applies when the sites are UNIFORM.** My first fix put the dup-pubkey guard in the
shared `TrustRoot._check` model — it BROKE the witness anti-rollback subsystem (`spine/witness.py` /
`test_a_duplicate_witness_key_cannot_forge_a_majority`), which DELIBERATELY builds a degenerate dup-pubkey roster and
honestly labels it "DETECTION only". Reverted to guard at the DELEGATION layer only (where the root is derived from
boundary-crossing data), documented the residual honestly in models.py + destruction_gate.py (other verify_threshold
consumers get owner/governance-provisioned roots, none attacker-injectable). Re-check PASS (no BLOCK/HIGH/MED; it
mutation-tested the scope binding → red when neutered). 14 delegation + 9 receiver-delegation tests; boundary +
signing-compat + all member suites green. (Pre-existing env failures: `qdrant_client` absent in .venv-offense →
test_robustness.py fails, NOT in CI, unrelated.)

**S5 UNDERSTAND (5-agent Workflow) — where the plan's S5 FAILS (operator asked to find this):** (1) the
offense spine key was EPHEMERAL per-run AND its pubkey persisted NOWHERE (SpineLine/SnapshotRecord/ExecRecord
have no pubkey field) → old spines UN-verifiable after process exit; the plan's "old ephemeral spines still
verify" migration is IMPOSSIBLE by construction (honest reframe: the stable key is the FIRST verifiable spine
identity). (2) A single-process "read-only unifier" importing sovereign `store.py` + CRUCIBLE `spine_chain.py`
CO-LOADS both trust domains → trips `assert_no_offense` (FATAL-2 boundary) → `vigil verify` MUST be a
subprocess-merge / public-key-only view, NOT in-process. (3) The 4 spines are HETEROGENEOUS, not one chain:
sovereign segmented-JSONL+head+floor · offense checkpoint JSONL · CRUCIBLE `spine_chain` = a DB-PROJECTION (not
file-backed, NOT wired into the live engine) · usage-ledger with its OWN record_hash/prev_hash chain (not vigil_core
ChainEntry) → "one logical chain" = a per-segment VERDICT view; segment#3 can't be byte-verified sovereign-side.
(4) S4 delegates GOVERNANCE, not the spine key → S5 needs a NEW `offense-spine` role (spine_kp ≠ the anchor-1
authority kp; BOTH were ephemeral). Offense already persists+seals a STABLE operator key (attestation/identity
load_or_create_operator_keypair under an offense Vault) — the working precedent to mirror. (One of the 5 agents
returned a green-wash STUB despite burning 196k tokens — enumerated the domain-tags directly by grep instead.)

**S5a — stable offense-spine identity + spine-domain registry. MERGED (PR #50 @f0f6220).** New
`vigil_core/keystore.py` = the ONE shared `load_or_create_sealed_keypair` (persist-once/0600/AEAD-sealed-when-
provisioned/weak-key-reject/priv-pub-roundtrip/fail-closed-on-locked-TPM); the operator key REFACTORED to a thin
wrapper over it (one reviewed impl, not two — persist FAILURE now WARN-logs since a silent fail re-creates the
pre-S5 orphan bug). `live/spine_identity.py`+wiring: offense spine key now STABLE (own AEAD context
`b"vigil/offense-spine.key"`), retiring the per-run `generate_keypair()` — plaintext-at-rest until vault
provisioned (same posture as operator key). `OFFENSE_SPINE_ROLE` + `governor.delegate_offense_spine`: spine
identity owner-DELEGATABLE as a role DISTINCT from the m-of-n governance authority (reuses S4 machinery, ZERO new
signing bytes). `vigil_core/spine_domains.py` = the ONE registry (trust-domain/signer-role/owner_rooted/file_backed
+ `verify_registration()`). Dual review + re-check. **Both reviewers converged on ONE honesty BLOCK/MED: registry
marked offense-spine `owner_rooted=True` but NOTHING consumes an OFFENSE_SPINE_ROLE delegation** (delegate-ABLE ≠
enforced — the "never overclaim what the deterministic layer enforces" rule). Fixed: offense-spine +
crucible-blackboard-chain → `owner_rooted=False` (offense-finding-anchor1 stays True — a real consumer,
`from_delegation`, exists). **Re-check then caught the fix guarded only the INSTANCE: `verify_registration`'s check
was ROLE-granular (`_OWNER_VERIFIED_ROLES`), so crucible-blackboard-chain — SHARING offense-governance role — could
still overclaim.** Re-fixed SEGMENT-granular: added `owner_tie_consumer` field, guard enforces `owner_rooted IFF a
named consumer` per-segment (the recurring "guard the WHOLE class at one helper, not the instance" lesson AGAIN),
mutation-tested across all 3 offense segments + the under-claim. Refactor behavior-preserving (diffed byte-for-byte);
AEAD context-isolation fail-closed; stability survives unprovisioned→provisioned migration; boundary+signing-compat
green. LESSON: a per-role honesty guard is NOT whole-class when 2 segments share a role — bind the claim to each
segment's OWN named evidence.

**S5b — boundary-safe `vigil verify` view. MERGED (PR #51 @4be38e3).** New `live/spine_verify.py`
(verify_offense_spine/ledger/home + SegmentVerdict) = public-key-only, inert-bytes-only per-segment verifier — the
FIRST live consumer of OFFENSE_SPINE_ROLE. Elegant trust bootstrap: the owner-signed delegation's authorizers
PUBLISH the blessed offense-spine pubkey, so the verifier derives the trusted key from the delegation itself (no
sealed-key access) then checks the spine's chain+sigs verify under it → owner_rooted. `readonly=True` VigilCoreSpine
(skips torn-tail repair + write-guard) so a verifier NEVER mutates the file it audits (reuses the SAME verify() —
DRY). `vigil verify` CLI verb (exit 3 iff a present segment FAILS). Registry flip: offense-spine → owner_rooted=True
(consumer now exists; auto-provisioning of the delegation still S7 — same honest bar as offense-finding-anchor1).
CRUCIBLE blackboard chain honestly UNVERIFIABLE (DB-projection, not byte-readable). Sovereign spine verified
SEPARATELY (`vigil sigil verify`) — one process can't co-load both trust domains. crypto-notary + re-check (a first
red-pen died on an API ENOTIMP mid-pass → the re-check completed the adversarial pass). Trust bootstrap SOUND (owner
pubkey sole anchor; authorizers inside owner-signed core; weak-key reject). 2 fixes, both mutation-verified: **HIGH
`int(now or 0)` mapped a missing clock to epoch-0 → expiry `0>not_after` NEVER-expired = fail-OPEN** (CLI passed a
real clock so latent) → now fail-CLOSED (missing now → FAILED; a bearer cert's not_after is its ONLY revocation
substitute); **MED the spine is SINGLE-SIGNER but the verifier accepted "any one authorizer" ignoring root.threshold
→ silently downgraded owner's m-of-n to 1-of-n** → require threshold==1 at verify + FIX it at mint
(delegate_offense_spine dropped the threshold param; 1-of-n over many authorizers = key rotation stays valid).
LESSON: a verify path must honor the delegated threshold, and NEVER coerce "unknown time" to the most-permissive
value (fail-closed on a missing clock).

**S6 — one gate of record. MERGED (PR #52 @bdde549).** 4-agent UNDERSTAND (1 stub'd on StructuredOutput retry-cap;
covered second-hand): **conjunctive_decide is ALREADY the gate of record for the offense LIVE `vigil engage` path**
(build_offense_gate ← wiring._build_gate ← authorize_tool_call, allow-only) AND the WARDEN tier ruleset is ALREADY
single-sourced (vigil_core.warden_tiers = golden-pinned port of Rust tiers.rs, S2). So the SAFE core of S6 = RELOCATE
the PURE composition (conjunctive_decide + GateVerdict/CrucibleResult/DestructionOutcome) from the offense
integration seam INTO the neutral shared `vigil_core/gate.py` (stdlib-only LEAF; WARDEN result duck-typed via a
WardenDecision Protocol so it never drags framework/strix into the owner-key process); `integration.conjunctive_gate`
RE-EXPORTS it (byte-identical, same class objects — back-compat). `test_gate.py` pins the fail-closed invariants
(only WARDEN "auto" opens; unknown-outcome→DENY; any conjunct raise→DENY; STRICT `authorized is True` on the
m-of-n destructive conjunct; destructive w/o gate→DENY). Red-pen DIFFED old-vs-new = byte-identical executable
semantics (only comment/annotation/docstring; strict-identity guard mutation-verified); leaf/boundary holds; PASS,
no fixes. **KEY DECISION — the plan's "fold every edge" is HAZARDOUS: each native edge enforces a conjunct the base
composition does NOT model, so a naive fold DROPS it → deny→allow.** DEFERRED to S7/S8 with an honest hazard doc
(docs/architecture/S6-gate-of-record.md): raw `vigil crucible engage` path (scope_gate charter-signature +
URL-derived destructiveness + running request-budget), MCP invoker (require_capability entitlement), SIGIL Governor
(tier from Rust-kernel G2 pin not the port + promotion + A0-observe-under-kill → compose AROUND, never replace).
LESSON: "one gate of record" was mostly ALREADY TRUE — the safe win was sharing the PRIMITIVE + pinning invariants,
NOT force-folding edges that each drop a conjunct. Also: reason strings still say "CRUCIBLE" (kept for byte-identity;
genericize in the sovereign fold).

**S7a — stable offense GOVERNANCE identity. MERGED (PR #53 @1c28e47).** The anchor-1 signer (signs the CRUCIBLE
authority + oracle-path evidence certs; the key an S4 OFFENSE_GOVERNANCE_ROLE delegation authorizes) was minted
FRESH per run in `provision_authority` → an owner delegation would need re-minting every run. Fixed by mirroring
S5a: new `live/governance_identity.py` (load_or_create_governance_keypair over the shared vigil_core.keystore,
context `b"vigil/offense-governance.key"`); `provision_authority` gains optional base_dir/vault (STABLE+sealed when
given, legacy per-run ephemeral back-compat when absent, explicit keypair still wins); build_engine builds op_vault
FIRST then provisions under base_dir+vault; `vigil provision --base-dir` persists it (shared with `vigil engage`).
Completes the offense STABLE-IDENTITY TRILOGY (operator+spine+governance, each its OWN AEAD context →
non-interchangeable). Red-pen PASS (clean S5a mirror; back-compat intact/every caller traced; no silent regen —
fail-closed on locked TPM + non-destructive plaintext→sealed migration; no authz outcome change, trust_root stays
threshold=1). NIT: the offense-integration full-suite `test_import_clean` co-load fragility is PRE-EXISTING (repros
with files S7 never touched; CI splits suites so it never fires) — out of scope.

**S7b — owner-tie delegation CEREMONY wired end-to-end. MERGED (PR #54 @7bdc4c2).** Connected the
mint→publish→consume loop the S4/S5/S7a primitives were built for, via 2 CLI commands across the boundary:
`vigil identity --base-dir X` (offense) exports the stable spine+governance PUBLIC keys+key_ids to
`offense-identity.json` (governance key_id MUST = DEFAULT_KEY_ID "root0" to match the anchor-1 signer); `sigil
delegate-offense --offense-identity F --scope S --hours N` (sovereign) has the OWNER mint owner-signed offense-spine
+ offense-governance DelegationCerts over those pubkeys → inert JSON; consumed by S5b `vigil verify --delegation` +
S4 from_delegation → offense spine verifies OWNER-ROOTED. Only public keys + inert signed JSON cross. Red-pen PASS
no-BLOCK (no private-key leak into identity/deleg files; sovereign cmd framework-free; veracity firewall intact — a
delegation says WHO-may-sign not WHAT-is-true). **MED caught: the ceremony silently trusted offense-identity.json
provenance** (owner mints over whatever pubkeys are in it; a file swapped IN TRANSIT gets an attacker's key
owner-blessed) → fixed: `delegate-offense` now ECHOES the exact pubkeys it's blessing + both cmds DOCUMENT the
file must arrive authenticated / be fingerprint-verified out-of-band. Also: hermetic sigil test (monkeypatch the
owner-key accessors — never touch the real ~/.sigil key); `--hours` validated (finite/positive — the recurring
int(inf) class) + identity schema checked, both fail-closed. LESSON: wiring a delegation CEREMONY reintroduces a
handed-in artifact one layer up — its transport authenticity is a trust assumption that MUST be documented + made
catchable in-band (echo what you sign), or the "don't blindly trust a handed-in root" doctrine is undone above the
crypto.

**S8 — whole-control-plane boundary guard + entrypoint reconciliation (CAPSTONE). MERGED (PR #55 @146f2da).**
Pure test+doc, no production code. `integration/tests/test_control_plane_boundary.py` locks the S1 routing
invariant across the WHOLE `vigil` surface: every passthrough verb → a FIXED env (ONLY sovereign route is
`vigil sigil`; no offense verb ever resolves into `.venv-sovereign`); native (engage/ledger/verify-ledger/verify/
provision/identity/detect) vs passthrough (sigil/crucible/aegis/strix/gateway) verbs DISJOINT; the dispatcher is
pure-stdlib exec-only (AST-checked — imports no framework/strix/sigil). ALL 3 guard classes MUTATION-VERIFIED
(mis-routed env / non-stdlib import / verb collision each → RED). `docs/architecture/S8-control-plane.md`: two
user-facing entrypoints (`vigil` offense/unified, `sigil` sovereign); crucible/aegis/strix/vigil-gateway are
INTERNAL console scripts reached via `vigil <verb>` — the ~8 pre-fusion entrypoints reconciled to two.

**PROGRAM COMPLETE.** The operator's ask ("AEGIS+SIGIL+CRUCIBLE+VIGIL as ONE system, end-to-end, + a
gesture/voice disable UI") is delivered as ONE control plane over TWO isolated processes: W0 UI, S1 super-CLI, S2
one WARDEN classifier, S3 one detection vocabulary, S4 owner-root delegation, S5 one spine-view + stable offense
id, S6 one gate of record, S7 owner-tie ceremony (stable governance key + mint/publish/consume), S8 boundary
guard. The core-to-core-in-ONE-process ask stays an owner-LOCKED FATAL-2 refusal (delivered "one system across two
isolated processes" instead — confirmed by the operator). Every slice: build→independent adversarial dual-review
(or red-pen)→re-check on the fixed branch→PR→6-job CI green→merge; the two-env boundary + no-v1-signing-drift held
throughout. ONLY OPTIONAL REMAINING: S7c (extend the inert seam to carry the S3 detection cert + transparency/scitt
over the S5 multi-segment view) — a refinement, not core to "one unified system".
