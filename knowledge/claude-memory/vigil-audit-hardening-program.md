---
name: vigil-audit-hardening-program
description: "VIGIL 100-domain critical audit → 5 foundational-gap hardening program (G1 keys-at-rest, G2 config/kernel/floor integrity, G3 durability, G4 LLM-seam closure, G5 live WARDEN); G1/G2/G4/G5 + G3(a) off-box backup + G3(b) witnessed anti-rollback MERGED; remaining = G3(c) manifest-sign (LOW value) + deferred-live pieces (paired device, SDK hook)"
metadata: 
  node_type: memory
  type: project
  originSessionId: 7758e121-f349-47d5-886b-6bb5a1d60e27
  modified: 2026-08-12T22:13:15.365Z
---

**M1–M7 "material findings" — CLOSED 2026-08-12 as UNRECOVERABLE (operator decision). Do NOT re-open or treat as a pending blocker.** They were named in an operator directive alongside A7/A5/A10/A14 and O1–O8 (all of which WERE identifiable in the repo and are now done), but M1–M7 themselves exist ONLY in an external audit report never pasted into the session — exhaustive grep over the repo AND `git log --all` finds nothing. Operator chose "drop it" over re-supplying the list or re-deriving via a fresh audit. If they ever resurface, the ONLY valid move is to ask for the list; never infer or invent security findings to close it.

A 13-agent critical audit + honesty critic assessed VIGIL (repo `thuram-nana/vigil-sovereign`,
code at `/home/kali/vigil`) against 100 infra domains on the axis "required? foundational-to-core
vs feature vs absent vs N/A". Verdict: the provable/sovereign core is genuinely foundational; the
SaaS-edge/cloud domains are correctly **N/A** (the sovereignty thesis). But it surfaced **5 genuine
foundational gaps**, all rooted in "everything of value lives in one unencrypted `~/.sigil` dir behind
0600, and a few authority/fact seams are LLM-influenceable or wired-not-live". Plan approved
(operator: build all 5; G1 unlock = TPM-sealed unattended). Discipline every slice: build → run green
→ independent red-pen → adversarial re-check → PR → CI green → merge; nothing crypto-sensitive merges
without the review. Two-env boundary (`.venv-sovereign` vs `.venv-offense`; only `.venv-offense`
exists on this box — run sigil tests via `SIGIL_HOME=$(mktemp -d) PYTHONPATH=apps/sigil:integration
.venv-offense/bin/python -m pytest ...`). Live TPM path deferred (no `tss` group / sudo needs pw) →
crypto is tested with an INJECTED fake-TPM runner; live seal is one-time operator setup. Related:
[[vigil-fusion-redamon-pentagi]] [[vigil-live-program]] [[gap-closure-13-workstream-program]].

**G1 — at-rest CONFIDENTIALITY of trust roots. MERGED (PRs #34-37).** AEAD sealed box
(`vigil_core/sealing.py`, ChaCha20Poly1305, domain+context AAD) + TPM-sealed KEK
(`vigil_core/kek.py`, injectable tpm2 runner seam) + shared `vigil_core/vault.py` (`Vault`,
`VaultLocked`; opt-in, non-bricking, non-destructive migrate, fail-CLOSED — never silent plaintext).
Owner key, secret store (API key + service pw), and the offense-side operator key all seal at rest.
`sigil vault status|provision`. Slice-4 (spine payload envelope encryption) DEFERRED — the invasive one.

**G2 — INTEGRITY of the unsigned trust inputs. FULLY MERGED (PR #38 @a4e78e3 slices 1+2; PR #39 @0b5b491 slice-3).**
`sigil.env`/config + `floor.json` were unsigned/off-spine; rewriting `SIGIL_KERNEL_BIN` swaps the
WARDEN A0-A3 classifier binary silently. Slice 1: `governor/integrity.py` owner-signs
`security.manifest.json` = {kernel content-sha256, SCOPE, OWNER_KEY_ID}; `KernelClassifier` resolves
ONCE and verifies the EXACT value it execs (no bare-name PATH fallback) → fail-closed A3 on
mismatch/forged/corrupt; `sigil kernel pin|status`, doctor exits non-zero on active tamper.
Slice 2: floor.json carries an owner sig (domain-tagged `sigil-floor-v1`) over its full monotonic
core, verified in `checkpoint.classify_head` against the SAME trust anchor that verifies the head
(one key source, no signer/verifier divergence) — content-tamper → TAMPERING; legacy-unsigned →
warn+accept (non-bricking, re-signed next checkpoint). +25 tests. **Red-pen lessons that recurred:**
(1) a pin must VERIFY the EXACT path it EXECUTES — a verify-path≠exec-path gap (bare-name PATH fallback
when unresolved) is a real bypass; (2) present-but-CORRUPT ≠ absent — collapsing them to "unpinned"
is a fail-OPEN (truncate/`>file` is a cheaper attack than delete, lands in the open direction);
(3) verification belongs where the ONE trust anchor already lives (classify_head with `tr`), not an
independent owner.pub re-read that diverges under test path-monkeypatching; (4) domain-separate every
owner signature (`sigil-floor-v1\x00`) to bar cross-protocol confusion. **Slice 3 DONE (PR #39):**
KEY FINDING — the LIVE offense gate wires the PURE in-process `live.wiring.default_classify`
(recon→A1 else→A2, NO subprocess), so `warden_gate.kernel_classifier` (the sigil-kernel subprocess
factory) is NOT on the live path — only a skip-guarded test uses it. So the re-check's "the gate the
fusion stack calls" premise was wrong; a full cross-env manifest-verify would be disproportionate for a
non-live path. Slice-3 therefore just closed the LATENT PATH-plant footgun: `kernel_classifier` no
longer bare-name-falls-back (`... or 'sigil-kernel'`) — unresolved → fail-closed A3 WITHOUT exec (same
BLOCK-1 lesson). Full pin-verify here deferred until/if the path is wired live (needs owner pubkey +
manifest plumbed cross-env; warden_gate stays import-clean). Lesson: TRACE THE LIVE WIRING before
assuming an exec site is a live surface — `_build_gate` uses default_classify, not kernel_classifier.

**G4 — close LLM-influenceable authority/fact seams. FULLY MERGED (PR #40 @508d3d4).** Two seams, both
red-penned PASS. Seam 1: `authorize_tool_call` scoped the gate/CRUCIBLE-scope/I4-destruction-bind on the
LLM's `tool_args` target STRING even though `live/executor` had already loopback-PINNED the real target
one line earlier → now the executor passes `resolved_target=disp` and the gate scopes on the exact host
the subprocess reaches; the 3 COPIED target extractors (react/governance/executor) unified into one
`agent/targets.extract_target` (guard-the-whole-class). Seam 2: `_build_oracle` re-fired the oracle over
`analysis.extracted_info['oracle_context']` (LLM-emitted) and SIGNED a FACT from it → `confirm_and_certify`
now takes `provenance` and mints a FACT ONLY when the context is REPRODUCED from a non-LLM channel
({reproduced, live_redrive}); default "llm" → LEAD (oracle still runs → LEAD labelled with what fired).
KEY INSIGHT: a single captured stdout CANNOT reproduce a DIFFERENTIAL (needs baseline+mutated) → the live
re-drive is genuinely deferred (already documented in oracle_adapter); so the honest scope was the
fail-closed provenance GATE (not an invented grounding heuristic — constitution: don't invent
confirmation). The gauntlet/detection FACT paths (grounded in executor-captured raw output + fresh
challenge / target logs) were UNAFFECTED (own path, never extracted_info). Owner notes: a hostname-scoped
authority now denies fail-closed (gate scopes on resolved IP); fsjob is a non-launching pre-check — a
future launcher MUST route through executor.execute. Red-pen method that worked: instrument
build_certificate + drive 13 provenance values → prove 0 mint calls for all non-reproduced.

**G5 — immediate device revocation (landable half). MERGED (PR #41 @2796369).** The gesture-injection
path's `arm_by_device` checked device authorization only AT ARM TIME; `handle` (per-frame) re-checked
only kill-switch+TTL → a device REVOKED mid-session kept injecting until TTL (≤300s). Now `handle`
re-checks the arming device is still owner-authorized every frame, bounded by the SAME change-token +
0.05s rescan floor as the kill-switch (revoke honored ~1-2 frames, cheap on a movement loop); fail-closed
on scan error (treat as revoked); owner sessions (armed_by_device=None) not gated. `Session` records the
arming pubkey. Bridge HTTP path was ALREADY per-request immediate. G5(a) live WARDEN SDK tool-invoke hook
(WardenGateHooks on Strix runner) DEFERRED — openai-agents SDK not vendored; offense tool calls already
enforced via the governed executor.execute path (the G4 seam-1 red-pen confirmed it's the ONE authoritative
exec site), WardenGateHooks fails safe (only AUTO runs) until SDK lands. Red-pen PASS (700-append flood
can't hold change_token stable past a revoke; cross-session cache-poison held).

**G3 — DURABILITY. (a)+(b) MERGED; only (c) remains (LOW value; deferred-live prevention still needs the paired device — do NOT pick (c) autonomously):**
 • (a) encrypted OFF-BOX backup + verified restore. **MERGED (PR #43 @1963fd9).** Operator chose the
   **owner-passphrase (scrypt-KDF)** key strategy (portable, unlike the TPM-bound KEK). `apps/sigil/sigil/
   backup.py` (`create_backup`/`restore_backup`, CLI `sigil backup <dest>` / `sigil restore <src> <home>`):
   packages the spine (segments+manifest+signed head + floor.json + G2 security.manifest.json + owner PUBLIC
   key) plus the re-wrapped owner PRIVATE key + spine DEK, all in one `hashlib.scrypt`(n=2^16,r=8,p=1) →
   ChaCha20Poly1305-sealed body (`vigil_core.sealing`, domain-context `sigil/backup/v1`). Restores on NEW
   hardware where this box's TPM is gone; restore re-seals secrets under the new box's TPM (`sigil vault
   provision`). INTEGRITY (precise, and the honesty focus): AEAD body + owner-signed MANIFEST (sha256 of
   every file) → wrong-passphrase/any-tamper fails BEFORE any write; AFTER the fresh-home write,
   `store.verify()` re-checks chain+payload-binding (KEYLESS) — it does NOT verify the owner SIGNATURE on the
   head (scope/config-bound → a follow-up `SIGIL_HOME=<restored> sigil verify` does, and genuinely validates
   the Ed25519 head sig against the restored owner.pub). 11 tests. **Review lessons (2 rounds):** (1) red-pen
   caught an HONESTY overclaim — the docstring implied restore verifies the owner-signed HEAD when it only
   does keyless chain+binding → reworded to say exactly which layer runs WHEN (never overclaim what the
   deterministic layer enforces). (2) The 3-lens adversarial verify caught a real **check≠write path-escape**:
   the traversal guard validated the NORMALISED path but the write used the RAW rel → a Windows drive-relative
   `D:evil` re-anchored on `new_home / rel` and escaped. FIX = class-complete at ONE site (`_safe_target`):
   strict `PureWindowsPath` reject (.., absolute, rooted, DRIVE-relative, NUL, empty) + `resolve().
   is_relative_to(new_home)` containment backstop + the caller writes the EXACT validated path (check and
   write can't diverge). Same lesson as F1/F5/F3 in [[vigil-fusion-redamon-pentagi]]: guard the WHOLE class at
   every site via one shared helper; a "validate norm, write raw" mismatch is the same bug shape as the
   fusion-repo per-path fixes. Also type-guard EVERY untrusted body field (files/hashes tables + the two
   re-wrapped secrets) → malformed-but-signed body fails closed as a clean BackupError, never a bare
   AttributeError at the vault `.encode()`. The passphrase is the ONLY key — never stored; lose it →
   unrecoverable BY DESIGN.
 • (b) WITNESS co-sign + verify-against-external-checkpoint. **MERGED (PR #44 @577408d).** New
   `apps/sigil/sigil/spine/witness.py` (dependency-injected/CONFIG-FREE, CLI = sole config boundary) REUSES
   the I2 transparency core `vigil_integration.transparency` (import-clean, vigil_core-only, offense-free —
   same boundary-safe pattern as `inbound.finding_receiver` importing `inert_finding`; the P5 two-env CI job
   confirms). CLI `sigil checkpoint emit|verify --external|cosign|witness {list,add,remove}`: emit
   witness-co-signs the head into a compact Checkpoint envelope to RETAIN OFF-BOX; verify proves the current
   head is a GENUINE append-only EXTENSION of an externally-retained checkpoint. KEY DESIGN: the proof is
   real, not asserted — `head_hash == entries[-1].entry_hash` and entry_hash hash-chains the WHOLE prefix,
   so the current chain's entry at the retained `last_seq` must carry the retained `head_hash` (match ⇒
   records 0..last_seq byte-identical; mismatch ⇒ higher-count REWRITE caught). Owner-signed witness roster
   (`witness.trust.json`, domain `sigil-witness-roster-v1\x00`); persisted emitter tip for the meta-chain
   across runs; `cosign_envelope` = the honest MANUAL stand-in for the DEFERRED live paired-device transport
   (an independent witness co-signs on ITS box, envelope shuttled back). HONEST GUARANTEE (labelled by
   `guarantee_label`): anti-rollback = EXTERNAL RETENTION, not a local sidecar; default owner-only witness =
   rollback DETECTION; split-view PREVENTION needs a strict-majority of ≥2 INDEPENDENT keys and is CONDITIONAL
   ("IF independently held" — independence is uncheckable by code; a single owner-only witness at 2*1>1 is
   NOT labelled prevention). **THREE adversarial rounds, each caught a real defect in the PRIOR round's work:**
   (1) an "append-only extension" OVERCLAIM the compact pairwise `consistent` couldn't back → added the
   hash-chain prefix PROOF; (2) that fix's `base_seq` pruned fallback was FAIL-OPEN (base_seq is an
   attacker-SIGNED head field → an owner-key attacker declares the anchored records "pruned" to SKIP the
   proof, ok=True) → made FAIL-CLOSED + bound `entries` to the authenticated head (`verify_chain` + tip ==
   head.head_hash) so a forged/unvalidated entries list can't smuggle a matching hash; (3) an independent
   forgery harness (forged base_prev_hash re-bases, mixed windows, negative/boundary base_seq, forged empty
   anchors) — EVERY attack failed closed, no residual defect → PASS. 18 tests. LESSONS: a compact summary
   check that ASSERTS a strong property (append-only extension) usually can't back it — either PROVE it
   (hash-chain the prefix) or WEAKEN the claim; an attacker-SIGNED field (base_seq) fed into a security
   decision is an escape hatch unless the ambiguous branch fails CLOSED; a security verifier must not TRUST
   its caller's inputs — bind entries to the authenticated head IN the function. The single-node PREVENTION
   (vs detection) still needs the LIVE paired device (same deferral as the phone bridge).
 • (c) sign the segment MANIFEST: LOW value now — `spine/manifest.py` is deliberately NON-LOAD-BEARING in
   retain-all (a doctored manifest fails CLOSED via chain re-derivation; docstring says so; `manifest_sig`
   field RESERVED null). Becomes load-bearing only with the DEFERRED hard-prune tier. Also awkward: the
   manifest is written by the keyless low-level `store` on ROTATION, not by the key-holding checkpoint, so
   inline signing is cross-layer. Catches only convenience-field (generation/scope) rewrites the chain
   doesn't.
**G1 slice-4 — FIELD-LEVEL spine payload encryption. MERGED (PR #42 @f9e8c70) — completes the G1
confidentiality milestone.** Whole-payload was UNSOUND (mixed metadata+content per payload → budget-cap
fail-open); the shipped design seals only content field-VALUES (`spine/envelope.py` `CONTENT_FIELDS` =
text/content/message/body/quote/captured_text/output/answer/title/description/tool_input/
vision_reading_advisory/grounded_objects/advisory_leads/statement), metadata always plaintext. cert_digest
over the STORED (metadata+ciphertext) payload → keyless chain/head/floor verify; opt-in (vault off →
byte-identical); per-field AEAD bound to (scope,seq,field); DEK sealed under the G1 TPM vault, loaded only
for a content record (kill-switch panic never blocked by a locked vault). `store.append` seals pre-digest
(seq derived first); `store.decrypted(r)` fail-closed for FUNCTIONAL readers (vectors/graph/consolidate
producer+serve/recall); `store.decrypted_or_raw(r)` for DISPLAY (tail/mcp/steward/cli); iter_records/
verify/entries/prune read RAW (keyless). THREE red-pen rounds each caught a real defect: (1) whole-payload
budget fail-open → field-level redesign; (2) classification LEAKS — tool_input (Write/Bash contents),
perception screen OCR (summary/vision_reading_advisory/grounded_objects/advisory_leads), statement → sealed
(summary made a non-content label); (3) serve-path defect — the 3 recall MCP tools + nightly brief served
ciphertext → decrypt at the shared `revise.iter_current`. Final re-check CONFIRMED classification COMPLETE
(every kind enumerated; no other content-bearer) + NO functional reader missing decrypt. +23 tests. KEY
LESSON: when metadata+content co-exist per payload, seal per-FIELD not per-record; the field classification
is an allow-list validated by red-pen (a miss = a plaintext LEAK, strictly safer than a fold fail-open).
Documented plaintext boundaries: CRUCIBLE `certificate` (sealing breaks offline re-verify), commit/email
`subject`. (Passphrase-KDF noted for a later G3 off-box backup.)
[HISTORICAL — superseded by the MERGED entry above]: The store WIRING built is CORRECT + REUSABLE: append restructured to derive seq
BEFORE sealing → seal payload with a (scope,seq)-bound AEAD under a per-spine DEK (DEK sealed under the
G1 TPM vault, `spine/envelope.py` + `SPINE_DEK_PATH`) → `cert_digest` over the CIPHERTEXT so a KEYLESS
verifier still verifies the chain/head/floor; `iter_records`/`verify`/`entries` stay RAW (verify
UNCHANGED, correct by construction), a new `store.decrypted(r)` projection decrypts for content consumers
(vectors/graph/consolidate call it), opt-in + non-bricking (vault off → byte-identical plaintext), mixed
spine, locked-vault fails content reads closed but verify stays green. **WHY whole-payload is UNSOUND (2
red-pen rounds):** a payload MIXES keyless governance METADATA (decision/tier/usage/governor/
promotion_key/folded_state/pubkey/count) with sealable CONTENT (text/quote/body) — so a whole-RECORD
`should_encrypt` cannot win: SEALING an agent action record (source="agent", no "signal") hides its
decision/usage → the §5 **budget-cap fold** (`governor/budget.py:205,210`) + the **C18 self-audit**
(`audit.py`) read them KEYLESS → under-count → the daily cap **FAILS OPEN** (BLOCK-1 HIGH, reproduced);
EXEMPTING archivist records (source="archivist") leaves **verbatim memory quotes** plaintext (BLOCK-2).
The record-level denylist is the wrong GRANULARITY. **SOUND design = FIELD-LEVEL:** encrypt only the
content field-VALUES ({text,content,message,body,quote,captured_text,…}) in EVERY record, keep all
metadata plaintext — no record-level policy; keyless folds read metadata (plaintext) so they work with a
locked vault, content readers decrypt the fields. Needs a careful CONTENT-FIELD classification (miss a
field → leak; include a metadata field → fold break) validated by a fresh red-pen. Keyless-fold input
discriminators enumerated: "signal" · kind∈{warden_checkpoint,snapshot} · source=="agent"(budget/audit) ·
source=="archivist"(snapshot/revise). Lesson: when metadata+content co-exist per payload, encryption MUST
be field-level, never whole-record. Session merged PRs #34-41 (G1, G2, G4, G5-landable = 8 PRs); each
crypto/authority slice independently red-penned + re-checked. REACHED a clean checkpoint: the cleanly-
sliceable gaps are DONE; the rest need operator decisions / live infra.
