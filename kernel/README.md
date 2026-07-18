# SIGIL KERNEL — Phase 1 (KERNEL + WARDEN)

The Rust core of SIGIL: a **KERNEL** that routes intent through the cognition cascade, and
**WARDEN**, the fail-closed authorization kernel every tool invocation crosses — tiered A0–A3
and appended to a hash-chained, Ed25519-signed **action log** (the same construction as the
Phase-0 episodic spine, pointed inward). Offense-free by doctrine: it orchestrates and gates;
it never scans, exploits, or targets third parties.

```
intent ─▶ KERNEL ─▶ T0 router ─┬─ answer_local ─▶ memory (Phase-0 sigil CLI)
(palette)                       ├─ escalate_T1 ──▶ claude -p  (fast: Haiku)
                                ├─ escalate_T2 ──▶ claude -p  (deep: Sonnet)
                                └─ dispatch_agent ▶ (agent mesh — Phase 3)
                                        │
        every tool invocation ─────────┴──▶ WARDEN: classify tier ─▶ gate ─▶ signed action log
```

## WARDEN — the authorization kernel (SIGIL §5)

- **Tiers, fail-closed.** `A0` observe/answer (auto) · `A1` reversible internal write (auto+logged)
  · `A2` external-visible (queued for one-tap) · `A3` destructive/financial/security (explicit,
  no promotion). Classification is **token-based** (the tool name is split on `.`/`_`/`-` into
  whole tokens): danger is checked first, `A0` is reachable only via a positive safe-verb
  allowlist, and anything not positively classified — unknown tools, or a benign token inside a
  dangerous word (`overwrite` ≠ `write`, `forget` ≠ `get`) — falls to **A3**. Secret/identity/
  network/financial *targets* are A3 regardless of verb (`secrets.read`, `iam.policy.write`).
- **Signed action spine.** Each record `{seq, ts, agent, tool, args_hash, tier, decision,
  approver, result_hash, cert_digest, prev_hash, entry_hash, sig}` is Ed25519-signed AND
  hash-chained. `ts` is bound into the digest (timestamps are tamper-evident). A separately-signed
  **head** anchors the log's *length*, so tamper (binding), reorder/delete (chain), tail-truncation
  or wipe (head), and forgery (signature) are all caught at the exact seq.
- **Anti-rollback anchor.** A stateless local `verify` cannot detect a rollback to an *older
  validly-signed head*. So each head `{count, head_hash}` is cross-checkpointed (Ed25519-signed by
  the WARDEN key, scoped by pubkey) into the append-only, separately-signed, actively-growing
  Phase-0 spine; `verify` **fails closed** if the on-disk head count is below the spine-anchored
  high-water (rollback, exit 2) OR if the anchor is unreachable/spine-tampered (unverifiable,
  exit 3 — `--allow-unanchored` is the explicit first-run/offline escape). Auto-anchors after every
  A2/A3 attempt. *(Ultimate residual: a full wipe + fresh key changes the visible pubkey; only
  hardware/remote monotonic state is absolute for a local audit log.)*
- **Tier registry.** Per-tool pins in `~/.sigil/warden/tools.json`, applied **raise-only**
  (`max(pin, inferred)`) so the file can make a tool more gated but never downgrade it.
- **Self-audit (C18).** `sigil-kernel audit` replays the log verbatim; `verify` re-checks the
  chain + every signature + the head + the anti-rollback anchor.

## Cognition cascade (SIGIL §7)

`T0` router (deterministic, rule-based v1 — a local Ollama model is a refinement) classifies every
input into {answer_local, escalate_T1, escalate_T2, dispatch_agent}. `T1`/`T2` run via headless
`claude -p` on the Max plan.

## Use

```bash
cargo build --release
K=./target/release/sigil-kernel
$K ask "what did i decide about the graph database"   # T0 → memory (A0), cited, logged
$K do memory.write "note: chose serve-the-quote"      # A1 auto, logged
$K do git.push origin main                            # A3 — BLOCKED, awaiting explicit approval
$K checkpoint                                         # cross-anchor the head into the spine (anti-rollback)
$K audit                                              # replay the signed action spine (C18)
$K verify                                             # chain + signatures + head + anti-rollback anchor
$K verify --allow-unanchored                          # weaker: local integrity only (first run/offline)
$K pubkey                                             # the WARDEN public key
```

Runtime data: `~/.sigil/warden/` (`keys/warden.key` 0600, `actionlog.jsonl` + signed
`actionlog.head.json`). `cargo test` runs the WARDEN test suite (crypto, tiers, action-log
integrity incl. tamper/reorder/tail-truncation/wipe/forged-key, router).

## Not yet (later phases)

Global hotkey + voice daemon (Phase 1.5/2), the real agent mesh (Phase 3), a local Ollama T0
router model, and — for absolute anti-rollback — hardware/remote monotonic state (the local
spine anchor raises the bar but a full wipe + fresh key is still a residual).
