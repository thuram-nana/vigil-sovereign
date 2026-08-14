---
name: sigil-phase6-hardening
description: "SIGIL Phase 6 — Hardening: authenticated governor (kill/budget/promotion), self-audit, signed approvals, dashboard, SSRF gate"
metadata:
  node_type: memory
  type: project
  originSessionId: 7758e121-f349-47d5-886b-6bb5a1d60e27
  modified: 2026-07-18T09:17:43.729Z
---

**SIGIL Phase 6 (Hardening) — BUILT + RED-PEN REVIEWED + MERGED** (final roadmap phase). **The SIGIL project is now a GIT REPO pushed to GitHub: `thuram-nana/sigil` (PRIVATE).** Phases 0-5 = initial commit on `main` (cb565e5); Phase 6 = **PR #1 merged @ 295440c**. `gh` active account resolves to **thuram-nana** (Junior Thuram Nana; note `gh auth status` mislabels it "Water-Hacker"). Future phases → PR flow. Extends [[sigil-phase5-perception-bastion]]. Enforces WARDEN §5 so the acceptance bar "zero unauthorized A2/A3 in the audit log" is PROVABLE from the log.

**GOVERNOR (`sigil/governor/`) consulted on EVERY proposal at `base._dispatch` → AUTO/QUEUE/DENY** (backward compatible: no kill/cap/promotion ⇒ original A1-auto/A2-queue behavior):
- **Kill switch** (`killswitch.py`): halts the mesh, leaves A0 observe/read alive. **Asymmetric auth: ANY engage halts (fail-safe); only an OWNER-SIGNED release un-halts.**
- **Budgets** (`budget.py`): per-agent daily action/interrupt caps, fail-closed; **uncapped by default** (opt-in via `~/.sigil/budgets.json`). Spine IS the ledger (counts auto/queued only — denials consume no budget).
- **Promotion** (`promotion.py`): per-(agent, **record-KIND**) A2 auto-approval; **ENVOY structurally excluded** (§4.6); A3 never auto-promotes.

**AUTHENTICATED GOVERNANCE (the keystone, from the red-pen):** `identity.py` (owner keypair anchor = the SAME `KEYS_DIR/owner.{priv,pub}` the spine checkpoint uses; read-only `owner_pubkey/keypair`, `ensure_owner_keypair` for signing) + `authn.py` (`signed_payload`/`verify_signed`). **Every promotion/kill-release/approval event is Ed25519-signed by the owner key and verified against the PERSISTED trusted pubkey — never a self-supplied one. Forged/unsigned/wrong-key/scope-tampered events are IGNORED (fail-closed).**

**Self-audit C18** (`audit.py`): "what did the mesh do and why" verbatim from the signed log, incl. BLOCKED attempts, each cited to a seq. **Signed approval queue** (`agents/approvals.py`, the mobile-bridge core): `pending()` resolves a queued item ONLY on a VERIFIED approval keyed by the SIGNED `target_seq`; approve/deny require the trusted owner key. **Dashboard** (`dashboard.py`): read-only status (kill state, approval queue, per-agent activity, budget, ingest lag) — writes nothing. **SCHOLAR SSRF gate** (`agents/sources.py`, carried debt CLOSED): resolve-once, verify-all-public (IPv6 + IPv4-mapped-unwrap), **PIN the vetted IP to the socket** (custom pinned HTTP/HTTPS handlers → closes the resolve-then-reconnect rebinding TOCTOU), no redirect-follow.

CLI: `sigil warden kill|release|promote|revoke|status`, `sigil audit [--agent]`, `sigil approve|deny <seq>`, `sigil dashboard`.

**RED-PEN (4-lens Workflow, 19 agents): 15 CONFIRMED, 0 refuted — the review found the CENTRAL PROMISE UNENFORCED.** I built `verify_approval` (Ed25519) but NEVER put it on the enforcement path, and left promotion/kill events entirely unauthenticated → a prompt-injected agent with `self.store` could forge a promotion (A2 auto-runs) or a kill-release (un-halts). Confirmed HIGH/CRITICAL: (RP-1/APPROVAL-1/3/4) `pending()` dropped a queued A3 on an UNVERIFIED approval + replay via raw supersedes_id + verify_approval dead; (RP-2/RP-4) unauthenticated promotion/kill — forged grant = A2 auto, indistinguishable from a real one; (RP-APPROVAL-2 CRITICAL) A3 gate checked "a key present" not "the TRUSTED key" (self-certifying); (SSRF-REBIND-TOCTOU HIGH) resolve-then-reconnect rebinding; (RP-3) self-asserted scope unbound to the action; + 2 greenwashed tests + dashboard denial double-count. **ALL FIXED. Adversarial re-check on the fixed code CLEAN** across self-promotion smuggle / attacker-key grant / scope-tamper / forged release / forged+replayed approval / IPv4-mapped-internal.

**Tests 17/17 (`tests/test_hardening.py`). Full system 110/110 (85 Python + 25 Rust).**

**RECURRING LESSONS reinforced:** (1) **a security primitive that isn't on the ENFORCEMENT PATH is theater** — building `verify_approval` and never calling it in `pending()` was the cardinal defect. (2) **fail-closed asymmetry**: halting/queuing are safe defaults (honor liberally); un-halting/auto-approving are dangerous (require a verified owner signature). (3) **don't self-certify** — the trusted key must be the PERSISTED identity, never the one the caller supplied. (4) **bind authz to the real action** (record kind), not a self-asserted label. (5) **near-zero-defect can't be self-certified** — the workflow caught 15 real defects self-review missed; the re-check on the fixed branch confirmed no fix-introduced regressions.

**HONEST OPEN ITEMS (deferred, non-blocking):** governor `is_engaged`/`is_promoted` scan the whole spine per decision (O(n·m)) — correctness-fine, a caching/tail-scan optimization is deferred (red-pen RP-4 LOW). Mobile-bridge TRANSPORT (Telegram/WhatsApp over WireGuard) is a documented seam over the authenticated approval core — not wired to a real channel. Wiring the Python mesh through the Rust `kernel/` WARDEN signed action log is still a cross-language integration seam.

**SIGIL ROADMAP COMPLETE: all 6 phases (0-5 + hardening) built, reviewed, merged.** Next = live daily-use soak (the acceptance is "one month, zero unauthorized A2/A3"), real mobile transport, and the Rust-WARDEN action-log wiring. Roadmap SIGIL.md §11.
