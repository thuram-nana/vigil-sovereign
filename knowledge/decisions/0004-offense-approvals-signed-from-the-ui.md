# ADR 0004 — Offense approvals are signed from the UI via the sovereign signer

- **Status:** Accepted (implemented; PRs #333 honesty, #335 wait-window + counter, #336 signing bridge)
- **Scope:** VIGIL (`/home/kali/vigil`, repo `thuram-nana/vigil-sovereign`)
- **Code:** `apps/sigil/sigil/ui/offense_approvals.py`, `apps/sigil/sigil/ui/actions.py`
  (`offense_bind_authority`/`offense_approve`/`offense_deny`), `packages/vigil-ui/app.js`
  (Safety-screen Approve/Deny + bind-on-demand), `integration/vigil_integration/live/approval_broker.py`
  + `approval_token.py` + `nonce_ledger.py` (the unchanged offense verifier).
- **Tests:** `apps/sigil/tests/test_offense_approvals_bridge.py`.

## Context

Two structurally disjoint approval queues exist, and only one was ever UI-approvable:

1. The **sovereign** queue (SIGIL spine, `apps/sigil/sigil/agents/approvals.py`) — the cockpit's
   Approve/Deny buttons POST `SOV /api/action`, which signs with the persisted owner key server-side.
   Fed only by SIGIL producers (agent-mesh A2/A3, gestures, learn-proposals).
2. The **offense** per-action approval broker (`live/approval_broker.py`) — the queue that actually gates
   Strix `exec_command`/`write_stdin` and every engage offense tool at A2+. The offense console is
   **keyless by design**: it holds only the *public* approval-authority and polls
   `<base>/approvals/signed/` for a token an owner signed. The only signer was the CLI
   (`vigil approve sign`, reading `VIGIL_APPROVAL_OWNER_KEY`).

So a codebase scan launched from the UI queued its shell calls and could only be released from a
terminal — and four places in the UI/CLI/error text falsely told the operator to "sign via the Safety
screen" or "the sovereign cockpit," neither of which could. (Fixed first, in #333, as pure honesty.)

A seam-mapping investigation established the decisive fact the design hinged on: **the offense approval
owner key and the sovereign cockpit owner key are DIFFERENT Ed25519 keypairs** (the offense key is minted
by `vigil approve provision-authority` and held off-box as `VIGIL_APPROVAL_OWNER_KEY`; the sovereign key
is `KEYS_DIR/owner.priv` managed by `governor/identity.py`). This was surfaced to the operator rather
than assumed, and the operator chose the key model.

## Decision

**Route offense approvals through the sovereign signer, unifying on the sovereign owner key, signing
in-process on Approve-click.**

- **Unify on the sovereign key.** `bind_authority()` pins the offense approval authority
  (`<base>/approval-authority.json`, public key only) to the sovereign owner keypair
  (`governor.identity.ensure_owner_keypair()`), so a token the cockpit signs is accepted by the offense
  broker. Binding is owner-gated (only via `do_action`, which derives the owner identity server-side) and
  can only ever install *this* owner's key — it can never repoint trust to an attacker.
- **Sign in-process on click.** `sign_pending(request_id)` reads the pending request from
  `<base>/approvals/pending/`, re-derives the `ApprovalAction(tool_name, target, action_digest)` from it,
  mints a per-action token with the owner private key (`key_id="owner"`, server clock, 300s TTL bound by
  the token dead-man's `max_token_lifetime`), and writes it to `<base>/approvals/signed/`.
- **The seam is the shared on-disk approvals dir**, never a cross-import. The offense worker WRITES
  `pending/`, the sovereign signer WRITES `signed/`, the offense worker READS `signed/` and burns the
  single-use nonce. This is boundary-clean (FATAL-2): `approval_broker.py`/`approval_token.py` are
  `vigil_core`+stdlib only and hold no private key, so **both planes may import them** — asserted by
  `integration/tests/test_two_env_boundary.py`. The sovereign side never imports `framework`/`strix`.
- **`deny_pending(request_id)`** removes the pending entry so it clears the queue; it writes no token, so
  the offense broker times out and the call is refused (fail-closed). It matches by globbing the real
  files in `pending/` and unlinking the matched entry — the attacker-controlled `request_id` FIELD is
  comparison-only and never joined into a path (see the traversal note below).

## Consequences

- **The private key never crosses planes.** Only a public-safe token hits the shared filesystem; the
  offense broker holds only the public key and **independently re-verifies** signature + key-id pin +
  action-binding and burns the single-use nonce. A forged or replayed token dropped in `signed/` is
  refused regardless of what the cockpit does.
- **Accepted trade-off (unify):** a leak of the one owner key now forges BOTH sigil governance
  (promotion/kill) AND offense approvals. This is the pragmatic choice for a solo 1-of-1 owner (one key
  = game over anyway); it weakens the compromise-isolation the two-key default gave. If a future
  deployment needs isolation, the alternatives are (B) teach the offense broker to pin a SECOND accepted
  key (one pin per `key_id`, mind the I4 free-key_id class) or (C) unseal the offense key into the
  cockpit (a new key in the web process). Not chosen here.
- **Accepted trade-off (sign-in-process):** the cockpit signs with the owner key held in memory
  (it already holds it for governance signing), so a UI click can sign. No new key exposure vs. today.
- **Related settings:** the approval wait window default changed **0 → 300s** (`_DEFAULT_WAIT_SECONDS`
  in `approval_broker._resolve_wait`), Settings-configurable via CONFIG_META `VIGIL_APPROVAL_WAIT_SECONDS`
  (an explicit `0` opts back into instant unattended deny; NaN/negative fail closed; capped at 900s). An
  UNATTENDED run (CI, autonomous) should set `0` — the old behaviour — because a 300s wait for a
  signature that never comes is dead time there. The top-bar "Waiting for you" counter now MERGES both
  planes (offense pending from `OFF /api/status.pending_approvals`), so a live Strix run's unsigned
  actions no longer read "0 waiting."

## Security notes for anyone touching this

- **`deny_pending` and path traversal.** The offense plane is the keyless, semi-trusted WRITER of
  `pending/`, so a pending record's `request_id` FIELD is attacker-controlled. It must NEVER be joined
  into a filesystem path (an early version rebuilt `pending/<field>.json` and a planted
  `request_id="../../approval-authority"` let a Deny click delete an arbitrary `*.json`). Glob the real
  entries and unlink the matched file; the field is comparison-only. `unlink` removes a symlinked entry
  (the link, not its target). Only a symlinked `pending/` *directory* could escape — out of the trust
  model (the offense subprocess shares the same OS user + base dir and could `os.unlink` directly).
- The offense verifier (`approval_token.verify_token`) is the security boundary, not the cockpit. Keep it
  the sole authority: one pinned key per `key_id`, signature over `token_signing_bytes`, action-binding
  on `(tool_name, target, action_digest)`, window check, single-use nonce. Never widen it to trust the
  writer of `signed/`.
