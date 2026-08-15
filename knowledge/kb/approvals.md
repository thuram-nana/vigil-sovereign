# Approvals — the two queues, the keyless offense console, and UI signing

VIGIL has **two structurally disjoint approval systems**. Knowing which is which prevents the most common
confusion in this area. Neither approval is a *fact* or an *authorization to conclude* — approvals gate
*actions*; the oracle-authority doctrine ([`../README.md`](../README.md)) is untouched by anything here.

## The two queues

| | Sovereign queue | Offense per-action broker |
|---|---|---|
| Where | SIGIL spine, `apps/sigil/sigil/agents/approvals.py` | `integration/vigil_integration/live/approval_broker.py` |
| Gates | agent-mesh A2/A3 proposals, gestures, learn-proposals | Strix `exec_command`/`write_stdin`, every engage offense tool at **A2+** |
| Signer | the sovereign owner key, held server-side (`governor/identity.py`) | an owner signature verified against a **pinned public key** |
| Console | the cockpit signs Approve/Deny in-process (`SOV /api/action`) | **keyless by design** — holds only the public authority |

The offense console being **keyless** is deliberate: the offense (`framework`/`strix`) process must never
hold the owner private key. It publishes a pending request and polls for a token someone else signed.

## The offense broker, precisely

- **Publish:** `publish_pending` writes `<base>/approvals/pending/<request_id>.json` (public-safe:
  `tool_name`, gate-seen `target`, `action_digest`, single-use `nonce`, redacted `args_preview`,
  `created_at_iso` — **no key, no raw args**). `request_id = sha256(action_digest + "\0" + nonce)[:16]`.
- **Sign (sovereign only — needs the private key):** `mint_token` builds an `ApprovalToken` bound to
  `(tool_name, target, action_digest, nonce)`, `key_id`, `not_before/not_after`, and owner-signs it;
  `write_signed_token` drops it at `<base>/approvals/signed/<request_id>.json`.
- **Verify + consume (offense, keyless):** `find_signed_token` content-matches on the action;
  `consume_token` → `verify_token` checks the signature against the pinned `authority.owner_public_key_b64`,
  requires `token.key_id == authority.owner_key_id` (a per-call `key_id` can never self-authorize),
  re-checks the action-binding and the time window, and **burns the nonce ONCE** via the atomic O_EXCL
  `NonceLedger`. A forged, replayed, or mis-bound token is refused regardless of who wrote it.
- **Wait window:** `token_source()` publishes then polls `signed/` for up to `_resolve_wait()` seconds
  (env `VIGIL_APPROVAL_WAIT_SECONDS`, **default 300s** — `_DEFAULT_WAIT_SECONDS`; an explicit `0` = instant
  non-blocking deny; NaN/negative fail closed; capped at 900s, the token dead-man's bound). With **no
  authority provisioned at all**, a QUEUE hard-blocks *before* any wait.

The pinned authority lives at `<base>/approval-authority.json` (**public key only**;
`persist_authority`/`load_authority`). `<base>` = `VIGIL_BASE_DIR` or `.vigil-live`, shared by both planes.

## Signing an offense approval from the UI (route-via-sovereign)

Since the offense console is keyless, the cockpit signs for it (see [ADR 0004](../decisions/0004-offense-approvals-signed-from-the-ui.md)):

1. `bind_authority()` (`apps/sigil/sigil/ui/offense_approvals.py`) pins the offense authority to the
   **sovereign owner key** — the chosen "unify" key model. One-time, owner-gated, idempotent re-pin.
2. On Approve, `sign_pending(request_id)` reads the pending, re-derives the action, `mint_token`s with the
   owner key in-process, and writes `signed/`. The offense broker picks it up and re-verifies everything.
3. `deny_pending(request_id)` removes the pending (no token written → the broker times out → refused).
4. Wired at `do_action` as `offense_bind_authority` / `offense_approve` / `offense_deny`; the Safety screen
   (`app.js`) shows Approve/Deny with a bind-on-first-approve confirm, keeping the CLI command as a fallback.

**The private key never crosses to the offense side** — only a public-safe token crosses the shared
filesystem seam. This is boundary-clean because `approval_broker`/`approval_token` are `vigil_core`+stdlib
only and import no `framework`/`strix` (asserted by `integration/tests/test_two_env_boundary.py`), so the
sovereign process may import them without pulling in the offense engine.

## The one signer that is NOT the UI

The CLI `vigil approve sign` (reading `VIGIL_APPROVAL_OWNER_KEY` from a terminal) is still a valid signer
and the fallback shown under each pending item. It is the right tool for an **unattended** run — where you
should also set `VIGIL_APPROVAL_WAIT_SECONDS=0` so a queued action is denied instantly instead of waiting
5 minutes for a signature that isn't coming (this is exactly why the live-fire CI drives unattended).

## The "Waiting for you" counter

The top-bar counter, Home tile, and nav badge MERGE both planes: sovereign pending (from
`SOV /api/snapshot`) + offense pending count (from `OFF /api/status.pending_approvals`, base-wide). If the
offense plane is down it falls back to the sovereign count — honest, never inflated.

## Invariants to keep

- The offense console stays **keyless**. Never put the owner private key in it.
- The offense broker (`verify_token`) is the **sole security authority** — one pinned key per `key_id`,
  signature + action-binding + window + single-use nonce. Never widen it to trust the writer of `signed/`.
- The offense plane is the semi-trusted **writer** of `pending/` — treat any field in a pending record as
  attacker-controlled; never join `request_id` into a path (see ADR 0004's traversal note).
