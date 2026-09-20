# Phase 0.1 — Remote engage requires a cryptographically-verified authority

## Context

Before this change, the console's remote-engage pre-flight (`_has_charter`) authorized a run whenever a
`targets/<slug>/charter.md` file merely *existed* — and the charter's authorization was a plaintext `Signed:`
name in a Markdown table. Any actor who could write that file could aim VIGIL at any host. For a
prove-don't-guess platform sold to a government, "authorization by text edit" is disqualifying: the tool
could be pointed at an arbitrary target with no cryptographic proof of owner intent.

## Decision

The console remote-engage gate now verifies an owner-signed authority instead of a file's existence.

<!-- CLAIM:PHASE0-1 -->
A remote (non-loopback) engage is authorized only by an owner-signed EngagementAuthority whose governance threshold signature verifies against the deployment trust root; a charter file that merely exists no longer authorizes anything.

Concretely:

- `console.actions._has_verified_authority(slug)` loads the deployment governance trust root
  (`entitlement.store.load_trust_root`) and calls `authority.store.load_verified_authority(slug, trust_root)`,
  which raises unless the m-of-n Ed25519 threshold signature over the authority's canonical bytes verifies.
  Every failure mode (missing trust root, missing/unsigned/tampered authority) returns `False` — fail-closed.
- The remote branch of `console.actions.launch_assessment` calls `_has_verified_authority` in place of the
  existence-only `_has_charter`.
- `vigil_integration.live.wiring.provision_authority` now persists the governance trust root (bootstrap-once,
  stable-key only, never overwriting an existing anchor) so a provisioned authority actually verifies
  downstream (previously the trust root was in-memory only and `framework.v2 engage` refused).

## Honest scope

This raises the bar from "write a plaintext name" to "produce a valid governance threshold signature." It
assumes the deployment trust root (`.entitlement/trust-root.json`) is not writable by the same low-privilege
actor who can author charters; an actor with arbitrary owner-uid filesystem write is outside the meaningful
threat model (they could equally edit code, the kill-switch, or the keys). Relocating `.entitlement` to a
read-only / HSM-backed mount via `CRUCIBLE_ENTITLEMENT_DIR` closes even that residual.

The loopback path is unchanged (it is exempt by design and auto-charters `127.0.0.1`); the engage layer's own
runtime authority + scope enforcement (`authority/gate.py`) is unchanged and remains the defense-in-depth
backstop.
