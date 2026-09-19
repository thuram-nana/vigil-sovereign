# Phase 1 — UI-driven live-external authorization spine

## Context

Phase 0 made a remote engage require an owner-signed, threshold-verified authority (0.1) and gave a client
deployment a fail-closed auth posture that still permits external egress (0.2). Phase 1 delivers the
capability the operator most directly asked for: **add a site I own → authorize it in the UI (the owner key
never leaves the sovereign process) → launch a live run** — end to end, across the two-environment boundary
(FATAL-2: the owner private key lives and signs only in SIGIL; CRUCIBLE only verifies + runs; only public
signed material crosses the `.vigil-live` seam).

The plan assumed the cockpit could mint the authority directly. Grounding disproved that: the boundary is
**structural** — a real sovereign venv does not install `framework`, so the existing minter (which lazy-imports
`framework.v2.authority.*`) would `ImportError` in the SIGIL process. The FATAL-2-clean resolution is to lift
the authority schema + canonical signing + an Ed25519 owner signer into the shared `vigil_core` integrity core,
so the sovereign plane signs with `vigil_core` alone and the offense plane verifies byte-identical material.

## Decisions

<!-- CLAIM:PHASE1-1 -->
The engagement-authority schema, its canonical signing bytes, and the owner signer/verifier are ONE definition
in vigil_core.authority (re-exported by framework.v2.authority), byte-identical across both planes; the
verifier never raises, rejects a duplicate-pubkey quorum collapse, and rejects any tampered authority.

<!-- CLAIM:PHASE1-2 -->
The cockpit owner-signs a scoped, time-boxed, GET-only-by-default engagement authorization for a live external
target IN-PROCESS (the owner private key is never written or sent — only the public signed bundle crosses the
seam), and refuses a categorical-safety-floor host (.gov/.mil/.edu/.int and *.gov.cm-class), a
loopback/link-local/metadata IP literal, and a live environment.

<!-- CLAIM:PHASE1-3 -->
A remote engage installs + launches only under an owner-signed authority whose trust root is the pinned owner
key, whose signature verifies, whose validity window is current, and whose scope covers the target host; a
bundle not tied to the pinned owner, a bad signature, an out-of-window authority, a non-bare-host scope entry,
a target host outside the scope, or a conflicting pre-existing trust root is refused fail-closed.

<!-- CLAIM:PHASE1-4 -->
When an owner-signed engagement authority verifies for a slug, its scope binds EVERY host-acting operation
— the sensor/tool gate enforces the signed-authority scope on the tool target too, not just the HTTP path —
so a tool targeting a host outside the signed scope is refused; this is a defense-in-depth ADD over the
charter check that never relaxes it, and is inert for a charter-only engagement with no signed authority.

<!-- CLAIM:PHASE1-5 -->
Under CRUCIBLE_ROOT_STRICT an explicitly-set CRUCIBLE_ROOT whose CLAUDE.md sentinel is missing is a
fail-closed error, never a silent fall-through to a different tree — so a pinned child cannot resolve a
foreign root for its charter / authority / trust-root. A console-launched engage sets it on the child by
default; it is available globally as an opt-in, off by default so dev / pre-init flows are unaffected.

Concretely:
- `vigil_core.authority`: `EngagementAuthority` / `SignedAuthority` / `TargetEnvironment` +
  `authority_signing_bytes` + `sign_engagement_authority` / `verify_engagement_authority`.
- `apps/sigil/sigil/ui/target_authorization.py`: the ceremony (`add_target` / `authority_status` /
  `list_targets`), owner-gated (`target_add` → `offense_authority`); `vigil_integration/live/authorization_broker.py`
  is the import-clean seam transport.
- `engine/crucible/framework/v2/console/actions.py`: `_install_target_authorization` (owner-pin tie + verify +
  window + scope re-validation + persist charter/authority/trust-root, refusing to downgrade a differing root)
  and `_has_verified_authority(slug, host)` (the launch gate: signature + window + target-scope).

## Honest scope (do not overclaim)

The owner-PIN tie is enforced at INSTALL time; the launch gate verifies the authority against whatever trust
root is on disk. Both the gate's and the install's completeness against a *full owner-uid filesystem-write*
attacker (who could plant their own trust root + self-signed authority, or swap both the seam bundle and the
owner-pubkey anchor) depend on anchoring the deployment trust root out-of-band — a read-only / HSM-backed
`.entitlement` mount via `CRUCIBLE_ENTITLEMENT_DIR`. Such an actor is outside the meaningful threat model
(they could equally edit code, the kill-switch, or the keys). This raises the bar from "write a plaintext
`Signed:` name into a charter" to "produce an owner-signed authority, over the target host, in window". These
residuals are recorded in `docs/limitations/inventory.json` and never worded as completeness.
