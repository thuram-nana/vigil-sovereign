# Runbook — anchor the deployment trust roots out-of-band (governed / national-agency deployments)

## Why

VIGIL's remote-engage **launch gate** verifies an owner-signed engagement authority against the deployment
**authority root** (`.authority-root/trust-root.json`, loaded by `authority.store.load_authority_root` — the
same store `_has_verified_authority`, `_install_target_authorization`, and `wiring.provision_authority` read
and write). By default that authority root lives *in-tree* under the crucible root — the same tree the offense
process can write. This raises the bar from "edit a plaintext charter" to "produce an owner-signed authority
whose trust root is the pinned owner key", which is the right default for a single-owner dev box. But a full
owner-uid filesystem-write actor could, in principle, swap *both* the authority root and a self-signed
authority. Such an actor is outside the meaningful threat model (they could equally edit code, the kill-switch,
or the keys) — but a governed / national-agency deployment should close even that, by anchoring the authority
root **out-of-band** on a read-only / HSM-backed mount.

> **Two distinct roots — do not conflate them.** The launch-gate **authority root** (`.authority-root/`, env
> `VIGIL_AUTHORITY_ROOT_DIR`) is a DEDICATED store, separate from the **entitlement** capability-enforcement
> root (`.entitlement/`, env `CRUCIBLE_ENTITLEMENT_DIR`). The launch gate reads ONLY the authority root; it
> does not read `.entitlement/`. The two are kept apart on purpose: `entitlement.policy._enforcement_active()`
> keys gated-capability enforcement on the mere *presence* of `.entitlement/trust-root.json`, so co-locating
> them would flip entitlement enforcement ON with no grant minted (denying `deep_static_analysis` /
> `active_recon` / `exploit_execution` on a fresh deploy). Harden each root in its own directory; never point
> `VIGIL_AUTHORITY_ROOT_DIR` and `CRUCIBLE_ENTITLEMENT_DIR` at the same dir.

`vigil doctor` surfaces the current state of each root as its own posture line, so an operator can see at a
glance whether this hardening is in place:

- **`authority-root-anchor`** (`DEFAULT-IN-TREE` vs `OUT-OF-BAND`) — the launch-gate authority root.
- **`entitlement-anchor`** (`DEFAULT-IN-TREE` vs `OUT-OF-BAND`) — the entitlement capability-enforcement root.

## Steps — anchor the launch-gate authority root (`.authority-root/`)

1. **Provision the authority root FIRST, then make it read-only.** The install-time "refuse to replace a
   differing trust root" guard (`_install_target_authorization`) only bites once a trust root exists — so a
   hardened-but-empty `.authority-root` directory gives no protection. Provision the authority root (the owner
   ceremony / `wiring.provision_authority` writing the owner-pinned `TrustRoot`) *before* mounting read-only.

2. **Place `.authority-root` on a mount the offense process cannot write.** Options, strongest first:
   - an **HSM / TPM-backed** volume the trust root is sealed to;
   - a **read-only bind mount** (`mount --bind -o ro`) or a container `readOnly` volume;
   - at minimum, an `.authority-root` directory owned by a *different* uid than the offense process, `0555`.

3. **Point VIGIL at it** with `VIGIL_AUTHORITY_ROOT_DIR=/secure/mount/.authority-root`. This is the single env
   the resolver (`framework.v2.common.paths.authority_root_dir`) honours; both `vigil doctor` and the launch
   gate read the authority root from there.

4. **Verify.** `vigil doctor` must show `authority-root-anchor: OUT-OF-BAND`. A remote engage against an
   unauthorized host must still be refused fail-closed.

## Steps — anchor the entitlement capability-enforcement root (`.entitlement/`)

If this deployment also provisions **entitlement** (gated-capability enforcement), anchor its trust root the
same way, in a SEPARATE directory:

1. Provision the entitlement trust root FIRST (the owner ceremony / `vigil-entitlement provision`), *before*
   mounting read-only — same refuse-to-replace caveat applies.
2. Place `.entitlement` on a read-only / HSM-backed mount owned by a different uid than the offense process.
3. Point VIGIL at it with `CRUCIBLE_ENTITLEMENT_DIR=/secure/mount/.entitlement` (the single env
   `framework.v2.common.paths.entitlement_dir` honours) — a DIFFERENT path from `VIGIL_AUTHORITY_ROOT_DIR`.
4. Verify `vigil doctor` shows `entitlement-anchor: OUT-OF-BAND` and `entitlement: ACTIVE` (trust root
   provisioned).

## Related hardening — hard root pin

Set `CRUCIBLE_ROOT_STRICT=1` so an explicitly-set `CRUCIBLE_ROOT` whose `CLAUDE.md` sentinel is absent is a
fail-closed error rather than a silent fall-through to another tree. Console-launched engagements set this on
the child automatically; a direct-CLI deployment sets it in the environment. See
`docs/decisions/phase1-ui-live-external-authorization.md`.

## Honest bound

This closes the *filesystem-write* residual for the trust roots. It does not change the two-env boundary
(the owner private key still lives and signs only in the sovereign plane) or the never-liftable egress floor.
