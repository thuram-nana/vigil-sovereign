# Runbook — anchor the deployment trust root out-of-band (governed / national-agency deployments)

## Why

VIGIL's remote-engage launch gate verifies an owner-signed engagement authority against the deployment
**trust root** (`.entitlement/trust-root.json`). By default that trust root lives *in-tree* under the
crucible root — the same tree the offense process can write. This raises the bar from "edit a plaintext
charter" to "produce an owner-signed authority whose trust root is the pinned owner key", which is the right
default for a single-owner dev box. But a full owner-uid filesystem-write actor could, in principle, swap
*both* the trust root and a self-signed authority. Such an actor is outside the meaningful threat model (they
could equally edit code, the kill-switch, or the keys) — but a governed / national-agency deployment should
close even that, by anchoring the trust root **out-of-band** on a read-only / HSM-backed mount.

`vigil doctor` surfaces the current state as the **`entitlement-anchor`** posture line
(`DEFAULT-IN-TREE` vs `OUT-OF-BAND`), so an operator can see at a glance whether this hardening is in place.

## Steps

1. **Provision the trust root FIRST, then make it read-only.** The install-time "refuse to replace a
   differing trust root" guard only bites once a trust root exists — so a hardened-but-empty `.entitlement`
   directory gives no protection. Provision the deployment trust root (the owner ceremony /
   `vigil-entitlement provision`) *before* mounting read-only.

2. **Place `.entitlement` on a mount the offense process cannot write.** Options, strongest first:
   - an **HSM / TPM-backed** volume the trust root is sealed to;
   - a **read-only bind mount** (`mount --bind -o ro`) or a container `readOnly` volume;
   - at minimum, an `.entitlement` directory owned by a *different* uid than the offense process, `0555`.

3. **Point VIGIL at it** with `CRUCIBLE_ENTITLEMENT_DIR=/secure/mount/.entitlement`. This is the single env
   the resolver (`framework.v2.common.paths.entitlement_dir`) honours; both `vigil doctor` and the launch
   gate read the trust root from there.

4. **Verify.** `vigil doctor` must show `entitlement-anchor: OUT-OF-BAND` and `entitlement: ACTIVE`
   (trust root provisioned). A remote engage against an unauthorized host must still be refused fail-closed.

## Related hardening — hard root pin

Set `CRUCIBLE_ROOT_STRICT=1` so an explicitly-set `CRUCIBLE_ROOT` whose `CLAUDE.md` sentinel is absent is a
fail-closed error rather than a silent fall-through to another tree. Console-launched engagements set this on
the child automatically; a direct-CLI deployment sets it in the environment. See
`docs/decisions/phase1-ui-live-external-authorization.md`.

## Honest bound

This closes the *filesystem-write* residual for the trust root. It does not change the two-env boundary
(the owner private key still lives and signs only in the sovereign plane) or the never-liftable egress floor.
