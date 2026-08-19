# Entitlement provisioning runbook

**Goal:** move a CRUCIBLE deployment from **UNGOVERNED** to **governed**
(enforcement ACTIVE) using only the CLI — no hand-written Python against
`framework.v2.entitlement.provision`.

The runtime only ever *verifies* entitlements. Creating them — minting an
authoriser key, building a trust root, signing an entitlement — is a
governance ceremony. Historically that ceremony had **no CLI verb**: an
operator had to import `entitlement/provision.py` and write Python, so most
deployments stayed UNGOVERNED forever. The `provision`, `new-authorizer`,
`build-trust-root`, and `sign-entitlement` verbs close that gap.

All commands are `python3 -m framework.v2 entitlement <verb>`. Every file the
CLI writes is owner-only (0600). The material lives under the deployment's
entitlement directory (`framework/v2/.entitlement/`, gitignored) unless you
override it with `CRUCIBLE_ENTITLEMENT_DIR`.

---

## ⚠ Read this first: provisioning changes AEGIS enforcement

While a deployment is **UNGOVERNED** (no trust root), every gated capability
— including AEGIS Gateway active enforcement, `AEGIS_RESPOND` — is *permitted
with a logged warning*. That is why `python3 -m framework.v2 aegis serve
--mode enforce` blocks proven attacks today.

The moment you provision a trust root, **enforcement is ACTIVE** and those
capabilities require a valid entitlement that grants them. If your entitlement
does not grant `AEGIS_RESPOND` (a **STANDARD**-tier capability), `aegis serve
--mode enforce` **silently downgrades to observe** — it will no longer block.

So if you rely on AEGIS blocking, provision at least the **standard** tier, or
list `AEGIS_RESPOND` explicitly:

```
python3 -m framework.v2 entitlement provision \
    --institution-id ... --institution-name ... \
    --tier standard --capability aegis_respond
```

This is deliberate: governance is opt-in, and turning it on is exactly the act
that starts enforcing capability gates. Do not be surprised by it.

---

## Path A — single-host quickstart (`provision`)

Use this when one host holds the issuance keys (a solo owner, a lab, a
single-operator institution). One command mints the authoriser(s), the trust
root, and a signed entitlement:

```
python3 -m framework.v2 entitlement provision \
    --institution-id  inst-0001 \
    --institution-name "Authorized Red Team Alpha" \
    --tier            offensive \
    --valid-days      365
```

Options:

| flag | meaning |
|------|---------|
| `--tier` | clearance tier: `baseline`, `standard`, `offensive`, `advanced` (monotone ladder — a higher tier permits everything below it). |
| `--capability CAP` | *(repeatable)* restrict the grant to these capabilities (least-privilege within the tier). Omit to confer everything the tier permits. |
| `--authorizers N` | number of authoriser keypairs to mint (default 1). |
| `--threshold M` | m-of-n signatures the grant must carry (default 1; `1 ≤ M ≤ N`). |
| `--valid-days D` | validity window from now (default 365). |
| `--operator-constraint ID` | bind the grant to an operator identity/prefix (matched against `CRUCIBLE_OPERATOR_IDENTITY` at runtime). |
| `--bind-identifier ID` | *(repeatable)* host-attestation binding: the runtime host must present one of these (`CRUCIBLE_ATTESTED_IDENTITY` / machine-id / hostname). Omit = runs anywhere. |
| `--entitlement-id` | stable id; a uuid4 is generated if omitted. |
| `--keys-out PATH` | where to write the generated authoriser **private** keys (default `<entitlement-dir>/authorizer-keys.json`). |
| `--force` | overwrite an existing trust root / entitlement. |

Then confirm:

```
python3 -m framework.v2 entitlement verify      # exits 0 when a tier is granted
python3 -m framework.v2 entitlement status
```

> **Crown-jewel warning.** `provision` writes the authoriser **private** keys to
> `authorizer-keys.json` (owner-only). Anyone holding them can mint or revoke
> entitlements. The runtime never reads that file — it exists only so you can
> reissue or revoke later. **Move it off this host** (ideally into an HSM) and
> delete the on-host copy once provisioning is done.

---

## Path B — distributed ceremony (keys stay on separate hosts)

Use this when the authoriser private keys must never sit together on one host
(the design intent of `provision.py`). Each authoriser generates its own key;
only the **public cards** are collected to build the trust root.

**1. Each authoriser mints a keypair** (on their own host):

```
python3 -m framework.v2 entitlement new-authorizer \
    --key-id  panel-a \
    --name    "Governance Panel Seat A" \
    --card-out panel-a.card.json \
    --key-out  panel-a.key            # PRIVATE — stays on this host
```

`--card-out` holds the public `AuthorizerKey` (safe to share). `--key-out`
holds the base64 private key — keep it off the runtime host.

**2. Build the trust root** from the collected public cards on the runtime host:

```
python3 -m framework.v2 entitlement build-trust-root \
    --card panel-a.card.json \
    --card panel-b.card.json \
    --threshold 2
```

Writing the trust root turns enforcement ON (see the AEGIS note above). With no
entitlement yet, `verify` will report ACTIVE-but-denied until step 3.

**3. Sign an entitlement** with at least `--threshold` authoriser keys:

```
python3 -m framework.v2 entitlement sign-entitlement \
    --institution-id  inst-0001 \
    --institution-name "Authorized Red Team Alpha" \
    --tier            offensive \
    --valid-days      365 \
    --signer panel-a=panel-a.key \
    --signer panel-b=panel-b.key
```

In a true HSM ceremony the private keys never leave their hosts: export the
canonical signing bytes (`canonical.entitlement_signing_bytes`) to each signer,
collect base64 signatures, and assemble the `SignedEntitlement` — see
`provision.py`. The `--signer key_id=PATH` form is the on-host convenience path.

**4. Verify:**

```
python3 -m framework.v2 entitlement verify
```

---

## Going back to UNGOVERNED

Remove the trust root (and entitlement) from the entitlement directory:

```
rm <entitlement-dir>/trust-root.json <entitlement-dir>/entitlement.json
```

With no trust root and `CRUCIBLE_ENTITLEMENT_ENFORCED` unset, the deployment is
UNGOVERNED again: baseline runs and gated capabilities are permitted with a
warning.

---

## What each verb maps to

| verb | provision.py function(s) |
|------|--------------------------|
| `new-authorizer` | `new_authorizer` |
| `build-trust-root` | `build_trust_root` + `write_trust_root` |
| `sign-entitlement` | `sign_entitlement` + `write_entitlement` |
| `provision` | all of the above, single-host, in one step |

Revocation issuance (`sign_revocation` / `write_revocation`) is **not** yet a
CLI verb; issue a revocation list via `provision.py` for now. Note that a grant
provisioned with `revocation_required=true` fails **closed** if no revocation
list is present — the CLI verbs above deliberately do not set that flag.
