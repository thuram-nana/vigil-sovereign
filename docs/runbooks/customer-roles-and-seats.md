# Customer roles

What each per-org customer role may do, the founder role and its flag, the owner verbs that change a
founder, and the rollback rule. Every role here is an **owner-signed per-org membership**: it applies inside
one org only, and none of them is a global account role.

## The roles

| Role | Granted by | Billing and members | Testing (prove a host, launch, read results) |
|---|---|---|---|
| `viewer` | an org admin or the founder | no | no |
| `analyst` | an org admin or the founder | no | no |
| `org_admin` | sign-up (founder flag off), an org admin, the founder | yes | no |
| `founder` | sign-up (founder flag on), the service owner | yes | yes, on hosts the org proves |
| `operator` | the service owner only | read only | yes, on hosts the org proves |

A customer org admin (or the founder) can grant only `viewer`, `analyst` and `org_admin`. `operator`,
`founder` and `owner` are never customer-grantable.

## The founder

The founder is the customer who signed the org up. With `VIGIL_SIGNUP_FOUNDER_TESTER_ENABLED` on, both
sign-up paths (email and Google) grant the founding customer `founder` instead of `org_admin`.

- **Permissions:** everything `org_admin` carries (billing, members, defensive monitoring requests) plus
  `run_engagement` and `view_assessments`.
- **Never carries:** `offense_authority`, `approve_a2`, `approve_a3`, `toggle_guard`, `config_nonsecret`,
  `queue_proposal`, `manage_org`, `manage_users`, `secrets`, `promote`, `kill_release`.
- **Never global:** every global-role check (the offense console and gated API, vscp, the cockpit account
  principal, the global leg of the org admission gate) uses `vigil_core.rbac.role_can_global`, which gives a
  per-org role name no permission.
- **Owner-only changes:** customer member management refuses to change or revoke a founder's membership,
  including the founder's own. Only the service owner changes it (owner verbs below).
- **No step-up requirement and no first-launch review** (owner decision). Leave
  `VIGIL_CUSTOMER_STEPUP_REQUIRED` unset.

## What every founder launch still passes

1. **Ownership proof:** a current proof that the org controls the exact host (`target_verify`).
2. **Authorization affirmation:** the inline "I am authorized to test this asset" affirmation, required at
   verify time and recorded on the owner-signed spine.
3. **Engagement authority:** the owner-signed engagement authority for that host, checked by the launch gate.
4. **Credits:** the launch reserves credits from the org's balance before any traffic.
5. **Live hold:** while `VIGIL_CUSTOMER_PROD_EXECUTION` is off, live customer targets are not executed.
6. **Trial limits:** an org on the trial preview may run only the trial product, on one registrable domain,
   under the daily trial cap.

## Flag and kill switch

`VIGIL_SIGNUP_FOUNDER_TESTER_ENABLED`, read by the cockpit (the provisioner and the launch gate run there).
Code default: OFF. Production value: `1`, set in `apps/sigil/deploy/cockpit.env.example` (owner decision).

| State | Sign-up grants | Existing founder memberships |
|---|---|---|
| ON | `founder` | admitted as `founder` |
| OFF | `org_admin` | admitted as `org_admin`: billing and members kept, no testing |

Turning the flag OFF is the kill switch. It writes nothing to the spine and takes effect on the next request;
setting it again restores the founders' testing. While it is OFF a founder cannot start, pause, resume or
cancel a launch; a launch already reserved settles through its lease expiry and the settle drain.

## Owner verbs

```bash
# Grant or change one member's per-org role (any per-org role, founder included).
sigil org set-member-role <org_id> <username> <role> --reason "<why>"

# Re-grant org_admin to every active founder membership (one org with --org). Idempotent.
sigil org demote-founders --reason "<why>"
sigil org demote-founders --org <org_id> --reason "<why>"
```

Each change writes a critical audit row before the owner-signed grant. `set-member-role` refuses an inactive
org, a target that is neither an active customer nor a member, and a change that would leave the org with no
administrator. Both verbs print ids and counts only.

## Rollback

Before rolling back to a build that has no `founder` role, run `sigil org demote-founders --reason "rollback"`.
An earlier build gives the `founder` role no permission, so an org whose only administrator is a founder would
have no administrator on that build. After upgrading again, grant `founder` back with `set-member-role` where
wanted.
