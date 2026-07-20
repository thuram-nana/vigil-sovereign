# `CHAIN-<NNN>-<slug>` — `<short title>`

| Field | Value |
|-------|-------|
| **ID** | `CHAIN-<NNN>` |
| **Title** | `<concise title describing the chained outcome>` |
| **Severity** | `Critical / High / Medium` |
| **Component findings** | `<comma-separated finding IDs that compose this chain>` |
| **Status** | `Reported / Fix in progress / Verified Mitigated / Bypassed` |
| **Reported** | `YYYY-MM-DD` |
| **Last updated** | `YYYY-MM-DD` |
| **Tester** | `OBSIDIAN` |

A chain is a sequence of independently-rated findings that together
produce an impact greater than any individually. Severity is rated
on the chain's outcome, not on the components.

If breaking any one link mitigates the chain, the chain's status
follows the weakest mitigation.

---

## Outcome

> What the chain achieves end-to-end. State this in attacker terms.
>
> Example: "An unauthenticated attacker can take over any user
> account by combining the password-reset host-header injection
> (FIND-007) with the open redirect on `/auth/callback` (FIND-014)."

---

## Components

For each step, link the finding and explain its role in the chain:

### Step 1 — `<finding-NNN>` `<title>`

- **Finding link:** `findings/<NNN>-<slug>.md`
- **Severity (in isolation):** `<level>` — e.g. Medium, often
  dismissed.
- **Role in chain:** What the attacker uses it for at this step.
- **Preconditions:** What must be true before this step works.

### Step 2 — `<finding-NNN+1>` `<title>`

- **Finding link:** `findings/<NNN+1>-<slug>.md`
- **Severity (in isolation):** `<level>`
- **Role in chain:** ...
- **Preconditions:** Includes outcome of Step 1.

(Continue for every step.)

---

## Walkthrough

Numbered, exact, reproducible steps. Compose the component PoCs
into one continuous narrative.

```bash
# Step 1: trigger reset email with attacker-controlled host
curl -X POST 'https://<target>/password/reset' \
     -H 'Host: attacker.example.com' \
     -d 'email=victim@example.com'
# → Email sent to victim with link
#   https://attacker.example.com/auth/callback?token=<...>

# Step 2: when victim clicks, attacker receives token...
```

Evidence: `evidence/CHAIN-<NNN>-*.{...}`.

---

## Impact

Why the chain matters more than the sum of its parts.

- **Outcome:** account takeover of arbitrary user.
- **Reach:** all users with valid email accounts.
- **Detection:** the reset triggers a normal email; the attacker's
  host receives the click silently. No reliable signal in operator
  logs.
- **Cross-tenant:** chain works against all tenants identically.

---

## Why severity rises in chain

Each component, in isolation:
- FIND-007 (host-header injection on reset): Medium — requires
  attacker to position host header in a way most users never
  encounter.
- FIND-014 (open redirect on callback): Low — open redirects are
  often dismissed.

Together: Critical. The chain produces account takeover with no
victim awareness. The components were under-prioritized; the chain
demonstrates why both must be fixed even though each looks minor.

---

## Mitigation

Breaking any link mitigates the chain:

- **Best:** fix both components. The chain becomes inapplicable
  and so do their independent impacts.
- **Sufficient (chain only):** fix one of the two — typically the
  cheaper. State the chain mitigation level.
- **Insufficient:** monitoring / alerting on the chain pattern.

State the operator's chosen mitigation in the Re-test section.

---

## Re-test history

| Date | Tester | Result | Notes |
|------|--------|--------|-------|
| 2026-MM-DD | OBSIDIAN | Reported | Initial chain discovery |
| 2026-MM-DD | OBSIDIAN | <result> | <retest notes> |

---

## References

- Component findings (linked above).
- `framework/cognitive/decision-frameworks.md` § severity ladder
  for chain rating rules.
