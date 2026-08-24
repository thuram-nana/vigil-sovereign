# Engagement authorization letter — `<target-name>`

**Version:** 1.0
**Status:** Draft → Signed (customer counter-signed)
**Date:** YYYY-MM-DD
**Engagement slug:** `<engagement-slug>`
**Authorization id:** `<uuid — matches the signed EngagementAuthorization>`

This letter is the **contract leg** of the engagement's authorization. It is
one of three artifacts that MUST describe the same in-scope systems and the
same enforcement envelope:

1. **this letter** (contract) — what the customer signs;
2. **`charter.md`** (runtime) — what the engine reads at gate time; and
3. the signed **`EngagementAuthorization`** (technical) — what the executor
   honours byte-for-byte.

`authority.crosscheck` checks all three against each other. If the in-scope
host set below diverges from `charter.md` § 2 or from the signed object's
`scope`, the framework refuses to act (`ScopeDrift`). Keep the three in
lockstep; amend all three together.

---

## 1. Parties

- **Customer (authorising party):** `<customer legal name>`
- **Issuing authority (on behalf of the customer's governance panel):** `<issuer>`
- The customer attests it is the legal owner / authorised representative for
  the systems in § 2 and authorises the engagement within the limits below.

Signed: `<name>`     Date: `__________`

---

## 2. In-scope systems

This table uses the **same format and heading** as `charter.md` § 2, parsed by
the same row logic (`authority.crosscheck.parse_scope_table`), so the two
documents cannot express scope in ways that only look equivalent. Every host
here MUST also appear in `charter.md` § 2 and in the signed authorization's
`scope`.

| Host / Surface | Notes | Auth required for testing |
|----------------|-------|---------------------------|
| `<primary-domain>` | Primary web app | Yes |
| `*.<primary-domain>` | All subdomains discovered during recon | Yes |
| `api.<primary-domain>` | Public API | Yes |
| `<staging-domain>` (if any) | Staging environment | Yes |

## 3. Enforcement envelope (mirrors the signed EngagementAuthorization)

The signed `EngagementAuthorization` carries these four enforcement bounds, and
the executor (`authority.authorization.EngagementExecutor`) honours all four.
State the same values here so the customer signs the exact envelope the
executor enforces:

| Bound | Value | Meaning |
|-------|-------|---------|
| **Danger ceiling** | `<A0 | A1 | A2 | A3>` | Maximum WARDEN autonomy tier any action may classify to. An action above this is refused. |
| **Validity window** | `<not_before>` → `<not_after>` | The engagement is authorized only within this window. |
| **Rate limit** | `<N>` actions per `<W>` s | No more than N actions in any W-second sliding window. |
| **Concurrency limit** | `<C>` | No more than C actions in flight at once. |

The table above is for the human reader; the block below is the **machine-checked**
declaration `authority.crosscheck` compares against the signed
`EngagementAuthorization`. Fill every field with the SAME value carried by the
signed object — `authority.crosscheck.assert_envelope_consistent` raises
`EnvelopeDrift` on any mismatch, and a missing or unparseable block is itself
drift (fail closed), so the customer cannot sign one envelope while the executor
honours a looser one. Keep the two representations equal.

<!-- ENVELOPE:BEGIN -->
    danger_ceiling: <A0 | A1 | A2 | A3>
    not_before: <YYYY-MM-DDThh:mm:ssZ>
    not_after: <YYYY-MM-DDThh:mm:ssZ>
    rate_limit: <N>
    rate_window_seconds: <W>
    concurrency_limit: <C>
<!-- ENVELOPE:END -->

## 4. Out of scope (explicit)

- `<third parties: payment processors, upstream APIs, IdPs, CDNs, WAFs>`
- `<sister sites the customer owns but did not include>`
- `<shared infrastructure other operators rely on>`

Findings that *reach* these via in-scope flaws are reported; the third-party
system itself is not exploited beyond minimum proof.

## 5. Amendment

Any change to the in-scope host set or the enforcement envelope requires:

1. Amending this letter, `charter.md` § 2, and re-issuing the signed
   `EngagementAuthorization` **together**;
2. Re-running the three-way cross-check (`authority.crosscheck`); and
3. The customer's counter-signature on the amended letter.

The framework does not assume an expansion was authorised because one artifact
mentions a system the others do not.
