# Retest Report — `<target-name>`

**Retest window:** `<start>` — `<end>`
**Tester:** OBSIDIAN
**Version:** `1.0`

This report aggregates the per-finding retest results. Findings are
detailed in their respective `findings/NNN-*.md` files; this report
is the executive view.

---

## 1. Summary

| Status | Count |
|--------|------:|
| Verified Fixed | N |
| Partially Fixed | M |
| Bypassed (still open) | K |
| Risk Accepted | L |
| Will Not Fix | P |
| New findings discovered during retest | Q |

## 2. Per-finding status

| ID | Title | Original severity | Retest result | Date |
|----|-------|-------------------|---------------|------|
| 003 | Webhook signature | Critical | Verified Fixed | YYYY-MM-DD |
| 007 | Admin defaults | Critical | Verified Fixed | YYYY-MM-DD |
| 014 | IDOR /order | High | Partially Fixed (variant succeeds) | YYYY-MM-DD |
| 022 | No login rate limit | High | Verified Fixed | YYYY-MM-DD |
| ... | ... | ... | ... | ... |

## 3. Verified Fixed

For each: ID, title, brief confirmation note (1–2 lines).

> **003 — Webhook signature**: signature is now verified using
> `hash_equals` against the expected HMAC. URL-encoding, case, and
> trailing-whitespace variants all rejected. Idempotency
> constraint also added at DB level.

> **007 — Admin defaults**: default credentials disabled; first-
> login forces password change. Admin path now allowlisted by IP
> as defense in depth.

(continue per fixed finding)

## 4. Partially Fixed (with bypass)

For each: ID, title, brief description of the bypass, and a new
finding number if opened.

> **014 — IDOR /order**: original PoC (numeric ID change) now
> returns 403. However, batch endpoint `/orders?ids=1,2,3` still
> returns cross-user data; this bypass is captured as new finding
> **069 — IDOR persists on batch endpoint** and is now Open.

(continue per partial finding)

## 5. Bypassed (still open)

For each: ID, title, current state, operator's planned fix.

> **<ID> — <title>**: original PoC still works; operator's planned
> fix did not address the root cause. Recommend `<approach>`.
> Operator targeting fix in next sprint.

## 6. Risk-accepted items

| Finding | Operator's reasoning | Compensating controls | Re-evaluate |
|---------|---------------------|----------------------|-------------|

## 7. Will-not-fix items

| Finding | Operator's reasoning |
|---------|---------------------|

## 8. New findings discovered during retest

For each: new ID, title, severity, brief description.

> **069 — IDOR persists on batch endpoint** (High). Discovered
> while validating fix for finding 014. The batch endpoint
> `/orders?ids=1,2,3` was not covered by the new authorization
> middleware. Detailed in `findings/069-idor-batch-endpoint.md`.

## 9. Regression issues observed

If the operator's fixes broke legitimate flows, list:

> Login rate limit (fix for 022) is too aggressive: real users on
> shared NAT (corporate networks, mobile carriers) are getting
> locked out at ~30 attempts/hour collectively. Recommend per-
> account in addition to per-IP, and CAPTCHA escalation rather
> than hard lockout.

## 10. Residual risk after this retest

A short paragraph describing the current security posture.

> After this retest, all Critical findings are closed. Two High
> findings (014 and 029) are partially fixed; their remaining
> exposure is limited to specific attack patterns (batch endpoint
> for 014; refund chain for 029). Both are scheduled for
> remediation in the next sprint. The operator's overall posture
> is materially improved versus the start of the engagement;
> realistic adversary success against the worst-case objectives
> would now require novel exploitation rather than the previously-
> available trivial paths.

## 11. Sign-off

- **Operator:** `<name>` — date: ____________
- **Tester:** OBSIDIAN — date: ____________
