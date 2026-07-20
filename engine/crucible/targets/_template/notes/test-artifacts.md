# Test artifacts log — `<target-name>`

Every artifact created during testing — accounts, orders, files,
sessions, DB rows. The log tracks what was created, what side
effects occurred, and whether cleanup is verified.

Why this matters: leaving test artifacts in production creates
operational risk (orphan records, monitoring noise) and
compliance risk (test PII in production, test charges that need
reversal). The cleanup log is part of stage 6 and stage 9 quality.

---

## Accounts created

| Account | Email | Role | Created | Cleanup | Notes |
|---------|-------|------|---------|---------|-------|
| alice | alice@test.example | user | 2026-MM-DD | retained for retest | per charter |
| bob | bob@test.example | user | 2026-MM-DD | retained for retest | per charter |
| eve | eve@test.example | user | 2026-MM-DD | deleted YYYY-MM-DD | created during stage 4 IDOR test |
| ... | ... | ... | ... | ... | ... |

---

## Orders / financial events

| Date | Account | Action | Amount | Order ID | Cleanup | Notes |
|------|---------|--------|--------|----------|---------|-------|
| 2026-MM-DD | alice | placed | $0.10 | 12345 | refunded YYYY-MM-DD | minimum-amount test order |
| 2026-MM-DD | alice | refund-attempted | $0.10 | 12345 | n/a | tested race; only one refund processed |
| ... | ... | ... | ... | ... | ... | ... |

---

## Files / uploads

| Date | Path / location | Type | Size | Cleanup | Notes |
|------|-----------------|------|------|---------|-------|
| 2026-MM-DD | `/uploads/avatars/alice/2026/test.png` | PNG | 1.2KB | deleted YYYY-MM-DD | upload test |
| 2026-MM-DD | `/uploads/temp/<uuid>.svg` | SVG | 200B | deleted YYYY-MM-DD | XXE probe |
| ... | ... | ... | ... | ... | ... |

---

## Sessions / tokens

| Date | Account | Type | Identifier (last 4) | Cleanup | Notes |
|------|---------|------|---------------------|---------|-------|
| 2026-MM-DD | alice | session | ...abcd | revoked YYYY-MM-DD | testing session invalidation |
| 2026-MM-DD | alice | api-key | ...wxyz | revoked YYYY-MM-DD | jwt attack test |
| 2026-MM-DD | alice | reset-token | ...1234 | naturally expired | host-header test |
| ... | ... | ... | ... | ... | ... |

---

## DB / state changes (post-exploit only)

If stage 6 was authorized:

| Date | Action | Authorization | Cleanup | Notes |
|------|--------|---------------|---------|-------|
| 2026-MM-DD | created marker file `/tmp/obsidian-poc.txt` on web server | charter §X + ack from operator | deleted YYYY-MM-DD | RCE proof |
| ... | ... | ... | ... | ... |

---

## Outbound / 3rd-party calls

When testing involves emails sent or webhooks fired:

| Date | Action | Recipient | Notes |
|------|--------|-----------|-------|
| 2026-MM-DD | password reset email triggered | alice@test.example | host-header test; received normally |
| 2026-MM-DD | password reset triggered with attacker host | alice@test.example | received with attacker URL — finding 007 |
| ... | ... | ... | ... |

---

## Cleanup verification checklist (engagement-end)

- [ ] All test accounts not retained for retest are deleted.
- [ ] All test orders refunded / canceled.
- [ ] All test uploads deleted.
- [ ] All test sessions / tokens revoked.
- [ ] All post-exploit artifacts removed.
- [ ] Operator briefed on cleanup status.
- [ ] If anything could not be cleaned, documented with reason and
       owner action item.
