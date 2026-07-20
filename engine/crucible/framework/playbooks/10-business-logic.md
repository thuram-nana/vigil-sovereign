# Playbook 10 — Business logic

**Goal:** find logic flaws specific to how *this* application is
supposed to work — bugs no scanner can find because they require
understanding the app's intent.

The single highest-yield phase on most modern apps. A typical
engagement's biggest findings live here.

---

## 10.1 The general approach

For every state-changing feature in the app:

1. Walk the **happy path** as a legitimate user. Note inputs,
   outputs, side effects, state transitions.
2. Identify the **invariants**: what should always be true?
   ("balance ≥ 0", "order quantity > 0", "refund ≤ amount paid",
   "coupon used at most once per user", "user can only update their
   own resources").
3. Generate **abuse cases**: how would an attacker violate each
   invariant?
4. Test each abuse case.

Invariant violations are business-logic bugs.

---

## 10.2 Numeric / type abuse on inputs

For every numeric field (quantity, amount, rate, price, age):

| Test | Expected |
|------|----------|
| Negative value (`-1`, `-1000`) | rejected |
| Zero (`0`) | rejected if business rule says >0 |
| Very large (`9999999999999`) | rejected at limit |
| Very small decimal (`0.00000001`) | handled correctly |
| Scientific notation (`1e10`) | rejected or handled |
| Hex / octal (`0x10`, `010`) | rejected |
| Plus prefix (`+1`) | accepted same as `1` |
| Whitespace (`" 1 "`) | trimmed |
| Unicode digits (`１`, `१`) | rejected or normalized |
| Non-numeric (`null`, `true`, `[1]`, `"abc"`) | rejected |
| Currency symbols in number (`$100`) | rejected |
| Floating-point edge cases (`0.1 + 0.2`) | precision-aware |
| Integer overflow (`2^31`, `2^63`) | safe |

Negative quantity in an order placement is the *classic* bug —
balance gets credited because `cost = quantity × rate` is negative.

---

## 10.3 State machine abuse

Most workflows have a state machine: `pending → confirmed → shipped
→ delivered → archived`. Each transition has rules (who can trigger,
preconditions, effects).

For each transition:
- Can it be triggered by users without permission?
- Can it be skipped / reverted / repeated?
- Out-of-order transitions accepted? (`pending → delivered` skipping
  intermediate states.)
- Race conditions in transitions (§10.6).

Examples:
- Cancel an order *after* it's marked delivered → refund without
  return.
- Mark a return *received* before it's actually shipped → refund
  shipped goods.
- Re-open a closed ticket, then escalate via reply.
- Reset password *after* deleting account, restoring access.

---

## 10.4 Price / rate / total tampering

If the request body / form contains `rate`, `price`, `total`,
`amount`, `cost`, `service_price`, `discount_amount`:

```bash
curl -sk -X POST "https://<target>/order/place" -b "$COOKIE" \
  -d "service_id=1&quantity=1000&rate=0.0001&total=0.10&discount=99"
```

Server should re-compute price from `service_id × quantity` and
ignore client-supplied price. If it trusts the client, attacker buys
expensive things for cents.

Test variants:
- Negative price.
- Zero price.
- Mismatched `rate * quantity ≠ total` — does server use rate or
  total?
- Currency mismatch.
- Different `service_id` on second-step confirmation than initial
  selection.

---

## 10.5 ID swap mid-flow

Multi-step flows often validate at step 1 but trust at step 2.

- Choose service A (cheap), proceed to confirmation, change
  `service_id` to B (expensive) at confirm. Charged at A's price?
- Choose product variant size S, payment step has `variant_id`
  changeable to size XL.
- Add coupon for product A, change to product B before checkout.

---

## 10.6 Race conditions

The single highest-leverage business-logic bug class. HTTP/2 single-
packet attacks fire 20+ requests within microseconds.

Pattern:
- User has $10 balance, single order costs $5 → can place 2 orders
  sequentially.
- Race: send 20 concurrent order placements. If 3+ succeed, balance
  was deducted non-atomically.

Tools:
- **Burp Turbo Intruder** with single-packet attack (HTTP/2).
- **Custom Python with httpx async** — see
  `framework/scripts/race/race-condition.py`.

Targets:

| Target | Race type |
|--------|-----------|
| Order placement | Spend more than balance |
| Refund | Refund same order twice |
| Coupon redeem | Reuse one-shot coupon |
| Balance withdrawal | Double-spend |
| First-deposit bonus | Trigger bonus repeatedly |
| Free trial activation | Multiple trials |
| Drip-feed scheduler | Schedule overlapping |
| Product purchase with low inventory | Buy more than stock |
| Vote / like / rating | Vote N times in 1ms |
| Account merge | Merge two accounts twice |
| Subscription cancel + charge | Cancel-and-charge race |
| Promo code generation | Generate multiple per user |

Always document:
- Number of concurrent requests sent.
- Number that succeeded.
- Balance / state delta vs. expected.
- Whether server logs or responses indicated the race.

---

## 10.7 Refund / return logic

- **Partial-fill refund at full price**: order for 1000 followers,
  upstream delivers 200 then fails. Panel refunds full amount.
  Free-money pump if attacker can intentionally trigger this.
- **Refund eligibility window**: refund expired order via direct
  API call?
- **Refund without authorization**: regular user triggers refund on
  someone else's order (combine with IDOR).
- **Negative refund amount**: rejected?
- **Refund + dispute combo**: refund issued, then dispute the
  payment via card processor, get money twice.

---

## 10.8 Coupons / vouchers / promos

- **Reuse**: apply same code twice.
- **Stack**: apply multiple codes if disallowed.
- **Apply after charge**: place order, apply coupon retroactively,
  refund difference.
- **Generate via predictable pattern**: brute-force codes if format
  guessable.
- **Decimal arithmetic**: 100% off, 110% off → balance increase.
- **Min-spend bypass**: code requires $10 min. Apply other discount
  to bring true spend below.
- **Usage-limit bypass**: code limit is 1-per-user. Race condition.
- **Cross-user use**: code generated for user A, applied to user B's
  cart.

---

## 10.9 Subscription / recurring billing

- Cancel right before renewal → still charged.
- Pause indefinitely → free service.
- Downgrade then upgrade → bypass commitment terms.
- Charge once / fulfil many — subscription that re-orders without
  re-charging.
- Re-activate dormant subscription at old (lower) price.
- Multi-tier subscription confusion (admin-tier features on a free
  account).

---

## 10.10 Multi-step / wizard flows

Wizards typically have a session storing partial state. Test:

- Skip steps via direct POST to final endpoint.
- Replay step N after completing — does it overwrite?
- Modify step 1 inputs after step 5 (state inconsistency).
- Two browser tabs running the wizard simultaneously.
- Resume on a different account.

---

## 10.11 Withdrawal logic

- Negative withdrawal amount.
- Withdraw more than balance via race.
- Withdraw to attacker-controlled address via IDOR on withdrawal
  request.
- Cancel withdrawal *after* funds restored AND payout already sent.
- Withdraw before pending deposit settles.
- Mass withdrawal via API without UI confirmation.

---

## 10.12 Account state machine abuse

- Email change without password re-confirm.
- Account deletion: does it delete pending orders, refunds,
  balance? If balance is restored before deletion, attacker can
  drain via repeat create-fund-delete.
- Account recovery: any path that re-binds account to new email
  without ownership proof.
- Account reactivation after delete: keeps old data, but with
  new owner if email re-registered.

---

## 10.13 Quota / rate / capacity bypass

- Per-user limits enforced per session, bypassable across sessions.
- Per-account limits ignored by API.
- "1 free trial per user" tied to email but allowing alias / +
  variants of same email.
- Storage quotas: split file across many small uploads.

---

## 10.14 Workflow shortcuts

For each multi-actor workflow (KYC, approval, escrow):

- Skip approval by hitting downstream endpoint directly.
- Self-approve.
- Approval via stale link / token.
- Bypass dual-control / segregation-of-duties.

---

## 10.15 Output

Findings filed as confirmed. Phase summary:
- Critical money-loss findings (almost always Critical regardless
  of CVSS).
- Race condition findings with reproduced impact.
- Refund / coupon / promo abuses.
- State-machine abuses.
- Quantified financial impact per finding ("attacker can drain
  balances at $X / request, no rate limit").
