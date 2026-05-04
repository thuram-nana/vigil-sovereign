# Race conditions — technique reference

## 1. Mental model

A race exists when **two or more code paths execute concurrently and the
outcome depends on ordering** that the developer assumed could not happen.
The classic shape:

```
T1: read state                 T2: read state
T1: validate (state ok)        T2: validate (state ok)
T1: act on state               T2: act on state
T1: write new state            T2: write new state   <-- one wins, the other is lost
```

The defender's job is to make the read-validate-act-write sequence atomic
(database transactions with proper isolation, row-level locks, optimistic
concurrency, distributed locks). When they fail to: race wins.

For this engagement type (web apps, especially anything with money or
balances), the highest-value races are:

- **Coupon / promo code redemption** — single-use code accepted N times
- **Balance withdrawal / refund** — withdraw N+1 times before balance updates
- **Payment crediting** — credit applied for one payment, multiple times
- **Order / stock decrement** — last-item-in-stock sold to multiple users
- **Account creation with reserved username** — collision before unique check
- **Email verification** — token consumed once but processes side effects N times
- **MFA token consumption** — single OTP consumed against multiple sessions
- **Limit-imposing actions** — "max 1 review per user" bypassed
- **State transitions** — accept-then-reject converted to accept-twice

## 2. Detection — quick triage

Identify any endpoint that:

1. Mutates server state.
2. Validates against state immediately before mutating.
3. Is reachable by an authenticated user (or unauthenticated, even better).
4. Returns a deterministic success/failure response.

For each, ask: *if I called this 50 times in 5 milliseconds, what happens?*

If you can't answer with confidence "the system serializes correctly", test.

## 3. Tooling

### 3.1 Burp Repeater "Send group in parallel" (recommended)

Burp Suite Pro 2023.10+ uses HTTP/2 single-packet attack: bundles N requests
into one TCP packet, fires them at once, neutralises network jitter (the main
source of false negatives in older race tools).

Steps: send candidate request to Repeater → "Add to group" → "Send group in
parallel". Use 20–30 copies as default, more for very-fast endpoints.

### 3.2 Turbo Intruder (Burp extension)

Python-scripted; supports `engine=Engine.BURP2` for single-packet attack.

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2)
    for i in range(20):
        engine.queue(target.req)
    engine.start()

def handleResponse(req, interesting):
    table.add(req)
```

### 3.3 race-the-web / oxdef/race

Standalone Go tool for non-Burp environments.

### 3.4 Custom curl

```bash
URL="https://target.tld/api/withdraw"
COOKIE="session=..."
BODY='{"amount":100}'
for i in $(seq 1 20); do
  curl -s -X POST "$URL" \
    -H "Cookie: $COOKIE" \
    -H "Content-Type: application/json" \
    -d "$BODY" \
    -o /tmp/race-$i.out -w "%{http_code} %{time_total}\n" &
done
wait
```

Limitation: kernel scheduling and TLS handshake timing add jitter. For
real-world exploit test, prefer single-packet attack via Burp/Turbo.

### 3.5 HTTP/2 single-packet primer

Modern servers accept multiple stream frames in a single TCP segment. By
withholding the last byte of each request, sending 20 nearly-complete
requests, then a final TCP packet containing all the last bytes, you arrive
at the server within the same network event — sub-millisecond delta.

## 4. Specific scenarios

### 4.1 Coupon / promo

Endpoint: `POST /cart/apply-coupon`
Hypothesis: validate-then-mark-used pattern not in a transaction.

Test: send `{"code":"SAVE50"}` 20× in parallel.
Pass: one request marks coupon used; other 19 fail.
Fail: multiple requests mark coupon used (cart shows 50% off twice; balance
moved twice).

Variant: applying coupon to multiple separate carts in parallel.

### 4.2 Balance withdrawal

Endpoint: `POST /wallet/withdraw`
Setup: account with $100 balance.

Test: 5 simultaneous requests of $80 each.
Pass: one succeeds, four fail with "insufficient funds".
Fail: more than one succeeds; balance goes negative or below correct value.

### 4.3 Order placement on limited stock

Endpoint: `POST /cart/checkout` with item where stock = 1.
Test: two separate users (different sessions) submit checkout simultaneously.
Pass: one succeeds, one returns "out of stock".
Fail: both succeed; later refund chaos.

### 4.4 Reseller panels — service / order specific

(Applies to reseller / SMM panels and similar credit-based order
flows: signed but unverified webhooks, balance state in the user
table, ID-bearing order URLs.)

- **Refund races** — `POST /api/v2/refund?order=N` — refunding partially
  completed orders multiple times before status updates.
- **Add-funds races** — paid once externally, claimed multiple times via
  parallel webhook delivery (test webhook idempotency).
- **Promotional credit application** — apply same promo across N orders in
  parallel.
- **Coupon-on-deposit** — deposit-bonus coupons applied multiple times.

### 4.5 MFA bypass

Endpoint: `POST /verify-totp`
Test: send same OTP code with same session 5× in parallel.
Pass: one succeeds, others fail with "code already used".
Fail: multiple succeed; opens replay window.

Variant: same OTP, different session IDs, parallel — should all fail except
one (or all fail if OTP is bound to first verifier).

### 4.6 Username / email registration

Endpoint: `POST /register` with `email=victim@x.tld`.
Setup: race two registrations with same email.
Pass: one succeeds, one fails uniqueness.
Fail: two accounts with same email — credential collision. Combined with
password reset flow → ATO.

### 4.7 Reverse — accept-then-reject

State machine: `pending → accepted → rejected` (terminal).
Race: send `accept` and `reject` simultaneously.
Pass: one wins, the other is rejected (or queued).
Fail: both transitions apply; record ends up in undefined state.

### 4.8 Limit bypass

"One review per product" — race to insert two reviews; if there's no DB
unique constraint, both inserted.

"One referral bonus per user" — race two referral redemptions with same
referrer; both credited.

## 5. Confirming exploitability

A successful race may look like:

- HTTP 200 from multiple requests when only one should succeed
- Balance / counter increments more than expected
- Multiple records in DB with same supposedly-unique key
- Audit log entries showing simultaneous state transitions
- Email / notification delivered N times when one was expected

Capture full request/response set with timestamps, plus DB-state-after if
you have read access (otherwise infer from app responses).

## 6. Single-server vs distributed considerations

Single-server apps with proper DB transactions and unique constraints rarely
race in dangerous ways at the DB layer — but app-level "check then act"
outside transactions still does. Distributed systems (multiple app servers
behind LB, queue-based workers, microservices) are *more* race-prone:

- Two webhook handlers consuming same idempotency key
- Cache-then-DB write patterns (cache hit before DB commit)
- Message queue redelivery (at-least-once guarantee → must be idempotent)
- Distributed lock TTL expiring mid-operation
- Eventually-consistent stores (DynamoDB, Cassandra) read-your-write gotchas

## 7. Source-code review heuristics

```
# Python
grep -rEn "if .*\.exists\(\)" --include='*.py'  # check then act
grep -rEn "\.first\(\)" --include='*.py'        # often part of check-then-update
grep -rEn "\.update\(.*=.*\+ ?1\)" --include='*.py'  # increment without atomic op

# Java
grep -rEn "if \(.*findBy.*\) \{" --include='*.java'

# Node
grep -rEn "await.*\.findOne.*\n.*await.*\.save" --include='*.js' -A3

# Look for transaction wrappers — their absence is the bug
grep -rEn "BEGIN|START TRANSACTION|with transaction|@Transactional|trx\."

# Lock primitives
grep -rEn "SELECT.*FOR UPDATE|with_for_update|lock_version|@Version|optimistic"
```

Flag: any "check existence / count / balance" followed by a write, not
inside a transaction with `SELECT … FOR UPDATE` or equivalent.

## 8. Defenses (for remediation)

1. **Database-level unique constraints** for any "must be unique" field.
2. **Atomic operations** — `UPDATE balance = balance - 80 WHERE id=? AND
   balance >= 80` returns 0 rows if insufficient; act on row count.
3. **`SELECT … FOR UPDATE`** within a transaction for read-then-write paths.
4. **Optimistic concurrency** — version column; update conditional on
   version, retry on conflict.
5. **Distributed locks** (Redis Redlock, ZooKeeper) for cross-process
   serialization; with timeouts and fencing tokens.
6. **Idempotency keys** — request includes `Idempotency-Key`; server stores
   and returns prior result for duplicates. Required for payment APIs.
7. **State-machine enforcement** — explicit allowed transitions with
   conditional updates (`UPDATE … WHERE status='pending'`).
8. **Queue-based serialization** — write to queue partitioned by key, single
   consumer per key processes serially.

## 9. CWE / standards mapping

- CWE-362 — Concurrent execution using shared resource with improper
  synchronisation (race)
- CWE-367 — TOCTOU
- CWE-209 — Information exposure through error message (sometimes how races
  are discovered)
- OWASP WSTG WSTG-BUSL-09
- OWASP API Top 10 2023 (often manifests as broken object-level auth or
  business-logic flaw under stress)

## 10. Reporting tips

- Always include parallel-request traces with µs-level timestamps where
  possible.
- Quantify financial / data impact: "with $0 balance, withdrew $400" reads
  starkly to executives.
- Demonstrate the fix testably — same race retest should fail to produce the
  bad state.
