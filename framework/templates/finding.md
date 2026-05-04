# Finding NNN — `<short slug>`

> Copy to `targets/<name>/findings/NNN-short-slug.md` per finding.
> Numbered sequentially in order of discovery.

---

## Metadata

- **ID:** `NNN`
- **Title:** `<action-noun-object — e.g., "Webhook callback accepts forged deposits without signature">`
- **Severity:** `Critical | High | Medium | Low | Info`
- **CVSS 3.1 vector:** `<vector>` (`<base score>`)
- **Contextual severity:** `<adjusted score>` — *reasoning if differs from CVSS base*
- **CWE:** `CWE-XXX (name)`
- **OWASP category:** `<A0X:202X — Name | API0X:202X — Name | LLM0X:202X — Name>`
- **MITRE ATT&CK:** `TA0001 / T1190` (or whichever applies)
- **Affected component:** `<file or endpoint>`
- **Discovered:** `YYYY-MM-DD`
- **Discoverer:** `OBSIDIAN`
- **Status:** `Open | Reported | Fix in progress | Verified Fixed | Partially Fixed | Bypassed | Risk Accepted | Will Not Fix`
- **Stage discovered:** `<stage number>`
- **Linked findings:** `<NNN, MMM>` (constituents of, related to, or dependencies on)

---

## Summary

One paragraph, plain language. The first sentence answers:
*"What can an attacker do?"*

> *Example: An unauthenticated attacker can credit any user's
> balance with arbitrary amounts by POSTing forged payment-success
> webhooks to the public callback URL, because the panel does not
> verify the signature header on incoming Cryptomus callbacks.*

## Impact

Why it matters in business terms.

- **Direct financial loss:** `<estimate per attack and per hour>`
- **Affected users:** `<single account / all users / admin / cross-tenant>`
- **Data exposure:** `<what's exposed and at what scope>`
- **Reputational / compliance:** `<what regulators or partners would flag>`
- **Cascading:** `<does this unlock further compromise?>`

Quantify where possible. "Per-attack max loss: $X (capped by upstream
provisioning). Time-to-exfil at observed rate: ~47 minutes.
Detectable: no (no current alerts on this endpoint)."

## Affected endpoint(s) / surface(s)

```
POST /payment/cryptomus/callback
POST /payment/coinbase/callback
```

## Reproduction

Step-by-step. A reader following these steps in their staging
environment should reproduce in 5 minutes.

```bash
# 1. Pre-conditions: a target user account exists.
TARGET_USER_ID="42"

# 2. Forge the webhook
curl -sk -X POST https://target/payment/cryptomus/callback \
  -H "Content-Type: application/json" \
  -d '{
    "order_id": "OBSIDIAN-FORGED-001",
    "status": "paid",
    "amount": "100.00",
    "currency": "USD",
    "user_id": "'"$TARGET_USER_ID"'"
  }'

# 3. Observe: target user's balance increased by $100.00.
```

**Expected behavior:** webhook rejected (`401` / signature mismatch).
**Observed behavior:** `200 OK`, balance credited.

## Evidence

Raw HTTP exchanges and (redacted) screenshots in
`evidence/NNN-short-slug/`:

- `request.http`
- `response.http`
- `before-balance.png` (redacted)
- `after-balance.png` (redacted)

## Root cause hypothesis (pre-source review)

Likely the controller for `/payment/cryptomus/callback` does not
verify the signature header (`sign` per Cryptomus docs). After
source review, verify and update.

## Root cause (post-source review)

`<file>:<line range>` — paste offending lines and explain.

```php
// app/Controllers/Payment/CryptomusController.php:47-58
public function callback(Request $r) {
    $body = json_decode($r->getContent(), true);
    // <-- no signature check anywhere here
    User::find($body['user_id'])->increment('balance', $body['amount']);
    return response('ok');
}
```

The handler binds `user_id` and `amount` directly from the body,
bypassing both signature verification and per-deposit idempotency
checks.

## Recommended fix

Concrete and minimal.

```php
public function callback(Request $r) {
    $sign = $r->header('sign');
    $body = $r->getContent();
    $expected = base64_encode(md5($body . config('services.cryptomus.api_key'), true));
    if (!hash_equals($expected, (string) $sign)) {
        return response()->json(['error' => 'invalid signature'], 401);
    }
    $payload = json_decode($body, true);
    // ... existing handler with parsed $payload, plus idempotency check
}
```

Defense-in-depth:
- Idempotency: `unique(provider, tx_id)` constraint on deposits table.
- Allowlist Cryptomus webhook source IPs at the WAF / firewall as a
  second layer.
- Log all incoming webhook attempts (signed and unsigned) for audit.
- Alert on any rejected webhook with a count threshold.

## References

- Cryptomus webhook signature docs: `<URL>`
- OWASP API Security Top 10 — API8:2023 Security Misconfiguration.
- CWE-345: Insufficient Verification of Data Authenticity.
- Past similar incidents in SMM-panel space: `<refs>`.

## Re-test

| Date | Tester | Result | Variants tried | Notes |
|------|--------|--------|----------------|-------|
|      |        |        |                |       |
