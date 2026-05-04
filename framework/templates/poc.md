# PoC — `<finding-id>-<slug>`

A self-contained proof-of-concept for one finding. Goal: an engineer
can run this end-to-end and reproduce the bug in their own
environment within minutes.

| Field | Value |
|-------|-------|
| Finding | `<finding-NNN-slug>` |
| Date | `YYYY-MM-DD` |
| Author | OBSIDIAN |
| Environment | `<staging / production / specific URL>` |

---

## Setup

What the runner needs before reproducing:

- Test accounts: list email + password (per charter test-account
  list).
- Tools: `curl`, `jq`, optionally `python3` for advanced payloads.
- Network: reachable to `<target>`.
- Time of day or rate windows that affect reproduction (rare).

---

## Reproduction

Numbered, atomic steps. Each step shows the exact command and the
exact expected output (or a redacted excerpt).

```bash
# Step 1: log in as test-user-A
curl -s -c /tmp/cookies-a.txt -X POST 'https://<target>/login' \
     -d 'email=alice@test.example' \
     -d 'password=<from charter>' | jq .
```

Expected response (excerpt):
```json
{ "ok": true, "user": { "id": 1001, "email": "alice@test.example" } }
```

```bash
# Step 2: place an order to obtain an order ID
ORDER_ID=$(curl -s -b /tmp/cookies-a.txt -X POST '<...>' -d '<...>' | jq -r .id)
echo "$ORDER_ID"
```

```bash
# Step 3: as bob (different account), request alice's order
curl -s -c /tmp/cookies-b.txt -X POST 'https://<target>/login' \
     -d 'email=bob@test.example' -d 'password=<...>'

curl -s -b /tmp/cookies-b.txt "https://<target>/api/v2/orders/${ORDER_ID}"
```

---

## Observed result

```json
{
  "id": 12345,
  "user_id": 1001,             /* belongs to alice, not bob */
  "amount": 99.99,
  "items": [...]
}
```

The response leaks alice's order data to bob.

---

## Expected result

```
HTTP 403 Forbidden
{ "error": "not authorized" }
```

---

## Variants tested

For audit purposes, list the variants tried and their results
(useful when retest verifies fix is structural):

- Method swap (GET/POST/PUT): `<results>`
- Encoding (URL/HTML/double): `<results>`
- Sibling endpoint (`/orders/{id}/items`): `<results>`

---

## Cleanup

If the PoC creates persistent state (orders, accounts, files):

- [ ] Created order ID `<X>` on alice — refunded / canceled? (yes/no)
- [ ] Test file uploaded — deleted? (yes/no)
- [ ] Session token issued — revoked? (yes/no)

---

## Evidence index

Files in `evidence/` related to this PoC:

- `<NNN>-burp.har`: Burp HTTP Archive of full session.
- `<NNN>-screenshot-1.png`: response screenshot.
- `<NNN>-curl-log.txt`: full curl transcript.

---

## Notes

(Optional context that helps a reproducer — gotchas, rate limits,
session timeouts, environment-specific quirks.)
