# Engagement charter — `meridian`

**Version:** 1.0
**Status:** Final (operator-confirmed)
**Date:** 2026-08-29
**Last updated:** 2026-08-29

This is the binding authorization document for exercising VIGIL against the **MERIDIAN** cyber-range — a
deliberately-vulnerable, **loopback-only**, *fictional* National Permits & Licensing Authority portal that
the operator runs on their own machine as an authorized test target. It holds no real data and is never
exposed beyond `127.0.0.1`.

---

## 1. Operator attestation

I, **Range Operator**, attest:

- I own and control the loopback host (`127.0.0.1`) on which the MERIDIAN range runs.
- The range is a synthetic lab target I stood up myself; it hosts no third-party system and no real data.
- I authorize VIGIL to perform security assessment activities against the systems listed in § 2, within
  the limits stated here.
- I have read and understood the OBSIDIAN constitution (`CLAUDE.md`).

Signed: Range Operator     Date: 2026-08-29

---

## 2. In-scope systems

| Host / Surface | Notes | Auth required for testing |
|----------------|-------|---------------------------|
| `127.0.0.1` | The MERIDIAN target portal (:19010) — the loopback lab | Yes |
| `localhost` | Same host, by name | Yes |

Only the loopback range is authorized. Any host not listed above is out of scope.

## 3. Out of scope (explicit)

- Every host that is not `127.0.0.1` / `localhost`.
- Any real, internet-facing, or third-party system reachable via an in-scope flaw (SSRF, redirect,
  webhook). Findings that *reach* such a system are valuable and should be reported, but the third-party
  system itself is never to be attacked.

## 4. Hard limits — never violated

- No DoS / resource-exhaustion testing.
- No traffic to any non-loopback address.
- No real-user contact, no real payment movement (the range has neither).
- The range binds `127.0.0.1` only; it must never be exposed to a network.

## 5. Test accounts

The range seeds synthetic accounts (citizens, clerk, inspector, registrar, admin). All range data is fake
and tagged; there are no real credentials to protect.

## 6. Objectives

- Demonstrate VIGIL end-to-end against a realistic surface: recon → oracle-confirmed findings →
  access-control → governed engage → verify → evidence → defensive detect → posture attest.
- Show the remediation loop: `target harden on` neutralizes every planted sink, and a VIGIL posture
  re-prove then returns a sound **CLOSED** (Certificate of Non-Exploitability).

## 7. Posture

Selected: **TEST** — identifiable, throttled, tagged. The operator expects to correlate all range traffic
in the MERIDIAN access/auth logs.

## 8. Stop conditions

VIGIL halts and surfaces immediately if a request would leave the loopback host, if authorization becomes
unclear, or if the operator says stop.
