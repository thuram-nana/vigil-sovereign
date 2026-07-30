# Engagement charter — `testasp`

**Version:** 1.0
**Status:** Final (operator-confirmed)
**Date:** 2026-07-29
**Last updated:** 2026-07-29

This is the binding authorization document for the engagement against
`testasp.vulnweb.com` — Acunetix's deliberately-vulnerable, publicly-published
ASP + Microsoft SQL Server test site, which the vendor explicitly stands up for
exactly this purpose. It is a LEGAL, owner-published practice target. Authorized
as the live substitute after the signed `testphp` target was found offline.

> **Charter format note:** the engine's scope parser reads the numbered
> `## 2. In-scope systems` table below (mirrors `targets/_template/charter.md`),
> NOT the free-form "Target hosts" heading the earlier `testphp` charter used —
> that older format parses to an EMPTY scope and would refuse every seed.

---

## 1. Operator attestation

I, **Junior Thuram Nana**, attest:

- `testasp.vulnweb.com` is a vendor-published deliberately-vulnerable test site
  that Acunetix makes available for anyone to test; I am authorized to test it.
- I explicitly authorized live testing of `testasp.vulnweb.com` in this session,
  on 2026-07-29, via the "Authorize testasp now" answer to the assistant's
  target-selection question — chosen because the previously-signed
  `testphp.vulnweb.com` was confirmed OFFLINE (its own outage) while
  `testasp.vulnweb.com` is live.
- I understand offense traffic will reach an external host and accept
  responsibility for originating it only from an environment I am authorized to.
- I have read and understood the OBSIDIAN constitution (`CLAUDE.md`).

Signed: `Junior Thuram Nana`     Date: `2026-07-29`

---

## 2. In-scope systems

| Host / Surface | Notes | Auth required for testing |
|----------------|-------|---------------------------|
| `testasp.vulnweb.com` | Acunetix published deliberately-vulnerable ASP / MS-SQL test app | Vendor-public |

**Nothing else is in scope.** Only `testasp.vulnweb.com` may be touched by any
tool — no pivoting to any other Acunetix host, no neighbouring IPs, no third party.

## 3. Out of scope (explicit)

- Every other `*.vulnweb.com` host (`testphp`, `testaspnet`, `testhtml5`, …).
- Any third-party / shared infrastructure the target depends on (CDN, DNS, hosting).
- Findings that *reach* an out-of-scope system via an in-scope flaw are reported,
  but the third-party system itself is never exploited beyond minimum proof.

## 4. Hard limits — never violated

- Single host only: every tool invocation MUST resolve to `testasp.vulnweb.com`;
  the signed-scope floor + never-liftable egress floor refuse any other host.
- No DoS / resource-exhaustion testing.
- No destructive tools (sqlmap/hydra/metasploit) without the m-of-n threshold gate —
  it is shared public infrastructure; be a good citizen.
- Throttle: low concurrency, capped pages / audit requests, recognizable
  User-Agent (`OBSIDIAN/1.0 (authorized owner-test 2026-07-29)`).
- No real user data (the app holds only Acunetix's fake forum/catalogue rows).

## 5. Stop conditions

- Any sign of degradation of the shared test site → stop and back off.
- The operator says stop, or the kill-switch is tripped.

## 6. How to run it

```
python3 -m framework.v2 engage testasp "http://testasp.vulnweb.com/search.asp?tfSearch=test" \
  --arsenal --spine --max-pages 6 --request-budget 70 --max-audit-requests 50
```

## 7. Live-fire result (2026-07-29) — VERIFIED

The governed engagement ran end-to-end against the live host through the full gate
chain; the executor default-DENIED every destructive probe (POST search, admin
paths) with no TTY confirmation. Two findings were oracle-confirmed over
executor-captured bytes and **re-verified OFFLINE 2/2** from the run's spine-retained
oracle context:

| Finding | Oracle | Conf | Surface | Offline re-verify |
|---|---|---|---|---|
| `boolean_sqli` (SQL injection) | `differential_response` | 0.987 | `search.asp` param `tfSearch` (deterministic 200→500 divergence on injection) | `[OK] matches-claim` |
| `open_redirect` | `achieved_state` | 0.900 | `query_value:0` | `[OK] matches-claim` |

**Negative control:** flipping the retained baseline status to erase the 200→500
divergence makes `verify` report `[BAD] CLAIM-MISMATCH (tampered?)` → `0/1 reproduced`.
The proof re-fires deterministically for genuine evidence and rejects a tampered byte
— the "the machine cannot lie about a finding" property, demonstrated LIVE and EXTERNAL.

**Re-corroborated 2026-07-30.** A fresh chartered run of the §6 command reproduced the
result live through the full gate chain — the executor **default-denied** every destructive
probe (POST `search.asp`, `/admin*`) with no TTY confirmation — and minted **4 oracle-confirmed,
certificate-backed findings** onto the signed spine (`.blackboard/store.sqlite`, `--spine`):
`boolean_sqli` @ `query_value:0` (`differential_response`, conf 0.99), `open_redirect` @
`query_value:0` (`achieved_state`, 0.90), and two `request_smuggling` (`differential_response`,
CL.TE / TE.TE, 0.70). This resolves the audit's telemetry-vs-charter discrepancy: the per-run
`.vigil-live/live-ui/telemetry.json` seen earlier reflected a run whose destructive edges were
denied (a refusal-heavy view), whereas the **signed spine carries the confirmed edge-plane
FACTs** — a fresh run mints them durably. The self-contained 3/3 offline re-verify is
demonstrated on-box by the **loopback** L1 FACT (`docs/AS-BUILT-LIVE.md` §L1); this external run
is corroborated by minting through the full gate + the tamper negative-control above.

> This is byte-for-byte the same oracle path L1 proved on loopback, now against a real
> published site. `testphp.vulnweb.com` (verbose-error MySQL, the near-guaranteed
> error-based FACT) was OFFLINE at run time; `testasp` suppresses verbose errors, so the
> FACTs came from the differential/achieved-state oracles rather than `error_signature`.
