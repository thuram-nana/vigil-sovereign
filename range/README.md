# VIGIL cyber-range — MERIDIAN

> ⚠ **INTENTIONALLY VULNERABLE — LAB ONLY.** MERIDIAN is a *fictional* government portal with **no real
> data**, bound to **loopback only**. It exists solely as an authorized target for exercising VIGIL against
> a realistic surface. Do not deploy it, do not expose it to a network, do not enter real data.

MERIDIAN is a deliberately-vulnerable, government-themed web application — a *National Permits & Licensing
Authority* — that serves as the estate's own end-to-end **lab** for VIGIL. It has two halves:

1. **MERIDIAN** (the target, `:19010`) — a citizen portal + a five-role staff back office carrying **real,
   oracle-confirmable** vulnerabilities (SQLi, XSS, IDOR/BOLA, path traversal, open redirect, SSRF, exposure,
   weak auth, business-logic, an LLM assistant). Every sink has a *hardened* twin that keeps the route and
   only neutralizes the weakness, so a VIGIL posture re-prove earns a **sound CLOSED** negative.
2. **Range Control** (the operator cockpit, `:19011`) — drives the real VIGIL verbs against MERIDIAN and
   streams the results: recon → oracle-confirmed findings → access-control → governed engage → verify →
   evidence → defensive `detect` on MERIDIAN's own logs → posture attest → **harden → re-prove CLOSED**.

## Run it

```
target up               # start MERIDIAN (:19010) + Range Control (:19011), loopback only
target up --hardened    # start with every planted sink neutralized (the negative control)
target status           # show running state / mode / ports
target harden on|off    # flip vuln ↔ hardened live (no restart) — for the harden → re-prove demo
target down             # stop
target charter          # print the engagement charter authorizing VIGIL against the range
```

`target` is installed as an offense-env console-script (`~/.local/bin/target`, symlinked by `bootstrap.sh`).

Then open **Range Control** at http://127.0.0.1:19011/ and click **Run all ▸** — it drives VIGIL against the
target and streams every step. Or run the verbs yourself against http://127.0.0.1:19010/.

## The end-to-end tour (what Range Control runs)

1. **Recon** — crawl the surface. 2. **Confirm SQLi + XSS** — `framework.v2 scan` → oracle FACTs.
3. **Confirm IDOR/BOLA** — two-identity `scan --access-control`. 4. **Confirm SSRF** — OOB oracle.
5. **Verify offline** — `framework.v2 verify` re-executes the retained oracle context (prove-don't-guess).
6. **Detect** — `vigil detect` fires the attack signatures from MERIDIAN's own logs. 7–9. **Harden →
re-prove → restore** — `target harden on`, then a re-scan returns **0 confirmed FACTs** (a sound CLOSED
negative), then back to vulnerable. Governed **engage** is available as an extra (approve-then-run).

## What the real engine produces (reproduce it: Range Control → Run all ▸)

Every planted weakness is confirmed by a VIGIL deterministic oracle, not asserted. The results below are
from a live loopback run against this range — reproduce them yourself from Range Control (the confidences
are what that run reported; the range's own tests pin the *signal* each sink emits, and the engine assigns
the grounding):

| Capability | Result the engine produced |
|---|---|
| SQL injection | `error_based_sqli \| fact` at `q` (re-verified offline, conf 0.88) |
| Reflected XSS | `xss \| fact` at `q` (re-verified offline, conf 0.95) |
| IDOR / BOLA | `idor \| fact` at `id` (two-identity access-control) |
| SSRF | `ssrf \| fact` at `url` (out-of-band callback) |
| Defensive detect | 6 detection FACTs — forced_browsing · sqli_structure · path_traversal · cmd_injection · port_scan · brute_force |
| Posture (hardened) | **0** confirmed FACTs on a live channel — a sound CLOSED negative |

## Why it's safe

- **Loopback only.** The launcher refuses any non-loopback bind — stricter than VIGIL's own bind guard.
- **No real data.** Only synthetic, tagged records; fabricated credentials in the shapes scanners match.
- **Decoys, not leaks.** A path-traversal attempt returns a *decoy* passwd string; no real file is ever read.
- **Authorized.** [`targets/meridian/charter.md`](../targets/meridian/charter.md) scopes the engagement to
  `127.0.0.1` and is accepted by VIGIL's own `ethics` scope gate.
- **No offense drift.** This package is stdlib-only and never imports `framework`/`strix`; Range Control
  shells the offense verbs as subprocesses, so the two-env boundary is unaffected.

## Layout

```
range/
  vigil_range/
    cli.py · launcher.py · apps.py     # the `target` command + loopback launcher + app registry
    meridian/                          # the MERIDIAN application
      app.py · router.py · config.py · logs.py · theme.py
      handlers/                        # the target surface (portal, records, api, staff, admin, …)
      rangecontrol/                    # the Range Control cockpit (live command-center)
  meridian_target.py                   # standalone launcher registered in the loopback-range manifest
  tests/                               # stdlib pytest (bind guard, vuln/hardened, logs, charter, registry)
```

The registry entry lives in [`tools/livefire/range_targets.json`](../tools/livefire/range_targets.json).
