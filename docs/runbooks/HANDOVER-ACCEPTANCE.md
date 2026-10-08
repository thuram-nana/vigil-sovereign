# Runbook — production handover acceptance (WS4)

**Audience:** whoever provisions and hands over a production / investor-eval VIGIL box.
**Goal:** prove, on the ACTUAL provisioned box, that the real VIGIL pipeline works end-to-end before the box
is handed over. Handover is gated on a **GREEN** run of the acceptance harness here — nothing else.

The harness (`vigil_integration.sovereign_deploy.acceptance`) is a per-VM self-test. It reuses the REAL
product paths (it stubs nothing) against the **bundled loopback MERIDIAN range** on `127.0.0.1:19010` — a
controlled vulnapp, never an external or customer target. It is **fail-closed**: every required check must
PASS; any FAIL, or a REQUIRED check NOT-RUN, is a **BLOCK**.

---

## When this runs

- **Automatically**, as the last step of `./bootstrap.sh --production` (or `VIGIL_POSTURE=production`). A
  non-zero verdict fails the bootstrap (wired through the same `SMOKE_FAIL` gate as every other smoke test;
  it is never `|| true`-swallowed). The generic fresh-box / dev bootstrap does **not** run it.
- **On demand**, any time, via the convenience verb:

  ```
  vigil deploy-acceptance --target-port 19010
  ```

Both invoke the same module and apply the same verdict. Exit `0` = `HANDOVER-READY`; non-zero =
`HANDOVER BLOCKED`.

---

## Prerequisites (a MISSING one BLOCKS — it does not skip)

1. **`ANTHROPIC_API_KEY` is provisioned** in the environment that runs the gate (the bootstrap shell, or the
   shell you run `vigil deploy-acceptance` from). The harness makes ONE real keyed `think` call to prove
   model reachability (check 1) and asserts the deterministic oracle STILL gates it. With no key wired,
   check 1 is reported **NOT-RUN** — and a required NOT-RUN **BLOCKS** handover. It is never rounded to green.
   - The keyed call runs under an owner-authorised self-test egress; the key never leaks into the proposal
     text (the harness asserts this). If nothing reaches Anthropic (network fail-close), check 1 is NOT-RUN
     and still BLOCKS — reachability was not provable, so handover is not granted.

2. **The MERIDIAN range is reachable on `:19010`.** Checks 2 (governed engage → signed FACT → offline
   re-verify, tamper rejected) and 6 (FACT-capable HexStrike `nmap` → `SERVICE_REACHABILITY`) read it.
   - Under `--production`, bootstrap brings the range up itself (`.venv-offense/bin/target up meridian`,
     loopback only) and tears down only a range it started. If you run the verb by hand, start it first:

     ```
     target up meridian --no-browser        # binds 127.0.0.1:19010 (and range-control :19011)
     ```
   - If the range cannot be brought up (launcher absent, or `:19010` never opens), checks 2 and 6 **FAIL**
     → **BLOCK**. That is the intended fail-closed behaviour, not a reason to skip.

3. **The `AEGIS_RESPOND` entitlement is grantable.** Check 3/5 requires AEGIS `enforce` to BLOCK a CONFIRMED
   attack with a 403 + a re-runnable certificate. The harness provisions a real OFFENSIVE-tier entitlement
   into its OWN isolated governed workspace (its own `CRUCIBLE_ROOT`, charter authorising ONLY the loopback
   target, and trust root) — so on a correctly built box this check passes. A box where the entitlement
   cannot be granted downgrades to observe and this check **FAILS** → **BLOCK**.

---

## Reading the verdict

The harness prints one line per check and a final verdict:

```
VIGIL PRODUCTION ACCEPTANCE HARNESS (WS4) — per-VM self-test
============================================================
[PASS ] 1. REAL Anthropic think returns a proposal AND the oracle still gates it — ...
[PASS ] 2. engage -> signed FACT -> offline re-verify (tamper rejected) — ...
[PASS ] 3. a LEAD stays a LEAD (non-confirmable finding never rounded to FACT/CLEAN) — ...
[PASS ] 4. codescan static FACT over a planted weak-crypto region (INV2) — ...
[PASS ] 5. AEGIS enforce blocks a CONFIRMED attack with a re-runnable certificate (INV3) — ...
[PASS ] 6. FACT-capable HexStrike tool mints (nmap -> SERVICE_REACHABILITY) — ...
============================================================
VERDICT: HANDOVER-READY — all required checks PASS
```

- `VERDICT: HANDOVER-READY` + exit `0` → the box may be handed over.
- `VERDICT: HANDOVER BLOCKED — N check(s) did not pass: ...` + non-zero exit → **do not hand over.** Fix the
  blocking prerequisite / defect and re-run. An empty result set is itself a BLOCK (nothing was proven).

| Blocked check | Most likely cause | Fix |
|---|---|---|
| 1 NOT-RUN | no `ANTHROPIC_API_KEY`, or nothing reached Anthropic | export a valid key; confirm egress is permitted for the self-test |
| 2 FAIL | `:19010` unreachable, or the engage minted no signed FACT | bring the MERIDIAN range up on `:19010` |
| 5 FAIL | `AEGIS_RESPOND` not granted (downgraded to observe) | rebuild the box so the OFFENSIVE-tier entitlement provisions |
| 6 FAIL | `:19010` unreachable (no reachability FACT) | bring the MERIDIAN range up on `:19010` |

---

## What this gate does NOT do

- It does **not** target a demo, a mock, or any external/customer system — only the controlled loopback
  MERIDIAN range (the CI/acceptance target). It is a GET-only read self-test of the box.
- It does **not** weaken any check or add any oracle (`_ALL_ORACLES` stays 15). NOT-RUN and LEAD are never
  rounded up to green / FACT / CLEAN.
