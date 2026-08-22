# W10-5b — `vigil panic` stops AND disables every cadence SIDECAR, not just the command unit

Issue: [#478](https://github.com/thuram-nana/vigil-sovereign/issues/478) ·
Milestone: W10 — SECURITY CONTROLS THAT DO NOT FIRE (fail-open) · Builds on
[W10-5 #477](https://github.com/thuram-nana/vigil-sovereign/issues/477).

## The claim (register in the claims registry, [W0-3] #398)

> `vigil panic` is a WHOLE-SURFACE hard-stop. It does not merely mask the `vigil-command` unit — it
> STOPS and DISABLES every cadence sidecar VIGIL ships (the `vigil-reprove`, `vigil-posture`,
> `vigil-ha-mirror`, `vigil-backup-push`, `vigil-backup`, `vigil-backup-drill` and `vigil-integrity`
> timers **and** their oneshot services), stops every live `vigil-witness@<port>` instance, and
> **resets each timer's `Persistent=` catch-up stamp** so a later re-enable does **not** replay the
> runs missed during the incident. It then **verifies** that nothing is left active or enabled and
> **warns loudly** on any leak. After `vigil panic`, no scheduled unit can re-fire the retained
> corpus against the target, re-scan the target, or replicate data off-host. `vigil down` (the
> routine UI stop) deliberately does **not** touch the sidecars.

This claim is TRUE of the code as of W10-5b:

- **Enumeration** — `uiproxy._SIDECAR_TIMERS` lists all seven cadence timers in a documented,
  target-/off-host-first order; `uiproxy._SIDECAR_SERVICES` is *derived from that tuple* (each
  timer's paired oneshot) so the two lists can never drift. `uiproxy._WITNESS_GLOB` /
  `_witness_instances()` enumerate the live `vigil-witness@<port>.service` instances.
- **Containment** — `uiproxy._contain_sidecar_units()` (subprocess `systemctl --user` only — no
  `framework`/`sigil` import) STOPs then DISABLEs each timer, then STOPs its oneshot (to interrupt a
  run already in flight — stopping a *timer* does not stop a running oneshot), then STOPs + DISABLEs
  each live witness instance. It is best-effort and idempotent: one unit's failure is recorded as a
  WARNING and never aborts the rest — a hard-stop must not be blockable by a stubborn unit.
- **`Persistent=` catch-up** — `_neutralize_persistent_catchup()` stamps each timer's
  `$XDG_DATA_HOME/systemd/timers/stamp-<timer>` to *now*. systemd records a timer's last realtime
  trigger as that stamp's mtime; with `Persistent=true` a re-enable compares it against `OnCalendar`
  and fires immediately for every elapsed window. Moving the stamp forward zeroes that catch-up
  window, so re-enabling a timer after an incident schedules the NEXT run, not a replay of the missed
  ones.
- **Verification** — `_verify_sidecar_containment()` re-queries `is-active` / `is-enabled` for every
  timer, service and witness instance and returns the LEAKS (empty ⇒ contained). `run_panic()` prints
  every leak to stderr with a "do NOT assume the system is contained" warning; a clean pass prints
  "containment verified (nothing active or enabled)".
- **Wiring** — `uiproxy.run_panic()` calls the command-unit containment (`_contain_service_unit`,
  W10-5), then `_contain_sidecar_units()`, then the pid-kill, then `_verify_sidecar_containment()`.
  `cli._cmd_panic` calls `run_panic` after tripping every engagement's kill-switch (the gate-level
  half, W10-5). `run_down()` is unchanged — it contains the command unit only.

Pinned by `integration/tests/test_panic_sidecars.py` (framework-free ⇒ runs in the required
"integration two-env boundary (P5)" CI job, which executes the whole `integration/tests/` directory).
The suite includes:

- **fail-without-the-fix** — `test_panic_stops_and_disables_every_cadence_sidecar` and
  `test_run_panic_contains_the_sidecars_and_verifies`: on the pre-#478 tree there is no
  `_contain_sidecar_units` and `run_panic` issued no `systemctl` verb for any sidecar timer, so both
  fail (observed on a tree without the fix — see the PR notes);
- **negative controls** — `test_verify_reports_a_leak_when_a_unit_survives` (verify is not a rubber
  stamp: an uncontained unit is reported, never green-washed), `test_no_user_manager_contains_nothing`
  (containment is conditional — only the `show` probe runs when there is no user manager),
  `test_only_live_witness_instances_are_contained` (instances are enumerated, not guessed — the bare
  template and an unseen port are left alone), and `test_run_down_leaves_the_sidecars_alone`;
- **the live measurement** — `test_sidecar_stays_down_under_live_systemd` installs a real Persistent
  timer, lets it fire, contains it, and asserts NO further run fires over a window longer than the
  timer interval (the AC's "measured, not assumed" negative control). It is gated behind
  `VIGIL_LIVE_SYSTEMD=1` (needs a real user systemd session) and is the honest live-only residual;
  the hermetic path proves the same property by construction (post-containment `is-active`/`is-enabled`
  are inactive/disabled for every unit AND the stamp is at ~now).

## Why `vigil panic`, not `vigil down`

`vigil down` is the routine "stop the interface" verb — an operator may run it to free the port
without wanting their nightly backups and HA mirror disabled. `vigil panic` is the emergency
hard-stop where disabling the whole shipped surface is exactly right. So the sidecar containment lives
in `run_panic` only; `run_down` stays command-unit-only (W10-5). The issue's Work section and every
acceptance criterion name `vigil panic`.

## Live-only residual (honest)

The end-to-end "no run fires over a >15-min window" measurement needs a real user systemd session and
is skipped in headless CI (`VIGIL_LIVE_SYSTEMD=1`). The containment *logic* — which `systemctl` verbs
fire, in which order, the stamp reset, and the post-condition verification — is asserted with a fake
`systemctl` + a tmp XDG stamp dir and runs in the required CI leg.

> **Registration:** fold this claim into the claims registry when [W0-3] #398 lands; until then this
> decision record is the source of truth for the claim, exactly as the W5-1 record is for its own.
