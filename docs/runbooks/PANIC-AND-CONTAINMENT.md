# Runbook — `vigil down` (containment) and `vigil panic` (hard-stop)

Owner-run, authorized-target framework. This runbook covers the two emergency controls added by
**W10-5 (#477)** and completed for the cadence sidecars by **W10-5b (#478)**. It is true of the code
in `integration/vigil_integration/{cli.py,uiproxy.py}`, `infra/systemd/vigil-command.service`, and the
sidecar units under `infra/systemd/`.

## TL;DR — which verb, when

| Situation | Verb | What it stops |
|---|---|---|
| Free the port / restart the UI cleanly | `vigil down` | the `vigil-command` unit **only** — backups/reprove/HA timers keep running |
| **Incident — stop everything now** | `vigil panic` | every engagement's gate **plus** the command unit **plus every cadence sidecar timer & unit** (with no catch-up replay), then **verifies** it held |

If in doubt during an incident, run `vigil panic` — it is the whole-surface hard-stop.

## Why these exist

`vigil up` is normally kept alive by the **`vigil-command.service` systemd *user* unit**, which sets
`Restart=always` / `RestartSec=5`. Before W10-5, `vigil down` only killed the tracked backend pids —
so systemd saw the orchestrator (the unit's `MainPID`) exit and **restored the whole stack in ~5 s**.
A pid-kill was therefore *not* containment. (The unit's `StartLimitIntervalSec`/`StartLimitBurst` also
sat in `[Service]`, where **systemd ignores them**, so the crash-loop burst cap never engaged. Both are
now in `[Unit]`.)

But the command unit is only ONE of the units VIGIL ships. The **cadence sidecars** keep acting during
an incident even after the command unit is down:

| Timer | Cadence | What it does during an incident |
|---|---|---|
| `vigil-reprove.timer` | every 6 h | **RE-FIRES the retained corpus AGAINST THE LIVE TARGET** |
| `vigil-posture.timer` | 30 min | **RE-SCANS the authorized target** |
| `vigil-ha-mirror.timer` | **15 min** | rsyncs `~/.sigil` **OFF-HOST** (the shortest interval) |
| `vigil-backup-push.timer` | daily | pushes an encrypted backup **OFF-HOST** |
| `vigil-backup.timer` | daily | local two-plane backup |
| `vigil-backup-drill.timer` | weekly | local restore drill |
| `vigil-integrity.timer` | 15 min | local read-only spine verify |

Every one carries `Persistent=true`, so simply disabling a timer is **not** enough: on a later
re-enable systemd fires *every run missed while it was down* — a catch-up burst straight back at the
target or the off-host store. The witness co-sign instances (`vigil-witness@<port>.service`) carry
`Restart=on-failure`. So before W10-5b, an operator who ran `vigil down` (or even masked the command
unit) believing they were contained was **still sending traffic to the target and replicating data
off-host**.

## `vigil down` — CONTAIN the interface (command unit only)

```bash
vigil down            # from the offense venv (.venv-offense/bin/vigil)
```

What it does, in order (`uiproxy.run_down` → `_contain_service_unit` then `_kill_tracked_pids`):

1. **Contain the command unit** (`systemctl --user`, subprocess only — no framework import):
   - `disable` the unit → the next boot does **not** restore it.
   - a **clean** `systemctl --user stop` → unlike a raw kill, a clean stop does **not** trigger
     `Restart=`, so the stack stays down.
   - Recursion-safe: when `vigil down` runs as the unit's own `ExecStop` (systemd sets
     `$SERVICE_RESULT` there), it skips the stop — systemd is already stopping it.
   - No-op when `vigil up` was started **by hand** (no unit) or there is no user manager.
2. **Kill the tracked pids** in `.vigil-live/ui/pids` (SIGTERM → 5 s grace → SIGKILL). Under a managed
   unit this is mop-up (the stop already took them via `KillMode=control-group`); started-by-hand it is
   the whole containment.

`vigil down` **deliberately leaves the cadence sidecars alone** — it is the routine "stop the interface"
verb, and disabling an operator's backups/HA on a routine restart would be wrong. Use `vigil panic` to
contain the sidecars.

**Verify it stayed down** (the negative control):

```bash
vigil down
sleep 30
systemctl --user is-active vigil-command.service    # -> inactive  (NOT active/activating)
```

**Bring it back:**

```bash
systemctl --user enable --now vigil-command.service
```

## `vigil panic` — emergency HARD-STOP (whole surface)

```bash
vigil panic                       # optional: --reason "why"
```

Stricter than `down`. `_cmd_panic` runs in order:

1. **Trip every engagement's kill-switch** (`_trip_all_killswitches`): the persistent, fail-closed
   kill-switch is tripped for every slug in the offense authority dir. Any in-flight **or
   later-launched** gated offense action is then DENIED at the gate — across process restarts, even for
   a process `panic` does not track. This runs **first**, so a racing engagement is refused before any
   pid is killed.
2. **Contain the whole surface** (`uiproxy.run_panic`):
   1. **Command unit** — same containment as `down` but the unit is additionally **masked**
      (`systemctl --user mask`): even a manual `systemctl start` is refused until it is unmasked.
   2. **Every cadence sidecar** (`_contain_sidecar_units`), in this documented order — the timers that
      reach the target or push data off-host **first**: `vigil-reprove` → `vigil-posture` →
      `vigil-ha-mirror` → `vigil-backup-push` → `vigil-backup` → `vigil-backup-drill` →
      `vigil-integrity`. For each timer: **stop** it, **disable** it (no boot restore), then **reset
      its `Persistent=` catch-up stamp** (`$XDG_DATA_HOME/systemd/timers/stamp-<timer>` touched to
      *now*) so a re-enable does **not** replay the missed runs. Then **stop + disable each paired
      oneshot service** (to interrupt a run already in flight — stopping a *timer* does not stop a
      running oneshot). Then **stop + disable every live `vigil-witness@<port>` instance**
      (`Restart=on-failure`).
   3. **Kill the tracked pids** (as `down`).
   4. **Verify containment held** (`_verify_sidecar_containment`): re-query `is-active` / `is-enabled`
      for every timer, service and witness instance. A clean pass prints
      `containment verified (nothing active or enabled)`; any leak is printed to **stderr** with a
      `do NOT assume the system is contained` warning so a partial containment is never silently
      assumed.

Every step is best-effort and idempotent — one stubborn unit's failure is reported and never aborts the
rest, because a hard-stop must not be blockable.

**Recover from a panic** (each step is a deliberate operator act, by design):

```bash
# 1. clear each engagement's kill-switch when it is safe (a logged, intentional act)
#    the kill-switch file lives at <CRUCIBLE_ROOT>/framework/v2/.authority/<slug>.halt
# 2. allow the command unit to run again
systemctl --user unmask vigil-command.service
systemctl --user enable --now vigil-command.service
# 3. re-enable ONLY the cadence timers you still want (they were disabled, not masked). Because panic
#    reset each timer's Persistent= stamp, re-enabling schedules the NEXT run — it does NOT replay the
#    runs missed during the incident:
systemctl --user enable --now vigil-reprove.timer vigil-posture.timer vigil-ha-mirror.timer \
                               vigil-backup-push.timer vigil-backup.timer vigil-backup-drill.timer \
                               vigil-integrity.timer
# ... and any witness instances:  systemctl --user enable --now vigil-witness@8801
systemctl --user list-timers 'vigil-*'    # confirm the next-run times look sane (no immediate burst)
```

## Drill — exercise the runbook

The containment *logic* (which `systemctl` verbs fire, in which order, the stamp reset, and the
post-condition verification) is asserted with a fake `systemctl` in
`integration/tests/test_panic_sidecars.py` and `integration/tests/test_down_contains.py`, which run in
the required **"integration two-env boundary (P5)"** CI job (they are framework-free, so the whole
`integration/tests/` directory picks them up). This exercises the runbook's commands on every push.

The end-to-end **live systemd** measurements need a real user systemd session and are skipped in
headless CI:

```bash
# 1. command unit stays down 30 s after `vigil down` (defeats Restart=always):
VIGIL_LIVE_SYSTEMD=1 .venv-offense/bin/python -m pytest -q \
  integration/tests/test_down_contains.py::test_down_stays_down_under_live_systemd
# 2. a Persistent sidecar timer fires NO further run over a window longer than its interval after panic
#    (the AC's "measured, not assumed" negative control — real timer, real wait):
VIGIL_LIVE_SYSTEMD=1 .venv-offense/bin/python -m pytest -q \
  integration/tests/test_panic_sidecars.py::test_sidecar_stays_down_under_live_systemd
```

Run these on a host with a real user systemd session (e.g. a login session with linger enabled) as a
recorded drill before relying on the controls in production.

## Live-only residual (honest)

The "no run fires over a >15-min window" measurement is a live-only assertion (real systemd, real
wait) and is skipped in headless CI behind `VIGIL_LIVE_SYSTEMD=1`. In the hermetic path the same
property is proven by construction: after `_contain_sidecar_units`, `_verify_sidecar_containment`
reports every timer/service/witness as inactive **and** disabled, and each timer's `Persistent=` stamp
sits at ~now (so a re-enable cannot replay). The claim is registered in
`docs/decisions/W10-5b-panic-disables-sidecars.md` (to be folded into the claims registry, [W0-3]
#398).
