# Runbook — `vigil down` (containment) and `vigil panic` (hard-stop)

Owner-run, authorized-target framework. This runbook covers the two emergency controls added by
**W10-5 (#477)**. It is true of the code in `integration/vigil_integration/{cli.py,uiproxy.py}` and
`infra/systemd/vigil-command.service`.

## Why these exist

`vigil up` is normally kept alive by the **`vigil-command.service` systemd *user* unit**, which sets
`Restart=always` / `RestartSec=5`. Before this change, `vigil down` only killed the tracked backend
pids — so systemd saw the orchestrator (the unit's `MainPID`) exit and **restored the whole stack in
~5 s**. A pid-kill was therefore *not* containment. (The unit's `StartLimitIntervalSec`/`StartLimitBurst`
also sat in `[Service]`, where **systemd ignores them**, so the crash-loop burst cap never engaged.
Both are now in `[Unit]`.)

## `vigil down` — CONTAIN the stack

```bash
vigil down            # from the offense venv (.venv-offense/bin/vigil)
```

What it does, in order (`uiproxy.run_down` → `_contain_service_unit` then `_kill_tracked_pids`):

1. **Contain the unit** (`systemctl --user`, subprocess only — no framework import):
   - `disable` the unit → the next boot does **not** restore it.
   - a **clean** `systemctl --user stop` → unlike a raw kill, a clean stop does **not** trigger
     `Restart=`, so the stack stays down.
   - Recursion-safe: when `vigil down` runs as the unit's own `ExecStop` (systemd sets
     `$SERVICE_RESULT` there), it skips the stop — systemd is already stopping it.
   - No-op when `vigil up` was started **by hand** (no unit) or there is no user manager.
2. **Kill the tracked pids** in `.vigil-live/ui/pids` (SIGTERM → 5 s grace → SIGKILL). Under a managed
   unit this is mop-up (the stop already took them via `KillMode=control-group`); started-by-hand it is
   the whole containment.

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

## `vigil panic` — emergency HARD-STOP

```bash
vigil panic                       # optional: --reason "why"
```

Stricter than `down`. `_cmd_panic` runs in order:

1. **Trip every engagement's kill-switch** (`_trip_all_killswitches`): the persistent, fail-closed
   kill-switch is tripped for every slug in the offense authority dir. Any in-flight **or
   later-launched** gated offense action is then DENIED at the gate — across process restarts, even for
   a process `panic` does not track. This runs **first**, so a racing engagement is refused before any
   pid is killed.
2. **Mask + stop the unit and kill the pids** (`uiproxy.run_panic`): same containment as `down` but the
   unit is **masked** (`systemctl --user mask`) — even a manual `systemctl start` is refused until it is
   unmasked.

**Recover from a panic** (each step is a deliberate operator act, by design):

```bash
# 1. clear each engagement's kill-switch when it is safe (a logged, intentional act)
#    the kill-switch file lives at <CRUCIBLE_ROOT>/framework/v2/.authority/<slug>.halt
# 2. allow the unit to run again
systemctl --user unmask vigil-command.service
systemctl --user enable --now vigil-command.service
```

## Residual (tracked, not done here)

- **`vigil panic` does not yet disable the sidecar timers/other units** — that is **W10-5b (#478)**.
  The timers can keep acting even when the command unit is down; #478 completes the picture.
- The end-to-end **live systemd** assertion (install the unit, start it, `vigil down`, still down 30 s
  later) is in `integration/tests/test_down_contains.py` behind `VIGIL_LIVE_SYSTEMD=1` — it needs a real
  user systemd session and is skipped in headless CI. The containment *logic* (which `systemctl` verbs
  fire, in which context) is asserted with a fake `run` in the same file, and that runs in CI.
