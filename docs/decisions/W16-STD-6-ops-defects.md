# W16-STD-6 — ops defects: log rotation, per-engagement scoping, CWD-independent live dir, SQLite integrity, uninstall

Five operational defects from §11 of the limitations inventory, each fixed with a test that fails on a tree
without the fix plus a negative control.

## (a) The engagement log rotates with retention — it never silently discards history

The engagement log used to rotate to a single `.1` backup, so a second rotation overwrote it and history
past ~2x the cap was lost with no record. It now rotates through a numbered backup ring and prunes only past
an explicit, documented retention window.

<!-- CLAIM:W16-STD-6a -->
Claim: The engagement log rotates through a numbered backup ring and retains history up to an explicit retention window, rather than discarding it in place.

Enforced by `_rotate_with_retention` in `engine/crucible/framework/v2/common/logging.py`; retention is
`_LOG_BACKUP_COUNT` backups (env-overridable via `VIGIL_LOG_BACKUP_COUNT`), bounding disk to
`~(_LOG_BACKUP_COUNT + 1) * _LOG_MAX_BYTES`.

## (b) Concurrent engagements do not cross-log

The bound engagement slug used to be a module-level global, so two engagements running concurrently in one
process cross-logged into whichever bound last. It is now a `ContextVar`, isolated per thread/task; a fresh
context defaults to the ambient process log.

<!-- CLAIM:W16-STD-6b -->
Claim: The bound engagement slug is held per execution context, so two concurrent engagements in one process write to separate log files instead of cross-logging.

Enforced by `bind_engagement` in `engine/crucible/framework/v2/common/logging.py`.

## (c) VIGIL_LIVE_DIR resolves to an absolute, CWD-independent path

The default `.vigil-live` used to be resolved against the process CWD, so `vigil` run from another directory
silently used a different store than the running engagement. The default is now anchored to the CRUCIBLE root
(CWD-independent); an explicit base or env value is absolutized once at read time.

<!-- CLAIM:W16-STD-6c -->
Claim: The default live directory resolves to an absolute path anchored to the CRUCIBLE root, so it is the same store regardless of the current working directory.

Enforced by `resolve_live_dir` in `integration/vigil_integration/live/instructions.py`.

## (d) SQLite corruption is detected at open

The blackboard store had no corruption detection, so a torn store surfaced later as a raw
`sqlite3.DatabaseError` traceback. It now runs `PRAGMA integrity_check` at open and raises a clear
`BlackboardError`.

<!-- CLAIM:W16-STD-6d -->
Claim: The blackboard SQLite store runs an integrity check on open and raises a clear error when the store is corrupt or not a database.

Enforced by `Blackboard._integrity_check` in `engine/crucible/framework/v2/agents/blackboard.py`.

## (e) Uninstall path

`uninstall.sh` is the inverse of `bootstrap.sh`: it removes the `~/.local/bin` launchers, the `~/.sigil/venv`
symlink and the user systemd units bootstrap installed (only when they point back into this repo), leaves the
repo, venvs, secrets and `.vigil-live` engagement data in place, and prints exactly what it leaves. It is
proved by `integration/tests/test_uninstall_script.py`. (Not registered as a machine-checked claim: its
enforcer is a shell script, which the claims registry — an AST symbol resolver over `.py` files — cannot
express.)
