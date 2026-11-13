# Runbook — snapshot schema bumps and rolling a build back safely

Operator runbook for the sovereign spine's versioned artifacts. Read it before upgrading, and **before**
you downgrade a build.

## What a snapshot schema bump means

The spine's folded state is persisted as a snapshot. The snapshot carries a schema version, and each build
knows the highest one it can read. That limit is `_MAX_SNAPSHOT_SCHEMA` in
[`apps/sigil/sigil/spine/snapshot.py`](../../apps/sigil/sigil/spine/snapshot.py). When a build adds state
to the fold (for example a new governor table), it raises this number and writes snapshots at the new
version.

A bump is a **one-way door for data**. Once a newer build has written a vN+1 snapshot, older builds can no
longer read that `SIGIL_HOME`.

### Recorded bumps

| Version | Adds | Rollback past it |
|---|---|---|
| v10 | `trial_claim_row` (governor.trial_claim: first-wins trial claims per canonical mailbox / registrable domain) and `report_unlock_billing` / `report_unlock_owner` (governor.report_unlock) | A v9 build refuses a v10 `SIGIL_HOME` (`SchemaTooNew`). Restore a pre-upgrade backup, or stay on v10. |

Earlier versions are described inline at `_MAX_SNAPSHOT_SCHEMA`.

## Refuse-newer behaviour (fail closed)

All versioned spine artifacts go through the shared gate in
[`apps/sigil/sigil/spine/schema_guard.py`](../../apps/sigil/sigil/spine/schema_guard.py). That covers the
signed head (`checkpoint.py`), the segment manifest, the snapshot, the anti-rollback floor (`floor.py`), the
witness envelope/roster, the kernel manifest, and the encrypted backup (`backup.py`). If an artifact's
version is newer than the build understands, the build raises `SchemaTooNew` ("upgrade sigil") and
**refuses to load it**. It never treats that data as clean.

Why: if a vN+1 snapshot were read as vN, the missing fields would quietly get empty defaults. That would
reset replay high-water marks, and a captured owner-signed grant could then be replayed.

The data directories use the same rule. `vigil_core.install_manifest`
([`packages/core/vigil_core/vigil_core/install_manifest.py`](../../packages/core/vigil_core/vigil_core/install_manifest.py))
plus [`integration/vigil_integration/install_gate.py`](../../integration/vigil_integration/install_gate.py)
refuse to operate on a directory that a newer build wrote. In that state only recovery verbs still run:
`doctor`, `backup`, `restore`, `upgrade`, `panic`, `emergency-stop`, and so on.

## Rolling a build back safely

There is **no in-place down-migration**. The supported rollback is to restore a backup taken *before* the
upgrade:

1. Stop everything that writes to the home (`vigil panic` / `vigil emergency-stop` if engagements are live).
2. Before any upgrade, `sigil upgrade --check` reports whether a migration is needed, without changing
   anything (exit 3 = needed). `sigil upgrade` runs backup → verify → migrate → verify, and **rolls back
   on any failure**. Only use `--no-backup` on a disposable store.
3. To return to the older build after a successful upgrade, install the older build and then
   `sigil restore <pre-upgrade-backup> <fresh SIGIL_HOME>` into a **fresh** home. Point the old build at
   that home. Do not point the old build at the upgraded home. It will refuse, and that refusal is the
   intended behaviour, not a bug to work around.
4. Anything written after the upgrade exists only in the upgraded home. Either replay it from upstream or
   accept losing it.

Never hand-edit a schema number to get an old build to load newer data. That is exactly the downgrade the
gate exists to stop.

## Backup / restore

- `sigil backup <dest>` writes a portable, passphrase-encrypted off-box backup of the trust root and spine.
- `sigil restore <src> <home>` verifies the backup before writing anything, and restores only into a fresh
  `SIGIL_HOME` (`--force` exists; read its help first).
- The backup format is gated too (`_MAX_BACKUP_SCHEMA` in `backup.py`). An old build refuses a backup made
  by a newer build. So keep the pre-upgrade backup, made by the old build, until you are sure you will not
  roll back.

See also [RELEASE-UPGRADE-ROLLBACK.md](RELEASE-UPGRADE-ROLLBACK.md).
