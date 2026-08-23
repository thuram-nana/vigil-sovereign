# W7-4 — Verify backup integrity at the destination, and ship a real remote transport

Issue: [#462](https://github.com/thuram-nana/vigil-sovereign/issues/462) ·
Milestone: W7 — BACKUP / DISASTER RECOVERY.
Blocks [W7-3](https://github.com/thuram-nana/vigil-sovereign/issues/461);
related to [W7-6](https://github.com/thuram-nana/vigil-sovereign/issues/464) (signing the top-level MANIFEST
makes destination verification meaningful against a coordinated at-rest rewrite) and
[W8-1](https://github.com/thuram-nana/vigil-sovereign/issues/467) (a verification failure raises an alert).

## The defect

`vigil backup --push <dest>` replicated the encrypted parts + `MANIFEST.json` off-host but **nobody checked
the copy landed intact**, and **only a local-directory transport shipped** (a `shutil.copy2` into a path — no
rsync/scp/S3). "Off-host backup" was a directory copy verified by nothing: a truncated, corrupted, or
tampered remote copy was accepted silently, and the operator learned it was useless only when a restore was
attempted — the worst possible moment.

## The claim (register in the claims registry, [W0-3] #398)

<!-- CLAIM:W7-4 -->
> `vigil backup --push` verifies the pushed copy AT THE DESTINATION — it re-reads the bytes that actually landed on the destination (a remote `sha256sum` over rsync+ssh, or a byte-for-byte read-back) and matches each against the sha256 of exactly what was sent, refusing a truncated, corrupted, or tampered copy fail-closed (non-zero exit); this is not a second local checksum. At least one real remote transport (rsync, over ssh or an rsync daemon) ships and is exercised end to end against the real `rsync` binary.

This claim is TRUE of the code as of W7-4:

- **The destination-side gate is on the transport contract, written once, fail-closed.**
  `tools/backup/transport.Transport.verify(remote_subdir, expected_sha256)` iterates the sent hashes and, for
  each, calls `Transport.remote_sha256(...)` — the backend's read-back of the **destination's own bytes** —
  and raises `TransportError` naming every file that is missing, truncated, corrupted, or altered. A backend
  cannot opt out: `verify` lives on the base class over the single `remote_sha256` readback each backend
  implements. The `expected_sha256` map is the sha256 of exactly the local parts that were sent, so the check
  compares *destination bytes* against *what was sent*, not the source against itself.
- **Two real backends provide `remote_sha256`.**
  * `LocalDirectoryTransport.remote_sha256` re-opens `<root>/<subdir>/<name>` and hashes the bytes on disk
    (used against a mounted remote FS / sshfs / removable disk, and in tests).
  * `RsyncTransport` is a **real remote transport** (not a stub) over the `rsync` binary — `rsync://…` daemon
    URLs, `[user@]host:path` ssh specs, and local/mounted paths. `push` shells out to real
    `rsync -a --mkpath`. `remote_sha256` is destination-side in the strongest form over ssh: it runs
    `sha256sum` **on the remote host** (the remote hashes its own stored bytes); for a daemon / local target
    it reads the landed copy back with `rsync` and hashes the bytes it actually receives.
- **The CLI wires push → verify, fail-closed.** `vigil_integration.cli._cmd_backup` runs `transport.push(...)`
  then `transport.verify(subdir.name, {part.name: sha256(part)})`; a `TransportError` from either prints a
  distinct message and returns exit **1**, leaving the (good) local backup untouched. A non-zero exit is what
  the `vigil-backup-push.service` `ExecStopPost=vigil unit-heartbeat` records, so a verification failure
  becomes a [W8-1] `unit-failed` alert.
- **The factory routes the real transport.** `get_transport` resolves `rsync://…` and `rsync:<spec>` to
  `RsyncTransport`, a bare path / `local:` to the local backend, and still errors clearly on the unbuilt
  `scp://` / `s3://` schemes (an honest residual, never a silent no-op).

## Tests (required job: `integration two-env boundary (P5)`)

`integration/tests/test_backup_push_transport.py` (offense leg — it `importorskip`s `framework` and is in the
job's offense-process list, so it runs where `framework` imports):

- `test_local_verify_catches_a_TRUNCATED_destination_copy`, `…_TAMPERED_…` (a same-length byte flip a
  byte-count check would miss), `…_MISSING_…` — negative controls proving the gate is not a no-op.
- `test_rsync_transport_roundtrips_via_the_real_binary` — a real transport round-trips (real `rsync`), and its
  destination read-back verifies; `test_rsync_verify_catches_a_tampered_destination_copy` — negative control
  over the real rsync backend; `test_rsync_over_ssh_remote_sha256_and_negative_control` — the remote
  `sha256sum` path, exercised for real via a fake-ssh wrapper that runs `sha256sum` locally.
- `test_cli_push_FAILS_CLOSED_when_the_destination_is_corrupted` — the **test that fails without this change**:
  a transport that truncates on landing makes `vigil backup --push` exit **1** (observed exit **0** on the
  pre-fix tree — the corrupt copy was silently accepted). `test_cli_push_reports_destination_verified_on_a_clean_push`
  is the positive companion.

## Honest residual

A real off-host rsync-over-ssh / daemon target needs the operator's endpoint + credentials (an ssh key or an
rsyncd secret) and a Linux remote that provides `sha256sum`. The transport, its push, and its destination
verification are real and tested end to end against the real `rsync` binary; only the network endpoint is
operator-supplied. `scp://` and `s3://` remain deliberately unbuilt and error with the contract to implement.
