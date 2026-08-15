"""progress — a stdlib-only, boundary-clean bridge that surfaces offense-child activity to the console's
live process box (W6c).

The console SSE endpoint ``/api/events?run=<run_id>`` tails ``<run_dir>/progress.jsonl`` — one JSON object
per line (see ``console/sse.py`` / ``console/actions.py:_append_progress``). A child the console spawned is
handed that run dir as ``$VIGIL_PROOF_RUN_DIR`` (``console/actions.py``). This module lets code running
INSIDE the offense child — the WARDEN gate (``warden_gate.py``) and the vendored Strix coordinator
(``strix/core/agents.py``) — append a compact progress line to that file so the operator's process box can
show WHAT the child is doing and WHY a call was blocked.

Two-env clean by construction: it imports ONLY the stdlib, so importing it from ``warden_gate.py`` keeps that
module ``framework``/``strix``/SDK-free (``integration/tests/test_two_env_boundary.py``), and the Strix side
imports it lazily+guarded so a bare vendored checkout with no ``vigil_integration`` on the path stays
byte-identical at runtime. It needs ZERO server changes — the existing ``/api/events`` tailer surfaces it.

Every write is BEST-EFFORT and, critically, NEVER BLOCKS: a missing env var, an unwritable path, a symlink or
hardlink, a non-regular file (FIFO/device/socket), a serialisation error, or an oversized payload is a silent
no-op that returns ``False`` and never raises — surfacing progress must never break a run or, especially,
delay a WARDEN block (the gate emits BEFORE it raises, so a blocking write here would hang the refusal
itself).

Appends go to a regular file opened ``O_APPEND|O_NONBLOCK|O_NOFOLLOW`` (+ an ``fstat`` ``S_ISREG``/``st_nlink``
check, since a reader-attached FIFO opens fine and a hardlink is a real regular file). On Linux the kernel
serialises appends to a regular file — the inode lock is held across the write — so a concurrent console-side
``_append_progress`` and this child write land as whole, non-interleaved lines.

Scope of the durability claim, stated honestly: oversized payloads are dropped rather than risk a torn write,
and short writes are looped to completion, so in normal operation an event is either fully written or not
written at all. If the filesystem errors PART-WAY through a line (ENOSPC/EFBIG/EIO), the partial bytes are
already on disk; we then best-effort append a newline so the damage is bounded to that one malformed line,
which the console tailer skips. Under a hard cap even that terminator can fail — in which case the next append
merges into the partial line and both events are lost. So: normally "an event is missing"; under a mid-line
write error, "one or two lines are lost" — never a wedged run, and never a blocked WARDEN refusal.
``O_NOFOLLOW`` guards the FINAL path component only; a symlinked parent *directory* is not defended here (the
run dir is created by the console, not by this writer).
"""

from __future__ import annotations

import json
import os
import stat
from collections.abc import Mapping
from typing import Any

_RUN_DIR_ENV = "VIGIL_PROOF_RUN_DIR"
_PROGRESS_FILE = "progress.jsonl"
_MAX_BYTES = 16384  # drop an oversized payload rather than write a line big enough to risk a torn append


def append_progress(event: Mapping[str, Any], *, run_dir_env: str = _RUN_DIR_ENV) -> bool:
    """Append one JSON-object ``event`` line to ``$<run_dir_env>/progress.jsonl`` for the console's live
    process box. Returns ``True`` iff a line was written; ``False`` — never raising — on any missing-env /
    non-mapping / encode / oversize / IO failure. Best-effort by contract: a progress write must never break
    the run that produced the event."""
    try:
        run_dir = os.environ.get(run_dir_env)
        if not run_dir or not isinstance(event, Mapping):
            return False
        # ensure_ascii=True: escape U+2028/U+2029/U+0085 too. They are NOT newlines to str.split("\n")
        # (what the console SSE tailer uses) but ARE line terminators to str.splitlines() (what some
        # readers use), so leaving them raw would make "one event = one line" depend on the reader.
        line = json.dumps(dict(event), default=str, ensure_ascii=True, separators=(",", ":"))
        data = (line + "\n").encode("utf-8", "replace")
        if len(data) > _MAX_BYTES:
            return False
        path = os.path.join(run_dir, _PROGRESS_FILE)
        # O_NONBLOCK: never BLOCK on open. Without it, a FIFO planted at this path wedges the caller
        # forever — and because the WARDEN gate emits BEFORE it raises, that would hang the gate and the
        # refusal would never fire. A non-blocking open of a readerless FIFO fails (ENXIO) instead.
        # O_NOFOLLOW: never follow a symlink here, so this path can't redirect the child's appends
        # elsewhere (the existing reader in report/runinfo.py already refuses a symlinked progress file).
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NONBLOCK | os.O_NOFOLLOW, 0o600)
        try:
            st = os.fstat(fd)
            # Belt-and-braces AFTER the flags, because the flags do not cover every case:
            #  * a FIFO with a reader ALREADY attached opens fine under O_NONBLOCK — S_ISREG is the only
            #    thing that stops it (and stops a device/socket too);
            #  * O_NOFOLLOW rejects a symlink at the final component, but a HARDLINK planted here is a
            #    real regular file — st_nlink != 1 refuses it, so these appends can't be redirected into
            #    a second name for the same inode.
            if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
                return False
            # Write the WHOLE line: a short write would truncate this event AND merge it with the next
            # append into one malformed line — losing two events instead of just this one.
            mv = memoryview(data)
            wrote = 0
            try:
                while mv:
                    n = os.write(fd, mv)
                    if n <= 0:
                        return False
                    wrote += n
                    mv = mv[n:]
            except OSError:
                # ENOSPC / EFBIG / EIO part-way through: those bytes are already in the file. Terminate
                # them with a newline so the NEXT append starts a fresh line and the tailer skips exactly
                # one malformed line instead of silently swallowing the event that follows. Best-effort:
                # under a hard cap even this 1-byte write fails, which is why the docstring scopes the
                # guarantee rather than asserting it absolutely.
                if wrote:
                    try:
                        os.write(fd, b"\n")
                    except OSError:
                        pass
                return False
        finally:
            os.close(fd)
        return True
    except Exception:  # noqa: BLE001 — progress is best-effort; a feed failure must never break the run
        return False


def strix_graph_event(snap: "Mapping[str, Any] | None") -> "dict[str, Any] | None":
    """Build the compact ``strix.graph`` progress event from a Strix coordinator snapshot (its
    ``{"statuses": {agent_id: state}}`` map). Returns ``None`` for an empty/None/non-mapping snapshot.
    Emits only a status HISTOGRAM (counts by state) and the agent COUNT — never agent ids, names, or
    metadata — so nothing sensitive rides the console feed. Never raises (any error → ``None``)."""
    try:
        if not snap or not isinstance(snap, Mapping):
            return None
        statuses = snap.get("statuses") or {}
        if not isinstance(statuses, Mapping):
            return None
        counts: dict[str, int] = {}
        for st in statuses.values():
            counts[str(st)] = counts.get(str(st), 0) + 1
        return {"event": "strix.graph", "agents": len(statuses), "statuses": counts}
    except Exception:  # noqa: BLE001 — telemetry helper is best-effort
        return None
