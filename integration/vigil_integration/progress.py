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

Every write is BEST-EFFORT: a missing env var, an unwritable path, a serialisation error, or an oversized
payload is a silent no-op that returns ``False`` and NEVER raises — surfacing progress must never break a run
or, especially, a WARDEN block. Each line is a single ``os.write`` in ``O_APPEND`` mode; on Linux the kernel
serialises appends to a regular file (the inode lock is held for the write), so a concurrent console-side
``_append_progress`` and this child write land as whole, non-interleaved lines. Oversized payloads are dropped
rather than risk a torn write, and the console tailer already skips any malformed line, so the failure mode is
"a line is missing", never "the feed is corrupt".
"""

from __future__ import annotations

import json
import os
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
        line = json.dumps(dict(event), default=str, ensure_ascii=False, separators=(",", ":"))
        data = (line + "\n").encode("utf-8", "replace")
        if len(data) > _MAX_BYTES:
            return False
        path = os.path.join(run_dir, _PROGRESS_FILE)
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            os.write(fd, data)
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
