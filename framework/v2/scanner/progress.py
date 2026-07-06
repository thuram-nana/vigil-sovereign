"""
scanner.progress — an OPT-IN, no-op-by-default progress sink for live views.

The scan campaign is silent during a run (findings live only in the final
`ScanReport`). To let a decoupled UI show phase/finding progress *without touching
the hot path*, `WebScanCampaign` accepts an optional `ProgressSink`:

  * default is `None` → the campaign makes NO calls at all (byte-for-byte the current
    behaviour; zero cost),
  * when a sink IS attached it is invoked only on RARE events — phase boundaries and
    each confirmed finding, never per-request — so even attached it is negligible.

The concrete `JsonlSink` appends one JSON line per event to a file a tailer (the Ops
Console SSE) reads; it is fire-and-forget (any write error is swallowed) so a broken
reader can never perturb a scan. Nothing here imports the console, and the console
never imports the scanner — the coupling is a plain file.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Protocol, runtime_checkable


@runtime_checkable
class ProgressSink(Protocol):
    """What `WebScanCampaign` calls when a sink is attached. All methods are
    best-effort and must never raise into the scan."""

    def phase(self, name: str, **fields: object) -> None: ...
    def finding(self, bug_class: str, confirmed_by: str, param: str, endpoint: str,
                confidence: float) -> None: ...
    def done(self, findings: int, requests_sent: int, elapsed_s: float) -> None: ...


class JsonlSink:
    """Append-only JSONL progress sink. One event per line
    (`{"event": "scan.<kind>", ...}`), matching the shape the console's SSE tailer
    already understands. Fire-and-forget: a write failure is swallowed so a dead
    reader never affects the scan. A monotonic `seq` orders events without a clock."""

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._seq = 0
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass

    def _emit(self, event: str, **fields: object) -> None:
        self._seq += 1
        rec = {"event": event, "seq": self._seq, **fields}
        try:
            with self._path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False, default=str, separators=(",", ":")) + "\n")
        except OSError:
            pass  # never let a progress write perturb the scan

    def phase(self, name: str, **fields: object) -> None:
        self._emit("scan.phase", phase=name, **fields)

    def finding(self, bug_class: str, confirmed_by: str, param: str, endpoint: str,
                confidence: float) -> None:
        self._emit("scan.finding", bug_class=bug_class, confirmed_by=confirmed_by,
                   param=param, endpoint=endpoint, confidence=round(confidence, 3))

    def done(self, findings: int, requests_sent: int, elapsed_s: float) -> None:
        self._emit("scan.done", findings=findings, requests_sent=requests_sent, elapsed_s=elapsed_s)
