"""Local-only telemetry sink (VIGIL sovereign build).

Replaces the upstream `posthog`/`scarf` modules, which POSTed scan/finding/skill events to
`us.i.posthog.com` and `strix.gateway.scarf.sh`. A sovereign, air-gappable security tool MUST NOT phone
home — least of all with offensive activity (the upstream `finding` event carried severity + CWE). This
sink keeps the same event surface (`start`/`finding`/`skill_loaded`/`end`/`error`) but records every event
to the LOCAL logger only; there is no network transport anywhere in this module, by construction. If
aggregate run metrics are wanted they are already captured in the run's local `ReportState`/usage ledger.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from ._common import SESSION_ID, base_props

if TYPE_CHECKING:
    from strix.report.state import ReportState

logger = logging.getLogger("strix.telemetry")


def _record(event: str, properties: dict[str, Any]) -> None:
    """The one sink for every telemetry event: a structured DEBUG log line, local only."""
    logger.debug("telemetry.%s session=%s %s", event, SESSION_ID, {**base_props(), **properties})


def start(**properties: Any) -> None:
    _record("scan_started", properties)


def finding(severity: str, cwe: str | None = None, is_cve: bool = False) -> None:
    _record("finding_reported", {"severity": severity, "cwe": cwe, "is_cve": is_cve})


def skill_loaded(skill_name: str) -> None:
    _record("skill_loaded", {"skill": skill_name})


def end(report_state: "ReportState", exit_reason: str = "completed") -> None:
    # send-once guard (state.py resolves both the finished-by-tool and the main-loop end paths)
    if getattr(report_state, "scan_ended_sent", False):
        return
    report_state.scan_ended_sent = True
    counts = getattr(report_state, "severity_counts", None)
    props: dict[str, Any] = {"exit_reason": exit_reason}
    if callable(counts):
        try:
            props["severity_counts"] = counts()
        except Exception:  # noqa: BLE001 — telemetry must never break a run
            logger.debug("telemetry.end severity_counts failed", exc_info=True)
    _record("scan_ended", props)


def error(error_type: str) -> None:
    _record("error", {"error_type": error_type})
