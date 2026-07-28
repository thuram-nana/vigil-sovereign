"""
proof.sink — the duck-typed hook Strix's reporting path calls, so ``vendor/strix`` stays import-clean (B2).

Strix's ``report.state`` exposes an optional module-level ``proof_sink`` invoked with the finished report
dict just BEFORE the finding is persisted (absent hook ⇒ vendored behaviour byte-identical). This module is
what gets assigned to that variable. It does exactly two things, fail-closed and NEVER raising into Strix:

  1. Screen the report's ``poc_script_code`` (and ``evidence`` / ``poc_description``) through the content
     gate. A DENY is quarantined; the finding stays a plain Strix report (a LEAD in Proof-Studio terms) and
     no proof is minted or replayed.
  2. On ALLOW, if an executor-captured exchange bundle is attached to the report AND a ``mint`` callback is
     wired, invoke it (that is where a FACT can be minted from non-LLM bytes). A Strix report ALONE carries
     only the model's free text — no reproduced bytes — so by itself it can never mint a FACT; the sink
     records the allow and returns.

Import-clean: ``content_gate`` only (stdlib). The mint callback (which lazily reaches ``framework`` via
``proof.engine``) is INJECTED by the wiring layer, never imported here — so importing ``proof.sink`` in the
sovereign env pulls no offense engine (FATAL-2).
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional

from .content_gate import ContentVerdict, screen_poc_content

# The report key an executor path may attach its captured exchanges under (a list of CapturedExchange plus
# a resolve map). Never populated by the LLM — only by the trusted capture path — so its mere presence is
# what distinguishes a mint-eligible report from a free-text-only one.
CAPTURE_KEY = "_vigil_capture"


@dataclass(frozen=True)
class SinkResult:
    """What the sink decided about one report. ``gate`` is ``"allow"``/``"deny"``; ``minted`` is True only
    when an attached capture drove a real mint. Advisory to the caller — Strix persists its own report
    regardless of this result."""

    gate: str
    finding_ref: str
    category: str = ""
    minted: bool = False
    reason: str = ""


class ProofSink:
    """A callable ``proof_sink`` registered into Strix. Construct with a ``quarantine_dir`` (where denied
    content is recorded) and an optional ``mint`` callback ``(report) -> Any`` invoked on an allowed report
    that carries an executor capture. Every path is fail-closed and swallows its own errors — the sink must
    never break Strix's persistence."""

    def __init__(
        self,
        *,
        quarantine_dir: Optional[str | os.PathLike] = None,
        mint: Optional[Callable[[dict], Any]] = None,
    ) -> None:
        self.quarantine_dir = quarantine_dir
        self._mint = mint

    def _finding_ref(self, report: dict) -> str:
        return str(
            report.get("id") or report.get("check_id") or report.get("finding_slug")
            or report.get("title") or "finding"
        )

    def _quarantine(self, finding_ref: str, code: object, verdict: ContentVerdict) -> None:
        if not self.quarantine_dir:
            return
        try:
            qd = Path(self.quarantine_dir)
            qd.mkdir(parents=True, exist_ok=True)
            os.chmod(qd, 0o700)
            stem = hashlib.sha256(f"{finding_ref}:{verdict.category}".encode("utf-8")).hexdigest()[:32]
            body = (
                f"finding_ref: {finding_ref}\n"
                f"category: {verdict.category}\n"
                f"reason: {verdict.reason}\n"
                f"matched: {verdict.matched}\n"
                f"--- refused poc_script_code ---\n"
                f"{code if isinstance(code, str) else type(code).__name__}\n"
            )
            (qd / f"{stem}.txt").write_text(body[: 1 << 20], encoding="utf-8")
        except OSError:
            pass

    def __call__(self, report: Any) -> SinkResult:
        """Screen a report and, on allow + attached capture + wired mint, mint. Never raises."""
        try:
            if not isinstance(report, dict):
                return SinkResult(gate="deny", finding_ref="finding", category="malformed",
                                  reason="report is not a dict (fail-closed)")
            ref = self._finding_ref(report)
            verdict = screen_poc_content(
                report.get("poc_script_code"),
                extra_texts=(report.get("evidence"), report.get("poc_description")),
            )
            if verdict.denied:
                self._quarantine(ref, report.get("poc_script_code"), verdict)
                return SinkResult(gate="deny", finding_ref=ref, category=verdict.category,
                                  reason=verdict.reason)

            minted = False
            if self._mint is not None and report.get(CAPTURE_KEY) is not None:
                try:
                    result = self._mint(report)
                    minted = bool(getattr(result, "is_fact", False))
                except Exception:  # noqa: BLE001 — a mint error never breaks Strix; the finding stays a LEAD
                    minted = False
            return SinkResult(gate="allow", finding_ref=ref, minted=minted,
                              reason="content-gate cleared")
        except Exception as exc:  # noqa: BLE001 — the sink must never raise into Strix's persistence path
            return SinkResult(gate="deny", finding_ref="finding", category="sink_error",
                              reason=f"proof sink errored — fail closed ({type(exc).__name__})")
