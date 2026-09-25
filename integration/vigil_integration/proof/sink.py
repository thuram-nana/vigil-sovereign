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
from .degradation import MINT_FAILED

# The report key an executor path may attach its captured exchanges under (a list of CapturedExchange plus
# a resolve map). Never populated by the LLM — only by the trusted capture path — so its mere presence is
# what distinguishes a mint-eligible report from a free-text-only one.
CAPTURE_KEY = "_vigil_capture"


def _web_redrivable(report: Any) -> bool:
    """True when this report maps to a web class VIGIL can re-drive for a FACT with its own gated probes —
    so the mint runs even without an attached ``_vigil_capture``. Delegates to ``run._web_redrive_class`` (the
    single source of truth), imported function-locally to break the run⇄sink import cycle. Fail-closed: any
    import/lookup error ⇒ not web-re-drivable (the report simply needs a capture as before)."""
    try:
        from .run import _web_redrive_class  # noqa: PLC0415 — function-local: breaks the run⇄sink cycle
        return _web_redrive_class(report) is not None
    except Exception:  # noqa: BLE001
        return False


def _errsig_redrivable(report: Any) -> bool:
    """True when this report maps to an injection class VIGIL can re-drive for a FACT with its OWN gated
    error-signature probe (error_based_sqli / nosqli / ldap_injection / xpath_injection) — so the mint runs
    even without an attached ``_vigil_capture`` (the W1a runner-owned re-drive is the SOUND primary for a
    Strix injection LEAD). Delegates to ``run._errsig_redrive_class`` (the single source of truth), imported
    function-locally to break the run⇄sink cycle. Fail-closed: any import/lookup error ⇒ not re-drivable."""
    try:
        from .run import _errsig_redrive_class  # noqa: PLC0415 — function-local: breaks the run⇄sink cycle
        return _errsig_redrive_class(report) is not None
    except Exception:  # noqa: BLE001
        return False


def _reflection_redrivable(report: Any) -> bool:
    """True when this report is a reflected-xss class VIGIL can re-drive for a FACT with its OWN gated canary
    probe (W2). Delegates to ``run._reflection_redrive_class`` (single source of truth). Fail-closed."""
    try:
        from .run import _reflection_redrive_class  # noqa: PLC0415 — function-local: breaks the run⇄sink cycle
        return _reflection_redrive_class(report) is not None
    except Exception:  # noqa: BLE001
        return False


def _ssti_redrivable(report: Any) -> bool:
    """True when this report is an SSTI class VIGIL can re-drive for a FACT with its OWN gated expression probe
    (W2). Delegates to ``run._ssti_redrive_class`` (single source of truth). Fail-closed."""
    try:
        from .run import _ssti_redrive_class  # noqa: PLC0415 — function-local: breaks the run⇄sink cycle
        return _ssti_redrive_class(report) is not None
    except Exception:  # noqa: BLE001
        return False


def _boolean_redrivable(report: Any) -> bool:
    """True when this report is a boolean-blind SQLi class VIGIL can re-drive for a FACT with its OWN gated
    true/false probe pairs (W2). Delegates to ``run._boolean_redrive_class`` (single source of truth).
    Fail-closed."""
    try:
        from .run import _boolean_redrive_class  # noqa: PLC0415 — function-local: breaks the run⇄sink cycle
        return _boolean_redrive_class(report) is not None
    except Exception:  # noqa: BLE001
        return False


def _timing_redrivable(report: Any) -> bool:
    """True when this report is a time-based blind SQLi class VIGIL can re-drive for a FACT with its OWN gated
    SLEEP probes (W2). Delegates to ``run._timing_redrive_class`` (single source of truth). Fail-closed."""
    try:
        from .run import _timing_redrive_class  # noqa: PLC0415 — function-local: breaks the run⇄sink cycle
        return _timing_redrive_class(report) is not None
    except Exception:  # noqa: BLE001
        return False


def _dom_xss_redrivable(report: Any) -> bool:
    """True when this report is a DOM-XSS class VIGIL can re-drive for a FACT in its OWN gated headless-browser
    harness (W3, dom_execution oracle). Delegates to ``run._dom_xss_redrive_class`` (single source of truth).
    Fail-closed."""
    try:
        from .run import _dom_xss_redrive_class  # noqa: PLC0415 — function-local: breaks the run⇄sink cycle
        return _dom_xss_redrive_class(report) is not None
    except Exception:  # noqa: BLE001
        return False


def _prototype_pollution_redrivable(report: Any) -> bool:
    """True when this report is a client-side prototype-pollution class VIGIL can re-drive for a FACT in its
    OWN gated headless-browser harness (W3, prototype_pollution oracle). Delegates to
    ``run._prototype_pollution_redrive_class`` (single source of truth). Fail-closed."""
    try:
        from .run import _prototype_pollution_redrive_class  # noqa: PLC0415 — function-local: breaks the cycle
        return _prototype_pollution_redrive_class(report) is not None
    except Exception:  # noqa: BLE001
        return False


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
        run_dir: Optional[str | os.PathLike] = None,
    ) -> None:
        self.quarantine_dir = quarantine_dir
        self._mint = mint
        # The run dir whose proofs/ manifest a degraded verification is recorded against (inv 12). When not
        # supplied the recorder falls back to VIGIL_PROOF_RUN_DIR (what the console exports).
        self.run_dir = run_dir

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

    def _record_degraded(self, kind: str, exc: BaseException) -> None:
        """Record a TYPED proof-degradation cause (inv 12) — never raises. Prefers the sink's own run_dir,
        else the run dir the console exported (VIGIL_PROOF_RUN_DIR)."""
        try:
            from .degradation import record_degradation, record_from_env
            where = "proof.sink.ProofSink"
            if self.run_dir is not None:
                record_degradation(self.run_dir, kind, where=where, detail=type(exc).__name__)
            else:
                record_from_env(kind, where=where, detail=type(exc).__name__)
        except Exception:  # noqa: BLE001 — the recorder must never raise into Strix's persistence path
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
            # Mint when the report carries an executor capture (error-signature bytes), OR when it is a
            # web-re-drivable class (S7), OR an injection class the W1a error-signature re-drive rail owns
            # (error_based_sqli / nosqli / ldap_injection / xpath_injection), OR one of the four W2
            # HTTP-response-derived re-drive classes (reflected xss / ssti / boolean_sqli / time_based_sqli),
            # OR one of the two W3 browser-backed DOM classes (dom_xss / prototype_pollution): every
            # re-drivable class reaches the mint WITHOUT a capture because the VIGIL-owned re-drive crafts its
            # OWN gated traffic (or drives its OWN gated headless browser) against the endpoint (the Strix
            # report is never proof). A mint error (or a re-drive that observed nothing / found the target
            # safe / had no usable browser) leaves the finding a LEAD — never propagates.
            if self._mint is not None and (report.get(CAPTURE_KEY) is not None or _web_redrivable(report)
                                           or _errsig_redrivable(report) or _reflection_redrivable(report)
                                           or _ssti_redrivable(report) or _boolean_redrivable(report)
                                           or _timing_redrivable(report) or _dom_xss_redrivable(report)
                                           or _prototype_pollution_redrivable(report)):
                try:
                    result = self._mint(report)
                    minted = bool(getattr(result, "is_fact", False))
                except Exception as exc:  # noqa: BLE001 — a mint error never breaks Strix; finding stays a LEAD
                    # inv 12 (S9): the mint CRASHED over a captured/re-drivable finding — that finding cannot
                    # reach a FACT (it stays a LEAD) and its absence must not read as "clean". Record the
                    # typed cause so the console distinguishes a crashed mint from a genuinely empty run.
                    minted = False
                    self._record_degraded(MINT_FAILED, exc)
            return SinkResult(gate="allow", finding_ref=ref, minted=minted,
                              reason="content-gate cleared")
        except Exception as exc:  # noqa: BLE001 — the sink must never raise into Strix's persistence path
            return SinkResult(gate="deny", finding_ref="finding", category="sink_error",
                              reason=f"proof sink errored — fail closed ({type(exc).__name__})")
