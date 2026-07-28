"""
proof.run — the run-integration seam: a Strix report + its executor capture → a persisted proof record.

``build_report_mint`` returns the ``mint(report)`` callback ``proof.sink`` invokes on an allowed report that
carries an executor capture. It reads the report's attached ``_vigil_capture`` (executor-captured exchanges +
raw blobs — NEVER the LLM's free text), builds :class:`evidence.poc.CapturedExchange` objects, mints via
:func:`proof.engine.mint_proof`, and PERSISTS a small proof record under ``<run_dir>/proofs/`` for the Proof
Studio screen to read (as plain JSON — the console reads it with no import of this package, so no
framework→integration dependency).

The capture is attached ONLY by the trusted capture path (never the model), so its mere presence is what makes
a report mint-eligible. ``_vigil_capture`` shape::

    {"exchanges": [{"channel": "request_payload", "role": "q", "request_bytes_ref": "req"}, ...],
     "blobs": {"req": b"' OR '1'='1"}}          # ref -> raw bytes (the non-LLM channel a FACT rests on)

FATAL-2: ``framework`` (``CapturedExchange``) is imported LAZILY inside the callback; the module scope pulls
only ``proof.engine``/``proof.sink`` (import-clean). Determinism: the proof-record id is a content address
(no wallclock/rng).
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Callable, Optional

from .engine import mint_proof
from .sink import CAPTURE_KEY

PROOFS_SUBDIR = "proofs"
REVERIFIABLE_NAME = "reverifiable.json"


def _proofs_dir(run_dir: str | os.PathLike) -> Path:
    d = Path(run_dir) / PROOFS_SUBDIR
    d.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(d, 0o700)
    except OSError:
        pass
    return d


def read_proofs(run_dir: str | os.PathLike) -> list[dict]:
    """Every persisted proof record for a run (plain JSON). Total on a missing dir / bad file."""
    d = Path(run_dir) / PROOFS_SUBDIR
    if not d.is_dir():
        return []
    out: list[dict] = []
    for f in sorted(d.glob("*.json")):
        if f.name == REVERIFIABLE_NAME:      # the C1 re-verifiable report is a sibling, not a proof record
            continue
        try:
            rec = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(rec, dict):
            out.append(rec)
    return out


# A minimal, honest map from a Strix finding's own taxonomy (title / CWE / class) onto the oracle's bug_class
# vocabulary. It only picks WHICH oracle to TRY — the oracle still judges the captured bytes, so a wrong hint
# simply fails to fire (→ an honest LEAD), never fabricates a FACT. The auto-capture channel is response-side
# error-signature (proof_capture), whose oracle is error-based injection, so those are the classes worth
# hinting; an unrecognised finding keeps its raw class and stays a LEAD.
def _oracle_bug_class(report: dict) -> str:
    explicit = str(report.get("bug_class") or "").strip()
    if explicit:
        return explicit
    hay = " ".join(str(report.get(k) or "") for k in ("cwe", "title", "finding_class", "description")).lower()
    if "cwe-89" in hay or "sql injection" in hay or "sqli" in hay:
        return "error_based_sqli"
    if "cwe-90" in hay or "ldap injection" in hay:
        return "error_based_sqli"          # the error-signature oracle scans generic datastore/parser errors
    if "cwe-91" in hay or "xpath injection" in hay:
        return "error_based_sqli"
    return str(report.get("finding_class") or "").strip()


def _finding_from_report(report: dict) -> dict:
    return {
        "check_id": report.get("id") or report.get("check_id") or report.get("finding_slug") or "finding",
        "bug_class": _oracle_bug_class(report),
        "insertion_point": report.get("insertion_point") or report.get("param") or report.get("endpoint") or "",
        "poc_script_code": report.get("poc_script_code"),
        "evidence": report.get("evidence"),
        "poc_description": report.get("poc_description"),
    }


def _persist_record(run_dir: str | os.PathLike, res: Any, finding: dict, capture: dict) -> dict:
    """Write a small, deterministic proof record for the Proof Studio screen. The id is a content address of
    the finding identity (no wallclock), so re-minting the same finding overwrites the same record."""
    pid = hashlib.sha256(
        f"{res.finding_ref}:{res.bug_class}:{res.confirmed_by}".encode("utf-8")
    ).hexdigest()[:24]
    rec = {
        "proof_id": pid,
        "finding_ref": res.finding_ref,
        "bug_class": res.bug_class or finding.get("bug_class", ""),
        "status": res.status,                       # "fact" | "lead" | "denied"
        "reason": res.reason,
        "confirmed_by": res.confirmed_by,
        "confidence": res.confidence,
        "reproduced": res.reproduced,
        "gate_category": res.gate_category,
        "spooled": bool(res.envelope_path),
        "exchanges": [{"channel": str(e.get("channel", "")), "role": str(e.get("role", ""))}
                      for e in (capture.get("exchanges") or [])],
        "poc_present": bool(finding.get("poc_script_code")),
    }
    (_proofs_dir(run_dir) / f"{pid}.json").write_text(json.dumps(rec, sort_keys=True), encoding="utf-8")
    return rec


def read_reverifiable(run_dir: str | os.PathLike) -> dict:
    """The run's re-verifiable proof report ({"active_findings": [...]}) — each entry a proven FACT with its
    ``oracle_context`` + ``action_id``, the material ``vigil proof-export`` builds a client bundle from. An
    empty ``active_findings`` doc on a missing/unreadable file (never raises)."""
    path = Path(run_dir) / PROOFS_SUBDIR / REVERIFIABLE_NAME
    if not path.is_file():
        return {"active_findings": []}
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"active_findings": []}
    findings = doc.get("active_findings") if isinstance(doc, dict) else None
    return {"active_findings": findings if isinstance(findings, list) else []}


def _persist_reverifiable(run_dir: str | os.PathLike, finding: dict, action_id: str,
                          exchanges: Any, resolve: Any, res: Any) -> None:
    """Append (dedup by check_id) a re-verifiable finding — the SAME plain-dict oracle_context shape a
    scan's reverifiable.json carries, so ``framework.v2 evidence verify`` re-fires it byte-identically. The
    finding's top-level ``bug_class`` mirrors the class embedded in the context (reverify refuses a flip)."""
    from framework.v2.verify.poc_translate import context_from_exchanges     # lazy — FATAL-2

    ctx = context_from_exchanges(exchanges, bug_class=str(finding.get("bug_class") or ""), resolve=resolve)
    if ctx is None:
        return
    embedded_class = str(getattr(ctx, "bug_class", "") or finding.get("bug_class") or "")
    entry = {
        "check_id": finding["check_id"],
        "bug_class": embedded_class,
        "insertion_point": finding.get("insertion_point", ""),
        "confirmed_by": res.confirmed_by,
        "confidence": res.confidence,
        "action_id": action_id,
        "oracle_context": ctx.model_dump(mode="json"),
    }
    doc = read_reverifiable(run_dir)
    findings = [f for f in doc["active_findings"] if f.get("check_id") != entry["check_id"]]
    findings.append(entry)
    findings.sort(key=lambda f: str(f.get("check_id")))
    path = _proofs_dir(run_dir) / REVERIFIABLE_NAME
    path.write_text(json.dumps({"active_findings": findings}, sort_keys=True), encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def build_report_mint(
    *,
    run_dir: str | os.PathLike,
    signers: "list[tuple[str, str]]",
    engagement_slug: str,
    evidence_root: Optional[str | os.PathLike] = None,
    spool_dir: Optional[str | os.PathLike] = None,
    quarantine_dir: Optional[str] = None,
) -> Callable[[dict], Any]:
    """Return the ``mint(report)`` callback for ``proof.sink``. It mints ONLY from the report's attached
    executor capture (``_vigil_capture``), persists a proof record, and returns the ``MintResult`` (or
    ``None`` if the capture is unusable — the finding then stays a plain Strix report / LEAD)."""

    def mint(report: dict) -> Any:
        from framework.v2.evidence.poc import CapturedExchange     # lazy — FATAL-2

        capture = report.get(CAPTURE_KEY) or {}
        ex_dicts = capture.get("exchanges") or []
        blobs = capture.get("blobs") or {}
        if not ex_dicts:
            return None
        try:
            exchanges = [CapturedExchange(**{k: v for k, v in ex.items() if k != "blob"}) for ex in ex_dicts]
        except Exception:  # noqa: BLE001 — a malformed/hostile capture drops the mint (stays a LEAD), never raises
            return None

        def _resolve(ref: str) -> "bytes | None":
            b = blobs.get(ref)
            if isinstance(b, (bytes, bytearray)):
                return bytes(b)
            if isinstance(b, str):
                return b.encode("utf-8")
            return None

        finding = _finding_from_report(report)
        action_id = "poc-" + hashlib.sha256(str(finding["check_id"]).encode("utf-8")).hexdigest()[:16]
        # Default the evidence root to <run_dir>/evidence so every FACT MATERIALISES its executor-captured
        # raw bytes into a cert-manifestable tree — that is what makes the exported proof bundle (C1)
        # artifact-integrity-checkable offline. An explicit evidence_root still wins.
        ev_root = str(evidence_root) if evidence_root else str(Path(run_dir) / "evidence")
        res = mint_proof(
            finding=finding, exchanges=exchanges, resolve=_resolve,
            engagement_slug=engagement_slug, signers=signers,
            evidence_root=ev_root, action_id=action_id,
            spool_dir=(str(spool_dir) if spool_dir else None),
            quarantine_dir=quarantine_dir,
        )
        _persist_record(run_dir, res, finding, capture)
        if getattr(res, "is_fact", False):
            # Retain the re-verifiable material (the oracle_context + action_id) so `vigil proof-export` can
            # rebuild a client-verifiable bundle later. Best-effort: a serialization hiccup never un-mints.
            try:
                _persist_reverifiable(run_dir, finding, action_id, exchanges, _resolve, res)
            except Exception:  # noqa: BLE001
                pass
        return res

    return mint
