"""
proof.engine — the deterministic reproduce-from-raw mint (Proof Studio B3, crypto-grade).

This is the module that turns a Strix PoC into an oracle-confirmed, signed, replayable, offline-verifiable
FACT — or, honestly, a labelled LEAD. It is the "reproduce-from-raw" follow-up the live oracle seam flagged
(``live/wiring.py`` ``_build_oracle``): where that seam passes the model's OWN ``extracted_info`` context
with ``provenance="llm"`` (always a LEAD), this seam builds the ``oracle_context`` ONLY from
EXECUTOR-captured, non-LLM bytes (:class:`evidence.poc.CapturedExchange` via
:func:`verify.poc_translate.context_from_exchanges`) and passes ``provenance="reproduced"``.

The mint enforces, in order, three independent gates before any FACT exists:

  1. **Content gate** (:mod:`proof.content_gate`) — the generated ``poc_script_code`` is screened for
     detection-evasion / persistence / destructive / self-propagating / credential-exfil payloads. A DENY
     quarantines the content and returns WITHOUT minting, EVEN IF the oracle would fire — a dangerous
     "proof" is never stored, surfaced, or replayed.
  2. **Reproduction** — the context is built strictly from the captured bytes; a capture that does not
     carry a reproducible structure translates to ``None`` → LEAD.
  3. **Oracle authority + provenance (G4)** — ``oracle_adapter.confirm_and_certify(provenance="reproduced")``
     mints a signed FACT ONLY when a deterministic oracle FIRES over the reproduced context AND the class is
     oracle-mapped AND the provenance is non-LLM. A non-fire, an unmapped class, or an LLM-provenanced
     context is a labelled LEAD, never spooled. The mint invents no fact any other way.

On a FACT it (a) binds the raw artifacts into the certificate via the EXISTING
``certify.build_certificate(evidence_root, action_id)``, (b) proves replay with ``reverify_context``, and
(c) crosses the ``SignedEvidence`` to the sovereign spine via ``offense_worker.emit_finding_envelope`` →
``finding_spool.spool_envelope`` (which refuses an unsigned envelope — a LEAD can never cross).

FATAL-2: this module is installed in BOTH venvs, so EVERY ``framework.v2`` import here is LAZY
(function-local). Its module-scope imports (``content_gate``, ``oracle_adapter``, ``offense_worker``,
``finding_spool``) are all import-clean, so importing ``proof.engine`` in the sovereign env never pulls
``framework``. Determinism: no wallclock / rng in this file; ``seq`` is passed in.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional, Sequence

from ..finding_spool import spool_envelope
from ..offense_worker import KeylessOffenseWorker
from .content_gate import screen_poc_content

ResolveFn = Callable[[str], "bytes | None"]

# Provenance is FIXED to the non-LLM reproduce-from-raw channel. The mint exists precisely to build the
# context from executor-captured bytes, so it never accepts an LLM-provenanced context (that route stays
# the live seam's LEAD-only path). This is a module constant, not a parameter, so a caller cannot relax it.
_REPRODUCED = "reproduced"


@dataclass(frozen=True)
class MintResult:
    """The outcome of one mint attempt. ``status`` is the honest disposition:
      * ``"fact"``   — oracle-confirmed + oracle-mapped + reproduced + signed (``signed`` is a SignedEvidence).
      * ``"lead"``   — the deterministic oracle did not fire / class unmapped / no reproducible context.
      * ``"denied"`` — the content gate refused the poc_script_code (quarantined; never minted or spooled).
    Only a ``"fact"`` ever carries a ``signed`` certificate or an ``envelope_path`` (a spooled proof)."""

    status: str
    reason: str
    finding_ref: str
    bug_class: str = ""
    signed: Any = None
    reproduced: bool = False
    confirmed_by: str = ""
    confidence: float = 0.0
    gate_category: str = ""              # the content-gate category on a DENY (else "")
    envelope_path: str = ""              # the spooled envelope path on a spooled FACT (else "")

    @property
    def is_fact(self) -> bool:
        return self.status == "fact"


def _finding_ref(finding: dict) -> str:
    return str(
        finding.get("check_id") or finding.get("finding_slug")
        or finding.get("bug_class") or "finding"
    )


def _reject_escape(rel: str) -> bool:
    """True if ``rel`` is a safe relative, ``..``-free path (defence in depth alongside the model
    validator, for duck-typed callers that did not go through the pydantic model)."""
    p = Path(rel)
    return not (p.is_absolute() or any(part == ".." for part in p.parts))


def _materialize(base: Path, exchanges: Sequence[Any], resolve: ResolveFn) -> None:
    """Write the resolved raw bytes of each exchange under ``base`` at its (confined) relative ref. ``base``
    MUST be the manifest root ``evidence_root/action_id`` — ``build_certificate`` hashes exactly that
    directory into the certificate's artifacts, so writing elsewhere would leave the raw-byte binding empty.
    Only refs that resolve are written; an unresolvable/escaping ref is skipped."""
    for ex in exchanges or []:
        for ref in (getattr(ex, "request_bytes_ref", "") or "", getattr(ex, "response_bytes_ref", "") or ""):
            if not ref or not _reject_escape(ref):
                continue
            data = resolve(ref)
            if data is None:
                continue
            dest = base / ref
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data if isinstance(data, (bytes, bytearray)) else str(data).encode("utf-8"))


def _quarantine(quarantine_dir: Optional[str], finding_ref: str, code: object, verdict: Any) -> None:
    """Best-effort: record a content-gate DENY so the operator can inspect what was refused. Never raises
    (a quarantine-write failure must not turn a DENY into a mint)."""
    if not quarantine_dir:
        return
    try:
        qd = Path(quarantine_dir)
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


def mint_proof(
    *,
    finding: dict,
    exchanges: Sequence[Any],
    resolve: ResolveFn,
    engagement_slug: str,
    signers: "list[tuple[str, str]]",
    seq: int = 0,
    evidence_root: Optional[str | os.PathLike] = None,
    action_id: Optional[str] = None,
    spool_dir: Optional[str | os.PathLike] = None,
    quarantine_dir: Optional[str] = None,
    discriminator: Optional[dict] = None,
    verifier: Any = None,
) -> MintResult:
    """Attempt to mint a signed FACT for ``finding`` from its executor-captured ``exchanges``.

    ``finding`` carries the Strix report fields this mint reads: an id (``check_id``/``finding_slug``),
    ``bug_class``, an optional ``insertion_point``, and the free-text ``poc_script_code`` (+ optional
    ``evidence`` / ``poc_description``) the CONTENT GATE screens. ``resolve`` maps a byte-ref to the raw
    bytes the executor captured (the ONLY channel a FACT may rest on). ``signers`` are the governance
    authorisers (from ``live.wiring.provision_authority``); an empty list is refused fail-closed by
    ``confirm_and_certify``. When ``evidence_root`` + ``action_id`` are given the raw bytes are materialised
    and bound into the certificate; when ``spool_dir`` is given a FACT crosses to the sovereign spine."""
    ref = _finding_ref(finding)
    bug_class = str(finding.get("bug_class", ""))

    # (1) content gate — screen BEFORE anything is minted, stored, or replayed. A DENY quarantines and
    #     returns without minting, even if the oracle would fire.
    verdict = screen_poc_content(
        finding.get("poc_script_code"),
        extra_texts=(finding.get("evidence"), finding.get("poc_description")),
    )
    if verdict.denied:
        _quarantine(quarantine_dir, ref, finding.get("poc_script_code"), verdict)
        return MintResult(
            status="denied", reason=verdict.reason, finding_ref=ref, bug_class=bug_class,
            gate_category=verdict.category,
        )

    # (2) reproduction — build the oracle_context ONLY from the captured bytes (lazy framework import).
    from framework.v2.verify.poc_translate import context_from_exchanges

    ctx = context_from_exchanges(
        exchanges, bug_class=bug_class, resolve=resolve, discriminator=discriminator
    )
    if ctx is None:
        return MintResult(
            status="lead", finding_ref=ref, bug_class=bug_class,
            reason="no reproducible oracle_context from the captured exchanges — retained as a lead",
        )
    oracle_context = ctx.model_dump(mode="json")

    # (3) oracle authority + provenance (G4) — the SOLE path to a FACT. confirm_and_certify re-fires the
    #     deterministic oracle over the REPRODUCED context; a non-fire / unmapped class / non-reproduced
    #     provenance is demoted to a labelled LEAD there.
    from ..oracle_adapter import confirm_and_certify

    finding_for_oracle = {
        "check_id": ref,
        "bug_class": bug_class,
        "insertion_point": str(finding.get("insertion_point") or finding.get("param") or ""),
        "oracle_context": oracle_context,
    }
    res = confirm_and_certify(
        finding_for_oracle, engagement_slug=engagement_slug, signers=signers, seq=seq,
        verifier=verifier, provenance=_REPRODUCED,
    )
    if not getattr(res, "is_fact", False):
        return MintResult(
            status="lead", reason=res.reason, finding_ref=res.finding_ref or ref,
            bug_class=res.bug_class or bug_class, confirmed_by=res.confirmed_by,
            confidence=float(res.confidence),
        )

    # FACT — bind artifacts (if an evidence dir is given) and prove replay, then cross to the spine.
    from framework.v2.evidence.certify import build_certificate, sign_certificate
    from framework.v2.verify.reverify import reverify_context

    from framework.v2.verify.poc_translate import context_from_exchanges

    signed = res.signed
    replay_ctx = oracle_context      # default: re-fire over the in-memory reproduced context
    if evidence_root is not None and action_id:
        manifest_root = Path(evidence_root) / action_id
        _materialize(manifest_root, exchanges, resolve)   # write UNDER the dir build_certificate manifests
        enriched = {
            **finding_for_oracle,
            "bug_class": res.bug_class,
            "confirmed_by": res.confirmed_by,
            "confidence": float(res.confidence),
        }
        cert = build_certificate(
            enriched, engagement_slug=engagement_slug, seq=seq,
            evidence_root=Path(evidence_root), action_id=action_id,
        )
        signed = sign_certificate(cert, signers)
        # prove replay from the RETAINED ON-DISK bytes (a genuine offline re-proof — it also catches a
        # materialization/tamper defect): re-resolve each ref from the manifest dir, re-translate, re-verify.
        def _disk_resolve(r: str) -> "bytes | None":
            try:
                return (manifest_root / r).read_bytes()
            except OSError:
                return None
        disk_ctx = context_from_exchanges(exchanges, bug_class=bug_class, resolve=_disk_resolve,
                                          discriminator=discriminator)
        replay_ctx = disk_ctx.model_dump(mode="json") if disk_ctx is not None else None

    # Fail-closed: a proof that will not re-confirm demotes to a LEAD. reverify compares the bug_class WITHOUT
    # normalising, so re-fire with the ORIGINAL class the context was built with (NOT the normalized
    # res.bug_class — that spuriously demotes every alias class).
    rr = reverify_context(replay_ctx, bug_class=bug_class, ref=res.finding_ref) if replay_ctx is not None else None
    if rr is None or not rr.reproduced:
        return MintResult(
            status="lead", finding_ref=res.finding_ref or ref, bug_class=res.bug_class,
            reason="minted certificate did not re-confirm on replay from the retained evidence — demoted",
            confirmed_by=res.confirmed_by, confidence=float(res.confidence),
        )

    envelope_path = ""
    if spool_dir is not None:
        worker = KeylessOffenseWorker(engagement_slug=engagement_slug)
        envelope = worker.emit_finding_envelope(signed)   # refuses an unsigned envelope (fail-closed)
        envelope_path = str(spool_envelope(spool_dir, envelope))

    return MintResult(
        status="fact", reason=res.reason, finding_ref=res.finding_ref or ref,
        bug_class=res.bug_class, signed=signed, reproduced=True,
        confirmed_by=res.confirmed_by, confidence=float(res.confidence),
        envelope_path=envelope_path,
    )
