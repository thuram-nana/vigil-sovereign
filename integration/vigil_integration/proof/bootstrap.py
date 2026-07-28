"""
proof.bootstrap — ASSIGN the Proof Studio ``proof_sink`` into a running Strix process (the B5 wiring).

Strix's ``report.state.proof_sink`` is an optional module-level hook (absent ⇒ vendored behaviour is
byte-identical). ``install`` sets it to a :class:`proof.sink.ProofSink` whose ``mint`` is
:func:`proof.run.build_report_mint` — so every finding that carries an executor capture is screened by the
content gate and, on a reproduced + oracle-mapped capture, minted into a signed FACT and persisted for the
Proof Studio screen. This runs IN the keyless offense Strix process (where ``strix.report.state`` and
``framework`` are importable); the sovereign key is never here.

``install_from_env`` is the zero-argument entry the Strix bootstrap calls best-effort at startup: absent the
``VIGIL_PROOF_RUN_DIR`` env var (i.e. Strix launched standalone, not by the VIGIL console) it is a NO-OP, so
vendored Strix keeps running unchanged. The console launcher exports the run context + provisions the run's
governance signers, so the mint signs with the real run authority.

FATAL-2: module scope pulls only import-clean ``proof.run`` / ``proof.sink``; ``strix.report.state`` and
``framework`` (via ``provision_authority``) are imported lazily inside the functions.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Optional, Sequence

from .run import build_report_mint
from .sink import ProofSink

logger = logging.getLogger(__name__)

# Loopback is the only scope this installer will provision for itself. A remote engagement's authority is a
# deliberate out-of-band ceremony (charter-signed) — never something a Strix bootstrap mints implicitly.
_DEFAULT_SCOPE = ("127.0.0.1",)


def _run_signers(engagement_slug: str, scope: Sequence[str], base_dir: Optional[str]) -> "list[tuple[str, str]]":
    """The run's cert signers, from the CRUCIBLE governance authority (``provision_authority``). Lazy —
    pulls ``framework`` only here."""
    from ..live.wiring import provision_authority

    prov = provision_authority(slug=engagement_slug, scope=list(scope), base_dir=base_dir)
    return list(prov.signers)


def install(
    *,
    run_dir: str | os.PathLike,
    engagement_slug: str,
    signers: "Optional[list[tuple[str, str]]]" = None,
    evidence_root: Optional[str | os.PathLike] = None,
    spool_dir: Optional[str | os.PathLike] = None,
    quarantine_dir: Optional[str] = None,
    scope: Sequence[str] = _DEFAULT_SCOPE,
    base_dir: Optional[str] = None,
) -> Any:
    """Assign the Proof Studio ``proof_sink`` for this run and return it. ``signers`` defaults to the run's
    provisioned governance authority (loopback scope)."""
    import strix.report.state as report_state    # lazy — offense-env only

    if signers is None:
        signers = _run_signers(engagement_slug, scope, base_dir)
    mint = build_report_mint(
        run_dir=run_dir, signers=signers, engagement_slug=engagement_slug,
        evidence_root=evidence_root, spool_dir=spool_dir, quarantine_dir=quarantine_dir)
    sink = ProofSink(quarantine_dir=quarantine_dir, mint=mint)
    report_state.proof_sink = sink
    logger.info("Proof Studio sink installed for engagement=%s run_dir=%s", engagement_slug, run_dir)
    return sink


def install_from_env() -> Any:
    """Best-effort install from the run context the VIGIL console exports. NO-OP (returns ``None``) when
    ``VIGIL_PROOF_RUN_DIR`` is unset (standalone Strix) or anything fails — the sink must never break Strix
    startup."""
    run_dir = os.environ.get("VIGIL_PROOF_RUN_DIR")
    if not run_dir:
        return None
    try:
        return install(
            run_dir=run_dir,
            engagement_slug=os.environ.get("VIGIL_ENGAGEMENT") or "engagement",
            evidence_root=os.environ.get("VIGIL_PROOF_EVIDENCE_ROOT") or None,
            spool_dir=os.environ.get("VIGIL_PROOF_SPOOL") or None,
            quarantine_dir=os.environ.get("VIGIL_PROOF_QUARANTINE") or None,
            base_dir=os.environ.get("VIGIL_BASE_DIR") or None,
        )
    except Exception:  # noqa: BLE001 — a bootstrap failure must never stop Strix; it just means no proofs
        logger.warning("Proof Studio sink install skipped (non-fatal)", exc_info=True)
        return None
