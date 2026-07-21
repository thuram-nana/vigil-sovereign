"""
detection.base — the DetectionOracle base, the FACT/LEAD grading, and offline re-verification.

A ``DetectionOracle`` is the deterministic heart of one Sentinel signature. It reads retained telemetry
records and either FIRES (returns an :class:`OracleHit`) or stays silent (``None`` — where every benign
twin must land). Firing alone is not truth: a FACT is minted ONLY when the oracle fires AND a signed
:class:`DetectionCertificate` is produced AND that certificate RE-VERIFIES (signature valid + evidence
digest matches + the oracle RE-EXECUTES over the embedded evidence). Anything softer — a LEAD-grade
signature (``waf_probe``, scanner-path bursts), no signer wired, or a certificate that fails to re-verify
— degrades to a LEAD, never a silent block.

The sovereign invariant, enforced structurally here (the red-pen attacks exactly this):

  * **Fires on the TRUE signature only; the benign twin does NOT fire.** ``evaluate`` returns ``None`` for
    legitimate look-alikes — that is the false-positive control, and a benign twin that fires is a BLOCK.
  * **Re-execution, not string trust.** ``reverify_certificate`` re-parses the certificate's own evidence
    and RE-RUNS the named oracle over it; a recorded/forged certificate whose evidence does not actually
    reproduce the fire cannot re-verify. ``detect`` runs this check on the certificate it just minted
    BEFORE emitting a FACT, so an un-reproducible detection fails closed to a LEAD.
  * **Deterministic + total.** No wallclock/RNG (windows come from the records' own ts/seq); ``seq`` is
    injected. Every public method degrades malformed input to "no signal", never raises.
  * **Offense-free.** Oracles read telemetry and wield no tool; ``detect`` performs NO egress.

Import-clean: pydantic/stdlib + vigil_core + the F2 ``agent.state.Finding`` + the detection cert/logs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional

from ..agent.state import Finding
from ..tools.mcp_registry import _redact_str
from .certificate import (
    DetectionCertificate,
    build_certificate,
    evidence_digest,
    redact_evidence,
    sign_certificate,
    verify_certificate_signature,
)
from .logs import parse_access_log, parse_auth_log, parse_conn_log

CertSigner = Callable[[bytes], str]


class Grade(str, Enum):
    """The veracity of a fire. ``FACT`` is oracle-proven + signed + re-verifiable; ``LEAD`` is an
    honest, non-authoritative suspicion (never a silent block)."""

    FACT = "fact"
    LEAD = "lead"


@dataclass(frozen=True)
class OracleHit:
    """A fire. ``grade`` may override the oracle's default (``scanner_fingerprint`` fires FACT on a
    scanner UA, LEAD on a path burst). ``evidence_records`` is the exact firing window — the proof the
    certificate embeds and re-runs over."""

    signature_kind: str
    summary: str
    evidence_records: tuple
    grade: Optional[Grade] = None
    source: str = ""
    params: dict = field(default_factory=dict)


@dataclass(frozen=True)
class Detection:
    """The result of one oracle over one telemetry batch. Carries the typed ``Finding`` (FACT or LEAD),
    the signed ``certificate`` (only for a re-verified FACT), and an honest ``note``."""

    oracle: str
    grade: Grade
    signature_kind: str
    bug_class: str
    severity: str
    summary: str
    source: str
    evidence: tuple
    finding: Finding
    certificate: Optional[DetectionCertificate] = None
    note: str = ""

    @property
    def is_fact(self) -> bool:
        return self.grade is Grade.FACT and self.certificate is not None


# ---------------------------------------------------------------------------------------------------
# windowing — the "rate/velocity" axis comes from the records (ts if present, else in-group position)
# ---------------------------------------------------------------------------------------------------


def group_by(records: Any, attr: str) -> dict:
    """Group records by a string attribute (e.g. ``src``), preserving order. Total; skips records
    missing/blank on that attribute."""
    out: dict = {}
    if not isinstance(records, (list, tuple)):
        return out
    for r in records:
        v = getattr(r, attr, "")
        if not isinstance(v, str) or not v:
            continue
        out.setdefault(v, []).append(r)
    return out


def windowed(events: Any, *, window_seconds: int, window_events: int, predicate: Callable) -> Optional[list]:
    """Slide a window over one group's events and return the FIRST window satisfying ``predicate`` (a
    list slice), else ``None``. The axis is the records' own timestamps when EVERY event has one (span in
    seconds), otherwise the in-group position (span in record count) — never a wallclock. ``predicate``
    must be monotone in the window (grows-only signals: counts / distinct-counts), which lets the
    maximal window at each right pointer be a complete test. Total: any error → ``None``."""
    try:
        ev = list(events or [])
        if not ev:
            return None
        all_ts = all(getattr(e, "ts", None) is not None for e in ev)
        if all_ts:
            ev = sorted(ev, key=lambda e: (e.ts, getattr(e, "seq", 0)))
            keys = [int(e.ts) for e in ev]
            span = int(window_seconds)
        else:
            ev = sorted(ev, key=lambda e: getattr(e, "seq", 0))
            keys = list(range(len(ev)))
            span = int(window_events)
        left = 0
        for right in range(len(ev)):
            while keys[right] - keys[left] > span:
                left += 1
            window = ev[left:right + 1]
            if predicate(window):
                return window
        return None
    except Exception:  # noqa: BLE001 — a windowing error is no signal, never a crash
        return None


# ---------------------------------------------------------------------------------------------------
# the oracle base
# ---------------------------------------------------------------------------------------------------


class DetectionOracle:
    """One deterministic detection signature. Subclasses set the class metadata and implement
    :meth:`evaluate`. The base owns grading, certificate minting + the fail-closed FACT gate, and the
    typed ``Finding`` construction."""

    name: str = "abstract"
    bug_class: str = "detection"
    severity: str = "info"
    evidence_kind: str = "access_log"     # "access_log" | "auth_log" | "conn_log"
    default_grade: Grade = Grade.FACT
    # window defaults (subclasses override); ts axis is seconds, seq axis is record count.
    window_seconds: int = 60
    window_events: int = 200

    # -- the signature (subclass implements) --------------------------------------------------------
    def evaluate(self, records: Any) -> Optional[OracleHit]:  # pragma: no cover - abstract
        raise NotImplementedError

    def _safe_evaluate(self, records: Any) -> Optional[OracleHit]:
        """Total wrapper: any error inside a subclass's ``evaluate`` degrades to no signal."""
        try:
            hit = self.evaluate(records)
        except Exception:  # noqa: BLE001 — an oracle must never crash on attacker-shaped telemetry
            return None
        return hit if isinstance(hit, OracleHit) else None

    def _params(self) -> dict:
        """Reproduction params embedded in the certificate (so a verifier re-runs with the same
        thresholds). Subclasses extend."""
        return {"window_seconds": self.window_seconds, "window_events": self.window_events}

    def _records_from_evidence(self, evidence_lines: Any) -> list:
        """Re-parse a certificate's redacted evidence lines back into records for the re-run, dispatched
        by ``evidence_kind``. Total."""
        try:
            text = "\n".join(str(x) for x in (evidence_lines or []))
        except Exception:  # noqa: BLE001
            return []
        if self.evidence_kind == "auth_log":
            return parse_auth_log(text)
        if self.evidence_kind == "conn_log":
            return parse_conn_log(text)
        return parse_access_log(text)

    def detect(
        self,
        records: Any,
        *,
        signer: Optional[CertSigner] = None,
        verify_key: str = "",
        key_id: str = "",
        seq: int = 0,
    ) -> Optional[Detection]:
        """Run the oracle over ``records``. Returns ``None`` on no signal (the benign-twin path). On a
        fire, mints a FACT ONLY if the resolved grade is FACT AND a signer + verify key are wired AND the
        signed certificate RE-VERIFIES (signature + digest + a live oracle RE-RUN); otherwise a LEAD.
        Fail-closed and total throughout."""
        hit = self._safe_evaluate(records)
        if hit is None:
            return None
        grade = hit.grade if isinstance(hit.grade, Grade) else self.default_grade
        redacted = redact_evidence([getattr(r, "raw", "") for r in hit.evidence_records])
        source = hit.source or ""
        # SECRET-FREE at the object boundary: the returned Detection.summary (which run_* hands to the
        # orchestrator/observability recorder) is scrubbed through the SAME F3 free-string redactor that
        # already cleans certificate.summary/evidence, so a credential in the request target can never
        # ride out on the transport object even though the spine artifacts are clean. Idempotent + total.
        safe_summary = _redact_str(hit.summary) if isinstance(hit.summary, str) else ""

        note = ""
        if grade is Grade.FACT:
            if callable(signer) and isinstance(verify_key, str) and verify_key.strip():
                cert = build_certificate(
                    oracle=self.name, signature_kind=hit.signature_kind, bug_class=self.bug_class,
                    severity=self.severity, evidence_kind=self.evidence_kind,
                    evidence_lines=[getattr(r, "raw", "") for r in hit.evidence_records],
                    summary=hit.summary, source=source,
                    params={**self._params(), **(hit.params or {})}, seq=seq,
                )
                signed = sign_certificate(cert, signer, key_id=key_id)
                if signed is not None and reverify_certificate(signed, verify_key):
                    finding = Finding(
                        ref=f"detection:{self.name}:{seq}", bug_class=self.bug_class,
                        title=f"{self.name} — {hit.signature_kind}", severity=self.severity,
                        status="fact", evidence_ref=signed.cert_id, source=f"detection/{self.name}",
                    )
                    return Detection(
                        oracle=self.name, grade=Grade.FACT, signature_kind=hit.signature_kind,
                        bug_class=self.bug_class, severity=self.severity, summary=safe_summary,
                        source=source, evidence=tuple(redacted), finding=finding, certificate=signed,
                        note="oracle fired and the signed certificate re-verifies offline",
                    )
                note = ("FACT downgraded to LEAD: the certificate could not be minted or re-verified "
                        "(fail-closed)")
            else:
                note = ("LEAD: no signer/verify key wired — a FACT requires a re-verifiable signed "
                        "certificate")

        # LEAD path (native LEAD grade, or a FACT that could not be certified): no evidence_ref.
        lead = Finding(
            ref=f"detection:{self.name}:{seq}", bug_class=self.bug_class,
            title=f"{self.name} — {hit.signature_kind}", severity=self.severity,
            status="lead", evidence_ref="", source=f"detection/{self.name}",
        )
        return Detection(
            oracle=self.name, grade=Grade.LEAD, signature_kind=hit.signature_kind,
            bug_class=self.bug_class, severity=self.severity, summary=safe_summary,
            source=source, evidence=tuple(redacted), finding=lead, certificate=None, note=note,
        )


def reverify_certificate(
    cert: Any, public_key_b64: object, *, resolve: Optional[Callable] = None,
) -> bool:
    """Re-verify a detection certificate OFFLINE — the anti-hallucination core. ALL must hold:

      1. the Ed25519 signature is valid over the canonical payload (``verify_certificate_signature``);
      2. the recomputed evidence digest equals the certificate's;
      3. the named oracle, RE-RUN over the certificate's own (redacted) evidence, FIRES with the SAME
         signature family.

    A recorded/forged certificate whose embedded evidence does not actually reproduce the fire cannot
    pass step 3 — proof by re-execution, not by trusting a stored string. Total/fail-closed: any missing
    piece, an unknown oracle, or any error → False (never a false re-verify, never a raise)."""
    if not verify_certificate_signature(cert, public_key_b64):
        return False
    try:
        if evidence_digest(cert.evidence) != cert.evidence_digest_hex:
            return False
        if resolve is None:
            from .registry import resolve_oracle as resolve  # lazy: avoids a base<->registry cycle
        oracle = resolve(cert.oracle)
        if not isinstance(oracle, DetectionOracle):
            return False
        records = oracle._records_from_evidence(cert.evidence)
        hit = oracle._safe_evaluate(records)
        if hit is None:
            return False
        return hit.signature_kind == cert.signature_kind
    except Exception:  # noqa: BLE001 — any re-run error re-verifies nothing (fail-closed)
        return False
