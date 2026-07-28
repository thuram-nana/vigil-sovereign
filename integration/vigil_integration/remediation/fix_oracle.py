"""
remediation.fix_oracle — the concrete, oracle-backed fix-verification the autopatch/codefix pipelines inject
(A6a). It earns ``remediated=True`` the ONLY sound way: by re-firing the SAME deterministic oracle that
confirmed the driving FACT against the PATCHED build, and signing a remediation certificate ONLY when that
oracle goes SILENT over the patched build's freshly re-captured bytes.

This reuses the Proof Studio oracle machinery end-to-end — a remediation is proven exactly the way a finding
is: by re-execution, never by assertion. ``context_from_exchanges`` (the SAME translator the mint uses) turns
the patched build's re-captured exchange into an ``oracle_context``, and ``reverify_context`` re-fires the
oracle over it.

THE SOUNDNESS CONTRACT (why this cannot fake a fix — the crypto-grade heart):
  * ``remediated`` (a ``FixVerdict`` with ``fired=False`` + a signed ``cert``) is returned ONLY when the
    oracle GENUINELY re-fired over re-driven bytes and did NOT confirm. EVERY other path RAISES (→ the
    caller's ``verify_patch``/``verify_fix`` maps a raise to ``unverified``), never a false "silent":
      - no re-drive capability, or the re-drive returns nothing → RAISE (a fix you can't exercise is unproven);
      - the re-driven capture yields no reproducible ``oracle_context`` → RAISE (unbuildable ≠ silent);
      - the finding's channel is REQUEST-SIDE (``request_payload``) → RAISE. A patch changes the SERVER's
        response, not the attacker's request; that class's remediation is simply not oracle-provable, so we
        refuse to adjudicate rather than claim a false "still-vulnerable-forever" or a false "silent";
      - the oracle went silent but no signer is wired → RAISE (a claim without a signature is not a proof).
  * When the oracle STILL fires on the patched build → ``FixVerdict(fired=True)`` → ``still-vulnerable``.

FATAL-2: every ``framework.v2`` import is LAZY (function-local); module scope pulls only stdlib.
Determinism: no wallclock / rng.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Callable, Optional

# The re-drive hands back the patched build's response to the ORIGINAL exploit, as the same plain-dict
# capture shape the live path builds: {"exchanges": [{"channel": ..., ...}], "blobs": {ref: bytes}}.
Redrive = Callable[[Any, Any], Optional[dict]]

# Channels whose oracle adjudicates the REQUEST (not the server's response). A patch cannot change the
# request, so re-firing over a re-drive is meaningless — remediation for these is not oracle-provable.
_REQUEST_SIDE = frozenset({"request_payload"})


@dataclass(frozen=True)
class FixVerdict:
    """The verdict ``verify_patch`` reads: ``fired`` (True = exploit still works), ``cert`` (the signed
    remediation ref, present ONLY on a signed silent verdict). ``reason`` is advisory."""

    fired: bool
    cert: str = ""
    reason: str = ""
    context_digest: str = ""


# A signer mints the remediation certificate ref from (finding_ref, bug_class, patched oracle_context). It is
# invoked ONLY after the oracle is confirmed silent over the patched build's real re-captured bytes.
FixSigner = Callable[[str, str, dict], Optional[str]]


def _capture_channel(capture: dict) -> str:
    exs = capture.get("exchanges") or []
    return str(exs[0].get("channel", "")) if exs and isinstance(exs[0], dict) else ""


def build_fix_oracle(
    *,
    bug_class: str,
    redrive: Optional[Redrive],
    expected_channel: str,
    driving_ref: str = "finding",
    signer: Optional[FixSigner] = None,
) -> Callable[[Any, Any], FixVerdict]:
    """Return the ``oracle(request, patched_build) -> FixVerdict`` the pipeline injects. It re-drives the
    ORIGINAL exploit against the patched build and re-fires the ``bug_class`` oracle over the result. Raises
    (→ ``unverified``) on any path where silence cannot be soundly confirmed (see the module contract).

    ``expected_channel`` is the ORACLE FAMILY the driving FACT was confirmed on (from the retained
    re-verifiable material). It is the AUTHORITATIVE request-vs-response signal — NOT the re-drive's
    self-reported channel, which is untrusted. The oracle refuses (raises) unless the re-driven capture's
    channel EQUALS ``expected_channel``: a mismatch would build a context for the WRONG oracle family whose
    input field the resolved oracle never reads, so ``reproduced=False`` would be a VACUOUS non-fire (the
    oracle's input is absent), which must never be minted as a genuine 'silent' remediation."""
    if not str(bug_class or "").strip():
        raise ValueError("build_fix_oracle: a bug_class is required to re-fire the original oracle")
    exp = str(expected_channel or "").strip()
    if not exp:
        raise ValueError("build_fix_oracle: the driving finding's oracle channel is required to pin the "
                         "re-drive (an unknown oracle family cannot be soundly re-verified)")
    if exp in _REQUEST_SIDE:
        raise ValueError(f"remediation not oracle-provable for a request-side finding (channel={exp!r}): a "
                         "patch changes the server response, not the attacker's request (fail-closed)")

    def oracle(request: Any, patched_build: Any) -> FixVerdict:
        from framework.v2.evidence.poc import CapturedExchange           # lazy — FATAL-2
        from framework.v2.verify.poc_translate import context_from_exchanges
        from framework.v2.verify.reverify import reverify_context

        if redrive is None:
            raise ValueError("no re-drive capability — a fix that cannot be exercised is unproven (fail-closed)")
        capture = redrive(request, patched_build)
        if not isinstance(capture, dict) or not (capture.get("exchanges") or []):
            raise ValueError("re-drive produced no captured exchange — cannot confirm the fix (fail-closed)")

        channel = _capture_channel(capture)
        if channel in _REQUEST_SIDE:
            raise ValueError(f"remediation not oracle-provable for a request-side finding (channel={channel!r}): "
                             "a patch changes the server response, not the attacker's request (fail-closed)")
        # PIN to the driving oracle family: a re-drive on a DIFFERENT channel builds a context the resolved
        # oracle can't read → a vacuous non-fire. Refuse rather than mint it as silence (adversarial-review fix).
        if channel != exp:
            raise ValueError(f"re-driven channel {channel!r} != the finding's confirmed oracle family {exp!r} "
                             "— refusing to adjudicate remediation over the wrong oracle (fail-closed)")

        blobs = capture.get("blobs") or {}

        def _resolve(ref: str) -> "bytes | None":
            b = blobs.get(ref)
            if isinstance(b, (bytes, bytearray)):
                return bytes(b)
            return b.encode("utf-8") if isinstance(b, str) else None

        try:
            exchanges = [CapturedExchange(**{k: v for k, v in ex.items() if k != "blob"})
                         for ex in capture["exchanges"]]
        except Exception as exc:  # noqa: BLE001 — a malformed re-drive is not silence
            raise ValueError(f"re-driven capture is malformed — cannot confirm the fix (fail-closed): {exc}")

        ctx = context_from_exchanges(exchanges, bug_class=bug_class, resolve=_resolve)
        if ctx is None:
            # A capture that yields no reproducible context is UNBUILDABLE, not silence — refuse.
            raise ValueError("re-driven capture yields no reproducible oracle_context — cannot distinguish a "
                             "fix from an unexercised probe (fail-closed)")
        oracle_context = ctx.model_dump(mode="json")

        rr = reverify_context(oracle_context, bug_class=bug_class, ref=driving_ref)
        if rr.reproduced:
            return FixVerdict(fired=True, reason="the ORIGINAL exploit STILL fires on the patched build")

        # GENUINE silence: the oracle re-fired over real re-driven bytes and did not confirm.
        digest = "sha256:" + hashlib.sha256(
            json.dumps(oracle_context, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
        if signer is None:
            raise ValueError("oracle silent but no remediation signer wired — a claim without a signature is "
                             "not a proof (fail-closed)")
        cert = signer(driving_ref, bug_class, oracle_context)
        if not (cert is not None and str(cert).strip()):
            raise ValueError("oracle silent but the signer produced no certificate (fail-closed)")
        return FixVerdict(fired=False, cert=str(cert), context_digest=digest,
                          reason="the ORIGINAL exploit oracle went SILENT on the patched build; remediation signed")

    return oracle


def build_fix_signer(*, engagement_slug: str, signers: "list[tuple[str, str]]") -> FixSigner:
    """Return a ``FixSigner`` that mints a signed remediation attestation binding (finding_ref, bug_class, the
    patched build's silent oracle_context digest) — an Ed25519 signature over a canonical payload with the
    run's governance key. A verifier who retains the patched oracle_context can re-fire the oracle, confirm it
    is silent, and check this signature. Empty signers is refused fail-closed (never an unsigned 'proof')."""
    if not signers:
        raise ValueError("build_fix_signer: governance signers are required (will not sign an unproven fix)")

    def sign_remediation(finding_ref: str, bug_class: str, patched_context: dict) -> str:
        from vigil_core import sign                                       # lazy — FATAL-2

        ctx_digest = hashlib.sha256(
            json.dumps(patched_context, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
        payload = {
            "schema": "vigil-remediation-v1",
            "engagement_slug": str(engagement_slug or ""),
            "finding_ref": str(finding_ref or ""),
            "bug_class": str(bug_class or ""),
            "patched_context_sha256": ctx_digest,
            "verdict": "oracle-silent",     # the original exploit oracle did NOT fire on the patched build
        }
        msg = b"vigil-remediation-v1\x00" + json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        key_id, priv = signers[0]
        sig = sign(priv, msg)
        # a content-addressed, non-empty ref (the payload digest) — the signature + payload travel with it.
        return "remediation:" + hashlib.sha256(msg).hexdigest()[:24] + ":" + key_id + ":" + sig

    return sign_remediation


def build_run_fix_oracle(
    *,
    run_dir: Any,
    finding_ref: str,
    redrive: Optional[Redrive],
    engagement_slug: str,
    signers: "list[tuple[str, str]]",
    bug_class: str = "",
    expected_channel: str = "",
) -> Callable[[Any, Any], FixVerdict]:
    """Wire a fix-oracle for a driving finding by resolving its EXACT oracle ``bug_class`` AND ``channel``
    (oracle family) from the run's retained re-verifiable material (``<run_dir>/proofs/reverifiable.json``,
    keyed by ``check_id`` — the same C1 material the proof bundle is built from), then constructing
    :func:`build_fix_oracle` + a signer. Explicit ``bug_class``/``expected_channel`` win; if either cannot be
    resolved it refuses (a remediation can't re-fire an unknown oracle, and can't pin an unknown family — both
    fail-closed). The ``redrive`` (exercising the patched build) is injected by the live pipeline."""
    resolved = str(bug_class or "").strip()
    channel = str(expected_channel or "").strip()
    if not resolved or not channel:
        from ..proof.run import read_reverifiable      # integration sibling — import-clean

        for f in read_reverifiable(run_dir).get("active_findings", []):
            if isinstance(f, dict) and str(f.get("check_id")) == str(finding_ref):
                resolved = resolved or str(f.get("bug_class") or "").strip()
                channel = channel or str(f.get("channel") or "").strip()
                break
    if not resolved:
        raise ValueError(f"cannot resolve the oracle bug_class for finding {finding_ref!r} — no retained "
                         "re-verifiable material and none supplied (a remediation cannot re-fire an unknown oracle)")
    if not channel:
        raise ValueError(f"cannot resolve the oracle CHANNEL for finding {finding_ref!r} — a remediation "
                         "cannot pin the re-drive to an unknown oracle family (fail-closed)")
    signer = build_fix_signer(engagement_slug=engagement_slug, signers=signers)
    return build_fix_oracle(bug_class=resolved, redrive=redrive, expected_channel=channel,
                            driving_ref=str(finding_ref), signer=signer)
