"""remediation.apex_pcr — APEX PR-3 Deliverable 2: the autonomous proof-carrying-remediation CLOSE-THE-LOOP.

This is the one orchestration that takes an oracle-confirmed FACT all the way to a signed, offline-re-verifiable
NEGATIVE remediation certificate — autonomously, through the gated auto-patch PR, with every soundness control
intact. It REUSES, end-to-end:

  * ``triage.may_remediate`` — the sovereign FACT-gate: a remediation is spawnable ONLY from an oracle-confirmed
    finding carrying a signed evidence ref (a LEAD can never be patched). Enforced here AND again inside
    ``autopatch`` (defense in depth).
  * ``autopatch.loop.autopatch`` — the fail-closed gated ladder: propose → clone → gated/deadline-approved edit →
    sandbox build → **gated, m-of-n-quorum PR** → verify. Every executor is injected; no live kernel/git/LLM.
  * ``remediation_cert.mint_remediation_certificate`` / ``verify_remediation_certificate`` — the v2 NEGATIVE
    proof-carrying cert: it is EARNED (the positive-control twin still FIRES, the patched build is SILENT, the
    target ANSWERED, the whole cert is signed) and re-verifies OFFLINE by re-execution, with no target and no
    trust in the tool that produced it.
  * ``fix_oracle.build_fix_oracle`` — the fix-verification oracle: it re-drives the ORIGINAL exploit against the
    patched build and re-fires the SAME deterministic oracle; it mints 'remediated' ONLY on genuine silence.

THE CLOSE: we hand ``autopatch`` a fix oracle whose signer, at the moment the oracle confirms silence over the
patched build's real re-captured bytes, mints the v2 negative certificate — binding the patched (silent) context
to the ORIGINAL confirmed finding's (firing) context as the positive control. So the certificate is produced by
the SAME re-execution that earned 'remediated', never asserted after the fact; if ANY control fails the mint
RAISES, the oracle reports no silence, and ``autopatch`` honestly returns an uncertified PR (fail-closed).

Soundness invariants (never violated):
  * Spawnable ONLY from a FACT (``may_remediate`` here + inside ``autopatch``).
  * A clearance is a SIGNED, OFFLINE-RE-VERIFIABLE NEGATIVE cert (positive control fires, patched silent, live,
    bound, authentic) — never "the oracle didn't fire".
  * The PR leg is the gated, m-of-n-quorum ``autopatch`` leg (every target/repo-touching action through the gate).
  * Default OFF (``VIGIL_APEX_IMPACT``) ⇒ inert, byte-identical.
  * FATAL-2: ``signers`` are INJECTED by the sovereign caller (this module holds no key); every ``framework`` /
    cert / oracle import is LAZY (function-local); module scope is stdlib only.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Optional


@dataclass
class ApexPcrResult:
    """The outcome of one autonomous close-the-loop. ``certified`` is the strong terminal: the gated PR opened,
    the oracle went silent on the patched build, AND the signed v2 negative cert re-verifies OFFLINE. Anything
    weaker is honest (an uncertified PR, a refusal); the certificate is attached only when it was minted."""

    status: str                                   # disabled | refused-not-confirmed | not-oracle-provable | patch-<st> | remediated-certified | remediated-uncertified
    reason: str = ""
    patch_result: Optional[Any] = None            # the autopatch PatchResult (the full gated ladder + status)
    remediation_cert: Optional[dict] = None       # the v2 NEGATIVE cert, present ONLY when minted
    offline_verification: Optional[Any] = None    # RemediationVerification — the OFFLINE re-verify of the cert
    remediated: bool = False                      # autopatch minted 'remediated' (oracle silent + signed + PR)
    certified: bool = False                       # remediated AND the v2 negative cert re-verifies offline
    steps: list = field(default_factory=list)     # the autopatch ladder steps (audit trail), when available


def _enabled() -> bool:
    from ..apex_flags import apex_impact_enabled   # keyless env read (shared offense flag)
    return apex_impact_enabled()


def close_remediation_loop(
    finding: Any,
    *,
    positive_control_context: dict,
    signers: "list[tuple[str, str]]",
    signer_pubkeys: "dict[str, str]",
    engagement_slug: str,
    redrive: Callable[[Any, Any], "Optional[dict]"],
    propose_patch: Callable[[Any], Any],
    gate: Callable[..., Any],
    clone: Callable[..., Any],
    build: Callable[..., Any],
    open_pr: Callable[..., Any],
    quorum: Callable[[Any], Any],
    approval: Callable[[Any], Any],
    now: Callable[[], Any],
    bug_class: str = "",
    expected_channel: str = "",
    original_finding_cert_digest: str = "",
    freshness_nonce: str = "",
    target_repo: str = "",
    target_branch: str = "",
    remediation_id: str = "",
) -> ApexPcrResult:
    """Drive the autonomous close-the-loop for ONE oracle-confirmed finding, fail-closed at every stage.

    ``positive_control_context`` is the ORIGINAL confirmed finding's retained ``oracle_context`` — the twin the
    oracle STILL fires on (CONTROL 1). ``redrive`` exercises the patched build to re-capture the bytes the
    oracle re-fires over (silence = CONTROL 2; a captured response = CONTROL 3 liveness). ``signers`` /
    ``signer_pubkeys`` are the governance key material INJECTED by the sovereign caller (this module is keyless).
    Every other callable is an injected executor (``gate``/``clone``/``build``/``open_pr``/``quorum``/
    ``approval``/``now``/``propose_patch``), so the whole loop runs without a live kernel, git, LLM, or sandbox.

    Returns an :class:`ApexPcrResult`. ``status='remediated-certified'`` (``certified=True``) is reached ONLY
    when the gated PR opened, the oracle went silent on the patched build, the v2 negative certificate minted,
    AND it re-verifies OFFLINE. A LEAD, a flag-off call, a non-oracle-provable class, or any control failure is
    an honest non-certified outcome — never a fabricated clearance."""
    # (0) default-OFF: inert, byte-identical.
    if not _enabled():
        return ApexPcrResult(status="disabled", reason="APEX Impact & Closure is off (VIGIL_APEX_IMPACT) — inert")

    # (1) THE SOVEREIGN FACT-GATE — a remediation is spawnable ONLY from an oracle-confirmed FACT.
    from .triage import may_remediate            # pure sibling (no framework)
    allowed, why = may_remediate(finding)
    if not allowed:
        return ApexPcrResult(status="refused-not-confirmed",
                             reason=f"close-the-loop REFUSED: {why} — a LEAD can never be remediated")

    if not (isinstance(positive_control_context, dict) and positive_control_context):
        return ApexPcrResult(status="refused-not-confirmed",
                             reason="the ORIGINAL finding's oracle_context (the positive-control twin) is required "
                                    "— without a firing twin, silence on the patched build is not a proof")
    if not signers:
        return ApexPcrResult(status="refused-not-confirmed",
                             reason="governance signers are required (a clearance is never an unsigned proof)")

    bc = str(bug_class or getattr(finding, "bug_class", "") or "").strip()
    channel = str(expected_channel or "").strip()
    finding_ref = str(getattr(finding, "ref", "") or "finding")

    # (2) the CAPTURING signer — at the exact moment the oracle confirms SILENCE over the patched build's real
    # re-captured bytes, mint the v2 NEGATIVE certificate (binding the firing positive-control twin). A control
    # failure RAISES → the oracle reports no silence → autopatch returns an uncertified PR (fail-closed).
    holder: dict[str, Any] = {}

    def _capturing_signer(fref: str, bclass: str, patched_context: dict) -> str:
        from .remediation_cert import mint_remediation_certificate   # lazy — framework (FATAL-2)
        cert = mint_remediation_certificate(
            finding_ref=fref, bug_class=bclass, patched_oracle_context=patched_context,
            positive_control_context=positive_control_context, engagement_slug=str(engagement_slug or ""),
            signers=signers, surface=str(getattr(finding, "target", "") or ""),
            original_finding_cert_digest=str(original_finding_cert_digest or ""),
            freshness_nonce=str(freshness_nonce or ""), repeats=1)
        holder["cert"] = cert
        # a non-empty content-addressed ref so the FixVerdict carries a cert (the full signed cert is in holder).
        return "remediation-cert:v2:" + str(cert.get("patched_context_sha256") or "")

    # (3) build the fix-verification oracle (re-drive + re-fire + the capturing signer). A non-oracle-provable
    # class (request-side, or an unresolved family) is refused BEFORE autopatch — an honest, named boundary.
    try:
        from .fix_oracle import build_fix_oracle   # lazy — framework (FATAL-2)
        verify_oracle = build_fix_oracle(
            bug_class=bc, redrive=redrive, expected_channel=channel,
            driving_ref=finding_ref, signer=_capturing_signer)
    except ValueError as e:
        return ApexPcrResult(status="not-oracle-provable",
                             reason=f"remediation is not oracle-provable for this finding: {e}")

    # (4) the gated auto-patch ladder — propose → clone → gated edit → build → GATED m-of-n PR → verify.
    from ..autopatch.loop import autopatch       # lazy (keeps module scope framework-free)
    patch = autopatch(
        finding, gate=gate, oracle=verify_oracle, propose_patch=propose_patch, clone=clone, build=build,
        open_pr=open_pr, quorum=quorum, approval=approval, now=now, remediation_id=remediation_id,
        target_repo=target_repo, target_branch=target_branch)

    cert = holder.get("cert")
    steps = list(getattr(patch, "steps", None) or [])
    remediated = bool(getattr(patch, "remediated", False))

    # (5) OFFLINE re-verification — the clearance is proven by RE-EXECUTION, offline, against the FROZEN cert.
    offline = None
    certified = False
    if isinstance(cert, dict):
        from .remediation_cert import verify_remediation_certificate   # lazy — framework (FATAL-2)
        offline = verify_remediation_certificate(cert, signer_pubkeys=signer_pubkeys)
        certified = bool(remediated and getattr(offline, "ok", False))

    if certified:
        status = "remediated-certified"
        reason = ("closed the loop: gated PR opened, the ORIGINAL exploit oracle is SILENT on the patched build, "
                  "and the signed NEGATIVE remediation certificate re-verifies offline")
    elif remediated:
        status = "remediated-uncertified"
        reason = ("autopatch reported remediated but the v2 negative certificate did not re-verify offline "
                  f"(fail-closed): {getattr(offline, 'reason', 'no cert minted')}")
    else:
        status = "patch-" + str(getattr(patch, "status", "unknown") or "unknown")
        reason = str(getattr(patch, "reason", "") or "the gated ladder did not reach a certified remediation")

    return ApexPcrResult(status=status, reason=reason, patch_result=patch, remediation_cert=cert,
                         offline_verification=offline, remediated=remediated, certified=certified, steps=steps)


__all__ = ["ApexPcrResult", "close_remediation_loop"]
