"""remediation.attestation — the Proof-Carrying Remediation Attestation (PCR / W5).

The novel core: a signed, OFFLINE-RE-VERIFIABLE certificate that binds TWO INDEPENDENT deterministic
oracles for one code fix, so a false "fixed" is not merely unlikely but re-checkable to be impossible:

  * **VULN-GONE** — the finding's deterministic oracle no longer fires over the PATCHED tree. For a static
    (DAA) code finding that is ``codescan.verify_finding_cleared`` (the rule fires NOWHERE) re-run over the
    patched clone; the attestation binds the rule id + the base/patched tree digests + the diff digest so a
    verifier can reconstruct and RE-RUN it.
  * **BEHAVIOR-PRESERVED** — the repo's REAL test suite passed on the patched tree (W1a), bound to the exact
    test command + the dependency inputs' digest + ``suite_ran``/``tests_passed``. When no runnable suite
    exists this axis is recorded ``established=False`` — HONESTLY not-established, NEVER faked.

Minting is FAIL-CLOSED: it refuses unless VULN-GONE holds, and refuses to record BEHAVIOR-PRESERVED as
established unless the suite actually ran AND passed. Verification is DEMOTE-ONLY and re-executes: given the
patched tree it re-digests it (binding), re-runs the DAA rule (VULN-GONE), and — with a dep cache — can
re-run the suite (BEHAVIOR-PRESERVED); any mismatch fails. Signatures are Ed25519 with m-of-n threshold.

Two-env clean: module scope imports only ``vigil_core`` (+ stdlib); the framework-backed DAA re-run is a
FUNCTION-LOCAL import inside verification, reached only when a patched tree is supplied.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from vigil_core import canonical_json, digest_payload, sign, verify_one
from vigil_core.signed_build_manifest import digest_tree

_ATT_SCHEMA = "vigil-remediation-attestation-v1"
# Domain separator: a self-contained literal (no import-time coupling to a specific vigil_core version), also
# recorded centrally in vigil_core.spine_domains.DOMAIN_TAGS["remediation-attestation"] as the registry of
# record. It ends in NUL and is distinct from every other tag, so a signature here can never replay under
# another protocol's tag and vice-versa (verified by the crypto-notary review).
_ATT_DOMAIN = b"vigil-remediation-attestation-v1\x00"

# behavior-axis tiers
BEHAVIOR_ESTABLISHED = "established"          # the real suite ran AND passed
BEHAVIOR_NOT_ESTABLISHED = "not-established"  # no runnable suite / it did not run — honestly unproven

# verification tiers
TIER_FULLY_SOUND = "fully-sound"     # authentic + VULN-GONE re-verified + BEHAVIOR established & re-verified
TIER_VULN_ONLY = "vuln-gone-only"    # authentic + VULN-GONE re-verified; behavior not established (honest)
TIER_UNVERIFIED = "unverified"       # signature/binding ok but a re-execution was not performed
TIER_FAIL = "fail"                   # a hard failure (bad signature, mismatch, or the vuln is NOT gone)


def _canon(obj: Any) -> bytes:
    return canonical_json(obj)


def _signing_bytes(att_without_sigs: dict) -> bytes:
    """Domain-tagged canonical bytes over the attestation MINUS its signatures — what each signer signs and
    every verifier re-derives. The domain tag prevents cross-protocol signature reuse."""
    return _ATT_DOMAIN + _canon(att_without_sigs)


class AttestationError(Exception):
    """Fail-closed: minting refused because a required control did not hold."""


def mint_remediation_attestation(
    *,
    finding_ref: str,
    bug_class: str,
    target: str,
    oracle_kind: str,
    rule_id: str,
    base_tree_digest: str,
    patched_tree_digest: str,
    diff_digest: str,
    vuln_gone: bool,
    original_evidence_ref: str = "",
    behavior_established: bool = False,
    test_cmd: str = "",
    deps_digest: str = "",
    suite_ran: bool = False,
    tests_passed: Optional[bool] = None,
    behavior_note: str = "",
    signers: "list[tuple[str, str]]" = (),   # [(key_id, private_key_b64), ...] — m-of-n
) -> dict:
    """Mint a signed attestation. FAIL-CLOSED: refuses unless ``vuln_gone`` is True; refuses to record the
    behavior axis as established unless the suite ran AND passed. Returns the attestation dict (with
    ``signatures``). Raises :class:`AttestationError` on any control that does not hold."""
    if not vuln_gone:
        raise AttestationError("refusing to attest: the VULN-GONE oracle did not clear over the patched tree")
    if behavior_established and not (suite_ran and tests_passed is True):
        raise AttestationError("refusing to record BEHAVIOR-PRESERVED as established: the real suite did not run+pass")
    if not (base_tree_digest and patched_tree_digest):
        raise AttestationError("refusing to attest: missing base/patched tree digests (the binding)")

    behavior = {
        "state": BEHAVIOR_ESTABLISHED if behavior_established else BEHAVIOR_NOT_ESTABLISHED,
        "test_cmd": test_cmd if behavior_established else "",
        "deps_digest": deps_digest if behavior_established else "",
        "suite_ran": bool(suite_ran and behavior_established),
        "tests_passed": bool(tests_passed) if behavior_established else None,
        "note": behavior_note or ("real suite passed" if behavior_established else
                                  "no runnable test suite / suite did not run — behavior NOT established"),
    }
    att: dict = {
        "schema": _ATT_SCHEMA,
        "finding": {"ref": finding_ref, "bug_class": bug_class, "target": target,
                    "original_evidence_ref": original_evidence_ref},
        "vuln_gone": {"cleared": True, "oracle_kind": oracle_kind, "rule_id": rule_id},
        "behavior_preserved": behavior,
        "binding": {"base_tree_digest": base_tree_digest, "patched_tree_digest": patched_tree_digest,
                    "diff_digest": diff_digest},
        "signatures": [],
    }
    body = {k: v for k, v in att.items() if k != "signatures"}
    msg = _signing_bytes(body)
    seen_keys: set[str] = set()
    for key_id, priv in (signers or ()):
        kid = str(key_id)
        if not kid or not priv or kid in seen_keys:
            continue
        seen_keys.add(kid)
        att["signatures"].append({"key_id": kid, "sig": sign(priv, msg)})
    if not att["signatures"]:
        raise AttestationError("refusing to mint an UNSIGNED attestation: at least one valid signer is required")
    return att


@dataclass(frozen=True)
class AttestationVerification:
    ok: bool
    tier: str
    authentic: bool = False
    signer_count: int = 0
    vuln_gone_reverified: Optional[bool] = None   # None = not re-run (no patched tree supplied)
    behavior_reverified: Optional[bool] = None
    behavior_established: bool = False
    bound: Optional[bool] = None                  # patched-tree digest matched (when a tree was supplied)
    reasons: tuple[str, ...] = field(default_factory=tuple)


def _fail(reason: str, **kw) -> AttestationVerification:
    return AttestationVerification(ok=False, tier=TIER_FAIL, reasons=(reason,), **kw)


def _authentic(att: dict, trust_root_pubkeys: "dict[str, str]", threshold: int) -> tuple[bool, int, str]:
    """Count DISTINCT key_ids whose signature over the domain-tagged body verifies against the trust root.
    m-of-n: authentic iff that count >= threshold."""
    body = {k: v for k, v in att.items() if k != "signatures"}
    msg = _signing_bytes(body)
    sigs = att.get("signatures")
    if not isinstance(sigs, list):    # malformed shape is NOT authentic — never a crash (crypto-notary MEDIUM)
        sigs = []
    good: set[str] = set()            # DISTINCT key_ids that verified
    seen_pubs: set[str] = set()       # …AND distinct public keys — one key can't satisfy m-of-n twice (LOW)
    for entry in sigs:
        if not isinstance(entry, dict):
            continue
        kid, sig = str(entry.get("key_id", "")), str(entry.get("sig", ""))
        pub = trust_root_pubkeys.get(kid)
        if not pub or not sig or kid in good or pub in seen_pubs:
            continue
        try:
            if verify_one(pub, msg, sig):
                good.add(kid)
                seen_pubs.add(pub)
        except Exception:  # noqa: BLE001 — malformed material is not authentic, never a crash
            continue
    thr = max(1, threshold)
    return (len(good) >= thr), len(good), (
        "" if len(good) >= thr else f"m-of-n not met: {len(good)} valid distinct signer(s) < threshold {thr}")


def verify_remediation_attestation(
    att: dict,
    *,
    trust_root_pubkeys: "dict[str, str]",
    threshold: int = 1,
    patched_root: Optional[str] = None,
    dep_cache: Optional[str] = None,
    reverify_suite: Optional[Callable[[str, str, Optional[str]], bool]] = None,
    max_files: int = 4000,
) -> AttestationVerification:
    """Verify an attestation, DEMOTE-ONLY and RE-EXECUTING. Checks (1) schema, (2) authenticity (m-of-n),
    (3) VULN-GONE holds — and, when ``patched_root`` is supplied, re-digests it (binding) and RE-RUNS the DAA
    rule (must clear), and (4) BEHAVIOR-PRESERVED — when established and a ``dep_cache`` + ``reverify_suite``
    are supplied, re-runs the suite; else re-checks the recorded binding. Any mismatch → TIER_FAIL. Zero trust
    in the minter: nothing is taken on faith that a supplied artifact lets us re-run."""
    if not isinstance(att, dict) or att.get("schema") != _ATT_SCHEMA:
        return _fail("not a vigil-remediation-attestation-v1")

    authentic, n, why = _authentic(att, trust_root_pubkeys or {}, threshold)
    if not authentic:
        return _fail(why or "not authentic", authentic=False, signer_count=n)

    vg = att.get("vuln_gone") or {}
    if not vg.get("cleared") is True:
        return _fail("attestation does not assert VULN-GONE", authentic=True, signer_count=n)

    beh = att.get("behavior_preserved") or {}
    behavior_established = (beh.get("state") == BEHAVIOR_ESTABLISHED)
    binding = att.get("binding") or {}
    finding = att.get("finding") or {}
    reasons: list[str] = []

    vuln_reverified: Optional[bool] = None
    bound: Optional[bool] = None
    if patched_root:
        # (a) binding: the supplied tree must be the one attested
        try:
            dig, _ = digest_tree(patched_root)
        except Exception as exc:  # noqa: BLE001
            return _fail(f"cannot digest patched_root: {type(exc).__name__}: {exc}", authentic=True, signer_count=n)
        bound = (dig == binding.get("patched_tree_digest"))
        if not bound:
            return _fail("patched tree digest does not match the attestation (binding broken)",
                         authentic=True, signer_count=n, bound=False)
        # (b) RE-RUN the VULN-GONE oracle (function-local framework import — offense path only)
        try:
            from ..codescan import verify_finding_cleared   # noqa: PLC0415 — FATAL-2: framework-backed, lazy
            res = verify_finding_cleared(root=patched_root, ref=finding.get("ref", ""), max_files=max_files)
            # verify_finding_cleared returns a dict {ref, rule_id, path, cleared, still_fires_at, ...}
            _cl = res.get("cleared") if isinstance(res, dict) else getattr(res, "cleared", False)
            vuln_reverified = bool(_cl)
        except Exception as exc:  # noqa: BLE001 — cannot re-run ⇒ cannot confirm ⇒ fail closed
            return _fail(f"could not re-run the VULN-GONE oracle: {type(exc).__name__}: {exc}",
                         authentic=True, signer_count=n, bound=True)
        if not vuln_reverified:
            return _fail("RE-RUN VULN-GONE oracle FIRES on the patched tree — the vulnerability is NOT gone",
                         authentic=True, signer_count=n, bound=True, vuln_gone_reverified=False)

    behavior_reverified: Optional[bool] = None
    if behavior_established and patched_root and dep_cache and reverify_suite is not None:
        try:
            behavior_reverified = bool(reverify_suite(patched_root, beh.get("test_cmd", ""), dep_cache))
        except Exception as exc:  # noqa: BLE001
            return _fail(f"could not re-run the behavior suite: {type(exc).__name__}: {exc}",
                         authentic=True, signer_count=n, bound=bound, vuln_gone_reverified=vuln_reverified,
                         behavior_established=True)
        if not behavior_reverified:
            return _fail("RE-RUN test suite FAILS on the patched tree — behavior NOT preserved",
                         authentic=True, signer_count=n, bound=bound, vuln_gone_reverified=vuln_reverified,
                         behavior_established=True, behavior_reverified=False)

    # tier: fully-sound needs BOTH axes re-verified; vuln-only when behavior is honestly not established;
    # unverified when we were not given the tree to re-run (signature+binding still checked).
    if patched_root and vuln_reverified:
        if behavior_established and behavior_reverified:
            tier = TIER_FULLY_SOUND
        elif behavior_established and not (dep_cache and reverify_suite):
            tier = TIER_VULN_ONLY
            reasons.append("behavior axis established in the attestation but not re-run here (no --dep-cache)")
        else:
            tier = TIER_VULN_ONLY
            if not behavior_established:
                reasons.append("behavior axis was honestly NOT established at mint (no runnable suite)")
    else:
        tier = TIER_UNVERIFIED
        reasons.append("no patched tree supplied — signature + binding verified, oracles NOT re-run")

    ok = authentic and (tier in (TIER_FULLY_SOUND, TIER_VULN_ONLY, TIER_UNVERIFIED))
    return AttestationVerification(
        ok=ok, tier=tier, authentic=True, signer_count=n,
        vuln_gone_reverified=vuln_reverified, behavior_reverified=behavior_reverified,
        behavior_established=behavior_established, bound=bound, reasons=tuple(reasons))


def attestation_digest(att: dict) -> str:
    """A content digest of the attestation body (minus signatures) — for anchoring / ledger entries."""
    return digest_payload({k: v for k, v in att.items() if k != "signatures"})
