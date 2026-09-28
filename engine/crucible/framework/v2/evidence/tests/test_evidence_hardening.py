"""PHASE 0.2 — evidence-verification hardening (operator review of certify.py).

Each test pins a protection the review found CLAIMED-but-not-ENFORCED, so the comment and the code now
agree. Grouped by the review's findings; the three highest-priority first.
"""
from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from framework.v2.entitlement.crypto import generate_keypair
from framework.v2.entitlement.models import AuthorizerKey, TrustRoot
from framework.v2.evidence import (
    OracleVersionStatus,
    VerificationTier,
    build_certificate,
    build_chain,
    sign_certificate,
    sign_head,
    verify_bundle,
    verify_certificate,
)
from framework.v2.evidence.certify import SUPPORTED_SCHEMA_VERSIONS, trust_root_fingerprint
from framework.v2.evidence.manifest import verify_manifest
from framework.v2.evidence.models import ArtifactRef, ReportClaim
from framework.v2.verify.adapter import FindingContext
from framework.v2.verify.confirmation import confirm_finding

_BASE = {"status": 200, "body": "No results found."}
_DIVERGENT = {"status": 200,
              "body": "id=1 name=alice role=user\nid=2 name=bob role=admin\nid=3 name=carol role=user"}


def _trust_root(threshold=2, n=3):
    keys = [generate_keypair() for _ in range(n)]
    tr = TrustRoot(schema_version=1, threshold=threshold, authorizers=[
        AuthorizerKey(key_id=f"gov-{i}", name=f"A{i}", public_key_b64=k.public_key_b64)
        for i, k in enumerate(keys)])
    signers = [(f"gov-{i}", k.private_key_b64) for i, k in enumerate(keys)]
    return tr, signers


def _finding(ref="error-based-sqli", engagement="acme"):
    ctx = FindingContext.from_http_responses(
        _BASE, _DIVERGENT, bug_class="error_based_sqli",
        discriminator={"dimensions": ["status", "length", "lexical"]})
    c = confirm_finding(finding={"bug_class": "error_based_sqli"}, context=ctx)
    return {"check_id": ref, "bug_class": "error_based_sqli",
            "confirmed_by": c.confirmed_by.value if c else "differential_response",
            "confidence": c.confidence if c else 0.9,
            "oracle_context": ctx.model_dump(mode="json")}, ctx.model_dump(mode="json")


# ============ #1 (CRITICAL) — a signed head is REQUIRED for BundleVerification.ok ==================

def test_unsigned_head_bundle_is_not_ok_even_with_signed_certs():
    tr, signers = _trust_root()
    f, ctx = _finding()
    cert = sign_certificate(build_certificate(f, engagement_slug="acme", seq=0), signers[:2])
    chain = build_chain([cert.certificate.cert_digest])
    # head=None: an internally-consistent UNSIGNED chain must NOT pass — the exact hole the review found.
    r = verify_bundle([cert], chain, None, contexts={"error-based-sqli": ctx}, trust_root=tr)
    assert r.chain_ok is True          # the unsigned chain is internally consistent...
    assert r.head_anchored is False    # ...but it is NOT anchored by a governance-signed head
    assert r.ok is False               # so the bundle is NOT sound
    # the same bundle WITH a valid signed head verifies
    head = sign_head(chain, engagement_slug="acme", signers=signers[:2])
    r2 = verify_bundle([cert], chain, head, contexts={"error-based-sqli": ctx}, trust_root=tr)
    assert r2.head_anchored is True and r2.ok is True


# ============ #2 — oracle-version POLICY: skew DOWNGRADES the tier, is never a bare SOUND ==========

def test_stale_oracle_version_downgrades_tier_not_bare_sound():
    """A cert minted under oracle vA, verified when the oracle is now vB, must NOT report a bare SOUND: the
    crypto ``ok`` stays True (authentic + reproduces under today's oracle, so old certs are not
    mass-invalidated), but the TIER downgrades to SOUND_ORACLE_VERSION_CHANGED and ``fully_sound`` is False."""
    tr, signers = _trust_root()
    f, ctx = _finding()
    cert = build_certificate(f, engagement_slug="acme", seq=0)
    minted_ov = cert.oracle_version
    assert minted_ov  # the mint stamped a real version over the firing oracle
    # a cert minted under a DIFFERENT (older) oracle body: stamp a version that differs from the current one,
    # then sign it — the signature authenticates the (skewed) stamp, so this is a genuine version-skewed cert.
    forged = cert.model_copy(update={"oracle_version": "sha256:0000deadbeef"})
    signed = sign_certificate(forged, signers[:2])
    v = verify_certificate(signed, oracle_context=ctx, trust_root=tr)
    # the mismatch is DETECTED + surfaced LOUDLY as first-class fields (not buried in reason):
    assert v.oracle_version_status is OracleVersionStatus.CHANGED
    assert v.stamped_oracle_version == "sha256:0000deadbeef"
    assert v.current_oracle_version == minted_ov and v.current_oracle_version != v.stamped_oracle_version
    assert v.oracle_version_current is False           # back-compat bool still flags it
    # crypto soundness holds (reproduces under the current oracle) → not mass-invalidated ...
    assert v.reproduced is True and v.ok is True
    # ... but it is NOT a bare SOUND: the government-facing tier is downgraded, fully_sound is False.
    assert v.tier is VerificationTier.SOUND_ORACLE_VERSION_CHANGED
    assert v.fully_sound is False
    assert "ORACLE-VERSION CHANGED" in v.reason


def test_same_oracle_version_is_fully_sound():
    """A cert whose stamped oracle version equals the current oracle body verifies as a bare SOUND / fully
    sound — the re-execution ran the SAME procedure the issuer signed."""
    tr, signers = _trust_root()
    f, ctx = _finding()
    signed = sign_certificate(build_certificate(f, engagement_slug="acme", seq=0), signers[:2])
    v = verify_certificate(signed, oracle_context=ctx, trust_root=tr)
    assert v.oracle_version_status is OracleVersionStatus.MATCH
    assert v.stamped_oracle_version == v.current_oracle_version != ""
    assert v.ok is True and v.fully_sound is True
    assert v.tier is VerificationTier.SOUND
    assert v.oracle_version_current is True


def test_empty_oracle_version_reported_unconfirmed_not_a_pass():
    """A legacy / source-less cert with NO stamped oracle version is reported HONESTLY as UNCONFIRMED — crypto
    ``ok`` stays True (not mass-invalidated), but it is NOT a bare SOUND / fully sound (currency unconfirmed)."""
    tr, signers = _trust_root()
    f, ctx = _finding()
    cert = build_certificate(f, engagement_slug="acme", seq=0)
    empty = cert.model_copy(update={"oracle_version": ""})   # a cert minted before/without a version stamp
    signed = sign_certificate(empty, signers[:2])
    v = verify_certificate(signed, oracle_context=ctx, trust_root=tr)
    assert v.oracle_version_status is OracleVersionStatus.UNCONFIRMED
    assert v.stamped_oracle_version == ""
    assert v.ok is True                                  # authentic + reproduces → crypto-sound, not invalidated
    assert v.fully_sound is False                        # ... but currency is NOT confirmed → not a full pass
    assert v.tier is VerificationTier.SOUND_ORACLE_VERSION_UNCONFIRMED
    assert v.oracle_version_current is True              # back-compat: empty is not the CHANGED case


def test_oracle_version_verification_is_deterministic():
    """Re-running verification over the same version-skewed cert yields an IDENTICAL result (tier, status, both
    version strings, serialized fields) — FATAL-2 determinism.

    NOTE (AUDIT-B6): this asserts determinism of the VERIFICATION, in one process. It cannot and does not
    catch a non-deterministic ``oracle_version`` itself — both calls sit behind the same ``@lru_cache`` and
    would return the same wrong value. The cross-PROCESS assertion that does catch it is
    ``test_B6_oracle_version_is_deterministic_across_processes`` below."""
    tr, signers = _trust_root()
    f, ctx = _finding()
    cert = build_certificate(f, engagement_slug="acme", seq=0)
    forged = cert.model_copy(update={"oracle_version": "sha256:0000deadbeef"})
    signed = sign_certificate(forged, signers[:2])
    v1 = verify_certificate(signed, oracle_context=ctx, trust_root=tr)
    v2 = verify_certificate(signed, oracle_context=ctx, trust_root=tr)
    assert v1.model_dump(mode="json") == v2.model_dump(mode="json")
    assert v1.tier is v2.tier is VerificationTier.SOUND_ORACLE_VERSION_CHANGED
    assert (v1.oracle_version_status, v1.stamped_oracle_version, v1.current_oracle_version) == \
           (v2.oracle_version_status, v2.stamped_oracle_version, v2.current_oracle_version)


def test_version_skewed_bundle_is_crypto_ok_but_not_fully_sound():
    """At bundle scope: a version-skewed but crypto-sound bundle has ``ok`` True (anti-rollback + anchoring
    intact) yet ``fully_sound`` False, so a caller gating on the government re-execution guarantee refuses it
    while a caller gating on crypto soundness (the legacy ``ok``) is unaffected."""
    tr, signers = _trust_root()
    f, ctx = _finding()
    cert = build_certificate(f, engagement_slug="acme", seq=0)
    forged = cert.model_copy(update={"oracle_version": "sha256:0000deadbeef"})
    signed = sign_certificate(forged, signers[:2])
    chain = build_chain([signed.certificate.cert_digest])
    head = sign_head(chain, engagement_slug="acme", signers=signers[:2])
    b = verify_bundle([signed], chain, head, contexts={"error-based-sqli": ctx}, trust_root=tr)
    assert b.ok is True and b.fully_sound is False
    assert b.certificate_results[0].tier is VerificationTier.SOUND_ORACLE_VERSION_CHANGED


# ============ #3 — authenticated freshness: three distinct states ==================================

def test_freshness_three_states():
    tr, signers = _trust_root()
    f, ctx = _finding()
    # a cert with a 60s TTL
    cert = build_certificate({**f, "freshness_ttl_seconds": 60}, engagement_slug="acme", seq=0)
    signed = sign_certificate(cert, signers[:2])
    # (a) no authenticated time → freshness NOT asserted
    v0 = verify_certificate(signed, oracle_context=ctx, trust_root=tr)
    assert v0.currently_fresh is None and v0.ok is True
    # (b) anchored, within TTL → fresh
    v1 = verify_certificate(signed, oracle_context=ctx, trust_root=tr, now=1000, anchor_gen_time=990)
    assert v1.currently_fresh is True and v1.ok is True
    # (c) anchored, beyond TTL → STALE, but authenticity/soundness SURVIVE expiration
    v2 = verify_certificate(signed, oracle_context=ctx, trust_root=tr, now=100000, anchor_gen_time=990)
    assert v2.currently_fresh is False and v2.ok is True and v2.authentic is True


def test_zero_ttl_is_non_expiring_once_anchored():
    tr, signers = _trust_root()
    f, ctx = _finding()
    signed = sign_certificate(build_certificate(f, engagement_slug="acme", seq=0), signers[:2])  # ttl 0
    v = verify_certificate(signed, oracle_context=ctx, trust_root=tr, now=10**9, anchor_gen_time=0)
    assert v.currently_fresh is True


# ============ #4 — trust-root fingerprint enforced at the entry point ==============================

def test_trust_root_pin_refuses_a_swapped_trust_root():
    tr, signers = _trust_root()
    f, ctx = _finding()
    signed = sign_certificate(build_certificate(f, engagement_slug="acme", seq=0), signers[:2])
    good_fp = trust_root_fingerprint(tr)
    # correct pin → authentic
    ok = verify_certificate(signed, oracle_context=ctx, trust_root=tr, expected_trust_root_fingerprint=good_fp)
    assert ok.authentic is True and ok.ok is True
    # an ATTACKER-supplied trust root (fresh keys) that validly signs a forged cert...
    atr, asigners = _trust_root()
    forged = sign_certificate(build_certificate(f, engagement_slug="acme", seq=0), asigners[:2])
    # ...its own signatures verify against ITS trust root, but the out-of-band pin refuses it:
    bad = verify_certificate(forged, oracle_context=ctx, trust_root=atr,
                             expected_trust_root_fingerprint=good_fp)
    assert bad.authentic is False and bad.ok is False and "PIN MISMATCH" in bad.reason


# ============ #5 — unknown schema version fails closed ============================================

def test_unknown_schema_version_fails_closed():
    tr, signers = _trust_root()
    f, ctx = _finding()
    cert = build_certificate(f, engagement_slug="acme", seq=0)
    forged = cert.model_copy(update={"schema_version": 999})
    signed = sign_certificate(forged, signers[:2])
    v = verify_certificate(signed, oracle_context=ctx, trust_root=tr)
    assert v.schema_ok is False and v.ok is False
    assert 999 not in SUPPORTED_SCHEMA_VERSIONS


# ============ #6 — render_as is a closed label set ================================================

def test_render_as_rejects_unknown_label():
    ReportClaim(sentence="x", bug_class="error_based_sqli", render_as="fact")               # ok
    ReportClaim(sentence="x", render_as="analyst-commentary")                            # ok
    for bad in ("verified", "machine-fact", "FACT", ""):
        with pytest.raises(ValidationError):
            ReportClaim(sentence="x", render_as=bad)


# ============ #7 — duplicate finding_ref bundle refused ===========================================

def test_duplicate_finding_ref_bundle_refused():
    tr, signers = _trust_root()
    f, ctx = _finding(ref="dup")
    c0 = sign_certificate(build_certificate({**f, "seq": 0}, engagement_slug="acme", seq=0), signers[:2])
    c1 = sign_certificate(build_certificate({**f, "confidence": 0.8}, engagement_slug="acme", seq=1), signers[:2])
    chain = build_chain([c0.certificate.cert_digest, c1.certificate.cert_digest])
    head = sign_head(chain, engagement_slug="acme", signers=signers[:2])
    r = verify_bundle([c0, c1], chain, head, contexts={"dup": ctx}, trust_root=tr)
    assert r.refs_unique is False and r.ok is False and "DUPLICATE finding_ref" in r.chain_note


# ============ #8 — cross-engagement bundle refused ================================================

def test_cross_engagement_bundle_refused():
    tr, signers = _trust_root()
    fa, ca = _finding(ref="a", engagement="acme")
    fb, cb = _finding(ref="b", engagement="acme")
    c0 = sign_certificate(build_certificate(fa, engagement_slug="acme", seq=0), signers[:2])
    c1 = sign_certificate(build_certificate(fb, engagement_slug="OTHER", seq=1), signers[:2])  # different engagement
    chain = build_chain([c0.certificate.cert_digest, c1.certificate.cert_digest])
    head = sign_head(chain, engagement_slug="acme", signers=signers[:2])
    r = verify_bundle([c0, c1], chain, head, contexts={"a": ca, "b": cb}, trust_root=tr)
    assert r.single_engagement is False and r.ok is False and "CROSS-ENGAGEMENT" in r.chain_note


# ============ #9 — artifact symlink / non-regular refused ==========================================

def test_manifest_refuses_a_symlinked_artifact(tmp_path):
    root = tmp_path / "ev"
    root.mkdir()
    (root / "real.txt").write_bytes(b"hello")
    secret = tmp_path / "secret.txt"
    secret.write_bytes(b"SECRET-OUTSIDE-ROOT")
    # (a) a symlink pointing OUTSIDE the root — caught by the confinement resolve ("escapes root").
    (root / "out.txt").symlink_to(secret)
    ro = verify_manifest([ArtifactRef(path="out.txt", sha256="0" * 64, size=19)], root=root)
    assert ro and ro[0][1] is False and "escape" in ro[0][2].lower()
    # (b) a symlink pointing INSIDE the root (to a real file) — resolves within root, so it passes the
    #     confinement check; the explicit is_symlink refusal is the load-bearing defense here.
    (root / "in.txt").symlink_to(root / "real.txt")
    ri = verify_manifest([ArtifactRef(path="in.txt", sha256="0" * 64, size=5)], root=root)
    assert ri and ri[0][1] is False and "symlink" in ri[0][2].lower()


# ============ tool_version + freshness_ttl round-trip + byte-identity when absent ==================

def test_tool_version_and_freshness_signed_and_absent_is_byte_identical():
    from framework.v2.evidence.canonical import evidence_signing_bytes
    tr, signers = _trust_root()
    f, ctx = _finding()
    # a cert WITHOUT the new fields serialises byte-identically to a cert that never had them
    plain = build_certificate(f, engagement_slug="acme", seq=0)
    assert "tool_version" not in plain.model_dump() and "freshness_ttl_seconds" not in plain.model_dump()
    # a cert WITH the fields carries them in the SIGNED bytes
    stamped = build_certificate({**f, "tool_version": "nmap 7.99", "freshness_ttl_seconds": 3600},
                                engagement_slug="acme", seq=0)
    d = stamped.model_dump()
    assert d["tool_version"] == "nmap 7.99" and d["freshness_ttl_seconds"] == 3600
    # the signature covers them: a signed stamped cert verifies, and tampering the tool_version breaks it
    signed = sign_certificate(stamped, signers[:2])
    assert verify_certificate(signed, oracle_context=ctx, trust_root=tr).ok is True
    tampered = signed.model_copy(update={"certificate": stamped.model_copy(update={"tool_version": "evil"})})
    assert verify_certificate(tampered, oracle_context=ctx, trust_root=tr).authentic is False


# ---------------------------------------------------------------------------
# AUDIT-B6 — oracle_version determinism ACROSS PROCESSES.
#
# The in-process test above is structurally incapable of catching a
# non-deterministic version identity, and two real defects hid behind exactly that
# blind spot for every one of the 47 kinds:
#
#   * `oracles._CMD_ALT` and `oracles._NOSQL_OP_ALT` were built by iterating a SET,
#     baking PYTHONHASHSEED into the compiled pattern string that `_canon` hashes.
#     Measured: FIVE distinct hashes for `command_injection_breakout` and for
#     `nosql_injection_breakout` across PYTHONHASHSEED 0/1/2/42/12345.
#   * `oracles._SECRET_RECOGNIZERS` holds LAMBDAS and `_canon` fell through to
#     `repr(<function <lambda> at 0x…>)` — a HEAP ADDRESS. Measured:
#     `secret_credential_validity` differed in ALL TEN of ten processes, including
#     between two runs at the SAME pinned seed. Every certificate of that kind was
#     therefore permanently "oracle_version CHANGED since mint" and could never
#     verify fully-sound.
#
# This test spawns REAL subprocesses at DIFFERENT PYTHONHASHSEEDs and compares all
# 47 kinds. It is the only shape that can fail on either defect.
# ---------------------------------------------------------------------------

_VERSION_DUMP = (
    "import json;"
    "from framework.v2.verify.models import OracleKind;"
    "from framework.v2.verify.oracle_version import oracle_version;"
    "print(json.dumps({k.value: oracle_version(k) for k in OracleKind}, sort_keys=True))"
)


def test_B6_oracle_version_is_deterministic_across_processes():
    """CRUCIBLE invariant 6, for the VERSION IDENTITY, asserted where it can fail."""
    import json as _json
    import os as _os
    import subprocess as _subprocess
    import sys as _sys

    def dump(seed: str) -> dict[str, str]:
        env = dict(_os.environ, PYTHONHASHSEED=seed)
        r = _subprocess.run([_sys.executable, "-c", _VERSION_DUMP],
                            capture_output=True, text=True, env=env, timeout=300)
        assert r.returncode == 0, r.stderr[-3000:]
        return _json.loads(r.stdout)

    # two runs at the SAME seed (catches a heap address) + different seeds (catches
    # set-iteration order baked into a pattern string).
    runs = {f"seed={s} run={r}": dump(s) for s in ("0", "1", "12345") for r in ("a", "b")}
    kinds = sorted(next(iter(runs.values())))
    assert len(kinds) >= 47, f"expected every OracleKind, got {len(kinds)}"

    drift = {k: sorted({d[k] for d in runs.values()}) for k in kinds
             if len({d[k] for d in runs.values()}) > 1}
    assert not drift, (
        "oracle_version is NOT deterministic across processes — every certificate of "
        f"these kinds is permanently 'version CHANGED since mint': "
        + ", ".join(f"{k} ({len(v)} distinct)" for k, v in drift.items()))

    # non-vacuity: the subprocess really did compute real versions, not empty strings
    first = next(iter(runs.values()))
    assert all(first[k].startswith("sha256:") for k in kinds), first
