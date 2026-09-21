"""The shared engagement-authority core (vigil_core.authority).

This is the primitive the SOVEREIGN plane uses to OWNER-SIGN an engagement authority WITHOUT importing
``framework`` (the two-env boundary, FATAL-2), which the OFFENSE plane then verifies byte-for-byte. These
tests lock:

* the canonical signing bytes are domain-tagged and format-stable (a golden digest — any change to the
  canonical form, which would invalidate every existing authority signature, fails here loudly);
* an owner sign -> verify round-trip succeeds, and a tampered scope / window / destructive-flag FAILS
  (fail-closed, never a partial-trust default);
* the window validator refuses a non-positive validity window;
* signing pulls in NO ``framework`` / ``strix`` — the property that makes it usable in a sovereign venv
  where those packages are not installed at all.

The cross-plane byte-identity with ``framework.v2.authority`` (the re-export) is proven in the offense
leg by ``framework/v2/authority/tests/test_shared_core_reexport.py``.
"""

from __future__ import annotations

import hashlib
import subprocess
import sys
from datetime import datetime, timedelta, timezone

import pytest

from vigil_core import AuthorizerKey, TrustRoot, generate_keypair
from vigil_core.authority import (
    EngagementAuthority, SignedAuthority, TargetEnvironment, authority_signing_bytes,
    sign_engagement_authority, verify_engagement_authority,
)

_TS = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)


def _doc(**over) -> EngagementAuthority:
    base = dict(
        engagement_slug="apme-cm", environment=TargetEnvironment.STAGING, scope=["apme.cm"],
        not_before=_TS, not_after=_TS + timedelta(hours=8), issued_by="owner",
    )
    base.update(over)
    return EngagementAuthority(**base)


def _owner_root():
    kp = generate_keypair()
    tr = TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="owner", name="owner", public_key_b64=kp.public_key_b64)])
    return kp, tr


def test_signing_bytes_are_domain_tagged_and_format_stable():
    """A GOLDEN vector: the exact canonical form for a fixed document. Locking it means a change to the
    domain tag or the JSON canonicalisation (which silently invalidates every prior authority signature)
    cannot land unnoticed."""
    doc = _doc(engagement_slug="golden", scope=["a.example", "b.example"],
               not_after=_TS + timedelta(hours=8), note="")
    b = authority_signing_bytes(doc)
    assert b.startswith(b"crucible-authority-v1\x00")
    # sorted keys, compact separators, ISO-Z datetimes — the entitlement layer's canonical form.
    assert b"\"environment\":\"staging\"" in b and b"\"not_after\":\"2026-01-02T11:04:05Z\"" in b
    # VF-2b (Wave 1.2) + DNS-OOB (Wave 1) + the OOB replay-policy pair (Wave 1 DNS-OOB soundness fix): the
    # DEDICATED OOB fields (the four pins/domains default "", plus oob_ttl_seconds/oob_skew_seconds — the
    # owner-signed receipt TTL DURATION + skew) are part of the canonical form now — a DELIBERATE, reviewed
    # change. It re-hashes the golden vector (below) and means an authority signed BEFORE this change re-verifies
    # only after re-signing. _AUTHORITY_DOMAIN is deliberately unchanged (no domain bump): the schema grew
    # additively, both planes agree by construction, and short-window authorities re-sign fine. The TTL/skew
    # duration bounding a receipt-bearing OOB hit's replay window is OWNER-SIGNED here (out-of-band), so a
    # producer cannot widen it. The golden pin still guards against any FURTHER unreviewed drift.
    assert b"\"oob_collector_pubkey\":\"\"" in b and b"\"oob_relay_host\":\"\"" in b
    assert b"\"oob_dns_domain\":\"\"" in b and b"\"oob_dns_collector_pubkey\":\"\"" in b
    assert b"\"oob_ttl_seconds\":300.0" in b and b"\"oob_skew_seconds\":5.0" in b
    assert hashlib.sha256(b).hexdigest() == (
        "c22cb3b2b3e7024517f72054acbd3cdb6f167b1fb2a1ae478cb1ef7b1549376e"
    ), "authority canonical form changed — this invalidates every existing signature; bump + migrate"


def test_owner_sign_then_verify_round_trip():
    kp, tr = _owner_root()
    signed = sign_engagement_authority(_doc(), {"owner": kp.private_key_b64})
    assert isinstance(signed, SignedAuthority) and len(signed.signatures) == 1
    ok, reason = verify_engagement_authority(signed, tr)
    assert ok, reason


@pytest.mark.parametrize("mutation", [
    {"scope": ["evil.example"]},                     # scope widened/redirected
    {"not_after": _TS + timedelta(days=3650)},       # window stretched
    {"allow_destructive": True},                     # destructive flag flipped
    {"environment": TargetEnvironment.LIVE},         # environment escalated
    {"max_actions": 10_000_000},                     # budget inflated
])
def test_tamper_after_signing_fails_verification(mutation):
    """Any post-signing change to the document must fail verification — the whole point of signing the
    scope/window/flags. Fail-closed: verify returns (False, reason), it does not raise-and-pass."""
    kp, tr = _owner_root()
    signed = sign_engagement_authority(_doc(), {"owner": kp.private_key_b64})
    tampered = signed.model_copy(update={"document": signed.document.model_copy(update=mutation)})
    ok, reason = verify_engagement_authority(tampered, tr)
    assert not ok, f"tampering with {mutation} still verified — FAIL-OPEN: {reason}"


def test_wrong_owner_key_does_not_verify():
    """A signature by a key that is not in the trust root does not satisfy the threshold."""
    kp, tr = _owner_root()
    other = generate_keypair()
    signed = sign_engagement_authority(_doc(), {"owner": other.private_key_b64})
    ok, reason = verify_engagement_authority(signed, tr)
    assert not ok, reason


def test_duplicate_pubkey_trust_root_is_rejected_not_collapsed():
    """A trust root with duplicate authorizer PUBLIC KEYS under distinct key_ids would let a single
    keyholder satisfy an m-of-n threshold. TrustRoot deliberately permits it (the witness subsystem needs
    it), so this live-attack-credential verifier rejects it at its OWN layer — like vigil_core.delegation.
    Reproduces red-pen ADVISORY #1."""
    kp = generate_keypair()
    dup = TrustRoot(threshold=2, authorizers=[
        AuthorizerKey(key_id="a", name="a", public_key_b64=kp.public_key_b64),
        AuthorizerKey(key_id="b", name="b", public_key_b64=kp.public_key_b64),  # SAME pubkey
    ])
    signed = sign_engagement_authority(_doc(), {"a": kp.private_key_b64, "b": kp.private_key_b64})
    ok, reason = verify_engagement_authority(signed, dup)
    assert not ok and "duplicate authorizer public keys" in reason, reason


def test_malformed_signature_returns_false_not_raises():
    """Adversary-influenced signature bytes (not valid base64 / wrong length) must be a fail-closed
    (False, reason), never an uncaught IntegrityError that crashes the caller. Reproduces red-pen
    ADVISORY #2 — the contract is 'never raises'."""
    kp, tr = _owner_root()
    signed = sign_engagement_authority(_doc(), {"owner": kp.private_key_b64})
    broken = signed.model_copy(update={
        "signatures": [signed.signatures[0].model_copy(update={"signature_b64": "!!!not-base64!!!"})]})
    ok, reason = verify_engagement_authority(broken, tr)   # must not raise
    assert not ok and reason, reason


def test_window_validator_refuses_nonpositive_window():
    with pytest.raises(Exception):
        _doc(not_after=_TS)                          # not_after == not_before
    with pytest.raises(Exception):
        _doc(not_after=_TS - timedelta(hours=1))     # not_after < not_before


def test_signing_imports_no_framework_or_strix():
    """FATAL-2: importing vigil_core.authority and signing must not pull framework/strix into
    sys.modules — the property that lets the sovereign plane sign where those packages are not installed.
    Run in a subprocess so an ambient framework import elsewhere in this session cannot mask a leak."""
    prog = (
        "import sys\n"
        "import vigil_core.authority as A\n"
        "from vigil_core import generate_keypair\n"
        "from datetime import datetime, timezone, timedelta\n"
        "ts = datetime(2026,1,1,tzinfo=timezone.utc)\n"
        "doc = A.EngagementAuthority(engagement_slug='s', environment=A.TargetEnvironment.STAGING,\n"
        "    scope=['apme.cm'], not_before=ts, not_after=ts+timedelta(hours=1))\n"
        "A.sign_engagement_authority(doc, {'owner': generate_keypair().private_key_b64})\n"
        "assert 'framework' not in sys.modules, 'framework leaked'\n"
        "assert 'strix' not in sys.modules, 'strix leaked'\n"
        "print('ok')\n"
    )
    proc = subprocess.run([sys.executable, "-c", prog], capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip().endswith("ok")
