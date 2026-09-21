"""Offline re-verification of OOB (VF-2b) FACTs through the REAL serialized reverify path.

This is the regression suite for the SYSTEMIC soundness gap the red-pen found: the offline reverify path
(``reverify.reverify_document`` / ``reverify_finding`` / the ``framework.v2 verify`` CLI) re-checked OOB FACTs
TOKEN-ONLY — the VF-2b collector receipt was never re-verified offline, so a VF-2b FACT silently dropped to
VF-2a on re-verify (fail-open). These tests drive the SAME serialized path a real re-verify uses (NOT a
hand-passed live pinned verifier), and prove:

  (a) a VF-2b HTTP or DNS FACT re-verified with NO authority pin ⇒ REFUSED (fail-closed, not token-only);
  (b) WITH the out-of-band pin from the SIGNED authority ⇒ confirmed;
  (c) a genuine VF-2a FACT (no collector receipt) ⇒ still token-only confirmed (byte-identical);
  (d) a stale/replayed receipt (received_at outside the authority-bound window) ⇒ EXPIRED/REPLAY, offline;
  (e) a producer-WIDENED window / huge skew in the retained ctx ⇒ still refused (authority TTL wins);
  (f) a receipt-bearing hit with the mint window DROPPED ⇒ refused;
  plus the CLI (`python3 -m framework.v2 verify <report> --authority ...`) end to end over a SIGNED authority.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from vigil_core import generate_keypair
from vigil_core.authority import EngagementAuthority, TargetEnvironment

from framework.v2.verify.adapter import FindingContext
from framework.v2.verify.oob import OOBHit, sign_oob_receipt
from framework.v2.verify import reverify
from framework.v2.verify.reverify import reverify_document, reverify_finding, verifier_from_authority

_NOW = datetime(2026, 6, 1, tzinfo=timezone.utc)
_TTL = 300.0
_SKEW = 5.0


def _authority(*, http_pin: str = "", dns_pin: str = "", ttl: float = _TTL, skew: float = _SKEW,
               slug: str = "eng") -> EngagementAuthority:
    return EngagementAuthority(
        engagement_slug=slug, environment=TargetEnvironment.TWIN, scope=["*.example.com"],
        not_before=_NOW - timedelta(hours=1), not_after=_NOW + timedelta(hours=1),
        oob_collector_pubkey=http_pin, oob_dns_collector_pubkey=dns_pin,
        oob_ttl_seconds=ttl, oob_skew_seconds=skew)


def _signed_hit(kp, *, method: str, token: str, received_at: float) -> OOBHit:
    path = (f"{token}.oob.op.example" if method == "DNS" else "/" + token)
    hit = OOBHit(token=token, method=method, path=path, query="", client_ip="10.0.0.9",
                 received_at=received_at)
    hit.collector_sig = sign_oob_receipt(kp.private_key_b64, hit)
    return hit


def _finding(kp, *, method: str, received_at: float, issued_at: float | None,
             expires_at: float | None = None, skew: float | None = None) -> dict:
    token = "t" * 32
    hit = _signed_hit(kp, method=method, token=token, received_at=received_at)
    ctx = FindingContext.from_oob([hit], bug_class="ssrf", expected_token=token,
                                  issued_at=issued_at, expires_at=expires_at, skew=skew)
    return {"bug_class": "ssrf", "check_id": f"{method.lower()}-oob",
            "oracle_context": ctx.model_dump(mode="json"),
            "confirmed_by": "oob_callback", "confidence": 0.95}


def _vf2a_finding() -> dict:
    """A genuine VF-2a finding: a token-matched hit with NO collector receipt."""
    token = "u" * 32
    hit = OOBHit(token=token, method="GET", path="/" + token, client_ip="127.0.0.1", received_at=_NOW.timestamp())
    ctx = FindingContext.from_oob([hit], bug_class="ssrf", expected_token=token)
    return {"bug_class": "ssrf", "check_id": "vf2a", "oracle_context": ctx.model_dump(mode="json"),
            "confirmed_by": "oob_callback", "confidence": 0.95}


# ------------------------------------------------------------------ (a) no pin ⇒ fail-closed (HTTP + DNS)
def test_a_vf2b_reverify_without_pin_is_failclosed_http_and_dns() -> None:
    kp = generate_keypair()
    ra = _NOW.timestamp() + 10.0
    for method in ("GET", "DNS"):
        f = _finding(kp, method=method, received_at=ra, issued_at=_NOW.timestamp())
        # NO verifier (no authority material) ⇒ the receipt cannot be re-verified ⇒ REFUSED, NOT token-only.
        r = reverify_finding(f)
        assert not r.reproduced, f"{method} VF-2b must fail closed offline without a pin"


# ------------------------------------------------------------------ (b) with the authority pin ⇒ confirmed
def test_b_vf2b_reverify_with_authority_pin_confirms_http_and_dns() -> None:
    kp = generate_keypair()
    ra = _NOW.timestamp() + 10.0
    http = _finding(kp, method="GET", received_at=ra, issued_at=_NOW.timestamp())
    dns = _finding(kp, method="DNS", received_at=ra, issued_at=_NOW.timestamp())
    vh = verifier_from_authority(_authority(http_pin=kp.public_key_b64))
    vd = verifier_from_authority(_authority(dns_pin=kp.public_key_b64))
    rh = reverify_finding(http, verifier=vh)
    rd = reverify_finding(dns, verifier=vd)
    assert rh.reproduced and rh.confirmed_by == "oob_callback"
    assert rd.reproduced and rd.confirmed_by == "oob_callback"
    # channel-crossed pins do NOT confirm (an HTTP pin cannot verify a DNS receipt and vice-versa).
    assert not reverify_finding(dns, verifier=vh).reproduced
    assert not reverify_finding(http, verifier=vd).reproduced


# ------------------------------------------------------------------ (c) genuine VF-2a ⇒ still token-only
def test_c_vf2a_finding_still_confirms_token_only() -> None:
    f = _vf2a_finding()
    # No receipt on the hit ⇒ genuine VF-2a ⇒ confirms with NO authority material (byte-identical behaviour):
    # this is the OTHER half of the fix — 'no receipt ⇒ VF-2a by design', distinct from a fail-open drop.
    r = reverify_finding(f)
    assert r.reproduced and r.confirmed_by == "oob_callback"
    # Anti-downgrade: WHEN the authority pins a collector key (the engagement is VF-2b), a no-receipt hit is a
    # stripped-receipt suspect and fails CLOSED — a producer cannot downgrade a VF-2b FACT to token-only.
    r2 = reverify_finding(f, verifier=verifier_from_authority(_authority(http_pin=generate_keypair().public_key_b64)))
    assert not r2.reproduced


# ------------------------------------------------------------------ (d) stale receipt ⇒ EXPIRED/REPLAY offline
def test_d_stale_receipt_is_replay_offline() -> None:
    kp = generate_keypair()
    stale = _NOW.timestamp() + _TTL + 3600.0
    f = _finding(kp, method="DNS", received_at=stale, issued_at=_NOW.timestamp())
    r = reverify_finding(f, verifier=verifier_from_authority(_authority(dns_pin=kp.public_key_b64)))
    assert not r.reproduced, "a receipt outside the authority-bound window must not re-confirm"


# ------------------------------------------------------------------ (e) producer-widened window ⇒ still refused
def test_e_producer_widened_window_is_ignored_offline() -> None:
    kp = generate_keypair()
    stale = _NOW.timestamp() + 100_000.0
    # The producer bakes a hugely-widened expires_at + skew into the RETAINED ctx. On the VF-2b path these are
    # IGNORED — the authority TTL (300s) wins — so the stale receipt is still REPLAY.
    f = _finding(kp, method="DNS", received_at=stale, issued_at=_NOW.timestamp(),
                 expires_at=stale + 1.0, skew=1_000_000.0)
    r = reverify_finding(f, verifier=verifier_from_authority(_authority(dns_pin=kp.public_key_b64)))
    assert not r.reproduced, "a producer-widened window must not re-confirm a stale receipt"
    # A huge AUTHORITY ttl WOULD admit it (owner's signed choice) — proving the duration is authority-sourced.
    r2 = reverify_finding(f, verifier=verifier_from_authority(_authority(dns_pin=kp.public_key_b64, ttl=1_000_000.0)))
    assert r2.reproduced


# ------------------------------------------------------------------ (f) window dropped ⇒ refused
def test_f_receipt_with_window_dropped_is_refused() -> None:
    kp = generate_keypair()
    f = _finding(kp, method="DNS", received_at=_NOW.timestamp(), issued_at=None)  # NO mint anchor
    r = reverify_finding(f, verifier=verifier_from_authority(_authority(dns_pin=kp.public_key_b64)))
    assert not r.reproduced, "a receipt-bearing hit with no window is replayable ⇒ refuse"


# ------------------------------------------------------------------ reverify_document + tamper check
def test_document_reverify_threads_the_verifier() -> None:
    kp = generate_keypair()
    ra = _NOW.timestamp() + 5.0
    report = {"active_findings": [
        _finding(kp, method="GET", received_at=ra, issued_at=_NOW.timestamp()),
        _vf2a_finding(),
    ]}
    v = verifier_from_authority(_authority(http_pin=kp.public_key_b64))
    with_pin = reverify_document(report, verifier=v)
    # WITH the pin: the VF-2b finding reproduces; the VF-2a one fails closed (anti-downgrade under a VF-2b authority).
    assert with_pin[0].reproduced and not with_pin[1].reproduced
    # WITHOUT the pin: the VF-2b finding fails closed (no key to verify the receipt) while the VF-2a confirms.
    without = reverify_document(report)
    assert not without[0].reproduced and without[1].reproduced


# ------------------------------------------------------------------ CLI end-to-end over a SIGNED authority
def test_cli_reverify_with_signed_authority(tmp_path: Path) -> None:
    from framework.v2.authority.signing import sign_authority
    from framework.v2.authority.store import save_signed_authority, write_authority_root
    from framework.v2.entitlement import provision

    kp = generate_keypair()
    ak, priv = provision.new_authorizer("owner", "Owner")
    trust_root = provision.build_trust_root([ak], 1)
    doc = _authority(http_pin=kp.public_key_b64)
    signed = sign_authority(doc, {"owner": priv})

    auth_file = tmp_path / "eng.authority.json"
    save_signed_authority(signed, auth_file)
    root_file = tmp_path / "authority-root.json"
    write_authority_root(trust_root, root_file)

    report = {"active_findings": [_finding(kp, method="GET",
                                           received_at=_NOW.timestamp() + 5.0, issued_at=_NOW.timestamp())]}
    report_file = tmp_path / "report.json"
    report_file.write_text(json.dumps(report), encoding="utf-8")

    # WITH the signed authority pin ⇒ the VF-2b certificate reproduces ⇒ exit 0.
    rc = reverify.main([str(report_file), "--authority-file", str(auth_file),
                        "--authority-root", str(root_file)])
    assert rc == 0
    # WITHOUT it ⇒ the receipt cannot be re-verified ⇒ fail-closed ⇒ exit 2.
    assert reverify.main([str(report_file)]) == 2
    # A TAMPERED signed authority (mutated pin) fails verification ⇒ the CLI refuses (exit 2), never a
    # silent fall-through to the no-pin path.
    blob = json.loads(auth_file.read_text(encoding="utf-8"))
    blob["document"]["oob_collector_pubkey"] = generate_keypair().public_key_b64
    tampered = tmp_path / "tampered.authority.json"
    tampered.write_text(json.dumps(blob), encoding="utf-8")
    assert reverify.main([str(report_file), "--authority-file", str(tampered),
                          "--authority-root", str(root_file)]) == 2
