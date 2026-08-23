"""W9-5 — SECURE per-host co-signer provisioning + MULTI-SIGNER as the production default.

The defect W9-5 closes has two halves:

  1. the m-of-n default was 1-of-1, and
  2. `generate_authority` minted EVERY private key on ONE host and printed them — a "quorum" whose members
     all live on one box is not a quorum.

This suite pins the fix on both axes, with the mandated controls:

  * PRODUCTION posture makes MULTI-SIGNER the default and REFUSES 1-of-1 (and a pubkey-collapsed roster) at
    BOTH provisioning and the authorization decision — the tests that observe this FAIL on a tree without the
    fix (on `origin/main`, `generate_authority(threshold=1)` under production SUCCEEDS and a 1-of-1
    `DestructionAuthority` constructs), so the failure is observed, not assumed;
  * secure provisioning: each signer's key is generated on its OWN host (`build_enrollment`), the enrolment
    request carries ONLY public material + a proof-of-possession, and the minting box (`assemble_authority`)
    holds NO private key;
  * NEGATIVE CONTROLS asserted in the same run: a quorum assembled from a pubkey that never proved possession
    on its own host is REFUSED (AC3); a duplicate/collapsed roster is REFUSED; and the positive controls
    (a genuine multi-signer quorum, and the unchanged non-production 1-of-1 path) still PASS — so the gate is
    not a blanket no-op.

Import-clean (vigil_core + the offense-local provisioning/gate only — no framework/strix/sigil), so it runs
in the required `integration two-env boundary (P5)` CI job (sovereign leg).
"""
from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from vigil_core import AuthorizerKey, TrustRoot, generate_keypair

from vigil_integration.destruction_gate import (
    DestructionAuthority,
    DestructiveAction,
    PRODUCTION_MIN_THRESHOLD,
    authorize_destruction,
    production_multisigner_reason,
)
from vigil_integration.live import destruction_provision as dp
from vigil_integration.live.codefix_runner import build_destruction_quorum
from vigil_integration.live.trusted_finding import (
    load_destruction_authority,
    load_signed_authorization,
)


def _prod(monkeypatch):
    monkeypatch.setenv("VIGIL_POSTURE", "production")


def _no_posture(monkeypatch):
    monkeypatch.delenv("VIGIL_POSTURE", raising=False)


# --- PHASE 1: per-host keygen + proof-of-possession -------------------------------------------------

def test_build_enrollment_carries_only_public_material_plus_pop():
    priv, doc = dp.build_enrollment(key_id="worker1", name="W1")
    d = json.loads(doc)
    # the enrolment request is PUBLIC-ONLY: pubkey + PoP, and it does NOT contain the private key
    assert set(d) == {"key_id", "name", "public_key_b64", "pop_signature_b64"}
    assert d["key_id"] == "worker1" and d["public_key_b64"] and d["pop_signature_b64"]
    assert priv not in doc, "the private key must never appear in the enrolment request"
    # the PoP verifies and yields the AuthorizerKey for the trust root
    ak = dp.verify_enrollment(doc)
    assert ak.key_id == "worker1" and ak.public_key_b64 == d["public_key_b64"]


def test_forged_pubkey_without_a_valid_pop_is_refused():
    """AC3 — a quorum member whose pubkey never proved possession on its own host is REFUSED. We swap the
    signed pubkey for a DIFFERENT real key (a copy-paste / forgery); the PoP no longer matches, so it is
    rejected. NEGATIVE CONTROL that verify_enrollment is not a no-op."""
    _priv, doc = dp.build_enrollment(key_id="worker1")
    other = generate_keypair().public_key_b64
    forged = json.loads(doc)
    forged["public_key_b64"] = other  # PoP was made by the original key, not this one
    with pytest.raises(ValueError):
        dp.verify_enrollment(json.dumps(forged))


def test_tampered_pop_signature_is_refused():
    _priv, doc = dp.build_enrollment(key_id="worker1")
    bad = json.loads(doc)
    # flip a character in the base64 PoP → invalid signature
    sig = bad["pop_signature_b64"]
    bad["pop_signature_b64"] = ("A" if sig[0] != "A" else "B") + sig[1:]
    with pytest.raises(ValueError):
        dp.verify_enrollment(json.dumps(bad))


def test_enrollment_rejects_weak_public_key():
    # an all-zero (identity / low-order) pubkey is barred by vigil_core.load_public_key even with a PoP field
    bad = json.dumps({"key_id": "w", "name": "w",
                      "public_key_b64": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                      "pop_signature_b64": "AA"})
    with pytest.raises(ValueError):
        dp.verify_enrollment(bad)


# --- PHASE 2: assemble on the minting box (no private keys) -----------------------------------------

def test_assemble_holds_no_private_keys_and_builds_the_quorum(monkeypatch):
    _no_posture(monkeypatch)
    _po, eo = dp.build_enrollment(key_id="owner")
    _p1, e1 = dp.build_enrollment(key_id="worker1")
    gen = dp.assemble_authority(enrollments=[("owner", eo), ("worker1", e1)], threshold=2, owner_id="owner")
    assert gen.private_keys == ()                       # the minting box mints NO private material
    assert gen.threshold == 2 and gen.mandatory_signer_ids == ("owner",)
    tr = TrustRoot.model_validate_json(gen.trust_root_json)
    assert tr.threshold == 2 and len(tr.authorizers) == 2


def test_assemble_refuses_duplicate_pubkey_collapse(monkeypatch):
    _no_posture(monkeypatch)
    _po, eo = dp.build_enrollment(key_id="owner")
    # reuse the SAME enrolment under a second id → same pubkey → collapses the quorum to one holder
    with pytest.raises(ValueError):
        dp.assemble_authority(enrollments=[("owner", eo), ("dup", eo)], threshold=2, owner_id="owner")


def test_assemble_refuses_mismatched_filename_hint(monkeypatch):
    _no_posture(monkeypatch)
    _po, eo = dp.build_enrollment(key_id="owner")
    _p1, e1 = dp.build_enrollment(key_id="worker1")
    # the file mapped as worker1 actually contains owner's PoP-signed key_id → refuse (mis-mapped file)
    with pytest.raises(ValueError):
        dp.assemble_authority(enrollments=[("owner", eo), ("worker1", eo)], threshold=2, owner_id="owner")


def test_assemble_refuses_when_owner_not_enrolled(monkeypatch):
    _no_posture(monkeypatch)
    _p1, e1 = dp.build_enrollment(key_id="worker1")
    _p2, e2 = dp.build_enrollment(key_id="worker2")
    with pytest.raises(ValueError):
        dp.assemble_authority(enrollments=[("worker1", e1), ("worker2", e2)], threshold=2, owner_id="owner")


# --- production posture makes multi-signer the default (FAILS WITHOUT THE FIX) ----------------------

def test_production_refuses_all_on_one_box_generate_authority(monkeypatch):
    """FAILS WITHOUT THE FIX: on a tree without W9-5, generate_authority(threshold=1) under production
    returns a GeneratedAuthority (no posture check) and this `raises` assertion fails. With the fix, the
    all-private-keys-on-one-box mint is refused entirely in production — even for M>1."""
    _prod(monkeypatch)
    with pytest.raises(ValueError):
        dp.generate_authority(threshold=1)
    with pytest.raises(ValueError):
        dp.generate_authority(threshold=2, worker_count=2)   # multi-signer, but still one box → refused


def test_production_refuses_building_a_1of1_authority(monkeypatch):
    """FAILS WITHOUT THE FIX: without W9-5, a 1-of-1 DestructionAuthority constructs fine under production."""
    _prod(monkeypatch)
    kp = generate_keypair()
    tr = TrustRoot(threshold=1, authorizers=[AuthorizerKey(key_id="owner", name="owner",
                                                           public_key_b64=kp.public_key_b64)])
    with pytest.raises(ValueError):
        DestructionAuthority(trust_root=tr, mandatory_signer_ids=frozenset({"owner"}))


def test_production_accepts_a_genuine_multisigner_authority(monkeypatch):
    """POSITIVE CONTROL: the production gate is not a blanket refuse — a real 2-of-2 loads."""
    _prod(monkeypatch)
    o, w = generate_keypair(), generate_keypair()
    tr = TrustRoot(threshold=2, authorizers=[
        AuthorizerKey(key_id="owner", name="owner", public_key_b64=o.public_key_b64),
        AuthorizerKey(key_id="w1", name="w1", public_key_b64=w.public_key_b64)])
    auth = DestructionAuthority(trust_root=tr, mandatory_signer_ids=frozenset({"owner"}))
    assert auth.mandatory_signer_ids == frozenset({"owner"})


def test_production_refuses_pubkey_collapsed_roster_even_at_threshold_2(monkeypatch):
    _prod(monkeypatch)
    o = generate_keypair()
    tr = TrustRoot(threshold=2, authorizers=[
        AuthorizerKey(key_id="owner", name="owner", public_key_b64=o.public_key_b64),
        AuthorizerKey(key_id="w1", name="w1", public_key_b64=o.public_key_b64)])  # same pubkey
    with pytest.raises(ValueError):
        DestructionAuthority(trust_root=tr, mandatory_signer_ids=frozenset({"owner"}))


def test_non_production_still_allows_1of1_add_only(monkeypatch):
    """The change is ADD-ONLY: with the posture unset, a 1-of-1 authority builds exactly as before."""
    _no_posture(monkeypatch)
    kp = generate_keypair()
    tr = TrustRoot(threshold=1, authorizers=[AuthorizerKey(key_id="owner", name="owner",
                                                           public_key_b64=kp.public_key_b64)])
    auth = DestructionAuthority(trust_root=tr, mandatory_signer_ids=frozenset({"owner"}))
    assert auth.trust_root.threshold == 1


def test_production_multisigner_reason_predicate():
    o, w = generate_keypair(), generate_keypair()
    solo = TrustRoot(threshold=1, authorizers=[AuthorizerKey(key_id="o", name="o", public_key_b64=o.public_key_b64)])
    assert production_multisigner_reason(solo)                         # 1-of-1 → reason
    multi = TrustRoot(threshold=2, authorizers=[
        AuthorizerKey(key_id="o", name="o", public_key_b64=o.public_key_b64),
        AuthorizerKey(key_id="w", name="w", public_key_b64=w.public_key_b64)])
    assert production_multisigner_reason(multi) == ""                  # genuine 2-of-2 → ok
    assert PRODUCTION_MIN_THRESHOLD == 2


# --- decision-time enforcement (defense in depth) --------------------------------------------------

def _signed_solo(tmp_path):
    kp = generate_keypair()
    tr = TrustRoot(threshold=1, authorizers=[AuthorizerKey(key_id="owner", name="owner",
                                                           public_key_b64=kp.public_key_b64)])
    auth = DestructionAuthority(trust_root=tr, mandatory_signer_ids=frozenset({"owner"}))  # built posture-unset
    doc = dp.sign_action(action_id="pr-x", engagement_slug="a", target="/r",
                         signer_private_keys=[("owner", kp.private_key_b64)], now=time.time(),
                         nonce=dp.fresh_nonce())
    p = tmp_path / "s.json"
    p.write_text(doc, encoding="utf-8")
    return auth, load_signed_authorization(str(p))


def test_authorize_refuses_1of1_when_production_injected(tmp_path):
    auth, signed = _signed_solo(tmp_path)
    action = DestructiveAction(action_id="pr-x", engagement_slug="a", target="/r", blast_class="destructive")
    dec = authorize_destruction(action, signed, authority=auth, now=time.time(),
                                is_consumed=lambda n: False, production=True)
    assert dec.authorized is False and "multi-signer" in dec.reason


def test_authorize_allows_1of1_when_not_production(tmp_path):
    auth, signed = _signed_solo(tmp_path)
    action = DestructiveAction(action_id="pr-x", engagement_slug="a", target="/r", blast_class="destructive")
    dec = authorize_destruction(action, signed, authority=auth, now=time.time(),
                                is_consumed=lambda n: False, production=False)
    assert dec.authorized is True


# --- end-to-end: per-host detached signing keeps keys apart at authorize time too -------------------

def test_end_to_end_per_host_multisigner_authorizes(monkeypatch, tmp_path):
    _no_posture(monkeypatch)
    # PHASE 1 on three "hosts"
    po, eo = dp.build_enrollment(key_id="owner")
    p1, e1 = dp.build_enrollment(key_id="worker1")
    p2, e2 = dp.build_enrollment(key_id="worker2")
    # PHASE 2 assemble (public only)
    gen = dp.assemble_authority(enrollments=[("owner", eo), ("worker1", e1), ("worker2", e2)],
                                threshold=2, owner_id="owner")
    tr_path = tmp_path / "tr.json"
    tr_path.write_text(gen.trust_root_json, encoding="utf-8")
    authority = load_destruction_authority(trust_root_path=str(tr_path), mandatory_signer_ids=["owner"])
    # coordinator mints the shared request; each host signs detached with its own key
    now = time.time()
    req = dp.build_authorization_request(action_id="pr-x", engagement_slug="acme", target="/repo",
                                         now=now, nonce=dp.fresh_nonce())
    s_owner = dp.sign_request_detached(request_json=req, key_id="owner", private_key_b64=po)
    s_w1 = dp.sign_request_detached(request_json=req, key_id="worker1", private_key_b64=p1)
    signed_doc = dp.combine_authorization(request_json=req, detached_signatures=[s_owner, s_w1])
    sp = tmp_path / "signed.json"
    sp.write_text(signed_doc, encoding="utf-8")
    signed = load_signed_authorization(str(sp))

    class _R:
        remediation_id = "x"
        target_repo = "/repo"
        finding = None

    q = build_destruction_quorum(authority=authority, signed=signed, slug="acme", is_consumed=lambda n: False)
    assert q(_R()).approved is True                                   # owner + worker1 = 2-of-3, owner present

    # NEGATIVE CONTROL: the owner alone (below threshold) is refused
    solo_doc = dp.combine_authorization(request_json=req, detached_signatures=[s_owner])
    sp2 = tmp_path / "solo.json"
    sp2.write_text(solo_doc, encoding="utf-8")
    q2 = build_destruction_quorum(authority=authority, signed=load_signed_authorization(str(sp2)),
                                  slug="acme", is_consumed=lambda n: False)
    assert q2(_R()).approved is False


def test_combine_refuses_empty_signature_set():
    req = dp.build_authorization_request(action_id="pr-x", engagement_slug="a", target="/r",
                                         now=time.time(), nonce=dp.fresh_nonce())
    with pytest.raises(ValueError):
        dp.combine_authorization(request_json=req, detached_signatures=[])


# --- the CLI verbs (the operator interface) --------------------------------------------------------

def test_cli_enroll_writes_0600_private_key_and_public_enrollment(tmp_path):
    from vigil_integration.cli import main
    kf = tmp_path / "w1.key"
    ef = tmp_path / "w1.enr.json"
    rc = main(["enroll-cosigner", "--key-id", "worker1", "--key-out", str(kf), "--out", str(ef)])
    assert rc == 0
    assert (kf.stat().st_mode & 0o777) == 0o600            # private key owner-only
    d = json.loads(ef.read_text(encoding="utf-8"))
    assert d["key_id"] == "worker1" and "pop_signature_b64" in d
    assert kf.read_text(encoding="utf-8").strip() not in ef.read_text(encoding="utf-8")


def test_cli_enroll_refuses_to_clobber_existing_key(tmp_path):
    from vigil_integration.cli import main
    kf = tmp_path / "w1.key"
    kf.write_text("EXISTING\n", encoding="utf-8")
    rc = main(["enroll-cosigner", "--key-id", "worker1", "--key-out", str(kf), "--out", str(tmp_path / "e.json")])
    assert rc == 2
    assert kf.read_text(encoding="utf-8") == "EXISTING\n"   # untouched


def test_cli_assemble_from_public_enrollments(tmp_path, monkeypatch):
    _no_posture(monkeypatch)
    from vigil_integration.cli import main
    from vigil_integration.live.destruction_provision import default_paths

    for kid in ("owner", "worker1"):
        rc = main(["enroll-cosigner", "--key-id", kid,
                   "--key-out", str(tmp_path / f"{kid}.key"), "--out", str(tmp_path / f"{kid}.enr.json")])
        assert rc == 0
    base = tmp_path / "live"
    rc = main(["assemble-destruction", "--base-dir", str(base), "--threshold", "2",
               "--enrollment", f"owner={tmp_path / 'owner.enr.json'}",
               "--enrollment", f"worker1={tmp_path / 'worker1.enr.json'}"])
    assert rc == 0
    tr = Path(default_paths(str(base))["trust_root"])
    assert tr.exists()
    root = TrustRoot.model_validate_json(tr.read_text(encoding="utf-8"))
    assert root.threshold == 2 and len(root.authorizers) == 2


def test_cli_provision_destruction_refused_in_production(tmp_path, monkeypatch):
    """The insecure all-on-one-box mint is refused in production posture."""
    _prod(monkeypatch)
    from vigil_integration.cli import main
    rc = main(["provision-destruction", "--base-dir", str(tmp_path / "p"), "--threshold", "2", "--signers", "2"])
    assert rc == 2
