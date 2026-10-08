"""M-11 — the OFFENSE-side (KEYLESS) verification + gate-ack injection of the EvalCapabilityGrant.

A grant may LIFT only the CLOSED-ENUM opt-in authority-gate vetoes (witness_quorum / blast_veto /
containment_preview) for ONE engagement/target, and ONLY when a verified, owner-signed, FRESH-evaluator-PoP'd
grant covers it on the shared seam. This test runs in the OFFENSE leg and must NOT import ``sigil`` — it
simulates exactly what the sovereign governor publishes, using ONLY the import-clean shared primitives
(``vigil_core`` sign/canonical + the ``eval_capability_grant`` broker). It locks the keyless verifier +
the acks + the four REQUIRED adversary fixes:

  * FIX B: the evaluator PoP is a FRESH signature over the GRANT core (binding overrides + max_covered_actions),
    re-verified here; a reused/attestation-shaped sig does not verify.
  * CLOSED ENUM: a non-enum override token record is ignored (no effect); the floors are never nameable.
  * two-party distinctness: an evaluator_pubkey that is a pinned owner key (self-grant) is refused fail-closed.
  * SEAL + rollback: a dropped/reordered list no longer seals; a replayed lower seq is refused.
  * FIX C2/F budget: a caller-vouched durable count >= max_covered_actions voids (the process counter is NOT used).
  * FIX E: an exercised ack appends an ``authority.override_applied`` attribution event.
  * BYTE-IDENTITY: absent/revoked grant => acks return False => the gate vetoes enforce.

FATAL-2: the offense plane only VERIFIES public signed material against the pinned owner key; it never imports
the sovereign governor nor holds the owner key.
"""

from __future__ import annotations

import json

import pytest

from vigil_core import canonical_json, generate_keypair, sign
from vigil_core.spine_domains import DOMAIN_TAGS

_ecg = pytest.importorskip("vigil_integration.live.eval_capability_grant")

_SLUG = "apme-cm"
_TGT = "https://apme.cm/app"
_CORE = (
    "signal", "state", "engagement_slug", "target", "allowed_gate_overrides", "issued_anchor",
    "max_covered_actions", "evaluator_pubkey",
)
_SIGNAL = "governor.eval_capability_grant"


@pytest.fixture()
def base(tmp_path, monkeypatch):
    b = tmp_path / ".vigil-live"
    b.mkdir()
    monkeypatch.setenv("VIGIL_BASE_DIR", str(b))
    # isolate the durable rollback high-water per test
    monkeypatch.setenv("VIGIL_EVAL_GRANT_HIGHWATER_DIR", str(tmp_path / "hw"))
    return str(b)


def _canon(core: dict) -> bytes:
    cb = canonical_json({k: core.get(k) for k in _CORE})
    return cb if isinstance(cb, (bytes, bytearray)) else str(cb).encode("utf-8")


def _norm(overrides):
    return sorted({str(x) for x in overrides})


def _grant_record(owner, evaluator, *, slug=_SLUG, target=_TGT,
                  overrides=("witness_quorum", "blast_veto", "containment_preview"),
                  issued_anchor=5.0, max_covered_actions=100, owner_signer=None, ev_signer=None,
                  tag=None, state="granted"):
    core = {
        "signal": _SIGNAL, "state": state, "engagement_slug": slug, "target": target,
        "allowed_gate_overrides": _norm(overrides), "issued_anchor": float(issued_anchor),
        "max_covered_actions": int(max_covered_actions), "evaluator_pubkey": evaluator.public_key_b64,
    }
    cb = _canon(core)
    osig = sign((owner_signer or owner).private_key_b64, cb)
    tagb = DOMAIN_TAGS["eval-capability-grant"] if tag is None else tag
    esig = sign((ev_signer or evaluator).private_key_b64, tagb + cb)
    return {**core, "sig": osig, "pubkey": owner.public_key_b64, "evaluator_sig": esig, "evaluator": "eval"}


def _revoke_record(owner, *, slug=_SLUG):
    core = {
        "signal": _SIGNAL, "state": "revoked", "engagement_slug": slug, "target": "",
        "allowed_gate_overrides": [], "issued_anchor": 0.0, "max_covered_actions": 0, "evaluator_pubkey": "",
    }
    return {**core, "sig": sign(owner.private_key_b64, _canon(core)), "pubkey": owner.public_key_b64}


def _seal_for(owner, records, *, seq=1):
    return _ecg.build_seal(_SLUG, seq, records,
                           sign_fn=lambda b: sign(owner.private_key_b64, b), pubkey=owner.public_key_b64)


def _write(base, records, *, seal_owner, seq=1, seal=None):
    _ecg.write_eval_capability_grants(
        base, _SLUG, records, seal=seal if seal is not None else _seal_for(seal_owner, records, seq=seq))


def _verify(base, owner, *, target=_TGT, actions_covered=None):
    return _ecg.verify_eval_capability_grant(
        base, engagement_slug=_SLUG, target=target, trusted_owner_pubkeys=[owner.public_key_b64],
        actions_covered=actions_covered)


# --- happy path + which vetoes it lifts ------------------------------------------------------------
def test_valid_grant_verifies_and_lifts_the_enum_vetoes(base):
    owner, ev = generate_keypair(), generate_keypair()
    _write(base, [_grant_record(owner, ev)], seal_owner=owner)
    v = _verify(base, owner)
    assert v.granted and v.witness_ok and v.blast_ok
    assert set(v.containment_caps) >= {"block_ip", "isolate_endpoint", "quarantine_host", "revoke_session"}
    assert v.allowed_gate_overrides == ("blast_veto", "containment_preview", "witness_quorum")


def test_absent_grant_is_ungranted(base):
    owner = generate_keypair()
    assert _verify(base, owner).granted is False


def test_wrong_target_does_not_cover(base):
    owner, ev = generate_keypair(), generate_keypair()
    _write(base, [_grant_record(owner, ev)], seal_owner=owner)
    assert _verify(base, owner, target="https://evil.example/x").granted is False


def test_only_granted_overrides_lift(base):
    owner, ev = generate_keypair(), generate_keypair()
    _write(base, [_grant_record(owner, ev, overrides=("witness_quorum",))], seal_owner=owner)
    v = _verify(base, owner)
    assert v.granted and v.witness_ok and not v.blast_ok and v.containment_caps == ()


# --- the four REQUIRED fixes -----------------------------------------------------------------------
def test_fix_b_fresh_pop_required(base):
    """A record whose evaluator PoP was signed WITHOUT the grant domain tag (e.g. a reused/other-purpose sig)
    does not verify — the FRESH grant-core PoP is mandatory."""
    owner, ev = generate_keypair(), generate_keypair()
    rec = _grant_record(owner, ev, tag=b"wrong-tag\x00")
    _write(base, [rec], seal_owner=owner)
    assert _verify(base, owner).granted is False


def test_closed_enum_non_member_token_ignored(base):
    owner, ev = generate_keypair(), generate_keypair()
    # a genuinely owner+evaluator-signed record that names a NON-enum token (a floor) is ignored — no effect
    rec = _grant_record(owner, ev, overrides=("egress_floor",))
    _write(base, [rec], seal_owner=owner)
    assert _verify(base, owner).granted is False


def test_self_grant_evaluator_is_owner_refused(base):
    owner = generate_keypair()
    # evaluator_pubkey IS the pinned owner key — a self-grant collapses the two-party control → refused
    rec = _grant_record(owner, owner)
    _write(base, [rec], seal_owner=owner)
    v = _verify(base, owner)
    assert v.granted is False and "DISTINCT from the owner" in v.reason


def test_fix_c2f_budget_voids_only_on_durable_count(base):
    owner, ev = generate_keypair(), generate_keypair()
    _write(base, [_grant_record(owner, ev, max_covered_actions=10)], seal_owner=owner)
    assert _verify(base, owner, actions_covered=None).granted is True       # no durable count → not voided
    assert _verify(base, owner, actions_covered=9).granted is True
    assert _verify(base, owner, actions_covered=10).granted is False        # reached ceiling → void


def test_fix_e_exercised_ack_is_attributed(base):
    owner, ev = generate_keypair(), generate_keypair()
    _write(base, [_grant_record(owner, ev)], seal_owner=owner)
    v = _verify(base, owner)
    wq_ack, bl_ack, caps = _ecg.grant_overrides(v, base_dir=base, engagement_slug=_SLUG)

    class Req:
        target = _TGT
        action_kind = "offense"
        bug_class = "sqli"

    class WQ:
        kinds = ("http_response",)
        required = 2
    assert wq_ack(Req(), WQ()) is True
    led = _ecg._override_ledger_path(base, _SLUG)
    assert led.is_file()
    rows = [json.loads(ln) for ln in led.read_text().splitlines() if ln.strip()]
    assert rows and rows[0]["event"] == "authority.override_applied" and rows[0]["gate"] == "6c"
    assert rows[0]["action_target"] == _TGT and rows[0]["grant_id"] == v.grant_id


# --- seal + rollback + revoke ----------------------------------------------------------------------
def test_revoke_voids_and_acks_go_false(base):
    owner, ev = generate_keypair(), generate_keypair()
    _write(base, [_grant_record(owner, ev), _revoke_record(owner)], seal_owner=owner, seq=2)
    v = _verify(base, owner)
    assert v.granted is False
    wq_ack, bl_ack, caps = _ecg.grant_overrides(v, base_dir=base, engagement_slug=_SLUG)
    assert wq_ack(object(), object()) is False and bl_ack(object(), object()) is False and caps == ()


def test_dropped_revoke_fails_the_seal(base):
    owner, ev = generate_keypair(), generate_keypair()
    # seal is minted over [grant, revoke] but only [grant] is written → recomputed seal bytes mismatch
    full = [_grant_record(owner, ev), _revoke_record(owner)]
    good_seal = _seal_for(owner, full, seq=2)
    _write(base, [full[0]], seal_owner=owner, seq=2, seal=good_seal)
    v = _verify(base, owner)
    assert v.granted is False and "seal" in v.reason.lower()


def test_unsealed_list_refused(base):
    owner, ev = generate_keypair(), generate_keypair()
    _ecg.write_eval_capability_grants(base, _SLUG, [_grant_record(owner, ev)], seal=None)
    assert _verify(base, owner).granted is False


def test_rollback_below_highwater_refused(base):
    owner, ev = generate_keypair(), generate_keypair()
    _write(base, [_grant_record(owner, ev, issued_anchor=9.0)], seal_owner=owner, seq=5)
    assert _verify(base, owner).granted is True                       # advances HW to 5
    # a replay of an OLDER published state (lower seq) is refused by the durable rollback floor
    _write(base, [_grant_record(owner, ev, issued_anchor=9.0)], seal_owner=owner, seq=3)
    assert _verify(base, owner).granted is False


def test_forged_owner_seal_refused(base):
    owner, ev, attacker = generate_keypair(), generate_keypair(), generate_keypair()
    recs = [_grant_record(owner, ev)]
    _write(base, recs, seal_owner=attacker)                           # sealed by a NON-pinned key
    assert _verify(base, owner).granted is False
