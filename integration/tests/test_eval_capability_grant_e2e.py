"""M-11 EvalCapabilityGrant — the WHOLE flow, end to end, over an isolated CRUCIBLE_ROOT + a loopback target.

This is the operator's "test it fully end to end" for the eval button: a SECURITY-CONTROL OVERRIDE
authorization. It drives the REAL offense-plane decision path — the keyless verifier
(``vigil_integration.live.eval_capability_grant``) feeding the grant ACKS into the REAL authority gate
(``framework.v2.authority.gate.authorize_action``) with the REAL witness-quorum predicate
(``witness_quorum_predicate(load_quorum_config())``) and a REAL blast-radius veto — and probes the
never-liftable floors directly. The seven numbered stages below mirror the acceptance script.

FATAL-2 / two-env: this test runs in the OFFENSE leg (``framework`` importable) and NEVER imports the
sovereign governor (``sigil.governor.eval_capability_grant``), which owns the owner signing key. So the
ARM step faithfully SIMULATES exactly what the sovereign governor PUBLISHES to the shared seam — the
owner signature over the grant core, the FRESH evaluator PoP over the domain-tagged grant core (FIX B),
and the owner SEAL over the ordered record list — using ONLY the import-clean shared primitives
(``vigil_core`` sign/canonical + the ``eval_capability_grant`` broker). The sovereign-side MINT refusals
(a non-owner / reused-attestation-sig / bad-token mint) are asserted here at the authoritative KEYLESS
boundary — the one control that actually protects the offense plane — and are independently covered on the
sovereign plane by ``apps/sigil/tests/test_eval_capability_grant.py``.

Run (offense leg): PYTHONPATH=engine/crucible:packages/core/vigil_core:integration:gateway
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from vigil_core import (
    AuthorizerKey,
    Signature,
    TrustRoot,
    canonical_json,
    generate_keypair,
    sign,
)
from vigil_core.spine_domains import DOMAIN_TAGS

# The offense-plane decision core + its real predicates (this is why the file is in the offense leg).
pytest.importorskip("framework")
from framework.v2.authority.gate import authorize_action  # noqa: E402
from framework.v2.authority.killswitch import KillSwitch  # noqa: E402
from framework.v2.authority.models import (  # noqa: E402
    ActionRequest,
    AuthorityState,
    EngagementAuthority,
    TargetEnvironment,
)
from framework.v2.authority.witness_quorum_gate import witness_quorum_predicate  # noqa: E402
from framework.v2.veracity.witness_quorum import load_quorum_config  # noqa: E402

# The keyless offense broker/verifier + the floor probes (egress + m-of-n destruction).
_ecg = pytest.importorskip("vigil_integration.live.eval_capability_grant")
from vigil_gateway import denylist  # noqa: E402
from vigil_integration import destruction_gate as _dg  # noqa: E402

# --- the loopback engagement + target under test ---------------------------------------------------
_SLUG = "eval-e2e"
_OTHER_SLUG = "eval-e2e-other"
_TGT = "https://eval-target.example.com/app"
_OTHER_TGT = "https://eval-target.example.com/other"
_NOW = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)
_SIGNAL = "governor.eval_capability_grant"
_CORE = (
    "signal", "state", "engagement_slug", "target", "allowed_gate_overrides", "issued_anchor",
    "max_covered_actions", "evaluator_pubkey",
)
_ALL_OVERRIDES = ("witness_quorum", "blast_veto", "containment_preview")


# ===================================================================================================
# fixtures + the sovereign-publish SIMULATION (faithful to governor.attest / .revoke / ._publish)
# ===================================================================================================


@pytest.fixture()
def base(tmp_path, monkeypatch):
    """An isolated CRUCIBLE_ROOT-equivalent seam base_dir + a per-test durable rollback high-water dir."""
    b = tmp_path / ".vigil-live"
    b.mkdir()
    monkeypatch.setenv("VIGIL_BASE_DIR", str(b))
    monkeypatch.setenv("VIGIL_EVAL_GRANT_HIGHWATER_DIR", str(tmp_path / "hw"))
    return str(b)


@pytest.fixture()
def quorum_policy_on(tmp_path, monkeypatch):
    """Operator witness-quorum policy ACTIVE: enabled, N=2, over the critical class 'sqli' (6c armed)."""
    p = tmp_path / "witness_quorum.json"
    p.write_text(json.dumps({"enabled": True, "quorum_n": 2, "critical_classes": ["sqli"]}))
    monkeypatch.setenv("CRUCIBLE_WITNESS_QUORUM_CONFIG", str(p))
    load_quorum_config.cache_clear() if hasattr(load_quorum_config, "cache_clear") else None
    from framework.v2.veracity import witness_quorum as _wq
    _wq._load_cached.cache_clear()
    return p


def _canon(core: dict) -> bytes:
    cb = canonical_json({k: core.get(k) for k in _CORE})
    return cb if isinstance(cb, (bytes, bytearray)) else str(cb).encode("utf-8")


def _norm(overrides):
    return sorted({str(x) for x in overrides})


def _grant_record(owner, evaluator, *, slug=_SLUG, target=_TGT, overrides=_ALL_OVERRIDES,
                  issued_anchor=5.0, max_covered_actions=100, owner_signer=None, tag=None,
                  state="granted"):
    """Byte-for-byte the record the sovereign governor.attest() appends + publishes: owner sig over the
    grant core, FRESH evaluator PoP over DOMAIN_TAGS['eval-capability-grant'] + the SAME core (FIX B)."""
    core = {
        "signal": _SIGNAL, "state": state, "engagement_slug": slug, "target": target,
        "allowed_gate_overrides": _norm(overrides), "issued_anchor": float(issued_anchor),
        "max_covered_actions": int(max_covered_actions), "evaluator_pubkey": evaluator.public_key_b64,
    }
    cb = _canon(core)
    osig = sign((owner_signer or owner).private_key_b64, cb)
    tagb = DOMAIN_TAGS["eval-capability-grant"] if tag is None else tag
    esig = sign(evaluator.private_key_b64, tagb + cb)
    return {**core, "sig": osig, "pubkey": owner.public_key_b64, "evaluator_sig": esig, "evaluator": "eval"}


def _revoke_record(owner, *, slug=_SLUG):
    core = {
        "signal": _SIGNAL, "state": "revoked", "engagement_slug": slug, "target": "",
        "allowed_gate_overrides": [], "issued_anchor": 0.0, "max_covered_actions": 0, "evaluator_pubkey": "",
    }
    return {**core, "sig": sign(owner.private_key_b64, _canon(core)), "pubkey": owner.public_key_b64}


def _publish(base, slug, records, *, seal_owner, seq):
    """Mirror governor._publish: write the ordered record list + an owner SEAL over it."""
    seal = _ecg.build_seal(slug, seq, records,
                           sign_fn=lambda b: sign(seal_owner.private_key_b64, b),
                           pubkey=seal_owner.public_key_b64)
    _ecg.write_eval_capability_grants(base, slug, records, seal=seal)


def _verify(base, owner, *, slug=_SLUG, target=_TGT, actions_covered=None):
    return _ecg.verify_eval_capability_grant(
        base, engagement_slug=slug, target=target,
        trusted_owner_pubkeys=[owner.public_key_b64], actions_covered=actions_covered)


# --- the real authority gate scaffolding -----------------------------------------------------------


def _authority(**kw):
    base = dict(
        engagement_slug=_SLUG, environment=TargetEnvironment.TWIN, scope=["*.example.com"],
        not_before=_NOW - timedelta(hours=1), not_after=_NOW + timedelta(hours=1),
        allow_destructive=True, max_actions=10_000,
    )
    base.update(kw)
    return EngagementAuthority(**base)


def _under_quorum_req():
    """An action tied to a 'sqli' finding whose retained witness_context re-fires < 2 oracle kinds → 6c fires."""
    return ActionRequest(target=_TGT, action_kind="offense", bug_class="sqli",
                         witness_context={"note": "retained-evidence-stub"})


def _over_blast_req():
    return ActionRequest(target=_TGT, action_kind="offense", destructive=True)


class _Blast:  # structural stand-in for the forward-world-model verdict (duck-typed by the gate)
    def __init__(self, blast, jewels):
        self.incremental_blast = blast
        self.newly_reachable_jewels = jewels


def _blast_fn_over(_req):
    return _Blast(100.0, ["datastore:crown"])


def _boom(_req):  # must never be consulted once a prior conjunct has denied
    raise AssertionError("a later-conjunct predicate was consulted after an earlier denial")


def _wq_fn():
    return witness_quorum_predicate(load_quorum_config())


def _grant_acks(verdict, base, slug=_SLUG):
    return _ecg.grant_overrides(verdict, base_dir=base, engagement_slug=slug)


def _ledger_rows(base, slug=_SLUG):
    led = _ecg._override_ledger_path(base, slug)
    if led is None or not led.is_file():
        return []
    return [json.loads(ln) for ln in led.read_text().splitlines() if ln.strip()]


# ===================================================================================================
# (1) ARM — owner+evaluator mint, published to the seam; non-owner / reused-sig / bad-token all FAIL
# ===================================================================================================


def test_1_arm_valid_grant_is_verifiable_on_the_seam(base):
    owner, ev = generate_keypair(), generate_keypair()
    _publish(base, _SLUG, [_grant_record(owner, ev)], seal_owner=owner, seq=1)
    v = _verify(base, owner)
    assert v.granted is True
    assert v.witness_ok and v.blast_ok
    assert v.allowed_gate_overrides == ("blast_veto", "containment_preview", "witness_quorum")
    assert set(v.containment_caps) >= {"block_ip", "isolate_endpoint", "quarantine_host", "revoke_session"}


def test_1_arm_non_owner_mint_fails(base):
    owner, ev, attacker = generate_keypair(), generate_keypair(), generate_keypair()
    # A grant owner-signed by a key the offense plane does NOT pin (a forged/non-owner mint) → ungranted.
    rec = _grant_record(owner, ev, owner_signer=attacker)
    _publish(base, _SLUG, [rec], seal_owner=owner, seq=1)
    assert _verify(base, owner).granted is False


def test_1_arm_reused_attestation_sig_fails(base):
    owner, ev = generate_keypair(), generate_keypair()
    # A PoP NOT produced over the grant domain tag (e.g. a sig reused from the covering attestation or any
    # other purpose) is not a FRESH grant-core PoP (FIX B) → ungranted.
    rec = _grant_record(owner, ev, tag=b"vigil-eval-offense-attestation-v1\x00")
    _publish(base, _SLUG, [rec], seal_owner=owner, seq=1)
    assert _verify(base, owner).granted is False


def test_1_arm_bad_token_mint_fails(base):
    owner, ev = generate_keypair(), generate_keypair()
    # A genuinely owner+evaluator-signed record naming a NON-enum token (a never-liftable floor) has no
    # effect — the closed enum is enforced at the keyless fold too.
    rec = _grant_record(owner, ev, overrides=("egress_floor",))
    _publish(base, _SLUG, [rec], seal_owner=owner, seq=1)
    assert _verify(base, owner).granted is False


def test_1_arm_self_grant_evaluator_is_owner_fails(base):
    owner = generate_keypair()
    rec = _grant_record(owner, owner)  # evaluator_pubkey == a pinned owner key: two-party control collapses
    _publish(base, _SLUG, [rec], seal_owner=owner, seq=1)
    v = _verify(base, owner)
    assert v.granted is False and "DISTINCT from the owner" in v.reason


# ===================================================================================================
# (2) PRE-AUTHORIZE — gates WIRED+ON + grant armed ⇒ 6c/6b actions ALLOWED with NO per-action signing,
#     each emitting an authority.override_applied spine event binding action→grant→gate (FIX E)
# ===================================================================================================


def test_2_grant_lifts_6c_under_quorum_with_no_per_action_signing(base, quorum_policy_on):
    owner, ev = generate_keypair(), generate_keypair()
    _publish(base, _SLUG, [_grant_record(owner, ev)], seal_owner=owner, seq=1)
    v = _verify(base, owner)
    wq_ack, _bl_ack, _caps = _grant_acks(v, base)
    req, auth, wq = _under_quorum_req(), _authority(), _wq_fn()

    # control: the 6c veto is ARMED and FIRES for this under-quorum action absent any ack.
    d_denied = authorize_action(auth, req, now=_NOW, witness_quorum_fn=wq, witness_quorum_ack=None)
    assert d_denied.allowed is False and d_denied.denial_code == "witness_quorum"

    # the grant ACK (a plain callable derived from the published grant — NO operator per-action signature)
    # lifts the veto for THIS action.
    d_allowed = authorize_action(auth, req, now=_NOW, witness_quorum_fn=wq, witness_quorum_ack=wq_ack)
    assert d_allowed.allowed is True and d_allowed.denial_code == ""

    rows = [r for r in _ledger_rows(base) if r.get("gate") == "6c"]
    assert rows, "an exercised 6c override must emit an authority.override_applied event"
    assert rows[-1]["event"] == "authority.override_applied"
    assert rows[-1]["grant_id"] == v.grant_id and rows[-1]["action_target"] == _TGT


def test_2_grant_lifts_6b_over_blast_with_no_per_action_signing(base):
    owner, ev = generate_keypair(), generate_keypair()
    _publish(base, _SLUG, [_grant_record(owner, ev)], seal_owner=owner, seq=1)
    v = _verify(base, owner)
    _wq_ack, bl_ack, _caps = _grant_acks(v, base)
    req, auth = _over_blast_req(), _authority()

    d_denied = authorize_action(auth, req, now=_NOW, blast_radius_fn=_blast_fn_over, blast_ceiling=10.0,
                                blast_radius_ack=None)
    assert d_denied.allowed is False and d_denied.denial_code == "blast_radius"

    d_allowed = authorize_action(auth, req, now=_NOW, blast_radius_fn=_blast_fn_over, blast_ceiling=10.0,
                                 blast_radius_ack=bl_ack)
    assert d_allowed.allowed is True and d_allowed.denial_code == ""

    rows = [r for r in _ledger_rows(base) if r.get("gate") == "6b"]
    assert rows and rows[-1]["grant_id"] == v.grant_id and rows[-1]["action_target"] == _TGT
    assert rows[-1]["incremental_blast"] == 100.0


# ===================================================================================================
# (3) FLOOR INTACT — the never-liftable floors are structurally un-liftable by any grant, and a granted
#     verdict lifts NOTHING beyond the closed enum (probe the egress floor + m-of-n destruction directly)
# ===================================================================================================


def test_3_floors_are_not_members_of_the_closed_override_enum(base):
    # structural un-liftability: the grant's closed enum cannot even NAME a floor.
    assert set(_ecg.ALLOWED_OVERRIDES) == set(_ALL_OVERRIDES)
    for floor in ("egress_floor", "destruction_quorum", "get_only_write", "egress", "m_of_n"):
        assert floor not in _ecg.ALLOWED_OVERRIDES


def test_3_egress_floor_still_refuses_metadata_and_rfc1918_under_a_live_grant(base):
    owner, ev = generate_keypair(), generate_keypair()
    _publish(base, _SLUG, [_grant_record(owner, ev)], seal_owner=owner, seq=1)
    assert _verify(base, owner).granted is True  # grant is LIVE

    # cloud metadata (link-local) is HARD-denied no matter what; the grant does not touch egress.
    denied_meta, _why = denylist.is_egress_denied("169.254.169.254", allowed_ips=["169.254.169.254"])
    assert denied_meta is True
    assert denylist.is_hard_denied("169.254.169.254") is True
    # RFC1918 is denied unless charter-allowlisted; with an empty allowlist it stays refused.
    denied_priv, _why2 = denylist.is_egress_denied("10.0.0.1", allowed_ips=())
    assert denied_priv is True


def test_3_m_of_n_destruction_still_requires_the_quorum_under_a_live_grant(base):
    owner, ev = generate_keypair(), generate_keypair()
    _publish(base, _SLUG, [_grant_record(owner, ev)], seal_owner=owner, seq=1)
    v = _verify(base, owner)
    assert v.granted is True
    # the granted verdict yields ONLY the 6b/6c acks + containment caps — never a destruction authorization.
    wq_ack, bl_ack, caps = _grant_acks(v, base)
    assert callable(wq_ack) and callable(bl_ack)

    # probe the destruction gate directly: a destructive action with NO quorum authorization is refused.
    a, b = generate_keypair(), generate_keypair()
    tr = TrustRoot(schema_version=1, threshold=2, authorizers=[
        AuthorizerKey(key_id="owner", name="owner", public_key_b64=a.public_key_b64),
        AuthorizerKey(key_id="second", name="second", public_key_b64=b.public_key_b64),
    ])
    auth = _dg.DestructionAuthority(trust_root=tr, mandatory_signer_ids=frozenset({"owner"}))
    action = _dg.DestructiveAction(action_id="act-1", engagement_slug=_SLUG, target=_TGT,
                                   blast_class=_dg.DESTRUCTIVE)
    decision = _dg.authorize_destruction(action, None, authority=auth, now=_NOW.timestamp(),
                                         is_consumed=lambda _n: False)
    assert decision.authorized is False  # no m-of-n quorum ⇒ refused; the grant cannot supply one


# ===================================================================================================
# (4) SCOPE — the grant does NOT pre-authorize a different engagement / target
# ===================================================================================================


def test_4_grant_does_not_cover_a_different_target(base):
    owner, ev = generate_keypair(), generate_keypair()
    _publish(base, _SLUG, [_grant_record(owner, ev)], seal_owner=owner, seq=1)
    assert _verify(base, owner, target=_OTHER_TGT).granted is False

    # at the gate: an action against the other target gets NO acks ⇒ the veto ENFORCES (fail-closed).
    v_other = _verify(base, owner, target=_OTHER_TGT)
    wq_ack, _bl, _c = _grant_acks(v_other, base)
    req = ActionRequest(target=_OTHER_TGT, action_kind="offense", bug_class="sqli",
                        witness_context={"note": "x"})
    # the quorum policy need not be loaded here: wq_ack from an ungranted verdict returns False regardless.
    assert wq_ack(req, object()) is False


def test_4_grant_does_not_cover_a_different_engagement(base):
    owner, ev = generate_keypair(), generate_keypair()
    _publish(base, _SLUG, [_grant_record(owner, ev)], seal_owner=owner, seq=1)
    # a DIFFERENT engagement slug has no published grant on the seam ⇒ ungranted.
    assert _verify(base, owner, slug=_OTHER_SLUG).granted is False


# ===================================================================================================
# (5) REVOKE / KILL — kill-switch denies at conjunct 1 before 6b/6c; an explicit revoke re-enforces
# ===================================================================================================


def test_5_killswitch_denies_before_the_grant_acks_are_consulted(base, tmp_path, quorum_policy_on):
    owner, ev = generate_keypair(), generate_keypair()
    _publish(base, _SLUG, [_grant_record(owner, ev)], seal_owner=owner, seq=1)
    v = _verify(base, owner)
    wq_ack, bl_ack, _caps = _grant_acks(v, base)

    ks = KillSwitch(_SLUG, path=tmp_path / "ks.json")
    ks.trip("operator emergency-stop")
    assert ks.is_tripped() is True

    # Even with the grant armed and its acks wired, the kill-switch (conjunct 1) halts FIRST — proven by
    # wiring _boom predicates that would raise if the gate reached 6b/6c.
    d = authorize_action(_authority(), _under_quorum_req(), now=_NOW, killswitch=ks,
                         blast_radius_fn=_boom, blast_ceiling=10.0, blast_radius_ack=bl_ack,
                         witness_quorum_fn=_boom, witness_quorum_ack=wq_ack)
    assert d.allowed is False
    assert d.denial_code == "halted" and d.state is AuthorityState.HALTED


def test_5_explicit_revoke_re_enforces_the_gates(base, quorum_policy_on):
    owner, ev = generate_keypair(), generate_keypair()
    _publish(base, _SLUG, [_grant_record(owner, ev)], seal_owner=owner, seq=1)
    assert _verify(base, owner).granted is True

    # the owner publishes a revoke (re-sealed over the ordered [grant, revoke] list, seq advanced).
    recs = [_grant_record(owner, ev), _revoke_record(owner)]
    _publish(base, _SLUG, recs, seal_owner=owner, seq=2)
    v = _verify(base, owner)
    assert v.granted is False

    # the acks from the revoked verdict lift nothing ⇒ the 6c veto ENFORCES again.
    wq_ack, _bl, _c = _grant_acks(v, base)
    d = authorize_action(_authority(), _under_quorum_req(), now=_NOW,
                         witness_quorum_fn=_wq_fn(), witness_quorum_ack=wq_ack)
    assert d.allowed is False and d.denial_code == "witness_quorum"


# ===================================================================================================
# (6) FAIL-CLOSED — grant absent/expired ⇒ the gates enforce the under-quorum / over-blast actions
# ===================================================================================================


def test_6_absent_grant_6c_enforces(base, quorum_policy_on):
    owner = generate_keypair()
    v = _verify(base, owner)  # nothing published ⇒ ungranted
    assert v.granted is False
    wq_ack, _bl, _c = _grant_acks(v, base)
    d = authorize_action(_authority(), _under_quorum_req(), now=_NOW,
                         witness_quorum_fn=_wq_fn(), witness_quorum_ack=wq_ack)
    assert d.allowed is False and d.denial_code == "witness_quorum"


def test_6_absent_grant_6b_enforces(base):
    owner = generate_keypair()
    v = _verify(base, owner)
    assert v.granted is False
    _wq, bl_ack, _c = _grant_acks(v, base)
    d = authorize_action(_authority(), _over_blast_req(), now=_NOW,
                         blast_radius_fn=_blast_fn_over, blast_ceiling=10.0, blast_radius_ack=bl_ack)
    assert d.allowed is False and d.denial_code == "blast_radius"


# ===================================================================================================
# (7) BYTE-IDENTITY — default (no grant, no policy) ⇒ authorize_action is byte-identical to today
# ===================================================================================================


def test_7_default_path_is_byte_identical(base, monkeypatch):
    # no witness-quorum policy configured (env unset ⇒ DISABLED) and no grant published.
    monkeypatch.delenv("CRUCIBLE_WITNESS_QUORUM_CONFIG", raising=False)
    from framework.v2.veracity import witness_quorum as _wq
    _wq._load_cached.cache_clear()

    owner = generate_keypair()
    auth, benign = _authority(), ActionRequest(target=_TGT, action_kind="offense")

    # (a) the pre-feature call shape (no new kwargs at all).
    baseline = authorize_action(auth, benign, now=_NOW)
    # (b) the feature wired with the default/ungranted inputs: a DISABLED wq_fn + the ungranted acks +
    #     the None blast kwargs — exactly what the live wiring passes when nothing is armed.
    v = _verify(base, owner)
    assert v.granted is False
    wq_ack, bl_ack, _caps = _grant_acks(v, base)
    wired = authorize_action(auth, benign, now=_NOW,
                             blast_radius_fn=None, blast_ceiling=None, blast_radius_ack=bl_ack,
                             witness_quorum_fn=witness_quorum_predicate(load_quorum_config()),
                             witness_quorum_ack=wq_ack)
    assert baseline.model_dump() == wired.model_dump()
    assert baseline.allowed is True and baseline.denial_code == ""


def test_7_no_grant_matches_passing_no_acks_under_active_policy(base, quorum_policy_on):
    # With the policy ACTIVE but NO grant, feeding the (ungranted) acks is byte-identical to feeding None:
    # both DENY the under-quorum action. Wiring the grant plumbing changes nothing when nothing is granted.
    owner = generate_keypair()
    v = _verify(base, owner)
    assert v.granted is False
    wq_ack, _bl, _c = _grant_acks(v, base)
    req, auth, wq = _under_quorum_req(), _authority(), _wq_fn()
    d_none = authorize_action(auth, req, now=_NOW, witness_quorum_fn=wq, witness_quorum_ack=None)
    d_acks = authorize_action(auth, req, now=_NOW, witness_quorum_fn=wq, witness_quorum_ack=wq_ack)
    assert d_none.model_dump() == d_acks.model_dump()
    assert d_none.allowed is False and d_none.denial_code == "witness_quorum"
