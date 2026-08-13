"""Anti-replay guard for the SIGNED, LAST-WRITER-WINS governance records.

THE DEFECT THIS PINS. A signature proves WHO authored a record — never WHEN it counts or HOW OFTEN.
Every one of these five signals resolves by folding the spine and letting the last verified record win,
so anyone able to APPEND could re-append a captured owner-signed record VERBATIM to resurrect a state
the owner had revoked. It passed every check the system had: the signature is genuine (it is the
owner's own bytes) and the hash chain extends cleanly (a replay is a NEW append with a fresh seq and
entry_hash). The five, and what one replay bought before this guard:

  governor.killswitch  / released    un-halt a halted mesh
  governor.capability  / enabled     re-enable a disabled gesture/voice/autolearn capability
  governor.promotion   / granted     restore a revoked A2 auto-approval grant
  mesh.device          / authorized  re-arm a REVOKED approval identity — the worst of the five:
                                     `authorized_devices()` is the `extra_pubkeys` allowlist for A2/A3
                                     approval, gesture remote-arm, the bridge daemon, the actor gate
                                     and the egress gate
  mesh.host_capability / (advertise) restore a stale/withdrawn host capability advertisement

THE FIX, and why the two obvious cheaper ones are wrong:
  * NOT signature dedup. Ed25519 is DETERMINISTIC (`reuse.sign` → a bare `Ed25519PrivateKey.sign` over
    canonical JSON, no nonce), so a legitimate grant→revoke→grant re-signs BYTE-IDENTICALLY. A dedup
    would silently swallow the owner's second REAL grant. `test_legitimate_retoggle_*` below is the
    regression guard for exactly that, one per record type.
  * NOT `record.seq`. It is assigned inside `store.append` AFTER signing and is not in any signed core,
    so a replay simply receives a fresh, valid one.
  * INSTEAD: an owner-set, strictly-increasing `issued_at` INSIDE the signed core, plus a PER-KEY
    high-water in the fold. A dangerous-direction record counts only while its `issued_at` strictly
    exceeds every one already honored for its key; honoring it consumes that value. Copied from
    `governor/offense_gate.py:state()`, which already solved this.

The high-water is PER KEY (per capability / per (agent,scope) / per device pubkey / per host_id), never
global: a global one would let a grant for agent A refuse a legitimate later grant for agent B that
carried a smaller `issued_at`.

Freshness gates ONLY the dangerous direction. engage / disable / revoke / revoke-device stay
unconditionally honored with NO `issued_at` requirement — gating a fail-SAFE direction would convert it
into a fail-OPEN, which is a worse bug than the one being fixed.

Run: SIGIL_HOME=$(mktemp -d) ~/.sigil/venv/bin/python -m pytest tests/test_governance_replay_guard.py -q
"""
import itertools
import tempfile

import pytest

from sigil.governor.authn import as_issued_at
from sigil.governor.capability import _CORE as CAP_CORE
from sigil.governor.capability import CapabilityGate
from sigil.governor.killswitch import _CORE as KS_CORE
from sigil.governor.killswitch import KillSwitch
from sigil.governor.promotion import _CORE as PROMO_CORE
from sigil.governor.promotion import PromotionPolicy
from sigil.mesh.registry import (_CAP_CORE, _DEV_CORE, advertise_capability, authorize_device,
                                 authorized_devices, capability_map, revoke_device)
from sigil.reuse import generate_keypair
from sigil.spine.snapshot import SnapshotState, build
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
OWNER_PUB = OWNER.public_key_b64

# Deterministic + strictly increasing. NEVER `time.time()`: two mints inside one clock tick would collide
# and the second would be refused as its own replay — a flake that would hide a real guard failure.
_issue = itertools.count(1)


def _iss() -> float:
    return float(next(_issue))


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _replay(store, payload: dict) -> int:
    """What an attacker who can APPEND (but holds no key) does: re-append captured signed bytes verbatim."""
    return store.append(kind="event", source="governor", actor="WARDEN", payload=dict(payload))


# =====================================================================================================
# The fail-closed `issued_at` parser — shared by every fold, so its edge cases are load-bearing for all.
# =====================================================================================================
@pytest.mark.parametrize("bad", ["not-a-number", None, [1, 2], {"a": 1}, "", (), object()])
def test_unparseable_issued_at_folds_to_the_bottom_without_raising(bad):
    """Every JSON type a hostile/corrupt payload can carry — the parser must return, never raise out of
    a fold (a raise would brick the kill-switch/gate evaluation for every caller)."""
    assert as_issued_at(bad) == 0.0


@pytest.mark.parametrize("poison", [float("nan"), "nan", float("inf"), "-inf", float("-inf")])
def test_non_finite_issued_at_cannot_poison_the_high_water(poison):
    """A NaN high-water would DEFEAT the guard outright: every `issued <= nan` is False, so every later
    replay would be accepted. +inf would brick the dangerous direction permanently. Both map to 0.0."""
    assert as_issued_at(poison) == 0.0


# =====================================================================================================
# governor.killswitch — replaying a captured `released` must not un-halt a re-halted mesh.
# =====================================================================================================
def _ks(store):
    return KillSwitch(store, owner_key=OWNER, trusted_pubkey=OWNER_PUB)


def test_killswitch_replay_of_release_after_engage_does_not_unhalt():
    s = _store()
    k = _ks(s)
    k.engage(reason="drill")
    seq = k.release(issued_at=100.0, reason="all clear")
    assert k._scan_engaged() is False
    captured = dict(s.get(seq).payload)          # the exact owner-signed release bytes
    k.engage(reason="incident")
    assert k._scan_engaged() is True
    _replay(s, captured)                          # attacker replays the genuine signed release
    assert k._scan_engaged() is True, "a replayed release must NOT un-halt the mesh"


def test_killswitch_stale_lower_issued_release_cannot_override_a_newer_one():
    s = _store()
    k = _ks(s)
    k.engage()
    old = dict(s.get(k.release(issued_at=10.0)).payload)
    k.release(issued_at=20.0)                     # consumes the high-water up to 20
    k.engage(reason="re-halt")
    _replay(s, old)                               # replay the OLDER release
    assert k._scan_engaged() is True


def test_killswitch_legitimate_retoggle_still_works():
    """THE REGRESSION GUARD. engage→release→engage→release re-signs BYTE-IDENTICALLY (deterministic
    Ed25519 over a canonical core), so any signature-dedup implementation of this fix would drop the
    second REAL release and leave the mesh halted. A fresh, larger `issued_at` must always work."""
    s = _store()
    k = _ks(s)
    for _ in range(3):
        k.engage(reason="halt")
        assert k._scan_engaged() is True
        k.release(issued_at=_iss(), reason="release")
        assert k._scan_engaged() is False, "a genuine owner release with a fresh issued_at must un-halt"


def test_killswitch_engage_needs_no_freshness_and_its_replay_is_harmless():
    """The SAFE direction keeps NO freshness requirement: any engage halts, replay included."""
    s = _store()
    k = _ks(s)
    eng = dict(s.get(k.engage(reason="halt")).payload)
    k.release(issued_at=_iss())
    assert k._scan_engaged() is False
    _replay(s, eng)                               # replaying a HALT is fail-safe — it must still halt
    assert k._scan_engaged() is True


def test_killswitch_issued_at_is_in_the_signed_core():
    assert "issued_at" in KS_CORE


def test_killswitch_tampered_issued_at_breaks_the_signature():
    """`issued_at` must be INSIDE the core — otherwise an attacker could bump a captured release's
    freshness past the high-water without breaking the signature, and the replay would land."""
    s = _store()
    k = _ks(s)
    k.engage()
    captured = dict(s.get(k.release(issued_at=10.0)).payload)
    k.engage(reason="re-halt")
    captured["issued_at"] = 10_000.0              # bump freshness WITHOUT re-signing
    _replay(s, captured)
    assert k._scan_engaged() is True, "a re-stamped release must fail verification, not un-halt"


def test_killswitch_high_water_survives_a_prune(monkeypatch):
    """HAZARD: the high-water must be CARRIED IN THE SNAPSHOT. If `snapshot.build()` did not fold it, the
    first hard prune would reset it to the bottom and make every release in the pruned prefix replayable
    again — the anti-replay guard would be silently undone by the pruning work."""
    s = _store()
    k = _ks(s)
    k.engage()
    captured = dict(s.get(k.release(issued_at=500.0)).payload)
    K = len(list(s.iter_records()))               # prune everything written so far
    prefix = [r for r in s.iter_records() if r.seq < K]
    synthetic = build(prefix, trusted_pubkey=OWNER_PUB, base_seq=K, snapshot_seq=K - 1)
    assert synthetic.killswitch_issued_hw == 500.0, "build() must fold the release high-water"

    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, store: synthetic))
    k.engage(reason="re-halt after the prune")
    assert k._scan_engaged() is True
    _replay(s, captured)                          # the replayed release now lives ONLY in the live window
    assert k._scan_engaged() is True, "a pruned-prefix release must stay un-replayable after the prune"


def test_killswitch_build_matches_the_live_scan_under_a_replay():
    """build() and `_scan_engaged` must agree RECORD FOR RECORD, replays included — the snapshot fold is
    the same fold. A build() that ignored the high-water would fold the replay to un-halted here."""
    s = _store()
    k = _ks(s)
    k.engage()
    captured = dict(s.get(k.release(issued_at=42.0)).payload)
    k.engage(reason="re-halt")
    _replay(s, captured)
    folded = build(list(s.iter_records()), trusted_pubkey=OWNER_PUB, base_seq=0, snapshot_seq=-1)
    assert folded.killswitch_engaged == k._scan_engaged() is True


@pytest.mark.parametrize("hostile", ["garbage", None, [1, 2], {"a": 1}, float("nan")])
def test_killswitch_hostile_issued_at_in_a_SIGNED_release_never_raises(hostile):
    """`issued_at` reaches the parser only AFTER the signature verifies, so the hostile case is an owner
    key that signed a malformed value (a buggy caller, a corrupt clock). It must fold, not raise — and a
    NaN must not poison the high-water into accepting every later replay."""
    s = _store()
    k = _ks(s)
    k.engage()
    from sigil.governor.authn import signed_payload
    from sigil.governor.killswitch import SIGNAL
    core = {"signal": SIGNAL, "state": "released", "issued_at": hostile}
    s.append(kind="event", source="governor", actor="WARDEN",
             payload={**signed_payload(core, OWNER), "tier": "A0", "decision": "auto"})
    assert k._scan_engaged() is False              # honored once (parses to the 0.0 bottom), no exception
    k.engage(reason="re-halt")
    captured = dict(list(s.iter_records())[-2].payload)
    _replay(s, captured)                           # its own replay must still be refused
    assert k._scan_engaged() is True


def test_killswitch_no_high_water_folds_to_the_none_sentinel():
    """-inf is not portable JSON and 0.0 is a legitimate high-water, so "none honored yet" is `None`."""
    s = _store()
    _ks(s).engage()
    folded = build(list(s.iter_records()), trusted_pubkey=OWNER_PUB, base_seq=0, snapshot_seq=-1)
    assert folded.killswitch_issued_hw is None
    assert SnapshotState.model_validate(folded.model_dump()).killswitch_issued_hw is None


# =====================================================================================================
# governor.capability — replaying a captured `enabled` must not re-enable a disabled capability.
# =====================================================================================================
def _cg(store):
    return CapabilityGate(store, owner_key=OWNER, trusted_pubkey=OWNER_PUB)


def test_capability_replay_of_enable_after_disable_does_not_reenable():
    s = _store()
    g = _cg(s)
    g.disable("gesture")
    seq = g.enable("gesture", issued_at=100.0)
    assert g._scan_enabled("gesture") is True
    captured = dict(s.get(seq).payload)
    g.disable("gesture", reason="panic")
    assert g._scan_enabled("gesture") is False
    _replay(s, captured)
    assert g._scan_enabled("gesture") is False, "a replayed enable must NOT re-enable a disabled capability"


def test_capability_stale_lower_issued_enable_cannot_override_a_newer_one():
    s = _store()
    g = _cg(s)
    g.disable("voice")
    old = dict(s.get(g.enable("voice", issued_at=10.0)).payload)
    g.enable("voice", issued_at=20.0)
    g.disable("voice", reason="panic")
    _replay(s, old)
    assert g._scan_enabled("voice") is False


def test_capability_legitimate_retoggle_still_works():
    """THE REGRESSION GUARD (cf. test_capability_latch.py's round-trip): disable→enable→disable→enable
    re-signs BYTE-IDENTICALLY, so a signature-dedup fix would strand the capability off."""
    s = _store()
    g = _cg(s)
    for _ in range(3):
        g.disable("autolearn")
        assert g._scan_enabled("autolearn") is False
        g.enable("autolearn", issued_at=_iss())
        assert g._scan_enabled("autolearn") is True, "a genuine enable with a fresh issued_at must re-enable"


def test_capability_high_water_is_PER_CAPABILITY_not_global():
    """HAZARD: a GLOBAL high-water would let a fresh enable(voice) refuse a legitimate later
    enable(gesture) that carried a smaller issued_at. The keys must be independent."""
    s = _store()
    g = _cg(s)
    g.disable("gesture")
    g.disable("voice")
    g.enable("voice", issued_at=900.0)              # a HIGH high-water, but only for `voice`
    g.enable("gesture", issued_at=5.0)              # a genuine, much older enable for `gesture`
    assert g._scan_enabled("gesture") is True, "a per-capability high-water must not leak across keys"
    assert g._scan_enabled("voice") is True


def test_capability_disable_needs_no_freshness_and_its_replay_is_harmless():
    s = _store()
    g = _cg(s)
    dis = dict(s.get(g.disable("gesture")).payload)
    g.enable("gesture", issued_at=_iss())
    assert g._scan_enabled("gesture") is True
    _replay(s, dis)                                  # replaying a DISABLE is fail-safe
    assert g._scan_enabled("gesture") is False


def test_capability_issued_at_is_in_the_signed_core():
    assert "issued_at" in CAP_CORE


def test_capability_tampered_issued_at_breaks_the_signature():
    s = _store()
    g = _cg(s)
    g.disable("gesture")
    captured = dict(s.get(g.enable("gesture", issued_at=10.0)).payload)
    g.disable("gesture", reason="panic")
    captured["issued_at"] = 10_000.0                 # re-stamp freshness WITHOUT re-signing
    _replay(s, captured)
    assert g._scan_enabled("gesture") is False


def test_capability_high_water_survives_a_prune(monkeypatch):
    s = _store()
    g = _cg(s)
    g.disable("gesture")
    captured = dict(s.get(g.enable("gesture", issued_at=500.0)).payload)
    K = len(list(s.iter_records()))
    prefix = [r for r in s.iter_records() if r.seq < K]
    synthetic = build(prefix, trusted_pubkey=OWNER_PUB, base_seq=K, snapshot_seq=K - 1)
    assert synthetic.capability_issued_map() == {"gesture": 500.0}, "build() must fold the enable high-water"

    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, store: synthetic))
    g.disable("gesture", reason="panic after the prune")
    _replay(s, captured)
    assert g._scan_enabled("gesture") is False, "a pruned-prefix enable must stay un-replayable"


def test_capability_build_matches_the_live_scan_under_a_replay():
    s = _store()
    g = _cg(s)
    g.disable("gesture")
    captured = dict(s.get(g.enable("gesture", issued_at=42.0)).payload)
    g.disable("gesture", reason="panic")
    _replay(s, captured)
    folded = build(list(s.iter_records()), trusted_pubkey=OWNER_PUB, base_seq=0, snapshot_seq=-1)
    assert folded.capability_latch_map()["gesture"] == g._scan_enabled("gesture") is False


def test_capability_state_all_inherits_the_guard():
    """`state_all()` is a comprehension over `is_enabled`, so it must report the guarded verdict — the
    'a mint-side gate must be mirrored at the read surface' invariant, satisfied by construction here."""
    s = _store()
    g = _cg(s)
    g.disable("gesture")
    captured = dict(s.get(g.enable("gesture", issued_at=100.0)).payload)
    g.disable("gesture", reason="panic")
    _replay(s, captured)
    assert g.state_all()["gesture"] == "disabled"


# =====================================================================================================
# governor.promotion — replaying a captured `granted` must not restore a revoked A2 auto-approval.
# =====================================================================================================
def _pp(store):
    return PromotionPolicy(store, owner_key=OWNER, trusted_pubkey=OWNER_PUB)


def test_promotion_replay_of_grant_after_revoke_does_not_repromote():
    s = _store()
    p = _pp(s)
    seq = p.grant("SCHOLAR", "draft", issued_at=100.0)
    assert p.is_promoted("SCHOLAR", "draft") is True
    captured = dict(s.get(seq).payload)
    p.revoke("SCHOLAR", "draft")
    assert p.is_promoted("SCHOLAR", "draft") is False
    _replay(s, captured)
    assert p.is_promoted("SCHOLAR", "draft") is False, "a replayed grant must NOT restore a revoked promotion"


def test_promotion_replayed_grant_is_not_LISTED_either():
    """BOTH read surfaces. `state_all` was a hand-copied second fold, and that duplication already cost a
    real defect once (the NO_PROMOTION denylist landed in is_promoted and had to be mirrored afterwards).
    Both now call the one `_fold`, so a listed grant is exactly one is_promoted would confirm."""
    s = _store()
    p = _pp(s)
    captured = dict(s.get(p.grant("SCHOLAR", "draft", issued_at=100.0)).payload)
    p.revoke("SCHOLAR", "draft")
    _replay(s, captured)
    assert p.state_all() == [], "state_all must not list a promotion is_promoted refuses to enforce"


def test_promotion_stale_lower_issued_grant_cannot_override_a_newer_one():
    s = _store()
    p = _pp(s)
    old = dict(s.get(p.grant("SCHOLAR", "draft", issued_at=10.0)).payload)
    p.grant("SCHOLAR", "draft", issued_at=20.0)
    p.revoke("SCHOLAR", "draft")
    _replay(s, old)
    assert p.is_promoted("SCHOLAR", "draft") is False


def test_promotion_legitimate_retoggle_still_works():
    """THE REGRESSION GUARD. grant→revoke→grant re-signs BYTE-IDENTICALLY, so a signature-dedup fix would
    swallow the owner's second REAL grant and silently leave the agent unpromoted."""
    s = _store()
    p = _pp(s)
    for _ in range(3):
        p.grant("SCHOLAR", "draft", issued_at=_iss())
        assert p.is_promoted("SCHOLAR", "draft") is True
        assert p.state_all() == [{"agent": "SCHOLAR", "scope": "draft"}]
        p.revoke("SCHOLAR", "draft")
        assert p.is_promoted("SCHOLAR", "draft") is False


def test_promotion_high_water_is_PER_AGENT_SCOPE_not_global():
    """HAZARD: a GLOBAL high-water would let a fresh grant for one agent refuse a legitimate later grant
    for another that carried a smaller issued_at. (agent, scope) keys must be independent."""
    s = _store()
    p = _pp(s)
    p.grant("SCHOLAR", "draft", issued_at=900.0)      # a HIGH high-water, but only for this key
    p.grant("ARTIFICER", "wire", issued_at=5.0)       # a genuine, much older grant for a DIFFERENT key
    p.grant("SCHOLAR", "report", issued_at=6.0)       # ...and a different SCOPE of the same agent
    assert p.is_promoted("ARTIFICER", "wire") is True, "a per-key high-water must not leak across agents"
    assert p.is_promoted("SCHOLAR", "report") is True, "...nor across scopes of one agent"


def test_promotion_revoke_needs_no_freshness_and_its_replay_is_harmless():
    s = _store()
    p = _pp(s)
    p.grant("SCHOLAR", "draft", issued_at=1.0)
    rev = dict(s.get(p.revoke("SCHOLAR", "draft")).payload)
    p.grant("SCHOLAR", "draft", issued_at=2.0)
    assert p.is_promoted("SCHOLAR", "draft") is True
    _replay(s, rev)                                    # replaying a REVOKE is fail-safe
    assert p.is_promoted("SCHOLAR", "draft") is False


def test_promotion_issued_at_is_in_the_signed_core():
    assert "issued_at" in PROMO_CORE


def test_promotion_tampered_issued_at_breaks_the_signature():
    s = _store()
    p = _pp(s)
    captured = dict(s.get(p.grant("SCHOLAR", "draft", issued_at=10.0)).payload)
    p.revoke("SCHOLAR", "draft")
    captured["issued_at"] = 10_000.0                   # re-stamp freshness WITHOUT re-signing
    _replay(s, captured)
    assert p.is_promoted("SCHOLAR", "draft") is False
    assert p.state_all() == []


def test_promotion_high_water_survives_a_prune(monkeypatch):
    s = _store()
    p = _pp(s)
    captured = dict(s.get(p.grant("SCHOLAR", "draft", issued_at=500.0)).payload)
    K = len(list(s.iter_records()))
    prefix = [r for r in s.iter_records() if r.seq < K]
    synthetic = build(prefix, trusted_pubkey=OWNER_PUB, base_seq=K, snapshot_seq=K - 1)
    assert synthetic.promotion_issued_map() == {("SCHOLAR", "draft"): 500.0}

    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, store: synthetic))
    p.revoke("SCHOLAR", "draft")
    _replay(s, captured)
    assert p.is_promoted("SCHOLAR", "draft") is False, "a pruned-prefix grant must stay un-replayable"
    assert p.state_all() == []


def test_promotion_build_matches_the_live_scan_under_a_replay():
    s = _store()
    p = _pp(s)
    captured = dict(s.get(p.grant("SCHOLAR", "draft", issued_at=42.0)).payload)
    p.revoke("SCHOLAR", "draft")
    _replay(s, captured)
    folded = build(list(s.iter_records()), trusted_pubkey=OWNER_PUB, base_seq=0, snapshot_seq=-1)
    assert folded.promotion_map()[("SCHOLAR", "draft")] == "revoked"
    assert p.is_promoted("SCHOLAR", "draft") is False


def test_promotion_foreign_pubkey_snapshot_bypass_restarts_the_high_water(monkeypatch):
    """HAZARD 7: the seeded high-water must follow the SAME pubkey-dependent bypass as the state it
    guards. A snapshot folded under a foreign anchor is invalid — including its high-water — so the fold
    must restart from the bottom, or a rotated key would resurrect grants (or refuse genuine ones)."""
    s = _store()
    p = _pp(s)
    p.grant("SCHOLAR", "draft", issued_at=5.0)
    poisoned = SnapshotState(base_seq=99, trusted_pubkey=generate_keypair().public_key_b64,
                             promotion=[["SCHOLAR", "draft", "revoked"]],
                             promotion_issued=[["SCHOLAR", "draft", 1e12]])
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, store: poisoned))
    assert p.is_promoted("SCHOLAR", "draft") is True, \
        "a foreign-anchor snapshot must be bypassed entirely — its high-water cannot refuse a real grant"


# =====================================================================================================
# mesh.device — THE MOST DANGEROUS of the five. `authorized_devices()` is the `extra_pubkeys` allowlist
# for A2/A3 approval, gesture remote-arm, the bridge daemon, the actor gate, the operator gate and the
# egress gate, so ONE replayed `authorized` re-arms a revoked approval identity across all of them.
# =====================================================================================================
def _mesh_replay(store, payload: dict) -> int:
    return store.append(kind="event", source="mesh", actor="OWNER", payload=dict(payload))


def test_device_replay_of_authorization_after_revoke_does_not_rearm():
    s = _store()
    dev = generate_keypair().public_key_b64
    seq = authorize_device(s, "phone-1", dev, OWNER, issued_at=100.0)
    assert authorized_devices(s, OWNER_PUB) == {dev}
    captured = dict(s.get(seq).payload)             # the exact owner-signed authorization bytes
    revoke_device(s, "phone-1", dev, OWNER)          # the phone is lost/stolen/sold
    assert authorized_devices(s, OWNER_PUB) == set()
    _mesh_replay(s, captured)
    assert authorized_devices(s, OWNER_PUB) == set(), \
        "a replayed authorization must NOT re-arm a revoked device"


def test_device_replay_does_not_restore_approval_authority():
    """The impact test, not just the set test: the replayed device must not regain the ability to approve
    an A2/A3 item — that is what `authorized_devices` is consumed FOR."""
    from sigil.agents.approvals import ApprovalQueue, verify_approval
    from sigil.mesh.registry import DeviceApprover
    s = _store()
    device = generate_keypair()
    captured = dict(s.get(authorize_device(s, "phone-1", device.public_key_b64, OWNER,
                                           issued_at=100.0)).payload)
    revoke_device(s, "phone-1", device.public_key_b64, OWNER)
    _mesh_replay(s, captured)                        # attacker re-arms the revoked phone

    q = ApprovalQueue(s, owner_key=OWNER, trusted_pubkey_b64=OWNER_PUB)
    target = s.append(kind="wire", source="agent", actor="ENVOY",
                      payload={"tier": "A3", "decision": "queued"})
    rec = s.get(DeviceApprover(s, device_key=device).approve(target))
    assert verify_approval(rec, OWNER_PUB, extra_pubkeys=authorized_devices(s, OWNER_PUB)) is False, \
        "a replay-re-armed device must not be able to approve anything"
    assert q is not None


def test_device_stale_lower_issued_authorization_cannot_override_a_newer_one():
    s = _store()
    dev = generate_keypair().public_key_b64
    old = dict(s.get(authorize_device(s, "phone-1", dev, OWNER, issued_at=10.0)).payload)
    authorize_device(s, "phone-1", dev, OWNER, issued_at=20.0)
    revoke_device(s, "phone-1", dev, OWNER)
    _mesh_replay(s, old)
    assert authorized_devices(s, OWNER_PUB) == set()


def test_device_legitimate_reauthorization_still_works():
    """THE REGRESSION GUARD. authorize→revoke→authorize re-signs BYTE-IDENTICALLY, so a signature-dedup
    fix would leave a re-paired phone permanently unable to approve."""
    s = _store()
    dev = generate_keypair().public_key_b64
    for _ in range(3):
        authorize_device(s, "phone-1", dev, OWNER, issued_at=_iss())
        assert authorized_devices(s, OWNER_PUB) == {dev}, "a genuine re-authorization must re-arm"
        revoke_device(s, "phone-1", dev, OWNER)
        assert authorized_devices(s, OWNER_PUB) == set()


def test_device_high_water_is_PER_DEVICE_not_global():
    """HAZARD: a GLOBAL high-water would let one phone's fresh authorization refuse another phone's
    legitimate later one carrying a smaller issued_at — silently un-pairing a device."""
    s = _store()
    a, b = generate_keypair().public_key_b64, generate_keypair().public_key_b64
    authorize_device(s, "phoneA", a, OWNER, issued_at=900.0)   # a HIGH high-water, only for phoneA
    authorize_device(s, "phoneB", b, OWNER, issued_at=5.0)     # a genuine, much older one for phoneB
    assert authorized_devices(s, OWNER_PUB) == {a, b}, "a per-device high-water must not leak across keys"


def test_device_revoke_needs_no_freshness_and_its_replay_is_harmless():
    """A revoke must ALWAYS land — it is how a lost phone is disarmed. Gating it on freshness would be a
    fail-OPEN: an attacker who could pin the high-water would block every future revoke."""
    s = _store()
    dev = generate_keypair().public_key_b64
    authorize_device(s, "phone-1", dev, OWNER, issued_at=1.0)
    rev = dict(s.get(revoke_device(s, "phone-1", dev, OWNER)).payload)
    authorize_device(s, "phone-1", dev, OWNER, issued_at=2.0)
    assert authorized_devices(s, OWNER_PUB) == {dev}
    _mesh_replay(s, rev)                             # replaying a REVOKE is fail-safe
    assert authorized_devices(s, OWNER_PUB) == set()


def test_device_issued_at_is_in_the_signed_core():
    assert "issued_at" in _DEV_CORE


def test_device_tampered_issued_at_breaks_the_signature():
    s = _store()
    dev = generate_keypair().public_key_b64
    captured = dict(s.get(authorize_device(s, "phone-1", dev, OWNER, issued_at=10.0)).payload)
    revoke_device(s, "phone-1", dev, OWNER)
    captured["issued_at"] = 10_000.0                 # re-stamp freshness WITHOUT re-signing
    _mesh_replay(s, captured)
    assert authorized_devices(s, OWNER_PUB) == set()


def test_device_high_water_survives_a_prune(monkeypatch):
    s = _store()
    dev = generate_keypair().public_key_b64
    captured = dict(s.get(authorize_device(s, "phone-1", dev, OWNER, issued_at=500.0)).payload)
    K = len(list(s.iter_records()))
    prefix = [r for r in s.iter_records() if r.seq < K]
    synthetic = build(prefix, trusted_pubkey=OWNER_PUB, base_seq=K, snapshot_seq=K - 1)
    assert synthetic.mesh_dev_issued_map() == {dev: 500.0}

    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, store: synthetic))
    revoke_device(s, "phone-1", dev, OWNER)
    _mesh_replay(s, captured)
    assert authorized_devices(s, OWNER_PUB) == set(), \
        "a pruned-prefix authorization must stay un-replayable after the prune"


def test_device_build_matches_the_live_scan_under_a_replay():
    s = _store()
    dev = generate_keypair().public_key_b64
    captured = dict(s.get(authorize_device(s, "phone-1", dev, OWNER, issued_at=42.0)).payload)
    revoke_device(s, "phone-1", dev, OWNER)
    _mesh_replay(s, captured)
    folded = build(list(s.iter_records()), trusted_pubkey=OWNER_PUB, base_seq=0, snapshot_seq=-1)
    assert dict(folded.mesh_dev_state)[dev] == "revoked"
    assert authorized_devices(s, OWNER_PUB) == set()


def test_device_foreign_pubkey_snapshot_bypass_restarts_the_high_water(monkeypatch):
    """HAZARD 7: the seeded high-water follows the SAME pubkey-dependent bypass as the state it guards."""
    s = _store()
    dev = generate_keypair().public_key_b64
    authorize_device(s, "phone-1", dev, OWNER, issued_at=5.0)
    poisoned = SnapshotState(base_seq=99, trusted_pubkey=generate_keypair().public_key_b64,
                             mesh_dev_state=[[dev, "revoked"]], mesh_dev_issued=[[dev, 1e12]])
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, store: poisoned))
    assert authorized_devices(s, OWNER_PUB) == {dev}, \
        "a foreign-anchor snapshot must be bypassed entirely — its high-water cannot refuse a real authz"


# =====================================================================================================
# mesh.host_capability — the one ledger with NO safe direction (an advertisement is the only
# transition), so freshness gates EVERY record. A replayed richer advertisement would otherwise
# resurrect capabilities a host has since truthfully withdrawn — `has_hid_inject` and
# `has_camera_stream` are what route real HID injection and camera streaming to a host.
# =====================================================================================================
def _advertise(store, host_id, *, issued_at, hid=False, camera_stream=False):
    return advertise_capability(store, {"host_id": host_id, "os": "linux", "has_screen": True,
                                        "has_camera": True, "has_gpu_vlm": True, "always_on": True,
                                        "has_hid_inject": hid, "has_camera_stream": camera_stream},
                                OWNER, issued_at=issued_at)


def _cap_replay(store, payload: dict) -> int:
    return store.append(kind="event", source="mesh", actor="OWNER", payload=dict(payload))


def test_host_capability_replay_cannot_resurrect_a_withdrawn_capability():
    s = _store()
    rich = dict(s.get(_advertise(s, "desk", issued_at=100.0, hid=True, camera_stream=True)).payload)
    assert capability_map(s, OWNER_PUB)["desk"]["has_hid_inject"] is True
    _advertise(s, "desk", issued_at=200.0, hid=False, camera_stream=False)   # host truthfully downgrades
    assert capability_map(s, OWNER_PUB)["desk"]["has_hid_inject"] is False
    _cap_replay(s, rich)                              # attacker replays the RICHER advertisement
    m = capability_map(s, OWNER_PUB)
    assert m["desk"]["has_hid_inject"] is False, "a replayed advertisement must not resurrect HID injection"
    assert m["desk"]["has_camera_stream"] is False


def test_host_capability_stale_lower_issued_advert_cannot_override_a_newer_one():
    s = _store()
    old = dict(s.get(_advertise(s, "desk", issued_at=10.0, hid=True)).payload)
    _advertise(s, "desk", issued_at=20.0, hid=False)
    _cap_replay(s, old)
    assert capability_map(s, OWNER_PUB)["desk"]["has_hid_inject"] is False


def test_host_capability_legitimate_re_advertisement_still_works():
    """THE REGRESSION GUARD. A host that re-advertises the SAME descriptor re-signs BYTE-IDENTICALLY, so
    a signature-dedup fix would drop every refresh after the first."""
    s = _store()
    for _ in range(3):
        _advertise(s, "desk", issued_at=_iss(), hid=True)
        assert capability_map(s, OWNER_PUB)["desk"]["has_hid_inject"] is True
        _advertise(s, "desk", issued_at=_iss(), hid=False)
        assert capability_map(s, OWNER_PUB)["desk"]["has_hid_inject"] is False


def test_host_capability_high_water_is_PER_HOST_not_global():
    s = _store()
    _advertise(s, "desk", issued_at=900.0)            # a HIGH high-water, but only for `desk`
    _advertise(s, "laptop", issued_at=5.0, hid=True)  # a genuine, much older advert for a DIFFERENT host
    m = capability_map(s, OWNER_PUB)
    assert set(m) == {"desk", "laptop"}, "a per-host high-water must not leak across hosts"
    assert m["laptop"]["has_hid_inject"] is True


def test_host_capability_issued_at_is_in_the_signed_core():
    assert "issued_at" in _CAP_CORE


def test_host_capability_descriptor_shape_is_unchanged_by_the_guard():
    """`issued_at` is bookkeeping, not something the host advertises about itself, so the projected
    descriptor deliberately excludes it — `capability_map`'s return shape is what it always was."""
    s = _store()
    _advertise(s, "desk", issued_at=1.0)
    assert set(capability_map(s, OWNER_PUB)["desk"]) == {
        "host_id", "os", "has_screen", "has_camera", "has_gpu_vlm", "always_on",
        "has_hid_inject", "has_camera_stream"}


def test_host_capability_tampered_issued_at_breaks_the_signature():
    s = _store()
    rich = dict(s.get(_advertise(s, "desk", issued_at=10.0, hid=True)).payload)
    _advertise(s, "desk", issued_at=20.0, hid=False)
    rich["issued_at"] = 10_000.0                      # re-stamp freshness WITHOUT re-signing
    _cap_replay(s, rich)
    assert capability_map(s, OWNER_PUB)["desk"]["has_hid_inject"] is False


def test_host_capability_high_water_survives_a_prune(monkeypatch):
    s = _store()
    rich = dict(s.get(_advertise(s, "desk", issued_at=500.0, hid=True)).payload)
    K = len(list(s.iter_records()))
    prefix = [r for r in s.iter_records() if r.seq < K]
    synthetic = build(prefix, trusted_pubkey=OWNER_PUB, base_seq=K, snapshot_seq=K - 1)
    assert synthetic.capability_map_issued_map() == {"desk": 500.0}

    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, store: synthetic))
    _advertise(s, "desk", issued_at=600.0, hid=False)
    _cap_replay(s, rich)
    assert capability_map(s, OWNER_PUB)["desk"]["has_hid_inject"] is False, \
        "a pruned-prefix advertisement must stay un-replayable after the prune"


def test_host_capability_build_matches_the_live_scan_under_a_replay():
    s = _store()
    rich = dict(s.get(_advertise(s, "desk", issued_at=42.0, hid=True)).payload)
    _advertise(s, "desk", issued_at=43.0, hid=False)
    _cap_replay(s, rich)
    folded = build(list(s.iter_records()), trusted_pubkey=OWNER_PUB, base_seq=0, snapshot_seq=-1)
    assert dict(folded.capability_map)["desk"] == capability_map(s, OWNER_PUB)["desk"]
    assert dict(folded.capability_map)["desk"]["has_hid_inject"] is False
