"""SIGIL Phase 7 WS-D — cross-platform + mobile bridge: per-OS backend selection, keyring-first
secrets, the owner-signed device-authorization ledger (a device approves ONLY while authorized),
minimal-payload push, and the WG bind guard. Run: ~/.sigil/venv/bin/python tests/test_mobile.py"""
import sys
import tempfile

from sigil.agents.approvals import pending, verify_approval
from sigil.agents.base import Agent, Proposal, Tier
from sigil.bridge import BridgeDaemon, PushNotifier, bind_ok
from sigil.governor import Governor
from sigil.mesh import (DeviceApprover, advertise_capability, authorize_device,
                        authorized_devices, capability_map, revoke_device)
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
OP = OWNER.public_key_b64


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


class _Emitter(Agent):
    name = "TESTER"
    ceiling = Tier.A2

    def __init__(self, store):
        super().__init__(store, governor=Governor(store, owner_key=OWNER, trusted_pubkey=OP))

    def run(self, tier, kind="draft"):
        return self._dispatch([Proposal(kind, {"subject": "TOP SECRET wire $1M"}, tier)])


# ---- D1 platform backend selection ---------------------------------------------------------------
def test_host_selects_backend_by_platform(monkeypatch=None):
    import sigil.platform as P
    real = sys.platform
    try:
        sys.platform = "linux"; assert type(P.host()).__name__ == "LinuxBackend"
        sys.platform = "darwin"; assert type(P.host()).__name__ == "MacOSBackend"
        sys.platform = "win32"; assert type(P.host()).__name__ == "WindowsBackend"
    finally:
        sys.platform = real


def test_linux_backend_delegates_and_probes_honestly():
    import sigil.platform.linux as L
    calls = {"screen": 0}
    L.grab_screen = lambda: (calls.__setitem__("screen", 1) or None)
    b = L.LinuxBackend()
    assert b.capture_screen() is None and calls["screen"] == 1, "Linux backend delegates to grab_screen"
    caps = b.capabilities()
    assert caps.os == "linux" and isinstance(caps.has_screen, bool), "capabilities are honest booleans"


# ---- D2 secrets: keyring-first, never on the spine -----------------------------------------------
def test_secret_store_roundtrips_and_env_fallback():
    from sigil.platform.secrets import SecretStore
    import os
    s = SecretStore()
    s.set("SIGIL_TEST_SECRET", "hunter2")
    assert s.get("SIGIL_TEST_SECRET") == "hunter2", "a stored secret round-trips"
    os.environ.pop("SIGIL_TEST_SECRET", None)


# ---- D4 device-authorization ledger (the keystone) -----------------------------------------------
def test_device_approves_only_while_authorized():
    s = _store()
    _Emitter(s).run(Tier.A2)                                   # queued A2 at seq 0
    tgt = pending(s, OP)[0].seq
    device = generate_keypair()
    # (a) an UNAUTHORIZED device approval does NOT resolve the item
    DeviceApprover(s, device_key=device).approve(tgt)
    assert len(pending(s, OP, extra_pubkeys=authorized_devices(s, OP))) == 1, "an unauthorized device can't approve"
    # (b) owner AUTHORIZES the device → a device approval now resolves it
    authorize_device(s, "phone-1", device.public_key_b64, OWNER)
    assert device.public_key_b64 in authorized_devices(s, OP)
    DeviceApprover(s, device_key=device).approve(tgt)
    assert not pending(s, OP, extra_pubkeys=authorized_devices(s, OP)), "an authorized device approval verifies + clears"


def test_forged_and_revoked_device_cannot_approve():
    s = _store()
    _Emitter(s).run(Tier.A3)
    tgt = pending(s, OP)[0].seq
    # a device that FORGES an authorization for itself (signed with its OWN key, not the owner's) → ignored
    attacker = generate_keypair()
    from sigil.governor.authn import signed_payload
    s.append(kind="event", source="mesh", actor="OWNER",
             payload=signed_payload({"signal": "mesh.device", "state": "authorized",
                                     "device_id": "evil", "device_pubkey": attacker.public_key_b64}, attacker))
    assert attacker.public_key_b64 not in authorized_devices(s, OP), "a self-signed authorization is not owner-minted"
    DeviceApprover(s, device_key=attacker).approve(tgt)
    assert len(pending(s, OP, extra_pubkeys=authorized_devices(s, OP))) == 1, "the forged device can't approve"
    # a genuinely authorized device that is later REVOKED loses approval power
    dev = generate_keypair()
    authorize_device(s, "phone-2", dev.public_key_b64, OWNER)
    revoke_device(s, "phone-2", dev.public_key_b64, OWNER)
    assert dev.public_key_b64 not in authorized_devices(s, OP), "a revoked device is no longer authorized"


def test_device_approval_target_seq_binding_no_replay():
    s = _store()
    _Emitter(s).run(Tier.A2, kind="draft")                    # harmless, seq 0
    _Emitter(s).run(Tier.A3, kind="wire")                     # dangerous, seq 1
    pend = pending(s, OP)
    harmless, dangerous = pend[0].seq, pend[1].seq
    device = generate_keypair()
    authorize_device(s, "phone", device.public_key_b64, OWNER)
    approved = DeviceApprover(s, device_key=device).approve(harmless)   # approve the HARMLESS one
    genuine = s.get(approved).payload
    s.append(kind="event", source="mesh", actor="DEVICE", supersedes_id=dangerous, payload=dict(genuine))  # replay
    still = [r.seq for r in pending(s, OP, extra_pubkeys=authorized_devices(s, OP))]
    assert dangerous in still and harmless not in still, "a replayed device approval (signed for another seq) can't resolve the dangerous item"


# ---- D3 signed capability map --------------------------------------------------------------------
def test_capability_map_ignores_forged_advertisements():
    s = _store()
    advertise_capability(s, {"host_id": "desk", "os": "linux", "has_screen": True, "has_camera": True,
                             "has_gpu_vlm": True, "always_on": True}, OWNER)
    attacker = generate_keypair()
    from sigil.governor.authn import signed_payload
    s.append(kind="event", source="mesh", actor="OWNER",
             payload=signed_payload({"signal": "mesh.host_capability", "host_id": "rogue", "os": "?",
                                     "has_screen": True, "has_camera": True, "has_gpu_vlm": True,
                                     "always_on": True}, attacker))
    m = capability_map(s, OP)
    assert "desk" in m and "rogue" not in m, "only owner-signed capability advertisements are trusted"


# ---- D5/D6 bridge daemon + push -------------------------------------------------------------------
def test_bridge_daemon_gates_device_approval():
    s = _store()
    _Emitter(s).run(Tier.A2)
    tgt = pending(s, OP)[0].seq
    d = BridgeDaemon(s, trusted_pubkey=OP)
    device = generate_keypair()
    from sigil.agents.approvals import _approval_message
    from sigil.reuse import sign
    msg = _approval_message(tgt, "approved", "phone")
    forged = {"signal": "governor.approval", "approval": "approved", "target_seq": tgt, "approver": "phone",
              "pubkey": device.public_key_b64, "sig": sign(device.private_key_b64, msg)}
    try:
        d.submit_device_approval(forged); assert False, "an unauthorized device approval must be refused"
    except ValueError:
        pass
    authorize_device(s, "phone", device.public_key_b64, OWNER)
    d.submit_device_approval(forged)                          # now authorized → accepted
    assert not d.pending(), "an authorized device approval clears the queue via the daemon"


def test_push_carries_no_subject_or_secret():
    s = _store()
    n = PushNotifier(s)                                       # starts at head → only new items
    _Emitter(s).run(Tier.A2)                                  # queue an A2 with a secret subject
    _Emitter(s).run(Tier.A1, kind="event")                   # an A1 auto action (must NOT push)
    pushes = n.poll()
    assert len(pushes) == 1 and pushes[0]["tier"] == "A2", "only A2/A3 queued items push"
    blob = str(pushes)
    assert "SECRET" not in blob and "subject" not in blob, "the push carries only {seq,tier,kind} — no subject/secret"


def test_bind_guard_refuses_public_and_unspecified():
    assert bind_ok("127.0.0.1") and bind_ok("10.13.13.2") and bind_ok("192.168.1.5")   # loopback / WG / private
    assert not bind_ok("0.0.0.0") and not bind_ok("::"), "0.0.0.0 / :: refused"
    assert not bind_ok("8.8.8.8") and not bind_ok("1.2.3.4"), "public addresses refused"


def test_authorized_device_authorizes_operator_execution():
    # BLOCK-1 fix: a device approval must authorize a real EXECUTION gate, not just a queue view.
    import tempfile as tf
    from pathlib import Path

    from sigil.agents.operator import Operator, Step
    from sigil.agents.operator_scope import OperatorScope

    class FC:
        def classify(self, t): return {"fs.read": Tier.A0, "fs.write": Tier.A1}.get(t, Tier.A3)

    root = Path(tf.mkdtemp(prefix="op-dev-")); (root / "a.txt").write_text("X")
    s = _store()
    op = Operator(s, scope=OperatorScope(read_roots=[str(root)], auto_write_roots=[str(root)]),
                  classifier=FC(), trusted_pubkey=OP)
    rep, _ = op.preview([Step("delete", path=str(root / "a.txt"))])   # A3 → queued, needs approval
    device = generate_keypair()
    DeviceApprover(s, device_key=device).approve(rep.plan_seq)        # UNauthorized device approval
    assert not op.execute(rep.plan_seq).applied and (root / "a.txt").exists(), \
        "an unauthorized device cannot authorize operator execution"
    authorize_device(s, "phone", device.public_key_b64, OWNER)       # owner authorizes the device
    DeviceApprover(s, device_key=device).approve(rep.plan_seq)
    ex = op.execute(rep.plan_seq)
    assert ex.applied and not (root / "a.txt").exists(), \
        "an owner-authorized device approval authorizes the real operator execution"


def test_secrets_never_reach_the_spine():
    import os
    from pathlib import Path

    from sigil.platform.secrets import SecretStore
    s = _store()
    s.append(kind="message", source="x", actor="u", payload={"text": "hi"})
    SecretStore().set("SIGIL_TEST_SECRET2", "topsecret999")
    assert "topsecret999" not in Path(s.path).read_text(), "a secret never enters the append-only spine"
    os.environ.pop("SIGIL_TEST_SECRET2", None)


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = 0
    for fn in fns:
        try:
            fn(); print(f"  PASS  {fn.__name__}"); passed += 1
        except AssertionError as e:
            print(f"  FAIL  {fn.__name__}: {e}")
        except Exception as e:  # noqa: BLE001
            import traceback
            print(f"  ERROR {fn.__name__}: {e}")
            traceback.print_exc()
    print(f"{passed}/{len(fns)} Phase-7 WS-D (cross-platform + mobile) guarantees hold")
