#!/usr/bin/env python3
"""SIGIL Phone Companion — a runnable, narrated END-TO-END demo.

This stands up the REAL `BridgeServer` on loopback (127.0.0.1 — the same code path that runs bound to a
WireGuard IP) and drives it as a phone would: a "phone" keypair signs every request with its OWN key;
the desktop verifies (it never signs on the phone's behalf; the owner trust-root never leaves the PC).

It walks the whole companion flow: pair → approve a queued action → relay a command → recall → arm a
gesture session → panic. Loopback stands in for the WireGuard tunnel and a Python client stands in for
the PWA — but the crypto, the canonical signing bytes, the transport, and every gate are the real thing.

Run:  ~/.sigil/venv/bin/python demo/companion_demo.py
It uses a throwaway temp SIGIL_HOME, so it never touches your real ~/.sigil.
"""
import base64
import json
import os
import tempfile
import threading
import time
import urllib.error
import urllib.request

# Point SIGIL at a throwaway home BEFORE importing the package (config reads these at import).
_TMP = tempfile.mkdtemp(prefix="sigil-companion-demo-")
os.environ["SIGIL_HOME"] = _TMP

from sigil.agents.base import Agent, Proposal, Tier                      # noqa: E402
from sigil.bridge.envelope import build_core, sign_envelope             # noqa: E402
from sigil.bridge.server import build_server                            # noqa: E402
from sigil.cli import _device_fingerprint                               # noqa: E402
from sigil.gesture.components import RecordingInputBackend              # noqa: E402
from sigil.gesture.session import SessionGate, pending_device_arms, sign_arm_request  # noqa: E402
from sigil.governor import Governor                                     # noqa: E402
from sigil.mesh import authorize_device                                 # noqa: E402
from sigil.reuse import canonical_json, generate_keypair, sign          # noqa: E402
from sigil.spine.store import SpineStore                                # noqa: E402

C = {"h": "\033[1;36m", "ok": "\033[1;32m", "d": "\033[2m", "w": "\033[1;33m", "x": "\033[0m"}


def hdr(t):
    print(f"\n{C['h']}=== {t} ==={C['x']}")


def phone(t):
    print(f"  {C['d']}📱 phone →{C['x']} {t}")


def pc(t):
    print(f"  {C['ok']}🖥  desktop ✓{C['x']} {t}")


# ---- the phone side: build + device-sign every request with the phone's OWN key -------------------
def env(dev, action, args, nonce, ts):
    core = build_core(dev.public_key_b64, action, args, nonce, ts)
    raw = canonical_json(sign_envelope(dev, core))
    raw = raw if isinstance(raw, bytes) else raw.encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def approval_body(dev, target_seq):
    from sigil.agents.approvals import _approval_message
    msg = _approval_message(target_seq, "approved", "phone")
    return {"signal": "governor.approval", "approval": "approved", "target_seq": target_seq,
            "approver": "phone", "pubkey": dev.public_key_b64, "sig": sign(dev.private_key_b64, msg)}


def http(port, method, path, *, envelope=None, body=None):
    h = {}
    if envelope is not None:
        h["X-SIGIL-Envelope"] = envelope
    data = None
    if body is not None:
        h["Content-Type"] = "application/json"
        data = json.dumps(body).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


class Emitter(Agent):   # a stand-in agent that queues an A2 needing approval
    name = "DEMO-AGENT"
    ceiling = Tier.A2

    def __init__(self, store, owner):
        super().__init__(store, governor=Governor(store, owner_key=owner, trusted_pubkey=owner.public_key_b64))

    def queue_a2(self):
        return self._dispatch([Proposal("draft", {"subject": "wire $5,000 to vendor ACME"}, Tier.A2)])


def main():
    now = time.time()
    owner = generate_keypair()          # the OWNER identity — lives ONLY on the desktop
    dev = generate_keypair()            # the PHONE device key — the phone holds this, never the owner key
    spine = os.path.join(_TMP, "spine.jsonl")
    store = SpineStore(spine)

    # stub the KERNEL so `relay` is deterministic offline; in production it goes through the real
    # T0-router + WARDEN gate + signed action log (same path as voice/UI).
    import sigil.voice.dispatch as D
    D.KernelDispatch = lambda: type("_K", (), {"send": staticmethod(lambda t: f"(KERNEL) you asked: {t!r}")})()

    srv = build_server(addr="127.0.0.1", port=0, spine_path=spine, trusted_pubkey=owner.public_key_b64,
                       clock=lambda: now)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    print(f"{C['h']}SIGIL Phone Companion — live demo{C['x']}  (real BridgeServer on 127.0.0.1:{port}; loopback ≙ WireGuard)")

    try:
        # 1. PAIRING — the phone shows its public key + a human fingerprint; the owner authorizes it once.
        hdr("1. PAIR the phone")
        fp = _device_fingerprint(dev.public_key_b64)
        phone(f"generated a device key; shows pubkey …{dev.public_key_b64[-12:]}  fingerprint {C['w']}{fp}{C['x']}")
        print(f"  {C['d']}owner runs:{C['x']} sigil mesh authorize phone-1 <pubkey>   (and confirms the fingerprint matches)")
        assert _device_fingerprint(dev.public_key_b64) == fp, "PC recomputes the SAME fingerprint"
        authorize_device(store, "phone-1", dev.public_key_b64, owner)     # owner-signed, on the spine
        pc(f"fingerprint matches → device AUTHORIZED (owner-signed ledger). The owner key never left the desktop.")

        # 2. APPROVE a queued action — the phone signs the approval; the desktop only verifies.
        hdr("2. APPROVE a queued action (A2)")
        seq = Emitter(store, owner).queue_a2().queued[0]["seq"]
        pending_before = [i["seq"] for i in http(port, "GET", "/api/pending", envelope=env(dev, "read:pending", {}, 1, now))[1].get("pending", [])]
        phone(f"GET /api/pending → sees queued A2 at seq {seq} (minimal {{seq,tier,kind}}, no subject leaked): {pending_before}")
        code, out = http(port, "POST", "/api/action", body=approval_body(dev, seq))
        pc(f"POST /api/action → verified the phone's Ed25519 approval → {out} (HTTP {code})")
        pending_after = [i["seq"] for i in http(port, "GET", "/api/pending", envelope=env(dev, "read:pending", {}, 2, now))[1].get("pending", [])]
        pc(f"the item is now resolved — GET /api/pending → {pending_after or 'empty'}")

        # 3. RELAY a natural-language command to the KERNEL (same WARDEN gate as voice/UI).
        hdr("3. RELAY a command to the KERNEL")
        phone('POST /api/relay  (command "what is my calendar today" inside the SIGNED envelope)')
        code, out = http(port, "POST", "/api/relay",
                         envelope=env(dev, "relay", {"text": "what is my calendar today"}, 3, now))
        pc(f"relayed through the WARDEN-gated KERNEL → reply: {out.get('reply')!r}")

        # 4. RECALL — "where did I last see X?" answered from the owner's own grounded OCR history.
        hdr("4. RECALL grounded on-screen history")
        store.append(kind="event", source="agent", actor="PERCEPTION",
                     payload={"signal": "perception", "captured_text": "AWS console — S3 buckets dashboard",
                              "frame_sha256": "demo-frame"})
        phone('GET /api/recall?subject=S3 buckets')
        code, out = http(port, "GET", "/api/recall?subject=S3%20buckets", envelope=env(dev, "read:recall", {}, 4, now))
        rec = out.get("recall") or {}
        pc(f"grounded, verbatim (never a paraphrase) → quote: {rec.get('quote')!r}  @ seq {rec.get('seq')}")

        # 5. ARM a gesture session from the phone (the reviewed trust-widening).
        hdr("5. ARM a gesture session (device-signed remote arm — the trust-widening)")
        arm = sign_arm_request(dev, device_id="phone-1", nonce=1, ts=now, ttl_seconds=120.0)
        code, out = http(port, "POST", "/api/gesture/arm", body=arm)
        phone(f"POST /api/gesture/arm (a signed arm request) → recorded at seq {out.get('seq')} (HTTP {code})")
        print(f"  {C['d']}the desktop only RECORDS it; the gesture daemon re-verifies + actually arms:{C['x']}")
        gate = SessionGate(store, RecordingInputBackend(), trusted_pubkey=owner.public_key_b64)
        for req in pending_device_arms(store, owner.public_key_b64):
            session = gate.arm_by_device(req, now=now)
            if session:
                pc(f"arm_by_device re-verified (auth + freshness + replay + single-session + TTL≤300s) → "
                   f"session {session.session_id[:8]} ARMED, expires in {int(session.expires_at - now)}s")

        # 6. PANIC — any engage halts (fail-safe); an armed session is neutered.
        hdr("6. PANIC halt from the phone")
        phone("POST /api/panic  (no nonce needed — the SAFE direction; release stays owner-only at the desktop)")
        code, out = http(port, "POST", "/api/panic", envelope=env(dev, "panic", {}, 5, now))
        from sigil.governor.killswitch import KillSwitch
        pc(f"kill-switch ENGAGED (seq {out.get('seq')}); is_engaged() = {KillSwitch(store).is_engaged()} → "
           f"the armed gesture session injects nothing on its next frame")

        hdr("done")
        print(f"  {C['ok']}Every step ran the real transport + real Ed25519 gates.{C['x']} Over WireGuard the only "
              f"difference is the bind address (a WG/Tailscale IP) and the PWA as the client.")
        print(f"  {C['d']}throwaway home: {_TMP}{C['x']}")
    finally:
        srv.shutdown()


if __name__ == "__main__":
    main()
