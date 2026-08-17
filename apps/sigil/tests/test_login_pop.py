"""Slice S3 — per-user cryptographic identities: owner-bound Ed25519 pubkey + challenge/response
proof-of-possession login. Two lanes:

  * registry lane (`AccountsRegistry`): enroll_pubkey owner-binds a key that folds through resolve()/
    accounts()/account(); the binding rides INSIDE the owner signature (a forged binding is ignored);
    mint_session_bearer rotates a fresh working bearer that resolves.
  * HTTP lane (`/api/login/challenge` + `/api/login`): a full challenge → sign → PoP login yields a
    working bearer; a REPLAYED challenge, a WRONG key, a WRONG username, and an account with NO bound
    pubkey are each refused 401; the challenge nonce is single-use and unpredictable; a MUTATION that
    neuters verify_one to always-true flips the wrong-key case pass → leak (proving the sig is the gate).

FATAL-2: the new modules import no framework/strix.
"""
from __future__ import annotations

import itertools
import json
import tempfile
import threading
import time
import urllib.error
import urllib.request

import pytest

from sigil.governor.accounts import AccountsRegistry, Principal
from sigil.governor.identity import ensure_owner_keypair
from sigil.reuse import generate_keypair, sign
from sigil.spine.store import SpineStore
from sigil.ui import server as srv_mod
from sigil.ui.login_challenges import ChallengeLedger
from sigil.ui.server import build_server

DOMAIN = b"vigil-login-pop-v1\x00"
TOKEN = "owner-shared-token-abc123"
_iss = itertools.count(1)


def _issue() -> float:
    return float(next(_iss))


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


# =============================== registry lane ====================================

def _reg(store, owner):
    return AccountsRegistry(store, owner_key=owner, trusted_pubkey=owner.public_key_b64)


def test_enroll_binds_pubkey_and_folds_through_resolve_and_accounts():
    owner = generate_keypair()
    user = generate_keypair()
    s = _store()
    reg = _reg(s, owner)
    reg.create("alice", "operator", bearer_token="B" * 40, issued_at=_issue())
    assert reg.account("alice").user_pubkey is None          # bearer-only until enrolled

    reg.enroll_pubkey("alice", user.public_key_b64, issued_at=_issue())
    a = reg.account("alice")
    assert a.user_pubkey == user.public_key_b64 and a.role == "operator"
    # the bearer still resolves (enroll preserves the credential) and the field folds into accounts()
    assert reg.resolve("B" * 40) == Principal(username="alice", role="operator")
    assert reg.accounts()[0].user_pubkey == user.public_key_b64


def test_enroll_preserves_pubkey_across_assign_role():
    owner = generate_keypair()
    user = generate_keypair()
    s = _store()
    reg = _reg(s, owner)
    reg.create("bob", "viewer", bearer_token="bob-bearer-aaaaaaaaaaaa", issued_at=_issue())
    reg.enroll_pubkey("bob", user.public_key_b64, issued_at=_issue())
    reg.assign_role("bob", "operator", issued_at=_issue())    # role change must not drop the bound key
    a = reg.account("bob")
    assert a.role == "operator" and a.user_pubkey == user.public_key_b64


def test_a_forged_pubkey_binding_is_ignored_by_the_fold():
    owner = generate_keypair()
    attacker = generate_keypair()
    evil_user = generate_keypair()
    s = _store()
    reg = _reg(s, owner)
    reg.create("carol", "viewer", bearer_token="carol-bearer-bbbbbbbbbb", issued_at=_issue())
    # attacker forges an ACTIVE grant binding their own key to carol, signed by the ATTACKER key (not owner)
    from sigil.governor import accounts as acc
    from sigil.governor.authn import signed_payload
    a0 = reg.account("carol")
    core = {"signal": acc.SIGNAL, "username": "carol", "role": "viewer",
            "cred_hash": a0.cred_hash, "cred_salt": a0.cred_salt, "state": "active",
            "issued_at": 10_000.0, "user_pubkey": evil_user.public_key_b64}
    s.append(kind="event", source="governor", actor="WARDEN",
             payload={**signed_payload(core, attacker), "by": "owner"})
    # the forged binding never verifies in the fold → carol still has NO bound key (fail-closed)
    assert reg.account("carol").user_pubkey is None


def test_enroll_rejects_a_weak_or_malformed_key_and_unknown_account():
    owner = generate_keypair()
    s = _store()
    reg = _reg(s, owner)
    reg.create("dave", "viewer", bearer_token="dave-bearer-cccccccccc", issued_at=_issue())
    for bad in ("", "not-base64!!", "AAAA", "A" * 43 + "="):   # malformed / wrong-length keys
        with pytest.raises(ValueError):
            reg.enroll_pubkey("dave", bad, issued_at=_issue())
    with pytest.raises(ValueError):                            # unknown account is fail-closed
        reg.enroll_pubkey("ghost", generate_keypair().public_key_b64, issued_at=_issue())


def test_mint_session_bearer_rotates_a_fresh_working_bearer_preserving_identity():
    owner = generate_keypair()
    user = generate_keypair()
    s = _store()
    reg = _reg(s, owner)
    reg.create("erin", "analyst", bearer_token="erin-bearer-dddddddddd", issued_at=_issue())
    reg.enroll_pubkey("erin", user.public_key_b64, issued_at=_issue())
    b1, _ = reg.mint_session_bearer("erin", issued_at=_issue())
    assert reg.resolve(b1) == Principal(username="erin", role="analyst")
    # a second mint yields a DISTINCT bearer that also resolves; identity (role + pubkey) is preserved
    b2, _ = reg.mint_session_bearer("erin", issued_at=_issue())
    assert b2 != b1 and reg.resolve(b2) == Principal(username="erin", role="analyst")
    assert reg.account("erin").user_pubkey == user.public_key_b64


# =============================== challenge ledger =================================

def test_challenge_ledger_is_single_use_and_ttl_bounded():
    led = ChallengeLedger(tempfile.mktemp(suffix=".chal"), ttl_seconds=100.0)
    led.issue("chal-A", now=1000.0)
    assert led.consume("chal-A", now=1001.0) is True          # fresh, first use wins
    assert led.consume("chal-A", now=1002.0) is False         # single-use: a second use is refused
    assert led.consume("never-issued") is False               # unknown challenge → refused
    led.issue("chal-B", now=1000.0)
    assert led.consume("chal-B", now=2000.0) is False         # past TTL → refused (and cleaned)


# =============================== HTTP lane ========================================

def _spine():
    p = tempfile.mktemp(suffix=".jsonl")
    SpineStore(p).append(kind="message", source="x", actor="user", payload={"text": "hi"})
    return p


def _serve(spine_path):
    ensure_owner_keypair()                                    # the persisted owner identity signs grants
    s = build_server(token=TOKEN, port=0, spine_path=spine_path)
    port = s.server_address[1]
    threading.Thread(target=s.serve_forever, daemon=True).start()
    time.sleep(0.05)
    return s, port


def _post(port, path, body):
    h = {"Content-Type": "application/json",
         "Origin": f"http://127.0.0.1:{port}", "Host": f"127.0.0.1:{port}",
         "X-SIGIL-Token": TOKEN}
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=json.dumps(body).encode(),
                                 headers=h, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


def _login_post(port, body):
    """/api/login and /api/login/challenge require NO token (only same-origin). Send Origin/Host, no token."""
    h = {"Content-Type": "application/json",
         "Origin": f"http://127.0.0.1:{port}", "Host": f"127.0.0.1:{port}"}
    req = urllib.request.Request(f"http://127.0.0.1:{port}/api/login", data=json.dumps(body).encode(),
                                 headers=h, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


def _get_challenge(port):
    h = {"Content-Type": "application/json",
         "Origin": f"http://127.0.0.1:{port}", "Host": f"127.0.0.1:{port}"}
    req = urllib.request.Request(f"http://127.0.0.1:{port}/api/login/challenge", data=b"{}",
                                 headers=h, method="POST")
    with urllib.request.urlopen(req, timeout=5) as r:
        return json.loads(r.read().decode())["challenge"]


def _enroll(port, username, role):
    """Owner-create an account (over the owner-token action plane) and owner-bind a fresh user keypair.
    Returns the user KeyPair whose private half the client will sign challenges with."""
    code, d = _post(port, "/api/action", {"action": "create_account", "username": username, "role": role})
    assert code == 200, d
    user = generate_keypair()
    code, d = _post(port, "/api/action",
                    {"action": "enroll_pubkey", "username": username, "user_pubkey": user.public_key_b64})
    assert code == 200, d
    return user


def _authed_get(port, path, token):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", headers={"X-SIGIL-Token": token})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


def test_full_pop_login_yields_a_working_bearer():
    s, port = _serve(_spine())
    try:
        user = _enroll(port, "otto", "operator")
        chal = _get_challenge(port)
        sig = sign(user.private_key_b64, DOMAIN + chal.encode("utf-8"))
        code, d = _login_post(port, {"username": "otto", "challenge": chal, "signature": sig})
        assert code == 200 and d["authenticated"] is True and d["username"] == "otto"
        assert d["role"] == "operator" and "approve_a2" in d["permissions"]
        bearer = d["bearer"]
        assert bearer and _authed_get(port, "/api/snapshot", bearer) == 200   # the bearer really works
    finally:
        s.shutdown()


def test_replayed_challenge_is_refused():
    s, port = _serve(_spine())
    try:
        user = _enroll(port, "otto", "operator")
        chal = _get_challenge(port)
        sig = sign(user.private_key_b64, DOMAIN + chal.encode("utf-8"))
        triple = {"username": "otto", "challenge": chal, "signature": sig}
        assert _login_post(port, triple)[0] == 200            # first use succeeds (consumes the challenge)
        code, d = _login_post(port, triple)                    # exact replay of the same triple
        assert code == 401 and d["authenticated"] is False     # single-use challenge → refused
    finally:
        s.shutdown()


def test_wrong_key_and_wrong_username_are_refused():
    s, port = _serve(_spine())
    try:
        user = _enroll(port, "otto", "operator")
        _enroll(port, "eve", "viewer")
        # signature by the WRONG key over a fresh, valid challenge → 401
        chal = _get_challenge(port)
        wrong = generate_keypair()
        wsig = sign(wrong.private_key_b64, DOMAIN + chal.encode("utf-8"))
        assert _login_post(port, {"username": "otto", "challenge": chal, "signature": wsig})[0] == 401
        # otto's genuine signature aimed at a DIFFERENT username (eve) → 401 (the key is not eve's)
        chal2 = _get_challenge(port)
        osig = sign(user.private_key_b64, DOMAIN + chal2.encode("utf-8"))
        assert _login_post(port, {"username": "eve", "challenge": chal2, "signature": osig})[0] == 401
    finally:
        s.shutdown()


def test_pop_for_account_with_no_bound_pubkey_is_refused():
    s, port = _serve(_spine())
    try:
        # create the account but DO NOT enroll a pubkey
        assert _post(port, "/api/action",
                     {"action": "create_account", "username": "nokey", "role": "viewer"})[0] == 200
        chal = _get_challenge(port)
        # even a syntactically valid signature (by some key) must be refused: no bound key → no PoP
        k = generate_keypair()
        sig = sign(k.private_key_b64, DOMAIN + chal.encode("utf-8"))
        code, d = _login_post(port, {"username": "nokey", "challenge": chal, "signature": sig})
        assert code == 401 and "no cryptographic identity" in d["error"]
    finally:
        s.shutdown()


def test_challenges_are_distinct_and_unpredictable():
    s, port = _serve(_spine())
    try:
        seen = {_get_challenge(port) for _ in range(20)}
        assert len(seen) == 20                                 # distinct per call
        assert all(len(c) >= 40 for c in seen)                 # token_urlsafe(32) ⇒ ~43 chars of entropy
    finally:
        s.shutdown()


def test_mutation_neutering_verify_one_flips_wrong_key_pass_to_leak():
    """The load-bearing invariant: the Ed25519 signature IS the PoP gate. If verify_one is neutered to
    always-true, the WRONG-key attempt (which must be 401) instead succeeds (200 + a working bearer) — a
    leak. This proves the wrong-key refusal is enforced by the signature check, not incidental."""
    s, port = _serve(_spine())
    orig = srv_mod.verify_one
    try:
        _enroll(port, "otto", "operator")
        chal = _get_challenge(port)
        wrong = generate_keypair()
        wsig = sign(wrong.private_key_b64, DOMAIN + chal.encode("utf-8"))
        triple = {"username": "otto", "challenge": chal, "signature": wsig}
        # baseline: with the real verify_one, the wrong key is refused
        assert _login_post(port, triple)[0] == 401
        # mutate: force verify_one to always accept → the SAME wrong-key attempt now leaks a session bearer
        srv_mod.verify_one = lambda *a, **k: True
        chal2 = _get_challenge(port)                            # fresh challenge (the first was consumed)
        wsig2 = sign(wrong.private_key_b64, DOMAIN + chal2.encode("utf-8"))
        code, d = _login_post(port, {"username": "otto", "challenge": chal2, "signature": wsig2})
        assert code == 200 and d.get("bearer"), "mutation must flip the wrong-key refusal into a leak"
    finally:
        srv_mod.verify_one = orig
        s.shutdown()


# =============================== FATAL-2 ==========================================

def test_fatal2_new_modules_import_no_offense():
    import pathlib

    from sigil.reuse import assert_no_offense
    from sigil.ui import login_challenges as _lc
    assert_no_offense()                                        # must not raise in a sovereign env
    for mod in (_lc, srv_mod):
        src = pathlib.Path(mod.__file__).read_text(encoding="utf-8")
        assert "import framework" not in src and "import strix" not in src
        assert "from framework" not in src and "from strix" not in src
