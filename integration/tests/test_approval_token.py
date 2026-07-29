"""M2 — the per-action, single-use, owner-signed approval token + its gate wrapper.

Crypto-grade: every property is a falsifiable test. The token authorizes EXACTLY ONE action, spent ONCE,
signed by the PINNED owner key, inside a bounded window — and can NEVER widen scope past a CRUCIBLE deny.

Framework-free (``vigil_core`` + stdlib only), so it runs in BOTH the sovereign-path and offense-path CI
invocations. Run: PYTHONPATH=integration:gateway pytest integration/tests/test_approval_token.py -q
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from vigil_core import IntegrityError, generate_keypair

from vigil_integration.live.approval_token import (
    ApprovalAction,
    ApprovalAuthority,
    ApprovalRefused,
    action_digest,
    consume_token,
    mint_token,
    require_approval,
    verify_token,
)
from vigil_integration.live.nonce_ledger import NonceLedger
from vigil_integration.live.wiring import build_approval_gate

NOW = 1000.0


def _owner():
    kp = generate_keypair()
    return kp, ApprovalAuthority(owner_key_id="owner-yubikey", owner_public_key_b64=kp.public_key_b64)


def _action(tool="sqlmap", target="127.0.0.1", args=None):
    args = {"target": target, "flags": ["--batch"]} if args is None else args
    return ApprovalAction(tool_name=tool, target=target, action_digest=action_digest(tool, target, args))


def _mint(kp, authority, action, *, nonce="nonce-1", nb=NOW - 10, na=NOW + 100, key_id=None):
    return mint_token(action, owner_private_key_b64=kp.private_key_b64,
                      key_id=key_id or authority.owner_key_id, nonce=nonce, not_before=nb, not_after=na)


def _ledger(tmp_path):
    return NonceLedger(str(tmp_path / "nonces"))


# --- the happy path + single-use --------------------------------------------------------------------

def test_valid_token_authorizes_then_is_single_use(tmp_path):
    kp, auth = _owner()
    act = _action()
    tok = _mint(kp, auth, act)
    led = _ledger(tmp_path)

    d1 = consume_token(tok, act, authority=auth, now=NOW, ledger=led)
    assert d1.authorized and d1.nonce == "nonce-1"
    # spent — a second consume of the SAME token is a replay DENY (nonce burned).
    d2 = consume_token(tok, act, authority=auth, now=NOW, ledger=led)
    assert not d2.authorized and "consumed" in d2.reason.lower()


def test_verify_token_is_pure_no_burn(tmp_path):
    # verify_token CHECKS is_consumed but never burns — two verifies both pass; only consume_token spends.
    kp, auth = _owner()
    act = _action()
    tok = _mint(kp, auth, act)
    led = _ledger(tmp_path)
    assert verify_token(tok, act, authority=auth, now=NOW, is_consumed=led.is_consumed).authorized
    assert verify_token(tok, act, authority=auth, now=NOW, is_consumed=led.is_consumed).authorized
    assert not led.is_consumed("nonce-1")           # still unspent
    assert consume_token(tok, act, authority=auth, now=NOW, ledger=led).authorized
    assert led.is_consumed("nonce-1")               # now spent


# --- action binding ---------------------------------------------------------------------------------

def test_token_bound_to_action_A_refuses_action_B(tmp_path):
    kp, auth = _owner()
    act_a = _action(tool="sqlmap", target="127.0.0.1", args={"flags": ["--dump"]})
    tok = _mint(kp, auth, act_a)
    led = _ledger(tmp_path)
    # same tool+target, DIFFERENT args ⇒ different action_digest ⇒ refuse.
    act_b = _action(tool="sqlmap", target="127.0.0.1", args={"flags": ["--os-shell"]})
    assert not consume_token(tok, act_b, authority=auth, now=NOW, ledger=led).authorized
    # different tool, and different target, also refuse.
    assert not consume_token(tok, _action(tool="hydra", target="127.0.0.1"),
                             authority=auth, now=NOW, ledger=led).authorized
    assert not consume_token(tok, _action(tool="sqlmap", target="10.0.0.9"),
                             authority=auth, now=NOW, ledger=led).authorized
    assert not led.is_consumed("nonce-1")           # a rejected token never burned the nonce


# --- window + dead-man's-switch ---------------------------------------------------------------------

def test_expired_and_not_yet_valid_tokens_refuse(tmp_path):
    kp, auth = _owner()
    act = _action()
    led = _ledger(tmp_path)
    expired = _mint(kp, auth, act, nonce="n-exp", nb=NOW - 200, na=NOW - 100)
    assert not consume_token(expired, act, authority=auth, now=NOW, ledger=led).authorized
    early = _mint(kp, auth, act, nonce="n-early", nb=NOW + 100, na=NOW + 200)
    assert not consume_token(early, act, authority=auth, now=NOW, ledger=led).authorized


def test_deadman_switch_rejects_a_long_lived_sleeper(tmp_path):
    kp, auth = _owner()
    act = _action()
    led = _ledger(tmp_path)
    # window 2 hours >> the 900s policy cap ⇒ void even though `now` is inside it.
    sleeper = _mint(kp, auth, act, nonce="n-sleep", nb=NOW - 10, na=NOW + 7200)
    d = consume_token(sleeper, act, authority=auth, now=NOW, ledger=led)
    assert not d.authorized and "lifetime" in d.reason.lower()


# --- key pin + forgery + tamper ---------------------------------------------------------------------

def test_wrong_key_id_refuses_even_if_signature_valid(tmp_path):
    # A token the owner key signed but that NAMES a different key_id must refuse (the I4 free-key_id BLOCK):
    # verification is pinned to the deployment owner_key_id, not the token's self-declared id.
    kp, auth = _owner()
    act = _action()
    led = _ledger(tmp_path)
    tok = _mint(kp, auth, act, key_id="worker-self")     # signed by the owner key but claims a worker id
    d = consume_token(tok, act, authority=auth, now=NOW, ledger=led)
    assert not d.authorized and "pinned owner key" in d.reason.lower()


def test_forged_token_from_a_non_owner_key_refuses(tmp_path):
    kp, auth = _owner()
    attacker, _ = _owner()                               # a different keypair
    act = _action()
    led = _ledger(tmp_path)
    # attacker signs a token but stamps the pinned owner_key_id — signature verify against the pinned owner
    # PUBLIC key fails.
    forged = mint_token(act, owner_private_key_b64=attacker.private_key_b64,
                        key_id=auth.owner_key_id, nonce="n-forge", not_before=NOW - 10, not_after=NOW + 100)
    d = consume_token(forged, act, authority=auth, now=NOW, ledger=led)
    assert not d.authorized and ("signature is invalid" in d.reason.lower())


def test_tampered_field_after_signing_refuses(tmp_path):
    kp, auth = _owner()
    act = _action(target="127.0.0.1")
    led = _ledger(tmp_path)
    tok = _mint(kp, auth, act)
    # move the token to a different target AFTER signing (both the token and the action, so binding passes)
    # — the signature no longer covers the payload ⇒ refuse.
    tampered = tok.__class__(**{**tok.__dict__, "target": "10.9.9.9"})
    act2 = ApprovalAction(tool_name=tok.tool_name, target="10.9.9.9", action_digest=tok.action_digest)
    d = consume_token(tampered, act2, authority=auth, now=NOW, ledger=led)
    assert not d.authorized and "signature is invalid" in d.reason.lower()


# --- malformed / fail-closed ------------------------------------------------------------------------

def test_blank_nonce_and_bad_inputs_refuse(tmp_path):
    kp, auth = _owner()
    act = _action()
    led = _ledger(tmp_path)
    blank = _mint(kp, auth, act, nonce="")
    assert not consume_token(blank, act, authority=auth, now=NOW, ledger=led).authorized
    # non-numeric now, wrong action type, wrong token type → deny, never raise.
    assert not verify_token(_mint(kp, auth, act), act, authority=auth, now="soon",
                            is_consumed=led.is_consumed).authorized
    assert not verify_token(_mint(kp, auth, act), SimpleNamespace(tool_name="x", target="y", action_digest="z"),
                            authority=auth, now=NOW, is_consumed=led.is_consumed).authorized


def test_weak_owner_key_is_rejected_at_authority_construction():
    # A non-canonical / low-order public key can never become a trust root (load_public_key bars it). The
    # all-zero 32-byte key is a LOW-ORDER point — assert that SPECIFIC rejection, not merely "some error".
    with pytest.raises(IntegrityError):
        ApprovalAuthority(owner_key_id="owner", owner_public_key_b64="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")


def test_require_approval_raises_fail_closed(tmp_path):
    kp, auth = _owner()
    act = _action()
    led = _ledger(tmp_path)
    assert require_approval(_mint(kp, auth, act), act, authority=auth, now=NOW, ledger=led) == "nonce-1"
    with pytest.raises(ApprovalRefused):
        require_approval(_mint(kp, auth, act, nonce="n2", na=NOW - 1), act, authority=auth, now=NOW, ledger=led)


# --- the gate wrapper: never widens scope; upgrades only a queue -------------------------------------

def _verdict(outcome):
    return SimpleNamespace(outcome=outcome, allowed=(outcome == "allow"), reason=f"base:{outcome}",
                           crucible_allowed=(outcome != "deny"), warden=None)


def test_gate_upgrades_a_queue_with_a_valid_token_once(tmp_path):
    kp, auth = _owner()
    act = _action(tool="sqlmap", target="127.0.0.1")
    tok = _mint(kp, auth, act)
    led = _ledger(tmp_path)
    gate = build_approval_gate(lambda t, tg, d=False, **k: _verdict("queue"),
                               authority=auth, ledger=led, now=lambda: NOW,
                               token_source=lambda: (tok, act))
    v1 = gate("sqlmap", "127.0.0.1", False)
    assert v1.allowed and v1.outcome == "allow" and "per-action token" in v1.reason
    # replay: the token is spent, so the SAME action stays queued (never a second auto-run).
    v2 = gate("sqlmap", "127.0.0.1", False)
    assert v2.outcome == "queue" and not getattr(v2, "allowed", False)


def test_gate_never_widens_a_crucible_deny(tmp_path):
    # THE load-bearing property: a token can NEVER lift a CRUCIBLE deny (out-of-scope / tripped kill-switch /
    # budget) — that is a 'deny', not a 'queue', so the wrapper returns it untouched and never burns a nonce.
    kp, auth = _owner()
    act = _action(tool="sqlmap", target="127.0.0.1")
    tok = _mint(kp, auth, act)
    led = _ledger(tmp_path)
    gate = build_approval_gate(lambda t, tg, d=False, **k: _verdict("deny"),
                               authority=auth, ledger=led, now=lambda: NOW,
                               token_source=lambda: (tok, act))
    v = gate("sqlmap", "127.0.0.1", False)
    assert v.outcome == "deny" and not v.allowed
    assert not led.is_consumed("nonce-1")           # a denied action never spent the token


def test_gate_auto_allow_untouched_and_no_token_spent(tmp_path):
    kp, auth = _owner()
    act = _action()
    led = _ledger(tmp_path)
    gate = build_approval_gate(lambda t, tg, d=False, **k: _verdict("allow"),
                               authority=auth, ledger=led, now=lambda: NOW, token_source=lambda: (_mint(kp, auth, act), act))
    v = gate("nmap", "127.0.0.1", False)
    assert v.outcome == "allow"
    assert not led.is_consumed("nonce-1")           # an auto-allow needs no token → none burned


def test_gate_without_a_matching_token_stays_queued(tmp_path):
    kp, auth = _owner()
    act = _action(tool="sqlmap", target="127.0.0.1")
    tok = _mint(kp, auth, act)
    led = _ledger(tmp_path)
    # a token for a DIFFERENT (tool,target) than the gate call → the wrapper refuses to apply it.
    gate = build_approval_gate(lambda t, tg, d=False, **k: _verdict("queue"),
                               authority=auth, ledger=led, now=lambda: NOW, token_source=lambda: (tok, act))
    assert gate("hydra", "127.0.0.1", False).outcome == "queue"        # tool mismatch
    assert not led.is_consumed("nonce-1")
    # no token at all → stays queued.
    gate2 = build_approval_gate(lambda t, tg, d=False, **k: _verdict("queue"),
                                authority=auth, ledger=led, now=lambda: NOW, token_source=lambda: None)
    assert gate2("sqlmap", "127.0.0.1", False).outcome == "queue"


def test_gate_expired_token_stays_queued(tmp_path):
    kp, auth = _owner()
    act = _action(tool="sqlmap", target="127.0.0.1")
    expired = _mint(kp, auth, act, na=NOW - 1)
    led = _ledger(tmp_path)
    gate = build_approval_gate(lambda t, tg, d=False, **k: _verdict("queue"),
                               authority=auth, ledger=led, now=lambda: NOW, token_source=lambda: (expired, act))
    assert gate("sqlmap", "127.0.0.1", False).outcome == "queue"
