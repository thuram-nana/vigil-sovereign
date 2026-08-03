"""I4 — m-of-n threshold authorization for destructive / high-blast offense actions.

Load-bearing properties: a destructive action is authorized ONLY when a quorum of distinct trusted
authorizers signed THIS exact action, EVERY mandatory signer (the owner) is among them, the
authorization is in-window, not a long-lived sleeper, and not already consumed. Fail-closed always."""

from __future__ import annotations

import threading

import pytest

from vigil_core import (
    AuthorizerKey,
    TrustRoot,
    evidence_signing_bytes,
    generate_keypair,
    sign,
)
from vigil_integration.destruction_gate import (
    DEFAULT_POLICY,
    DestructionAuthority,
    DestructionAuthorization,
    DestructionRefused,
    DestructiveAction,
    Signature,
    SignedDestructionAuthorization,
    authorization_signing_bytes,
    authorize_destruction,
    consume_authorization,
    require_destruction_authorization,
    sign_authorization,
)
from vigil_integration.live.nonce_ledger import NonceLedger

OWNER, WORKER, POLICY = generate_keypair(), generate_keypair(), generate_keypair()
TRUST = TrustRoot(threshold=2, authorizers=[
    AuthorizerKey(key_id="owner", name="owner", public_key_b64=OWNER.public_key_b64),
    AuthorizerKey(key_id="worker", name="worker", public_key_b64=WORKER.public_key_b64),
    AuthorizerKey(key_id="policy", name="policy", public_key_b64=POLICY.public_key_b64)])
AUTHORITY = DestructionAuthority(trust_root=TRUST, mandatory_signer_ids={"owner"})

NOW = 1_000_000.0
_SIGNERS = {"owner": OWNER, "worker": WORKER, "policy": POLICY}
_FRESH = lambda nonce: False  # noqa: E731 — nothing consumed yet (explicit, never a default)


def _action(**over):
    base = dict(action_id="rm-target-db-001", engagement_slug="acme", target="db.acme.internal",
                blast_class="destructive")
    base.update(over)
    return DestructiveAction(**base)


def _auth(action=None, *, not_before=NOW - 10, not_after=NOW + 300, nonce="nonce-abc-123"):
    a = action or _action()
    return DestructionAuthorization(
        action_id=a.action_id, engagement_slug=a.engagement_slug, target=a.target,
        blast_class=a.blast_class, not_before=not_before, not_after=not_after, nonce=nonce)


def _signed(auth=None, signer_ids=("owner", "worker", "policy")):
    auth = auth or _auth()
    return sign_authorization(auth, [(kid, _SIGNERS[kid].private_key_b64) for kid in signer_ids])


def _decide(action=None, signed=None, **over):
    kw = dict(authority=AUTHORITY, now=NOW, is_consumed=_FRESH)
    kw.update(over)
    return authorize_destruction(action or _action(), signed or _signed(), **kw)


# --- the authority artifact binds the mandatory signer set (BLOCK-1 fix) ----------------------

def test_authority_rejects_empty_or_unregistered_mandatory_set():
    with pytest.raises(ValueError, match="mandatory"):
        DestructionAuthority(trust_root=TRUST, mandatory_signer_ids=frozenset())
    with pytest.raises(ValueError, match="not registered"):
        DestructionAuthority(trust_root=TRUST, mandatory_signer_ids={"ghost"})


def test_full_quorum_with_owner_authorizes():
    d = _decide()
    assert d.authorized is True and d.nonce == "nonce-abc-123"


def test_quorum_without_the_mandatory_owner_is_refused():
    # worker + policy meet threshold 2, but the authority's mandatory owner is absent; the mandatory
    # set lives in the immutable authority, so a caller cannot rename the owner to a signer present.
    d = _decide(signed=_signed(signer_ids=("worker", "policy")))
    assert d.authorized is False and "mandatory" in d.reason


def test_worker_cannot_rename_itself_as_owner():
    # the BLOCK-1 attack: a compromised worker names its own id mandatory. With the mandatory set bound
    # into the authority (not a per-call string) it cannot — building an authority whose mandatory set
    # is {"worker"} is a DIFFERENT deployment artifact, and the real authority still demands the owner.
    d = _decide(signed=_signed(signer_ids=("worker", "policy")))
    assert d.authorized is False  # under the REAL authority, worker+policy is refused
    # even an authority that (mis)designates worker as mandatory still requires a genuine worker sig —
    # it cannot conjure the owner's authority; and such an authority is a distinct, owner-chosen config.
    worker_authority = DestructionAuthority(trust_root=TRUST, mandatory_signer_ids={"worker"})
    assert authorize_destruction(_action(), _signed(signer_ids=("owner", "policy")),
                                 authority=worker_authority, now=NOW, is_consumed=_FRESH).authorized is False


def test_below_threshold_is_refused():
    d = _decide(signed=_signed(signer_ids=("owner",)))  # 1 < 2
    assert d.authorized is False and "threshold" in d.reason


def test_owner_plus_one_meets_threshold_and_mandatory():
    for second in ("worker", "policy"):
        assert _decide(signed=_signed(signer_ids=("owner", second))).authorized is True


def test_multiple_mandatory_signers_all_required():
    auth2 = DestructionAuthority(trust_root=TRUST, mandatory_signer_ids={"owner", "policy"})
    kw = dict(authority=auth2, now=NOW, is_consumed=_FRESH)
    assert authorize_destruction(_action(), _signed(signer_ids=("owner", "policy")), **kw).authorized is True
    # owner + worker meets threshold 2 but 'policy' (also mandatory) is missing → refused
    d = authorize_destruction(_action(), _signed(signer_ids=("owner", "worker")), **kw)
    assert d.authorized is False and "policy" in d.reason


# --- action binding ---------------------------------------------------------------------------

def test_action_binding_rejects_a_different_target():
    auth = _auth(_action(target="db.acme.internal"))
    d = _decide(action=_action(target="prod.acme.internal"), signed=_signed(auth))
    assert d.authorized is False and "binding" in d.reason


def test_action_binding_rejects_a_different_action_id_or_class():
    signed = _signed(_auth(_action(action_id="rm-target-db-001", blast_class="destructive")))
    assert _decide(action=_action(action_id="DIFFERENT"), signed=signed).authorized is False
    assert _decide(action=_action(blast_class="high-blast"), signed=signed).authorized is False


# --- window + dead-man's-switch ---------------------------------------------------------------

def test_outside_the_window_is_refused():
    assert _decide(now=NOW - 100).authorized is False    # before not_before
    assert _decide(now=NOW + 10_000).authorized is False  # after not_after


def test_dead_mans_switch_rejects_a_long_lived_sleeper():
    sleeper = _auth(not_before=NOW - 10, not_after=NOW + 100_000)
    d = _decide(signed=_signed(sleeper))
    assert d.authorized is False and "lifetime" in d.reason


def test_window_exactly_at_the_policy_bound_is_allowed():
    lifetime = DEFAULT_POLICY.max_authorization_lifetime
    edge = _auth(not_before=NOW, not_after=NOW + lifetime)
    assert _decide(signed=_signed(edge), now=NOW + 1).authorized is True
    over = _auth(not_before=NOW, not_after=NOW + lifetime + 1)
    assert _decide(signed=_signed(over), now=NOW + 1).authorized is False


# --- single-use (required, no fail-open default) ----------------------------------------------

def test_single_use_replay_is_refused():
    consumed = {"nonce-abc-123"}
    d = _decide(is_consumed=lambda n: n in consumed)
    assert d.authorized is False and "consumed" in d.reason


def test_single_use_is_required_no_permissive_default():
    # the gate has NO default is_consumed — omitting it is a TypeError, never a silent fail-open.
    with pytest.raises(TypeError):
        authorize_destruction(_action(), _signed(), authority=AUTHORITY, now=NOW)


def test_single_use_check_error_fails_closed():
    def boom(_n):
        raise RuntimeError("spine unavailable")
    d = _decide(is_consumed=boom)
    assert d.authorized is False and "fail closed" in d.reason


def test_empty_nonce_is_refused():
    d = _decide(signed=_signed(_auth(nonce="")))
    assert d.authorized is False and "nonce" in d.reason


# --- fail-closed on malformed / type-confused input (MED-2) -----------------------------------

def test_string_window_is_a_deny_not_a_raise():
    bad = SignedDestructionAuthorization(
        authorization=DestructionAuthorization(
            **{**_auth().signing_payload(), "not_before": "soon"}),  # str, not numeric
        signatures=_signed().signatures)
    d = _decide(signed=bad)
    assert d.authorized is False and "numeric" in d.reason


def test_non_signature_in_the_list_is_a_deny_not_a_raise():
    bad = SignedDestructionAuthorization(authorization=_auth(), signatures=("not-a-signature",))
    d = _decide(signed=bad)
    assert d.authorized is False and "signature list" in d.reason


def test_non_numeric_now_is_refused():
    d = _decide(now="later")
    assert d.authorized is False


def test_behavior_overriding_subclass_is_refused():
    # a subclass that overrides matches() could decouple action-binding from the signed bytes; the
    # gate accepts only the concrete record (exact-type check), so such an instance is denied.
    class LyingAuth(DestructionAuthorization):
        def matches(self, action):  # would authorize ANY action
            return True
    lying = LyingAuth(**_auth(_action(target="db.acme.internal")).signing_payload())
    signed = SignedDestructionAuthorization(authorization=lying, signatures=_signed().signatures)
    d = _decide(action=_action(target="prod.acme.internal"), signed=signed)
    assert d.authorized is False and "malformed authorization" in d.reason


def test_tampered_authorization_breaks_the_threshold():
    signed = _signed(_auth(_action(target="db.acme.internal")))
    tampered = SignedDestructionAuthorization(
        authorization=DestructionAuthorization(
            **{**signed.authorization.signing_payload(), "target": "prod.acme.internal"}),
        signatures=signed.signatures)
    d = _decide(action=_action(target="prod.acme.internal"), signed=tampered)
    assert d.authorized is False and "threshold" in d.reason


def test_malformed_signature_material_fails_closed():
    signed = _signed()
    bad = SignedDestructionAuthorization(
        authorization=signed.authorization,
        signatures=(Signature(key_id="owner", signature_b64="!!!not-base64!!!"), signed.signatures[1]))
    d = _decide(signed=bad)
    assert d.authorized is False  # IntegrityError normalized to a deny, not raised


def test_non_gated_blast_class_is_refused_here():
    a = DestructiveAction(action_id="x", engagement_slug="acme", target="t", blast_class="benign")
    auth = DestructionAuthorization(action_id="x", engagement_slug="acme", target="t",
                                    blast_class="benign", not_before=NOW - 1, not_after=NOW + 10,
                                    nonce="n1")
    d = authorize_destruction(a, sign_authorization(auth, [("owner", OWNER.private_key_b64),
                                                           ("worker", WORKER.private_key_b64)]),
                              authority=AUTHORITY, now=NOW, is_consumed=_FRESH)
    assert d.authorized is False and "not threshold-gated" in d.reason


# --- domain separation ------------------------------------------------------------------------

def test_a_destruction_authorization_signature_cannot_be_an_evidence_cert():
    auth = _auth()
    cert_payload = auth.signing_payload()  # identical field bytes, different domain
    assert authorization_signing_bytes(auth) != evidence_signing_bytes(cert_payload)
    ev_sigs = (Signature(key_id="owner", signature_b64=sign(OWNER.private_key_b64, evidence_signing_bytes(cert_payload))),
               Signature(key_id="worker", signature_b64=sign(WORKER.private_key_b64, evidence_signing_bytes(cert_payload))))
    d = _decide(signed=SignedDestructionAuthorization(authorization=auth, signatures=ev_sigs))
    assert d.authorized is False and "threshold" in d.reason


# --- the raising wrapper ----------------------------------------------------------------------

def test_require_raises_on_refusal_and_returns_nonce_on_allow():
    assert require_destruction_authorization(
        _action(), _signed(), authority=AUTHORITY, now=NOW, is_consumed=_FRESH) == "nonce-abc-123"
    with pytest.raises(DestructionRefused, match="mandatory"):
        require_destruction_authorization(
            _action(), _signed(signer_ids=("worker", "policy")),
            authority=AUTHORITY, now=NOW, is_consumed=_FRESH)


# --- T6: the ATOMIC check-and-consume (overclaim O5 fix) --------------------------------------

def test_consume_authorization_atomic_single_winner(tmp_path):
    # THE O5 fix: of N concurrent consumers of ONE authorization over ONE ledger, EXACTLY ONE wins the
    # atomic burn (the ledger's O_EXCL create is the serialization point); every other loses the race and
    # is DENIED as a replay. Mirrors the 16-thread barrier harness in test_codefix_runner.py.
    ledger = NonceLedger(str(tmp_path / "nonces"))
    signed = _signed()                       # one owner+worker+policy authorization, nonce "nonce-abc-123"
    results = []
    barrier = threading.Barrier(16)
    lock = threading.Lock()

    def _race():
        barrier.wait()
        d = consume_authorization(_action(), signed, authority=AUTHORITY, now=NOW, ledger=ledger)
        with lock:
            results.append(d)
    threads = [threading.Thread(target=_race) for _ in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    won = [d for d in results if d.authorized is True]
    lost = [d for d in results if d.authorized is False]
    assert len(won) == 1 and won[0].nonce == "nonce-abc-123"     # atomic single-use under concurrency
    assert len(lost) == 15
    assert all("consumed" in d.reason for d in lost)             # every loser is a replay DENY
    assert ledger.is_consumed("nonce-abc-123") is True           # the one authorization is now spent


def test_consume_authorization_sequential_replay_denied(tmp_path):
    ledger = NonceLedger(str(tmp_path / "nonces"))
    signed = _signed()
    first = consume_authorization(_action(), signed, authority=AUTHORITY, now=NOW, ledger=ledger)
    assert first.authorized is True and first.nonce == "nonce-abc-123"
    second = consume_authorization(_action(), signed, authority=AUTHORITY, now=NOW, ledger=ledger)
    assert second.authorized is False and "consumed" in second.reason


def test_consume_authorization_ledger_error_fails_closed(tmp_path):
    # a burn that errors (e.g. try_consume raises an I/O error) must FAIL CLOSED — DENY, never authorized,
    # even though the pure authority/threshold/window checks all passed.
    ledger = NonceLedger(str(tmp_path / "nonces"))

    def _boom(_n):
        raise OSError("ledger unwritable")
    ledger.try_consume = _boom               # instance shadow; type(ledger) is still NonceLedger
    d = consume_authorization(_action(), _signed(), authority=AUTHORITY, now=NOW, ledger=ledger)
    assert d.authorized is False and "fail closed" in d.reason


def test_consume_authorization_rejects_a_non_ledger():
    # a caller-supplied object that is not a real NonceLedger is a DENY (no duck-typed / behavior-overriding
    # ledger can slip a non-atomic burn past the gate).
    d = consume_authorization(_action(), _signed(), authority=AUTHORITY, now=NOW, ledger=object())
    assert d.authorized is False and "malformed nonce ledger" in d.reason


def test_consume_authorization_denies_unauthorized_without_burning(tmp_path):
    # an invalid authorization (below the mandatory-owner requirement) is DENIED by the PURE check and its
    # nonce is NEVER burned — an invalid authorization can't grief-burn a victim's single-use nonce.
    ledger = NonceLedger(str(tmp_path / "nonces"))
    signed = _signed(signer_ids=("worker", "policy"))            # meets threshold 2 but no mandatory owner
    d = consume_authorization(_action(), signed, authority=AUTHORITY, now=NOW, ledger=ledger)
    assert d.authorized is False and "mandatory" in d.reason
    assert ledger.is_consumed("nonce-abc-123") is False          # nonce untouched


def test_pure_authorize_destruction_never_burns(tmp_path):
    # the PURE gate is unchanged: it CHECKS the ledger's is_consumed but does NOT burn — two pure calls both
    # pass and the nonce stays unspent (only consume_authorization / the caller's own try_consume burns).
    ledger = NonceLedger(str(tmp_path / "nonces"))
    assert authorize_destruction(_action(), _signed(), authority=AUTHORITY, now=NOW,
                                 is_consumed=ledger.is_consumed).authorized is True
    assert authorize_destruction(_action(), _signed(), authority=AUTHORITY, now=NOW,
                                 is_consumed=ledger.is_consumed).authorized is True
    assert ledger.is_consumed("nonce-abc-123") is False          # pure check never spent it


def test_require_destruction_authorization_atomic_ledger(tmp_path):
    # the raising wrapper routed through a ledger does the ATOMIC burn: returns the nonce once, then a replay
    # is refused fail-closed.
    ledger = NonceLedger(str(tmp_path / "nonces"))
    assert require_destruction_authorization(
        _action(), _signed(), authority=AUTHORITY, now=NOW, ledger=ledger) == "nonce-abc-123"
    with pytest.raises(DestructionRefused, match="consumed"):
        require_destruction_authorization(
            _action(), _signed(), authority=AUTHORITY, now=NOW, ledger=ledger)


def test_import_clean_no_offense_modules():
    import sys
    import vigil_integration.destruction_gate  # noqa: F401
    assert not any(m == "framework" or m.startswith("framework.")
                   or m == "strix" or m.startswith("strix.") for m in sys.modules)
