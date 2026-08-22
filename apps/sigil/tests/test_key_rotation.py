"""W9-1 (#434) — owner-key ROTATION as a signed key HISTORY with cross-signed succession.

Load-bearing invariants (a false-green here would either ORPHAN every historical grant on rotation, or let
a retired/forged key mint new authority):

  * `sigil key rotate` cross-signs a successor into an append-only key history; EVERY pre-rotation head and
    grant still verifies afterwards (the anti-orphan property, the whole point of the design);
  * verification WALKS the succession chain from a pinned genesis and authenticates each record under the
    owner key valid AT ITS SEQ (time-windowed validity) — so a NEW forged grant minted with a retired key
    at a later seq is REFUSED;
  * NEGATIVE CONTROLS (asserted in the same run, so the gate is proven not a no-op): a successor NOT
    cross-signed by the incumbent does not extend the chain; a FORKED succession (incumbent cross-signs two
    different successors) is fail-closed DENY;
  * the "fails without the fix" delta is OBSERVED, not assumed: a pre-rotation grant verified under the
    naive single (current) key — the pre-W9-1 behaviour — is refused, while the succession resolver accepts
    it under the key valid at its seq;
  * the RE-GENESIS fallback deliberately ABANDONS continuity (every pre-re-genesis grant stops verifying);
  * FATAL-2: `key_history` imports no framework/strix.

The LIVE-only residual (TPM-sealing the new private key on real hardware) is out of scope here; the vault
runs plaintext-fallback and the succession/rotation LOGIC is exercised with generated keypairs + a temp home.
"""
from __future__ import annotations

import itertools
import tempfile
import time

import pytest

from sigil.governor import identity, key_history as kh
from sigil.governor.accounts import SIGNAL as ACCT_SIGNAL
from sigil.governor.accounts import AccountsRegistry, _core_fields
from sigil.governor.authn import signed_payload, verify_signed
from sigil.governor.promotion import PromotionPolicy
from sigil.reuse import canonical_json, generate_keypair, verify_one
from sigil.spine.store import SpineStore

_iss = itertools.count(1)


def _issue() -> float:
    return float(next(_iss))


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


# ============================ FATAL-2 ============================================================

def test_key_history_imports_no_offense():
    import sys
    assert not any(m == "framework" or m.startswith("framework.") or m == "strix" or m.startswith("strix.")
                   for m in sys.modules), "an offense module leaked into the sovereign test process"


# ============================ pure succession logic (no disk) ====================================

def _rotate_record(store, incumbent, new_kp, *, epoch, prev, mode="rotate", issued_at=None):
    """Append a cross-signed owner-key-history record straight to the store (bypassing at-rest key swap),
    so the walk/fold logic is exercised without touching disk key material."""
    payload = kh.cross_sign(incumbent, new_kp, epoch=epoch, prev_pubkey=prev, mode=mode,
                            issued_at=issued_at if issued_at is not None else _issue())
    return store.append(kind=kh.KEY_HISTORY_KIND, source="governor", actor="OWNER",
                        payload={**payload, "by": "owner", "requested_by": "owner",
                                 "tier": "A0", "decision": "auto", "reason": "test"})


def test_build_succession_walks_and_windows():
    g = generate_keypair()
    k1 = generate_keypair()
    k2 = generate_keypair()
    store = _store()
    g0 = store.append(kind="event", source="t", actor="u", payload={"i": 0})   # a genesis-era record @ seq 0
    s0 = _rotate_record(store, g, k1, epoch=1, prev=g.public_key_b64)           # rotation @ seq 1
    g1 = store.append(kind="event", source="t", actor="u", payload={"i": 1})    # a k1-era record
    s1 = _rotate_record(store, k1, k2, epoch=2, prev=k1.public_key_b64)         # rotation @ seq 3
    succ = kh.succession_from_store(store, genesis_pubkey=g.public_key_b64)
    assert succ.current == k2.public_key_b64
    assert [e.pubkey for e in succ.epochs] == [g.public_key_b64, k1.public_key_b64, k2.public_key_b64]
    # time-windowed: genesis is valid up to the first rotation seq; k1 between the two; k2 open.
    assert succ.pubkey_valid_at(g0) == g.public_key_b64          # a record before any rotation
    assert succ.pubkey_valid_at(g1) == k1.public_key_b64         # a record between the two rotations
    assert succ.pubkey_valid_at(s1) == k2.public_key_b64         # at/after the second rotation record
    assert succ.pubkey_valid_at(9999) == k2.public_key_b64


def test_uncrossed_successor_does_not_extend():
    """NEGATIVE CONTROL: a successor record NOT cross-signed by the incumbent is refused."""
    g = generate_keypair()
    rogue = generate_keypair()
    store = _store()
    payload = kh.cross_sign(g, rogue, epoch=1, prev_pubkey=g.public_key_b64, issued_at=_issue())
    payload["sig_prev"] = ""                                      # strip the incumbent's authorization
    store.append(kind=kh.KEY_HISTORY_KIND, source="governor", actor="OWNER",
                 payload={**payload, "by": "owner", "requested_by": "owner", "tier": "A0",
                          "decision": "auto", "reason": "forged"})
    succ = kh.succession_from_store(store, genesis_pubkey=g.public_key_b64)
    assert succ.current == g.public_key_b64                       # the rogue never became the tip
    assert rogue.public_key_b64 not in succ.pubkeys


def test_successor_pop_required():
    """NEGATIVE CONTROL: a valid incumbent signature but an INVALID successor proof-of-possession is refused
    (you cannot cross-sign to a key you do not control)."""
    g = generate_keypair()
    victim = generate_keypair()
    store = _store()
    payload = kh.cross_sign(g, victim, epoch=1, prev_pubkey=g.public_key_b64, issued_at=_issue())
    payload["sig_new"] = payload["sig_prev"]                      # a non-PoP signature under new_pubkey
    store.append(kind=kh.KEY_HISTORY_KIND, source="governor", actor="OWNER",
                 payload={**payload, "by": "owner", "requested_by": "owner", "tier": "A0",
                          "decision": "auto", "reason": "no-pop"})
    succ = kh.succession_from_store(store, genesis_pubkey=g.public_key_b64)
    assert succ.current == g.public_key_b64


def test_forged_new_pubkey_swap_is_refused():
    """NEGATIVE CONTROL: mutating `new_pubkey` after the incumbent signed (the incumbent authorized a
    DIFFERENT successor) breaks `sig_prev` -> the record does not extend the chain."""
    g = generate_keypair()
    intended = generate_keypair()
    attacker = generate_keypair()
    store = _store()
    payload = kh.cross_sign(g, intended, epoch=1, prev_pubkey=g.public_key_b64, issued_at=_issue())
    # swap in the attacker key + a self-PoP, but keep the incumbent sig over the ORIGINAL new_pubkey
    payload["new_pubkey"] = attacker.public_key_b64
    from sigil.reuse import sign
    payload["sig_new"] = sign(attacker.private_key_b64, canonical_json(kh._core_from_payload(payload)))
    store.append(kind=kh.KEY_HISTORY_KIND, source="governor", actor="OWNER",
                 payload={**payload, "by": "owner", "requested_by": "owner", "tier": "A0",
                          "decision": "auto", "reason": "swap"})
    succ = kh.succession_from_store(store, genesis_pubkey=g.public_key_b64)
    assert succ.current == g.public_key_b64
    assert attacker.public_key_b64 not in succ.pubkeys


def test_forked_succession_is_fail_closed():
    """NEGATIVE CONTROL: the incumbent cross-signing TWO different successors at the same epoch is a genuine
    authority FORK -> SuccessionError (DENY-all until re-genesis)."""
    g = generate_keypair()
    a = generate_keypair()
    b = generate_keypair()
    store = _store()
    _rotate_record(store, g, a, epoch=1, prev=g.public_key_b64)
    _rotate_record(store, g, b, epoch=1, prev=g.public_key_b64)   # a SECOND validly cross-signed successor
    with pytest.raises(kh.SuccessionError):
        kh.succession_from_store(store, genesis_pubkey=g.public_key_b64)


def test_resolver_no_history_is_single_current_window():
    """With no rotation, the resolver is byte-identical to the pre-W9-1 single-key behaviour."""
    cur = generate_keypair().public_key_b64
    store = _store()
    store.append(kind="event", source="t", actor="u", payload={"i": 1})
    res = kh.key_resolver(store, current=cur)
    assert res.at(0) == cur and res.at(50) == cur


# ============================ end-to-end with disk key material ==================================

@pytest.fixture
def home(tmp_path, monkeypatch):
    """Relocate ALL owner-key path state (identity + checkpoint + floor) into an isolated temp dir, so
    `kh.rotate`/`re_genesis`, the folds and the head anchor exercise the REAL disk paths hermetically."""
    from sigil.platform.vault import reset_owner_vault_for_test
    from sigil.spine import checkpoint as cp
    from sigil.spine import floor as fl
    keys = tmp_path / "keys"
    keys.mkdir(parents=True, exist_ok=True)
    for mod, name, val in [
        (identity, "_PRIV", keys / "owner.priv"), (identity, "_PUB", keys / "owner.pub"),
        (identity, "_GENESIS_PUB", keys / "owner.genesis.pub"),
        (cp, "_PRIV", keys / "owner.priv"), (cp, "_PUB", keys / "owner.pub"),
        (cp, "KEYS_DIR", keys), (cp, "HEAD_PATH", tmp_path / "head.json"),
        (fl, "FLOOR_PATH", tmp_path / "floor.json"),
    ]:
        monkeypatch.setattr(mod, name, val)
    reset_owner_vault_for_test()
    kh.clear_resolver_cache()
    yield tmp_path
    kh.clear_resolver_cache()
    reset_owner_vault_for_test()


def _acct_grant_records(store):
    return [r for r in store.iter_records()
            if isinstance(r.payload, dict) and r.payload.get("signal") == ACCT_SIGNAL
            and r.payload.get("state") == "active"]


def test_rotate_preserves_every_pre_rotation_grant(home):
    """ACCEPTANCE: `sigil key rotate` cross-signs a successor; every pre-rotation head and grant still
    verifies. Covers accounts + promotion grants + the signed head."""
    from sigil.spine.checkpoint import checkpoint, verify_checkpoint
    store = SpineStore(str(home / "spine.jsonl"))
    identity.ensure_owner_keypair()

    AccountsRegistry(store).create("alice", "operator", bearer_token="alice-bearer-token-xyz",
                                   issued_at=_issue())
    PromotionPolicy(store).grant("SENTINEL", scope="sigil", issued_at=_issue())
    checkpoint(store)
    assert verify_checkpoint(store)[0]
    assert AccountsRegistry(store).resolve("alice-bearer-token-xyz") is not None

    new_kp, seq = kh.rotate(store, issued_at=time.time())
    checkpoint(store)

    # every pre-rotation grant survives the rotation (NOT orphaned) ...
    assert AccountsRegistry(store).resolve("alice-bearer-token-xyz") is not None, "alice was ORPHANED"
    assert PromotionPolicy(store).is_promoted("SENTINEL", scope="sigil"), "the grant was ORPHANED"
    # ... the head re-anchored under the new key still verifies ...
    assert verify_checkpoint(store)[0]
    # ... and a NEW grant signed by the rotated-in key also works.
    AccountsRegistry(store).create("bob", "analyst", bearer_token="bob-bearer-token-abcd", issued_at=_issue())
    assert AccountsRegistry(store).resolve("bob-bearer-token-abcd") is not None
    assert identity.owner_pubkey() == new_kp.public_key_b64


def test_fails_without_the_fix_delta_and_seq_window(home):
    """The "fails without this change" observation, IN THE SAME RUN: a pre-rotation grant verified under the
    naive single (current) key — the pre-W9-1 fold — is REFUSED (orphaned), while the succession resolver
    accepts it under the key valid at its seq. And a NEW forged grant minted with the RETIRED key at a later
    seq is refused by the resolver (time-windowed validity)."""
    store = SpineStore(str(home / "spine.jsonl"))
    genesis_kp = identity.ensure_owner_keypair()
    AccountsRegistry(store).create("alice", "operator", bearer_token="alice-bearer-token-xyz",
                                   issued_at=_issue())
    alice_rec = _acct_grant_records(store)[0]
    new_kp, _seq = kh.rotate(store, issued_at=time.time())

    # WITHOUT the fix (naive single-key verify under the CURRENT key): the genesis-signed grant is orphaned.
    assert verify_signed(alice_rec.payload, _core_fields(alice_rec.payload), new_kp.public_key_b64) is False
    # WITH the fix (verify under the key valid at the grant's seq): it verifies.
    resolver = kh.key_resolver(store, current=new_kp.public_key_b64)
    assert resolver.at(alice_rec.seq) == genesis_kp.public_key_b64
    assert verify_signed(alice_rec.payload, _core_fields(alice_rec.payload), resolver.at(alice_rec.seq)) is True

    # A NEW forged 'active' grant signed by the RETIRED genesis key at a later seq is refused end-to-end.
    core = {"signal": ACCT_SIGNAL, "username": "mallory", "role": "owner", "cred_hash": "x",
            "cred_salt": "y", "state": "active", "issued_at": time.time()}
    forged = {**signed_payload(core, genesis_kp), "by": "owner", "requested_by": "owner",
              "tier": "A0", "decision": "auto", "reason": "forged"}
    store.append(kind="event", source="governor", actor="WARDEN", payload=forged)
    assert "mallory" not in {a.username for a in AccountsRegistry(store).accounts()}


def test_forked_chain_fails_the_account_fold_closed(home):
    """A forked succession makes the RBAC fold fail closed (DENY-all) — an ambiguous owner authority admits
    no one until a re-genesis."""
    store = SpineStore(str(home / "spine.jsonl"))
    identity.ensure_owner_keypair()
    AccountsRegistry(store).create("alice", "operator", bearer_token="alice-bearer-token-xyz",
                                   issued_at=_issue())
    a, b = generate_keypair(), generate_keypair()
    incumbent = identity.owner_keypair()
    identity.pin_genesis(incumbent.public_key_b64)
    _rotate_record(store, incumbent, a, epoch=1, prev=incumbent.public_key_b64)
    _rotate_record(store, incumbent, b, epoch=1, prev=incumbent.public_key_b64)   # FORK
    kh.clear_resolver_cache()
    assert AccountsRegistry(store).accounts() == [], "a forked owner-key succession must fail closed"


def test_re_genesis_abandons_continuity(home):
    """The compromise fallback: re-genesis mints a fresh root, repins it, and DELIBERATELY abandons every
    pre-re-genesis grant."""
    store = SpineStore(str(home / "spine.jsonl"))
    identity.ensure_owner_keypair()
    AccountsRegistry(store).create("alice", "operator", bearer_token="alice-bearer-token-xyz",
                                   issued_at=_issue())
    assert AccountsRegistry(store).resolve("alice-bearer-token-xyz") is not None

    fresh, _seq = kh.re_genesis(store, issued_at=time.time())
    assert identity.genesis_owner_pubkey() == fresh.public_key_b64
    assert identity.owner_pubkey() == fresh.public_key_b64
    # continuity abandoned: the pre-re-genesis grant no longer authenticates under the new root.
    assert AccountsRegistry(store).resolve("alice-bearer-token-xyz") is None
    # a fresh grant under the new root works.
    AccountsRegistry(store).create("carol", "viewer", bearer_token="carol-bearer-token-1234",
                                   issued_at=_issue())
    assert AccountsRegistry(store).resolve("carol-bearer-token-1234") is not None


def test_rotate_refuses_when_owner_key_not_the_tip(home):
    """Fail-closed: rotating when the on-disk owner key is NOT the validated succession tip (a tampered key
    state) is refused rather than forking the chain."""
    store = SpineStore(str(home / "spine.jsonl"))
    identity.ensure_owner_keypair()
    kh.rotate(store, issued_at=time.time())                       # legitimate rotation -> owner.pub = k1
    # now clobber the on-disk owner key to an unrelated one WITHOUT a succession record
    identity.set_owner_key(generate_keypair())
    kh.clear_resolver_cache()
    with pytest.raises(kh.SuccessionError):
        kh.rotate(store, issued_at=time.time())
