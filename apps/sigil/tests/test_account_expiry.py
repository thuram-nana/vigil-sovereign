"""Slice 1a — per-token TTL / expiry on AccountsRegistry (soundness-touching, red-penned).

Load-bearing invariants (a false-green here would let an EXPIRED bearer keep authenticating, let an
attacker EXTEND a deadline, or silently DOWNGRADE an expiring account to never-expiring):
  * an expired bearer no longer resolves, and an expired account cannot mint a fresh session bearer
    (the login-bypass guard on account());
  * the absolute `expires_at` is inside the OWNER-signed core — EXTENDING it or STRIPPING it breaks the
    signature (malleability closed in both directions), and a poisoned value fails CLOSED (denied);
  * expiry NEVER touches the anti-replay high-water: a revoked/expired grant cannot be resurrected, and a
    replayed expired grant stays expired;
  * the absolute deadline is carried forward UNCHANGED by every re-sign (role change, key/TOTP/password
    enrolment, login rotation) — it does NOT slide forward (the "signed ttl" trap);
  * backward-compat: a legacy grant with no `expires_at` verifies byte-identically and never expires;
  * bulk revoke revokes exactly the active non-owner set, is replay-safe, and cannot lock the owner out.
"""
from __future__ import annotations

import itertools
import tempfile

import pytest

from sigil.governor import accounts as acc
from sigil.governor.accounts import AccountsRegistry, Principal
from sigil.governor.authn import signed_payload, verify_signed
from sigil.reuse import generate_keypair, sha256_hex
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
OP = OWNER.public_key_b64
ATTACKER = generate_keypair()

_iss = itertools.count(1)


def _issue() -> float:
    return float(next(_iss))


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _reg(store):
    return AccountsRegistry(store, owner_key=OWNER, trusted_pubkey=OP)


# --- the derivation helper -------------------------------------------------------

def test_derive_expires_at_absolute_and_none():
    assert acc._derive_expires_at(100.0, None) is None
    assert acc._derive_expires_at(100.0, 3600) == 3700.0


@pytest.mark.parametrize("bad", [0, -5, float("inf"), float("nan"), acc.MAX_ACCOUNT_TTL + 1, "x"])
def test_derive_expires_at_rejects_bad_ttl(bad):
    with pytest.raises(ValueError):
        acc._derive_expires_at(100.0, bad)


# --- expiry enforced at the auth read surfaces -----------------------------------

def test_expired_bearer_does_not_authenticate():
    s = _store()
    reg = _reg(s)
    bearer = "ttl-bearer-aaaaaaaaaaaaaaaa"
    reg.create("alice", "operator", bearer_token=bearer, issued_at=100.0, ttl_seconds=3600)
    # before the deadline it resolves; at/after it does NOT (fail-closed), from BOTH read surfaces
    assert reg.resolve(bearer, now=100.0).role == "operator"
    assert reg.resolve(bearer, now=3699.0).role == "operator"
    assert reg.resolve(bearer, now=3700.0) is None          # exactly at the deadline → expired
    assert reg.resolve(bearer, now=9_999.0) is None
    assert reg.account("alice", now=3699.0) is not None
    assert reg.account("alice", now=3700.0) is None          # account() also denies (login-bypass guard)
    # but the account is STILL in the list (so the UI can show an "expired" pill and offer revoke)
    assert "alice" in {a.username for a in reg.accounts()}
    a = next(x for x in reg.accounts() if x.username == "alice")
    assert a.expires_at == 3700.0
    assert a.expired(3700.0) is True and a.expired(3699.0) is False
    assert a.remaining(3700.0) == 0.0 and a.remaining(3699.0) == 1.0


def test_expired_account_cannot_mint_a_fresh_session_bearer():
    # account() is the login lookup; if it denies an expired account, PoP/password login cannot mint a new
    # bearer that would otherwise slip past the deadline.
    s = _store()
    reg = _reg(s)
    reg.create("bob", "operator", bearer_token="bob-bearer-bbbbbbbbbbbb", issued_at=100.0, ttl_seconds=3600)
    assert reg.account("bob", now=5_000.0) is None            # expired → login lookup fails → no mint


def test_never_expiring_account_is_backward_compatible():
    s = _store()
    reg = _reg(s)
    # ttl_seconds=None ⇒ no expires_at field at all ⇒ never expires (authenticates arbitrarily far ahead)
    reg.create("carol", "viewer", bearer_token="carol-bearer-cccccccccc", issued_at=1.0, ttl_seconds=None)
    assert reg.resolve("carol-bearer-cccccccccc", now=1e18).role == "viewer"
    # and the grant carries NO expires_at key (byte-identical to a pre-slice grant)
    assert all("expires_at" not in r.payload for r in s.iter_records()
               if isinstance(r.payload, dict) and r.payload.get("username") == "carol")


def test_expiry_survives_a_store_reopen_from_disk():
    # the absolute deadline is a float signed into the core; it must round-trip through JSON on disk so the
    # OWNER signature still verifies (canonical encoding stable across a reload) AND expiry still enforces.
    s = _store()
    _reg(s).create("reopen", "operator", bearer_token="reopen-bearer-nnnnnnnnnn",
                   issued_at=100.0, ttl_seconds=3600)
    s2 = SpineStore(s.path)                      # a FRESH store object over the same file (disk round-trip)
    reg2 = AccountsRegistry(s2, owner_key=OWNER, trusted_pubkey=OP)
    assert reg2.resolve("reopen-bearer-nnnnnnnnnn", now=3600.0).role == "operator"   # sig verified post-reload
    assert reg2.resolve("reopen-bearer-nnnnnnnnnn", now=3700.0) is None              # …and expiry enforces


def test_a_legacy_base7_grant_verifies_and_never_expires():
    # hand-build a grant with the base-7 core only (no optional fields) signed by the owner — exactly a
    # pre-slice record — and prove it still verifies and never expires under the new fold.
    s = _store()
    reg = _reg(s)
    salt, bearer = "legacysalt", "legacy-bearer-dddddddddddd"
    core = {"signal": acc.SIGNAL, "username": "legacy", "role": "operator",
            "cred_hash": sha256_hex((salt + bearer).encode("utf-8")), "cred_salt": salt,
            "state": "active", "issued_at": 500.0}
    s.append(kind="event", source="governor", actor="WARDEN",
             payload={**signed_payload(core, OWNER), "by": "owner"})
    assert reg.resolve(bearer, now=1e18).role == "operator"


# --- the signed deadline is tamper-evident (malleability closed both ways) --------

def test_expires_at_is_inside_the_owner_signed_core():
    s = _store()
    reg = _reg(s)
    seq = reg.create("dana", "operator", bearer_token="dana-bearer-eeeeeeeeee",
                     issued_at=100.0, ttl_seconds=3600)
    genuine = s.get(seq).payload
    assert genuine.get("expires_at") == 3700.0
    assert verify_signed(genuine, acc._core_fields(genuine), OP)       # genuine verifies

    extended = dict(genuine)
    extended["expires_at"] = 3700.0 + 1e9                              # attacker tries to push the deadline out
    assert not verify_signed(extended, acc._core_fields(extended), OP), "extending expiry must break the sig"

    stripped = dict(genuine)
    del stripped["expires_at"]                                         # attacker tries to remove the deadline
    assert not verify_signed(stripped, acc._core_fields(stripped), OP), "stripping expiry must break the sig"


def test_attacker_cannot_forge_an_extended_deadline_in_the_fold():
    s = _store()
    reg = _reg(s)
    reg.create("erin", "operator", bearer_token="erin-bearer-ffffffffff", issued_at=100.0, ttl_seconds=3600)
    # attacker mints a FRESH (high issued_at) grant that would extend the deadline, signed by their own key
    core = {"signal": acc.SIGNAL, "username": "erin", "role": "operator",
            "cred_hash": sha256_hex(("s" + "erin-bearer-ffffffffff").encode("utf-8")), "cred_salt": "s",
            "state": "active", "issued_at": 10_000.0, "expires_at": 1e18}
    s.append(kind="event", source="governor", actor="WARDEN",
             payload={**signed_payload(core, ATTACKER), "by": "owner"})
    assert reg.resolve("erin-bearer-ffffffffff", now=5_000.0) is None   # forgery ignored; real deadline stands


@pytest.mark.parametrize("poison", ["not-a-number", "9e99", "1000000000000", True, [1], {"x": 1}])
def test_poisoned_expires_at_fails_closed(poison):
    # an owner could sign a garbage expires_at; the fold coerces it via _as_deadline → 0.0 → always expired
    # (deny) rather than crashing or treating a corrupt value as never-expiring. CRUCIALLY a NUMERIC STRING
    # ("9e99"/"1000000000000") must ALSO deny — the fail-open a tolerant float()-parse would have allowed.
    s = _store()
    reg = _reg(s)
    salt, bearer = "ps", "poison-bearer-gggggggggggg"
    core = {"signal": acc.SIGNAL, "username": "poison", "role": "operator",
            "cred_hash": sha256_hex((salt + bearer).encode("utf-8")), "cred_salt": salt,
            "state": "active", "issued_at": 1000.0, "expires_at": poison}
    s.append(kind="event", source="governor", actor="WARDEN",
             payload={**signed_payload(core, OWNER), "by": "owner"})
    assert reg.resolve(bearer, now=0.0) is None                        # fail-closed: poisoned deadline ⇒ denied


def test_as_deadline_is_strict_fail_closed():
    # a genuine finite number passes through; every non-number (incl. a numeric string and a bool) → 0.0
    assert acc._as_deadline(3700.0) == 3700.0
    assert acc._as_deadline(3700) == 3700.0
    for bad in ("9e99", "3700", True, False, [1], {"x": 1}, float("inf"), float("nan")):
        assert acc._as_deadline(bad) == 0.0, f"{bad!r} must fail closed to 0.0 (deny)"


# --- expiry NEVER interacts with the anti-replay high-water -----------------------

def test_expired_active_grant_cannot_be_resurrected_by_replay():
    s = _store()
    reg = _reg(s)
    bearer = "replay-bearer-hhhhhhhhhhhh"
    seq = reg.create("frank", "operator", bearer_token=bearer, issued_at=100.0, ttl_seconds=3600)
    captured = s.get(seq).payload
    assert reg.resolve(bearer, now=5_000.0) is None                    # expired
    # re-append the genuine owner-signed grant VERBATIM after expiry — same issued_at ≤ high-water AND still
    # carries the same past deadline → ignored either way; the bearer stays dead.
    s.append(kind="event", source="governor", actor="WARDEN", payload=captured)
    assert reg.resolve(bearer, now=5_000.0) is None, "replay must not resurrect an expired bearer"
    # and the replay did NOT push the deadline out — it is still the original 3700 (checked before expiry)
    assert reg.account("frank", now=0.0).expires_at == 3700.0


def test_revoked_stays_revoked_regardless_of_expiry():
    s = _store()
    reg = _reg(s)
    bearer = "revoked-ttl-bearer-iiiiiiii"
    reg.create("grace", "operator", bearer_token=bearer, issued_at=100.0, ttl_seconds=3600)
    reg.revoke("grace")
    assert reg.resolve(bearer, now=100.0) is None                      # revoked before the deadline
    assert reg.resolve(bearer, now=200.0) is None                      # expiry never flips a revoke back
    assert "grace" not in {a.username for a in reg.accounts()}


# --- the absolute deadline is carried forward UNCHANGED (no sliding window) -------

def test_deadline_is_carried_forward_unchanged_by_every_resign():
    s = _store()
    reg = _reg(s)
    reg.create("heidi", "viewer", bearer_token="heidi-bearer-jjjjjjjjjj", issued_at=100.0, ttl_seconds=3600)
    exp = 3700.0
    assert reg.account("heidi", now=100.0).expires_at == exp

    reg.assign_role("heidi", "operator", issued_at=200.0)              # role change
    a1 = reg.account("heidi", now=200.0)
    assert a1.role == "operator" and a1.expires_at == exp             # deadline UNCHANGED (not slid to 200+3600)

    reg.set_password("heidi", "a-strong-password", issued_at=300.0)    # password enrolment
    assert reg.account("heidi", now=300.0).expires_at == exp

    newb, _ = reg.mint_session_bearer("heidi", issued_at=400.0)        # login rotation
    a2 = reg.account("heidi", now=400.0)
    assert a2.expires_at == exp                                        # STILL the original absolute deadline
    # the rotated bearer inherits the SAME absolute deadline (dies at exp, does not renew)
    assert reg.resolve(newb, now=exp - 1).role == "operator"
    assert reg.resolve(newb, now=exp + 1) is None


def test_never_expire_stays_never_expire_across_resign():
    s = _store()
    reg = _reg(s)
    reg.create("ivan", "viewer", bearer_token="ivan-bearer-kkkkkkkkkk", issued_at=1.0, ttl_seconds=None)
    reg.assign_role("ivan", "operator", issued_at=2.0)
    assert reg.account("ivan", now=1e18).expires_at is None            # a role change must not invent a deadline


# --- bulk revoke -----------------------------------------------------------------

def test_revoke_all_revokes_the_exact_active_set_and_is_replay_safe():
    s = _store()
    reg = _reg(s)
    reg.create("a1", "viewer", bearer_token="a1a1a1a1a1a1a1a1a1a1", issued_at=_issue())
    reg.create("a2", "operator", bearer_token="a2a2a2a2a2a2a2a2a2a2", issued_at=_issue())
    reg.create("a3", "analyst", bearer_token="a3a3a3a3a3a3a3a3a3a3", issued_at=_issue())
    revoked = reg.revoke_all()
    assert sorted(u for u, _ in revoked) == ["a1", "a2", "a3"]
    assert reg.resolve("a1a1a1a1a1a1a1a1a1a1") is None
    assert reg.resolve("a2a2a2a2a2a2a2a2a2a2") is None
    assert reg.resolve("a3a3a3a3a3a3a3a3a3a3") is None
    assert reg.accounts() == []
    # replay-safe / idempotent: re-running changes nothing
    assert reg.revoke_all() == []
    assert reg.accounts() == []
    # a FRESH create (new issued_at) legitimately re-activates one
    reg.create("a2", "operator", bearer_token="fresh-a2-token-mmmmmmmm", issued_at=_issue())
    assert reg.resolve("fresh-a2-token-mmmmmmmm").role == "operator"


def test_revoke_all_respects_exclude_and_cannot_touch_owner():
    s = _store()
    reg = _reg(s)
    reg.create("keep", "operator", bearer_token="keepkeepkeepkeepkeep", issued_at=_issue())
    reg.create("drop", "viewer", bearer_token="dropdropdropdropdrop1", issued_at=_issue())
    revoked = reg.revoke_all(exclude=frozenset({"keep"}))
    assert [u for u, _ in revoked] == ["drop"]
    assert reg.resolve("keepkeepkeepkeepkeep").role == "operator"     # excluded account survives
    assert reg.resolve("dropdropdropdropdrop1") is None
    # the owner is never an Account, so it is structurally absent from the revoke set
    assert "owner" not in {a.username for a in reg.accounts()}
    assert acc.OWNER_PRINCIPAL == Principal(username="owner", role="owner")
