"""Claim 6 — the AccountsRegistry: owner-signed per-user RBAC grants on the spine.

Load-bearing invariants (a false-green here would let a revoked user back in or let a forged grant elevate):
  * a bearer resolves to its Principal; the plaintext bearer is NEVER stored (only a salted hash);
  * per-account salt → the same bearer yields different cred_hash on two accounts;
  * ASYMMETRIC auth: create/assign_role need an OWNER signature + strictly-increasing issued_at; revoke is
    the safe direction (honored even unsigned);
  * ANTI-REPLAY: a revoked account cannot be resurrected by re-appending a captured owner-signed active
    grant — proven in BOTH read paths (resolve() AND accounts());
  * a forged / attacker-signed grant is ignored by the fold (fail-closed);
  * default-deny: an unmapped action / unknown role carries no permission;
  * 'owner' is not a grantable bearer role (single-owner-key doctrine);
  * FATAL-2: the module imports no framework/strix.
"""
from __future__ import annotations

import itertools
import tempfile

import pytest

from sigil.governor import accounts as acc
from sigil.governor.accounts import (
    PERMISSIONS,
    AccountsRegistry,
    PermissionDenied,
    Principal,
    role_can,
)
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


# --- role hierarchy + default-deny -----------------------------------------------

def test_roles_are_cumulative_owner_superset():
    assert PERMISSIONS["viewer"] <= PERMISSIONS["analyst"] <= PERMISSIONS["operator"] <= PERMISSIONS["owner"]
    # the owner-only permissions live nowhere below owner
    for p in ("manage_users", "approve_a3", "kill_release", "promote", "secrets",
              "offense_authority", "toggle_protected_guard"):
        assert p in PERMISSIONS["owner"]
        assert p not in PERMISSIONS["operator"]
    # operator carries the operator-tier set; analyst/viewer do not
    for p in ("approve_a2", "config_nonsecret", "toggle_guard", "run_engagement"):
        assert p in PERMISSIONS["operator"] and p not in PERMISSIONS["analyst"]


def test_default_deny():
    # an unmapped action (perm None/"") always refuses, for every role incl. owner
    for r in PERMISSIONS:
        assert role_can(r, None) is False
        assert role_can(r, "") is False
    assert role_can("viewer", "manage_users") is False
    assert role_can("owner", "manage_users") is True
    assert role_can("nonexistent-role", "read") is False       # unknown role → no permissions


def test_read_is_the_floor_for_every_role():
    for r in ("viewer", "analyst", "operator", "owner"):
        assert role_can(r, "read") is True


# --- create / resolve roundtrip + secret handling --------------------------------

def test_create_then_resolve_roundtrips_the_principal():
    s = _store()
    reg = _reg(s)
    reg.create("alice", "operator", bearer_token="B" * 40, issued_at=_issue())
    p = reg.resolve("B" * 40)
    assert p == Principal(username="alice", role="operator")
    assert reg.resolve("wrong-token") is None                  # fail-closed on a wrong token
    assert reg.resolve("") is None and reg.resolve(None) is None


def test_bearer_is_never_stored_in_plaintext():
    s = _store()
    bearer = "SUPER-SECRET-BEARER-abc123def456"
    seq = _reg(s).create("bob", "viewer", bearer_token=bearer, issued_at=_issue())
    rec = s.get(seq)
    # the record carries a salted HASH, never the bearer
    assert rec.payload.get("cred_hash") and bearer not in str(rec.payload)
    assert bearer not in s.path.read_text(encoding="utf-8")     # nor anywhere in the spine file


def test_same_bearer_two_accounts_distinct_hashes_per_salt():
    s = _store()
    reg = _reg(s)
    same = "IDENTICAL-BEARER-xxxxxxxxxxxxxxxx"
    s1 = reg.create("u1", "viewer", bearer_token=same, issued_at=_issue())
    s2 = reg.create("u2", "viewer", bearer_token=same, issued_at=_issue())
    h1 = s.get(s1).payload["cred_hash"]
    h2 = s.get(s2).payload["cred_hash"]
    assert h1 != h2, "a per-account salt must make the same bearer hash differently"
    # each bearer still resolves to its own account (first match by username order is deterministic)
    assert reg.resolve(same) is not None


def test_cred_hash_is_salted_sha256():
    s = _store()
    seq = _reg(s).create("carol", "analyst", bearer_token="tok-carol-1234567890", issued_at=_issue())
    p = s.get(seq).payload
    assert p["cred_hash"] == sha256_hex((p["cred_salt"] + "tok-carol-1234567890").encode("utf-8"))


# --- assign_role ----------------------------------------------------------------

def test_assign_role_changes_role_keeps_the_bearer():
    s = _store()
    reg = _reg(s)
    reg.create("dave", "viewer", bearer_token="dave-tok-abcdefghij", issued_at=_issue())
    assert reg.resolve("dave-tok-abcdefghij").role == "viewer"
    reg.assign_role("dave", "operator", issued_at=_issue())
    assert reg.resolve("dave-tok-abcdefghij").role == "operator"   # same bearer, new role


def test_assign_role_on_unknown_account_refused():
    with pytest.raises(ValueError):
        _reg(_store()).assign_role("ghost", "operator", issued_at=_issue())


def test_owner_role_is_not_grantable():
    reg = _reg(_store())
    with pytest.raises(ValueError):
        reg.create("eve", "owner", bearer_token="eve-tok-abcdefghij", issued_at=_issue())
    reg.create("eve", "viewer", bearer_token="eve-tok-abcdefghij", issued_at=_issue())
    with pytest.raises(ValueError):
        reg.assign_role("eve", "owner", issued_at=_issue())


def test_bad_username_refused():
    reg = _reg(_store())
    for bad in ("", " has space", "owner", "a" * 65, "-startsdash"):
        with pytest.raises(ValueError):
            reg.create(bad, "viewer", bearer_token="x" * 20, issued_at=_issue())


# --- revoke + anti-replay resurrection (the headline guard) ----------------------

def test_revoke_blocks_and_survives_replay_resurrection_in_both_read_paths():
    s = _store()
    reg = _reg(s)
    bearer = "operator-bearer-zzzzzzzzzzzzzzzz"
    create_seq = reg.create("frank", "operator", bearer_token=bearer, issued_at=_issue())
    assert reg.resolve(bearer).role == "operator"
    captured = s.get(create_seq).payload                       # the genuine owner-signed active grant

    reg.revoke("frank")
    assert reg.resolve(bearer) is None                         # revoked → cannot authenticate
    assert "frank" not in {a.username for a in reg.accounts()}

    # ATTACK: re-append the captured owner-signed active grant VERBATIM after the revoke. Genuine
    # signature, cleanly-extending chain — but its issued_at <= the per-username high-water → ignored.
    s.append(kind="event", source="governor", actor="WARDEN", payload=captured)
    assert reg.resolve(bearer) is None, "resurrection via replayed active grant must fail (resolve path)"
    assert "frank" not in {a.username for a in reg.accounts()}, "…and the accounts() path too"


def test_owner_can_legitimately_reactivate_after_revoke_with_a_fresh_grant():
    s = _store()
    reg = _reg(s)
    reg.create("grace", "operator", bearer_token="old-bearer-aaaaaaaaaaaa", issued_at=5.0)
    reg.revoke("grace")
    assert reg.resolve("old-bearer-aaaaaaaaaaaa") is None
    # a FRESH owner-signed grant (strictly-greater issued_at) legitimately re-activates
    reg.create("grace", "analyst", bearer_token="new-bearer-bbbbbbbbbbbb", issued_at=99.0)
    p = reg.resolve("new-bearer-bbbbbbbbbbbb")
    assert p is not None and p.role == "analyst"
    assert reg.resolve("old-bearer-aaaaaaaaaaaa") is None      # the old bearer stays dead


def test_revoke_is_honored_even_unsigned_safe_direction():
    s = _store()
    reg = _reg(s)
    reg.create("heidi", "operator", bearer_token="heidi-bearer-cccccccccc", issued_at=_issue())
    # an UNSIGNED revoke (no owner key) still takes effect — the safe direction
    AccountsRegistry(s, owner_key=None, trusted_pubkey=OP).revoke("heidi")
    assert reg.resolve("heidi-bearer-cccccccccc") is None


# --- forged / stale grants are ignored (fail-closed fold) ------------------------

def test_attacker_signed_grant_is_ignored():
    s = _store()
    # an active grant signed by the ATTACKER key (not the trusted owner) must not resolve
    forged = AccountsRegistry(s, owner_key=ATTACKER, trusted_pubkey=OP)
    forged.create("mallory", "operator", bearer_token="mallory-tok-dddddddddd", issued_at=_issue())
    assert _reg(s).resolve("mallory-tok-dddddddddd") is None
    assert "mallory" not in {a.username for a in _reg(s).accounts()}


def test_forged_elevation_does_not_change_an_existing_role():
    s = _store()
    reg = _reg(s)
    reg.create("nancy", "viewer", bearer_token="nancy-tok-eeeeeeeeee", issued_at=_issue())
    # attacker forges an active grant for nancy at operator, signed by the attacker key → not honored
    from sigil.governor.authn import signed_payload
    core = {"signal": acc.SIGNAL, "username": "nancy", "role": "operator",
            "cred_hash": sha256_hex(("s" + "nancy-tok-eeeeeeeeee").encode("utf-8")), "cred_salt": "s",
            "state": "active", "issued_at": 10_000.0}
    s.append(kind="event", source="governor", actor="WARDEN",
             payload={**signed_payload(core, ATTACKER), "by": "owner"})
    assert reg.resolve("nancy-tok-eeeeeeeeee").role == "viewer"   # role unchanged (forgery ignored)


def test_stale_active_replay_is_refused():
    s = _store()
    reg = _reg(s)
    seq = reg.create("olivia", "operator", bearer_token="olivia-tok-ffffffffff", issued_at=50.0)
    captured = s.get(seq).payload
    # re-appending the same active grant (same issued_at) is a no-op replay; the account stays exactly one
    s.append(kind="event", source="governor", actor="WARDEN", payload=captured)
    assert reg.resolve("olivia-tok-ffffffffff").role == "operator"
    assert len([a for a in reg.accounts() if a.username == "olivia"]) == 1


# --- coverage: every routed action maps to a permission, and FATAL-2 -------------

def test_permission_map_covers_every_routed_action():
    from sigil.ui import actions as _actions
    from sigil.governor.accounts import PERMISSION_BY_ACTION
    for action in _actions.ACTIONS:
        assert action in PERMISSION_BY_ACTION, f"{action} is routable but unmapped (would default-deny)"
        if action in ("approve", "deny"):
            assert PERMISSION_BY_ACTION[action] is None       # tier-resolved downstream
        else:
            assert PERMISSION_BY_ACTION[action], f"{action} maps to an empty permission"


def test_protected_guard_env_is_named_for_the_owner_only_special_case():
    assert acc.PROTECTED_GUARD_ENV == "VIGIL_ALLOW_PROTECTED_DOMAINS"
    assert "toggle_protected_guard" in PERMISSIONS["owner"]
    assert "toggle_protected_guard" not in PERMISSIONS["operator"]


def test_fatal2_accounts_imports_no_offense():
    import sigil.governor.accounts as m
    from sigil.reuse import assert_no_offense
    assert_no_offense()                                        # must not raise in a sovereign env
    src = __import__("pathlib").Path(m.__file__).read_text(encoding="utf-8")
    assert "import framework" not in src and "import strix" not in src
    assert "from framework" not in src and "from strix" not in src
