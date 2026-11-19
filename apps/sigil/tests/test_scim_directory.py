"""PR-H edge — the owner-signed per-org SCIM directory (`governor.scim_directory`).

Load-bearing invariants (the directory feeds role SELECTION, so a forged or replayed record must be inert):
  * every record is OWNER-SIGNED; an unsigned / attacker-signed record is ignored by the fold;
  * per-(org, rtype, rid) LWW high-water: re-appending a captured older record (e.g. "U is in group admins" after
    U was removed) is refused;
  * ORG-SCOPED: one org's directory never shows another org's users/groups/edges;
  * DELETE cascades (a deterministic user id re-created later starts in no group);
  * identical re-writes append nothing (an IdP re-sync never grows the spine);
  * ids are charset-fixed (an IdP string never becomes a record key); attributes are bounded.
"""
from __future__ import annotations

import itertools
import re
import tempfile

import pytest

from sigil.governor import scim_directory as sd
from sigil.governor.scim_directory import DirectoryError, ScimDirectoryRegistry
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
OP = OWNER.public_key_b64
ATTACKER = generate_keypair()
U1, U2 = "sso_" + "a" * 24, "sso_" + "b" * 24
G1, G2 = "grp_" + "1" * 24, "grp_" + "2" * 24
_t = itertools.count(1)


def _now() -> float:
    return float(next(_t))


def _reg(store, owner=OWNER):
    return ScimDirectoryRegistry(store, owner_key=owner, trusted_pubkey=OP)


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _records(store):
    return [r.payload for r in store.iter_records() if isinstance(r.payload, dict)
            and r.payload.get("signal") == sd.SCIM_DIRECTORY_SIGNAL]


def test_users_groups_edges_roundtrip_through_a_fresh_fold():
    s = _store()
    d = _reg(s).directory("acme")
    assert d.put_user(U1, user_name="Alice@Acme.com", external_id="00u1", display_name="Alice", active=True,
                      selectors=["sec"], profile={"emails": [{"value": "alice@acme.com", "primary": True}]},
                      now=_now())
    d.put_group(G1, display_name="Admins", now=_now())
    d.add_member(G1, U1, now=_now())
    fresh = _reg(s).directory("acme")                       # re-folded from the spine, not the in-memory view
    u = fresh.user(U1)
    assert u.user_name == "Alice@Acme.com" and u.external_id == "00u1" and u.active and u.selectors == ("sec",)
    assert u.profile["emails"][0]["value"] == "alice@acme.com"
    assert fresh.user_by_name("alice@ACME.com").id == U1                 # userName is case-insensitive
    assert fresh.user_by_external_id("00u1").id == U1 and fresh.user_by_external_id("00U1") is None   # exact
    assert fresh.group_by_name("admins").id == G1 and fresh.members(G1) == [U1]
    assert [g.id for g in fresh.groups_of(U1)] == [G1]


def test_an_unsigned_or_attacker_signed_record_is_inert():
    s = _store()
    _reg(s, owner=ATTACKER).directory("acme").put_user(U1, user_name="evil", active=True, now=_now())
    assert _reg(s).directory("acme").user(U1) is None             # attacker-signed → ignored
    # an unsigned forgery of "U2 is in G1" appended raw is ignored too
    d = _reg(s).directory("acme")
    d.put_user(U2, user_name="bob", active=True, now=_now())
    d.put_group(G1, display_name="Admins", now=_now())
    s.append(kind="event", source="governor", actor="WARDEN",
             payload={"signal": sd.SCIM_DIRECTORY_SIGNAL, "org_id": "acme", "rtype": "member",
                      "rid": f"{G1}|{U2}", "state": "active", "issued_at": 10_000.0, "data": {}})
    assert _reg(s).directory("acme").members(G1) == []


def test_a_captured_older_record_cannot_be_replayed():
    s = _store()
    d = _reg(s).directory("acme")
    d.put_user(U1, user_name="alice", active=True, now=_now())
    d.put_group(G1, display_name="Admins", now=_now())
    d.add_member(G1, U1, now=_now())
    captured = [p for p in _records(s) if p.get("rtype") == "member" and p.get("state") == "active"][-1]
    d.remove_member(G1, U1, now=_now())
    assert _reg(s).directory("acme").members(G1) == []
    s.append(kind="event", source="governor", actor="WARDEN", payload=dict(captured))   # replay the signed add
    assert _reg(s).directory("acme").members(G1) == []                                 # high-water refuses it


def test_org_scoped():
    s = _store()
    _reg(s).directory("acme").put_user(U1, user_name="alice", active=True, now=_now())
    beta = _reg(s).directory("beta")
    assert beta.user(U1) is None and beta.users() == [] and beta.user_by_name("alice") is None
    assert beta.add_member(G1, U1, now=_now()) is False                  # nothing of acme's resolves in beta


def test_delete_user_cascades_its_edges_so_a_recreate_starts_in_no_group():
    s = _store()
    d = _reg(s).directory("acme")
    d.put_user(U1, user_name="alice", active=True, now=_now())
    d.put_group(G1, display_name="Admins", now=_now())
    d.add_member(G1, U1, now=_now())
    assert d.delete_user(U1, now=_now()) is True
    d2 = _reg(s).directory("acme")
    assert d2.user(U1) is None and d2.members(G1) == []
    d2.put_user(U1, user_name="alice", active=True, now=_now())          # the same deterministic id again
    assert _reg(s).directory("acme").groups_of(U1) == []


def test_delete_group_cascades_and_reports_former_members():
    s = _store()
    d = _reg(s).directory("acme")
    d.put_user(U1, user_name="alice", active=True, now=_now())
    d.put_user(U2, user_name="bob", active=True, now=_now())
    d.put_group(G1, display_name="Admins", now=_now())
    d.add_member(G1, U1, now=_now())
    d.add_member(G1, U2, now=_now())
    assert d.delete_group(G1, now=_now()) == [U1, U2]
    fresh = _reg(s).directory("acme")
    assert fresh.group(G1) is None and fresh.groups_of(U1) == [] and fresh.groups_of(U2) == []


def test_identical_rewrites_append_nothing():
    s = _store()
    d = _reg(s).directory("acme")
    d.put_user(U1, user_name="alice", active=True, now=_now())
    d.put_group(G1, display_name="Admins", now=_now())
    d.add_member(G1, U1, now=_now())
    n = len(_records(s))
    assert d.put_user(U1, user_name="alice", active=True, now=_now()) is False
    assert d.put_group(G1, display_name="Admins", now=_now()) is False
    assert d.add_member(G1, U1, now=_now()) is False
    assert d.remove_member(G2, U1, now=_now()) is False
    assert len(_records(s)) == n


def test_a_stale_issued_at_is_bumped_past_the_highwater():
    s = _store()
    d = _reg(s).directory("acme")
    d.put_user(U1, user_name="alice", active=True, now=500.0)
    d.put_user(U1, user_name="alice2", active=True, now=1.0)          # a clock that went backwards
    assert _reg(s).directory("acme").user(U1).user_name == "alice2"    # still honored (never silently inert)


@pytest.mark.parametrize("uid", ["alice", "sso_xyz", "../../etc", "sso_" + "a" * 25, "grp_" + "1" * 24])
def test_user_ids_are_charset_fixed(uid):
    with pytest.raises(DirectoryError):
        _reg(_store()).directory("acme").put_user(uid, user_name="x", active=True, now=_now())


def test_group_ids_are_charset_fixed():
    with pytest.raises(DirectoryError):
        _reg(_store()).directory("acme").put_group("admins", display_name="x", now=_now())


def test_attributes_are_bounded_and_control_free():
    d = _reg(_store()).directory("acme")
    with pytest.raises(DirectoryError):
        d.put_user(U1, user_name="x" * 300, active=True, now=_now())
    with pytest.raises(DirectoryError):
        d.put_user(U1, user_name="a\nb", active=True, now=_now())
    with pytest.raises(DirectoryError):
        d.put_user(U1, user_name="a", active=True, selectors=[f"g{i}" for i in range(65)], now=_now())
    with pytest.raises(DirectoryError):
        d.put_group(G1, display_name="", now=_now())


def test_a_write_needs_the_owner_key():
    reg = _reg(_store())
    reg.owner_key = None
    with pytest.raises(DirectoryError):
        reg.directory("acme").put_user(U1, user_name="alice", active=True, now=_now())


def test_tenant_re_lockstep_with_orgs():
    from sigil.governor import orgs
    assert sd._TENANT_RE.pattern == orgs._TENANT_RE.pattern


def test_user_id_shape_matches_sso_username():
    from sigil.governor import scim as gscim
    from sigil.governor.sso_config import SsoConfig
    cfg = SsoConfig(org_id="acme", protocol="saml", issued_at=1.0, state="active", idp_entity_id="https://idp")
    assert re.fullmatch(sd._USER_ID_RE, gscim.sso_username(cfg, "someone@acme.com"))
