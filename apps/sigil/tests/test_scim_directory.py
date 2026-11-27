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


def test_user_by_name_matches_by_letter_case_only_never_a_case_folding_look_alike():
    d = _reg(_store()).directory("acme")
    names = {"sam@acme.test": U1, "Kate@acme.test": U2, "strasse@acme.test": "sso_" + "c" * 24,
             "fiona@acme.test": "sso_" + "d" * 24}
    for name, uid in names.items():
        d.put_user(uid, user_name=name, active=True, now=_now())
    for twin, uid in (("SAM@ACME.TEST", U1), ("kATE@acme.TEST", U2), ("Strasse@Acme.Test", "sso_" + "c" * 24)):
        assert d.user_by_name(twin).id == uid, twin                       # letter case alone: the same name
    # each of these casefolds onto a stored name, yet is a DIFFERENT name an IdP may give a different person
    for look_alike in ("\u017fam@acme.test",           # LONG S -> s
                       "\u212aate@acme.test",          # KELVIN SIGN -> k
                       "stra\u00dfe@acme.test",        # SHARP S -> ss
                       "STRA\u1e9eE@acme.test",        # CAPITAL SHARP S -> ss
                       "\ufb01ona@acme.test"):         # LATIN SMALL LIGATURE FI -> fi
        assert d.user_by_name(look_alike) is None, ascii(look_alike)


@pytest.mark.parametrize("pad", ["\u00a0", "\u3000", "\u2003", "\u0085", "\u2028", " ", "\t"],
                         ids=lambda p: f"U+{ord(p):04X}")
def test_a_lookup_key_padded_with_whitespace_matches_nobody(pad):
    # a key that differs from a member's userName / externalId only by surrounding whitespace is a DIFFERENT
    # identifier: it is never trimmed into the member's
    d = _reg(_store()).directory("acme")
    d.put_user(U1, user_name="kate@acme.test", external_id="00u-kate", active=True, now=_now())
    for padded in (pad + "kate@acme.test", "KATE@acme.test" + pad):
        assert d.user_by_name(padded) is None, ascii(padded)
    for padded in (pad + "00u-kate", "00u-kate" + pad):
        assert d.user_by_external_id(padded) is None, ascii(padded)
    for blank in ("", pad, pad * 3):
        assert d.user_by_name(blank) is None and d.user_by_external_id(blank) is None
    assert d.user_by_name("KATE@acme.test").id == U1 and d.user_by_external_id("00u-kate").id == U1   # controls


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


def test_the_sign_in_clamp_note_round_trips_and_a_malformed_one_is_no_note():
    s = _store()
    d = _reg(s).directory("acme")
    assert d.put_user(U1, user_name="bob@acme.test", active=True, clamp=("org_admin", 12.5), now=_now())
    assert _reg(s).directory("acme").user(U1).clamp == ("org_admin", 12.5)        # re-folded from the spine
    assert not d.put_user(U1, user_name="bob@acme.test", active=True, clamp=("org_admin", 12.5), now=_now())
    assert d.put_user(U1, user_name="bob@acme.test", active=True, now=_now())       # a write without one clears it
    assert _reg(s).directory("acme").user(U1).clamp == ()
    for bad in ({"from": "", "at": 1.0}, {"from": 7, "at": 1.0}, {"from": "x" * (sd.MAX_ATTR + 1), "at": 1.0},
                {"from": "org_admin", "at": "1"}, {"from": "org_admin", "at": True},
                {"from": "org_admin", "at": float("nan")}, {"from": "org_admin", "at": float("inf")},
                ["org_admin", 1.0], None):
        assert sd._clamp_from(bad) == (), bad
    with pytest.raises(DirectoryError, match="clamp"):
        d.put_user(U2, user_name="y@acme.test", active=True, clamp=("org_admin", float("nan")), now=_now())
    # a signed record carrying a malformed note still folds — as a user with NO note (the fail-safe direction)
    _reg(s)._append("acme", "user", U2, "active", {"userName": "y@acme.test", "active": True,
                                                   "clamp": {"from": "org_admin", "at": "soon"}}, issued_at=_now())
    u = _reg(s).directory("acme").user(U2)
    assert u is not None and u.user_name == "y@acme.test" and u.clamp == ()


def test_a_staged_change_reaches_the_spine_only_on_commit_and_then_exactly():
    """`staged()` journals a multi-record change without writing it (the caller acts on the post-change state first);
    `commit` appends exactly those records, in order, and the result folds back identical to the staged view."""
    s = _store()
    d = _reg(s).directory("acme")
    d.put_user(U1, user_name="ann@acme.test", active=True, now=_now())
    d.put_user(U2, user_name="bob@acme.test", active=True, now=_now())
    d.put_group(G1, display_name="Admins", now=_now())
    d.add_member(G1, U1, now=_now())
    n = len(_records(s))
    st = d.staged()
    assert st.delete_group(G1, now=_now()) == [U1] and st.put_group(G2, display_name="Staff", now=_now())
    st.add_member(G2, U2, now=_now())
    assert len(_records(s)) == n                                       # nothing written yet …
    assert d.group(G1) is not None and d.members(G1) == [U1] and d.group(G2) is None   # … nor seen by the view
    assert st.group(G1) is None and st.members(G2) == [U2]
    d.commit(st)
    assert len(_records(s)) == n + 4                                   # edge + group delete, group + edge put
    for view in (d, _reg(s).directory("acme")):                        # the in-memory view and a fresh fold agree
        assert view.group(G1) is None and view.members(G2) == [U2] and [g.id for g in view.groups_of(U1)] == []


def test_a_staged_change_commits_only_onto_the_unchanged_view_it_came_from():
    s = _store()
    d = _reg(s).directory("acme")
    d.put_group(G1, display_name="Admins", now=_now())
    st = d.staged()
    st.put_group(G1, display_name="Staff", now=_now())
    other = _reg(s).directory("acme")
    with pytest.raises(DirectoryError):
        other.commit(st)                                               # a different view
    d.put_group(G2, display_name="Ops", now=_now())
    with pytest.raises(DirectoryError):
        d.commit(st)                                                   # the view moved since it was staged
    assert _reg(s).directory("acme").group(G1).display_name == "Admins"


def test_a_staged_write_is_refused_like_a_real_one_without_the_owner_key():
    d = ScimDirectoryRegistry(_store(), owner_key=None, trusted_pubkey=OP).directory("acme")
    with pytest.raises(DirectoryError):
        d.staged().put_group(G1, display_name="Admins", now=_now())


def test_an_explicit_no_owner_key_is_honored_even_when_one_is_persisted(monkeypatch):
    # The leaking state a full suite run reproduces: an earlier test persisted an owner keypair under the shared
    # keystore, so `owner_keypair()` answers with one. An EXPLICIT `owner_key=None` must still build a read-only
    # registry — never silently borrow that ambient key — so a (staged or direct) write refuses.
    monkeypatch.setattr(sd, "owner_keypair", lambda: OWNER)
    reg = ScimDirectoryRegistry(_store(), owner_key=None, trusted_pubkey=OP)
    assert reg.owner_key is None                                   # honored as given, not the ambient key
    d = reg.directory("acme")
    with pytest.raises(DirectoryError):
        d.staged().put_group(G1, display_name="Admins", now=_now())
    with pytest.raises(DirectoryError):
        d.put_group(G1, display_name="Admins", now=_now())
    # an OMITTED owner_key still falls back to the persisted identity (the production default is unchanged)
    assert ScimDirectoryRegistry(_store(), trusted_pubkey=OP).owner_key is OWNER


def test_a_key_less_registry_refuses_even_a_no_op_write_of_a_record_already_present(monkeypatch):
    # The refusal is UNCONDITIONAL: a put of a group ALREADY present (an identical re-write that would append
    # nothing) still raises, so a read-only registry never accepts a mutation just because it changes nothing —
    # whether staged or direct, and whether the view was folded fresh or read from the cache.
    monkeypatch.setattr(sd, "owner_keypair", lambda: OWNER)
    s = _store()
    _reg(s).directory("acme").put_group(G1, display_name="Admins", now=_now())      # a real-key write lands G1
    ro = ScimDirectoryRegistry(s, owner_key=None, trusted_pubkey=OP).directory("acme")
    assert ro.group(G1) is not None                               # the view already shows the group
    with pytest.raises(DirectoryError):
        ro.staged().put_group(G1, display_name="Admins", now=_now())   # identical ⇒ a no-op, yet refused
    with pytest.raises(DirectoryError):
        ro.put_group(G1, display_name="Admins", now=_now())            # the direct no-op refuses too
