"""TENANCY/IDENTITY slice 1 — owner-signed ORG/WORKSPACE entities + per-org memberships.

Load-bearing invariants (a false-green here would let a forged org/membership grant elevate a tenant, or
let a revoked org/member back in):
  * org create + membership grant are the DANGEROUS direction: OWNER-signed + strictly-increasing issued_at;
    a bad/attacker signature is REFUSED (inert in the fold);
  * revoke is the SAFE direction (honored even unsigned, fixed issued_at 0.0);
  * ANTI-REPLAY: a revoked org/membership cannot be resurrected by re-appending a captured owner-signed
    active grant (per-record LWW high-water);
  * PER-ORG scoping: a member of org A has NO role in org B; high-waters are independent per (org, user);
  * org == tenant_id: org_tenant_id derives/validates a _TENANT_RE-satisfying id, fail-closed on an
    unmappable org_id;
  * default-deny admission; 'owner' is not a grantable per-org role (single-owner doctrine);
  * FATAL-2: the module imports no framework/strix; the replicated _TENANT_RE / username regex stay in
    lockstep with their source-of-truth literals.
"""
from __future__ import annotations

import itertools
import pathlib
import re
import tempfile

import pytest

from sigil.governor import orgs as og
from sigil.governor.orgs import Membership, Org, OrgRegistry, org_tenant_id  # noqa: F401
from sigil.reuse import generate_keypair
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
    return OrgRegistry(store, owner_key=OWNER, trusted_pubkey=OP)


# --- org create / resolve roundtrip ----------------------------------------------

def test_create_org_then_resolve_roundtrips():
    s = _store()
    reg = _reg(s)
    reg.create_org("acme", "Acme Corp", owner="owner", issued_at=_issue())
    o = reg.org("acme")
    assert o is not None and o.name == "Acme Corp" and o.owner == "owner" and o.state == "active"
    assert "acme" in {x.org_id for x in reg.orgs()}
    assert reg.org("ghost") is None                        # fail-closed on an unknown org


def test_create_org_bad_signature_refused():
    s = _store()
    # an org grant signed by the ATTACKER key (not the trusted owner) must not fold in
    forged = OrgRegistry(s, owner_key=ATTACKER, trusted_pubkey=OP)
    forged.create_org("acme", "Acme", owner="owner", issued_at=_issue())
    assert _reg(s).org("acme") is None
    assert "acme" not in {o.org_id for o in _reg(s).orgs()}


def test_bad_org_id_refused():
    reg = _reg(_store())
    for bad in ("", "bad/slug", "../escape", ".", "a" * 65, "-startsdash", "white space"):
        with pytest.raises(ValueError):
            reg.create_org(bad, "n", owner="owner", issued_at=_issue())


def test_bad_org_name_refused():
    reg = _reg(_store())
    with pytest.raises(ValueError):
        reg.create_org("acme", "", owner="owner", issued_at=_issue())
    with pytest.raises(ValueError):
        reg.create_org("acme", "x" * 201, owner="owner", issued_at=_issue())
    with pytest.raises(ValueError):
        reg.create_org("acme", "bad\x00name", owner="owner", issued_at=_issue())


def test_create_org_requires_owner_key():
    # with no signing key the DANGEROUS direction is refused (a grant with no owner signature is inert).
    # (owner_key=None in the ctor would fall back to the persisted owner identity, so null it explicitly.)
    reg = _reg(_store())
    reg.owner_key = None
    with pytest.raises(ValueError):
        reg.create_org("acme", "Acme", owner="owner", issued_at=_issue())


# --- membership grant / revoke + per-org role scoping ----------------------------

def test_membership_grant_and_role_resolution():
    s = _store()
    reg = _reg(s)
    reg.create_org("acme", "Acme", owner="owner", issued_at=_issue())
    reg.grant_membership("acme", "alice", "analyst", issued_at=_issue())
    assert reg.membership_role("alice", "acme") == "analyst"
    assert [m.username for m in reg.memberships("acme")] == ["alice"]


def test_membership_revoke_strips_role():
    s = _store()
    reg = _reg(s)
    reg.create_org("acme", "Acme", owner="owner", issued_at=_issue())
    reg.grant_membership("acme", "bob", "operator", issued_at=_issue())
    assert reg.membership_role("bob", "acme") == "operator"
    reg.revoke_membership("acme", "bob")
    assert reg.membership_role("bob", "acme") is None
    assert reg.memberships("acme") == []


def test_per_org_role_scoping_member_of_A_has_no_role_in_B():
    s = _store()
    reg = _reg(s)
    reg.create_org("orga", "A", owner="owner", issued_at=_issue())
    reg.create_org("orgb", "B", owner="owner", issued_at=_issue())
    reg.grant_membership("orga", "alice", "analyst", issued_at=_issue())
    # alice is analyst in A, and has NO role whatsoever in B
    assert reg.membership_role("alice", "orga") == "analyst"
    assert reg.membership_role("alice", "orgb") is None
    assert reg.org_role_can("alice", "orga", "queue_proposal") is True    # analyst carries it in A
    assert reg.org_role_can("alice", "orga", "run_engagement") is False   # but not operator-tier
    assert reg.org_role_can("alice", "orgb", "read") is False             # and nothing at all in B


def test_grant_membership_unknown_org_refused():
    reg = _reg(_store())
    with pytest.raises(ValueError):
        reg.grant_membership("ghost", "alice", "viewer", issued_at=_issue())


def test_grant_membership_revoked_org_refused():
    s = _store()
    reg = _reg(s)
    reg.create_org("acme", "Acme", owner="owner", issued_at=_issue())
    reg.revoke_org("acme")
    with pytest.raises(ValueError):
        reg.grant_membership("acme", "alice", "viewer", issued_at=_issue())


def test_owner_role_not_grantable_per_org():
    s = _store()
    reg = _reg(s)
    reg.create_org("acme", "Acme", owner="owner", issued_at=_issue())
    with pytest.raises(ValueError):
        reg.grant_membership("acme", "alice", "owner", issued_at=_issue())


def test_owner_username_is_not_an_org_member():
    s = _store()
    reg = _reg(s)
    reg.create_org("acme", "Acme", owner="owner", issued_at=_issue())
    with pytest.raises(ValueError):
        reg.grant_membership("acme", "owner", "operator", issued_at=_issue())


def test_bad_member_username_refused():
    s = _store()
    reg = _reg(s)
    reg.create_org("acme", "Acme", owner="owner", issued_at=_issue())
    # (usernames are .strip()'d first — mirroring accounts — so " x" would normalise to the valid "x";
    # these are invalid even after stripping.)
    for bad in ("", "has space", "a" * 65, "-dash", "bad/slash"):
        with pytest.raises(ValueError):
            reg.grant_membership("acme", bad, "viewer", issued_at=_issue())


# --- default-deny admission primitive --------------------------------------------

def test_default_deny_org_role_can():
    s = _store()
    reg = _reg(s)
    reg.create_org("acme", "Acme", owner="owner", issued_at=_issue())
    reg.grant_membership("acme", "alice", "operator", issued_at=_issue())
    assert reg.org_role_can("alice", "acme", None) is False          # unmapped permission
    assert reg.org_role_can("alice", "acme", "") is False
    assert reg.org_role_can("nobody", "acme", "read") is False       # non-member
    assert reg.org_role_can("alice", "ghost", "read") is False       # unknown org
    assert reg.org_role_can("alice", "acme", "manage_users") is False  # operator lacks the owner-only perm
    assert reg.org_role_can("alice", "acme", "run_engagement") is True
    assert reg.org_role_can("alice", "acme", "read") is True


def test_revoke_org_strips_every_member_effective_role():
    s = _store()
    reg = _reg(s)
    reg.create_org("acme", "Acme", owner="owner", issued_at=_issue())
    reg.grant_membership("acme", "alice", "operator", issued_at=_issue())
    assert reg.org_role_can("alice", "acme", "run_engagement") is True
    reg.revoke_org("acme")
    # a decommissioned tenant admits no one, even a still-"active" membership record
    assert reg.membership_role("alice", "acme") is None
    assert reg.org_role_can("alice", "acme", "read") is False


# --- anti-replay / resurrection (the headline guard) -----------------------------

def test_org_revoke_survives_replay_resurrection():
    s = _store()
    reg = _reg(s)
    seq = reg.create_org("acme", "Acme", owner="owner", issued_at=_issue())
    captured = s.get(seq).payload                          # the genuine owner-signed active grant
    reg.revoke_org("acme")
    assert reg.org("acme") is None
    # ATTACK: re-append the captured owner-signed active grant VERBATIM after the revoke. Genuine
    # signature — but issued_at <= the per-org high-water → ignored.
    s.append(kind="event", source="governor", actor="WARDEN", payload=captured)
    assert reg.org("acme") is None, "resurrection via replayed active org grant must fail"
    assert "acme" not in {o.org_id for o in reg.orgs()}


def test_membership_revoke_survives_replay_resurrection():
    s = _store()
    reg = _reg(s)
    reg.create_org("acme", "Acme", owner="owner", issued_at=_issue())
    seq = reg.grant_membership("acme", "alice", "operator", issued_at=_issue())
    captured = s.get(seq).payload
    reg.revoke_membership("acme", "alice")
    assert reg.membership_role("alice", "acme") is None
    s.append(kind="event", source="governor", actor="WARDEN", payload=captured)
    assert reg.membership_role("alice", "acme") is None, "membership resurrection via replay must fail"


def test_stale_active_membership_replay_refused():
    s = _store()
    reg = _reg(s)
    reg.create_org("acme", "Acme", owner="owner", issued_at=_issue())
    seq = reg.grant_membership("acme", "alice", "operator", issued_at=50.0)
    captured = s.get(seq).payload
    s.append(kind="event", source="governor", actor="WARDEN", payload=captured)   # replay same issued_at
    assert reg.membership_role("alice", "acme") == "operator"
    assert len(reg.memberships("acme")) == 1


def test_membership_highwater_is_scoped_per_org_user():
    s = _store()
    reg = _reg(s)
    reg.create_org("orga", "A", owner="owner", issued_at=_issue())
    reg.create_org("orgb", "B", owner="owner", issued_at=_issue())
    # alice granted in A at a HIGH issued_at, then in B at a LOWER one — B is honored (independent high-water,
    # not shadowed by A's). Proves the LWW state is keyed per (org_id, username), not per username.
    reg.grant_membership("orga", "alice", "operator", issued_at=100.0)
    reg.grant_membership("orgb", "alice", "viewer", issued_at=5.0)
    assert reg.membership_role("alice", "orga") == "operator"
    assert reg.membership_role("alice", "orgb") == "viewer"


def test_forged_membership_elevation_is_ignored():
    s = _store()
    reg = _reg(s)
    reg.create_org("acme", "Acme", owner="owner", issued_at=_issue())
    reg.grant_membership("acme", "bob", "viewer", issued_at=_issue())
    # attacker forges an active membership for bob at operator, signed by the attacker key → not honored
    from sigil.governor.authn import signed_payload
    core = {"signal": og.MEMBERSHIP_SIGNAL, "org_id": "acme", "username": "bob", "role": "operator",
            "state": "active", "issued_at": 10_000.0}
    s.append(kind="event", source="governor", actor="WARDEN",
             payload={**signed_payload(core, ATTACKER), "by": "owner"})
    assert reg.membership_role("bob", "acme") == "viewer"   # role unchanged (forgery ignored)


def test_revoke_is_honored_even_unsigned_safe_direction():
    s = _store()
    reg = _reg(s)
    reg.create_org("acme", "Acme", owner="owner", issued_at=_issue())
    reg.grant_membership("acme", "alice", "operator", issued_at=_issue())
    # an UNSIGNED revoke (no owner key) still takes effect — the safe direction
    nokey = OrgRegistry(s, owner_key=OWNER, trusted_pubkey=OP)
    nokey.owner_key = None                                 # truly unsigned (no fallback to a persisted key)
    nokey.revoke_membership("acme", "alice")
    assert reg.membership_role("alice", "acme") is None
    nokey.revoke_org("acme")
    assert reg.org("acme") is None


def test_owner_can_reactivate_org_after_revoke_with_a_fresh_grant():
    s = _store()
    reg = _reg(s)
    reg.create_org("acme", "Acme", owner="owner", issued_at=5.0)
    reg.revoke_org("acme")
    assert reg.org("acme") is None
    # a FRESH owner-signed grant (strictly-greater issued_at) legitimately re-activates
    reg.create_org("acme", "Acme v2", owner="owner", issued_at=99.0)
    o = reg.org("acme")
    assert o is not None and o.name == "Acme v2" and o.created_at == 99.0


# --- org -> tenant_id mapping (org == tenant_id) ---------------------------------

def test_org_tenant_id_identity_mapping():
    s = _store()
    reg = _reg(s)
    reg.create_org("acme-prod_01", "Acme Prod", owner="owner", issued_at=_issue())
    o = reg.org("acme-prod_01")
    assert org_tenant_id(o) == "acme-prod_01"              # org == tenant_id (from an Org)
    assert org_tenant_id("acme-prod_01") == "acme-prod_01"  # and from a raw org_id string


def test_org_tenant_id_fails_closed_on_unmappable_id():
    # an Org reconstructed with an org_id that cannot be a safe tenant path component → fail-closed
    bad_org = Org(org_id="bad/slug", name="x", owner="owner", created_at=1.0, state="active")
    with pytest.raises(ValueError):
        org_tenant_id(bad_org)
    for bad_id in ("", "bad/slug", "../escape", ".", "a" * 65, "-startsdash", "has space"):
        with pytest.raises(ValueError):
            org_tenant_id(bad_id)


def test_valid_org_id_always_maps(tmp_path=None):
    # every id create_org accepts must map cleanly (the create-time check and the derive share _TENANT_RE)
    reg = _reg(_store())
    for good in ("a", "acme", "acme-prod", "acme_prod.01", "A1", "x" * 64):
        reg.create_org(good, "n", owner="owner", issued_at=_issue())
        assert org_tenant_id(reg.org(good)) == good


# --- FATAL-2 + lockstep drift guards ---------------------------------------------

def test_fatal2_orgs_imports_no_offense():
    import sigil.governor.orgs as m
    from sigil.reuse import assert_no_offense
    assert_no_offense()                                    # must not raise in a sovereign env
    src = pathlib.Path(m.__file__).read_text(encoding="utf-8")
    assert "import framework" not in src and "import strix" not in src
    assert "from framework" not in src and "from strix" not in src


def test_username_re_in_lockstep_with_accounts():
    # we REPLICATE accounts._USERNAME_RE (to stay independently importable); assert it never drifts.
    from sigil.governor import accounts as acc
    assert og._USERNAME_RE.pattern == acc._USERNAME_RE.pattern


def test_tenant_re_in_lockstep_with_engine_paths_literal():
    # FATAL-2: engine paths.py is framework/offense-side and MUST NOT be imported. Read it as TEXT and
    # assert the replicated _TENANT_RE literal is byte-identical (mirror-drift guard).
    root = pathlib.Path(og.__file__).resolve().parents[4]     # .../<repo root>
    paths_py = root / "engine" / "crucible" / "framework" / "v2" / "common" / "paths.py"
    assert paths_py.is_file(), f"engine paths.py not found at {paths_py}"
    text = paths_py.read_text(encoding="utf-8")
    m = re.search(r'_TENANT_RE = re\.compile\((r"[^"]+")\)', text)
    assert m, "could not locate _TENANT_RE literal in engine paths.py"
    assert m.group(1) == r'r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}"'
    assert og._TENANT_RE.pattern == r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}"
