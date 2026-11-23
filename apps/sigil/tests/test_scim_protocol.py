"""PR-H edge — the SCIM 2.0 protocol handler (`ui.scim.scim_dispatch`) against the request shapes real IdPs send.

What an IdP needs for correct reconciliation, and what an attacker holding a SCIM token must NOT get:
  * Users: `filter=userName eq "x"` answers "does x exist?" (0 or 1 — never "everyone"), a created user reads back
    with the userName/externalId the IdP wrote, PATCH in both Okta (`value:{active:false}`) and Entra
    (`op:"Replace", path:"active", value:"False"`) shapes, PUT, DELETE, pagination, 409 on a duplicate userName;
  * Groups: create with members, PATCH add / remove (Entra value list, Okta `members[value eq "id"]` path),
    rename, delete, `excludedAttributes=members` — and every membership change re-roles the members through the
    owner-signed config's map, capped;
  * ATTACKS: a group literally named `founder`/`owner`, `roles:[owner]`, a PATCH writing `roles`, and a group
    rename onto a mapped name can never reach founder/owner; a SCIM token can never touch a member it did not
    provision (the org's password founder) nor any other org's user; org A's token on org B is a 401; a member the
    owner elevated by hand is never re-granted (but deactivation still revokes it);
  * every grant / revoke is preceded by the audit hook — a failing audit aborts the change (fail-closed).
"""
from __future__ import annotations

import datetime
import itertools
import tempfile

import pytest

from sigil.governor.orgs import OrgRegistry
from sigil.governor.sso_config import SsoConfigRegistry
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore
from sigil.ui import scim as uiscim

OWNER = generate_keypair()
OP = OWNER.public_key_b64
NOW = 1_000_400_000.0
TOKEN_A = "ACME-" + "a" * 40
TOKEN_B = "BETA-" + "b" * 40
_iss = itertools.count(1)


def _issue() -> float:
    return float(next(_iss))


def _cert_pem():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    n = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "idp")])
    c = (x509.CertificateBuilder().subject_name(n).issuer_name(n).public_key(k.public_key()).serial_number(1)
         .not_valid_before(datetime.datetime(2020, 1, 1)).not_valid_after(datetime.datetime(2035, 1, 1))
         .sign(k, hashes.SHA256()))
    return c.public_bytes(serialization.Encoding.PEM).decode()


CERT = _cert_pem()


class Env:
    def __init__(self):
        self.store = SpineStore(tempfile.mktemp(suffix=".jsonl"))
        self.orgs = OrgRegistry(self.store, owner_key=OWNER, trusted_pubkey=OP)
        self.cfg = SsoConfigRegistry(self.store, owner_key=OWNER, trusted_pubkey=OP)
        self.audits: list = []
        for org, tok in (("acme", TOKEN_A), ("beta", TOKEN_B)):
            self.orgs.create_org(org, org.title(), owner="owner", issued_at=_issue())
            self.cfg.set_saml_config(org, idp_entity_id="https://idp", idp_certs_pem=[CERT],
                                     sp_entity_id=f"https://sp/{org}", acs_url=f"https://app/acs/{org}",
                                     default_role="viewer",
                                     group_role_map={"Admins": "org_admin", "Security": "analyst"},
                                     role_cap="org_admin", scim_enabled=True, scim_token=tok, issued_at=_issue())

    def call(self, method, path, body=None, *, org="acme", token=TOKEN_A, query="", audit=None):
        return uiscim.scim_dispatch(method, path, body, f"Bearer {token}", org_id=org, config_registry=self.cfg,
                                    org_registry=self.orgs, now=NOW, query=query, issued_at=_issue(),
                                    audit=audit if audit is not None else
                                    (lambda a, t, o: self.audits.append((a, t, o))))

    def role(self, uid, org="acme"):
        return OrgRegistry(self.store, owner_key=OWNER, trusted_pubkey=OP).membership_role(uid, org)


@pytest.fixture
def env():
    return Env()


def _okta_user(user_name="alice@acme.com", ext="00u1alice", active=True):
    return {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": user_name,
            "name": {"givenName": "Alice", "familyName": "Ng"}, "emails": [{"primary": True, "value": user_name,
                                                                            "type": "work"}],
            "displayName": "Alice Ng", "externalId": ext, "groups": [], "active": active}


# --- Users ---------------------------------------------------------------------------------------------

def test_okta_reconcile_flow_filter_create_read_back(env):
    r = env.call("GET", "/Users", query='filter=userName+eq+%22alice%40acme.com%22&startIndex=1&count=100')
    assert r.status == 200 and r.body["totalResults"] == 0 and r.body["Resources"] == []   # "does it exist?" → no
    c = env.call("POST", "/Users", _okta_user())
    assert c.status == 201 and c.body["userName"] == "alice@acme.com" and c.body["externalId"] == "00u1alice"
    uid = c.body["id"]
    assert c.body["roles"] == [{"value": "viewer"}] and env.role(uid) == "viewer"
    hit = env.call("GET", "/Users", query='filter=userName eq "ALICE@acme.com"')            # case-insensitive
    assert hit.body["totalResults"] == 1 and hit.body["Resources"][0]["id"] == uid
    by_ext = env.call("GET", "/Users", query='filter=externalId eq "00u1alice"')
    assert by_ext.body["totalResults"] == 1
    got = env.call("GET", f"/Users/{uid}")
    assert got.status == 200 and got.body["name"]["givenName"] == "Alice" and got.body["emails"][0]["type"] == "work"


def test_username_filter_and_uniqueness_compare_letter_case_only_never_a_look_alike(env):
    import urllib.parse
    uid = env.call("POST", "/Users", _okta_user("sam@acme.com", "00u-sam")).body["id"]
    look = "\u017fam@acme.com"                    # LONG S: a DIFFERENT userName that merely casefolds to sam's
    miss = env.call("GET", "/Users", query=urllib.parse.urlencode({"filter": f'userName eq "{look}"'}))
    assert miss.status == 200 and miss.body["totalResults"] == 0         # "does it exist?" is never answered by sam
    hit = env.call("GET", "/Users", query=urllib.parse.urlencode({"filter": 'userName eq "SAM@ACME.COM"'}))
    assert hit.body["totalResults"] == 1 and hit.body["Resources"][0]["id"] == uid     # letter case alone matches
    other = env.call("POST", "/Users", _okta_user(look, "00u-other"))
    assert other.status == 201 and other.body["id"] != uid               # its own user, never a 409 against sam
    assert env.call("POST", "/Users", _okta_user("SAM@acme.com", "00u-sam2")).status == 409   # a true duplicate


def test_duplicate_username_is_409_uniqueness(env):
    assert env.call("POST", "/Users", _okta_user()).status == 201
    dup = env.call("POST", "/Users", _okta_user(ext="00u2other"))
    assert dup.status == 409 and dup.body["scimType"] == "uniqueness"


@pytest.mark.parametrize("flt", ['userName co "a"', 'userName eq "a" and active eq true', 'title eq "x"',
                                 'userName eq a', 'userName eq "unterminated'])
def test_unsupported_filters_are_400_never_an_unfiltered_list(env, flt):
    env.call("POST", "/Users", _okta_user())
    import urllib.parse
    r = env.call("GET", "/Users", query="filter=" + urllib.parse.quote(flt))
    assert r.status == 400 and r.body["scimType"] == "invalidFilter"


def test_pagination(env):
    for i in range(5):
        env.call("POST", "/Users", _okta_user(user_name=f"u{i}@acme.com", ext=f"00u{i}"))
    page = env.call("GET", "/Users", query="startIndex=2&count=2")
    assert page.body["totalResults"] == 5 and page.body["startIndex"] == 2 and page.body["itemsPerPage"] == 2
    assert env.call("GET", "/Users", query="count=0").body["Resources"] == []


def test_okta_patch_deactivate_revokes_and_reports_the_username(env):
    uid = env.call("POST", "/Users", _okta_user()).body["id"]
    r = env.call("PATCH", f"/Users/{uid}", {"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                                            "Operations": [{"op": "replace", "value": {"active": False}}]})
    assert r.status == 200 and r.body["active"] is False and r.body["roles"] == []
    assert env.role(uid) is None and r.deactivated == (uid,)
    # re-activation re-grants
    r2 = env.call("PATCH", f"/Users/{uid}", {"Operations": [{"op": "replace", "value": {"active": True}}]})
    assert r2.status == 200 and env.role(uid) == "viewer"


def test_entra_patch_shapes(env):
    uid = env.call("POST", "/Users", _okta_user()).body["id"]
    r = env.call("PATCH", f"/Users/{uid}", {"Operations": [
        {"op": "Replace", "path": "emails[type eq \"work\"].value", "value": "alice2@acme.com"},
        {"op": "Replace", "path": "displayName", "value": "Alice N."},
        {"op": "Add", "path": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department",
         "value": "Sec"},
        {"op": "Replace", "path": "active", "value": "False"}]})
    assert r.status == 200 and r.body["displayName"] == "Alice N."
    assert {"value": "alice2@acme.com", "type": "work"} in r.body["emails"]
    assert env.role(uid) is None                                    # Entra's string "False" deactivates


def test_put_replaces_and_rename_conflict_is_409(env):
    a = env.call("POST", "/Users", _okta_user()).body["id"]
    env.call("POST", "/Users", _okta_user(user_name="bob@acme.com", ext="00u2bob"))
    r = env.call("PUT", f"/Users/{a}", {**_okta_user(), "userName": "bob@acme.com"})
    assert r.status == 409
    r = env.call("PUT", f"/Users/{a}", {**_okta_user(), "displayName": "A", "active": False})
    assert r.status == 200 and r.body["displayName"] == "A" and env.role(a) is None


def test_delete_revokes_and_unknown_is_404(env):
    uid = env.call("POST", "/Users", _okta_user()).body["id"]
    d = env.call("DELETE", f"/Users/{uid}")
    assert d.status == 204 and d.body is None and d.deactivated == (uid,) and env.role(uid) is None
    assert env.call("GET", f"/Users/{uid}").status == 404
    assert env.call("DELETE", f"/Users/{uid}").status == 404


def test_bad_bodies_are_clean_400s(env):
    assert env.call("POST", "/Users", ["not", "an", "object"]).status == 400
    assert env.call("POST", "/Users", {"active": "maybe", "userName": "x"}).status == 400
    uid = env.call("POST", "/Users", _okta_user()).body["id"]
    assert env.call("PATCH", f"/Users/{uid}", {"Operations": []}).status == 400
    assert env.call("PATCH", f"/Users/{uid}", {"Operations": [{"op": "frobnicate"}]}).status == 400
    assert env.call("PATCH", f"/Users/{uid}", {"Operations": [{"op": "remove"}]}).status == 400
    assert env.call("POST", f"/Users/{uid}", {}).status == 405


# --- Groups -------------------------------------------------------------------------------------------

def test_groups_drive_the_capped_role(env):
    a = env.call("POST", "/Users", _okta_user()).body["id"]
    b = env.call("POST", "/Users", _okta_user(user_name="bob@acme.com", ext="00u2bob")).body["id"]
    g = env.call("POST", "/Groups", {"displayName": "Admins", "members": [{"value": a}]})
    assert g.status == 201 and [m["value"] for m in g.body["members"]] == [a]
    assert env.role(a) == "org_admin" and env.role(b) == "viewer"
    gid = g.body["id"]
    # Entra-shaped add of b
    env.call("PATCH", f"/Groups/{gid}", {"Operations": [{"op": "Add", "path": "members", "value": [{"value": b}]}]})
    assert env.role(b) == "org_admin"
    # Okta-shaped remove of a by path filter
    r = env.call("PATCH", f"/Groups/{gid}", {"Operations": [{"op": "remove", "path": f'members[value eq "{a}"]'}]})
    assert r.status == 200 and env.role(a) == "viewer"
    # rename: Admins → Security re-roles every member (org_admin → analyst)
    env.call("PATCH", f"/Groups/{gid}", {"Operations": [{"op": "replace", "value": {"id": gid,
                                                                                    "displayName": "Security"}}]})
    assert env.role(b) == "analyst"
    # excludedAttributes=members
    lst = env.call("GET", "/Groups", query="excludedAttributes=members&filter=displayName+eq+%22security%22")
    assert lst.body["totalResults"] == 1 and "members" not in lst.body["Resources"][0]
    # delete the group → its members fall back to the default role
    assert env.call("DELETE", f"/Groups/{gid}").status == 204 and env.role(b) == "viewer"


def test_group_put_replaces_members(env):
    a = env.call("POST", "/Users", _okta_user()).body["id"]
    b = env.call("POST", "/Users", _okta_user(user_name="bob@acme.com", ext="00u2bob")).body["id"]
    gid = env.call("POST", "/Groups", {"displayName": "Admins", "members": [{"value": a}]}).body["id"]
    r = env.call("PUT", f"/Groups/{gid}", {"displayName": "Admins", "members": [{"value": b}]})
    assert r.status == 200 and [m["value"] for m in r.body["members"]] == [b]
    assert env.role(a) == "viewer" and env.role(b) == "org_admin"


def test_duplicate_group_name_is_409(env):
    env.call("POST", "/Groups", {"displayName": "Admins"})
    assert env.call("POST", "/Groups", {"displayName": "admins"}).status == 409


# --- ATTACKS: role escalation, cross-principal, cross-org -----------------------------------------------

def test_attack_scim_can_never_reach_founder_or_owner(env):
    uid = env.call("POST", "/Users", {**_okta_user(), "roles": [{"value": "owner"}, {"value": "founder"}],
                                      "groups": [{"value": "founder"}]}).body["id"]
    assert env.role(uid) == "viewer"
    for name in ("founder", "owner", "operator"):
        gid = env.call("POST", "/Groups", {"displayName": name, "members": [{"value": uid}]}).body["id"]
        assert env.role(uid) == "viewer", name
        env.call("DELETE", f"/Groups/{gid}")
    env.call("PATCH", f"/Users/{uid}", {"Operations": [{"op": "add", "path": "roles",
                                                        "value": [{"value": "owner"}, {"value": "Admins"}]}]})
    assert env.role(uid) == "org_admin"              # the owner-mapped selector caps at org_admin, never above
    assert env.role(uid) not in ("founder", "owner", "operator")


def test_attack_scim_cannot_touch_a_member_it_did_not_provision(env):
    env.orgs.grant_membership("acme", "cust_founder1", "founder", issued_at=_issue())
    for method, body in (("DELETE", None), ("PATCH", {"Operations": [{"op": "replace", "path": "active",
                                                                      "value": False}]}),
                         ("PUT", {"userName": "x", "active": False}), ("GET", None)):
        assert env.call(method, "/Users/cust_founder1", body).status == 404, method
    gid = env.call("POST", "/Groups", {"displayName": "Admins"}).body["id"]
    env.call("PATCH", f"/Groups/{gid}", {"Operations": [{"op": "add", "path": "members",
                                                         "value": [{"value": "cust_founder1"}]}]})
    assert env.role("cust_founder1") == "founder"    # untouched: not in this org's SCIM directory


def test_attack_org_a_token_on_org_b_is_401_and_ids_never_cross(env):
    uid = env.call("POST", "/Users", _okta_user()).body["id"]
    for method, path in (("GET", "/Users"), ("POST", "/Users"), ("DELETE", f"/Users/{uid}"), ("GET", "/Groups")):
        assert env.call(method, path, _okta_user() if method == "POST" else None, org="beta",
                        token=TOKEN_A).status == 401
    # beta's own token cannot reach acme's user by id either
    assert env.call("DELETE", f"/Users/{uid}", org="beta", token=TOKEN_B).status == 404
    gid = env.call("POST", "/Groups", {"displayName": "Admins", "members": [{"value": uid}]}, org="beta",
                   token=TOKEN_B).body["id"]
    assert env.call("GET", f"/Groups/{gid}", org="beta", token=TOKEN_B).body["members"] == []
    assert env.role(uid) == "viewer" and env.role(uid, "beta") is None


def test_an_owner_elevated_member_is_never_regranted_but_still_deactivates(env):
    uid = env.call("POST", "/Users", _okta_user()).body["id"]
    env.orgs.grant_membership("acme", uid, "founder", issued_at=_issue())     # the owner's hand-set role
    gid = env.call("POST", "/Groups", {"displayName": "Security", "members": [{"value": uid}]}).body["id"]
    assert env.role(uid) == "founder"                # SCIM did not overwrite the owner's grant
    env.call("PATCH", f"/Groups/{gid}", {"Operations": [{"op": "remove", "path": "members"}]})
    assert env.role(uid) == "founder"
    env.call("PATCH", f"/Users/{uid}", {"Operations": [{"op": "replace", "path": "active", "value": False}]})
    assert env.role(uid) is None                     # deprovisioning (the safe direction) always wins


def test_auth_is_checked_before_routing(env):
    bad = uiscim.scim_dispatch("GET", "/Nope", None, "Bearer wrong", org_id="acme", config_registry=env.cfg,
                               org_registry=env.orgs, now=NOW)
    assert bad.status == 401                          # an unknown endpoint is not revealed without the token
    assert uiscim.scim_dispatch("GET", "/Users", None, None, org_id="acme", config_registry=env.cfg,
                                org_registry=env.orgs, now=NOW).status == 401


# --- the audit hook is fail-closed ----------------------------------------------------------------------

def test_every_grant_and_revoke_is_audited_first_and_a_failing_audit_aborts(env):
    uid = env.call("POST", "/Users", _okta_user()).body["id"]
    assert ("scim_grant", uid, "role=viewer") in env.audits

    def boom(*_a):
        raise OSError("audit store unavailable")
    with pytest.raises(OSError):
        env.call("PATCH", f"/Users/{uid}", {"Operations": [{"op": "replace", "path": "active", "value": False}]},
                 audit=boom)
    assert env.role(uid) == "viewer"                  # the revoke never happened without its audit row


# --- discovery -------------------------------------------------------------------------------------------

def test_discovery_endpoints(env):
    spc = env.call("GET", "/ServiceProviderConfig")
    assert spc.status == 200 and spc.body["patch"]["supported"] is True and spc.body["bulk"]["supported"] is False
    assert spc.body["filter"]["maxResults"] == uiscim.MAX_RESULTS
    rt = env.call("GET", "/ResourceTypes")
    assert {r["id"] for r in rt.body["Resources"]} == {"User", "Group"}
    assert env.call("GET", "/ResourceTypes/User").body["endpoint"] == "/Users"
    sch = env.call("GET", "/Schemas")
    assert sch.body["totalResults"] == 2
    assert env.call("POST", "/ServiceProviderConfig", {}).status == 405


# --- per-request bounds: what ONE request may write is bounded, whatever its body repeats -------------------------

def _spine(env) -> int:
    return sum(1 for _ in env.store.iter_records())


def _mk_users(env, n: int, prefix: str = "m") -> list:
    out = []
    for i in range(n):
        r = env.call("POST", "/Users", _okta_user(f"{prefix}{i}@acme.com", f"00u-{prefix}{i}"))
        assert r.status == 201, r.body
        out.append(r.body["id"])
    return out


def test_member_references_are_bounded_over_the_whole_patch_not_per_operation(env):
    """The member-reference bound is SUMMED over every operation: repeating an operation cannot multiply it. Re-adding
    the same ten members 101 times writes no more than ten edges, so only that bound can refuse it."""
    ids = _mk_users(env, 10)
    gid = env.call("POST", "/Groups", {"displayName": "Plain"}).body["id"]
    refs = [{"value": u} for u in ids]
    ops = [{"op": "add", "path": "members", "value": refs}] * (uiscim.MAX_MEMBER_VALUES // len(refs) + 1)
    before = _spine(env)
    r = env.call("PATCH", f"/Groups/{gid}", {"Operations": ops})
    assert r.status == 400 and r.body["scimType"] == "tooMany", r.body
    assert _spine(env) == before and r.records == 0                  # refused whole: not one record written
    assert env.call("GET", f"/Groups/{gid}").body["members"] == []
    # the stateless pre-check the provisioner runs before its critical section refuses the same body
    pre = uiscim.request_bound_refusal("PATCH", f"/Groups/{gid}", {"Operations": ops})
    assert pre is not None and pre.status == 400 and pre.body["scimType"] == "tooMany"
    # exactly at the bound passes (and the pre-check counts each shape the dispatcher counts)
    at = ops[:-1] + [{"op": "remove", "path": f'members[value eq "{ids[0]}"]'}]
    assert uiscim.request_bound_refusal("PATCH", f"/Groups/{gid}", {"Operations": at + [at[-1]]}) is not None
    assert uiscim.request_bound_refusal("PATCH", f"/Groups/{gid}", {"Operations": at[1:] + [at[-1]]}) is None
    assert uiscim.request_bound_refusal("PATCH", f"/Groups/{gid}",
                                        {"Operations": [{"op": "add", "value": {"members": refs}}] * 101}) is not None
    ok = env.call("PATCH", f"/Groups/{gid}", {"Operations": at[1:]})               # 1000 references
    assert ok.status == 200 and len(ok.body["members"]) == 9


def test_an_alternating_add_remove_flood_is_refused_with_nothing_written(env):
    """add-N / remove-all repeated: every repetition would write N edges and remove them again. Refused whole."""
    ids = _mk_users(env, 20)
    gid = env.call("POST", "/Groups", {"displayName": "Plain"}).body["id"]
    refs = [{"value": u} for u in ids]
    ops: list = []
    while len(ops) < uiscim.MAX_PATCH_OPS:
        ops += [{"op": "add", "path": "members", "value": refs}, {"op": "remove", "path": "members"}]
    before = _spine(env)
    r = env.call("PATCH", f"/Groups/{gid}", {"Operations": ops})
    assert r.status == 400 and r.body["scimType"] == "tooMany" and _spine(env) == before and r.records == 0


def test_a_group_write_authoring_more_than_the_directory_bound_is_refused_before_any_record(env, monkeypatch):
    """Within the reference bound, a change can still author more records than it names (an add then a replace that
    takes the added members out again): it is refused WHOLE before a single record lands. Removing state that was
    already there is never capped — a DELETE or a remove-all of a group larger than the bound still deprovisions."""
    monkeypatch.setattr(uiscim, "MAX_DIRECTORY_WRITES", 20)
    ids = _mk_users(env, 12)
    refs = [{"value": u} for u in ids]
    gid = env.call("POST", "/Groups", {"displayName": "Plain"}).body["id"]
    churn = {"Operations": [{"op": "add", "path": "members", "value": refs},
                            {"op": "replace", "path": "members", "value": []},
                            {"op": "add", "path": "members", "value": refs}]}        # 36 records, 24 references
    before = _spine(env)
    r = env.call("PATCH", f"/Groups/{gid}", churn)
    assert r.status == 400 and r.body["scimType"] == "tooMany", r.body
    assert _spine(env) == before and env.call("GET", f"/Groups/{gid}").body["members"] == []
    # an ordinary change under the bound lands; so does removing more existing state than the bound allows
    admins = env.call("POST", "/Groups", {"displayName": "Admins", "members": refs})       # 13 records
    assert admins.status == 201 and all(env.role(u) == "org_admin" for u in ids)
    env.call("PATCH", f"/Groups/{gid}", {"Operations": [{"op": "add", "path": "members", "value": refs}]})
    assert env.call("PATCH", f"/Groups/{gid}", {"Operations": [{"op": "remove", "path": "members"}]}).status == 200
    assert env.call("GET", f"/Groups/{gid}").body["members"] == []
    more = _mk_users(env, 10, prefix="x")
    env.call("PATCH", f"/Groups/{admins.body['id']}",
             {"Operations": [{"op": "add", "path": "members", "value": [{"value": u} for u in more]}]})
    d = env.call("DELETE", f"/Groups/{admins.body['id']}")                                 # 22 members, 23 records
    assert d.status == 204 and d.records > 20
    assert all(env.role(u) == "viewer" for u in ids + more)                  # every member deprovisioned to default


def test_a_replace_reads_the_group_once_not_once_per_reference(env, monkeypatch):
    """`replace members` of many ids (even ids that exist nowhere) is linear: the group is read a fixed number of
    times, never once per named reference."""
    from sigil.governor.scim_directory import OrgDirectory
    gid = env.call("POST", "/Groups", {"displayName": "T"}).body["id"]
    calls = {"n": 0}
    real = OrgDirectory.members

    def counted(self, group_id):
        calls["n"] += 1
        return real(self, group_id)
    monkeypatch.setattr(OrgDirectory, "members", counted)
    junk = [{"value": f"x{i}"} for i in range(uiscim.MAX_MEMBER_VALUES)]
    r = env.call("PATCH", f"/Groups/{gid}", {"Operations": [{"op": "replace", "path": "members", "value": junk}]})
    assert r.status == 200 and r.records == 0
    assert calls["n"] < 10, calls


def test_records_reports_exactly_what_the_request_appended(env):
    """`ScimResult.records` (what the provisioner charges to the write budget) is every spine record the request
    appended: directory records, membership grants / revokes and one critical audit row per hook call."""
    def audit(action, target, outcome):
        env.store.append(kind="event", source="provision", actor="WARDEN",
                         payload={"signal": "provision.audit", "action": action, "target": target})

    def call(*a, **kw):
        before = _spine(env)
        r = env.call(*a, audit=audit, **kw)
        assert r.records == _spine(env) - before, (a[:2], r.records, _spine(env) - before)
        return r
    a = call("POST", "/Users", _okta_user("a@acme.com", "00u-a"))
    b = call("POST", "/Users", _okta_user("b@acme.com", "00u-b"))
    assert a.records == 3                                                    # user record + audit + grant
    g = call("POST", "/Groups", {"displayName": "Admins", "members": [{"value": a.body["id"]},
                                                                       {"value": b.body["id"]}]})
    assert g.records == 7                                                    # group + 2 edges + 2 x (audit + grant)
    assert call("PUT", f"/Users/{a.body['id']}", _okta_user("a@acme.com", "00u-a")).records == 0   # a no-op re-sync
    call("PATCH", f"/Groups/{g.body['id']}", {"Operations": [{"op": "remove", "path": "members",
                                                               "value": [{"value": b.body["id"]}]}]})
    call("DELETE", f"/Users/{a.body['id']}")
    call("DELETE", f"/Groups/{g.body['id']}")
    assert call("PATCH", "/Groups/grp_" + "0" * 24, {"Operations": [{"op": "remove", "path": "members"}]}).records == 0


def _seed_users(env, n: int) -> list:
    """`n` directory users with their default (viewer) membership, written in one view (fast setup only — the bound
    under test is on the GROUP requests that follow, which go through the dispatcher)."""
    from sigil.governor.scim_directory import ScimDirectoryRegistry
    d = ScimDirectoryRegistry(env.store, owner_key=OWNER, trusted_pubkey=OP).directory("acme")
    ids = []
    for i in range(n):
        uid = "sso_" + f"{i:024x}"
        d.put_user(uid, user_name=f"s{i}@acme.com", external_id=f"00u-s{i}", active=True, now=_issue())
        env.orgs.grant_membership("acme", uid, "viewer", issued_at=_issue())
        ids.append(uid)
    return ids


def test_a_realistic_group_sync_of_a_few_hundred_members_passes(env):
    """Ordinary IdP traffic is untouched: a few hundred members created, moved and replaced in single requests."""
    ids = _seed_users(env, 300)
    refs = [{"value": u} for u in ids]
    g = env.call("POST", "/Groups", {"displayName": "Security", "members": refs[:250]})
    assert g.status == 201 and len(g.body["members"]) == 250
    p = env.call("PATCH", f"/Groups/{g.body['id']}",
                 {"Operations": [{"op": "add", "path": "members", "value": refs[250:]},
                                 {"op": "remove", "path": "members", "value": refs[:100]}]})
    assert p.status == 200 and len(p.body["members"]) == 200
    put = env.call("PUT", f"/Groups/{g.body['id']}", {"displayName": "Security", "members": refs})
    assert put.status == 200 and len(put.body["members"]) == 300
    roles = {m.username: m.role for m in OrgRegistry(env.store, owner_key=OWNER, trusted_pubkey=OP).memberships("acme")}
    assert all(roles[u] == "analyst" for u in ids)
