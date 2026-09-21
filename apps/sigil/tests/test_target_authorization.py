"""Phase 1 — the sovereign TARGET-AUTHORIZATION ceremony.

"Add a site I own -> authorize it in the UI (the owner key never leaves this process)." The cockpit
owner-signs a scoped, time-boxed EngagementAuthority for a live external target and writes ONLY public
material to the shared seam; the offense side verifies the identical bytes (proven in the vigil_core +
framework suites). These tests lock: the happy path (owner-signed, verifiable, non-destructive default),
public-only seam material, the deliberate refusals (categorical safety floor, live env, non-hostname,
bad window), tamper-on-seam -> verification fails, dispatch + RBAC (target_add is owner-only, list/status
are read), and FATAL-2 (the ceremony imports no offense engine).
"""

from __future__ import annotations

import json
import os
import tempfile

import pytest


@pytest.fixture(autouse=True)
def _iso(monkeypatch):
    monkeypatch.setenv("VIGIL_BASE_DIR", tempfile.mkdtemp())      # the shared seam
    monkeypatch.setenv("SIGIL_SPINE_DIR", tempfile.mkdtemp())     # isolate the owner vault/spine
    monkeypatch.setenv("SIGIL_HOME", tempfile.mkdtemp())


def _bundle_path(host: str = "apme.cm") -> str:
    """The on-disk bundle path for a HOST — derives the slug exactly as the ceremony does (apme.cm -> apme-cm)."""
    from sigil.ui.target_authorization import _slug_for
    return os.path.join(os.environ["VIGIL_BASE_DIR"], "target-authorizations", f"{_slug_for(host, None)}.json")


# --- happy path -----------------------------------------------------------------------------------
def test_add_target_writes_an_owner_signed_verifiable_authorization():
    from sigil.governor.identity import ensure_owner_keypair
    from sigil.ui import target_authorization as ta
    from vigil_core import verify_engagement_authority
    from vigil_integration.live.authorization_broker import read_authorization

    r = ta.add_target("apme.cm", environment="staging", duration_hours=8.0, note="first gov target")
    # slug is the console-canonical form (apme.cm -> apme-cm); scope is the literal HOST.
    assert r["ok"] and r["slug"] == "apme-cm" and r["scope"] == ["apme.cm"] and r["environment"] == "staging"

    got = read_authorization(os.environ["VIGIL_BASE_DIR"], "apme-cm")
    assert got is not None
    ok, reason = verify_engagement_authority(got.signed_authority, got.trust_root)
    assert ok, reason
    # signed by THIS cockpit's owner key; GET-only / non-destructive by default.
    kp = ensure_owner_keypair()
    assert {a.public_key_b64 for a in got.trust_root.authorizers} == {kp.public_key_b64}
    assert got.signed_authority.document.allow_destructive is False


# the KNOWN-PUBLIC field set for the seam bundle, at every level — a STRUCTURAL allowlist (red-pen #16):
# any key not listed here means private/unexpected material crossed the seam.
_PUBLIC_SCHEMA = {
    "": {"schema_version", "kind", "slug", "signed_authority", "trust_root"},
    "signed_authority": {"document", "signatures"},
    "signed_authority.document": {"engagement_slug", "environment", "scope", "not_before", "not_after",
                                  "allow_destructive", "live_destructive_acknowledged", "max_actions",
                                  "issued_by", "note", "oob_relay_host", "oob_collector_pubkey",
                                  "oob_dns_domain", "oob_dns_collector_pubkey"},
    "signed_authority.signatures[]": {"key_id", "signature_b64"},
    "trust_root": {"schema_version", "threshold", "authorizers"},
    "trust_root.authorizers[]": {"key_id", "name", "public_key_b64"},
}


def _assert_public_only(node, path=""):
    """Recursively assert every object key at every level is in the known-public allowlist — stronger than a
    'priv' substring scan (a renamed/base64'd secret would evade a substring check, not this)."""
    if isinstance(node, dict):
        allowed = _PUBLIC_SCHEMA.get(path)
        assert allowed is not None, f"unexpected object at {path!r}: {sorted(node)}"
        assert set(node) <= allowed, f"non-public key(s) at {path!r}: {sorted(set(node) - allowed)}"
        for k, v in node.items():
            _assert_public_only(v, f"{path}.{k}" if path else k)
    elif isinstance(node, list):
        for item in node:
            _assert_public_only(item, f"{path}[]")


def test_seam_bundle_carries_no_private_material():
    from sigil.ui import target_authorization as ta
    ta.add_target("apme.cm")
    raw = open(_bundle_path(), encoding="utf-8").read()
    assert "priv" not in raw.lower(), "private material must never cross the seam"
    _assert_public_only(json.loads(raw))   # structural allowlist: every key at every level is public


def test_status_and_list_reflect_the_authorization():
    from sigil.ui import target_authorization as ta
    ta.add_target("apme.cm")
    st = ta.authority_status("apme.cm")
    assert st["present"] and st["bound"] and st["scope"] == ["apme.cm"]
    lst = ta.list_targets()
    assert any(t["slug"] == "apme-cm" and t["bound"] for t in lst["targets"]), lst


# --- deliberate refusals --------------------------------------------------------------------------
@pytest.mark.parametrize("host", ["example.gov", "foo.mil", "test.edu", "who.int", "x.gov.cm"])
def test_refuses_categorical_safety_floor(host):
    from sigil.ui import target_authorization as ta
    r = ta.add_target(host)
    assert not r["ok"] and "safety floor" in r["error"], r
    assert not os.path.exists(_bundle_path(host)), "a refused host must write no bundle"


def test_refuses_live_environment():
    from sigil.ui import target_authorization as ta
    r = ta.add_target("apme.cm", environment="live")
    assert not r["ok"] and "LIVE" in r["error"], r


@pytest.mark.parametrize("bad", ["https://apme.cm/", "apme.cm:8443", "a b", "", "..", "-bad-.example",
                                 "foo/bar", "x..y"])
def test_refuses_non_hostname(bad):
    from sigil.ui import target_authorization as ta
    assert ta.add_target(bad)["ok"] is False


def test_refuses_bad_duration():
    from sigil.ui import target_authorization as ta
    assert ta.add_target("apme.cm", duration_hours=0)["ok"] is False
    assert ta.add_target("apme.cm", duration_hours=-1)["ok"] is False
    assert ta.add_target("apme.cm", duration_hours=10 ** 6)["ok"] is False


@pytest.mark.parametrize("ip", ["127.0.0.1", "169.254.169.254", "0.0.0.0", "224.0.0.1", "255.255.255.255"])
def test_refuses_loopback_linklocal_metadata_ip_literals(ip):
    """red-pen #14: a 'live external' authorization must refuse loopback / link-local (incl. cloud metadata
    169.254.169.254) / multicast / reserved / unspecified IP literals, which pass the hostname regex."""
    from sigil.ui import target_authorization as ta
    r = ta.add_target(ip)
    assert not r["ok"], r
    assert "loopback" in r["error"] or "link-local" in r["error"] or "reserved" in r["error"], r


def test_unsafe_explicit_slug_returns_contract_not_raises():
    """red-pen #13: a slug that sanitizes to empty returns {ok:false}, never an uncaught ValueError."""
    from sigil.ui import target_authorization as ta
    for bad in ("..", ".", "///", "..."):
        r = ta.add_target("apme.cm", slug=bad)
        assert isinstance(r, dict) and r["ok"] is False, (bad, r)


def test_traversal_slug_is_sanitized_not_reflected():
    """A path-traversal explicit slug is NEUTRALISED to a safe token (dots/slashes -> '-'), never reflected
    as a path — so it cannot escape the authorizations dir."""
    from sigil.ui import target_authorization as ta
    r = ta.add_target("apme.cm", slug="../../etc")
    assert r["ok"] is True and r["slug"] == "etc" and "/" not in r["slug"] and ".." not in r["slug"], r


# --- tamper on the seam is caught by verification (the offense side's guarantee) ------------------
def test_tampering_the_seam_bundle_scope_fails_verification():
    from sigil.ui import target_authorization as ta
    from vigil_core import verify_engagement_authority
    from vigil_integration.live.authorization_broker import read_authorization

    ta.add_target("apme.cm")
    p = _bundle_path()
    d = json.loads(open(p, encoding="utf-8").read())
    d["signed_authority"]["document"]["scope"] = ["evil.example"]   # attacker widens the scope on disk
    open(p, "w", encoding="utf-8").write(json.dumps(d))
    got = read_authorization(os.environ["VIGIL_BASE_DIR"], "apme-cm")
    ok, _ = verify_engagement_authority(got.signed_authority, got.trust_root)
    assert not ok, "a tampered on-disk scope must FAIL verification (fail-closed)"


# --- dispatch + RBAC ------------------------------------------------------------------------------
def test_do_action_routes_target_actions_and_add_is_owner_only():
    import tempfile as _t

    from sigil.governor.accounts import PermissionDenied, Principal
    from sigil.spine.store import SpineStore
    from sigil.ui import actions

    assert {"target_add", "target_list", "target_authority_status"} <= actions.ACTIONS
    store = SpineStore(_t.mktemp(suffix=".jsonl"))
    # owner (principal=None ⇒ the CLI/host owner) can authorize a target
    assert actions.do_action("target_add", {"host": "apme.cm"}, store=store)["ok"] is True
    # an OPERATOR is refused BEFORE any signing (owner-only, like minting a charter)
    with pytest.raises(PermissionDenied):
        actions.do_action("target_add", {"host": "apme.cm"}, store=store,
                          principal=Principal("otto", "operator"))
    # read-only list/status are allowed for any authenticated role (public-safe)
    assert actions.do_action("target_list", {}, store=store,
                             principal=Principal("vera", "viewer"))["ok"] is True


# --- FATAL-2 --------------------------------------------------------------------------------------
def test_ceremony_imports_no_offense_engine():
    import sys
    for m in [m for m in list(sys.modules) if m.startswith(("framework", "strix"))]:
        sys.modules.pop(m, None)
    from sigil.ui import target_authorization  # noqa: F401
    assert not any(m == "framework" or m.startswith("framework.") or m == "strix" or m.startswith("strix.")
                   for m in sys.modules), "the ceremony dragged the offense engine into the sovereign process"
