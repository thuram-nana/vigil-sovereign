"""AEGIS AS-2g — the SOVEREIGN origin BINDING + PUBLISH step (bind, publish, read-back, revert, status).

Deterministic, NO-LLM, FATAL-2-clean. Load-bearing invariants a false-green would break (a grant forwarded to an
unbound/forged origin; a bound grant left active without a verifiable published binding; a plaintext secret in
the published record; a non-deterministic published artifact):

  * ``bind_and_publish`` publishes a binding the keyless plane can VERIFY and mints a grant that CROSS-CHECKS
    against it (``grant_binds_origin`` passes over the PUBLISHED files — what the data plane reads);
  * the published binding carries NO plaintext secret — only the keyed-PRF COMMITMENT (HMAC-SHA256 over the
    origin-lock secret), never the secret itself nor a bare sha256 of it;
  * ``origin_secret_commitment`` is deterministic (differs per secret / epoch / host; a keyed PRF, not a bare
    sha256 of plaintext, and not the secret);
  * FAIL-CLOSED: no owner key, a bad origin, or a publish/read-back fault leaves NOTHING bound — a grant refusal
    publishes nothing; a publish fault REVERTS, unpublishing BOTH files data-plane-first and fault-tolerantly
    (even a fault DURING the revert cannot strand a cross-checking grant+binding pair), so no bound-but-
    unverifiable grant;
  * the status read is fail-closed (a deleted/forged binding file reads UNBOUND) and derived from the published
    artifacts the defence verifies;
  * the UNBOUND grant path is unchanged (origin=None — the AS-2f byte-identity seam);
  * determinism: identical inputs produce byte-identical published binding bytes + digest;
  * FATAL-2: the module imports no `framework.*` / `strix.*`.
"""
from __future__ import annotations

import itertools
import os
import tempfile
from pathlib import Path

import pytest

_iss = itertools.count(1000)
_SECRET = b"origin-lock-secret-ABCDEFGHIJKLMNOP"


def _pubdir(reg) -> Path:
    return Path(reg.publish_dir())


@pytest.fixture(autouse=True)
def _iso(monkeypatch):
    monkeypatch.setenv("VIGIL_BASE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_SPINE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_HOME", tempfile.mkdtemp())
    monkeypatch.setenv("VIGIL_MONITORING_PUBLISH_DIR", os.path.join(tempfile.mkdtemp(), "pub"))


def _store():
    from sigil.governor.identity import ensure_owner_keypair
    from sigil.spine.store import SpineStore
    ensure_owner_keypair()
    return SpineStore(os.path.join(tempfile.mkdtemp(), "spine.jsonl"))


def _prove(store, org, host, *, ttl=1e9):
    from sigil.governor.asset_ownership import METHOD_DNS_TXT, AssetOwnershipRegistry
    reg = AssetOwnershipRegistry(store)
    ch = reg.issue_challenge(org, host, issued_at=float(next(_iss)))
    reg.verify_and_record(org, host, method=METHOD_DNS_TXT, observed=[ch.marker], now=float(next(_iss)),
                          ttl_seconds=ttl)


def _owner_root():
    from sigil.governor.identity import owner_keypair
    from vigil_core import AuthorizerKey, TrustRoot
    return TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="owner", name="owner", public_key_b64=owner_keypair().public_key_b64)])


def _reg(store, *, owner=object()):
    from sigil.governor.monitoring_authority_v2 import MonitoringAuthorityV2Registry
    if owner is None:
        return MonitoringAuthorityV2Registry(store, owner_key=None)
    return MonitoringAuthorityV2Registry(store)


def _commit(org, host, epoch):
    from sigil.governor import monitoring_binding as mb
    return mb.origin_secret_commitment(org, host, epoch, _SECRET)


def _bind(reg, org, host, *, now=5000.0, issued=5000.0, root=None, origin_host="origin.example.com",
          origin_port=443, edge_chain="shared_actor", commit=None):
    from vigil_core import MonitoringCapability
    from sigil.governor import monitoring_binding as mb
    return mb.bind_and_publish(
        reg, org, host, origin_host=origin_host, origin_port=origin_port, edge_chain=edge_chain,
        origin_secret_sha256=commit if commit is not None else _commit(org, host, 1),
        capabilities=[MonitoringCapability.OBSERVE], not_before=now, not_after=now + 1000.0,
        lease_not_before=now, lease_not_after=now + 200.0, instance_id="i1", now=now, issued_at=issued,
        binding_issued_at=issued, trust_root=root or _owner_root())


# --- positive bind + cross-check ----------------------------------------------------------------------
def test_bind_and_publish_produces_a_bound_grant_that_cross_checks():
    from vigil_core import SignedAegisOriginBinding, SignedMonitoringAuthorityV2, grant_binds_origin
    from sigil.governor import monitoring_binding as mb
    s = _store()
    _prove(s, "org_a", "api.example.com")
    reg, root = _reg(s), _owner_root()
    res = _bind(reg, "org_a", "api.example.com", root=root)
    assert res["bound"] is True and res["epoch"] == 1 and res["origin_host"] == "origin.example.com"
    # the PUBLISHED grant + binding (what the data plane reads) cross-check under the owner root
    pub = _pubdir(reg)
    sg = SignedMonitoringAuthorityV2.model_validate_json((pub / res["grant_published"]).read_text())
    sb = SignedAegisOriginBinding.model_validate_json((pub / res["binding_published"]).read_text())
    ok, reason = grant_binds_origin(sg.document, sb, root)
    assert ok and reason == "bound"
    # and the status read agrees (read from the same published files)
    st = mb.binding_status(reg, "org_a", "api.example.com", now=5100.0, trust_root=root)
    assert st["bound"] is True and st["active"] is True and st["origin_host"] == "origin.example.com"
    ov = mb.bindings_overview(reg, "org_a", now=5100.0, trust_root=root)
    assert [r["host"] for r in ov] == ["api.example.com"] and ov[0]["bound"] is True


def test_published_binding_carries_no_plaintext_secret():
    s = _store()
    _prove(s, "org_a", "api.example.com")
    reg = _reg(s)
    res = _bind(reg, "org_a", "api.example.com")
    for name in (res["grant_published"], res["binding_published"]):
        data = (_pubdir(reg) / name).read_text()
        assert _SECRET.decode() not in data and "origin-lock-secret" not in data
    # the PUBLISHED commitment (origin_secret_sha256) is a keyed PRF over the secret — not the raw secret and not
    # a bare sha256 of plaintext. (binding_sha256 is the whole-document digest, a different value; assert over the
    # actual published commitment so weakening it toward sha256(plaintext) would fail HERE.)
    import hashlib
    commitment = res["binding"]["document"]["origin_secret_sha256"]
    assert commitment != hashlib.sha256(_SECRET).hexdigest() and _SECRET.hex() not in commitment


def test_origin_secret_commitment_is_deterministic_and_hides_the_secret():
    from sigil.governor import monitoring_binding as mb
    c1 = mb.origin_secret_commitment("org_a", "api.example.com", 1, _SECRET)
    c2 = mb.origin_secret_commitment("org_a", "api.example.com", 1, _SECRET)
    assert c1 == c2 and len(c1) == 64                                  # deterministic (no RNG)
    import hashlib
    assert c1 != hashlib.sha256(_SECRET).hexdigest()                  # a keyed PRF, not a bare hash of plaintext
    # a different epoch / secret / host => a different commitment (domain + content binding)
    assert mb.origin_secret_commitment("org_a", "api.example.com", 2, _SECRET) != c1
    assert mb.origin_secret_commitment("org_a", "api.example.com", 1, _SECRET + b"x") != c1
    assert mb.origin_secret_commitment("org_b", "api.example.com", 1, _SECRET) != c1


# --- fail-closed --------------------------------------------------------------------------------------
def test_bind_without_the_owner_key_is_refused_and_publishes_nothing():
    s = _store()
    _prove(s, "org_a", "api.example.com")
    reg = _reg(s, owner=None)
    with pytest.raises(ValueError):
        _bind(reg, "org_a", "api.example.com")
    assert not list(_pubdir(reg).glob("*.json"))


def test_a_bad_origin_publishes_nothing():
    s = _store()
    _prove(s, "org_a", "api.example.com")
    reg = _reg(s)
    with pytest.raises(ValueError):
        _bind(reg, "org_a", "api.example.com", origin_host="169.254.169.254")     # IP literal refused
    # no binding and no grant were left on disk
    assert not list(_pubdir(reg).glob("*.binding.json"))
    from sigil.governor import monitoring_binding as mb
    st = mb.binding_status(reg, "org_a", "api.example.com", now=5100.0, trust_root=_owner_root())
    assert st["bound"] is False


def test_bind_without_proven_ownership_publishes_no_grant():
    # the ownership proof is the grant's precondition; the binding is published first, so a grant refusal must
    # unpublish the orphan binding (fail-closed: no dangling binding without a grant).
    s = _store()                           # NO _prove -> grant() refuses (no current ownership proof)
    reg = _reg(s)
    with pytest.raises(ValueError):
        _bind(reg, "org_a", "api.example.com")
    assert not list(_pubdir(reg).glob("*.binding.json")) and not list(_pubdir(reg).glob("*.json"))


def test_a_publish_fault_reverts_both_the_grant_and_the_binding(monkeypatch):
    from sigil.governor import monitoring_binding as mb
    s = _store()
    _prove(s, "org_a", "api.example.com")
    reg, root = _reg(s), _owner_root()
    # make the binding read-back fault AFTER the grant + binding are published
    monkeypatch.setattr(mb, "read_back_binding", lambda *a, **k: (_ for _ in ()).throw(ValueError("boom")))
    with pytest.raises(ValueError):
        _bind(reg, "org_a", "api.example.com", root=root)
    # the grant is revoked (no active grant) and BOTH published files are gone — nothing bound survived
    assert reg.grant_for("org_a", "api.example.com") is None
    assert not list(_pubdir(reg).glob("*.binding.json"))
    st = mb.binding_status(reg, "org_a", "api.example.com", now=5100.0, trust_root=root)
    assert st["bound"] is False


def test_a_fault_during_the_revert_still_unpublishes_both_files(monkeypatch):
    # Correlated fault: the publish path faults AND a revert step faults too (a disk/IO condition can hit both).
    # The two data-plane-arming PUBLISHED files (grant + binding) must STILL both come down — grant_binds_origin
    # cross-checks the published files and never consults the spine revocation, so a revert ordered revoke-first
    # and unguarded would strand a cross-checking (bound) pair visible to the keyless plane while the op reports
    # failure (fail-open). Regression for: revert is data-plane-first + each step independently guarded.
    from sigil.governor import monitoring_binding as mb
    s = _store()
    _prove(s, "org_a", "api.example.com")
    reg, root = _reg(s), _owner_root()
    # fault the main try AFTER both files are published...
    monkeypatch.setattr(mb, "read_back_binding", lambda *a, **k: (_ for _ in ()).throw(ValueError("boom")))
    # ...and fault the spine revoke DURING the revert (the step that, if run first + unguarded, strands the files)
    monkeypatch.setattr(reg, "revoke",
                        lambda *a, **k: (_ for _ in ()).throw(OSError("spine append failed during revert")))
    with pytest.raises(ValueError):                                   # the original publish fault is still surfaced
        _bind(reg, "org_a", "api.example.com", root=root)
    # despite the revoke fault, BOTH published files are gone -> the keyless plane cannot arm this grant
    assert not list(_pubdir(reg).glob("*.binding.json"))             # binding file came down
    st = mb.binding_status(reg, "org_a", "api.example.com", now=5100.0, trust_root=root)
    assert st["bound"] is False and st["reason"] == "grant-file-unreadable"   # grant file came down too


def test_binding_status_fails_closed_when_the_published_binding_is_removed():
    from sigil.governor import monitoring_binding as mb
    s = _store()
    _prove(s, "org_a", "api.example.com")
    reg, root = _reg(s), _owner_root()
    _bind(reg, "org_a", "api.example.com", root=root)
    assert mb.binding_status(reg, "org_a", "api.example.com", now=5100.0, trust_root=root)["bound"] is True
    mb.unpublish_binding(reg, "org_a", "api.example.com")              # the defence would no longer read it
    st = mb.binding_status(reg, "org_a", "api.example.com", now=5100.0, trust_root=root)
    assert st["bound"] is False and st["reason"] == "binding-file-unreadable"


# --- determinism + the unbound seam -------------------------------------------------------------------
def test_bind_is_deterministic_across_independent_rigs():
    outs = []
    for _ in range(2):
        s = _store()
        _prove(s, "org_a", "api.example.com")
        reg = _reg(s)
        res = _bind(reg, "org_a", "api.example.com", commit="d" * 64)
        outs.append((res["binding_sha256"], (_pubdir(reg) / res["binding_published"]).read_bytes()))
    assert outs[0][0] == outs[1][0] and outs[0][1] == outs[1][1]      # identical digest + bytes


def test_the_unbound_grant_path_is_unchanged_origin_is_none():
    from vigil_core import MonitoringCapability
    s = _store()
    _prove(s, "org_a", "api.example.com")
    reg = _reg(s)
    _view, signed = reg.grant("org_a", "api.example.com", capabilities=[MonitoringCapability.OBSERVE],
                              not_before=5000.0, not_after=6000.0, lease_not_before=5000.0,
                              lease_not_after=5200.0, instance_id="i1", now=5000.0, issued_at=5000.0)
    assert signed.document.origin is None and signed.document.origin_binding_sha256 is None


def test_fatal2_module_imports_no_framework_or_offense():
    import subprocess
    import sys
    code = ("import sys; import sigil.governor.monitoring_binding as m; "
            "bad=[k for k in sys.modules if k=='framework' or k.startswith('framework.') or k.startswith('strix')]; "
            "assert not bad, bad; print('ok')")
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert r.returncode == 0 and r.stdout.strip() == "ok", (r.stdout, r.stderr)


# =====================================================================================================================
# The bind+publish FLOW through the Provisioner + the custui read surface (AS-2g UI hot-set)
# =====================================================================================================================
def _prov(monkeypatch):
    monkeypatch.setenv("VIGIL_CUSTOMER_MONITORING_ENABLED", "1")
    monkeypatch.setenv("VIGIL_AEGIS_SOVEREIGN_V2", "1")
    monkeypatch.delenv("VIGIL_CUSTOMER_STEPUP_REQUIRED", raising=False)
    from sigil.governor.customers import CustomerRegistry
    from sigil.governor.identity import ensure_owner_keypair
    from sigil.governor.monitoring_subscription import MonitoringSubscriptionRegistry
    from sigil.governor.orgs import OrgRegistry
    from sigil.governor.wallet import WalletRegistry
    from sigil.spine.store import SpineStore
    from sigil.ui.email_channel import EmailTokenLedger, NullEmailSender
    from sigil.ui.login_ratelimit import LoginRateLimiter
    from sigil.ui.provision import Provisioner
    ensure_owner_keypair()
    s = SpineStore(os.path.join(tempfile.mkdtemp(), "spine.jsonl"))
    orgs = OrgRegistry(s)
    p = Provisioner(s, customers=CustomerRegistry(s), orgs=orgs, wallet=WalletRegistry(s),
                    email_tokens=EmailTokenLedger(tempfile.mkdtemp(), ttl_s=1e4),
                    rate_limiter=LoginRateLimiter(tempfile.mkdtemp(), max_fails=1000, window_s=1e4, base_lock_s=1.0),
                    email_sender=NullEmailSender(), now_fn=lambda: float(next(_iss)))
    if orgs.org("org_a") is None:
        orgs.create_org("org_a", "org_a", owner="alice", issued_at=float(next(_iss)))
    orgs.grant_membership("org_a", "alice", "org_admin", issued_at=float(next(_iss)))
    _prove(s, "org_a", "apme.cm")
    MonitoringSubscriptionRegistry(s).subscribe("org_a", "aegis_respond_5h", 0, period_start=0.0,
                                                period_end=1e12, issued_at=float(next(_iss)))
    return p, s


def test_provisioner_binds_publishes_and_surfaces_on_monitor_list(monkeypatch):
    p, s = _prov(monkeypatch)
    commit = _commit("org_a", "apme.cm", 1)
    r = p.monitor_authorize_v2("alice", "org_a", "apme.cm", origin_host="origin.example.com",
                               origin_secret_sha256=commit, now=5000.0)
    assert r["bound"] is True and r["origin_host"] == "origin.example.com" and r["epoch"] == 1
    assert "binding_sha256_prefix" in r and len(r["binding_sha256_prefix"]) == 12
    # the v1 monitor_list read, which the Monitoring page uses, now carries the v2 binding status
    lst = p.monitor_list("alice", "org_a", now=5100.0)
    binds = {b["host"]: b for b in lst.get("bindings", [])}
    assert binds["apme.cm"]["bound"] is True and binds["apme.cm"]["origin_host"] == "origin.example.com"
    # and the dedicated sovereign read agrees
    bl = p.monitor_binding_list("alice", "org_a", now=5100.0)
    assert bl["enabled"] is True and bl["bindings"][0]["bound"] is True


def test_provisioner_bind_without_the_commitment_is_refused(monkeypatch):
    from sigil.ui.provision import ProvisionDenied
    p, s = _prov(monkeypatch)
    with pytest.raises(ProvisionDenied):
        p.monitor_authorize_v2("alice", "org_a", "apme.cm", origin_host="origin.example.com", now=5000.0)
    # nothing was bound: no active grant was left published
    from sigil.governor.monitoring_authority_v2 import MonitoringAuthorityV2Registry
    assert MonitoringAuthorityV2Registry(s, owner_key=None).grant_for("org_a", "apme.cm") is None


def test_provisioner_unbound_authorize_still_has_no_origin(monkeypatch):
    from vigil_core.authority_v2 import SignedMonitoringAuthorityV2
    from sigil import config
    p, s = _prov(monkeypatch)
    r = p.monitor_authorize_v2("alice", "org_a", "apme.cm", now=5000.0)   # no origin -> unbound (AS-2f seam)
    assert r.get("bound") is None
    signed = SignedMonitoringAuthorityV2.model_validate_json(
        (config.monitoring_v2_publish_dir() / r["published"]).read_text())
    assert signed.document.origin is None and signed.document.origin_binding_sha256 is None


def test_monitor_list_has_no_bindings_key_when_v2_is_off(monkeypatch):
    p, s = _prov(monkeypatch)
    monkeypatch.delenv("VIGIL_AEGIS_SOVEREIGN_V2")        # v2 surface off -> the page renders no binding section
    assert "bindings" not in p.monitor_list("alice", "org_a", now=5100.0)
