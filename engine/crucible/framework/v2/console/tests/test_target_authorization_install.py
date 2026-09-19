"""Phase 1.c — the OFFENSE-side installer that closes the UI live-external loop.

The sovereign cockpit owner-signs an engagement authorization onto the seam; ``_install_target_authorization``
reads it back, VERIFIES it against the PINNED owner key, and materialises the charter + authority + owner
trust root this offense root needs so a remote engage passes ``_has_verified_authority``.

Boundary discipline: this test runs in the OFFENSE leg (framework present) and must NOT import ``sigil``
(the sovereign plane lives in a separate venv). It simulates exactly what the sovereign ceremony writes,
using ONLY the import-clean shared primitives the ceremony itself uses (``vigil_core.sign_engagement_authority``
+ the ``authorization_broker`` seam + the ``approval_broker`` owner pin) — the sovereign half is proven
separately in ``apps/sigil/tests/test_target_authorization.py``; the bundle FORMAT is the shared contract.

Locks: install -> gate passes; and the fail-CLOSED refusals — no bundle, no owner pin, a bundle not signed
by the pinned owner, a bad signature, an expired window, a tampered on-disk scope, and a CONFLICTING
pre-existing trust root (no silent downgrade).
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from framework.v2.console import actions
from vigil_core import (
    AuthorizerKey, EngagementAuthority, TargetEnvironment, TrustRoot, generate_keypair,
    sign_engagement_authority,
)
from vigil_integration.live.approval_broker import persist_authority
from vigil_integration.live.authorization_broker import write_authorization

# the console-canonical slug for host apme.cm (console._slugify + ceremony._slug_for both map apme.cm ->
# apme-cm). The SLUG (an id) and the SCOPE host (apme.cm) are deliberately distinct.
_SLUG = "apme-cm"


@pytest.fixture()
def env(tmp_path, monkeypatch):
    """A tmp crucible root (with the CLAUDE.md sentinel so crucible_root() resolves to it) + a tmp seam."""
    root = tmp_path / "cruc"
    (root / "framework" / "v2").mkdir(parents=True)
    (root / "CLAUDE.md").write_text("# crucible\n", encoding="utf-8")
    base = tmp_path / ".vigil-live"
    base.mkdir()
    monkeypatch.setenv("CRUCIBLE_ROOT", str(root))
    monkeypatch.setenv("VIGIL_BASE_DIR", str(base))
    return {"root": root, "base": str(base)}


def _doc(slug=_SLUG, host="apme.cm", *, not_before=None, not_after=None):
    ts = datetime.now(timezone.utc)
    return EngagementAuthority(
        engagement_slug=slug, environment=TargetEnvironment.STAGING, scope=[host],
        not_before=not_before or (ts - timedelta(minutes=1)),
        not_after=not_after or (ts + timedelta(hours=8)), issued_by="owner",
    )


def _seed(base, *, owner=None, signer=None, root_owner=None, pin=True, doc=None):
    """Write an owner-signed bundle to the seam and (optionally) pin the owner pubkey. ``signer`` defaults
    to ``owner`` (the honest case); ``root_owner`` (the pubkey placed in the bundle's trust root) defaults
    to ``owner`` too. Vary them to build the adversarial cases."""
    owner = owner or generate_keypair()
    signer = signer or owner
    root_owner = root_owner or owner
    document = doc or _doc()
    tr = TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="owner", name="owner", public_key_b64=root_owner.public_key_b64)])
    signed = sign_engagement_authority(document, {"owner": signer.private_key_b64})
    write_authorization(base, document.engagement_slug, signed, tr)
    if pin:
        persist_authority(base, owner_key_id="owner", owner_public_key_b64=owner.public_key_b64)
    return owner


# --- the happy path: install -> gate passes -------------------------------------------------------
def test_install_then_verified_authority_gate_passes(env):
    from framework.v2.common import paths
    _seed(env["base"])
    root, reason = actions._install_target_authorization(_SLUG)
    assert reason == "installed" and root == str(paths.crucible_root()), (root, reason)
    # the gate now verifies (owner-signed authority against the just-installed owner trust root)
    assert actions._has_verified_authority(_SLUG) is True
    # material landed under the crucible root, and the charter carries the scope + a signed line
    assert paths.authority_path(_SLUG).is_file()
    assert paths.trust_root_path().is_file()
    charter = paths.charter_path(_SLUG).read_text(encoding="utf-8")
    assert "## 2. In-scope systems" in charter and "apme.cm" in charter and "Signed:" in charter


# --- fail-closed refusals -------------------------------------------------------------------------
def test_no_bundle_on_seam_refuses(env):
    root, reason = actions._install_target_authorization(_SLUG)
    assert root == "" and "no owner-signed authorization" in reason
    assert actions._has_verified_authority(_SLUG) is False


def test_no_owner_pin_refuses(env):
    _seed(env["base"], pin=False)             # bundle present, but no owner pinned out-of-band
    root, reason = actions._install_target_authorization(_SLUG)
    assert root == "" and "no pinned owner key" in reason
    assert actions._has_verified_authority(_SLUG) is False


def test_bundle_not_signed_by_pinned_owner_refuses(env):
    pinned_owner = generate_keypair()
    other = generate_keypair()
    # the bundle's trust root is OTHER's key, but the deployment pinned pinned_owner
    _seed(env["base"], owner=pinned_owner, signer=other, root_owner=other, pin=True)
    root, reason = actions._install_target_authorization(_SLUG)
    assert root == "" and "not (exactly) the pinned owner key" in reason
    assert actions._has_verified_authority(_SLUG) is False


def test_bad_signature_refuses(env):
    owner = generate_keypair()
    forger = generate_keypair()
    # trust root = owner (matches the pin), but the document was signed by a DIFFERENT key
    _seed(env["base"], owner=owner, signer=forger, root_owner=owner, pin=True)
    root, reason = actions._install_target_authorization(_SLUG)
    assert root == "" and "does not verify" in reason
    assert actions._has_verified_authority(_SLUG) is False


def test_expired_authorization_refuses(env):
    ts = datetime.now(timezone.utc)
    expired = _doc(not_before=ts - timedelta(hours=2), not_after=ts - timedelta(hours=1))  # valid window, past
    _seed(env["base"], doc=expired)
    root, reason = actions._install_target_authorization(_SLUG)
    assert root == "" and "expired" in reason
    assert actions._has_verified_authority(_SLUG) is False


def test_tampered_on_disk_scope_refuses(env):
    from vigil_integration.live.authorization_broker import authorization_path
    _seed(env["base"])
    p = authorization_path(env["base"], _SLUG)
    d = json.loads(p.read_text(encoding="utf-8"))
    d["signed_authority"]["document"]["scope"] = ["evil.example"]     # widen the scope after signing
    p.write_text(json.dumps(d), encoding="utf-8")
    root, reason = actions._install_target_authorization(_SLUG)
    assert root == "" and "does not verify" in reason
    assert actions._has_verified_authority(_SLUG) is False


def test_validly_signed_malformed_scope_entry_is_refused(env):
    """red-pen #8: a VALIDLY owner-signed authority whose scope carries a table-injection / non-bare-host
    entry must be refused at install (independent scope re-validation), not materialised verbatim into the
    charter table. The signature is genuine — the defense is content validation, not signature failure."""
    bad = _doc(host="apme.cm | evil.example")   # a pipe would inject a second charter row / widen parse_scope
    _seed(env["base"], doc=bad)
    root, reason = actions._install_target_authorization(_SLUG)
    assert root == "" and "not a bare host" in reason
    assert actions._has_verified_authority(_SLUG) is False


def test_not_yet_valid_authorization_refuses(env):
    """red-pen #2/#6: a future-dated (not_before) authority must not install (nor pass the gate)."""
    ts = datetime.now(timezone.utc)
    future = _doc(not_before=ts + timedelta(days=30), not_after=ts + timedelta(days=31))
    _seed(env["base"], doc=future)
    root, reason = actions._install_target_authorization(_SLUG)
    assert root == "" and "not yet valid" in reason
    assert actions._has_verified_authority(_SLUG) is False


def test_gate_rejects_a_verified_but_out_of_window_authority(env):
    """red-pen #1/#15: _has_verified_authority now also checks the validity window. Persist a genuine
    owner-signed authority + matching trust root DIRECTLY (bypassing install) but expired — the gate must
    return False even though the signature verifies."""
    from framework.v2.authority.store import save_signed_authority
    from framework.v2.entitlement.provision import write_trust_root
    owner = generate_keypair()
    ts = datetime.now(timezone.utc)
    expired = _doc(not_before=ts - timedelta(hours=2), not_after=ts - timedelta(hours=1))
    signed = sign_engagement_authority(expired, {"owner": owner.private_key_b64})
    write_trust_root(TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="owner", name="owner", public_key_b64=owner.public_key_b64)]))
    save_signed_authority(signed)
    assert actions._has_verified_authority(_SLUG) is False


def test_malformed_existing_trust_root_is_not_overwritten(env):
    """red-pen #3: a PRESENT-but-unreadable trust root is a hard conflict, not 'absent' — install must
    refuse rather than silently overwrite it."""
    from framework.v2.common import paths
    tp = paths.trust_root_path()
    tp.parent.mkdir(parents=True, exist_ok=True)
    tp.write_text("{ not valid json", encoding="utf-8")
    _seed(env["base"])
    root, reason = actions._install_target_authorization(_SLUG)
    assert root == "" and "unreadable" in reason


def test_conflicting_existing_trust_root_is_not_replaced(env):
    from framework.v2.entitlement.provision import write_trust_root
    # a DIFFERENT trust root is already provisioned on this deployment
    stranger = generate_keypair()
    write_trust_root(TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="owner", name="owner", public_key_b64=stranger.public_key_b64)]))
    _seed(env["base"])                        # a valid owner-signed bundle + owner pin (a DIFFERENT owner)
    root, reason = actions._install_target_authorization(_SLUG)
    assert root == "" and "different deployment trust root" in reason


def test_launch_refuses_a_target_host_outside_the_authorized_scope(env, monkeypatch, tmp_path):
    """red-pen #5: the console launch gate binds an authority to the SLUG; also confirm the TARGET HOST being
    scanned is within that authority's scope. An authority for slug apme.cm (scope [apme.cm]) must NOT launch
    a scan of a different host under the same slug — refused up-front, fail-closed, before any spawn."""
    monkeypatch.setattr(actions, "console_dir", lambda: tmp_path / ".console")
    monkeypatch.setattr(actions, "_spawn_background", lambda *a, **k: None)   # never reached on refusal
    _seed(env["base"])                        # owner-signed bundle for slug apme-cm, scope [apme.cm], pinned
    r = actions.launch_assessment({"mode": "url", "target": "https://evil.example/", "slug": _SLUG})
    assert "error" in r and "evil.example" in r["error"] and "covering the target host" in r["error"], r
    # the authorized host does NOT hit the scope refusal (it may proceed / hit later steps, but not THIS gate)
    r2 = actions.launch_assessment({"mode": "url", "target": "https://apme.cm/", "slug": _SLUG})
    assert "covering the target host" not in str(r2.get("error", "")), r2


def test_launch_hard_pins_the_child_crucible_root(env, monkeypatch, tmp_path):
    """red-pen #10: a console-launched remote engage hard-pins the child — it sets CRUCIBLE_ROOT (the root
    the charter/authority were written under) AND CRUCIBLE_ROOT_STRICT=1, so the child fails closed rather
    than silently resolving a FOREIGN root if the pinned root's sentinel is missing."""
    monkeypatch.setattr(actions, "console_dir", lambda: tmp_path / ".console")
    seen: dict = {}

    def _cap(run_id, rd, cmd, meta, *, capture_report, env_extra=None, env_remove=None):
        seen["env"] = dict(env_extra or {})

    monkeypatch.setattr(actions, "_spawn_background", _cap)
    _seed(env["base"])                        # owner-signed bundle for slug apme-cm, scope [apme.cm], pinned
    r = actions.launch_assessment({"mode": "url", "target": "https://apme.cm/", "slug": _SLUG})
    assert r.get("status") == "running", r
    assert seen["env"].get("CRUCIBLE_ROOT") and seen["env"].get("CRUCIBLE_ROOT_STRICT") == "1", seen
