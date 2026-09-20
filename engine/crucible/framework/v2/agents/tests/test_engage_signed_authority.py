"""W16-2 — the production ``engage`` path REQUIRES a signed EngagementAuthority.

The engage path used to build ``HttpExecutor(auto_load_authority=True)`` with NO
``trust_root``, so the executor's ``_authority_gate`` fail-closed branch (which fires only
when a trust root is pinned) never engaged: an UNSIGNED authority document was loaded via
``load_authority`` and its window / ``allow_destructive`` / ``live_destructive_acknowledged``
/ ``max_actions`` were TRUSTED without any signature check. The VIGIL plane
(``conjunctive_gate.build_offense_gate``) refuses exactly this — a ``None`` trust root loads
the CRUCIBLE authority UNSIGNED — so the two planes disagreed and CRUCIBLE was the weaker one.

These tests prove, end to end against a loopback ``pytest-httpserver`` (nothing leaves the
host), that when an authority is provisioned alongside a governance trust root the engage path
now PINS that trust root:

  * an UNSIGNED authority is REFUSED before any I/O (the fail-before/pass-after test — the
    NEGATIVE CONTROL is the same run's assertion that reverting the pin trusts the doc);
  * a TAMPERED signed authority is REFUSED;
  * a correctly-signed authority is ACCEPTED (the gate is not a blanket no-op);
  * greenfield (no authority provisioned) still runs;
  * all four governed fields are enforced on the engage-loaded authority;
  * CRUCIBLE and VIGIL load through the SAME verified loader, so they cannot diverge again.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from pytest_httpserver import HTTPServer
from werkzeug.wrappers import Response

from framework.v2 import engage as engage_mod
from framework.v2.authority.gate import authorize_action, load_authority_for_gate
from framework.v2.authority.models import (
    ActionRequest,
    EngagementAuthority,
    TargetEnvironment,
)
from framework.v2.authority.signing import sign_authority
from framework.v2.authority.store import (
    AuthorityError,
    load_verified_authority,
    save_authority,
    save_signed_authority,
)
from framework.v2.common import paths as _paths
from framework.v2.engage import (
    EngagementRefused,
    _engage_authority_trust_root,
    run_engagement,
)
from framework.v2.entitlement import provision

_CHARTER = """\
# Engagement charter — `{slug}`

**Status:** Final

## 1. Operator attestation

Signed: `tester`     Date: `2026-05-04`

## 2. In-scope systems

| Host / Surface | Notes | Auth |
|----------------|-------|------|
| `{host}` | Test app | Yes |

## 3. Out of scope

- Anything not listed above.

## 7. Posture

- [x] **TEST**
- [ ] **AUDIT**
- [ ] **EMULATE**
"""


@pytest.fixture()
def isolated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Isolate targets, the authority store, AND the governance trust root under a tmp
    root, so nothing touches the real deployment material."""
    targets_root = tmp_path / "targets"
    targets_root.mkdir()
    auth_dir = tmp_path / ".authority"
    auth_dir.mkdir()
    ent_dir = tmp_path / ".entitlement"
    ent_dir.mkdir()
    auth_root_dir = tmp_path / ".authority-root"
    auth_root_dir.mkdir()

    def build(slug: str, host: str) -> Path:
        td = targets_root / slug
        td.mkdir(parents=True, exist_ok=True)
        (td / "charter.md").write_text(_CHARTER.format(slug=slug, host=host), encoding="utf-8")
        return td

    monkeypatch.setattr(_paths, "target_dir", lambda s: targets_root / s)
    monkeypatch.setattr(_paths, "charter_path", lambda s: targets_root / s / "charter.md")
    monkeypatch.setattr(_paths, "killswitch_path", lambda s: auth_dir / f"{s}.halt")
    monkeypatch.setattr(_paths, "authority_path", lambda s: auth_dir / f"{s}.authority.json")
    monkeypatch.setattr(_paths, "trust_root_path", lambda: ent_dir / "trust-root.json")
    # Phase 0.1 decouple: the engage/authority gate now reads the authority root from the DEDICATED store,
    # not the entitlement trust root — isolate it here too so _engage_authority_trust_root finds it.
    monkeypatch.setattr(_paths, "authority_root_path", lambda: auth_root_dir / "trust-root.json")
    return build


def _deny(_q: str, _t: float) -> bool:
    return False


def _page(_request) -> Response:
    return Response("<html><body>ok</body></html>", status=200, mimetype="text/html")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _authority(host: str, *, env=TargetEnvironment.TWIN, allow_destructive=True,
               max_actions=10_000, not_before=None, not_after=None,
               live_ack=False) -> EngagementAuthority:
    return EngagementAuthority(
        engagement_slug="alpha",
        environment=env,
        scope=[host],
        not_before=not_before or (_now() - timedelta(hours=1)),
        not_after=not_after or (_now() + timedelta(hours=1)),
        allow_destructive=allow_destructive,
        live_destructive_acknowledged=live_ack,
        max_actions=max_actions,
    )


def _provision_trust_root():
    from framework.v2.authority.store import write_authority_root
    ak, priv = provision.new_authorizer("a0", "Authoriser 0")
    tr = provision.build_trust_root([ak], threshold=1)
    write_authority_root(tr)   # the engage/authority gate reads the DECOUPLED authority-root store (Phase 0.1)
    return tr, {"a0": priv}


# ---------------------------------------------------------------------------
# end-to-end engage path
# ---------------------------------------------------------------------------


def test_engage_refuses_unsigned_authority_when_trust_root_present(
    isolated, httpserver: HTTPServer,
):
    """FAIL-BEFORE / PASS-AFTER + NEGATIVE CONTROL.

    A governance trust root is provisioned and an UNSIGNED authority document is written that
    grants everything (destructive, a huge budget, the target in scope). With the W16-2 pin,
    the engage path loads the authority VERIFIED — an unsigned doc fails that load, the gate
    fails closed, and NOT ONE request reaches the server.

    Reverting only the engage-path pin (``trust_root=_engage_authority_trust_root(...)``)
    restores the old unsigned load: the doc is TRUSTED and the scan reaches the server — so
    ``len(httpserver.log) == 0`` flips to a non-empty log. That is the negative control that
    proves the pin, not some unrelated gate, is doing the work."""
    isolated("alpha", "127.0.0.1")
    httpserver.expect_request("/").respond_with_handler(_page)
    _provision_trust_root()
    # An attacker-writable UNSIGNED authority granting itself the world.
    save_authority(_authority("127.0.0.1", allow_destructive=True, max_actions=1_000_000))

    run_engagement(
        "alpha", f"http://127.0.0.1:{httpserver.port}/",
        max_pages=1, enable_oob=False, prompt_callback=_deny,
    )

    assert len(httpserver.log) == 0, (
        "unsigned authority was TRUSTED — a request reached the server; the engage path did "
        "not pin the governance trust root"
    )


def test_engage_refuses_tampered_signed_authority(isolated, httpserver: HTTPServer):
    """A validly-signed authority whose document is then tampered (scope widened, budget
    inflated) must fail the verified load and be refused before any I/O."""
    isolated("alpha", "127.0.0.1")
    httpserver.expect_request("/").respond_with_handler(_page)
    tr, privs = _provision_trust_root()
    signed = sign_authority(_authority("127.0.0.1"), {"a0": privs["a0"]})
    p = _paths.authority_path("alpha")
    save_signed_authority(signed, p)
    blob = json.loads(p.read_text(encoding="utf-8"))
    blob["document"]["scope"] = ["*"]
    blob["document"]["max_actions"] = 1_000_000
    p.write_text(json.dumps(blob), encoding="utf-8")

    run_engagement(
        "alpha", f"http://127.0.0.1:{httpserver.port}/",
        max_pages=1, enable_oob=False, prompt_callback=_deny,
    )

    assert len(httpserver.log) == 0, "tampered signed authority was trusted — a request leaked"


def test_engage_accepts_correctly_signed_authority(isolated, httpserver: HTTPServer):
    """NEGATIVE CONTROL for the refusals above: the pinned gate is NOT a blanket deny. A
    correctly-signed, in-window, in-scope authority is ACCEPTED and the scan reaches the
    server."""
    isolated("alpha", "127.0.0.1")
    httpserver.expect_request("/").respond_with_handler(_page)
    tr, privs = _provision_trust_root()
    signed = sign_authority(_authority("127.0.0.1"), {"a0": privs["a0"]})
    save_signed_authority(signed, _paths.authority_path("alpha"))

    run_engagement(
        "alpha", f"http://127.0.0.1:{httpserver.port}/",
        max_pages=1, enable_oob=False, prompt_callback=_deny,
    )

    assert len(httpserver.log) > 0, "a correctly-signed authority was refused — the gate is a no-op deny"


def test_engage_greenfield_no_authority_still_runs(isolated, httpserver: HTTPServer):
    """Greenfield: no authority document and no trust root provisioned. The documented
    kill-switch-only path is preserved and the scan runs normally."""
    isolated("alpha", "127.0.0.1")
    httpserver.expect_request("/").respond_with_handler(_page)
    # no _provision_trust_root(), no save_authority()

    assert _engage_authority_trust_root("alpha") is None

    run_engagement(
        "alpha", f"http://127.0.0.1:{httpserver.port}/",
        max_pages=1, enable_oob=False, prompt_callback=_deny,
    )

    assert len(httpserver.log) > 0, "greenfield engage was broken — no request reached the server"


# ---------------------------------------------------------------------------
# the resolver's discovery contract
# ---------------------------------------------------------------------------


def test_resolver_pins_trust_root_only_when_authority_provisioned(isolated):
    """The discovery contract: greenfield -> None; authority + trust root -> the trust root;
    authority provisioned but NO trust root -> EngagementRefused (an unpinned authority must
    never be applied unsigned)."""
    isolated("alpha", "127.0.0.1")

    # greenfield
    assert _engage_authority_trust_root("alpha") is None

    # authority provisioned, trust root discoverable -> pin it
    tr, privs = _provision_trust_root()
    save_signed_authority(
        sign_authority(_authority("127.0.0.1"), {"a0": privs["a0"]}),
        _paths.authority_path("alpha"),
    )
    resolved = _engage_authority_trust_root("alpha")
    assert resolved is not None
    assert resolved.threshold == tr.threshold

    # authority provisioned but NO trust root -> refuse (unpinned authority). Remove the DECOUPLED
    # authority root (what the engage gate reads), not the entitlement trust root (Phase 0.1).
    _paths.authority_root_path().unlink()
    with pytest.raises(EngagementRefused, match="trust root"):
        _engage_authority_trust_root("alpha")


# ---------------------------------------------------------------------------
# W16-2 (LOW): the autonomous DISCOVERY leg SURFACES the resolver's EngagementRefused
# (it used to be swallowed by the best-effort `except Exception` into a silent skip).
# ---------------------------------------------------------------------------


def test_autonomous_discover_surfaces_engagement_refused(isolated):
    """FAIL-BEFORE / PASS-AFTER for the LOW: with the resolver call moved OUTSIDE the discover
    leg's best-effort ``try``, an EngagementRefused (an authority IS provisioned but no governance
    trust root is discoverable to verify it) PROPAGATES out of ``_run_autonomous`` instead of being
    swallowed into ``discover_send = None``. The engage CLI turns it into a clean fail-closed
    refusal. Before the fix the resolver raised INSIDE the try and the refusal was silently hidden
    (``_run_autonomous`` returned normally)."""
    from types import SimpleNamespace

    from framework.v2.authority.store import save_authority
    from framework.v2.engage import _run_autonomous

    isolated("alpha", "127.0.0.1")
    # an authority IS provisioned (an unsigned doc is enough to exist on disk); NO trust root.
    save_authority(_authority("127.0.0.1"))
    assert not _paths.trust_root_path().exists()

    args = SimpleNamespace(slug="alpha", seed_url="http://127.0.0.1/",
                           autonomous_discover=True, autonomous_budget=8)
    with pytest.raises(EngagementRefused, match="trust root"):
        _run_autonomous(args, None, None)


def test_autonomous_discover_greenfield_does_not_raise(isolated):
    """NEGATIVE CONTROL: greenfield (no authority provisioned) resolves to a None pin, so the
    discovery leg does NOT raise EngagementRefused — the refusal is specific to a provisioned-but-
    unverifiable authority, never a blanket abort of the autonomous cycle."""
    from types import SimpleNamespace

    from framework.v2.engage import _run_autonomous

    isolated("alpha", "127.0.0.1")   # no authority, no trust root
    args = SimpleNamespace(slug="alpha", seed_url="http://127.0.0.1:1/",
                           autonomous_discover=True, autonomous_budget=8)
    # the best-effort cycle over a None result returns (an AutonomyResult or None) but never raises
    # the authorization refusal.
    _run_autonomous(args, None, None)


# ---------------------------------------------------------------------------
# all four governed fields, on the engage-loaded authority
# ---------------------------------------------------------------------------


def test_engage_loaded_authority_enforces_all_four_governed_fields(isolated):
    """Load the authority exactly as the engage path does (verified, via the pinned trust
    root) and prove each of the four governed fields is enforced by ``authorize_action`` — the
    same evaluator the executor's ``_authority_gate`` runs. A clean action is the positive
    control."""
    isolated("alpha", "127.0.0.1")
    tr, privs = _provision_trust_root()

    def _load(doc: EngagementAuthority) -> EngagementAuthority:
        save_signed_authority(sign_authority(doc, {"a0": privs["a0"]}),
                              _paths.authority_path("alpha"))
        # exactly the engage-path load: pin the resolved trust root, verified load.
        pinned = _engage_authority_trust_root("alpha")
        return load_verified_authority("alpha", pinned)

    req = ActionRequest(target="http://127.0.0.1/x", action_kind="exploit", destructive=False)
    dreq = ActionRequest(target="http://127.0.0.1/x", action_kind="exploit", destructive=True)

    # positive control: a clean, in-window, non-destructive action is allowed.
    ok = authorize_action(_load(_authority("127.0.0.1")), req)
    assert ok.allowed

    # 1. validity window
    expired = _load(_authority("127.0.0.1", not_before=_now() - timedelta(days=2),
                               not_after=_now() - timedelta(days=1)))
    assert not authorize_action(expired, req).allowed
    assert authorize_action(expired, req).denial_code == "expired"

    # 2. allow_destructive
    nodestruct = _load(_authority("127.0.0.1", allow_destructive=False))
    assert not authorize_action(nodestruct, dreq).allowed
    assert authorize_action(nodestruct, dreq).denial_code == "destructive"

    # 3. live_destructive_acknowledged
    live = _load(_authority("127.0.0.1", env=TargetEnvironment.LIVE,
                            allow_destructive=True, live_ack=False))
    assert not authorize_action(live, dreq).allowed
    assert authorize_action(live, dreq).denial_code == "live_destructive"

    # 4. max_actions
    budget = _load(_authority("127.0.0.1", max_actions=3))
    assert not authorize_action(budget, req, actions_taken=3).allowed
    assert authorize_action(budget, req, actions_taken=3).denial_code == "budget"


# ---------------------------------------------------------------------------
# cross-plane parity: CRUCIBLE and VIGIL cannot diverge again
# ---------------------------------------------------------------------------


def test_crucible_and_vigil_reach_the_same_verdict(isolated):
    """The two planes load through the SAME verified loader. VIGIL's
    ``conjunctive_gate.build_offense_gate`` calls ``load_authority_for_gate(slug,
    trust_root=tr)``; the CRUCIBLE engage path now pins the same trust root and calls
    ``load_verified_authority`` — which ``load_authority_for_gate`` delegates to for a non-None
    trust root. Prove they agree on both a signed doc (both load the identical document) and a
    tampered doc (both refuse)."""
    isolated("alpha", "127.0.0.1")
    tr, privs = _provision_trust_root()
    p = _paths.authority_path("alpha")

    # signed: both planes load the identical document.
    signed = sign_authority(_authority("127.0.0.1", max_actions=42), {"a0": privs["a0"]})
    save_signed_authority(signed, p)
    pinned = _engage_authority_trust_root("alpha")           # CRUCIBLE engage path
    crucible_doc = load_verified_authority("alpha", pinned)
    vigil_doc = load_authority_for_gate("alpha", trust_root=tr)  # VIGIL conjunctive gate
    assert crucible_doc.max_actions == vigil_doc.max_actions == 42
    assert crucible_doc.scope == vigil_doc.scope

    # tampered: both planes refuse.
    blob = json.loads(p.read_text(encoding="utf-8"))
    blob["document"]["max_actions"] = 999_999
    p.write_text(json.dumps(blob), encoding="utf-8")
    with pytest.raises(AuthorityError):
        load_verified_authority("alpha", pinned)
    with pytest.raises(AuthorityError):
        load_authority_for_gate("alpha", trust_root=tr)


# ---------------------------------------------------------------------------
# doc-truth: the V2-LIMITATIONS claim is mirrored from the code, so it can't drift
# ---------------------------------------------------------------------------


def test_v2_limitations_authority_claim_is_true_of_the_code():
    """The updated "Authority signing" entry in V2-LIMITATIONS.md claims the engage path
    PINS the trust root via ``_engage_authority_trust_root``. Derive that claim from the
    engine source so the doc cannot silently drift back to the fail-open: if the pin is
    removed from either executor construction, or the stale "not threshold-signed" wording
    returns, this fails."""
    v2_dir = Path(engage_mod.__file__).resolve().parent
    engage_src = (v2_dir / "engage.py").read_text(encoding="utf-8")
    limitations = (v2_dir.parents[1] / "V2-LIMITATIONS.md").read_text(encoding="utf-8")

    # the code the doc names must actually exist and be wired at BOTH executor sites.
    assert "def _engage_authority_trust_root(" in engage_src
    assert "trust_root=_engage_authority_trust_root(slug)" in engage_src         # scan path
    # discover path: the resolver is called for the discover slug OUTSIDE the best-effort try (so an
    # EngagementRefused surfaces, not swallowed — W16-2 LOW) and its result is pinned as trust_root.
    assert "discover_trust_root = _engage_authority_trust_root(args.slug)" in engage_src
    assert "trust_root=discover_trust_root" in engage_src

    # the doc must name the real function and must NOT still assert the authority is unsigned.
    assert "_engage_authority_trust_root" in limitations
    assert "not threshold-signed" not in limitations
