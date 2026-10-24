"""
Governed-engage ACCESS-CONTROL re-drive seam (idor / bola / bfla / mass_assignment).

Mirrors test_engine_runtime_redrive_seam.py: (A) ROUTING — engine._redrive_spec emits a
{"kind": "access_control", ...} spec for the class + its aliases; (B) the TRUSTED-CHANNEL LOCK —
_with_trusted_access_control_material UNCONDITIONALLY strips any producer-supplied identity material, so a
model-authored discriminator/headers can never reach the arm and, with no feeder wired, the seam returns None
(LEAD); (C) a LIVE POSITIVE over a real two-identity loopback server where the attacker reaches the victim's
ref-independent unique discriminator (absent from a same-shape unauthorized-authenticated peer, from the
attacker's own control object, and from the logged-out baseline) => a signed idor FACT; (D) the decisive
NEGATIVES (correctly-gated 403; same-shape reflection; public datum; missing attacker; missing unauth
baseline; out-of-scope refusal; mass_assignment with no 0.3 write approval => INCONCLUSIVE, never a FACT);
(E) the FEEDER is fail-closed by default.
"""

from __future__ import annotations

import http.server
import threading
import types
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable here")


def _decision(bug_class: str, *, url: str) -> types.SimpleNamespace:
    analysis = types.SimpleNamespace(exploit_succeeded=True, extracted_info={"bug_class": bug_class})
    tool = types.SimpleNamespace(tool_args={"url": url})
    return types.SimpleNamespace(tool=tool, output_analysis=analysis)


# ---------------------------------------------------------------------------------------------------
# (A) routing — engine._redrive_spec emits an access_control spec for the class + its aliases
# ---------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("claimed,norm", [
    ("idor", "idor"), ("insecure_direct_object_reference", "idor"),
    ("bola", "bola"), ("broken_object_level_authorization", "bola"),
    ("bfla", "bfla"), ("broken_function_level_authorization", "bfla"),
    ("mass_assignment", "mass_assignment"),
])
def test_redrive_spec_emits_an_access_control_spec(claimed, norm):
    from vigil_integration.live.engine import VigilEngine
    spec = VigilEngine._redrive_spec(
        _decision(claimed, url="http://127.0.0.1:19010/api/records?id=1"), None)
    assert spec is not None, f"{claimed} should be re-drivable through the access-control seam"
    assert spec["kind"] == "access_control"
    assert spec["bug_class"] == norm
    assert spec["url"].endswith("/api/records?id=1")


def test_redrive_spec_access_control_emits_no_identity_material():
    """The router's ONLY inputs are LLM-derived, so it emits class + url ONLY (the triple-lock). No identity
    headers / discriminator / cross-specs ever ride the spec from the model."""
    from vigil_integration.live.engine import VigilEngine
    spec = VigilEngine._redrive_spec(_decision("idor", url="http://127.0.0.1:19010/x?id=1"), None)
    assert spec is not None
    for forbidden in ("victim_headers", "attacker_headers", "unauth_headers", "cross_specs",
                      "access_control_material", "victim_discriminator", "mutating_send"):
        assert forbidden not in spec, f"the router must NEVER source {forbidden!r} from the model"


# ---------------------------------------------------------------------------------------------------
# shared isolation + provisioning + a two-identity loopback server
# ---------------------------------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def _isolate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from framework.v2.common import paths
    monkeypatch.setattr(paths, "killswitch_path", lambda slug: tmp_path / f"{slug}.halt")
    monkeypatch.setattr(paths, "target_dir", lambda slug: tmp_path / slug)
    monkeypatch.setattr(paths, "charter_path", lambda slug: tmp_path / slug / "charter.md")


def _grant_active_recon(monkeypatch: pytest.MonkeyPatch) -> None:
    from framework.v2 import entitlement
    monkeypatch.setattr(entitlement, "require_capability", lambda cap: None)


def _charter(tmp_path: Path, host: str, slug: str = "alpha") -> None:
    d = tmp_path / slug
    d.mkdir(parents=True, exist_ok=True)
    (d / "charter.md").write_text(
        f"# Engagement charter — `{slug}`\n\n**Status:** Final\n\n## 1. Operator attestation\n\n"
        f"Signed: `tester`     Date: `2026-05-04`\n\n## 2. In-scope systems\n\n"
        f"| Host | Notes | Auth |\n|---|---|---|\n| `{host}` | Host | Yes |\n\n"
        f"## 7. Posture\n\n- [x] **TEST**\n", encoding="utf-8")


def _prov(slug: str = "alpha"):
    from vigil_core import AuthorizerKey, TrustRoot, generate_keypair
    from vigil_integration.live.wiring import Provisioned
    kp = generate_keypair()
    tr = TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="gov0", name="gov0", public_key_b64=kp.public_key_b64)])
    return Provisioned(keypair=kp, trust_root=tr, signers=[("gov0", kp.private_key_b64)],
                       authority_path="", slug=slug)


# The victim's REF-INDEPENDENT UNIQUE discriminator — a datum that only bob's authoritative record carries.
_VICTIM_SECRET = "SECRET-BOB-INVOICE-#2-total=$9001-acct=bob@example.test"
_VICTIM_REF = "2"        # bob's object
_ATTACKER_OWN_REF = "1"  # the attacker's OWN object (control)
_SHELL = "<html><nav>Home</nav>{body}<footer>Acme</footer></html>"


def _who(handler: http.server.BaseHTTPRequestHandler) -> str:
    return (handler.headers.get("X-Id") or "").strip().lower()


def _rid(handler: http.server.BaseHTTPRequestHandler) -> str:
    return (parse_qs(urlsplit(handler.path).query).get("id") or [""])[0]


class _AcVulnApp(http.server.BaseHTTPRequestHandler):
    """VULNERABLE IDOR. Four identities keyed on the X-Id header:
      * victim   — the owner: id=2 serves the authoritative record carrying the discriminator;
      * attacker — a DISTINCT user: id=2 (bob's ref) VULNERABLY serves the discriminator; id=1 (own) omits it;
      * unauth   — a THIRD unauthorized-authenticated principal: id=2 renders a SAME-SHAPE 200 WITHOUT it;
      * nobody   — logged out (no X-Id): 403, the discriminator is never served (authorization-gated)."""

    def do_GET(self):  # noqa: N802
        who, rid = _who(self), _rid(self)
        if who == "victim":
            return self._send(200, _VICTIM_SECRET)
        if who == "attacker":
            if rid == _VICTIM_REF:
                return self._send(200, _SHELL.format(body=_VICTIM_SECRET))
            return self._send(200, _SHELL.format(body="alice-own-account-0001"))
        if who == "unauth":
            return self._send(200, _SHELL.format(body="record #2 owner=bob body=(restricted)"))
        return self._send(403, _SHELL.format(body="login required"))

    def _send(self, code: int, body: str):
        raw = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *a):  # silence
        return


class _AcGatedApp(_AcVulnApp):
    """CORRECTLY ACCESS-CONTROLLED: the attacker's cross-read of bob's ref is DENIED (403, no discriminator)."""

    def do_GET(self):  # noqa: N802
        who, rid = _who(self), _rid(self)
        if who == "victim":
            return self._send(200, _VICTIM_SECRET)
        if who == "attacker" and rid == _VICTIM_REF:
            return self._send(403, _SHELL.format(body="forbidden"))
        if who == "attacker":
            return self._send(200, _SHELL.format(body="alice-own-account-0001"))
        if who == "unauth":
            return self._send(200, _SHELL.format(body="record #2 owner=bob body=(restricted)"))
        return self._send(403, _SHELL.format(body="login required"))


class _AcReflectApp(_AcVulnApp):
    """SAME-SHAPE REFLECTION: the unauthorized-authenticated peer render ALSO carries the 'discriminator', so
    it is a reflected per-object token, not private content — the absence-from-unauth clause fails => LEAD."""

    def do_GET(self):  # noqa: N802
        who = _who(self)
        if who == "victim":
            return self._send(200, _VICTIM_SECRET)
        if who == "attacker":
            return self._send(200, _SHELL.format(body=_VICTIM_SECRET))
        if who == "unauth":
            return self._send(200, _SHELL.format(body=_VICTIM_SECRET))   # reflected into the peer render too
        return self._send(403, _SHELL.format(body="login required"))


class _AcPublicApp(_AcVulnApp):
    """PUBLIC datum: the logged-out baseline ALSO serves the discriminator, so it is not authorization-gated
    private content — the round-2 gating clause fails => LEAD."""

    def do_GET(self):  # noqa: N802
        who = _who(self)
        if who == "victim":
            return self._send(200, _VICTIM_SECRET)
        if who == "attacker":
            return self._send(200, _SHELL.format(body=_VICTIM_SECRET))
        if who == "unauth":
            return self._send(200, _SHELL.format(body="record #2 owner=bob body=(restricted)"))
        return self._send(200, _SHELL.format(body=_VICTIM_SECRET))       # logged-out serves it too => PUBLIC


def _serve(handler):
    srv = http.server.HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _spec(url: str, bug_class: str, *, victim=True, attacker=True, unauth=True,
          mass_assignment=None, mutating_send=None) -> dict:
    from framework.v2.scanner.access_control import CrossAccessSpec
    cross_specs = ()
    if bug_class in ("idor", "bola", "bfla"):
        cross_specs = (CrossAccessSpec(bug_class=bug_class, ref_param="id", victim_ref=_VICTIM_REF,
                                       victim_discriminator=_VICTIM_SECRET, control_ref=_ATTACKER_OWN_REF),)
    material = {
        "victim_headers": (("X-Id", "victim"),) if victim else (),
        "attacker_headers": (("X-Id", "attacker"),) if attacker else (),
        "unauth_headers": (("X-Id", "unauth"),) if unauth else (),
        "cross_specs": cross_specs,
        "mass_assignment": mass_assignment,
        "mutating_send": mutating_send,
    }
    return {"kind": "access_control", "url": url, "bug_class": bug_class, "access_control_material": material}


def _drive(monkeypatch, tmp_path, handler, bug_class: str, *, scope_host="127.0.0.1", **kw):
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, scope_host)
    from vigil_integration.live.wiring import _live_access_control_redrive_fact
    srv = _serve(handler)
    port = srv.server_address[1]
    try:
        spec = _spec(f"http://127.0.0.1:{port}/obj", bug_class, **kw)
        return _live_access_control_redrive_fact(_prov(), {}, spec)
    finally:
        srv.shutdown()


# ---------------------------------------------------------------------------------------------------
# (C) live positive
# ---------------------------------------------------------------------------------------------------
def test_live_seam_mints_an_idor_fact(monkeypatch, tmp_path):
    ref = _drive(monkeypatch, tmp_path, _AcVulnApp, "idor")
    assert ref, "a two-identity cross-read reaching the victim-unique discriminator must mint a signed FACT"


def test_live_seam_mints_a_bola_fact(monkeypatch, tmp_path):
    ref = _drive(monkeypatch, tmp_path, _AcVulnApp, "bola")
    assert ref, "the same achieved cross-read, claimed as bola, must mint a signed bola FACT"


def test_live_idor_fact_reverifies_offline(monkeypatch, tmp_path):
    """The minted FACT re-verifies OFFLINE from the retained oracle_context (no network, no runner)."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from framework.v2.evidence.certify import verify_certificate
    from vigil_integration.live.access_control_redrive import access_control_redrive
    from framework.v2.scanner.access_control import CrossAccessSpec
    from vigil_core import AuthorizerKey, TrustRoot, generate_keypair
    kp = generate_keypair()
    tr = TrustRoot(threshold=1, authorizers=[AuthorizerKey(key_id="gov0", name="gov0",
                                                           public_key_b64=kp.public_key_b64)])
    signers = [("gov0", kp.private_key_b64)]
    srv = _serve(_AcVulnApp); port = srv.server_address[1]
    try:
        rr = access_control_redrive(
            f"http://127.0.0.1:{port}/obj", slug="alpha", engagement_slug="alpha", signers=signers,
            cross_specs=(CrossAccessSpec(bug_class="idor", ref_param="id", victim_ref=_VICTIM_REF,
                                         victim_discriminator=_VICTIM_SECRET, control_ref=_ATTACKER_OWN_REF),),
            victim_headers=(("X-Id", "victim"),), attacker_headers=(("X-Id", "attacker"),),
            unauth_headers=(("X-Id", "unauth"),))
    finally:
        srv.shutdown()
    assert rr.family_verdict("idor") == "FACT"
    f = rr.facts[0]
    ctx = rr.contexts[f.finding_ref]
    assert verify_certificate(f.signed, oracle_context=ctx, trust_root=tr).ok is True


# ---------------------------------------------------------------------------------------------------
# (B) the trusted-channel lock — a producer-supplied bundle is stripped; no feeder => LEAD
# ---------------------------------------------------------------------------------------------------
def test_producer_supplied_material_is_stripped_and_mints_nothing(monkeypatch, tmp_path):
    """DECISIVE: a MODEL/producer-authored identity bundle on the spec is UNCONDITIONALLY stripped by
    _with_trusted_access_control_material; with provider=None (no feeder) the seam then sees NO material and
    returns None (LEAD) even against the VULNERABLE server. A model-authored discriminator can NEVER mint."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from vigil_integration.live.wiring import (
        _live_access_control_redrive_fact, _with_trusted_access_control_material)
    srv = _serve(_AcVulnApp); port = srv.server_address[1]
    try:
        producer_spec = _spec(f"http://127.0.0.1:{port}/obj", "idor")   # carries access_control_material
        stripped = _with_trusted_access_control_material(producer_spec, None, {})
        assert "access_control_material" not in stripped, "producer material must be stripped unconditionally"
        for k in ("victim_headers", "attacker_headers", "unauth_headers", "cross_specs"):
            assert k not in stripped
        assert _live_access_control_redrive_fact(_prov(), {}, stripped) is None, (
            "with the producer bundle stripped and no trusted feeder, the seam must stay a LEAD")
    finally:
        srv.shutdown()


def test_seam_without_material_is_fail_closed(monkeypatch, tmp_path):
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from vigil_integration.live.wiring import _live_access_control_redrive_fact
    assert _live_access_control_redrive_fact(_prov(), {"bug_class": "idor"},
                                             {"kind": "access_control", "url": "http://127.0.0.1:1/obj",
                                              "bug_class": "idor"}) is None
    assert _live_access_control_redrive_fact(_prov(), {}, None) is None


# ---------------------------------------------------------------------------------------------------
# (D) the decisive negatives — a FACT must NOT mint
# ---------------------------------------------------------------------------------------------------
def test_negctl_correctly_gated_endpoint_mints_nothing(monkeypatch, tmp_path):
    assert _drive(monkeypatch, tmp_path, _AcGatedApp, "idor") is None, (
        "a 403 to the attacker's cross-read is correct access control — no FACT")


def test_negctl_same_shape_reflection_mints_nothing(monkeypatch, tmp_path):
    assert _drive(monkeypatch, tmp_path, _AcReflectApp, "idor") is None, (
        "a reflected per-object token that appears in the same-shape unauth peer render too must not mint")


def test_negctl_public_datum_mints_nothing(monkeypatch, tmp_path):
    assert _drive(monkeypatch, tmp_path, _AcPublicApp, "idor") is None, (
        "a datum present in the logged-out baseline is PUBLIC, not an access-control bug — no FACT")


def test_negctl_missing_attacker_identity_mints_nothing(monkeypatch, tmp_path):
    assert _drive(monkeypatch, tmp_path, _AcVulnApp, "idor", attacker=False) is None, (
        "without a DISTINCT attacker identity the cross-read collapses onto anonymous — a LEAD, never a FACT")


def test_negctl_missing_unauth_baseline_mints_nothing(monkeypatch, tmp_path):
    assert _drive(monkeypatch, tmp_path, _AcVulnApp, "idor", unauth=False) is None, (
        "without the unauthorized-authenticated same-shape baseline the cross-read downgrades to a LEAD")


def test_negctl_out_of_scope_target_is_refused(monkeypatch, tmp_path):
    assert _drive(monkeypatch, tmp_path, _AcVulnApp, "idor", scope_host="example.test") is None, (
        "an out-of-charter target is refused before any traffic — no FACT")


def test_negctl_mass_assignment_without_write_approval_is_inconclusive(monkeypatch, tmp_path):
    """mass_assignment with NO mutating_send (no 0.3 owner-signed per-action write approval): the write never
    happens => INCONCLUSIVE, never a FACT (and never a false CLEAN)."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from vigil_integration.live.wiring import _live_access_control_redrive_fact
    ma = types.SimpleNamespace(field="is_admin", readback_request=None)
    srv = _serve(_AcVulnApp); port = srv.server_address[1]
    try:
        spec = _spec(f"http://127.0.0.1:{port}/obj", "mass_assignment", mass_assignment=ma, mutating_send=None)
        ref = _live_access_control_redrive_fact(_prov(), {}, spec)
    finally:
        srv.shutdown()
    assert ref is None, "mass_assignment without the 0.3 write approval must be INCONCLUSIVE, never a FACT"


# ---------------------------------------------------------------------------------------------------
# (E) the feeder is fail-closed by default
# ---------------------------------------------------------------------------------------------------
def test_feeder_fail_closed_without_config():
    from vigil_integration.live.wiring import EngineConfig, _governed_access_control_material
    prov = _prov()
    # master switch off (default)
    assert _governed_access_control_material(prov, EngineConfig(slug="alpha")) is None
    # enabled but no material
    assert _governed_access_control_material(
        prov, EngineConfig(slug="alpha", access_control_enable=True)) is None
    # enabled with material but IDENTICAL victim==attacker (a self-read) => None
    same = {"victim_headers": (("X-Id", "a"),), "attacker_headers": (("X-Id", "a"),),
            "unauth_headers": (("X-Id", "u"),), "cross_specs": ("x",)}
    assert _governed_access_control_material(
        prov, EngineConfig(slug="alpha", access_control_enable=True, access_control_material=same)) is None
    # distinct identities but NO unauth baseline => None
    no_unauth = {"victim_headers": (("X-Id", "v"),), "attacker_headers": (("X-Id", "a"),),
                 "unauth_headers": (), "cross_specs": ("x",)}
    assert _governed_access_control_material(
        prov, EngineConfig(slug="alpha", access_control_enable=True, access_control_material=no_unauth)) is None
