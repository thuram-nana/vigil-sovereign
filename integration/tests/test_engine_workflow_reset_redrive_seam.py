"""
Governed-engage WORKFLOW (request_race / business_logic) + PASSWORD-RESET (reuse / collision / cross_user)
re-drive seams.

Mirrors test_engine_runtime_redrive_seam.py / test_engine_access_control_redrive_seam.py:
 (A) ROUTING — engine._redrive_spec emits {"kind":"workflow",...} for request_race/business_logic and
     {"kind":"reset",...} for the password_reset_* classes, class+url ONLY (no material from the model);
 (B) the TRUSTED-CHANNEL LOCK — _with_trusted_{workflow,reset}_material UNCONDITIONALLY strips any producer-
     supplied material, so with no feeder the seam returns None (LEAD);
 (C) LIVE POSITIVES — the workflow seam mints a signed request_race FACT against the benchmark over-redeem
     fixture behind an OWNER-SIGNED WorkflowSpec; the reset seam mints a signed password_reset_cross_user FACT
     over a real two-identity loopback server;
 (D) DECISIVE NEGATIVES — an UNSIGNED WorkflowSpec mints nothing (owner_signed_spec False => INCONCLUSIVE);
     the benign locked twin does not fire; a correctly-gated reset cross-read mints nothing; and the feeders
     are fail-closed by default.
"""

from __future__ import annotations

import http.server
import threading
import types
import urllib.request
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable here")


def _decision(bug_class: str, *, url: str) -> types.SimpleNamespace:
    analysis = types.SimpleNamespace(exploit_succeeded=True, extracted_info={"bug_class": bug_class})
    tool = types.SimpleNamespace(tool_args={"url": url})
    return types.SimpleNamespace(tool=tool, output_analysis=analysis)


# ---------------------------------------------------------------------------------------------------
# (A) routing
# ---------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("claimed,kind", [
    ("request_race", "workflow"), ("business_logic", "workflow"),
    ("password_reset_reuse", "reset"), ("password_reset_collision", "reset"),
    ("password_reset_cross_user", "reset"),
])
def test_redrive_spec_emits_the_right_kind(claimed, kind):
    from vigil_integration.live.engine import VigilEngine
    spec = VigilEngine._redrive_spec(_decision(claimed, url="http://127.0.0.1:19010/x?id=1"), None)
    assert spec is not None, f"{claimed} should be re-drivable"
    assert spec["kind"] == kind
    assert spec["bug_class"] == claimed


@pytest.mark.parametrize("claimed", ["request_race", "password_reset_reuse"])
def test_redrive_spec_emits_no_material(claimed):
    """The router emits class + url ONLY (the triple-lock). No spec/signature/driver material from the model."""
    from vigil_integration.live.engine import VigilEngine
    spec = VigilEngine._redrive_spec(_decision(claimed, url="http://127.0.0.1:19010/x"), None)
    assert spec is not None
    for forbidden in ("workflow_material", "workflow_spec", "spec_signature_b64", "owner_public_key_b64",
                      "reset_material", "reuse_driver", "cross_specs", "mutating_send"):
        assert forbidden not in spec, f"the router must NEVER source {forbidden!r} from the model"


# ---------------------------------------------------------------------------------------------------
# isolation + provisioning
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


# ---------------------------------------------------------------------------------------------------
# WORKFLOW — request_race against the benchmark over-redeem fixture, behind an owner-signed WorkflowSpec
# ---------------------------------------------------------------------------------------------------
_RACE_MARKER = "COUPON-REDEEMED-OK"
_RACE_SUCCESS_PREDICATE = {"contains": [{"var": "body"}, _RACE_MARKER]}


def _demo_spec():
    from framework.v2.scanner.bizlogic import TamperProbe, WorkflowSpec, WorkflowStep
    return WorkflowSpec(
        name="seam-order-workflow",
        steps=(WorkflowStep(name="add", path="/order/add", params={"qty": 1},
                            effect={"gt": [{"var": "qty"}, 0]}),),
        tamper_probes=(TamperProbe(step="add", overrides={"qty": -5},
                                   danger={"eq": [{"var": "qty"}, -5]}, label="negative cart quantity"),))


def _sign_spec(spec, kp):
    from vigil_core import canonical_json, sign
    from vigil_integration.live.race_bizlogic_redrive import _WORKFLOW_SPEC_DOMAIN
    message = _WORKFLOW_SPEC_DOMAIN + canonical_json(spec.model_dump(mode="json"))
    return sign(kp.private_key_b64, message), kp.public_key_b64


def _workflow_bundle(*, signed: bool, action_path="/race/redeem"):
    from vigil_core import generate_keypair
    from vigil_integration.live.race_bizlogic_redrive import RaceTarget
    spec = _demo_spec()
    kp = generate_keypair()
    sig, pub = _sign_spec(spec, kp)
    if not signed:
        sig, pub = "", ""     # NOT owner-signed → the arm refuses (owner_signed_spec False)
    return {
        "workflow_spec": spec, "spec_signature_b64": sig, "owner_public_key_b64": pub,
        "race_targets": (RaceTarget(action_path=action_path, max_allowed=1, count=8,
                                    success_predicate=_RACE_SUCCESS_PREDICATE),),
    }


def _drive_workflow(monkeypatch, tmp_path, *, signed: bool, action_path="/race/redeem"):
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from framework.v2.eval.benchmark_app import serve
    from vigil_integration.live.wiring import _live_race_bizlogic_redrive_fact
    with serve() as base_url:
        urllib.request.urlopen(
            urllib.request.Request(base_url + "/race/reset", data=b"", method="POST"), timeout=5).close()
        spec = {"kind": "workflow", "url": base_url, "bug_class": "request_race",
                "workflow_material": _workflow_bundle(signed=signed, action_path=action_path)}
        return _live_race_bizlogic_redrive_fact(_prov(), {}, spec)


def test_live_workflow_seam_mints_a_request_race_fact(monkeypatch, tmp_path):
    ref = _drive_workflow(monkeypatch, tmp_path, signed=True)
    assert ref, "an owner-signed race re-drive over the over-redeem fixture must mint a signed request_race FACT"


def test_negctl_workflow_unsigned_spec_mints_nothing(monkeypatch, tmp_path):
    assert _drive_workflow(monkeypatch, tmp_path, signed=False) is None, (
        "an UNSIGNED WorkflowSpec must mint NO FACT (owner_signed_spec False ⇒ INCONCLUSIVE)")


def test_negctl_workflow_benign_locked_twin_mints_nothing(monkeypatch, tmp_path):
    assert _drive_workflow(monkeypatch, tmp_path, signed=True, action_path="/race/redeem-locked") is None, (
        "the correctly-locked benign twin wins exactly once — no limit overrun, no FACT")


def test_workflow_seam_without_material_is_fail_closed(monkeypatch, tmp_path):
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from vigil_integration.live.wiring import _live_race_bizlogic_redrive_fact
    assert _live_race_bizlogic_redrive_fact(
        _prov(), {}, {"kind": "workflow", "url": "http://127.0.0.1:1/x", "bug_class": "request_race"}) is None
    assert _live_race_bizlogic_redrive_fact(_prov(), {}, None) is None


def test_workflow_producer_material_is_stripped(monkeypatch, tmp_path):
    """A MODEL/producer-authored workflow bundle is UNCONDITIONALLY stripped; with no feeder the seam stays a
    LEAD even against the vulnerable fixture."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from framework.v2.eval.benchmark_app import serve
    from vigil_integration.live.wiring import (
        _live_race_bizlogic_redrive_fact, _with_trusted_workflow_material)
    with serve() as base_url:
        urllib.request.urlopen(
            urllib.request.Request(base_url + "/race/reset", data=b"", method="POST"), timeout=5).close()
        producer = {"kind": "workflow", "url": base_url, "bug_class": "request_race",
                    "workflow_material": _workflow_bundle(signed=True)}
        stripped = _with_trusted_workflow_material(producer, None, {})
        assert "workflow_material" not in stripped, "producer workflow material must be stripped unconditionally"
        assert _live_race_bizlogic_redrive_fact(_prov(), {}, stripped) is None


# ---------------------------------------------------------------------------------------------------
# PASSWORD-RESET — cross_user via a real two-identity loopback server
# ---------------------------------------------------------------------------------------------------
_VICTIM_SECRET = "SECRET-BOB-RESET-#2-acct=bob@example.test"
_SHELL = "<html><nav>Home</nav>{body}<footer>Acme</footer></html>"


def _who(h):
    return (h.headers.get("X-Id") or "").strip().lower()


def _rid(h):
    return (parse_qs(urlsplit(h.path).query).get("id") or [""])[0]


class _ResetVulnApp(http.server.BaseHTTPRequestHandler):
    """VULNERABLE cross-user reset: the attacker's reset token reaches bob's (id=2) private record; the
    unauthorized-authenticated peer render and the logged-out baseline omit it."""

    def do_GET(self):  # noqa: N802
        who, rid = _who(self), _rid(self)
        if who == "victim":
            return self._send(200, _VICTIM_SECRET)
        if who == "attacker":
            body = _VICTIM_SECRET if rid == "2" else "alice-own-account-0001"
            return self._send(200, _SHELL.format(body=body))
        if who == "unauth":
            return self._send(200, _SHELL.format(body="record #2 owner=bob body=(restricted)"))
        return self._send(403, _SHELL.format(body="login required"))

    def _send(self, code, body):
        raw = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *a):
        return


class _ResetGatedApp(_ResetVulnApp):
    """CORRECTLY ACCESS-CONTROLLED: the attacker's cross-read of bob's ref is denied (403)."""

    def do_GET(self):  # noqa: N802
        who, rid = _who(self), _rid(self)
        if who == "victim":
            return self._send(200, _VICTIM_SECRET)
        if who == "attacker" and rid == "2":
            return self._send(403, _SHELL.format(body="forbidden"))
        if who == "attacker":
            return self._send(200, _SHELL.format(body="alice-own-account-0001"))
        if who == "unauth":
            return self._send(200, _SHELL.format(body="record #2 owner=bob body=(restricted)"))
        return self._send(403, _SHELL.format(body="login required"))


def _serve(handler):
    srv = http.server.HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _reset_cross_bundle():
    from framework.v2.scanner.access_control import CrossAccessSpec
    return {
        "cross_specs": (CrossAccessSpec(bug_class="password_reset_cross_user", ref_param="id",
                                        victim_ref="2", victim_discriminator=_VICTIM_SECRET, control_ref="1"),),
        "victim_headers": (("X-Id", "victim"),),
        "attacker_headers": (("X-Id", "attacker"),),
        "unauth_headers": (("X-Id", "unauth"),),
    }


def _drive_reset(monkeypatch, tmp_path, handler):
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from vigil_integration.live.wiring import _live_reset_invariant_redrive_fact
    srv = _serve(handler); port = srv.server_address[1]
    try:
        spec = {"kind": "reset", "url": f"http://127.0.0.1:{port}/obj",
                "bug_class": "password_reset_cross_user", "reset_material": _reset_cross_bundle()}
        return _live_reset_invariant_redrive_fact(_prov(), {}, spec)
    finally:
        srv.shutdown()


def test_live_reset_seam_mints_a_cross_user_fact(monkeypatch, tmp_path):
    ref = _drive_reset(monkeypatch, tmp_path, _ResetVulnApp)
    assert ref, "a cross-user reset token reaching the victim-unique discriminator must mint a signed FACT"


def test_negctl_reset_correctly_gated_mints_nothing(monkeypatch, tmp_path):
    assert _drive_reset(monkeypatch, tmp_path, _ResetGatedApp) is None, (
        "a 403 to the attacker's cross-read is correct access control — no FACT")


def test_reset_seam_without_material_is_fail_closed(monkeypatch, tmp_path):
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from vigil_integration.live.wiring import _live_reset_invariant_redrive_fact
    assert _live_reset_invariant_redrive_fact(
        _prov(), {}, {"kind": "reset", "url": "http://127.0.0.1:1/obj",
                      "bug_class": "password_reset_cross_user"}) is None
    assert _live_reset_invariant_redrive_fact(_prov(), {}, None) is None


def test_reset_producer_material_is_stripped(monkeypatch, tmp_path):
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from vigil_integration.live.wiring import (
        _live_reset_invariant_redrive_fact, _with_trusted_reset_material)
    srv = _serve(_ResetVulnApp); port = srv.server_address[1]
    try:
        producer = {"kind": "reset", "url": f"http://127.0.0.1:{port}/obj",
                    "bug_class": "password_reset_cross_user", "reset_material": _reset_cross_bundle()}
        stripped = _with_trusted_reset_material(producer, None, {})
        assert "reset_material" not in stripped, "producer reset material must be stripped unconditionally"
        assert _live_reset_invariant_redrive_fact(_prov(), {}, stripped) is None
    finally:
        srv.shutdown()


# ---------------------------------------------------------------------------------------------------
# (E) the feeders are fail-closed by default
# ---------------------------------------------------------------------------------------------------
def test_feeders_fail_closed_without_config():
    from vigil_integration.live.wiring import (
        EngineConfig, _governed_reset_material, _governed_workflow_material)
    prov = _prov()
    assert _governed_workflow_material(prov, EngineConfig(slug="alpha")) is None
    assert _governed_workflow_material(prov, EngineConfig(slug="alpha", workflow_enable=True)) is None
    # enabled but the spec is not owner-signed (no signature) ⇒ None
    unsigned = {"workflow_spec": object(), "spec_signature_b64": "", "owner_public_key_b64": ""}
    assert _governed_workflow_material(
        prov, EngineConfig(slug="alpha", workflow_enable=True, workflow_material=unsigned)) is None
    assert _governed_reset_material(prov, EngineConfig(slug="alpha")) is None
    assert _governed_reset_material(prov, EngineConfig(slug="alpha", reset_enable=True)) is None
    # enabled but no usable consumer (no driver, no cross_specs) ⇒ None
    assert _governed_reset_material(
        prov, EngineConfig(slug="alpha", reset_enable=True, reset_material={"victim_headers": (("a", "b"),)})) is None
