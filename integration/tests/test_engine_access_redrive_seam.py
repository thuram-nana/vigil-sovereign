"""Wave 3 — the ENGAGE oracle seam confirms broken object-level authorization (bola / idor) via a
TWO-IDENTITY cross-object read (``live.runtime_redrive.access_redrive``).

The FACT is an achieved-state proof: an UNDER-privileged identity's response actually contains the object
content only the PRIVILEGED (owning) identity should see (attacker got 200, the victim body has real content,
and the attacker body contains it). This pins:

  * ``VigilEngine._redrive_spec`` emits a ``{"kind": "access", ...}`` spec ONLY when a privileged (victim)
    session is supplied (no session ⇒ LEAD, fail-closed).
  * ``wiring._live_access_redrive_fact`` mints a signed FACT only on a confirmed cross-tenant read — and
    mints NOTHING when the endpoint properly authorizes (attacker 403), the two identities are the same, no
    victim session is supplied, or the target is out of scope.
"""
from __future__ import annotations

import http.server
import threading
import types
from pathlib import Path

import pytest

pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable here")


# ---------------------------------------------------------------------------------------------------
# hermetic: _redrive_spec routing
# ---------------------------------------------------------------------------------------------------

def _decision(bug_class: str, *, url: str, info_extra: dict | None = None) -> types.SimpleNamespace:
    info = {"bug_class": bug_class}
    info.update(info_extra or {})
    analysis = types.SimpleNamespace(exploit_succeeded=True, extracted_info=info)
    tool = types.SimpleNamespace(tool_args={"url": url})
    return types.SimpleNamespace(tool=tool, output_analysis=analysis)


@pytest.mark.parametrize("claimed", ["bola", "idor", "insecure_direct_object_reference",
                                     "broken_object_level_authorization"])
def test_redrive_spec_emits_an_access_spec_with_a_victim_session(claimed):
    from vigil_integration.live.engine import VigilEngine
    spec = VigilEngine._redrive_spec(
        _decision(claimed, url="http://127.0.0.1:19010/api/applications?id=2",
                  info_extra={"victim_cookie": "session=v", "attacker_cookie": "session=a",
                              "ref_param": "id", "victim_ref": "2"}), None)
    assert spec is not None and spec["kind"] == "access"
    assert spec["bug_class"] in ("bola", "idor")
    assert spec["victim_cookie"] == "session=v" and spec["ref_param"] == "id" and spec["victim_ref"] == "2"


def test_redrive_spec_access_without_a_victim_session_is_not_redrivable():
    from vigil_integration.live.engine import VigilEngine
    assert VigilEngine._redrive_spec(
        _decision("bola", url="http://127.0.0.1:19010/api/applications?id=2"), None) is None


# ---------------------------------------------------------------------------------------------------
# live: _live_access_redrive_fact over a loopback app (positive + mandatory negative controls)
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


def _session(handler) -> str:
    """The session= value from the request's Cookie header, or '' if anonymous."""
    raw = handler.headers.get("Cookie", "") or ""
    for part in raw.split(";"):
        k, _, v = part.strip().partition("=")
        if k == "session":
            return v
    return ""


# The private object each user owns. id=N is owned by userN; the body is that user's distinctive PII.
_OBJECTS = {"1": '{"id":1,"owner":"aturing","national_id":"MRD-100001","email":"a@lab"}',
            "2": '{"id":2,"owner":"glovelace","national_id":"MRD-100002","email":"g@lab"}'}


class _VulnApp(http.server.BaseHTTPRequestHandler):
    """BROKEN object-level authz: any AUTHENTICATED user may read ANY object (no ownership check), but an
    ANONYMOUS request is denied — so the object IS access-controlled, and a cross-tenant read is a real BOLA."""
    def do_GET(self):  # noqa: N802
        from urllib.parse import parse_qs, urlsplit
        q = parse_qs(urlsplit(self.path).query)
        oid = (q.get("id") or [""])[0]
        if not _session(self):
            self.send_response(401); self.end_headers(); self.wfile.write(b'{"error":"login required"}'); return
        if oid in _OBJECTS:
            return self._json(_OBJECTS[oid])
        self.send_response(404); self.end_headers()

    def _json(self, body: str):
        raw = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *a):
        return


class _SafeApp(_VulnApp):
    """PROPER object-level authz: returns an object only to its OWNER (session=user{id}); else 403."""
    def do_GET(self):  # noqa: N802
        from urllib.parse import parse_qs, urlsplit
        q = parse_qs(urlsplit(self.path).query)
        oid = (q.get("id") or [""])[0]
        owner = {"1": "aturing", "2": "glovelace"}.get(oid)
        if oid in _OBJECTS and _session(self) == owner:
            return self._json(_OBJECTS[oid])
        if oid in _OBJECTS:
            self.send_response(403); self.end_headers(); self.wfile.write(b'{"error":"forbidden"}'); return
        self.send_response(404); self.end_headers()


class _PublicApp(_VulnApp):
    """near-miss: the object is PUBLIC — served to EVERYONE including anonymous. A cross-tenant read of a
    public object is NOT a BOLA; the anon-control leg must refuse it (anon also receives the content)."""
    def do_GET(self):  # noqa: N802
        from urllib.parse import parse_qs, urlsplit
        oid = (parse_qs(urlsplit(self.path).query).get("id") or [""])[0]
        if oid in _OBJECTS:
            return self._json(_OBJECTS[oid])   # no auth check at all — public
        self.send_response(404); self.end_headers()


def _serve(handler):
    srv = http.server.HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _access(url_tpl, *, victim_cookie, attacker_cookie, ref_param="id", victim_ref="2", handler=_VulnApp):
    def _run(monkeypatch, tmp_path):
        _grant_active_recon(monkeypatch)
        _charter(tmp_path, "127.0.0.1")
        from vigil_integration.live.wiring import _live_access_redrive_fact
        srv = _serve(handler); port = srv.server_address[1]
        redrive = {"kind": "access", "url": url_tpl.format(port=port), "bug_class": "bola",
                   "victim_cookie": victim_cookie, "attacker_cookie": attacker_cookie,
                   "ref_param": ref_param, "victim_ref": victim_ref}
        try:
            return _live_access_redrive_fact(_prov(), {}, redrive)
        finally:
            srv.shutdown()
    return _run


def test_live_bola_cross_tenant_read_mints_a_fact(monkeypatch, tmp_path):
    # attacker (aturing) reads glovelace's object id=2 → gets her PII → FACT
    ref = _access("http://127.0.0.1:{port}/api/applications",
                  victim_cookie="session=glovelace", attacker_cookie="session=aturing")(monkeypatch, tmp_path)
    assert ref, "an attacker reading another identity's private object must mint a BOLA FACT"


def test_negctl_properly_authorized_endpoint_mints_nothing(monkeypatch, tmp_path):
    # SafeApp 403s the attacker → attacker_status != 200 → no FACT
    ref = _access("http://127.0.0.1:{port}/api/applications", victim_cookie="session=glovelace",
                  attacker_cookie="session=aturing", handler=_SafeApp)(monkeypatch, tmp_path)
    assert ref is None, "a properly object-authorized endpoint (attacker 403) must not mint a BOLA FACT"


def test_negctl_same_identity_read_mints_nothing(monkeypatch, tmp_path):
    # attacker == victim → reading your OWN object is not BOLA
    ref = _access("http://127.0.0.1:{port}/api/applications", victim_cookie="session=glovelace",
                  attacker_cookie="session=glovelace")(monkeypatch, tmp_path)
    assert ref is None, "a same-identity read must not mint a BOLA FACT"


def test_negctl_no_victim_session_mints_nothing(monkeypatch, tmp_path):
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from vigil_integration.live.wiring import _live_access_redrive_fact
    srv = _serve(_VulnApp); port = srv.server_address[1]
    try:
        ref = _live_access_redrive_fact(_prov(), {}, {
            "kind": "access", "url": f"http://127.0.0.1:{port}/api/applications", "bug_class": "bola",
            "victim_cookie": "", "attacker_cookie": "session=aturing", "ref_param": "id", "victim_ref": "2"})
    finally:
        srv.shutdown()
    assert ref is None, "no privileged (victim) session ⇒ the differential cannot be established → LEAD"


def test_out_of_scope_url_mints_nothing(monkeypatch, tmp_path):
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from vigil_integration.live.wiring import _live_access_redrive_fact
    ref = _live_access_redrive_fact(_prov(), {}, {
        "kind": "access", "url": "http://10.99.99.99/api/applications", "bug_class": "bola",
        "victim_cookie": "session=glovelace", "attacker_cookie": "session=aturing",
        "ref_param": "id", "victim_ref": "2"})
    assert ref is None, "an out-of-scope target must never mint a FACT"


def test_negctl_public_object_mints_nothing(monkeypatch, tmp_path):
    """near-miss: a PUBLIC object (served to anon too) must not mint a BOLA FACT — the anon-control leg
    refuses it, since a public object read by another user is not a broken object-level authorization."""
    ref = _access("http://127.0.0.1:{port}/api/applications", victim_cookie="session=glovelace",
                  attacker_cookie="session=aturing", handler=_PublicApp)(monkeypatch, tmp_path)
    assert ref is None, "a public object (also served to anon) must not mint a BOLA FACT"
