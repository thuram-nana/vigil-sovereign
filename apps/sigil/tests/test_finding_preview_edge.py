"""S5b — the preview holds END TO END: every customer read route, through custui → hop → provisioner, and the
notification centre and cockpit, never return a locked finding's detail.

  * EDGE ROUND-TRIP LEAK SCAN: plant unique sentinels in how_to_verify / report_claims / summary /
    oracle_context_digest / artifact_manifest for N findings of a locked trial org, serialise EVERY route in the
    module-level `custui._READS`, and assert no sentinel of a non-revealed finding appears anywhere;
  * ROUTE CENSUS: every route in `_READS` is in the scanned set — a new read route fails CI until it is added
    here (and routed through the preview if it carries finding detail);
  * NOTIFICATIONS: a locked finding's body is fixed copy; the completed-outcome text has locked wording; a
    one-time `billing:reports_unlocked` notice appears after the unlock;
  * COCKPIT: a per-org member gets the preview; a global role with view_assessments gets full detail.
"""
from __future__ import annotations

import json
import time

from test_custui import _get, _opener, _post, _stack

from sigil.governor.asset_ownership import METHOD_DNS_TXT, AssetOwnershipRegistry
from sigil.governor.report_unlock import ReportUnlockRegistry
from sigil.ui import custui
from sigil.ui.target_authorization import _customer_slug

_SCANNED = {"/api/customer/billing", "/api/customer/invoices", "/api/customer/assessments",
            "/api/customer/assessments/findings", "/api/customer/assets", "/api/customer/notifications"}
_FIELDS = ("HTV", "RC", "SUM", "OCD", "AM")


def test_route_census():
    assert set(custui._READS) == _SCANNED, "a new customer read route must be added to the preview leak scan"


def _plant(store, org, host, refs):
    reg = AssetOwnershipRegistry(store)
    ch = reg.issue_challenge(org, host, issued_at=time.time() + 1e6)
    reg.verify_and_record(org, host, method=METHOD_DNS_TXT, observed=[ch.marker], now=time.time(), ttl_seconds=1e9)
    for ref in refs:
        cert = {"engagement_slug": _customer_slug(org, host), "finding_ref": ref, "bug_class": "sqli",
                "surface": "/login", "confidence": 0.9,
                "how_to_verify": f"S-HTV-{ref}", "report_claims": [{"sentence": f"S-RC-{ref}"}],
                "summary": f"S-SUM-{ref}", "oracle_context_digest": f"S-OCD-{ref}",
                "artifact_manifest": {"x": f"S-AM-{ref}"}}
        store.append(kind="finding", source="offense", actor="ORACLE",
                     payload={"certificate": cert, "finding_ref": ref,
                              "signatures": [{"key_id": "g", "signature_b64": "x"}]})
    store.append(kind="assessment_outcome", source="settle", actor="X",
                 payload={"engagement_slug": _customer_slug(org, host), "outcome": "completed", "nonce": "n1",
                          "ts": time.time()})


def _locked_org(tmp_path, monkeypatch):
    from sigil.governor.orgs import OrgRegistry
    monkeypatch.setenv("VIGIL_TRIAL_PREVIEW_ENABLED", "1")
    sov, edge, ep, sp = _stack(tmp_path, monkeypatch)
    op = _opener()
    t = _post(op, ep, "/api/customer/signup/request", {"email": "trial@acme.io"})[1]["dev_token"]
    conf = _post(op, ep, "/api/customer/signup/confirm",
                 {"token": t, "password": "customer-pw-1", "org_name": "Acme"})[1]
    oid, u = conf["org_id"], conf["username"]
    assert "trial" not in conf                                         # the preview trial was granted
    OrgRegistry(sov.store()).grant_membership(oid, u, "operator", issued_at=time.time() + 2e6)
    refs = [f"f{i}" for i in range(4)]
    _plant(sov.store(), oid, "app.acme.io", refs)
    return sov, edge, ep, sp, op, oid, refs


def test_no_locked_detail_leaves_any_customer_read_route(tmp_path, monkeypatch):
    sov, edge, ep, sp, op, oid, refs = _locked_org(tmp_path, monkeypatch)
    try:
        c, found = _get(op, ep, "/api/customer/assessments/findings")
        assert c == 200 and found["preview"]["locked"] and found["count"] == len(refs)
        revealed = [r["finding_ref"] for r in found["findings"] if not r["locked"]]
        assert revealed == ["f0"]
        blob = ""
        for path in sorted(_SCANNED):
            code, body = _get(op, ep, path)
            blob += json.dumps(body)
        for ref in refs[1:]:
            for f in _FIELDS:
                assert f"S-{f}-{ref}" not in blob, (ref, f)
        assert "S-HTV-f0" in blob                                          # the one reveal is full
        _, notes = _get(op, ep, "/api/customer/notifications")
        items = {n["id"]: n for n in notes["notifications"]} if isinstance(notes, dict) else {}
        assert "Billing" in items["finding:f1"]["body"]
        done = [n for n in items.values() if n["kind"] == "assessment"]
        assert done and "unlock" in done[0]["body"]
        assert "billing:reports_unlocked" not in items
        ReportUnlockRegistry(sov.store()).unlock(oid, "topup", source_ref="evt_1", issued_at=time.time())
        _, full = _get(op, ep, "/api/customer/assessments/findings")
        assert "preview" not in full and all("how_to_verify" in r for r in full["findings"])
        _, notes = _get(op, ep, "/api/customer/notifications")
        assert "billing:reports_unlocked" in {n["id"] for n in notes["notifications"]}
    finally:
        sov.shutdown(); edge.shutdown()


def test_cockpit_gives_full_detail_only_to_a_global_role(monkeypatch):
    """Over the real cockpit route: the owner token (global role) reads full detail; a global viewer who is an
    operator of the locked trial org reads the preview."""
    from test_ui_assessments import _bearer, _get as _cget, _seed, _serve

    from sigil.governor.wallet import WalletRegistry
    from sigil.spine.store import SpineStore
    monkeypatch.setenv("VIGIL_TRIAL_PREVIEW_ENABLED", "1")
    path = _seed()                                                    # acme: F1, F2; alice = operator@acme
    WalletRegistry(SpineStore(path)).grant("acme", 100, "trial", entry_id="trial-preview:acme", issued_at=1e9)
    srv, port = _serve(path)
    try:
        code, owner_view = _cget(port, "/api/assessments/findings?org=acme")
        assert code == 200 and "preview" not in owner_view
        assert all(not r.get("locked") for r in owner_view["findings"])
        alice = _bearer(port, "alice", "viewer")
        code, member = _cget(port, "/api/assessments/findings?org=acme", token=alice)
        assert code == 200 and member["preview"]["locked"] is True and member["count"] == 2
        assert sum(1 for r in member["findings"] if r["locked"]) == 1
        code, summ = _cget(port, "/api/assessments?org=acme", token=alice)
        assert code == 200 and summ["preview"] is True
    finally:
        srv.shutdown()
