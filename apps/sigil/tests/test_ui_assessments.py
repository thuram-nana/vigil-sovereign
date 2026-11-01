"""Slice K6 — the tenant-scoped ASSESSMENT RESULTS read API (/api/assessments[/findings]).

Load-bearing invariant (a false-green leaks one tenant's security findings to another):
  * tenant-scoped by construction — the org's engagement-slug set is derived SERVER-SIDE from its OWN current
    ownership proofs (proven_hosts -> _customer_slug); a finding whose signed cert engagement_slug is not in
    that set is NEVER returned. A per-org member reads ONLY their tenant; cross-tenant / non-member → 403.
  * gated on `view_assessments` (operator-tier, NOT org_admin): a billing tenant-admin does not auto-see
    security findings (billing-authz != testing-authz). Read-only; missing org → 400; unauthenticated → 401.
"""
from __future__ import annotations

import json
import tempfile
import threading
import time
import urllib.error
import urllib.request

from sigil.governor.asset_ownership import METHOD_DNS_TXT, AssetOwnershipRegistry
from sigil.governor.identity import ensure_owner_keypair
from sigil.governor.orgs import OrgRegistry
from sigil.spine.store import SpineStore
from sigil.ui.server import build_server
from sigil.ui.target_authorization import _customer_slug

TOKEN = "owner-shared-token-xyz789"


def _finding(store, slug, ref, **cert):
    """Append a synthetic kind='finding' spine record for `slug` (what finding_receiver.ingest would land)."""
    c = {"engagement_slug": slug, "finding_ref": ref, "bug_class": cert.get("bug_class", "xss"),
         "surface": cert.get("surface", "https://x/" + ref), "confidence": cert.get("confidence", "high")}
    store.append(kind="finding", source="offense", actor="ORACLE",
                 payload={"certificate": c, "finding_ref": ref, "signatures": [{"key_id": "gov", "signature_b64": "x"}]})


def _seed():
    path = tempfile.mktemp(suffix=".jsonl")
    SpineStore(path).append(kind="message", source="x", actor="user", payload={"text": "hi"})
    owner = ensure_owner_keypair()
    store = SpineStore(path)
    orgs = OrgRegistry(store, owner_key=owner)
    it = iter(range(1, 10_000))
    orgs.create_org("acme", "Acme Corp", owner="owner", issued_at=float(next(it)))
    orgs.create_org("other", "Other Inc", owner="owner", issued_at=float(next(it)))
    orgs.grant_membership("acme", "alice", "operator", issued_at=float(next(it)))
    reg = AssetOwnershipRegistry(store)
    for org, host in (("acme", "acme.example"), ("other", "beta.example")):
        ch = reg.issue_challenge(org, host, issued_at=float(next(it)))
        reg.verify_and_record(org, host, method=METHOD_DNS_TXT, observed=[ch.marker], now=10.0, ttl_seconds=1e12)
    acme_slug = _customer_slug("acme", "acme.example")
    other_slug = _customer_slug("other", "beta.example")
    _finding(store, acme_slug, "F1")
    _finding(store, acme_slug, "F2", bug_class="sqli")
    _finding(store, other_slug, "F9")                       # a DIFFERENT tenant's finding — must never leak
    return path


def _serve(spine_path):
    srv = build_server(token=TOKEN, port=0, spine_path=spine_path)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.05)
    return srv, port


def _get(port, path, *, token=TOKEN):
    h = {"X-SIGIL-Token": token} if token is not None else {}
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", headers=h)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def _post(port, path, body, *, token=TOKEN):
    h = {"Content-Type": "application/json", "Origin": f"http://127.0.0.1:{port}", "Host": f"127.0.0.1:{port}"}
    if token is not None:
        h["X-SIGIL-Token"] = token
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=json.dumps(body).encode(),
                                 headers=h, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def _bearer(port, username, role):
    code, body = _post(port, "/api/action", {"action": "create_account", "username": username, "role": role})
    assert code == 200, (code, body)
    return body["bearer_token"]


def test_owner_reads_a_tenants_findings_scoped():
    srv, port = _serve(_seed())
    try:
        code, body = _get(port, "/api/assessments/findings?org=acme")
        assert code == 200, (code, body)
        assert body["org_id"] == "acme" and body["count"] == 2
        refs = {f["finding_ref"] for f in body["findings"]}
        assert refs == {"F1", "F2"} and "F9" not in refs            # never the other tenant's finding
        code, other = _get(port, "/api/assessments/findings?org=other")
        assert code == 200 and other["count"] == 1 and other["findings"][0]["finding_ref"] == "F9"
    finally:
        srv.shutdown()


def test_summary_rolls_up_per_engagement():
    srv, port = _serve(_seed())
    try:
        code, body = _get(port, "/api/assessments?org=acme")
        assert code == 200, (code, body)
        assert body["assessments"] == [{"slug": _customer_slug("acme", "acme.example"),
                                        "host": "acme.example", "findings": 2}]
    finally:
        srv.shutdown()


def test_per_org_member_reads_only_their_tenant_findings():
    # THE IDOR class: alice is operator@acme ONLY — she reads acme's findings, never other's.
    srv, port = _serve(_seed())
    try:
        alice = _bearer(port, "alice", "viewer")                    # global viewer, operator in acme
        code, body = _get(port, "/api/assessments/findings?org=acme", token=alice)
        assert code == 200 and body["count"] == 2, (code, body)
        assert all(f["finding_ref"] in ("F1", "F2") for f in body["findings"])
        assert _get(port, "/api/assessments/findings?org=other", token=alice)[0] == 403   # cross-tenant denied
        bob = _bearer(port, "bob", "viewer")                        # no membership anywhere
        assert _get(port, "/api/assessments/findings?org=acme", token=bob)[0] == 403
    finally:
        srv.shutdown()


def test_missing_org_400_and_unauthenticated_401():
    srv, port = _serve(_seed())
    try:
        assert _get(port, "/api/assessments/findings")[0] == 400
        assert _get(port, "/api/assessments/findings?org=bad%2Fslash")[0] == 400
        assert _get(port, "/api/assessments/findings?org=acme", token=None)[0] == 401
        assert _get(port, "/api/assessments?org=acme", token=None)[0] == 401
    finally:
        srv.shutdown()
