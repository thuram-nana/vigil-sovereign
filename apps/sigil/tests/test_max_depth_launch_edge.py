"""L1 — the Max depth is selectable over the REAL customer hop only when the owner enables it.

The real stack (a sovereign cockpit + the custui edge over the hop key — the ``test_custui`` helpers): a signed-up
customer who may run assessments posts ``launch/reserve`` naming the Max product. With the tiered launch products on but
``VIGIL_MAX_DEPTH`` unset, the provisioner refuses the product itself ("unknown or unavailable launch product") before
any other check; with the flag on, the product resolves and the reserve goes on to the next conjunct (this host has no
ownership proof), so the refusal no longer names the product. The edge never decides what may be selected: it relays the
catalog id, and the server's owner catalog is the only authority.

Mutation target: ``catalog.launch_products()`` offering Max without ``config.max_depth_enabled()`` -> the flag-off half
of the test reds.
"""
from __future__ import annotations

import time

from test_custui import _scrub_shared_owner_state  # noqa: F401  (autouse: keep the shared SIGIL_HOME owner state pristine)
from test_custui import _opener, _post, _stack


def _operator_session(sov, ep):
    """Sign up a customer over the edge, then (an owner act on the sovereign store) grant it the operator role, which
    carries run_engagement — a signed-up member is a billing-only org_admin and may not launch."""
    from sigil.governor.orgs import OrgRegistry
    op = _opener()
    token = _post(op, ep, "/api/customer/signup/request", {"email": "max@acme.com"})[1]["dev_token"]
    conf = _post(op, ep, "/api/customer/signup/confirm",
                 {"token": token, "password": "customer-pw-1", "org_name": "Acme"})[1]
    OrgRegistry(sov.store()).grant_membership(conf["org_id"], conf["username"], "operator",
                                              issued_at=time.time() + 1e6)
    return op, conf["org_id"]


def test_the_max_product_is_selectable_over_the_real_hop_only_when_the_owner_enables_it(tmp_path, monkeypatch):
    monkeypatch.setenv("VIGIL_TIERED_PRODUCTS", "1")
    for k in ("VIGIL_MAX_DEPTH", "VIGIL_METERED_BILLING", "VIGIL_CUSTOMER_STEPUP_REQUIRED",
              "VIGIL_TRIAL_PREVIEW_ENABLED"):
        monkeypatch.delenv(k, raising=False)
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        op, oid = _operator_session(sov, ep)
        body = {"host": "acme.example", "product_id": "vigil_launch_max"}
        code, resp = _post(op, ep, "/api/customer/launch/reserve", body)
        assert code == 403 and "launch product" in resp["error"], (code, resp)   # flag off: Max is not on offer
        monkeypatch.setenv("VIGIL_MAX_DEPTH", "1")
        code, resp = _post(op, ep, "/api/customer/launch/reserve", body)
        assert code == 403, (code, resp)                                          # the next conjunct refuses ...
        assert "launch product" not in resp["error"] and oid in resp["error"], resp   # ... Max itself resolved
    finally:
        sov.shutdown(); edge.shutdown()
