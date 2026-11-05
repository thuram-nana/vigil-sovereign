"""SOVEREIGN half of the AEGIS-SaaS acceptance test (test_aegis_saas_acceptance.py).

``framework`` (offense) and ``sigil`` (sovereign) cannot co-load in one process (assert_no_offense), so the
acceptance test drives the sovereign plane through THIS script in a child process. State persists between calls
through the env the parent sets (SIGIL_HOME / VIGIL_BASE_DIR / SIGIL_SPINE_DIR / VIGIL_MONITORING_PUBLISH_DIR)
plus the spine file named by AEGIS_ACC_STORE. Each verb prints ONE JSON object on stdout.

  setup                      seat org_a/alice + org_b/bob (org_admin), prove apme.cm / beta.cm; print owner pubkey
  authorize <org> <user> <host> <mode>
  revoke <org> <user> <host>
  drain <spool> <secrets.json>   secrets.json: {"<org>\\u0000<host>": "<hex>"}; prints drain result + events per org
"""
from __future__ import annotations

import itertools
import json
import os
import sys
import tempfile
import time

_iss = itertools.count(int(time.time() * 1000))


def _store():
    from sigil.spine.store import SpineStore
    return SpineStore(os.environ["AEGIS_ACC_STORE"])


def _prov(store):
    from sigil.governor.customers import CustomerRegistry
    from sigil.governor.identity import ensure_owner_keypair
    from sigil.governor.orgs import OrgRegistry
    from sigil.governor.wallet import WalletRegistry
    from sigil.ui.email_channel import EmailTokenLedger, NullEmailSender
    from sigil.ui.login_ratelimit import LoginRateLimiter
    from sigil.ui.provision import Provisioner
    ensure_owner_keypair()
    orgs = OrgRegistry(store)
    p = Provisioner(store, customers=CustomerRegistry(store), orgs=orgs, wallet=WalletRegistry(store),
                    email_tokens=EmailTokenLedger(tempfile.mkdtemp(), ttl_s=1e4),
                    rate_limiter=LoginRateLimiter(tempfile.mkdtemp(), max_fails=1000, window_s=1e4,
                                                  base_lock_s=1.0),
                    email_sender=NullEmailSender())
    return p, orgs


def setup() -> dict:
    from sigil.governor.asset_ownership import METHOD_DNS_TXT, AssetOwnershipRegistry
    from sigil.governor.identity import owner_keypair
    s = _store()
    _, orgs = _prov(s)
    reg = AssetOwnershipRegistry(s)
    for org, user, host in (("org_a", "alice", "apme.cm"), ("org_b", "bob", "beta.cm")):
        orgs.create_org(org, org, owner=user, issued_at=float(next(_iss)) / 1000)
        orgs.grant_membership(org, user, "org_admin", issued_at=float(next(_iss)) / 1000)
        ch = reg.issue_challenge(org, host, issued_at=time.time())
        reg.verify_and_record(org, host, method=METHOD_DNS_TXT, observed=[ch.marker], now=time.time(),
                              ttl_seconds=1e9)
    return {"owner_public_key_b64": owner_keypair().public_key_b64}


def authorize(org, user, host, mode) -> dict:
    p, _ = _prov(_store())
    try:
        r = p.monitor_authorize(user, org, host, mode=mode)
    except Exception as e:  # noqa: BLE001 — the parent asserts on the refusal
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}
    return {"ok": True, "mode": r["mode"], "published": r["published"]}


def revoke(org, user, host) -> dict:
    p, _ = _prov(_store())
    return {"ok": True, **p.monitor_revoke(user, org, host)}


def drain(spool, secrets_path) -> dict:
    from sigil.governor.monitoring_authority import MonitoringAuthorityRegistry
    from sigil.inbound.monitoring_spool import MonitoringSpoolWatcher, monitoring_events
    with open(secrets_path, encoding="utf-8") as fh:
        secrets = {k: bytes.fromhex(v) for k, v in json.load(fh).items()}
    s = _store()
    w = MonitoringSpoolWatcher(s, spool_dir=spool, secret_for=lambda o, h: secrets.get(o + "\x00" + h),
                               authority=MonitoringAuthorityRegistry(s, owner_key=None))
    res = w.drain()
    return {"drain": res, "events": {o: monitoring_events(s, o) for o in ("org_a", "org_b")}}


if __name__ == "__main__":
    verb, args = sys.argv[1], sys.argv[2:]
    print(json.dumps({"setup": setup, "authorize": authorize, "revoke": revoke, "drain": drain}[verb](*args)))
