"""SOVEREIGN half of the seam-migration engine-floor test (test_seam_migration_engine_floor.py).

``framework`` (offense) and ``sigil`` (sovereign) cannot co-load in one process (assert_no_offense), so the test
drives the sovereign plane through THIS script in a child process. The owner key lives in the child's SIGIL_HOME;
the spine is the file named by SEAM_TEST_STORE. Each verb prints ONE JSON object on stdout.

  lease <base> <slug> <host> <org> <nonce> <issued_at>   publish an owner-signed launch lease; print the owner pubkey
  migrate <from> <to>                                     `sigil seam migrate --apply` from one tree into the other
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import sys


def _store():
    from sigil.spine.store import SpineStore
    return SpineStore(os.environ["SEAM_TEST_STORE"])


def lease(base: str, slug: str, host: str, org: str, nonce: str, issued: str) -> dict:
    from sigil.governor.identity import ensure_owner_keypair
    from vigil_core import AuthorizerKey, CreditLaunchLease, TrustRoot, sign_credit_launch_lease
    from vigil_integration.live.credit_lease_broker import write_credit_lease
    owner = ensure_owner_keypair()
    t = _dt.datetime.fromtimestamp(float(issued), tz=_dt.timezone.utc)
    doc = CreditLaunchLease(engagement_slug=slug, org_id=org, scope_host=host, units_reserved=10,
                            not_before=t - _dt.timedelta(hours=1), not_after=t + _dt.timedelta(hours=8),
                            nonce=nonce, issued_at=float(issued))
    root = TrustRoot(threshold=1, authorizers=[AuthorizerKey(key_id="owner", name="owner",
                                                             public_key_b64=owner.public_key_b64)])
    write_credit_lease(base, slug, sign_credit_launch_lease(doc, {"owner": owner.private_key_b64}), root)
    return {"owner_public_key_b64": owner.public_key_b64}


def migrate(src: str, dst: str) -> dict:
    from sigil import seam_migrate
    from sigil.governor.identity import owner_keypair
    code, rep = seam_migrate.run(_store(), owner_keypair(), seam=dst, sources=[src], apply=True)
    return {"code": code, "report": rep}


if __name__ == "__main__":
    verb, *args = sys.argv[1:]
    print(json.dumps({"lease": lease, "migrate": migrate}[verb](*args)))
