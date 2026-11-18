"""Red-Pen R4 — the System-review TICKET seam (``live/redpen_system_seam.py``): transport, not trust.

Pinned: a ticket round-trips the owner-signed lease + its scope (``profile="full"``) and carries only PUBLIC
material; a slug can never escape the tickets dir; one ticket per repo slug (a later period replaces it); a malformed
or foreign file is 'no ticket'; removal honours ``expect_nonce`` (never clobbers a newer ticket); and the tickets live
in their OWN directory, apart from the credit-launch leases a PR review or a host launch publishes. Framework-free.
"""
from __future__ import annotations

import json
import os
import stat
from datetime import datetime, timedelta, timezone

import pytest

from vigil_core import (
    AuthorizerKey, CreditLaunchLease, TrustRoot, generate_keypair, sign_credit_launch_lease,
)
from vigil_integration.live import redpen_system_seam as seam

OWNER = generate_keypair()
SLUG, ORG, REPO = "cust_" + "a" * 24, "org_a", "github.com/acme/widgets"
T0 = datetime(2026, 11, 16, 12, tzinfo=timezone.utc)


def _lease(nonce="sch-2026-W47", *, org=ORG, repo=REPO, slug=SLUG):
    doc = CreditLaunchLease(engagement_slug=slug, org_id=org, scope_host=repo, units_reserved=5,
                            not_before=T0, not_after=T0 + timedelta(hours=8), nonce=nonce,
                            issued_at=T0.timestamp())
    root = TrustRoot(threshold=1, authorizers=[AuthorizerKey(key_id="owner", name="owner",
                                                             public_key_b64=OWNER.public_key_b64)])
    return sign_credit_launch_lease(doc, {"owner": OWNER.private_key_b64}), root


def test_a_ticket_round_trips_its_owner_signed_lease_and_full_scope(tmp_path):
    signed, root = _lease()
    path = seam.write_system_ticket(tmp_path, SLUG, org_id=ORG, repo=REPO, signed_lease=signed, trust_root=root)
    assert path.parent == seam.tickets_root(tmp_path) and path.name == f"{SLUG}.json"
    t = seam.read_system_ticket(tmp_path, SLUG)
    assert t is not None and t.profile == "full" and t.org_id == ORG and t.repo == REPO
    assert t.signed_lease.document.nonce == "sch-2026-W47" and t.signed_lease == signed
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


def test_a_ticket_carries_only_public_material(tmp_path):
    signed, root = _lease()
    path = seam.write_system_ticket(tmp_path, SLUG, org_id=ORG, repo=REPO, signed_lease=signed, trust_root=root)
    raw = path.read_text(encoding="utf-8")
    assert OWNER.private_key_b64 not in raw and OWNER.public_key_b64 in raw


@pytest.mark.parametrize("bad", ["", "..", "a/b", "a\\b", "x\x00y", "../escape", " "])
def test_an_unsafe_slug_can_never_leave_the_tickets_dir(tmp_path, bad):
    signed, root = _lease()
    with pytest.raises(ValueError):
        seam.write_system_ticket(tmp_path, bad, org_id=ORG, repo=REPO, signed_lease=signed, trust_root=root)
    assert seam.ticket_path(tmp_path, bad) is None and seam.read_system_ticket(tmp_path, bad) is None
    assert seam.remove_system_ticket(tmp_path, bad) is False


def test_one_ticket_per_repo_slug_a_later_period_replaces_it(tmp_path):
    for nonce in ("sch-2026-W47", "sch-2026-W48"):
        signed, root = _lease(nonce)
        seam.write_system_ticket(tmp_path, SLUG, org_id=ORG, repo=REPO, signed_lease=signed, trust_root=root)
    (only,) = seam.list_system_tickets(tmp_path)
    assert only.signed_lease.document.nonce == "sch-2026-W48"


def test_a_malformed_or_foreign_file_is_no_ticket(tmp_path):
    signed, root = _lease()
    seam.write_system_ticket(tmp_path, SLUG, org_id=ORG, repo=REPO, signed_lease=signed, trust_root=root)
    d = seam.tickets_root(tmp_path)
    (d / "garbage.json").write_text("{not json", encoding="utf-8")
    (d / "foreign.json").write_text(json.dumps({"kind": "vigil-credit-launch-lease-seam-v1", "slug": "x"}),
                                    encoding="utf-8")
    (d / "nolease.json").write_text(json.dumps({"kind": "vigil-redpen-system-ticket-v1", "slug": "cust_b",
                                                "org_id": ORG, "repo": REPO}), encoding="utf-8")
    assert [t.slug for t in seam.list_system_tickets(tmp_path)] == [SLUG]


def test_removal_honours_expect_nonce_and_never_clobbers_a_newer_ticket(tmp_path):
    signed, root = _lease("sch-2026-W48")
    seam.write_system_ticket(tmp_path, SLUG, org_id=ORG, repo=REPO, signed_lease=signed, trust_root=root)
    assert seam.remove_system_ticket(tmp_path, SLUG, expect_nonce="sch-2026-W47") is False   # an OLDER nonce
    assert seam.read_system_ticket(tmp_path, SLUG) is not None
    assert seam.remove_system_ticket(tmp_path, SLUG, expect_nonce="sch-2026-W48") is True
    assert seam.read_system_ticket(tmp_path, SLUG) is None
    assert seam.remove_system_ticket(tmp_path, SLUG) is False                                 # idempotent


def test_tickets_live_apart_from_the_credit_launch_leases(tmp_path):
    from vigil_integration.live.credit_lease_broker import leases_root, list_credit_leases
    signed, root = _lease()
    seam.write_system_ticket(tmp_path, SLUG, org_id=ORG, repo=REPO, signed_lease=signed, trust_root=root)
    assert seam.tickets_root(tmp_path) != leases_root(tmp_path)
    assert list_credit_leases(tmp_path) == []          # a launch / PR-review lease reader never sees a ticket
