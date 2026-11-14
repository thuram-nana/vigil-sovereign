"""`sigil seam migrate` — the plan, the report and the refusals (report-only unless --apply).

A host whose cockpit used another seam directory before the one seam base (``$SIGIL_HOME/.vigil-live``) keeps
launch-seam records there. ``seam migrate`` plans their carry-over into the seam the configured units use: it verifies
every legacy lease under the owner key, reads the spine once for their settlement, classifies each lease
(settled / live / expired_unsettled) and lists every conflict for the operator. Without ``--apply`` it writes NOTHING:
no journal, no spool move, no spine record, and the seam is byte-identical.

Sovereign leg: PYTHONPATH=apps/sigil:integration:packages/core/vigil_core.

Mutation-verify targets (each neuter reds a NAMED test here):
  * report-only writes (the plan path calls the apply path)      -> test_report_only_writes_nothing
  * a different lease for an unsettled legacy slug not a conflict -> test_a_newer_lease_on_the_seam_is_a_conflict
  * the overlap refusal removed                                   -> test_overlapping_trees_are_refused
"""
from __future__ import annotations

import hashlib
import itertools
import json
import os
import tempfile
from pathlib import Path

import pytest

from sigil import seam_migrate
from sigil.governor.asset_ownership import METHOD_DNS_TXT, AssetOwnershipRegistry
from sigil.governor.identity import ensure_owner_keypair
from sigil.governor.orgs import OrgRegistry
from sigil.governor.wallet import WalletRegistry
from sigil.spine.store import SpineStore
from sigil.ui.launch_gate import LaunchGate
from sigil.ui.target_authorization import add_customer_target
from vigil_integration import seam_migration as sm
from vigil_integration.live.credit_lease_pause import record_lease_pause

_iss = itertools.count(1)
ORG, HOST, NOW = "org_a", "apme.cm", 2000.0
LATE = NOW + 3600.0 + 100.0          # past a 1h lease's window


@pytest.fixture
def trees(monkeypatch, tmp_path):
    return make_trees(monkeypatch, tmp_path)


def make_trees(monkeypatch, tmp_path):
    """``(legacy, seam, spool)``; the processes run on the LEGACY tree until :func:`_move` switches them."""
    from sigil import config
    legacy, seam, spool = tmp_path / "home" / ".vigil-live", tmp_path / "credit-lease", tmp_path / "spool"
    legacy.mkdir(parents=True)
    seam.mkdir()
    monkeypatch.setenv("VIGIL_BASE_DIR", str(legacy))
    monkeypatch.setenv("SIGIL_SPINE_DIR", tempfile.mkdtemp())
    monkeypatch.setattr(config, "MODEL_METER_DIR", tmp_path / "model_meter")
    for k in ("VIGIL_SETTLE_SPINE_RECORD", "VIGIL_METERED_BILLING", "VIGIL_COST_LEDGER_WRITE",
              "VIGIL_ONE_LAUNCH_PER_HOST", "VIGIL_SEAM_MIGRATION_GUARD", sm.LEGACY_DIRS_ENV):
        monkeypatch.delenv(k, raising=False)
    return legacy, seam, spool


def _move(monkeypatch, seam) -> None:
    """The processes now resolve the new seam (the units' VIGIL_BASE_DIR)."""
    monkeypatch.setenv("VIGIL_BASE_DIR", str(seam))


def _store() -> SpineStore:
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _seat(store, *, credits=100) -> None:
    ensure_owner_keypair()
    orgs = OrgRegistry(store)
    orgs.create_org(ORG, ORG, owner="u", issued_at=float(next(_iss)))
    orgs.grant_membership(ORG, "u", "operator", issued_at=float(next(_iss)))
    WalletRegistry(store).grant(ORG, credits, "trial", entry_id=f"trial:{ORG}", issued_at=float(next(_iss)))
    reg = AssetOwnershipRegistry(store)
    ch = reg.issue_challenge(ORG, HOST, issued_at=float(next(_iss)))
    reg.verify_and_record(ORG, HOST, method=METHOD_DNS_TXT, observed=[ch.marker], now=NOW, ttl_seconds=1e12)
    assert add_customer_target(HOST, org_id=ORG, store=store, now=NOW)["ok"]


def _reserve(store, units=30, publish=True, now=NOW):
    g = LaunchGate(store)
    r = g.reserve_launch(requester="u", org_id=ORG, host=HOST, units=units, now=now, duration_hours=1)
    assert r["ok"], r
    if publish:
        assert g.publish_lease(signed_lease=r["lease"], expect_org_id=ORG)["ok"]
    return r


def _settle(store, r, consumed, now=NOW + 60):
    return LaunchGate(store).settle_launch(signed_lease=r["lease"], consumed_units=consumed, now=now)


def _avail(store) -> int:
    return WalletRegistry(store).available(ORG)


def _tree_bytes(root: Path) -> dict:
    out = {}
    if not root.exists():
        return out
    for p in sorted(root.rglob("*")):
        if p.is_file() and not p.is_symlink():
            out[str(p.relative_to(root))] = hashlib.sha256(p.read_bytes()).hexdigest()
    return out


def _run(store, seam, legacy, spool=None, *, apply=False, now=LATE):
    return seam_migrate.run(store, ensure_owner_keypair(), seam=seam, sources=[str(legacy)], spool=spool,
                            apply=apply, now=now)


def _legacy_launches(store, legacy):
    """A legacy tree with a COMPLETED + settled launch, then a started (unsettled) one, and a recorded pause."""
    _seat(store)
    done = _reserve(store)
    assert _settle(store, done, 30)["refunded"] == 0                # completed: charged, marker only
    started = _reserve(store, now=NOW + 100)                        # supersedes the slug's bundle, unsettled
    record_lease_pause(str(legacy), started["slug"], started["nonce"])
    return done, started


def test_report_only_writes_nothing(trees, monkeypatch):
    legacy, seam, spool = trees
    s = _store()
    done, started = _legacy_launches(s, legacy)
    _move(monkeypatch, seam)
    (spool / "processed").mkdir(parents=True)
    before_legacy, before_spool = _tree_bytes(legacy), _tree_bytes(spool)
    tip = s.next_seq
    code, report = _run(s, seam, legacy, spool)
    assert code == 0 and report["applied"] is False
    (src,) = report["sources"]
    assert src["status"] == "planned" and src["classes"]["settlements"]["nonces_added"] == 1
    assert src["classes"]["pauses"]["nonces_added"] == 1
    assert src["leases"] == [{"slug": started["slug"], "nonce": started["nonce"], "state": "expired_unsettled",
                              "action": "copy"}]
    assert src["held"] == [{"slug": started["slug"], "nonce": started["nonce"], "why": "no archived completion"}]
    assert _tree_bytes(seam) == {} and list(seam.iterdir()) == []          # nothing written to the seam
    assert _tree_bytes(legacy) == before_legacy and _tree_bytes(spool) == before_spool
    assert not sm.journal_path(seam).exists() and s.next_seq == tip       # no journal, no spine record
    assert "_ops" not in src and "report only" in seam_migrate.format_report(report)


def test_the_plan_classifies_each_legacy_lease(trees, monkeypatch):
    legacy, seam, _ = trees
    s = _store()
    _done, started = _legacy_launches(s, legacy)
    _move(monkeypatch, seam)
    (src,) = _run(s, seam, legacy, now=NOW + 200)[1]["sources"]
    assert src["leases"] == [{"slug": started["slug"], "nonce": started["nonce"], "state": "live",
                              "action": "copy"}]
    (src,) = _run(s, seam, legacy, now=LATE + 3600)[1]["sources"]
    assert src["leases"][0]["state"] == "expired_unsettled"
    assert _settle(s, started, 0)["refunded"] == 30                       # settled on the seam (the marker is there)
    (src,) = _run(s, seam, legacy, now=LATE + 3600)[1]["sources"]
    assert src["leases"] == [{"slug": started["slug"], "nonce": started["nonce"], "state": "settled",
                              "action": "copy"}]


def test_owner_state_only_is_nothing_to_carry(trees, monkeypatch):
    legacy, seam, _ = trees
    (legacy / "webauthn-credentials.json").write_text("{}")
    (legacy / "cockpit-bootstrap-token").write_text("t")
    code, report = _run(_store(), seam, legacy)
    assert code == 0 and report["sources"][0]["status"] == "empty"


def test_a_newer_lease_on_the_seam_is_a_conflict(trees, monkeypatch):
    legacy, seam, _ = trees
    s = _store()
    _seat(s)
    old = _reserve(s)                                                      # unsettled, published in the legacy tree
    _move(monkeypatch, seam)
    assert add_customer_target(HOST, org_id=ORG, store=s, now=NOW + 50)["ok"]   # re-authorized on the seam
    new = _reserve(s, now=NOW + 100)                                       # a later launch published on the seam
    assert new["nonce"] != old["nonce"]
    code, report = _run(s, seam, legacy)
    (src,) = report["sources"]
    assert code == 1 and src["status"] == "conflict"
    assert src["leases"][0]["action"] == "conflict"
    assert any(c["class"] == "leases" for c in src["conflicts"])


def test_a_symlink_in_a_legacy_class_path_is_unsafe(trees):
    legacy, seam, _ = trees
    d = legacy / "credit-lease-settlements"
    d.mkdir()
    (d / "cust_x.json").symlink_to(legacy.parent / "elsewhere.json")
    code, report = _run(_store(), seam, legacy)
    assert code == 1 and report["sources"][0]["status"] == "unsafe"


def test_overlapping_trees_are_refused(trees):
    legacy, seam, _ = trees
    ensure_owner_keypair()
    with pytest.raises(seam_migrate.MigrateRefused, match="overlap"):
        _run(_store(), legacy / "sub", legacy)
    with pytest.raises(seam_migrate.MigrateRefused, match="overlap"):
        _run(_store(), legacy, legacy)


def test_no_owner_key_is_refused(trees):
    legacy, seam, _ = trees
    with pytest.raises(seam_migrate.MigrateRefused, match="owner"):
        seam_migrate.run(_store(), None, seam=seam, sources=[str(legacy)])


def test_an_unreadable_journal_is_refused(trees):
    legacy, seam, _ = trees
    sm.journal_path(seam).parent.mkdir(parents=True)
    sm.journal_path(seam).write_text("{not json")
    ensure_owner_keypair()
    with pytest.raises(seam_migrate.MigrateRefused, match="journal"):
        _run(_store(), seam, legacy)


def test_the_cli_reports_and_exits_by_status(trees, monkeypatch, capsys):
    from sigil import cli
    legacy, seam, spool = trees
    s = _store()
    monkeypatch.setattr(cli, "SpineStore", lambda *a, **k: s)
    _legacy_launches(s, legacy)
    _move(monkeypatch, seam)
    with pytest.raises(SystemExit) as ex:
        cli.main(["seam", "migrate", "--from", str(legacy), "--to", str(seam), "--completion-spool", str(spool),
                  "--json"])
    assert ex.value.code == 0
    out = json.loads(capsys.readouterr().out)
    assert out["applied"] is False and out["sources"][0]["status"] == "planned"
    assert list(seam.iterdir()) == []
    with pytest.raises(SystemExit) as ex:
        cli.main(["seam", "migrate", "--from", str(legacy), "--to", str(legacy)])
    assert ex.value.code == 2 and "overlap" in capsys.readouterr().err


def test_the_completion_schema_is_the_drains():
    from sigil.inbound.completion_spool import _SEAM_SCHEMA
    from vigil_integration.jobs.completion_signal import COMPLETION_SEAM_SCHEMA
    assert _SEAM_SCHEMA == COMPLETION_SEAM_SCHEMA
    assert os.path.basename(seam_migrate.__file__) == "seam_migrate.py"


def test_settled_by_the_spine_alone_is_settled(trees, monkeypatch):
    """A refunded settle is on the spine: the lease is settled even with no marker in either tree."""
    legacy, seam, _ = trees
    s = _store()
    _done, started = _legacy_launches(s, legacy)
    _move(monkeypatch, seam)
    assert _settle(s, started, 0)["refunded"] == 30
    for f in (seam / "credit-lease-settlements").glob("*.json"):
        f.unlink()                                                         # the seam marker lost
    (src,) = _run(s, seam, legacy, now=LATE + 3600)[1]["sources"]
    assert src["leases"][0]["state"] == "settled"


def test_settled_by_the_seam_marker_alone_is_settled(trees, monkeypatch):
    """A completed settle (refund 0, settle record off) leaves only its marker: on the seam, it still counts."""
    legacy, seam, _ = trees
    s = _store()
    _done, started = _legacy_launches(s, legacy)
    _move(monkeypatch, seam)
    assert _settle(s, started, 30)["refunded"] == 0
    (src,) = _run(s, seam, legacy, now=LATE + 3600)[1]["sources"]
    assert src["leases"][0]["state"] == "settled"
