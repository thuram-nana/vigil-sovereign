"""WS3 — the read-only cross-VM FLEET MONITOR roll-up + the fleet KILL-SWITCH fan-out driver
(vigil_integration.fleet_monitor).

fold_roster is a PURE, one-way projection of per-box telemetry snapshots (+ optional attestation ledgers)
into one operator view: deterministic (byte-identical on re-run), never an input to a gate, and it NEVER
launders an absent/unreadable/unverified attestation into verified/clean. fan_out_kill drives the existing
per-box primitives (run_panic + an owner-signed entitlement revoke) across a roster, fail-closed without an
owner-signed revocation. Each test carries its own positive AND safe-negative controls.
"""

from __future__ import annotations

import json
import sqlite3
from types import SimpleNamespace

import pytest

from vigil_integration import cli
from vigil_integration import fleet_monitor as fm


# --------------------------------------------------------------------------------------------------
# A blackboard stand-in (mirrors the telemetry test's FakeBB) so the collect_snapshot fold path is real.
# --------------------------------------------------------------------------------------------------


class FakeBB:
    def __init__(self, by_slug):
        self._by = by_slug
        self._conn = sqlite3.connect(":memory:")
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("CREATE TABLE bb_engagements(id INTEGER PRIMARY KEY, slug TEXT)")
        self._conn.executemany("INSERT INTO bb_engagements(slug) VALUES(?)", [(s,) for s in by_slug])

    def replay(self, *, engagement, since_id=0):
        return [SimpleNamespace(id=i, kind=k, payload=p)
                for (i, k, p) in self._by.get(engagement, []) if i > since_id]

    def close(self):
        pass


def _snapshot(events=0, facts=0, leads=0, refusals=0, tool_calls=0, findings=0, engagements=1):
    """A telemetry-shaped snapshot dict (what collect_snapshot produces)."""
    return {"schema": 1,
            "engagements": [{"slug": f"e{i}"} for i in range(engagements)],
            "totals": {"events": events, "facts": facts, "leads": leads, "refusals": refusals,
                       "tool_calls": tool_calls, "messages": 0, "findings": findings,
                       "by_kind": {"finding": findings} if findings else {}, "last_event_id": events}}


def _two_instance_roster():
    """A fixed 2-instance fixture roster: one box with a rich snapshot + an UPSTREAM-verified attestation,
    one box with a lighter snapshot + a present-but-unverified attestation (raw records)."""
    return [
        fm.FleetInstance(
            "vm-west",
            snapshot=_snapshot(events=8, facts=1, leads=2, refusals=1, tool_calls=3, findings=3),
            attestation={"verified": True, "records": 4, "attested_targets": ["10.0.0.5", "10.0.0.6"],
                         "operators": ["fp-west"], "head": "headwest"}),
        fm.FleetInstance(
            "vm-east",
            snapshot=_snapshot(events=3, facts=0, leads=1, refusals=0, tool_calls=1, findings=1),
            attestation=[{"seq": 0, "target": "192.168.1.9", "record_hash": "h0",
                          "operator": {"key_fingerprint": "fp-east"}},
                         {"seq": 1, "target": "192.168.1.9", "record_hash": "h1",
                          "operator": {"key_fingerprint": "fp-east"}}]),
    ]


# --------------------------------------------------------------------------------------------------
# (d1) the aggregator folds a 2-instance fixture roster DETERMINISTICALLY (byte-identical on re-run)
# --------------------------------------------------------------------------------------------------


def test_fold_roster_is_byte_identical_on_rerun():
    roster = _two_instance_roster()
    a = json.dumps(fm.fold_roster(roster), sort_keys=True)
    b = json.dumps(fm.fold_roster(roster), sort_keys=True)
    assert a == b                                      # PURE + DETERMINISTIC: no wallclock / RNG

    snap = fm.fold_roster(roster)
    # instances are emitted in instance_id order (east before west), regardless of roster order
    assert [i["instance_id"] for i in snap["instances"]] == ["vm-east", "vm-west"]

    west = next(i for i in snap["instances"] if i["instance_id"] == "vm-west")
    assert west["spine_events"] == 8 and west["commands"] == 3 and west["engagements"] == 1
    assert west["facts"] == 1 and west["leads"] == 2 and west["refusals"] == 1 and west["findings"] == 3
    assert west["attested_targets"] == ["10.0.0.5", "10.0.0.6"]          # carried + sorted
    assert west["attestation"]["status"] == "verified"

    east = next(i for i in snap["instances"] if i["instance_id"] == "vm-east")
    # raw records summarized STRUCTURALLY — present, with the head = highest-seq record_hash, NOT verified
    assert east["attestation"]["status"] == "present_unverified"
    assert east["attestation"]["verified"] is None
    assert east["attestation"]["records"] == 2 and east["attestation"]["head"] == "h1"
    assert east["attested_targets"] == ["192.168.1.9"]
    assert east["attestation"]["operators"] == ["fp-east"]

    t = snap["totals"]
    assert t["instances"] == 2
    assert t["spine_events"] == 11 and t["commands"] == 4 and t["facts"] == 1 and t["leads"] == 3
    assert t["findings"] == 4 and t["by_kind"] == {"finding": 4}
    assert t["attestation"]["attested_targets"] == ["10.0.0.5", "10.0.0.6", "192.168.1.9"]


def test_fold_roster_folds_a_live_blackboard_via_collect_snapshot():
    """The snapshot source may be an opened blackboard (not only a dict/path): it is folded through the
    existing telemetry.collect_snapshot, and the result is still deterministic."""
    bb = FakeBB({"loopback": [(1, "finding", {"verified_by_oracle": True}),
                              (2, "finding", {}), (3, "action", {"tool": "nmap"})]})
    roster = [fm.FleetInstance("vm-bb", snapshot=bb)]
    snap = fm.fold_roster(roster)
    inst = snap["instances"][0]
    assert inst["facts"] == 1 and inst["leads"] == 1 and inst["commands"] == 1 and inst["spine_events"] == 3
    assert json.dumps(fm.fold_roster(roster), sort_keys=True) == json.dumps(snap, sort_keys=True)


# --------------------------------------------------------------------------------------------------
# (d4) NO inconclusive->clean laundering in the roll-up — the load-bearing soundness test.
# --------------------------------------------------------------------------------------------------


def test_rollup_never_launders_absent_or_unverified_into_verified(tmp_path):
    missing = tmp_path / "nope.jsonl"                                   # a file that does NOT exist
    roster = [
        fm.FleetInstance("i-verified", snapshot=_snapshot(events=1),
                         attestation={"verified": True, "records": 2, "attested_targets": ["t"]}),
        fm.FleetInstance("i-failed", snapshot=_snapshot(events=1),
                         attestation={"verified": False, "records": 2}),       # an explicit FAILED verdict
        fm.FleetInstance("i-unverified", snapshot=_snapshot(events=1),
                         attestation=[{"seq": 0, "target": "u", "record_hash": "h"}]),  # present, unchecked
        fm.FleetInstance("i-absent", snapshot=_snapshot(events=1), attestation=None),    # no attestation
        fm.FleetInstance("i-absent-file", snapshot=_snapshot(events=1), attestation=str(missing)),
    ]
    att = fm.fold_roster(roster)["totals"]["attestation"]
    # verified counts ONLY the one explicitly-verified box — never the failed/unverified/absent ones
    assert att["verified"] == 1
    assert att["by_status"] == {"verified": 1, "failed": 1, "present_unverified": 1, "absent": 2, "error": 0}
    # the buckets partition the fleet exactly (nothing dropped, nothing double-counted)
    assert sum(att["by_status"].values()) == 5
    # a missing ledger FILE is 'absent', NOT a verified/clean zero (fail-closed, mirrors verify-ledger)
    inst = {i["instance_id"]: i for i in fm.fold_roster(roster)["instances"]}
    assert inst["i-absent-file"]["attestation"]["status"] == "absent"
    assert inst["i-absent-file"]["attestation"]["verified"] is None
    # 'present' counts only boxes with real records/verdicts — absent boxes do not inflate it
    assert att["present"] == 3


def test_unchecked_summary_is_not_promoted_to_verified():
    """Safe-negative: an upstream summary with NO explicit verdict (no 'verified' key) is reported
    present_unverified — this view never promotes an unchecked summary to verified/clean."""
    roster = [fm.FleetInstance("x", snapshot=_snapshot(), attestation={"records": 9, "head": "h"})]
    a = fm.fold_roster(roster)["instances"][0]["attestation"]
    assert a["status"] == "present_unverified" and a["verified"] is None and a["records"] == 9


def test_fold_instance_is_total_on_unreadable_sources(tmp_path):
    """Safe-negative: a non-JSON snapshot file and a malformed source never crash and never read clean."""
    bad = tmp_path / "bad.json"
    bad.write_text("}{ not json", encoding="utf-8")
    roster = [fm.FleetInstance("i-err", snapshot=str(bad), attestation=12345)]   # int attestation = error
    inst = fm.fold_roster(roster)["instances"][0]
    assert inst["snapshot_status"] == "error" and inst["spine_events"] == 0
    assert inst["attestation"]["status"] == "error" and inst["attestation"]["verified"] is None


# --------------------------------------------------------------------------------------------------
# (d2) the fleet verb prints the roll-up
# --------------------------------------------------------------------------------------------------


def test_cmd_fleet_status_prints_rollup(tmp_path, capsys):
    snap_a = tmp_path / "snap_a.json"
    snap_a.write_text(json.dumps(_snapshot(events=5, facts=1, leads=2, tool_calls=3, findings=3)),
                      encoding="utf-8")
    roster = {"instances": [
        {"instance_id": "vm-a", "snapshot": str(snap_a)},
        {"instance_id": "vm-b", "snapshot": str(tmp_path / "gone.json")},   # absent snapshot
    ]}
    roster_path = tmp_path / "roster.json"
    roster_path.write_text(json.dumps(roster), encoding="utf-8")
    out = tmp_path / "rollup.json"
    ns = SimpleNamespace(roster=str(roster_path), out=str(out))

    rc = cli._cmd_fleet_status(ns)
    assert rc == 0
    printed = capsys.readouterr().out
    assert "vigil fleet — 2 instance(s)" in printed
    assert "vm-a" in printed and "vm-b" in printed
    assert "fleet totals: instances=2" in printed
    # the --out roll-up is written and is the SAME deterministic projection
    written = json.loads(out.read_text(encoding="utf-8"))
    assert written["totals"]["instances"] == 2
    assert written["totals"]["snapshots"]["by_status"] == {"ok": 1, "absent": 1, "error": 0}


def test_cmd_fleet_status_rejects_a_malformed_roster(tmp_path, capsys):
    bad = tmp_path / "roster.json"
    bad.write_text("not json at all", encoding="utf-8")
    rc = cli._cmd_fleet_status(SimpleNamespace(roster=str(bad), out=""))
    assert rc == 2                                                  # fails LOUD, not a silent empty fold
    assert "fleet status" in capsys.readouterr().err


# --------------------------------------------------------------------------------------------------
# (d3) the kill fan-out calls the right per-instance primitives
# --------------------------------------------------------------------------------------------------


def test_fan_out_kill_invokes_panic_and_revoke_per_instance():
    calls = []

    def fake_panic(*, base_dir):
        calls.append(("panic", base_dir))
        return 0

    def fake_revoke(signed, path):
        calls.append(("revoke", signed, path))
        return path or "default-rev-path"

    roster = [fm.FleetInstance("vm-b", base_dir="/home/b", revocation_path="/rev/b"),
              fm.FleetInstance("vm-a", base_dir="/home/a", revocation_path="/rev/a")]
    rep = fm.fan_out_kill(roster, signed_revocation="SIGNED-DOC",
                          panic_fn=fake_panic, revoke_fn=fake_revoke)
    # every instance got BOTH legs, with its own base_dir / revocation_path, in id order
    assert calls == [("panic", "/home/a"), ("revoke", "SIGNED-DOC", "/rev/a"),
                     ("panic", "/home/b"), ("revoke", "SIGNED-DOC", "/rev/b")]
    assert rep["totals"] == {"instances": 2, "panic_ok": 2, "revoke_ok": 2,
                             "revoke_refused": 0, "revoke_error": 0}
    assert rep["revocation_supplied"] is True


def test_fan_out_kill_fails_revoke_closed_without_owner_signature():
    """Safe-negative: with NO owner-signed revocation the revoke leg is REFUSED (m-of-n authorization is
    required and unchanged) — but containment (run_panic) still runs, and the revoke primitive is NEVER
    called with a missing/forged signature."""
    revoke_called = []
    rep = fm.fan_out_kill(
        [fm.FleetInstance("vm-a", base_dir="/home/a", revocation_path="/rev/a")],
        signed_revocation=None,
        panic_fn=lambda *, base_dir: 0,
        revoke_fn=lambda signed, path: revoke_called.append((signed, path)))
    assert revoke_called == []                                     # the revoke primitive was never invoked
    r = rep["instances"][0]
    assert r["panic"]["ok"] is True and r["panic"]["status"] == "contained"
    assert r["revoke"]["ok"] is False and r["revoke"]["status"] == "refused"
    assert rep["totals"]["revoke_refused"] == 1 and rep["revocation_supplied"] is False


def test_fan_out_kill_is_total_when_a_primitive_raises():
    """One instance's containment failure must never stop the fan-out; it is reported, not raised."""
    def boom_panic(*, base_dir):
        if base_dir == "/home/a":
            raise OSError("systemctl unavailable")
        return 0

    rep = fm.fan_out_kill(
        [fm.FleetInstance("vm-a", base_dir="/home/a"), fm.FleetInstance("vm-b", base_dir="/home/b")],
        signed_revocation="S", panic_fn=boom_panic, revoke_fn=lambda s, p: p)
    by = {r["instance_id"]: r for r in rep["instances"]}
    assert by["vm-a"]["panic"]["status"] == "error" and by["vm-a"]["panic"]["ok"] is False
    assert by["vm-b"]["panic"]["ok"] is True
    assert rep["totals"]["panic_ok"] == 1


# The framework-dependent CLI verbs that drive these primitives — `vigil fleet kill` (_cmd_fleet_kill) and
# `vigil sign-revocation` (_cmd_sign_revocation), whose handlers lazy-import framework.v2.entitlement.* —
# live in test_fleet_kill_sign.py (offense-leg only; it skips cleanly in the keyless sovereign P5 leg). See
# that file for the framework-gated kill/sign tests. Everything in THIS file is keyless-safe by construction.


# --------------------------------------------------------------------------------------------------
# roster loading
# --------------------------------------------------------------------------------------------------


def test_load_roster_accepts_object_and_bare_list(tmp_path):
    obj = tmp_path / "o.json"
    obj.write_text(json.dumps({"instances": [{"instance_id": "a"}, {"instance_id": "b"}]}), encoding="utf-8")
    lst = tmp_path / "l.json"
    lst.write_text(json.dumps([{"instance_id": "c", "base_dir": "/x"}]), encoding="utf-8")
    assert [i.instance_id for i in fm.load_roster(str(obj))] == ["a", "b"]
    got = fm.load_roster(str(lst))
    assert got[0].instance_id == "c" and got[0].base_dir == "/x"


def test_load_roster_rejects_an_instance_without_id(tmp_path):
    p = tmp_path / "r.json"
    p.write_text(json.dumps({"instances": [{"snapshot": "s.json"}]}), encoding="utf-8")
    with pytest.raises(ValueError):
        fm.load_roster(str(p))
