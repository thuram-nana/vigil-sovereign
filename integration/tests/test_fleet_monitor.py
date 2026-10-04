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


def test_cmd_fleet_kill_refuses_without_yes(tmp_path, monkeypatch):
    """The CLI kill verb must refuse a fleet-wide hard-stop without --yes, and must NOT reach the driver."""
    roster = tmp_path / "roster.json"
    roster.write_text(json.dumps({"instances": [{"instance_id": "vm-a", "base_dir": "/home/a"}]}),
                      encoding="utf-8")

    def _must_not_run(*a, **k):
        raise AssertionError("fan_out_kill must not run without --yes")

    monkeypatch.setattr(fm, "fan_out_kill", _must_not_run)
    rc = cli._cmd_fleet_kill(SimpleNamespace(roster=str(roster), revocation="", reason="", yes=False))
    assert rc == 2


def test_cmd_fleet_kill_passes_a_loaded_signed_revocation(tmp_path, monkeypatch):
    """With --yes + a valid --revocation the CLI loads the SignedRevocation and hands it to the driver;
    the driver itself is stubbed so NO real run_panic / systemctl is touched by the test."""
    from framework.v2.entitlement import provision
    from framework.v2.entitlement.models import RevocationDocument
    from datetime import datetime, timezone

    _, priv = provision.new_authorizer("k1", "Owner One")
    doc = RevocationDocument(serial=1, issued_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
                             revoked_entitlement_ids=["ent-123"])
    signed = provision.sign_revocation(doc, {"k1": priv})
    rev_path = tmp_path / "revocation.json"
    rev_path.write_text(json.dumps(signed.model_dump(mode="json")), encoding="utf-8")
    roster = tmp_path / "roster.json"
    roster.write_text(json.dumps({"instances": [{"instance_id": "vm-a", "base_dir": "/home/a",
                                                  "revocation_path": str(tmp_path / "out-rev.json")}]}),
                      encoding="utf-8")

    seen = {}

    def _capture(roster_arg, *, signed_revocation, reason, **k):
        seen["sig"] = signed_revocation
        seen["n"] = len(list(roster_arg))
        return {"totals": {"instances": 1, "panic_ok": 1, "revoke_ok": 1, "revoke_refused": 0,
                           "revoke_error": 0}, "reason": reason, "revocation_supplied": True,
                "instances": [{"instance_id": "vm-a", "panic": {"status": "contained", "ok": True},
                               "revoke": {"status": "applied", "ok": True}}]}

    monkeypatch.setattr(fm, "fan_out_kill", _capture)
    rc = cli._cmd_fleet_kill(SimpleNamespace(roster=str(roster), revocation=str(rev_path),
                                             reason="drill", yes=True))
    assert rc == 0
    # the CLI handed the driver a REAL SignedRevocation parsed from disk (not None, not a raw string)
    assert seen["sig"].document.serial == 1
    assert seen["sig"].document.revoked_entitlement_ids == ["ent-123"]
    assert seen["n"] == 1


# --------------------------------------------------------------------------------------------------
# sign-revocation CLI verb wires the real sign_revocation library (owner ceremony, m-of-n unchanged)
# --------------------------------------------------------------------------------------------------


def test_cmd_sign_revocation_mints_a_verifiable_signed_list(tmp_path, capsys):
    """Positive: the verb signs with the real library and the output verifies against the authoriser's
    PUBLIC key — proving a genuine Ed25519 signature, not a stubbed blob."""
    from framework.v2.entitlement import provision
    from framework.v2.entitlement.canonical import revocation_signing_bytes
    from framework.v2.entitlement.crypto import verify_one as crypto_verify
    from framework.v2.entitlement.models import SignedRevocation

    pub, priv = provision.new_authorizer("owner-key-1", "Owner One")
    signers = tmp_path / "signers.json"
    signers.write_text(json.dumps({"owner-key-1": priv}), encoding="utf-8")
    out = tmp_path / "revocation.json"

    rc = cli._cmd_sign_revocation(SimpleNamespace(
        revoke=["ent-aaa", "ent-bbb"], serial=7, signers=str(signers),
        issued_at="2024-01-01T00:00:00+00:00", out=str(out)))
    assert rc == 0
    assert "serial=7" in capsys.readouterr().out

    signed = SignedRevocation.model_validate_json(out.read_text(encoding="utf-8"))
    assert signed.document.serial == 7
    assert signed.document.revoked_entitlement_ids == ["ent-aaa", "ent-bbb"]
    # the signature is REAL: it verifies against the authoriser public key over the canonical bytes
    msg = revocation_signing_bytes(signed.document)
    assert crypto_verify(pub.public_key_b64, msg, signed.signatures[0].signature_b64) is True


def test_cmd_sign_revocation_refuses_an_empty_signer_bundle(tmp_path, capsys):
    """Safe-negative: no signer keys ⇒ no signature (refuse with exit 2), never an unsigned 'revocation'."""
    signers = tmp_path / "signers.json"
    signers.write_text(json.dumps({}), encoding="utf-8")
    rc = cli._cmd_sign_revocation(SimpleNamespace(
        revoke=["ent-x"], serial=1, signers=str(signers), issued_at="", out=str(tmp_path / "r.json")))
    assert rc == 2
    assert not (tmp_path / "r.json").exists()
    assert "non-empty" in capsys.readouterr().err


def test_cmd_sign_revocation_warns_below_threshold(tmp_path, capsys, monkeypatch):
    """The advisory note fires when fewer than the trust root threshold sign — but the runtime, not this
    verb, is the authority: it still produces the (insufficient) signed document and warns."""
    from framework.v2.entitlement import provision

    # a 2-of-2 trust root, signed by only ONE authoriser
    a_pub, a_priv = provision.new_authorizer("a", "A")
    b_pub, _ = provision.new_authorizer("b", "B")
    tr = provision.build_trust_root([a_pub, b_pub], threshold=2)
    provision.write_trust_root(tr)                       # under CRUCIBLE_ROOT scratch (hermetic env)

    signers = tmp_path / "signers.json"
    signers.write_text(json.dumps({"a": a_priv}), encoding="utf-8")
    rc = cli._cmd_sign_revocation(SimpleNamespace(
        revoke=["ent-x"], serial=2, signers=str(signers),
        issued_at="2024-01-01T00:00:00+00:00", out=str(tmp_path / "r.json")))
    assert rc == 0
    out = capsys.readouterr().out
    assert "BELOW the trust root threshold" in out and "1 signer(s)" in out


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
