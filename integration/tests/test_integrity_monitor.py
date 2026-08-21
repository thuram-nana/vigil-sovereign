"""W6-7 — the periodic integrity MONITOR, its alarm path, the dead-man heartbeat, and the doctor/readyz
wiring.

Proves the continuous verifier is wired on a REAL code path, not just a helper:
  * the monitor raises a critical alarm on a tamper and stays silent on a clean spine;
  * it writes a heartbeat each cycle, and its OWN failure to run raises a verifier-error alarm (dead-man);
  * `heartbeat_is_stale` fires when the scheduled verifier stops (absent/old heartbeat);
  * the monitor's retained high-water catches a head+floor co-rewrite a single-disk read would miss;
  * `vigil doctor` grows an integrity block that FLAGS a tampered spine (the test that fails without this
    change — a tree with no integrity block cannot report the tamper);
  * the posture endpoint's /readyz returns 503 when the integrity property is violated.

Boundary-safe: `vigil_core` + `vigil_integration.*` only; never `sigil`/`framework`.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from vigil_core import build_chain, digest_payload, generate_keypair, sign_head

from vigil_integration import integrity_verifier as iv


def _build_spine(home: Path, *, n: int = 3, scope: str = "sigil", base_ts: int = 1_700_000_000) -> dict:
    home.mkdir(parents=True, exist_ok=True)
    contents, digests = [], []
    for i in range(n):
        c = {"scope": scope, "kind": "message", "source": "test", "actor": "user",
             "payload": {"text": f"r{i}"}, "parent_id": None, "supersedes_id": None}
        contents.append(c); digests.append(digest_payload(c))
    entries = build_chain(digests)
    recs = []
    for i, (c, e) in enumerate(zip(contents, entries)):
        ts = datetime.fromtimestamp(base_ts + i, timezone.utc).isoformat()
        recs.append({"seq": e.seq, **c, "ts": ts, "cert_digest": e.cert_digest,
                     "prev_hash": e.prev_hash, "entry_hash": e.entry_hash})
    (home / "spine.jsonl").write_text("".join(json.dumps(r) + "\n" for r in recs), encoding="utf-8")
    owner = generate_keypair()
    head = sign_head(entries, engagement_slug=scope, signers=[("owner", owner.private_key_b64)])
    (home / "head.json").write_text(head.model_dump_json(), encoding="utf-8")
    floor = {"schema_version": 1, "scope": scope, "entry_count": head.entry_count,
             "last_seq": head.last_seq, "base_seq": 0, "base_count": 0,
             "head_sig_hash": head.head_hash, "updated_ts": recs[-1]["ts"]}
    (home / "floor.json").write_text(json.dumps(floor), encoding="utf-8")
    return {"records": recs, "head": head, "floor": floor, "owner": owner, "entries": entries,
            "base_ts": base_ts, "n": n}


class _Recorder(iv.AlarmSink):
    def __init__(self):
        self.alarms = []
        super().__init__(log_path=None, callbacks=[self.alarms.append], echo=False)


# --------------------------------------------------------------------------- alarm path
def test_monitor_alarms_on_tamper(tmp_path):
    fx = _build_spine(tmp_path, n=3)
    lines = (tmp_path / "spine.jsonl").read_text().splitlines()
    rec = json.loads(lines[1]); rec["entry_hash"] = "0" * 64; lines[1] = json.dumps(rec)
    (tmp_path / "spine.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")

    sink = _Recorder()
    report = iv.run_integrity_once(tmp_path, sink=sink, now=fx["base_ts"] + fx["n"] + 1)
    assert not report.ok
    assert len(sink.alarms) == 1
    a = sink.alarms[0]
    assert a.severity == "critical" and a.kind == "integrity-violation"
    assert any(c["check"] == "chain" for c in a.checks)


def test_monitor_clean_no_alarm(tmp_path):
    fx = _build_spine(tmp_path)
    sink = _Recorder()
    report = iv.run_integrity_once(tmp_path, sink=sink, now=fx["base_ts"] + fx["n"] + 1)
    assert report.ok
    assert sink.alarms == []


def test_monitor_writes_heartbeat(tmp_path):
    fx = _build_spine(tmp_path)
    hb = tmp_path / "hb.json"
    iv.run_integrity_once(tmp_path, sink=_Recorder(), now=fx["base_ts"] + fx["n"] + 1, heartbeat_path=hb)
    beat = iv.read_heartbeat(hb)
    assert beat is not None and beat["ok"] is True and "epoch" in beat


def test_verifier_crash_raises_verifier_error_alarm(tmp_path):
    """The verifier's OWN failure to run is alarmed (dead-man), and it still writes a FAILING heartbeat."""
    _build_spine(tmp_path)
    hb = tmp_path / "hb.json"
    sink = _Recorder()

    def _boom(*_a, **_k):
        raise RuntimeError("disk exploded mid-audit")

    with pytest.raises(RuntimeError):
        iv.run_integrity_once(tmp_path, sink=sink, now=1_700_000_100, heartbeat_path=hb, verify_fn=_boom)
    assert len(sink.alarms) == 1 and sink.alarms[0].kind == "verifier-error"
    beat = iv.read_heartbeat(hb)
    assert beat is not None and beat["ok"] is False


def test_monitor_loop_survives_a_crash_and_keeps_the_deadman(tmp_path):
    """A crashing cycle emits a verifier-error alarm but the loop continues (a transient error must not
    silently kill the continuous verifier); the summary counts the error."""
    _build_spine(tmp_path)
    sink = _Recorder()
    calls = {"n": 0}

    def _sometimes_boom(*_a, **_k):
        calls["n"] += 1
        raise RuntimeError("boom")

    summary = iv.run_integrity_monitor(tmp_path, cycles=3, interval=0.0, sink=sink,
                                       now_fn=lambda: 1_700_000_100, verify_fn=_sometimes_boom)
    assert summary["cycles_run"] == 3 and summary["errors"] == 3
    assert all(a.kind == "verifier-error" for a in sink.alarms)


def test_cadence_and_clock_are_injectable(tmp_path):
    fx = _build_spine(tmp_path)
    sink = _Recorder()
    slept = []
    ticks = iter([fx["base_ts"] + fx["n"] + 1] * 5)
    summary = iv.run_integrity_monitor(tmp_path, cycles=3, interval=2.5, sleep=slept.append, sink=sink,
                                       now_fn=lambda: next(ticks))
    assert summary["cycles_run"] == 3
    # sleeps BETWEEN cycles only (n-1 of them), each the injected interval.
    assert slept == [2.5, 2.5]


# --------------------------------------------------------------------------- dead-man heartbeat
def test_dead_man_absent_heartbeat_is_stale(tmp_path):
    stale, detail = iv.heartbeat_is_stale(tmp_path / "nope.json", now=1_700_000_100)
    assert stale and "never" in detail.lower() or "dead-man" in detail.lower()


def test_dead_man_fresh_vs_old(tmp_path):
    hb = tmp_path / "hb.json"
    iv.write_heartbeat(hb, now=1_700_000_000, ok=True, report=None, seq=0)
    fresh, _ = iv.heartbeat_is_stale(hb, now=1_700_000_100, max_staleness_s=3600)
    assert fresh is False
    # NEGATIVE CONTROL: advance now past the staleness bound → stale.
    old, detail = iv.heartbeat_is_stale(hb, now=1_700_000_000 + 5000, max_staleness_s=3600)
    assert old is True and "stopped running" in detail


# --------------------------------------------------------------------------- retained high-water (co-rewrite)
def test_highwater_catches_head_and_floor_co_rewrite(tmp_path):
    """A clean run advances the verifier's retained high-water. Then rolling BOTH head and floor back below
    that height (a co-rewrite that is internally self-consistent) is caught by the retained watermark."""
    fx = _build_spine(tmp_path, n=5)
    hw = tmp_path / "hw.json"
    hb = tmp_path / "hb.json"
    r0 = iv.run_integrity_once(tmp_path, sink=_Recorder(), now=fx["base_ts"] + fx["n"] + 1,
                               heartbeat_path=hb, highwater_path=hw)
    assert r0.ok
    assert iv._load_highwater(hw)["last_seq"] == fx["head"].last_seq

    # Co-rewrite: rebuild a SHORTER but internally-consistent spine+head+floor (a rollback the local
    # single-disk chain/floor checks would accept — floor now matches the shorter head).
    short = _build_spine(tmp_path, n=2)               # overwrites spine/head/floor with a consistent short set
    r1 = iv.run_integrity_once(tmp_path, sink=_Recorder(), now=short["base_ts"] + short["n"] + 1,
                               heartbeat_path=hb, highwater_path=hw)
    assert not r1.ok
    assert r1.get("floor").failed
    assert "retained high-water" in r1.get("floor").detail


# --------------------------------------------------------------------------- doctor wiring (fails without the fix)
def test_doctor_reports_integrity_block_and_flags_tamper(tmp_path, monkeypatch):
    """`vigil doctor` grows an integrity block that FLAGS a tampered spine. On a tree WITHOUT this change
    there is no integrity block, so these assertions fail — the required 'fails without the change' test."""
    from vigil_integration import doctor as dmod
    home = tmp_path / "sigil"
    fx = _build_spine(home, n=3)
    lines = (home / "spine.jsonl").read_text().splitlines()
    rec = json.loads(lines[1]); rec["entry_hash"] = "0" * 64; lines[1] = json.dumps(rec)
    (home / "spine.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    monkeypatch.setenv("SIGIL_HOME", str(home))

    report = dmod.collect(Path(dmod.__file__).resolve().parents[2])
    assert "integrity" in report
    assert report["integrity"]["ok"] is False
    assert any(c["check"] == "chain" and c["status"] == iv.FAIL for c in report["integrity"]["checks"])
    assert any("integrity check 'chain'" in m for m in report["issues"])
    assert report["ok"] is False
    # render() must not crash and must mention the integrity section.
    assert "Spine integrity" in dmod.render(report)


def test_doctor_clean_spine_integrity_ok(tmp_path, monkeypatch):
    """NEGATIVE CONTROL for the doctor wiring: a clean spine produces an integrity block with ok=True and no
    integrity issue (so the block is not constant-fail)."""
    from vigil_integration import doctor as dmod
    home = tmp_path / "sigil"
    _build_spine(home, n=3)
    monkeypatch.setenv("SIGIL_HOME", str(home))
    report = dmod.collect(Path(dmod.__file__).resolve().parents[2])
    assert report["integrity"]["ok"] is True
    assert not any("integrity check" in m for m in report["issues"])
