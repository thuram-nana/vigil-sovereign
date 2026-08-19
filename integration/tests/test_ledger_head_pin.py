"""W10-4 #476 — a TRUNCATED present ledger must FAIL closed against a durable OUT-OF-BASE head/count pin.

`_load_and_verify_ledger` (fixed in #558 to fail-closed on an ABSENT file) still verified a present-but-
TRUNCATED ledger clean: it read the ledger and called `verify_ledger` with NO pin, and internal consistency
alone cannot see that the tail was dropped (a valid prefix is itself internally consistent). This wires a
durable head+count pin, persisted in the HOST-LEVEL attestation dir (OUTSIDE the base dir, so `rm -rf <base>`
cannot erase it), into the CLI verify path:

  * a populated ledger with a MATCHING pin verifies;
  * dropping its last record now FAILS closed (pinned count/head mismatch);
  * a fresh ledger with NO pin still verifies honestly and is REPORTED as unpinned (no false truncation claim);
  * the absent-file case from #558 still fails closed.

Fail-before / pass-after is provable by reverting the CLI hunk (stop consulting the pin): the truncated
ledger then reports VERIFIED again.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from vigil_integration.attestation import (
    MonotonicAnchor,
    OperatorIdentity,
    fingerprint,
    load_or_create_operator_keypair,
    make_ledger_writer,
    operator_signer,
    read_ledger,
    record_usage,
)
from vigil_integration.attestation import anchor as _anchor
from vigil_integration.attestation import head_pin as _head_pin
from vigil_integration.cli import _cmd_verify_ledger


def _provision(base_dir: Path):
    kp = load_or_create_operator_keypair(path=str(base_dir / "operator.key"))
    op = OperatorIdentity(
        os_login="kali", git_name="Op", git_email="op@example.test",
        key_fingerprint=fingerprint(kp.public_key_b64), hostname="kali",
    )
    return kp, op


def _write_records(kp, op, ledger_path: Path, n: int) -> None:
    signer = operator_signer(keypair=kp)
    writer = make_ledger_writer(str(ledger_path))
    prev = "0" * 64
    for i in range(n):
        att = record_usage(
            operator=op, action="nmap 127.0.0.1", target="http://127.0.0.1/",
            phase="informational", at=f"2026-07-21T00:0{i}:00Z", prev_hash=prev, signer=signer,
            seq=i, anchor=MonotonicAnchor(value=10 * (i + 1), grounded="software"),
        )
        assert att is not None
        writer(att)
        prev = att.record_hash


# ============================ head_pin store unit behavior ============================


def test_head_pin_roundtrips_and_is_path_bound(tmp_path, monkeypatch):
    monkeypatch.setattr(_anchor, "DEFAULT_STATE_DIR", tmp_path / "host")
    ledger = tmp_path / "a" / "usage-ledger.jsonl"
    assert _head_pin.read_head_pin(ledger) is None                 # absent → unpinned (honest)
    assert _head_pin.write_head_pin(ledger, head="deadbeef", count=3) is True
    pin = _head_pin.read_head_pin(ledger)
    assert pin is not None and pin.head == "deadbeef" and pin.count == 3
    # a pin written for one ledger path does NOT answer for a different path (keyed by abspath).
    assert _head_pin.read_head_pin(tmp_path / "b" / "usage-ledger.jsonl") is None
    # the pin lives OUTSIDE the ledger's dir — under the host state dir.
    assert (tmp_path / "host").exists() and not (tmp_path / "a" / "head-pins").exists()


def test_head_pin_rejects_bad_types_and_corrupt_files(tmp_path, monkeypatch):
    monkeypatch.setattr(_anchor, "DEFAULT_STATE_DIR", tmp_path / "host")
    ledger = tmp_path / "usage-ledger.jsonl"
    assert _head_pin.write_head_pin(ledger, head="", count=3) is False        # empty head rejected
    assert _head_pin.write_head_pin(ledger, head="h", count=True) is False     # bool is not a count
    assert _head_pin.write_head_pin(ledger, head="h", count=-1) is False       # negative count rejected
    assert _head_pin.read_head_pin(ledger) is None                            # nothing was written
    # a corrupt pin file degrades to unpinned (honest), never a crash.
    assert _head_pin.write_head_pin(ledger, head="h", count=1) is True
    from vigil_integration.attestation.head_pin import _pin_file
    _pin_file(ledger).write_text("{not json", encoding="utf-8")
    assert _head_pin.read_head_pin(ledger) is None


# ============================ the CLI verify path, pinned ============================


def test_populated_ledger_with_matching_pin_verifies(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(_anchor, "DEFAULT_STATE_DIR", tmp_path / "host")
    base = tmp_path / "base"
    base.mkdir()
    kp, op = _provision(base)
    ledger = tmp_path / "usage-ledger.jsonl"
    _write_records(kp, op, ledger, 3)
    recs = read_ledger(ledger)
    _head_pin.write_head_pin(ledger, head=recs[-1].record_hash, count=len(recs))

    rc = _cmd_verify_ledger(SimpleNamespace(path=str(ledger), base_dir=str(base)))
    out = capsys.readouterr().out
    assert rc == 0
    assert "VERIFIED" in out and "3 records" in out
    assert "durable head anchor pinned" in out                    # reported as pinned, honestly


def test_truncated_tail_fails_closed_against_the_pin(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(_anchor, "DEFAULT_STATE_DIR", tmp_path / "host")
    base = tmp_path / "base"
    base.mkdir()
    kp, op = _provision(base)
    ledger = tmp_path / "usage-ledger.jsonl"
    _write_records(kp, op, ledger, 3)
    recs = read_ledger(ledger)
    _head_pin.write_head_pin(ledger, head=recs[-1].record_hash, count=len(recs))   # pin at 3

    # drop the last record — a truncated tail. The ledger's prefix is still internally consistent.
    lines = ledger.read_text(encoding="utf-8").splitlines()
    ledger.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")
    assert len(read_ledger(ledger)) == 2

    rc = _cmd_verify_ledger(SimpleNamespace(path=str(ledger), base_dir=str(base)))
    out = capsys.readouterr().out
    assert rc != 0                                                # fail-closed
    assert "FAILED" in out and "VERIFIED" not in out.replace("records — VERIFIED", "")
    assert "truncated" in out or "dropped" in out                 # names the tail-truncation


def test_fresh_ledger_without_a_pin_verifies_but_reports_unpinned(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(_anchor, "DEFAULT_STATE_DIR", tmp_path / "host")
    base = tmp_path / "base"
    base.mkdir()
    kp, op = _provision(base)
    ledger = tmp_path / "usage-ledger.jsonl"
    _write_records(kp, op, ledger, 2)                             # a real ledger, but NO pin was persisted
    assert _head_pin.read_head_pin(ledger) is None

    rc = _cmd_verify_ledger(SimpleNamespace(path=str(ledger), base_dir=str(base)))
    out = capsys.readouterr().out
    assert rc == 0                                                # verifies on internal consistency
    assert "VERIFIED" in out
    assert "UNPINNED" in out                                      # honest: no truncation protection claimed


def test_absent_file_still_fails_closed(tmp_path, monkeypatch, capsys):
    # #558 regression: an absent ledger is an evidence-integrity failure regardless of any pin.
    monkeypatch.setattr(_anchor, "DEFAULT_STATE_DIR", tmp_path / "host")
    base = tmp_path / "base"
    base.mkdir()
    _provision(base)
    missing = tmp_path / "nope" / "usage-ledger.jsonl"
    rc = _cmd_verify_ledger(SimpleNamespace(path=str(missing), base_dir=str(base)))
    out = capsys.readouterr().out
    assert rc != 0 and "ABSENT" in out


# ============================ the WRITER side: wiring persists the pin on attest ============================


def test_wiring_persists_a_head_pin_on_attest_out_of_base(tmp_path, monkeypatch):
    """End-to-end: build_engine's attest closure writes the durable pin OUT of base, so a subsequent
    truncation is caught. Proves the producer half of the mechanism (the CLI tests prove the consumer)."""
    import pytest
    pytest.importorskip("framework.v2.authority.charter", reason="CRUCIBLE (offense) not importable here")

    from framework.v2.agents import blackboard as _bb
    from vigil_integration.agent.state import ActionType, LLMDecision
    from vigil_integration.live.think_claude import ReplayThinker
    from vigil_integration.live.wiring import EngineConfig, build_engine, provision_authority

    monkeypatch.setenv("CRUCIBLE_ROOT", str(tmp_path / "crucible-root"))
    db = tmp_path / "bb.sqlite"
    monkeypatch.setattr(_bb, "open_blackboard", lambda **_kw: _bb.Blackboard(db_path=db))
    host_dir = tmp_path / "host-attest"
    monkeypatch.setattr(_anchor, "DEFAULT_STATE_DIR", host_dir)

    def _echo_runner(argv, *, timeout=0, output_cap=1 << 20):
        return SimpleNamespace(exit_code=0, stdout="ok", stderr="", timed_out=False, truncated=False)

    base = tmp_path / "live"
    prov = provision_authority(slug="loopback", scope=["127.0.0.1"])
    cfg = EngineConfig(slug="loopback", base_dir=str(base), replay=ReplayThinker([
        LLMDecision(action=ActionType.COMPLETE, summary="done")]), provisioned=prov,
        runner=_echo_runner, max_iterations=4, owner_approves_offense=True)
    build_engine(cfg).engage("http://127.0.0.1:18080/search?q=1", objective="smoke")

    ledger = base / "usage-ledger.jsonl"
    recs = read_ledger(ledger)
    assert len(recs) >= 1
    pin = _head_pin.read_head_pin(ledger)
    assert pin is not None                                        # the pin was persisted...
    assert pin.head == recs[-1].record_hash and pin.count == len(recs)   # ...matching the ledger head/count
    # and it lives OUT of base — surviving a base wipe.
    assert str(host_dir) not in str(base) and host_dir.exists()
