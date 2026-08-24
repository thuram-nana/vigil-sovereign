"""`sigil doctor` fails when a records-bearing host has no signed head (issue #530, W16-STD-4 sub-part 4).

The reference-host defect: a spine that HOLDS RECORDS but has no valid owner-signed head served un-anchored
memory with no tamper-evidence, and nothing failed. `sigil doctor` now carries a REQUIRED `signed_head`
check that flips its exit code.

FAIL WITHOUT THE FIX: on the pre-#530 tree cmd_doctor has no signed_head check, so a records-without-a-head
host exits 0 (this test's first assertion fails).
NEGATIVE CONTROL (the exit is read, not constant): the SAME host, once `sigil sign` writes a valid head,
exits 0. And an empty pristine box (no records, no head) also exits 0 — it is not the defect.

Pure-Python; runs in the required "SIGIL governor gates (P7)" job.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

import sigil.spine.checkpoint as _cp
import sigil.spine.floor as _fl
from sigil import cli
from sigil.spine import health as _health
from sigil.spine.store import SpineStore


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    """Isolate the owner head + keys + floor so verify_checkpoint reads THIS test's head, and fake the
    heavy doctor dependencies (vault / kernel pin / config-drift / shared security block) so only the
    signed_head verdict drives the exit code."""
    import sigil.config as cfg
    import sigil.governor.integrity as integ
    from vigil_integration import doctor as idoc

    head = tmp_path / "head.json"
    keys = tmp_path / "keys"
    monkeypatch.setattr(_cp, "HEAD_PATH", head)
    monkeypatch.setattr(cfg, "HEAD_PATH", head, raising=False)
    monkeypatch.setattr(_cp, "KEYS_DIR", keys)
    monkeypatch.setattr(_cp, "_PRIV", keys / "owner.priv")
    monkeypatch.setattr(_cp, "_PUB", keys / "owner.pub")
    monkeypatch.setattr(_fl, "FLOOR_PATH", tmp_path / "floor.json")

    # heavy doctor deps → benign fakes (advisory, never a required failure of their own)
    monkeypatch.setattr(cfg, "doctor", lambda: [("sigil_home_writable", True, "writable")])
    monkeypatch.setattr(cfg, "effective_config", lambda: {"SCOPE": "sigil"})
    # the REAL owner_vault is left in place (plaintext at rest in the isolated KEYS_DIR) so `sigil sign` /
    # checkpoint can read+write the owner key in the negative-control test; its enabled()/status() are advisory.
    monkeypatch.setattr(integ, "kernel_pin_status", lambda: ("**", "unpinned"))
    monkeypatch.setattr(integ, "config_drift", list)
    monkeypatch.setattr(idoc, "find_repo_root", lambda: tmp_path)
    monkeypatch.setattr(idoc, "security_report", lambda repo: {
        "posture": [], "backup_timers": [],
        "production_gate": {"armed": False, "posture": None, "ok": True, "controls": [], "unmet": []}})
    return head


def _store(tmp_path, monkeypatch, n):
    s = SpineStore(tmp_path / "spine.jsonl")
    s.migrate()
    for i in range(n):
        s.append(kind="message", source="t", actor="u", payload={"text": f"m{i}"})
    # the doctor's probe reads the process store; point it at THIS isolated one.
    monkeypatch.setattr(cli, "_signed_head_doctor", lambda: _health.signed_head_health(s))
    return s


def _exit(as_json=False):
    with pytest.raises(SystemExit) as exc:
        cli.cmd_doctor(SimpleNamespace(json=as_json))
    return int(exc.value.code or 0)


def test_records_without_signed_head_fails_doctor(tmp_path, monkeypatch, isolated):
    _store(tmp_path, monkeypatch, n=16)
    assert not isolated.exists()                       # no head signed
    assert _exit() != 0, "a records-bearing host with no signed head must FAIL `sigil doctor`"


def test_signed_head_passes_doctor(tmp_path, monkeypatch, isolated):
    # NEGATIVE CONTROL: sign the head → the SAME host now passes (the exit is read, not stuck-failing).
    s = _store(tmp_path, monkeypatch, n=16)
    _cp.checkpoint(s)
    assert isolated.exists()
    assert _exit() == 0


def test_empty_pristine_box_passes_doctor(tmp_path, monkeypatch, isolated):
    # an empty box with no head is a pristine install, not the defect — doctor stays green.
    _store(tmp_path, monkeypatch, n=0)
    assert _exit() == 0
