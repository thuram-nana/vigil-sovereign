"""W6-6 — `sigil doctor` is driven by the ONE shared check registry and honours the exit code.

`sigil doctor` used to be a disjoint self-check: no security-posture block, no machine-readable output, and
an exit code `make smoke` threw away with `|| true` (and which failed on a *missing optional dependency*,
which is exactly why it had to be discarded). It now:

* builds its report from ``vigil_core.doctor`` (the SAME registry `vigil doctor` uses) and renders the SAME
  shared security-posture block via ``vigil_integration.doctor.security_report`` — one implementation, two
  entry points;
* exits NON-ZERO when the opt-in production gate is armed and a control is bad, and — the NEGATIVE CONTROL —
  exits 0 when the same armed gate sees a good posture (so the exit is read, not constant);
* reclassifies optional dependencies as ADVISORY: a missing kernel binary no longer fails the doctor
  (that is the change that lets `make smoke` drop `|| true`), while an ACTIVE kernel tamper still does;
* supports ``--json``.

The tests that FAIL WITHOUT THE CHANGE: the old `cmd_doctor` failed (exit 1) on a missing kernel binary and
emitted no JSON / no posture block. Pure-Python; runs in the required "SIGIL governor gates (P7)" job.
"""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from sigil import cli


class _FakeVault:
    def __init__(self, enabled=False):
        self._enabled = enabled

    def enabled(self):
        return self._enabled

    def status(self):
        return "SEALED" if self._enabled else "UNSEALED — plaintext at rest"


def _install(monkeypatch, *, sovereign_rows, kernel_pin=("**", "unpinned"), gate):
    """Wire cmd_doctor's dependencies to controlled fakes. `sovereign_rows` is the config.doctor() list,
    `kernel_pin` the (mark, detail) pin status, `gate` the shared production-gate verdict dict."""
    import sigil.config as cfg
    import sigil.governor.integrity as integ
    import sigil.platform.vault as vault
    from vigil_integration import doctor as idoc

    monkeypatch.setattr(cfg, "doctor", lambda: list(sovereign_rows))
    monkeypatch.setattr(cfg, "effective_config", lambda: {"SCOPE": "sigil"})
    monkeypatch.setattr(vault, "owner_vault", lambda: _FakeVault(enabled=False))
    monkeypatch.setattr(integ, "kernel_pin_status", lambda: kernel_pin)
    monkeypatch.setattr(integ, "config_drift", list)
    monkeypatch.setattr(idoc, "find_repo_root", lambda: __import__("pathlib").Path("/nonexistent-repo"))
    monkeypatch.setattr(idoc, "security_report", lambda repo: {
        "posture": [{"control": "egress-gate", "state": "OFF", "detail": "no gateway"},
                    {"control": "vault", "state": "UNPROVISIONED", "detail": "keys plaintext"}],
        "backup_timers": [],
        "production_gate": gate,
    })


def _armed_gate(ok):
    unmet = [] if ok else [{"control": "vault", "state": "UNPROVISIONED", "requirement": "seal it"}]
    return {"armed": True, "posture": "production", "ok": ok, "controls": [], "unmet": unmet}


_INERT_GATE = {"armed": False, "posture": None, "ok": True, "controls": [], "unmet": []}
_ALL_GOOD_ROWS = [("sigil_home_writable", True, "/x writable"), ("kernel_binary", True, "/x/sigil-kernel"),
                  ("qdrant", True, "embedded"), ("keyring", True, "available")]


def _run(monkeypatch, capsys, *, as_json=False):
    with pytest.raises(SystemExit) as exc:
        cli.cmd_doctor(SimpleNamespace(json=as_json))
    out = capsys.readouterr().out
    return int(exc.value.code or 0), out


def test_exit_nonzero_when_armed_gate_is_bad(monkeypatch, capsys):
    _install(monkeypatch, sovereign_rows=_ALL_GOOD_ROWS, gate=_armed_gate(ok=False))
    code, _out = _run(monkeypatch, capsys)
    assert code != 0


def test_exit_zero_when_armed_gate_is_good(monkeypatch, capsys):
    # NEGATIVE CONTROL: the SAME armed path with a good posture exits 0 — the exit is read, not constant.
    _install(monkeypatch, sovereign_rows=_ALL_GOOD_ROWS, gate=_armed_gate(ok=True))
    code, _out = _run(monkeypatch, capsys)
    assert code == 0


def test_missing_kernel_binary_is_advisory_not_a_failure(monkeypatch, capsys):
    # THE fix that lets `make smoke` drop `|| true`: a missing kernel binary (advisory) no longer fails.
    rows = [("sigil_home_writable", True, "/x writable"), ("kernel_binary", False, "not found"),
            ("qdrant", False, "unreachable"), ("keyring", False, "not installed")]
    _install(monkeypatch, sovereign_rows=rows, gate=_INERT_GATE)
    code, _out = _run(monkeypatch, capsys)
    assert code == 0


def test_unwritable_sigil_home_is_required_failure(monkeypatch, capsys):
    # NEGATIVE CONTROL for the advisory reclassification: a REQUIRED sovereign check still fails the doctor.
    rows = [("sigil_home_writable", False, "NOT writable"), ("kernel_binary", True, "/x/sigil-kernel")]
    _install(monkeypatch, sovereign_rows=rows, gate=_INERT_GATE)
    code, _out = _run(monkeypatch, capsys)
    assert code != 0


def test_active_kernel_tamper_is_required_failure(monkeypatch, capsys):
    _install(monkeypatch, sovereign_rows=_ALL_GOOD_ROWS, kernel_pin=("!!", "tampered"), gate=_INERT_GATE)
    code, _out = _run(monkeypatch, capsys)
    assert code != 0


def test_json_output_is_machine_readable(monkeypatch, capsys):
    _install(monkeypatch, sovereign_rows=_ALL_GOOD_ROWS, gate=_INERT_GATE)
    code, out = _run(monkeypatch, capsys, as_json=True)
    doc = json.loads(out)
    assert code == 0 and doc["ok"] is True
    assert {"checks", "posture", "production_gate", "backup_timers"} <= set(doc)
    # the shared posture block is present, one entry per control.
    assert {p["control"] for p in doc["posture"]} == {"egress-gate", "vault"}


def test_human_output_renders_the_shared_posture_block(monkeypatch, capsys):
    _install(monkeypatch, sovereign_rows=_ALL_GOOD_ROWS, gate=_INERT_GATE)
    _code, out = _run(monkeypatch, capsys)
    assert "Security posture" in out
    assert "egress-gate:" in out
