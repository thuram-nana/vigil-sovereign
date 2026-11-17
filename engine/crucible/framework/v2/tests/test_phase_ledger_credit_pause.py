"""M1c-2b — a metered run's terminal credit stop RE-RAISES past the PhaseLedger swallow-wrapper.

``PhaseLedger.run_phase`` is fail-open: a best-effort reasoning phase that raises is recorded ``failed`` and
returns its default, so one broken phase never sinks the run. M1c-2b makes ONE deliberate exception: a
``CreditsExhausted`` (the model gateway's terminal credit stop in a metered run) is RE-RAISED past the wrapper —
the phase is recorded ``halted`` (reversible, not a failure) and the exception propagates to the engage seam,
which holds the lease for a top-up + resume. Without this, a credit stop mid-reasoning would be SWALLOWED and the
run would settle COMPLETED on a half-reasoned deliverable.

DEFAULT-OFF: an unmetered run never raises ``CreditsExhausted``, so ``run_phase`` is byte-identical for every
other exception (still swallowed → ``failed`` → default).

Mutation-verify target: drop the ``except CreditsExhausted`` branch (the credit stop is swallowed like any other
error) -> test_a_credit_stop_re_raises_and_records_halted.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from framework.v2.common import paths as _paths
from framework.v2.common.errors import CreditsExhausted
from framework.v2.phase_ledger import PhaseLedger


@pytest.fixture()
def ledger_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(_paths, "phase_ledger_path", lambda s: tmp_path / f"{s}.phases.jsonl")
    monkeypatch.setattr(_paths, "phase_report_path", lambda s: tmp_path / f"{s}.report.json")
    return lambda s="alpha": tmp_path / f"{s}.phases.jsonl"


def _records(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    return [json.loads(ln) for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]


def test_a_credit_stop_re_raises_and_records_halted(ledger_path):
    led = PhaseLedger("alpha")

    def _fn():
        raise CreditsExhausted("the model gateway stopped this run: credits exhausted")

    with pytest.raises(CreditsExhausted):
        led.run_phase("chaining", _fn)                    # RE-RAISED past the swallow-wrapper (not returned default)
    statuses = [(r["phase"], r["status"]) for r in _records(ledger_path("alpha"))]
    assert ("chaining", "started") in statuses
    assert ("chaining", "halted") in statuses             # reversible pause, never ``completed`` and never ``failed``
    assert ("chaining", "failed") not in statuses
    assert ("chaining", "completed") not in statuses


def test_an_ordinary_phase_error_is_still_swallowed(ledger_path):
    # DEFAULT-OFF / byte-identical: a NON-credit error stays fail-open — swallowed, recorded ``failed``, default
    # returned — exactly as before this slice.
    led = PhaseLedger("alpha")
    out = led.run_phase("chaining", lambda: (_ for _ in ()).throw(RuntimeError("boom")), default="DFLT")
    assert out == "DFLT"
    statuses = [(r["phase"], r["status"]) for r in _records(ledger_path("alpha"))]
    assert ("chaining", "failed") in statuses
    assert ("chaining", "halted") not in statuses


def test_a_completing_phase_is_unchanged(ledger_path):
    led = PhaseLedger("alpha")
    out = led.run_phase("chaining", lambda: "value")
    assert out == "value"
    statuses = [(r["phase"], r["status"]) for r in _records(ledger_path("alpha"))]
    assert ("chaining", "completed") in statuses
