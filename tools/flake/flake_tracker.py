"""W11-5 (#486) — flake tracking: historical pass rates + EXPLICIT quarantine.

"A skipped proof and a passing proof are the same colour on a dashboard." A flaky test that is silently
skipped, or a green quarantine no reviewer can see, is exactly the drift the sovereign CI doctrine
forbids. This module makes both observable and, for quarantine, ENFORCED:

  * historical pass rates — every CI run of the concurrency stress suite appends a one-line outcome record
    to a JSONL ledger (``docs/flake/ledger.jsonl`` locally; a per-run ``flake-ledger`` artifact in CI,
    since a PR runner cannot push). ``pass_rate`` / ``historical_report`` compute the pass rate per test id
    over that ledger, and ``flaky_tests`` surfaces the quarantine CANDIDATES (below a threshold over a
    minimum number of runs) — a signal, never an automatic skip.

  * explicit quarantine — a test may only be quarantined (skipped as known-flaky) if it is listed in
    ``docs/flake/quarantine.json`` with a reason and a tracking issue. ``require_registered_quarantine``
    is the gate: it RAISES for an UNREGISTERED id, so a test physically cannot skip itself as "flaky"
    without a registry entry a reviewer can read. That is what makes quarantine explicit, not silent.

STDLIB ONLY (json / pathlib / argparse / datetime) so the guard test that exercises it runs in the
minimal ``sigil-governor`` job with no extra install. No network, no third-party import.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
from pathlib import Path
from typing import Iterable

_REPO = Path(__file__).resolve().parents[2]
DEFAULT_LEDGER = _REPO / "docs" / "flake" / "ledger.jsonl"
DEFAULT_QUARANTINE = _REPO / "docs" / "flake" / "quarantine.json"

# Outcomes that COUNT toward a pass rate. A "skip" is deliberately EXCLUDED from the denominator: a
# skipped run is neither a pass nor a fail, and counting it would let quarantining a test inflate its
# rate. It is still recorded (so a suddenly-all-skipped test is visible), just not scored.
_PASSING = {"pass"}
_SCORED = {"pass", "fail", "error"}
VALID_OUTCOMES = _SCORED | {"skip"}


class QuarantineError(Exception):
    """A test tried to quarantine (skip-as-flaky) itself without a registry entry — refused, fail-closed."""


# --------------------------------------------------------------------------------------------------
# Ledger — append-only JSONL of {test_id, outcome, run_id, ts}.
# --------------------------------------------------------------------------------------------------
def record_outcome(ledger_path: Path | str, *, test_id: str, outcome: str,
                   run_id: str, ts: str | None = None) -> dict:
    """Append ONE outcome record to the JSONL ledger and return it. Refuses an unknown outcome so a typo
    can never silently corrupt a rate. Creates the parent dir + file on first write."""
    if outcome not in VALID_OUTCOMES:
        raise ValueError(f"unknown outcome {outcome!r} (valid: {sorted(VALID_OUTCOMES)})")
    if not test_id:
        raise ValueError("test_id must be non-empty")
    rec = {
        "test_id": test_id,
        "outcome": outcome,
        "run_id": run_id,
        "ts": ts or _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    p = Path(ledger_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as f:
        f.write(json.dumps(rec, sort_keys=True) + "\n")
    return rec


def read_ledger(ledger_path: Path | str) -> list[dict]:
    """Parse the JSONL ledger. A blank line is skipped; a malformed line RAISES (a corrupt ledger must be
    loud, not silently under-counted)."""
    p = Path(ledger_path)
    if not p.is_file():
        return []
    out: list[dict] = []
    for i, line in enumerate(p.read_text(encoding="utf-8").splitlines(), start=1):
        s = line.strip()
        if not s:
            continue
        try:
            rec = json.loads(s)
        except json.JSONDecodeError as e:
            raise ValueError(f"{p}: malformed ledger line {i}: {e}") from e
        if not (isinstance(rec, dict) and rec.get("test_id") and rec.get("outcome") in VALID_OUTCOMES):
            raise ValueError(f"{p}: ledger line {i} is not a valid outcome record: {rec!r}")
        out.append(rec)
    return out


def _records(ledger: Path | str | Iterable[dict]) -> list[dict]:
    if isinstance(ledger, (str, Path)):
        return read_ledger(ledger)
    return list(ledger)


def pass_rate(ledger: Path | str | Iterable[dict], test_id: str) -> dict:
    """Historical pass rate for one test id over the ledger. ``runs`` is the SCORED count (pass+fail+error;
    skips excluded); ``rate`` is passes/runs, or None when there are no scored runs yet."""
    recs = [r for r in _records(ledger) if r["test_id"] == test_id]
    scored = [r for r in recs if r["outcome"] in _SCORED]
    passes = sum(1 for r in scored if r["outcome"] in _PASSING)
    runs = len(scored)
    return {
        "test_id": test_id,
        "passes": passes,
        "runs": runs,
        "skips": sum(1 for r in recs if r["outcome"] == "skip"),
        "rate": (passes / runs) if runs else None,
    }


def historical_report(ledger: Path | str | Iterable[dict]) -> dict[str, dict]:
    recs = _records(ledger)
    ids = sorted({r["test_id"] for r in recs})
    return {tid: pass_rate(recs, tid) for tid in ids}


def flaky_tests(ledger: Path | str | Iterable[dict], *, threshold: float = 1.0,
                min_runs: int = 5) -> list[dict]:
    """Quarantine CANDIDATES: tests whose historical pass rate is BELOW ``threshold`` over at least
    ``min_runs`` scored runs. A signal for a human to triage + register — never an automatic skip."""
    report = historical_report(ledger)
    out = [st for st in report.values()
           if st["runs"] >= min_runs and st["rate"] is not None and st["rate"] < threshold]
    return sorted(out, key=lambda s: (s["rate"], s["test_id"]))


# --------------------------------------------------------------------------------------------------
# Quarantine — EXPLICIT (registry-backed) or refused.
# --------------------------------------------------------------------------------------------------
_QUARANTINE_REQUIRED = ("test_id", "reason", "issue", "since")


def load_quarantine(path: Path | str = DEFAULT_QUARANTINE) -> dict:
    """Load + validate the quarantine registry. Shape: ``{"version": 1, "quarantined": [ {...}, ... ]}``.
    An entry needs a non-empty test_id, reason, issue and since. Duplicate ids RAISE. An absent file is a
    valid EMPTY registry (nothing quarantined) — but a present-and-malformed file RAISES."""
    p = Path(path)
    if not p.is_file():
        return {"version": 1, "quarantined": []}
    data = json.loads(p.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("quarantined"), list):
        raise ValueError(f"{p}: quarantine registry must be an object with a 'quarantined' list")
    seen: set[str] = set()
    for e in data["quarantined"]:
        if not isinstance(e, dict):
            raise ValueError(f"{p}: quarantine entry is not an object: {e!r}")
        for k in _QUARANTINE_REQUIRED:
            if not e.get(k):
                raise ValueError(f"{p}: quarantine entry missing/empty {k!r}: {e!r}")
        if e["test_id"] in seen:
            raise ValueError(f"{p}: duplicate quarantine test_id: {e['test_id']!r}")
        seen.add(e["test_id"])
    return data


def quarantined_ids(quarantine: dict) -> set[str]:
    return {e["test_id"] for e in quarantine.get("quarantined", [])}


def is_registered_quarantine(test_id: str, quarantine: dict) -> bool:
    return test_id in quarantined_ids(quarantine)


def require_registered_quarantine(test_id: str, quarantine: dict | None = None) -> dict:
    """The GATE that makes quarantine explicit. Return the registry entry for ``test_id`` if it is
    registered; otherwise RAISE ``QuarantineError``. A caller that wants to skip a test as known-flaky
    must go through here, so an UNREGISTERED skip is impossible — there is no silent-quarantine path."""
    q = quarantine if quarantine is not None else load_quarantine()
    for e in q.get("quarantined", []):
        if e["test_id"] == test_id:
            return e
    raise QuarantineError(
        f"{test_id!r} is not in the quarantine registry ({DEFAULT_QUARANTINE.name}); quarantine is "
        f"EXPLICIT — add an entry with a reason + tracking issue before skipping this test as flaky")


def check_quarantine_explicit(observed_quarantine_skips: Iterable[str],
                              quarantine: dict) -> list[str]:
    """Given the test ids that were skipped AS QUARANTINE in a run, return those NOT in the registry — the
    silent-quarantine violations. Empty == every quarantine skip is explicitly registered."""
    registered = quarantined_ids(quarantine)
    return sorted(tid for tid in observed_quarantine_skips if tid not in registered)


def quarantine_skip(test_id: str, quarantine_path: Path | str = DEFAULT_QUARANTINE):
    """Test-side helper: skip ``test_id`` IFF it is a registered quarantine, else RAISE. Import pytest
    lazily so this module stays importable (and unit-testable) outside a pytest process."""
    entry = require_registered_quarantine(test_id, load_quarantine(quarantine_path))
    import pytest
    pytest.skip(f"QUARANTINED ({entry['issue']}): {entry['reason']}")


# --------------------------------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------------------------------
def _main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="flake_tracker", description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("record", help="append an outcome to the ledger")
    r.add_argument("--ledger", default=str(DEFAULT_LEDGER))
    r.add_argument("--test-id", required=True)
    r.add_argument("--outcome", required=True, choices=sorted(VALID_OUTCOMES))
    r.add_argument("--run-id", required=True)
    r.add_argument("--ts", default=None)

    rep = sub.add_parser("report", help="print the historical pass-rate report")
    rep.add_argument("--ledger", default=str(DEFAULT_LEDGER))
    rep.add_argument("--threshold", type=float, default=1.0)
    rep.add_argument("--min-runs", type=int, default=5)

    q = sub.add_parser("check-quarantine", help="validate the quarantine registry loads + is well-formed")
    q.add_argument("--quarantine", default=str(DEFAULT_QUARANTINE))

    args = ap.parse_args(argv)
    if args.cmd == "record":
        rec = record_outcome(args.ledger, test_id=args.test_id, outcome=args.outcome,
                             run_id=args.run_id, ts=args.ts)
        print(json.dumps(rec, sort_keys=True))
        return 0
    if args.cmd == "report":
        report = historical_report(args.ledger)
        print(json.dumps(report, indent=2, sort_keys=True))
        flaky = flaky_tests(args.ledger, threshold=args.threshold, min_runs=args.min_runs)
        if flaky:
            print(f"\nQUARANTINE CANDIDATES (rate < {args.threshold} over >= {args.min_runs} runs):")
            for st in flaky:
                print(f"  {st['test_id']}: {st['passes']}/{st['runs']} = {st['rate']:.3f}")
        return 0
    if args.cmd == "check-quarantine":
        q = load_quarantine(args.quarantine)
        print(f"quarantine registry OK: {len(q.get('quarantined', []))} entry(ies)")
        for e in q.get("quarantined", []):
            print(f"  {e['test_id']} — {e['issue']}: {e['reason']}")
        return 0
    return 2


if __name__ == "__main__":                                # pragma: no cover
    raise SystemExit(_main())
