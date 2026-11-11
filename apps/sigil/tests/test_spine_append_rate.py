"""Front C S1 — append-rate instrumentation (`sigil.spine.append_rate`, `sigil spine append-rate`).

What must hold: the report equals a brute-force count over the same timestamps (randomised differential); it is
READ-ONLY (a measured spine is byte-identical afterwards, and the append path never imports the module); it
carries NO built-in target (a ceiling is the caller's or absent); bad timestamps are counted, never guessed.
"""
from __future__ import annotations

import hashlib
import json
import random
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from sigil.spine import append_rate as ar
from sigil.spine.store import SpineStore

T0 = datetime(2026, 11, 1, 12, 0, 0, tzinfo=timezone.utc)


def _rec(offset_s: float, signal: "str | None" = "s", source: str = "t", kind: str = "event"):
    payload = {} if signal is None else {"signal": signal}
    return SimpleNamespace(ts=(T0 + timedelta(seconds=offset_s)).isoformat(), kind=kind, source=source,
                           payload=payload)


def _brute_peak(times: "list[float]", window: int) -> int:
    """The most appends in any [s, s + window) of whole seconds — the definition, computed the slow way."""
    secs = [int(t // 1) for t in times]
    if not secs:
        return 0
    return max(sum(1 for x in secs if s <= x < s + window) for s in range(min(secs) - window, max(secs) + 1))


# -- parse_ts ------------------------------------------------------------------------------------------------
def test_parse_ts_accepts_the_spine_format_z_and_naive_as_utc():
    want = T0.timestamp()
    assert ar.parse_ts(T0.isoformat()) == want
    assert ar.parse_ts("2026-11-01T12:00:00Z") == want
    assert ar.parse_ts("2026-11-01T12:00:00") == want                      # naive => UTC, not local time
    assert ar.parse_ts("2026-11-01T13:00:00+01:00") == want


def test_a_naive_ts_is_utc_whatever_the_process_timezone(monkeypatch):
    import time
    monkeypatch.setenv("TZ", "Asia/Tokyo")
    time.tzset()
    try:
        assert ar.parse_ts("2026-11-01T12:00:00") == T0.timestamp()
    finally:
        monkeypatch.undo()
        time.tzset()


@pytest.mark.parametrize("bad", [None, "", "yesterday", 1730462400, 20261101, 1.5, b"2026-11-01T12:00:00Z",
                                 {"ts": 1}, "Z"])
def test_parse_ts_refuses_what_it_cannot_read(bad):
    assert ar.parse_ts(bad) is None


# -- the rates -----------------------------------------------------------------------------------------------
def test_a_known_burst_is_reported_exactly():
    # 5 in second 0, 3 in second 1, then one lone record at second 30
    recs = [_rec(0.1 * i) for i in range(5)] + [_rec(1 + 0.1 * i) for i in range(3)] + [_rec(30.0)]
    rep = ar.measure(recs)
    assert rep["records"] == rep["dated"] == 9 and rep["undated"] == 0 and rep["out_of_order"] == 0
    assert rep["peak"]["1"] == {"appends": 5, "per_s": 5.0, "window_start": int(T0.timestamp())}
    assert rep["peak"]["10"]["appends"] == 8 and rep["peak"]["10"]["per_s"] == 0.8
    assert rep["peak"]["60"]["appends"] == 9 and rep["peak"]["60"]["per_s"] == 9 / 60
    assert rep["span_s"] == 30.0 and rep["mean_per_s"] == 9 / 30.0
    assert rep["first_ts"] == T0.timestamp() and rep["last_ts"] == T0.timestamp() + 30


def test_peak_matches_a_brute_force_count_on_random_streams():
    rng = random.Random(1106)
    for _ in range(60):
        n = rng.randrange(0, 80)
        offs = sorted(rng.choice([rng.uniform(0, 5), rng.uniform(0, 200), rng.uniform(0, 5000)]) for _ in range(n))
        kinds = [rng.choice(["a", "b", "c"]) for _ in offs]
        recs = [_rec(o, k) for o, k in zip(offs, kinds)]
        windows = tuple(sorted({rng.randrange(1, 90) for _ in range(3)}))
        rep = ar.measure(recs, windows=windows)
        times = [T0.timestamp() + o for o in offs]
        for w in windows:
            assert rep["peak"][str(w)]["appends"] == _brute_peak(times, w), (offs, w)
            start = rep["peak"][str(w)]["window_start"]
            if n:                                                          # the reported window really holds the peak
                assert sum(1 for t in times if start <= int(t // 1) < start + w) == rep["peak"][str(w)]["appends"]
        assert sum(s["appends"] for s in rep["signals"]) + rep["other"]["appends"] == n
        for s in rep["signals"]:
            mine = [t for t, k in zip(times, kinds) if k == s["signal"]]
            assert s["appends"] == len(mine)
            for w in windows:
                assert s["peak"][str(w)]["appends"] == _brute_peak(mine, w)


def test_empty_and_single_record_have_no_mean_rate():
    rep = ar.measure([])
    assert rep["dated"] == 0 and rep["mean_per_s"] is None and rep["peak"]["1"]["appends"] == 0
    assert rep["peak"]["1"]["window_start"] is None and rep["signals"] == [] and rep["first_ts"] is None
    one = ar.measure([_rec(3)])
    assert one["dated"] == 1 and one["mean_per_s"] is None and one["peak"]["1"]["appends"] == 1
    ar.render(rep), ar.render(one)                                         # both render


def test_undated_records_are_counted_and_left_out_of_the_rates():
    recs = [_rec(0), SimpleNamespace(ts=None, kind="event", source="t"),
            SimpleNamespace(ts="not a time", kind="event", source="t"), SimpleNamespace(kind="event"), _rec(1)]
    rep = ar.measure(recs)
    assert rep["records"] == 5 and rep["dated"] == 2 and rep["undated"] == 3
    assert rep["signals"][0]["appends"] == 2


def test_out_of_order_timestamps_are_counted_and_still_bucketed_at_their_own_ts():
    rep = ar.measure([_rec(10), _rec(5), _rec(5.5), _rec(11)])
    assert rep["out_of_order"] == 1 and rep["dated"] == 4
    assert ar.measure([_rec(1), _rec(1), _rec(1)])["out_of_order"] == 0    # the same instant is not "backwards"
    assert rep["peak"]["1"]["appends"] == 2 and rep["first_ts"] == T0.timestamp() + 5


def test_since_is_inclusive_and_until_is_exclusive():
    recs = [_rec(i) for i in range(10)]
    t = T0.timestamp()
    rep = ar.measure(recs, since=t + 3, until=t + 7)
    assert rep["dated"] == 4 and rep["first_ts"] == t + 3 and rep["last_ts"] == t + 6
    assert rep["records"] == 10                                            # every record was still read
    assert ar.measure(recs, since=t + 3)["dated"] == 7 and ar.measure(recs, until=t + 3)["dated"] == 3


def test_signal_dimensions_and_top_fold_the_rest_into_other():
    recs = ([_rec(i, "login", "provision") for i in range(5)] + [_rec(i, "login", "edge") for i in range(2)]
            + [_rec(i, "settle", "provision") for i in range(3)] + [_rec(0, "zeta", "x")])
    by_signal = ar.measure(recs)
    assert by_signal["by"] == "signal"
    assert [(s["signal"], s["appends"]) for s in by_signal["signals"]] == [("login", 7), ("settle", 3), ("zeta", 1)]
    assert abs(sum(s["share"] for s in by_signal["signals"]) - 1.0) < 1e-12
    by_source = ar.measure(recs, by="source")
    assert [(s["signal"], s["appends"]) for s in by_source["signals"]] == [("provision", 8), ("edge", 2), ("x", 1)]
    assert [(s["signal"], s["appends"]) for s in ar.measure(recs, by="kind")["signals"]] == [("event", 11)]
    two = ar.measure(recs, top=1)
    assert [(s["signal"], s["appends"]) for s in two["signals"]] == [("login", 7)]
    assert two["other"] == {"signals": 2, "appends": 4}
    assert ar.measure(recs, top=0)["signals"] == [] and ar.measure(recs, top=0)["other"]["appends"] == 11
    tie = ar.measure([_rec(0, "b"), _rec(0, "a")])
    assert [s["signal"] for s in tie["signals"]] == ["a", "b"]             # ties ordered by name: deterministic


def test_a_record_that_names_no_signal_is_grouped_under_its_kind():
    recs = [_rec(0, None, kind="decision"), _rec(0, None, kind="decision"), _rec(0, "", kind="message"),
            SimpleNamespace(ts=T0.isoformat(), kind="event", source="t", payload={"signal": 7}),
            SimpleNamespace(ts=T0.isoformat(), kind="event", source="t", payload=None),
            SimpleNamespace(ts=T0.isoformat(), kind="event", source="t", payload={"signal": ["x"]}),
            _rec(0, "wallet.debit")]
    got = {s["signal"]: s["appends"] for s in ar.measure(recs)["signals"]}
    assert got == {"(decision)": 2, "(message)": 1, "(event)": 3, "wallet.debit": 1}


# -- no target is built in ----------------------------------------------------------------------------------------
def test_no_ceiling_is_assumed_and_a_given_one_only_scales_the_peak():
    recs = [_rec(0.01 * i) for i in range(50)]
    plain = ar.measure(recs)
    assert plain["ceiling_per_s"] is None
    assert all("peak_fraction_of_ceiling" not in row for row in plain["peak"].values())
    assert "ceiling" not in ar.render(plain)
    given = ar.measure(recs, ceiling=200.0)
    assert given["peak"]["1"]["peak_fraction_of_ceiling"] == 50 / 200.0
    assert given["peak"]["10"]["peak_fraction_of_ceiling"] == (50 / 10) / 200.0
    assert "25.0% of the given ceiling 200/s" in ar.render(given)
    stripped = json.loads(json.dumps(given))
    for row in stripped["peak"].values():
        del row["peak_fraction_of_ceiling"]
    stripped["ceiling_per_s"] = None
    assert stripped == json.loads(json.dumps(plain))                       # nothing else depends on it


def test_the_module_holds_no_numeric_threshold():
    src = Path(ar.__file__).read_text()
    code = src.split('"""', 2)[2]                                          # past the module docstring
    assert "900" not in code and "1000" not in code and "threshold" not in code.lower()


@pytest.mark.parametrize("kw", [{"windows": ()}, {"windows": (0,)}, {"windows": (-5, 10)}, {"by": "actor"}, {"by": "kind+source"},
                                {"top": -1}, {"ceiling": 0}, {"ceiling": -3.0}, {"ceiling": float("nan")}])
def test_bad_arguments_are_refused(kw):
    with pytest.raises(ValueError):
        ar.measure([_rec(0)], **kw)


# -- read-only ---------------------------------------------------------------------------------------------------
def _tree_digest(d: Path) -> "dict[str, str]":
    return {str(p.relative_to(d)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(d.rglob("*")) if p.is_file()}


def test_measuring_a_real_spine_reads_every_record_and_writes_nothing():
    d = Path(tempfile.mkdtemp(prefix="sigil-rate-"))
    s = SpineStore(d / "spine.jsonl", seg_max_bytes=0, seg_max_records=7)  # several sealed segments + an active one
    for i in range(25):
        s.append(kind="event" if i % 3 else "decision", source="t", actor="u",
                 payload={"signal": "wallet.debit", "n": i} if i % 3 else {"n": i},
                 ts=(T0 + timedelta(seconds=i // 5)).isoformat())
    s.compact()
    before = _tree_digest(d)
    rep = ar.measure(SpineStore(d / "spine.jsonl").iter_records())
    assert _tree_digest(d) == before, "append-rate must not write, rotate, index or touch the spine directory"
    assert rep["records"] == rep["dated"] == 25 and rep["peak"]["1"]["appends"] == 5 and rep["span_s"] == 4.0
    assert {x["signal"]: x["appends"] for x in rep["signals"]} == {"wallet.debit": 16, "(decision)": 9}
    ok, why = SpineStore(d / "spine.jsonl").verify()
    assert ok, why


def test_the_default_append_ts_is_what_gets_measured():
    d = Path(tempfile.mkdtemp(prefix="sigil-rate-"))
    s = SpineStore(d / "spine.jsonl")
    lo = datetime.now(timezone.utc).timestamp()
    for i in range(4):
        s.append(kind="event", source="t", actor="u", payload={"n": i})
    hi = datetime.now(timezone.utc).timestamp()
    rep = ar.measure(s.iter_records())
    assert rep["dated"] == 4 and rep["undated"] == 0 and lo <= rep["first_ts"] <= rep["last_ts"] <= hi


def test_the_append_path_never_imports_the_instrumentation():
    """Byte-identical write path: the store, and an append through it, do not load `append_rate`."""
    code = ("import sys, tempfile, pathlib\n"
            "from sigil.spine.store import SpineStore\n"
            "s = SpineStore(pathlib.Path(tempfile.mkdtemp()) / 'spine.jsonl')\n"
            "s.append(kind='event', source='t', actor='u', payload={'n': 1})\n"
            "import sigil.cli\n"
            "print('sigil.spine.append_rate' in sys.modules)\n")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip().splitlines()[-1] == "False"


def test_the_store_source_does_not_reference_the_instrumentation():
    import sigil.spine.store as store_mod
    assert "append_rate" not in Path(store_mod.__file__).read_text()


# -- the CLI verb ------------------------------------------------------------------------------------------------
def _ns(**kw):
    base = dict(action="append-rate", since=None, until=None, window=None, by="signal", top=20, ceiling=None,
                json=False)
    base.update(kw)
    return SimpleNamespace(**base)


@pytest.fixture()
def default_spine():
    SpineStore().reset()
    try:
        s = SpineStore()
        for i in range(6):
            s.append(kind="event" if i < 4 else "decision", source="t", actor="u",
                     payload={"signal": "provision.audit", "n": i} if i < 4 else {"n": i},
                     ts=(T0 + timedelta(seconds=i)).isoformat())
        yield s
    finally:
        SpineStore().reset()


def test_cli_append_rate_reports_and_is_read_only(default_spine, capsys):
    from sigil.cli import cmd_spine
    spine_dir = Path(default_spine.path).parent
    before = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in spine_dir.glob("spine*") if p.is_file()}
    cmd_spine(_ns())
    out = capsys.readouterr().out
    assert "append rate by signal: 6 dated of 6 record(s)" in out and "provision.audit" in out and "(decision)" in out
    assert "capacity telemetry, not evidence" in out and "ceiling" not in out
    cmd_spine(_ns(json=True, window=[2], by="source", ceiling=10.0,
                  since=(T0 + timedelta(seconds=2)).isoformat(), until="2026-11-01T12:00:05Z"))
    rep = json.loads(capsys.readouterr().out)
    assert rep["dated"] == 3 and rep["records"] == 6 and rep["windows_s"] == [2] and rep["by"] == "source"
    assert rep["peak"]["2"] == {"appends": 2, "per_s": 1.0, "peak_fraction_of_ceiling": 0.1,
                                "window_start": int(T0.timestamp()) + 2}
    after = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in spine_dir.glob("spine*") if p.is_file()}
    assert after == before and default_spine.count() == 6


@pytest.mark.parametrize("kw", [{"since": "soon"}, {"until": "later"}, {"window": [0]}, {"ceiling": 0.0},
                                {"top": -2}])
def test_cli_append_rate_refuses_bad_arguments_with_exit_2(default_spine, capsys, kw):
    from sigil.cli import cmd_spine
    with pytest.raises(SystemExit) as e:
        cmd_spine(_ns(**kw))
    assert e.value.code == 2 and "append-rate:" in capsys.readouterr().err


def test_cli_parser_exposes_the_verb_and_its_flags(default_spine, capsys, monkeypatch):
    from sigil import cli
    monkeypatch.setattr(sys, "argv", ["sigil"])
    try:
        cli.main(["spine", "append-rate", "--json", "--window", "3", "--window", "1", "--top", "1"])
    except SystemExit as e:                                               # an install/migration gate, not a parse error
        assert e.code in (0, None), e.code
    rep = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert rep["windows_s"] == [1, 3] and len(rep["signals"]) == 1 and rep["other"]["signals"] == 1
