"""Front C S1 — append-rate instrumentation (`sigil.spine.append_rate`, `sigil spine append-rate`).

What must hold: the peak is the TRUE sliding-window maximum on the exact timestamps (randomised differential
against a brute-force count, including a burst that straddles a second boundary and pre-epoch times); the fold
is READ-ONLY (a measured SIGIL_HOME is byte-identical afterwards, on a legacy AND a segmented + gzip-compacted
spine, and the append path never imports the module); NO target is built in (a ceiling is the caller's or
absent); bad timestamps are counted, never guessed; the verb's flags cannot leak onto other `spine` actions.
"""
from __future__ import annotations

import hashlib
import json
import os
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


def _rec(offset_s: float, signal: "str | None" = "s", source: str = "t", kind: str = "event", base=T0):
    payload = {} if signal is None else {"signal": signal}
    return SimpleNamespace(ts=(base + timedelta(seconds=offset_s)).isoformat(), kind=kind, source=source,
                           payload=payload)


def _brute_peak(times: "list[float]", window: int) -> int:
    """The most timestamps in any half-open interval of `window` seconds — the definition, the slow way: an
    optimal interval can always be slid right until it starts on a timestamp."""
    return max((sum(1 for x in times if s <= x < s + window) for s in times), default=0)


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
    assert rep["records"] == rep["counted"] == 9 and rep["undated"] == rep["out_of_range"] == 0
    assert rep["out_of_order"] == 0
    assert rep["peak"]["1"] == {"appends": 5, "per_s": 5.0, "window_start": T0.timestamp()}
    assert rep["peak"]["10"]["appends"] == 8 and rep["peak"]["10"]["per_s"] == 0.8
    assert rep["peak"]["60"]["appends"] == 9 and rep["peak"]["60"]["per_s"] == 9 / 60
    assert rep["span_s"] == 30.0 and rep["mean_per_s"] == 8 / 30.0
    assert rep["first_ts"] == T0.timestamp() and rep["last_ts"] == T0.timestamp() + 30


def test_a_burst_that_straddles_a_second_boundary_is_counted_whole():
    """The review's case: 1000 appends inside one second, from .500 to 1.499 — a clock-aligned bucket would
    report 500/s (and "50% of a 1000/s ceiling" for a writer that was at 100%)."""
    recs = [_rec(0.5 + 0.001 * i) for i in range(1000)]
    rep = ar.measure(recs, ceiling=1000.0)
    assert rep["peak"]["1"]["appends"] == 1000 and rep["peak"]["1"]["peak_fraction_of_ceiling"] == 1.0
    assert rep["peak"]["1"]["window_start"] == pytest.approx(T0.timestamp() + 0.5)
    two = ar.measure([_rec(0.9, "a")] * 500 + [_rec(10.5, "a")] * 500, windows=(10,))
    assert two["peak"]["10"]["appends"] == 1000                           # 9.6 s apart: one 10 s interval


def test_the_interval_is_half_open():
    assert ar.measure([_rec(0), _rec(1.0)], windows=(1,))["peak"]["1"]["appends"] == 1   # exactly W apart: two
    assert ar.measure([_rec(0), _rec(0.999)], windows=(1,))["peak"]["1"]["appends"] == 2
    assert ar.measure([_rec(0), _rec(0)], windows=(1,))["peak"]["1"]["appends"] == 2


def test_peak_matches_a_brute_force_count_on_random_streams():
    rng = random.Random(1106)
    epochs = [T0, datetime(1969, 12, 31, 23, 59, 58, tzinfo=timezone.utc)]   # incl. times that cross the epoch
    for round_ in range(80):
        base = epochs[round_ % 2]
        n = rng.randrange(0, 80)
        offs = [rng.choice([rng.uniform(0, 5), rng.uniform(0, 200), rng.uniform(0, 5000),
                            float(rng.randrange(0, 6))]) for _ in range(n)]
        if round_ % 3:
            offs.sort()                                                     # else: an out-of-order spine
        kinds = [rng.choice(["a", "b", "c"]) for _ in offs]
        recs = [_rec(o, k, base=base) for o, k in zip(offs, kinds)]
        windows = tuple(sorted({rng.randrange(1, 90) for _ in range(3)}))
        rep = ar.measure(recs, windows=windows, top=rng.choice([1, 2, 20]))
        times = [ar.parse_ts(r.ts) for r in recs]
        for w in windows:
            row = rep["peak"][str(w)]
            assert row["appends"] == _brute_peak(times, w), (offs, w)
            if n:                                                           # the reported interval holds the peak
                start = row["window_start"]
                assert start in times and min(times) <= start
                assert sum(1 for t in times if start <= t < start + w) == row["appends"]
        assert sum(s["appends"] for s in rep["signals"]) + rep["other"]["appends"] == n
        for s in rep["signals"]:
            mine = [t for t, k in zip(times, kinds) if k == s["signal"]]
            assert s["appends"] == len(mine)
            for w in windows:
                assert s["peak"][str(w)]["appends"] == _brute_peak(mine, w)
                assert s["peak"][str(w)]["window_start"] in mine


def test_empty_and_single_record_have_no_mean_rate():
    rep = ar.measure([])
    assert rep["counted"] == 0 and rep["mean_per_s"] is None and rep["peak"]["1"]["appends"] == 0
    assert rep["peak"]["1"]["window_start"] is None and rep["signals"] == [] and rep["first_ts"] is None
    assert rep["other"] == {"signals": 0, "appends": 0}
    one = ar.measure([_rec(3)])
    assert one["counted"] == 1 and one["mean_per_s"] is None and one["peak"]["1"]["appends"] == 1
    assert one["peak"]["60"]["window_start"] == T0.timestamp() + 3          # the record itself, never before it
    assert "more signal" not in ar.render(one) and ar.render(rep)


def test_the_mean_never_exceeds_the_peak_of_a_window_that_fits_the_span():
    rep = ar.measure([_rec(0), _rec(0.001), _rec(0.002)])                   # 3 appends in 2 ms
    assert rep["mean_per_s"] == pytest.approx(2 / 0.002, rel=1e-3)          # (n - 1) / span, stated as such
    steady = ar.measure([_rec(0.5 * i) for i in range(21)])                 # 2/s for 10 s
    assert steady["mean_per_s"] == pytest.approx(2.0) and steady["peak"]["1"]["per_s"] == 2.0


def test_undated_and_out_of_range_records_are_counted_and_left_out_of_the_rates():
    recs = [_rec(0, "a"), SimpleNamespace(ts=None, kind="event", source="t", payload={}),
            SimpleNamespace(ts="not a time", kind="event", source="t", payload={}),
            SimpleNamespace(kind="event"), _rec(1, "a"), _rec(2, "b"), _rec(50, "b")]
    rep = ar.measure(recs, until=T0.timestamp() + 10)
    assert (rep["records"], rep["counted"], rep["undated"], rep["out_of_range"]) == (7, 3, 3, 1)
    assert rep["records"] == rep["counted"] + rep["undated"] + rep["out_of_range"]
    assert {s["signal"]: s["share"] for s in rep["signals"]} == {"a": 2 / 3, "b": 1 / 3}   # of the COUNTED
    assert rep["span_s"] == 2.0 and rep["mean_per_s"] == 1.0
    assert "3 counted of 7 record(s) | undated 3 | out of range 1" in ar.render(rep)


def test_out_of_order_is_a_whole_spine_count_and_those_records_keep_their_own_ts():
    rep = ar.measure([_rec(10), _rec(5), _rec(5.5), _rec(11)])
    assert rep["out_of_order"] == 1 and rep["counted"] == 4
    assert rep["peak"]["1"]["appends"] == 2 and rep["first_ts"] == T0.timestamp() + 5
    assert rep["peak"]["1"]["window_start"] == T0.timestamp() + 5
    assert ar.measure([_rec(1), _rec(1), _rec(1)])["out_of_order"] == 0    # the same instant is not "backwards"
    # whole-spine: the backwards step is outside the range, the count still reports it
    ranged = ar.measure([_rec(10), _rec(5), _rec(20), _rec(21)], since=T0.timestamp() + 15)
    assert ranged["out_of_order"] == 1 and ranged["counted"] == 2 and ranged["out_of_range"] == 2


def test_since_is_inclusive_and_until_is_exclusive():
    recs = [_rec(i) for i in range(10)]
    t = T0.timestamp()
    rep = ar.measure(recs, since=t + 3, until=t + 7)
    assert rep["counted"] == 4 and rep["first_ts"] == t + 3 and rep["last_ts"] == t + 6
    assert rep["records"] == 10 and rep["out_of_range"] == 6               # every record was still read
    assert rep["peak"]["60"]["window_start"] == t + 3                      # never before `since`
    assert ar.measure(recs, since=t + 3)["counted"] == 7 and ar.measure(recs, until=t + 3)["counted"] == 3


def test_signal_dimensions_and_top_fold_the_rest_into_other():
    recs = ([_rec(i, "login", "provision") for i in range(5)] + [_rec(i, "login", "edge") for i in range(2)]
            + [_rec(i, "settle", "provision") for i in range(3)] + [_rec(0, "zeta", "x")])
    by_signal = ar.measure(recs)
    assert by_signal["by"] == "signal"
    assert [(s["signal"], s["appends"]) for s in by_signal["signals"]] == [("login", 7), ("settle", 3), ("zeta", 1)]
    assert abs(sum(s["share"] for s in by_signal["signals"]) - 1.0) < 1e-12
    assert by_signal["other"] == {"signals": 0, "appends": 0} and "more signal" not in ar.render(by_signal)
    by_source = ar.measure(recs, by="source")
    assert [(s["signal"], s["appends"]) for s in by_source["signals"]] == [("provision", 8), ("edge", 2), ("x", 1)]
    assert [(s["signal"], s["appends"]) for s in ar.measure(recs, by="kind")["signals"]] == [("event", 11)]
    one = ar.measure(recs, top=1)
    assert [(s["signal"], s["appends"]) for s in one["signals"]] == [("login", 7)]
    assert one["other"] == {"signals": 2, "appends": 4} and "(+2 more signal(s), 4 append(s))" in ar.render(one)
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


# -- render is total ----------------------------------------------------------------------------------------------
@pytest.mark.parametrize("ts", ["0001-01-01T00:00:00Z", "0001-01-01T00:00:00+14:00", "9999-12-31T23:59:59-12:00"])
def test_a_ts_at_the_edge_of_the_calendar_is_reported_not_a_crash(ts):
    recs = [SimpleNamespace(ts=ts, kind="event", source="t", payload={})]
    rep = ar.measure(recs)
    assert rep["counted"] == 1
    out = ar.render(rep)
    assert "1 counted of 1 record(s)" in out
    json.dumps(rep, allow_nan=False)


def test_odd_signal_names_cannot_break_the_table():
    long = "x" * 200
    recs = [_rec(0, long), _rec(0, "evil\nname\x1b[31m\t"), _rec(0, "ok")]
    out = ar.render(ar.measure(recs))
    lines = out.splitlines()
    assert not any("\x1b" in ln or "\t" in ln for ln in lines) and "evil\\nname\\x1b[31m\\t" in out
    assert "x" * 39 + "…" in out and "x" * 41 not in out
    assert len(lines) == 2 + 3 + 1 + 3 + 1                                 # header, span, peaks, table, note


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


@pytest.mark.parametrize("kw", [{"windows": ()}, {"windows": (0,)}, {"windows": (-5, 10)}, {"by": "actor"},
                                {"by": "kind+source"}, {"top": -1}, {"ceiling": 0}, {"ceiling": -3.0},
                                {"ceiling": float("nan")}, {"ceiling": float("inf")}, {"ceiling": 1e-320}])
def test_bad_arguments_are_refused(kw):
    with pytest.raises(ValueError):
        ar.measure([_rec(0)], **kw)


# -- read-only ---------------------------------------------------------------------------------------------------
def _tree(d: Path) -> "dict[str, str]":
    """Every entry under `d`: files by content hash, directories by name — a created lock file, sidecar, head
    or directory shows up."""
    return {str(p.relative_to(d)): (hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else "<dir>")
            for p in sorted(d.rglob("*"))}


def _segmented_spine(d: Path) -> SpineStore:
    s = SpineStore(d / "spine.jsonl", seg_max_bytes=0, seg_max_records=7)
    s.migrate()                                                            # a legacy spine never rotates
    for i in range(25):
        s.append(kind="event" if i % 3 else "decision", source="t", actor="u",
                 payload={"signal": "wallet.debit", "n": i} if i % 3 else {"n": i},
                 ts=(T0 + timedelta(seconds=i // 5)).isoformat())
    assert s.compact() > 0 and len(s.segment_info()) > 2, "the precondition: sealed + gzip segments + an active one"
    return s


def test_measuring_a_segmented_compacted_spine_reads_every_record_and_writes_nothing():
    d = Path(tempfile.mkdtemp(prefix="sigil-rate-"))
    _segmented_spine(d)
    before = _tree(d)
    rep = ar.measure(SpineStore(d / "spine.jsonl").iter_records())
    assert _tree(d) == before, "append-rate must not write, rotate, index or touch the spine directory"
    assert rep["records"] == rep["counted"] == 25 and rep["peak"]["1"]["appends"] == 5 and rep["span_s"] == 4.0
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
    assert rep["counted"] == 4 and rep["undated"] == 0 and lo <= rep["first_ts"] <= rep["last_ts"] <= hi


def test_the_append_path_never_imports_the_instrumentation():
    """Byte-identical write path: the store, an append through it, and the CLI module do not load `append_rate`."""
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


def test_the_module_imports_only_the_standard_library():
    import ast
    tree = ast.parse(Path(ar.__file__).read_text())
    mods = {n.module if isinstance(n, ast.ImportFrom) else a.name
            for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom))
            for a in (n.names if isinstance(n, ast.Import) else [None])}
    assert mods <= {"__future__", "math", "array", "datetime", "typing"}, mods


# -- the CLI verb ------------------------------------------------------------------------------------------------
def _ns(**kw):
    base = dict(action="append-rate", since=None, until=None, window=None, group_by="signal", top=20,
                ceiling=None, json=False, boundary=None, yes=False, archive=None)
    base.update(kw)
    return SimpleNamespace(**base)


def _fill(s: SpineStore, lo: int = 0, hi: int = 6) -> None:
    for i in range(lo, hi):
        s.append(kind="event" if i < 4 else "decision", source="t", actor="u",
                 payload={"signal": "provision.audit", "n": i} if i < 4 else {"n": i},
                 ts=(T0 + timedelta(seconds=i)).isoformat())


@pytest.fixture(params=["legacy", "segmented"])
def default_spine(request):
    SpineStore().reset()
    try:
        s = SpineStore()
        if request.param == "segmented":
            s.migrate()
            _fill(s, 0, 3)
            s.rotate()
            assert s.compact() > 0
            _fill(s, 3, 6)                                                  # a non-empty ACTIVE segment too
        else:
            _fill(s)
        yield SpineStore()
    finally:
        SpineStore().reset()


def test_cli_append_rate_reports_and_leaves_the_whole_home_untouched(default_spine, capsys):
    from sigil.cli import cmd_spine
    home = Path(os.environ["SIGIL_HOME"])
    assert Path(default_spine.path).resolve().is_relative_to(home.resolve())
    before = _tree(home)
    cmd_spine(_ns())
    out = capsys.readouterr().out
    assert "append rate by signal: 6 counted of 6 record(s)" in out and "provision.audit" in out
    assert "(decision)" in out and "capacity telemetry, not evidence" in out and "ceiling" not in out
    cmd_spine(_ns(json=True, window=[2], group_by="source", ceiling=10.0,
                  since=(T0 + timedelta(seconds=2)).isoformat(), until="2026-11-01T12:00:05Z"))
    rep = json.loads(capsys.readouterr().out)
    assert rep["counted"] == 3 and rep["records"] == 6 and rep["windows_s"] == [2] and rep["by"] == "source"
    assert rep["peak"]["2"] == {"appends": 2, "per_s": 1.0, "peak_fraction_of_ceiling": 0.1,
                                "window_start": T0.timestamp() + 2}
    assert _tree(home) == before, "the verb changed something under SIGIL_HOME"
    assert SpineStore().count() == 6


@pytest.mark.parametrize("kw", [{"since": "soon"}, {"until": "later"}, {"window": [0]}, {"ceiling": 0.0},
                                {"ceiling": float("inf")}, {"ceiling": 1e-320}, {"top": -2}])
def test_cli_append_rate_refuses_bad_arguments_with_exit_2(default_spine, capsys, kw):
    from sigil.cli import cmd_spine
    with pytest.raises(SystemExit) as e:
        cmd_spine(_ns(**kw))
    assert e.value.code == 2 and "append-rate:" in capsys.readouterr().err


@pytest.mark.parametrize("kw,flag", [({"boundary": 3}, "--boundary"), ({"yes": True}, "--yes"),
                                     ({"archive": "/x"}, "--archive")])
def test_append_rate_refuses_the_prune_flags(default_spine, capsys, kw, flag):
    from sigil.cli import cmd_spine
    with pytest.raises(SystemExit) as e:
        cmd_spine(_ns(**kw))
    assert e.value.code == 2 and flag in capsys.readouterr().err


@pytest.mark.parametrize("kw,flag", [({"json": True}, "--json"), ({"since": "2026-01-01"}, "--since"),
                                     ({"until": "2026-01-01"}, "--until"), ({"window": [5]}, "--window"),
                                     ({"group_by": "kind"}, "--group-by"), ({"top": 1}, "--top"),
                                     ({"ceiling": 9.0}, "--ceiling")])
@pytest.mark.parametrize("action", ["status", "prune", "rotate"])
def test_other_spine_actions_refuse_the_append_rate_flags_before_doing_anything(default_spine, capsys, action,
                                                                                kw, flag):
    from sigil.cli import cmd_spine
    home = Path(os.environ["SIGIL_HOME"])
    before = _tree(home)
    with pytest.raises(SystemExit) as e:
        cmd_spine(_ns(action=action, yes=(action == "prune"), boundary=(3 if action == "prune" else None), **kw))
    assert e.value.code == 2 and flag in capsys.readouterr().err
    assert _tree(home) == before


def test_a_bare_namespace_still_drives_the_other_actions(default_spine, capsys):
    """`cmd_spine` is called with partial namespaces elsewhere: absent flags read as their defaults."""
    from sigil.cli import cmd_spine
    cmd_spine(SimpleNamespace(action="status"))
    assert "6 records" in capsys.readouterr().out


def _main(argv, capsys):
    from sigil import cli
    code = 0
    try:
        cli.main(argv)
    except SystemExit as e:
        code = e.code or 0
    cap = capsys.readouterr()
    return code, cap.out, cap.err


def test_cli_parser_exposes_the_verb_and_its_flags(default_spine, capsys):
    code, out, _ = _main(["spine", "append-rate", "--json", "--window", "3", "--window", "1", "--top", "1",
                          "--ceiling", "4", "--group-by", "kind"], capsys)
    assert code == 0
    rep = json.loads(out.strip().splitlines()[-1])
    assert rep["windows_s"] == [1, 3] and len(rep["signals"]) == 1 and rep["other"]["signals"] == 1
    assert rep["ceiling_per_s"] == 4.0 and rep["by"] == "kind" and rep["peak"]["1"]["peak_fraction_of_ceiling"] == 0.25
    code, _, err = _main(["spine", "append-rate", "--group-by", "actor"], capsys)
    assert code == 2 and "invalid choice" in err
    code, _, err = _main(["spine", "append-rate", "--top", "many"], capsys)
    assert code == 2
    code, _, err = _main(["spine", "status", "--json"], capsys)
    assert code == 2 and "--json" in err


def test_the_boundary_abbreviation_still_parses(default_spine, capsys):
    """`--b` was a unique prefix of `--boundary` before this slice; a `--by` flag would have made it ambiguous."""
    code, _, err = _main(["spine", "prune-plan", "--b", "3"], capsys)
    assert "ambiguous" not in err and "unrecognized" not in err
