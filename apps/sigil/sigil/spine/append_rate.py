"""Front C S1 — APPEND-RATE instrumentation: how fast is the signed spine being written, and by what?

THE QUESTION THIS ANSWERS (docs/decisions/FRONT-C-1M-SCALE-DESIGN.md §3 W2, §4 S1). The sovereign spine has ONE
writer path; a signed append costs about a millisecond. Whether that is a wall at scale is a MEASUREMENT, not a
guess: this module reports appends per second, overall and by signal (the `signal` a record's payload names —
`provision.audit`, a credit debit, a kill-switch trip … — or its `kind` / `source`), with the PEAK rate: the
most appends in ANY interval of W seconds, found on the exact timestamps (a true sliding window, not
clock-aligned buckets — a burst that straddles a second boundary is counted whole).

THE FOLD WRITES NOTHING. The rate is a fold over the `ts` each record already carries. Nothing is added to the
append path (no counter, no hook, no lock, no extra byte) and no behaviour changes for any caller: the write
path is byte-identical with or without this module, which is only ever imported by the `sigil spine
append-rate` verb. (The verb opens the store like every other `sigil spine` verb: constructing a `SpineStore`
rolls forward an interrupted segment migration, and the CLI start-up gate records the install manifest on a
fresh home. Neither is this module's doing.)

WHAT `ts` IS — AND IS NOT. `ts` is INFORMATIONAL: it is outside the content digest, so it is not covered by the
chain or a signature. It is the append's wall-clock time UNLESS the caller supplied one — the git and transcript
ingesters pass the EVENT's own time (the commit's author date, the message's timestamp), so their records are
placed at event time and the burst an import really wrote is not visible here (`--group-by source` separates
them). This report is therefore capacity telemetry, never evidence: nothing may gate, bill or authorise on it.
A record whose `ts` does not parse is counted `undated`; one outside `since` / `until` is counted
`out_of_range`; a parseable `ts` earlier than its predecessor's is counted `out_of_order` (over the WHOLE
spine, whatever the range — it describes the quality of the timestamps) and is still placed at its own `ts`.

NO TARGET LIVES HERE. The report carries no threshold and passes no judgement. A caller may hand in a `ceiling`
(appends/s it measured for its own deployment) and gets each peak as a fraction of it — the scale targets are
the owner's (design §7.3), so none is built in.

COST. One pass over the spine. Each COUNTED record keeps its time and its signal id (12 bytes), plus 8 more
while the per-signal peaks of the `top` rows are computed — about 2 GB for a full run over 100M records, so
bound a large spine with `since` / `until`. Counted timestamps that are not already in order are sorted once.

FATAL-2: sovereign-only, stdlib-only.
"""
from __future__ import annotations

import math
from array import array
from datetime import datetime, timezone
from typing import Any, Iterable, Optional

__all__ = ["DEFAULT_WINDOWS", "measure", "parse_ts", "render"]

DEFAULT_WINDOWS: "tuple[int, ...]" = (1, 10, 60)


def parse_ts(ts: Any) -> "Optional[float]":
    """The POSIX time of a record's ISO-8601 `ts`, or None when it is absent or does not parse. A naive
    timestamp is read as UTC (the spine writes UTC-aware ones; an import may not)."""
    if not isinstance(ts, str) or not ts:
        return None
    try:
        dt = datetime.fromisoformat(ts)                 # accepts a trailing "Z" (Python >= 3.11)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()                               # pure arithmetic on an aware datetime: never raises


def _signal_of(r: Any, by: str) -> str:
    if by == "kind":
        return str(getattr(r, "kind", ""))
    if by == "source":
        return str(getattr(r, "source", ""))
    payload = getattr(r, "payload", None)
    sig = payload.get("signal") if isinstance(payload, dict) else None
    return sig if isinstance(sig, str) and sig else f"({getattr(r, 'kind', '')})"


def _peak(times, window: int) -> "tuple[int, Optional[float]]":
    """For time-ordered `times`: the most of them in any half-open interval of `window` seconds, and the first
    time in the earliest such interval (so the interval is `[start, start + window)`). O(n)."""
    best, best_start, lo = 0, None, 0
    for hi in range(len(times)):
        t = times[hi]
        while times[lo] <= t - window:                  # keep (t - window, t]
            lo += 1
        if hi - lo + 1 > best:
            best, best_start = hi - lo + 1, times[lo]
    return best, best_start


def _rates(times, windows: "tuple[int, ...]") -> dict:
    out = {}
    for w in windows:
        n, start = _peak(times, w)
        out[str(w)] = {"appends": n, "per_s": n / w, "window_start": start}
    return out


def measure(records: Iterable[Any], *, since: "Optional[float]" = None, until: "Optional[float]" = None,
            windows: "Iterable[int]" = DEFAULT_WINDOWS, by: str = "signal", top: int = 20,
            ceiling: "Optional[float]" = None) -> dict:
    """Fold `records` (anything with `.ts`, `.kind`, `.source`, `.payload` — `SpineStore.iter_records()`) into
    an append-rate report. `since` / `until` (POSIX seconds, inclusive / exclusive) restrict the records
    COUNTED (every record is still read). `by` is the dimension: "signal" (the payload's `signal` string; a
    record that names none is grouped as `(<kind>)`), "kind" or "source". `top` bounds the per-signal rows (by
    total, ties by name); the rest are summed into `other`. `ceiling` (appends/s, the CALLER's measured write
    ceiling) adds `peak_fraction_of_ceiling` per window — no ceiling is assumed without one.

    Counts: `records` == `undated` + `out_of_range` + `counted`. `peak[W]` is the most counted appends in any
    W-second interval `[window_start, window_start + W)`, `window_start` being the first append in it.
    `mean_per_s` is `(counted - 1) / span_s` — the appends after the first, over the observed first-to-last
    span (NOT the requested range); None when there is no span."""
    ws = tuple(sorted({int(w) for w in windows}))
    if not ws or ws[0] < 1:
        raise ValueError("windows must be whole seconds >= 1")
    if by not in ("signal", "kind", "source"):
        raise ValueError('by must be "signal", "kind" or "source"')
    if top < 0:
        raise ValueError("top must be >= 0")
    if ceiling is not None and not (math.isfinite(ceiling) and ceiling > 0):
        raise ValueError("ceiling must be a finite number > 0")
    times = array("d")
    sigs = array("I")
    names: "list[str]" = []
    ids: "dict[str, int]" = {}
    counts: "list[int]" = []
    records_seen = undated = out_of_order = out_of_range = 0
    prev: "Optional[float]" = None
    ordered = True
    for r in records:
        records_seen += 1
        t = parse_ts(getattr(r, "ts", None))
        if t is None:
            undated += 1
            continue
        if prev is not None and t < prev:
            out_of_order += 1
        prev = t
        if (since is not None and t < since) or (until is not None and t >= until):
            out_of_range += 1
            continue
        sig = _signal_of(r, by)
        i = ids.get(sig)
        if i is None:
            i = ids[sig] = len(names)
            names.append(sig)
            counts.append(0)
        counts[i] += 1
        if times and t < times[-1]:
            ordered = False
        times.append(t)
        sigs.append(i)
    counted = len(times)
    if not ordered:
        order = sorted(range(counted), key=times.__getitem__)
        times = array("d", (times[k] for k in order))
        sigs = array("I", (sigs[k] for k in order))
    first: "Optional[float]" = times[0] if counted else None
    last: "Optional[float]" = times[-1] if counted else None
    span = (last - first) if first is not None and last is not None else 0.0
    overall = _rates(times, ws)
    if ceiling is not None:
        for row in overall.values():
            row["peak_fraction_of_ceiling"] = row["per_s"] / ceiling
            if not math.isfinite(row["peak_fraction_of_ceiling"]):
                raise ValueError("ceiling is too small to express the peak as a fraction of it")
    ranked = sorted(range(len(names)), key=lambda k: (-counts[k], names[k]))
    shown = ranked[:top]
    mine: "dict[int, array]" = {k: array("d") for k in shown}
    if mine:
        for t, i in zip(times, sigs):
            a = mine.get(i)
            if a is not None:
                a.append(t)
    return {
        "by": by, "windows_s": list(ws), "records": records_seen, "counted": counted, "undated": undated,
        "out_of_range": out_of_range, "out_of_order": out_of_order,
        "first_ts": first, "last_ts": last, "span_s": span,
        "mean_per_s": ((counted - 1) / span) if span > 0 else None,
        "peak": overall, "ceiling_per_s": ceiling,
        "signals": [{"signal": names[k], "appends": counts[k], "share": counts[k] / counted,
                     "peak": _rates(mine[k], ws)} for k in shown],
        "other": {"signals": len(ranked) - len(shown), "appends": sum(counts[k] for k in ranked[top:])},
    }


def _iso(t: "Optional[float]") -> str:
    if t is None:
        return "-"
    try:
        return datetime.fromtimestamp(t, timezone.utc).isoformat(timespec="milliseconds")
    except (ValueError, OverflowError, OSError):         # a ts at the edge of the calendar: show the number
        return f"@{t!r}"


def _label(name: str, width: int = 40) -> str:
    """A signal name made safe for one terminal line: non-printables escaped, truncation marked."""
    s = "".join(c if c.isprintable() else c.encode("unicode_escape").decode("ascii") for c in name)
    return s if len(s) <= width else s[:width - 1] + "…"


def render(rep: dict) -> str:
    """The human report for `sigil spine append-rate`."""
    ws = [str(w) for w in rep["windows_s"]]
    mean = rep["mean_per_s"]
    lines = [
        f"append rate by {rep['by']}: {rep['counted']} counted of {rep['records']} record(s)"
        f" | undated {rep['undated']} | out of range {rep['out_of_range']}"
        f" | out-of-order ts (whole spine) {rep['out_of_order']}",
        f"  span   {_iso(rep['first_ts'])} .. {_iso(rep['last_ts'])} ({rep['span_s']:.3f} s)"
        f" | mean over that span {'-' if mean is None else format(mean, '.3f')} appends/s",
    ]
    for w in ws:
        row = rep["peak"][w]
        frac = row.get("peak_fraction_of_ceiling")
        lines.append(f"  peak {w:>4}s  {row['per_s']:>10.2f} appends/s ({row['appends']} in the {w} s from "
                     f"{_iso(row['window_start'])})"
                     + ("" if frac is None else f" = {frac * 100:.1f}% of the given ceiling "
                                                f"{rep['ceiling_per_s']:g}/s"))
    if rep["signals"]:
        lines.append("  " + f"{'signal':40} {'appends':>10} {'share':>7} "
                     + " ".join(f"{'peak/' + w + 's':>10}" for w in ws))
        for s in rep["signals"]:
            lines.append("  " + f"{_label(s['signal']):40} {s['appends']:>10} {s['share'] * 100:>6.1f}% "
                         + " ".join(f"{s['peak'][w]['per_s']:>10.2f}" for w in ws))
    if rep["other"]["signals"]:
        lines.append(f"  (+{rep['other']['signals']} more signal(s), {rep['other']['appends']} append(s))")
    lines.append("  note: `ts` is informational (outside the signed chain; an ingest supplies the event's own "
                 "time) — capacity telemetry, not evidence.")
    return "\n".join(lines)
