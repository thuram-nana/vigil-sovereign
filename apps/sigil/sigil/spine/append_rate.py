"""Front C S1 — APPEND-RATE instrumentation: how fast is the signed spine being written, and by what?

THE QUESTION THIS ANSWERS (docs/decisions/FRONT-C-1M-SCALE-DESIGN.md §3 W2, §4 S1). The sovereign spine has ONE
writer path; a signed append costs about a millisecond. Whether that is a wall at scale is a MEASUREMENT, not a
guess: this module reports appends per second, overall and by signal (the `signal` a record's payload names —
`provision.audit`, a credit debit, a kill-switch trip … — or its `kind` / `source`), with the PEAK rate over sliding windows — the number to compare with a measured write ceiling before anyone touches
group commit or batch signing.

READ-ONLY BY CONSTRUCTION. Every record already carries the wall-clock `ts` it was appended with, so the rate is
a fold over the records the spine holds. Nothing is added to the append path (no counter, no hook, no lock, no
extra byte), nothing is written, and no behaviour changes for any caller: the write path is byte-identical with
or without this module, which is only ever imported by the `sigil spine append-rate` verb.

WHAT `ts` IS — AND IS NOT. `ts` is INFORMATIONAL: it is outside the content digest, so it is not covered by the
chain or a signature, and a caller may pass its own (`append(ts=…)` — replays and imports do). This report is
therefore capacity telemetry, never evidence: nothing may gate, bill or authorise on it. Records whose `ts` does
not parse are counted as `undated` and left out of the rates; a record whose `ts` runs backwards relative to
its predecessor is counted in `out_of_order` (it is still bucketed at its own `ts`).

NO TARGET LIVES HERE. The report carries no threshold and passes no judgement. A caller may hand in a `ceiling`
(appends/s it measured for its own deployment) and gets the peak expressed as a fraction of it — the scale
targets are the owner's (design §7.3), so none is built in.

FATAL-2: sovereign-only, stdlib-only.
"""
from __future__ import annotations

from collections import Counter
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
    try:
        return dt.timestamp()
    except (OverflowError, OSError, ValueError):
        return None


def _peak(buckets: "dict[int, int]", window: int) -> "tuple[int, Optional[int]]":
    """The largest number of appends in any `window` consecutive whole seconds, and the second that window
    starts at. O(distinct seconds), independent of the idle time between them."""
    if not buckets:
        return 0, None
    secs = sorted(buckets)
    best, best_start, run, lo = 0, None, 0, 0
    for s in secs:
        run += buckets[s]
        while secs[lo] <= s - window:
            run -= buckets[secs[lo]]
            lo += 1
        if run > best:
            best, best_start = run, s - window + 1
    return best, best_start


def _rates(buckets: "dict[int, int]", windows: "tuple[int, ...]") -> dict:
    out = {}
    for w in windows:
        n, start = _peak(buckets, w)
        out[str(w)] = {"appends": n, "per_s": n / w, "window_start": start}
    return out


def measure(records: Iterable[Any], *, since: "Optional[float]" = None, until: "Optional[float]" = None,
            windows: "Iterable[int]" = DEFAULT_WINDOWS, by: str = "signal", top: int = 20,
            ceiling: "Optional[float]" = None) -> dict:
    """Fold `records` (anything with `.ts`, `.kind`, `.source`, `.payload` — `SpineStore.iter_records()`) into
    an append-rate report. `since` / `until` (POSIX seconds, inclusive / exclusive) restrict the dated records
    counted. `by` is the dimension: "signal" (the payload's `signal` string; a record that names none is grouped
    as `(<kind>)`), "kind" or "source". `top` bounds the per-signal rows
    (by total, ties by name); the rest are summed into `other`. `ceiling` (appends/s, the CALLER's measured
    write ceiling) adds `peak_fraction_of_ceiling` per window — no ceiling is assumed without one."""
    ws = tuple(sorted({int(w) for w in windows}))
    if not ws or ws[0] < 1:
        raise ValueError("windows must be whole seconds >= 1")
    if by not in ("signal", "kind", "source"):
        raise ValueError('by must be "signal", "kind" or "source"')
    if top < 0:
        raise ValueError("top must be >= 0")
    if ceiling is not None and not ceiling > 0:
        raise ValueError("ceiling must be > 0")
    total: "dict[int, int]" = {}
    per: "dict[str, dict[int, int]]" = {}
    counts: "Counter[str]" = Counter()
    records_seen = undated = out_of_order = dated = 0
    first: "Optional[float]" = None
    last: "Optional[float]" = None
    prev: "Optional[float]" = None
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
            continue
        dated += 1
        first = t if first is None or t < first else first
        last = t if last is None or t > last else last
        sig = _signal_of(r, by)
        sec = int(t // 1)
        total[sec] = total.get(sec, 0) + 1
        b = per.get(sig)
        if b is None:
            b = per[sig] = {}
        b[sec] = b.get(sec, 0) + 1
        counts[sig] += 1
    span = (last - first) if first is not None and last is not None else 0.0
    overall = _rates(total, ws)
    if ceiling is not None:
        for row in overall.values():
            row["peak_fraction_of_ceiling"] = row["per_s"] / ceiling
    ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    signals = [{"signal": sig, "appends": n, "share": n / dated, "peak": _rates(per[sig], ws)}
               for sig, n in ranked[:top]]
    return {
        "by": by, "windows_s": list(ws), "records": records_seen, "dated": dated, "undated": undated,
        "out_of_order": out_of_order, "first_ts": first, "last_ts": last, "span_s": span,
        # the mean over the observed span; None for fewer than two distinct instants (no rate to speak of)
        "mean_per_s": (dated / span) if span > 0 else None,
        "peak": overall, "ceiling_per_s": ceiling,
        "signals": signals, "other": {"signals": max(0, len(ranked) - top),
                                      "appends": sum(n for _, n in ranked[top:])},
    }


def _signal_of(r: Any, by: str) -> str:
    if by == "kind":
        return str(getattr(r, "kind", ""))
    if by == "source":
        return str(getattr(r, "source", ""))
    payload = getattr(r, "payload", None)
    sig = payload.get("signal") if isinstance(payload, dict) else None
    return sig if isinstance(sig, str) and sig else f"({getattr(r, 'kind', '')})"


def _iso(t: "Optional[float]") -> str:
    return "-" if t is None else datetime.fromtimestamp(t, timezone.utc).isoformat(timespec="seconds")


def render(rep: dict) -> str:
    """The human report for `sigil spine append-rate`."""
    ws = [str(w) for w in rep["windows_s"]]
    mean = rep["mean_per_s"]
    lines = [
        f"append rate by {rep['by']}: {rep['dated']} dated of {rep['records']} record(s)"
        f" | undated {rep['undated']} | out-of-order {rep['out_of_order']}",
        f"  span   {_iso(rep['first_ts'])} .. {_iso(rep['last_ts'])} ({rep['span_s']:.1f} s)"
        f" | mean {'-' if mean is None else format(mean, '.3f')} appends/s",
    ]
    for w in ws:
        row = rep["peak"][w]
        frac = row.get("peak_fraction_of_ceiling")
        lines.append(f"  peak {w:>4}s  {row['per_s']:>10.2f} appends/s ({row['appends']} in the window from "
                     f"{_iso(row['window_start'])})"
                     + ("" if frac is None else f" = {frac * 100:.1f}% of the given ceiling "
                                                f"{rep['ceiling_per_s']:g}/s"))
    if rep["signals"]:
        lines.append("  " + f"{'signal':40} {'appends':>10} {'share':>7} "
                     + " ".join(f"{'peak/' + w + 's':>10}" for w in ws))
        for s in rep["signals"]:
            lines.append("  " + f"{s['signal'][:40]:40} {s['appends']:>10} {s['share'] * 100:>6.1f}% "
                         + " ".join(f"{s['peak'][w]['per_s']:>10.2f}" for w in ws))
    if rep["other"]["signals"]:
        lines.append(f"  (+{rep['other']['signals']} more signal(s), {rep['other']['appends']} append(s))")
    lines.append("  note: `ts` is informational (outside the signed chain) — capacity telemetry, not evidence.")
    return "\n".join(lines)
