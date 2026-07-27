"""
verify.drift — continuous drift / watch over a run store (Phase D1).

Re-running an engagement on a cadence answers one question the blue team actually
asks: *did the confirmed-fact set change since last time?* A confirmed FACT that
NEWLY appears is a regression (a new exposure); one that DISAPPEARS is a fix (or a
silently-lost detection). This module surfaces both as drift findings.

The whole design turns on one honesty rule, inherited straight from prove-don't-guess:

  * A "confirmed fact" is ONLY a finding whose retained ``oracle_context`` STILL
    RE-FIRES (``verify.reverify`` re-runs the pure oracle offline). A finding that is
    merely LISTED — no certificate, or a certificate that no longer reproduces — is
    NOT a confirmed fact and can never enter the diff. So the diff cannot fabricate a
    regression out of a lead, a heuristic, or a tampered cert. Only a deterministic
    oracle re-firing confirms.

  * ``diff_confirmed`` is a PURE set-diff over two confirmed-fact IDENTITY sets — no
    wallclock, no rng, total on garbage. Given the same two retained states it always
    produces the same ``{added, removed, unchanged}``, so the drift result itself
    re-verifies. The only clock in the whole module is the ``--watch`` cadence sleep,
    which is OUTSIDE the diff and injectable for tests.

    python3 -m framework.v2 drift <prev.json> <curr.json>
    python3 -m framework.v2 drift --run-store [--target HOST]
    python3 -m framework.v2 drift --watch <secs> --cycles <n> --baseline <prev.json> <curr.json>

Exit 0 normally; with ``--fail-on-drift``, exit 3 iff the confirmed-fact set drifted
(any fact appeared or disappeared) — the CI hook for a regression gate.
"""

from __future__ import annotations

import argparse
import json
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from . import reverify

# The fields that make a confirmed fact IDENTICAL across two runs. Deliberately EXCLUDES
# volatile evidence (confidence, rationale, the oracle_context bytes themselves, any
# wallclock): the same weakness at the same point on the same endpoint is the SAME fact
# run-to-run even if its calibrated score wobbles. Stable + deterministic.
#
# TRUST MODEL (red-pen MEDIUM-1) — these are the finding's SELF-DESCRIBED location fields,
# NOT oracle-attested proof. That is sound because identity is ONLY a MATCHING KEY over facts
# that ``confirmed_fact_ids`` has ALREADY admitted by RE-FIRING their retained ``oracle_context``
# (``reverify_finding(...).ok``). So the oracle remains the sole authority for WHAT is a fact;
# ``_fact_identity`` only decides which two ALREADY-confirmed facts are "the same" across runs.
# The worst a spoofed/mislabelled location can do is mis-pair two genuinely-confirmed facts —
# surfacing spurious churn (an extra add+remove in the diff) — which is a false NEGATIVE-control
# / noise, never a false FACT: drift can never manufacture a confirmed weakness that the oracle
# did not re-fire. A regression the diff reports is a change in the *oracle-confirmed* set, full
# stop. `bug_class` (an oracle-attested field) anchors the key so cross-class collisions cannot occur.
_IDENTITY_FIELDS = ("bug_class", "endpoint", "insertion_point", "param")


# ---- confirmed-fact identity -------------------------------------------------


def _fact_identity(finding: Mapping[str, Any]) -> str:
    """A stable, canonical identity string for one ALREADY-oracle-confirmed finding — canonical
    JSON over the identity fields (sorted keys, compact), the same discipline evidence integrity
    uses. This is a matching key, not a confirmation: the oracle re-fire in ``confirmed_fact_ids``
    is what admits a finding; see the ``_IDENTITY_FIELDS`` trust-model note. Total: a missing/None
    field coerces to ``""`` so a hand-built or legacy finding still keys deterministically."""
    key = {}
    for f in _IDENTITY_FIELDS:
        v = finding.get(f, "")
        key[f] = "" if v is None else str(v)
    return json.dumps(key, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _findings_of(doc: Any) -> list:
    """The finding list inside a run document. Accepts a ScanReport-shaped dict
    (``active_findings``), a bare list of findings, or a single finding dict. Total:
    anything else yields ``[]``."""
    if isinstance(doc, Mapping):
        af = doc.get("active_findings")
        if isinstance(af, list):
            return af
        # a single finding document
        if doc.get("oracle_context") is not None or doc.get("bug_class") is not None:
            return [doc]
        return []
    if isinstance(doc, list):
        return doc
    return []


def confirmed_fact_ids(doc: Any) -> frozenset[str]:
    """The set of oracle-CONFIRMED fact identities in a run document.

    A finding is included IFF its retained ``oracle_context`` re-fires under the pure
    oracle (``reverify.reverify_finding(...).ok`` — reproduced AND matching its own claim).
    A finding with no certificate, or one whose certificate no longer reproduces, is
    silently excluded — it is not a confirmed fact, so it can never seed a fabricated
    regression. Deterministic (a pure function of the retained evidence); total (a
    malformed finding is skipped, never raised)."""
    out: set[str] = set()
    for f in _findings_of(doc):
        if not isinstance(f, Mapping):
            continue
        try:
            r = reverify.reverify_finding(dict(f))
        except Exception:
            continue
        if getattr(r, "ok", False):
            out.add(_fact_identity(f))
    return frozenset(out)


def _coerce_id_set(x: Any) -> set[str]:
    """Coerce an input into a set of identity strings — total on garbage. A str/bytes is
    NOT a set of ids (iterating it yields characters), so it maps to the empty set; a
    non-iterable maps to the empty set; only string elements of an iterable are kept.
    This is what keeps ``diff_confirmed`` total: it can be handed anything and never
    raises, and it never invents an identity from a non-string element."""
    if isinstance(x, (str, bytes, bytearray)):
        return set()
    # A mapping is NOT a confirmed-fact set — iterating it would silently promote its keys
    # into identities. Refuse it (fail-closed against fabricating a fact from the wrong type).
    if isinstance(x, Mapping):
        return set()
    if not isinstance(x, Iterable):
        return set()
    out: set[str] = set()
    for e in x:
        if isinstance(e, str):
            out.add(e)
    return out


# ---- the pure diff -----------------------------------------------------------


@dataclass(frozen=True)
class DriftDiff:
    """The result of comparing two confirmed-fact identity sets. Fields are SORTED tuples
    so the object is deterministic and hashable — the same two inputs always compare equal.

      * ``added``     — a confirmed fact present now but NOT before (a new exposure / regression)
      * ``removed``   — a confirmed fact present before but NOT now (a fix, or a lost detection)
      * ``unchanged`` — a confirmed fact present in BOTH runs
    """

    added: tuple[str, ...]
    removed: tuple[str, ...]
    unchanged: tuple[str, ...]

    @property
    def has_drift(self) -> bool:
        """True iff the confirmed-fact set changed at all (a fact appeared or disappeared)."""
        return bool(self.added or self.removed)

    def to_dict(self) -> dict:
        return {"added": list(self.added), "removed": list(self.removed),
                "unchanged": list(self.unchanged)}


def diff_confirmed(prev_facts: Any, curr_facts: Any) -> DriftDiff:
    """PURE set-diff over two confirmed-fact identity sets → ``DriftDiff``.

    No wallclock, no rng — a pure function of its two inputs, so a drift verdict
    re-verifies exactly the way a finding certificate does. Total on garbage: each input
    is coerced to a set of identity strings (a non-iterable, a bare string, or non-string
    elements degrade to nothing rather than raising), so the diff never crashes and never
    fabricates an identity that was not actually a confirmed fact.

    ``added = curr - prev``, ``removed = prev - curr``, ``unchanged = prev ∩ curr`` —
    each returned as a SORTED tuple for determinism."""
    prev = _coerce_id_set(prev_facts)
    curr = _coerce_id_set(curr_facts)
    return DriftDiff(
        added=tuple(sorted(curr - prev)),
        removed=tuple(sorted(prev - curr)),
        unchanged=tuple(sorted(prev & curr)),
    )


def diff_run_docs(prev_doc: Any, curr_doc: Any) -> DriftDiff:
    """Diff the confirmed-fact sets of two run documents (report/reverifiable JSON). Re-fires
    each doc's retained certs (``confirmed_fact_ids``) then applies the pure ``diff_confirmed``.
    Deterministic and offline — no traffic, no target."""
    return diff_confirmed(confirmed_fact_ids(prev_doc),
                          confirmed_fact_ids(curr_doc))


# ---- drift findings ----------------------------------------------------------


def drift_findings(diff: DriftDiff) -> list[dict]:
    """Render a ``DriftDiff`` as neutral, honest drift findings — one per changed fact.

    Each is a small record (``drift_kind`` ∈ {``appeared``, ``disappeared``}, the parsed
    identity fields, and a plain-language note). ``appeared`` = a confirmed FACT that was
    not confirmed last run (a new exposure to triage); ``disappeared`` = a fact that no
    longer confirms (a fix, or a detection that silently stopped firing — worth a look
    either way). These are DIFF observations over oracle-confirmed facts, NOT new oracle
    verdicts: nothing here promotes a claim. Deterministic (sorted inputs → stable order)."""
    findings: list[dict] = []
    for kind, ids in (("appeared", diff.added), ("disappeared", diff.removed)):
        note = ("a previously-unconfirmed weakness now re-fires its oracle (new exposure)"
                if kind == "appeared" else
                "a previously-confirmed fact no longer re-fires its oracle (fixed, or lost)")
        for ident in ids:
            try:
                fields = json.loads(ident)
            except (TypeError, ValueError):
                fields = {}
            findings.append({
                "drift_kind": kind,
                "identity": ident,
                "bug_class": fields.get("bug_class", ""),
                "endpoint": fields.get("endpoint", ""),
                "insertion_point": fields.get("insertion_point", ""),
                "param": fields.get("param", ""),
                "note": note,
            })
    return findings


# ---- run store ---------------------------------------------------------------


@dataclass(frozen=True)
class RunRef:
    """A pointer to one saved run in the store: its id (the run directory name), the
    re-verifiable document path, and the target it scanned (from ``meta.json``, best-effort)."""

    run_id: str
    doc_path: Path
    target: str = ""


def default_run_store() -> Path:
    """The console run store — ``framework/v2/.console/runs`` — where a launched scan saves
    its ``reverifiable.json`` (retained certs) + ``meta.json``. Computed from ``paths`` directly
    so this module never imports the console package (no import cycle)."""
    from ..common import paths
    return paths.v2_root() / ".console" / "runs"


def load_run_doc(path: str | Path) -> Any:
    """Load a run document (a report / reverifiable JSON) from disk. Raises on a missing or
    unparseable file — callers that want totality catch it."""
    return json.loads(Path(path).read_text(encoding="utf-8"))


def list_runs(base: str | Path | None = None, *, target: str | None = None) -> list[RunRef]:
    """Enumerate saved runs in the store, oldest → newest by run-id (the directory name is a
    sortable timestamp, so ordering is a PURE lexicographic sort — no wallclock read). A run
    counts only if it has a re-verifiable artifact (``reverifiable.json``, else ``report.json``).
    ``target`` filters on the run's recorded ``meta.json`` target (substring match). Total: a
    missing store or unreadable meta yields what it can, never raises."""
    root = Path(base) if base is not None else default_run_store()
    refs: list[RunRef] = []
    try:
        entries = sorted(p for p in root.iterdir() if p.is_dir())
    except OSError:
        return []
    for d in entries:
        doc = d / "reverifiable.json"
        if not doc.is_file():
            doc = d / "report.json"
        if not doc.is_file():
            continue
        tgt = ""
        try:
            meta = json.loads((d / "meta.json").read_text(encoding="utf-8"))
            tgt = str(meta.get("target", "") or "")
        except (OSError, ValueError):
            pass
        if target and target not in tgt:
            continue
        refs.append(RunRef(run_id=d.name, doc_path=doc, target=tgt))
    return refs


@dataclass(frozen=True)
class DriftReport:
    """A completed drift comparison between two named runs."""

    prev: str
    curr: str
    diff: DriftDiff
    findings: list[dict]

    def to_dict(self) -> dict:
        return {"prev": self.prev, "curr": self.curr,
                "diff": self.diff.to_dict(), "drift_findings": self.findings}


def drift_over_store(base: str | Path | None = None, *, target: str | None = None) -> DriftReport | None:
    """Diff the two most recent runs in the store (optionally filtered to ``target``). Returns
    None when fewer than two comparable runs exist. Deterministic and offline."""
    runs = list_runs(base, target=target)
    if len(runs) < 2:
        return None
    prev, curr = runs[-2], runs[-1]
    diff = diff_run_docs(load_run_doc(prev.doc_path), load_run_doc(curr.doc_path))
    return DriftReport(prev=prev.run_id, curr=curr.run_id, diff=diff,
                       findings=drift_findings(diff))


# ---- watch / cadence ---------------------------------------------------------


def watch(
    load_prev: Callable[[], Any],
    load_curr: Callable[[], Any],
    *,
    cycles: int = 1,
    interval: float = 0.0,
    sleep: Callable[[float], None] = time.sleep,
    on_diff: Callable[[int, DriftDiff], None] | None = None,
) -> list[DriftDiff]:
    """Re-fire the oracles on a cadence and diff the confirmed-fact set against the PRIOR
    cycle's set, surfacing regressions as they land in a live-updating run store.

    ``load_prev`` seeds the baseline confirmed-fact set once; then for each of ``cycles``
    iterations, ``load_curr`` is re-read, its confirmed facts re-fired, and diffed against
    the previous cycle. The cadence ``sleep`` is the ONLY clock and is injectable (tests
    pass a no-op), so the whole thing is deterministic under test. The diff at each step is
    the pure ``diff_confirmed``; it never fabricates a regression. Returns the per-cycle
    diffs (length ``cycles``)."""
    prev_ids = confirmed_fact_ids(load_prev())
    diffs: list[DriftDiff] = []
    for i in range(max(0, int(cycles))):
        if i:
            sleep(interval)
        curr_ids = confirmed_fact_ids(load_curr())
        d = diff_confirmed(prev_ids, curr_ids)
        diffs.append(d)
        if on_diff is not None:
            on_diff(i, d)
        prev_ids = curr_ids
    return diffs


# ---- CLI ---------------------------------------------------------------------


def _print_report(rep: DriftReport, *, as_json: bool) -> None:
    if as_json:
        print(json.dumps(rep.to_dict(), indent=2, sort_keys=True))
        return
    print(f"drift {rep.prev} -> {rep.curr}")
    print(f"  appeared (new)    : {len(rep.diff.added)}")
    print(f"  disappeared (gone): {len(rep.diff.removed)}")
    print(f"  unchanged         : {len(rep.diff.unchanged)}")
    for f in rep.findings:
        mark = "＋" if f["drift_kind"] == "appeared" else "－"
        loc = f["endpoint"] or f["insertion_point"] or f["param"] or "-"
        print(f"    [{mark}] {f['bug_class']} @ {loc} — {f['note']}")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="python3 -m framework.v2 drift",
        description="Continuous drift: diff the oracle-CONFIRMED fact set between two runs "
                    "(re-firing each run's retained certs). A newly-appeared fact is a "
                    "regression; a disappeared one is a fix/lost detection.",
    )
    parser.add_argument("prev", nargs="?", help="Prior run document (report/reverifiable JSON).")
    parser.add_argument("curr", nargs="?", help="Current run document (report/reverifiable JSON).")
    parser.add_argument("--run-store", action="store_true",
                        help="Ignore prev/curr and diff the two most recent runs in the "
                             "console run store (framework/v2/.console/runs).")
    parser.add_argument("--store-dir", default=None,
                        help="Run-store base dir (default: the console run store).")
    parser.add_argument("--target", default=None,
                        help="With --run-store, only consider runs whose target matches this.")
    parser.add_argument("--watch", type=float, default=None, metavar="SECS",
                        help="Re-diff on a cadence: re-read curr every SECS, diffing against "
                             "the prior cycle. Requires --baseline for the seed and --cycles.")
    parser.add_argument("--baseline", default=None,
                        help="With --watch: the baseline (prior) run document to seed from.")
    parser.add_argument("--cycles", type=int, default=1, metavar="N",
                        help="With --watch: number of re-diff cycles (bounded; default 1).")
    parser.add_argument("--json", action="store_true", help="Machine-readable JSON output.")
    parser.add_argument("--fail-on-drift", action="store_true",
                        help="Exit 3 (not 0) if the confirmed-fact set drifted at all.")
    args = parser.parse_args(argv)

    # --watch mode: cadence re-diff of a (live-updating) current doc against a baseline.
    if args.watch is not None:
        if not (args.baseline and args.curr):
            print("error: --watch requires --baseline <prev.json> and a curr document")
            return 2
        try:
            base_doc = load_run_doc(args.baseline)
        except (OSError, ValueError) as e:
            print(f"error: cannot read baseline {args.baseline}: {e}")
            return 2
        drifted = False

        def _emit(i: int, d: DriftDiff) -> None:
            nonlocal drifted
            drifted = drifted or d.has_drift
            rep = DriftReport(prev="baseline@cycle0", curr=f"cycle{i + 1}",
                              diff=d, findings=drift_findings(d))
            _print_report(rep, as_json=args.json)

        try:
            watch(lambda: base_doc, lambda: load_run_doc(args.curr),
                  cycles=args.cycles, interval=args.watch, on_diff=_emit)
        except (OSError, ValueError) as e:
            print(f"error: cannot read curr {args.curr}: {e}")
            return 2
        return 3 if (args.fail_on_drift and drifted) else 0

    # --run-store mode: pick the two most recent runs.
    if args.run_store:
        rep = drift_over_store(args.store_dir, target=args.target)
        if rep is None:
            print("drift: need at least two comparable runs in the store (none/one found)")
            return 2
        _print_report(rep, as_json=args.json)
        return 3 if (args.fail_on_drift and rep.diff.has_drift) else 0

    # default: diff two explicit documents.
    if not (args.prev and args.curr):
        print("error: provide two run documents (prev curr), or --run-store, or --watch")
        return 2
    try:
        prev_doc, curr_doc = load_run_doc(args.prev), load_run_doc(args.curr)
    except (OSError, ValueError) as e:
        print(f"error: cannot read a run document: {e}")
        return 2
    diff = diff_run_docs(prev_doc, curr_doc)
    rep = DriftReport(prev=args.prev, curr=args.curr, diff=diff, findings=drift_findings(diff))
    _print_report(rep, as_json=args.json)
    return 3 if (args.fail_on_drift and diff.has_drift) else 0
