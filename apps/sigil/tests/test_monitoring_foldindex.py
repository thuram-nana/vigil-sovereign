"""Front C S0d follow-up — the monitoring bell poll (`inbound/monitoring_spool.monitoring_events`) reads from a
verified INCREMENTAL per-org fold, O(its own events), not an O(N) `iter_records()` scan of the whole spine.

Mirrors `test_front_c_scale.py`'s P1/P2 for this one read, with a counting instrument that measures RECORDS FOLDED
(the monitoring fold verifies no signatures — it is the unsigned, `live_window` twin of the assessments fold):

  * EQUIVALENCE — the folded read (cache ON) returns EXACTLY the flag-OFF scan, at several N, every org, every
    limit edge, first-wins report_id dedup, and on REALLY DRAINED events (fidelity).
  * P1 INCREMENTAL — a warm read folds ZERO records when nothing was appended; k new events fold EXACTLY k; FLAT
    (0) across a sweep of N (if it were O(N) the warm fold count would track N). The cold full fold grows with N —
    the wall the cache removes.
  * P2 O(RETURNED) — a per-org read touches a BOUNDED number of index entries regardless of the number of orgs
    (proven by wrapping the warmed view's own `by_org` dict with a counting Mapping — a regression that scanned
    every org would register >= #orgs).
  * TENANT — an org sees only its own events.
  * FLAG-OFF — with the cache off the read is the unchanged scan, byte-identical, and the fold is never consulted.

Run: SIGIL_HOME=$(mktemp -d) .venv-sovereign/bin/python -m pytest apps/sigil/tests/test_monitoring_foldindex.py -q
"""
from __future__ import annotations

import contextlib
import json
import os
from typing import Any, Callable

import pytest

from sigil.inbound import monitoring_spool as ms
from sigil.spine import fold_cache
from sigil.spine.store import SpineStore
from test_monitoring_spool import _drop, _report, _rig, _seal   # the real drain rig (ownership proof + MAC + authority)


@pytest.fixture(autouse=True)
def _cache_on(monkeypatch):
    monkeypatch.setenv("VIGIL_FOLD_CACHE_ENABLED", "1")
    fold_cache.clear_all()
    yield
    fold_cache.clear_all()


# --- the spine under test: monitoring events, shaped EXACTLY as the drain's `_record` writes them --------------
def _ev_payload(org: str, i: int, *, report_id=None, host="h.example.com", decision="confirmed") -> dict:
    return {"signal": ms.EVENT_SIGNAL, "source_class": "gateway_reported", "org_id": org, "host": host,
            "ts": 1000.0 + i, "decision": decision, "attack_class": "sqli", "action": "observe", "confidence": 0.9,
            "provenance_tier": "certified", "certificate_sha256": "c" * 64,
            "report_id": report_id if report_id is not None else f"{org}-r{i}"}


def _append_event(store: SpineStore, org: str, i: int, **kw) -> int:
    return store.append(kind="event", source="aegis", actor="AEGIS", payload=_ev_payload(org, i, **kw))


def _seed(store: SpineStore, org: str, n: int, start: int = 0) -> None:
    for i in range(start, start + n):
        _append_event(store, org, i)


def _read_flag_off(fn: Callable[[], Any]) -> Any:
    """Run `fn` with the fold cache OFF (the unchanged full scan), restoring the flag after."""
    old = os.environ.get("VIGIL_FOLD_CACHE_ENABLED")
    os.environ["VIGIL_FOLD_CACHE_ENABLED"] = ""
    try:
        return fn()
    finally:
        if old is None:
            os.environ.pop("VIGIL_FOLD_CACHE_ENABLED", None)
        else:
            os.environ["VIGIL_FOLD_CACHE_ENABLED"] = old


# --- instrument 1: records folded (the monitoring fold's `step`), for the incrementality proof ----------------
@contextlib.contextmanager
def _counting_steps():
    """Count every record the monitoring fold folds (`_MONITORING_FOLD._step`): a warm read that folds nothing
    counts 0, k appends count k. The scan never calls `step`, so a read served by the scan counts 0 too — which is
    why the cold read must count > 0 (it proves the FOLD, not the scan, served the measured reads)."""
    counter = [0]
    fold = ms._MONITORING_FOLD
    real = fold._step

    def counting(view, r, ctx):
        counter[0] += 1
        return real(view, r, ctx)

    fold._step = counting
    try:
        yield counter
    finally:
        fold._step = real


def test_counting_steps_counts_every_folded_record(tmp_path):
    """The instrument's self-test: a cold read folds EVERY record on the spine exactly once, so the count equals
    the record count — hence a later count of 0 means 0 records folded, not a miscount."""
    store = SpineStore(str(tmp_path / "self.jsonl"))
    _seed(store, "acme", 7)
    total = len(list(store.iter_records()))
    assert total >= 7
    with _counting_steps() as c:
        ms.monitoring_events(store, "acme")                 # cold: folds every record once
        assert c[0] == total


# --- instrument 2: index-entry touches (the view's `by_org`), for the O(returned) proof -----------------------
class _CountingDict(dict):
    """Counts every element access: a lookup (`get`/`[]`/`in`) is one, and every iteration API is one PER ELEMENT,
    so an O(#orgs) scan registers #orgs however it is spelled. Dropped into the warmed view's `by_org` slot."""

    __slots__ = ("_counter",)

    def __init__(self, inner: dict, counter: list) -> None:
        super().__init__(inner)
        self._counter = counter

    def get(self, key, default=None):
        self._counter[0] += 1
        return super().get(key, default)

    def __getitem__(self, key):
        self._counter[0] += 1
        return super().__getitem__(key)

    def __contains__(self, key):
        self._counter[0] += 1
        return super().__contains__(key)

    def __iter__(self):
        for k in super().__iter__():
            self._counter[0] += 1
            yield k

    def keys(self):  # type: ignore[override]
        return list(self.__iter__())

    def values(self):  # type: ignore[override]
        return [super(_CountingDict, self).__getitem__(k) for k in self.__iter__()]

    def items(self):  # type: ignore[override]
        return [(k, super(_CountingDict, self).__getitem__(k)) for k in self.__iter__()]


def test_counting_dict_counts_every_scan_spelling():
    """The instrument's self-test: a lookup costs 1, a scan costs >= #elements however spelled — so the O(returned)
    proof below cannot be false-passed by re-spelling a scan of all orgs."""
    c: list = [0]
    d = _CountingDict({i: str(i) for i in range(40)}, c)
    for op in (lambda: d.get(3), lambda: d[3], lambda: 3 in d):
        c[0] = 0
        op()
        assert c[0] == 1
    for op in (lambda: list(d), lambda: d.keys(), lambda: d.values(), lambda: d.items(), lambda: sorted(d),
               lambda: set(d)):
        c[0] = 0
        op()
        assert c[0] >= 40


def _single_view():
    entries = list(ms._MONITORING_FOLD._entries.values())
    assert len(entries) == 1, f"expected exactly one warmed fold entry, got {len(entries)}"
    return entries[0].state


# ============ EQUIVALENCE — the folded read equals the scan ===========================================
def test_folded_read_equals_the_scan(tmp_path):
    """The cache changed HOW the read is served, never WHAT it says: for several N, every org and every limit edge,
    the folded read (cache ON) == the flag-OFF scan, byte for byte."""
    for n in (1, 25, 400):
        store = SpineStore(str(tmp_path / f"eq-{n}.jsonl"))
        for org in ("acme", "globex", "initech"):
            _seed(store, org, n)
        fold_cache.clear_all()
        for org in ("acme", "globex", "initech", "absent"):
            for lim in (200, 1, 0, 3, n + 5):
                got = ms.monitoring_events(store, org, limit=lim)
                want = _read_flag_off(lambda s=store, o=org, l=lim: ms.monitoring_events(s, o, limit=l))
                assert got == want, (n, org, lim)


def test_dedup_keeps_the_first_occurrence_like_the_scan(tmp_path):
    """report_id dedup is FIRST-wins (lowest seq), exactly the scan's `rid in seen` over records in seq order — a
    later record re-using a report_id is dropped, and the kept row is the earlier one's."""
    store = SpineStore(str(tmp_path / "dedup.jsonl"))
    _append_event(store, "acme", 1, report_id="DUP", decision="confirmed")
    _append_event(store, "acme", 2, report_id="other", decision="lead")
    _append_event(store, "acme", 3, report_id="DUP", decision="lead")        # same rid, later — dropped
    got = ms.monitoring_events(store, "acme")
    assert got == _read_flag_off(lambda: ms.monitoring_events(store, "acme"))
    kept = [e for e in got if e["report_id"] == "DUP"]
    assert len(kept) == 1 and kept[0]["decision"] == "confirmed"             # the FIRST occurrence won
    assert [e["report_id"] for e in got] == ["other", "DUP"]                 # newest-first by kept seq


def test_limit_edges_match_the_scan(tmp_path):
    store = SpineStore(str(tmp_path / "lim.jsonl"))
    _seed(store, "acme", 10)
    for lim in (0, 1, 5, 10, 100, -3):
        got = ms.monitoring_events(store, "acme", limit=lim)
        assert got == _read_flag_off(lambda l=lim: ms.monitoring_events(store, "acme", limit=l)), lim
    assert ms.monitoring_events(store, "acme", limit=0) == []
    assert len(ms.monitoring_events(store, "acme", limit=3)) == 3


def test_absent_and_invalid_org_are_empty(tmp_path):
    store = SpineStore(str(tmp_path / "inv.jsonl"))
    _seed(store, "acme", 3)
    assert ms.monitoring_events(store, "absent") == []
    assert ms.monitoring_events(store, "") == []
    assert ms.monitoring_events(store, None) == []       # type: ignore[arg-type]


def test_fold_equals_scan_on_really_drained_events():
    """Fidelity (P5): the fold == the scan on events written by the REAL drain (MAC-verified, authority-bound) —
    so the fast direct-append seed above is not vacuous; a drained event folds exactly like a seeded one."""
    s, _reg, w = _rig()
    for org, host in (("org_a", "apme.cm"), ("org_b", "beta.cm")):
        for _ in range(4):
            _drop(w, _seal(_report(org=org, host=host)))
    assert w.drain()["recorded"] == 8
    for org in ("org_a", "org_b"):
        got = ms.monitoring_events(s, org)
        assert got == _read_flag_off(lambda o=org: ms.monitoring_events(s, o))
        assert len(got) == 4 and all(e["org_id"] == org for e in got)


# ============ P1 — incremental: a warm read folds 0, k appends fold k, FLAT in N ======================
_SWEEP = tuple(sorted({500, 2000, int(os.environ.get("VIGIL_SCALE_N", "2000"))}))


def test_p1_warm_read_is_flat_in_N_and_appends_cost_exactly_k(tmp_path):
    """The headline scale claim. Across a sweep of N, a warm per-request read folds ZERO records and k appends
    fold EXACTLY k — both INDEPENDENT of N. The cold full fold grows with N (the wall the cache removes). If any
    read were O(N) its warm fold count would track N, not stay 0."""
    warm_counts, cold_counts = [], []
    for n in _SWEEP:
        store = SpineStore(str(tmp_path / f"p1-{n}.jsonl"))
        _seed(store, "acme", n)
        _seed(store, "globex", n)                           # a second org: the fold is multi-org at scale
        total = len(list(store.iter_records()))
        with _counting_steps() as c:
            ms.monitoring_events(store, "acme")             # COLD: folds every record (proves the FOLD served it)
            cold_counts.append(c[0])
            assert c[0] == total and total > 0, f"cold folded {c[0]} != {total}"
            c[0] = 0
            ms.monitoring_events(store, "acme")             # WARM reads: nothing new -> fold nothing
            ms.monitoring_events(store, "globex")
            assert c[0] == 0, f"a warm read at N={n} folded {c[0]} records (expected 0 — O(N)?)"
            warm_counts.append(c[0])
            k = 3
            for i in range(k):
                _append_event(store, "acme", n + i, report_id=f"acme-new-{n}-{i}")
            ms.monitoring_events(store, "acme")             # one warm read folds EXACTLY the k new records
            assert c[0] == k, f"{k} appends at N={n} folded {c[0]} records (expected {k})"
    assert warm_counts == [0] * len(_SWEEP), f"warm cost not flat across N: {warm_counts}"
    assert all(cold > 0 for cold in cold_counts) and cold_counts == sorted(cold_counts)
    assert cold_counts[-1] > cold_counts[0], f"the cold full fold did not grow with N: {cold_counts}"


# ============ P2 — a per-org read is O(returned), not a scan of all orgs ===============================
def test_p2_per_org_read_is_O_returned_not_a_scan_of_all_orgs(tmp_path):
    """A per-org read touches a BOUNDED number of `by_org` entries regardless of the number of orgs, while an
    all-orgs scan would touch >= #orgs. Measured by wrapping the warmed view's own `by_org` dict with a counting
    Mapping, so a regression that turned the per-org lookup into a scan of every org is caught."""
    store = SpineStore(str(tmp_path / "p2.jsonl"))
    n_orgs = 500
    for j in range(n_orgs):
        _seed(store, f"org{j}", 2)
    ms.monitoring_events(store, "org0")                     # warm the cache (one entry, every org folded)
    view = _single_view()
    counter: list = [0]
    original = view.by_org
    view.by_org = _CountingDict(original, counter)
    try:
        got = ms.monitoring_events(store, f"org{n_orgs // 2}")   # ONE org
        assert len(got) == 2
        per_org = counter[0]
        counter[0] = 0
        _ = sum(1 for _ in view.by_org)                     # a hypothetical all-orgs scan
        all_orgs = counter[0]
        assert _single_view() is view, "the measured read was not served by the instrumented entry"
    finally:
        view.by_org = original
    assert per_org <= 4, f"a per-org read touched {per_org} index entries at {n_orgs} orgs (expected O(1))"
    assert all_orgs >= n_orgs, f"an all-orgs scan touched {all_orgs} (expected >= {n_orgs}) — the instrument is blind"


# ============ TENANT — an org sees only its own events ================================================
def test_tenant_scoped_an_org_sees_only_its_own(tmp_path):
    store = SpineStore(str(tmp_path / "tenant.jsonl"))
    orgs = [f"t{j}" for j in range(20)]
    for j, org in enumerate(orgs):
        _seed(store, org, 3, start=j * 100)
    all_rids = {f"{o}-r{j * 100 + i}" for j, o in enumerate(orgs) for i in range(3)}
    for org in orgs:
        got = ms.monitoring_events(store, org)
        assert got and all(e["org_id"] == org for e in got), org
        mine = {f"{org}-r{orgs.index(org) * 100 + i}" for i in range(3)}
        rids = {e["report_id"] for e in got}
        assert rids == mine                                 # exactly its own
        assert not (rids & (all_rids - mine)), org          # and never another org's


# ============ FLAG-OFF — byte-identical and the fold is never consulted ===============================
def test_flag_off_is_byte_identical_and_never_folds(tmp_path):
    """With the cache OFF the read is the unchanged scan — byte-identical to the cached answer — and the fold's
    `step` is never called (the scan does not touch the fold), nor is any fold entry built."""
    store = SpineStore(str(tmp_path / "off.jsonl"))
    _seed(store, "acme", 20)
    _seed(store, "globex", 20)
    for org in ("acme", "globex", "absent"):
        for lim in (200, 1, 0):
            on = ms.monitoring_events(store, org, limit=lim)
            with _counting_steps() as c:
                off = _read_flag_off(lambda o=org, l=lim: ms.monitoring_events(store, o, limit=l))
                assert c[0] == 0, "the flag-off scan must never fold a record"
            assert on == off, (org, lim)
    fold_cache.clear_all()
    _read_flag_off(lambda: ms.monitoring_events(store, "acme"))
    assert ms._MONITORING_FOLD._entries == {}, "a flag-off read must not build a fold entry"
