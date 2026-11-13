"""Front C S0d — the S0 closing items:

  * FRESH-STORE FAST PATH (`SpineStore.tail_after`): the cockpit builds a new `SpineStore` per request, and a fresh
    store rebuilds its whole seq index on the first `get` / `iter_records(since_seq=…)`. The fold cache now proves
    its anchor and reads the new records from the END of the active segment: it must return EXACTLY what
    `iter_records(since_seq=anchor)` returns, or decline (None), and must never prove a wrong anchor. An anchor
    that is the last record of a gzip-sealed segment is proven from the manifest's boundary hash — no
    decompression (the sealed-anchor item);
  * REBUILD-AND-COMPARE (`FoldCache.audit` / `fold_warm.audit`): every cached fold equals a rebuild from the
    spine; an injected divergence and an in-place edit BEFORE the anchor (which the anchor check does not
    re-read — the documented gap) are both reported as MISMATCH, the entry is dropped and the next read is
    correct;
  * WARM-UP at process start + the periodic audit thread and its report, which `sigil verify` prints (a recorded
    MISMATCH fails it) and `vigil doctor` reads.
"""
from __future__ import annotations

import gzip
import itertools
import json
import random
import time

import pytest

from sigil import cli, config
from sigil.governor import customers as cu
from sigil.governor import fold_read, fold_warm
from sigil.governor import orgs as og
from sigil.governor.identity import ensure_owner_keypair
from sigil.reuse import generate_keypair
from sigil.spine import fold_cache
from sigil.spine import store as store_mod
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
OWNER_PUB = OWNER.public_key_b64
_issue = itertools.count(1)


def _iss() -> float:
    return float(next(_issue))


@pytest.fixture(autouse=True)
def _cache_on(monkeypatch):
    monkeypatch.setenv("VIGIL_FOLD_CACHE_ENABLED", "1")
    fold_cache.clear_all()
    yield
    fold_cache.clear_all()


def _append(s, n, start=0):
    for i in range(start, start + n):
        s.append(kind="event", source="t", actor="u", payload={"signal": "noise", "i": i})


# ---- tail_after == iter_records(since_seq=anchor), or an honest None ----------------------------------------
@pytest.mark.parametrize("seed", [71, 72, 73])
def test_tail_after_returns_exactly_what_iter_records_returns(tmp_path, seed):
    rng = random.Random(seed)
    p = tmp_path / "spine.jsonl"
    rotating = seed != 71
    s = SpineStore(p, seg_max_bytes=0, seg_max_records=7 if rotating else 0)
    if rotating:
        s.migrate()
    decided = 0
    for i in range(60):
        _append(s, rng.randint(1, 3), start=i * 10)
        if rotating and rng.random() < 0.15:
            s.compact()
        recs = list(SpineStore(p).iter_records())
        for anchor in [recs[-1]] + rng.sample(recs, min(4, len(recs))):
            got = SpineStore(p).tail_after(anchor.seq, anchor.entry_hash)
            if got is None:
                continue                                    # undecidable here: the indexed path answers
            assert got is not False, "a true anchor must never be refuted"
            assert got == list(SpineStore(p).iter_records(since_seq=anchor.seq))
            decided += 1
            assert SpineStore(p).tail_after(anchor.seq, "0" * 64) in (False, None), "a wrong anchor is never proven"
        assert SpineStore(p).tail_after(recs[-1].seq, recs[-1].entry_hash) == [], "the tip is always decided"
    assert decided >= 60


def test_tail_after_skips_torn_and_malformed_lines_exactly_like_iter_records(tmp_path):
    p = tmp_path / "spine.jsonl"
    s = SpineStore(p)
    _append(s, 5)
    tip = list(SpineStore(p).iter_records())[-1]
    with open(p, "ab") as f:
        f.write(b'{"not": "a record"}\n{"seq": 99, "trunc')       # a malformed line + a torn tail
    assert SpineStore(p).tail_after(tip.seq, tip.entry_hash) == list(SpineStore(p).iter_records(since_seq=tip.seq)) == []


def test_tail_after_refutes_a_rolled_back_or_rewritten_anchor(tmp_path):
    p = tmp_path / "spine.jsonl"
    s = SpineStore(p)
    _append(s, 6)
    recs = list(SpineStore(p).iter_records())
    lines = p.read_bytes().splitlines(keepends=True)
    p.write_bytes(b"".join(lines[:3]))                               # rolled back below the anchor
    assert SpineStore(p).tail_after(recs[-1].seq, recs[-1].entry_hash) is False
    p.unlink()
    other = SpineStore(p)                                            # a different spine at the same path
    other.append(kind="event", source="t", actor="x", payload={"signal": "other"})
    _append(other, 5, start=100)
    assert SpineStore(p).tail_after(recs[-1].seq, recs[-1].entry_hash) is False


def test_tail_after_never_proves_an_anchor_whose_line_was_corrupted(tmp_path):
    """A corrupted (unparseable) anchor line is a gap at `seq`: undecidable from the tail, never a delta — the
    indexed path then finds no record at the anchor and the cache rebuilds."""
    p = tmp_path / "spine.jsonl"
    s = SpineStore(p)
    _append(s, 8)
    recs = list(SpineStore(p).iter_records())
    anchor = recs[4]
    lines = p.read_bytes().splitlines(keepends=True)
    lines[4] = b"#" * (len(lines[4]) - 1) + b"\n"
    p.write_bytes(b"".join(lines))
    assert SpineStore(p).tail_after(anchor.seq, anchor.entry_hash) is None
    assert SpineStore(p).get(anchor.seq) is None


# ---- the fold cache on a FRESH store per request: no seq index, no decompression ------------------------------
def _spy_index(monkeypatch):
    calls = {"index": 0, "gzip": 0}
    real_index, real_gz = SpineStore._ensure_index, store_mod.gzip.open

    def index(self):
        calls["index"] += 1
        return real_index(self)

    def gz(*a, **kw):
        calls["gzip"] += 1
        return real_gz(*a, **kw)

    monkeypatch.setattr(SpineStore, "_ensure_index", index)
    monkeypatch.setattr(store_mod.gzip, "open", gz)
    return calls


def test_a_warm_read_through_a_fresh_store_builds_no_seq_index(tmp_path, monkeypatch):
    p = tmp_path / "spine.jsonl"
    writer = cu.CustomerRegistry(SpineStore(p), owner_key=OWNER, trusted_pubkey=OWNER_PUB)
    for i in range(30):
        writer.create(f"user{i}@example.com", issued_at=_iss())
    reader = lambda: cu.CustomerRegistry(SpineStore(p), owner_key=OWNER, trusted_pubkey=OWNER_PUB)  # noqa: E731
    assert reader().by_email("user3@example.com") is not None                  # cold build (indexes once)
    calls = _spy_index(monkeypatch)
    for i in range(30, 40):
        writer.create(f"user{i}@example.com", issued_at=_iss())
        assert reader().by_email(f"user{i}@example.com") is not None           # new store per "request"
        assert reader().by_email("nobody@example.com") is None
    assert calls["index"] == 0, "a per-request store must not rebuild the seq index to extend the cache"
    monkeypatch.setenv("VIGIL_FOLD_CACHE_ENABLED", "")
    assert [c.email for c in reader().customers()] == [c.email for c in writer.customers()]


def test_a_gzip_sealed_anchor_is_proven_from_the_manifest_without_decompressing(tmp_path, monkeypatch):
    p = tmp_path / "spine.jsonl"
    s = SpineStore(p, seg_max_bytes=0, seg_max_records=0)
    s.migrate()
    writer = cu.CustomerRegistry(s, owner_key=OWNER, trusted_pubkey=OWNER_PUB)
    for i in range(12):
        writer.create(f"user{i}@example.com", issued_at=_iss())
    assert cu.CustomerRegistry(SpineStore(p), owner_key=OWNER, trusted_pubkey=OWNER_PUB).by_email("user1@example.com")
    assert s.rotate() and s.compact() >= 1                 # the anchor is now the last record of a .gz segment
    # Built before the spy: with an EMPTY active segment, a store's own construction reads the last sealed
    # segment's final line to find the chain tip (pre-existing, once per store object, not the cache's doing).
    stores = [SpineStore(p) for _ in range(3)]
    calls = _spy_index(monkeypatch)
    for st in stores:
        assert cu.CustomerRegistry(st, owner_key=OWNER, trusted_pubkey=OWNER_PUB).by_email("user11@example.com")
    assert calls == {"index": 0, "gzip": 0}, "a sealed anchor must be proven from the manifest boundary hash"
    writer.create("late@example.com", issued_at=_iss())    # the next append lands in the new active segment
    st = SpineStore(p)
    calls.update(index=0, gzip=0)                           # only the READ is measured (not the writer's append)
    assert cu.CustomerRegistry(st, owner_key=OWNER, trusted_pubkey=OWNER_PUB).by_email("late@example.com")
    assert calls == {"index": 0, "gzip": 0}, "the delta is read from the active tail, the anchor from the manifest"


# ---- rebuild-and-compare ---------------------------------------------------------------------------------------
def _entry(cache, p):
    return cache._entries[(str(p.resolve()),)]


def _audit_customers(p) -> dict:
    """Audit the customer fold through a FRESH registry on a fresh store (as the cockpit's audit thread does)."""
    fresh = cu.CustomerRegistry(SpineStore(p), owner_key=OWNER, trusted_pubkey=OWNER_PUB)
    (rep,) = fold_read.audit_with(lambda: fresh.by_email("probe@example.com"))
    return rep


def test_an_audit_matches_after_random_activity(tmp_path):
    p = tmp_path / "spine.jsonl"
    rng = random.Random(81)
    s = SpineStore(p)
    creg = cu.CustomerRegistry(s, owner_key=OWNER, trusted_pubkey=OWNER_PUB)
    oreg = og.OrgRegistry(s, owner_key=OWNER, trusted_pubkey=OWNER_PUB)
    for i in range(40):
        op = rng.choice(["create", "revoke", "org", "noise"])
        try:
            if op == "create":
                creg.create(f"u{rng.randint(0, 9)}@example.com", issued_at=_iss())
            elif op == "revoke" and creg.customers():
                creg.revoke(rng.choice(creg.customers()).username)
            elif op == "org":
                oreg.create_org(f"org{rng.randint(0, 5)}", "Org", owner="owner", issued_at=_iss())
            else:
                _append(s, 1, start=1000 + i)
        except ValueError:
            pass
        creg.by_email("u1@example.com")
        oreg.orgs()
    fresh = SpineStore(p)
    c2 = cu.CustomerRegistry(fresh, owner_key=OWNER, trusted_pubkey=OWNER_PUB)
    o2 = og.OrgRegistry(fresh, owner_key=OWNER, trusted_pubkey=OWNER_PUB)
    by_fold = {r["fold"]: r for r in fold_read.audit_with(lambda: (c2.by_email("u1@example.com"), o2.orgs()))}
    assert set(by_fold) == {"governor.customer", "governor.org+membership"}
    assert all(r["status"] == "match" for r in by_fold.values()), by_fold


def test_an_injected_divergence_is_a_mismatch_and_the_next_read_is_rebuilt(tmp_path):
    p = tmp_path / "spine.jsonl"
    creg = cu.CustomerRegistry(SpineStore(p), owner_key=OWNER, trusted_pubkey=OWNER_PUB)
    for i in range(5):
        creg.create(f"user{i}@example.com", issued_at=_iss())
    assert creg.by_email("user2@example.com") is not None
    e = _entry(cu._CUSTOMER_FOLD, p)
    victim = next(iter(e.state.active))
    del e.state.active[victim]                              # a bookkeeping defect the anchor cannot see
    rep = _audit_customers(p)
    assert rep["status"] == "MISMATCH" and "active" in rep["difference"]
    assert _entry(cu._CUSTOMER_FOLD, p).state is not e.state, "the divergent entry was dropped and rebuilt"
    assert len(creg.customers()) == 5 and _audit_customers(p)["status"] == "match"


def test_an_in_place_edit_before_the_anchor_is_caught_by_the_audit(tmp_path, monkeypatch):
    """The documented gap: an in-place edit that breaks the chain BEFORE the anchor is not re-read by the anchor
    check, so the cache keeps serving its verified fold. The audit rebuilds from the (edited) spine — where the
    tampered grant no longer verifies — and reports the divergence."""
    p = tmp_path / "spine.jsonl"
    creg = cu.CustomerRegistry(SpineStore(p), owner_key=OWNER, trusted_pubkey=OWNER_PUB)
    for i in range(4):
        creg.create(f"user{i}@example.com", issued_at=_iss())
    assert creg.by_email("user0@example.com") is not None                  # warm
    lines = p.read_bytes().splitlines(keepends=True)
    rec = json.loads(lines[0])
    rec["payload"]["email"] = "attacker@example.com"                          # entry_hash left as it was
    lines[0] = (json.dumps(rec) + "\n").encode()
    p.write_bytes(b"".join(lines))
    assert not SpineStore(p).verify()[0], "the chain check sees the edit"
    assert creg.by_email("user0@example.com") is not None, "the anchor still holds: the cache keeps its fold"
    assert _audit_customers(p)["status"] == "MISMATCH"
    monkeypatch.setenv("VIGIL_FOLD_CACHE_ENABLED", "")
    full = creg.by_email("user0@example.com")
    monkeypatch.setenv("VIGIL_FOLD_CACHE_ENABLED", "1")
    assert creg.by_email("user0@example.com") == full, "after the audit the cache answers as the full fold"


def test_an_audit_skips_a_moved_anchor_an_empty_fold_and_another_key(tmp_path):
    p = tmp_path / "spine.jsonl"
    assert _audit_customers(p) == {"fold": "governor.customer", "status": "empty"}   # nothing cached yet
    creg = cu.CustomerRegistry(SpineStore(p), owner_key=OWNER, trusted_pubkey=OWNER_PUB)
    creg.create("user0@example.com", issued_at=_iss())
    assert creg.by_email("user0@example.com") is not None
    other = generate_keypair()
    (rep,) = fold_read.audit_with(lambda: cu.CustomerRegistry(SpineStore(p), owner_key=other,
                                                              trusted_pubkey=other.public_key_b64).by_email("x@y.z"))
    assert rep["status"] == "skipped" and "another key" in rep["reason"]
    assert creg.by_email("user0@example.com") is not None                  # back under the owner key
    p.write_bytes(b"")                                                       # reset under the live process
    rep = _audit_customers(p)
    assert rep["status"] == "skipped" and "anchor" in rep["reason"]
    assert creg.by_email("user0@example.com") is None, "rebuilt from the (reset) spine"


def test_an_entry_keeps_no_build_that_would_pin_a_request_store(tmp_path):
    """Entries must not reference the request's store or registry (each store can carry a full seq index)."""
    import gc
    import weakref
    p = tmp_path / "spine.jsonl"
    s = SpineStore(p)
    cu.CustomerRegistry(s, owner_key=OWNER, trusted_pubkey=OWNER_PUB).create("a@example.com", issued_at=_iss())
    s.get(0)                                                                 # build this store's seq index
    ref = weakref.ref(s)
    assert cu.CustomerRegistry(s, owner_key=OWNER, trusted_pubkey=OWNER_PUB).by_email("a@example.com")
    del s
    gc.collect()
    assert ref() is None, "the cached entry keeps the request's SpineStore alive"


# ---- warm-up, the audit thread and its report ------------------------------------------------------------------
WARMED_FOLDS = {
    "governor.customer", "governor.org+membership", "governor.wallet", "governor.plan_credit",
    "governor.subscription:governor.subscription", "governor.subscription:governor.monitoring_subscription",
    "governor.account", "governor.customer_credential", "governor.invoice", "governor.cost_ledger",
    "governor.trial_claim", "governor.report_unlock",
    "governor.postpaid:governor.postpaid", "governor.postpaid_arrears", "governor.promotion",
    "governor.asset_ownership_proof", "governor.asset_ownership_challenge", "governor.monitoring_authority",
    "governor.killswitch", "governor.capability", "governor.budget", "ui.assessments", "ui.margin.settle_events",
}
def _seed_owner_spine(p):
    owner = ensure_owner_keypair()
    s = SpineStore(p)
    cu.CustomerRegistry(s, owner_key=owner).create("warm@example.com", issued_at=_iss())
    og.OrgRegistry(s, owner_key=owner).create_org("acme", "Acme", owner="owner", issued_at=_iss())
    return s


def test_warm_all_builds_every_cached_fold_and_the_audit_matches(tmp_path, monkeypatch):
    s = _seed_owner_spine(tmp_path / "spine.jsonl")
    warmed = fold_warm.warm_all(s)
    assert warmed and all(w["status"] == "warm" for w in warmed), warmed
    rep = fold_warm.audit(SpineStore(s.path))
    assert rep["ok"] and {f["status"] for f in rep["folds"]} <= {"match", "empty"}
    matched = {f["fold"] for f in rep["folds"] if f["status"] == "match"}
    assert matched == WARMED_FOLDS, f"not warmed: {sorted(WARMED_FOLDS - matched)}"
    monkeypatch.setenv("VIGIL_FOLD_CACHE_ENABLED", "")
    assert fold_warm.warm_all(s) == [] and fold_warm.start_background(lambda: s) is None


def test_the_background_thread_warms_then_writes_the_audit_report(tmp_path, monkeypatch):
    s = _seed_owner_spine(tmp_path / "spine.jsonl")
    report = tmp_path / "audit.json"
    monkeypatch.setattr(config, "FOLD_AUDIT_PATH", report)
    monkeypatch.setenv("VIGIL_FOLD_CACHE_AUDIT_S", "0.2")
    monkeypatch.setattr(fold_warm, "_STARTED", set())
    stop = fold_warm.start_background(lambda: SpineStore(s.path), name="test")
    try:
        assert stop is not None and fold_warm.start_background(lambda: SpineStore(s.path)) is None
        deadline = time.monotonic() + 30
        while not report.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        rep = json.loads(report.read_text())
        assert rep["ok"] and rep["interval_s"] == 0.2 and (report.stat().st_mode & 0o777) == 0o600
    finally:
        stop.set()
        stop.thread.join(timeout=60)                  # never let it outlive the monkeypatched report path
    assert not stop.thread.is_alive()


def test_the_audit_interval_parses_fail_safe(monkeypatch):
    for raw, want in [("", 21600.0), ("junk", 21600.0), ("0", 0.0), ("-5", 0.0), ("nan", 0.0), ("inf", 0.0),
                      ("90", 90.0)]:
        monkeypatch.setenv("VIGIL_FOLD_CACHE_AUDIT_S", raw)
        assert config.fold_cache_audit_interval() == want, raw


def test_sigil_verify_prints_the_audit_and_fails_on_a_recorded_mismatch(tmp_path, monkeypatch, capsys):
    report = tmp_path / "audit.json"
    monkeypatch.setattr(config, "FOLD_AUDIT_PATH", report)
    assert cli._verify_fold_caches(False) is True and capsys.readouterr().out == "", "no report: no line"
    report.write_text(json.dumps({"ts": "2026-11-11T00:00:00+00:00", "pid": 7, "folds": [
        {"fold": "governor.customer", "status": "match", "seq": 4}]}))
    assert cli._verify_fold_caches(False) is True and "folds OK" in capsys.readouterr().out
    report.write_text(json.dumps({"ts": "2026-11-11T00:00:00+00:00", "pid": 7, "folds": [
        {"fold": "governor.wallet", "status": "MISMATCH", "seq": 9, "difference": "state.granted"}]}))
    assert cli._verify_fold_caches(False) is False
    out = capsys.readouterr().out
    assert "folds FAIL" in out and "governor.wallet at seq 9" in out


def test_sigil_verify_folds_rebuilds_in_process(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(config, "FOLD_AUDIT_PATH", tmp_path / "none.json")
    spine = tmp_path / "spine.jsonl"                  # never the session's default spine
    _seed_owner_spine(spine)
    monkeypatch.setattr(cli, "SpineStore", lambda *a, **kw: SpineStore(spine))
    assert cli._verify_fold_caches(True) is True
    assert "rebuilt" in capsys.readouterr().out
    monkeypatch.setenv("VIGIL_FOLD_CACHE_ENABLED", "")
    assert cli._verify_fold_caches(True) is True and "needs VIGIL_FOLD_CACHE_ENABLED" in capsys.readouterr().out


def test_gzip_module_is_the_one_the_store_reads_through():
    assert store_mod.gzip is gzip


def test_the_cockpit_starts_the_warm_up_at_boot(monkeypatch, capsys):
    from sigil.ui import server as srv_mod

    class _Srv:
        server_address = ("127.0.0.1", 8733)

        def store(self):
            return SpineStore(config.SPINE_PATH)

        def serve_forever(self):
            raise KeyboardInterrupt

        def shutdown(self):
            pass

        def server_close(self):
            pass

    fake = _Srv()
    seen = {}
    monkeypatch.setattr(srv_mod, "build_server", lambda **kw: fake)
    monkeypatch.setattr(fold_warm, "start_background",
                        lambda factory, name: seen.update(factory=factory, name=name) or object())
    srv_mod.serve(token="t")
    assert seen == {"factory": fake.store, "name": "cockpit"}
    assert "fold cache: warming in the background" in capsys.readouterr().out
