"""AEGIS AS-3c part 3 — drain-boundary hardening: ACCEPT-SET admission control + DEDUP (at-most-once).

Parts 1+2 made the strict drain crash-durable (``test_monitoring_drain_hardening``) and flood-isolated
(``test_monitoring_drain_flood``). Part 3 closes the last two slices of the AS-3c scope
(``accept-set; DRR; dedup; append-rate budget`` — FORGE-DOMAIN-MAP) over the SAME per-domain subtree drain:

  * ACCEPT-SET. A report is drained for a declared domain only if its OWN authenticated ``(org_id, host)``
    slugs to the ``incoming/<slug>/`` subtree it was filed under — checked AFTER the MAC, so the identity is
    trusted. A correctly-sealed report of ANOTHER tenant (its real secret, an active authority) mis-filed into
    this subtree PASSES the MAC but is REJECTED/quarantined here. The MAC proves *who produced it*; the accept-set
    proves it belongs to *the domain whose drain path drained it* (binding AS-3a location isolation to identity).

  * DEDUP. A bounded, file-persisted ``(org_id, report_id)`` window (``<spool>/.dedup-window``, read + superseded
    under the SAME single-drainer flock as the DRR cursor, so it survives a drainer restart) makes a re-delivered
    report drain AT MOST ONCE — even when it is re-emitted with a FRESH envelope (same ``report_id``, different
    bytes -> a content hash the ``processed/<sha256>`` marker cannot catch). Fail-closed: a CORRUPT window is
    UNTRUSTED and a window-miss falls back to the authoritative durable spine baseline — never a double-drain.

DETERMINISTIC (no wall-clock in the accept-set or dedup math). FATAL-2: sovereign-only (``monitoring_spool``
imports no framework/strix). Counts are read RAW (``_raw_events`` is NOT report_id-deduped, so a double-spine
shows as a count of 2 — the read-side ``monitoring_events`` dedup would otherwise MASK it).
"""
from __future__ import annotations

import hashlib
import hmac
import itertools
import json
import os
import tempfile
from pathlib import Path

import pytest

from sigil.governor.asset_ownership import METHOD_DNS_TXT, AssetOwnershipRegistry
from sigil.governor.monitoring_authority import MonitoringAuthorityRegistry
from sigil.inbound import monitoring_spool as ms
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
NOW = 1_000_000.0
A = ("org_a", "apme.cm")
B = ("org_b", "beta.cm")
C = ("org_c", "gamma.cm")
SECRETS = {A: b"A" * 32, B: b"B" * 32, C: b"C" * 32}
_n = itertools.count(1)


def _store() -> SpineStore:
    return SpineStore(os.path.join(tempfile.mkdtemp(), "spine.jsonl"))


def _grant(store: SpineStore, org: str, host: str) -> MonitoringAuthorityRegistry:
    own = AssetOwnershipRegistry(store, owner_key=OWNER, trusted_pubkey=OWNER.public_key_b64)
    ch = own.issue_challenge(org, host, issued_at=NOW - 100)
    own.verify_and_record(org, host, method=METHOD_DNS_TXT, observed=[ch.marker], now=NOW - 99, ttl_seconds=1e9)
    reg = MonitoringAuthorityRegistry(store, owner_key=OWNER, trusted_pubkey=OWNER.public_key_b64)
    reg.grant(org, host, not_before=NOW - 50, not_after=NOW + 1e6, now=NOW - 50)
    return reg


def _rig(domains=(A, B), grants=None, **kw):
    s = _store()
    reg = None
    for o, h in (grants if grants is not None else domains):
        reg = _grant(s, o, h)
    w = ms.MonitoringSpoolWatcher(s, spool_dir=tempfile.mkdtemp(), secret_for=lambda o, h: SECRETS.get((o, h)),
                                  authority=reg, now_fn=lambda: NOW, domains=domains, **kw)
    return s, w


def _report(org="org_a", host="apme.cm", **kw) -> dict:
    rep = {"schema": ms.REPORT_SCHEMA, "org_id": org, "host": host, "ts": NOW - 10, "decision": "confirmed",
           "attack_class": "sqli", "action": "observe", "confidence": 0.9, "provenance_tier": "certified",
           "certificate_sha256": "c" * 64, "report_id": f"r{next(_n)}"}
    rep.update(kw)
    return rep


def _seal(rep: dict, secret: bytes | None = None) -> str:
    body = json.dumps(rep, sort_keys=True, separators=(",", ":"))
    key = secret if secret is not None else SECRETS[(rep["org_id"], rep["host"])]
    mac = hmac.new(key, ms.REPORT_DOMAIN + body.encode(), hashlib.sha256).hexdigest()
    return json.dumps({"schema": ms.REPORT_SCHEMA, "body": body, "mac": mac})


def _raw_events(s: SpineStore) -> list[dict]:
    return [r.payload for r in s.iter_records()
            if isinstance(r.payload, dict) and r.payload.get("signal") == ms.EVENT_SIGNAL]


def _raw_ids(s: SpineStore, org: str) -> list[str]:
    return [p.get("report_id") for p in _raw_events(s) if p.get("org_id") == org]


def _alerts(s: SpineStore) -> list[dict]:
    return [r.payload for r in s.iter_records()
            if isinstance(r.payload, dict) and r.payload.get("signal") == ms.DRAIN_ALERT_SIGNAL]


def _subdir(w, org: str, host: str) -> Path:
    d = w.incoming / ms.domain_slug(org, host)
    d.mkdir(parents=True, exist_ok=True)
    return d


def _drop(w, rep: dict, name=None) -> Path:
    """Drop a sealed report into ITS OWN declared subtree (the correct location)."""
    p = _subdir(w, rep["org_id"], rep["host"]) / (name or f"{next(_n)}.json")
    p.write_text(_seal(rep))
    return p


def _drop_into(w, rep: dict, org: str, host: str, name=None) -> Path:
    """Drop a sealed report into the (org, host) subtree — used to MIS-FILE a report into another domain."""
    p = _subdir(w, org, host) / (name or f"{next(_n)}.json")
    p.write_text(_seal(rep))
    return p


# ============================================================================================================
# ACCEPT-SET — admission control at the drain boundary
# ============================================================================================================

def test_accept_set_accepts_an_in_set_report():
    # POSITIVE control: a correctly-sealed report filed in ITS OWN declared subtree is admitted and spined.
    s, w = _rig(domains=(A, B))
    rep = _report(org="org_a", host="apme.cm")
    _drop(w, rep)
    r = w.drain()
    assert r["recorded"] == 1 and r["rejected"] == 0
    assert _raw_ids(s, "org_a") == [rep["report_id"]]
    assert _alerts(s) == []                                    # a clean pass raises no strictness alert


def test_accept_set_rejects_a_correctly_sealed_report_misfiled_into_another_domain():
    # THE headline negative. org_b is a LEGITIMATE tenant: its real secret, an ACTIVE authority. A valid org_b
    # report is mis-filed into org_a's declared subtree. It PASSES the MAC (B's own secret) and B's authority —
    # so neither the MAC bind nor the freshness/authority checks catch it — but the ACCEPT-SET rejects it: its
    # (org_b, beta.cm) does not slug to org_a's subtree. Nothing is spined for org_b; it is quarantined + alerted.
    s, w = _rig(domains=(A, B))
    rep_b = _report(org="org_b", host="beta.cm")              # sealed with B's REAL secret (a valid report)
    _drop_into(w, rep_b, *A)                                  # ... but dropped into org_a's declared subtree
    r = w.drain()
    assert (r["recorded"], r["rejected"]) == (0, 1)
    assert _raw_events(s) == []                               # NOTHING spined — not for org_b, not for org_a
    assert len(_alerts(s)) == 1 and _alerts(s)[0]["poisoned"] == 1   # the rejection fired the coalesced alert
    # the quarantine reason names the accept-set (not a MAC/authority failure — those passed).
    reasons = [p.read_text() for p in w.rejected.glob("*.reason")]
    assert any("accept-set" in t for t in reasons)


def test_accept_set_does_not_disturb_the_sibling_domains_own_reports():
    # Isolation holds: org_a's own valid reports drain while a mis-filed org_b report in org_a's subtree is
    # rejected, and org_b's OWN subtree still drains normally. One tenant's mis-file never taints another's drain.
    s, w = _rig(domains=(A, B))
    a_ids = [_report(org="org_a", host="apme.cm") for _ in range(3)]
    for rep in a_ids:
        _drop(w, rep)
    _drop_into(w, _report(org="org_b", host="beta.cm"), *A)   # a mis-filed (valid) B report in A's subtree
    b_ids = [_report(org="org_b", host="beta.cm") for _ in range(2)]
    for rep in b_ids:
        _drop(w, rep)
    r = w.drain()
    assert r["recorded"] == 5 and r["rejected"] == 1
    assert sorted(_raw_ids(s, "org_a")) == sorted(x["report_id"] for x in a_ids)
    assert sorted(_raw_ids(s, "org_b")) == sorted(x["report_id"] for x in b_ids)   # only B's OWN-subtree reports


def test_accept_set_rejection_spends_no_append_budget():
    # The accept-set rejection happens BEFORE _record, so a mis-filed report never spends a RECORDED write of the
    # append budget — a flood of mis-filed reports cannot consume the per-pass spine-write budget of the domain
    # whose subtree they were dumped into.
    s, w = _rig(domains=(A, B), append_ceiling_per_s=2.0, pass_window_s=1.0)   # budget 2 writes/pass
    for _ in range(10):
        _drop_into(w, _report(org="org_b", host="beta.cm"), *A)   # 10 mis-filed (valid) B reports in A's subtree
    good = _report(org="org_a", host="apme.cm")
    _drop(w, good)                                                 # one legit A report
    r = w.drain()
    assert r["recorded"] == 1 and _raw_ids(s, "org_a") == [good["report_id"]]   # the budget served the real report
    assert r["rejected"] == 10 and _raw_events(s) == [e for e in _raw_events(s) if e["org_id"] == "org_a"]


def test_global_mode_has_no_accept_set_and_writes_no_dedup_window():
    # The accept-set + dedup window are STRICT-only (like DRR / the budget). Global mode (domains=None) keeps the
    # unchanged identity-only admission and writes NO .dedup-window / lock / drr-cursor — byte-identical.
    s = _store()
    reg = _grant(s, *A)
    w = ms.MonitoringSpoolWatcher(s, spool_dir=tempfile.mkdtemp(), secret_for=lambda o, h: SECRETS.get((o, h)),
                                  authority=reg, now_fn=lambda: NOW, domains=None)   # GLOBAL
    rep = _report(org="org_a", host="apme.cm")
    (w.incoming / "r.json").write_text(_seal(rep))                # placed flat — no subtree, no accept-set
    r = w.drain()
    assert r["recorded"] == 1 and set(r) == {"recorded", "rejected", "deduped", "seqs"}
    assert not (w.spool / ms._DEDUP_FILE).exists()               # global mode persists no dedup window


# ============================================================================================================
# DEDUP — at-most-once over the bounded, flock-persisted (org, report_id) window
# ============================================================================================================

def test_redelivered_report_fresh_envelope_same_id_drains_at_most_once():
    # The gap the content marker CANNOT close: the SAME logical report (same report_id) re-emitted with DIFFERENT
    # bytes (a refined field -> a different envelope -> a different sha256). Without the report_id window both
    # spine twice; with it, the re-delivery is deduped.
    s, w = _rig(domains=(A,))
    rid = "stable-report-id-1"
    rep1 = _report(org="org_a", host="apme.cm", report_id=rid, confidence=0.9)
    rep2 = _report(org="org_a", host="apme.cm", report_id=rid, confidence=0.95)   # same id, DIFFERENT bytes
    assert _seal(rep1) != _seal(rep2)                           # distinct content hashes (marker cannot catch it)
    _drop(w, rep1)
    assert w.drain()["recorded"] == 1
    _drop(w, rep2)
    r = w.drain()
    assert r["recorded"] == 0 and r["deduped"] == 1
    assert _raw_ids(s, "org_a").count(rid) == 1                 # spined EXACTLY once (RAW count, not read-deduped)


def test_dedup_window_persists_across_a_simulated_drainer_restart():
    # The window must survive a drainer RESTART (a systemd/cron/CLI drain unit reconstructs the watcher each run),
    # exactly like the DRR rotation cursor — else a fresh process would re-record a re-delivery. A BRAND-NEW
    # watcher per pass shares one spool + store; the window read from <spool>/.dedup-window still dedups.
    s = _store()
    reg = None
    for o, h in (A,):
        reg = _grant(s, o, h)
    spool = tempfile.mkdtemp()

    def fresh():
        return ms.MonitoringSpoolWatcher(s, spool_dir=spool, secret_for=lambda o, h: SECRETS.get((o, h)),
                                         authority=reg, now_fn=lambda: NOW, domains=(A,))

    rid = "survives-restart-1"
    w1 = fresh()
    _drop(w1, _report(org="org_a", host="apme.cm", report_id=rid, confidence=0.9))
    assert w1.drain()["recorded"] == 1
    assert (Path(spool) / ms._DEDUP_FILE).exists()             # the window was persisted to disk
    w2 = fresh()                                               # a FRESH process — its window is read from disk
    _drop(w2, _report(org="org_a", host="apme.cm", report_id=rid, confidence=0.99))   # same id, fresh bytes
    r = w2.drain()
    assert r["deduped"] == 1 and r["recorded"] == 0
    assert _raw_ids(s, "org_a").count(rid) == 1                 # still exactly once across the restart


def test_distinct_reports_are_not_falsely_deduped():
    # The dedup key is (org, report_id): distinct report_ids are NEVER collapsed, and the SAME report_id under a
    # DIFFERENT org is NOT deduped (the key carries the org). All four distinct records drain.
    s, w = _rig(domains=(A, B))
    rid = "shared-id"
    reps = [
        _report(org="org_a", host="apme.cm", report_id="a-1"),
        _report(org="org_a", host="apme.cm", report_id="a-2"),   # distinct id, same org -> not deduped
        _report(org="org_a", host="apme.cm", report_id=rid),
        _report(org="org_b", host="beta.cm", report_id=rid),     # same id, DIFFERENT org -> not deduped
    ]
    for rep in reps:
        _drop(w, rep)
    r = w.drain()
    assert r["recorded"] == 4 and r["deduped"] == 0
    assert sorted(_raw_ids(s, "org_a")) == ["a-1", "a-2", rid]
    assert _raw_ids(s, "org_b") == [rid]


def test_redelivery_within_the_same_pass_is_deduped():
    # Two files carrying the same report_id with DIFFERENT bytes, both present in ONE pass: the window dedups the
    # second within the pass (the in-memory window updates on the first record), so only one spines.
    s, w = _rig(domains=(A,))
    rid = "same-pass-dup"
    _drop(w, _report(org="org_a", host="apme.cm", report_id=rid, confidence=0.9), name="001.json")
    _drop(w, _report(org="org_a", host="apme.cm", report_id=rid, confidence=0.95), name="002.json")
    r = w.drain()
    assert r["recorded"] == 1 and r["deduped"] == 1
    assert _raw_ids(s, "org_a").count(rid) == 1


def test_dedup_window_is_bounded_to_its_cap():
    # The window is BOUNDED (dedup_window). With a cap of 1 it retains only the most-recent key: a re-delivery of
    # the CURRENT key is deduped, but a key that has been evicted past the cap is re-recorded — proving the window
    # is bounded (not an unbounded ledger). Each report uses fresh bytes so the content marker is never the dedup.
    s, w = _rig(domains=(A,), dedup_window=1)
    assert w.dedup_window_cap == 1
    x = "evict-x"
    _drop(w, _report(org="org_a", host="apme.cm", report_id=x, confidence=0.1))
    assert w.drain()["recorded"] == 1                          # X recorded; window = {X}
    _drop(w, _report(org="org_a", host="apme.cm", report_id=x, confidence=0.2))
    assert w.drain()["deduped"] == 1                           # re-delivery of the CURRENT key X -> deduped
    _drop(w, _report(org="org_a", host="apme.cm", report_id="evict-y", confidence=0.3))
    assert w.drain()["recorded"] == 1                          # Y recorded; window evicts X -> {Y}
    _drop(w, _report(org="org_a", host="apme.cm", report_id=x, confidence=0.4))
    assert w.drain()["recorded"] == 1                          # X aged out of the bounded window -> re-recorded


# ============================================================================================================
# DEDUP — fail-closed on a corrupt / hostile window
# ============================================================================================================

def test_corrupt_dedup_window_falls_back_to_the_spine_and_never_double_drains():
    # Fail-closed: a CORRUPT window must not cause a double-drain. Record X (window written), then clobber the
    # window file with garbage; a re-delivery of X (fresh bytes) under the UNTRUSTED window falls back to the
    # authoritative durable spine baseline and is DEDUPED — X is never spined twice.
    s, w = _rig(domains=(A,))
    rid = "corrupt-window-x"
    _drop(w, _report(org="org_a", host="apme.cm", report_id=rid, confidence=0.9))
    assert w.drain()["recorded"] == 1
    (w.spool / ms._DEDUP_FILE).write_text("}{ not json at all\n\x00garbage")   # corrupt the persisted window
    _drop(w, _report(org="org_a", host="apme.cm", report_id=rid, confidence=0.95))   # same id, fresh bytes
    r = w.drain()
    assert r["deduped"] == 1 and r["recorded"] == 0
    assert _raw_ids(s, "org_a").count(rid) == 1                 # still exactly once despite the corrupt window


def test_corrupt_window_with_unreadable_spine_defers_rather_than_double_drains(monkeypatch):
    # The strongest fail-closed corner: the window is corrupt AND the spine baseline cannot be loaded. The report
    # cannot be proven new OR seen, so it is DEFERRED (left claimed in working/, reclaimed + retried next pass) —
    # never drained blind. Once the spine is readable again it dedups correctly, exactly once.
    s, w = _rig(domains=(A,))
    rid = "defer-x"
    _drop(w, _report(org="org_a", host="apme.cm", report_id=rid, confidence=0.9))
    assert w.drain()["recorded"] == 1
    (w.spool / ms._DEDUP_FILE).write_text("totally corrupt")    # untrusted window
    _drop(w, _report(org="org_a", host="apme.cm", report_id=rid, confidence=0.95))
    real = w._load_seen_rids
    calls = {"n": 0}

    def _flaky():
        calls["n"] += 1
        if calls["n"] == 1:
            raise OSError("spine compaction churn")             # untrusted window + unreadable spine -> defer
        return real()

    monkeypatch.setattr(w, "_load_seen_rids", _flaky)
    r1 = w.drain()                                              # must DEFER, not double-drain
    assert r1["recorded"] == 0
    assert _raw_ids(s, "org_a").count(rid) == 1                 # not re-recorded during the unresolved pass
    r2 = w.drain()                                              # spine readable now -> reclaimed + deduped
    assert _raw_ids(s, "org_a").count(rid) == 1                 # STILL exactly once


def test_hostile_nonregular_dedup_window_does_not_crash_the_drain():
    # Hardened read (O_NOFOLLOW/O_NONBLOCK + S_ISREG): a FIFO planted at .dedup-window is UNTRUSTED, not followed,
    # and never wedges or crashes the drain — a valid report still drains (the spine fallback oracle is empty).
    s, w = _rig(domains=(A,))
    os.mkfifo(w.spool / ms._DEDUP_FILE)
    rep = _report(org="org_a", host="apme.cm")
    _drop(w, rep)
    r = w.drain()                                              # must not hang/raise on the FIFO
    assert r["recorded"] == 1 and _raw_ids(s, "org_a") == [rep["report_id"]]


def test_dedup_window_heals_a_corrupt_file_by_superseding_it():
    # Append-only/supersede: after a pass reads a corrupt window it rewrites a CLEAN one atomically (never edits
    # in place), so the next pass trusts the file again. The file is valid JSON-lines of [org, rid] pairs.
    s, w = _rig(domains=(A,))
    _drop(w, _report(org="org_a", host="apme.cm", report_id="heal-1"))
    w.drain()
    (w.spool / ms._DEDUP_FILE).write_text("corrupt!!!")
    _drop(w, _report(org="org_a", host="apme.cm", report_id="heal-2"))
    w.drain()                                                  # reads corrupt, records heal-2, SUPERSEDES clean
    text = (w.spool / ms._DEDUP_FILE).read_text()
    pairs = [json.loads(line) for line in text.splitlines() if line.strip()]
    assert all(isinstance(p, list) and len(p) == 2 for p in pairs)   # a clean, well-formed window file
    assert ["org_a", "heal-2"] in pairs


# ============================================================================================================
# CONFIG surface — strict-only, positive-integer
# ============================================================================================================

@pytest.mark.parametrize("kw, needle", [
    (dict(domains=None, dedup_window=16), "strict-domain mode"),   # the window is refused in global mode
])
def test_dedup_window_requires_strict_domain_mode(kw, needle):
    s = _store()
    reg = _grant(s, *A)
    with pytest.raises(ValueError) as e:
        ms.MonitoringSpoolWatcher(s, spool_dir=tempfile.mkdtemp(), secret_for=lambda o, h: SECRETS.get((o, h)),
                                  authority=reg, now_fn=lambda: NOW, **kw)
    assert needle in str(e.value)


@pytest.mark.parametrize("bad", [0, -1, -100])
def test_dedup_window_must_be_positive(bad):
    with pytest.raises(ValueError) as e:
        _rig(domains=(A,), dedup_window=bad)
    assert "positive integer" in str(e.value)


def test_dedup_window_default_cap_is_the_bounded_safe_default():
    _, w = _rig(domains=(A,))
    assert w.dedup_window_cap == ms._DEDUP_WINDOW_CAP          # None -> the bounded safe default (not unbounded)


# ============================================================================================================
# COMPOSITION — accept-set + dedup hold together with the part-1 reclaim and part-2 DRR/heartbeat
# ============================================================================================================

def test_accept_set_and_dedup_compose_with_drr_and_the_reserved_heartbeat():
    # A full strict pass with a heartbeat + append budget (part 2), a crash-reclaim path (part 1), the accept-set
    # and the dedup window (part 3) all at once: the heartbeat drains, a mis-filed report is rejected, a
    # re-delivery is deduped, and no report is double-spined.
    by_slug = sorted((A, B, C), key=lambda d: ms.domain_slug(*d))
    hb, t1, t2 = by_slug[0], by_slug[1], by_slug[2]
    s, w = _rig(domains=(A, B, C), heartbeat=hb, append_ceiling_per_s=9.0, pass_window_s=1.0)
    hb_rep = _report(org=hb[0], host=hb[1])
    _drop(w, hb_rep)
    t1_rep = _report(org=t1[0], host=t1[1], report_id="t1-dup")
    _drop(w, t1_rep)
    # a correctly-sealed t2 report MIS-FILED into t1's subtree -> accept-set reject
    _drop_into(w, _report(org=t2[0], host=t2[1]), *t1)
    r = w.drain()
    assert _raw_ids(s, hb[0]) == [hb_rep["report_id"]]         # heartbeat got through
    assert _raw_ids(s, t1[0]) == ["t1-dup"]                    # t1's own report drained
    assert r["rejected"] == 1                                  # the mis-filed t2 report was rejected (accept-set)
    # now re-deliver t1's report with fresh bytes -> deduped, not double-spined
    _drop(w, _report(org=t1[0], host=t1[1], report_id="t1-dup", confidence=0.123))
    r2 = w.drain()
    assert r2["deduped"] == 1 and _raw_ids(s, t1[0]).count("t1-dup") == 1
