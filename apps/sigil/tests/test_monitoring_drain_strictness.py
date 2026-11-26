"""AEGIS AS-3a — drain STRICTNESS for the monitoring spool.

The sovereign monitoring drain (``sigil.inbound.monitoring_spool``) can run in a STRICT-DOMAIN mode (opt-in,
default-OFF): it processes ONLY each DECLARED ``(org, host)`` domain's own ``incoming/<slug>/`` subtree, and
quarantines everything else OFF-DOMAIN by LOCATION — never opening it, never MAC/authority-checking it (NO GLOBAL
SCAN). This isolates a tenant's drain cost to its own subtree, so a poisoned / flooded TT-B never degrades TT-A's
p95, and fires ONE coalesced alert per pass when any strictness quarantine happens.

Pinned here: the ``domain_slug`` contract MATCHES the gateway reporter (cross-plane, FATAL-2); default mode is
byte-identical to the pre-AS-3a global drain; an off-domain item is quarantined WITHOUT being scanned (a would-be
valid report is NOT recorded); a valid in-domain item drains normally; a poisoned in-domain item is quarantined;
the off-domain sweep is bounded; the alert is coalesced to one per pass and leaks no tenant content; and the
negative control — a poisoned (and flooded) TT-B leaves TT-A's own drain untouched.
"""
from __future__ import annotations

import hashlib
import hmac
import itertools
import json
import os
import re
import tempfile
from pathlib import Path

import pytest

from sigil.governor.asset_ownership import METHOD_DNS_TXT, AssetOwnershipRegistry
from sigil.governor.monitoring_authority import MonitoringAuthorityRegistry
from sigil.inbound import monitoring_spool as ms
from sigil.inbound import quarantined_count
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
NOW = 1_000_000.0
A = ("org_a", "apme.cm")
B = ("org_b", "beta.cm")
SECRETS = {A: b"A" * 32, B: b"B" * 32}
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


def _strict_rig(domains=(A, B), grants=(A, B), **kw):
    s = _store()
    reg = MonitoringAuthorityRegistry(s, owner_key=OWNER, trusted_pubkey=OWNER.public_key_b64)
    for o, h in grants:
        reg = _grant(s, o, h)
    w = ms.MonitoringSpoolWatcher(s, spool_dir=tempfile.mkdtemp(), secret_for=lambda o, h: SECRETS.get((o, h)),
                                  authority=reg, now_fn=lambda: NOW, domains=domains, **kw)
    return s, reg, w


def _report(org="org_a", host="apme.cm", **kw) -> dict:
    rep = {"schema": ms.REPORT_SCHEMA, "org_id": org, "host": host, "ts": NOW - 10, "decision": "confirmed",
           "attack_class": "sqli", "action": "observe", "confidence": 0.9, "provenance_tier": "certified",
           "certificate_sha256": "c" * 64, "report_id": f"r{next(_n)}"}
    rep.update(kw)
    return rep


def _seal(rep: dict, secret=None) -> dict:
    body = json.dumps(rep, sort_keys=True, separators=(",", ":"))
    key = secret if secret is not None else SECRETS[(rep["org_id"], rep["host"])]
    mac = hmac.new(key, ms.REPORT_DOMAIN + body.encode(), hashlib.sha256).hexdigest()
    return {"schema": ms.REPORT_SCHEMA, "body": body, "mac": mac}


def _domain_dir(w, org: str, host: str) -> Path:
    d = w.incoming / ms.domain_slug(org, host)
    d.mkdir(parents=True, exist_ok=True)
    return d


def _drop_in_domain(w, env, org: str, host: str, name=None) -> Path:
    data = env if isinstance(env, (bytes, str)) else json.dumps(env)
    p = _domain_dir(w, org, host) / (name or f"{next(_n)}.json")
    (p.write_bytes if isinstance(data, bytes) else p.write_text)(data)
    return p


def _drop_flat(w, env, name=None) -> Path:
    data = env if isinstance(env, (bytes, str)) else json.dumps(env)
    p = w.incoming / (name or f"{next(_n)}.json")
    (p.write_bytes if isinstance(data, bytes) else p.write_text)(data)
    return p


def _alerts(s: SpineStore) -> list[dict]:
    return [r.payload for r in s.iter_records()
            if isinstance(r.payload, dict) and r.payload.get("signal") == ms.DRAIN_ALERT_SIGNAL]


def _events(s: SpineStore, org: str) -> list[dict]:
    return ms.monitoring_events(s, org)


# --- the slug contract (cross-plane, FATAL-2) ---------------------------------------------------------------
def test_domain_slug_is_pinned_and_non_aliasing():
    # a fixed vector (also asserted engine-side) pins the two planes together, and the length-prefix guarantees
    # distinct (org, host) pairs can NEVER collapse into one slug.
    assert ms.domain_slug("org_a", "apme.cm") == "3b47c421ee2b04ed814c44a99213f64c"
    assert ms.domain_slug("ab", "c") != ms.domain_slug("a", "bc")
    assert re.fullmatch(r"[0-9a-f]{32}", ms.domain_slug("x", "y"))


def test_domain_slug_matches_the_gateway_reporter_source():
    # mirror pin (like REPORT_DOMAIN): the engine reporter defines the SAME prefix + algorithm. Read as TEXT —
    # the sovereign plane must not IMPORT the engine (FATAL-2); the two share the contract, not the code.
    src = (Path(__file__).resolve().parents[3]
           / "engine/crucible/framework/v2/aegis/monitoring_report.py").read_text()
    assert ms.DOMAIN_SLUG_PREFIX == b"vigil.aegis.monitoring-domain.v1\x00"
    assert re.search(r'DOMAIN_SLUG_PREFIX = b"vigil\.aegis\.monitoring-domain\.v1\\x00"', src)
    assert 'f"{len(org_id)}:{org_id}\\x1f{len(host)}:{host}"' in src
    assert 'DOMAIN_SLUG_PREFIX + key' in src and "hexdigest()[:32]" in src


# --- default mode is unchanged -------------------------------------------------------------------------------
def test_default_mode_is_the_unchanged_global_drain():
    # domains=None ⇒ flat incoming/, no off_domain/alert keys, byte-for-byte the pre-AS-3a behavior.
    s = _store()
    reg = _grant(s, *A)
    w = ms.MonitoringSpoolWatcher(s, spool_dir=tempfile.mkdtemp(), secret_for=lambda o, h: SECRETS.get((o, h)),
                                  authority=reg, now_fn=lambda: NOW)
    assert w._domains is None
    (w.incoming / "x.json").write_text(json.dumps(_seal(_report())))
    r = w.drain()
    assert (r["recorded"], r["rejected"], r["deduped"]) == (1, 0, 0)
    assert "off_domain" not in r and "alert_seq" not in r
    assert _alerts(s) == []


# --- in-domain drains normally -------------------------------------------------------------------------------
def test_valid_in_domain_report_drains_normally():
    s, _, w = _strict_rig()
    rep = _report()
    _drop_in_domain(w, _seal(rep), *A)
    r = w.drain()
    assert (r["recorded"], r["rejected"], r["off_domain"]) == (1, 0, 0)
    ev = _events(s, "org_a")
    assert [e["report_id"] for e in ev] == [rep["report_id"]]
    assert r["alert_seq"] == -1 and _alerts(s) == []           # clean pass fires NO alert


# --- off-domain is QUARANTINED, never SCANNED ----------------------------------------------------------------
def test_off_domain_flat_file_quarantined_without_being_scanned():
    s, _, w = _strict_rig()
    # a fully-valid, in-authority report — but placed FLAT in incoming/ (outside any declared domain subtree).
    # If it were scanned it would RECORD; strict mode quarantines it by LOCATION, so recorded stays 0.
    _drop_flat(w, _seal(_report()))
    r = w.drain()
    assert (r["recorded"], r["off_domain"]) == (0, 1)
    assert _events(s, "org_a") == []                           # proves it was NOT scanned/recorded
    assert quarantined_count(w.rejected) == 1
    reasons = [f for f in os.listdir(w.rejected) if f.endswith(".reason")]
    assert reasons and "off-domain" in (w.rejected / reasons[-1]).read_text()
    assert len(_alerts(s)) == 1                                # an ALERT fired


def test_off_domain_undeclared_subtree_quarantined_by_location():
    s, _, w = _strict_rig(domains=(A,))                        # only org_a is declared
    # a VALID, in-authority org_b report, but org_b is NOT a declared domain -> its whole subtree is off-domain.
    _drop_in_domain(w, _seal(_report(org="org_b", host="beta.cm")), *B)
    r = w.drain()
    assert (r["recorded"], r["off_domain"]) == (0, 1)
    assert _events(s, "org_b") == []                           # not scanned, not recorded
    assert len(_alerts(s)) == 1


# --- poisoned in-domain item is quarantined ------------------------------------------------------------------
@pytest.mark.parametrize("payload", [b"\xff\xfe", b"not json", b"x" * (16 * 1024 + 1),
                                     json.dumps({"schema": "other"}).encode()])
def test_poisoned_in_domain_item_quarantined_and_alerts(payload):
    s, _, w = _strict_rig()
    _drop_in_domain(w, payload, *A)
    r = w.drain()
    assert (r["recorded"], r["rejected"], r["off_domain"]) == (0, 1, 0)
    assert _events(s, "org_a") == []
    assert quarantined_count(w.rejected) == 1
    assert len(_alerts(s)) == 1


def test_forged_cross_tenant_in_domain_report_quarantined():
    # a report for org_b sealed with org_a's secret, dropped into org_a's own declared subtree: it IS scanned
    # (in-domain) but fails the MAC bind -> quarantined, nothing recorded, alert fires.
    s, _, w = _strict_rig()
    forged = _seal(_report(org="org_b", host="beta.cm"), secret=SECRETS[A])
    _drop_in_domain(w, forged, *A)
    r = w.drain()
    assert (r["recorded"], r["rejected"]) == (0, 1)
    assert _events(s, "org_b") == [] and len(_alerts(s)) == 1


# --- the alert is coalesced + metadata-only ------------------------------------------------------------------
def test_alert_is_coalesced_once_per_pass_and_leaks_no_content():
    s, _, w = _strict_rig()
    for _ in range(5):
        _drop_flat(w, _seal(_report()))                        # 5 off-domain items
    _drop_in_domain(w, b"not json", *A)                        # + 1 poisoned in-domain
    r = w.drain()
    assert r["off_domain"] == 5 and r["rejected"] == 1
    al = _alerts(s)
    assert len(al) == 1                                        # ONE alert for the whole pass, not one-per-file
    a = al[0]
    assert a["off_domain"] == 5 and a["poisoned"] == 1 and a["source_class"] == "drain_strictness"
    # metadata only: no org/host/report_id/body of any off-domain item leaks into the alert
    blob = json.dumps(a)
    for leak in ("org_a", "apme.cm", "sqli", "body", "mac"):
        assert leak not in blob


def test_off_domain_sweep_is_bounded():
    s, _, w = _strict_rig(off_domain_limit=3)
    for _ in range(10):
        _drop_flat(w, _seal(_report()))
    r = w.drain()
    assert r["off_domain"] == 3                                # a flood cannot blow up one pass
    assert quarantined_count(w.rejected) == 3


# --- THE NEGATIVE CONTROL: poisoned/flooded TT-B leaves TT-A untouched ---------------------------------------
def test_poisoned_and_flooded_tt_b_does_not_touch_tt_a():
    s, _, w = _strict_rig(domains=(A, B))
    # TT-A: one legitimate report in its own subtree.
    rep_a = _report(org="org_a", host="apme.cm")
    _drop_in_domain(w, _seal(rep_a), *A)
    # TT-B: a FLOOD of poison in ITS OWN subtree (malformed) + off-domain junk flat in incoming/.
    for _ in range(50):
        _drop_in_domain(w, b"poison-not-json", *B)
    for _ in range(50):
        _drop_flat(w, b"off-domain-junk")
    r = w.drain()
    # TT-A's one report drained normally — its result is INDEPENDENT of TT-B's volume (the p95-isolation proxy).
    assert r["recorded"] == 1
    a = _events(s, "org_a")
    assert [e["report_id"] for e in a] == [rep_a["report_id"]]
    # TT-B's poison never produced a monitoring event for ANY tenant; it is quarantined, and an alert fired.
    assert _events(s, "org_b") == []
    assert r["rejected"] == 50 and r["off_domain"] == 50
    assert len(_alerts(s)) == 1


def test_tt_a_served_even_when_tt_b_subtree_is_huge():
    # Stronger isolation: TT-A records regardless of a large TT-B subtree, and TT-B's VALID reports in its own
    # declared subtree also drain (both declared) — but each is read only from its OWN subtree.
    s, _, w = _strict_rig(domains=(A, B))
    _drop_in_domain(w, _seal(_report(org="org_a", host="apme.cm")), *A)
    for _ in range(20):
        _drop_in_domain(w, _seal(_report(org="org_b", host="beta.cm")), *B)
    r = w.drain()
    assert r["recorded"] == 21 and r["off_domain"] == 0 and r["rejected"] == 0
    assert len(_events(s, "org_a")) == 1 and len(_events(s, "org_b")) == 20
    assert _alerts(s) == []                                    # an all-valid pass fires no alert


def test_per_domain_limit_bounds_one_domains_work_per_pass():
    s, _, w = _strict_rig(domains=(A, B), per_domain_limit=2)
    for _ in range(5):
        _drop_in_domain(w, _seal(_report(org="org_a", host="apme.cm")), *A)
    r = w.drain()
    assert r["recorded"] == 2                                  # only 2 of org_a's 5 this pass (fairness bound)
    assert w.drain()["recorded"] == 2                          # next pass drains 2 more
    assert w.drain()["recorded"] == 1                          # and the last one


# ============================================================================================================
# AS-3a RED-PEN follow-up — three confirmed MEDIUM findings on _drain_strict's bounding.
# ============================================================================================================
def _scandir_counter(monkeypatch):
    """Install a TRANSPARENT ``os.scandir`` spy that counts how many entries the drain PULLS from each directory.
    Proves red-pen #1: the strict drain BOUNDS THE ENUMERATION (scandir early-stop) instead of materializing +
    sorting the whole directory — so a flood is READ only up to the cap. Returns ``{dir_path_str: pulled}``."""
    real = os.scandir
    pulled: dict = {}

    class _Counting:
        def __init__(self, path):
            self._inner = real(path)
            self._key = os.fspath(path)
            pulled.setdefault(self._key, 0)

        def __iter__(self):
            return self

        def __next__(self):
            entry = next(self._inner)                          # raises StopIteration at the real end
            pulled[self._key] += 1
            return entry

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return self._inner.__exit__(*a)

        def close(self):
            self._inner.close()

    monkeypatch.setattr(ms.os, "scandir", lambda path: _Counting(path))
    return pulled


# --- MEDIUM #1: count-bounded -> COST-bounded (bound the ENUMERATION, not just the processed slice) ----------
def test_off_domain_sweep_bounds_the_enumeration_not_just_the_slice(monkeypatch):
    # Before: sorted(incoming.iterdir()) read + sorted the WHOLE dir before applying off_domain_limit, so a
    # sustained flood was fully read every pass. The fix early-stops the scandir at the cap.
    s, _, w = _strict_rig(domains=(A,), off_domain_limit=5)
    for _ in range(200):
        _drop_flat(w, b"off-domain-junk")
    pulled = _scandir_counter(monkeypatch)
    r = w.drain()
    assert r["off_domain"] == 5                                # the sweep itself is still bounded
    incoming_pulled = pulled.get(os.fspath(w.incoming), 0)
    assert incoming_pulled <= 10                               # ~off_domain_limit + 1, decisively NOT 200
    assert sum(pulled.values()) < 200                          # the 200-file flood was never read in full


def test_declared_subtree_flood_bounds_the_enumeration(monkeypatch):
    # Before: sorted(ddir.glob("*.json")) read + sorted the WHOLE subtree before per_domain_limit. The fix
    # bounds the per-subtree enumeration too — a flood in a declared subtree is read only up to the caps.
    s, _, w = _strict_rig(domains=(A,), per_domain_limit=3, off_domain_limit=3)
    for _ in range(80):
        _drop_in_domain(w, _seal(_report()), *A)
    pulled = _scandir_counter(monkeypatch)
    r = w.drain()
    assert r["recorded"] == 3                                  # only per_domain_limit drained this pass
    subtree_pulled = pulled.get(os.fspath(w.incoming / ms.domain_slug(*A)), 0)
    assert subtree_pulled <= 3 + 3 + 2                         # ~ per_domain_limit + off_domain_limit (+ slack)
    assert subtree_pulled < 80                                 # the 80-deep flood was never read in full


# --- MEDIUM #2: declared-subtree blind spot (non-.json / nested is SWEPT by location + alerted, not retained) -
def test_non_json_and_nested_in_declared_subtree_are_quarantined_and_alerted():
    # Before: step 1 read ONLY sorted(ddir.glob("*.json")), so a non-.json file or any NESTED path inside a
    # declared subtree was never claimed/scanned/quarantined/alerted -> silent retention. The fix sweeps every
    # non-report entry BY LOCATION into rejected/ (never scanning it) and fires the coalesced alert.
    s, _, w = _strict_rig(domains=(A,))
    rep = _report()
    _drop_in_domain(w, _seal(rep), *A)                         # a legit flat *.json report -> drains
    ddir = _domain_dir(w, *A)
    (ddir / "payload.bin").write_bytes(b"\x00\x01\x02")        # a non-.json file dropped into the subtree
    nested = ddir / "nested"
    nested.mkdir()
    buried = _seal(_report())                                  # a would-be-VALID report, but NESTED one level down
    (nested / "report.json").write_text(json.dumps(buried))
    r = w.drain()
    assert r["recorded"] == 1                                  # only the flat valid *.json drained
    assert [e["report_id"] for e in _events(s, "org_a")] == [rep["report_id"]]
    assert r["in_domain_foreign"] == 2                         # payload.bin (1) + nested/report.json (1)
    assert not (ddir / "payload.bin").exists()                 # swept out — no silent retention
    assert not (nested / "report.json").exists()
    assert quarantined_count(w.rejected) == 2                  # both reached rejected/ for operator action
    assert len(_events(s, "org_a")) == 1                       # the buried report was NEVER scanned/recorded
    al = _alerts(s)
    assert len(al) == 1 and al[0]["in_domain_foreign"] == 2 and al[0]["source_class"] == "drain_strictness"
    # metadata-only: the by-location sweep leaks no tenant content into the alert
    assert all(leak not in json.dumps(al[0]) for leak in ("org_a", "apme.cm", "sqli", "body", "mac"))


def test_in_domain_foreign_sweep_is_bounded():
    # the in-domain-foreign sweep is bounded (like the off-domain sweep) so a flood of junk in a declared
    # subtree cannot blow up a drain pass either.
    s, _, w = _strict_rig(domains=(A,), off_domain_limit=4)
    ddir = _domain_dir(w, *A)
    for i in range(20):
        (ddir / f"junk{i}.bin").write_bytes(b"x")              # 20 non-.json files in the declared subtree
    r = w.drain()
    assert r["in_domain_foreign"] == 4                         # bounded by off_domain_limit, not all 20
    assert quarantined_count(w.rejected) == 4


# --- MEDIUM #3: per-domain flood must not starve another declared tenant in one pass ------------------------
def test_per_domain_limit_has_a_bounded_safe_default():
    # Before: per_domain_limit=None meant UNBOUNDED, so a flooded tenant whose slug sorts first ate the whole
    # pass. The default is now a BOUNDED positive cap — fairness is the DEFAULT, not opt-in.
    s, _, w = _strict_rig()                                    # no per_domain_limit passed
    assert w.per_domain_limit is not None
    assert isinstance(w.per_domain_limit, int) and w.per_domain_limit > 0
    assert w.per_domain_limit == ms._PER_DOMAIN_DRAIN_CAP


def test_flooded_first_tenant_does_not_starve_the_next():
    # With a bounded per-domain cap, a flood in the FIRST-sorted declared tenant is capped to that many drains
    # per pass, and the NEXT declared tenant is STILL served in the SAME pass (p95 isolation is real, not claimed).
    s, _, w = _strict_rig(domains=(A, B), per_domain_limit=3)
    first, second = (A, B) if ms.domain_slug(*A) < ms.domain_slug(*B) else (B, A)
    for _ in range(8):                                         # flood whichever tenant the drain serves FIRST
        _drop_in_domain(w, _seal(_report(org=first[0], host=first[1])), *first)
    served = _report(org=second[0], host=second[1])
    _drop_in_domain(w, _seal(served), *second)                # the next tenant drops a single report
    r = w.drain()
    assert len(_events(s, first[0])) == 3                      # flooded tenant drains only its cap, NOT all 8
    assert [e["report_id"] for e in _events(s, second[0])] == [served["report_id"]]   # next tenant SERVED
    assert r["recorded"] == 4


# --- DEFAULT (domains=None) stays byte-identical: the three fixes are STRICT-ONLY --------------------------
def test_default_global_drain_unchanged_ignores_non_json_and_subdirs():
    # The DEFAULT global drain stays byte-identical to pre-AS-3a: it processes sorted(incoming/*.json) and
    # IGNORES everything else — no off-domain/foreign sweep, no alert, no new return keys. (Complements
    # test_default_mode_is_the_unchanged_global_drain.)
    s = _store()
    reg = _grant(s, *A)
    w = ms.MonitoringSpoolWatcher(s, spool_dir=tempfile.mkdtemp(), secret_for=lambda o, h: SECRETS.get((o, h)),
                                  authority=reg, now_fn=lambda: NOW)
    rep = _report()
    (w.incoming / "a.json").write_text(json.dumps(_seal(rep)))
    (w.incoming / "ignore.bin").write_bytes(b"\x00\xff")       # a non-.json file
    (w.incoming / "sub").mkdir()                               # a nested subdir with a would-be report
    (w.incoming / "sub" / "x.json").write_text(json.dumps(_seal(_report())))
    r = w.drain()
    assert set(r) == {"recorded", "rejected", "deduped", "seqs"}   # NO off_domain/in_domain_foreign/alert_seq
    assert (r["recorded"], r["rejected"], r["deduped"]) == (1, 0, 0)
    assert _alerts(s) == []
    assert (w.incoming / "ignore.bin").exists()                # untouched — the global drain leaves non-.json
    assert (w.incoming / "sub" / "x.json").exists()            # nested: likewise untouched, never swept
    assert quarantined_count(w.rejected) == 0
