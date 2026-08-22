"""W7-5 (#463) — schedule the off-box witnessed checkpoint and FAIL ON A STALE ANCHOR (offense parity).

The off-box witnessed checkpoint is the anchor the whole HA anti-rollback interlock depends on. Before
this change it was emitted by hand and unscheduled, and the guard did NOT check its freshness: a months-old
anchor still passed, silently widening the rollback window to the operator's last manual run. This suite
pins the fix on the offense plane (``vigil_integration.witnessed_anchor`` + ``.floor_witness``):

  * FRESHNESS VERDICT — the documented bounds and the fail-closed edges (un-dated, future-dated).
  * THE GUARD REFUSES A STALE ANCHOR — a back-dated anchor that would otherwise PASS every rollback/fork
    check is refused once freshness is enforced (fails-without-the-change: the same input PASSES with
    ``now=None`` and REFUSES with a stale ``now`` — so the refusal is freshness, not a no-op).
  * NEGATIVE CONTROLS — a fresh anchor is accepted, a back-dated one refused, asserted in the same run.
  * THE SCHEDULER — emits + refreshes the off-box anchor, writes a dead-man heartbeat, and ALARMS on
    staleness BEFORE the refusal bound is crossed (warn), and CRITICAL past it / on emit failure.
  * BYTE-COMPAT — ``emitted_at`` is optional top-level metadata; a legacy (un-dated) envelope round-trips
    byte-identically to the pre-W7-5 format.

FATAL-2: imports NO ``sigil``/``apps.sigil``/``framework`` — vigil_core + vigil_integration only.
"""
from __future__ import annotations

from vigil_core import build_chain, generate_keypair, sha256_hex, sign_head
from vigil_integration import floor_witness as FW
from vigil_integration import witnessed_anchor as WA
from vigil_integration.transparency import Witness

SCOPE = "loopback"
GOV = generate_keypair()

# a small, explicit bound pair for deterministic tests (real defaults are 6h warn / 24h refuse)
WARN = 100
REFUSE = 200


def _chain(n, salt=""):
    entries = build_chain([sha256_hex(f"{i}:{salt}".encode()) for i in range(n)])
    head = sign_head(entries, engagement_slug=SCOPE, signers=[("spine", GOV.private_key_b64)])
    return entries, head


def _hw(head):
    return {"entry_count": head.entry_count, "last_seq": head.last_seq}


def _tr():
    return FW.offense_witness_trust_root(GOV.public_key_b64)


def _emit(head, retain, *, now):
    return FW.emit_highwater_witness(head, _hw(head), [FW.offense_governance_witness(GOV)],
                                     retain_path=retain, scope=SCOPE, now=now)


# ─────────────────────────────────────────────────────── freshness verdict (bounds + fail-closed edges) ──

def test_freshness_verdict_bounds_and_edges():
    now = 10_000
    assert WA.freshness_verdict(now - 10, now=now, warn_after_s=WARN, refuse_after_s=REFUSE).status == WA.FRESH
    assert WA.freshness_verdict(now - (WARN + 5), now=now, warn_after_s=WARN,
                                refuse_after_s=REFUSE).status == WA.STALE_WARN
    assert WA.freshness_verdict(now - (REFUSE + 5), now=now, warn_after_s=WARN,
                                refuse_after_s=REFUSE).status == WA.STALE_REFUSE
    # fail-closed edges: un-dated + future-dated both REFUSE
    fv_none = WA.freshness_verdict(None, now=now, warn_after_s=WARN, refuse_after_s=REFUSE)
    assert fv_none.status == WA.UNKNOWN_AGE and fv_none.refuse
    fv_future = WA.freshness_verdict(now + 10_000, now=now, warn_after_s=WARN, refuse_after_s=REFUSE)
    assert fv_future.status == WA.FUTURE_SKEW and fv_future.refuse
    # a warn is an ALERT but NOT a refusal (it is usable, surfaced early)
    warn = WA.freshness_verdict(now - (WARN + 5), now=now, warn_after_s=WARN, refuse_after_s=REFUSE)
    assert warn.alert and not warn.refuse and warn.severity == "warning"


def test_env_override_thresholds(monkeypatch):
    monkeypatch.setenv(WA._REFUSE_AFTER_S_ENV, "50")
    monkeypatch.setenv(WA._WARN_AFTER_S_ENV, "10")
    assert WA.freshness_verdict(0, now=60).status == WA.STALE_REFUSE
    assert WA.freshness_verdict(0, now=20).status == WA.STALE_WARN


# ───────────────────────────────────────────── the guard REFUSES a stale anchor (fails-without-change) ──

def test_stale_anchor_is_refused_but_a_fresh_one_accepts(tmp_path):
    """THE fix. Same local head, same off-box anchor, at the EXACT witnessed height (passes every
    rollback/fork check). With ``now=None`` the guard PASSES (proving the refusal below is NOT some other
    check firing — the gate is not a no-op). With a STALE ``now`` the guard REFUSES; with a FRESH ``now`` it
    accepts. On a tree WITHOUT this change ``verify_highwater_against_witnessed`` has no ``now`` kwarg, so
    this test cannot even run (TypeError) — the failure is observed, not assumed."""
    retain = tmp_path / "hw.json"
    _e, h = _chain(3)
    _emit(h, retain, now=1_000)                 # anchor emitted at t=1000
    env = retain.read_text()

    # (a) no freshness gate -> PASSES (all rollback/fork checks satisfied)
    ok0, _msg0, _ = FW.verify_highwater_against_witnessed(h, _hw(h), [env], scope=SCOPE, trust_root=_tr())
    assert ok0, "the non-freshness path must PASS, else the refusal below is a false attribution"

    # (b) fresh now -> ACCEPT (negative-control positive)
    ok1, _msg1, _ = FW.verify_highwater_against_witnessed(
        h, _hw(h), [env], scope=SCOPE, trust_root=_tr(), now=1_000 + WARN - 1,
        warn_after_s=WARN, refuse_after_s=REFUSE)
    assert ok1

    # (c) back-dated / stale now -> REFUSE (negative-control negative), asserted in the SAME run
    ok2, msg2, _ = FW.verify_highwater_against_witnessed(
        h, _hw(h), [env], scope=SCOPE, trust_root=_tr(), now=1_000 + REFUSE + 1,
        warn_after_s=WARN, refuse_after_s=REFUSE)
    assert not ok2 and "STALE ANCHOR" in msg2


def test_undated_legacy_anchor_is_refused_fail_closed(tmp_path):
    """A legacy anchor emitted with NO timestamp (``now`` omitted) cannot be proven fresh → REFUSE when
    freshness is enforced (fail-closed migration: re-emit with the scheduler)."""
    retain = tmp_path / "hw.json"
    _e, h = _chain(3)
    FW.emit_highwater_witness(h, _hw(h), [FW.offense_governance_witness(GOV)],
                              retain_path=retain, scope=SCOPE)     # no now -> no emitted_at
    assert WA.envelope_emitted_at(retain.read_text()) is None
    ok, msg, _ = FW.verify_highwater_against_witnessed(
        h, _hw(h), [retain.read_text()], scope=SCOPE, trust_root=_tr(), now=5_000,
        warn_after_s=WARN, refuse_after_s=REFUSE)
    assert not ok and "STALE ANCHOR" in msg


def test_select_highest_with_age_enforces_on_the_anchor_it_uses(tmp_path):
    """A batch of a FRESH-but-low anchor and a STALE-but-high anchor: the guard relies on the HIGHEST, so it
    must judge freshness on the STALE high one (and refuse), never on the freshest present."""
    r_low, r_high = tmp_path / "low.json", tmp_path / "high.json"
    _e2, h2 = _chain(2)
    _e5, h5 = _chain(5)
    _emit(h2, r_low, now=9_999)                 # low + fresh
    _emit(h5, r_high, now=1_000)                # high + stale
    ok, msg, _ = FW.verify_highwater_against_witnessed(
        h5, _hw(h5), [r_low.read_text(), r_high.read_text()], scope=SCOPE, trust_root=_tr(),
        now=1_000 + REFUSE + 1, warn_after_s=WARN, refuse_after_s=REFUSE)
    assert not ok and "STALE ANCHOR" in msg


# ─────────────────────────────────────────────────────────────────── the scheduler (emit + alert + dead-man) ──

class _Rec:
    """A recording alarm sink: captures every Alarm the scheduler emits."""
    def __init__(self):
        self.alarms = []

    def emit(self, alarm):
        self.alarms.append(alarm)


def _offense_emit_fn(head, retain):
    def _emit(now):
        return FW.emit_highwater_witness(head, _hw(head), [FW.offense_governance_witness(GOV)],
                                         retain_path=retain, scope=SCOPE, now=now)
    return _emit


def test_scheduler_emits_and_writes_a_heartbeat(tmp_path):
    retain = tmp_path / "hw.json"
    _e, h = _chain(3)
    sink = _Rec()
    wc = WA.run_checkpoint_once(_offense_emit_fn(h, retain), retain_path=retain, now=1_000, sink=sink)
    assert wc.checkpoint.entry_count == 3
    assert WA.envelope_emitted_at(retain.read_text()) == 1_000
    # dead-man heartbeat written + fresh
    stale, _detail = WA.emit_heartbeat_is_stale(retain, now=1_000, max_staleness_s=REFUSE)
    assert not stale
    assert sink.alarms == []                      # a clean first emit raises nothing


def test_scheduler_alerts_before_the_refusal_bound(tmp_path):
    """The 'alert before it reaches the refusal threshold' criterion: an anchor aged past WARN but before
    REFUSE fires a WARNING alarm on the next cycle that runs (never a critical yet)."""
    retain = tmp_path / "hw.json"
    _e, h = _chain(3)
    _emit(h, retain, now=0)                        # anchor at t=0
    sink = _Rec()
    # a cycle at t = WARN+10 (< REFUSE): the pre-existing anchor is STALE_WARN -> warning alarm, then refresh
    WA.run_checkpoint_once(_offense_emit_fn(h, retain), retain_path=retain, now=WARN + 10, sink=sink,
                           warn_after_s=WARN, refuse_after_s=REFUSE)
    warns = [a for a in sink.alarms if a.kind == "anchor-stale"]
    assert len(warns) == 1 and warns[0].severity == "warning"
    assert not any(a.severity == "critical" for a in sink.alarms)
    # the anchor is now refreshed to WARN+10
    assert WA.envelope_emitted_at(retain.read_text()) == WARN + 10


def test_scheduler_criticals_past_the_refusal_bound(tmp_path):
    retain = tmp_path / "hw.json"
    _e, h = _chain(3)
    _emit(h, retain, now=0)
    sink = _Rec()
    WA.run_checkpoint_once(_offense_emit_fn(h, retain), retain_path=retain, now=REFUSE + 10, sink=sink,
                           warn_after_s=WARN, refuse_after_s=REFUSE)
    crit = [a for a in sink.alarms if a.kind == "anchor-stale" and a.severity == "critical"]
    assert len(crit) == 1


def test_scheduler_alarms_on_emit_failure_and_deadman_goes_stale(tmp_path):
    """If the emitter FAILS, a critical emit-error alarm fires and a FAILING heartbeat is written; the loop
    keeps going (errors counted). And an absent/old emitter heartbeat is itself stale (dead-man)."""
    retain = tmp_path / "hw.json"
    sink = _Rec()

    def _boom(now):
        raise RuntimeError("off-box push unreachable")

    summary = WA.run_checkpoint_monitor(_boom, retain_path=retain, cycles=2, interval=0.0,
                                        now_fn=lambda: 1_000, sink=sink)
    assert summary["errors"] == 2 and summary["emits"] == 0
    assert any(a.kind == "anchor-emit-error" and a.severity == "error" for a in sink.alarms)
    # dead-man: a heartbeat that never advanced (all failing writes at t=1000) is stale far in the future
    stale, _d = WA.emit_heartbeat_is_stale(retain, now=1_000 + REFUSE + 1, max_staleness_s=REFUSE)
    assert stale
    # and an ENTIRELY absent heartbeat is stale (fail-closed)
    stale2, _d2 = WA.emit_heartbeat_is_stale(tmp_path / "nope.json", now=1_000, max_staleness_s=REFUSE)
    assert stale2


def test_monitor_runs_bounded_cycles_with_injected_clock(tmp_path):
    retain = tmp_path / "hw.json"
    _e, h = _chain(3)
    ticks = iter([100, 200, 300])
    summary = WA.run_checkpoint_monitor(_offense_emit_fn(h, retain), retain_path=retain, cycles=3,
                                        interval=0.0, sleep=lambda _s: None, now_fn=lambda: next(ticks))
    assert summary["cycles_run"] == 3 and summary["emits"] == 3 and summary["errors"] == 0
    # liveness refresh advanced the anchor's emitted_at to the last tick even though the spine was idle
    assert WA.envelope_emitted_at(retain.read_text()) == 300


# ─────────────────────────────────────────────────────────────────────────── byte-compat of the envelope ──

def test_undated_envelope_is_byte_identical_to_legacy(tmp_path):
    """``emitted_at=None`` OMITS the key, so a hand-emitted / legacy envelope is byte-identical to the
    pre-W7-5 format (and ``envelope_emitted_at`` reads None from it)."""
    from vigil_integration.transparency import WitnessedCheckpoint, checkpoint_of
    _e, h = _chain(3)
    cp = checkpoint_of(h)
    wc = WitnessedCheckpoint(cp, ())
    legacy = WA.dump_witnessed_envelope(wc, scope=SCOPE)
    dated = WA.dump_witnessed_envelope(wc, scope=SCOPE, emitted_at=1234)
    assert "emitted_at" not in legacy
    assert WA.envelope_emitted_at(legacy) is None
    assert WA.envelope_emitted_at(dated) == 1234
    # a dated envelope drops back to the legacy bytes when the key is removed (additive, sorted metadata)
    import json
    obj = json.loads(dated)
    obj.pop("emitted_at")
    assert json.dumps(obj, sort_keys=True, separators=(",", ":")) == legacy
