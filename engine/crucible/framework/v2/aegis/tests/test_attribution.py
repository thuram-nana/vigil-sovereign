"""AEGIS AS-5b (gateway DENIAL-SOURCE ATTRIBUTION) — deterministic, offline acceptance tests.

AS-5b is the SOURCE dimension of the denied-enforcement load: a deterministic, READ-ONLY rollup that reads the
AS-5a per-caller buckets (the only plane with per-caller state) and reports WHICH sources hold the current
shed/denial pressure — address-free (opaque ids, never a raw caller address) — paired with the AS-5e per-reason
breakdown (the "what"), surfaced read-only on the AS-5c probe snapshot. It is not a detector, so DoD-1's "detector
near-zero-FP" is N/A; it is substituted by rollup-correctness vs a hand-computed expectation + a byte-identity
negative control. The DoD points, mapped to the sections below:

  (1) e2e behavioral — a configured gateway with the flag ON (and its AS-5a/AS-5e/AS-5d deps ON) surfaces the
      attribution rollup on the AS-5c probe snapshot, computed from the live capacity buckets + the live impact
      rollup, end-to-end through the gateway, address-free.
  (2) gate-invariance — importing aegis leaves verify.verifier._ALL_ORACLES at exactly 15 (AS-5b adds NO
      OracleKind); attribution.py is NOT import-reachable from aegis/__init__ or framework.v2.__main__ (and
      neither is capacity/impact_budget/receipts, through it); gateway.ATTRIBUTION_ENV is in lockstep.
  (3) FATAL-2 — attribution.py imports ONLY the stdlib (reaching the AS-5a capacity + AS-5e impact planes by
      RELATIVE import for types, consuming their live objects by injection); never sigil/governor/strix/apps/
      vigil_core.
  (4) determinism — identical per-caller loads + reason tally + salt yield a byte-identical summary; no wall-clock,
      no RNG in the math; effective-token pressure reuses the AS-5a INJECTED clock.
  (5) default-OFF + byte-identity — VIGIL_AEGIS_ATTRIBUTION off (or ANY dep off: capacity / impact_budget /
      receipts) => NO meter is active, nothing is computed, and the AS-5c/AS-5e probe snapshot is byte-identical
      (no attribution keys); the flag is strict/fail-closed, inert at runtime if any dep flag flips off.
  (6) rollup correctness + negative controls — the concentration ratio, the constrained count and the bounded
      top-N source ranking match a hand-computed expectation; the surfaced ids are OPAQUE (no raw address leaks);
      the AS-5e denied-reason tally is consumed through; a tampered receipt chain is DETECTED (verified=False
      flows through from AS-5e); a rollup is NOT a block/verdict (it never acts).
  (7) read-only — AS-5b NEVER mutates a capacity bucket (caller_loads computes effective tokens without
      writeback, so admit decisions stay byte-identical), NEVER mutates the receipt ledger, and NEVER drives an
      admit/shed/allow/block decision; only a fired oracle blocks.

Everything is a pure function of its inputs; no real secret and no network beyond the loopback gateway/upstream.
"""
from __future__ import annotations

import ast
import dataclasses
import http.server
import json
import os
import socketserver
import subprocess
import sys
import threading
import urllib.error
import urllib.request
from collections.abc import Iterator
from pathlib import Path

import pytest

from framework.v2.aegis import attribution as AT
from framework.v2.aegis.attribution import (
    ATTRIBUTION_ENV,
    AttributionMeter,
    AttributionSummary,
    SourceLoad,
    attribution_enabled,
    summarize,
)
from framework.v2.aegis.capacity import CallerLoad, CapacityBudget, CapacityGovernor
from framework.v2.aegis.impact_budget import ImpactBudget, ImpactBudgetMeter
from framework.v2.aegis.receipts import Outcome, ReceiptLedger

_SALT = b"fixed-test-salt-16b"            # a FIXED salt => byte-identical ids across a test (not a real secret)


def _counter(start: float = 1.0, step: float = 1.0):
    """A deterministic injected 'monotonic' clock: 1.0, 2.0, 3.0, ... (never a wall-clock)."""
    state = {"t": start - step}

    def _now() -> float:
        state["t"] += step
        return state["t"]

    return _now


def _load(caller: str, *, inflight: int = 0, tokens: float = 2.0, at_cap: bool = False) -> CallerLoad:
    """Build one CallerLoad directly (depleted is derived exactly as the governor derives it: tokens < 1.0)."""
    return CallerLoad(caller=caller, inflight=inflight, tokens=tokens, depleted=tokens < 1.0, at_cap=at_cap)


# ==================================================================================================
# (6) rollup correctness — concentration / constrained / bounded top-N ranking vs a HAND expectation.
# ==================================================================================================
def test_concentration_and_constrained_match_a_hand_computed_expectation():
    # A: inflight 3, tokens 0.0 (depleted)  -> pressure 3 + 1.0 = 4.0
    # B: inflight 1, tokens 0.5 (depleted)  -> pressure 1 + 0.5 = 1.5
    # C: inflight 0, tokens 2.0 (idle)      -> pressure 0 + 0.0 = 0.0 (not a source)
    loads = [_load("A", inflight=3, tokens=0.0), _load("B", inflight=1, tokens=0.5),
             _load("C", inflight=0, tokens=2.0)]
    s = summarize(loads, {"rate": 2, "sqli": 1}, verified=True, salt=_SALT)
    assert s.tracked == 3 and s.constrained == 2 and s.inflight == 4          # C is not constrained
    # concentration = top pressure / total pressure = 4.0 / (4.0 + 1.5 + 0.0) = 0.727273
    assert s.concentration == round(4.0 / 5.5, 6)
    ids = [src.id for src in s.sources]
    assert len(s.sources) == 2                                                # only A, B have pressure > 0
    assert s.sources[0].inflight == 3 and s.sources[0].depleted is True and s.sources[0].deficit == 1.0
    assert s.sources[1].inflight == 1 and s.sources[1].deficit == 0.5
    assert s.reasons == {"rate": 2, "sqli": 1} and s.verified is True
    assert "A" not in ids and "B" not in ids and "C" not in ids              # ids are OPAQUE, never the raw key


def test_sources_are_bounded_to_the_top_n_by_pressure():
    """A spray of distinct sources is capped to the top-N by pressure, so a wide source set cannot bloat the
    snapshot. The survivors are the heaviest, ranked deterministically."""
    loads = [_load(f"c{i:04d}", inflight=i, tokens=2.0) for i in range(AT._MAX_SOURCES + 25)]
    s = summarize(loads, {}, verified=True, salt=_SALT)
    assert len(s.sources) == AT._MAX_SOURCES                                  # bounded
    assert s.sources[0].inflight == AT._MAX_SOURCES + 24                      # the heaviest survived, ranked first
    # strictly descending in-flight across the surfaced top-N (pressure here == inflight; tokens all full)
    assert [src.inflight for src in s.sources] == sorted((src.inflight for src in s.sources), reverse=True)


def test_equal_pressure_sources_tie_break_on_the_opaque_id_deterministically():
    loads = [_load("x", inflight=2, tokens=2.0), _load("y", inflight=2, tokens=2.0)]
    s = summarize(loads, {}, verified=True, salt=_SALT)
    ids = [src.id for src in s.sources]
    assert ids == sorted(ids)                                                # equal pressure -> id-ascending order
    assert summarize(loads, {}, verified=True, salt=_SALT).to_dict() == s.to_dict()   # reproducible


def test_empty_governor_is_zero_attribution():
    s = summarize([], {}, verified=True, salt=_SALT)
    assert s.tracked == 0 and s.constrained == 0 and s.inflight == 0 and s.concentration == 0.0
    assert s.sources == () and s.reasons == {}


def test_idle_callers_are_tracked_but_are_not_sources():
    """Tracked callers with a full bucket and no in-flight hold NO denial pressure: they count toward ``tracked``
    but never appear as a driving source, and the concentration is 0."""
    loads = [_load(f"idle{i}", inflight=0, tokens=2.0) for i in range(5)]
    s = summarize(loads, {}, verified=True, salt=_SALT)
    assert s.tracked == 5 and s.constrained == 0 and s.sources == () and s.concentration == 0.0


def test_at_cap_counts_as_constrained_even_when_not_rate_depleted():
    """A caller at its per-caller concurrency cap but with a full rate bucket is constrained (a request now would
    be concurrency-shed) and drives pressure via its in-flight."""
    loads = [_load("hot", inflight=4, tokens=2.0, at_cap=True), _load("cool", inflight=0, tokens=2.0)]
    s = summarize(loads, {}, verified=True, salt=_SALT)
    assert s.constrained == 1 and s.inflight == 4
    assert len(s.sources) == 1 and s.sources[0].inflight == 4 and s.sources[0].depleted is False


# ==================================================================================================
# (6) ADDRESS-FREE — the surface carries opaque ids, never a raw caller address (the charter discipline).
# ==================================================================================================
def test_summary_is_address_free_opaque_ids_no_raw_address_leaks():
    loads = [_load("203.0.113.7", inflight=2, tokens=0.0), _load("198.51.100.42", inflight=1, tokens=0.0)]
    s = summarize(loads, {"rate": 3}, verified=True, salt=_SALT)
    blob = json.dumps(s.to_dict())
    assert "203.0.113.7" not in blob and "198.51.100.42" not in blob          # no raw caller address anywhere
    for src in s.sources:
        assert len(src.id) == AT._ID_LEN and all(c in "0123456789abcdef" for c in src.id)   # opaque hex id
    # a rollup is a MEASUREMENT, not a block: it mints no certificate/verdict/decision.
    assert "certificate" not in blob and "verdict" not in blob and "decision" not in blob


def test_opaque_id_is_stable_under_a_fixed_salt_and_changes_under_a_different_salt():
    loads = [_load("203.0.113.7", inflight=1, tokens=0.0)]
    a = summarize(loads, {}, verified=True, salt=_SALT).sources[0].id
    b = summarize(loads, {}, verified=True, salt=_SALT).sources[0].id
    c = summarize(loads, {}, verified=True, salt=b"a-different-salt").sources[0].id
    assert a == b                                                             # stable for cross-snapshot correlation
    assert a != c                                                            # unlinkable across (process) salts


def test_salt_changes_ids_but_never_the_counts_or_ratio():
    """The salt only opacifies ids — it is NOT part of the aggregation, so the counts/ratio are salt-invariant."""
    loads = [_load("A", inflight=3, tokens=0.0), _load("B", inflight=1, tokens=0.5)]
    s1 = summarize(loads, {"rate": 2}, verified=True, salt=_SALT).to_dict()
    s2 = summarize(loads, {"rate": 2}, verified=True, salt=b"other-salt-value").to_dict()
    for k in ("tracked", "constrained", "inflight", "concentration", "reasons", "verified"):
        assert s1[k] == s2[k]
    assert [x["id"] for x in s1["sources"]] != [x["id"] for x in s2["sources"]]   # ids differ


# ==================================================================================================
# (4) determinism — identical loads + reasons + salt yield a byte-identical summary.
# ==================================================================================================
def test_identical_inputs_and_salt_yield_a_byte_identical_summary():
    loads = [_load("A", inflight=2, tokens=0.0), _load("B", inflight=1, tokens=0.25)]
    reasons = {"rate": 2, "xss": 1}

    def _run() -> str:
        return json.dumps(summarize(loads, reasons, verified=True, salt=_SALT).to_dict(), sort_keys=True)

    assert _run() == _run()


def test_summarize_is_a_pure_function_of_its_inputs():
    loads = [_load("A", inflight=1, tokens=0.0)]
    a = summarize(loads, {"rate": 1}, verified=True, salt=_SALT)
    b = summarize(loads, {"rate": 1}, verified=True, salt=_SALT)
    assert isinstance(a, AttributionSummary) and isinstance(a.sources[0], SourceLoad)
    assert json.dumps(a.to_dict(), sort_keys=True) == json.dumps(b.to_dict(), sort_keys=True)


# ==================================================================================================
# (7) READ-ONLY — the AS-5a caller_loads accessor computes effective tokens WITHOUT writeback.
# ==================================================================================================
def test_caller_loads_reports_rate_depletion_and_concurrency():
    gov = CapacityGovernor(CapacityBudget(rate_per_s=1.0, burst=3, max_inflight_per_caller=0),
                           monotonic=lambda: 100.0)
    for _ in range(3):
        gov.admit("A", now=100.0)                                            # 3 admits over burst 3 -> tokens 0
    gov.admit("B", now=100.0)                                                # 1 admit -> tokens 2
    loads = {cl.caller: cl for cl in gov.caller_loads(now=100.0)}
    assert loads["A"].inflight == 3 and loads["A"].tokens == 0.0 and loads["A"].depleted is True
    assert loads["B"].inflight == 1 and loads["B"].tokens == 2.0 and loads["B"].depleted is False


def test_caller_loads_reports_concurrency_cap():
    gov = CapacityGovernor(CapacityBudget(rate_per_s=1.0, burst=10, max_inflight_per_caller=2),
                           monotonic=lambda: 50.0)
    gov.admit("A", now=50.0)
    gov.admit("A", now=50.0)                                                 # inflight 2 == cap
    cl = {c.caller: c for c in gov.caller_loads(now=50.0)}["A"]
    assert cl.inflight == 2 and cl.at_cap is True and cl.depleted is False    # at cap, rate bucket still full


def test_caller_loads_computes_effective_tokens_without_writing_them_back():
    """A load read applies refill for the READ only — it must not mutate the stored bucket, or a later admit would
    see a silently-topped-up balance."""
    gov = CapacityGovernor(CapacityBudget(rate_per_s=1.0, burst=5, max_inflight_per_caller=0),
                           monotonic=lambda: 100.0)
    gov.admit("A", now=100.0)                                                # stored tokens 4, last 100
    eff_future = {c.caller: c for c in gov.caller_loads(now=105.0)}["A"].tokens
    assert eff_future == 5.0                                                 # read at +5s refills to the burst cap
    eff_now = {c.caller: c for c in gov.caller_loads(now=100.0)}["A"].tokens
    assert eff_now == 4.0                                                    # stored balance was NOT written back
    a2 = gov.admit("A", now=100.0)                                           # consumes from the stored 4, not 5
    assert a2.admitted is True
    assert {c.caller: c for c in gov.caller_loads(now=100.0)}["A"].tokens == 3.0


def test_caller_loads_never_changes_admit_decisions():
    """Interleaving load reads with admits must yield the identical admit/shed sequence as a control governor that
    was never read."""
    def _seq(read: bool) -> list[bool]:
        gov = CapacityGovernor(CapacityBudget(rate_per_s=0.001, burst=2, max_inflight_per_caller=0),
                               monotonic=lambda: 10.0)
        out = []
        for _ in range(6):
            out.append(gov.admit("A", now=10.0).admitted)
            if read:
                gov.caller_loads(now=10.0)
                gov.caller_loads(now=99.0)
        return out
    assert _seq(read=True) == _seq(read=False) == [True, True, False, False, False, False]


# ==================================================================================================
# (6)/(7) meter level — consumes AS-5e reasons; verified flows through; never mutates governor or ledger.
# ==================================================================================================
def _ledger(outcomes: "list[tuple[str, str]]") -> ReceiptLedger:
    led = ReceiptLedger(monotonic=_counter())
    for kind, reason in outcomes:
        led.record(kind, reason)
    return led


def test_meter_consumes_the_impact_reason_breakdown():
    led = _ledger([(Outcome.ALLOWED, "relayed"), (Outcome.SHED, "rate"), (Outcome.BLOCKED, "sqli"),
                   (Outcome.BLOCKED, "sqli")])
    impact = ImpactBudgetMeter(led, ImpactBudget(max_denied_ratio=1.0, window=100))
    gov = CapacityGovernor(CapacityBudget(rate_per_s=1.0, burst=2, max_inflight_per_caller=0),
                           monotonic=lambda: 1.0)
    gov.admit("A", now=1.0)
    s = AttributionMeter(gov, impact, source_salt=_SALT).summary(now=1.0)
    assert s.reasons == {"rate": 1, "sqli": 2}                               # exactly AS-5e's denied_reasons
    assert s.reasons == dict(impact.summary().denied_reasons)
    assert s.tracked == 1                                                    # the governor's single caller


def test_meter_verified_flows_through_and_a_tampered_chain_is_detected():
    led = _ledger([(Outcome.ALLOWED, "relayed"), (Outcome.BLOCKED, "sqli"), (Outcome.SHED, "rate")])
    impact = ImpactBudgetMeter(led)
    gov = CapacityGovernor(CapacityBudget(rate_per_s=1.0, burst=2, max_inflight_per_caller=0),
                           monotonic=lambda: 1.0)
    meter = AttributionMeter(gov, impact, source_salt=_SALT)
    assert meter.summary(now=1.0).verified is True                          # clean chain
    # EDIT an interior retained receipt (keeping its stored hash) -> the ledger's verify() now fails, and that
    # tampered-chain detection flows through AS-5e into the attribution surface.
    led._tail[1] = dataclasses.replace(led._tail[1], outcome=Outcome.ALLOWED)
    assert meter.summary(now=1.0).verified is False


def test_meter_never_mutates_the_governor_or_the_ledger():
    led = _ledger([(Outcome.ALLOWED, "relayed"), (Outcome.BLOCKED, "sqli")])
    before_head, before_count = led.head, led.count
    gov = CapacityGovernor(CapacityBudget(rate_per_s=0.001, burst=2, max_inflight_per_caller=0),
                           monotonic=lambda: 7.0)
    gov.admit("A", now=7.0)
    meter = AttributionMeter(gov, ImpactBudgetMeter(led), source_salt=_SALT)
    for _ in range(50):
        meter.snapshot(now=7.0)
    assert led.head == before_head and led.count == before_count and led.verify() is True
    # the governor's next admit is byte-identical to a control that was never snapshotted (no bucket mutation).
    ctrl = CapacityGovernor(CapacityBudget(rate_per_s=0.001, burst=2, max_inflight_per_caller=0),
                            monotonic=lambda: 7.0)
    ctrl.admit("A", now=7.0)
    assert gov.admit("A", now=7.0).admitted == ctrl.admit("A", now=7.0).admitted


# ==================================================================================================
# (5) default-OFF + fail-closed flag parse.
# ==================================================================================================
def test_attribution_env_flag_is_strict_fail_closed(monkeypatch):
    monkeypatch.delenv(ATTRIBUTION_ENV, raising=False)
    assert attribution_enabled() is False
    for on in ("1", "true", "YES", "on", " On "):
        monkeypatch.setenv(ATTRIBUTION_ENV, on)
        assert attribution_enabled() is True, on
    for off in ("0", "false", "", "nope", "2", "enable"):
        monkeypatch.setenv(ATTRIBUTION_ENV, off)
        assert attribution_enabled() is False, off


# ==================================================================================================
# (2) gate-invariance — AS-5b adds NO OracleKind; attribution.py off the __init__/__main__ import path.
# ==================================================================================================
def test_importing_aegis_leaves_all_oracles_frozen_at_15():
    import framework.v2.aegis  # noqa: F401
    from framework.v2.verify import verifier as V
    assert len(V._ALL_ORACLES) == 15                                        # a rollup is a measurement, not an oracle


def test_attribution_not_import_reachable_from_init_or_main():
    root = Path(__file__).resolve().parents[4]                              # repo .../engine/crucible
    code = (
        "import sys;"
        "import framework.v2.aegis;"
        "import framework.v2.__main__;"
        "assert 'framework.v2.aegis.attribution' not in sys.modules, "
        "'attribution.py must be OFF the __init__/__main__ import path (make-gate byte-identity)';"
        "assert 'framework.v2.aegis.capacity' not in sys.modules, "
        "'capacity.py must stay OFF the import path (attribution must not drag it on eagerly)';"
        "assert 'framework.v2.aegis.impact_budget' not in sys.modules, "
        "'impact_budget.py must stay OFF the import path';"
        "assert 'framework.v2.aegis.receipts' not in sys.modules, 'receipts.py must stay OFF the import path';"
        "print('OK')"
    )
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([str(root), str(root.parents[1] / "packages/core/vigil_core"),
                                         env.get("PYTHONPATH", "")])
    out = subprocess.run([sys.executable, "-c", code], cwd=str(root), env=env,
                         capture_output=True, text=True)
    assert out.returncode == 0, f"attribution reachable from init/main:\n{out.stdout}\n{out.stderr}"


def test_gateway_attribution_env_in_lockstep_with_module():
    from framework.v2.aegis import gateway as G
    assert G.ATTRIBUTION_ENV == ATTRIBUTION_ENV == "VIGIL_AEGIS_ATTRIBUTION"


# ==================================================================================================
# (3) FATAL-2 — attribution.py imports ONLY the stdlib (reaching capacity + impact_budget by RELATIVE import).
# ==================================================================================================
def test_attribution_imports_only_its_allowed_plane():
    src = Path(AT.__file__).read_text(encoding="utf-8")
    tree = ast.parse(src)
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.level == 0:          # absolute imports only
            roots.add((node.module or "").split(".")[0])
    for forbidden in ("sigil", "governor", "strix", "apps", "vigil_core"):
        assert forbidden not in roots, f"attribution must never import {forbidden!r} (FATAL-2)"
    allowed = {"__future__", "hashlib", "hmac", "os", "secrets", "dataclasses", "typing"}
    assert roots <= allowed, f"unexpected absolute import roots in attribution.py: {sorted(roots - allowed)}"
    # the sibling AS-5a / AS-5e planes are reached by RELATIVE import only (never an absolute framework.* root).
    rel = {(n.module or "") for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.level == 1}
    assert "capacity" in rel and "impact_budget" in rel, "attribution must reach AS-5a/AS-5e by relative import"


# ==================================================================================================
# (1)/(5) gateway integration — end-to-end through the live gateway over real loopback sockets.
# ==================================================================================================
class _Upstream(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_a):
        return

    def _reply(self):
        body = b"UPSTREAM-OK"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    do_GET = _reply
    do_POST = _reply


@pytest.fixture()
def upstream() -> Iterator[int]:
    srv = socketserver.TCPServer(("127.0.0.1", 0), _Upstream)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield srv.server_address[1]
    finally:
        srv.shutdown()
        srv.server_close()


def _run_gateway(upstream_port: int, *, capacity_budget=None, impact_budget=None):
    from framework.v2.aegis.gateway import serve_gateway
    from framework.v2.aegis.models import AegisConfig
    cfg = AegisConfig(deployment_secret="k", mode="observe")
    gw = serve_gateway(f"http://127.0.0.1:{upstream_port}", config=cfg, host="127.0.0.1", port=0,
                       capacity_budget=capacity_budget, impact_budget=impact_budget, monotonic_fn=_counter())
    threading.Thread(target=gw.serve_forever, daemon=True).start()
    return gw, gw.server_address[1]


def _get(port: int, path: str):
    try:
        r = urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=5)   # noqa: S310
        return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def _all_on(monkeypatch):
    monkeypatch.setenv("VIGIL_AEGIS_CAPACITY", "1")
    monkeypatch.setenv("VIGIL_AEGIS_RECEIPTS", "1")
    monkeypatch.setenv("VIGIL_AEGIS_IMPACT_BUDGET", "1")
    monkeypatch.setenv(ATTRIBUTION_ENV, "1")


def test_gateway_attribution_off_builds_no_meter_and_probe_is_byte_identical(upstream, monkeypatch):
    """DEFAULT-OFF byte-identity: VIGIL_AEGIS_ATTRIBUTION unset (deps on) => NO active meter, the data path still
    forwards, and the probe snapshot carries NO attribution keys (byte-identical to AS-5e)."""
    monkeypatch.setenv("VIGIL_AEGIS_CAPACITY", "1")
    monkeypatch.setenv("VIGIL_AEGIS_RECEIPTS", "1")
    monkeypatch.setenv("VIGIL_AEGIS_IMPACT_BUDGET", "1")
    monkeypatch.delenv(ATTRIBUTION_ENV, raising=False)
    gw, port = _run_gateway(upstream, capacity_budget=CapacityBudget(rate_per_s=1.0, burst=5))
    try:
        assert gw.settings.attribution_meter is None
        assert gw.settings.attribution_active is False
        assert [_get(port, "/x")[0] for _ in range(3)] == [200] * 3          # data path byte-identical
        snap = gw.settings._probe_snapshot()
        assert "attribution" not in snap and "attribution_active" not in snap
    finally:
        gw.shutdown(); gw.server_close()


def test_gateway_attribution_on_but_capacity_off_is_inert(upstream, monkeypatch):
    """No per-caller SOURCE signal => inert. Two ways: (a) no capacity budget configured (no governor); (b) the
    budget is configured but VIGIL_AEGIS_CAPACITY is off, so the source read is inactive."""
    _all_on(monkeypatch)
    # (a) no capacity budget at all -> no governor -> no meter built
    gw, port = _run_gateway(upstream, capacity_budget=None)
    try:
        assert gw.settings.capacity_governor is None and gw.settings.attribution_meter is None
        assert gw.settings.attribution_active is False
        assert "attribution" not in gw.settings._probe_snapshot()
    finally:
        gw.shutdown(); gw.server_close()
    # (b) budget configured but the capacity flag is off -> meter may be built, but it is NOT active
    monkeypatch.setenv("VIGIL_AEGIS_CAPACITY", "0")
    gw, port = _run_gateway(upstream, capacity_budget=CapacityBudget(rate_per_s=1.0, burst=5))
    try:
        assert gw.settings.capacity_active is False and gw.settings.attribution_active is False
        assert "attribution" not in gw.settings._probe_snapshot()
    finally:
        gw.shutdown(); gw.server_close()


def test_gateway_attribution_on_but_impact_or_receipts_off_is_inert(upstream, monkeypatch):
    """No reason "what" (AS-5e/AS-5d) => inert: with the impact-budget or receipts dep off, no impact meter is
    built, so no attribution meter is built."""
    monkeypatch.setenv("VIGIL_AEGIS_CAPACITY", "1")
    monkeypatch.setenv(ATTRIBUTION_ENV, "1")
    monkeypatch.setenv("VIGIL_AEGIS_RECEIPTS", "1")
    monkeypatch.delenv("VIGIL_AEGIS_IMPACT_BUDGET", raising=False)            # impact dep off
    gw, port = _run_gateway(upstream, capacity_budget=CapacityBudget(rate_per_s=1.0, burst=5))
    try:
        assert gw.settings.impact_budget_meter is None and gw.settings.attribution_meter is None
        assert gw.settings.attribution_active is False
        assert "attribution" not in gw.settings._probe_snapshot()
    finally:
        gw.shutdown(); gw.server_close()


def test_gateway_attribution_on_surfaces_the_rollup_on_the_probe_snapshot(upstream, monkeypatch):
    """All deps ON => a tight per-caller budget sheds the loopback caller after it drains; the probe snapshot
    surfaces the attribution rollup computed from the live buckets + the live impact rollup, ADDRESS-FREE."""
    _all_on(monkeypatch)
    gw, port = _run_gateway(upstream, capacity_budget=CapacityBudget(rate_per_s=0.001, burst=2),
                            impact_budget=ImpactBudget(max_denied_ratio=1.0, window=100))
    try:
        assert gw.settings.attribution_meter is not None and gw.settings.attribution_active is True
        for _ in range(6):                                                  # 2 relayed, then the caller is shed
            _get(port, "/x")
        snap = gw.settings._probe_snapshot()
        assert snap["attribution_active"] is True
        a = snap["attribution"]
        assert a["tracked"] >= 1 and a["constrained"] >= 1                   # the loopback caller is driving sheds
        assert a["verified"] is True
        assert len(a["sources"]) >= 1
        src = a["sources"][0]
        assert src["depleted"] is True and len(src["id"]) == AT._ID_LEN
        assert a["reasons"].get("per-caller rate budget exhausted", 0) >= 1  # the AS-5e denied-reason tally
        assert "127.0.0.1" not in json.dumps(snap)                          # NO raw caller/upstream address leaks
    finally:
        gw.shutdown(); gw.server_close()


def test_gateway_attribution_flip_off_at_runtime_stops_surfacing_the_rollup(upstream, monkeypatch):
    """Flipping ANY of the attribution / capacity / impact-budget / receipts flags OFF at runtime makes the rollup
    go inert live, so the probe answer drops the attribution keys again."""
    _all_on(monkeypatch)
    gw, port = _run_gateway(upstream, capacity_budget=CapacityBudget(rate_per_s=1.0, burst=5),
                            impact_budget=ImpactBudget(max_denied_ratio=1.0, window=100))
    try:
        _get(port, "/x")
        assert "attribution" in gw.settings._probe_snapshot()
        for flag in (ATTRIBUTION_ENV, "VIGIL_AEGIS_CAPACITY", "VIGIL_AEGIS_IMPACT_BUDGET", "VIGIL_AEGIS_RECEIPTS"):
            monkeypatch.setenv(flag, "0")
            assert gw.settings.attribution_active is False
            assert "attribution" not in gw.settings._probe_snapshot()
            monkeypatch.setenv(flag, "1")                                   # restore for the next flag
        assert "attribution" in gw.settings._probe_snapshot()               # all restored -> surfaced again
    finally:
        gw.shutdown(); gw.server_close()
