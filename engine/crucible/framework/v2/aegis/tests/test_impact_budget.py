"""AEGIS AS-5e (gateway IMPACT BUDGET) — deterministic, offline acceptance tests.

AS-5e is a deterministic, READ-ONLY rollup over the AS-5d receipt chain: over a bounded recent window it measures
the DENIED ratio (shed + blocked, the availability cost of enforcement) and compares it against a configured
budget ceiling, surfaced read-only on the AS-5c probe snapshot. It is not a detector, so DoD-1's "detector
near-zero-FP" is N/A; it is substituted by rollup-correctness vs a hand-computed expectation + a byte-identity
negative control. The DoD points, mapped to the sections below:

  (1) e2e behavioral — a configured gateway with the flag ON (and its AS-5d dependency ON) surfaces the impact
      rollup on the AS-5c probe snapshot, computed from the live receipt ledger, end-to-end through the gateway.
  (2) gate-invariance — importing aegis leaves verify.verifier._ALL_ORACLES at exactly 15 (AS-5e adds NO
      OracleKind); impact_budget.py is NOT import-reachable from aegis/__init__ or framework.v2.__main__ (and
      neither is receipts, through it); gateway.IMPACT_BUDGET_ENV is in lockstep with the module.
  (3) FATAL-2 — impact_budget.py imports ONLY the stdlib (plus its sibling AS-5d receipts plane by RELATIVE
      import); never sigil/governor/strix/apps/vigil_core.
  (4) determinism — a fixed set of receipts over a fixed budget yields a byte-identical summary; no wall-clock,
      no RNG; the recent window is COUNT-based so the rollup needs no clock at all.
  (5) default-OFF + byte-identity — VIGIL_AEGIS_IMPACT_BUDGET off (or its AS-5d dep off) => NO meter is built,
      nothing is computed, and the AS-5c/AS-5d probe snapshot is byte-identical (no impact keys); the flag is
      strict/fail-closed, and the rollup is ALSO inert if the dep flag is off (even at runtime).
  (6) rollup correctness + negative controls — the denied ratio and the within/over-budget verdict match a
      hand-computed expectation; a tampered / reordered / dropped receipt chain is DETECTED (verified=False); the
      snapshot carries NO raw caller address and NO secret; a rollup is NOT a block/verdict (it never acts).
  (7) read-only / append-only — AS-5e NEVER mutates the ledger and NEVER drives an admit/shed/allow/block
      decision; only a fired oracle blocks.

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

from framework.v2.aegis import impact_budget as IB
from framework.v2.aegis.impact_budget import (
    IMPACT_BUDGET_ENV,
    ImpactBudget,
    ImpactBudgetMeter,
    ImpactSummary,
    impact_budget_enabled,
    summarize,
)
from framework.v2.aegis.receipts import Outcome, ReceiptLedger


def _counter(start: float = 1.0, step: float = 1.0):
    """A deterministic injected 'monotonic' clock for the AS-5d ledger: 1.0, 2.0, 3.0, ... (never a wall-clock)."""
    state = {"t": start - step}

    def _now() -> float:
        state["t"] += step
        return state["t"]

    return _now


def _ledger(outcomes: "list[tuple[str, str]]") -> ReceiptLedger:
    """Build a receipt ledger from a fixed (outcome, reason) sequence over a fixed injected clock."""
    led = ReceiptLedger(monotonic=_counter())
    for kind, reason in outcomes:
        led.record(kind, reason)
    return led


# ==================================================================================================
# (6) rollup correctness — the denied ratio + the within/over verdict vs a HAND-COMPUTED expectation.
# ==================================================================================================
def test_denied_ratio_and_verdict_match_a_hand_computed_expectation():
    # 2 allowed + 1 shed + 1 blocked => denied=2, considered=4, denied_ratio = 2/4 = 0.5.
    led = _ledger([(Outcome.ALLOWED, "relayed"), (Outcome.ALLOWED, "relayed"),
                   (Outcome.SHED, "per-caller rate budget exhausted"), (Outcome.BLOCKED, "sqli")])
    s = ImpactBudgetMeter(led, ImpactBudget(max_denied_ratio=0.5, window=10)).snapshot()
    assert s["considered"] == 4 and s["allowed"] == 2 and s["shed"] == 1 and s["blocked"] == 1 and s["other"] == 0
    assert s["denied"] == 2 and s["denied_ratio"] == 0.5
    assert s["within_budget"] is True and s["over_budget"] is False      # 0.5 <= 0.5 ceiling
    assert s["verified"] is True and s["total"] == 4


def test_a_tighter_ceiling_reports_over_budget():
    led = _ledger([(Outcome.ALLOWED, "relayed"), (Outcome.ALLOWED, "relayed"),
                   (Outcome.SHED, "rate"), (Outcome.BLOCKED, "xss")])
    s = ImpactBudgetMeter(led, ImpactBudget(max_denied_ratio=0.4, window=10)).snapshot()
    assert s["denied_ratio"] == 0.5
    assert s["within_budget"] is False and s["over_budget"] is True       # 0.5 > 0.4 ceiling


def test_denied_reasons_is_a_bounded_tally_of_the_denied_outcomes_only():
    """The per-reason breakdown AS-5b consumes tallies the machine reason of the DENIED receipts (shed reasons +
    blocked attack-classes) only — an ``allowed`` relay's reason is never in it."""
    led = _ledger([(Outcome.ALLOWED, "relayed"), (Outcome.SHED, "rate"), (Outcome.SHED, "rate"),
                   (Outcome.BLOCKED, "sqli"), (Outcome.BLOCKED, "xss"), (Outcome.BLOCKED, "xss")])
    s = ImpactBudgetMeter(led, ImpactBudget(max_denied_ratio=1.0, window=10)).snapshot()
    assert s["denied_reasons"] == {"rate": 2, "sqli": 1, "xss": 2}
    assert "relayed" not in s["denied_reasons"]                           # allowed reasons are not impact


def test_denied_reasons_breakdown_is_bounded_and_deterministic():
    """A spray of distinct blocked attack-classes is capped to the top-N by count (deterministic tie-break), so a
    caller-influenced category string cannot bloat the operator-facing snapshot."""
    outcomes = [(Outcome.BLOCKED, f"class-{i:04d}") for i in range(IB._MAX_REASONS + 50)]
    # give one class a clear lead so the top-N is unambiguous
    outcomes += [(Outcome.BLOCKED, "class-0000")] * 5
    led = _ledger(outcomes)
    s = ImpactBudgetMeter(led, ImpactBudget(max_denied_ratio=1.0, window=100000)).snapshot()
    assert len(s["denied_reasons"]) == IB._MAX_REASONS                    # bounded
    assert s["denied_reasons"]["class-0000"] == 6                         # the lead survives the cap
    # deterministic: identical input -> identical bounded breakdown
    s2 = ImpactBudgetMeter(_ledger(outcomes), ImpactBudget(1.0, 100000)).snapshot()
    assert json.dumps(s["denied_reasons"], sort_keys=True) == json.dumps(s2["denied_reasons"], sort_keys=True)


def test_empty_ledger_is_within_budget_with_zero_impact():
    """No traffic => no impact => within budget even under a zero ceiling (0.0 <= 0.0)."""
    s = ImpactBudgetMeter(_ledger([]), ImpactBudget(max_denied_ratio=0.0, window=10)).snapshot()
    assert s["considered"] == 0 and s["denied"] == 0 and s["denied_ratio"] == 0.0
    assert s["within_budget"] is True and s["verified"] is True


def test_window_considers_only_the_last_n_receipts():
    """BOUNDED RECENT WINDOW: with window=4 over 6 allowed + 2 blocked, only the last 4 are considered."""
    led = _ledger([(Outcome.ALLOWED, "relayed")] * 6 + [(Outcome.BLOCKED, "xss")] * 2)
    s = ImpactBudgetMeter(led, ImpactBudget(max_denied_ratio=0.9, window=4)).snapshot()
    assert s["considered"] == 4 and s["allowed"] == 2 and s["blocked"] == 2
    assert s["denied"] == 2 and s["denied_ratio"] == 0.5
    assert s["total"] == 8                                                # the lifetime count still reflects all 8


def test_non_canonical_outcome_counts_as_other_never_as_denied():
    """A non-canonical receipt kind (the ledger records it honestly) is counted under ``other`` and NEVER inflates
    the denied ratio."""
    led = _ledger([(Outcome.ALLOWED, "relayed"), ("weird", "??"), (Outcome.SHED, "rate")])
    s = ImpactBudgetMeter(led, ImpactBudget(max_denied_ratio=1.0, window=10)).snapshot()
    assert s["allowed"] == 1 and s["shed"] == 1 and s["other"] == 1 and s["blocked"] == 0
    assert s["denied"] == 1 and s["considered"] == 3 and s["denied_ratio"] == 1 / 3


# ==================================================================================================
# (4) determinism — a fixed set of receipts over a fixed budget yields a byte-identical summary.
# ==================================================================================================
def test_identical_receipts_and_budget_yield_a_byte_identical_summary():
    outcomes = [(Outcome.ALLOWED, "relayed"), (Outcome.BLOCKED, "xss"), (Outcome.SHED, "global capacity saturated")]
    budget = ImpactBudget(max_denied_ratio=0.5, window=1024)

    def _run() -> str:
        led = _ledger(outcomes)
        return json.dumps(ImpactBudgetMeter(led, budget).snapshot(), sort_keys=True)

    assert _run() == _run()


def test_summarize_is_a_pure_function_of_its_inputs():
    """The aggregation is a pure function (receipts, budget, verified, total, head) -> summary — no clock, no RNG."""
    led = _ledger([(Outcome.ALLOWED, "relayed"), (Outcome.BLOCKED, "sqli")])
    rs = led.receipts()
    a = summarize(rs, ImpactBudget(0.5, 10), verified=True, total=led.count, head=led.head)
    b = summarize(rs, ImpactBudget(0.5, 10), verified=True, total=led.count, head=led.head)
    assert isinstance(a, ImpactSummary)
    assert json.dumps(a.to_dict(), sort_keys=True) == json.dumps(b.to_dict(), sort_keys=True)


# ==================================================================================================
# (6) tamper detection — a tampered / reordered / dropped chain is DETECTED (verified=False).
# ==================================================================================================
def test_a_tampered_receipt_chain_is_detected_as_unverified():
    led = _ledger([(Outcome.ALLOWED, "relayed"), (Outcome.BLOCKED, "sqli"), (Outcome.SHED, "rate")])
    chain = list(led.receipts())
    # EDIT an interior receipt's outcome (keeping its stored hash) => re-hash no longer matches.
    tampered = [chain[0], dataclasses.replace(chain[1], outcome=Outcome.ALLOWED), chain[2]]
    s = summarize(tuple(tampered), ImpactBudget(0.9, 10),
                  verified=ReceiptLedger.verify_chain(tampered), total=led.count, head=led.head)
    assert s.verified is False                                            # the edit is detected


def test_a_dropped_interior_receipt_is_detected_as_unverified():
    led = _ledger([(Outcome.ALLOWED, "relayed")] * 4)
    chain = list(led.receipts())
    dropped = [chain[0], chain[2], chain[3]]                              # dropped chain[1] => prev_hash mismatch
    s = summarize(tuple(dropped), ImpactBudget(0.9, 10),
                  verified=ReceiptLedger.verify_chain(dropped), total=led.count, head=led.head)
    assert s.verified is False


def test_the_meter_verified_flag_ties_the_window_to_the_live_head():
    """The meter's verified flag comes from the ledger's own verify() (retained window re-hashed AND tied to the
    live head) — race-free and True for an untampered live ledger."""
    led = _ledger([(Outcome.ALLOWED, "relayed"), (Outcome.SHED, "rate")])
    assert ImpactBudgetMeter(led).snapshot()["verified"] is True
    assert led.verify() is True


# ==================================================================================================
# (7)/(6) read-only + metadata-only — AS-5e never mutates the ledger; no address, no secret, no verdict.
# ==================================================================================================
def test_the_rollup_never_mutates_the_ledger():
    """READ-ONLY: snapshotting many times must not append/edit/drop a single receipt."""
    led = _ledger([(Outcome.ALLOWED, "relayed"), (Outcome.BLOCKED, "sqli")])
    before_head, before_count = led.head, led.count
    meter = ImpactBudgetMeter(led)
    for _ in range(50):
        meter.snapshot()
    assert led.head == before_head and led.count == before_count         # the append-only chain is untouched
    assert led.verify() is True


def test_snapshot_is_metadata_only_no_address_no_secret_no_verdict():
    led = _ledger([(Outcome.ALLOWED, "relayed"), (Outcome.SHED, "rate"), (Outcome.BLOCKED, "sqli")])
    s = ImpactBudgetMeter(led).snapshot()
    blob = json.dumps(s)
    assert "127.0.0.1" not in blob                                        # no caller/upstream address
    # a rollup is a MEASUREMENT, not a block: it mints no certificate/verdict/decision.
    assert "certificate" not in blob and "verdict" not in blob and "decision" not in blob


# ==================================================================================================
# (5) default-OFF + fail-closed flag parse; budget fail-closed construction.
# ==================================================================================================
def test_impact_budget_env_flag_is_strict_fail_closed(monkeypatch):
    monkeypatch.delenv(IMPACT_BUDGET_ENV, raising=False)
    assert impact_budget_enabled() is False
    for on in ("1", "true", "YES", "on", " On "):
        monkeypatch.setenv(IMPACT_BUDGET_ENV, on)
        assert impact_budget_enabled() is True, on
    for off in ("0", "false", "", "nope", "2", "enable"):
        monkeypatch.setenv(IMPACT_BUDGET_ENV, off)
        assert impact_budget_enabled() is False, off


def test_budget_construction_is_fail_closed():
    for bad_ratio in (-0.1, 1.1, "x"):
        with pytest.raises(ValueError):
            ImpactBudget(max_denied_ratio=bad_ratio)                      # type: ignore[arg-type]
    for bad_window in (0, -1, True, 1.5):
        with pytest.raises(ValueError):
            ImpactBudget(window=bad_window)                              # type: ignore[arg-type]
    d = ImpactBudget.default()
    assert 0.0 <= d.max_denied_ratio <= 1.0 and d.window >= 1


# ==================================================================================================
# (2) gate-invariance — AS-5e adds NO OracleKind; impact_budget.py off the __init__/__main__ import path.
# ==================================================================================================
def test_importing_aegis_leaves_all_oracles_frozen_at_15():
    import framework.v2.aegis  # noqa: F401
    from framework.v2.verify import verifier as V
    assert len(V._ALL_ORACLES) == 15                                     # a rollup is a measurement, not an oracle


def test_impact_budget_not_import_reachable_from_init_or_main():
    root = Path(__file__).resolve().parents[4]                           # repo .../engine/crucible
    code = (
        "import sys;"
        "import framework.v2.aegis;"
        "import framework.v2.__main__;"
        "assert 'framework.v2.aegis.impact_budget' not in sys.modules, "
        "'impact_budget.py must be OFF the __init__/__main__ import path (make-gate byte-identity)';"
        "assert 'framework.v2.aegis.receipts' not in sys.modules, "
        "'receipts.py must stay OFF the import path (impact_budget must not drag it on eagerly)';"
        "print('OK')"
    )
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([str(root), str(root.parents[1] / "packages/core/vigil_core"),
                                         env.get("PYTHONPATH", "")])
    out = subprocess.run([sys.executable, "-c", code], cwd=str(root), env=env,
                         capture_output=True, text=True)
    assert out.returncode == 0, f"impact_budget reachable from init/main:\n{out.stdout}\n{out.stderr}"


def test_gateway_impact_budget_env_in_lockstep_with_module():
    from framework.v2.aegis import gateway as G
    assert G.IMPACT_BUDGET_ENV == IMPACT_BUDGET_ENV == "VIGIL_AEGIS_IMPACT_BUDGET"


# ==================================================================================================
# (3) FATAL-2 — impact_budget.py imports ONLY the stdlib (plus its sibling AS-5d receipts by RELATIVE import).
# ==================================================================================================
def test_impact_budget_imports_only_its_allowed_plane():
    src = Path(IB.__file__).read_text(encoding="utf-8")
    tree = ast.parse(src)
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.level == 0:        # absolute imports only
            roots.add((node.module or "").split(".")[0])
    for forbidden in ("sigil", "governor", "strix", "apps", "vigil_core"):
        assert forbidden not in roots, f"impact_budget must never import {forbidden!r} (FATAL-2)"
    allowed = {"__future__", "os", "dataclasses", "typing"}
    assert roots <= allowed, f"unexpected absolute import roots in impact_budget.py: {sorted(roots - allowed)}"
    # the sibling AS-5d plane is reached by RELATIVE import only (never an absolute framework.* root here).
    rel = [n for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.level == 1]
    assert any((n.module or "") == "receipts" for n in rel), "impact_budget must use the AS-5d receipts verifier"


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


def _run_gateway(upstream_port: int, *, mode="observe", config=None, impact_budget=None):
    from framework.v2.aegis.gateway import serve_gateway
    from framework.v2.aegis.models import AegisConfig
    cfg = config or AegisConfig(deployment_secret="k", mode=mode)
    gw = serve_gateway(f"http://127.0.0.1:{upstream_port}", config=cfg, host="127.0.0.1", port=0,
                       impact_budget=impact_budget, monotonic_fn=_counter())
    threading.Thread(target=gw.serve_forever, daemon=True).start()
    return gw, gw.server_address[1]


def _get(port: int, path: str):
    try:
        r = urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=5)   # noqa: S310
        return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def test_gateway_impact_off_builds_no_meter_and_probe_is_byte_identical(upstream, monkeypatch):
    """DEFAULT-OFF byte-identity: VIGIL_AEGIS_IMPACT_BUDGET unset => NO meter, the data path still forwards, and
    the probe snapshot carries NO impact keys (byte-identical to AS-5d)."""
    monkeypatch.delenv(IMPACT_BUDGET_ENV, raising=False)
    monkeypatch.setenv("VIGIL_AEGIS_RECEIPTS", "1")                       # even with the dep on, impact stays off
    gw, port = _run_gateway(upstream)
    try:
        assert gw.settings.impact_budget_meter is None
        assert gw.settings.impact_budget_active is False
        assert [_get(port, "/x")[0] for _ in range(4)] == [200] * 4       # data path byte-identical
        snap = gw.settings._probe_snapshot()
        assert "impact" not in snap and "impact_budget_active" not in snap
    finally:
        gw.shutdown(); gw.server_close()


def test_gateway_impact_on_but_receipts_off_is_inert(upstream, monkeypatch):
    """The rollup is inert if its AS-5d dependency flag is off — there is no chain to roll up, so NO meter is
    built even with the impact flag on."""
    monkeypatch.setenv(IMPACT_BUDGET_ENV, "1")
    monkeypatch.delenv("VIGIL_AEGIS_RECEIPTS", raising=False)
    gw, port = _run_gateway(upstream)
    try:
        assert gw.settings.receipt_ledger is None                        # no AS-5d ledger
        assert gw.settings.impact_budget_meter is None                   # => no AS-5e meter
        assert gw.settings.impact_budget_active is False
        assert _get(port, "/x")[0] == 200
        assert "impact" not in gw.settings._probe_snapshot()
    finally:
        gw.shutdown(); gw.server_close()


def test_gateway_impact_on_surfaces_the_rollup_on_the_probe_snapshot(upstream, monkeypatch):
    """Flag ON + its AS-5d dependency ON => each inspected-and-relayed request appends an ``allowed`` receipt, and
    the probe snapshot surfaces the impact rollup computed from the live ledger, address-free."""
    monkeypatch.setenv(IMPACT_BUDGET_ENV, "1")
    monkeypatch.setenv("VIGIL_AEGIS_RECEIPTS", "1")
    gw, port = _run_gateway(upstream, impact_budget=ImpactBudget(max_denied_ratio=0.5, window=100))
    try:
        assert gw.settings.impact_budget_meter is not None and gw.settings.impact_budget_active is True
        for _ in range(3):
            assert _get(port, "/x")[0] == 200
        snap = gw.settings._probe_snapshot()
        assert snap["impact_budget_active"] is True
        imp = snap["impact"]
        assert imp["considered"] == 3 and imp["allowed"] == 3 and imp["denied"] == 0
        assert imp["denied_ratio"] == 0.0 and imp["within_budget"] is True and imp["verified"] is True
        assert imp["budget"] == {"max_denied_ratio": 0.5, "window": 100}
        assert "127.0.0.1" not in json.dumps(snap)                       # no upstream/caller address leaks
    finally:
        gw.shutdown(); gw.server_close()


def test_gateway_impact_flip_off_at_runtime_stops_surfacing_the_rollup(upstream, monkeypatch):
    """Flipping EITHER the impact flag OR its AS-5d dependency OFF at runtime makes the rollup go inert live, so
    the probe answer drops the impact keys again."""
    monkeypatch.setenv(IMPACT_BUDGET_ENV, "1")
    monkeypatch.setenv("VIGIL_AEGIS_RECEIPTS", "1")
    gw, port = _run_gateway(upstream)
    try:
        assert _get(port, "/x")[0] == 200
        assert "impact" in gw.settings._probe_snapshot()
        monkeypatch.setenv(IMPACT_BUDGET_ENV, "0")                       # live flip-OFF
        assert gw.settings.impact_budget_active is False
        assert "impact" not in gw.settings._probe_snapshot()
        monkeypatch.setenv(IMPACT_BUDGET_ENV, "1")
        monkeypatch.setenv("VIGIL_AEGIS_RECEIPTS", "0")                  # dep flip-OFF -> also inert
        assert gw.settings.impact_budget_active is False
        assert "impact" not in gw.settings._probe_snapshot()
    finally:
        gw.shutdown(); gw.server_close()
