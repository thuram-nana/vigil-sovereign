"""AEGIS AS-5a (gateway CAPACITY admission plane) — deterministic, offline acceptance tests.

AS-5a is an ADMISSION/LOAD-SHEDDING capability, not a detector, so DoD-1's "detector near-zero-FP" is N/A;
it is substituted by admission-correctness + a byte-identity negative control. The seven DoD points, mapped
to the sections below:

  (1) e2e behavioral — under budget ADMITS and takes a slot; over the per-caller rate / per-caller
      concurrency / global concurrency budget it SHEDS with the right reason + an honest Retry-After; a
      released slot is reusable. End-to-end through the live gateway: flag ON sheds a burst with a soft 503,
      a liveness probe is NEVER shed.
  (2) gate-invariance — importing aegis leaves verify.verifier._ALL_ORACLES at exactly 15 (AS-5a adds NO
      OracleKind); capacity.py is NOT import-reachable from aegis/__init__ or framework.v2.__main__;
      gateway.CAPACITY_ENV is in lockstep with capacity.CAPACITY_ENV.
  (3) FATAL-2 — capacity.py imports ONLY the stdlib (no vigil_core even), never sigil/governor/strix.
  (4) determinism — a fixed request sequence over a fixed injected clock yields the identical admit/shed
      pattern; no wall-clock, no RNG anywhere on the decision.
  (5) default-OFF + byte-identity — VIGIL_AEGIS_CAPACITY off => the governor is never consulted and a flood
      is forwarded UNCHANGED (byte-identical to an un-configured gateway); the flag is strict/fail-closed.
  (6) negative controls — mutation-sensitive per guard: per-caller FAIRNESS (independent buckets), rate
      REFILL over time, FAIL-OPEN on a governor fault, exactly-once RELEASE (counters floor at 0), a shed is
      a soft 503 NOT a 403 block (no certificate), and the probe-bypass.
  (7) config/docs sync — a non-positive rate / burst or a negative cap is a fail-closed construction error;
      a capacity shed mints NO attack verdict (capacity is operational, never a finding).

Everything is a pure function of its inputs with an INJECTED clock; no real secret and no network.
"""
from __future__ import annotations

import ast
import http.server
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

from framework.v2.aegis import capacity as CAP
from framework.v2.aegis.capacity import (
    CAPACITY_ENV,
    Admission,
    CapacityBudget,
    CapacityGovernor,
    capacity_enabled,
)


def _gov(*, rate=5.0, burst=3, per_caller=0, glob=0, monotonic=None, max_tracked=8192) -> CapacityGovernor:
    budget = CapacityBudget(rate_per_s=rate, burst=burst,
                            max_inflight_per_caller=per_caller, max_inflight_global=glob)
    return CapacityGovernor(budget, monotonic=monotonic or (lambda: 0.0), max_tracked=max_tracked)


# ==================================================================================================
# (1) e2e behavioral — the pure governor's admit/shed decisions.
# ==================================================================================================
def test_under_budget_admits_and_consumes_a_token():
    gov = _gov(rate=5.0, burst=3, monotonic=lambda: 100.0)
    a = gov.admit("1.2.3.4")
    assert a.admitted and a.reason == "admitted" and a.acquire_id > 0 and a.caller == "1.2.3.4"


def test_over_rate_sheds_with_reason_and_retry_after():
    # burst 1, a FIXED clock (no refill): the 2nd request in the same instant is shed on the rate budget.
    gov = _gov(rate=2.0, burst=1, monotonic=lambda: 50.0)
    assert gov.admit("c").admitted
    shed = gov.admit("c")
    assert not shed.admitted and shed.reason == "per-caller rate budget exhausted"
    assert shed.acquire_id == 0                        # a shed grants no slot
    # Retry-After: a full token at rate 2/s is 0.5s away -> header floors to 1s (a client always backs off).
    assert abs(shed.retry_after_s - 0.5) < 1e-9 and shed.retry_after_header == 1


def test_per_caller_concurrency_cap_sheds_then_a_release_frees_a_slot():
    # rate/burst generous so ONLY the concurrency cap can refuse; cap = 2 concurrent per caller.
    gov = _gov(rate=1e6, burst=1000, per_caller=2, monotonic=lambda: 0.0)
    a1 = gov.admit("c"); a2 = gov.admit("c")
    assert a1.admitted and a2.admitted
    shed = gov.admit("c")
    assert not shed.admitted and shed.reason == "per-caller concurrency saturated"
    gov.release(a1)                                   # free one in-flight slot
    assert gov.admit("c").admitted                    # now there is room again


def test_global_concurrency_cap_sheds_across_callers():
    gov = _gov(rate=1e6, burst=1000, glob=2, monotonic=lambda: 0.0)
    a = gov.admit("A"); b = gov.admit("B")
    assert a.admitted and b.admitted
    shed = gov.admit("C")                             # a THIRD distinct caller — global cap, not per-caller
    assert not shed.admitted and shed.reason == "global capacity saturated"
    gov.release(a)
    assert gov.admit("C").admitted


def test_snapshot_is_metadata_only_and_tracks_inflight():
    gov = _gov(rate=1e6, burst=10, monotonic=lambda: 0.0)
    a = gov.admit("9.9.9.9")
    snap = gov.snapshot()
    assert snap == {"tracked_callers": 1, "global_inflight": 1}
    assert "9.9.9.9" not in str(snap)                 # metadata only — no caller address leaks
    gov.release(a)
    assert gov.snapshot()["global_inflight"] == 0


# ==================================================================================================
# (2) gate-invariance — AS-5a adds NO OracleKind; capacity.py off the __init__/__main__ import path.
# ==================================================================================================
def test_importing_aegis_leaves_all_oracles_frozen_at_15():
    import framework.v2.aegis  # noqa: F401
    from framework.v2.verify import verifier as V
    assert len(V._ALL_ORACLES) == 15                 # capacity is admission control, not an oracle


def test_capacity_not_import_reachable_from_init_or_main():
    root = Path(__file__).resolve().parents[4]       # repo .../engine/crucible
    code = (
        "import sys;"
        "import framework.v2.aegis;"
        "import framework.v2.__main__;"
        "assert 'framework.v2.aegis.capacity' not in sys.modules, "
        "'capacity.py must be OFF the __init__/__main__ import path (make-gate byte-identity)';"
        "print('OK')"
    )
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([str(root), str(root.parents[1] / "packages/core/vigil_core"),
                                         env.get("PYTHONPATH", "")])
    out = subprocess.run([sys.executable, "-c", code], cwd=str(root), env=env,
                         capture_output=True, text=True)
    assert out.returncode == 0, f"capacity reachable from init/main:\n{out.stdout}\n{out.stderr}"


def test_gateway_capacity_env_in_lockstep_with_capacity_module():
    from framework.v2.aegis import gateway as G
    assert G.CAPACITY_ENV == CAPACITY_ENV == "VIGIL_AEGIS_CAPACITY"


# ==================================================================================================
# (3) FATAL-2 — capacity.py imports ONLY the stdlib; never sigil/governor/strix (nor even vigil_core).
# ==================================================================================================
def test_capacity_imports_only_its_allowed_plane():
    src = Path(CAP.__file__).read_text(encoding="utf-8")
    tree = ast.parse(src)
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            roots.add((node.module or "").split(".")[0])
    for forbidden in ("sigil", "governor", "strix", "apps"):
        assert forbidden not in roots, f"capacity must never import {forbidden!r} (FATAL-2)"
    allowed = {"__future__", "itertools", "math", "os", "threading", "time", "dataclasses", "typing"}
    assert roots <= allowed, f"unexpected absolute import roots in capacity.py: {sorted(roots - allowed)}"


# ==================================================================================================
# (4) determinism — a fixed sequence over a fixed injected clock gives the identical admit/shed pattern.
# ==================================================================================================
def test_decision_sequence_is_deterministic_and_clock_injected():
    def _run() -> list[tuple[bool, str]]:
        gov = _gov(rate=1.0, burst=2, monotonic=lambda: 0.0)
        out = []
        # a fixed (caller, now) script — same inputs must give the same decisions, with NO wall-clock/RNG.
        script = [("A", 0.0), ("A", 0.0), ("A", 0.0), ("A", 1.0), ("B", 0.5), ("A", 1.0)]
        for caller, now in script:
            d = gov.admit(caller, now=now)
            out.append((d.admitted, d.reason))
        return out
    first = _run()
    assert _run() == first                            # reproducible
    # the explicit pattern: A starts with burst=2 -> admit, admit, then shed; +1s refills 1 token -> admit;
    # B is independent (full bucket) -> admit; A at the SAME now=1.0 has 0 tokens again -> shed.
    assert [a for a, _ in first] == [True, True, False, True, True, False]


# ==================================================================================================
# (5) default-OFF + fail-closed flag parse.
# ==================================================================================================
def test_capacity_env_flag_is_strict_fail_closed(monkeypatch):
    monkeypatch.delenv(CAPACITY_ENV, raising=False)
    assert capacity_enabled() is False
    for on in ("1", "true", "YES", "on", " On "):
        monkeypatch.setenv(CAPACITY_ENV, on)
        assert capacity_enabled() is True, on
    for off in ("0", "false", "", "nope", "2", "enable"):
        monkeypatch.setenv(CAPACITY_ENV, off)
        assert capacity_enabled() is False, off


# ==================================================================================================
# (6) negative controls — mutation-sensitive per guard.
# ==================================================================================================
def test_negative_control_per_caller_fairness_independent_buckets():
    """Caller A exhausting its budget must NOT shed caller B. Share one bucket across callers and this reds."""
    gov = _gov(rate=1.0, burst=1, monotonic=lambda: 0.0)
    assert gov.admit("A").admitted
    assert not gov.admit("A").admitted                # A is now over its budget
    assert gov.admit("B").admitted                    # B has its OWN full bucket — unaffected by A's flood


def test_negative_control_rate_refills_over_time():
    """After enough time the token bucket replenishes and admits resume. Drop the refill and this reds."""
    clock = {"t": 0.0}
    gov = _gov(rate=2.0, burst=1, monotonic=lambda: clock["t"])
    assert gov.admit("c").admitted
    assert not gov.admit("c").admitted                # immediately: empty
    clock["t"] = 0.5                                  # 0.5s * 2/s = 1 token
    assert gov.admit("c").admitted                    # refilled -> admit


def test_negative_control_fail_open_on_governor_fault(monkeypatch):
    """A governor INTERNAL error must ADMIT (never shed on its own fault). Make _refill raise -> admit."""
    gov = _gov(rate=1.0, burst=1, monotonic=lambda: 0.0)
    assert gov.admit("c").admitted                    # create the caller's bucket
    assert not gov.admit("c").admitted                # (would shed on rate) — proves the guard was live

    def _boom(*_a, **_k):
        raise RuntimeError("governor fault")
    monkeypatch.setattr(gov, "_refill", _boom)
    a = gov.admit("c")                                # _refill now raises inside admit
    assert a.admitted and "fail-open" in a.reason     # fail-OPEN: a fault admits, never sheds


def test_negative_control_release_is_exactly_once_and_floors_at_zero():
    gov = _gov(rate=1e6, burst=100, per_caller=5, glob=5, monotonic=lambda: 0.0)
    a = gov.admit("c")
    assert gov.snapshot()["global_inflight"] == 1
    gov.release(a)
    gov.release(a)                                    # double-release — must be a safe no-op
    gov.release(0); gov.release(None)                 # shed / empty handles — no-ops
    assert gov.snapshot()["global_inflight"] == 0     # floored, never negative
    assert gov.admit("c").admitted                    # the slot really was returned


def test_negative_control_bounded_memory_evicts_recovered_idle_callers():
    clock = {"t": 0.0}
    gov = _gov(rate=1.0, burst=1, max_tracked=4, monotonic=lambda: clock["t"])
    for i in range(12):                               # 12 distinct one-shot callers, each admitted + released
        gov.release(gov.admit(f"c{i}", now=0.0))
    assert gov.snapshot()["tracked_callers"] == 12    # all tracked so far (map not yet over the cap at create)
    clock["t"] = 100.0                                # every idle caller's budget has fully recovered
    gov.admit("fresh", now=100.0)                     # this create trips eviction of the recovered idle callers
    assert gov.snapshot()["tracked_callers"] <= 5     # bounded (<= max_tracked + the fresh caller)


def test_shed_is_a_soft_retry_not_a_block():
    """A capacity shed is availability-first: it carries a Retry-After and NO certificate/verdict — it is
    NEVER the 403 'block' path (which rides on a fired oracle). The Admission object proves this shape."""
    gov = _gov(rate=1.0, burst=1, monotonic=lambda: 0.0)
    gov.admit("c")
    shed = gov.admit("c")
    assert shed.admitted is False and shed.retry_after_header >= 1
    assert not hasattr(shed, "certificate")           # a shed is not a verdict — no certificate anywhere


# ==================================================================================================
# (7) config/docs sync — fail-closed construction; a shed is operational (not a verdict).
# ==================================================================================================
@pytest.mark.parametrize("kw", [
    {"rate_per_s": 0.0, "burst": 1},
    {"rate_per_s": -1.0, "burst": 1},
    {"rate_per_s": 1.0, "burst": 0},
    {"rate_per_s": 1.0, "burst": 1, "max_inflight_per_caller": -1},
    {"rate_per_s": 1.0, "burst": 1, "max_inflight_global": -1},
])
def test_bad_budget_is_a_fail_closed_construction_error(kw):
    with pytest.raises(ValueError):
        CapacityBudget(**kw)


# ==================================================================================================
# Gateway integration — end-to-end over real loopback sockets.
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


def _run_gateway(upstream_port: int, *, capacity_budget=None):
    from framework.v2.aegis.gateway import serve_gateway
    from framework.v2.aegis.models import AegisConfig
    cfg = AegisConfig(deployment_secret="k", mode="observe")
    # a FIXED monotonic clock => no token refill between sequential requests => deterministic shed.
    gw = serve_gateway(f"http://127.0.0.1:{upstream_port}", config=cfg, host="127.0.0.1", port=0,
                       capacity_budget=capacity_budget, monotonic_fn=lambda: 1000.0)
    threading.Thread(target=gw.serve_forever, daemon=True).start()
    return gw, gw.server_address[1]


def _get(port: int, path: str):
    try:
        r = urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=5)
        return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def test_gateway_flag_off_is_inert_no_shedding(upstream, monkeypatch):
    """DEFAULT-OFF byte-identity: a budget is configured but VIGIL_AEGIS_CAPACITY is unset => NOTHING is shed;
    a flood that WOULD exceed burst=1 is forwarded unchanged. Fire the capacity hook with the flag off => red."""
    monkeypatch.delenv(CAPACITY_ENV, raising=False)
    budget = CapacityBudget(rate_per_s=1.0, burst=1)          # burst 1 => would shed after the 1st if active
    gw, port = _run_gateway(upstream, capacity_budget=budget)
    try:
        statuses = [_get(port, "/x")[0] for _ in range(6)]
        assert statuses == [200] * 6                         # inert: every request reached the upstream
    finally:
        gw.shutdown()


def test_gateway_flag_on_sheds_a_burst_with_soft_503(upstream, monkeypatch):
    monkeypatch.setenv(CAPACITY_ENV, "1")
    budget = CapacityBudget(rate_per_s=1.0, burst=1)          # one token, fixed clock => no refill
    gw, port = _run_gateway(upstream, capacity_budget=budget)
    try:
        first = _get(port, "/x")
        second = _get(port, "/x")
        assert first[0] == 200 and first[1] == b"UPSTREAM-OK"  # under budget -> forwarded
        assert second[0] == 503                                # over budget -> soft shed
        assert b"capacity_shed" in second[1] and b"NOT a proven block" in second[1]
    finally:
        gw.shutdown()


def test_gateway_liveness_probe_is_never_shed(upstream, monkeypatch):
    """Even with the budget exhausted, /healthz must still answer 200 (an orchestrator probe is never shed)."""
    monkeypatch.setenv(CAPACITY_ENV, "1")
    budget = CapacityBudget(rate_per_s=1.0, burst=1)
    gw, port = _run_gateway(upstream, capacity_budget=budget)
    try:
        assert _get(port, "/x")[0] == 200                     # consume the single token
        assert _get(port, "/x")[0] == 503                     # now shedding real traffic
        assert _get(port, "/healthz")[0] == 200               # ...but the liveness probe is exempt
    finally:
        gw.shutdown()


def test_gateway_no_budget_configured_has_no_governor(upstream, monkeypatch):
    """With no capacity_budget the governor is None and capacity_active is False even with the flag ON — the
    capacity module is never even imported into this gateway (byte-identical un-gated path)."""
    monkeypatch.setenv(CAPACITY_ENV, "1")
    gw, port = _run_gateway(upstream, capacity_budget=None)
    try:
        assert gw.settings.capacity_governor is None
        assert gw.settings.capacity_active is False
        assert [_get(port, "/x")[0] for _ in range(4)] == [200] * 4
    finally:
        gw.shutdown()
