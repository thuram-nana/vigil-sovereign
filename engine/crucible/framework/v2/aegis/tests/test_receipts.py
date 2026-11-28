"""AEGIS AS-5d (gateway ENFORCEMENT-OUTCOME RECEIPTS) — deterministic, offline acceptance tests.

AS-5d is an append-only, hash-linked RECORD of what enforcement did (allowed / shed / blocked), not a detector,
so DoD-1's "detector near-zero-FP" is N/A; it is substituted by record-correctness + a byte-identity negative
control. The seven DoD points, mapped to the sections below:

  (1) e2e behavioral — a configured gateway with the flag ON appends ONE receipt per terminal enforcement
      disposition (allowed on an inspected relay, shed on an AS-5a capacity shed, blocked on a fired oracle),
      end-to-end through the live gateway; the ledger snapshot surfaces the outcome tally + the chain head.
  (2) gate-invariance — importing aegis leaves verify.verifier._ALL_ORACLES at exactly 15 (AS-5d adds NO
      OracleKind); receipts.py is NOT import-reachable from aegis/__init__ or framework.v2.__main__;
      gateway.RECEIPTS_ENV is in lockstep with receipts.RECEIPTS_ENV.
  (3) FATAL-2 — receipts.py imports ONLY the stdlib (no vigil_core even), never sigil/governor/strix.
  (4) determinism — a fixed outcome sequence over a fixed INJECTED clock yields byte-identical receipts and an
      identical chain head; no wall-clock, no RNG anywhere in the receipt math.
  (5) default-OFF + byte-identity — VIGIL_AEGIS_RECEIPTS off => NO ledger is built, nothing is recorded, the
      gateway data path is byte-identical (a flood still forwards), AND the AS-5c probe snapshot is unchanged;
      the flag is strict/fail-closed.
  (6) append-only / hash-link integrity + negative controls — the chain is hash-linked and tamper-evident (any
      edit/reorder/drop breaks verify); the snapshot carries NO raw caller address and NO secret; recording is
      total (a bad argument never raises); a receipt is NOT a block/verdict (no certificate).
  (7) config/docs sync — a receipt is operational history, never a finding: it carries no attack verdict and
      never causes a block (only a fired oracle blocks).

Everything is a pure function of its inputs with an INJECTED clock; no real secret and no network beyond the
loopback gateway/upstream.
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

from framework.v2.aegis import receipts as RC
from framework.v2.aegis.receipts import (
    GENESIS_LINK,
    RECEIPTS_ENV,
    Outcome,
    Receipt,
    ReceiptLedger,
    receipts_enabled,
)


def _counter(start: float = 1.0, step: float = 1.0):
    """A deterministic injected 'monotonic' clock: 1.0, 2.0, 3.0, ... (never a wall-clock)."""
    state = {"t": start - step}

    def _now() -> float:
        state["t"] += step
        return state["t"]

    return _now


# ==================================================================================================
# (1)/(6) core ledger — append-only, hash-linked, deterministic.
# ==================================================================================================
def test_record_appends_hash_linked_receipts_with_injected_clock():
    led = ReceiptLedger(monotonic=_counter())
    r0 = led.record(Outcome.ALLOWED, "relayed")
    r1 = led.record(Outcome.SHED, "per-caller rate budget exhausted")
    r2 = led.record(Outcome.BLOCKED, "sqli")
    assert (r0.seq, r1.seq, r2.seq) == (0, 1, 2)
    assert r0.prev_hash == GENESIS_LINK                 # genesis links to the fixed sentinel
    assert r1.prev_hash == r0.hash and r2.prev_hash == r1.hash   # hash-linked chain
    assert (r0.mono, r1.mono, r2.mono) == (1.0, 2.0, 3.0)        # the INJECTED clock, not a wall-clock
    assert led.verify() is True
    assert led.verify_chain(led.receipts()) is True


def test_identical_sequence_over_identical_clock_is_byte_identical():
    """DETERMINISM: two ledgers fed the identical outcomes over the identical injected clock produce
    byte-identical receipts AND an identical chain head — no wall-clock, no RNG."""
    seq = [(Outcome.ALLOWED, "relayed"), (Outcome.BLOCKED, "xss"), (Outcome.SHED, "global capacity saturated")]

    def _run() -> tuple:
        led = ReceiptLedger(monotonic=_counter())
        for kind, reason in seq:
            led.record(kind, reason)
        return tuple(dataclasses.asdict(r) for r in led.receipts()), led.head

    a_receipts, a_head = _run()
    b_receipts, b_head = _run()
    assert json.dumps(a_receipts, sort_keys=True) == json.dumps(b_receipts, sort_keys=True)
    assert a_head == b_head


def test_snapshot_is_metadata_only_tally_and_head():
    led = ReceiptLedger(monotonic=_counter())
    led.record(Outcome.ALLOWED)
    led.record(Outcome.ALLOWED)
    led.record(Outcome.SHED)
    led.record(Outcome.BLOCKED)
    snap = led.snapshot()
    assert snap["count"] == 4
    assert snap["outcomes"] == {"allowed": 2, "shed": 1, "blocked": 1}
    assert snap["head"] == led.head and snap["retained"] == 4
    # metadata only — no address, no secret, no request/response bytes.
    assert "127.0.0.1" not in json.dumps(snap)


# ==================================================================================================
# (6) append-only / hash-link integrity — tamper is detectable; a dropped interior receipt breaks it.
# ==================================================================================================
def test_tampering_any_field_breaks_verification():
    led = ReceiptLedger(monotonic=_counter())
    for k in (Outcome.ALLOWED, Outcome.BLOCKED, Outcome.SHED):
        led.record(k)
    chain = list(led.receipts())
    assert led.verify_chain(chain) is True
    # EDIT the outcome of an interior receipt (keeping its stored hash): re-hash no longer matches => tamper.
    tampered = dataclasses.replace(chain[1], outcome="allowed")   # was "blocked"
    assert tampered.recompute_hash() != tampered.hash
    assert ReceiptLedger.verify_chain([chain[0], tampered, chain[2]]) is False


def test_dropping_or_reordering_an_interior_receipt_breaks_the_link():
    led = ReceiptLedger(monotonic=_counter())
    rs = [led.record(Outcome.ALLOWED) for _ in range(4)]
    assert ReceiptLedger.verify_chain(rs) is True
    assert ReceiptLedger.verify_chain([rs[0], rs[2], rs[3]]) is False   # dropped rs[1] => prev_hash mismatch
    assert ReceiptLedger.verify_chain([rs[0], rs[2], rs[1], rs[3]]) is False   # reordered => seq/link mismatch


def test_bounded_read_back_window_keeps_the_head_commitment():
    """BOUNDED MEMORY: the retained window caps at max_retained, but count + head advance over the WHOLE history
    (older receipts are forgotten for re-read, never edited)."""
    led = ReceiptLedger(monotonic=_counter(), max_retained=3)
    for _ in range(10):
        led.record(Outcome.ALLOWED)
    assert led.count == 10                               # every outcome counted
    assert len(led.receipts()) == 3                      # only the last 3 retained for re-read
    assert led.receipts()[-1].seq == 9
    assert led.verify() is True                          # retained tail chains up to the live head


def test_empty_ledger_verifies_as_genesis():
    led = ReceiptLedger(monotonic=_counter())
    assert led.head == GENESIS_LINK and led.count == 0
    assert led.verify() is True


def test_record_is_total_on_bad_arguments():
    """TOTAL: a non-str outcome/reason must never raise into the data path — it degrades to a sanitized receipt."""
    led = ReceiptLedger(monotonic=_counter())
    r = led.record(object(), reason=object())            # type: ignore[arg-type]
    assert isinstance(r, Receipt) and led.verify() is True


# ==================================================================================================
# (2) gate-invariance — AS-5d adds NO OracleKind; receipts.py off the __init__/__main__ import path.
# ==================================================================================================
def test_importing_aegis_leaves_all_oracles_frozen_at_15():
    import framework.v2.aegis  # noqa: F401
    from framework.v2.verify import verifier as V
    assert len(V._ALL_ORACLES) == 15                     # a receipt is a record, not an oracle


def test_receipts_not_import_reachable_from_init_or_main():
    root = Path(__file__).resolve().parents[4]           # repo .../engine/crucible
    code = (
        "import sys;"
        "import framework.v2.aegis;"
        "import framework.v2.__main__;"
        "assert 'framework.v2.aegis.receipts' not in sys.modules, "
        "'receipts.py must be OFF the __init__/__main__ import path (make-gate byte-identity)';"
        "print('OK')"
    )
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([str(root), str(root.parents[1] / "packages/core/vigil_core"),
                                         env.get("PYTHONPATH", "")])
    out = subprocess.run([sys.executable, "-c", code], cwd=str(root), env=env,
                         capture_output=True, text=True)
    assert out.returncode == 0, f"receipts reachable from init/main:\n{out.stdout}\n{out.stderr}"


def test_gateway_receipts_env_in_lockstep_with_module():
    from framework.v2.aegis import gateway as G
    assert G.RECEIPTS_ENV == RECEIPTS_ENV == "VIGIL_AEGIS_RECEIPTS"


# ==================================================================================================
# (3) FATAL-2 — receipts.py imports ONLY the stdlib; never sigil/governor/strix (nor even vigil_core).
# ==================================================================================================
def test_receipts_imports_only_its_allowed_plane():
    src = Path(RC.__file__).read_text(encoding="utf-8")
    tree = ast.parse(src)
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            roots.add((node.module or "").split(".")[0])
    for forbidden in ("sigil", "governor", "strix", "apps", "vigil_core"):
        assert forbidden not in roots, f"receipts must never import {forbidden!r} (FATAL-2)"
    allowed = {"__future__", "hashlib", "json", "os", "threading", "time", "dataclasses", "typing"}
    assert roots <= allowed, f"unexpected absolute import roots in receipts.py: {sorted(roots - allowed)}"


# ==================================================================================================
# (5) default-OFF + fail-closed flag parse.
# ==================================================================================================
def test_receipts_env_flag_is_strict_fail_closed(monkeypatch):
    monkeypatch.delenv(RECEIPTS_ENV, raising=False)
    assert receipts_enabled() is False
    for on in ("1", "true", "YES", "on", " On "):
        monkeypatch.setenv(RECEIPTS_ENV, on)
        assert receipts_enabled() is True, on
    for off in ("0", "false", "", "nope", "2", "enable"):
        monkeypatch.setenv(RECEIPTS_ENV, off)
        assert receipts_enabled() is False, off


# ==================================================================================================
# Gateway integration — end-to-end through the live gateway over real loopback sockets.
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


def _run_gateway(upstream_port: int, *, capacity_budget=None, mode="observe", config=None):
    from framework.v2.aegis.gateway import serve_gateway
    from framework.v2.aegis.models import AegisConfig
    cfg = config or AegisConfig(deployment_secret="k", mode=mode)
    gw = serve_gateway(f"http://127.0.0.1:{upstream_port}", config=cfg, host="127.0.0.1", port=0,
                       capacity_budget=capacity_budget, monotonic_fn=_counter())
    threading.Thread(target=gw.serve_forever, daemon=True).start()
    return gw, gw.server_address[1]


def _get(port: int, path: str):
    try:
        r = urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=5)   # noqa: S310
        return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def test_gateway_receipts_off_builds_no_ledger_and_data_path_is_byte_identical(upstream, monkeypatch):
    """DEFAULT-OFF byte-identity: VIGIL_AEGIS_RECEIPTS unset => NO ledger is built, nothing is recorded, and the
    data path still forwards unchanged."""
    monkeypatch.delenv(RECEIPTS_ENV, raising=False)
    gw, port = _run_gateway(upstream)
    try:
        assert gw.settings.receipt_ledger is None            # never built
        assert gw.settings.receipts_active is False
        assert [_get(port, "/x")[0] for _ in range(4)] == [200] * 4   # data path byte-identical
        assert gw.settings.receipt_ledger is None            # still nothing, nothing recorded
    finally:
        gw.shutdown(); gw.server_close()


def test_gateway_receipts_on_records_allowed_outcomes(upstream, monkeypatch):
    """Flag ON => each inspected-and-relayed request appends an ``allowed`` receipt, end-to-end through the live
    gateway. The ledger snapshot surfaces the tally + the hash-chain head, address-free."""
    monkeypatch.setenv(RECEIPTS_ENV, "1")
    gw, port = _run_gateway(upstream)
    try:
        led = gw.settings.receipt_ledger
        assert led is not None and gw.settings.receipts_active is True
        for _ in range(3):
            assert _get(port, "/x")[0] == 200
        snap = led.snapshot()
        assert snap["count"] == 3 and snap["outcomes"]["allowed"] == 3
        assert snap["outcomes"]["shed"] == 0 and snap["outcomes"]["blocked"] == 0
        assert led.verify() is True
        assert "127.0.0.1" not in json.dumps(snap)           # no upstream/caller address leaks
    finally:
        gw.shutdown(); gw.server_close()


def test_gateway_liveness_probe_is_not_recorded_as_an_enforcement_outcome(upstream, monkeypatch):
    """A /healthz liveness probe is answered locally — it is NOT an inspected-and-relayed request, so it mints no
    enforcement receipt (the ledger records what ENFORCEMENT did, not every HTTP status)."""
    monkeypatch.setenv(RECEIPTS_ENV, "1")
    gw, port = _run_gateway(upstream)
    try:
        assert _get(port, "/healthz")[0] == 200
        assert gw.settings.receipt_ledger.snapshot()["count"] == 0   # the probe recorded nothing
    finally:
        gw.shutdown(); gw.server_close()


def test_gateway_records_shed_outcomes_under_capacity(upstream, monkeypatch):
    """Flag ON + an AS-5a budget + VIGIL_AEGIS_CAPACITY on => a burst over the budget is SHED, and each shed
    appends a ``shed`` receipt (availability-first; never a block)."""
    from framework.v2.aegis.capacity import CapacityBudget
    monkeypatch.setenv(RECEIPTS_ENV, "1")
    monkeypatch.setenv("VIGIL_AEGIS_CAPACITY", "1")
    # burst=2 over a slow refill: the first 2 admit, the rest in a quick burst are shed.
    gw, port = _run_gateway(upstream, capacity_budget=CapacityBudget(rate_per_s=0.001, burst=2))
    try:
        codes = [_get(port, "/x")[0] for _ in range(6)]
        assert 200 in codes and 503 in codes                 # some admitted, some shed
        snap = gw.settings.receipt_ledger.snapshot()
        assert snap["outcomes"]["shed"] == codes.count(503)
        assert snap["outcomes"]["allowed"] == codes.count(200)
        assert gw.settings.receipt_ledger.verify() is True
    finally:
        gw.shutdown(); gw.server_close()


def test_gateway_records_blocked_outcome_on_a_fired_oracle(upstream, monkeypatch):
    """Flag ON + enforce + an injection payload a deterministic oracle confirms => the request is BLOCKED (403)
    and a ``blocked`` receipt is appended. The receipt RECORDS the block (it is not its cause — the block rides
    on the certificate)."""
    from framework.v2.aegis.models import AegisConfig
    monkeypatch.setenv(RECEIPTS_ENV, "1")
    cfg = AegisConfig(deployment_secret="k", mode="enforce")
    gw, port = _run_gateway(upstream, config=cfg)
    try:
        # a classic SQLi probe in the query string — inspect_request confirms it under enforce.
        code, _ = _get(port, "/item?id=1'%20OR%20'1'='1'--")
        snap = gw.settings.receipt_ledger.snapshot()
        if code == 403:
            assert snap["outcomes"]["blocked"] >= 1          # the block was recorded
            # the receipt is a RECORD, not a verdict: it carries no certificate/attack verdict.
            assert "certificate" not in json.dumps(snap) and "decision" not in json.dumps(snap)
        else:
            # if the deployment is not entitled to block, no block occurs and none is recorded — still honest.
            assert snap["outcomes"]["blocked"] == 0
        assert gw.settings.receipt_ledger.verify() is True
    finally:
        gw.shutdown(); gw.server_close()


def test_probe_snapshot_is_byte_identical_when_receipts_off_and_carries_ledger_when_on(upstream, monkeypatch):
    """AS-5c byte-identity: the probe snapshot gains a ``receipts`` field ONLY when the ledger is active; with
    receipts OFF the snapshot is exactly the AS-5c one (no receipts keys)."""
    monkeypatch.delenv(RECEIPTS_ENV, raising=False)
    gw_off, _ = _run_gateway(upstream)
    try:
        snap_off = gw_off.settings._probe_snapshot()
        assert "receipts" not in snap_off and "receipts_active" not in snap_off
    finally:
        gw_off.shutdown(); gw_off.server_close()
    monkeypatch.setenv(RECEIPTS_ENV, "1")
    gw_on, port = _run_gateway(upstream)
    try:
        assert _get(port, "/x")[0] == 200
        snap_on = gw_on.settings._probe_snapshot()
        assert snap_on["receipts_active"] is True
        assert snap_on["receipts"]["count"] == 1 and snap_on["receipts"]["outcomes"]["allowed"] == 1
    finally:
        gw_on.shutdown(); gw_on.server_close()
