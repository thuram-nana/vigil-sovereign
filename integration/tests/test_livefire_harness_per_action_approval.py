"""W0-11 (#406) — the livefire harness is a TRUSTED multi-action driver, so it must approve EACH offense
action PER ACTION now that the standing ``--approve-offense`` grant is per-action + single-use.

THE REGRESSION THIS PINS. W0-11 made :class:`StandingApproval` a PER-ACTION, single-use grant: the approval
gate (:func:`_approval_gate`) upgrades a WARDEN ``queue`` to ``allow`` ONLY for the exact ``(tool, target)``
the grant is bound to and spent on — an autonomous agent can no longer blanket-auto-fire every queued action
from one flag. But the REAL-CI livefire smoke drove its gate through the OLD blanket wrapper
``_approval_gate(with_destruction(real_gate))`` with NO per-action source. With the standing grant now
per-action, ``source=None`` promotes NOTHING, so EVERY hydra leg was denied at the gate:

    authorization denied: in envelope, but WARDEN needs owner approval: A2 requires owner approval

THE FIX. ``tools/livefire/tool_drivers_livefire.py`` stores the base gate WITHOUT the approval wrapper and
mints a FRESH single-use grant per row (:func:`approve_action_gate`), bound to exactly that row's action —
precisely as the engine's ``run_tool`` binds each action before executing it. The harness is the operator's
human leg, approving EACH action; the grant is spent per action and re-granted for the next.

WHAT THESE TESTS PROVE, at the exact seam the executor uses (``authorize_tool_call`` → the conjunctive gate):
  * a TRUSTED driver of MANY distinct offense actions (the CI scenario: nmap + the two hydra rows' four legs)
    approves each one and ALL run;
  * the SECURITY property holds — an action the harness did NOT bind (a different action, a replay of a spent
    grant, an underivable/out-of-scope target) is DENIED: no blanket promote-all is reintroduced;
  * fail-before/pass-after — the reverted wiring (the blanket ``_approval_gate`` with no per-action source)
    denies every A2 action exactly as CI saw, and the per-action helper allows each.

The REAL harness governance (``build_governance`` → a signed CRUCIBLE authority + ``build_offense_gate`` + the
m-of-n destructive leg) is exercised, and the REAL harness helper ``approve_action_gate`` — no stubs of the
thing under test. No subprocess is spawned (the decision is made at the gate, before any argv is built), so
this is deterministic and needs neither the live range nor hydra installed.

``framework`` co-loads the offense env, so this module runs in the OFFENSE CI leg (it is listed there) and
SKIPS in the sovereign leg. FATAL-2: integration plane only — it never imports ``sigil``.
"""
from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

pytest.importorskip("framework.v2.authority.charter", reason="CRUCIBLE (offense) not importable here")

# The livefire harness lives outside the PYTHONPATH the suite runs on; its module top-level is stdlib-only
# (every heavy import is deferred into a function), so importing it here is cheap and side-effect-free.
_HARNESS_DIR = Path(__file__).resolve().parents[2] / "tools" / "livefire"
if str(_HARNESS_DIR) not in sys.path:
    sys.path.insert(0, str(_HARNESS_DIR))
harness = importlib.import_module("tool_drivers_livefire")

from vigil_core.gate import GateVerdict  # noqa: E402
from vigil_integration.live.executor import derive_gate_binding  # noqa: E402
from vigil_integration.live.wiring import (  # noqa: E402
    DEFAULT_DESTRUCTIVE_VIEW,
    DEFAULT_TOOL_VIEW,
    _approval_gate,
)
from vigil_integration.tools import authorize_tool_call  # noqa: E402

LOOPBACK = "127.0.0.1"

# The CI scenario, honestly: nmap (recon, classifies A1 → the gate ALLOWS it, no approval needed) plus the
# two hydra rows, each with a vulnerable + clean leg. hydra classifies A2 AND is destructive, so under the A1
# offense ceiling the conjunctive gate QUEUES every leg for the owner's approval — the four legs the CI smoke
# denied. Distinct ports make them four DISTINCT gate actions.
_NMAP = ("nmap", {"target": LOOPBACK})
_HYDRA_LEGS = [
    ("hydra", {"target": f"{LOOPBACK}:8081", "service": "http-get",
               "username": "svc", "passlist": "/tmp/pw.txt"}),          # http-get, vulnerable twin
    ("hydra", {"target": f"{LOOPBACK}:8082", "service": "http-get",
               "username": "svc", "passlist": "/tmp/pw.txt"}),          # http-get, clean control
    ("hydra", {"target": f"{LOOPBACK}:8083", "service": "http-post-form",
               "username": "svc", "passlist": "/tmp/pw.txt"}),          # http-post-form, vulnerable twin
    ("hydra", {"target": f"{LOOPBACK}:8084", "service": "http-post-form",
               "username": "svc", "passlist": "/tmp/pw.txt"}),          # http-post-form, clean control
]


@pytest.fixture()
def gov(tmp_path, monkeypatch):
    """The harness's REAL governance: a signed loopback CRUCIBLE authority + the conjunctive gate (base only,
    no approval wrapper) + the m-of-n destructive leg. One per test, under its own CRUCIBLE_ROOT."""
    monkeypatch.setenv("CRUCIBLE_ROOT", str(tmp_path / "crucible-root"))
    return harness.build_governance(str(tmp_path / "gov"))


def _decide(gate, tool, args):
    """Route ONE action through the exact seam the executor uses: derive the gate-seen ``(tool, target)`` with
    the executor's own ``derive_gate_binding`` (default loopback scope, matching ``run_leg``'s ``execute``),
    then ``authorize_tool_call`` — which classifies the tier, marks hydra destructive, and calls the gate with
    that pair. Returns the ToolCallVerdict; no argv is built and nothing is spawned."""
    binding = derive_gate_binding(tool, args)
    assert binding is not None, f"{tool} {args!r} should derive to an in-scope loopback target"
    _gtool, gtarget = binding
    return authorize_tool_call(tool, args, "exploitation", gate=gate, view=DEFAULT_TOOL_VIEW,
                               destructive_view=DEFAULT_DESTRUCTIVE_VIEW, resolved_target=gtarget)


# ---------------------------------------------------------------------------------------------------
# per-action approval works for a TRUSTED multi-action driver — ALL rows run
# ---------------------------------------------------------------------------------------------------


def test_harness_approves_each_row_and_all_run(gov):
    # The whole CI scenario: nmap + the four hydra legs, each approved on its own via the harness's real
    # per-row helper. ALL run (the recon row allows directly; each queued hydra leg is promoted by its own
    # fresh single-use grant). This is the run the CI smoke could not complete.
    for tool, args in [_NMAP, *_HYDRA_LEGS]:
        gate = harness.approve_action_gate(gov.base_gate, tool, args)
        verdict = _decide(gate, tool, args)
        assert verdict.allowed is True, f"{tool} {args!r} was not allowed: {verdict.reason}"
        assert verdict.outcome == "allow"


def test_each_hydra_leg_needs_its_own_grant_they_do_not_share_one(gov):
    # A grant minted for leg 1 does NOT carry leg 2 (single-use, bound to leg 1's action) — the driver must
    # re-approve each. Proven by the reuse being denied while a FRESH per-leg grant allows it.
    leg1, leg2 = _HYDRA_LEGS[0], _HYDRA_LEGS[2]

    gate1 = harness.approve_action_gate(gov.base_gate, *leg1)
    assert _decide(gate1, *leg1).allowed is True            # leg 1's grant runs leg 1
    assert _decide(gate1, *leg2).allowed is False           # ...and refuses leg 2 (a different action)

    gate2 = harness.approve_action_gate(gov.base_gate, *leg2)
    assert _decide(gate2, *leg2).allowed is True            # leg 2 runs under ITS OWN fresh grant


# ---------------------------------------------------------------------------------------------------
# the security property — nothing the harness did NOT approve runs
# ---------------------------------------------------------------------------------------------------


def test_an_unbound_action_is_denied_no_blanket_bypass(gov):
    # A grant bound to action A never promotes a DIFFERENT action B — and binding B does not spend A's grant,
    # so A still runs. The harness only approves the exact rows it drives.
    action_a = _HYDRA_LEGS[0]
    action_b = ("hydra", {"target": f"{LOOPBACK}:9099", "service": "http-get",
                          "username": "svc", "passlist": "/tmp/pw.txt"})   # never approved

    gate = harness.approve_action_gate(gov.base_gate, *action_a)
    assert _decide(gate, *action_b).allowed is False        # the unapproved action is DENIED
    assert _decide(gate, *action_a).allowed is True         # the approved action still runs


def test_a_spent_grant_does_not_run_the_same_action_twice(gov):
    # Single-use: even the SAME action is promoted once. A driver that tried to reuse one approval for two
    # executions gets the second denied — a blanket bypass would let it through.
    action = _HYDRA_LEGS[1]
    gate = harness.approve_action_gate(gov.base_gate, *action)
    assert _decide(gate, *action).allowed is True           # spent on this one action
    assert _decide(gate, *action).allowed is False          # a second execution is NOT re-promoted


def test_an_underivable_target_binds_nothing_and_is_denied():
    # An out-of-scope / unresolvable target cannot be pinned, so derive_gate_binding returns None and
    # approve_action_gate leaves the grant UNBOUND — the gate promotes nothing (fail-closed). Isolated at the
    # approval layer with a stand-in gate that queues everything, so the CRUCIBLE scope leg is not what denies.
    def queue_everything(tool_name, target, destructive=False, **kw):
        return GateVerdict(False, "queue", "in envelope, WARDEN needs owner approval", True, None)

    gate = harness.approve_action_gate(queue_everything, "hydra", {"target": "203.0.113.7:80"})
    verdict = gate("hydra", "203.0.113.7:80", True)
    assert verdict.outcome == "queue"                       # NOT promoted — nothing was bound


# ---------------------------------------------------------------------------------------------------
# fail-before / pass-after — the reverted wiring is exactly what CI saw
# ---------------------------------------------------------------------------------------------------


def test_reverting_to_the_blanket_wrapper_denies_every_hydra_leg_like_ci(gov):
    # THE REVERTED WIRING: the OLD ``gov.gate = _approval_gate(with_destruction(real_gate))`` — the blanket
    # wrapper with NO per-action source. With the standing grant now per-action, source=None promotes nothing,
    # so every queued A2 leg is DENIED ("A2 requires owner approval"), reproducing the REAL-CI failure. The
    # per-action helper above allows the same legs — the fix, isolated.
    reverted_gate = _approval_gate(gov.base_gate)           # source defaults to None (the pre-fix behaviour)
    for tool, args in _HYDRA_LEGS:
        verdict = _decide(reverted_gate, tool, args)
        assert verdict.allowed is False, f"{args!r} should be denied under the reverted wiring"
        assert verdict.outcome != "allow"

    # ...and the SAME legs, driven through the per-action helper, all run (pass-after).
    for tool, args in _HYDRA_LEGS:
        gate = harness.approve_action_gate(gov.base_gate, tool, args)
        assert _decide(gate, tool, args).allowed is True


# ===================================================================================================
# CAUSE A — a TRANSIENT reset on the clean-control probe self-heals via a bounded re-run, and NEVER
# weakens the fail-closed control. The nightly full-table job's httpx control probe aims at a closed
# loopback port; the kernel usually returns ECONNREFUSED (httpx records `{"failed":true}`, which
# `control_liveness` reads as evidence) but SOMETIMES a RST (Errno 104), on which httpx writes nothing
# and the row fails closed at tool_drivers_livefire.py:2218-2220. A transient reset should re-run the
# REAL probe (bounded); a probe that resets on EVERY attempt must still FAIL closed.
# ===================================================================================================


class _FakeReader:
    """A stand-in for an engine reader: it mints one item per non-empty line that is neither a reset
    nor a `failed` record, so the vuln leg parses to a signal and every control leg parses to nothing."""
    symbol = "fake-reader"

    def parse(self, stdout: str) -> list:
        return [ln for ln in stdout.splitlines()
                if ln.strip() and "failed" not in ln and "reset" not in ln]


def _control_reset_proof():
    """A minimal one-row proof whose control_liveness matches the real httpx row: the closed-port probe
    is 'live' iff it recorded a `{"failed":true}` refusal. A reset writes no such record."""
    return harness.ToolProof(
        tool="httpx",
        phase="informational",
        weakness="a fake weakness, reported iff the reader mints anything",
        identify=(("-version",), "irrelevant — identify is monkeypatched"),
        vuln=lambda e: {"target": "http://loopback/"},      # no port -> the target-gone probe is skipped
        clean=lambda e: {"target": "http://loopback/"},
        vuln_label=lambda e: "VULN",
        clean_label=lambda e: "CLEAN",
        reader=_FakeReader(),
        signal=lambda items, raw: bool(items),
        control_liveness=lambda raw: '"failed":true' in raw.replace(" ", ""),
        liveness_desc="httpx recorded a failed probe for the closed port, so it ran and reached it",
    )


def _install_fake_run_leg(monkeypatch, *, clean_raws):
    """Replace ``run_leg`` so the VULN leg always returns a parseable hit and the CLEAN leg returns
    ``clean_raws[attempt]`` (the last value repeats if attempts exceed the list). Records call counts so
    a test can prove the vuln leg is NEVER re-run by the control-retry path. Also makes the binary
    'present' and the backoff instant, so the retry runs without spawning anything or blocking."""
    calls = {"vuln": 0, "clean": 0}

    def fake_run_leg(proof, tool_args, label, gov, seq):
        leg = harness.Leg(label=label)
        leg.ran = True
        leg.exit_code = 0
        if label == "VULN":
            calls["vuln"] += 1
            leg.stdout = leg.raw = "hit"                     # parses to one item -> signal True
        else:
            idx = min(calls["clean"], len(clean_raws) - 1)
            calls["clean"] += 1
            leg.stdout = leg.raw = clean_raws[idx]
        return leg

    monkeypatch.setattr(harness, "run_leg", fake_run_leg)
    monkeypatch.setattr(harness, "identify_binary", lambda tool, spec: (True, "fake binary"))
    monkeypatch.setattr(harness, "_CONTROL_RESET_BACKOFF_S", 0.0)
    return calls


def test_a_transient_control_reset_self_heals_and_the_row_passes(monkeypatch):
    # The control probe resets on its FIRST attempt (no `failed:true` record -> liveness unmet), then a
    # re-run of the REAL probe gets the normal refusal. The row PASSES, and the vuln leg is never re-run.
    calls = _install_fake_run_leg(
        monkeypatch, clean_raws=["connection reset by peer", '{"failed":true}'])
    row = harness.run_row(_control_reset_proof(), object(), None, seq=0)

    assert row.verdict == "PASS", row.failures
    assert calls["clean"] == 2, "the transient reset was not re-run exactly once"
    assert calls["vuln"] == 1, "the control-retry path must NEVER re-run the vuln leg"
    # The retry kept the REAL healed leg — it did not fabricate a record or force liveness.
    assert row.clean.raw == '{"failed":true}'
    assert row.clean.signal is False


def test_a_control_that_resets_on_every_attempt_still_fails_closed(monkeypatch):
    # The control probe resets on EVERY attempt: the transient self-heal is bounded and exhausts without
    # ever satisfying liveness, so the row FAILS CLOSED with the exact 2219-2220 message. The retry never
    # fabricated a record, never set a signal, never made control_liveness pass.
    reset = "connection reset by peer (errno 104)"
    calls = _install_fake_run_leg(monkeypatch, clean_raws=[reset])
    row = harness.run_row(_control_reset_proof(), object(), None, seq=0)

    assert row.verdict == "FAIL"
    assert calls["clean"] == harness._CONTROL_RESET_MAX_ATTEMPTS, "the retry is not bounded"
    assert calls["vuln"] == 1, "the control-retry path must NEVER re-run the vuln leg"
    # The exact fail-closed control-liveness message from _judge (tool_drivers_livefire.py:2219-2220).
    assert any("the control run cannot be read as evidence" in f
               and "did not hold, so its silence proves nothing" in f
               for f in row.failures), row.failures
    # The kept leg is the REAL last probe, unchanged — not a fabricated pass.
    assert row.clean.raw == reset
    assert row.clean.signal is False


def test_a_control_that_fails_liveness_for_a_NON_reset_reason_is_not_retried(monkeypatch):
    # A control leg that is simply empty (no `failed:true`, and NOT a reset) is a real liveness failure,
    # not a transient fault. It must FAIL closed WITHOUT any retry — the self-heal is scoped to resets.
    calls = _install_fake_run_leg(monkeypatch, clean_raws=[""])
    row = harness.run_row(_control_reset_proof(), object(), None, seq=0)

    assert row.verdict == "FAIL"
    assert calls["clean"] == 1, "a non-reset liveness failure must not be retried"
    assert calls["vuln"] == 1
