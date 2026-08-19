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
