"""Every typed argv builder must be reachable through the phase gate.

THE DEFECT THIS PINS. Three builders — nikto, wapiti, zaproxy — were written, registered in
`_BUILDERS`, mirrored into the tool-admission gate, and reported to the operator as "Controllable
(cli)". They were also completely unreachable: `DEFAULT_TOOL_VIEW`, the fail-closed phase manifest
whose own comment says "an unlisted tool is DENIED in a phase", never gained them. An adversarial
review ran the real executor and got 9 denials out of 9 attempts across every phase, and found the
agent's own tool menu never offered them either.

So the screen claimed control the engine did not have — the exact false claim the admission gate
exists to prevent, relocated one layer down where the gate could not see it. There was already a
drift guard keeping the admission mirror equal to `_BUILDERS`; what was missing was anything checking
that a builder can actually be REACHED. A tool can now be fully built, correctly mirrored, honestly
labelled, and still dead.

WHY THIS IS THE RIGHT SHAPE OF TEST. It derives both sides from the source rather than listing tools,
so a builder added tomorrow is covered without anyone remembering this file exists. That is the whole
point: the previous three were added by people who did remember the mirror and still missed the view.
"""

from __future__ import annotations

import pytest

wiring = pytest.importorskip("vigil_integration.live.wiring")
executor = pytest.importorskip("vigil_integration.live.executor")


def test_every_typed_builder_is_reachable_in_at_least_one_phase():
    """A builder absent from the phase manifest is denied everywhere — built, and dead."""
    unreachable = sorted(set(executor._BUILDERS) - set(wiring.DEFAULT_TOOL_VIEW))
    assert not unreachable, (
        "these tools have a typed argv builder but appear in NO phase, so the fail-closed phase gate "
        f"denies them in every phase: {unreachable}\n\n"
        "The operator's tools screen will report them controllable while the engine refuses every "
        "call. Add each to DEFAULT_TOOL_VIEW with the phases it belongs to — registering a tool there "
        "grants reachability only; the conjunctive gate still queues it for owner approval."
    )


def test_the_phase_manifest_does_not_promise_tools_that_cannot_be_built():
    """The reverse direction. A phase entry with no builder and no other executor path is a menu item
    that fails when chosen — the agent is offered a capability that does not exist.

    Entries that are executed by something other than a builder are legitimate and listed here, so
    that a NEW unbacked name still fails rather than being quietly absorbed."""
    NON_BUILDER_EXECUTED = {
        "curl",           # executed directly by the executor's own request path
        "terminal.run",   # the governed local terminal
        "sandbox.exec",   # the bubblewrap tier
    }
    promised = set(wiring.DEFAULT_TOOL_VIEW) - set(executor._BUILDERS) - NON_BUILDER_EXECUTED
    assert not promised, (
        f"the phase manifest offers tools nothing can build or execute: {sorted(promised)}. "
        "Either add a builder, or remove the entry — an agent offered a tool that cannot run wastes "
        "a turn discovering that."
    )


def test_the_reachability_check_is_actually_looking_at_something():
    """MUTATION CONTROL. Both assertions above pass trivially if either source reads empty — a rename
    of `_BUILDERS` or `DEFAULT_TOOL_VIEW` would turn this file into a no-op that still reports green,
    which is worse than not having written it. Pin that both sides are populated."""
    assert len(executor._BUILDERS) >= 6, f"builder set looks wrong: {sorted(executor._BUILDERS)}"
    assert len(wiring.DEFAULT_TOOL_VIEW) >= 6, "phase manifest looks wrong"
    # And that the two genuinely overlap, so the sets are about the same namespace.
    assert set(executor._BUILDERS) & set(wiring.DEFAULT_TOOL_VIEW), "no overlap — are these the same keys?"
