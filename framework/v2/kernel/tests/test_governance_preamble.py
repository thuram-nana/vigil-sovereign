"""
Nervous-System N5 — the governance preamble in the runtime system prompt.

The metacognition / multi-critic / cognitive-refusal / self-consistency / learning doctrine is
injected — quoted verbatim — into EVERY reasoning call's system prompt, above the per-call
cognitive doc. It is bounded and cache-stable (identical across calls), and it degrades
gracefully to nothing if the doc is missing.
"""

from __future__ import annotations

from framework.v2.common import docs
from framework.v2.kernel.binding import _governance_preamble, build_system_prompt

_DIRECTIVES = [
    "Prove, don't guess", "Reflect in the loop", "Submit to the critics",
    "Refuse honestly", "Vote against yourself", "Learn, don't fabricate",
]


def test_governance_is_in_force_on_every_call() -> None:
    doc = docs.cognitive("reasoning-loops")
    p = build_system_prompt(doc, [], "do the task")
    assert "Governance (in force on every call)" in p
    for k in _DIRECTIVES:
        assert k in p, f"missing governance directive: {k}"
    # governance sits ABOVE the per-call doc and the task
    assert p.index("Governance (in force") < p.index("--- Source:") < p.index("--- Task ---")


def test_governance_prefix_is_cache_stable() -> None:
    doc = docs.cognitive("reasoning-loops")
    a = build_system_prompt(doc, [], "task A")
    b = build_system_prompt(doc, [], "task B")
    # the whole prefix up to the per-call source is identical regardless of task → cache-friendly
    assert a.split("--- Source:")[0] == b.split("--- Source:")[0]


def test_governance_is_bounded() -> None:
    assert 0 < len(_governance_preamble()) < 5500     # small, bounded token cost


def test_oracle_authority_and_refusal_doctrine_present() -> None:
    g = " ".join(_governance_preamble().split())            # normalise markdown line-wrapping
    assert "You ADVISE; the oracle CONFIRMS" in g           # oracle authority
    assert "Refuse to conclude what you cannot ground" in g  # cognitive refusal
    assert "never by skipping an authorized attack surface" in g  # coverage doctrine
