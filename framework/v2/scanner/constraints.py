"""
scanner.constraints — infer a filter's predicate from black-box membership queries.

Burp and Nuclei carry fixed payload lists. A skilled human does something better:
probes a WAF/filter to learn *what it actually blocks*, then crafts an input that
provably crosses it. This module mechanizes that. The target is treated as a
black-box oracle for a boolean predicate — "does this input reach the sink /
satisfy the condition?" — which is exactly what the Wave-5 boolean oracle already
provides. Active learning over a small feature basis then recovers the filter's
predicate and synthesizes a satisfying input the oracle confirms.

The algorithm is ablation-based membership-query learning (a CEGIS special case):
find one input that IS a member, then toggle each feature one at a time — if
removing a present feature breaks membership it is REQUIRED; if adding an absent
feature breaks membership it is FORBIDDEN. The inferred constraint is the
conjunction, and a satisfying input is synthesized and re-queried to confirm.

Honest limits: features are toggled independently, so a filter with entangled
conditions (blocks ``'`` only when also preceded by a digit) is approximated, not
solved exactly. When nothing reaches the sink the module reports "no constraint
inferred" rather than inventing one. Pure w.r.t. state: the only side effect is
calling the injected ``membership_fn``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable

MembershipFn = Callable[[str], bool]


@dataclass(frozen=True)
class Feature:
    """One toggleable, substring-defined feature of an input (a character class,
    a SQL/HTML keyword). ``present`` tests it; ``add``/``remove`` toggle it."""

    name: str
    token: str

    def present(self, s: str) -> bool:
        return self.token.lower() in s.lower()

    def add(self, s: str) -> str:
        return s if self.present(s) else (s + self.token)

    def remove(self, s: str) -> str:
        return re.sub(re.escape(self.token), "", s, flags=re.IGNORECASE)


# A basis covering the common SQLi/XSS filter surface. Extend freely; the learner
# is basis-agnostic.
DEFAULT_FEATURES: tuple[Feature, ...] = (
    Feature("single_quote", "'"),
    Feature("double_quote", '"'),
    Feature("angle_open", "<"),
    Feature("angle_close", ">"),
    Feature("paren_open", "("),
    Feature("space", " "),
    Feature("kw_select", "SELECT"),
    Feature("kw_union", "UNION"),
    Feature("kw_or", " OR "),
    Feature("kw_sleep", "SLEEP"),
    Feature("kw_script", "<script"),
    Feature("kw_onerror", "onerror"),
    Feature("equals", "="),
    Feature("comment_dashdash", "--"),
)

# Seed inputs to search for an initial member. Each toggles a different corner of
# the feature space so at least one is likely to reach the sink.
_SEEDS: tuple[str, ...] = (
    "x' OR '1'='1",
    "1' OR 1=1--",
    "' UNION SELECT 1",
    "<script>x</script>",
    "\"'><x>",
    "1",
    "x",
    "' SLEEP(1)",
)


@dataclass
class InferredConstraint:
    """The learned filter predicate: features that must be present / absent for an
    input to reach the sink."""

    required: list[str] = field(default_factory=list)
    forbidden: list[str] = field(default_factory=list)

    def describe(self) -> str:
        parts: list[str] = []
        if self.required:
            parts.append("has " + " & ".join(self.required))
        if self.forbidden:
            parts.append("lacks " + " & ".join(self.forbidden))
        return "reaches sink iff " + (" and ".join(parts) if parts else "(no filter detected)")


@dataclass
class InferenceResult:
    """The outcome of one inference: the constraint, a synthesized satisfying
    input, and whether the membership oracle CONFIRMED that input."""

    constraint: InferredConstraint | None
    synthesized: str | None
    confirmed: bool
    queries: int
    note: str = ""


def _synthesize(features: tuple[Feature, ...], constraint: InferredConstraint, member: str) -> str:
    """Build an input that satisfies the constraint, starting from a known member:
    ensure every required feature is present and every forbidden one removed."""
    by_name = {f.name: f for f in features}
    out = member
    for name in constraint.forbidden:
        if name in by_name:
            out = by_name[name].remove(out)
    for name in constraint.required:
        if name in by_name:
            out = by_name[name].add(out)
    return out


def infer_predicate(
    membership_fn: MembershipFn,
    *,
    features: tuple[Feature, ...] = DEFAULT_FEATURES,
    seeds: tuple[str, ...] = _SEEDS,
    max_queries: int = 200,
) -> InferenceResult:
    """Infer the filter predicate behind ``membership_fn`` and synthesize a
    satisfying input. Returns an :class:`InferenceResult`; when no seed reaches
    the sink it reports failure honestly rather than inventing a constraint."""
    queries = 0

    def ask(s: str) -> bool:
        nonlocal queries
        queries += 1
        return bool(membership_fn(s))

    member: str | None = None
    for seed in seeds:
        if queries >= max_queries:
            break
        if ask(seed):
            member = seed
            break
    if member is None:
        return InferenceResult(None, None, False, queries,
                               note="no seed reached the sink — no constraint inferred")

    required: list[str] = []
    forbidden: list[str] = []
    for f in features:
        if queries >= max_queries:
            break
        if f.present(member):
            # necessity: does removing it break membership?
            if not ask(f.remove(member)):
                required.append(f.name)
        else:
            # prohibition: does adding it break membership?
            if not ask(f.add(member)):
                forbidden.append(f.name)

    constraint = InferredConstraint(required=required, forbidden=forbidden)
    synthesized = _synthesize(features, constraint, member)
    confirmed = ask(synthesized) if queries < max_queries else False
    return InferenceResult(
        constraint=constraint, synthesized=synthesized, confirmed=confirmed, queries=queries,
        note=constraint.describe(),
    )
