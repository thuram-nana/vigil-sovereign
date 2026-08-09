"""verdict — the single admission point where evidence becomes a verdict.

Before this module the mapping was distributed: each check decided what to put in its predicate, and the
runner separately decided whether a non-firing meant CLEAN or INCONCLUSIVE. Distributed rules drift — the
registry in ``docs/capability-matrix/evidence-branches.json`` described capabilities that nothing consulted,
so it documented intent rather than governing behaviour.

Here the registry is load-bearing. Every verdict passes through :func:`admit`, which:

  * refuses to score a branch that is not registered (an unregistered branch cannot produce a verdict, so a
    new evidence path cannot silently inherit FACT/CLEAN authority);
  * refuses to mint a FACT from a branch declared ``fact_capable: false`` even if its oracle fired;
  * refuses to report CLEAN from a branch declared ``clean_capable: false``, or one whose declared
    preconditions did not hold for THIS observation — those are INCONCLUSIVE.

Preconditions are evaluated PER BRANCH against the specific capture, not globally. "The body was readable"
is meaningless for a header-derived branch and decisive for a markup one, so a single capture can legitimately
yield a header-derived CLEAN and a body-derived INCONCLUSIVE at the same time. Treating availability as one
flag over the whole response conflated those.

Pure stdlib; no framework imports (FATAL-2 safe).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from functools import lru_cache
from pathlib import Path


class Verdict(str, Enum):
    """The CLOSED set of verdicts. Anything outside it cannot reach output by construction, so "only these
    four appear" is a property of the type rather than a convention reviewers must police."""

    FACT = "FACT"
    LEAD = "LEAD"
    CLEAN = "CLEAN"
    INCONCLUSIVE = "INCONCLUSIVE"


# Back-compat aliases for call sites that compare against the module constants.
FACT, LEAD, CLEAN, INCONCLUSIVE = Verdict.FACT, Verdict.LEAD, Verdict.CLEAN, Verdict.INCONCLUSIVE

# Only :func:`admit` may construct an AdmittedVerdict. Making the token module-private is what turns "every
# verdict passes through admission" from a convention into something a caller has to deliberately defeat.
_ADMISSION_TOKEN = object()


class DirectVerdictConstruction(RuntimeError):
    """An AdmittedVerdict was built outside admission. Certificate minting and report rendering accept only
    admitted verdicts, so bypassing admission must fail loudly rather than silently produce output."""


# The declared surface an evidence branch reads. Typed, because deciding "is this body-derived?" from the
# branch NAME is fragile — a future `dom_redirect` or `html_meta_refresh` would escape a substring rule.
_EVIDENCE_SURFACES = frozenset({
    "response_headers", "response_body", "transport", "tls_handshake", "service_response",
    "artifact", "composite",
})

_REGISTRY = Path(__file__).resolve().parents[3] / "docs" / "capability-matrix" / "evidence-branches.json"


class UnregisteredBranch(KeyError):
    """A verdict was requested for an evidence branch with no capability declaration.

    Deliberately fatal rather than permissive: silently defaulting an unknown branch to "allowed" is how a
    new evidence path acquires FACT authority nobody reviewed."""


@dataclass(frozen=True)
class AdmittedVerdict:
    """A verdict that has passed admission. Constructible only by :func:`admit`."""

    verdict: Verdict
    branch: str
    reason: str = ""
    _token: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._token is not _ADMISSION_TOKEN:
            raise DirectVerdictConstruction(
                "AdmittedVerdict may only be produced by verdict.admit() — a FACT or CLEAN built directly "
                "would carry authority nothing reviewed")

    @property
    def is_fact(self) -> bool:
        return self.verdict is Verdict.FACT


@lru_cache(maxsize=1)
def _branches(path: str = "") -> dict:
    raw = json.loads(Path(path or _REGISTRY).read_text(encoding="utf-8"))
    return {b["id"]: b for b in raw["branches"]}


def branch_ids() -> "frozenset[str]":
    return frozenset(_branches())


def preconditions_hold(branch_id: str, observed: "dict") -> "tuple[bool, str]":
    """Evaluate THIS branch's declared preconditions against THIS observation.

    ``observed`` carries the facts a capture knows about itself — ``channel_established``,
    ``body_semantically_available``, ``not_followed_redirect``, ``gate_authorized``, ``manifest_parsed``.
    A precondition that is declared but absent from ``observed`` counts as NOT held: an unknown is not a yes.
    """
    branch = _branches().get(branch_id)
    if branch is None:
        raise UnregisteredBranch(branch_id)
    for name in branch.get("preconditions", []):
        if not bool(observed.get(name, False)):
            return False, f"precondition {name!r} did not hold"
    return True, ""


def admit(branch_id: str, *, fired: bool, conclusive: bool, observed: "dict") -> AdmittedVerdict:
    """Map one branch's oracle outcome to a verdict, under that branch's declared capabilities.

    ``fired``/``conclusive`` come from the deterministic oracle. Everything else is policy the registry owns,
    so a capability change is a reviewed edit to a declaration rather than a scattered code change."""
    branch = _branches().get(branch_id)
    if branch is None:
        raise UnregisteredBranch(
            f"{branch_id!r} is not declared in evidence-branches.json — an unregistered evidence branch "
            f"may not produce a verdict")

    held, why = preconditions_hold(branch_id, observed)
    if not held:
        # The observation never satisfied what this branch needs, so neither a positive nor a negative
        # conclusion is supported over it.
        return AdmittedVerdict(Verdict.INCONCLUSIVE, branch_id, why, _ADMISSION_TOKEN)

    if fired:
        if branch["fact_capable"]:
            return AdmittedVerdict(Verdict.FACT, branch_id,
                                   "oracle fired over a branch declared FACT-capable", _ADMISSION_TOKEN)
        return AdmittedVerdict(Verdict.LEAD, branch_id,
                               f"oracle fired but this branch is not FACT-capable: {branch['limitation']}",
                               _ADMISSION_TOKEN)

    if not conclusive:
        return AdmittedVerdict(Verdict.INCONCLUSIVE, branch_id, "oracle was not conclusive",
                               _ADMISSION_TOKEN)
    if branch["clean_capable"]:
        return AdmittedVerdict(Verdict.CLEAN, branch_id,
                               "conclusive non-firing over a branch declared CLEAN-capable", _ADMISSION_TOKEN)
    return AdmittedVerdict(Verdict.INCONCLUSIVE, branch_id,
                           f"non-firing, but this branch may not assert absence: {branch['limitation']}",
                           _ADMISSION_TOKEN)


def evidence_surface(branch_id: str) -> str:
    """The declared surface this branch reads (see ``_EVIDENCE_SURFACES``)."""
    branch = _branches().get(branch_id)
    if branch is None:
        raise UnregisteredBranch(branch_id)
    return branch.get("evidence_surface", "")


def known_surfaces() -> "frozenset[str]":
    return _EVIDENCE_SURFACES


# Family-level composition. Per-branch admission is only half the guarantee: the moment several branch
# verdicts are summarised for a human or a report, the summary can assert something no branch did.
# `location_header=CLEAN` next to `body_markup=FACT` must never be presented as "open redirect: CLEAN".
_COMPOSITION_ORDER = (Verdict.FACT, Verdict.LEAD, Verdict.INCONCLUSIVE, Verdict.CLEAN)


def compose(verdicts: "list[Verdict] | list[str]") -> Verdict:
    """The conservative family verdict over several branch outcomes.

        any FACT          -> FACT
        else any LEAD     -> LEAD
        else any INCONCLUSIVE -> INCONCLUSIVE
        else all CLEAN    -> CLEAN

    CLEAN is reachable ONLY when every relevant branch was itself CLEAN, so a family is called clean only if
    nothing was left unexamined. An EMPTY set composes to INCONCLUSIVE, not CLEAN: nothing examined is not
    the same as nothing found, and defaulting the empty case to clean is precisely how a family that was
    never probed would be reported as safe."""
    seen = {Verdict(v) if not isinstance(v, Verdict) else v for v in verdicts}
    if not seen:
        return Verdict.INCONCLUSIVE
    for candidate in _COMPOSITION_ORDER:
        if candidate in seen:
            return candidate
    return Verdict.INCONCLUSIVE     # pragma: no cover - the enum is closed, so this is unreachable
