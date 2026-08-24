"""
authority.crosscheck — the three legs of an engagement's authorization must agree.

An engagement is authorized by three artifacts that MUST describe the same
in-scope host set:

  1. the **authorization letter** (contract leg) — the document a customer
     signs, from ``framework/templates/authorization-letter.md``;
  2. the **charter.md** scope table (runtime leg) — what the engine reads at
     gate time via :func:`common.ethics.parse_scope`; and
  3. the signed **EngagementAuthorization** (technical leg) — the
     machine-verifiable object the executor honours
     (:mod:`authority.authorization`).

If they disagree the engagement's scope has *drifted* between what the
customer signed, what the runtime enforces, and what the technical object
carries. This module extracts the scope from each leg and refuses (fail
closed, :class:`~common.errors.ScopeDrift`) on any divergence.

By design the authorization letter and the charter use the SAME
``## 2. In-scope systems`` table format, parsed by the SAME row logic, so the
two documents cannot express scope in ways that only *look* equivalent. The
signed object carries the scope as an explicit list.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..common.errors import ScopeDrift

# The scope-table header the charter template uses (``## 2. In-scope systems``)
# and the authorization letter mirrors verbatim. Same header, same parser, so a
# format drift between the two documents is impossible.
_SCOPE_HEADER = re.compile(r"^##\s*2\.\s*In[- ]scope systems\b", re.MULTILINE | re.IGNORECASE)
_NEXT_H2 = re.compile(r"^##\s+\d", re.MULTILINE)


def _normalize(host: str) -> str:
    """Canonical comparison form: lowercase, trimmed, backticks and a trailing
    dot removed. Mirrors :func:`common.ethics.host_matches_scope`'s per-entry
    normalization so the same string compares equal here and at the gate."""
    return host.lower().strip().strip("`").rstrip(".")


def parse_scope_table(text: str) -> list[str]:
    """Extract the host column of the ``## 2. In-scope systems`` markdown table
    from ``text``. Same row logic as :func:`common.ethics.parse_scope`, applied
    to arbitrary text (the authorization letter, which is not on the charter
    path). Returns the literal host strings, in order, or ``[]`` if the table
    is absent."""
    m = _SCOPE_HEADER.search(text)
    if not m:
        return []
    after = text[m.end():]
    nxt = _NEXT_H2.search(after)
    block = after if nxt is None else after[: nxt.start()]

    hosts: list[str] = []
    for raw in block.splitlines():
        line = raw.strip()
        if not line.startswith("|"):
            continue
        cols = [c.strip() for c in line.strip("|").split("|")]
        if not cols:
            continue
        first = cols[0].strip("`").strip()
        if not first:
            continue
        if set(first) <= {"-", " ", ":"}:  # separator row
            continue
        if first.lower().startswith("host"):  # header row
            continue
        first = re.sub(r"\s*\(.*?\)\s*$", "", first).strip()  # drop "(if any)"
        if first:
            hosts.append(first)
    return hosts


@dataclass(frozen=True)
class ScopeCrossCheck:
    """The result of comparing the three legs' scope. ``agree`` is True iff all
    three normalized host sets are identical. The ``*_only`` sets name exactly
    which host diverges where, so a drift is actionable rather than opaque."""

    agree: bool
    letter: frozenset[str]
    charter: frozenset[str]
    authorization: frozenset[str]
    reason: str = ""
    divergences: dict[str, list[str]] = field(default_factory=dict)


def crosscheck_scope(
    *,
    letter: list[str],
    charter: list[str],
    authorization: list[str],
) -> ScopeCrossCheck:
    """Compare the three legs' scope host lists (normalized to sets). All three
    must be identical; any host present in one leg but missing from another is a
    drift. Pure — the caller supplies each leg's already-extracted host list."""
    ls = frozenset(_normalize(h) for h in letter if _normalize(h))
    cs = frozenset(_normalize(h) for h in charter if _normalize(h))
    az = frozenset(_normalize(h) for h in authorization if _normalize(h))

    # Fail closed on an empty leg — an authorization that scopes nothing, or a
    # document whose table failed to parse, must not silently "agree" with
    # another empty leg into a no-op authorization.
    empties = [name for name, s in (("letter", ls), ("charter", cs), ("authorization", az)) if not s]
    if empties:
        return ScopeCrossCheck(
            agree=False,
            letter=ls,
            charter=cs,
            authorization=az,
            reason=(
                "empty scope in leg(s): "
                + ", ".join(empties)
                + " (a leg with no in-scope host cannot be cross-checked; fail closed)"
            ),
            divergences={},
        )

    if ls == cs == az:
        return ScopeCrossCheck(
            agree=True,
            letter=ls,
            charter=cs,
            authorization=az,
            reason=f"all three legs agree on {len(ls)} in-scope host(s)",
        )

    everything = ls | cs | az
    divergences: dict[str, list[str]] = {}
    for host in sorted(everything):
        legs_with = [
            name
            for name, s in (("letter", ls), ("charter", cs), ("authorization", az))
            if host in s
        ]
        if len(legs_with) != 3:
            missing = [n for n in ("letter", "charter", "authorization") if n not in legs_with]
            divergences[host] = missing
    return ScopeCrossCheck(
        agree=False,
        letter=ls,
        charter=cs,
        authorization=az,
        reason=(
            "scope drift: "
            + "; ".join(f"{host!r} missing from {', '.join(missing)}" for host, missing in divergences.items())
        ),
        divergences=divergences,
    )


def assert_scope_consistent(
    *,
    letter: list[str],
    charter: list[str],
    authorization: list[str],
) -> ScopeCrossCheck:
    """Cross-check the three legs and RAISE :class:`ScopeDrift` if they disagree.
    The typed violation must not be silently caught — it is the framework
    refusing to act on an authorization whose contract, runtime, and technical
    scope have drifted apart. Returns the (agreeing) result otherwise."""
    result = crosscheck_scope(letter=letter, charter=charter, authorization=authorization)
    if not result.agree:
        raise ScopeDrift(result.reason)
    return result
