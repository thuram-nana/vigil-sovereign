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

**The enforcement envelope, too, is cross-checked.** Scope (WHICH hosts) is only
half the authorization; the other half is the ENVELOPE (how dangerous, how long,
how fast, how many at once). The authorization letter declares that envelope in a
machine-checked ``<!-- ENVELOPE:BEGIN -->`` block, and
:func:`crosscheck_envelope` / :func:`assert_envelope_consistent` compare the
letter's declared danger ceiling, validity window, rate limit and concurrency
limit against the signed :class:`EngagementAuthorization` — raising
:class:`~common.errors.EnvelopeDrift` on any mismatch (and treating a missing or
unparseable declaration as drift, fail closed). Without this a customer could
sign one envelope while the executor honours a looser one, with nothing to catch
it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from ..common.errors import EnvelopeDrift, ScopeDrift

if TYPE_CHECKING:
    from .authorization import EngagementAuthorization

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


# ---------------------------------------------------------------------------
# The enforcement envelope — letter's declared bounds vs the signed object
# ---------------------------------------------------------------------------

# The machine-checked declaration in the authorization letter. HTML-comment
# delimited so it is invisible in the rendered document but unambiguous to parse.
_ENVELOPE_BLOCK = re.compile(
    r"<!--\s*ENVELOPE:BEGIN\s*-->(?P<body>.*?)<!--\s*ENVELOPE:END\s*-->",
    re.DOTALL,
)
# The envelope fields the letter declares and the signed object carries. Both the
# letter block and the EngagementAuthorization are compared field-by-field.
_ENVELOPE_FIELDS = (
    "danger_ceiling",
    "not_before",
    "not_after",
    "rate_limit",
    "rate_window_seconds",
    "concurrency_limit",
)


def parse_envelope_declaration(text: str) -> dict[str, str] | None:
    """Extract the ``<!-- ENVELOPE:BEGIN -->…<!-- ENVELOPE:END -->`` block from a
    filled authorization letter and return its ``key: value`` lines as a dict of
    raw strings, or ``None`` if the block is absent. Values are returned verbatim
    (not coerced) — :func:`crosscheck_envelope` does the typed comparison, so a
    placeholder or malformed value surfaces there as drift rather than being
    silently dropped here."""
    m = _ENVELOPE_BLOCK.search(text)
    if not m:
        return None
    out: dict[str, str] = {}
    for raw in m.group("body").splitlines():
        line = raw.strip()
        if not line or ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        if key:
            out[key] = value.strip()
    return out


@dataclass(frozen=True)
class EnvelopeCrossCheck:
    """The result of comparing the letter's declared enforcement envelope against
    the signed EngagementAuthorization. ``agree`` is True iff every envelope field
    matches. ``mismatches`` maps each diverging field to ``(letter, signed)`` so a
    drift names exactly which bound the customer signed differently."""

    agree: bool
    reason: str = ""
    mismatches: dict[str, tuple[str, str]] = field(default_factory=dict)


def _as_utc(dt: datetime) -> datetime:
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def _parse_dt(value: str) -> datetime | None:
    """Parse an ISO-8601 timestamp (tolerating a trailing ``Z``) to aware UTC, or
    None if it is not a valid timestamp (e.g. a template placeholder)."""
    try:
        dt = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None
    return _as_utc(dt)


def _signed_envelope(authorization: "EngagementAuthorization") -> dict[str, str]:
    """The signed object's envelope rendered as the canonical comparison strings
    the letter is checked against."""
    return {
        "danger_ceiling": str(authorization.danger_ceiling).strip().upper(),
        "not_before": _as_utc(authorization.not_before).isoformat(),
        "not_after": _as_utc(authorization.not_after).isoformat(),
        "rate_limit": str(int(authorization.rate_limit)),
        "rate_window_seconds": repr(float(authorization.rate_window_seconds)),
        "concurrency_limit": str(int(authorization.concurrency_limit)),
    }


def _letter_field_repr(name: str, raw: str) -> str | None:
    """Coerce a raw letter value to the SAME canonical comparison string
    ``_signed_envelope`` uses, or None if it does not parse (a placeholder /
    malformed value — which is drift, never a silent match)."""
    raw = raw.strip()
    if name == "danger_ceiling":
        up = raw.upper()
        return up if re.fullmatch(r"A[0-3]", up) else None
    if name in ("not_before", "not_after"):
        dt = _parse_dt(raw)
        return dt.isoformat() if dt is not None else None
    if name in ("rate_limit", "concurrency_limit"):
        try:
            return str(int(raw))
        except (ValueError, TypeError):
            return None
    if name == "rate_window_seconds":
        try:
            return repr(float(raw))
        except (ValueError, TypeError):
            return None
    return None


def crosscheck_envelope(
    *,
    letter: dict[str, str] | None,
    authorization: "EngagementAuthorization",
) -> EnvelopeCrossCheck:
    """Compare the letter's declared enforcement envelope (from
    :func:`parse_envelope_declaration`) against the signed EngagementAuthorization.
    Every field (danger ceiling, both window endpoints, rate limit + window,
    concurrency limit) must match. Fail closed: a missing block, a missing field,
    or an unparseable value is drift — the letter cannot vacuously agree with any
    signed object."""
    if letter is None:
        return EnvelopeCrossCheck(
            agree=False,
            reason="authorization letter carries no machine-checked ENVELOPE block "
            "(fail closed — a letter that omits the envelope cannot be reconciled "
            "with the signed authorization the executor honours)",
        )
    signed = _signed_envelope(authorization)
    mismatches: dict[str, tuple[str, str]] = {}
    for name in _ENVELOPE_FIELDS:
        signed_repr = signed[name]
        if name not in letter:
            mismatches[name] = ("<absent>", signed_repr)
            continue
        letter_repr = _letter_field_repr(name, letter[name])
        if letter_repr is None:
            mismatches[name] = (f"<unparseable:{letter[name]!r}>", signed_repr)
        elif letter_repr != signed_repr:
            mismatches[name] = (letter_repr, signed_repr)
    if not mismatches:
        return EnvelopeCrossCheck(
            agree=True,
            reason="letter envelope matches the signed authorization on all "
            f"{len(_ENVELOPE_FIELDS)} fields",
        )
    return EnvelopeCrossCheck(
        agree=False,
        reason=(
            "envelope drift: "
            + "; ".join(
                f"{name} letter={lv} signed={sv}" for name, (lv, sv) in mismatches.items()
            )
        ),
        mismatches=mismatches,
    )


def assert_envelope_consistent(
    *,
    letter: dict[str, str] | None,
    authorization: "EngagementAuthorization",
) -> EnvelopeCrossCheck:
    """Cross-check the letter's declared envelope against the signed object and
    RAISE :class:`EnvelopeDrift` on any mismatch (or a missing/unparseable
    declaration). The typed violation must not be silently caught — it is the
    framework refusing to honour an envelope the customer did not sign. Returns
    the (agreeing) result otherwise."""
    result = crosscheck_envelope(letter=letter, authorization=authorization)
    if not result.agree:
        raise EnvelopeDrift(result.reason)
    return result
