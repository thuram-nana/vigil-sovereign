"""
authority.counsel_review — no client legal instrument ships until counsel has
reviewed it AND every placeholder in it is resolved (W14-2 #504).

An engagement puts three client-facing LEGAL instruments in front of a customer:

  * the **authorization letter** — the contract leg a customer signs
    (``framework/templates/authorization-letter.md``);
  * the mutual **NDA** — confidentiality before any target detail is exchanged
    (``framework/templates/legal/nda.md``); and
  * the **DPA** — the data-processing terms for any personal data the engagement
    touches (``framework/templates/legal/dpa.md``).

Two things about these instruments are HUMAN actions and cannot be performed by
the framework:

  1. **counsel review** — a qualified lawyer reading the instrument and signing
     off that its terms are sound for the jurisdiction; and
  2. **resolving the governing-law (and every other) placeholder** — deciding
     the actual governing law, venue, parties, dates, and terms.

This module does NOT do either. It implements the *enforcement* that makes an
unreviewed or placeholder-bearing instrument **unshippable**, so the human steps
cannot be silently skipped:

  * a machine **placeholder scanner** (:func:`find_placeholders`) that flags the
    unresolved-fill-in tokens a shipped instrument must never contain
    (``[GOVERNING LAW]``, ``<PLACEHOLDER>``, ``TBD``, angle/bracket template
    fill-ins, ``YYYY-MM-DD`` and signature blanks); and

  * a **review-status manifest** (:func:`load_review_manifest`) recording, per
    instrument, whether counsel has reviewed it — defaulting to ``False`` /
    ``PENDING`` and failing closed on anything missing or malformed; and

  * a fail-closed **ship gate** (:func:`assert_shippable` / :func:`ship_instruments`)
    that refuses to assemble an instrument into a deliverable unless BOTH the
    counsel-review flag is recorded true AND the placeholder scan is empty. The
    two checks are conjunctive on purpose: a mistakenly-flipped review flag still
    cannot ship placeholder text, and clean text still cannot ship without a
    recorded review.

This is a facade over an assurance fact, in the same spirit as
:mod:`authority.crosscheck`: it makes no legal judgement of its own and grants no
approval. It only refuses to ship until the human record says the human work is
done. As of W14-2 all three instruments are recorded **PENDING** — the honest
current state — so the gate refuses to ship every one of them.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from ..common.errors import InstrumentNotShippable

# ``engine/crucible`` — the CRUCIBLE tree root, the base every manifest path is
# resolved against. This module lives at framework/v2/authority/, so parents[3]
# is engine/crucible.
_CRUCIBLE_ROOT = Path(__file__).resolve().parents[3]

# The committed review-status manifest for the three client legal instruments.
DEFAULT_MANIFEST = _CRUCIBLE_ROOT / "framework" / "templates" / "legal" / "counsel-review-status.json"


# ---------------------------------------------------------------------------
# Placeholder scanner — the tokens a SHIPPED instrument must never contain.
# ---------------------------------------------------------------------------
#
# A template legitimately contains placeholders (that is what a template IS); a
# SHIPPED (filled-in) instrument must contain NONE. Each pattern names a family
# of unresolved fill-in. The patterns are deliberately conservative: they match
# the template fill-in styles used across this framework's instruments without
# flagging ordinary legal prose, markdown links (``[lower case](url)``), acronyms
# in brackets (``[GDPR]``), HTML comments (``<!-- … -->``), or autolinked URLs.
_PLACEHOLDER_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    # 1. Bare fill-in words that mean "not yet decided".
    ("literal", re.compile(r"\b(?:TBD|TODO|FIXME|XXX|PLACEHOLDER)\b")),
    # 2. Bracketed ALL-CAPS multi-word placeholders: ``[GOVERNING LAW]``,
    #    ``[CUSTOMER LEGAL NAME]``. Requires at least one internal separator so a
    #    bare acronym like ``[GDPR]`` or a footnote ``[1]`` is NOT matched.
    ("bracket", re.compile(r"\[[A-Z][A-Z0-9]*(?:[ _/\-][A-Z0-9]+)+\]")),
    # 3. Angle-bracket template fill-ins: ``<PLACEHOLDER>``, ``<customer legal
    #    name>``, ``<target-name>``, ``<A0 | A1 | A2 | A3>``, ``<not_before>``.
    #    Excludes HTML comments/close-tags (first char must be a letter), URLs
    #    (no ``://``), and email autolinks (no ``@``).
    ("angle", re.compile(r"<(?!https?://)[A-Za-z][^<>@]{0,80}>")),
    # 4. Unfilled date and signature blanks.
    ("blank", re.compile(r"\bYYYY-MM-DD\b")),
    ("blank", re.compile(r"_{4,}")),
)


@dataclass(frozen=True)
class Placeholder:
    """One unresolved placeholder occurrence found in an instrument's text.

    ``kind`` is the pattern family (``literal`` / ``bracket`` / ``angle`` /
    ``blank``); ``token`` is the exact matched text, so a report can point at
    precisely what a human still has to resolve."""

    kind: str
    token: str


def find_placeholders(text: str) -> list[Placeholder]:
    """Return the distinct unresolved placeholder tokens in ``text``, sorted for
    determinism. Empty iff the text carries no unresolved fill-in — the property
    a shipped instrument must satisfy. Pure and stdlib-only."""
    seen: set[tuple[str, str]] = set()
    for kind, pat in _PLACEHOLDER_PATTERNS:
        for m in pat.finditer(text):
            seen.add((kind, m.group(0)))
    return [Placeholder(kind=k, token=t) for k, t in sorted(seen)]


# ---------------------------------------------------------------------------
# The review-status manifest — the recorded HUMAN counsel-review decision.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class InstrumentRecord:
    """One row of the counsel-review manifest.

    ``reviewed_by_counsel`` is the recorded human decision; it DEFAULTS to
    ``False`` (PENDING) and any missing/malformed value fails closed to
    ``False``. ``governing_law_resolved`` records whether the governing-law (and
    the rest of the) placeholders have been resolved — also defaulting to
    ``False``. ``path`` is resolved against the manifest's base directory."""

    id: str
    title: str
    path: Path
    reviewed_by_counsel: bool
    governing_law_resolved: bool
    reviewer: str = ""
    review_date: str = ""
    notes: str = ""


class ManifestError(InstrumentNotShippable):
    """The review-status manifest itself is missing, unparseable, or does not
    describe a required instrument. Fail closed: with no trustworthy record of
    the human review, nothing ships."""


def _coerce_bool(value: object) -> bool:
    """Fail-closed truthiness: only a real JSON ``true`` counts as reviewed.
    Any other value — missing, null, a string, a number — is ``False``."""
    return value is True


def load_review_manifest(manifest_path: Path | str | None = None) -> list[InstrumentRecord]:
    """Load the review-status manifest into :class:`InstrumentRecord`s. Fails
    closed (:class:`ManifestError`) if the file is missing or unparseable, or if
    an entry lacks an ``id``, ``title`` or ``path``. Unknown review state
    defaults to un-reviewed (PENDING)."""
    path = Path(manifest_path) if manifest_path is not None else DEFAULT_MANIFEST
    if not path.is_file():
        raise ManifestError(f"counsel-review manifest missing: {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:  # pragma: no cover - defensive
        raise ManifestError(f"counsel-review manifest unparseable: {path}: {exc}") from exc

    entries = data.get("instruments") if isinstance(data, dict) else None
    if not isinstance(entries, list) or not entries:
        raise ManifestError(f"counsel-review manifest has no 'instruments' list: {path}")

    base = path.parent
    records: list[InstrumentRecord] = []
    for raw in entries:
        if not isinstance(raw, dict):
            raise ManifestError(f"counsel-review manifest entry is not an object: {raw!r}")
        iid = raw.get("id")
        title = raw.get("title")
        rel = raw.get("path")
        if not (isinstance(iid, str) and iid and isinstance(title, str) and title
                and isinstance(rel, str) and rel):
            raise ManifestError(f"counsel-review manifest entry missing id/title/path: {raw!r}")
        records.append(
            InstrumentRecord(
                id=iid,
                title=title,
                path=(base / rel).resolve(),
                reviewed_by_counsel=_coerce_bool(raw.get("reviewed_by_counsel")),
                governing_law_resolved=_coerce_bool(raw.get("governing_law_resolved")),
                reviewer=str(raw.get("reviewer") or ""),
                review_date=str(raw.get("review_date") or ""),
                notes=str(raw.get("notes") or ""),
            )
        )
    return records


# ---------------------------------------------------------------------------
# The ship gate — refuse to assemble an unreviewed or placeholder-bearing instrument.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ShipCheck:
    """The result of checking one instrument against the ship gate. ``shippable``
    is True iff counsel has recorded a review AND no placeholder remains.
    ``reasons`` names every failing condition (both are reported, not just the
    first) so a human sees the whole outstanding worklist."""

    instrument_id: str
    shippable: bool
    reasons: list[str] = field(default_factory=list)
    placeholders: list[Placeholder] = field(default_factory=list)


def check_instrument(record: InstrumentRecord, content: str) -> ShipCheck:
    """Evaluate the ship gate for one instrument, without raising. An instrument
    ships iff BOTH: (a) ``reviewed_by_counsel`` is recorded true, AND (b) the
    placeholder scan of ``content`` is empty. Pure."""
    reasons: list[str] = []
    if not record.reviewed_by_counsel:
        reasons.append("not counsel-reviewed (recorded PENDING; counsel review is a human action)")
    placeholders = find_placeholders(content)
    if placeholders:
        reasons.append(
            "unresolved placeholder(s): "
            + ", ".join(sorted({p.token for p in placeholders}))
            + " (resolving the governing law and every fill-in is a human action)"
        )
    return ShipCheck(
        instrument_id=record.id,
        shippable=not reasons,
        reasons=reasons,
        placeholders=placeholders,
    )


def assert_shippable(record: InstrumentRecord, content: str) -> ShipCheck:
    """Ship gate for one instrument: RAISE :class:`InstrumentNotShippable` unless
    counsel has recorded a review AND no placeholder remains. The typed violation
    must never be silently caught — it is the framework refusing to put an
    unreviewed or placeholder-bearing legal instrument in front of a customer.
    Returns the (shippable) :class:`ShipCheck` otherwise."""
    check = check_instrument(record, content)
    if not check.shippable:
        raise InstrumentNotShippable(f"instrument {record.id!r} is not shippable: " + "; ".join(check.reasons))
    return check


def review_report(manifest_path: Path | str | None = None) -> list[ShipCheck]:
    """Evaluate the ship gate for every instrument in the manifest, WITHOUT
    raising, reading each instrument's bytes from disk. A missing instrument file
    is reported as unshippable (fail closed), never skipped. For dashboards and
    the reviewer package; :func:`ship_instruments` is the enforcing chokepoint."""
    checks: list[ShipCheck] = []
    for record in load_review_manifest(manifest_path):
        try:
            content = record.path.read_text(encoding="utf-8")
        except OSError:
            checks.append(
                ShipCheck(
                    instrument_id=record.id,
                    shippable=False,
                    reasons=[f"instrument file unreadable: {record.path}"],
                )
            )
            continue
        checks.append(check_instrument(record, content))
    return checks


def ship_instruments(manifest_path: Path | str | None = None) -> list[str]:
    """The assemble/ship chokepoint. Read every instrument named in the manifest
    and RAISE :class:`InstrumentNotShippable` on the FIRST one that is not
    shippable (fail closed, first-failure-wins). Returns the ids of the shipped
    instruments only when EVERY one passes — so an assembler that routes its
    legal instruments through this function cannot emit a deliverable while any
    instrument is unreviewed or placeholder-bearing.

    A missing instrument file is itself a refusal (a file the manifest promises
    but cannot be read must never silently ship as empty)."""
    records = load_review_manifest(manifest_path)
    shipped: list[str] = []
    for record in records:
        try:
            content = record.path.read_text(encoding="utf-8")
        except OSError as exc:
            raise InstrumentNotShippable(
                f"instrument {record.id!r} file unreadable ({record.path}): {exc}"
            ) from exc
        assert_shippable(record, content)
        shipped.append(record.id)
    return shipped
