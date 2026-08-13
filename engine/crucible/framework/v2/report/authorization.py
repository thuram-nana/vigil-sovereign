"""
report.authorization — read the engagement charter that authorised the work.

A dossier without this section documents activity that a lawyer cannot distinguish from an
attack. The charter (``targets/<slug>/charter.md``) is the binding authorisation document: it
names who authorised the work, which systems they authorised, what was placed out of scope, and
carries the operator's attestation. This module locates it, reads it, and reports precisely what
it says — or reports, loudly, that no charter was found.

The rule that governs everything here is that **a missing charter must be stated, never
omitted**. An absent section reads as an oversight; a section that says "no authorisation record
was found for this engagement" is a finding in its own right, and the reader is entitled to it.

Nothing is inferred. The signed/unsigned determination reuses the platform's own authority
(:func:`common.ethics.is_charter_signed`), which fails closed on any ambiguity and treats an
unfilled placeholder name as unsigned. The in-scope host list reuses
:func:`common.ethics.parse_scope`, which reads only the charter's numbered scope table; when a
charter is written with different headings that parser returns nothing, and this module says so
rather than guessing at the scope from prose.

Read-only and total: a missing, unreadable or malformed charter yields an
:class:`Authorization` that describes the gap.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# Headings whose bodies carry the parts a reader needs, matched case-insensitively against a
# markdown heading line. Each maps to the label used in the rendered document.
_SECTION_ALIASES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("In-scope systems", ("in-scope systems", "in scope systems", "target hosts (in scope)",
                          "target hosts", "scope", "in-scope")),
    ("Explicitly out of scope", ("out of scope", "out-of-scope", "explicitly out of scope",
                                 "exclusions")),
    ("Operator attestation", ("operator attestation", "attestation", "authorisation",
                              "authorization")),
    ("Hard limits", ("hard limits", "hard limits (inviolable)", "inviolable limits")),
    ("Soft limits", ("soft limits",)),
    ("Stop conditions", ("stop conditions", "stop condition")),
    ("Objectives", ("objectives", "objective")),
    ("Engagement window", ("engagement window", "dates", "window", "authorisation dates",
                           "authorization dates")),
)

_HEADING_RE = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")
_SIGNED_RE = re.compile(r"^Signed:\s*(.*)$", re.MULTILINE)
_DATE_RE = re.compile(r"Date:\s*([^\s|]+)")


@dataclass
class Authorization:
    """What the engagement's authorisation record says — or the fact that there is none."""

    slug: str = ""
    charter_path: Optional[str] = None
    found: bool = False
    signed: bool = False
    signed_reason: str = ""            # the platform's own evidence, either way
    signatory: Optional[str] = None
    dates: list[str] = field(default_factory=list)
    scope_hosts: list[str] = field(default_factory=list)
    scope_parsed: bool = False         # the machine-readable scope table was found and read
    sections: dict[str, str] = field(default_factory=dict)   # label -> verbatim body
    charter_text: Optional[str] = None
    notes: list[str] = field(default_factory=list)


def _heading_label(text: str) -> Optional[str]:
    t = text.strip().lower().rstrip(":")
    t = re.sub(r"^\d+[.)]\s*", "", t)          # drop a leading "2. "
    t = t.strip("`* ")
    for label, aliases in _SECTION_ALIASES:
        if any(t == a or t.startswith(a) for a in aliases):
            return label
    return None


def _split_sections(text: str) -> dict[str, str]:
    """Verbatim bodies of the charter headings this module recognises. Everything else in the
    charter is left alone — the full text ships in the archive regardless, so nothing is lost by
    this module recognising only some headings."""
    out: dict[str, str] = {}
    current: Optional[str] = None
    buf: list[str] = []
    for line in text.splitlines():
        m = _HEADING_RE.match(line)
        if m:
            if current and buf:
                out.setdefault(current, "\n".join(buf).strip())
            buf = []
            current = _heading_label(m.group(2))
            continue
        if current:
            buf.append(line)
    if current and buf:
        out.setdefault(current, "\n".join(buf).strip())
    return {k: v for k, v in out.items() if v}


def read_authorization(slug: str) -> Authorization:
    """Locate and read the charter authorising ``slug``. Never raises."""
    a = Authorization(slug=slug)
    try:
        from ..common import paths

        cp = paths.charter_path(slug)
    except Exception as e:  # noqa: BLE001
        a.notes.append(f"the charter location could not be resolved for this engagement ({e})")
        return a
    a.charter_path = str(cp)
    try:
        if cp.is_symlink() or not cp.is_file():
            a.notes.append(
                f"NO ENGAGEMENT CHARTER WAS FOUND for this engagement. The expected location is "
                f"{cp}. Nothing in this archive records who authorised the testing, which systems "
                f"they authorised, or what was placed out of scope."
            )
            return a
        text = cp.read_text(encoding="utf-8")
    except OSError as e:
        a.notes.append(f"the charter at {cp} could not be read ({e})")
        return a

    a.found = True
    a.charter_text = text
    a.sections = _split_sections(text)

    try:
        from ..common.ethics import is_charter_signed

        a.signed, a.signed_reason = is_charter_signed(slug)
    except Exception as e:  # noqa: BLE001
        a.signed, a.signed_reason = (False, f"the signature could not be checked ({e})")
    m = _SIGNED_RE.search(text)
    if m:
        value = re.split(r"Date:", m.group(1), maxsplit=1)[0].strip().strip("`").strip()
        a.signatory = value or None
    a.dates = sorted({d.strip() for d in _DATE_RE.findall(text) if d.strip()})

    try:
        from ..common.ethics import parse_scope

        hosts = parse_scope(slug)
        a.scope_hosts = [h for h in hosts if h]
        a.scope_parsed = bool(a.scope_hosts)
    except Exception as e:  # noqa: BLE001
        a.notes.append(f"the charter's scope table could not be read ({e})")

    if not a.scope_parsed:
        a.notes.append(
            "The charter's machine-readable scope table could not be read. The enforcement layer "
            "reads in-scope hosts from a numbered '## 2. In-scope systems' table; this charter "
            "does not use that heading, so the scope below is reproduced from the charter's own "
            "wording rather than from the parsed table."
        )
    if not a.signed:
        a.notes.append(
            f"THE CHARTER IS NOT SIGNED: {a.signed_reason}. A charter without a completed "
            f"signature line does not evidence that a named person authorised this work."
        )
    return a
