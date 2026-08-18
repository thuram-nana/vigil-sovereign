"""
report.adapt — a faithful adapter from the STORED scan export to the renderer's finding shape.

A finished run leaves a ``report.json`` on disk in the **scanner export shape**
(:mod:`scanner.report`), whose findings look like::

    {kind, bug_class, title, severity, confidence, location, confirmed_by,
     evidence, remediation, references, re_verifiable, grounding, check_id}

``check_id`` is the producing check's stable id — non-empty ONLY when that finding's
``grounding`` is ``"fact"`` (its oracle re-fired at render time). Every lead carries "": the
passive/DOM-XSS ones, and any ACTIVE finding whose proof no longer re-grounds. This adapter
neither reads nor needs it; it is listed here only so the documented shape stays honest about
what the export actually contains.

The report renderers (:mod:`report.generate`, :mod:`report.export`) consume a very different
shape — :class:`agents.models.FindingPayload` — which *requires* ``finding_slug``, ``surface``
and ``summary``. Feeding a stored ``report.json`` straight into ``generate_reports()`` therefore
raises a pydantic ``ValidationError``, which is exactly why a stored run's dossier used to carry
no human-readable reports at all. This module is the missing translation.

Two rules govern every mapping here, and they are the whole point:

  * **Never invent.** Every value written out is either copied from the export, derived
    mechanically from it (a slug from the title, a float parsed from a numeric string), or
    left empty. Fields with no source in the export — ``impact``, ``cvss_vector``,
    ``cvss_base``, ``derived_from_hypothesis`` — are left empty/``None``. The reports then
    say "impact unspecified" rather than asserting an impact nobody measured.
  * **Never lose.** The export carries two things ``FindingPayload`` has no room for: the
    scanner's own finding-specific ``remediation`` text and its ``references`` (CWE/CAPEC).
    Rather than dropping them, :func:`adapt_scan_export` returns them alongside, keyed by the
    slug it minted, so the case-file renderer can show them verbatim.

**The proof join.** ``report.json`` does *not* retain each finding's ``oracle_context`` — the
captured bytes a deterministic oracle re-fires over. ``reverifiable.json`` does. Without the
join, every once-confirmed finding would grade as DEMOTED ("recorded a proof that failed
re-verification"), which is a false and alarming statement: the proof did not fail, it simply
was not in the file being read. So :func:`adapt_scan_export` JOINS the two documents on
(bug class, insertion point, confirming oracle), attaches the retained ``oracle_context``, and
lets :func:`report.grounding.grade_finding` re-execute the real proof. A finding whose proof
cannot be located is marked ``verified_by_oracle=False`` — it grades as an unproven lead, and
the adapter records WHY in its notes and in the finding's own summary, so the under-claim is
explained rather than silent. Under-claiming is the safe direction; over-claiming is not.

Pure and deterministic: no wallclock, no RNG, no I/O. The same two documents adapt to the
same bytes every time.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

# The five ratings ``FindingPayload.severity`` accepts. Anything else in the export is shown as
# "Info" (the least alarming choice — we never inflate a rating we cannot place) and its
# original text is preserved in the finding's summary + the adapter notes, so nothing is lost.
_SEVERITIES = ("Critical", "High", "Medium", "Low", "Info")

# A trailing "[insertion point]" on a scanner location, e.g.
# "http://host/search?q=test  [query_value:0]" -> "query_value:0".
_INSERTION_RE = re.compile(r"\s*\[([^\]]*)\]\s*$")

# Characters kept in a generated slug.
_SLUG_STRIP_RE = re.compile(r"[^a-z0-9]+")

# ``confirmed_by`` values the scanner writes for finding kinds that no oracle confirmed. These
# name the *source* of a lead, not a deterministic oracle, so they must never be rendered as
# "the oracle that fired".
_NON_ORACLE_SOURCES = frozenset({"", "passive", "static-lead", "static_lead", "lead"})


def auditfinding_to_payload(f: dict) -> dict:
    """Coerce an ``AuditFinding``-shaped dict — the shape a run's ``reverifiable.json`` retains
    (``check_id/bug_class/insertion_point/param/endpoint/confidence/confirmed_by/oracle_context``)
    — onto the ``FindingPayload`` fields the report grader validates.

    This is the NARROW coercion used wherever a retained proof must be GRADED: it exists because
    ``FindingPayload`` requires descriptive fields a retained proof does not carry, so
    ``model_validate`` rejects the raw dict and the caller silently treats a genuine fact as an
    unproven lead. Only the fields the grader reads carry meaning here — above all the retained
    ``oracle_context`` (what re-fires), plus ``bug_class`` and the oracle metadata. The descriptive
    fields are filled from the finding's own identifiers purely so validation succeeds; severity is
    ``Info`` and the summary is empty because a retained proof genuinely carries neither.

    It therefore cannot produce a READABLE finding — for that, see :func:`adapt_scan_export`, which
    works from the stored ``report.json`` (title, severity, remediation, references, and the passive
    findings a ``reverifiable.json`` never contains) and joins the retained proof back onto it.

    Never invents a proof: no ``oracle_context`` in, no fact out. Deterministic; pure."""
    return {
        "finding_slug": str(f.get("check_id") or f.get("bug_class") or "finding"),
        "title": str(f.get("bug_class") or f.get("check_id") or "finding"),
        "severity": "Info",
        "bug_class": str(f.get("bug_class") or ""),
        "surface": str(f.get("insertion_point") or f.get("param") or f.get("endpoint") or ""),
        "summary": "",
        "oracle_context": f.get("oracle_context"),
        # A reverifiable finding is oracle-RECORDED by construction (confirmed_by + retained
        # context); mark it so a non-re-firing one grades DEMOTED (a lead), never LEAD-only.
        "verified_by_oracle": bool(f.get("confirmed_by") or f.get("oracle_context")),
        "confidence": f.get("confidence"),
        "oracle_kind": f.get("confirmed_by"),
    }


def slugify(text: str, *, limit: int = 48) -> str:
    """A stable, readable, filesystem-safe slug fragment from free text. Deterministic."""
    s = _SLUG_STRIP_RE.sub("-", (text or "").strip().lower()).strip("-")
    if len(s) > limit:
        s = s[:limit].rstrip("-")
    return s or "finding"


def split_location(location: str) -> tuple[str, str]:
    """Split a scanner ``location`` into ``(endpoint, insertion_point)``.

    ``"http://h/search?q=t  [query_value:0]"`` -> ``("http://h/search?q=t", "query_value:0")``;
    a location with no bracket returns ``(location, "")``. Never raises."""
    loc = (location or "").strip()
    m = _INSERTION_RE.search(loc)
    if not m:
        return (loc, "")
    return (loc[: m.start()].strip(), (m.group(1) or "").strip())


def _normalise_severity(raw: Any) -> tuple[str, Optional[str]]:
    """``(severity, unrecognised_original)``. A rating the renderers accept passes through;
    anything else becomes ``"Info"`` and is returned as the second element so the caller can
    say so out loud instead of silently re-rating the finding."""
    s = str(raw or "").strip()
    for known in _SEVERITIES:
        if s.lower() == known.lower():
            return (known, None)
    return ("Info", s or None)


def _parse_confidence(raw: Any) -> Optional[float]:
    """A 0..1 float from the export's ``confidence``, which is a *string* — ``"0.76"`` for an
    oracle-confirmed active finding, but a word like ``"Certain"`` for a passive observation.
    Only a real number in range is returned; a word yields ``None``, because
    ``FindingPayload.confidence`` means "calibrated exploitability probability from an oracle"
    and a passive header check has no such number."""
    if isinstance(raw, bool):
        return None
    if isinstance(raw, (int, float)):
        v = float(raw)
        return v if 0.0 <= v <= 1.0 else None
    try:
        v = float(str(raw).strip())
    except (TypeError, ValueError):
        return None
    return v if 0.0 <= v <= 1.0 else None


def _oracle_kind(raw: Any) -> Optional[str]:
    """The confirming oracle's name, or ``None`` when ``confirmed_by`` merely names a
    non-oracle source (``passive``, ``static-lead``)."""
    s = str(raw or "").strip()
    return None if s.lower() in _NON_ORACLE_SOURCES else s


@dataclass
class FindingExtras:
    """What the export carries but ``FindingPayload`` has no field for. Returned alongside the
    adapted findings, keyed by the slug the adapter minted, so nothing in the source document
    goes unshown."""

    slug: str
    kind: str = ""                     # active | passive | dom_xss_candidate
    location: str = ""                 # the raw location, verbatim
    endpoint: str = ""
    insertion_point: str = ""
    confirmed_by: str = ""             # verbatim, including non-oracle sources
    evidence: str = ""
    scanner_remediation: str = ""      # the scanner library's finding-specific fix text
    references: list[str] = field(default_factory=list)   # CWE / CAPEC identifiers
    recorded_confidence: str = ""      # the export's confidence string, verbatim ("Certain", "0.76")
    recorded_grounding: str = ""       # what the SCAN recorded (fact | unclassified | …)
    recorded_re_verifiable: bool = False
    proof_joined: bool = False         # a retained oracle_context was located and attached
    unrecognised_severity: Optional[str] = None
    parameter: str = ""                # the affected input name, when one can be identified


@dataclass
class AdaptResult:
    """The adapter's output: renderer-ready findings, the extras they could not carry, and an
    honest account of what happened during the translation."""

    findings: list[dict] = field(default_factory=list)
    extras: dict[str, FindingExtras] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    proofs_joined: int = 0
    proofs_unjoined: int = 0
    proofs_unused: int = 0             # retained proofs that matched no exported finding


def _reverifiable_actives(docs: Iterable[Any]) -> list[dict]:
    """Every ``active_findings`` entry across the supplied re-verifiable documents, in order.
    Accepts the parsed documents (dicts); anything unusable is skipped silently."""
    out: list[dict] = []
    for doc in docs or ():
        if not isinstance(doc, dict):
            continue
        fs = doc.get("active_findings")
        if isinstance(fs, list):
            out += [f for f in fs if isinstance(f, dict)]
    return out


def _proof_key(bug_class: Any, insertion_point: Any, confirmed_by: Any) -> tuple[str, str, str]:
    return (str(bug_class or "").strip().lower(),
            str(insertion_point or "").strip().lower(),
            str(confirmed_by or "").strip().lower())


def adapt_scan_export(
    export_doc: Any,
    reverifiable_docs: Iterable[Any] = (),
) -> AdaptResult:
    """Translate a stored scanner ``report.json`` into ``FindingPayload``-shaped dicts the
    report renderers accept, joining each finding to its retained proof where one exists.

    ``export_doc`` is the parsed ``report.json``; ``reverifiable_docs`` are the parsed
    ``reverifiable.json`` document(s) that retain the ``oracle_context`` the export omits.
    Returns an :class:`AdaptResult`. Total: a malformed document yields an empty result with a
    note, never an exception."""
    res = AdaptResult()
    if not isinstance(export_doc, dict):
        res.notes.append("no structured scan export was found, so no findings could be adapted")
        return res
    raw_findings = export_doc.get("findings")
    if not isinstance(raw_findings, list):
        res.notes.append("the scan export carried no 'findings' list, so no findings could be adapted")
        return res

    # ---- index the retained proofs, so each is consumed at most once -------------------------
    proofs = _reverifiable_actives(reverifiable_docs)
    by_key: dict[tuple[str, str, str], list[dict]] = {}
    for p in proofs:
        by_key.setdefault(
            _proof_key(p.get("bug_class"), p.get("insertion_point"), p.get("confirmed_by")), []
        ).append(p)
    consumed: set[int] = set()

    def _take_proof(bug_class: Any, insertion_point: Any, confirmed_by: Any) -> Optional[dict]:
        """The first not-yet-consumed retained proof for this finding.

        Tried in order: an exact match on (bug class, insertion point, oracle); then the same
        bug class and the same oracle at any insertion point. The looser key is still an exact
        match on WHAT was proven and WHICH deterministic check proved it — only the insertion
        point may be spelled differently, because the export's ``location`` and the retained
        finding's ``insertion_point`` are written by different code paths. Bug class and oracle
        are never relaxed, so a proof can never be attached to a different kind of finding."""
        exact = _proof_key(bug_class, insertion_point, confirmed_by)
        for cand in by_key.get(exact, ()):
            if id(cand) not in consumed:
                consumed.add(id(cand))
                return cand
        for key in sorted(by_key):
            if (key[0], key[2]) != (exact[0], exact[2]):
                continue
            for cand in by_key[key]:
                if id(cand) not in consumed:
                    consumed.add(id(cand))
                    return cand
        return None

    # ---- translate each exported finding ----------------------------------------------------
    unrecognised: list[str] = []
    for i, f in enumerate(raw_findings, start=1):
        if not isinstance(f, dict):
            continue
        title = str(f.get("title") or "").strip() or f"Finding {i}"
        bug_class = str(f.get("bug_class") or "").strip()
        kind = str(f.get("kind") or "").strip()
        location = str(f.get("location") or "").strip()
        endpoint, insertion = split_location(location)
        confirmed_by = str(f.get("confirmed_by") or "").strip()
        evidence = str(f.get("evidence") or "").strip()
        severity, odd = _normalise_severity(f.get("severity"))
        if odd:
            unrecognised.append(f"{title!r} recorded severity {odd!r}")

        slug = f"{i:03d}-{slugify(title)}"

        # The surface the renderers parse for method/location/parameter. The endpoint carries
        # the query string, from which report.howto derives the affected parameter.
        surface = endpoint or location

        # The proof join. Only an ACTIVE finding the scan marked re-verifiable can have one.
        proof: Optional[dict] = None
        if kind == "active" and bool(f.get("re_verifiable")):
            proof = _take_proof(bug_class, insertion, confirmed_by)

        oracle_context = None
        confidence = _parse_confidence(f.get("confidence"))
        if proof is not None:
            oc = proof.get("oracle_context")
            if isinstance(oc, dict) and oc:
                oracle_context = oc
            # the retained confidence is the raw oracle value at full precision; the export
            # rounded it to 2dp for display. Prefer the retained one.
            pc = _parse_confidence(proof.get("confidence"))
            if pc is not None:
                confidence = pc

        joined = oracle_context is not None
        if kind == "active" and bool(f.get("re_verifiable")):
            if joined:
                res.proofs_joined += 1
            else:
                res.proofs_unjoined += 1

        # `summary` gets the observation the scan recorded. Where the translation had to give
        # something up, the summary says so in the finding itself — not only in a build note.
        summary_parts: list[str] = []
        if evidence:
            summary_parts.append(evidence)
        if odd:
            summary_parts.append(
                f"Severity as recorded by the scan was \"{odd}\", which is not one of the five "
                f"standard ratings; it is shown here as Info so that it is not over-stated."
            )
        if kind == "active" and bool(f.get("re_verifiable")) and not joined:
            summary_parts.append(
                "The scan recorded this as confirmed by an automated check, but the saved "
                "evidence needed to re-prove it was not available when this document was "
                "produced. It is therefore presented as unproven."
            )
        summary = "  ".join(summary_parts)

        payload = {
            "finding_slug": slug,
            "title": title,
            "severity": severity,
            "bug_class": bug_class,
            "surface": surface,
            "summary": summary,
            # No source in the export for any of these. Left empty rather than invented.
            "impact": "",
            "cvss_vector": "",
            "cvss_base": None,
            "derived_from_hypothesis": None,
            "oracle_context": oracle_context,
            # True ONLY when a real retained proof was attached, so a finding whose proof is
            # simply absent reads as unproven rather than as a proof that failed.
            "verified_by_oracle": joined,
            "confidence": confidence if joined else None,
            "oracle_kind": _oracle_kind(confirmed_by) if joined else None,
            "oracle_rationale": "",
        }
        res.findings.append(payload)
        # The affected input's name. The retained proof records it explicitly; otherwise it is the
        # first parameter in the endpoint's query string. Empty when neither is available — the
        # documents then omit it rather than naming a parameter nothing recorded.
        parameter = str((proof or {}).get("param") or "").strip()
        # Only an ACTIVE finding is bound to a particular input. A passive observation (a missing
        # header) is a property of the whole response, and the query string of the URL that
        # happened to be fetched says nothing about it — naming it as the "affected input" would
        # point a reader at the wrong thing.
        if not parameter and kind == "active" and "?" in endpoint:
            first = endpoint.partition("?")[2].split("&", 1)[0]
            parameter = first.split("=", 1)[0].strip()

        res.extras[slug] = FindingExtras(
            slug=slug,
            parameter=parameter,
            kind=kind,
            location=location,
            endpoint=endpoint,
            insertion_point=insertion,
            confirmed_by=confirmed_by,
            evidence=evidence,
            scanner_remediation=str(f.get("remediation") or "").strip(),
            references=[str(r) for r in (f.get("references") or []) if str(r).strip()],
            recorded_confidence=str(f.get("confidence") or "").strip(),
            recorded_grounding=str(f.get("grounding") or "").strip(),
            recorded_re_verifiable=bool(f.get("re_verifiable")),
            proof_joined=joined,
            unrecognised_severity=odd,
        )

    res.proofs_unused = sum(1 for p in proofs if id(p) not in consumed)

    # ---- honest notes about the translation -------------------------------------------------
    res.notes.append(
        f"adapted {len(res.findings)} finding(s) from the stored scan export into the report format"
    )
    if res.proofs_joined:
        res.notes.append(
            f"attached the saved evidence for {res.proofs_joined} finding(s) so their proofs "
            f"could be re-run while this dossier was built"
        )
    if res.proofs_unjoined:
        res.notes.append(
            f"{res.proofs_unjoined} finding(s) the scan recorded as confirmed had no saved "
            f"evidence available at build time and are presented as unproven"
        )
    if res.proofs_unused:
        res.notes.append(
            f"{res.proofs_unused} saved proof(s) did not correspond to any finding in the scan "
            f"export; they are covered by the proof bundle, not by the findings list"
        )
    if unrecognised:
        res.notes.append(
            "severity not one of the five standard ratings, shown as Info: " + "; ".join(unrecognised)
        )
    return res
