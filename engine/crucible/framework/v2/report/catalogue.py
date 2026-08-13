"""
report.catalogue — what the engine is able to look for, and what this engagement recorded.

A reader who is handed a list of findings has no way to judge what the silence means. Three
findings out of three categories examined is a very different document from three findings out of
ninety, and neither is knowable from the findings alone. This module builds the missing half: the
catalogue of every weakness category the deterministic layer can confirm, with this engagement's
status against each one.

**The catalogue is derived from the code, not written by hand.** Its rows come from
``verify.verifier.BUG_CLASS_ORACLES`` — the registry that binds each weakness category to the
deterministic checks able to confirm it — so a category added to the engine appears here on the
next build, and a category removed disappears. A hand-maintained list would drift silently into a
false claim of breadth, which is precisely the failure this document exists to prevent.

**The status column is the honest part, and it is deliberately weak.** Each row is one of:

  ``confirmed``    a finding of this category was proven in this engagement (the finding is named).
  ``reported``     a finding of this category was recorded but NOT proven (it is a lead).
  ``not_recorded`` the run's stored record does not say whether this category was examined.

There is no "examined and found clean" state, and there must not be one, because the run record
does not support it. A scan writes what it found; it does not write the list of checks it
attempted. Inferring "examined and clean" from the absence of a finding would convert a gap in
the record into an assurance — the single most dangerous thing a security document can do. So the
absence of a finding produces ``not_recorded``, and the rendered document says in terms that this
is not a clean result.

Recording real coverage would require the scan itself to emit the set of checks it attempted
alongside its findings; :data:`COVERAGE_GAP_NOTE` states that, so the limitation is documented as
a specific, fixable gap rather than as vagueness.

Standards identifiers (OWASP / CWE / PCI DSS / SOC 2 / ISO 27001 / ATT&CK) come from
:mod:`report.standards`, which is explicit that a mapping shows what a weakness of that category
*would* implicate — it asserts coverage only for a proven fact. This module preserves that
distinction by carrying the mapping on every row while marking the status separately.

Pure and deterministic given the graded findings; imports the registries lazily and totally, so an
unavailable registry yields an empty catalogue with a note rather than an exception.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

from .plainspeak import short_plain

STATUS_CONFIRMED = "confirmed"
STATUS_REPORTED = "reported"
STATUS_NOT_RECORDED = "not_recorded"

COVERAGE_GAP_NOTE = (
    "The engine records what it found; it does not record the list of checks it attempted. That "
    "is why so many rows below read \"not recorded\" rather than \"examined, nothing found\". "
    "Closing this gap needs one change in the engine: the scan would have to write out the set of "
    "checks it attempted, alongside the findings it already writes. Until it does, a blank row "
    "here means the record is silent — it does not mean the category was checked and found clean."
)

# Presentational grouping only. A category that matches no family falls into "Other categories",
# which is listed like any other — nothing is dropped for want of a family.
_FAMILIES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("Injection — supplied text changes what the system does",
     ("sqli", "nosqli", "ldap_injection", "xpath_injection", "ssti", "el_injection",
      "command_injection", "os_command", "rce", "deserial", "xxe", "evaluation",
      "injection_breakout", "injection_attempt")),
    ("Cross-site scripting — supplied text becomes code in a visitor's browser",
     ("xss", "reflection_context", "dom_execution")),
    ("Access control — who is allowed to do what",
     ("idor", "bola", "bfla", "broken_access", "authorization", "authz", "auth_bypass",
      "privilege_escalation", "priv_esc", "mass_assignment", "request_race")),
    ("Server-side request and file handling",
     ("ssrf", "path_traversal", "lfi", "rfi")),
    ("Browser and transport protections",
     ("cors", "host_header", "open_redirect", "jwt", "weak_tls", "tls_weakness", "weak_cipher",
      "request_smuggling", "websocket", "clickjack", "header")),
    ("Query interfaces (GraphQL and similar)", ("graphql",)),
    ("Business logic — correct steps, wrong outcome", ("business_logic",)),
    ("Single sign-on and identity",
     ("oidc", "saml", "identity_misconfiguration", "email_auth")),
    ("Exposure and configuration",
     ("exposure", "info_disclosure", "security_misconfiguration", "directory_listing",
      "version_disclosure", "rate_limit", "signature", "secret_credential", "weak_crypto",
      "mobile_misconfiguration", "cicd", "mesh")),
    ("Infrastructure, cloud and containers",
     ("k8s", "kube", "cloud", "iam", "policy_path", "service_reachab", "service_reachable",
      "anonymous_reachable", "port", "imds", "gcp_", "excessive_privilege", "privilege_path")),
    ("Third-party components", ("version_range", "supply_chain", "dependency", "outdated",
                                "framework_version")),
    ("AI and automated-abuse surfaces",
     ("prompt_injection", "system_prompt", "credential_stuffing", "automated_access", "llm")),
    ("Memory safety", ("sanitizer", "buffer_overflow", "use_after_free", "crash", "memory")),
    ("Timing-based inference", ("time_based",)),
)

_OTHER_FAMILY = "Other categories"


@dataclass
class CatalogueRow:
    """One weakness category the engine can confirm, and this engagement's status against it."""

    bug_class: str
    family: str
    meaning: Optional[str]                 # None when no plain description is on file
    oracles: tuple[str, ...] = ()          # the deterministic checks able to confirm this category
    standards: Optional[dict] = None       # what a weakness of this category WOULD implicate
    status: str = STATUS_NOT_RECORDED
    findings: list[str] = field(default_factory=list)   # slugs of this engagement's findings

    @property
    def status_text(self) -> str:
        if self.status == STATUS_CONFIRMED:
            return "Confirmed in this engagement"
        if self.status == STATUS_REPORTED:
            return "Reported, not confirmed"
        return "Not recorded whether examined"


@dataclass
class Catalogue:
    rows: list[CatalogueRow] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def confirmed(self) -> list[CatalogueRow]:
        return [r for r in self.rows if r.status == STATUS_CONFIRMED]

    @property
    def reported(self) -> list[CatalogueRow]:
        return [r for r in self.rows if r.status == STATUS_REPORTED]

    @property
    def not_recorded(self) -> list[CatalogueRow]:
        return [r for r in self.rows if r.status == STATUS_NOT_RECORDED]

    def by_family(self) -> list[tuple[str, list[CatalogueRow]]]:
        order = [name for name, _ in _FAMILIES] + [_OTHER_FAMILY]
        grouped: dict[str, list[CatalogueRow]] = {}
        for r in self.rows:
            grouped.setdefault(r.family, []).append(r)
        out: list[tuple[str, list[CatalogueRow]]] = []
        for name in order:
            rows = sorted(grouped.get(name, ()), key=lambda r: r.bug_class)
            if rows:
                out.append((name, rows))
        return out


def _family_for(bug_class: str) -> str:
    b = (bug_class or "").lower()
    for name, keys in _FAMILIES:
        if any(k in b for k in keys):
            return name
    return _OTHER_FAMILY


def _registry() -> tuple[dict[str, tuple[str, ...]], list[str]]:
    """``({bug_class: (oracle name, …)}, notes)`` read from the live verifier registry. The oracle
    names are the enum VALUES (``differential_response``), which is what a certificate records and
    therefore what a reader will see elsewhere in the archive."""
    notes: list[str] = []
    try:
        from ..verify.verifier import BUG_CLASS_ORACLES
    except Exception as e:  # noqa: BLE001
        return ({}, [f"the engine's check registry could not be read ({e}), so no catalogue of "
                     f"categories could be produced"])
    out: dict[str, tuple[str, ...]] = {}
    for bug_class, oracles in BUG_CLASS_ORACLES.items():
        names: list[str] = []
        for o in oracles or ():
            value = getattr(o, "value", None)
            names.append(str(value if value is not None else o))
        out[str(bug_class)] = tuple(names)
    if not out:
        notes.append("the engine's check registry is empty, so no categories are listed")
    return (out, notes)


def _standards_for(bug_class: str) -> Optional[dict]:
    try:
        from .standards import controls_for

        return controls_for(bug_class)
    except Exception:  # noqa: BLE001
        return None


def build_catalogue(graded: Iterable[Any]) -> Catalogue:
    """Build the catalogue and mark each row with this engagement's status.

    ``graded`` are the run's :class:`report.grounding.GradedFinding` objects. A category is marked
    ``confirmed`` only when a finding of that category graded as a proven fact — i.e. its retained
    proof RE-FIRED — so the catalogue and the findings document can never disagree about what was
    proven. A category with no finding is ``not_recorded``; it is never marked clean."""
    cat = Catalogue()
    registry, notes = _registry()
    cat.notes += notes

    proven: dict[str, list[str]] = {}
    reported: dict[str, list[str]] = {}
    unknown_classes: set[str] = set()
    for g in graded or ():
        finding = getattr(g, "finding", None)
        bug_class = str(getattr(finding, "bug_class", "") or "").strip()
        slug = str(getattr(finding, "finding_slug", "") or "")
        if not bug_class or bug_class.lower() == "passive":
            continue
        bucket = proven if getattr(g, "is_fact", False) else reported
        bucket.setdefault(bug_class, []).append(slug)
        if bug_class not in registry:
            unknown_classes.add(bug_class)

    for bug_class in sorted(registry):
        oracles = registry[bug_class]
        if bug_class in proven:
            status, slugs = STATUS_CONFIRMED, proven[bug_class]
        elif bug_class in reported:
            status, slugs = STATUS_REPORTED, reported[bug_class]
        else:
            status, slugs = STATUS_NOT_RECORDED, []
        cat.rows.append(CatalogueRow(
            bug_class=bug_class,
            family=_family_for(bug_class),
            meaning=short_plain(bug_class),
            oracles=oracles,
            standards=_standards_for(bug_class),
            status=status,
            findings=sorted(slugs),
        ))

    # A finding whose category is not in the registry still belongs in the catalogue — dropping it
    # would make the findings document and the catalogue disagree about what exists.
    for bug_class in sorted(unknown_classes):
        slugs = proven.get(bug_class) or reported.get(bug_class) or []
        cat.rows.append(CatalogueRow(
            bug_class=bug_class,
            family=_family_for(bug_class),
            meaning=short_plain(bug_class),
            oracles=(),
            standards=_standards_for(bug_class),
            status=(STATUS_CONFIRMED if bug_class in proven else STATUS_REPORTED),
            findings=sorted(slugs),
        ))
    if unknown_classes:
        cat.notes.append(
            f"{len(unknown_classes)} recorded category(-ies) are not in the engine's check "
            f"registry: {', '.join(sorted(unknown_classes))}. They are listed so the catalogue "
            f"agrees with the findings, but no deterministic check is registered against them."
        )
    return cat


def catalogue_export(cat: Catalogue) -> dict:
    """The catalogue as a deterministic, JSON-safe document for the archive appendix."""
    return {
        "schema": "vigil.catalogue/v1",
        "statuses": {
            STATUS_CONFIRMED: "a finding of this category was PROVEN in this engagement",
            STATUS_REPORTED: "a finding of this category was recorded but NOT proven",
            STATUS_NOT_RECORDED: ("the run record does not say whether this category was examined; "
                                  "this is NOT a statement that it was checked and found clean"),
        },
        "coverage_gap": COVERAGE_GAP_NOTE,
        "counts": {
            STATUS_CONFIRMED: len(cat.confirmed),
            STATUS_REPORTED: len(cat.reported),
            STATUS_NOT_RECORDED: len(cat.not_recorded),
            "total": len(cat.rows),
        },
        "categories": [
            {
                "bug_class": r.bug_class,
                "family": r.family,
                "meaning": r.meaning,
                "confirmable_by": list(r.oracles),
                "standards": r.standards,
                "status": r.status,
                "findings": list(r.findings),
            }
            for r in sorted(cat.rows, key=lambda r: r.bug_class)
        ],
        "notes": list(cat.notes),
    }
