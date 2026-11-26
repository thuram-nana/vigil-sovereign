"""
aegis.license_policy — the §7 service-use-vs-distribution licence classifier (AS-7a).

The plan's §7 draws ONE load-bearing distinction: whether an artefact is used as a *service*
(the SaaS gateway runs it behind the network) or *distributed* (shipped to a customer: the CFN
template, the kit, the forwarder/SDK, rule content pushed to customers). The obligations differ:

  * Service use — GPL / LGPL / Apache / BSD / MIT impose nothing; AGPL §13 bites only when the
    engine is MODIFIED; SSPL / Elastic-2.0 / BUSL / Commons-Clause / CC-BY-NC are DENIED; a
    DRL-1.1 detection rule may be used but its author must be attributed in match views.
  * Distribution — a strong-copyleft (GPL / AGPL) artefact is denied for kits by default;
    permissive/weak-copyleft carry a NOTICE / relink obligation (tracked, non-blocking);
    first-party artefacts carry customer terms (D10).

This module is a PURE classifier: ``evaluate`` is a total function of its input and the loaded
policy — no wallclock, no RNG, no I/O on the decision path (the policy JSON is read once at
construction). It is the single place that NAMES the §7 rules; the deploy-time ledger gate in
``license_gate`` composes it. Nothing here is imported by scan/engage/benchmark/__main__, so
``make gate`` stays byte-identical, and it imports only the shared engine substrate (never SIGIL).
"""

from __future__ import annotations

import enum
import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

_POLICY_PATH = Path(__file__).resolve().parent / "license_policy.json"


class UseMode(str, enum.Enum):
    """How an artefact reaches an end user — the §7 pivot."""

    SERVICE = "service"            # run behind the SaaS network; nothing is handed to the customer
    DISTRIBUTION = "distribution"  # shipped to the customer (CFN template, kit, forwarder/SDK, pushed rules)


class LicenseClass(str, enum.Enum):
    """The obligation family a licence belongs to (the §7 buckets)."""

    PERMISSIVE = "permissive"              # Apache / MIT / BSD / ISC
    WEAK_COPYLEFT = "weak_copyleft"        # LGPL / MPL (relink / file-level)
    STRONG_COPYLEFT = "strong_copyleft"    # GPL-2.0 / GPL-3.0 (source obligation on distribution)
    NETWORK_COPYLEFT = "network_copyleft"  # AGPL (§13 — triggers only when modified)
    SOURCE_AVAILABLE = "source_available"  # SSPL / Elastic-2.0 / BUSL / Commons-Clause (deny)
    NONCOMMERCIAL = "noncommercial"        # CC-BY-NC (deny)
    ATTRIBUTION = "attribution"            # DRL-1.1 (allowed, but the author must be named)
    FIRST_PARTY = "first_party"            # PolyForm-NC / commercial (our own terms)
    UNKNOWN = "unknown"                    # not in the policy — fail closed


class Disposition(str, enum.Enum):
    """The verdict for a (class, use_mode) pair."""

    ALLOW = "allow"
    ALLOW_WITH_OBLIGATION = "allow_with_obligation"
    DENY = "deny"


class PolicyFinding(BaseModel):
    """The pure verdict for one artefact under the policy. ``allowed`` is False only on DENY;
    ``obligation`` is the non-blocking duty an ALLOW_WITH_OBLIGATION carries (NOTICE, relink,
    attribution, customer terms)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    artefact: str
    license: str
    license_class: LicenseClass
    use_mode: UseMode
    disposition: Disposition
    allowed: bool
    obligation: str | None = None
    reason: str = ""


class _Record(BaseModel):
    """The minimal projection ``evaluate`` needs from a ledger entry (so the policy never imports
    the gate's richer model — no cycle)."""

    model_config = ConfigDict(extra="ignore")

    artefact: str = ""
    license: str = ""
    use_mode: UseMode = UseMode.SERVICE
    modified: bool = False
    author: str | None = None


class LicensePolicy:
    """The loaded §7 policy. Construct once (``LicensePolicy.load()`` reads the shipped JSON) and
    reuse: every method below is a pure function of the parsed tables."""

    def __init__(
        self,
        *,
        classes: dict[str, LicenseClass],
        dispositions: dict[LicenseClass, dict[UseMode, Disposition]],
        obligations: dict[LicenseClass, dict[UseMode, str]],
        requires_author: frozenset[LicenseClass],
        modified_network_copyleft_denies_service: bool,
    ) -> None:
        self._classes = classes
        self._dispositions = dispositions
        self._obligations = obligations
        self._requires_author = requires_author
        self._modified_agpl_denies_service = modified_network_copyleft_denies_service

    # -- construction ------------------------------------------------------
    @classmethod
    def load(cls, path: Path | None = None) -> "LicensePolicy":
        """Parse the policy JSON (the shipped ``license_policy.json`` by default)."""
        raw: dict[str, Any] = json.loads((path or _POLICY_PATH).read_text(encoding="utf-8"))
        classes: dict[str, LicenseClass] = {
            str(k): LicenseClass(str(v)) for k, v in dict(raw.get("classes", {})).items()
        }
        dispositions: dict[LicenseClass, dict[UseMode, Disposition]] = {}
        for cls_name, modes in dict(raw.get("dispositions", {})).items():
            dispositions[LicenseClass(str(cls_name))] = {
                UseMode(str(m)): Disposition(str(d)) for m, d in dict(modes).items()
            }
        obligations: dict[LicenseClass, dict[UseMode, str]] = {}
        for cls_name, modes in dict(raw.get("obligations", {})).items():
            obligations[LicenseClass(str(cls_name))] = {
                UseMode(str(m)): str(text) for m, text in dict(modes).items()
            }
        requires_author = frozenset(
            LicenseClass(str(c)) for c in list(raw.get("requires_author", []))
        )
        modified_flag = bool(raw.get("modified_network_copyleft_denies_service", True))
        return cls(
            classes=classes,
            dispositions=dispositions,
            obligations=obligations,
            requires_author=requires_author,
            modified_network_copyleft_denies_service=modified_flag,
        )

    # -- classification ----------------------------------------------------
    def classify(self, license_id: str) -> LicenseClass:
        """Map an SPDX-style id to its obligation family. Exact, then case-insensitive; an
        id the policy does not list is ``UNKNOWN`` (fail-closed — never guessed by prefix)."""
        name = (license_id or "").strip()
        if name in self._classes:
            return self._classes[name]
        lowered = name.lower()
        for known, klass in self._classes.items():
            if known.lower() == lowered:
                return klass
        return LicenseClass.UNKNOWN

    def _base_disposition(self, klass: LicenseClass, use_mode: UseMode) -> Disposition:
        return self._dispositions.get(klass, {}).get(use_mode, Disposition.DENY)

    # -- evaluation (the pure decision) ------------------------------------
    def evaluate(self, record: "_Record | Any") -> PolicyFinding:
        """Return the §7 verdict for one artefact. Total and deterministic.

        Order of the special rules (each can only tighten a base ALLOW to DENY):
          1. an UNKNOWN class denies in every mode (fail-closed);
          2. a MODIFIED network-copyleft (AGPL §13) denies in service;
          3. an attribution-required licence (DRL-1.1) with no author denies (duty unmet)."""
        rec = record if isinstance(record, _Record) else _Record.model_validate(
            record if isinstance(record, dict) else record.model_dump()
        )
        klass = self.classify(rec.license)
        disposition = self._base_disposition(klass, rec.use_mode)
        reason = f"{rec.license or '<none>'} classed {klass.value}; base {disposition.value} for {rec.use_mode.value}"

        if klass is LicenseClass.UNKNOWN:
            disposition = Disposition.DENY
            reason = f"unknown licence {rec.license or '<none>'!r} is not ledgered in the policy — fail closed"
        elif (
            klass is LicenseClass.NETWORK_COPYLEFT
            and rec.use_mode is UseMode.SERVICE
            and rec.modified
            and self._modified_agpl_denies_service
        ):
            disposition = Disposition.DENY
            reason = f"{rec.license} is network-copyleft and MODIFIED — AGPL §13 bites on service use"
        elif klass in self._requires_author and not (rec.author or "").strip():
            disposition = Disposition.DENY
            reason = f"{rec.license} requires author attribution but no author is recorded"

        obligation = self._obligations.get(klass, {}).get(rec.use_mode)
        if disposition is Disposition.ALLOW_WITH_OBLIGATION and obligation is None:
            obligation = f"{klass.value} obligation for {rec.use_mode.value}"
        return PolicyFinding(
            artefact=rec.artefact,
            license=rec.license,
            license_class=klass,
            use_mode=rec.use_mode,
            disposition=disposition,
            allowed=disposition is not Disposition.DENY,
            obligation=obligation if disposition is not Disposition.DENY else None,
            reason=reason,
        )


__all__ = [
    "UseMode",
    "LicenseClass",
    "Disposition",
    "PolicyFinding",
    "LicensePolicy",
]
