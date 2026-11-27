"""
aegis.license_gate — the AS-7a deploy-time licence/advisory ledger gate.

§7 requires a record for EVERY deployed engine (R1) before the first third-party deploy. This
module holds the ledger shape and the deploy-time check that AEGIS runs over it:

  * COMPLETENESS — every artefact in the deploy set has a ledger record (a deployed engine with
    no record fails closed: ``missing_ledger_record``);
  * CONSISTENCY — the use_mode a deploy carries matches the use_mode the record was ledgered
    under, and no artefact is recorded twice (a service-only engine shipped in a distributed kit
    fails: ``use_mode_inconsistent``);
  * POLICY — every non-advisory record passes the §7 ``LicensePolicy`` for its use_mode
    (``policy_denied``).

A record flagged ``advisory`` is TRACKED but NEVER blocks (pySigma dev-only, an engine still
under licence review): its findings land in ``advisories``, not ``blocking``. Obligations
(NOTICE, relink, DRL attribution, customer terms) are likewise tracked, non-blocking.

The check is a PURE function of (ledger, deploy set, policy): no wallclock, no RNG — the same
inputs give a byte-identical result and ``ledger_digest`` (so a deploy record can be pinned,
and bundles can carry a licence digest). It reuses the shared engine integrity primitive
(``evidence.canonical`` ⇒ ``vigil_core.canonical``) for digests — no crypto is reinvented, and
nothing from SIGIL is imported. Standalone: not on the scan/engage/benchmark gate path.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal, Sequence

from pydantic import BaseModel, ConfigDict

from vigil_core.canonical import digest_payload  # the shared integrity core (evidence.canonical re-exports it)

from .license_policy import Disposition, LicensePolicy, PolicyFinding, UseMode

_LEDGER_PATH = Path(__file__).resolve().parent / "engine-pins.json"

ComponentKind = Literal["engine", "dependency", "rule", "artifact"]
FindingCode = Literal[
    "missing_ledger_record",
    "duplicate_record",
    "use_mode_inconsistent",
    "policy_denied",
    "obligation",
]


class LicenseRecord(BaseModel):
    """One ledger entry — the §7 record for one engine, dependency or rule set. ``use_mode``
    tags how the artefact reaches the user; ``advisory`` marks an entry that is tracked but may
    never block a deploy; ``digest`` optionally pins the artefact bundle this record covers."""

    model_config = ConfigDict(extra="forbid")

    artefact: str
    component_kind: ComponentKind = "engine"
    license: str
    use_mode: UseMode
    modified: bool = False
    author: str | None = None
    advisory: bool = False
    bundle: str | None = None
    digest: str | None = None
    notes: str = ""


class DeployItem(BaseModel):
    """One artefact in a deploy set — the artefact id and the use_mode it is deployed under."""

    model_config = ConfigDict(extra="forbid")

    artefact: str
    use_mode: UseMode


class GateFinding(BaseModel):
    """A single ledger-gate outcome. ``blocking`` is True only for a fail-closed violation on a
    non-advisory artefact; obligations and advisory-record denials are non-blocking."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    artefact: str
    code: FindingCode
    blocking: bool
    reason: str
    policy: PolicyFinding | None = None


class LicenseGateResult(BaseModel):
    """The deploy-time verdict. ``passed`` is True iff there are no blocking findings — a
    complete, consistent, policy-clean ledger. ``ledger_digest`` is the pinnable canonical
    digest of the ledger's licence content."""

    model_config = ConfigDict(extra="forbid")

    passed: bool
    checked: int
    blocking: list[GateFinding]
    advisories: list[GateFinding]
    ledger_digest: str


def _license_fields(record: LicenseRecord) -> dict[str, Any]:
    """The licence-bearing projection of a record — what a licence digest is taken over, so the
    digest moves iff an artefact's licence content moves (not its free-text notes)."""
    return {
        "artefact": record.artefact,
        "component_kind": record.component_kind,
        "license": record.license,
        "use_mode": record.use_mode.value,
        "modified": record.modified,
        "author": record.author,
        "advisory": record.advisory,
        "bundle": record.bundle,
        "digest": record.digest,
    }


def ledger_digest(ledger: Sequence[LicenseRecord]) -> str:
    """A deterministic sha256 over the ledger's licence content (records sorted by artefact).
    Pure — reuses the shared canonical digest primitive. Pins a deploy's licence posture."""
    fields = sorted((_license_fields(r) for r in ledger), key=lambda d: str(d["artefact"]))
    return digest_payload(fields)


def bundle_digests(ledger: Sequence[LicenseRecord]) -> dict[str, str]:
    """Per-bundle licence digest: every record carrying a ``bundle`` contributes to that bundle's
    digest, so a distributed bundle can carry — and later re-verify — its licence set (§7)."""
    groups: dict[str, list[dict[str, Any]]] = {}
    for record in ledger:
        if record.bundle:
            groups.setdefault(record.bundle, []).append(_license_fields(record))
    return {
        bundle: digest_payload(sorted(items, key=lambda d: str(d["artefact"])))
        for bundle, items in sorted(groups.items())
    }


class LicenseGate:
    """The deploy-time licence gate. Construct once with a ``LicensePolicy`` (the shipped §7
    policy by default) and call ``check`` against a ledger and an optional deploy set."""

    def __init__(self, policy: LicensePolicy | None = None) -> None:
        self.policy = policy if policy is not None else LicensePolicy.load()

    def check(
        self,
        ledger: Sequence[LicenseRecord],
        deploy: Sequence[DeployItem] | None = None,
    ) -> LicenseGateResult:
        """Run the deploy-time check. ``deploy`` names the artefacts being deployed and their
        use_mode; when omitted, every ledger record is treated as deployed exactly as recorded
        (the 'does the whole ledger pass?' check)."""
        blocking: list[GateFinding] = []
        advisories: list[GateFinding] = []

        index: dict[str, list[LicenseRecord]] = {}
        for record in ledger:
            index.setdefault(record.artefact, []).append(record)

        # CONSISTENCY — no artefact ledgered twice. A duplicate blocks unless every copy is advisory.
        for artefact, records in sorted(index.items()):
            if len(records) > 1:
                is_advisory = all(r.advisory for r in records)
                finding = GateFinding(
                    artefact=artefact,
                    code="duplicate_record",
                    blocking=not is_advisory,
                    reason=f"{artefact} has {len(records)} ledger records — the entry is ambiguous",
                )
                (advisories if is_advisory else blocking).append(finding)

        deploy_items: list[DeployItem] = (
            [DeployItem(artefact=r.artefact, use_mode=r.use_mode) for r in ledger]
            if deploy is None
            else list(deploy)
        )

        for item in deploy_items:
            recs = index.get(item.artefact)
            if not recs:
                # COMPLETENESS (R1) — a deployed artefact with no record fails closed.
                blocking.append(GateFinding(
                    artefact=item.artefact,
                    code="missing_ledger_record",
                    blocking=True,
                    reason=f"deployed artefact {item.artefact!r} has no §7 licence record (R1)",
                ))
                continue
            record = recs[0]

            # CONSISTENCY — deployed use_mode must match the ledgered use_mode.
            if item.use_mode is not record.use_mode:
                blocking_flag = not record.advisory
                finding = GateFinding(
                    artefact=item.artefact,
                    code="use_mode_inconsistent",
                    blocking=blocking_flag,
                    reason=(f"{item.artefact} deployed as {item.use_mode.value} but ledgered as "
                            f"{record.use_mode.value}"),
                )
                (blocking if blocking_flag else advisories).append(finding)
                continue

            # POLICY — the §7 verdict for this record under its use_mode.
            pf = self.policy.evaluate(record)
            if pf.disposition is Disposition.DENY:
                blocking_flag = not record.advisory
                prefix = "advisory-only (tracked, non-blocking): " if record.advisory else ""
                (advisories if record.advisory else blocking).append(GateFinding(
                    artefact=item.artefact,
                    code="policy_denied",
                    blocking=blocking_flag,
                    reason=prefix + pf.reason,
                    policy=pf,
                ))
            elif pf.disposition is Disposition.ALLOW_WITH_OBLIGATION:
                advisories.append(GateFinding(
                    artefact=item.artefact,
                    code="obligation",
                    blocking=False,
                    reason=pf.obligation or f"{pf.license_class.value} obligation",
                    policy=pf,
                ))

        return LicenseGateResult(
            passed=not blocking,
            checked=len(deploy_items),
            blocking=blocking,
            advisories=advisories,
            ledger_digest=ledger_digest(ledger),
        )


def load_ledger(path: Path | None = None) -> list[LicenseRecord]:
    """Parse the shipped engine-pins ledger (``engine-pins.json`` by default)."""
    raw: dict[str, Any] = json.loads((path or _LEDGER_PATH).read_text(encoding="utf-8"))
    return [LicenseRecord.model_validate(entry) for entry in list(raw.get("records", []))]


def main(argv: list[str] | None = None) -> int:
    """Deploy-time entry point: run the gate over the shipped ledger and print the verdict.
    Exit 0 iff the ledger is complete, consistent and policy-clean (fail-closed otherwise)."""
    gate = LicenseGate()
    result = gate.check(load_ledger())
    print(result.model_dump_json(indent=2))
    return 0 if result.passed else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())


__all__ = [
    "ComponentKind",
    "FindingCode",
    "LicenseRecord",
    "DeployItem",
    "GateFinding",
    "LicenseGateResult",
    "LicenseGate",
    "ledger_digest",
    "bundle_digests",
    "load_ledger",
    "main",
]
