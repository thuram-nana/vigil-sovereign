"""framework.v2.aegis.provider_runtime — AS-10a: the telemetry-PROVIDER RUNTIME (engine plane).

AS-10a is the generic PROVIDER RUNTIME the concrete AEGIS telemetry sources plug into. The program ships a
heterogeneous set of per-tenant, DEFAULT-OFF telemetry SOURCES — the EDR provider (AS-10b), the AWS CloudTrail
source (AS-17b), the IdP source (AS-17c) — each of which, when armed, turns a vendor's alerts/logs into INERT,
metadata-only LEAD findings on the shared AS-9b ingest path. This slice gives them ONE honest home:

  1. A UNIFIED, append-only PROVIDER INVENTORY. Each source is an intel-tier telemetry provider that OBSERVES
     and ALERTS — it never *prevents* and can never mint a re-runnable certificate. So each registers the SAME
     honest capability: ``outcome_class=detected_without_enforcement`` (class 5) + ``effect_verification=
     reported`` (K17 — provider-REPORTED, never independently verified). :func:`build_provider_runtime_registry`
     APPENDS the EDR / CloudTrail / IdP :class:`~vigil_core.protection_contract.ProviderDescriptor`\\ s onto the
     AS-1a baseline registry (:func:`~vigil_core.protection_contract.baseline_provider_registry`) — never a
     central-enum edit, so the AS-4b baseline golden is unchanged. (``EDR_PROVIDER`` is reused verbatim from
     ``edr_provider`` so there is ONE source of truth; CloudTrail/IdP — which ship as pure readers — get their
     descriptor here, where the runtime catalogs them.)

  2. A fault-isolated RUNTIME over the armed sources. :class:`ProviderRuntime` holds a set of
     :class:`ProviderSource` adapters (one per concrete telemetry source) and runs each ARMED one, returning a
     unified, value-free :class:`ProviderRuntimeReport`. A single source's SYSTEMIC fault (a down broker, a
     dead transport) is CONTAINED to that provider — the other providers still run — mirroring the per-record
     resilience the EDR poll already has, lifted to the per-source level.

"Wire, don't rebuild": this slice COMPOSES merged machinery (the AS-10b/AS-17b/AS-17c sources, the AS-2b
provider registry) and writes almost no net-new code. It adds NO fleet WorkerKind, NO OracleKind, and NO new
spool/wire format — the sources push through the already-covered AS-9b receiver entrypoint.

THREE independent DEFAULT-OFF gates cover the live path (belt-and-suspenders):
  1. ``VIGIL_AEGIS_PROVIDER_RUNTIME`` (:func:`provider_runtime_enabled`) — the runtime's own gate. OFF ⇒
     :meth:`ProviderRuntime.run_all` is INERT: it runs NO source, opens no credential, pushes nothing. (The
     PURE inventory :func:`build_provider_runtime_registry` needs NO flag — building a catalog opens nothing.)
  2. Each source's OWN gate (``VIGIL_AEGIS_EDR_PROVIDER`` / ``VIGIL_AEGIS_CLOUDTRAIL`` / ``VIGIL_AEGIS_IDP``) —
     a source whose own flag is off is SKIPPED inert by the runtime (it is never asked to run / open a secret).
  3. ``VIGIL_AEGIS_CONNECTOR_BROKER`` — the AS-9a materialisation gate each source honours before any plaintext.

GATE-INVARIANCE: nothing under ``aegis/__init__`` or ``framework.v2.__main__`` imports this module (off the
scan/engage/make-gate path, like ``edr_provider`` / ``cloudtrail_source`` / ``idp_source``); its tests import
it directly, so ``make gate`` stays byte-identical.

FATAL-2: engine leg — imports only ``vigil_core`` (the shared provider contract), the stdlib, and
``framework.v2.aegis`` DEFENSIVE siblings (``edr_provider`` for the shared EDR descriptor). NEVER ``sigil``.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Callable, Optional, Protocol, runtime_checkable

from vigil_core.protection_contract import (
    AdapterCapability,
    EffectVerification,
    OutcomeClass,
    ProviderDescriptor,
    ProviderRegistry,
    baseline_provider_registry,
)

from .edr_provider import EDR_PROVIDER

__all__ = [
    "PROVIDER_RUNTIME_ENV",
    "provider_runtime_enabled",
    "CLOUDTRAIL_PROVIDER",
    "IDP_PROVIDER",
    "build_provider_runtime_registry",
    "SourceRunResult",
    "ProviderSource",
    "IngestProviderSource",
    "PollProviderSource",
    "ProviderRuntimeReport",
    "ProviderRuntime",
]

# The DEFAULT-OFF switch that ARMS the runtime's active fan-out (strict, fail-closed; mirrors the source flags).
# OFF ⇒ ``run_all`` runs NO source and opens nothing.
PROVIDER_RUNTIME_ENV = "VIGIL_AEGIS_PROVIDER_RUNTIME"


def provider_runtime_enabled() -> bool:
    """Is the provider runtime's active fan-out ARMED? Strict, fail-closed, DEFAULT OFF — only an explicit
    affirmative token arms it. The PURE :func:`build_provider_runtime_registry` does NOT consult this flag
    (building a catalog opens nothing); only :meth:`ProviderRuntime.run_all` does."""
    return (os.environ.get(PROVIDER_RUNTIME_ENV) or "").strip().lower() in ("1", "true", "yes", "on")


# ==================================================================================================
# The provider descriptors for the sources that ship as pure readers (CloudTrail / IdP). Each is the SAME
# honest intel-tier capability the EDR provider declares: it OBSERVES/ALERTS (class 5), never prevents, and
# its effect is provider-REPORTED (K17), never independently verified. ``EDR_PROVIDER`` is imported (one
# source of truth), not redefined.
# ==================================================================================================
#: The AWS CloudTrail telemetry provider descriptor (AS-17b reader; appended to the registry here).
CLOUDTRAIL_PROVIDER: ProviderDescriptor = ProviderDescriptor(
    provider_id="cloudtrail",
    title="AWS CloudTrail telemetry",
    capabilities=[
        AdapterCapability(kind="cloudtrail", outcome_class=OutcomeClass.DETECTED_WITHOUT_ENFORCEMENT,
                          effect_verification=EffectVerification.REPORTED),
    ],
)

#: The identity-provider (Okta System Log) sign-in/audit telemetry provider descriptor (AS-17c reader).
IDP_PROVIDER: ProviderDescriptor = ProviderDescriptor(
    provider_id="idp",
    title="Identity-provider sign-in telemetry",
    capabilities=[
        AdapterCapability(kind="idp", outcome_class=OutcomeClass.DETECTED_WITHOUT_ENFORCEMENT,
                          effect_verification=EffectVerification.REPORTED),
    ],
)

#: The telemetry providers the runtime catalogs, in a stable, deterministic order (insertion order is part of
#: the registry's canonical bytes). Appended onto the baseline; never a central edit.
_RUNTIME_PROVIDERS: tuple[ProviderDescriptor, ...] = (EDR_PROVIDER, CLOUDTRAIL_PROVIDER, IDP_PROVIDER)


def build_provider_runtime_registry(base: Optional[ProviderRegistry] = None) -> ProviderRegistry:
    """APPEND the EDR / CloudTrail / IdP telemetry providers onto ``base`` (default: the AS-1a
    :func:`baseline_provider_registry`) and return the resulting append-only :class:`ProviderRegistry`. PURE /
    OFFLINE / DETERMINISTIC — opens no credential, reaches no network, consults NO flag (building a catalog is
    always safe). The baseline is never edited (append-only doctrine): the returned registry's provider prefix
    equals ``base``'s exactly, so the AS-4b baseline golden is unchanged. Fail-closed: a duplicate provider id
    raises :class:`~vigil_core.protection_contract.DuplicateProviderError` (an existing provider is never
    silently overwritten)."""
    registry = base if base is not None else baseline_provider_registry()
    for descriptor in _RUNTIME_PROVIDERS:
        registry = registry.register(descriptor)
    return registry


# ==================================================================================================
# The unified, value-free run result + the ProviderSource seam the runtime fans out over.
# ==================================================================================================
@dataclass
class SourceRunResult:
    """One telemetry source's run outcome, value-free w.r.t. secrets. ``enabled`` is False (and every count 0)
    when the source is DEFAULT-OFF — INERT. ``spooled``/``deduped``/``dropped``/``rejected`` mirror the receiver
    outcomes; ``normalized`` is the records seen (ingest sources); ``skipped`` is benign/non-detection events
    (poll sources); ``errors`` is contained per-record/source faults; ``anchor_errors`` is failed anchor mints."""

    provider_id: str
    enabled: bool
    normalized: int = 0
    spooled: int = 0
    deduped: int = 0
    dropped: int = 0
    rejected: int = 0
    skipped: int = 0
    errors: int = 0
    anchor_errors: int = 0
    note: str = ""


@runtime_checkable
class ProviderSource(Protocol):
    """The seam the runtime fans out over: a named telemetry source that reports whether it is ARMED and runs
    ONE cycle into a value-free :class:`SourceRunResult`. The concrete adapters wrap the merged EDR poll /
    CloudTrail reader / IdP reader; injected so the runtime is tested offline with canned sources."""

    provider_id: str

    @property
    def enabled(self) -> bool: ...

    def run_once(self) -> SourceRunResult: ...


class IngestProviderSource:
    """A :class:`ProviderSource` over an INGEST reader (a :class:`~framework.v2.aegis.cloudtrail_source.
    CloudTrailSource` or :class:`~framework.v2.aegis.idp_source.IdpSource` — both expose ``enabled`` +
    ``ingest_text`` and return an identically-shaped ingest result). ``delivery`` supplies the next delivery
    text to ingest (injected so no network/file lives in this core — a production delivery is an operator file
    or a brokered pull, a test delivery is canned bytes)."""

    __slots__ = ("provider_id", "_source", "_delivery")

    def __init__(self, provider_id: str, source: Any, delivery: Callable[[], str]) -> None:
        self.provider_id = str(provider_id)
        self._source = source
        self._delivery = delivery

    @property
    def enabled(self) -> bool:
        return bool(getattr(self._source, "enabled", False))

    def run_once(self) -> SourceRunResult:
        res = self._source.ingest_text(self._delivery())
        return SourceRunResult(
            provider_id=self.provider_id, enabled=bool(res.enabled), normalized=int(res.normalized),
            spooled=int(res.spooled), deduped=int(res.deduped), dropped=int(res.dropped),
            rejected=int(res.rejected), anchor_errors=int(res.anchor_errors), note=str(res.note))


class PollProviderSource:
    """A :class:`ProviderSource` over a POLL source (the AS-10b EDR poll, whose ``run`` returns an
    ``EdrPollResult``-shaped value with ``push_count``/``skipped``/``dropped``/``errors``). ``enabled`` and the
    ``run`` callable are injected (the EDR poll job keeps its own arm flag private); the runtime only asks an
    ARMED source to run, so ``run`` is invoked only when the source is armed AND the runtime is on."""

    __slots__ = ("provider_id", "_enabled", "_run")

    def __init__(self, provider_id: str, *, enabled: bool, run: Callable[[], Any]) -> None:
        self.provider_id = str(provider_id)
        self._enabled = bool(enabled)
        self._run = run

    @property
    def enabled(self) -> bool:
        return self._enabled

    def run_once(self) -> SourceRunResult:
        res = self._run()
        return SourceRunResult(
            provider_id=self.provider_id, enabled=bool(getattr(res, "enabled", True)),
            spooled=int(getattr(res, "push_count", 0)), skipped=int(getattr(res, "skipped", 0)),
            dropped=int(getattr(res, "dropped", 0)), errors=int(getattr(res, "errors", 0)))


# ==================================================================================================
# The runtime.
# ==================================================================================================
@dataclass
class ProviderRuntimeReport:
    """The unified outcome of one runtime pass, value-free w.r.t. secrets. ``enabled`` is False (and
    ``results`` empty) when the runtime is DEFAULT-OFF — INERT: no source was run and nothing was opened."""

    enabled: bool
    results: list[SourceRunResult] = field(default_factory=list)
    note: str = ""

    @property
    def total_spooled(self) -> int:
        return sum(r.spooled for r in self.results)

    @property
    def total_errors(self) -> int:
        return sum(r.errors for r in self.results)

    @property
    def armed_provider_ids(self) -> tuple[str, ...]:
        """The ids of the sources that were ARMED (their own flag on) in this pass — the ones that actually ran."""
        return tuple(r.provider_id for r in self.results if r.enabled)


class ProviderRuntime:
    """The telemetry-provider runtime: a unified inventory + a fault-isolated fan-out over the armed sources.

    DEFAULT-OFF (the runtime's own gate ``VIGIL_AEGIS_PROVIDER_RUNTIME``): with the runtime off,
    :meth:`run_all` is INERT — it runs NO source and opens nothing. With it on, each source is run ONLY when its
    OWN flag is armed (``source.enabled``); a default-off source is recorded inert, never asked to run. A single
    source's SYSTEMIC fault is CONTAINED to that provider (recorded as an error on its result) so the other
    providers still run — the per-record resilience the EDR poll has, lifted to the per-source level."""

    __slots__ = ("_sources", "_enabled", "_registry")

    def __init__(self, sources: list[ProviderSource], *, enabled: Optional[bool] = None,
                 registry: Optional[ProviderRegistry] = None) -> None:
        self._sources = list(sources)
        self._enabled = provider_runtime_enabled() if enabled is None else bool(enabled)
        self._registry = registry

    @property
    def enabled(self) -> bool:
        return self._enabled

    def inventory(self) -> ProviderRegistry:
        """The append-only provider inventory (the catalog of telemetry providers). PURE: opens nothing, needs
        no flag — readable even when the runtime is DEFAULT-OFF."""
        return self._registry if self._registry is not None else build_provider_runtime_registry()

    def run_all(self) -> ProviderRuntimeReport:
        """Run every ARMED source once and return the unified, value-free report. DEFAULT-OFF ⇒ INERT (no
        source run, nothing opened). A default-off source is recorded inert and NOT run. A single source's fault
        is CONTAINED (counted as an error on that provider) so one bad provider never aborts the others."""
        if not self._enabled:
            return ProviderRuntimeReport(enabled=False, note="provider runtime is default-off")
        report = ProviderRuntimeReport(enabled=True)
        for source in self._sources:
            if not source.enabled:
                report.results.append(SourceRunResult(
                    provider_id=source.provider_id, enabled=False, note="source default-off"))
                continue
            try:
                report.results.append(source.run_once())
            except Exception as exc:        # noqa: BLE001 — a single source's fault must NOT abort the others
                report.results.append(SourceRunResult(
                    provider_id=source.provider_id, enabled=True, errors=1,
                    note=f"contained source fault: {type(exc).__name__}"))
        return report
