"""
aegis.aegis_fleet — AS-6a: the AEGIS fleet PLACEMENT engine + declarative RECONCILER (§5.7).

The control-plane piece that turns an owner-signed monitoring grant into a *routed* worker with NO
operator step: a declarative reconciler converges the ACTUAL fleet toward the DESIRED state the grants
describe. It owns the worker-kind registry (units, broker, prover, receiver, jobs, Suricata, executor,
judge), the deployed-image DIGEST check (tampered image => refuse), the LoadCredential-style credential
delivery (SSM only), per-worker HEALTH, rollout (target-group swap with drain) and retire (snapshot
FIRST). It is the seam that makes AS-2h's sealing-secret delivery real (``SsmSecretDelivery``).

DOCTRINE (non-negotiable, enforced here and tested):
  * DEFENSIVE + CONTROL-PLANE ONLY. This routes the operator's OWN managed defense units; it never
    attacks and never reaches a tenant's traffic. It lives in the ENGINE plane beside the gateway it
    places (FATAL-2: it imports only ``vigil_core`` + stdlib + ``..common`` — never ``sigil``).
  * NEVER RENDER ENFORCEMENT BEFORE AS-29. The enforce env (``VIGIL_AEGIS_SAAS_ENFORCE`` /
    ``AEGIS_RESPOND``) is rendered ONLY from a VERIFIED ``EnforceRelease`` (D30, release root). AS-29
    (``enforce_release.py`` + the release root) is owner-gated / unbuilt, so this slice's reconciler
    wires NO release source: every worker renders OBSERVE-only and the enforce env is never set, even for
    a grant that carries BLOCK/VIRTUAL_PATCH/RESPOND (those are necessary-not-sufficient). The release
    gate in :func:`render_worker` is the AS-29 seam, proven live by its own test so the observe-only
    outcome is the ABSENCE of a release, not a hardcoded constant.
  * ONLY SIGIL TT ORIGINS BEFORE AS-2g. Tenant→origin binding lands in AS-2g; until then a v2 grant
    carries no tenant origin, so the fleet admits ONLY the internal SIGIL test-tenant (TT) origins and
    REFUSES any other tenant's worker (fail closed).
  * PROVE-THE-IMAGE. A worker is routed only when its attested deployed image digest EQUALS the AS-28
    locked digest (``saas-closure.json`` / ``Dockerfile.saas``); a mismatch REFUSES (fail closed).
  * DETERMINISM. No wall-clock, no RNG. ``now`` is injected; snapshot ids, placement ids and action ids
    are content hashes of canonical fields. The same desired+actual+now yields a byte-identical result.
  * DEFAULT-OFF. The whole reconciler is gated behind ``VIGIL_AEGIS_FLEET`` (strict, fail-closed, DEFAULT
    OFF — the ``_saas_enforce_flag`` pattern). With the flag off the reconciler is INERT: it places and
    retires nothing and returns a fixed ``disabled`` result (``flag-off golden byte-identical``).

Nothing under ``aegis/__init__`` or ``framework.v2.__main__`` imports this module (it is off the gate
path, like ``tt_rig``), so ``make gate`` stays byte-identical. Its tests import it directly.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Iterable, Mapping, Optional, Protocol, runtime_checkable

from ..common.logging import get_logger

# vigil_core is plane-neutral (importable in BOTH planes; FATAL-2 safe). These are the AS-2a authority
# contracts and the AS-2h sealing seam — CONSUMED, never re-coded.
from vigil_core.aegis_sealing import DeliveryReceipt, SecretBundle
from vigil_core.authority_v2 import (
    ENFORCING_CAPABILITIES,
    EnforceRelease,
    MonitoringAuthorityV2,
    MonitoringCapability,
)

_log = get_logger("aegis.fleet")

__all__ = [
    "FLEET_ENV", "fleet_enabled",
    "WorkerKind", "WorkerKindSpec", "WORKER_KIND_REGISTRY", "worker_kind_spec",
    "SIGIL_TT_TENANTS",
    "FleetError", "TamperedImageError", "OriginNotPermittedError", "SnapshotFailed",
    "locked_image_digest", "verify_image_digest",
    "DesiredMode", "DesiredWorker",
    "WorkerHealth", "RoutedWorker", "FleetState",
    "Snapshot", "SnapshotSink",
    "SsmCredentialChannel", "SsmSecretDelivery",
    "RenderedUnit", "render_worker",
    "FleetAction", "Refusal", "ReconcileResult", "FleetReconciler",
    "desired_from_grant",
]


# ==================================================================================================
# Default-OFF flag (the _saas_enforce_flag pattern — strict, fail-closed, DEFAULT OFF).
# ==================================================================================================
FLEET_ENV = "VIGIL_AEGIS_FLEET"


def fleet_enabled() -> bool:
    """The AS-6a fleet reconciler flag — strict, fail-closed, DEFAULT OFF. Only an explicit affirmative
    token turns the reconciler on; anything else (unset, typo, empty) keeps it INERT (the managed SaaS
    fleet is not placed/retired by this process)."""
    return (os.environ.get(FLEET_ENV) or "").strip().lower() in ("1", "true", "yes", "on")


# ==================================================================================================
# The worker-kind registry — the closed set of fleet worker kinds (plan AS-6a row), each with its
# placement / credentials / health contract.
# ==================================================================================================
class WorkerKind(str, Enum):
    """The closed set of AEGIS fleet worker kinds the placement engine routes. The VALUE is the stable
    registry label used in deterministic keys and snapshot ids."""

    UNITS = "units"            # the R15 isolated per-tenant gateway units (AS-2j), the data plane
    BROKER = "broker"          # the egress broker + lock (AS-2d)
    PROVER = "prover"          # the origin-challenge prover (AS-2g)
    RECEIVER = "receiver"      # the sensor/provider push receiver (AS-9b)
    JOBS = "jobs"              # the per-tenant job substrate runner (AS-30)
    SURICATA = "suricata"      # the mirror-IDS sensor (AS-20)
    EXECUTOR = "executor"      # the defensive action executor (AS-13a)
    JUDGE = "judge"            # the Z3 verifier/judge (sends nothing)


@dataclass(frozen=True)
class WorkerKindSpec:
    """The per-kind placement/credentials/health contract. Pure data — the reconciler reads it, never
    mutates it. ``enforce_capable`` records whether the kind has any enforcing data path AT ALL; even
    True is inert in this slice (no release source — see the module doctrine). ``credential_names`` are
    the LoadCredential names a placed unit expects, delivered SSM-only (AS-2h → :class:`SsmSecretDelivery`)."""

    kind: WorkerKind
    systemd_template: str
    credential_names: tuple[str, ...]
    enforce_capable: bool
    health_probe: str
    description: str


# The registry of record. The ``units`` row mirrors the shipped infra/systemd/aegis-saas-gateway@.service
# (LoadCredential report-secret + gw-secret, delivered via the credential store — never the environment).
WORKER_KIND_REGISTRY: Mapping[WorkerKind, WorkerKindSpec] = {
    WorkerKind.UNITS: WorkerKindSpec(
        kind=WorkerKind.UNITS, systemd_template="aegis-saas-gateway@.service",
        credential_names=("report-secret", "gw-secret"), enforce_capable=True,
        health_probe="unix:/run/aegis-saas/%i/gw.sock readyz",
        description="R15 isolated per-tenant gateway (AS-2j); the keyless inline inspector."),
    WorkerKind.BROKER: WorkerKindSpec(
        kind=WorkerKind.BROKER, systemd_template="aegis-broker@.service",
        credential_names=("broker-secret",), enforce_capable=False,
        health_probe="unix:/run/aegis-broker/%i/broker.sock ping",
        description="Egress broker + origin lock (AS-2d); forwards to NAT/origin."),
    WorkerKind.PROVER: WorkerKindSpec(
        kind=WorkerKind.PROVER, systemd_template="aegis-prover@.service",
        credential_names=("prover-secret",), enforce_capable=False,
        health_probe="unix:/run/aegis-prover/%i/prover.sock ping",
        description="Origin-challenge prover (AS-2g); proves origin control over the broker."),
    WorkerKind.RECEIVER: WorkerKindSpec(
        kind=WorkerKind.RECEIVER, systemd_template="aegis-receiver@.service",
        credential_names=("ingest-hmac", "ingest-mtls"), enforce_capable=False,
        health_probe="unix:/run/aegis-receiver/%i/ingest.sock health",
        description="Sensor/provider push receiver (AS-9b); HMAC/mTLS, caps, landing dirs."),
    WorkerKind.JOBS: WorkerKindSpec(
        kind=WorkerKind.JOBS, systemd_template="aegis-jobs@.service",
        credential_names=("job-runner-secret",), enforce_capable=False,
        health_probe="unix:/run/aegis-jobs/%i/jobs.sock health",
        description="Per-tenant job substrate runner (AS-30); killed job degrades one tenant only."),
    WorkerKind.SURICATA: WorkerKindSpec(
        kind=WorkerKind.SURICATA, systemd_template="aegis-suricata@.service",
        credential_names=("suricata-secret",), enforce_capable=False,
        health_probe="unix:/run/aegis-suricata/%i/eve.sock health",
        description="Mirror-IDS sensor (AS-20); packets in, no enforcement path."),
    WorkerKind.EXECUTOR: WorkerKindSpec(
        kind=WorkerKind.EXECUTOR, systemd_template="aegis-executor@.service",
        credential_names=("executor-secret",), enforce_capable=True,
        health_probe="unix:/run/aegis-executor/%i/exec.sock health",
        description="Defensive action executor (AS-13a); single-use token, conjunctive gate."),
    WorkerKind.JUDGE: WorkerKindSpec(
        kind=WorkerKind.JUDGE, systemd_template="aegis-judge@.service",
        credential_names=("judge-secret",), enforce_capable=False,
        health_probe="unix:/run/aegis-judge/%i/judge.sock health",
        description="Z3 verifier/judge (AS-14); sends nothing, verifies only."),
}


def worker_kind_spec(kind: WorkerKind) -> WorkerKindSpec:
    """The :class:`WorkerKindSpec` for ``kind``. Fail-closed: an unregistered kind raises
    :class:`FleetError` rather than placing an unknown worker."""
    spec = WORKER_KIND_REGISTRY.get(kind)
    if spec is None:
        raise FleetError(f"no placement contract for worker kind {kind!r}")
    return spec


# The recognised SIGIL test tenants (plan AS-1a). Before AS-2g there is NO tenant→origin binding, so the
# fleet admits ONLY these SIGIL TT origins and refuses any real tenant's worker (the pre-2g guard rail).
SIGIL_TT_TENANTS: frozenset[str] = frozenset({"tt-a", "tt-b"})


# ==================================================================================================
# Exceptions — every one is fail-closed (REFUSE), never a silent pass.
# ==================================================================================================
class FleetError(Exception):
    """A fleet-placement contract was violated and the operation was REFUSED (fail-closed)."""


class TamperedImageError(FleetError):
    """A worker's attested deployed image digest does NOT equal the AS-28 locked digest, or the lock
    itself is internally inconsistent — the image is refused placement (fail closed)."""


class OriginNotPermittedError(FleetError):
    """A worker's tenant/origin is not a SIGIL TT origin; before AS-2g no other origin may be routed."""


class SnapshotFailed(FleetError):
    """The mandatory pre-retirement snapshot could not be taken, so retirement is REFUSED (snapshot
    FIRST is inviolable — a worker is never torn down without its state captured)."""


# ==================================================================================================
# The deployed-image DIGEST check (AS-28 lock). Reads the AS-28 closure lock and refuses any image
# whose attested digest differs — "tampered image refuses".
# ==================================================================================================
_AEGIS_DIR = Path(__file__).resolve().parent
_CLOSURE_LOCK = _AEGIS_DIR / "saas-closure.json"
_DOCKERFILE_SAAS = _AEGIS_DIR / "Dockerfile.saas"
_FROM_DIGEST_RE = re.compile(r"^FROM\s+\S+@(sha256:[0-9a-f]{64})\s*$", re.MULTILINE)
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def locked_image_digest(*, closure_lock: Optional[Path] = None,
                        dockerfile: Optional[Path] = None) -> str:
    """The AS-28 locked image digest the fleet pins against, read from ``saas-closure.json`` and
    CROSS-CHECKED against the ``Dockerfile.saas`` ``FROM`` pin. The two AS-28 artifacts must agree; if
    they disagree the lock itself has been tampered with and this raises :class:`TamperedImageError`
    (fail closed). Pure file reads — deterministic, no network, no Docker daemon.

    Honest scope: AS-28's final-image build/scan/SBOM/cosign-sign is the owner-gated A14 CI leg, so the
    digest cryptographically pinned in the repo today is the base-image digest; the fleet pins the
    DEPLOYED image against whatever AS-28 locks here, so when A14 re-pins the final signed digest the
    fleet enforces that with no code change."""
    lock_path = closure_lock if closure_lock is not None else _CLOSURE_LOCK
    df_path = dockerfile if dockerfile is not None else _DOCKERFILE_SAAS
    try:
        manifest = json.loads(lock_path.read_text(encoding="utf-8"))
        locked = str(manifest["dockerfile"]["base_image_digest"])
    except (OSError, ValueError, KeyError, TypeError) as e:
        raise TamperedImageError(f"AS-28 closure lock unreadable/malformed at {lock_path}: {e}") from e
    if not _DIGEST_RE.match(locked):
        raise TamperedImageError(f"AS-28 locked digest is not a sha256 digest: {locked!r}")
    try:
        from_m = _FROM_DIGEST_RE.search(df_path.read_text(encoding="utf-8"))
    except OSError as e:
        raise TamperedImageError(f"Dockerfile.saas unreadable at {df_path}: {e}") from e
    if from_m is None:
        raise TamperedImageError(f"Dockerfile.saas has no @sha256 FROM pin at {df_path}")
    if not hmac.compare_digest(locked, from_m.group(1)):
        raise TamperedImageError(
            "AS-28 lock inconsistent: saas-closure.json digest != Dockerfile.saas FROM pin "
            f"({locked} != {from_m.group(1)})")
    return locked


def verify_image_digest(attested: str, *, locked: Optional[str] = None,
                        closure_lock: Optional[Path] = None) -> str:
    """Verify an attested DEPLOYED image digest against the AS-28 lock. Returns the locked digest on a
    match; raises :class:`TamperedImageError` on ANY mismatch or malformed input — the fail-closed
    "tampered image refuses" guarantee. Constant-time compare (``hmac.compare_digest``)."""
    ref = locked if locked is not None else locked_image_digest(closure_lock=closure_lock)
    if not isinstance(attested, str) or not _DIGEST_RE.match(attested or ""):
        raise TamperedImageError(f"attested image digest is not a sha256 digest: {attested!r}")
    if not hmac.compare_digest(attested, ref):
        raise TamperedImageError(
            f"deployed image digest {attested} does not match the AS-28 locked digest {ref} — refusing "
            "to route a tampered/unverified image")
    return ref


# ==================================================================================================
# Desired state — what the control plane wants placed (derived from grants, declaratively).
# ==================================================================================================
# "observe" => route the worker (read-only inspection). "off" => retire it (snapshot FIRST). There is no
# "enforce" desired mode in this slice — enforcement is rendered from a release, which does not exist
# before AS-29 (see render_worker).
DesiredMode = str  # Literal["observe", "off"]
_DESIRED_MODES = ("observe", "off")


@dataclass(frozen=True)
class DesiredWorker:
    """One desired fleet worker: a (kind, tenant, host, replica) placement the control plane wants in
    ``desired_mode``, carrying the grant's capabilities, the attested deployed image digest to prove, the
    monotone placement epoch, and (optionally) the sealed credential bundles to deliver SSM-only."""

    kind: WorkerKind
    tenant: str
    host: str
    desired_mode: DesiredMode = "observe"
    capabilities: tuple[MonitoringCapability, ...] = (MonitoringCapability.OBSERVE,)
    image_digest: str = ""
    epoch: int = 1
    replica_index: int = 0
    credential_bundles: tuple[SecretBundle, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.kind, WorkerKind):
            raise FleetError("kind must be a WorkerKind")
        if self.desired_mode not in _DESIRED_MODES:
            raise FleetError(f"desired_mode must be one of {_DESIRED_MODES}, got {self.desired_mode!r}")
        if not isinstance(self.tenant, str) or not self.tenant:
            raise FleetError("tenant must be a non-empty str")
        if not isinstance(self.host, str) or not self.host:
            raise FleetError("host must be a non-empty str")
        if not isinstance(self.epoch, int) or isinstance(self.epoch, bool) or self.epoch < 1:
            raise FleetError("epoch must be a positive int")
        if not isinstance(self.replica_index, int) or isinstance(self.replica_index, bool) or self.replica_index < 0:
            raise FleetError("replica_index must be a non-negative int")

    @property
    def key(self) -> str:
        """The stable deterministic placement key (kind, tenant, host, replica)."""
        return f"{self.kind.value}|{self.tenant}|{self.host}|{self.replica_index}"


# ==================================================================================================
# Health + the routed-worker record + the fleet state.
# ==================================================================================================
class WorkerHealth(str, Enum):
    """The per-worker health state this slice tracks. A richer state machine (CRASH_LOOP, EXPIRING,
    REVOCATION_PENDING) is AS-3d; this slice ships the placement-lifecycle core."""

    STARTING = "starting"    # newly placed / rolled; not yet proven healthy
    HEALTHY = "healthy"      # placed and converged
    DRAINING = "draining"    # being replaced (rollout) or torn down
    RETIRED = "retired"      # snapshot taken, stopped, credentials destroyed


@dataclass(frozen=True)
class RoutedWorker:
    """The actual state of one placed worker. Immutable; the reconciler produces a NEW one on every
    transition (append-only-in-spirit). ``mode`` is always ``observe`` in this slice (the enforce env is
    never rendered before AS-29)."""

    key: str
    kind: WorkerKind
    tenant: str
    host: str
    replica_index: int
    mode: str                 # "observe" (never "enforce" pre-AS-29)
    health: WorkerHealth
    epoch: int
    image_digest: str
    credential_status: str    # "delivered" | "deferred" | "none"
    routed_at: float
    snapshot_id: str = ""     # set when RETIRED


# A FleetState is just an immutable mapping key -> RoutedWorker. A small frozen wrapper keeps it hashable
# and gives deterministic ordering helpers.
@dataclass(frozen=True)
class FleetState:
    """The declarative fleet state: key -> RoutedWorker, ordered by key. Immutable; the reconciler
    returns a NEW state each pass."""

    workers: tuple[RoutedWorker, ...] = ()

    def by_key(self) -> dict[str, RoutedWorker]:
        return {w.key: w for w in self.workers}

    def get(self, key: str) -> Optional[RoutedWorker]:
        return self.by_key().get(key)

    def active(self) -> tuple[RoutedWorker, ...]:
        """Workers that are not retired, in key order."""
        return tuple(sorted((w for w in self.workers if w.health != WorkerHealth.RETIRED),
                            key=lambda w: w.key))

    @staticmethod
    def from_workers(workers: "Iterable[RoutedWorker]") -> "FleetState":
        return FleetState(workers=tuple(sorted(workers, key=lambda w: w.key)))


# ==================================================================================================
# Snapshots — retire takes a snapshot FIRST (deterministic, content-addressed).
# ==================================================================================================
@dataclass(frozen=True)
class Snapshot:
    """A pre-retirement snapshot of a worker's state. ``snapshot_id`` is a content hash (no RNG, no
    wall-clock beyond the injected ``taken_at``), so the same worker+now snapshots to the same id."""

    snapshot_id: str
    worker_key: str
    taken_at: float
    reason: str
    state_digest: str


@runtime_checkable
class SnapshotSink(Protocol):
    """Where a pre-retirement snapshot is durably recorded. The fleet refuses retirement if this raises
    or returns falsey (snapshot FIRST is inviolable). The real sink (owner-gated storage) is injected;
    tests use an in-memory list."""

    def store(self, snapshot: Snapshot) -> bool: ...


def _content_id(*parts: object) -> str:
    """A deterministic sha256 content id over canonical JSON of ``parts`` (16 hex = 64 bits, enough to
    disambiguate a worker lifecycle; the full digest is overkill for an id). No RNG, no wall-clock."""
    blob = json.dumps(parts, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


# ==================================================================================================
# Credentials — LoadCredential-style, SSM ONLY. SsmSecretDelivery is the REAL AS-2h SecretDelivery seam.
# ==================================================================================================
@runtime_checkable
class SsmCredentialChannel(Protocol):
    """The SSM parameter transport the fleet writes a sealed credential to. ``put_parameter`` returns
    True iff the SSM write is confirmed. The REAL AWS SSM client (boto3 ``ssm.put_parameter``) is
    owner-provided and deploy-gated — offline the channel is an injected in-memory transport, so the
    delivery PATH is exercised deterministically without an AWS call. SSM is the ONLY delivery channel:
    there is no environment/file/HTTP fallback (plan AS-6a: "SSM only")."""

    def put_parameter(self, name: str, sealed_blob: bytes) -> bool: ...


def _ssm_parameter_name(bundle: SecretBundle, epoch: int) -> str:
    """The deterministic SSM parameter path a unit's LoadCredential reads one sealed secret from. Keyed by
    (kind, org, scope, epoch) so a rotation's overlap epochs each land at a distinct, stable path."""
    scope = bundle.scope or "-"
    return f"/aegis-saas/{bundle.org}/{scope}/{bundle.kind.value}/e{epoch}"


class SsmSecretDelivery:
    """The REAL AS-6a implementation of AS-2h's ``SecretDelivery`` contract: push a sealed
    :class:`SecretBundle` to the fleet's units via SSM, and ONLY via SSM.

    It writes each accepted epoch's KEK-sealed blob to its deterministic SSM parameter path through the
    injected :class:`SsmCredentialChannel`; a unit then installs each as a ``LoadCredential=`` from the
    SSM-populated credential store (never the environment — mirrors aegis-saas-gateway@.service). The
    receipt is ``delivered=True`` ONLY when EVERY sealed epoch's SSM write is confirmed; a single failed
    write yields ``delivered=False, status="refused"`` so the caller never closes a rotation overlap on a
    half-delivered bundle (fail closed).

    This is the seam AS-2h staged: with the ``VIGIL_AEGIS_SEALING_DELIVER`` flag on and an instance of
    this class injected, ``vigil_core.aegis_sealing.deliver_bundle`` hands the bundle here and delivery
    becomes real; with no channel/flag it falls back to the default-OFF ``DeferredDelivery``."""

    def __init__(self, channel: SsmCredentialChannel) -> None:
        if not isinstance(channel, SsmCredentialChannel):
            raise FleetError("SsmSecretDelivery requires an SsmCredentialChannel")
        self._channel = channel

    def deliver(self, bundle: SecretBundle) -> DeliveryReceipt:
        if not isinstance(bundle, SecretBundle):
            return DeliveryReceipt(delivered=False, status="refused", detail="not a SecretBundle")
        written: list[str] = []
        for sealed in bundle.sealed:
            name = _ssm_parameter_name(bundle, sealed.epoch)
            try:
                ok = bool(self._channel.put_parameter(name, sealed.blob))
            except Exception as e:  # noqa: BLE001 — a transport error is a REFUSED delivery, never a crash
                return DeliveryReceipt(delivered=False, status="refused",
                                       detail=f"SSM write failed for {name}: {e}")
            if not ok:
                return DeliveryReceipt(delivered=False, status="refused",
                                       detail=f"SSM declined the write for {name}")
            written.append(name)
        if not written:
            return DeliveryReceipt(delivered=False, status="refused", detail="bundle carried no sealed secret")
        return DeliveryReceipt(delivered=True, status="delivered",
                               detail=f"delivered {len(written)} sealed secret(s) via SSM")


# ==================================================================================================
# Rendering — the OBSERVE/ENFORCE gate. The enforce env is rendered ONLY from a verified EnforceRelease.
# ==================================================================================================
# The real enforce env names (kept as literals so this control-plane module need not import the data
# plane). They are set ONLY by a release-gated render — never in this slice.
_ENFORCE_ENV = "VIGIL_AEGIS_SAAS_ENFORCE"
_RESPOND_ENV = "AEGIS_RESPOND"
_SAAS_MODE_ENV = "AEGIS_SAAS_MODE"


@dataclass(frozen=True)
class RenderedUnit:
    """The runtime rendering of a worker: its mode and the env the unit is started with. ``enforce`` is
    True only when a verified release covers an enforcing capability; otherwise it is observe and ``env``
    carries NO enforce key."""

    mode: str                       # "observe" | "enforce"
    env: tuple[tuple[str, str], ...]  # sorted (name, value) pairs; NO enforce key unless mode == "enforce"
    enforced_capabilities: tuple[str, ...] = ()

    def env_dict(self) -> dict[str, str]:
        return dict(self.env)


def render_worker(worker: DesiredWorker, *, release: Optional[EnforceRelease] = None,
                  now: Optional[float] = None) -> RenderedUnit:
    """Render ``worker`` to its runtime mode + env. OBSERVE unless a VERIFIED ``EnforceRelease`` (D30,
    release root) covers an enforcing capability the worker holds AT ``now``.

    This slice's reconciler wires NO release source (AS-29 ``enforce_release.py`` + the release root are
    owner-gated / unbuilt), so it ALWAYS passes ``release=None`` and every worker renders observe-only —
    the enforce env (``VIGIL_AEGIS_SAAS_ENFORCE`` / ``AEGIS_RESPOND``) is NEVER set, even for a grant that
    carries BLOCK/VIRTUAL_PATCH/RESPOND. ``release`` is the AS-29 seam: it is release-gated here (proven
    live by ``test_fleet_render_release_gate``) so the observe outcome is the ABSENCE of a release, not a
    hardcoded constant. Determinism: pure function of the worker + release + injected ``now``."""
    enforcing = tuple(c for c in worker.capabilities if c in ENFORCING_CAPABILITIES)
    covered: tuple[MonitoringCapability, ...] = ()
    if release is not None and enforcing:
        when = datetime.fromtimestamp(float(now), tz=timezone.utc) if now is not None else None
        if when is not None and release.covers(when):
            covered = tuple(c for c in enforcing if release.releases(c))
    if not covered:
        # Observe-only: NO enforce key in the env (the guard rail — never render enforcement pre-AS-29).
        return RenderedUnit(mode="observe", env=(( _SAAS_MODE_ENV, "observe"),), enforced_capabilities=())
    env = {_SAAS_MODE_ENV: "enforce", _ENFORCE_ENV: "1"}
    if MonitoringCapability.RESPOND in covered:
        env[_RESPOND_ENV] = "1"
    return RenderedUnit(mode="enforce", env=tuple(sorted(env.items())),
                        enforced_capabilities=tuple(sorted(c.value for c in covered)))


# ==================================================================================================
# Reconcile actions / refusals / result.
# ==================================================================================================
@dataclass(frozen=True)
class FleetAction:
    """One deterministic action the reconciler took. ``action_id`` is a content hash so the same
    desired+actual+now produces byte-identical actions."""

    verb: str                 # "route" | "rollout" | "retire" | "snapshot" | "deliver_credentials"
    worker_key: str
    detail: str
    at: float
    action_id: str


@dataclass(frozen=True)
class Refusal:
    """A desired worker the reconciler REFUSED to route, with a stable machine code (fail closed)."""

    worker_key: str
    code: str                 # "origin_not_sigil_tt" | "tampered_image" | "unknown_kind" | "snapshot_failed"
    reason: str


@dataclass(frozen=True)
class ReconcileResult:
    """The outcome of one reconcile pass: the new state, the ordered actions, the refusals and the
    snapshots taken. ``disabled`` is True when the DEFAULT-OFF flag is off (the inert result)."""

    disabled: bool
    state: FleetState
    actions: tuple[FleetAction, ...] = ()
    refusals: tuple[Refusal, ...] = ()
    snapshots: tuple[Snapshot, ...] = ()

    def routed_keys(self) -> tuple[str, ...]:
        return tuple(w.key for w in self.state.active())

    def retired_keys(self) -> tuple[str, ...]:
        return tuple(sorted(w.key for w in self.state.workers if w.health == WorkerHealth.RETIRED))

    def golden(self) -> dict:
        """A deterministic, JSON-safe projection used by the flag-off byte-identity test and by auditors.
        Pure function of the result — no wall-clock, no RNG."""
        return {
            "disabled": self.disabled,
            "routed": list(self.routed_keys()),
            "retired": list(self.retired_keys()),
            "actions": [[a.verb, a.worker_key, a.action_id] for a in self.actions],
            "refusals": [[r.worker_key, r.code] for r in self.refusals],
            "snapshots": [[s.worker_key, s.snapshot_id] for s in self.snapshots],
        }


# ==================================================================================================
# The reconciler.
# ==================================================================================================
class FleetReconciler:
    """The declarative AEGIS fleet reconciler: converge the ACTUAL fleet toward the DESIRED state with NO
    operator step. Construct ONCE with the injected dependencies (deterministic); call :meth:`reconcile`
    with the desired workers + the current state + the injected ``now``.

    Guard rails, enforced here:
      * NEVER enforce before AS-29 — constructed with no release source, so :meth:`reconcile` always
        renders observe-only (``self._render`` passes ``release=None``); a worker's enforce env is never
        set, even with BLOCK/RESPOND capabilities.
      * ONLY SIGIL TT origins before AS-2g — a worker whose tenant is not in ``sigil_tt_tenants`` is
        REFUSED (``origin_not_sigil_tt``).
      * PROVE THE IMAGE — a worker whose attested image digest != the AS-28 lock is REFUSED
        (``tampered_image``).
      * RETIRE SNAPSHOT-FIRST — a worker going Off is snapshotted (and the snapshot durably stored)
        BEFORE it is stopped; a failed snapshot REFUSES the retirement."""

    def __init__(self, *, snapshot_sink: SnapshotSink,
                 sigil_tt_tenants: frozenset[str] = SIGIL_TT_TENANTS,
                 ssm_channel: Optional[SsmCredentialChannel] = None,
                 locked_digest: Optional[str] = None,
                 closure_lock: Optional[Path] = None) -> None:
        if not isinstance(snapshot_sink, SnapshotSink):
            raise FleetError("FleetReconciler requires a SnapshotSink")
        self._snapshot_sink = snapshot_sink
        self._sigil_tt_tenants = frozenset(sigil_tt_tenants)
        self._ssm_channel = ssm_channel
        self._delivery = SsmSecretDelivery(ssm_channel) if ssm_channel is not None else None
        # The AS-28 digest lock, resolved ONCE at construction (deterministic). A caller may override it
        # (tests inject a tampered lock); otherwise it is read from the committed saas-closure.json.
        self._locked_digest = locked_digest if locked_digest is not None else locked_image_digest(
            closure_lock=closure_lock)
        # NO release source: AS-29 is unbuilt. This is the structural reason the fleet renders observe-only.
        self._release_source = None

    # -- the one public entrypoint -----------------------------------------------------------------
    def reconcile(self, desired: "list[DesiredWorker]", state: FleetState, *, now: float,
                  hold_keys: "frozenset[str]" = frozenset()) -> ReconcileResult:
        """Converge ``state`` toward ``desired`` at the injected ``now``. DEFAULT-OFF: with the flag off
        this is INERT — it returns a fixed ``disabled`` result and changes nothing (flag-off golden
        byte-identical). Deterministic: the result is a pure function of (desired, state, now, the
        injected deps).

        ``hold_keys`` is the AS-6e rolling seam (default empty — byte-identical to AS-6a when unused): a
        key in ``hold_keys`` is left UNTOUCHED this pass — it is neither converged toward its desired entry
        nor retired for being absent from the desired set. The rolling reconciler
        (:mod:`framework.v2.aegis.aegis_fleet_rolling`) uses it to HOLD a worker whose rollout is over the
        per-tick surge budget, so a staged rollout keeps the held worker on its current, proven placement
        until a later tick admits it — instead of this slice's big-bang (all workers roll at once)."""
        if not fleet_enabled():
            return ReconcileResult(disabled=True, state=state)

        current = state.by_key()
        desired_by_key = {w.key: w for w in sorted(desired, key=lambda w: w.key)}
        new_workers: dict[str, RoutedWorker] = dict(current)
        actions: list[FleetAction] = []
        refusals: list[Refusal] = []
        snapshots: list[Snapshot] = []

        # 1) Drive every desired worker toward its desired mode.
        for key in sorted(desired_by_key):
            if key in hold_keys:
                continue  # AS-6e: held this tick (over the rolling surge budget) — leave it untouched.
            w = desired_by_key[key]
            # Guard rail: only SIGIL TT origins before AS-2g.
            if w.tenant not in self._sigil_tt_tenants:
                refusals.append(Refusal(worker_key=key, code="origin_not_sigil_tt",
                                        reason=f"tenant {w.tenant!r} is not a SIGIL TT origin; before AS-2g "
                                               "no tenant origin is routed"))
                continue
            try:
                worker_kind_spec(w.kind)
            except FleetError as e:
                refusals.append(Refusal(worker_key=key, code="unknown_kind", reason=str(e)))
                continue

            if w.desired_mode == "off":
                self._retire(w, new_workers.get(key), now, actions, snapshots, refusals, new_workers,
                             reason="desired off")
                continue

            # desired_mode == "observe": prove the image, render observe-only, deliver creds, route.
            try:
                verify_image_digest(w.image_digest, locked=self._locked_digest)
            except TamperedImageError as e:
                refusals.append(Refusal(worker_key=key, code="tampered_image", reason=str(e)))
                continue

            rendered = self._render(w, now=now)
            prior = new_workers.get(key)
            # Decide convergence BEFORE delivering credentials. Credential delivery is a real SSM write (a side
            # effect) plus an audit action, so it must NOT run on an already-converged worker whose credentials
            # have already reached a terminal, no-further-work state ("delivered", or the no-op "none"/"deferred").
            # Otherwise a steady HEALTHY fleet would re-push its sealed secrets to SSM and emit a
            # deliver_credentials action on EVERY reconcile tick — breaking the "converged => no action
            # (idempotent, no operator step)" contract and determinism. A prior "refused" delivery is NOT terminal:
            # it falls through below and is retried.
            base_converged = (prior is not None and prior.health in (WorkerHealth.HEALTHY, WorkerHealth.STARTING)
                              and prior.epoch == w.epoch and prior.image_digest == w.image_digest
                              and prior.mode == rendered.mode)
            if base_converged and prior is not None and prior.credential_status in ("delivered", "none", "deferred"):
                continue  # already converged incl. credentials — NO action (idempotent, no operator step)
            cred_status = self._deliver_credentials(w, actions, now)

            verb = "route"
            if prior is not None and prior.health != WorkerHealth.RETIRED and (
                    prior.epoch != w.epoch or prior.image_digest != w.image_digest):
                # A placement change on a live worker is a ROLLOUT: drain the old, place the new (6e seam).
                verb = "rollout"
                actions.append(self._action("rollout", key,
                                            f"drain epoch {prior.epoch} -> place epoch {w.epoch}", now))
            new_workers[key] = RoutedWorker(
                key=key, kind=w.kind, tenant=w.tenant, host=w.host, replica_index=w.replica_index,
                mode=rendered.mode, health=WorkerHealth.STARTING if verb == "rollout" else WorkerHealth.HEALTHY,
                epoch=w.epoch, image_digest=w.image_digest, credential_status=cred_status, routed_at=now)
            actions.append(self._action(verb, key, f"routed {w.kind.value} in {rendered.mode} mode", now))

        # 2) Declarative convergence: any ACTIVE worker not in the desired set is Off -> retire it.
        for key in sorted(current):
            if key in desired_by_key or key in hold_keys:
                continue  # AS-6e: a held worker is NOT "absent from desired" — it is paused, not retired.
            cur = current[key]
            if cur.health == WorkerHealth.RETIRED:
                continue
            self._retire_existing(cur, now, actions, snapshots, refusals, new_workers, reason="absent from desired")

        return ReconcileResult(
            disabled=False, state=FleetState.from_workers(new_workers.values()),
            actions=tuple(actions), refusals=tuple(refusals), snapshots=tuple(snapshots))

    # -- rendering (always observe-only in this slice) ---------------------------------------------
    def _render(self, worker: DesiredWorker, *, now: float) -> RenderedUnit:
        # The reconciler has NO release source (AS-29 unbuilt), so release is always None => observe-only.
        return render_worker(worker, release=self._release_source, now=now)

    # -- credential delivery (SSM only) ------------------------------------------------------------
    def _deliver_credentials(self, worker: DesiredWorker, actions: list[FleetAction], now: float) -> str:
        if not worker.credential_bundles:
            return "none"
        if self._delivery is None:
            return "deferred"  # no SSM channel wired (owner-gated); creds staged, not delivered
        delivered_all = True
        for bundle in worker.credential_bundles:
            receipt = self._delivery.deliver(bundle)
            if not receipt.delivered:
                delivered_all = False
        actions.append(self._action("deliver_credentials", worker.key,
                                    f"{'delivered' if delivered_all else 'refused'} "
                                    f"{len(worker.credential_bundles)} bundle(s) via SSM", now))
        return "delivered" if delivered_all else "refused"

    # -- retire (snapshot FIRST) -------------------------------------------------------------------
    def _retire(self, worker: DesiredWorker, prior: Optional[RoutedWorker], now: float,
                actions: list[FleetAction], snapshots: list[Snapshot], refusals: list[Refusal],
                new_workers: dict[str, RoutedWorker], *, reason: str) -> None:
        if prior is None or prior.health == WorkerHealth.RETIRED:
            # Nothing placed (or already retired): record a desired-off tombstone, no snapshot needed.
            new_workers[worker.key] = RoutedWorker(
                key=worker.key, kind=worker.kind, tenant=worker.tenant, host=worker.host,
                replica_index=worker.replica_index, mode="observe", health=WorkerHealth.RETIRED,
                epoch=worker.epoch, image_digest=worker.image_digest, credential_status="none",
                routed_at=now, snapshot_id="")
            return
        self._retire_existing(prior, now, actions, snapshots, refusals, new_workers, reason=reason)

    def _retire_existing(self, prior: RoutedWorker, now: float, actions: list[FleetAction],
                         snapshots: list[Snapshot], refusals: list[Refusal],
                         new_workers: dict[str, RoutedWorker], *, reason: str) -> None:
        """Retire a placed worker SNAPSHOT-FIRST: snapshot (and durably store it) -> stop -> destroy
        credentials -> RETIRED. If the snapshot cannot be stored the retirement is REFUSED and the worker
        is left DRAINING (never torn down without its state captured)."""
        state_digest = _content_id("worker-state", prior.key, prior.kind.value, prior.epoch,
                                   prior.image_digest, prior.mode, prior.credential_status)
        snap = Snapshot(
            snapshot_id=_content_id("snapshot", prior.key, now, reason, state_digest),
            worker_key=prior.key, taken_at=now, reason=reason, state_digest=state_digest)
        try:
            stored = bool(self._snapshot_sink.store(snap))
        except Exception as e:  # noqa: BLE001 — a sink error is a REFUSED retirement, never a crash/teardown
            stored = False
            _log.warning("retire snapshot sink raised for %s: %s", prior.key, e)
        if not stored:
            refusals.append(Refusal(worker_key=prior.key, code="snapshot_failed",
                                    reason="pre-retirement snapshot could not be stored; retirement refused "
                                           "(snapshot FIRST is inviolable)"))
            new_workers[prior.key] = RoutedWorker(
                key=prior.key, kind=prior.kind, tenant=prior.tenant, host=prior.host,
                replica_index=prior.replica_index, mode=prior.mode, health=WorkerHealth.DRAINING,
                epoch=prior.epoch, image_digest=prior.image_digest,
                credential_status=prior.credential_status, routed_at=prior.routed_at)
            return
        snapshots.append(snap)
        actions.append(self._action("snapshot", prior.key, f"snapshot {snap.snapshot_id} ({reason})", now))
        # stop -> destroy credentials (SSM delete, if a channel is wired) -> RETIRED.
        self._destroy_credentials(prior, actions, now)
        actions.append(self._action("retire", prior.key, f"retired after snapshot ({reason})", now))
        new_workers[prior.key] = RoutedWorker(
            key=prior.key, kind=prior.kind, tenant=prior.tenant, host=prior.host,
            replica_index=prior.replica_index, mode=prior.mode, health=WorkerHealth.RETIRED,
            epoch=prior.epoch, image_digest=prior.image_digest, credential_status="none",
            routed_at=prior.routed_at, snapshot_id=snap.snapshot_id)

    def _destroy_credentials(self, prior: RoutedWorker, actions: list[FleetAction], now: float) -> None:
        # Credential destruction is part of the retirement order (snapshot -> stop -> destroy creds). The
        # real SSM delete is owner-gated; recorded as an action so the retirement order is auditable.
        if prior.credential_status == "delivered":
            actions.append(self._action("destroy_credentials", prior.key, "SSM credentials scheduled for destruction", now))

    # -- deterministic action id -------------------------------------------------------------------
    def _action(self, verb: str, worker_key: str, detail: str, now: float) -> FleetAction:
        return FleetAction(verb=verb, worker_key=worker_key, detail=detail, at=now,
                           action_id=_content_id("action", verb, worker_key, detail, now))


# ==================================================================================================
# Adapter — derive a DesiredWorker from an AS-2a MonitoringAuthorityV2 grant (shows the contract wiring).
# ==================================================================================================
def desired_from_grant(grant: MonitoringAuthorityV2, *, kind: WorkerKind, image_digest: str,
                       now: float, off: bool = False) -> DesiredWorker:
    """Map an AS-2a ``MonitoringAuthorityV2`` grant to a :class:`DesiredWorker`. The desired mode is
    OBSERVE while the grant's lease is live at ``now`` (and ``off`` is not forced), else Off. The grant's
    capabilities ride along, but enforcement is NEVER rendered in this slice (no release — see
    :func:`render_worker`); the epoch and (tenant, host) come straight from the grant."""
    when = datetime.fromtimestamp(float(now), tz=timezone.utc)
    live = grant.lease_active(when) and grant.covers(when) and not off
    return DesiredWorker(
        kind=kind, tenant=grant.subject.org_id, host=grant.subject.host,
        desired_mode="observe" if live else "off",
        capabilities=tuple(grant.capabilities), image_digest=image_digest,
        epoch=int(grant.epoch), replica_index=int(grant.replica_index))
