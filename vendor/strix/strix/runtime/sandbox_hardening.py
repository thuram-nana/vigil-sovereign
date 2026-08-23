"""VIGIL S5 — least-privilege hardening for the Strix runtime container.

THE DEFECT THIS CLOSES. The tool-runner path already runs an offense container safely:
``DockerTopologyBackend`` (``integration/vigil_integration/live/external_tool.py``) drops all
caps, sets ``no-new-privileges``, caps memory/cpu/pids, uses a read-only rootfs with a size-capped
``/tmp`` tmpfs, runs as ``nobody``, and REFUSES an image not pinned by ``@sha256`` digest. NONE of
it reached the Strix *agent* container
(``docker_client.StrixDockerSandboxClient._create_container``): it ran with the daemon defaults —
unbounded memory, an unbounded pid table (a fork bomb takes the host down with it), no
``no-new-privileges``, and a MUTABLE image tag a registry retag can repoint at arbitrary bytes
between provisioning and run. And because the SDK container is created *detached* running ``tail
-f /dev/null``, a host process that is ``SIGKILL``ed (the console kill switch signals only the
HOST pid) left the box running forever with nothing to reap it.

WHAT THIS MODULE DOES. Pure dict-in / dict-out transforms over the ``containers.create`` kwargs,
plus a best-effort reaper and an explicit container kill switch that take an INJECTED docker
client (duck- typed, never imported here). Deliberately SDK-FREE and docker-FREE — stdlib only —
for the reason ``vigil_upstream.py`` is: a control whose tests can only ``importorskip`` the SDK
is a control whose tests never run where it matters. Everything here is unit-testable with no
docker daemon and no Agents SDK installed; ``docker_client.py`` is the single SDK-bound caller.

DEFAULT-ON vs OPT-IN (an honest split, not a lazy one). The Strix agent container is long-lived
and its image entrypoint (``docker-entrypoint.sh``) writes to the rootfs and needs root to install
CA trust and start ``caido-cli`` — unlike the throwaway single-tool ``DockerTopologyBackend``
container. Forcing a read-only rootfs or a non-root user by default would break the box, so those
are env OPT-IN. What IS default-on cannot break a legitimate run: ``no-new-privileges`` (except on
the FUSE/SYS_ADMIN branch, which must not be weakened), a generous pids cap (fork-bomb guard), a
Chromium-friendly but bounded ``/dev/shm``, ``--rm``, lifecycle labels and the reaper. A fixed
memory/cpu cap is OPT-IN because a wrong value silently OOM-kills or throttles a legitimate heavy
run on an unknown host.

Plane note (FATAL-2): stdlib only — no ``sigil``, no ``framework``, no ``agents``/``docker``
imports.
"""
from __future__ import annotations

import contextlib
import logging
import os
import re
import time
from pathlib import Path
from typing import Any


logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------------------------------
# Image digest pinning (mirrors A14 / DockerTopologyBackend.require_digest_pin, fail-closed)
# --------------------------------------------------------------------------------------------------

#: Images built FROM THIS REPO. Their provenance is the tree, not a registry, so there is no
#: upstream digest to pin — same rule as ``image_pins.FIRST_PARTY_IMAGE_PREFIXES``.
FIRST_PARTY_IMAGE_PREFIXES = ("vigil-gateway", "vigil/")

#: A digest-pinned ref ends in ``@sha256:`` + 64 lowercase hex — content-addressed, daemon-verified.
_DIGEST_RE = re.compile(r"@sha256:[0-9a-f]{64}$")

#: Loud, explicit escape hatch for a trusted local dev image that is neither first-party nor pinned.
ALLOW_UNPINNED_ENV = "STRIX_ALLOW_UNPINNED_IMAGE"

_TRUE = {"1", "true", "yes", "on"}


def _truthy(value: str | None) -> bool:
    return str(value or "").strip().lower() in _TRUE


def is_runtime_image_acceptable(image: str | None) -> bool:
    """True iff the image is first-party (tree-provenanced) OR pinned by ``@sha256`` digest.

    A bare tag (``ghcr.io/usestrix/strix-sandbox:1.0.0``) is a mutable pointer and is NOT
    acceptable — a registry retag, benign or hostile, would silently change what the agent runs.
    """
    img = str(image or "").strip()
    if not img:
        return False
    if img.startswith(FIRST_PARTY_IMAGE_PREFIXES):
        return True
    return bool(_DIGEST_RE.search(img))


class UnpinnedRuntimeImageError(RuntimeError):
    """Raised when the Strix runtime image is a mutable tag and the operator has not opted out."""


def assert_runtime_image_pinned(image: str | None, *, log: logging.Logger | None = None) -> None:
    """Fail-closed guard: refuse to launch on a mutable-tag runtime image.

    First-party and digest-pinned images pass silently. Anything else RAISES unless
    ``STRIX_ALLOW_UNPINNED_IMAGE`` is set, which proceeds with a loud warning (mirrors the
    ``--allow-ungated-egress`` hatch: the default is refusal, the override is never silent).
    """
    lg = log or logger
    if is_runtime_image_acceptable(image):
        return
    if _truthy(os.environ.get(ALLOW_UNPINNED_ENV)):
        lg.warning(
            "%s is set — launching the Strix sandbox on the UNPINNED image %r. A registry retag "
            "can repoint this tag at arbitrary bytes; pin it as image@sha256:<digest> for a real "
            "guarantee.",
            ALLOW_UNPINNED_ENV, image,
        )
        return
    raise UnpinnedRuntimeImageError(
        f"the Strix runtime image {image!r} is not digest-pinned (@sha256:...) and is not built "
        f"from this repo (vigil/...). A mutable tag can be repointed at arbitrary bytes between "
        f"provisioning and run. Pin it as image@sha256:<digest>, use the first-party "
        f"vigil/strix-sandbox:local, or set {ALLOW_UNPINNED_ENV}=1 for a trusted local dev image."
    )


# --------------------------------------------------------------------------------------------------
# create_kwargs transforms — least privilege on the container itself
# --------------------------------------------------------------------------------------------------


def _security_opt_list(create_kwargs: dict[str, Any]) -> list[str]:
    sec = create_kwargs.setdefault("security_opt", [])
    if not isinstance(sec, list):
        sec = list(sec)
        create_kwargs["security_opt"] = sec
    return sec


def apply_security_hardening(create_kwargs: dict[str, Any], *, privileged: bool) -> None:
    """Add ``no-new-privileges:true`` unless this is the FUSE/SYS_ADMIN branch.

    ``no-new-privileges`` blocks gaining privileges via setuid/file-caps on ``execve`` — cheap
    defence-in-depth that does not remove caps granted at create time. On the FUSE/SYS_ADMIN branch
    the SDK deliberately sets ``apparmor:unconfined`` + ``SYS_ADMIN`` (mount needs it); we must NOT
    weaken that, so we leave it exactly as the SDK built it.
    """
    if privileged:
        return
    sec = _security_opt_list(create_kwargs)
    if not any(str(s).startswith("no-new-privileges") for s in sec):
        sec.append("no-new-privileges:true")


def apply_resource_limits(create_kwargs: dict[str, Any]) -> None:
    """Cap the container's host footprint.

    Default-ON (generous, bounded, override-able):
      * ``pids_limit`` — a fork bomb cannot exhaust the host pid table. Default 4096 (an agent +
        Chromium + concurrent tools stays well under). ``STRIX_SANDBOX_PIDS_LIMIT`` overrides;
        ``0``/``off`` disables.
      * ``shm_size`` — docker's 64m default crashes Chromium; 1g gives room while bounding
        ``/dev/shm``. ``STRIX_SANDBOX_SHM_SIZE`` overrides; ``0``/``off`` reverts to the default.

    OPT-IN (env only; unset => docker default = unbounded) — a fixed cap risks OOM-killing or
    throttling a legitimate heavy run on an unknown host, so the operator sets these per host:
      * ``STRIX_SANDBOX_MEM_LIMIT`` -> ``mem_limit``
      * ``STRIX_SANDBOX_CPUS`` -> ``nano_cpus``
    """
    mem_limit = os.environ.get("STRIX_SANDBOX_MEM_LIMIT", "").strip()
    if mem_limit:
        create_kwargs["mem_limit"] = mem_limit

    cpus = os.environ.get("STRIX_SANDBOX_CPUS", "").strip()
    if cpus:
        with contextlib.suppress(ValueError, OverflowError):
            nano_cpus = int(float(cpus) * 1_000_000_000)
            if 0 < nano_cpus <= 2**63 - 1:
                create_kwargs["nano_cpus"] = nano_cpus

    pids = os.environ.get("STRIX_SANDBOX_PIDS_LIMIT", "").strip()
    if pids.lower() not in ("0", "off", "none", "unlimited"):
        try:
            create_kwargs["pids_limit"] = int(pids) if pids else 4096
        except ValueError:
            create_kwargs["pids_limit"] = 4096

    shm = os.environ.get("STRIX_SANDBOX_SHM_SIZE", "").strip()
    if shm.lower() not in ("0", "off", "none"):
        create_kwargs["shm_size"] = shm or "1g"


def apply_optional_isolation(create_kwargs: dict[str, Any]) -> None:
    """OPT-IN read-only rootfs and non-root user, for an operator who has hardened the image.

    Default OFF: the vendored strix-sandbox image's entrypoint writes to the rootfs and needs root
    to install CA trust and start caido; forcing these on breaks the box without an image rework.
    Enable per deployment once the image tolerates it:
      * ``STRIX_SANDBOX_READ_ONLY=1`` -> read-only rootfs + a size-capped ``/tmp`` tmpfs
        (``STRIX_SANDBOX_TMPFS_SIZE``, default 256m).
      * ``STRIX_SANDBOX_USER=nobody`` (or ``65534:65534``) -> run as that user.
    """
    if _truthy(os.environ.get("STRIX_SANDBOX_READ_ONLY")):
        create_kwargs["read_only"] = True
        tmpfs = create_kwargs.setdefault("tmpfs", {})
        if isinstance(tmpfs, dict):
            size = os.environ.get("STRIX_SANDBOX_TMPFS_SIZE", "").strip() or "256m"
            tmpfs.setdefault("/tmp", f"rw,size={size}")  # noqa: S108 - container mount, not host

    user = os.environ.get("STRIX_SANDBOX_USER", "").strip()
    if user:
        create_kwargs["user"] = user


# --------------------------------------------------------------------------------------------------
# Lifecycle: --rm + labels so a SIGKILLed run cannot strand a container, and a reaper/kill switch
# --------------------------------------------------------------------------------------------------

#: Every container VIGIL creates carries these labels so the reaper and kill switch can find it even
#: after the process that created it is gone (its in-memory session cache died with it).
LABEL_MANAGED = "vigil.strix.managed"
LABEL_OWNER_PID = "vigil.strix.owner_pid"
LABEL_OWNER_BOOT = "vigil.strix.owner_boot"
LABEL_SESSION = "vigil.strix.session_id"
LABEL_CREATED = "vigil.strix.created"

#: Disable ``--rm`` (auto-remove on stop) for post-mortem debugging of a crashed container.
KEEP_CONTAINER_ENV = "STRIX_SANDBOX_KEEP_CONTAINER"


def owner_boot_id() -> str:
    """This boot's id (Linux). Containers labelled with a DIFFERENT boot id are definitively
    orphaned (those pids died at reboot), so a host crash/reboot is reaped even if a pid was reused.
    Empty on platforms without the file — the reaper then falls back to pid liveness only."""
    try:
        return Path("/proc/sys/kernel/random/boot_id").read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def pid_alive(pid: int) -> bool:
    """Whether ``pid`` names a live process. ``os.kill(pid, 0)`` — never ``waitpid`` — so this only
    probes, never reaps. ``PermissionError`` means it exists, owned by someone else (alive)."""
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    else:
        return True


def apply_run_labels(create_kwargs: dict[str, Any], *, session_id: Any = None) -> None:
    """Label the container with its owner (pid + boot) and add ``--rm`` (auto-remove on stop).

    ``--rm`` reaps the container when it stops cleanly; the labels let
    :func:`reap_orphan_containers` reap the case ``--rm`` cannot — a container whose owner was
    ``SIGKILL``ed while it was still running ``tail -f /dev/null`` (nothing stops it, so nothing
    auto-removes it)."""
    labels = create_kwargs.setdefault("labels", {})
    if not isinstance(labels, dict):
        # docker-py also accepts a list of "k=v" or "k"; normalise to a dict.
        normalised: dict[str, str] = {}
        for item in labels:
            k, sep, v = str(item).partition("=")
            normalised[k] = v if sep else ""
        labels = normalised
        create_kwargs["labels"] = labels
    labels[LABEL_MANAGED] = "1"
    labels[LABEL_OWNER_PID] = str(os.getpid())
    labels[LABEL_OWNER_BOOT] = owner_boot_id()
    labels[LABEL_CREATED] = str(int(time.time()))
    if session_id is not None:
        labels[LABEL_SESSION] = getattr(session_id, "hex", None) or str(session_id)

    if not _truthy(os.environ.get(KEEP_CONTAINER_ENV)):
        create_kwargs["auto_remove"] = True


def apply_all(create_kwargs: dict[str, Any], *, session_id: Any = None) -> None:
    """Apply every create-time hardening transform in one call.

    Detects the FUSE/SYS_ADMIN branch from the (already fully populated) caps/security_opt so it is
    not weakened, then layers on no-new-privileges, resource caps, opt-in isolation, and lifecycle
    labels. Call AFTER all cap/security_opt/network injection so privileged detection sees the final
    set.
    """
    caps = create_kwargs.get("cap_add") or []
    sec = create_kwargs.get("security_opt") or []
    privileged = ("SYS_ADMIN" in caps) or any("apparmor" in str(s) for s in sec)
    apply_security_hardening(create_kwargs, privileged=privileged)
    apply_resource_limits(create_kwargs)
    apply_optional_isolation(create_kwargs)
    apply_run_labels(create_kwargs, session_id=session_id)


# --- reaper / kill switch (INJECTED docker client, duck-typed) ---------------------------------


def _list_managed(docker_client: Any, extra_labels: list[str] | None = None) -> list[Any]:
    labels = [f"{LABEL_MANAGED}=1", *(extra_labels or [])]
    try:
        return list(docker_client.containers.list(all=True, filters={"label": labels}))
    except Exception as exc:  # noqa: BLE001 — a broken/absent daemon must not raise into a launch
        logger.debug("could not list managed containers: %s: %s", type(exc).__name__, exc)
        return []


def _force_remove(container: Any) -> bool:
    try:
        container.remove(force=True)
    except Exception as exc:  # noqa: BLE001 — best-effort teardown
        logger.debug("could not remove container %r: %s: %s",
                     getattr(container, "id", "?"), type(exc).__name__, exc)
        return False
    else:
        return True


def _labels_of(container: Any) -> dict[str, str]:
    labels = getattr(container, "labels", None)
    if isinstance(labels, dict):
        return labels
    attrs = getattr(container, "attrs", None) or {}
    cfg = attrs.get("Config", {}) if isinstance(attrs, dict) else {}
    got = cfg.get("Labels") if isinstance(cfg, dict) else None
    return got if isinstance(got, dict) else {}


def _is_orphan(labels: dict[str, str], *, current_pid: int, current_boot: str) -> bool:
    """A managed container is an orphan when its owning process is gone.

    Conservative on uncertainty: if ownership cannot be read, DON'T reap — falsely reaping a live
    run's container is far worse than leaving one to the next launch. (Opposite trade-off from the
    digest-pin GATE, which denies on uncertainty; here the safe default is to spare, not to kill.)
    """
    owner_boot = labels.get(LABEL_OWNER_BOOT, "")
    # A container from a different boot cannot have a live owner (all those pids died at reboot).
    if current_boot and owner_boot and owner_boot != current_boot:
        return True
    try:
        owner_pid = int(labels.get(LABEL_OWNER_PID, ""))
    except (TypeError, ValueError):
        return False
    if owner_pid == current_pid:
        return False  # ours, still running
    return not pid_alive(owner_pid)


def reap_orphan_containers(docker_client: Any, *, log: logging.Logger | None = None) -> int:
    """Best-effort: remove managed containers whose owning process is dead or from a prior boot.

    Called at the start of each new launch, so a run that was ``SIGKILL``ed (leaving its detached
    ``tail -f /dev/null`` container running with nothing to stop it) is cleaned up by the next run.
    Never raises — a launch must not fail because reaping did."""
    lg = log or logger
    current_pid = os.getpid()
    current_boot = owner_boot_id()
    reaped = 0
    for container in _list_managed(docker_client):
        labels = _labels_of(container)
        orphan = _is_orphan(labels, current_pid=current_pid, current_boot=current_boot)
        if orphan and _force_remove(container):
            reaped += 1
            cid = getattr(container, "short_id", getattr(container, "id", "?"))
            lg.info("reaped orphaned Strix container %s (owner gone)", cid)
    return reaped


def kill_scan_container(
    docker_client: Any, session_id: Any, *, log: logging.Logger | None = None
) -> int:
    """Container-level kill switch: force-remove the container(s) for ``session_id``, independent of
    the host process. Complements the console kill switch, which signals only the HOST pid. Returns
    the number removed. Never raises."""
    lg = log or logger
    sid = getattr(session_id, "hex", None) or str(session_id)
    removed = 0
    for container in _list_managed(docker_client, [f"{LABEL_SESSION}={sid}"]):
        if _force_remove(container):
            removed += 1
    if removed:
        lg.info("kill switch removed %d Strix container(s) for session %s", removed, sid)
    return removed


def kill_containers_for_owner(
    docker_client: Any,
    *,
    owner_pid: Any,
    owner_boot: str | None = None,
    log: logging.Logger | None = None,
) -> int:
    """S10 kill switch by OWNER pid — force-remove the managed container(s) an owning process spawned.

    This is the cross-process complement to :func:`kill_scan_container` (which needs the SDK
    ``session_id``, known only inside the spawning process). The VIGIL console, a SEPARATE process,
    holds only the host pid it recorded and the boot id — never the sandbox session id — so after its
    kill switch ``SIGKILL``s that host pid it reaps the stranded container by the ``LABEL_OWNER_PID``
    the container carries.

    Unlike :func:`reap_orphan_containers`, this does NOT gate on pid liveness: the caller has already
    decided this owner's container must die (the console just killed that owner, or this very process
    is tearing itself down in a signal handler where its own pid is still alive). When ``owner_boot``
    is given a container is removed only if its boot label ALSO matches, so a recycled pid from a
    different boot is never mistaken for the target. Returns the number removed. Never raises.
    """
    lg = log or logger
    try:
        pid_s = str(int(owner_pid))
    except (TypeError, ValueError):
        return 0
    if int(pid_s) <= 0:
        return 0
    boot = str(owner_boot) if owner_boot else ""
    removed = 0
    for container in _list_managed(docker_client, [f"{LABEL_OWNER_PID}={pid_s}"]):
        if boot and _labels_of(container).get(LABEL_OWNER_BOOT, "") != boot:
            continue  # same pid number, different boot — not the container we mean
        if _force_remove(container):
            removed += 1
    if removed:
        lg.info("kill switch removed %d Strix container(s) for owner pid %s", removed, pid_s)
    return removed
