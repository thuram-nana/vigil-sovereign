"""Per-scan sandbox session lifecycle."""

from __future__ import annotations

import logging
import os
import shutil
from pathlib import Path
from typing import Any

from agents.sandbox.entries import BaseEntry, LocalDir
from agents.sandbox.manifest import Environment, Manifest

from strix.config import load_settings
from strix.runtime import sandbox_hardening
from strix.runtime.backends import get_backend
from strix.runtime.caido_bootstrap import bootstrap_caido
from strix.runtime.local_dir_staging import stage_symlink_safe_dir


logger = logging.getLogger(__name__)


# In-container Caido sidecar port (matches the image's caido-cli bind).
_CONTAINER_CAIDO_PORT = 48080


_SESSION_CACHE: dict[str, dict[str, Any]] = {}

# Manifest root inside the container; entry keys hang off this path.
_WORKSPACE_ROOT = "/workspace"


def build_session_entries(
    local_sources: list[dict[str, Any]],
) -> tuple[dict[str | Path, BaseEntry], list[dict[str, Any]], list[Path]]:
    """Split local sources into copied manifest entries and host bind mounts.

    Sources flagged ``mount`` are bind-mounted read-only at
    ``/workspace/<workspace_subdir>`` (not added to the manifest, so the SDK
    does not stream them in file-by-file). Every other source becomes a
    ``LocalDir`` entry copied into the container as before. Trees containing
    symlinks (which the SDK's ``LocalDir`` walker refuses outright) are first
    staged into a symlink-safe temp copy; those temp dirs are returned so the
    caller can remove them once the upload completes.
    """
    entries: dict[str | Path, BaseEntry] = {}
    bind_mounts: list[dict[str, Any]] = []
    staged_dirs: list[Path] = []
    for src in local_sources:
        ws_subdir = src.get("workspace_subdir") or ""
        host_path = src.get("source_path") or ""
        if not ws_subdir or not host_path:
            continue
        resolved = Path(host_path).expanduser().resolve()
        if src.get("mount"):
            bind_mounts.append(
                {
                    "source": str(resolved),
                    "target": f"{_WORKSPACE_ROOT}/{ws_subdir}",
                    "read_only": True,
                }
            )
        else:
            upload_path, staged = stage_symlink_safe_dir(resolved)
            if staged is not None:
                staged_dirs.append(staged)
            entries[ws_subdir] = LocalDir(src=upload_path)
    return entries, bind_mounts, staged_dirs


async def create_or_reuse(
    scan_id: str,
    *,
    image: str,
    local_sources: list[dict[str, Any]],
) -> dict[str, Any]:
    """Return the existing session bundle for ``scan_id`` or create a new one.

    Each ``local_sources`` entry exposes its host ``source_path`` at
    ``/workspace/<workspace_subdir>`` inside the container — copied in, or
    bind-mounted read-only when the entry is flagged ``mount``.
    """
    cached = _SESSION_CACHE.get(scan_id)
    if cached is not None:
        logger.info("Reusing existing sandbox session for scan %s", scan_id)
        return cached

    entries, bind_mounts, staged_dirs = build_session_entries(local_sources)

    # Caido runs as an in-container sidecar; HTTP(S) traffic from any
    # process started via ``session.exec`` (the SDK's Shell tool, etc.)
    # picks up these env vars automatically. ``NO_PROXY`` keeps the
    # agent-browser CDP daemon's localhost traffic from looping back
    # through Caido.
    container_caido_url = f"http://127.0.0.1:{_CONTAINER_CAIDO_PORT}"
    manifest = Manifest(
        entries=entries,
        environment=Environment(
            value={
                "PYTHONUNBUFFERED": "1",
                "HOST_GATEWAY": "host.docker.internal",
                "http_proxy": container_caido_url,
                "https_proxy": container_caido_url,
                "ALL_PROXY": container_caido_url,
                "NO_PROXY": "localhost,127.0.0.1",
            },
        ),
    )

    backend_name = load_settings().runtime.backend
    backend = get_backend(backend_name)

    logger.info(
        "Creating sandbox session for scan %s (backend=%s, image=%s)",
        scan_id,
        backend_name,
        image,
    )
    try:
        client, session = await backend(
            image=image,
            manifest=manifest,
            exposed_ports=(_CONTAINER_CAIDO_PORT,),
            bind_mounts=bind_mounts,
        )
    finally:
        for staged in staged_dirs:
            shutil.rmtree(staged, ignore_errors=True)

    caido_endpoint = await session.resolve_exposed_port(_CONTAINER_CAIDO_PORT)
    scheme = "https" if caido_endpoint.tls else "http"
    host_caido_url = f"{scheme}://{caido_endpoint.host}:{caido_endpoint.port}"
    logger.debug("Caido host endpoint resolved: %s", host_caido_url)

    caido_client = await bootstrap_caido(
        session,
        host_url=host_caido_url,
        container_url=container_caido_url,
    )

    bundle = {
        "client": client,
        "session": session,
        "caido_client": caido_client,
    }
    _SESSION_CACHE[scan_id] = bundle
    logger.info("Sandbox session for scan %s ready and cached", scan_id)
    return bundle


async def cleanup(scan_id: str) -> None:
    """Tear down ``scan_id``'s container and drop its cache entry.

    Best-effort: any error during ``client.delete`` is logged and
    swallowed. We never want a cleanup failure to prevent the next
    scan from starting; the worst case is a stranded container that
    Docker's normal reaping will catch on next ``docker prune``.
    """
    bundle = _SESSION_CACHE.pop(scan_id, None)
    if bundle is None:
        logger.debug("cleanup(%s): no cached session", scan_id)
        return

    caido_client = bundle.get("caido_client")
    if caido_client is not None:
        try:
            await caido_client.aclose()
        except Exception:  # noqa: BLE001
            logger.debug("cleanup(%s): caido_client.aclose() raised", scan_id, exc_info=True)

    client = bundle["client"]
    try:
        await client.delete(bundle["session"])
        logger.info("Cleaned up sandbox session for scan %s", scan_id)
    except Exception:
        logger.exception(
            "cleanup(%s): client.delete raised; container may need manual reaping",
            scan_id,
        )

    docker_client = getattr(client, "docker_client", None)
    if docker_client is not None:
        # S5 defence-in-depth: while we still hold a live docker client, reap any container a
        # SIBLING run stranded by being SIGKILLed. Best-effort; never raises.
        sandbox_hardening.reap_orphan_containers(docker_client, log=logger)
        try:
            docker_client.close()
        except Exception:  # noqa: BLE001
            logger.debug("cleanup(%s): docker_client.close() raised", scan_id, exc_info=True)


async def kill_run(scan_id: str) -> int:
    """Container-level kill switch for ``scan_id`` — S5.

    The console kill switch (``cancel_run``) signals only the HOST process pid; the detached
    sandbox container it spawned keeps running ``tail -f /dev/null`` unless something removes it.
    This force-removes the container(s) for the run directly (addressed by the
    ``vigil.strix.session_id`` label), independent of any host pid, then drops the cached session so
    a later reuse cannot hand back a dead handle. Returns the number removed. Never raises.

    NOTE: this addresses the SAME-PROCESS kill (the CLI/console that spawned the run is still
    alive). A run whose host process was hard-``SIGKILL``ed loses this in-memory cache with it; that
    case is covered by :func:`sandbox_hardening.reap_orphan_containers`, which the NEXT launch runs.
    """
    bundle = _SESSION_CACHE.get(scan_id)
    removed = 0
    if bundle is not None:
        client = bundle.get("client")
        docker_client = getattr(client, "docker_client", None)
        state = getattr(getattr(bundle.get("session"), "_inner", None), "state", None)
        session_id = getattr(state, "session_id", None)
        if docker_client is not None and session_id is not None:
            removed = sandbox_hardening.kill_scan_container(docker_client, session_id, log=logger)
    await cleanup(scan_id)
    return removed


def kill_run_sync(scan_id: str) -> int:
    """SYNCHRONOUS container teardown for a SIGNAL handler — S10.

    The SIGINT/SIGTERM/SIGHUP handler in ``strix/interface/cli.py`` runs in the main thread and
    CANNOT ``await``; the async :func:`cleanup` / :func:`kill_run` paths need the running event loop
    (which the signal is tearing down). Before this, a signalled run destroyed its report state but
    left its detached sandbox container running ``tail -f /dev/null`` — the exact strand the reaper
    exists to catch, but only on the NEXT launch.

    This tears the container down NOW, synchronously, from the same process that spawned it (so the
    in-memory session cache is live): force-remove by the SDK session label when it is readable,
    else — because the label read reaches into SDK internals — fall back to removing by THIS process's
    own owner-pid label (``kill_containers_for_owner``); then reap any sibling orphan and close the
    docker client. It never touches the event loop, never awaits, and never raises: a teardown
    failure must not stop the process from exiting. Returns the number of containers removed.
    """
    bundle = _SESSION_CACHE.pop(scan_id, None)
    if bundle is None:
        return 0
    removed = 0
    client = bundle.get("client")
    docker_client = getattr(client, "docker_client", None)
    if docker_client is None:
        return 0
    try:
        state = getattr(getattr(bundle.get("session"), "_inner", None), "state", None)
        session_id = getattr(state, "session_id", None)
        if session_id is not None:
            removed = sandbox_hardening.kill_scan_container(docker_client, session_id, log=logger)
        if removed == 0:
            # Session id unreadable (or already gone): this very process owns the container, and its
            # pid is still alive inside the handler, so reap_orphan_containers would SPARE it. Remove
            # by our own owner-pid label instead — unconditional, exactly what the console does to us.
            removed = sandbox_hardening.kill_containers_for_owner(
                docker_client,
                owner_pid=os.getpid(),
                owner_boot=sandbox_hardening.owner_boot_id(),
                log=logger,
            )
        sandbox_hardening.reap_orphan_containers(docker_client, log=logger)
    except Exception:  # noqa: BLE001 — a signal handler must never raise
        logger.debug("kill_run_sync(%s): teardown raised", scan_id, exc_info=True)
    finally:
        try:
            docker_client.close()
        except Exception:  # noqa: BLE001
            logger.debug("kill_run_sync(%s): docker_client.close() raised", scan_id, exc_info=True)
    return removed
