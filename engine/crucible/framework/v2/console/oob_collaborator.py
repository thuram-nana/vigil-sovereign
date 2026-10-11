"""
console.oob_collaborator — a per-slug MANAGED out-of-band collaborator registry.

Stands up / probes / tears down the operator-hosted OOB collaborator relay
(``framework.v2.verify.collaborator.RelayServer``, launched via ``collaborator
serve``) as a loopback-bound child process, so the OOB UI can arm an engagement's
blind-callback channel from the front end instead of the operator hand-running the
relay in a terminal. Modelled on ``uiproxy.PlaneControl`` (the single-flight,
MEASURED, never-raises process lifecycle) and the AEGIS gateway's pid + boot_id
single-pointer meta (``console.actions`` ~_aegis_current / _pid_alive), so a child
orphaned by a console/host restart reconciles instead of reading live forever.

INVARIANTS (load-bearing — a regression here is a soundness break, not a bug):

  * **127.0.0.1 ONLY.** The managed relay binds loopback, never ``0.0.0.0``. A
    remote target reaches it through an operator-fronted TLS reverse proxy whose
    ``advertise_url`` is recorded here; THIS process never opens a routable port.

  * **FATAL-2 — never signs an authority.** This module mints only the relay's OWN
    independent collector keypair (public pin material + the private key the relay
    process itself reads). ARMING — binding that collector pubkey into an
    owner-signed engagement authority — is a SOVEREIGN-side ceremony: a LOOPBACK arm
    shells the exec-only ``vigil provision`` (governance-signed inside that
    subprocess, never here), and a REMOTE arm is GUIDE-ONLY (mints nothing).

  * **The poll SECRET never leaves.** It never enters a response body, a log line,
    or an argv. The relay child mints it and writes it to
    ``<slug-dir>/.oob-relay-secret`` (0600, cwd-relative); we read it ONLY to
    health-probe the relay and hand its PATH (never its value) to a launch.
    ``collector.json`` + the secret file are 0600 and PURGED on :func:`stop`.

  * **MEASURED, not asserted.** Liveness is a real ``poll()`` / pid probe plus a
    loopback ``/_poll`` ping; ``armed`` is a real verified-authority read whose
    OOB collector pin must EQUAL this relay's pubkey — never a sticky flag.

  * **Fail-closed.** A spawn that does not bind is terminated and refused; a bad
    slug / advertise URL is refused before anything is spawned; every teardown path
    purges the secret even when the process was already gone.
"""

from __future__ import annotations

import hmac
import json
import os
import re
import secrets
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

from ..common import paths

# A slug is a single path-safe component — the SAME discipline the console's run ids / engagement slugs use
# (alnum plus ``-_.``, no separator, no "..", no leading dot). It names a directory under the state dir, so a
# hostile value must never traverse out of it.
_SLUG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")

# The managed relay is loopback-only, ALWAYS. This is not configurable from a request; it is the invariant.
_HOST = "127.0.0.1"

# Wait-for-bind budget: the child must bind its loopback port AND write its 0600 secret within this window,
# or it is terminated and the start is refused (fail-closed — a relay that never binds must not read "armed").
_START_TIMEOUT_S = 12.0
_PROBE_TIMEOUT_S = 1.5
_TERMINATE_GRACE_S = 5.0

# One coarse module lock serialises start/stop so two clicks (or two browser tabs) cannot race two relays onto
# one slug, nor a stop into a half-finished start. OOB lifecycle is infrequent; a coarse lock is correct here.
_LOCK = threading.Lock()

# Live Popen handles for the relays WE started, keyed by slug. Empty after a console restart — orphan
# reconciliation then falls back to the persisted pid + boot_id meta (exactly as reconcile_orphaned_runs does).
_children: "dict[str, subprocess.Popen]" = {}


# ---------------------------------------------------------------------------
# state-dir layout (mirrors console.actions.console_dir without its runs side effect)
# ---------------------------------------------------------------------------
def _console_dir() -> Path:
    # The SAME ``<v2_root>/.console`` the rest of the console uses, so status/stop and orphan reconcile share
    # state with a future console boot. We do NOT import console.actions.console_dir (that would couple this
    # module to actions at import time); we derive the identical path from the shared paths module.
    return Path(paths.v2_root()) / ".console"


def _oob_root() -> Path:
    d = _console_dir() / "oob"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _safe_slug(slug: str) -> str:
    s = str(slug or "").strip()
    if ".." in s or _SLUG_RE.match(s) is None:
        raise ValueError(f"unsafe oob slug: {slug!r}")
    return s


def _slug_dir(slug: str) -> Path:
    return _oob_root() / _safe_slug(slug)


def _meta_path(slug: str) -> Path:
    return _slug_dir(slug) / "collaborator.json"


def _secret_path(slug: str) -> Path:
    # The relay child writes .oob-relay-secret (0600) into its cwd; we set cwd = the slug dir, so it lands here.
    return _slug_dir(slug) / ".oob-relay-secret"


def _keypair_path(slug: str) -> Path:
    return _slug_dir(slug) / "collector.json"


def _read_meta(slug: str) -> dict:
    try:
        return json.loads(_meta_path(slug).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _write_json_0600(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(data, fh, default=str)
    os.replace(str(tmp), str(path))
    try:
        os.chmod(str(path), 0o600)
    except OSError:
        pass


def _read_secret(slug: str) -> "str | None":
    """The relay's poll secret, read from its 0600 file ONLY for probing / to hand its PATH to a launch. The
    value is never returned to a caller, logged, or put on an argv."""
    try:
        txt = _secret_path(slug).read_text(encoding="utf-8").strip()
        return txt or None
    except OSError:
        return None


# ---------------------------------------------------------------------------
# process liveness (local copies of the actions._boot_id / _pid_alive discipline,
# so this module stays independently importable and free of a console.actions
# import at load time)
# ---------------------------------------------------------------------------
def _boot_id() -> str:
    try:
        return Path("/proc/sys/kernel/random/boot_id").read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def _pid_alive(pid) -> bool:
    try:
        p = int(pid)
    except (TypeError, ValueError):
        return False
    if p <= 0:
        return False
    try:
        reaped, _ = os.waitpid(p, os.WNOHANG)   # reap OUR exited child first, so a zombie does not read alive
        if reaped == p:
            return False
    except ChildProcessError:
        pass                                    # not our child (console restarted) — probe by signal below
    except OSError:
        pass
    try:
        os.kill(p, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True                             # exists but not ours to signal — still alive
    except OSError:
        return False
    return True


def _terminate(pid: int) -> bool:
    """SIGTERM, then SIGKILL after a grace — mirrors uiproxy._terminate / PlaneControl.stop_offense."""
    try:
        os.kill(int(pid), signal.SIGTERM)
    except (ProcessLookupError, PermissionError, TypeError, ValueError):
        return False
    deadline = time.monotonic() + _TERMINATE_GRACE_S
    while time.monotonic() < deadline:
        try:
            os.kill(int(pid), 0)
        except ProcessLookupError:
            return True
        time.sleep(0.1)
    try:
        os.kill(int(pid), signal.SIGKILL)
    except ProcessLookupError:
        pass
    return True


def _meta_alive(slug: str, meta: dict) -> bool:
    """MEASURED liveness: a child WE hold (poll()), else the persisted pid under a boot_id guard (a pid from a
    PRIOR boot is definitively dead regardless of what now holds that number — orphan reconcile)."""
    proc = _children.get(slug)
    if proc is not None:
        return proc.poll() is None
    pid = meta.get("pid")
    if not pid:
        return False
    boot = str(meta.get("boot_id") or "")
    if boot and boot != _boot_id():
        return False
    return _pid_alive(pid)


# ---------------------------------------------------------------------------
# loopback probes
# ---------------------------------------------------------------------------
def _pick_loopback_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((_HOST, 0))
        return int(s.getsockname()[1])
    finally:
        s.close()


def _port_in_use(port) -> bool:
    try:
        with socket.create_connection((_HOST, int(port)), timeout=0.3):
            return True
    except (OSError, ValueError, OverflowError):
        return False


def _probe(port, secret: "str | None") -> bool:
    """True iff the relay answers an AUTHENTICATED poll on loopback right now — i.e. it is bound AND the secret
    we hold matches (the relay returns 200 + ``[]`` for an unknown token, 403 for a bad key). A random probe
    token, so this reads nothing of the operator's real interactions."""
    if not port or not secret:
        return False
    url = f"http://{_HOST}:{int(port)}/_poll/{secrets.token_hex(8)}"
    try:
        req = urllib.request.Request(url, headers={
            "X-Relay-Key": secret, "User-Agent": "OBSIDIAN-oob-probe/1.0",
        })
        with urllib.request.urlopen(req, timeout=_PROBE_TIMEOUT_S) as resp:  # noqa: S310 — loopback only
            return resp.getcode() == 200
    except (urllib.error.URLError, OSError, ValueError):
        return False


def _validate_advertise_url(raw: str) -> "tuple[str, str]":
    """Validate the optional operator-fronted advertise URL (the PUBLIC callback base a remote target hits, in
    front of this loopback relay). Returns ``(url, "")`` or ``("", reason)``. http(s) with a hostname, single
    line, bounded — defence in depth so it can never be mistaken for a flag downstream."""
    url = str(raw or "").strip()
    if not url:
        return "", ""   # optional — a loopback-only arming never needs one
    if len(url) > 2048 or any(ord(c) < 0x20 for c in url):
        return "", "advertise URL must be a single-line http(s) URL ≤2048 chars"
    from urllib.parse import urlsplit
    sp = urlsplit(url)
    if sp.scheme not in ("http", "https") or not sp.hostname:
        return "", "advertise URL must be a full http(s) URL, e.g. https://relay.op.example"
    return url, ""


def _child_env() -> dict:
    """The child env: inherit ours, but PREPEND the ABSOLUTE framework root + vigil_core dir to PYTHONPATH so
    ``python -m framework.v2`` imports the SAME code this console runs REGARDLESS of cwd — we set the child's
    cwd to the slug dir (so .oob-relay-secret lands there), so we cannot anchor framework resolution on cwd the
    way the aegis/benchmark spawns do. Inherited (possibly relative) PYTHONPATH entries are resolved to
    absolute against THIS process's cwd before the spawn, so the cwd change does not break them."""
    env = dict(os.environ)
    extra: list[str] = [str(Path(__file__).resolve().parents[3])]   # …/console/oob_collaborator.py → dir holding framework/
    try:
        import vigil_core as _vc
        extra.append(str(Path(_vc.__file__).resolve().parents[1]))  # the dir that holds the vigil_core package
    except Exception:  # noqa: BLE001 — vigil_core resolves via the inherited env too; this is belt-and-braces
        pass
    for entry in (env.get("PYTHONPATH", "") or "").split(os.pathsep):
        if entry:
            try:
                extra.append(str(Path(entry).resolve()))
            except Exception:  # noqa: BLE001
                extra.append(entry)
    env["PYTHONPATH"] = os.pathsep.join(dict.fromkeys(extra))   # dedup, order-preserving
    return env


def _log_tail(slug: str, n: int = 800) -> str:
    try:
        return (_slug_dir(slug) / "collaborator.log").read_text(encoding="utf-8", errors="replace")[-n:].strip()
    except OSError:
        return ""


def _wait_for_bind(proc: "subprocess.Popen", port: int, slug: str) -> "tuple[bool, str]":
    deadline = time.monotonic() + _START_TIMEOUT_S
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            tail = _log_tail(slug)
            return False, (f"the OOB collaborator exited at startup (rc={proc.returncode})"
                           + (f": {tail}" if tail else ""))
        secret = _read_secret(slug)              # the child writes this 0600 right after it binds
        if secret and _probe(port, secret):
            return True, ""
        time.sleep(0.2)
    return False, f"the OOB collaborator did not bind {_HOST}:{port} within {int(_START_TIMEOUT_S)}s"


# ---------------------------------------------------------------------------
# public API: start / status / stop
# ---------------------------------------------------------------------------
def start(slug: str, advertise_url: "str | None" = None) -> dict:
    """Stand up (or return the already-listening) managed OOB collaborator for ``slug``.

    Mints the relay's independent collector keypair (``collector.json`` 0600), picks an ephemeral loopback
    port, spawns ``collaborator serve --host 127.0.0.1 --port <p> --collector-keypair-file <that>`` with
    ``cwd = <slug-dir>`` (so ``.oob-relay-secret`` lands there 0600), waits for it to BIND + write its secret,
    and returns ``{ok, status:"listening", collector_pubkey, relay_poll_url, advertise_url, port, pid}`` — and
    NEVER the secret. Fail-closed: a bad slug/URL is refused before any spawn; a child that does not bind is
    terminated and the keypair purged. Idempotent: an already-listening relay is returned as-is, not doubled."""
    try:
        slug = _safe_slug(slug)
    except ValueError as e:
        return {"ok": False, "error": str(e)}
    advertise, why = _validate_advertise_url(advertise_url or "")
    if why:
        return {"ok": False, "error": why}

    with _LOCK:
        # Idempotent: a relay already listening for this slug is returned, not re-spawned (no orphan on a
        # double-click). A meta that is present but DEAD/stale is torn down first so we can start cleanly.
        cur = _read_meta(slug)
        if cur and _meta_alive(slug, cur) and _probe(cur.get("port"), _read_secret(slug)):
            return {"ok": True, "status": "listening", "already": True, "slug": slug,
                    "collector_pubkey": cur.get("collector_pubkey", ""), "port": cur.get("port"),
                    "pid": cur.get("pid"), "relay_poll_url": cur.get("relay_poll_url"),
                    "advertise_url": cur.get("advertise_url"),
                    "note": "an OOB collaborator is already listening for this engagement"}
        if cur:
            _kill_and_purge_locked(slug, cur)

        slug_dir = _slug_dir(slug)
        slug_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(str(slug_dir), 0o700)
        except OSError:
            pass

        # The relay's INDEPENDENT collector keypair (VF-2b). PUBLIC material is the pin distributed/armed into
        # the authority; the private key is read ONLY by the relay child from this 0600 file. We never sign an
        # authority with it (FATAL-2) — it is the collector's own receipt-signing key, not governance material.
        from vigil_core import generate_keypair
        kp = generate_keypair()
        _write_json_0600(_keypair_path(slug),
                         {"public_key_b64": kp.public_key_b64, "private_key_b64": kp.private_key_b64})

        # Remove any stale secret so _wait_for_bind blocks on the FRESH one the new child writes (never an old
        # file left by a prior relay — that would let a dead relay read as bound).
        try:
            _secret_path(slug).unlink()
        except OSError:
            pass

        port = _pick_loopback_port()
        cmd = [sys.executable, "-m", "framework.v2", "collaborator", "serve",
               "--host", _HOST, "--port", str(port),
               "--collector-keypair-file", str(_keypair_path(slug))]
        try:
            logf = open(slug_dir / "collaborator.log", "ab")  # noqa: SIM115 — held by the persistent child
            proc = subprocess.Popen(cmd, cwd=str(slug_dir), env=_child_env(),  # noqa: S603
                                    stdout=logf, stderr=subprocess.STDOUT)
        except (OSError, ValueError) as e:
            self_purge(slug)
            return {"ok": False, "error": f"could not launch the OOB collaborator: {type(e).__name__}: {e}"}

        ok, why = _wait_for_bind(proc, port, slug)
        if not ok:
            try:
                _terminate(proc.pid)
            except OSError:
                pass
            self_purge(slug)
            return {"ok": False, "error": why}

        relay_poll_url = f"http://{_HOST}:{port}"
        meta = {"slug": slug, "pid": proc.pid, "boot_id": _boot_id(), "port": port, "host": _HOST,
                "collector_pubkey": kp.public_key_b64, "secret_path": str(_secret_path(slug)),
                "keypair_path": str(_keypair_path(slug)), "relay_poll_url": relay_poll_url,
                "advertise_url": advertise or None, "started": time.time()}
        _write_json_0600(_meta_path(slug), meta)
        _children[slug] = proc
        # Return material SAFE to surface — the PUBLIC collector pubkey, the loopback poll URL, the operator's
        # advertise URL, the port/pid. The poll SECRET is deliberately absent (it stays in its 0600 file).
        return {"ok": True, "status": "listening", "slug": slug, "collector_pubkey": kp.public_key_b64,
                "relay_poll_url": relay_poll_url, "advertise_url": advertise or None,
                "port": port, "pid": proc.pid,
                "note": "OOB collaborator listening on loopback; the poll secret stays in its 0600 file "
                        "(never returned). Arm the engagement to pin this collector pubkey into the authority."}


def status(slug: str) -> dict:
    """MEASURED status for ``slug`` — never a sticky flag. ``running`` is a real poll()/pid probe, ``listening``
    an authenticated loopback ping, and ``armed`` a real read: an installed, owner-signed, threshold-VERIFIED,
    in-window authority for ``slug`` whose ``oob_collector_pubkey`` EQUALS this relay's pubkey. The poll secret
    is never included. An absent/invalid slug is the honest not-running state, never a raise."""
    try:
        slug = _safe_slug(slug)
    except ValueError:
        return {"ok": True, "running": False, "listening": False, "armed": False, "slug": str(slug or "")}
    meta = _read_meta(slug)
    if not meta:
        return {"ok": True, "slug": slug, "running": False, "listening": False, "armed": False}
    port = meta.get("port")
    collector_pubkey = str(meta.get("collector_pubkey") or "")
    running = _meta_alive(slug, meta)
    listening = bool(running and _probe(port, _read_secret(slug)))
    return {
        "ok": True, "slug": slug, "running": bool(running), "listening": listening,
        "pid": meta.get("pid"), "port": port, "host": _HOST,
        "collector_pubkey": collector_pubkey,
        "armed": _is_armed(slug, collector_pubkey),
        "advertise_url": meta.get("advertise_url"), "relay_poll_url": meta.get("relay_poll_url"),
        "secret_path": meta.get("secret_path"), "started": meta.get("started"),
    }


def stop(slug: str) -> dict:
    """Stop the managed collaborator for ``slug`` (SIGTERM→SIGKILL under a poll() guard) and PURGE its secret +
    collector keypair + meta. Idempotent — a no-op process-wise if none is running, but it STILL purges any
    stray 0600 material (fail-closed hygiene). Returns ``{ok, stopped, purged, port, port_freed}``."""
    try:
        slug = _safe_slug(slug)
    except ValueError as e:
        return {"ok": False, "error": str(e)}
    with _LOCK:
        meta = _read_meta(slug)
        stopped = _kill_and_purge_locked(slug, meta)
        port = (meta or {}).get("port")
        purged = [p.name for p in (_secret_path(slug), _keypair_path(slug)) if not p.exists()]
        port_freed = (not port) or (not _port_in_use(port))
        return {"ok": True, "slug": slug, "stopped": stopped, "purged": purged,
                "port": port, "port_freed": port_freed,
                "note": ("stopped and purged" if stopped else "nothing was running; purged any stray material")}


def self_purge(slug: str) -> None:
    """Best-effort purge of the slug's 0600 material + meta (no process signalling). Used on a failed start."""
    for p in (_secret_path(slug), _keypair_path(slug), _meta_path(slug)):
        try:
            p.unlink()
        except OSError:
            pass


def _kill_and_purge_locked(slug: str, meta: dict) -> bool:
    """Terminate the relay (handle first, else persisted pid under the boot_id guard) and purge its secret +
    keypair + meta. Caller holds ``_LOCK``. Returns True iff a live process was signalled."""
    stopped = False
    proc = _children.pop(slug, None)
    if proc is not None and proc.poll() is None:
        try:
            _terminate(proc.pid)
            stopped = True
        except OSError:
            pass
    elif meta:
        pid = meta.get("pid")
        boot = str(meta.get("boot_id") or "")
        if pid and (not boot or boot == _boot_id()) and _pid_alive(pid):
            try:
                _terminate(int(pid))
                stopped = True
            except (OSError, TypeError, ValueError):
                pass
    self_purge(slug)
    return stopped


# ---------------------------------------------------------------------------
# armed = a verified, owner-signed authority for the slug whose OOB pin == this pubkey
# ---------------------------------------------------------------------------
def _authority_oob_pin(slug: str) -> str:
    """The ``oob_collector_pubkey`` of the slug's threshold-VERIFIED, in-window owner-signed authority, or ""
    (no authority / unsigned / out of window / no pin). Same-plane (framework.v2.authority) read, mirroring
    actions._has_verified_authority's load — never fetched from a producer context. Never raises."""
    try:
        import datetime as _dt

        from ..authority.store import load_authority_root, load_verified_authority
        trust_root = load_authority_root()
        if trust_root is None:
            return ""
        doc = load_verified_authority(slug, trust_root)   # raises unless the threshold signature verifies
        now = _dt.datetime.now(_dt.timezone.utc)
        if not (doc.not_before <= now < doc.not_after):
            return ""
        return str(getattr(doc, "oob_collector_pubkey", "") or "")
    except Exception:  # noqa: BLE001 — any load/verify failure is a fail-closed "not pinned"
        return ""


def _is_armed(slug: str, collector_pubkey: str) -> bool:
    """True iff an installed, owner-signed, threshold-verified, in-window authority for ``slug`` pins EXACTLY
    this relay's collector pubkey. The pin equality is the soundness anchor (a DIFFERENT collector's authority
    must not read as arming THIS relay); it is layered on top of the SAME authoritative gate a remote engage
    passes (actions._has_verified_authority — verify + window + owner-pin + live-attestation), so armed status
    never claims more than a launch would accept. Fail-closed on any error."""
    if not collector_pubkey:
        return False
    pin = _authority_oob_pin(slug)
    if not pin or not hmac.compare_digest(pin, collector_pubkey):
        return False
    try:
        from . import actions as _actions
        return bool(_actions._has_verified_authority(slug))
    except Exception:  # noqa: BLE001
        return False
