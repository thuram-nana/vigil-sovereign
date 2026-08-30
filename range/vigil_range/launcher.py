"""Launch/teardown for the range — loopback bind-guard, pidfile, and process control.

Stricter than VIGIL's own `uiproxy.bind_ok`: a deliberately-vulnerable target must bind LOOPBACK ONLY. A
private/LAN/tunnel address is refused here (exposing a planted-SQLi app to a LAN is exactly the accident this
guard exists to prevent).
"""

from __future__ import annotations

import atexit
import os
import signal
import socket
import sys

from . import apps
from .meridian.config import Config, default_base_dir, is_loopback_host, read_mode

__all__ = ["is_loopback_host", "run_up", "run_down", "run_status"]


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def _read_pidfile(path: str) -> int | None:
    try:
        with open(path, encoding="utf-8") as fh:
            return int(fh.read().strip())
    except (OSError, ValueError):
        return None


def _remove_quietly(path: str) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass


def _port_free(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((host, port))
        except OSError:
            return False
    return True


def run_up(app_name: str, *, base_dir: str | None = None, host: str = "127.0.0.1",
           target_port: int | None = None, control_port: int | None = None,
           hardened: bool = False, no_browser: bool = False) -> int:
    """Bring an app up (blocking, foreground). Returns a process exit code."""
    if not is_loopback_host(host):
        print(f"refusing to bind {host!r}: the range binds LOOPBACK ONLY (try 127.0.0.1).", file=sys.stderr)
        return 2

    spec = apps.get(app_name)
    base = base_dir or default_base_dir()
    tport = target_port or spec.target_port
    cport = control_port or spec.control_port
    config = Config(base_dir=base, target_port=tport, control_port=cport, host="127.0.0.1")
    config.ensure_dirs()

    existing = _read_pidfile(config.pidfile)
    if existing and _pid_alive(existing):
        print(f"{app_name} already running (pid {existing}); run `target down` first.", file=sys.stderr)
        return 3
    for name, port in (("target", tport), ("control", cport)):
        if not _port_free("127.0.0.1", port):
            print(f"port {port} ({name}) is already in use.", file=sys.stderr)
            return 3

    with open(config.pidfile, "w", encoding="utf-8") as fh:
        fh.write(str(os.getpid()))
    atexit.register(lambda: _remove_quietly(config.pidfile))

    mode = "HARDENED" if hardened else "VULNERABLE"
    print("┌────────────────────────────────────────────────────────────────────┐")
    print(f"│  {spec.title}")
    print(f"│  ⚠ INTENTIONALLY VULNERABLE — LAB ONLY   ·   mode: {mode}")
    print(f"│  target portal   →  http://127.0.0.1:{tport}/")
    print(f"│  range control   →  http://127.0.0.1:{cport}/")
    print(f"│  logs            →  {config.logs_dir}")
    print(f"│  charter         →  targets/{app_name}/charter.md")
    print("│  Ctrl-C to stop.")
    print("└────────────────────────────────────────────────────────────────────┘", flush=True)

    if not no_browser:
        _try_open_browser(f"http://127.0.0.1:{cport}/")

    def _term(_signum: int, _frame: object) -> None:
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, _term)
    try:
        spec.serve(config, hardened=hardened, block=True)
    except KeyboardInterrupt:
        pass
    finally:
        _remove_quietly(config.pidfile)
    print("range stopped.")
    return 0


def run_down(app_name: str, *, base_dir: str | None = None) -> int:
    config = Config(base_dir=base_dir or default_base_dir())
    pid = _read_pidfile(config.pidfile)
    if not pid or not _pid_alive(pid):
        print("range is not running.")
        _remove_quietly(config.pidfile)
        return 0
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError as exc:
        print(f"could not stop pid {pid}: {exc}", file=sys.stderr)
        return 1
    print(f"stopped range (pid {pid}).")
    return 0


def run_status(app_name: str, *, base_dir: str | None = None) -> int:
    spec = apps.get(app_name)
    config = Config(base_dir=base_dir or default_base_dir(), target_port=spec.target_port,
                    control_port=spec.control_port)
    pid = _read_pidfile(config.pidfile)
    running = bool(pid and _pid_alive(pid))
    mode = read_mode(config.base_dir)
    print(f"app       : {app_name}")
    print(f"running   : {f'yes (pid {pid})' if running else 'no'}")
    print(f"mode      : {mode}")
    print(f"target    : http://127.0.0.1:{config.target_port}/  ({'up' if not _port_free('127.0.0.1', config.target_port) else 'down'})")
    print(f"control   : http://127.0.0.1:{config.control_port}/  ({'up' if not _port_free('127.0.0.1', config.control_port) else 'down'})")
    print(f"base dir  : {config.base_dir}")
    return 0 if running else 1


def _try_open_browser(url: str) -> None:
    try:
        import webbrowser
        webbrowser.open(url)
    except Exception:
        pass
