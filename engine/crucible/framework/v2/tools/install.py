"""
tools.install — runtime, on-demand tool provisioning (Phase B2).

When a task needs a profiled-but-missing tool, the operator can install it on demand (or the system ASKS
first). This mirrors ``bootstrap.sh``'s installer but as a bounded, gated, per-tool Python call.

Safety properties (why this can't be abused):
  * ONLY a B1-ADMITTED tool (globally-recognised AND CLI/background-controllable) may be installed — a
    random/unknown/refused name is rejected before anything runs.
  * ONLY the tool's DECLARED install hint from the frozen host roster is used (the ``apt`` package or the
    ``pip`` app) — never a caller-supplied package/command. Every command is a LIST argv (no shell), so a
    package string cannot inject a second command.
  * OPERATOR CONSENT is required: without ``consent=True`` the call returns a ``needs_consent`` ask (the
    "or asks you" path); autonomous code therefore never mutates the host. The console only sets consent
    from a same-origin operator action.
  * HONEST failure: apt that needs root on a non-root/no-sudo host is refused with the manual hint, never a
    silent no-op; the result reflects a live re-probe (real state, not a claim).
Offense-side, host-mutating; issues no network traffic itself beyond the package manager the operator asked
for. Advisory verdicts elsewhere (B1) still gate what may be ADOPTED; this only provisions an adopted tool.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from typing import Callable, Optional

from .profile import build_profiles

_INSTALL_TIMEOUT_S = 300.0


def _profile(name: str) -> Optional[dict]:
    for p in build_profiles().get("profiles", []):
        if p.get("name") == name:
            return p
    return None


def _apt_usable() -> bool:
    """apt can install here iff apt-get exists AND we are root or can sudo (matches bootstrap's APT_OK)."""
    if not shutil.which("apt-get"):
        return False
    try:
        return os.geteuid() == 0 or shutil.which("sudo") is not None
    except AttributeError:      # non-POSIX — no geteuid; treat as not-usable (apt is Debian-only anyway)
        return False


def _plan_argv(p: dict) -> tuple[Optional[list], str]:
    """The DECLARED install command (list argv) for a profile, or (None, why-it-can't). apt preferred when
    usable (matches bootstrap precedence), else pipx, else pip --user. Package name is the roster's own."""
    apt, pip = str(p.get("apt") or ""), str(p.get("pip") or "")
    if apt and _apt_usable():
        base = [] if os.geteuid() == 0 else ["sudo", "-n"]   # -n: never PROMPT for a password in a daemon
        return base + ["apt-get", "install", "-y", apt], "apt"
    if pip:
        if shutil.which("pipx"):
            return ["pipx", "install", pip], "pipx"
        return [sys.executable, "-m", "pip", "install", "--user", pip], "pip"
    if apt and not _apt_usable():
        return None, "needs root/sudo for apt on this host"
    return None, "no declared install method"


def _default_runner(argv: list) -> tuple[int, str]:
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=_INSTALL_TIMEOUT_S)  # noqa: S603
    except subprocess.TimeoutExpired:
        return 124, "install timed out"
    except OSError as e:
        return 127, f"could not launch installer ({type(e).__name__})"
    tail = ((proc.stdout or "") + (proc.stderr or ""))[-1500:]
    return proc.returncode, tail


def install_tool(name: str, *, consent: bool = False,
                 runner: Optional[Callable[[list], tuple]] = None) -> dict:
    """Install ONE B1-admitted, missing tool via its declared hint. Fail-closed + honest; never raises for
    an operator-input problem. Returns a dict with ok/status and, when consent is absent, ``needs_consent``
    + the exact command that WOULD run (the ask-operator path)."""
    name = str(name or "").strip().lower()
    p = _profile(name)
    if p is None:
        return {"ok": False, "name": name, "error": "unknown tool — not in the arsenal (refused)"}
    if not p.get("admitted"):
        # never provision a tool the consciousness gate refused (not recognised / not drivable)
        return {"ok": False, "name": name, "error": f"refused: {p.get('admit_reason', 'not adopted')}"}
    if p.get("installed"):
        return {"ok": True, "name": name, "already_installed": True, "status": p.get("status")}
    argv, method = _plan_argv(p)
    if argv is None:
        return {"ok": False, "name": name,
                "error": f"cannot auto-install ({method}); install manually: {p.get('install_hint', '')}"}
    if not consent:
        # the "or asks you" path — surface the EXACT declared command; run nothing.
        return {"ok": False, "name": name, "needs_consent": True, "method": method,
                "command": " ".join(argv), "install_hint": p.get("install_hint", "")}

    rc, tail = (runner or _default_runner)(argv)
    after = _profile(name) or {}
    installed = bool(after.get("installed"))
    return {"ok": installed, "name": name, "method": method, "rc": rc,
            "installed": installed, "status": after.get("status"),
            "error": "" if installed else f"install did not make {name!r} usable (rc={rc})",
            "output": tail}
