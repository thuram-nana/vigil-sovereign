"""Voice → KERNEL dispatch. Recognized text is routed through the Phase-1 KERNEL (`sigil-kernel
ask`), so a voice request crosses the SAME T0 router + WARDEN gate + signed action log as any
other — voice is just another interface onto the one authorized path. The spoken response is the
KERNEL's answer body (the bracketed [T0…]/[WARDEN…] status lines are stripped)."""
from __future__ import annotations

import logging
import os
import subprocess

from ..config import kernel_bin as _resolve_kernel_bin

_log = logging.getLogger(__name__)

# a clear, actionable message spoken/returned when the kernel binary cannot be resolved — chosen
# over ENOENT-ing on a bare name (which surfaces a confusing generic error) or crashing the loop.
_NO_KERNEL_MSG = ("the SIGIL kernel binary was not found — set SIGIL_KERNEL_BIN, add sigil-kernel "
                  "to PATH, or build kernel/target/release/sigil-kernel.")


def _default_bin() -> str:
    """Resolve the kernel binary via config (env SIGIL_KERNEL_BIN → package-relative build dir →
    PATH). Kept for `KernelClassifier`, whose doctrine is fail-CLOSED (any error → A3): when the
    binary is unresolved this returns the bare name so its subprocess ENOENTs into that safe path.
    `KernelDispatch` instead fails LOUD (see below) rather than run a bare name."""
    exe = "sigil-kernel.exe" if os.name == "nt" else "sigil-kernel"
    return _resolve_kernel_bin() or exe


class KernelDispatch:
    def __init__(self, kernel_bin: str | None = None, timeout: int = 60):
        # resolve via config; keep None (not a bare name) when unresolved so send() fails LOUD.
        self.kernel_bin = kernel_bin or _resolve_kernel_bin()
        self.timeout = timeout

    # exact KERNEL status-line prefixes to strip (so a legitimate answer line that merely starts
    # with '[' is NOT dropped, and a BLOCKED/error is NOT masked as an answer).
    _STATUS = ("[t0", "[warden", "[blocked", "[direct", "[dispatch")

    def send(self, text: str) -> str:
        text = (text or "").strip()
        if not text:
            return "I didn't catch that."
        if not self.kernel_bin:                       # FAIL LOUD: no bare-name ENOENT, clear message + WARNING log
            _log.warning("kernel dispatch requested but no kernel binary is resolvable")
            return _NO_KERNEL_MSG
        _log.debug("kernel dispatch: %d chars", len(text))
        try:
            proc = subprocess.run([self.kernel_bin, "ask", text],
                                  capture_output=True, text=True, timeout=self.timeout)
        except (subprocess.SubprocessError, OSError) as e:
            _log.warning("kernel unavailable: %s", e)
            return f"the kernel is unavailable ({e})"
        if proc.returncode != 0:
            tail = (proc.stderr or proc.stdout).strip().splitlines()
            return f"that request was refused or errored: {tail[-1][:200]}" if tail else "that request was refused."
        if any(ln.lstrip().lower().startswith("[blocked") for ln in proc.stdout.splitlines()):
            return "that action needs your approval — it wasn't run."
        body = [ln.strip() for ln in proc.stdout.splitlines()
                if ln.strip() and not any(ln.lstrip().lower().startswith(s) for s in self._STATUS)]
        answer = " ".join(body).strip()
        return answer[:600] if answer else "there's no answer for that in memory yet."
