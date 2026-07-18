"""Voice → KERNEL dispatch. Recognized text is routed through the Phase-1 KERNEL (`sigil-kernel
ask`), so a voice request crosses the SAME T0 router + WARDEN gate + signed action log as any
other — voice is just another interface onto the one authorized path. The spoken response is the
KERNEL's answer body (the bracketed [T0…]/[WARDEN…] status lines are stripped)."""
from __future__ import annotations

import subprocess
from pathlib import Path


def _default_bin() -> str:
    for p in ("kernel/target/release/sigil-kernel", "kernel/target/debug/sigil-kernel"):
        f = Path("/home/kali/sigil") / p
        if f.exists():
            return str(f)
    return "sigil-kernel"


class KernelDispatch:
    def __init__(self, kernel_bin: str | None = None, timeout: int = 60):
        self.kernel_bin = kernel_bin or _default_bin()
        self.timeout = timeout

    # exact KERNEL status-line prefixes to strip (so a legitimate answer line that merely starts
    # with '[' is NOT dropped, and a BLOCKED/error is NOT masked as an answer).
    _STATUS = ("[t0", "[warden", "[blocked", "[direct", "[dispatch")

    def send(self, text: str) -> str:
        text = (text or "").strip()
        if not text:
            return "I didn't catch that."
        try:
            proc = subprocess.run([self.kernel_bin, "ask", text],
                                  capture_output=True, text=True, timeout=self.timeout)
        except (subprocess.SubprocessError, OSError) as e:
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
