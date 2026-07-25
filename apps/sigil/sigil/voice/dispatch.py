"""Voice → KERNEL dispatch. Recognized text is routed through the Phase-1 KERNEL (`sigil-kernel
ask`), so a voice request crosses the SAME T0 router + WARDEN gate + signed action log as any
other — voice is just another interface onto the one authorized path. The spoken response is the
KERNEL's answer body (the bracketed [T0…]/[WARDEN…] status lines are stripped)."""
from __future__ import annotations

import logging
import subprocess

from ..config import kernel_bin as _resolve_kernel_bin

_log = logging.getLogger(__name__)

# a clear, actionable message spoken/returned when the kernel binary cannot be resolved — chosen
# over ENOENT-ing on a bare name (which surfaces a confusing generic error) or crashing the loop.
_NO_KERNEL_MSG = ("the SIGIL kernel binary was not found — set SIGIL_KERNEL_BIN, add sigil-kernel "
                  "to PATH, or build kernel/target/release/sigil-kernel.")

# spoken/returned when the resolved kernel binary FAILS its owner-signed integrity pin (audit G2) —
# fail-closed: the binary is NOT run.
_PIN_FAIL_MSG = ("the SIGIL kernel binary failed its owner-signed integrity pin and was NOT run — "
                 "re-pin with `sigil kernel pin` if you changed it on purpose.")


_VOICE_DISABLED_MSG = ("voice control is disabled — re-enable it (owner-signed) from the SIGIL cockpit "
                       "or run `sigil capability voice on`.")


class KernelDispatch:
    def __init__(self, kernel_bin: str | None = None, timeout: int = 60, *,
                 voice_channel: bool = False, store=None):
        # `voice_channel=True` marks THIS dispatch as the live voice pipeline's channel, which alone is
        # gated by the `voice` capability latch. The default (False) leaves the cockpit `/api/ask` box and
        # the phone relay — which build a plain KernelDispatch() and also call send() — UNGATED, so
        # disabling voice control never breaks typed asks. `store` is lazily resolved only when the gate
        # actually needs to read the latch (so /api/ask never constructs a SpineStore for nothing).
        self.voice_channel = voice_channel
        self._store = store
        # resolve via config; keep None (not a bare name) when unresolved so send() fails LOUD. Only a
        # None (unset) kernel_bin falls back to the env-resolved path — an explicit '' is honoured as-is
        # (send() then fails LOUD), so the verified value and the executed value never diverge (symmetry
        # with KernelClassifier: `'' or _resolve()` would have run the UNVERIFIED env binary).
        self.kernel_bin = kernel_bin if kernel_bin is not None else _resolve_kernel_bin()
        self.timeout = timeout
        # G2: verify the resolved binary against the owner-signed pin before it can be `ask`-executed.
        # A pin mismatch / forged manifest → fail-closed (send() returns the LOUD non-run message, never
        # runs the binary). An explicit kernel_bin (trusted caller) bypasses the pin.
        self._pin_blocked = False
        if kernel_bin is None and self.kernel_bin:
            from ..governor.integrity import verify_kernel_bin  # lazy: avoids an import cycle
            verdict = verify_kernel_bin(self.kernel_bin)
            if not verdict.ok:
                self._pin_blocked = True
                _log.error("kernel dispatch refusing to run: %s", verdict.detail)

    def _voice_enabled(self) -> bool:
        """Is the `voice` capability latch enabled? Fail-closed toward DISABLED on any error (so a broken
        store never leaves voice control silently on). Lazily resolves a SpineStore only for the voice
        channel."""
        try:
            store = self._store
            if store is None:
                from ..spine.store import SpineStore
                store = SpineStore()
            from ..governor.capability import CapabilityGate
            return CapabilityGate(store).is_enabled("voice")
        except Exception:  # noqa: BLE001 — cannot resolve the latch ⇒ fail-closed toward disabled
            return False

    # exact KERNEL status-line prefixes to strip (so a legitimate answer line that merely starts
    # with '[' is NOT dropped, and a BLOCKED/error is NOT masked as an answer).
    _STATUS = ("[t0", "[warden", "[blocked", "[direct", "[dispatch")

    def send(self, text: str) -> str:
        text = (text or "").strip()
        if not text:
            return "I didn't catch that."
        if self.voice_channel and not self._voice_enabled():  # governed latch — only the voice channel is gated
            return _VOICE_DISABLED_MSG
        if self._pin_blocked:                         # G2: pin mismatch/forged → never run the binary
            return _PIN_FAIL_MSG
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
