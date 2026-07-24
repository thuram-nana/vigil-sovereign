"""KernelClassifier (Phase 7, P0.1) — the Python↔Rust WARDEN bridge. The authoritative danger
classifier is Rust `kernel/src/tiers.rs::classify` (token-based, danger-first, fail-closed to A3),
composed with the raise-only registry pins in `Warden::decide`. Python's `Governor` otherwise
TRUSTS a Proposal's declared tier; this bridge lets the mesh DERIVE a tool's tier from that
fail-closed oracle instead of self-declaring it — so an Operator step or a Vision egress hop is
tiered by the same code that enforces at the kernel.

Consulting the kernel is a pure A0 observation (`sigil-kernel classify` writes NO action-log
record). Any failure — missing binary, timeout, non-zero exit, unparseable output, or an unknown
tier string — resolves to **A3** (fail-closed to the most-gated tier), mirroring the Rust
classifier's own posture: never let a bridge error silently downgrade a dangerous tool."""
from __future__ import annotations

import json
import logging
import subprocess

from ..config import kernel_bin as _resolve_kernel_bin
from .base import Tier

_log = logging.getLogger(__name__)
_TIER = {"A0": Tier.A0, "A1": Tier.A1, "A2": Tier.A2, "A3": Tier.A3}


class KernelClassifier:
    def __init__(self, kernel_bin: str | None = None, timeout: int = 15):
        # Resolve ONCE and verify+execute the IDENTICAL value. When unresolved keep None — NEVER a bare
        # PATH name: classify() then fail-closes to A3, so no attacker-planted `sigil-kernel` on PATH can
        # be exec'd at classify time. (Fixes the verify-path ≠ exec-path pin bypass: config.kernel_bin()
        # already resolves via PATH, so a genuine on-PATH kernel is a real path here, not None.)
        resolved = kernel_bin if kernel_bin is not None else _resolve_kernel_bin()
        self.kernel_bin = resolved
        self.timeout = timeout
        # G2: verify the resolved binary against the owner-signed pin BEFORE it can ever be executed. A
        # pin MISMATCH / forged manifest → fail-closed A3 (never runs the binary). An EXPLICIT kernel_bin
        # (tests / a trusted caller) is not the attacker-controlled env path, so it bypasses the pin.
        self._pin_blocked = False
        if kernel_bin is None:
            from ..governor.integrity import verify_kernel_bin  # lazy: keep import light + cycle-free
            verdict = verify_kernel_bin(resolved)              # verify the EXACT value we will execute
            if not verdict.ok:
                self._pin_blocked = True
                _log.error("KernelClassifier refusing to run the kernel: %s", verdict.detail)

    def classify(self, tool: str) -> Tier:
        """Return the WARDEN tier for `tool`. Fail-closed to A3 on ANY error/ambiguity."""
        if not tool or not tool.strip():
            return Tier.A3
        if self._pin_blocked or not self.kernel_bin:
            return Tier.A3           # G2: pin mismatch/forged OR unresolved → never execute → most-gated tier
        try:
            proc = subprocess.run([self.kernel_bin, "classify", tool, "--json"],
                                  capture_output=True, text=True, timeout=self.timeout)
        except (subprocess.SubprocessError, OSError):
            return Tier.A3
        if proc.returncode != 0:
            return Tier.A3
        try:
            data = json.loads(proc.stdout.strip().splitlines()[-1])
        except (ValueError, IndexError):
            return Tier.A3                    # empty / unparseable output → fail-closed
        if not isinstance(data, dict):
            # Non-object JSON (a bare string/number/null/array/bool): `.get` would raise
            # AttributeError and crash the classifier. The documented contract is fail-closed
            # to the MOST-gated tier, so a kernel that emits a non-object resolves to A3.
            return Tier.A3
        return _TIER.get(str(data.get("tier")), Tier.A3)
