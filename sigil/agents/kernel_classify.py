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
import subprocess

from ..voice.dispatch import _default_bin  # reuse the exact kernel-binary resolution
from .base import Tier

_TIER = {"A0": Tier.A0, "A1": Tier.A1, "A2": Tier.A2, "A3": Tier.A3}


class KernelClassifier:
    def __init__(self, kernel_bin: str | None = None, timeout: int = 15):
        self.kernel_bin = kernel_bin or _default_bin()
        self.timeout = timeout

    def classify(self, tool: str) -> Tier:
        """Return the WARDEN tier for `tool`. Fail-closed to A3 on ANY error/ambiguity."""
        if not tool or not tool.strip():
            return Tier.A3
        try:
            proc = subprocess.run([self.kernel_bin, "classify", tool, "--json"],
                                  capture_output=True, text=True, timeout=self.timeout)
        except (subprocess.SubprocessError, OSError):
            return Tier.A3
        if proc.returncode != 0:
            return Tier.A3
        try:
            data = json.loads(proc.stdout.strip().splitlines()[-1])
            return _TIER.get(str(data.get("tier")), Tier.A3)
        except (ValueError, IndexError, KeyError, TypeError):
            return Tier.A3
