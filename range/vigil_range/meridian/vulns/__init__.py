"""The planted-vulnerability registry — the single source of truth for what MERIDIAN plants and why."""

from __future__ import annotations

from .registry import VULNS, Vuln, by_id

__all__ = ["VULNS", "Vuln", "by_id"]
