"""MERIDIAN — a fictional National Permits & Licensing Authority portal.

The deliberately-vulnerable target half of the VIGIL cyber-range. Every sink has a `vuln` and a `hardened`
behavior keyed on the runtime mode; the hardened twin keeps every route/param and only neutralizes the
sink, so a VIGIL posture re-prove earns a sound CLOSED negative.
"""

from __future__ import annotations

from .app import serve
from .config import Config, default_base_dir

__all__ = ["serve", "Config", "default_base_dir"]
