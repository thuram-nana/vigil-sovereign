"""Compatibility shim — CRUCIBLE `evidence.canonical` is now `vigil_core.canonical` (the shared integrity core).

Re-exports the full module namespace (public API + private helpers) so every `from ..evidence.canonical import X`
across the engine keeps resolving against the single source of truth. No integrity primitive is defined twice.
"""
from __future__ import annotations

from vigil_core import canonical as _src

globals().update({_k: _v for _k, _v in vars(_src).items() if not _k.startswith("__")})
del _src
