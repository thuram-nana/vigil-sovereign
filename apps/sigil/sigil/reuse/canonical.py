"""Compatibility shim — `sigil.reuse.canonical` is now `vigil_core.canonical` (the shared integrity core).

Re-exports the FULL module namespace (public API + private helpers such as `_head_payload`, `_GENESIS_PREV`,
`_entry_hash`, `_EVIDENCE_DOMAIN`) so every existing `from ..reuse.canonical import X` in SIGIL keeps resolving
against the single source of truth. No integrity primitive is defined twice.
"""
from __future__ import annotations

from vigil_core import canonical as _src

globals().update({_k: _v for _k, _v in vars(_src).items() if not _k.startswith("__")})
del _src
