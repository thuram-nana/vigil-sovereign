"""langplugins.registry — the ONE new dispatch point (MULTILANG-P1, plan §2.1).

Every scattered per-language site becomes a thin call into ``for_path(path)`` / ``for_language(id)``. The
registry is PURE / TOTAL / DETERMINISTIC: hostile input must not crash (mirrors buildsys's hostile-repo
totality), and the same inputs always resolve the same plugin.

Lazy bootstrap: the Python reference plugin is registered on FIRST USE (the first ``for_*`` / ``all_extensions``
call), not at import — so importing this module pulls neither ``framework`` nor the plugin's framework-backed
methods. Phase-1 registers ONLY the Python plugin; later phases add a language by ``register()``-ing another
plugin, with ZERO edits here.
"""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from .base import LanguagePlugin

# id -> plugin, and extension -> id. Guarded by a lock so a concurrent first-use bootstrap is race-free.
_BY_ID: "dict[str, LanguagePlugin]" = {}
_BY_EXT: "dict[str, str]" = {}
_LOCK = threading.RLock()
_BOOTSTRAPPED = False


def register(plugin: "LanguagePlugin") -> None:
    """Register ``plugin`` under its canonical id and each of its extensions. Idempotent on id (re-registering
    the same id replaces it). TOTAL: a plugin with a blank/empty id or no extensions is ignored rather than
    corrupting the maps (defensive — a real plugin always carries both)."""
    pid = str(getattr(plugin, "id", "") or "").strip().lower()
    if not pid:
        return
    with _LOCK:
        _BY_ID[pid] = plugin
        for ext in getattr(plugin, "extensions", frozenset()) or frozenset():
            e = str(ext or "").strip().lower()
            if e:
                _BY_EXT[e] = pid


def _ensure_bootstrapped() -> None:
    """Register the built-in plugins on first use (lazy). Importing ``python_plugin`` is framework-free; its
    framework imports are function-local, run only when a FACT-path method is called."""
    global _BOOTSTRAPPED
    if _BOOTSTRAPPED:
        return
    with _LOCK:
        if _BOOTSTRAPPED:
            return
        try:
            from .python_plugin import PythonPlugin  # noqa: PLC0415 — lazy, framework-free at import
            register(PythonPlugin())
        except Exception:  # noqa: BLE001 — a broken plugin must not crash dispatch; it just won't resolve
            pass
        _BOOTSTRAPPED = True


def for_language(language: str) -> "Optional[LanguagePlugin]":
    """The registered plugin for a canonical language id (``"python"``) or a common alias (``"py"``), or
    ``None`` when no plugin is registered for it. ``None`` is the fail-closed answer the FACT oracle treats as
    today's non-Python refuse → a LEAD. TOTAL: any hostile/typed input yields ``None``, never a raise."""
    _ensure_bootstrapped()
    lang = str(language or "").strip().lower()
    if not lang:
        return None
    plugin = _BY_ID.get(lang)
    if plugin is not None:
        return plugin
    # Resolve a common extension-style alias (``py`` -> ``.py`` -> python) so the oracle's ``("python","py")``
    # vocabulary keeps working through the registry without hard-coding aliases here.
    for ext in (lang, "." + lang):
        owner = _BY_EXT.get(ext)
        if owner is not None:
            return _BY_ID.get(owner)
    return None


def for_path(path: str) -> "Optional[LanguagePlugin]":
    """The registered plugin that OWNS ``path`` (by extension), or ``None`` when no registered language claims
    it — the fail-closed answer that keeps a non-``.py`` file a LEAD exactly as today. TOTAL over hostile
    input."""
    _ensure_bootstrapped()
    p = str(path or "")
    if not p:
        return None
    # match on the longest known extension suffix (so ``.tsx`` beats ``.ts`` etc. in later phases).
    low = p.lower()
    best_ext = ""
    for ext in _BY_EXT:
        if low.endswith(ext) and len(ext) > len(best_ext):
            best_ext = ext
    if not best_ext:
        return None
    return _BY_ID.get(_BY_EXT[best_ext])


def all_extensions() -> "frozenset[str]":
    """The UNION of every registered plugin's extensions. Phase-1 this is a SUBSET of
    ``analysis.models.DEFAULT_EXTENSIONS`` (only Python is registered); ``DEFAULT_EXTENSIONS`` stays
    authoritative for the language-agnostic DAA tree-walk until plugins cover every extension (see the plan's
    DEFAULT_EXTENSIONS note — deriving the walk set from the registry in phase-1 would SHRINK it and break the
    multi-lang walk)."""
    _ensure_bootstrapped()
    return frozenset(_BY_EXT)


def _reset_for_tests() -> None:
    """Clear the registry + bootstrap latch (test-only; lets a test re-register a controlled plugin set)."""
    global _BOOTSTRAPPED
    with _LOCK:
        _BY_ID.clear()
        _BY_EXT.clear()
        _BOOTSTRAPPED = False


__all__ = ["register", "for_language", "for_path", "all_extensions"]
