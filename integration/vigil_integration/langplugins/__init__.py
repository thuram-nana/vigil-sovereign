"""langplugins — the offense-plane ``LanguagePlugin`` registry (MULTILANG-P1, plan §2.1).

The architectural spine for multi-language FACT-grade code scanning: adding a language LATER is a bounded,
additive unit — ``register()`` a plugin, with ZERO edits to the registry, the FACT oracle, the single mint
site, or the certificate. Phase-1 ships ONLY the Python reference plugin (a byte-identical refactor of the
existing Python FACT path) and adds NO new dependency — tree-sitter is a phase-2 concern and is never imported
here.

Import-clean + lazy (FATAL-2): importing this package pulls neither ``framework`` nor ``tree_sitter``. The
Python plugin is registered on FIRST USE of the registry (``registry.for_path`` / ``for_language`` /
``all_extensions``), not at import, and its framework-backed methods import ``framework`` only function-locally
when actually called. The master flag that gates the FACT-path dispatch is ``VIGIL_MULTILANG_CODESCAN`` — read
via :mod:`vigil_integration.multilang_flag`, which lives OUTSIDE this package so the OFF path never imports a
``langplugins`` module.
"""

from __future__ import annotations

from .base import LanguagePlugin, PatternRule
from .registry import all_extensions, for_language, for_path, register

__all__ = [
    "LanguagePlugin",
    "PatternRule",
    "all_extensions",
    "for_language",
    "for_path",
    "register",
]
