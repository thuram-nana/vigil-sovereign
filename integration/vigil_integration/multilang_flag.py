"""multilang_flag — the master, default-OFF flag for the multi-language code-scan FACT path (MULTILANG-P1).

``VIGIL_MULTILANG_CODESCAN`` gates the ``LanguagePlugin`` registry dispatch on the FACT-grade code path
(``static_rule_oracle`` + ``codescan._static_rule_for`` / ``_retain_source_region``). It mirrors
``redpen.engine.redpen_enabled`` / ``kernel.metered`` exactly: a KEYLESS, offense-plane ENV read, never a
secret, framework-free (stdlib ``os`` only), so BOTH the framework oracle AND the integration codescan path
can reach it via a thin function-local import without coupling either plane to ``framework`` or to the plugin
package at module scope (FATAL-2).

Default OFF: unset / empty / any value outside ``{1,true,yes,on}`` is OFF. When OFF the FACT path is
BYTE-IDENTICAL to the pre-MULTILANG Python-only path and no ``langplugins`` / ``tree_sitter`` / grammar module
is ever imported — reading this flag imports only THIS stdlib-only module, never the plugin registry.

This module lives OUTSIDE the ``langplugins`` package ON PURPOSE: the OFF path must be able to CHECK the flag
without importing any ``langplugins`` module (I4 asserts, via ``sys.modules``, that no ``langplugins`` /
``tree_sitter`` module is imported when the flag is unset). Only when the flag is ON does a caller go on to
import ``langplugins.registry``.
"""

from __future__ import annotations

import os

MULTILANG_CODESCAN_ENV = "VIGIL_MULTILANG_CODESCAN"
_TRUTHY = frozenset({"1", "true", "yes", "on"})


def multilang_codescan_enabled() -> bool:
    """True iff the multi-language code-scan FACT path is switched on
    (``VIGIL_MULTILANG_CODESCAN`` ∈ {1,true,yes,on}, case-insensitive). Default OFF: unset / empty / any other
    value is OFF, and the FACT path stays byte-identically the Python-only path with no plugin import. Keyless:
    it reads an env flag, never a secret — FATAL-2 clean, mirroring ``redpen_enabled``."""
    return (os.environ.get(MULTILANG_CODESCAN_ENV) or "").strip().lower() in _TRUTHY
