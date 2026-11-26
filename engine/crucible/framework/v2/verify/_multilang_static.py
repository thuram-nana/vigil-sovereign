"""Isolated multilang static-rule dispatch (MULTILANG-P1).

This lives OUTSIDE ``static_rule_oracle``'s re-execution closure on purpose: re-firing a Python
``STATIC_RULE`` certificate must stay stdlib-only and offline-re-verifiable
(``integration/tests/test_general_reexecutable.py``). The flag read is a pure ``os.environ`` lookup
(stdlib), and the ONLY non-stdlib import — the offense-plane ``langplugins`` registry — is lazy here
and reached ONLY on the flag-ON path, never on the Python offline-re-verification path.

FATAL-2: the ``vigil_integration`` import is function-local; the sovereign leg never imports this
module (it sits under the framework verify layer, which that leg does not load).
"""

from __future__ import annotations

import os
from typing import Any

# Mirrors ``vigil_integration.multilang_flag``'s truthy set, kept here (stdlib-only) so the oracle's
# re-execution needs no ``vigil_integration`` import merely to read the default-OFF flag.
_TRUTHY = frozenset({"1", "true", "yes", "on"})
_FLAG_ENV = "VIGIL_MULTILANG_CODESCAN"


def multilang_enabled() -> bool:
    """True iff the default-OFF ``VIGIL_MULTILANG_CODESCAN`` flag is set (pure stdlib ``os.environ`` read)."""
    return os.environ.get(_FLAG_ENV, "").strip().lower() in _TRUTHY


def multilang_dispatch(language: str) -> "tuple[bool, Any]":
    """Return ``(machinery_available, plugin_or_None)`` for ``language``.

    Reached only when the flag is ON. Lazily imports the offense-plane LanguagePlugin registry; if that
    machinery is unavailable, returns ``(False, None)`` so the caller degrades to the byte-identical
    Python-only legacy path. Never raises.
    """
    try:
        from vigil_integration.langplugins import registry as _lp_registry  # noqa: PLC0415 (FATAL-2: framework-free offense plugin)
    except Exception:  # noqa: BLE001 — plugin machinery unavailable ⇒ degrade to the Python-only path
        return (False, None)
    try:
        return (True, _lp_registry.for_language(language))
    except Exception:  # noqa: BLE001 — never raise out of the oracle
        return (False, None)
