"""
framework.v2.tools — the external host-CLI catalog + live status probe (WS-TOOLS).

Offense-side only (the tools are the offense engine's; the sovereign process must never
import ``framework``). See :mod:`.registry` for the canonical roster shared by
``bootstrap.sh`` (the installer) and the console's ``GET /api/tools`` endpoint (the live
status the UI renders).

The public names re-export lazily (PEP 562) so ``python -m framework.v2.tools.registry``
(bootstrap's roster/state-path bridge) executes the submodule without the parent package
having eagerly imported it first — no ``runpy`` double-import warning, no import-time cost.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

__all__ = [
    "HOST_TOOLS",
    "SANDBOX_IMAGE",
    "SANDBOX_TOOLS",
    "ToolSpec",
    "install_hint",
    "platform_info",
    "probe_tool",
    "probe_tools",
]

if TYPE_CHECKING:  # for type checkers / IDEs only — no runtime import
    from .registry import (  # noqa: F401
        HOST_TOOLS,
        SANDBOX_IMAGE,
        SANDBOX_TOOLS,
        ToolSpec,
        install_hint,
        platform_info,
        probe_tool,
        probe_tools,
    )


def __getattr__(name: str) -> object:
    """Resolve a public name from :mod:`.registry` on first access (PEP 562)."""
    if name in __all__:
        from . import registry
        return getattr(registry, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
