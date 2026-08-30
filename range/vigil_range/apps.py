"""Registry of range apps. Today: MERIDIAN. Kept as a registry so future targets are `range/<name>` + a row.

Each app is stdlib-only and exposes a `serve(config, *, hardened, block)` entry point.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .meridian import Config
from .meridian import serve as meridian_serve
from .meridian.config import DEFAULT_CONTROL_PORT, DEFAULT_TARGET_PORT

ServeFn = Callable[..., object]


@dataclass(frozen=True)
class AppSpec:
    name: str
    title: str
    target_port: int
    control_port: int
    serve: ServeFn


REGISTRY: dict[str, AppSpec] = {
    "meridian": AppSpec(
        name="meridian",
        title="MERIDIAN — National Permits & Licensing Authority (fictional)",
        target_port=DEFAULT_TARGET_PORT,
        control_port=DEFAULT_CONTROL_PORT,
        serve=meridian_serve,
    ),
}

DEFAULT_APP = "meridian"


def get(name: str) -> AppSpec:
    try:
        return REGISTRY[name]
    except KeyError:
        known = ", ".join(sorted(REGISTRY))
        raise SystemExit(f"unknown range app '{name}' (known: {known})") from None


__all__ = ["AppSpec", "REGISTRY", "DEFAULT_APP", "get", "Config"]
