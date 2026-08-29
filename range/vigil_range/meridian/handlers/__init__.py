"""Handler registration for the MERIDIAN target surface.

`build_router()` assembles the full route table. Each slice registers its handlers here so the app stays
one wiring point. S0 ships the base chrome (home, robots, sitemap, health, manifest); later slices add the
records/api/staff/admin/documents/assistant/auth surfaces.
"""

from __future__ import annotations

from ..router import Router
from . import base


def build_router() -> Router:
    r = Router()
    base.register(r)
    return r
