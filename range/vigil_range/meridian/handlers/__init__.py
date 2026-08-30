"""Handler registration for the MERIDIAN target surface.

`build_router()` assembles the full route table. Each slice registers its handlers here so the app stays
one wiring point. S0 ships the base chrome (home, robots, sitemap, health, manifest); later slices add the
records/api/staff/admin/documents/assistant/auth surfaces.
"""

from __future__ import annotations

from ..router import Router
from . import api, authroutes, base, discovery, documents, portal, records, staff


def build_router() -> Router:
    r = Router()
    base.register(r)          # home, robots, sitemap, health, lab-manifest
    records.register(r)       # S1: SQLi + reflected XSS
    documents.register(r)     # S1: path traversal (SSRF/XXE in S3)
    portal.register(r)        # S1: apply + track (stored XSS)
    authroutes.register(r)    # S1: login (weak authn, auth.log) + open redirect; S2: rate-limit hardening
    discovery.register(r)     # S1: .env / actuator env exposure
    api.register(r)           # S2: BOLA/IDOR + CORS + host-header + pay (business logic) + openapi
    staff.register(r)         # S2: broken access control (queue) + BFLA (approve) + priv-esc (role change)
    return r
