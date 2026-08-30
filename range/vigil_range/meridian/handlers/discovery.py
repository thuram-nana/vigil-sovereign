"""Exposure decoys — a leaked `.env` and a Spring-style `/actuator/env`.

Vuln mode serves a (FAKE) secret-bearing body with the signature the exposure oracle keys on; hardened mode
returns 404. Every value here is fabricated — the point is the SIGNATURE, not a usable secret.
"""

from __future__ import annotations

from ..router import Ctx, Response, Router

# A leaked application .env — fabricated values in the shapes a secret scanner / exposure oracle matches.
_DOTENV = (
    "# MERIDIAN application environment (LAB DECOY — all values fabricated)\n"
    "APP_ENV=production\n"
    "DB_HOST=127.0.0.1\n"
    "DB_NAME=meridian\n"
    "DB_USER=meridian_app\n"
    "DB_PASSWORD=Sup3rSecret-LAB-DECOY-not-real\n"
    "SECRET_KEY=lab-decoy-3f9c1e77aa41b0c2d5e6f7081920abcd\n"
    "JWT_SECRET=meridian-hs256-lab-decoy\n"
)

# A Spring-Boot-style actuator env dump — the `propertySources` signature + a fake datasource password.
_ACTUATOR_ENV = {
    "activeProfiles": ["production"],
    "propertySources": [
        {"name": "systemEnvironment", "properties": {"APP_ENV": {"value": "production"}}},
        {"name": "applicationConfig: [classpath:/application.yml]",
         "properties": {
             "spring.datasource.url": {"value": "jdbc:postgresql://127.0.0.1/meridian"},
             "spring.datasource.password": {"value": "Sup3rSecret-LAB-DECOY-not-real"},
         }},
    ],
}


def _dotenv(ctx: Ctx) -> Response:
    if ctx.hardened:
        return Response.text("Not Found", status=404)
    return Response.text(_DOTENV, content_type="text/plain; charset=utf-8")


def _actuator_env(ctx: Ctx) -> Response:
    if ctx.hardened:
        return Response.json({"error": "Not Found"}, status=404)
    return Response.json(_ACTUATOR_ENV)


def register(r: Router) -> None:
    r.add("GET", "/.env", _dotenv)
    r.add("GET", "/actuator/env", _actuator_env)
