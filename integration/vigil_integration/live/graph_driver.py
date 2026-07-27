"""
live.graph_driver — the OFFENSE-side Neo4j driver-factory (F1, cloud/remote auto-connect).

The one place the ``neo4j`` driver is opened on the offense plane. It reads the connection details the
operator entered in the sovereign Settings plane (delivered to this keyless offense process as env by
``vigil up`` — see ``settings.export_runtime_env`` + the ``uiproxy`` allowlist), constructs a Neo4j driver,
and returns a zero-arg ``session_factory`` to inject into :class:`live.graph_neo4j.Neo4jGraphWriter`.

Boundary + safety posture:

  * **Two-env clean (FATAL-2).** ``neo4j`` is a neutral third-party dependency (like ``boto3``), imported
    LAZILY inside the factory so importing ``vigil_integration`` in the sovereign venv never pulls it, and
    this process holds no owner key. The sovereign Settings probe opens its OWN driver only to run
    ``RETURN 1``; this offense process opens its OWN driver to project the graph. They never share a live
    handle — the only offense↔sovereign bridge is the signed append-only spine.
  * **Honest omission / fail-closed.** Any of the three vars unset → ``None`` (the engine simply does not
    mirror to Neo4j — it never fakes a connection). A bad scheme, an unreachable host, or a rejected
    credential → the driver is closed and ``None`` is returned (the run still proceeds; the projection is
    omitted). ``verify_connectivity()`` is the deploy-time "test + connect".
  * **Secret-free logs.** The password is passed only to the driver's ``auth`` tuple; it is never logged,
    printed, put in argv, or included in a message.
  * **Scheme allowlist.** Only ``bolt``/``neo4j`` (optionally ``+s``/``+ssc``) URIs are accepted, matching
    the settings validator + the sovereign probe.
"""

from __future__ import annotations

import os
from typing import Any, Callable, Optional

SessionFactory = Callable[[], Any]

# The bolt/neo4j URI schemes we will open. Identical to the settings validator + the sovereign probe.
_NEO4J_SCHEMES = ("bolt://", "bolt+s://", "bolt+ssc://", "neo4j://", "neo4j+s://", "neo4j+ssc://")

_CONNECT_TIMEOUT_S = 8.0


def neo4j_env_present(env: Optional[dict] = None) -> bool:
    """True iff all three connection vars (URI + username + password) are set. Used to decide whether the
    engine wires the Neo4j projection at all (honest omission when not)."""
    e = env if env is not None else os.environ
    return bool(str(e.get("NEO4J_URI", "") or "").strip()
                and str(e.get("NEO4J_USERNAME", "") or "").strip()
                and str(e.get("NEO4J_PASSWORD", "") or "").strip())


def build_neo4j_session_factory(
    env: Optional[dict] = None, *, graphdb: Any = None,
) -> Optional[SessionFactory]:
    """Build a zero-arg ``session_factory`` for :class:`Neo4jGraphWriter` from the env, or ``None`` when
    Neo4j is not configured / not reachable (honest omission, fail-closed).

    ``env`` defaults to ``os.environ`` (the delivered offense env). ``graphdb`` is the Neo4j
    ``GraphDatabase`` module/namespace — injected in tests with a fake; ``None`` lazily imports the real
    driver (absent driver ⇒ ``None``, never a crash). Opens ONE driver and calls ``verify_connectivity()``
    (the "test + connect on deploy" step); on any failure the driver is closed and ``None`` returned. The
    password is never logged/printed/argv'd."""
    e = env if env is not None else os.environ
    uri = str(e.get("NEO4J_URI", "") or "").strip()
    user = str(e.get("NEO4J_USERNAME", "") or "").strip()
    password = str(e.get("NEO4J_PASSWORD", "") or "").strip()
    if not (uri and user and password):
        return None                                    # honest omission: not configured
    if not uri.startswith(_NEO4J_SCHEMES):
        return None                                    # fail-closed: refuse a non-bolt/neo4j scheme
    if graphdb is None:
        try:
            from neo4j import GraphDatabase as graphdb  # type: ignore  # optional dependency
        except Exception:                              # noqa: BLE001 — driver absent ⇒ projection omitted
            return None
    try:
        driver = graphdb.driver(uri, auth=(user, password),
                                connection_timeout=_CONNECT_TIMEOUT_S,
                                max_transaction_retry_time=_CONNECT_TIMEOUT_S)
        driver.verify_connectivity()                   # the deploy-time test+connect; raises if unreachable
    except Exception:                                  # noqa: BLE001 — unreachable/bad creds ⇒ omit, fail-closed
        try:
            driver.close()  # type: ignore[has-type]
        except Exception:                              # noqa: BLE001
            pass
        return None
    return lambda: driver.session()
