"""AEGIS AS-9b — the ingest DISTRIBUTION (``apps/aegis-ingest``) re-exports the engine-plane receiver core.

The receiver LOGIC + its strict acceptance live engine-side (``framework.v2.aegis.tests.test_receiver`` and
``test_connector_secrets_inbound``) and sigil-side (``apps/sigil/tests/test_aegis_ingest_roundtrip``). This
smoke test only pins that the distribution package re-exports the public surface unchanged and is DEFAULT-OFF.

Run with the engine on PYTHONPATH, e.g.
``PYTHONPATH=packages/core/vigil_core:engine/crucible:apps/aegis-ingest pytest apps/aegis-ingest/tests``.
"""
from __future__ import annotations

import aegis_ingest
from framework.v2.aegis import receiver as core


def test_distribution_reexports_the_engine_core():
    for name in ("IngestReceiver", "IngestResult", "IngestOutcome", "ReceiverServer", "serve_receiver",
                 "receiver_enabled", "INGEST_FINDING_SCHEMA", "RECEIVER_ENV"):
        assert getattr(aegis_ingest, name) is getattr(core, name)


def test_default_off(monkeypatch):
    monkeypatch.delenv(aegis_ingest.RECEIVER_ENV, raising=False)
    assert aegis_ingest.receiver_enabled() is False
