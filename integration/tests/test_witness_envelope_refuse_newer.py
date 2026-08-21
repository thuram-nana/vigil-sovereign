"""W5-3 (#447) red-pen regression: the INTEGRATION-plane witnessed-checkpoint reader must refuse-newer too.

The sovereign ``spine.witness`` reader got the refuse-newer gate, but its byte-compatible integration twin
``witnessed_anchor.load_witnessed_envelope`` (read on the retained-anchor + reprove paths) did not — so a
schema>1 envelope was parsed as v1: a silent downgrade / mislabelled anchor. This pins the gate."""
from __future__ import annotations

import json

import pytest

from vigil_integration.witnessed_anchor import AnchorError, _ENVELOPE_SCHEMA, load_witnessed_envelope


def _envelope(schema) -> str:
    return json.dumps({"schema": schema, "scope": "alpha", "checkpoint": {}, "witness_signatures": []})


def test_a_newer_envelope_schema_is_refused_with_an_upgrade_message():
    with pytest.raises(AnchorError) as ei:
        load_witnessed_envelope(_envelope(_ENVELOPE_SCHEMA + 1))
    assert "newer than this build" in str(ei.value) and "upgrade" in str(ei.value).lower()


def test_an_uncoercible_schema_fails_closed():
    with pytest.raises(AnchorError) as ei:
        load_witnessed_envelope(_envelope("banana"))
    assert "newer than this build" in str(ei.value)


def test_current_schema_passes_the_gate_and_fails_only_on_the_body():
    # a schema-1 envelope with an empty checkpoint clears the schema gate, then fails validation for a
    # DIFFERENT (body) reason — proving the gate accepts the current version rather than refusing it.
    with pytest.raises(AnchorError) as ei:
        load_witnessed_envelope(_envelope(_ENVELOPE_SCHEMA))
    assert "newer than this build" not in str(ei.value)


def test_absent_schema_defaults_to_current_and_clears_the_gate():
    body = json.dumps({"scope": "alpha", "checkpoint": {}, "witness_signatures": []})  # no schema key
    with pytest.raises(AnchorError) as ei:
        load_witnessed_envelope(body)
    assert "newer than this build" not in str(ei.value)
