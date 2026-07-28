"""B0 — evidence.poc: the typed, deterministic PoC artifact model.

The proof artifact is a typed, ``extra="forbid"`` pydantic model (not a free-text dict). Byte refs are
confined (no absolute / ``..`` path can be bound into a certificate), and the model serializes deterministically.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from framework.v2.evidence.poc import CapturedExchange, EnvironmentManifest, PoCArtifact


def test_captured_exchange_forbids_unknown_fields():
    with pytest.raises(ValidationError):
        CapturedExchange(channel="request_payload", role="q", surprise="evil")


def test_byte_refs_are_path_confined():
    # an absolute or ``..`` ref must be rejected (it would otherwise bind arbitrary bytes into a cert).
    with pytest.raises(ValidationError):
        CapturedExchange(channel="process", request_bytes_ref="../../etc/passwd")
    with pytest.raises(ValidationError):
        CapturedExchange(channel="process", response_bytes_ref="/etc/shadow")
    ok = CapturedExchange(channel="process", response_bytes_ref="proc/stdout.txt")   # a safe relative ref
    assert ok.response_bytes_ref == "proc/stdout.txt"


def test_artifact_serializes_deterministically():
    env = EnvironmentManifest(image_digest="sha256:" + "a" * 64, tool_versions={"nmap": "7.94"},
                              payload_sha256="b" * 64)
    art = PoCArtifact(finding_ref="poc-1", bug_class="sqli_attempt",
                      exchanges=[CapturedExchange(channel="request_payload", role="q",
                                                  request_bytes_ref="req.bin")],
                      env=env)
    d1 = art.model_dump(mode="json")
    d2 = PoCArtifact(**art.model_dump()).model_dump(mode="json")
    assert d1 == d2                                              # round-trips byte-stable (no wallclock/rng)
    assert d1["bug_class"] == "sqli_attempt" and d1["env"]["image_digest"].startswith("sha256:")
