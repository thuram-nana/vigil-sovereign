"""PHASE 0.3 — the canonical Observation schema (integration criterion 4), pure model.

Sovereign-safe (no framework import): the Observation normalizes every tool run into ONE shape and binds the
tool's raw output by sha256 — the tool's say-so, never a verdict. The RUNNER's emission of it is asserted in
test_external_tool_runner.py (which has the gated-run fixtures).
"""
from __future__ import annotations

import hashlib

from vigil_integration.live.observation import observe, refused_observation


class _Outcome:
    def __init__(self, stdout="", stderr="", backend="x", truncated=False):
        self.stdout, self.stderr, self.backend, self.truncated = stdout, stderr, backend, truncated


class _Spec:
    name = "nmap"


class _Prop:
    def __init__(self, host, port, protocol="tcp"):
        self.host, self.port, self.protocol = host, port, protocol


def test_observe_normalizes_and_digests_raw_output():
    out = _Outcome(stdout="80/open/tcp", stderr="warn", backend="local", truncated=True)
    obs = observe(_Spec(), "127.0.0.1", out, [_Prop("127.0.0.1", 80)], tool_version="nmap 7.99")
    assert obs.tool == "nmap" and obs.target == "127.0.0.1" and obs.outcome_class == "ran"
    assert obs.tool_version == "nmap 7.99" and obs.truncated is True and obs.backend == "local"
    assert obs.proposals == (("127.0.0.1", 80, "tcp"),)
    want = "sha256:" + hashlib.sha256(b"80/open/tcp\x00warn").hexdigest()
    assert obs.raw_output_sha256 == want
    d = obs.to_dict()
    assert d["schema"] == "vigil-observation/1" and d["proposals"] == [["127.0.0.1", 80, "tcp"]]


def test_a_tampered_tool_row_changes_the_digest():
    a = observe(_Spec(), "t", _Outcome(stdout="80/open/tcp"), [])
    b = observe(_Spec(), "t", _Outcome(stdout="80/open/tcp EVIL"), [])
    assert a.raw_output_sha256 != b.raw_output_sha256   # the tool's say-so is bound, tamper-evident


def test_refused_observation_records_no_run():
    obs = refused_observation(_Spec(), "127.0.0.1")
    assert obs.outcome_class == "refused" and obs.raw_output_sha256 == "" and obs.proposals == ()


def test_observe_is_total_on_missing_fields():
    obs = observe(_Spec(), "t", None, None)   # no outcome, no proposals
    assert obs.outcome_class == "ran" and obs.raw_output_sha256 == "" and obs.proposals == ()
