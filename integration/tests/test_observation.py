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
    # LENGTH-PREFIXED framing (injective): len(stdout)\n stdout \n stderr
    so, se = b"80/open/tcp", b"warn"
    want = "sha256:" + hashlib.sha256(f"{len(so)}\n".encode("ascii") + so + b"\n" + se).hexdigest()
    assert obs.raw_output_sha256 == want
    d = obs.to_dict()
    assert d["schema"] == "vigil-observation/1" and d["proposals"] == [["127.0.0.1", 80, "tcp"]]


def test_a_tampered_tool_row_changes_the_digest():
    a = observe(_Spec(), "t", _Outcome(stdout="80/open/tcp"), [])
    b = observe(_Spec(), "t", _Outcome(stdout="80/open/tcp EVIL"), [])
    assert a.raw_output_sha256 != b.raw_output_sha256   # the tool's say-so is bound, tamper-evident


def test_digest_framing_is_injective_no_null_boundary_collision():
    """Red-pen LOW-1 fix: the length-prefixed framing has no \\x00-boundary collision. The two inputs that
    collided under a plain-\\x00 delimiter now yield DIFFERENT digests."""
    a = observe(_Spec(), "t", _Outcome(stdout="a\x00", stderr="b"), [])
    b = observe(_Spec(), "t", _Outcome(stdout="a", stderr="\x00b"), [])
    assert a.raw_output_sha256 != b.raw_output_sha256


def test_refused_observation_records_no_run():
    obs = refused_observation(_Spec(), "127.0.0.1")
    assert obs.outcome_class == "refused" and obs.raw_output_sha256 == "" and obs.proposals == ()


def test_observe_is_total_on_missing_fields():
    obs = observe(_Spec(), "t", None, None)   # no outcome, no proposals
    assert obs.outcome_class == "ran" and obs.raw_output_sha256 == "" and obs.proposals == ()
