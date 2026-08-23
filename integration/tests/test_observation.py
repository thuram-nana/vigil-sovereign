"""PHASE 0.3 — the canonical Observation schema (integration criterion 4), pure model.

Sovereign-safe (no framework import): the Observation normalizes every tool EXECUTION into ONE shape and
binds the tool's raw output, the exact argv, and the trusted binary bytes by sha256 — provenance, never a
verdict. The RUNNER's emission of it on every path is asserted in test_external_tool_runner.py (which has the
gated-run fixtures).
"""
from __future__ import annotations

import dataclasses
import hashlib

from vigil_integration.live.observation import Observation, observe, refused_observation


class _Outcome:
    def __init__(self, stdout="", stderr="", backend="x", truncated=False, argv=None, binary_sha256=""):
        self.stdout, self.stderr, self.backend, self.truncated = stdout, stderr, backend, truncated
        self.argv = argv if argv is not None else []
        self.binary_sha256 = binary_sha256


class _Spec:
    name = "nmap"


class _Prop:
    def __init__(self, host, port, protocol="tcp"):
        self.host, self.port, self.protocol = host, port, protocol


def test_observe_normalizes_and_digests_raw_output():
    out = _Outcome(stdout="80/open/tcp", stderr="warn", backend="local", truncated=True,
                   argv=["nmap", "-p", "80", "127.0.0.1"], binary_sha256="sha256:" + "a" * 64)
    obs = observe(_Spec(), "127.0.0.1", out, [_Prop("127.0.0.1", 80)], tool_version="nmap 7.99",
                  artifact_refs=("finding:abc",))
    assert obs.tool == "nmap" and obs.target == "127.0.0.1" and obs.outcome_class == "ran"
    assert obs.tool_version == "nmap 7.99" and obs.truncated is True and obs.backend == "local"
    assert obs.proposals == (("127.0.0.1", 80, "tcp"),)
    assert obs.binary_sha256 == "sha256:" + "a" * 64          # trusted binary digest, threaded from backend
    assert obs.artifact_refs == ("finding:abc",)              # pointers to what the run produced
    assert obs.error_reason == ""                             # a clean run carries no error
    # LENGTH-PREFIXED framing (injective): len(stdout)\n stdout \n stderr
    so, se = b"80/open/tcp", b"warn"
    want = "sha256:" + hashlib.sha256(f"{len(so)}\n".encode("ascii") + so + b"\n" + se).hexdigest()
    assert obs.raw_output_sha256 == want
    d = obs.to_dict()
    assert d["schema"] == "vigil-observation/2" and d["proposals"] == [["127.0.0.1", 80, "tcp"]]
    assert d["binary_sha256"] == obs.binary_sha256 and d["args_sha256"] == obs.args_sha256
    assert d["artifact_refs"] == ["finding:abc"] and d["error_reason"] == ""


def test_args_digest_is_deterministic_and_injective():
    """crit-4 args digest: a stable, injective digest over the EXACT argv the tool ran with. Distinct argv
    can never collide (length-prefixed framing), and the same argv always yields the same digest."""
    a = observe(_Spec(), "t", _Outcome(argv=["nmap", "-p", "80", "t"]), [])
    b = observe(_Spec(), "t", _Outcome(argv=["nmap", "-p", "80", "t"]), [])
    c = observe(_Spec(), "t", _Outcome(argv=["nmap", "-p", "8", "0t"]), [])   # same joined chars, diff split
    assert a.args_sha256 and a.args_sha256.startswith("sha256:")
    assert a.args_sha256 == b.args_sha256                      # deterministic (no wallclock)
    assert a.args_sha256 != c.args_sha256                      # injective across argv boundaries
    assert observe(_Spec(), "t", _Outcome(argv=[]), []).args_sha256 == ""   # no argv ⇒ no digest


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


def test_refused_observation_records_no_run_and_why():
    obs = refused_observation(_Spec(), "127.0.0.1", reason="out of scope")
    assert obs.outcome_class == "refused" and obs.raw_output_sha256 == "" and obs.proposals == ()
    assert obs.binary_sha256 == "" and obs.args_sha256 == "" and obs.artifact_refs == ()
    assert obs.error_reason == "out of scope"       # the negative is recorded honestly, with its reason


def test_observe_is_total_on_missing_fields():
    obs = observe(_Spec(), "t", None, None)   # no outcome, no proposals
    assert obs.outcome_class == "ran" and obs.raw_output_sha256 == "" and obs.proposals == ()
    assert obs.binary_sha256 == "" and obs.args_sha256 == "" and obs.error_reason == ""


def test_observation_structurally_cannot_hold_a_fact():
    """Load-bearing honesty (FP-0): the normalizer emits proposals/LEADs and CAN NEVER emit a FACT. The
    record has NO field that can hold a verdict, a signature, or a confirmed finding, and ``outcome_class``
    is one of ran/errored/refused — never 'fact'. A FACT is minted only by the runner's oracle re-drive."""
    field_names = {f.name for f in dataclasses.fields(Observation)}
    forbidden = {"fact", "facts", "verdict", "signature", "signed", "confirmed", "is_fact",
                 "finding", "admitted", "certificate", "proof"}
    assert not (field_names & forbidden), f"Observation must carry no verdict field: {field_names & forbidden}"

    # every path's outcome_class stays inside the proposal/negative taxonomy — never a fact
    ran = observe(_Spec(), "t", _Outcome(stdout="80/open/tcp", argv=["nmap", "t"]), [_Prop("t", 80)])
    refused = refused_observation(_Spec(), "t", reason="denied")
    for obs in (ran, refused):
        assert obs.outcome_class in {"ran", "errored", "refused"}
        assert obs.outcome_class != "fact"
        # the serialized form likewise exposes no verdict key an audit could mistake for a confirmed finding
        assert not (set(obs.to_dict()) & forbidden)

    # artifact_refs are POINTERS to produced artifacts, not the artifacts (and not a verdict) — even when the
    # run produced leads/facts elsewhere, the Observation only names them; it asserts nothing about them.
    with_refs = observe(_Spec(), "t", _Outcome(argv=["nmap", "t"]), [], artifact_refs=("finding:x",))
    assert with_refs.artifact_refs == ("finding:x",) and with_refs.outcome_class == "ran"
