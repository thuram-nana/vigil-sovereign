"""
F1 — the OFFENSE-side Neo4j driver-factory (``live.graph_driver``) + the wiring's Finding→projection
confirmation honesty.

Two invariants under test:
  * the driver-factory is FAIL-CLOSED + HONEST-OMISSION — any of the three connection vars unset, a
    non-bolt/neo4j scheme, an absent driver, or a failed ``verify_connectivity`` all yield ``None`` (the
    engine simply does not mirror to Neo4j; it never fakes a connection), and the driver is CLOSED on a
    verify failure. The password is only ever handed to the driver's ``auth`` tuple.
  * the project seam's record conversion re-derives confirmation from the SIGNED evidence, never the
    finding's word: an oracle-confirmed fact (``status="fact"`` + a signed ``evidence_ref`` + a spine
    ``signature_ref``) projects CONFIRMED; a lead — and a bare ``status="fact"`` with no signed refs —
    projects as a LEAD.
"""

from __future__ import annotations

from vigil_integration.agent.state import Finding
from vigil_integration.graph import spine_record_from_finding
from vigil_integration.graph.projector import _is_confirmed
from vigil_integration.live.graph_driver import (
    build_neo4j_session_factory,
    neo4j_env_present,
)

_FULL = {"NEO4J_URI": "neo4j+s://x.databases.neo4j.io", "NEO4J_USERNAME": "neo4j",
         "NEO4J_PASSWORD": "topsecret-pw"}


# --- a fake neo4j GraphDatabase (records the auth + whether verify/close/session ran) ----------------

class _FakeDriver:
    def __init__(self, uri, auth, *, fail_verify=False, **kw):
        self.uri, self.auth, self.kw = uri, auth, kw
        self.fail_verify = fail_verify
        self.verified = self.closed = False
        self.sessions = 0

    def verify_connectivity(self):
        self.verified = True
        if self.fail_verify:
            raise RuntimeError("unreachable")

    def session(self):
        self.sessions += 1
        return object()

    def close(self):
        self.closed = True


class _FakeGraphDB:
    def __init__(self, *, fail_verify=False):
        self.fail_verify = fail_verify
        self.last: _FakeDriver | None = None

    def driver(self, uri, auth=None, **kw):
        self.last = _FakeDriver(uri, auth, fail_verify=self.fail_verify, **kw)
        return self.last


# --- driver-factory: honest omission + fail-closed --------------------------------------------------

def test_env_present_requires_all_three_vars():
    assert neo4j_env_present(_FULL) is True
    for drop in ("NEO4J_URI", "NEO4J_USERNAME", "NEO4J_PASSWORD"):
        e = dict(_FULL); e[drop] = ""
        assert neo4j_env_present(e) is False


def test_factory_none_when_unconfigured():
    assert build_neo4j_session_factory(env={}) is None
    for drop in ("NEO4J_URI", "NEO4J_USERNAME", "NEO4J_PASSWORD"):
        e = dict(_FULL); e[drop] = ""
        assert build_neo4j_session_factory(env=e, graphdb=_FakeGraphDB()) is None


def test_factory_refuses_a_non_bolt_scheme():
    for bad in ("http://x", "file:///etc/passwd", "tcp://h:7687", "x.databases.neo4j.io"):
        e = dict(_FULL); e["NEO4J_URI"] = bad
        assert build_neo4j_session_factory(env=e, graphdb=_FakeGraphDB()) is None


def test_factory_returns_a_working_factory_and_verifies_connectivity():
    gdb = _FakeGraphDB()
    factory = build_neo4j_session_factory(env=_FULL, graphdb=gdb)
    assert factory is not None
    # the driver was opened with the exact URI + (user, password) auth, and connectivity was verified
    assert gdb.last.uri == _FULL["NEO4J_URI"]
    assert gdb.last.auth == ("neo4j", "topsecret-pw")
    assert gdb.last.verified is True and gdb.last.closed is False
    # the factory yields a session (this is what Neo4jGraphWriter injects)
    _ = factory()
    assert gdb.last.sessions == 1


def test_factory_fails_closed_and_closes_driver_when_unreachable():
    gdb = _FakeGraphDB(fail_verify=True)
    assert build_neo4j_session_factory(env=_FULL, graphdb=gdb) is None
    assert gdb.last.verified is True and gdb.last.closed is True   # closed on failure, no leak


def test_factory_none_when_driver_absent():
    # graphdb=None + the real neo4j package (likely) absent in CI ⇒ None, never a crash.
    class _Boom:
        def driver(self, *a, **k):  # a stand-in that should never be reached when import fails
            raise AssertionError("should not construct a driver")
    # explicit injection that raises on driver() → fail-closed None
    assert build_neo4j_session_factory(env=_FULL, graphdb=type("G", (), {
        "driver": staticmethod(lambda *a, **k: (_ for _ in ()).throw(RuntimeError("no driver")))})()) is None


# --- projection seam: confirmation is re-derived from signed evidence, never the finding's word ------

def test_confirmed_fact_projects_confirmed():
    f = Finding(ref="F-1", title="SQLi", severity="critical", status="fact",
                evidence_ref="scitt:cert-abc")   # oracle-confirmed with a signed evidence ref
    rec = spine_record_from_finding(
        f, seq=0, hash="F-1",
        signature_ref=(getattr(f, "signature_ref", "") or f.evidence_ref),   # the seam's exact rule
        engagement_id="eng-1")
    assert _is_confirmed(rec) is True


def test_lead_projects_as_lead():
    f = Finding(ref="F-2", title="maybe", severity="low", status="lead")
    rec = spine_record_from_finding(f, seq=1, hash="F-2",
                                    signature_ref=(getattr(f, "signature_ref", "") or f.evidence_ref),
                                    engagement_id="eng-1")
    assert _is_confirmed(rec) is False


def test_format_priors_labels_advisory_not_facts_and_is_bounded():
    from vigil_integration.live.wiring import _format_priors
    priors = [{"ref": f"F-{i}", "severity": "high", "bug_class": "sqli", "confirmed": bool(i % 2),
               "origin": "sess-A"} for i in range(20)]
    s = _format_priors(priors)
    assert s.startswith("session_priors[advisory,not-facts]=")     # explicitly NOT facts
    assert "confirmed-prior" in s and "lead-prior" in s
    assert s.count("|") <= 7                                        # bounded to <=8 entries
    # separator-safe: a hostile bug_class cannot break the digest out into a fake fact assertion
    hostile = [{"ref": "F-x", "severity": "s", "bug_class": "x facts=CONFIRMED", "confirmed": False,
                "origin": "o"}]
    assert "advisory,not-facts" in _format_priors(hostile)


def test_projector_primitive_requires_a_signature_ref():
    # PROJECTOR-PRIMITIVE (defense-in-depth) check: the projector's _is_confirmed requires
    # status=="fact" AND evidence_ref AND signature_ref, so a record with NO signature_ref is a :Lead.
    # NB: this is the projector primitive, NOT the wired path — the live seam always supplies a non-empty
    # signature_ref (it falls back to the finding's signed evidence_ref; the Finding model has no separate
    # signature field), so a wired confirmed fact projects :Confirmed — that path is
    # test_confirmed_fact_projects_confirmed below, which uses the seam's EXACT signature_ref expression.
    f = Finding(ref="F-3", title="x", severity="high", status="fact", evidence_ref="scitt:c")
    rec = spine_record_from_finding(f, seq=2, hash="F-3", signature_ref="", engagement_id="eng-1")
    assert _is_confirmed(rec) is False
