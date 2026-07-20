"""
Anti-hallucination P3 — the veracity firewall applied to LIVE findings, plus the
strengthened contradiction invariant.

P0 built ``admit()`` as a caller-less primitive. Here it starts running over real output:
``admit_finding`` re-fires a finding's OWN retained oracle_context against the chained
world-model. A finding the scan marked active but whose proof no longer reproduces
(altered evidence, a dry-run stub) is DEMOTED to UNGROUNDED — the firewall catching a
"confirmed" that is no longer true. A finding whose surface the graph net-refutes is
CONTRADICTED. Nothing the oracle refused is ever promoted; the layer only demotes.

The contradiction check itself gains a second, conservative trigger: an entity whose
belief LOWER BOUND has collapsed is refuted even when its mean sits above the mean floor.
"""

from __future__ import annotations

from framework.v2.scanner.engine import AuditFinding
from framework.v2.veracity import VeracityVerdict, admit_finding, claim_from_finding
from framework.v2.veracity.consistency import contradicts
from framework.v2.verify.adapter import FindingContext
from framework.v2.verify.confirmation import confirm_finding
from framework.v2.worldmodel.graph import WorldModel
from framework.v2.worldmodel.models import Node, NodeKind

_BASE = {"status": 200, "body": "No results."}
_DIVERGENT = {"status": 200, "body": "id=1 alice user\nid=2 bob admin\nid=3 carol user"}
_DISC = {"dimensions": ["status", "length", "lexical"]}


def _ctx(mutated=_DIVERGENT) -> dict:
    return FindingContext.from_http_responses(
        _BASE, mutated, bug_class="boolean_sqli", discriminator=_DISC).model_dump(mode="json")


def _finding(ctx, *, param="q", ipoint="query:q", bug_class="boolean_sqli") -> dict:
    """A serialized AuditFinding, with confirmed_by/confidence taken from the REAL oracle
    re-fire so the token's claim matches what reverification produces."""
    c = confirm_finding(finding={"bug_class": bug_class}, context=FindingContext.model_validate(ctx))
    return {
        "check_id": "s1", "bug_class": bug_class, "insertion_point": ipoint, "param": param,
        "confidence": c.confidence if c else 0.5,
        "confirmed_by": c.confirmed_by.value if c else None,
        "oracle_context": ctx,
    }


def _world_with_endpoint(nid="endpoint:q", confidence=1.0, times=3) -> WorldModel:
    w = WorldModel()
    for _ in range(times):
        w.add_node(Node(id=nid, kind=NodeKind.ENDPOINT, provenance="scan:t",
                        confidence=confidence, first_seen=1, last_seen=1))
    return w


# ---- the firewall runs live over real findings ------------------------------


def test_admit_finding_grounds_a_reproducing_live_finding() -> None:
    a = admit_finding(_finding(_ctx()), _world_with_endpoint("endpoint:q"))
    assert a.verdict is VeracityVerdict.GROUNDED and a.is_fact


def test_admit_finding_demotes_a_finding_whose_proof_no_longer_reproduces() -> None:
    # the scan recorded this as active, but the retained evidence does NOT re-fire
    # (non-divergent responses) — the firewall demotes the "confirmed" to commentary.
    f = {"check_id": "s1", "bug_class": "boolean_sqli", "insertion_point": "query:q",
         "param": "q", "confidence": 0.9, "confirmed_by": "differential_response",
         "oracle_context": _ctx(_BASE)}
    a = admit_finding(f, _world_with_endpoint("endpoint:q"))
    assert a.verdict is VeracityVerdict.UNGROUNDED and not a.is_fact


def test_admit_finding_with_no_retained_proof_is_ungrounded() -> None:
    f = {"check_id": "s1", "bug_class": "boolean_sqli", "insertion_point": "query:q",
         "param": "q", "confidence": 0.9, "confirmed_by": "x", "oracle_context": None}
    a = admit_finding(f, _world_with_endpoint("endpoint:q"))
    assert a.verdict is VeracityVerdict.UNGROUNDED


def test_admit_finding_grounds_without_a_world_on_oracle_alone() -> None:
    # no world → entity existence is not enforced, but the oracle still re-fires.
    a = admit_finding(_finding(_ctx()), None)
    assert a.is_fact


def test_admit_finding_contradicted_when_the_world_refutes_the_surface() -> None:
    # the graph net-refutes the finding's endpoint → CONTRADICTED, checked before grounds,
    # so even a re-firing oracle cannot lift a claim the world actively disbelieves.
    w = WorldModel()
    for c in (0.05, 0.05, 0.05):
        w.add_node(Node(id="endpoint:q", kind=NodeKind.ENDPOINT, provenance="scan:t",
                        confidence=c, first_seen=1, last_seen=1))
    a = admit_finding(_finding(_ctx()), w)
    assert a.verdict is VeracityVerdict.CONTRADICTED


def test_admit_finding_accepts_a_pydantic_auditfinding() -> None:
    # the adapter reads a real AuditFinding model, not only a dict.
    d = _finding(_ctx())
    f = AuditFinding(check_id="s1", bug_class="boolean_sqli", insertion_point="query:q",
                     param="q", confidence=d["confidence"], confirmed_by=d["confirmed_by"],
                     oracle_context=d["oracle_context"])
    a = admit_finding(f, _world_with_endpoint("endpoint:q"))
    assert a.is_fact


def test_claim_from_finding_binds_subject_and_names_the_surface() -> None:
    claim = claim_from_finding(_finding(_ctx()))
    assert claim.bug_class == "boolean_sqli"
    assert claim.entity_refs == ["endpoint:q"]              # the surface the graph is consulted about
    assert len(claim.tokens) == 1 and claim.tokens[0].bug_class == "boolean_sqli"  # oracle bound to subject


def test_admit_finding_rejects_a_bug_class_flipped_finding() -> None:
    # a GENUINE boolean_sqli proof whose top-level bug_class was flipped to 'rce' must NOT
    # ground as an RCE fact — the finding-level defeat the adversarial review found. The
    # oracle re-fires only under the class the EVIDENCE proves, so reverify refuses the
    # relabelled claim at the re-execution boundary. (review fix: binding-forgery)
    tampered = _finding(_ctx())          # a real, firing boolean_sqli oracle_context
    tampered["bug_class"] = "rce"        # tamper ONLY the label, leave the proof intact
    a = admit_finding(tampered, _world_with_endpoint("endpoint:q"))
    assert a.verdict is VeracityVerdict.UNGROUNDED and not a.is_fact


def test_admit_finding_empty_param_binds_to_the_real_endpoint_node() -> None:
    # an empty-named param yields a finding the chainer keys as "endpoint:" — the adapter
    # must MIRROR that (not mint a phantom "endpoint:<insertion_point>"), so a net-refuted
    # empty-param surface is still caught as CONTRADICTED. (review fix: node-id-mismatch)
    assert claim_from_finding(_finding(_ctx(), param="", ipoint="query_value:0")).entity_refs == ["endpoint:"]
    w = WorldModel()
    for c in (0.05, 0.05, 0.05):
        w.add_node(Node(id="endpoint:", kind=NodeKind.ENDPOINT, provenance="scan:t",
                        confidence=c, first_seen=1, last_seen=1))
    a = admit_finding(_finding(_ctx(), param="", ipoint="query_value:0"), w)
    assert a.verdict is VeracityVerdict.CONTRADICTED


# ---- strengthened contradiction: the lower-bound trigger --------------------


def test_contradicts_fires_on_a_collapsed_lower_bound_above_the_mean_floor() -> None:
    # mean 0.40 (ABOVE the 0.35 mean floor) but lcb ~0.14 (BELOW the 0.20 lcb floor):
    # only the new lower-bound trigger catches it — a thinly-evidenced, undercut belief.
    node = Node(id="host:wide", kind=NodeKind.HOST, provenance="oracle:x", confidence=0.4,
                alpha=1.0, beta=1.5, first_seen=1, last_seen=1)

    class _W:
        def get_node(self, r):
            return node if r == "host:wide" else None

    contra, score, reason = contradicts(["host:wide"], _W())
    assert contra and "lower bound" in reason and score > 0.0


def test_contradicts_does_not_fire_on_a_well_supported_fact() -> None:
    # a tightly-corroborated node (high mean, small sd) trips neither trigger — the
    # strengthening must not turn healthy facts into false contradictions.
    node = Node(id="endpoint:real", kind=NodeKind.ENDPOINT, provenance="oracle:f1",
                confidence=0.9, alpha=9.0, beta=1.0, first_seen=1, last_seen=1)

    class _W:
        def get_node(self, r):
            return node if r == "endpoint:real" else None

    contra, _, _ = contradicts(["endpoint:real"], _W())
    assert not contra


def test_contradicts_is_read_only_and_safe_without_a_world() -> None:
    assert contradicts(["x"], None) == (False, 0.0, "no world-model to check against")
