"""
Default mode="observe" is read-only: it never escalates the action beyond "observe", even for a
confirmed verdict. Any acting is gated on a confirmed certificate (D1). A fabricated actor not
in the world-model ⇒ admit() returns UNGROUNDED (the anti-hallucination floor).
"""

from __future__ import annotations

from framework.v2.aegis import Aegis, ActorRef, Surface
from framework.v2.aegis.guard import LLMGuard
from framework.v2.aegis.models import AegisConfig
from framework.v2.veracity.claims import Claim
from framework.v2.veracity.firewall import admit
from framework.v2.worldmodel.graph import WorldModel

CANARY = "AEGIS-READONLY-11aa22bb33cc44dd"


def test_observe_mode_never_acts_even_when_confirmed():
    a = Aegis(AegisConfig(deployment_secret="k", mode="observe"), guard=LLMGuard(canary=CANARY))
    hp = a.guard.honeypot_paths[0]
    v = a.observe(surface=Surface.REQUEST, actor=ActorRef(ip="198.51.100.5"), requested_path=hp)
    assert v.decision == "confirmed"
    assert v.action == "observe"          # read-only: no challenge/throttle/block


def test_enforce_action_rides_only_on_a_confirmed_certificate():
    a = Aegis(AegisConfig(deployment_secret="k", mode="enforce"), guard=LLMGuard(canary=CANARY))
    hp = a.guard.honeypot_paths[0]
    # a confirmed verdict may act (D1) ...
    v_conf = a.observe(surface=Surface.REQUEST, actor=ActorRef(ip="198.51.100.5"), requested_path=hp)
    assert v_conf.decision == "confirmed" and v_conf.action == "challenge"
    # ... but a LEAD or CLEAR never acts, even in enforce mode.
    v_lead = a.observe(surface=Surface.REQUEST, actor=ActorRef(ip="198.51.100.6"), requested_path="/normal")
    assert v_lead.decision != "confirmed" and v_lead.action == "observe"


def test_fabricated_actor_is_ungrounded():
    claim = Claim(text="fabricated", source="aegis", bug_class="system_prompt_disclosure",
                  entity_refs=["session:does-not-exist"], tokens=[])
    admitted = admit(claim, world=WorldModel())
    assert admitted.verdict.value == "ungrounded"
    assert not admitted.is_fact
