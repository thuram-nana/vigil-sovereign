"""
aegis.pipeline — ``detect()``: the signal → observation → scored → oracle → verdict flow.

The defensive dual of prove-don't-guess, assembled from reused CRUCIBLE machinery:

    boundary.ingest            (untrusted-input hardening + PII redaction)
      → sensors.normalize      (mint provenance-tagged Observations — a LEAD)
      → actor_graph.observe    (per-actor Beta belief via project_observation)
      → OracleVerifier.confirm  (a deterministic AEGIS oracle fires over retained evidence)
      → veracity.admit          (re-executes the ground bound to the class; can ONLY demote)
      → confidence.assess_finding (posterior vs the MECE benign twin — the honest FP guard)
      → Verdict {decision, attack_class, certificate, band, top_alternative, provenance, ...}

Two load-bearing invariants, enforced here and by ``Verdict``'s model validator:
  * ``decision == "confirmed"`` ⇒ a ``certificate`` (the offline-re-runnable oracle evidence).
  * ``provenance == "grounded:…"`` ⇒ an oracle fired AND ``admit()`` re-admitted it as a fact.

Fully deterministic: a pure function of the (redacted) input + the caller's monotonic ``seq``.
Same evidence → byte-identical Verdict → identical certificate id.
"""

from __future__ import annotations

import hashlib

from ..confidence.decision import assess_finding
from ..veracity.claims import Claim
from ..veracity.firewall import admit
from ..veracity.tokens import GroundingToken
from ..verify.adapter import FindingContext
from ..verify.confirmation import confirm_finding
from ..verify.verifier import OracleVerifier, normalize_bug_class
from .actor_graph import ActorGraph
from .boundary import ingest
from .guard import LLMGuard
from .models import (
    AegisConfig,
    CertRef,
    RefuteChannel,
    Surface,
    TelemetryEnvelope,
    Verdict,
)
from .sensors import AuthTelemetrySensor, LLMInteractionSensor, RequestTelemetrySensor

_LEAD_PRIOR = 0.4     # a structural-marker LEAD seeds the SCE weakly — the benign twin stays live
_CLEAR_PRIOR = 0.05


def _dismiss_token(actor_id: str, attack_class: str, anchor: str) -> str:
    """A deterministic dismiss token (a pure function of the verdict content), so the same
    evidence mints the same token — never a wallclock/rng value."""
    return hashlib.sha256(f"{actor_id}|{attack_class}|{anchor}".encode("utf-8")).hexdigest()[:16]


def _candidates(env: TelemetryEnvelope, guard: LLMGuard, *, crawler_allowlisted: bool):
    """Ordered (bug_class, FindingContext) candidates for this envelope. LLM prefers the
    stronger control-vs-treatment `prompt_injection` claim, then the canary-substring
    `system_prompt_disclosure`. REQUEST is the honeypot set-membership."""
    out: list[tuple[str, FindingContext]] = []
    if env.surface is Surface.LLM and env.llm is not None:
        llm = env.llm
        if llm.control_behavior is not None and llm.treatment_behavior is not None:
            out.append(("prompt_injection",
                        guard.inspect_behavior(llm.control_behavior, llm.treatment_behavior)))
        canary = llm.canary or guard.canary
        if canary:
            out.append(("system_prompt_disclosure",
                        FindingContext.from_llm_disclosure(canary, llm.llm_output)))
    elif env.surface is Surface.REQUEST and env.requested_path is not None:
        out.append(("automated_access",
                    guard.honeypot_context(env.requested_path, crawler_allowlisted=crawler_allowlisted)))
    elif env.surface is Surface.AUTH and env.auth is not None:
        out.append(("credential_stuffing",
                    FindingContext.from_auth_activity(
                        [e.model_dump() for e in env.auth.events],
                        benign_sources=env.auth.benign_sources)))
    return out


def detect(
    raw,
    *,
    config: AegisConfig,
    guard: LLMGuard,
    actor_graph: ActorGraph | None = None,
    crawler_allowlisted: bool = False,
) -> Verdict:
    """Run the full detection pipeline over one telemetry unit and return an honest Verdict.

    ``raw`` is a dict / JSON str/bytes / ``TelemetryEnvelope``. ``actor_graph`` is the shared,
    continuously-updated per-actor belief graph (a fresh one is made if omitted)."""
    if isinstance(raw, TelemetryEnvelope):
        raw = raw.model_dump(mode="json")
    env = ingest(raw, config)
    actor_graph = actor_graph if actor_graph is not None else ActorGraph()
    actor_id = env.actor.node_id

    # 1-3. sensors → observations → per-actor Beta belief.
    observations = []
    if env.surface is Surface.LLM:
        observations = LLMInteractionSensor(config).observations(env, seq=env.seq)
    elif env.surface is Surface.REQUEST:
        observations = RequestTelemetrySensor(config).observations(
            env, seq=env.seq, crawler_allowlisted=crawler_allowlisted,
            honeypot_paths=guard.honeypot_paths)
    elif env.surface is Surface.AUTH:
        observations = AuthTelemetrySensor(config).observations(env, seq=env.seq)
    actor_graph.observe_all(observations)
    contributing = [o.obs_id for o in observations]

    candidates = _candidates(env, guard, crawler_allowlisted=crawler_allowlisted)
    primary_class = candidates[0][0] if candidates else "automated_access"

    # 4-6. the oracle gate + the veracity firewall. The FIRST candidate that both fires AND is
    #      admitted as a fact wins. No oracle fired / admit demoted → not confirmed.
    verifier = OracleVerifier()
    confirmed_class: str | None = None
    certificate: CertRef | None = None
    confirmed_conf = 0.0
    for bug_class, fc in candidates:
        cf = confirm_finding({"bug_class": bug_class}, fc, verifier=verifier)
        if cf is None:
            continue
        oracle_context = fc.to_verifier_context()
        token = GroundingToken.oracle(
            oracle_context, bug_class=bug_class,
            confirmed_by=cf.confirmed_by.value, confidence=cf.confidence)
        claim = Claim(
            text=f"aegis: confirmed {bug_class} by {cf.confirmed_by.value}",
            source="aegis", bug_class=bug_class, tokens=[token], entity_refs=[actor_id])
        admitted = admit(claim, world=actor_graph.world, verifier=verifier)
        if not admitted.is_fact:
            continue   # firewall demoted (e.g. fabricated actor) — never confirm
        confirmed_class = bug_class
        confirmed_conf = cf.confidence
        certificate = CertRef.mint(
            oracle_context, bug_class=bug_class,
            confirmed_by=cf.confirmed_by.value, confidence=cf.confidence)
        break

    # 7. decision + SCE posterior vs the MECE benign twin.
    if confirmed_class is not None:
        attack_class = confirmed_class
        decision = "confirmed"
        provenance = f"grounded:aegis:{attack_class}"
        finding = {"bug_class": attack_class, "confidence": confirmed_conf,
                   "confirmed_by": "oracle", "oracle_context": certificate.oracle_context}
    else:
        # LEAD iff a structural-override marker raised belief (LLM); else CLEAR ("no oracle
        # fired and signals below band" — NOT "safe").
        lead_signal = any(o.polarity.value == "affirms" and o.confidence >= 0.5
                          for o in observations)
        decision = "lead" if lead_signal else "clear"
        # a marker-driven LLM lead names the ATTEMPTED attack the markers indicate
        # (prompt_injection) — honestly a LEAD, never confirmed; a CLEAR keeps the tested class.
        if env.surface is Surface.LLM and decision == "lead":
            attack_class = "prompt_injection"
        else:
            attack_class = primary_class
        provenance = f"intel:aegis:{attack_class}"
        prior = _LEAD_PRIOR if decision == "lead" else _CLEAR_PRIOR
        finding = {"bug_class": attack_class, "confidence": prior, "confirmed_by": "", "oracle_context": None}

    report = assess_finding(finding)
    band = (report.focal.ci_low, report.focal.ci_high)
    top_alternative = (
        (report.alternatives[0].id, report.alternatives[0].posterior)
        if report.alternatives else None
    )

    # 8. enforce-mode action rides ONLY on a confirmed certificate (doctrine D1); default observe.
    action = "observe"
    if config.mode == "enforce" and decision == "confirmed":
        action = "challenge"

    anchor = certificate.cert_id if certificate is not None else decision
    refutation = RefuteChannel(
        how_to_dispute="dispute via the operator's AEGIS console with this dismiss_token (feeds credit_outcome)",
        dismiss_token=_dismiss_token(actor_id, normalize_bug_class(attack_class), anchor))

    return Verdict(
        decision=decision,
        attack_class=attack_class,
        confidence=report.focal.posterior,
        belief=actor_graph.belief(actor_id),
        band=band,
        top_alternative=top_alternative,
        certificate=certificate,
        provenance=provenance,
        action=action,
        refutation=refutation,
        contributing=contributing,
    )
