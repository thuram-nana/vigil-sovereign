"""
aegis.sensors — the inbound producers, implementing the universal ``sensors.base.Sensor``.

A Sensor mints OBSERVATIONS, never facts (``sensors/base.py`` doctrine): each observation
enters the per-actor world-model as ``GROUNDING_INTEL`` (the ``intel:`` tier) and reaches
FACT strength only when an AEGIS oracle re-fires (``pipeline.detect``). The two MVP sensors:

  * ``LLMInteractionSensor``  — normalises one LLM turn (class 1). A structural-override
    marker in the user turn raises belief (a LEAD); a provably-benign turn REFUTES.
  * ``RequestTelemetrySensor`` — normalises one in-request-path event (the honeypot tripwire).
    A honeypot-path fetch raises belief; an allowlisted known-good crawler REFUTES.

Determinism: ``obs_id`` is the ``(source_kind, seq, actor, claim)`` key — no positional
counter, no wallclock, no rng — so re-ingest / reordering collapses idempotently and the Beta
belief never inflates from input ordering.
"""

from __future__ import annotations

from typing import Any

from ..agents.tools import ToolContext, ToolResult
from ..intel.models import (
    Credibility,
    IntelSourceKind,
    Observation,
    Polarity,
    Reliability,
    SourceReliability,
)
from ..intel.refs import EntityRef
from ..worldmodel.models import NodeKind
from .boundary import structural_override_markers
from .models import AegisConfig, TelemetryEnvelope

# In-request-path / LLM telemetry is a LEAD tier, exactly like the third-party web-scanner
# source: reliability C, credibility 3 — real, but never a fact on its own.
_LEAD_RELIABILITY = SourceReliability(reliability=Reliability.C, credibility=Credibility.C3)


def _actor_ref(env: TelemetryEnvelope) -> EntityRef:
    """The world-model node (NodeKind.SESSION) this actor projects onto."""
    return EntityRef(kind=NodeKind.SESSION, key=env.actor.stable_key)


def _mint(
    subject: EntityRef, *, source_kind: IntelSourceKind, seq: int, claim: str,
    confidence: float, polarity: Polarity, evidence: str, attrs: dict | None = None,
) -> Observation:
    src = f"aegis:{source_kind.value}"
    return Observation(
        obs_id=f"{src}:{seq}:{subject.node_id}|{claim}",
        source=src, source_kind=source_kind, collector="aegis",
        subject=subject, attrs=attrs or {}, source_reliability=_LEAD_RELIABILITY,
        confidence=confidence, polarity=polarity, seq=seq, evidence=evidence,
    )


class LLMInteractionSensor:
    """Normalises one LLM interaction into per-actor observations (source_kind
    ``llm_interaction``). Passive: it inspects already-observed I/O; it never calls the LLM."""

    name = "aegis.llm_interaction"

    def __init__(self, config: AegisConfig) -> None:
        self._config = config

    # -- Sensor protocol ---------------------------------------------------
    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        """Passive wrap of already-provided telemetry (no traffic) — the Sensor protocol's
        gated ``run``. The envelope rides in ``args['envelope']``; nothing is fetched."""
        return ToolResult(ok=True, summary="aegis llm telemetry (passive)", output=dict(args or {}))

    def normalize(self, result: ToolResult, ctx: ToolContext, *, seq: int) -> list[Observation]:
        env = TelemetryEnvelope.model_validate(result.output.get("envelope"))
        return self.observations(env, seq=seq)

    # -- convenience -------------------------------------------------------
    def observations(self, env: TelemetryEnvelope, *, seq: int) -> list[Observation]:
        if env.llm is None:
            return []
        subject = _actor_ref(env)
        out = [_mint(subject, source_kind=IntelSourceKind.LLM_INTERACTION, seq=seq,
                     claim="llm_turn", confidence=0.2, polarity=Polarity.AFFIRMS,
                     evidence="actor made an LLM interaction")]
        markers = structural_override_markers(env.llm.user_input, max_chars=self._config.max_field_chars)
        if markers:
            # a structural-override marker RAISES belief — but it is only a LEAD; the oracle confirms.
            out.append(_mint(subject, source_kind=IntelSourceKind.LLM_INTERACTION, seq=seq,
                             claim="override_marker", confidence=0.5, polarity=Polarity.AFFIRMS,
                             evidence=f"structural-override markers in user turn: {markers}",
                             attrs={"markers": markers}))
        else:
            # a clean turn with no override markers is a (weak) REFUTES — it lowers suspicion.
            out.append(_mint(subject, source_kind=IntelSourceKind.LLM_INTERACTION, seq=seq,
                             claim="clean_turn", confidence=0.5, polarity=Polarity.REFUTES,
                             evidence="no structural-override markers in the user turn (benign)"))
        return out


class RequestTelemetrySensor:
    """Normalises one in-request-path event into per-actor observations (source_kind
    ``request_telemetry``). Watches for honeypot-path fetches; an allowlisted crawler REFUTES."""

    name = "aegis.request_telemetry"

    def __init__(self, config: AegisConfig) -> None:
        self._config = config

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        return ToolResult(ok=True, summary="aegis request telemetry (passive)", output=dict(args or {}))

    def normalize(self, result: ToolResult, ctx: ToolContext, *, seq: int) -> list[Observation]:
        env = TelemetryEnvelope.model_validate(result.output.get("envelope"))
        crawler_allowlisted = bool(result.output.get("crawler_allowlisted", False))
        return self.observations(env, seq=seq, crawler_allowlisted=crawler_allowlisted)

    def observations(self, env: TelemetryEnvelope, *, seq: int, crawler_allowlisted: bool = False,
                     honeypot_paths: Any = None) -> list[Observation]:
        if env.requested_path is None:
            return []
        subject = _actor_ref(env)
        # Single source of truth: when the caller (the pipeline) passes the guard's live
        # honeypot set, use it — so the sensor's lead-tagging can never desync from the
        # AUTOMATED_ACCESS oracle (which judges membership against the same guard set).
        paths = set(honeypot_paths) if honeypot_paths is not None else set(self._config.honeypot_paths)
        is_honeypot = env.requested_path in paths
        if is_honeypot and not crawler_allowlisted:
            return [_mint(subject, source_kind=IntelSourceKind.REQUEST_TELEMETRY, seq=seq,
                          claim="honeypot_fetch", confidence=0.6, polarity=Polarity.AFFIRMS,
                          evidence=f"fetched honeypot path {env.requested_path!r}",
                          attrs={"path": env.requested_path})]
        if is_honeypot and crawler_allowlisted:
            # allowlisted known-good crawler/monitor — its honeypot fetch REFUTES suspicion (P1).
            return [_mint(subject, source_kind=IntelSourceKind.REQUEST_TELEMETRY, seq=seq,
                          claim="allowlisted_fetch", confidence=0.6, polarity=Polarity.REFUTES,
                          evidence="allowlisted known-good crawler/monitor fetched the honeypot (benign)")]
        return [_mint(subject, source_kind=IntelSourceKind.REQUEST_TELEMETRY, seq=seq,
                      claim="request", confidence=0.15, polarity=Polarity.AFFIRMS,
                      evidence=f"request for {env.requested_path!r}")]


class AuthTelemetrySensor:
    """Normalises one auth-outcome window into per-actor observations (source_kind
    ``auth_telemetry``). Passive: it inspects already-observed login outcomes; it never
    authenticates anyone.

    A breadth of UNSEEN-(account, source) SUCCESSES across many accounts RAISES belief (a LEAD —
    the credential_stuffing oracle CONFIRMS). A failed-only burst stays a LEAD (it raises
    suspicion but can never be confirmed — the NAT/CGNAT benign twin). A benign returning-user
    window REFUTES. Allowlisted known-good egress sources are excluded (their successes REFUTE)."""

    name = "aegis.auth_telemetry"

    def __init__(self, config: AegisConfig) -> None:
        self._config = config

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        return ToolResult(ok=True, summary="aegis auth telemetry (passive)", output=dict(args or {}))

    def normalize(self, result: ToolResult, ctx: ToolContext, *, seq: int) -> list[Observation]:
        env = TelemetryEnvelope.model_validate(result.output.get("envelope"))
        return self.observations(env, seq=seq)

    def observations(self, env: TelemetryEnvelope, *, seq: int) -> list[Observation]:
        if env.auth is None:
            return []
        subject = _actor_ref(env)
        allow = set(env.auth.benign_sources)
        # replay (bounded — the boundary already capped the window): count unseen-(account, source)
        # successes and the fail/success mix over the NON-allowlisted sources. Deterministic.
        seen: set[tuple[str, str]] = set()
        unseen_success = 0
        n_success = 0
        n_failure = 0
        for e in env.auth.events:
            if e.source in allow:
                continue
            if e.success:
                n_success += 1
                key = (e.source, e.account)
                if key not in seen:
                    unseen_success += 1
                    seen.add(key)
            else:
                n_failure += 1
        out = [_mint(subject, source_kind=IntelSourceKind.AUTH_TELEMETRY, seq=seq,
                     claim="auth_window", confidence=0.2, polarity=Polarity.AFFIRMS,
                     evidence=f"auth window of {len(env.auth.events)} outcome(s)")]
        if unseen_success >= 2:
            # breadth of unseen-pair successes RAISES belief — a LEAD; only the oracle confirms.
            out.append(_mint(subject, source_kind=IntelSourceKind.AUTH_TELEMETRY, seq=seq,
                             claim="unseen_pair_successes", confidence=0.55, polarity=Polarity.AFFIRMS,
                             evidence=f"{unseen_success} unseen-(account, source) successes across accounts",
                             attrs={"unseen_success": unseen_success, "distinct": len(seen)}))
        elif n_failure and not n_success:
            # a failed-only burst is a LEAD (raises suspicion) but can NEVER be confirmed here
            # (the oracle keys on successes) — the NAT/CGNAT benign twin.
            out.append(_mint(subject, source_kind=IntelSourceKind.AUTH_TELEMETRY, seq=seq,
                             claim="failed_burst", confidence=0.5, polarity=Polarity.AFFIRMS,
                             evidence=f"{n_failure} failed logins, no successes — stays a LEAD (NAT/CGNAT twin)",
                             attrs={"failures": n_failure}))
        else:
            # a returning-user window (repeat successes / few unseen pairs) REFUTES.
            out.append(_mint(subject, source_kind=IntelSourceKind.AUTH_TELEMETRY, seq=seq,
                             claim="benign_auth", confidence=0.5, polarity=Polarity.REFUTES,
                             evidence="auth window consistent with returning users (benign)"))
        return out
