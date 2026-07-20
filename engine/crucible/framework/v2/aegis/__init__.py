"""
aegis — AEGIS, the DEFENSIVE dual of CRUCIBLE.

An embeddable AI-attack-detection API built on CRUCIBLE's prove-don't-guess core pointed
inward at the operator's OWN app. A detection is a provenance-tagged LEAD; it becomes a
CONFIRMED AI attack only when a deterministic oracle re-fires over retained evidence and the
veracity firewall admits it — emitting an offline-re-runnable certificate.

MVP scope (class 1 + the honeypot tripwire):
  * ``system_prompt_disclosure`` — a planted high-entropy canary appeared verbatim in the
    app's own LLM output (the secret leaked);
  * ``prompt_injection`` — an injected directive provably flipped a structurally-detectable
    behavior vs a clean control (the adversarial cause);
  * ``automated_access`` — a non-interactive client fetched a seeded honeypot resource.

DOCTRINE: defensive only (never attacks), correlatable, not anti-defender. Default
``mode="observe"`` is read-only. Nothing here is imported by scan/engage/benchmark/__main__ —
``make gate`` stays byte-identical.

Public surface:
    from framework.v2.aegis import Aegis, Surface, Verdict, ActorRef, LLMInteraction
    aegis = Aegis.from_config({"deployment_secret": "..."})
    v = aegis.observe(surface=Surface.REQUEST, actor=ActorRef(ip="203.0.113.7"),
                      requested_path="/__aegis_hp__/xyz")
    with aegis.llm_turn(actor, system_prompt_id="sp_v7") as turn:
        turn.record_input(user_text); turn.record_output(model_out)
        verdict = turn.verdict()
"""

from __future__ import annotations

import json
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from .actor_graph import ActorGraph
from .guard import LLMGuard
from .models import (
    ActorRef,
    AegisConfig,
    AuthActivity,
    AuthEvent,
    BeliefRef,
    CertRef,
    LLMInteraction,
    RefuteChannel,
    Surface,
    TelemetryEnvelope,
    Verdict,
)
from .pipeline import detect

__all__ = [
    "Aegis",
    "Surface",
    "Verdict",
    "ActorRef",
    "LLMInteraction",
    "AuthActivity",
    "AuthEvent",
    "TelemetryEnvelope",
    "AegisConfig",
    "CertRef",
    "BeliefRef",
    "RefuteChannel",
    "LLMGuard",
    "ActorGraph",
    "detect",
]


class LLMTurn:
    """A single LLM turn's recorder (tier B). The app records the untrusted input and the
    model output (and optionally a clean-control-vs-treatment behavior pair), then asks for a
    verdict. Passive: AEGIS never calls the LLM."""

    def __init__(self, aegis: "Aegis", actor: ActorRef, *, system_prompt_id: str,
                 canary: str, seq: int) -> None:
        self._aegis = aegis
        self._actor = actor
        self._system_prompt_id = system_prompt_id
        self._canary = canary
        self._seq = seq
        self._input = ""
        self._output = ""
        self._control: dict[str, Any] | None = None
        self._treatment: dict[str, Any] | None = None

    def record_input(self, user_text: str) -> None:
        self._input = user_text

    def record_output(self, output: str) -> None:
        self._output = output

    def record_behavior(self, *, control: dict[str, Any], treatment: dict[str, Any]) -> None:
        """Record a clean-control-turn behavior vs the attacker-treatment-turn behavior — the
        ONLY path that earns the adversarial ``prompt_injection`` class."""
        self._control = dict(control)
        self._treatment = dict(treatment)

    def verdict(self) -> Verdict:
        llm = LLMInteraction(
            system_prompt_id=self._system_prompt_id, canary=self._canary,
            user_input=self._input, llm_output=self._output,
            control_behavior=self._control, treatment_behavior=self._treatment)
        return self._aegis.observe(surface=Surface.LLM, actor=self._actor, seq=self._seq, llm=llm)


class Aegis:
    """The embeddable facade. Holds the config, the guard (planted canary + honeypot registry),
    and the continuously-updated per-actor belief graph. Thread-affinity is the caller's
    concern; scoring is a pure function of the input, so parallel callers with distinct
    ``seq`` streams stay deterministic."""

    def __init__(self, config: AegisConfig, *, guard: LLMGuard | None = None,
                 actor_graph: ActorGraph | None = None) -> None:
        self.config = config
        self.guard = guard if guard is not None else LLMGuard(
            honeypot_paths=list(config.honeypot_paths) or None,
            crawler_allowlist=list(config.crawler_allowlist) or None)
        # keep config.honeypot_paths in sync with the guard so the sensor sees the same set.
        if not config.honeypot_paths:
            self.config = config.model_copy(update={"honeypot_paths": self.guard.honeypot_paths})
        self.actor_graph = actor_graph if actor_graph is not None else ActorGraph()
        self._seq = 0

    # -- construction ------------------------------------------------------
    @classmethod
    def from_config(cls, source: "str | Path | dict[str, Any] | AegisConfig", *,
                    guard: LLMGuard | None = None) -> "Aegis":
        """Build from a mapping, an ``AegisConfig``, or a path to a JSON/TOML config file.
        (Loads config, warms the guard/oracles, opens the belief graph.)"""
        if isinstance(source, AegisConfig):
            config = source
        elif isinstance(source, dict):
            config = AegisConfig.from_mapping(source)
        else:
            config = _load_config_file(Path(source))
        return cls(config, guard=guard)

    # -- monotonic sequence ------------------------------------------------
    def next_seq(self) -> int:
        """A process-monotonic sequence for callers that don't supply their own. Monotonic,
        deterministic per process, never wallclock."""
        self._seq += 1
        return self._seq

    # -- passive detection (tier A) ---------------------------------------
    def observe(self, *, surface: Surface, actor: ActorRef, seq: int | None = None,
                requested_path: str | None = None, llm: LLMInteraction | None = None,
                auth: AuthActivity | None = None,
                crawler_allowlisted: bool = False) -> Verdict:
        """Ingest one telemetry unit and return a Verdict. PASSIVE and read-only — the default
        ``observe`` mode never invokes a response Tool."""
        seq = self.next_seq() if seq is None else seq
        env = TelemetryEnvelope(surface=surface, actor=actor, seq=seq,
                                requested_path=requested_path, llm=llm, auth=auth)
        return detect(env, config=self.config, guard=self.guard,
                      actor_graph=self.actor_graph, crawler_allowlisted=crawler_allowlisted)

    # -- auth-outcome window (credential-stuffing / ATO) ------------------
    def observe_auth(self, actor: ActorRef, events: "list[AuthEvent | dict[str, Any]]", *,
                     benign_sources: list[str] | None = None, seq: int | None = None) -> Verdict:
        """Ingest one actor's ORDERED auth-outcome window and return a Verdict. Confirms
        ``credential_stuffing`` only when a source's UNSEEN-(account, source) SUCCESSES cross the
        SPRT + Holm family-wise control; a failed-only burst stays a LEAD. PASSIVE / read-only."""
        norm = [e if isinstance(e, AuthEvent) else AuthEvent.model_validate(e) for e in (events or [])]
        auth = AuthActivity(events=norm, benign_sources=list(benign_sources or []))
        return self.observe(surface=Surface.AUTH, actor=actor, seq=seq, auth=auth)

    # -- explicit LLM guard (tier B) --------------------------------------
    @contextmanager
    def llm_turn(self, actor: ActorRef, *, system_prompt_id: str = "",
                 canary: str | None = None, seq: int | None = None) -> Iterator[LLMTurn]:
        """Wrap one chatbot/agent turn. The app records input/output; ``turn.verdict()`` runs
        the canary + control-vs-treatment oracles over the retained I/O."""
        seq = self.next_seq() if seq is None else seq
        yield LLMTurn(self, actor, system_prompt_id=system_prompt_id,
                      canary=canary or self.guard.canary, seq=seq)


def _load_config_file(path: Path) -> AegisConfig:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".toml":
        try:
            import tomllib
        except ModuleNotFoundError as e:   # pragma: no cover - py<3.11
            raise RuntimeError("TOML config requires Python 3.11+ (tomllib)") from e
        data = tomllib.loads(text)
    else:
        data = json.loads(text)
    return AegisConfig.from_mapping(data)
