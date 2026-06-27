"""
defender.models — schemas for telemetry modelling and self-detection.

Data flow:

    ActionDescriptor  --telemetry-->  [ActionSignal]
    [ActionSignal] + DetectionRuleset  --scoring-->  DetectionScore
    DetectionScore + Posture  --posture-->  PostureAnnotation

A signal is something an action writes to a telemetry channel (an access
log line, a WAF event, an auth-log failure, a netflow record). A rule is
a Sigma-style detection over signals on one channel. A score is the
self-assessed detectability of the action. None of this mutates an
action or generates a bypass — it measures footprint.
"""

from __future__ import annotations

import enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


# ---------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------


class ActionKind(str, enum.Enum):
    """The shape of an action, for telemetry modelling. Coarse on
    purpose: the channel/signal mapping keys off this."""

    HTTP_REQUEST = "http_request"
    LOGIN_ATTEMPT = "login_attempt"
    INJECTION_PROBE = "injection_probe"      # SQLi/SSTI/cmd payload in a request
    DIRECTORY_BRUTEFORCE = "directory_bruteforce"
    PORT_SCAN = "port_scan"
    GENERIC = "generic"


class ActionDescriptor(BaseModel):
    """A planned or performed action, described enough to model its
    telemetry. `attributes` carries kind-specific detail (payload markers,
    failed-login counts, distinct ports/paths, status codes)."""

    model_config = ConfigDict(extra="forbid")

    kind: ActionKind
    target_surface: str = Field(default="")
    method: str = Field(default="GET")
    user_agent: str = Field(
        default="OBSIDIAN/1.0 (authorized owner-test)",
        description="The framework uses a recognisable UA on purpose "
        "(constitution § VI.4: be correlatable, not evasive).",
    )
    requests: int = Field(default=1, ge=0)
    attributes: dict[str, str] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Signals
# ---------------------------------------------------------------------------

Channel = Literal[
    "http_access_log",
    "waf",
    "auth_log",
    "netflow",
    "edr_process",
    "dns",
]


class ActionSignal(BaseModel):
    """One telemetry record an action emits on one channel. `fields` are
    the matchable attributes a detection rule evaluates."""

    model_config = ConfigDict(extra="forbid")

    channel: str = Field(description="One of the Channel literals.")
    fields: dict[str, str | int] = Field(default_factory=dict)
    note: str = Field(default="")


# ---------------------------------------------------------------------------
# Detection rules
# ---------------------------------------------------------------------------

Severity = Literal["info", "low", "medium", "high", "critical"]
Op = Literal["eq", "ne", "contains", "icontains", "gte", "lte", "in"]


class RuleCondition(BaseModel):
    """One field test. A rule fires when ALL its conditions hold against
    a single signal on the rule's channel."""

    model_config = ConfigDict(extra="forbid")

    field: str
    op: Op
    value: str | int | list[str]


class DetectionRule(BaseModel):
    """A Sigma-style detection over signals on one channel."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1)
    title: str = Field(min_length=1)
    channel: str
    severity: Severity = "medium"
    conditions: list[RuleCondition] = Field(default_factory=list)
    description: str = Field(default="")


# ---------------------------------------------------------------------------
# Scores
# ---------------------------------------------------------------------------


class DetectionHit(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule_id: str
    title: str
    channel: str
    severity: Severity
    why: str = ""


class DetectionScore(BaseModel):
    """Self-assessed detectability of an action."""

    model_config = ConfigDict(extra="forbid")

    kind: ActionKind
    signals_emitted: int = Field(ge=0)
    hits: list[DetectionHit] = Field(default_factory=list)
    detectability: float = Field(ge=0.0, le=1.0, description="noisy-OR over hit severities")
    loudest_channel: str = ""
    loudest_severity: Severity = "info"


# ---------------------------------------------------------------------------
# Posture
# ---------------------------------------------------------------------------


class Posture(str, enum.Enum):
    """TEST: full footprint, maximum correlatability — the default for
    authorised owner-testing (be loud, be greppable). EMULATE: the
    operator wants to understand detectability as an adversary would
    experience it; DEL surfaces honest self-assessment, NOT evasion."""

    TEST = "TEST"
    EMULATE = "EMULATE"


class PostureAnnotation(BaseModel):
    """An action's detectability under a posture, with defensive guidance.
    `guidance` is self-assessment for the operator and the blue team —
    never an evasion recipe."""

    model_config = ConfigDict(extra="forbid")

    posture: Posture
    score: DetectionScore
    guidance: list[str] = Field(default_factory=list)
