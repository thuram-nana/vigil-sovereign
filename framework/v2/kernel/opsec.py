"""
opsec() — wraps framework/cognitive/opsec-discipline.md.

Posture-aware guidance for a proposed action. Returns OpsecGuidance
that says whether the action is allowed in the current posture, what
pre-approval is required, and the concrete UA / rate / cleanup
expectations.
"""

from __future__ import annotations

from .binding import run
from .llm import LLMBackend
from .models import CallTrace, OpsecGuidance


def opsec(
    action_summary: str,
    *,
    posture: str = "TEST",
    target_url: str = "",
    expected_traffic: str = "",
    backend: LLMBackend | None = None,
) -> tuple[OpsecGuidance, CallTrace]:
    """Return posture-aware guidance for an action.

    Args:
        action_summary: one-sentence description of what's about to run.
        posture: TEST / AUDIT / EMULATE.
        target_url: full URL or hostname; affects routing decisions.
        expected_traffic: e.g. "1 request" / "ffuf 100k wordlist" /
            "stored XSS payload to ticket subject".
        backend: override the active LLM backend.

    Returns:
        (OpsecGuidance, CallTrace).
    """
    structured = {
        "action_summary": action_summary,
        "posture": posture.upper(),
        "target_url": target_url,
        "expected_traffic": expected_traffic,
    }
    parsed, trace = run(
        schema=OpsecGuidance,
        schema_name="OpsecGuidance",
        cognitive_doc_stem="opsec-discipline",
        section_anchors=[
            "1-three-postures",
            "2-test-posture-the-defaults",
            "3-audit-posture-additions",
            "4-emulate-posture-additions",
            "7-what-you-do-not-do-ever-in-any-posture",
        ],
        task_directive=(
            "Decide whether the action is allowed under the requested "
            "posture. The § 7 absolutes (attack out-of-scope systems, "
            "exfil real PII, real-money movement, real-user contact, "
            "destructive cleanup) are inviolable in any posture and "
            "require allowed=false. Mark pre_approval_required=true for "
            "anything that could change state at scale (mass account "
            "creation, mass orders, admin settings, payment provider "
            "callbacks with real money, file uploads). Set posture-"
            "appropriate user_agent_recommendation and "
            "rate_limit_recommendation per § 2 / 3 / 4. List "
            "cleanup_required artefacts."
        ),
        structured_input=structured,
        backend=backend,
    )
    assert isinstance(parsed, OpsecGuidance)
    return parsed, trace
