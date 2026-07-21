"""
vigil_integration.safety — the untrusted-input + typed-proposal boundary (VIGIL-FUSION F1).

Two load-bearing invariants every later fusion phase depends on:

  * everything the LLM READS is framed as untrusted DATA (``prompt_safety``);
  * everything the LLM EMITS is a typed, non-authoritative PROPOSAL (``llm_intake``);

plus two deny-by-default pre-filters that sit BEFORE the charter/gate and complement — never
replace — the sovereign core:

  * ``hard_guardrail`` — a deterministic, non-disableable scope block for categorically-never targets
    (government / military / educational / intergovernmental), evaluated before the charter is even
    consulted;
  * ``url_guard`` — an application-layer SSRF/metadata pre-filter for LLM inference endpoints and
    agent fetch targets, delegating IP classification to the P6 egress gate's denylist so there is a
    single source of truth for the always-denied ranges.

Design note (the fusion doctrine): these guards HARDEN the sovereign core; they are not authorities.
A guard may only DENY / frame / downgrade — a signed FACT and an authorization still come solely from
the deterministic oracle and the conjunctive gate. Every lenient/fail-open default from the source
material (redamon, MIT) is inverted to deny-by-default here.

Import-clean: stdlib + ``vigil_gateway.denylist`` (a pure, offense-free module) only — no
``framework.*``/``strix.*``, so it runs in either environment.
"""

from .hard_guardrail import HardBlockError, is_hard_blocked, normalize_domain
from .llm_intake import (
    ProposalParseError,
    extract_json,
    is_transient_llm_error,
    parse_proposal,
    retry_call,
)
from .prompt_safety import UNTRUSTED_OUTPUT_GUIDANCE, wrap_untrusted, wrap_untrusted_inline
from .url_guard import UnsafeURLError, assert_safe_url, is_safe_url

__all__ = [
    "UNTRUSTED_OUTPUT_GUIDANCE",
    "wrap_untrusted",
    "wrap_untrusted_inline",
    "HardBlockError",
    "is_hard_blocked",
    "normalize_domain",
    "ProposalParseError",
    "extract_json",
    "parse_proposal",
    "is_transient_llm_error",
    "retry_call",
    "UnsafeURLError",
    "assert_safe_url",
    "is_safe_url",
]
