"""
vigil_integration.kb — three governed knowledge tools (VIGIL-FUSION F12).

Ported from redamon's ``tradecraft_lookup``/``crawl``, ``skill_loader`` and ``llm_guard`` (MIT; see
NOTICE) through the sovereign core (ANALYSIS §5 C9/C12). None of these is an authority:

  * ``corpus`` — an offensive-corpus RAG (``lookup``). Deterministic lexical ranking (jaccard +
    substring overlap) with an INJECTED LLM tiebreak spent only on a genuinely ambiguous query. EVERY
    result body is wrapped in the F1 ``[UNTRUSTED]`` envelope — KB content is a prompt-injection
    channel, never a fact and never an authorization.
  * ``skills`` — a markdown skills loader. Discovers ``.md`` playbooks, parses scalar frontmatter,
    loads a body by id behind an ``is_relative_to`` path-traversal guard, capped at ``MAX_SKILLS``. A
    skill is ADVISORY prompt context only — it grants NO tier and authorizes nothing.
  * ``budget`` — a non-authoritative budget/rate/spend meter. Deterministic (injected ``now``),
    append-only, secret-free. It can only DEFER (advisory back-pressure); it never gates a finding's
    truth (the oracle's job) nor authorizes an action (the gate's job).

Import-clean: pydantic/stdlib + ``safety.prompt_safety`` + ``tools.redact_tool_args`` only.
"""

from .budget import (
    BudgetMeter,
    BudgetVerdict,
    RollingSpendCap,
    TokenBucket,
    constant_time_key_match,
)
from .corpus import (
    AMBIGUITY_MIN_CANDIDATES,
    AMBIGUITY_SCORE_CEILING,
    DEFAULT_TOP_K,
    UNTRUSTED_LABEL,
    CorpusEntry,
    LookupResponse,
    LookupResult,
    TiebreakCandidate,
    lookup,
)
from .skills import MAX_SKILLS, Skill, SkillLoader

__all__ = [
    # corpus RAG
    "lookup",
    "LookupResponse",
    "LookupResult",
    "CorpusEntry",
    "TiebreakCandidate",
    "DEFAULT_TOP_K",
    "AMBIGUITY_MIN_CANDIDATES",
    "AMBIGUITY_SCORE_CEILING",
    "UNTRUSTED_LABEL",
    # skills loader
    "SkillLoader",
    "Skill",
    "MAX_SKILLS",
    # budget meter
    "BudgetMeter",
    "BudgetVerdict",
    "TokenBucket",
    "RollingSpendCap",
    "constant_time_key_match",
]
