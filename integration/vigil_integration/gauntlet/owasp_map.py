"""
gauntlet.owasp_map — the OWASP-LLM-Top-10 taxonomy + the FACT/LEAD routing seam (VIGIL-FUSION F8).

Adapted from redamon's ``ai_attack_surface_scan/adapters/**/owasp_map.py`` (MIT; see NOTICE). Each
red-team probe / attack / detector / plugin family maps to a 3-tuple ``(owasp_llm_id, chip,
oracle_kind)`` — co-locating WHAT the finding is (the OWASP LLM category) with HOW it can be confirmed
(``oracle_kind``). The ``oracle_kind`` field is the load-bearing seam this whole sensor family exists to
exploit:

  * ``contains`` / ``classifier`` / ``regex`` are **DETERMINISTIC** kinds — a VIGIL randomized-challenge
    oracle can RE-EXECUTE the check over a fresh per-run token, so a confirmed one may mint a signed
    FACT (see ``gauntlet.sensor``).
  * ``judge_llm`` is **NON-DETERMINISTIC** — the verdict comes from an LLM judge (an ASR, a toxicity
    score). It can NEVER be re-executed into a deterministic proof, so it stays a LEAD forever. Piping
    an LLM-judge ASR straight to a signed FACT would launder a guess into the transparency log; that is
    exactly the sovereign-honesty violation F8 must not commit.

Sovereign inversion of redamon's fail-open default: redamon falls back to
``('LLM01','prompt-injection','classifier')`` for an unknown probe — i.e. an UNKNOWN category becomes
eligible for the deterministic (promotable) path. VIGIL inverts this: an unmapped/unknown category
defaults to ``judge_llm`` so it can only ever be a LEAD. We never route a category we have not
classified onto the promotion path.

Pure/deterministic. Import-clean (stdlib only).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# --- oracle_kind vocabulary ---------------------------------------------------------------------

CONTAINS = "contains"
CLASSIFIER = "classifier"
REGEX = "regex"
JUDGE_LLM = "judge_llm"

# The kinds a deterministic randomized-challenge oracle can RE-EXECUTE → eligible for a signed FACT.
# ``judge_llm`` is deliberately absent: it is NON-deterministic and can only ever produce a LEAD.
DETERMINISTIC_KINDS = frozenset({CONTAINS, CLASSIFIER, REGEX})


@dataclass(frozen=True)
class OwaspEntry:
    """One taxonomy row: the OWASP LLM id, the human chip label, and the confirmation kind."""

    owasp_llm_id: str
    chip: str
    oracle_kind: str

    def as_tuple(self) -> tuple[str, str, str]:
        return (self.owasp_llm_id, self.chip, self.oracle_kind)

    @property
    def is_deterministic(self) -> bool:
        return self.oracle_kind in DETERMINISTIC_KINDS


# Sovereign fail-closed default: an UNMAPPED category can only ever be a LEAD (judge_llm), never routed
# onto the deterministic promotion path. This is the inversion of redamon's fail-open classifier default.
DEFAULT_ENTRY = OwaspEntry("unmapped", "unmapped", JUDGE_LLM)


# The canonical map. Keys are lowercased family/chip names; a probe classname like
# ``promptinject.HijackHateHumans`` reduces to its family (``promptinject``) via ``family_of``. The
# deterministic-vs-judge split follows redamon's own ``oracle_kind`` reality (the SCOUT-INVENTORY §5 C7
# examples) — its "depends on the LLM judge" categories are the ``judge_llm`` rows here.
OWASP_MAP: dict[str, OwaspEntry] = {
    # --- LLM01 prompt injection / jailbreak (garak promptinject, dan; promptfoo injection) ---------
    "promptinject": OwaspEntry("LLM01", "prompt-injection", CLASSIFIER),
    "prompt-injection": OwaspEntry("LLM01", "prompt-injection", CLASSIFIER),
    "injection": OwaspEntry("LLM01", "prompt-injection", CLASSIFIER),
    "dan": OwaspEntry("LLM01", "jailbreak", CLASSIFIER),
    "jailbreak": OwaspEntry("LLM01", "jailbreak", CLASSIFIER),
    "grandma": OwaspEntry("LLM01", "jailbreak", CLASSIFIER),
    # encoding-bypass: a DETERMINISTIC decode-check (base64/rot13/…) — regex/decode, re-executable.
    "encoding": OwaspEntry("LLM01", "encoding-bypass", REGEX),
    "base64": OwaspEntry("LLM01", "encoding-bypass", REGEX),
    # --- LLM02 sensitive-information disclosure (garak apikey leak — deterministic canary contains) --
    "apikey": OwaspEntry("LLM02", "data-disclosure", CONTAINS),
    "data-disclosure": OwaspEntry("LLM02", "data-disclosure", CONTAINS),
    "secret-leak": OwaspEntry("LLM02", "data-disclosure", CONTAINS),
    "pii": OwaspEntry("LLM02", "pii-leak", CONTAINS),
    "pii-leak": OwaspEntry("LLM02", "pii-leak", CONTAINS),
    # --- LLM03 supply chain (garak packagehallucination — classifier over package names) ------------
    "packagehallucination": OwaspEntry("LLM03", "supply-chain", CLASSIFIER),
    "supply-chain": OwaspEntry("LLM03", "supply-chain", CLASSIFIER),
    # --- LLM06 training-data / sensitive leak replay (garak leakreplay — canary contains) -----------
    "leakreplay": OwaspEntry("LLM06", "training-data-leak", CONTAINS),
    "training-data-leak": OwaspEntry("LLM06", "training-data-leak", CONTAINS),
    # --- LLM07 system-prompt leakage (garak sysprompt extraction — deterministic contains) ----------
    "sysprompt": OwaspEntry("LLM07", "system-prompt-leak", CONTAINS),
    "sysprompt_extraction": OwaspEntry("LLM07", "system-prompt-leak", CONTAINS),
    "system-prompt-leak": OwaspEntry("LLM07", "system-prompt-leak", CONTAINS),
    # --- LLM09 misinformation (garak misleading — classifier) ---------------------------------------
    "misleading": OwaspEntry("LLM09", "misinformation", CLASSIFIER),
    "misinformation": OwaspEntry("LLM09", "misinformation", CLASSIFIER),
    # --- NON-DETERMINISTIC judge_llm categories — an LLM judge decides → ALWAYS a LEAD --------------
    "malwaregen": OwaspEntry("safety", "harmful-generation", JUDGE_LLM),
    "harmful-generation": OwaspEntry("safety", "harmful-generation", JUDGE_LLM),
    "harmful": OwaspEntry("safety", "harmful-generation", JUDGE_LLM),
    "harmfulness": OwaspEntry("safety", "harmful-generation", JUDGE_LLM),
    "toxicity": OwaspEntry("safety", "toxicity", JUDGE_LLM),
    "hate": OwaspEntry("safety", "toxicity", JUDGE_LLM),
    "hallucination": OwaspEntry("LLM09", "hallucination", JUDGE_LLM),
    "stereotypes": OwaspEntry("safety", "bias", JUDGE_LLM),
    "bias": OwaspEntry("safety", "bias", JUDGE_LLM),
    "ethical": OwaspEntry("safety", "ethical-violation", JUDGE_LLM),
}


_FAMILY_SPLIT_RE = re.compile(r"[./:\s]")


def family_of(name: object) -> str:
    """Reduce a probe/attack classname (``promptinject.HijackHateHumans``, ``encoding/InjectBase64``)
    to its lowercased family token. Total: a non-str / empty value yields ``""``."""
    s = str(name or "").strip().lower()
    if not s:
        return ""
    return _FAMILY_SPLIT_RE.split(s, maxsplit=1)[0]


def map_family(family: object) -> OwaspEntry:
    """Look up a family token, falling back to the sovereign ``judge_llm`` default (LEAD-only)."""
    return OWASP_MAP.get(str(family or "").strip().lower(), DEFAULT_ENTRY)


def map_category(name: object) -> OwaspEntry:
    """Resolve any tool-reported category name to its taxonomy row. Tries an exact (lowercased) match,
    then the family token, then the fail-closed ``judge_llm`` default. Total on any input — the emitted
    ``chip``/``owasp_llm_id`` are always TRUSTED taxonomy constants, never the raw (attacker-influenced)
    category string, so nothing untrusted reaches the finding record."""
    s = str(name or "").strip().lower()
    if not s:
        return DEFAULT_ENTRY
    if s in OWASP_MAP:
        return OWASP_MAP[s]
    return OWASP_MAP.get(family_of(s), DEFAULT_ENTRY)


def oracle_kind_of(name: object) -> str:
    """The ``oracle_kind`` for a category (``contains``/``classifier``/``regex``/``judge_llm``)."""
    return map_category(name).oracle_kind


def is_deterministic_category(name: object) -> bool:
    """True iff a category is routed onto the deterministic (FACT-eligible) path. An unmapped or
    ``judge_llm`` category is False — it can only ever be a LEAD."""
    return map_category(name).is_deterministic
