"""secret_discovery — the WARDEN-gated exposed-secret DISCOVERY runner (BUILD-PLAN §E5, discovery half).

The COMPLEMENT of ``secret_runner`` (which VALIDATES one operator-supplied secret) and of the E5 oracle
(``framework.v2.verify.oracles.exposed_secret_validity_oracle``, which ADJUDICATES a validated capture to a
FACT). This module HUNTS: it scans a retained text surface (a JS bundle, a git blob, a config file, an env
dump) for strings whose SHAPE matches a known secret format and emits a secret-safe CANDIDATE for each.

THE INVARIANT THIS MODULE ENFORCES — a candidate is a LEAD, never a FACT. A regex match on a byte string is
a structural HINT, not proof a secret is valid; a value that merely LOOKS like an AWS key may be a rotated,
revoked, or example key. So this runner:

  * emits only ``SecretCandidate`` objects whose ``verdict`` is permanently ``"LEAD"`` — there is NO code path
    in this module that mints, admits, certifies, or otherwise promotes a candidate to a FACT;
  * to become a FACT a candidate must be handed to the SEPARATE, WARDEN-gated ``secret_runner`` (which issues
    the per-type confirming call) and then adjudicated by the deterministic E5 oracle over that capture. The
    oracle remains the SOLE authority — discovery bytes alone never fire it (a candidate with no confirming
    call is left a LEAD, proven by ``integration/tests/test_secret_discovery.py``).

SECRET-SAFE. A candidate NEVER retains the raw matched value: it keeps a short non-secret IDENTIFIER (an AWS
AccessKeyId is a public id; a prefixed token keeps only its ``ghp_``/``glpat-``/``xox?-`` prefix), a REDACTED
preview (a masked, length-annotated form), and a domain-separated FINGERPRINT (``secret_runner.secret_fingerprint``
— the SAME fingerprint the validation runner stamps, so a later validated FACT can be correlated back to the
candidate WITHOUT the raw value ever being stored here). The raw match is discarded inside ``scan``.

DISCOVERY RECOGNISES A SUPERSET of the oracle's FACT-capable types. ``fact_capable`` on a candidate is TRUE
iff its type is one the E5 oracle can adjudicate (the ``secret_runner`` table — kept in sync by import, not a
second copy). Shapes with no sound identity-confirming endpoint (a Google API key is not identity-bound; a
Slack incoming-webhook URL grants posting, not an identity) are recognised as LEADs but are HONESTLY marked
``fact_capable=False`` — they can be reported, but they are not promotable to a FACT by this system.

FATAL-2 / purity: stdlib only at module scope (plus the offense-free ``secret_runner`` sibling), so importing
this co-loads no offense engine. There is no network I/O here at all — it reads a string a caller already
retained.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Pattern

# The FACT-capable secret types are exactly those the WARDEN-gated validation runner (and thus the E5 oracle)
# supports — imported, never re-listed, so discovery's ``fact_capable`` labelling cannot drift from the set the
# oracle can actually adjudicate. ``secret_runner`` is offense-import-free at module scope, so this stays
# sovereign-safe.
from .secret_runner import SUPPORTED_SECRET_TYPES, secret_fingerprint

_FACT_CAPABLE_TYPES = frozenset(SUPPORTED_SECRET_TYPES)

# How many leading characters of a matched value are shown in the redacted preview (never the whole secret).
_REVEAL = 4


def _prefix_identifier(n: int) -> Callable[[str], str]:
    """A non-secret identifier that is the first ``n`` characters of the match (a structural prefix)."""
    return lambda m: m[:n]


def _whole_identifier(m: str) -> str:
    """The whole match is a PUBLIC identifier (e.g. an AWS AccessKeyId is not itself the secret)."""
    return m


# The discovery recognizer table: secret_type -> (compiled full-token pattern, identifier extractor). This is a
# SUPERSET of the oracle's recognizer set: the first four rows are FACT-capable (the oracle can adjudicate them
# given a confirming call); ``google_api_key`` and ``slack_webhook_url`` are DISCOVERY-only LEADs (no sound
# identity-confirming endpoint), honestly non-promotable. Patterns are anchored on word/URL boundaries to keep
# recall high without matching arbitrary substrings.
DISCOVERY_PATTERNS: "dict[str, tuple[Pattern[str], Callable[[str], str]]]" = {
    # --- FACT-capable (a confirming call can promote these via secret_runner + the E5 oracle) ---
    "aws_access_key": (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), _whole_identifier),
    "github_pat": (re.compile(r"\b(?:gh[posru]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b"),
                   _prefix_identifier(4)),
    "gitlab_pat": (re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b"), _prefix_identifier(6)),
    "slack_token": (re.compile(r"\bxox[baprse]-[A-Za-z0-9-]{10,}\b"), _prefix_identifier(5)),
    # --- discovery-only LEADs (recognised, but NOT FACT-capable — no sound identity endpoint) ---
    "google_api_key": (re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), _prefix_identifier(4)),
    "slack_webhook_url": (re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9_]+/[A-Za-z0-9_]+/[A-Za-z0-9_]+"),
                          lambda _m: "hooks.slack.com/services/"),
}


def discovery_types() -> "frozenset[str]":
    """Every secret type this runner can recognise (a superset of the FACT-capable set)."""
    return frozenset(DISCOVERY_PATTERNS)


def fact_capable_types() -> "frozenset[str]":
    """The recognised types the E5 oracle can adjudicate to a FACT (given a WARDEN-gated confirming call)."""
    return _FACT_CAPABLE_TYPES


def _redact(match: str) -> str:
    """A secret-safe preview: a few leading characters, then a mask, then the length. The raw value is never
    stored on the candidate — only this preview and the fingerprint survive."""
    head = match[:_REVEAL]
    return f"{head}…[REDACTED, {len(match)} chars]"


@dataclass(frozen=True)
class SecretCandidate:
    """One discovered secret candidate — a LEAD. Secret-safe: no raw value is retained.

    ``verdict`` is a constant ``"LEAD"``: discovery never produces a FACT. ``fact_capable`` says only whether
    the E5 oracle COULD adjudicate this type to a FACT if a WARDEN-gated confirming call were made; discovery
    itself makes no such call and mints nothing."""

    secret_type: str
    identifier: str          # a non-secret structural id (AWS AccessKeyId / token prefix)
    redacted: str            # a masked, length-annotated preview — never the raw value
    fingerprint: str         # domain-separated (secret_runner.secret_fingerprint) — correlates to a later FACT
    source: str              # where it was found (a locator string the caller supplies)
    start: int               # byte offset of the match within the scanned text
    fact_capable: bool       # whether the E5 oracle can adjudicate this type (given a confirming call)

    @property
    def verdict(self) -> str:
        return "LEAD"


def scan(text: str, *, source: str = "", max_candidates: int = 1000) -> "list[SecretCandidate]":
    """Scan ``text`` for secret candidates and return secret-safe LEADs (never FACTs).

    Every match is fingerprinted (so a later validated FACT can be correlated) and then the raw value is
    DISCARDED — only the non-secret identifier, a redacted preview, and the fingerprint are kept. ``source`` is
    a locator string retained as evidence. ``max_candidates`` bounds output. Never raises on odd input: a
    non-string yields an empty list."""
    if not isinstance(text, str) or not text:
        return []
    out: "list[SecretCandidate]" = []
    seen: "set[tuple[str, int]]" = set()
    for secret_type, (pattern, identify) in DISCOVERY_PATTERNS.items():
        fact_capable = secret_type in _FACT_CAPABLE_TYPES
        for m in pattern.finditer(text):
            raw = m.group(0)
            key = (secret_type, m.start())
            if key in seen:
                continue
            seen.add(key)
            out.append(SecretCandidate(
                secret_type=secret_type,
                identifier=identify(raw),
                redacted=_redact(raw),
                fingerprint=secret_fingerprint(raw),   # raw is used ONLY to fingerprint, then dropped
                source=source,
                start=m.start(),
                fact_capable=fact_capable,
            ))
            if len(out) >= max_candidates:
                return out
    return out


def candidate_finding(candidate: SecretCandidate) -> dict:
    """A LEAD finding dict for a discovered candidate — for a report / the world model. It is a LEAD by
    construction: promoting it to a FACT requires the SEPARATE WARDEN-gated ``secret_runner`` confirming call
    and the E5 oracle's adjudication over that capture. This function never mints, admits, or certifies."""
    return {
        "check_id": f"secret_discovery:{candidate.secret_type}:{candidate.fingerprint[:19]}",
        "bug_class": "secret_exposure",
        "verdict": "LEAD",
        "secret_type": candidate.secret_type,
        "identifier": candidate.identifier,
        "redacted": candidate.redacted,
        "source": candidate.source,
        "fact_capable": candidate.fact_capable,
        "note": ("a structurally-recognised secret candidate (a LEAD). Validity is NOT proven here — it "
                 "becomes a FACT only via the WARDEN-gated secret_runner confirming call adjudicated by the "
                 "E5 oracle" + ("" if candidate.fact_capable else
                                "; this TYPE has no sound identity-confirming endpoint, so it is NOT "
                                "promotable to a FACT by this system and stays a LEAD permanently")),
    }
