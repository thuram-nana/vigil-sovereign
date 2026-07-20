"""
challenge_oracle — per-run randomized-challenge oracles + kernel-minted Verified|Abstain (VIGIL I1).

Generalizes DARPA CGC's proof-of-vulnerability model — Type-1 (set a randomly-chosen register/PC to
a randomly-chosen value) and Type-2 (read a secret placed at a random location) — to every web / API
finding class, so a RECORDED or HALLUCINATED proof is structurally UN-REPLAYABLE:

  * Each confirmation issues a FRESH, unpredictable random challenge (a per-run nonce/canary/token).
  * The finding is VERIFIED only if the live target satisfies THAT specific challenge — a response
    captured for an earlier challenge, or invented by an LLM, cannot satisfy a new one.

Two properties that make this rigorous:

  1. Replay/hallucination impossibility (not merely improbability): the oracle checks the exact
     per-run token, so `verify(new_challenge, response_for_old_challenge)` is always ABSTAIN.
  2. Kernel-minted epistemics (EG-VAR): only the deterministic oracle can MINT a VERIFIED verdict —
     it is HMAC-bound to the exact (kind, token) under a per-run oracle key, so no LLM / critic /
     confidence path can forge the "Verified" token; a downstream trusts a verdict only if its MAC
     verifies. The value is Verified | Abstain — never a bare boolean an agent could assert.

Pure/stdlib-only and import-clean (no framework.*/strix.*): the challenge token is a security nonce
(``secrets``), injectable for deterministic tests; the verdict math is deterministic given inputs.
"""

from __future__ import annotations

import hmac
import json
import secrets
from dataclasses import dataclass
from enum import Enum
from hashlib import sha256
from typing import Callable, Iterable


class Verdict(str, Enum):
    VERIFIED = "verified"  # minted ONLY by a deterministic oracle over a fresh challenge
    ABSTAIN = "abstain"    # the challenge was not satisfied (or evidence absent) — never a fact


@dataclass(frozen=True)
class Challenge:
    kind: str    # "nonce-echo" | "canary-leak" | "oob-token" | "value-control"
    token: str   # the per-run random value the live target must satisfy


TokenFactory = Callable[[], str]


def _default_token() -> str:
    # 128 bits of unpredictability — a captured/guessed token cannot satisfy a fresh challenge.
    return secrets.token_hex(16)


_MIN_TOKEN_LEN = 16  # reject a degenerate low-entropy token (>=64 bits) even if a weak factory is injected


def _valid_token(token: object) -> bool:
    return isinstance(token, str) and len(token) >= _MIN_TOKEN_LEN


class ChallengeOracle:
    """A randomized-challenge oracle for one finding class. Subclasses implement ``_satisfied``."""

    kind: str = "abstract"

    def issue(self, *, token_factory: TokenFactory = _default_token) -> Challenge:
        return Challenge(kind=self.kind, token=token_factory())

    def verify(self, challenge: Challenge, response: object) -> Verdict:
        """VERIFIED iff ``response`` satisfies EXACTLY ``challenge`` (this class's rule); else ABSTAIN.
        Fail-closed: a wrong-kind challenge, or missing/None response, abstains."""
        if (not isinstance(challenge, Challenge) or challenge.kind != self.kind
                or not _valid_token(challenge.token)):
            return Verdict.ABSTAIN
        try:
            return Verdict.VERIFIED if self._satisfied(challenge.token, response) else Verdict.ABSTAIN
        except Exception:
            return Verdict.ABSTAIN  # any evaluation error → abstain, never a false Verified

    def _satisfied(self, token: str, response: object) -> bool:  # pragma: no cover - abstract
        raise NotImplementedError


class NonceEchoOracle(ChallengeOracle):
    """Injection/reflection (SQLi, reflected-XSS, SSTI): the target must ECHO the exact per-run
    nonce back in its response (e.g. the injected ``SELECT '<nonce>'`` or ``{{'<nonce>'}}`` renders)."""

    kind = "nonce-echo"

    def _satisfied(self, token: str, response: object) -> bool:
        return isinstance(response, str) and token in response


class CanaryLeakOracle(ChallengeOracle):
    """Information disclosure / IDOR / LFI: a per-run canary is planted as the protected secret;
    the finding is Verified only if the leak reveals EXACTLY that canary (not merely 'some data')."""

    kind = "canary-leak"

    def _satisfied(self, token: str, response: object) -> bool:
        return isinstance(response, str) and token in response


class OOBTokenOracle(ChallengeOracle):
    """Out-of-band (SSRF, blind RCE/XXE, blind command injection): the target must contact the OOB
    collector carrying the exact per-run token. ``response`` is the set/list of tokens the collector
    observed — Verified only if the fresh token is among them."""

    kind = "oob-token"

    def _satisfied(self, token: str, response: object) -> bool:
        if isinstance(response, (set, frozenset, list, tuple)):
            return token in {str(x) for x in response}
        return isinstance(response, str) and token in response


class ValueControlOracle(ChallengeOracle):
    """Control primitive (memory-safety / code-exec, CGC Type-1): the crash/exec must set the
    controlled register/PC/return-value to EXACTLY the randomly-chosen per-run value. ``response``
    is the achieved value; Verified only on an exact match (constant-time compared)."""

    kind = "value-control"

    def _satisfied(self, token: str, response: object) -> bool:
        return hmac.compare_digest(token, str(response))


# -- kernel-minted, unforgeable verdicts (EG-VAR) ------------------------------------------------


@dataclass(frozen=True)
class MintedVerdict:
    verdict: Verdict
    challenge: Challenge
    mac: str = ""  # HMAC over (kind, token, "verified") under the oracle key; "" for ABSTAIN

    @property
    def is_verified(self) -> bool:
        return self.verdict is Verdict.VERIFIED


def _mac(challenge: Challenge, *, oracle_key: bytes) -> str:
    # Canonical, unambiguous message (a JSON-escaped list) so no (kind, token) pair can collide with
    # another via delimiter confusion — JSON escapes any ':'/'"' inside a field.
    msg = json.dumps(
        ["vigil.i1.verdict", challenge.kind, challenge.token, Verdict.VERIFIED.value],
        separators=(",", ":"), ensure_ascii=False,
    ).encode()
    return hmac.new(oracle_key, msg, sha256).hexdigest()


def mint(verdict: Verdict, challenge: Challenge, *, oracle_key: bytes) -> MintedVerdict:
    """Bind a verdict to its challenge. A VERIFIED verdict carries an HMAC only the holder of
    ``oracle_key`` can produce, so 'Verified' cannot be forged by a non-oracle (LLM/critic)."""
    # Never mint VERIFIED over a degenerate low-entropy token, even if a caller bypasses verify().
    if verdict is Verdict.VERIFIED and not _valid_token(challenge.token):
        verdict = Verdict.ABSTAIN
    mac = _mac(challenge, oracle_key=oracle_key) if verdict is Verdict.VERIFIED else ""
    return MintedVerdict(verdict=verdict, challenge=challenge, mac=mac)


def verify_minted(minted: MintedVerdict, *, oracle_key: bytes) -> bool:
    """True iff ``minted`` is a genuine VERIFIED verdict minted by this oracle key over its
    challenge. Fail-closed: an ABSTAIN, a missing/forged MAC, or any mismatch → False."""
    if not isinstance(minted, MintedVerdict) or minted.verdict is not Verdict.VERIFIED or not minted.mac:
        return False
    return hmac.compare_digest(minted.mac, _mac(minted.challenge, oracle_key=oracle_key))


Prober = Callable[[Challenge], object]


def confirm_with_challenge(
    oracle: ChallengeOracle,
    prober: Prober,
    *,
    oracle_key: bytes,
    token_factory: TokenFactory = _default_token,
) -> MintedVerdict:
    """Issue a fresh challenge, drive the live target with it (``prober(challenge)`` injects the
    token / plants the canary and returns what the target produced), verify, and MINT the verdict.

    This is the anti-hallucination confirmation: ``prober`` must make the REAL target satisfy the
    FRESH token; a stubbed/recorded/invented response cannot, so it abstains.
    """
    challenge = oracle.issue(token_factory=token_factory)
    response = prober(challenge)
    verdict = oracle.verify(challenge, response)
    return mint(verdict, challenge, oracle_key=oracle_key)


# A registry so a bug_class can select its randomized-challenge oracle.
_ORACLES = {o.kind: o for o in (NonceEchoOracle(), CanaryLeakOracle(), OOBTokenOracle(), ValueControlOracle())}

# Which challenge kind proves which bug class (the oracle-mappable set from the honesty invariant).
BUG_CLASS_CHALLENGE = {
    "sqli": "nonce-echo",
    "xss": "nonce-echo",
    "ssti": "nonce-echo",
    "reflection": "nonce-echo",
    "idor": "canary-leak",
    "lfi": "canary-leak",
    "info_leak": "canary-leak",
    "ssrf": "oob-token",
    "rce": "oob-token",
    "xxe": "oob-token",
    "memory_safety": "value-control",
}


def oracle_for(bug_class: str) -> ChallengeOracle | None:
    kind = BUG_CLASS_CHALLENGE.get((bug_class or "").strip().lower())
    return _ORACLES.get(kind) if kind else None


def challenge_kinds() -> Iterable[str]:
    return tuple(_ORACLES)
