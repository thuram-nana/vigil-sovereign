"""
aegis.guard — the LLM guard + honeypot seeding.

The class-1 flagship needs the app to control both ends of its LLM I/O. The guard:

  * MINTS a high-entropy random canary sentinel (``os.urandom`` at setup) the app plants in
    its system prompt out of band. Because the sentinel is a dedicated random token, a
    verbatim appearance in the model's output is collision-resistant proof of disclosure.
    (Tests may inject a FIXED canary for determinism — the only place randomness enters.)
  * builds the ``FindingContext`` the disclosure / prompt-injection oracles judge —
    ``inspect(output)`` for the canary path, ``inspect_behavior(control, treatment)`` for the
    provable behavior-delta path.
  * SEEDS honeypot paths (invisible, robots-disallowed links no human UI renders) and keeps a
    crawler allowlist whose fetches REFUTE rather than confirm (doctrine P1).

The canary and honeypot tokens are the ONLY randomness in AEGIS; everything downstream of them
is a pure, replayable function of the retained evidence.
"""

from __future__ import annotations

import base64
import os

from ..verify.adapter import FindingContext


def mint_canary() -> str:
    """A fresh high-entropy random sentinel (~24 chars, ~108 bits). Collision-resistant, so a
    verbatim substring match in model output cannot be coincidental. The ONE rng call."""
    token = base64.urlsafe_b64encode(os.urandom(18)).decode("ascii").rstrip("=")
    return f"AEGIS-{token}"


def seed_honeypot_path() -> str:
    """A fresh invisible, robots-disallowed honeypot path no human UI links."""
    token = base64.urlsafe_b64encode(os.urandom(9)).decode("ascii").rstrip("=").lower()
    return f"/__aegis_hp__/{token}"


class LLMGuard:
    """Per-deployment guard: a planted canary + a seeded honeypot registry + a crawler
    allowlist. Construct once at setup; reuse across turns."""

    def __init__(
        self,
        *,
        canary: str | None = None,
        honeypot_paths: list[str] | None = None,
        crawler_allowlist: list[str] | None = None,
    ) -> None:
        # allow injecting a FIXED canary for deterministic tests; otherwise mint a random one.
        self.canary: str = canary or mint_canary()
        self._honeypot_paths: list[str] = list(honeypot_paths) if honeypot_paths else [seed_honeypot_path()]
        self._crawler_allowlist: set[str] = set(crawler_allowlist or ())

    # -- honeypot registry -------------------------------------------------
    @property
    def honeypot_paths(self) -> list[str]:
        return list(self._honeypot_paths)

    def register_honeypot(self, path: str) -> None:
        if path and path not in self._honeypot_paths:
            self._honeypot_paths.append(path)

    def is_honeypot(self, path: str) -> bool:
        return path in set(self._honeypot_paths)

    # -- crawler allowlist (P1: an allowlisted fetch REFUTES) --------------
    def allow_crawler(self, token: str) -> None:
        if token:
            self._crawler_allowlist.add(token)

    def is_allowlisted(self, token: str | None) -> bool:
        return bool(token) and token in self._crawler_allowlist

    # -- oracle-input builders --------------------------------------------
    def inspect(self, llm_output: str) -> FindingContext:
        """Build the disclosure FindingContext: did the planted canary appear verbatim in the
        model's output? (Proves DISCLOSURE, not that an injection caused it — P2.)"""
        return FindingContext.from_llm_disclosure(self.canary, llm_output)

    def inspect_behavior(self, control: dict, treatment: dict) -> FindingContext:
        """Build the prompt-injection FindingContext from a clean control turn's behavior vs
        the attacker treatment turn's behavior — the ONLY path that earns `prompt_injection`."""
        return FindingContext.from_prompt_injection(control, treatment)

    def honeypot_context(self, requested_path: str, *, crawler_allowlisted: bool = False) -> FindingContext:
        """Build the honeypot FindingContext for a requested path (set-membership over the
        seeded honeypot registry)."""
        return FindingContext.from_honeypot(
            requested_path, self._honeypot_paths, crawler_allowlisted=crawler_allowlisted)
