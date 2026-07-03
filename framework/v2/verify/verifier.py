"""
verify.verifier — the confirmation authority.

`OracleVerifier.confirm(finding_context)` is the load-bearing gate. It selects
the oracle(s) appropriate to a finding's bug_class, runs each over the
already-observed data the context carries, and returns a VerificationResult
whose `confirmed` is True only when at least one oracle fired at or above the
high-confidence threshold.

This is the "prove, don't guess" contract in code: no oracle, no confirmation.
It is deliberately conservative — an absent input yields a non-firing signal,
never an assumed pass.
"""

from __future__ import annotations

from typing import Any, Mapping

from . import oracles
from .models import OracleKind, OracleSignal, VerificationResult

# A fired signal must reach this confidence to confirm a finding.
HIGH_CONFIDENCE = 0.7


# ---------------------------------------------------------------------------
# bug_class -> which oracle(s) can prove it
# ---------------------------------------------------------------------------

# Canonical bug classes to the ordered oracle kinds that can confirm them.
BUG_CLASS_ORACLES: dict[str, tuple[OracleKind, ...]] = {
    "boolean_sqli": (OracleKind.DIFFERENTIAL_RESPONSE,),
    "time_based_sqli": (OracleKind.DIFFERENTIAL_RESPONSE,),
    "error_based_sqli": (OracleKind.SIDE_EFFECT, OracleKind.DIFFERENTIAL_RESPONSE),
    "sqli": (OracleKind.DIFFERENTIAL_RESPONSE, OracleKind.OOB_CALLBACK, OracleKind.SIDE_EFFECT),
    "nosqli": (OracleKind.DIFFERENTIAL_RESPONSE,),
    "idor": (OracleKind.ACHIEVED_STATE,),
    "bola": (OracleKind.ACHIEVED_STATE,),
    "bfla": (OracleKind.ACHIEVED_STATE,),
    "broken_access_control": (OracleKind.ACHIEVED_STATE,),
    "authorization": (OracleKind.ACHIEVED_STATE,),
    "auth_bypass": (OracleKind.ACHIEVED_STATE, OracleKind.DIFFERENTIAL_RESPONSE),
    "mass_assignment": (OracleKind.ACHIEVED_STATE,),
    "privilege_escalation": (OracleKind.ACHIEVED_STATE,),
    "ssrf": (OracleKind.OOB_CALLBACK,),
    "xxe": (OracleKind.OOB_CALLBACK, OracleKind.SIDE_EFFECT),
    "blind_xxe": (OracleKind.OOB_CALLBACK,),
    "deserialization": (OracleKind.OOB_CALLBACK, OracleKind.SANITIZER_SIGNAL),
    "rce": (OracleKind.OOB_CALLBACK, OracleKind.SIDE_EFFECT, OracleKind.SANITIZER_SIGNAL),
    "command_injection": (OracleKind.OOB_CALLBACK, OracleKind.SIDE_EFFECT),
    "ssti": (OracleKind.SIDE_EFFECT, OracleKind.DIFFERENTIAL_RESPONSE),
    "xss": (OracleKind.SIDE_EFFECT,),
    "path_traversal": (OracleKind.SIDE_EFFECT,),
    "lfi": (OracleKind.SIDE_EFFECT,),
    "memory_corruption": (OracleKind.SANITIZER_SIGNAL,),
    "buffer_overflow": (OracleKind.SANITIZER_SIGNAL,),
    "use_after_free": (OracleKind.SANITIZER_SIGNAL,),
    "crash": (OracleKind.SANITIZER_SIGNAL,),
}

# Spelling/format aliases folded onto canonical keys.
_ALIASES: dict[str, str] = {
    "sql_injection": "sqli",
    "blind_sqli": "boolean_sqli",
    "boolean_based_sqli": "boolean_sqli",
    "time_sqli": "time_based_sqli",
    "no_sqli": "nosqli",
    "nosql_injection": "nosqli",
    "insecure_direct_object_reference": "idor",
    "broken_object_level_authorization": "bola",
    "broken_function_level_authorization": "bfla",
    "access_control": "broken_access_control",
    "authz": "authorization",
    "authentication_bypass": "auth_bypass",
    "privesc": "privilege_escalation",
    "server_side_request_forgery": "ssrf",
    "xml_external_entity": "xxe",
    "insecure_deserialization": "deserialization",
    "remote_code_execution": "rce",
    "os_command_injection": "command_injection",
    "cmdi": "command_injection",
    "server_side_template_injection": "ssti",
    "cross_site_scripting": "xss",
    "reflected_xss": "xss",
    "stored_xss": "xss",
    "directory_traversal": "path_traversal",
    "local_file_inclusion": "lfi",
    "file_read": "lfi",
}

_ALL_ORACLES: tuple[OracleKind, ...] = tuple(OracleKind)


def normalize_bug_class(bug_class: str) -> str:
    key = (bug_class or "").strip().lower().replace("-", "_").replace(" ", "_")
    while "__" in key:
        key = key.replace("__", "_")
    return _ALIASES.get(key, key)


class OracleVerifier:
    """Runs deterministic oracles to confirm (or refuse) a finding."""

    def __init__(self, high_confidence: float = HIGH_CONFIDENCE) -> None:
        self.high_confidence = high_confidence

    def oracles_for(self, bug_class: str) -> tuple[OracleKind, ...]:
        """The oracle kinds that can prove `bug_class`. Unknown classes fall
        back to every oracle; `confirm` then runs only those with inputs."""
        return BUG_CLASS_ORACLES.get(normalize_bug_class(bug_class), _ALL_ORACLES)

    def confirm(self, finding_context: Mapping[str, Any]) -> VerificationResult:
        """Confirm a finding from already-observed data.

        Recognised context keys (all optional; an oracle is skipped when its
        inputs are absent):

          bug_class                          str — selects the oracle set
          baseline, mutated, discriminator   -> differential_response_oracle
          expected_state, observed_state     -> achieved_state_oracle
          marker, observed_sink              -> side_effect_oracle
          process_output                     -> sanitizer_signal_oracle
          oob_hits                           -> oob_callback_oracle
        """
        ctx = dict(finding_context or {})
        bug_class = str(ctx.get("bug_class", ""))
        kinds = self.oracles_for(bug_class)

        signals: list[OracleSignal] = []
        skipped: list[str] = []
        for kind in kinds:
            sig = self._run(kind, ctx)
            if sig is None:
                skipped.append(kind.value)
            else:
                signals.append(sig)

        confirming = [s for s in signals if s.fired and s.confidence >= self.high_confidence]
        confirmed = len(confirming) > 0

        # Multi-oracle combine policy: any-high-confidence-fired (safety-monotone).
        # A non-firing oracle cannot veto a fired one, so when the finding is
        # confirmed we RECORD the oracles that ran but did not confirm as dissent
        # rather than treating them as a refutation. Dissent is only meaningful
        # once something confirmed (otherwise "not confirmed" already says it).
        confirming_kinds = {s.kind for s in confirming}
        dissent = (
            [s.kind.value for s in signals if s.kind not in confirming_kinds]
            if confirmed
            else []
        )

        return VerificationResult(
            confirmed=confirmed,
            bug_class=bug_class,
            signals=signals,
            combine_policy="any_high_confidence_fired",
            dissent=dissent,
            rationale=self._rationale(bug_class, kinds, signals, confirming, skipped, dissent),
        )

    # -- dispatch ----------------------------------------------------------

    def _run(self, kind: OracleKind, ctx: Mapping[str, Any]) -> OracleSignal | None:
        """Run one oracle if its inputs are present; else None (skipped)."""
        if kind is OracleKind.DIFFERENTIAL_RESPONSE:
            if "baseline" in ctx and "mutated" in ctx:
                return oracles.differential_response_oracle(
                    ctx["baseline"], ctx["mutated"], ctx.get("discriminator")
                )
            return None
        if kind is OracleKind.ACHIEVED_STATE:
            if "expected_state" in ctx and "observed_state" in ctx:
                return oracles.achieved_state_oracle(
                    ctx["expected_state"], ctx["observed_state"]
                )
            return None
        if kind is OracleKind.SIDE_EFFECT:
            if "marker" in ctx and "observed_sink" in ctx:
                return oracles.side_effect_oracle(ctx["marker"], ctx["observed_sink"])
            return None
        if kind is OracleKind.SANITIZER_SIGNAL:
            if "process_output" in ctx:
                return oracles.sanitizer_signal_oracle(ctx["process_output"])
            return None
        if kind is OracleKind.OOB_CALLBACK:
            if "oob_hits" in ctx:
                return oracles.oob_callback_oracle(ctx["oob_hits"])
            return None
        return None

    # -- rationale ---------------------------------------------------------

    def _rationale(
        self,
        bug_class: str,
        kinds: tuple[OracleKind, ...],
        signals: list[OracleSignal],
        confirming: list[OracleSignal],
        skipped: list[str],
        dissent: list[str] | None = None,
    ) -> str:
        if confirming:
            parts = "; ".join(
                f"{s.kind.value}@{s.confidence:.2f}: {s.evidence}" for s in confirming
            )
            msg = (
                f"CONFIRMED {bug_class or 'finding'} — "
                f"{len(confirming)} oracle(s) fired at high confidence: {parts}"
            )
            if dissent:
                # Record the disagreement without letting it veto (safety-monotone).
                msg += (
                    f". Dissent (ran, did not confirm, cannot veto): {dissent}"
                )
            return msg
        fired_low = [s for s in signals if s.fired]
        if fired_low:
            parts = "; ".join(
                f"{s.kind.value}@{s.confidence:.2f}" for s in fired_low
            )
            return (
                f"NOT confirmed — {len(fired_low)} oracle(s) fired but below the "
                f"{self.high_confidence:.2f} threshold: {parts}"
            )
        ran = [s.kind.value for s in signals]
        detail = f"ran {ran}" if ran else "no oracle had sufficient observed data"
        if skipped:
            detail += f"; skipped (no inputs): {skipped}"
        return f"NOT confirmed — no oracle fired for {bug_class or 'finding'}; {detail}"
