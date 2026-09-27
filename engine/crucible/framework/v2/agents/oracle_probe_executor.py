"""
agents.oracle_probe_executor — a verification-probe Executor that collects
oracle-observable evidence from a localhost target and hands it to the
deterministic oracle layer as the confirmation authority.

This is the producer half of the "prove-don't-guess" loop. The oracle layer
(`verify/`) and the critique-agent already treat a Finding's `oracle_context`
as authoritative; until a producer actually *populates* it from real traffic,
the oracle only ever fired in isolation. This executor closes that gap:

    hypothesis (localhost surface)
        -> run the TRUTH-VALUE ATTRIBUTION protocol (distinct, shape-varied
           always-true and always-false clauses, each sent twice byte-identically,
           preceded by an identical-request determinism pre-gate)
        -> capture every real response
        -> FindingContext.from_boolean_probes(...)
        -> ExecutionOutcome(success=True, finding=..., oracle_context=<serialized>)

The exploit-agent then posts the Finding with that `oracle_context`, and the
critique-agent confirms it ONLY if the SPRT boolean-inference oracle fires —
never on an LLM's say-so.

It used to capture ONE benign response and ONE tautology response and hand that
pair to the differential oracle. That inference has NO ATTRIBUTION STEP — it
cannot separate "the injected boolean changed the query" from "the app treated
two strings differently" — and it confirmed at rate 1.0 against a static page
behind a WAF tautology rule and against an app doing strict input validation,
neither of which has a database. DIFFERENTIAL_RESPONSE is no longer an
acceptable confirmer for any truth-value class (`verify.verifier.
DIFFERENTIAL_LEAD_ONLY_CLASSES`), so this producer collects the evidence the
sound oracle can actually adjudicate.

Boundary (DEFENSIVE / VERIFICATION only — see AUTONOMY-CHARTER.md §4):

  * It refuses any non-loopback host. Test targets are localhost, operator-owned,
    and consented. It does not touch live or third-party systems.
  * It sends only GETs of the PUBLIC, FIXED boolean clause set (`scanner.checks.
    boolean_clause_families`) into the one configured parameter — an identical-request
    determinism pre-gate plus `rounds` x 4 x K clause sends. It mints no other payloads,
    extracts no data, and runs no exploit logic.
  * It DECIDES nothing. It reports observations; the oracle is the authority.
"""

from __future__ import annotations

import urllib.parse
import urllib.request
from dataclasses import dataclass

from .executor_proto import ExecutionOutcome
from .models import FindingPayload, HypothesisPayload, PlanPayload

# Reuse the verify layer's single collection path so this executor and the
# verify-layer self-check speak the same SOUND dialect (truth-value attribution).
from ..verify.confirmation import boolean_probe_context

_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1", "[::1]"})
_USER_AGENT = "CRUCIBLE-verify/1.0 (localhost oracle probe)"


@dataclass
class OracleProbeExecutor:
    """Differential-probe a loopback target and attach the observed
    baseline/mutated responses as oracle evidence.

    `base_url` is the loopback origin of the operator-owned test target (e.g.
    ``http://127.0.0.1:54321``). `path`/`param` locate the injectable surface;
    `rounds` is how many truth-value-attribution rounds to collect before the SPRT
    is handed the evidence.
    """

    base_url: str
    path: str = "/search"
    param: str = "q"
    rounds: int = 3
    bug_class: str = "boolean_sqli"
    timeout: float = 5.0

    def execute(
        self,
        hypothesis: HypothesisPayload,
        plan: PlanPayload,
    ) -> ExecutionOutcome:
        host = (urllib.parse.urlsplit(self.base_url).hostname or "").lower()
        if host not in _LOOPBACK_HOSTS:
            # Fail closed: this executor only ever probes loopback test targets.
            return ExecutionOutcome(
                success=False,
                note=f"OracleProbeExecutor refuses non-loopback host {host!r}",
            )

        try:
            context = boolean_probe_context(
                self._get, rounds=self.rounds, bug_class=self.bug_class)
        except Exception as e:  # network/URL error — report, never crash the loop
            return ExecutionOutcome(
                success=False,
                note=f"OracleProbeExecutor probe error: {type(e).__name__}: {e}",
            )
        last = (context.probe_rounds or [{}])[-1]
        witness = ((last.get("trues") or [{}])[-1]) if isinstance(last, dict) else {}

        surface = f"GET {self.path}?{self.param}="
        finding = FindingPayload(
            finding_slug=self._slug(hypothesis),
            title=f"{self.bug_class} candidate on {self.path}",
            severity="High",
            bug_class=self.bug_class,
            surface=surface,
            summary=(
                "Distinct, shape-varied always-true and always-false clauses were driven into "
                "the loopback target, each twice byte-identically; the SPRT boolean-inference "
                "oracle adjudicates whether the response PARTITIONS BY TRUTH VALUE."
            ),
        )

        # success=True means "a candidate worth adjudicating was produced" — it
        # is NOT a confirmation. The oracle (via critique-agent) is the gate: a
        # non-partitioning response set (e.g. against a safe target) will refute it.
        return ExecutionOutcome(
            success=True,
            status_code=int(witness.get("status", 0) or 0),
            body_excerpt=str(witness.get("body", ""))[:300],
            note=(
                "OracleProbeExecutor: truth-value-attribution rounds captured on loopback; "
                "oracle_context attached for deterministic adjudication"
            ),
            finding=finding,
            oracle_context=context.model_dump(),
        )

    # ---- helpers ----

    @staticmethod
    def _slug(hypothesis: HypothesisPayload) -> str:
        handle = (hypothesis.handle or "H").strip().lower().replace(" ", "-")
        return f"{handle}-oracle-probe"

    def _get(self, value: str) -> dict:
        url = f"{self.base_url}{self.path}?" + urllib.parse.urlencode(
            {self.param: value}
        )
        req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310 (loopback only)
            body = resp.read().decode("utf-8", errors="replace")
            return {"status": resp.status, "body": body}
