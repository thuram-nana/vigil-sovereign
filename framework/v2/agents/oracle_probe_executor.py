"""
agents.oracle_probe_executor — a verification-probe Executor that collects
oracle-observable evidence from a localhost target and hands it to the
deterministic oracle layer as the confirmation authority.

This is the producer half of the "prove-don't-guess" loop. The oracle layer
(`verify/`) and the critique-agent already treat a Finding's `oracle_context`
as authoritative; until a producer actually *populates* it from real traffic,
the oracle only ever fired in isolation. This executor closes that gap:

    hypothesis (localhost surface)
        -> send a benign BASELINE request and a boolean PROBE request
        -> capture both real responses
        -> FindingContext.from_http_responses(baseline, mutated)
        -> ExecutionOutcome(success=True, finding=..., oracle_context=<serialized>)

The exploit-agent then posts the Finding with that `oracle_context`, and the
critique-agent confirms it ONLY if the differential oracle fires — never on an
LLM's say-so.

Boundary (DEFENSIVE / VERIFICATION only — see AUTONOMY-CHARTER.md §4):

  * It refuses any non-loopback host. Test targets are localhost, operator-owned,
    and consented. It does not touch live or third-party systems.
  * It sends exactly two GETs (a baseline and a probe) using the query values it
    was configured with; it mints no other payloads and runs no exploit logic.
  * It DECIDES nothing. It reports observations; the oracle is the authority.
"""

from __future__ import annotations

import urllib.parse
import urllib.request
from dataclasses import dataclass

from .executor_proto import ExecutionOutcome
from .models import FindingPayload, HypothesisPayload, PlanPayload

# Reuse the canonical benign/tautology query values so this executor and the
# verify-layer self-check speak the same differential dialect.
from ..verify.confirmation import _BENIGN_QUERY, _TAUTOLOGY_QUERY
from ..verify.adapter import FindingContext

_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1", "[::1]"})
_USER_AGENT = "CRUCIBLE-verify/1.0 (localhost oracle probe)"


@dataclass
class OracleProbeExecutor:
    """Differential-probe a loopback target and attach the observed
    baseline/mutated responses as oracle evidence.

    `base_url` is the loopback origin of the operator-owned test target (e.g.
    ``http://127.0.0.1:54321``). `path`/`param` locate the injectable surface;
    `baseline_value` vs `probe_value` are the benign and boolean-probe query
    values whose response differential the oracle judges.
    """

    base_url: str
    path: str = "/search"
    param: str = "q"
    baseline_value: str = _BENIGN_QUERY
    probe_value: str = _TAUTOLOGY_QUERY
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
            baseline = self._get(self.baseline_value)
            mutated = self._get(self.probe_value)
        except Exception as e:  # network/URL error — report, never crash the loop
            return ExecutionOutcome(
                success=False,
                note=f"OracleProbeExecutor probe error: {type(e).__name__}: {e}",
            )

        context = FindingContext.from_http_responses(
            baseline,
            mutated,
            bug_class=self.bug_class,
            discriminator={"dimensions": ["status", "length", "lexical"]},
        )

        surface = f"GET {self.path}?{self.param}="
        finding = FindingPayload(
            finding_slug=self._slug(hypothesis),
            title=f"{self.bug_class} candidate on {self.path}",
            severity="High",
            bug_class=self.bug_class,
            surface=surface,
            summary=(
                "A baseline vs. boolean-probe request pair was captured from the "
                "loopback target; the differential oracle adjudicates whether the "
                "responses diverge enough to confirm."
            ),
        )

        # success=True means "a candidate worth adjudicating was produced" — it
        # is NOT a confirmation. The oracle (via critique-agent) is the gate:
        # a non-firing differential (e.g. against a safe target) will refute it.
        return ExecutionOutcome(
            success=True,
            status_code=int(mutated.get("status", 0)),
            body_excerpt=str(mutated.get("body", ""))[:300],
            note=(
                "OracleProbeExecutor: baseline vs probe captured on loopback; "
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
