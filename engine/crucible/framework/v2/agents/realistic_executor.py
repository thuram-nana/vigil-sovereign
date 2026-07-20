"""
agents.realistic_executor — test harness producing substantive synthetic evidence.

`DeterministicExecutor` returns Results with empty `body_excerpt` and
a one-line `note`.  When the live critique-agent walks the parent_id
chain, it sees a thin chain that does not support the Finding's
claim — and correctly returns `objections`.  That is the gate doing
its job; it is not a bug.

`RealisticExecutor` closes the gap by populating each Result with the
shape a real engagement records: a `body_excerpt` long enough to
carry the actual HTTP response, and a `note` long enough to carry a
multi-step reproduction log (with negative control, DB attestation,
and auth-boundary walk).  The exploit-agent's wiring does not change;
it forwards `outcome.body_excerpt` and `outcome.note` straight into
the Result event.

Three pre-baked scenarios ship.  Each maps a (bug_class, surface)
key to an `ExecutionOutcome`:

  - STRONG  — webhook-forgery / /payment/cryptomus/callback
              full HTTP exchange + 5-step repro + negative control +
              DB attestation; finding is Critical with rich summary.
              Critique should `confirm` under live URK.
  - WEAK    — information-disclosure / /robots.txt
              single observation, no reproduction, no impact walk.
              Critique should `objections` (or `more_evidence_needed`)
              under live URK.
  - MIXED   — timing-side-channel / /api/login
              5 measurements with honest equivocation; reasoning
              matters more than outcome.  Critique decision is
              the empirical question; the test asserts whichever
              comes back is grounded in the evidence.

Built-in scenarios are exposed as `BUILT_IN_SCENARIOS`.  Tests can
use them directly or copy + adapt them.  Caller-supplied scenarios
override built-ins by (bug_class, surface) key.

The gate is NOT weakened.  Weak claims still fail.  Real findings
posted from this harness with substantive evidence pass; real
findings with thin evidence still get bounced.  See the integration
test at `tests/test_realistic_pipeline_live.py`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from .executor_proto import ExecutionOutcome, Executor
from .models import FindingPayload, HypothesisPayload, PlanPayload


# ---------------------------------------------------------------------------
# scenario shape
# ---------------------------------------------------------------------------


EvidenceStrength = Literal["strong", "weak", "mixed"]


@dataclass
class Scenario:
    """One pre-baked scenario.  Wraps an `ExecutionOutcome` plus a
    documented `evidence_strength` so tests can assert on critique's
    decision against the harness's intent."""

    bug_class: str
    surface: str
    evidence_strength: EvidenceStrength
    outcome: ExecutionOutcome


# ---------------------------------------------------------------------------
# Built-in scenarios
# ---------------------------------------------------------------------------


# 1. STRONG ------------------------------------------------------------------
#
# Webhook forgery against an unauthenticated payment-callback endpoint.
# Evidence chain: 5-step reproduction with vary-user, vary-amount, replay,
# negative control, and a DB attestation.  This is the canonical "should
# pass critique" shape — every objection a senior reviewer might raise
# (ownership, scope, replay, auth boundary) is addressed in the note.

_STRONG_BODY = """\
HTTP/1.1 200 OK
Server: nginx/1.21.6
Content-Type: application/json
Content-Length: 218
Date: Mon, 04 May 2026 18:15:42 GMT
X-Request-ID: 7f3a8c1e-2b9d-4e6a-8c7f-5d4a9b3e1f8c

{"status":"received","tx_id":"OBSIDIAN-FORGED-001","credited":{"user_id":42,"amount":"100.00","currency":"USD","new_balance":"100.00"},"signature_verified":false,"signature_header_present":false}\
"""

_STRONG_NOTE = """\
Reproduction (5 of 5 successful, no failed attempts in this batch):

  Run 1: POST /payment/cryptomus/callback with body
         {"order_id":"OBS-FORGED-001","status":"paid","amount":"100",
          "currency":"USD","user_id":"42"}
         and NO Signature header.
         → 200 OK; balances.user_id=42 went 0.00 → 100.00 (verified via
           direct psql SELECT).

  Run 2: same payload, second request.
         → 200 OK; balance now 200.00.  No idempotency check on
           order_id; replay accepted.

  Run 3: vary user_id to 43 (different test account).
         → 200 OK; user 43 balance 0.00 → 100.00.  Confirms the
           handler trusts user_id from the request body, not from a
           PSP-side mapping.

  Run 4: vary amount to 999999.
         → 200 OK; user 43 balance now 1,000,099.  No upper-bound
           sanity check.

  Run 5: omit Signature header entirely (already absent above; this
         run sets it to a literal "invalid" string).
         → 200 OK; same effect.  Confirms the handler does not
           inspect the signature even when present and wrong.

Negative control: same payload against non-existent user_id=99999.
         → 200 OK with response body {"status":"received","credited":null}
           and NO row written to balances or transactions.  Confirms
           the user_id is the only field the handler trusts and that
           the absence of a matching row is the only thing the handler
           validates against.

DB attestation (psql, run after the five attempts above):
  SELECT id, balance FROM users WHERE id IN (42, 43);
   id |  balance
  ----+-----------
   42 |    200.00
   43 | 1000099.00

  SELECT id, signature_header FROM transactions
    WHERE order_id LIKE 'OBS-FORGED-%';
   id |     signature_header
  ----+--------------------------
   88 | (null)
   89 | (null)
   90 | (null)
   91 | (null)
   92 | invalid

Auth boundary: the endpoint is intentionally unauthenticated (it is
a callback URL).  The missing control is signature verification,
not authentication.

Evidence files captured at evidence/live-001-webhook/:
  request-1.http through request-5.http
  response-1.http through response-5.http
  db-snapshot-before.txt and db-snapshot-after.txt\
"""

_STRONG_FINDING = FindingPayload(
    finding_slug="real-001-webhook-forgery",
    title="Forged Cryptomus webhook credits balance to attacker user (no signature verification)",
    severity="Critical",
    bug_class="webhook-forgery",
    surface="/payment/cryptomus/callback",
    summary=(
        "POST /payment/cryptomus/callback accepts arbitrary user_id and "
        "amount with no signature verification.  Reproduced 5 times "
        "across 2 distinct user_ids and 2 distinct amounts; replay of "
        "the same order_id was accepted (no idempotency).  Negative "
        "control with non-existent user_id confirms the handler trusts "
        "the user_id field from the request body as authoritative."
    ),
    impact=(
        "Direct unbounded balance creation.  Each request credits an "
        "arbitrary amount to any user_id; tested up to $1,000,000 "
        "single-request credits.  Money flow integrity is broken; "
        "attacker drains operator funds through withdrawals or service "
        "consumption with zero financial outlay."
    ),
    cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    cvss_base=9.8,
)


# 2. WEAK --------------------------------------------------------------------
#
# Information disclosure via robots.txt.  Single observation, no
# reproduction, no impact walk.  This is the canonical "should be
# objected to" shape.

_WEAK_BODY = """\
HTTP/1.1 200 OK
Content-Type: text/plain
Content-Length: 47

User-agent: *
Disallow: /admin/
Disallow: /uploads/\
"""

_WEAK_NOTE = """\
Single observation: GET /robots.txt returned 200 with two Disallow
directives.

No reproduction.  No impact assessment.  No verification that the
disallowed paths actually exist or are sensitive.  No probe of
/admin/ to see whether it is reachable, requires auth, or 404s.\
"""

_WEAK_FINDING = FindingPayload(
    finding_slug="real-002-robots-disclosure",
    title="robots.txt discloses /admin/ and /uploads/ paths",
    severity="Low",
    bug_class="information-disclosure",
    surface="/robots.txt",
    summary=(
        "robots.txt at /robots.txt lists Disallow entries for /admin/ "
        "and /uploads/, which may give attackers a path map.  "
        "Possibly exploitable; not verified."
    ),
    impact=(
        "Hint that /admin/ exists.  Attackers might use this as input "
        "to a content-discovery scan.  Real impact unknown without "
        "probing those paths."
    ),
    cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    cvss_base=3.1,
)


# 3. MIXED -------------------------------------------------------------------
#
# Timing side-channel suggesting username enumeration on /api/login.
# Reproduces 5 measurements with a 56ms median delta, but small N
# and no baseline-jitter measurement.  Honest equivocation in the
# note.  Critique should land somewhere defensible — confirm if it
# accepts the small-N delta plus the structural argument, object if
# it wants more measurements.  Either is correct; the test asserts
# the decision and a non-empty deception_check.

_MIXED_BODY = """\
HTTP/1.1 401 Unauthorized
Content-Type: application/json
Content-Length: 35

{"error":"invalid_credentials"}

# (5 trials each, captured via curl -w '%{time_total}\\n' ...)
# Wrong password against KNOWN-VALID username (obsidian-test-user-A):
#   trial 1: 0.142s
#   trial 2: 0.156s
#   trial 3: 0.138s
#   trial 4: 0.151s
#   trial 5: 0.147s
#   median:  0.147s
#
# Wrong password against KNOWN-INVALID username (obsidian-test-bogus-12345):
#   trial 1: 0.089s
#   trial 2: 0.095s
#   trial 3: 0.102s
#   trial 4: 0.087s
#   trial 5: 0.091s
#   median:  0.091s\
"""

_MIXED_NOTE = """\
Timing-side-channel measurement on POST /api/login:

  Valid-username branch median:    147 ms
  Invalid-username branch median:    91 ms
  Delta:                             56 ms (consistently above zero
                                            across 5/5 trials)

Honest equivocation:
  - n=5 per branch is small; statistical power is low.
  - No baseline measurement of network jitter on the same client/
    server pair was taken; some of the delta could be noise.
  - The valid-username branch likely runs a bcrypt check; the
    invalid branch presumably exits before reaching it.  If the
    server uses bcrypt rounds in the typical 10-12 range, the delta
    is consistent with that hypothesis (~50-150ms is the expected
    bcrypt cost on commodity hardware).
  - But: the same delta could appear from any pre-bcrypt early-
    return path that the implementation happens to take for invalid
    users (e.g. cache-miss vs cache-hit on the user lookup).

What's NOT proven:
  - That a real attacker, with a different network path and a
    larger sample, would consistently see this delta.
  - That the delta is large enough to enable enumeration at scale.

What is proven:
  - The two branches are timing-distinguishable in this measurement
    set.

Suggested next steps for a follow-up: take n=200 per branch with
network-jitter baseline; if the delta survives, recommend
constant-time auth.\
"""

_MIXED_FINDING = FindingPayload(
    finding_slug="real-003-login-timing",
    title="Timing differential on /api/login may enable username enumeration",
    severity="Medium",
    bug_class="timing-side-channel",
    surface="/api/login",
    summary=(
        "POST /api/login responds ~56ms slower for valid usernames "
        "than for invalid ones (medians of 147ms vs 91ms across 5 "
        "trials each).  Consistent with a bcrypt-cost gap between "
        "the valid-username branch and an early-return invalid-"
        "username branch.  N is small; baseline jitter not "
        "measured; could be noise."
    ),
    impact=(
        "If the delta survives a larger sample, it enables "
        "username enumeration at HTTP rate.  Could feed a "
        "credential-stuffing campaign with a curated valid-"
        "username list.  Severity Medium pending follow-up "
        "measurements."
    ),
    cvss_vector="AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
    cvss_base=3.7,
)


BUILT_IN_SCENARIOS: list[Scenario] = [
    Scenario(
        bug_class="webhook-forgery",
        surface="/payment/cryptomus/callback",
        evidence_strength="strong",
        outcome=ExecutionOutcome(
            success=True, status_code=200, elapsed_ms=187.0,
            body_excerpt=_STRONG_BODY,
            note=_STRONG_NOTE,
            finding=_STRONG_FINDING,
        ),
    ),
    Scenario(
        bug_class="information-disclosure",
        surface="/robots.txt",
        evidence_strength="weak",
        outcome=ExecutionOutcome(
            success=True, status_code=200, elapsed_ms=42.0,
            body_excerpt=_WEAK_BODY,
            note=_WEAK_NOTE,
            finding=_WEAK_FINDING,
        ),
    ),
    Scenario(
        bug_class="timing-side-channel",
        surface="/api/login",
        evidence_strength="mixed",
        outcome=ExecutionOutcome(
            success=True, status_code=401, elapsed_ms=147.0,
            body_excerpt=_MIXED_BODY,
            note=_MIXED_NOTE,
            finding=_MIXED_FINDING,
        ),
    ),
]


# ---------------------------------------------------------------------------
# RealisticExecutor
# ---------------------------------------------------------------------------


@dataclass
class RealisticExecutor:
    """Executor that returns rich-evidence outcomes from a scenario map.

    Layered identically to `DeterministicExecutor`: lookup by
    `(bug_class, surface)`, fall through to a default outcome when
    no scenario matches.  The exploit-agent does not need to change.

    Default scenarios from `BUILT_IN_SCENARIOS` are loaded unless
    `use_built_ins=False`.  Caller-supplied `extra_scenarios`
    override matching keys.
    """

    extra_scenarios: list[Scenario] = field(default_factory=list)
    use_built_ins: bool = True
    default: ExecutionOutcome = field(default_factory=lambda: ExecutionOutcome(
        success=False, status_code=404,
        body_excerpt="",
        note=(
            "RealisticExecutor: no scenario for this (bug_class, surface). "
            "The harness only fires for keys it knows about; everything "
            "else returns failure with no finding."
        ),
    ))

    def __post_init__(self) -> None:
        scenarios: dict[tuple[str, str], Scenario] = {}
        if self.use_built_ins:
            for s in BUILT_IN_SCENARIOS:
                scenarios[(s.bug_class, s.surface)] = s
        for s in self.extra_scenarios:
            scenarios[(s.bug_class, s.surface)] = s
        self._scenarios = scenarios

    def execute(
        self,
        hypothesis: HypothesisPayload,
        plan: PlanPayload,
    ) -> ExecutionOutcome:
        key = (hypothesis.bug_class, hypothesis.surface)
        scenario = self._scenarios.get(key)
        if scenario is None:
            return self.default
        return scenario.outcome

    # ---- introspection helpers (used by tests) ----

    def keys(self) -> list[tuple[str, str]]:
        """The (bug_class, surface) keys this executor responds to."""
        return list(self._scenarios.keys())

    def scenario_for(self, bug_class: str, surface: str) -> Scenario | None:
        return self._scenarios.get((bug_class, surface))


# ---------------------------------------------------------------------------
# Convenience: validate the executor satisfies the protocol
# ---------------------------------------------------------------------------

# A runtime-safe check: at import time, confirm the dataclass really
# does conform to Executor.  This catches signature drift if Executor
# changes.
_re: Executor = RealisticExecutor()  # noqa: F841  — type-narrowing assertion only
