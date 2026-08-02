"""remediation.live_adapter — a REAL live-HTTP re-drive adapter behind :class:`LiveTargetAdapter` (VF-1a.2).

:mod:`prove_driver` is a pure four-state protocol orchestrator over an INJECTED :class:`LiveTargetAdapter`;
:mod:`test_prove_driver` exercises the whole state machine offline against a fake. This module is the FIRST
real adapter: it re-drives the ORIGINAL exploit against a live, authorized target through CRUCIBLE's gated
:class:`HttpExecutor` (charter/scope/kill-switch/budget/rate-limit), captures the fresh response bytes, and
turns them into the exact ``oracle_context`` the ORIGINAL oracle re-fires over — so the driver's REMEDIATED /
STILL_VULNERABLE / INCONCLUSIVE / REFUSED verdict is earned over FRESH evidence, not the retained finding.

Scope of this slice: the response-side ``error_signature`` channel (``error_based_sqli``). A general
multi-channel adapter (differential, boolean, evaluation, …) is a documented follow-up.

The freshness split this adapter implements, stated plainly and HONESTLY (it is the load-bearing soundness
argument, and its LIMIT is disclosed — never overclaimed):

  * the POSITIVE CONTROL re-uses the RETAINED original firing bytes — it proves ONLY that the SAME oracle is
    still capable of FIRING (the harness is not broken), so a live silence is not a harness artefact. It is
    deliberately NOT a live fetch, so it does NOT prove the LIVE observation channel is intact right now — a
    LIVE positive control (a benign probe demonstrating the exploit's parameter still reaches the app's
    processing path) is the documented VF-1a.3 follow-up that would.
  * The exploit TRIALS establish **F1 (the target answered THIS run)**: each trial carries a fresh,
    unpredictable ``challenge`` (the driver's causal-chain nonce) in a query param the target ECHOES into its
    response body, and the driver re-checks the echo is in the oracle-JUDGED bytes. So a silent-but-echoed
    trial proves the exploit did not reproduce over a FRESH, live-answered response (not a replay of retained
    bytes).
  * **HONEST LIMIT (why this is F1, not F2):** the nonce rides a SEPARATE query param, not the exploit
    payload, so an echo proves the target is *responsive*, NOT that the *vulnerable code path* was exercised.
    An interposing edge / WAF block page / down-origin gateway that reflects the nonce is therefore NOT
    distinguished at F1 — it can yield REMEDIATED@F1. Ruling that out is **F2+ (nonce through the exploit path)
    + a LIVE positive control**, the disclosed follow-up. A verifier that needs it sets
    ``policy.minimum_freshness_level >= F2`` — which this adapter honestly cannot meet, so it returns
    INCONCLUSIVE rather than a falsely-strong REMEDIATED.

Invariants honoured here (mirroring prove_driver / remediation_cert):
  * FATAL-2 — every ``framework.v2`` import is function-local; module scope is stdlib + vigil_core (via the
    import-clean :mod:`prove_driver` types) only.
  * Determinism — no wallclock / rng in this adapter. The driver supplies ``now`` / ``run_id`` / the nonces;
    the ``challenge`` is passed in per call. The only I/O is the gated HTTP send.
  * Fail-closed — every error path yields ``reachable=False`` / a raised identity sample; a firing or silent
    context is NEVER fabricated (the bytes come from the wire or not at all).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urlencode, urlsplit

from vigil_core import digest_payload   # stdlib+crypto only — FATAL-2 safe at module scope

# prove_driver's module scope is stdlib + vigil_core (+ remediation_cert, also framework-free), so importing
# these observation/enum/type shapes here is FATAL-2 safe — no framework is pulled at import time.
from .prove_driver import (
    ControlObservation,
    EffectiveAuthorization,
    Freshness,
    LiveTargetAdapter,
    TrialObservation,
)

# The channel/oracle family this slice drives. A response-side, deterministic-per-observation error signature.
_ERROR_SIGNATURE_CHANNEL = "error_signature"


@dataclass(frozen=True)
class _HttpRequest:
    """The minimal duck-typed shape :meth:`HttpExecutor.gated_fetch` reads (``.method`` / ``.url`` /
    ``.headers`` / ``.body``). Kept local so the adapter never imports the scanner's request model."""

    url: str
    method: str = "GET"
    headers: tuple = ()
    body: Optional[str] = None


@dataclass
class LiveHttpAdapter:
    """A live-HTTP :class:`LiveTargetAdapter` for the ``error_signature`` / ``error_based_sqli`` channel.

    Re-drives the original exploit (``endpoint_path`` with ``param`` = ``payload``) through the gated
    ``executor`` and adjudicates the FRESH response with the original oracle, while carrying the driver's
    per-run ``challenge`` in ``nonce_param`` (echoed by the target) to establish freshness.

    Required construction inputs:
      * ``executor`` — a constructed CRUCIBLE ``HttpExecutor`` (holds the charter/scope/kill-switch/budget
        gate chain). The adapter never bypasses it: every send is a ``gated_fetch``.
      * ``base_url`` — the target's scheme+host(:port); the target identity is derived from it.
      * ``endpoint_path`` / ``param`` / ``payload`` — the original exploit request.
      * ``nonce_param`` — the query param the target echoes (freshness).
      * ``original_firing_context`` — the RETAINED original firing ``oracle_context`` (the positive control).

    Oracle/finding metadata (``bug_class`` / ``oracle_*`` / digests / ``destructive``) rides on the cert.
    """

    executor: Any
    base_url: str
    endpoint_path: str
    param: str
    payload: str
    nonce_param: str
    original_firing_context: dict
    bug_class: str = "error_based_sqli"
    oracle_family: str = _ERROR_SIGNATURE_CHANNEL
    oracle_id: str = "oracle:error_signature"
    oracle_version: str = "1.0"
    original_probe_recipe_digest: str = ""
    execution_profile_digest: str = ""
    destructive: bool = False

    _host: str = field(init=False, default="")

    def __post_init__(self) -> None:
        # The identity of the target for the policy match + the F0 target-identity digest. Derived from the
        # authorized base_url (a config fact), NOT from a live probe — liveness is proven by the trials.
        # Designed so a stronger identity (a TLS SPKI pin) can slot in alongside ``host`` later.
        self._host = urlsplit(self.base_url).hostname or ""
        # Bind the ACTUALLY re-driven probe into the cert (N4): if the caller did not supply a probe digest,
        # derive one over the concrete re-drive spec (endpoint/param/payload/nonce_param/bug_class) so the
        # signed "fixed" verdict attests WHICH exploit request was re-driven. Honest-producer tier: this binds
        # the probe THIS adapter sends; cryptographically tying it back to the ORIGINAL finding's probe (vs a
        # malicious producer swapping in a benign payload) stays the deferred frontier, stated in the docstring.
        if not self.original_probe_recipe_digest:
            self.original_probe_recipe_digest = digest_payload({
                "endpoint_path": self.endpoint_path, "param": self.param, "payload": self.payload,
                "nonce_param": self.nonce_param, "bug_class": self.bug_class, "method": "GET"})

    # ---- identity ----------------------------------------------------------------------------------
    def identity_sample(self) -> dict:
        """Return the target's stable identity ``{"host": <host>}``. Best-effort issues one gated base
        request so an authorization/scope failure is surfaced early: a GATE REFUSAL (not authorized to even
        probe this host) RAISES — the driver maps that to a REFUSED / TARGET_UNAVAILABLE disposition. A pure
        transport failure (the app is simply DOWN) does NOT raise: identity ("who this host is") is a policy
        fact, while liveness ("did it answer THIS run") is established by the exploit trials — so a down
        target surfaces as an INCONCLUSIVE unreachable trial, not a refusal to test. Never fabricates.
        """
        try:
            resp = self.executor.gated_fetch(_HttpRequest(url=self.base_url, method="GET"))
        except Exception as exc:  # noqa: BLE001 — an executor crash is a genuine "cannot sample" (fail-closed)
            raise RuntimeError(f"identity sample failed: {exc}") from exc
        note = str((resp or {}).get("refused") or "")
        # A GATE refusal (charter/scope/kill-switch/authority) is stamped "REFUSED:" by the executor; a
        # transport error is stamped with the exception type ("httpx.…"). Only the former is a "cannot test".
        if "REFUSED:" in note:
            raise RuntimeError(f"identity sample refused by gate: {note}")
        return {"host": self._host}

    # ---- positive control (retained bytes; NOT a live fetch) --------------------------------------
    def run_positive_control(self, *, challenge: str, auth: EffectiveAuthorization) -> ControlObservation:
        """The positive-control twin: return the RETAINED original firing ``oracle_context`` so the driver
        confirms the SAME oracle STILL FIRES on the known-vulnerable bytes (the harness is capable of firing
        now). This is intentionally NOT a live send — liveness/freshness is the trials' job (see module
        docstring). ``reachable``/``channel_alive`` are True because the retained bytes are always present;
        the driver independently re-fires the oracle over ``oracle_context`` to credit the control.

        HONEST LIMIT (do not overclaim): because it is not live, this control does NOT prove the LIVE
        observation channel is intact right now — so it does NOT catch a WAF/edge that blocks the exploit while
        still answering (the F1 limit in the module docstring). A LIVE positive control that demonstrates the
        exploit's parameter still reaches the app's processing path is the VF-1a.3 follow-up that closes it.
        """
        return ControlObservation(
            reachable=True,
            channel_alive=True,
            oracle_context=dict(self.original_firing_context),
            freshness_level=Freshness.F0_NONCE_GENERATED,
            definition_digest=self.original_probe_recipe_digest,
            detail="positive control = retained original firing bytes (harness-capability proof only)",
        )

    # ---- exploit trial (the live re-drive) --------------------------------------------------------
    def run_exploit_trial(self, *, challenge: str, trial_index: int,
                          auth: EffectiveAuthorization) -> TrialObservation:
        """Re-drive the ORIGINAL exploit over the live target and return the FRESH observation. Builds the
        mutated request (``param`` = ``payload`` AND ``nonce_param`` = ``challenge``), gated-fetches it,
        turns the response body into an ``error_signature`` ``oracle_context`` (the exact context the
        original oracle re-fires over), and reports freshness from whether the target echoed the challenge
        into the JUDGED bytes. Any refusal/exception ⇒ ``reachable=False`` (the driver → INCONCLUSIVE);
        never fabricates a firing/silent context.
        """
        req = _HttpRequest(url=self._exploit_url(challenge), method="GET")
        try:
            resp = self.executor.gated_fetch(req)
        except Exception as exc:  # noqa: BLE001 — a transport/executor crash is an unreachable trial
            return TrialObservation(reachable=False, valid=False, oracle_context=None,
                                    detail=f"trial send crashed: {exc}")
        status = (resp or {}).get("status")
        # status 0 covers BOTH a gate refusal and a transport failure — either way the target did not answer
        # this trial: report unreachable (the driver classifies it INCONCLUSIVE / TARGET_UNAVAILABLE).
        if status in (0, None):
            return TrialObservation(reachable=False, valid=False, oracle_context=None,
                                    detail=f"trial not answered: {str((resp or {}).get('refused') or status)}")

        body = str((resp or {}).get("body") or "")
        ctx = self._context_from_body(body)
        if ctx is None:
            # The bytes could not be turned into a judgeable context — recorded but not counted (fail-closed:
            # never claim a silent/firing context we could not build).
            return TrialObservation(reachable=True, valid=False, oracle_context=None,
                                    detail="could not build oracle_context from the captured body")

        echoed = challenge in body
        # HONEST level: a nonce on a SEPARATE param that the target echoes establishes F1 (the target answered
        # THIS run), NOT F2 (the operator's "nonce through the relevant/exploit path") — the exploit payload
        # rides a different param, so an edge/WAF that merely reflects the nonce also satisfies an echo. This
        # adapter therefore never claims F2; F2+ needs the nonce IN the exploit path + a live positive control
        # (VF-1a.3). A verifier requiring F2 sets policy.minimum_freshness_level>=F2 → this run goes INCONCLUSIVE.
        level = Freshness.F1_TARGET_ECHOES if echoed else Freshness.F0_NONCE_GENERATED
        return TrialObservation(reachable=True, valid=True, oracle_context=ctx,
                                freshness_level=level, nonce_echoed=echoed,
                                detail=f"live re-drive: status={status} echoed={echoed} (F1: responsive)")

    # ---- helpers ----------------------------------------------------------------------------------
    def _exploit_url(self, challenge: str) -> str:
        """The mutated exploit URL: the endpoint with the injectable param = the exploit payload AND the
        freshness nonce param = the run challenge. ``urlencode`` preserves the payload's special chars over
        the wire (the target decodes them back). Deterministic (sorted params, no wallclock/rng)."""
        base = self.base_url.rstrip("/")
        path = "/" + self.endpoint_path.lstrip("/")
        query = urlencode(sorted({self.param: self.payload, self.nonce_param: challenge}.items()))
        return f"{base}{path}?{query}"

    def _context_from_body(self, body: str) -> Optional[dict]:
        """Turn a captured response body into the ``error_signature`` ``oracle_context`` the ORIGINAL oracle
        re-fires over — the SAME translator the base RemediationCertificate uses. Returns None (fail-closed)
        if the capture cannot be reshaped. Framework imports are function-local (FATAL-2)."""
        from framework.v2.evidence.poc import CapturedExchange          # lazy — FATAL-2
        from framework.v2.verify.poc_translate import context_from_exchanges

        body_bytes = body.encode("utf-8", errors="replace")
        ex = CapturedExchange(channel=_ERROR_SIGNATURE_CHANNEL, role="mutated", response_bytes_ref="resp")
        ctx = context_from_exchanges([ex], bug_class=self.bug_class, resolve=lambda _ref: body_bytes)
        if ctx is None:
            return None
        return ctx.model_dump(mode="json")


# Structural conformance: assert LiveHttpAdapter satisfies the LiveTargetAdapter protocol at import time
# (a runtime_checkable Protocol check catches attribute/method drift here rather than at first drive).
def _assert_conforms() -> None:
    # A cheap, side-effect-free instance purely for the isinstance check (no executor call is made).
    probe = LiveHttpAdapter(executor=None, base_url="http://127.0.0.1/", endpoint_path="/", param="q",
                            payload="x", nonce_param="rc", original_firing_context={"bug_class": "error_based_sqli"})
    assert isinstance(probe, LiveTargetAdapter)


_assert_conforms()
