"""
agents.http_executor — bounded live-HTTP executor for the exploit-agent.

Conforms to the same `Executor` protocol as `DeterministicExecutor`
and `RealisticExecutor` (one `execute(hypothesis, plan) -> ExecutionOutcome`
method) so the exploit-agent wiring does not change. What changes is
that this executor actually issues an HTTP request against a real
host — and therefore gates every action through the inviolable
charter / scope / destructive-confirm / budget / rate-limit chain.

Six load-bearing safety gates, all called per-action, none bypassable
without code change:

  1. Charter signature gate (via `scope_gate.validate_action`).
  2. Scope gate                 ".
  3. Destructive-action confirm — `prompt_callback`, default-deny on
                                  timeout.
  4. Per-engagement request budget.
  5. Posture-aware rate limit (TEST = aggressive, AUDIT = moderate,
                              EMULATE = slow + jittered).
  6. Posture-aware User-Agent.

Plus standard hygiene: configurable timeout (default 30s), redirect
chain captured, evidence archived to `targets/<slug>/evidence/<action_id>/`,
structured event written to `targets/<slug>/.crucible-v2.log`.

If a gate refuses, the executor returns an `ExecutionOutcome` with
`success=False` and a note describing the refusal. The caller (the
exploit-agent) records this into the Result event chain — the gate's
output is preserved as evidence that the framework chose not to act.
"""

from __future__ import annotations

import json
import os
import random
import re
import select
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Literal
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlsplit, urlunsplit

import httpx

from ..common import logging as v2log
from ..common import paths, redact
from ..common.errors import SovereigntyViolation
from ..verify.adapter import FindingContext
from ..authority import (
    ActionRequest,
    EngagementAuthority,
    KillSwitch,
    authorize_action,
)
from ..authority.store import AuthorityError, load_authority, load_verified_authority
from .egress_guard import (
    EgressAllowlist,
    SovereignHttpxTransport,
    build_engagement_allowlist,
)
from .executor_proto import ExecutionOutcome, Executor
from .models import FindingPayload, HypothesisPayload, PlanPayload
from .scope_gate import ScopeDecision, Posture, is_destructive, validate_action

_log = v2log.get_logger(__name__)

# Body-excerpt cap (bytes). The full body is archived to evidence/.
_BODY_EXCERPT_BYTES = 8 * 1024

# Per-posture rate parameters: (min_seconds_between_requests, jitter_seconds_max).
_RATE_PROFILES: dict[Posture, tuple[float, float]] = {
    "TEST":    (0.2, 0.0),
    "AUDIT":   (1.0, 0.0),
    "EMULATE": (5.0, 3.0),
}

# Per-posture User-Agent strings. The TEST/AUDIT UAs are intentionally
# correlatable per opsec-discipline.md § 2.1; the EMULATE UA is a
# realistic-looking browser string.
_UA_REALISTIC = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)


def _today_iso() -> str:
    return datetime.now(timezone.utc).date().isoformat()


def _set_query_param(url: str, param: str, value: str) -> str:
    """Return ``url`` with ``param`` set to ``value`` in its query string
    (replacing any existing occurrence). Used to render the baseline and probe
    URLs for a differential without disturbing the rest of the request."""
    parts = urlsplit(url)
    kept = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k != param]
    kept.append((param, value))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(kept), parts.fragment))


def user_agent_for(
    posture: Posture, operator_identifier: str | None = None,
) -> str:
    if posture == "EMULATE":
        return _UA_REALISTIC
    base = f"OBSIDIAN/1.0 (authorized owner-test {_today_iso()})"
    if posture == "AUDIT":
        return base + "; control-test"
    if operator_identifier:
        return base + f"; {operator_identifier}"
    return base


# ---------------------------------------------------------------------------
# Charter posture parser
# ---------------------------------------------------------------------------

# Section 7 of the charter template uses `[x] **POSTURE**` checkboxes.
_POSTURE_CHECKBOX = re.compile(
    r"-\s*\[(?P<mark>[xX ])\]\s*\*\*(?P<posture>TEST|AUDIT|EMULATE)\*\*",
    re.MULTILINE,
)


def parse_posture(slug: str) -> Posture:
    """Read the posture from `targets/<slug>/charter.md` § 7. Default
    to TEST if no posture is checked or no charter exists."""
    cp = paths.charter_path(slug)
    if not cp.is_file():
        return "TEST"
    text = cp.read_text(encoding="utf-8")
    for m in _POSTURE_CHECKBOX.finditer(text):
        if m.group("mark").lower() == "x":
            posture: Posture = m.group("posture")  # type: ignore[assignment]
            return posture
    return "TEST"


# ---------------------------------------------------------------------------
# Operator prompt for destructive actions
# ---------------------------------------------------------------------------

PromptCallback = Callable[[str, float], bool]


def stdin_prompt_with_timeout(question: str, timeout_seconds: float) -> bool:
    """Synchronous y/N prompt on stderr with a stdin read timeout.

    Returns True only on an explicit "y"/"yes" response within the
    timeout. Empty input, "n", any other input, EOF, or timeout all
    return False (default-deny).

    Uses `select` so we never block past the timeout. This is a
    POSIX-only path; on Windows the operator prompt simply default-
    denies since `select.select` on stdin is not portable. That is
    correct behaviour: refuse rather than silently bypass.
    """
    if not sys.stdin.isatty():
        # No interactive operator → default-deny.
        sys.stderr.write(
            f"[http_executor] DESTRUCTIVE: {question} "
            f"[default-deny: stdin not a tty]\n"
        )
        return False
    sys.stderr.write(f"[http_executor] DESTRUCTIVE: {question} [y/N] ")
    sys.stderr.flush()
    try:
        ready, _, _ = select.select([sys.stdin], [], [], timeout_seconds)
    except (ValueError, OSError):
        # select can fail on a closed/abnormal stdin; default-deny.
        sys.stderr.write("\n[http_executor] default-deny (stdin unavailable)\n")
        return False
    if not ready:
        sys.stderr.write(f"\n[http_executor] default-deny ({timeout_seconds:.0f}s timeout)\n")
        return False
    try:
        line = sys.stdin.readline().strip().lower()
    except Exception:
        return False
    return line in {"y", "yes"}


# ---------------------------------------------------------------------------
# HttpExecutor
# ---------------------------------------------------------------------------


@dataclass
class HttpExecutor:
    """Live-HTTP executor with full safety stack.

    Construct one per engagement. The executor holds the per-engagement
    request budget; constructing a new one resets the count.

    Required:
      - engagement_slug: directs charter, scope, evidence, log paths.
      - base_url: scheme + host the executor is allowed to target.
                  Per-action URLs that resolve to other hosts are
                  refused by the scope gate.

    Optional:
      - posture: override the charter-declared posture. Default reads
                  from `targets/<slug>/charter.md` § 7.
      - request_budget: total HTTP requests allowed across the
                  executor's lifetime. Default 100.
      - timeout_seconds: per-request httpx timeout. Default 30.
      - prompt_callback: invoked for destructive actions; signature
                  (question:str, timeout:float) -> bool. Default
                  is `stdin_prompt_with_timeout` (POSIX TTY).
      - prompt_timeout_seconds: passed to prompt_callback. Default 30.
      - operator_identifier: appended to TEST/AUDIT user-agent.
      - dry_run: log/budget/check but never call the network. Useful
                  for paranoid offline rehearsal.
    """

    engagement_slug: str
    base_url: str
    posture: Posture | None = None
    request_budget: int = 100
    timeout_seconds: float = 30.0
    prompt_callback: PromptCallback = field(default=stdin_prompt_with_timeout)
    prompt_timeout_seconds: float = 30.0
    operator_identifier: str | None = None
    dry_run: bool = False

    # Optional engagement authority + kill-switch (Pillar: trustworthy
    # autonomy). When set, every action is gated through them BEFORE the
    # scope gate and before any network I/O — so a kill-switch tripped
    # from anywhere (even another process / the CLI) halts the engagement
    # at its very next action. Backward compatible: both default None, in
    # which case the executor behaves exactly as before.
    authority: EngagementAuthority | None = None
    killswitch: KillSwitch | None = None

    # When True and no `authority` was supplied, load the engagement's
    # persisted authority document from disk at construction (via
    # `load_authority`). Backward compatible: defaults False, so
    # callers that never provisioned an authority are unaffected. When
    # a `trust_root` is also given, the *signed* authority is required
    # and verified (`load_verified_authority`) — fail-closed: a missing
    # or badly-signed document leaves `authority` None rather than
    # silently trusting an unverified one.
    auto_load_authority: bool = False
    trust_root: object | None = None

    # Optional runtime egress allowlist (Pillar: sovereignty /
    # defence-in-depth). When set, the httpx client is built on a
    # `SovereignHttpxTransport` so any request to a host outside the
    # allowlist raises `SovereigntyViolation` before bytes leave the
    # host — a belt-and-braces backstop behind the scope gate. When
    # None (the default) the client is built exactly as before, so
    # existing callers/tests are unaffected.
    egress_allowlist: EgressAllowlist | None = None

    # Internal mutable state.
    _requests_made: int = 0
    _last_request_at: float = 0.0
    _scope_violations: int = 0
    _budget_refusals: int = 0
    _destructive_refusals: int = 0
    _http_client: httpx.Client | None = None
    _resolved_posture: Posture = "TEST"

    def __post_init__(self) -> None:
        # Resolve posture once at construction.
        self._resolved_posture = (
            self.posture if self.posture is not None
            else parse_posture(self.engagement_slug)
        )
        # The off-switch is always present: auto-wire a kill-switch bound
        # to this engagement when the caller did not supply one. This is
        # backward compatible — an absent `.halt` file means not tripped,
        # so behaviour is unchanged until an operator trips it (via the
        # `authority halt` CLI or any process). It guarantees the operator
        # can always halt a running engagement, opt-in or not.
        if self.killswitch is None:
            self.killswitch = KillSwitch(self.engagement_slug)
        # Optionally hydrate the engagement authority from disk so the
        # time-box / scope / environment checks in `_authority_gate`
        # apply. Fail-closed and quiet: any load/verify error leaves the
        # authority unset (behaviour identical to not provisioning one).
        if self.authority is None and self.auto_load_authority \
                and not self.engagement_slug.startswith("<"):
            try:
                if self.trust_root is not None:
                    self.authority = load_verified_authority(
                        self.engagement_slug, self.trust_root,  # type: ignore[arg-type]
                    )
                else:
                    self.authority = load_authority(self.engagement_slug)
            except AuthorityError as exc:
                self._log_event(
                    "authority.load_skipped", reason=f"{type(exc).__name__}: {exc}",
                )
        # bind_engagement() is a global mutator. Skip the import-time
        # protocol-assertion path (sentinel slug) but bind for real
        # engagements so structured logs route to the engagement file.
        if not self.engagement_slug.startswith("<"):
            v2log.bind_engagement(self.engagement_slug)

    # ---------------- public protocol ----------------

    def _authority_gate(
        self, method: str, url: str, action_id: str,
    ) -> ExecutionOutcome | None:
        """Check the kill-switch and engagement authority. Returns a
        refusal ExecutionOutcome if the action is denied, or None if it
        may proceed. The kill-switch is checked first and works even
        without a full authority object."""
        # Kill-switch: the absolute stop. Re-read from disk every action,
        # so a trip from any source halts the next action immediately.
        if self.killswitch is not None and self.killswitch.is_tripped():
            self._log_event(
                "authority.halted", action_id=action_id,
                reason=self.killswitch.reason(),
            )
            return self._refused(
                f"engagement halted by kill-switch: {self.killswitch.reason()}",
                status_code=0,
            )

        if self.authority is not None:
            destructive = is_destructive(method, url)
            decision = authorize_action(
                self.authority,
                ActionRequest(
                    target=url, action_kind="exploit", destructive=destructive,
                ),
                killswitch=self.killswitch,
                actions_taken=self._requests_made,
            )
            self._log_event(
                "authority.decision", action_id=action_id,
                decision=decision.model_dump(mode="json"),
            )
            if not decision.allowed:
                return self._refused(
                    f"authority refused ({decision.denial_code}): {decision.reason}",
                    status_code=0,
                )
        return None

    def _gate_redirect(
        self, method: str, url: str, action_id: str,
    ) -> str | None:
        """Re-run the kill-switch + engagement-authority + scope gate for
        a redirect *target* before it is issued. Returns a human-readable
        refusal reason if the redirect must not be followed, or None if it
        is safe to proceed.

        This closes the redirect TOCTOU/SSRF: the initial URL is gated in
        `execute()`, but a 30x Location can point anywhere. Without this
        re-gate an in-scope URL could bounce the executor to an
        out-of-scope host (cloud metadata, an internal service, a third
        party) with no further check. Every hop is now gated exactly like
        the first request.
        """
        halt = self._authority_gate(method, url, action_id)
        if halt is not None:
            return halt.note
        decision = validate_action(
            slug=self.engagement_slug,
            method=method,
            target_url=url,
            posture=self._resolved_posture,
        )
        self._log_event(
            "redirect.scope_decision", action_id=action_id,
            decision=decision.__dict__,
        )
        if not decision.allowed:
            self._scope_violations += 1
            return f"scope_gate refused ({decision.refusal_kind}): {decision.reason}"
        return None

    def _run_gates(
        self, method: str, url: str, action_id: str,
    ) -> ExecutionOutcome | None:
        """Run the full per-action safety chain and return a refusal outcome if
        any gate denies, else None (the action may proceed to I/O).

        Order is load-bearing: authority/kill-switch (before any I/O, so a trip
        halts at the very next action) -> scope -> destructive-confirm (default-
        deny) -> per-engagement budget -> posture rate-limit. Shared by
        ``execute`` and ``execute_differential`` so NO action path can skip a
        gate — a new confirmation mode cannot become a hole in the safety stack.
        """
        halt = self._authority_gate(method, url, action_id)
        if halt is not None:
            return halt

        decision = validate_action(
            slug=self.engagement_slug,
            method=method,
            target_url=url,
            posture=self._resolved_posture,
        )
        self._log_event("scope.decision", action_id=action_id,
                        decision=decision.__dict__)
        if not decision.allowed:
            self._scope_violations += 1
            return self._refused(
                f"scope_gate refused ({decision.refusal_kind}): {decision.reason}",
                status_code=0,
            )

        if decision.is_destructive:
            question = (
                f"about to issue {method} {url} "
                f"(classified destructive). proceed?"
            )
            granted = self.prompt_callback(question, self.prompt_timeout_seconds)
            self._log_event(
                "destructive.prompt", action_id=action_id,
                question=question, granted=granted,
            )
            if not granted:
                self._destructive_refusals += 1
                return self._refused(
                    "destructive action declined / prompt timeout (default-deny)",
                    status_code=0,
                )

        if self._requests_made >= self.request_budget:
            self._budget_refusals += 1
            self._log_event(
                "budget.exhausted", action_id=action_id,
                budget=self.request_budget, requests_made=self._requests_made,
            )
            return self._refused(
                f"per-engagement request budget {self.request_budget} exhausted",
                status_code=0,
            )

        # Rate limit (posture-aware).
        self._sleep_for_rate_limit()
        return None

    def execute(
        self,
        hypothesis: HypothesisPayload,
        plan: PlanPayload,
    ) -> ExecutionOutcome:
        method, url = self._derive_request(hypothesis, plan)
        action_id = self._next_action_id()

        refusal = self._run_gates(method, url, action_id)
        if refusal is not None:
            return refusal

        if self.dry_run:
            self._requests_made += 1
            self._log_event(
                "dry_run.skipped", action_id=action_id, method=method, url=url,
            )
            return ExecutionOutcome(
                success=False, status_code=0, elapsed_ms=0.0,
                body_excerpt="",
                note=f"http_executor: dry_run=True; would have issued {method} {url}",
            )

        return self._issue(action_id=action_id, method=method, url=url,
                           hypothesis=hypothesis)

    def execute_differential(
        self,
        hypothesis: HypothesisPayload,
        plan: PlanPayload,
        *,
        param: str,
        baseline_value: str,
        probe_value: str,
        bug_class: str = "boolean_sqli",
        discriminator: dict | None = None,
    ) -> ExecutionOutcome:
        """Issue a benign BASELINE and a boolean PROBE for ``param`` — both
        through the full ``_run_gates`` chain — and attach the two observed
        responses as ``oracle_context`` so the deterministic differential oracle,
        not the LLM critique, adjudicates.

        This is the live-path counterpart to ``OracleProbeExecutor`` (which only
        probes loopback): every request here still passes authority/scope/
        destructive/budget/rate-limit/egress, so a *live* finding now carries the
        same machine-checkable, independently re-verifiable evidence a loopback
        finding does. Returns ``success=True`` when a candidate worth adjudicating
        was produced — never a confirmation; the oracle remains the gate.
        """
        method, base = self._derive_request(hypothesis, plan)
        baseline_url = _set_query_param(base, param, baseline_value)
        probe_url = _set_query_param(base, param, probe_value)

        captured: dict[str, dict] = {}
        for label, url in (("baseline", baseline_url), ("probe", probe_url)):
            action_id = self._next_action_id()
            refusal = self._run_gates(method, url, action_id)
            if refusal is not None:
                return refusal  # a gate denied one probe -> the whole finding is refused
            if self.dry_run:
                self._requests_made += 1
                self._log_event("dry_run.skipped", action_id=action_id, method=method, url=url)
                return ExecutionOutcome(
                    success=False,
                    note=f"http_executor: dry_run=True; would have issued {method} {url}",
                )
            ua = user_agent_for(self._resolved_posture, self.operator_identifier)
            headers = {"User-Agent": ua, "Accept": "*/*"}
            resp, refusal = self._capture(method, url, action_id, headers)
            if refusal is not None:
                return refusal
            captured[label] = resp  # type: ignore[assignment]

        baseline, mutated = captured["baseline"], captured["probe"]
        context = FindingContext.from_http_responses(
            baseline, mutated, bug_class=bug_class,
            discriminator=discriminator or {"dimensions": ["status", "length", "lexical"]},
        )
        finding = FindingPayload(
            finding_slug=f"{(hypothesis.handle or 'H').strip().lower().replace(' ', '-')}-differential",
            title=f"{bug_class} candidate on {base}",
            severity="High",
            bug_class=bug_class,
            surface=f"{method} {base} [{param}]",
            summary=(
                "A benign baseline and a boolean probe were captured live through "
                "the gated executor; the differential oracle adjudicates whether "
                "the responses diverge enough to confirm."
            ),
        )
        return ExecutionOutcome(
            success=True,
            status_code=int(mutated.get("status", 0)),
            body_excerpt=str(mutated.get("body", ""))[:300],
            note=(
                "http_executor: baseline vs probe captured through the gated stack; "
                "oracle_context attached for deterministic adjudication"
            ),
            finding=finding,
            oracle_context=context.model_dump(),
        )

    def gated_fetch(self, request: object) -> dict:
        """Run one scanner ``HttpRequest`` (``.method``/``.url``/``.headers``/
        ``.body``) through the full gate chain and return
        ``{status, body, headers, latency_ms}`` — a refusal yields status 0 and a
        ``refused`` note.

        This is the adapter that makes the scanner's injected ``send`` *be* the
        gated executor in production: the whole Wave-1 arsenal (crawl + point
        checks + request-level checks) runs against an authorized target with
        every request passing authority/kill-switch/scope/budget/rate-limit/
        egress. It is the ``engage`` runner's bridge between the scanner's
        ``send(HttpRequest)->dict`` contract and the safety stack."""
        method = getattr(request, "method", "GET")
        url = getattr(request, "url", "")
        body = getattr(request, "body", None) or None
        raw_headers = list(getattr(request, "headers", []) or [])
        action_id = self._next_action_id()

        refusal = self._run_gates(method, url, action_id)
        if refusal is not None:
            return {"status": 0, "body": "", "headers": [], "latency_ms": 0.0, "refused": refusal.note}
        if self.dry_run:
            self._requests_made += 1
            self._log_event("dry_run.skipped", action_id=action_id, method=method, url=url)
            return {"status": 0, "body": "", "headers": [], "latency_ms": 0.0}

        headers = {str(k): str(v) for k, v in raw_headers}
        headers.setdefault("User-Agent", user_agent_for(self._resolved_posture, self.operator_identifier))
        headers.setdefault("Accept", "*/*")
        resp, refusal = self._capture(method, url, action_id, headers, body)
        if refusal is not None:
            return {"status": 0, "body": "", "headers": [], "latency_ms": 0.0, "refused": refusal.note}
        return resp  # type: ignore[return-value]

    def stats(self) -> dict[str, int]:
        return {
            "requests_made": self._requests_made,
            "budget": self.request_budget,
            "scope_violations": self._scope_violations,
            "budget_refusals": self._budget_refusals,
            "destructive_refusals": self._destructive_refusals,
        }

    def close(self) -> None:
        if self._http_client is not None:
            self._http_client.close()
            self._http_client = None

    # ---------------- request derivation ----------------

    _METHOD_PREFIX = re.compile(
        r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(?P<rest>.+)$",
        re.IGNORECASE,
    )

    def _derive_request(
        self, hypothesis: HypothesisPayload, plan: PlanPayload,
    ) -> tuple[str, str]:
        """Translate (hypothesis, plan) into a concrete (method, url).

        Conventions, in order of precedence:
          1. `hypothesis.surface` may be prefixed with an HTTP method:
             `POST /payment/cb`, `DELETE /api/users/{id}`.
          2. If `hypothesis.surface` looks like an absolute URL, use it
             as-is (host must still pass the scope gate).
          3. Otherwise default to GET, joined with `self.base_url`.

        Path templates `{id}`, `{slug}`, `{user_id}` are substituted
        with synthetic test-safe values so the request is well-formed.
        """
        surface = hypothesis.surface.strip() or "/"
        method = "GET"
        m = self._METHOD_PREFIX.match(surface)
        if m:
            method = m.group(1).upper()
            surface = m.group("rest").strip()

        # template substitution — test-safe defaults
        surface = surface.replace("{id}", "1")
        surface = surface.replace("{slug}", "test")
        surface = surface.replace("{user_id}", "1")

        if surface.startswith(("http://", "https://")):
            url = surface
        else:
            base = self.base_url.rstrip("/") + "/"
            url = urljoin(base, surface.lstrip("/"))

        return method, url

    # ---------------- HTTP issuance ----------------

    def _client(self) -> httpx.Client:
        if self._http_client is None:
            kwargs: dict[str, object] = dict(
                timeout=self.timeout_seconds,
                follow_redirects=False,  # capture redirect chain manually
            )
            if self.egress_allowlist is not None:
                # Route every request through the sovereign egress guard.
                # In non-strict sovereign mode the transport passes
                # through; in strict mode it refuses non-allowlisted
                # hosts before any bytes leave the host.
                kwargs["transport"] = SovereignHttpxTransport(self.egress_allowlist)
            self._http_client = httpx.Client(**kwargs)  # type: ignore[arg-type]
        return self._http_client

    def _issue(
        self, *, action_id: str, method: str, url: str,
        hypothesis: HypothesisPayload,
    ) -> ExecutionOutcome:
        ua = user_agent_for(self._resolved_posture, self.operator_identifier)
        headers = {"User-Agent": ua, "Accept": "*/*"}
        evidence_dir = self._evidence_dir(action_id)
        paths.secure_dir(evidence_dir)          # X2: owner-only evidence dir

        redirect_chain: list[tuple[int, str]] = []
        redirect_refused: str | None = None
        try:
            t0 = time.perf_counter()
            client = self._client()
            current_method, current_url = method, url
            response = None
            for hop in range(5):  # initial request + up to 4 redirects
                if hop > 0:
                    # Re-gate the redirect target BEFORE issuing it. A
                    # refusal here means the redirect points out of scope
                    # (or the kill-switch/authority now denies) — we stop
                    # the chain and never contact the redirect host.
                    redirect_refused = self._gate_redirect(
                        current_method, current_url, action_id,
                    )
                    if redirect_refused is not None:
                        self._log_event(
                            "redirect.refused", action_id=action_id,
                            refused_url=current_url, reason=redirect_refused,
                            redirect_chain=redirect_chain,
                        )
                        break
                response = client.request(
                    current_method, current_url, headers=headers,
                )
                redirect_chain.append((response.status_code, current_url))
                if response.is_redirect and response.headers.get("location"):
                    current_url = urljoin(current_url, response.headers["location"])
                    # GET on redirect by default
                    current_method = "GET"
                    continue
                break
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
        except SovereigntyViolation as exc:
            # The egress guard refused the host (belt-and-braces behind
            # the scope gate). Treat it like any other gate refusal:
            # a success=False refusal outcome, not a crash.
            self._scope_violations += 1
            self._log_event(
                "egress.refused", action_id=action_id, method=method, url=url,
                error=str(exc), redirect_chain=redirect_chain,
            )
            return self._refused(f"egress guard: {exc}", status_code=0)
        except httpx.HTTPError as exc:
            self._requests_made += 1
            self._last_request_at = time.time()
            self._log_event(
                "http.error", action_id=action_id, method=method, url=url,
                error=f"{type(exc).__name__}: {exc}",
            )
            return ExecutionOutcome(
                success=False, status_code=0, elapsed_ms=0.0,
                body_excerpt="",
                note=f"http_executor: {type(exc).__name__}: {exc}",
            )

        assert response is not None  # for type-checker; loop guarantees one

        self._requests_made += 1
        self._last_request_at = time.time()

        body_bytes = response.content
        body_excerpt = body_bytes[:_BODY_EXCERPT_BYTES].decode(
            "utf-8", errors="replace",
        )
        # archive full request + response
        try:
            (evidence_dir / "request.http").write_text(
                self._format_request(method, url, headers),
                encoding="utf-8",
            )
            (evidence_dir / "response.http").write_text(
                self._format_response(response, redirect_chain),
                encoding="utf-8",
            )
            (evidence_dir / "response.body").write_bytes(body_bytes)
        except OSError as e:
            self._log_event("evidence.write_failed", action_id=action_id, error=str(e))

        self._log_event(
            "http.request",
            action_id=action_id, method=method, url=url,
            status=response.status_code, elapsed_ms=elapsed_ms,
            posture=self._resolved_posture, ua=ua,
            body_bytes=len(body_bytes),
            redirect_chain=redirect_chain,
            evidence_dir=str(evidence_dir),
        )

        # A redirect target was refused by the re-gate: the chain was
        # truncated and the out-of-scope host was never contacted. Report
        # it as a refusal (with the evidence captured up to that point).
        if redirect_refused is not None:
            return ExecutionOutcome(
                success=False,
                status_code=response.status_code,
                elapsed_ms=elapsed_ms,
                body_excerpt=body_excerpt,
                note=(
                    f"http_executor: REFUSED redirect ({redirect_refused}); "
                    f"chain not followed past scope; evidence at {evidence_dir}; "
                    f"redirect_chain={redirect_chain}"
                ),
            )

        # HttpExecutor never claims `success=True` autonomously — that's
        # the exploit-agent's call once it sees the body. Status reach-
        # ability gives a useful signal but isn't a confirmed-bug claim.
        return ExecutionOutcome(
            success=False,
            status_code=response.status_code,
            elapsed_ms=elapsed_ms,
            body_excerpt=body_excerpt,
            note=(
                f"http_executor: {method} {url} -> {response.status_code} "
                f"in {elapsed_ms:.0f}ms; evidence at {evidence_dir}; "
                f"posture={self._resolved_posture}; "
                f"redirect_chain={redirect_chain}"
            ),
        )

    def _capture(
        self, method: str, url: str, action_id: str, headers: dict[str, str],
        body: str | bytes | None = None,
    ) -> tuple[dict | None, ExecutionOutcome | None]:
        """Issue one ALREADY-GATED request (following + re-gating redirects) and
        return its response as an oracle-ready dict
        ``{status, body, headers, latency_ms}``, or ``(None, refusal)``.

        Mirrors ``_issue``'s I/O (redirect re-gate, evidence archive, budget
        increment, egress/http-error handling) but yields structured response
        data for the oracle layer instead of a human-readable outcome. The
        gating itself is NOT duplicated — the caller runs ``_run_gates`` first
        and redirects re-enter ``_gate_redirect`` here. ``body`` is sent on the
        initial hop and dropped on any redirect (which becomes a GET)."""
        evidence_dir = self._evidence_dir(action_id)
        paths.secure_dir(evidence_dir)          # X2: owner-only evidence dir
        redirect_chain: list[tuple[int, str]] = []
        redirect_refused: str | None = None
        try:
            t0 = time.perf_counter()
            client = self._client()
            current_method, current_url = method, url
            current_body = body
            response = None
            for hop in range(5):
                if hop > 0:
                    redirect_refused = self._gate_redirect(current_method, current_url, action_id)
                    if redirect_refused is not None:
                        self._log_event(
                            "redirect.refused", action_id=action_id,
                            refused_url=current_url, reason=redirect_refused,
                            redirect_chain=redirect_chain,
                        )
                        break
                content = None
                if current_body is not None:
                    content = current_body.encode("utf-8") if isinstance(current_body, str) else current_body
                response = client.request(current_method, current_url, headers=headers, content=content)
                redirect_chain.append((response.status_code, current_url))
                if response.is_redirect and response.headers.get("location"):
                    current_url = urljoin(current_url, response.headers["location"])
                    current_method = "GET"
                    current_body = None  # a redirected request carries no body
                    continue
                break
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
        except SovereigntyViolation as exc:
            self._scope_violations += 1
            self._log_event("egress.refused", action_id=action_id, method=method, url=url,
                            error=str(exc), redirect_chain=redirect_chain)
            return None, self._refused(f"egress guard: {exc}", status_code=0)
        except httpx.HTTPError as exc:
            self._requests_made += 1
            self._last_request_at = time.time()
            self._log_event("http.error", action_id=action_id, method=method, url=url,
                            error=f"{type(exc).__name__}: {exc}")
            return None, ExecutionOutcome(
                success=False, status_code=0,
                note=f"http_executor: {type(exc).__name__}: {exc}")

        assert response is not None
        self._requests_made += 1
        self._last_request_at = time.time()

        body_bytes = response.content
        body_excerpt = body_bytes[:_BODY_EXCERPT_BYTES].decode("utf-8", errors="replace")
        try:
            (evidence_dir / "request.http").write_text(
                self._format_request(method, url, headers), encoding="utf-8")
            (evidence_dir / "response.http").write_text(
                self._format_response(response, redirect_chain), encoding="utf-8")
            (evidence_dir / "response.body").write_bytes(body_bytes)
        except OSError as e:
            self._log_event("evidence.write_failed", action_id=action_id, error=str(e))

        self._log_event(
            "http.request", action_id=action_id, method=method, url=url,
            status=response.status_code, elapsed_ms=elapsed_ms,
            posture=self._resolved_posture, body_bytes=len(body_bytes),
            redirect_chain=redirect_chain, evidence_dir=str(evidence_dir),
        )

        if redirect_refused is not None:
            return None, ExecutionOutcome(
                success=False, status_code=response.status_code, elapsed_ms=elapsed_ms,
                body_excerpt=body_excerpt,
                note=f"http_executor: REFUSED redirect ({redirect_refused})")

        return {
            "status": response.status_code,
            "body": body_excerpt,
            "headers": [(k, v) for k, v in response.headers.items()],
            "latency_ms": elapsed_ms,
        }, None

    # ---------------- helpers ----------------

    def _refused(self, note: str, *, status_code: int) -> ExecutionOutcome:
        return ExecutionOutcome(
            success=False, status_code=status_code, elapsed_ms=0.0,
            body_excerpt="",
            note=f"http_executor: REFUSED: {note}",
        )

    def _next_action_id(self) -> str:
        return f"H-{int(time.time() * 1000) % 1_000_000_000:09d}"

    def _evidence_dir(self, action_id: str) -> Path:
        return paths.target_dir(self.engagement_slug) / "evidence" / action_id

    def _sleep_for_rate_limit(self) -> None:
        floor, jitter_max = _RATE_PROFILES[self._resolved_posture]
        if self._last_request_at <= 0.0:
            base_wait = 0.0
        else:
            elapsed = time.time() - self._last_request_at
            base_wait = max(0.0, floor - elapsed)
        jitter = random.uniform(0.0, jitter_max) if jitter_max > 0 else 0.0
        total = base_wait + jitter
        if total > 0:
            time.sleep(total)

    def _log_event(self, kind: str, **fields: object) -> None:
        try:
            _log.info(f"http_executor.{kind}", **fields)
        except Exception:  # logging never raises through the executor
            pass

    def _format_request(
        self, method: str, url: str, headers: dict[str, str],
    ) -> str:
        # X2: mask credential header VALUES (Authorization/Cookie/…) in the archived
        # human-readable dump — a shared-host credential leak that outlives the run.
        # The name is kept; the raw response.body is untouched (byte-fidelity).
        lines = [f"{method} {url} HTTP/1.1"]
        for k, v in headers.items():
            lines.append(f"{k}: {redact.redact_header(k, v)}")
        lines.append("")
        return "\n".join(lines)

    def _format_response(
        self, response: httpx.Response, chain: list[tuple[int, str]],
    ) -> str:
        lines = [f"HTTP/{response.http_version} {response.status_code} {response.reason_phrase}"]
        for k, v in response.headers.items():
            lines.append(f"{k}: {redact.redact_header(k, v)}")   # X2: mask Set-Cookie/token values
        lines.append("")
        lines.append("# redirect chain (status, url):")
        for st, u in chain:
            lines.append(f"#   {st}  {u}")
        lines.append("")
        lines.append(f"# body: {len(response.content)} bytes (full body in response.body)")
        return "\n".join(lines)


# Runtime-safe protocol assertion. If Executor's signature drifts,
# this fails at import time rather than at first use.
_he: Executor = HttpExecutor(  # noqa: F841 — type-narrowing only
    engagement_slug="<unused>", base_url="https://unused.example",
    dry_run=True,
)
