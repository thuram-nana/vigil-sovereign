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
from urllib.parse import urljoin, urlparse

import httpx

from ..common import logging as v2log
from ..common import paths
from ..authority import (
    ActionRequest,
    EngagementAuthority,
    KillSwitch,
    authorize_action,
)
from .executor_proto import ExecutionOutcome, Executor
from .models import HypothesisPayload, PlanPayload
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

    def execute(
        self,
        hypothesis: HypothesisPayload,
        plan: PlanPayload,
    ) -> ExecutionOutcome:
        method, url = self._derive_request(hypothesis, plan)
        action_id = self._next_action_id()

        # Engagement-authority + kill-switch gate. Checked first, before
        # the scope gate and before any I/O, so a tripped kill-switch
        # halts the engagement at the very next action.
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
            self._http_client = httpx.Client(
                timeout=self.timeout_seconds,
                follow_redirects=False,  # capture redirect chain manually
            )
        return self._http_client

    def _issue(
        self, *, action_id: str, method: str, url: str,
        hypothesis: HypothesisPayload,
    ) -> ExecutionOutcome:
        ua = user_agent_for(self._resolved_posture, self.operator_identifier)
        headers = {"User-Agent": ua, "Accept": "*/*"}
        evidence_dir = self._evidence_dir(action_id)
        evidence_dir.mkdir(parents=True, exist_ok=True)

        redirect_chain: list[tuple[int, str]] = []
        try:
            t0 = time.perf_counter()
            client = self._client()
            current_method, current_url = method, url
            response = None
            for _hop in range(5):  # max 5 redirects
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
        lines = [f"{method} {url} HTTP/1.1"]
        for k, v in headers.items():
            lines.append(f"{k}: {v}")
        lines.append("")
        return "\n".join(lines)

    def _format_response(
        self, response: httpx.Response, chain: list[tuple[int, str]],
    ) -> str:
        lines = [f"HTTP/{response.http_version} {response.status_code} {response.reason_phrase}"]
        for k, v in response.headers.items():
            lines.append(f"{k}: {v}")
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
