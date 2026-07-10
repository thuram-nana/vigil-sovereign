"""
repeater.tool — ``HttpRepeaterTool``: the gated Tier-2 capability that REPLAYS a request (W4.D).

This is the load-bearing piece: a replay must never touch a raw un-gated socket. The tool reuses
BOTH existing gate seams, weakening neither:

  1. It is a W1.4 ``agents.tools.Tool``, so ``invoke_tool`` runs the fail-closed chain BEFORE
     ``run`` is ever called: kill-switch -> entitlement (``EXPLOIT_EXECUTION``) -> charter scope
     (on ``args['target']``) -> destructive-confirm -> egress. A refused invocation NEVER runs.
  2. Inside ``run``, it issues NOTHING itself. It hands the request to a per-engagement
     ``agents.http_executor.HttpExecutor`` via ``gated_fetch`` — which re-runs the FULL HTTP gate
     chain (authority/kill-switch -> scope -> destructive-confirm -> per-engagement budget ->
     posture rate-limit -> egress), archives request+response evidence, re-gates every redirect,
     and forces the correlatable OBSIDIAN User-Agent.

So every replayed request is DOUBLE-gated (entitlement at the tool seam; scope/budget/rate-limit/
redirect/egress at the executor) and every byte that leaves the host is charter-scope-validated and
correlatable. An out-of-scope target, a missing entitlement, or a tripped kill-switch refuses and
sends nothing.

Entitlement choice: a repeater crafts and re-sends MODIFIED requests (mutated bodies, injection
payloads) to actively probe a single hypothesis — that is exploitation, so it requires the
OFFENSIVE-tier ``EXPLOIT_EXECUTION`` grant (deliberately stricter than the recon sensors).

CORRELATABLE, NOT EVASIVE (hard doctrine line): the tool STRIPS any operator-supplied
``User-Agent`` before replay so the executor's recognizable OBSIDIAN UA always wins — the repeater
cannot be used to rotate identity, impersonate a browser, or hide from the operator's own
defenders. There is no proxy-chaining and no stealth here by construction.

Determinism: gate composition and arg handling are a pure function of ``(args, ctx)``; the response
reflects the live target but nothing in the gate path reads the wallclock or a global rng.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from ..agents.http_executor import HttpExecutor, stdin_prompt_with_timeout
from ..agents.tools import ToolContext, ToolResult
from ..entitlement.models import Capability
from .models import normalize_headers

# The identity header the executor sets to the recognizable OBSIDIAN value. The repeater strips
# any operator-supplied instance of it so correlatability is enforced by construction, never
# overridable — the doctrine line against identity rotation / defender evasion.
_IDENTITY_HEADER = "user-agent"


def base_url_of(url: str) -> str:
    """The scheme://host[:port] origin of ``url`` (no path/query/fragment) — what an
    ``HttpExecutor`` is constructed with. Defaults to https when the URL omits a scheme. Pure."""
    parts = urlsplit(url if "://" in url else "https://" + url)
    return urlunsplit((parts.scheme, parts.netloc, "", "", ""))


@dataclass
class _RepeaterHttpRequest:
    """The duck-typed request ``HttpExecutor.gated_fetch`` consumes (``.method``/``.url``/
    ``.headers``/``.body``). ``headers`` is a list of ``(name, value)`` pairs."""

    method: str
    url: str
    headers: list
    body: str | None = None


class HttpRepeaterTool:
    """Replay ONE captured/edited HTTP request against a single in-scope target, through the full
    gate chain. args: ``{"url": <target>, "target": <same>, "method": "GET"?, "headers": [[k,v]]?,
    "body": str?}``.

    ``target`` MUST equal ``url`` — the invoker scope-gates ``args['target']`` and the executor
    issues ``args['url']``; requiring them identical closes any gap between the URL that was
    authorized and the URL that is sent. Active (Tier-2): declares ``capability =
    EXPLOIT_EXECUTION`` (the entitlement gate refuses it without that grant). ``destructive`` is
    intentionally False at the tool level because destructive-confirm is enforced PER-REQUEST and
    precisely at the executor layer (POST/PUT/DELETE/PATCH or a destructive path prompts;
    a benign GET does not)."""

    name = "http_repeater"
    tier = "T2"
    capability = Capability.EXPLOIT_EXECUTION
    destructive = False
    egress_hosts: tuple = ()   # the concrete target is scope-gated via args['target'] + the executor

    def __init__(
        self,
        *,
        request_budget: int = 100,
        timeout_seconds: float = 30.0,
        executor_factory: Any = None,
    ) -> None:
        self._request_budget = request_budget
        self._timeout_seconds = timeout_seconds
        # A test seam: (slug, base_url, ctx) -> HttpExecutor. Production leaves it None and builds
        # a real HttpExecutor. Never used to bypass a gate — the returned executor is still gated.
        self._executor_factory = executor_factory
        # One executor per engagement slug, so the per-engagement request BUDGET is shared across
        # every replay in a session (re-capturing cannot reset it). Keyed by slug (deterministic).
        self._executors: dict[str, HttpExecutor] = {}

    def _executor_for(self, slug: str, base_url: str, ctx: ToolContext) -> HttpExecutor:
        ex = self._executors.get(slug)
        if ex is None:
            if self._executor_factory is not None:
                ex = self._executor_factory(slug=slug, base_url=base_url, ctx=ctx)
            else:
                ex = HttpExecutor(
                    engagement_slug=slug,
                    base_url=base_url,
                    # Load the signed EngagementAuthority (time-box validity window, max-actions
                    # ceiling, environment binding) exactly as the production engage path does
                    # (engage.py) — else the offensive-tier repeater would enforce ONLY the
                    # kill-switch and a replay could fire after the authorization window closed.
                    auto_load_authority=True,
                    prompt_callback=getattr(ctx, "prompt_callback", None) or stdin_prompt_with_timeout,
                    request_budget=self._request_budget,
                    timeout_seconds=self._timeout_seconds,
                    dry_run=bool(getattr(ctx, "dry_run", False)),
                )
            self._executors[slug] = ex
        return ex

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        if not isinstance(args, dict):
            return ToolResult(ok=False, note="http_repeater requires a dict of args")
        url = str(args.get("url") or args.get("target") or "").strip()
        target = str(args.get("target") or url).strip()
        if not url:
            return ToolResult(ok=False, note="http_repeater requires args['url'] (an in-scope target URL)")
        # AUTHORIZATION-CRITICAL: the URL the executor issues MUST be the URL the invoker's scope
        # gate validated. If a caller passes a divergent target/url, refuse (fail-closed) rather
        # than issue an unauthorized URL.
        if target and target != url:
            return ToolResult(ok=False, note=(
                "http_repeater: args['target'] must equal args['url'] — the scope-gated URL and the "
                "issued URL must be identical (refused to avoid a scope-vs-issue mismatch)"))

        method = str(args.get("method") or "GET").upper().strip() or "GET"
        body = args.get("body")
        if body is not None and not isinstance(body, (str, bytes)):
            body = str(body)

        # CORRELATABLE, NOT EVASIVE: drop any operator-supplied User-Agent so the executor's
        # setdefault installs the recognizable OBSIDIAN UA. No identity rotation, no browser
        # impersonation — the replay is always attributable to this authorized run.
        pairs = normalize_headers(args.get("headers"))
        headers = [[k, v] for (k, v) in pairs if k.lower() != _IDENTITY_HEADER]

        executor = self._executor_for(ctx.slug, base_url_of(url), ctx)
        request = _RepeaterHttpRequest(method=method, url=url, headers=headers, body=body)
        resp = executor.gated_fetch(request)

        refused = resp.get("refused") if isinstance(resp, dict) else None
        request_view = {"method": method, "url": url, "headers": headers, "has_body": body is not None}
        if refused:
            # The executor's inner gate chain (scope/destructive/budget/rate-limit/egress/authority)
            # declined the replay — nothing left the host. Surface it as a refusal.
            return ToolResult(
                ok=False, refused=True, gate="http-gate", note=str(refused),
                output={"response": None, "request": request_view})
        status = resp.get("status") if isinstance(resp, dict) else 0
        return ToolResult(
            ok=True,
            summary=f"http_repeater {method} {url} -> {status}",
            output={"response": resp, "request": request_view})

    def close(self) -> None:
        """Close every per-engagement executor's HTTP client. The executor OBJECTS are retained
        (not cleared) so their counters remain readable for the audit trail after close; a later
        replay reuses them and the executor lazily rebuilds its client."""
        for ex in self._executors.values():
            try:
                ex.close()
            except Exception:
                pass
