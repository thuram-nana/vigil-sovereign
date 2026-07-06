"""
agents.egress_guard — runtime egress allowlist for sovereign-mode httpx.

Why this exists:
  Even after the source-level egress audit (SOVEREIGNTY-EGRESS-AUDIT.md)
  confirms every production code path either targets an in-scope host
  (HttpExecutor, UTI fetcher) or an in-policy LLM endpoint (Ollama
  localhost, etc.), a future code change or a malicious dependency
  could introduce a new egress path. Sovereign deployments need a
  belt-and-braces guarantee: any unexpected egress raises
  `SovereigntyViolation` instead of silently leaving the host.

How it works:
  This module exposes a `SovereignHttpxTransport` — a wrapper around
  `httpx.HTTPTransport` (or `MockTransport`, in tests). On every
  request, the transport extracts the target host and matches it
  against an allowlist. Mismatches raise `SovereigntyViolation`
  before bytes leave the host.

Construction:
  ```
  from framework.v2.agents.egress_guard import (
      SovereignHttpxTransport, build_engagement_allowlist,
  )

  allowlist = build_engagement_allowlist(slug="alpha")
  transport = SovereignHttpxTransport(allowlist=allowlist)
  client = httpx.Client(transport=transport)
  ```

Where to install:
  HttpExecutor and the UTI Fetcher are the two production code paths
  that issue HTTP requests. Both can be constructed with a
  pre-configured `httpx.Client`. Sovereign deployments inject a
  guarded client into both. Tests confirm the guard fires.

This module does not monkeypatch the global httpx default client.
A monkeypatch would catch unauthorised egress *and* break legitimate
test fixtures (pytest-httpserver, etc.). Per-instance guards are
explicit, type-checkable, and impossible to confuse with global
state. Sovereign deployments are responsible for wiring the guard
into every `httpx.Client` they construct.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

import httpx

from ..common import ethics
from ..common.errors import SovereigntyViolation
from ..kernel import sovereignty


# Backends classified `local` by sovereignty.classify() expose
# endpoints on these hosts. Sovereign mode permits egress to these
# even when no engagement-specific allowlist names them.
_LOCAL_LLM_HOSTS: frozenset[str] = frozenset({
    "localhost",
    "127.0.0.1",
    "::1",
})


@dataclass(frozen=True)
class EgressAllowlist:
    """Hosts permitted to receive HTTP requests from this process.

    Four categories:
      - `target_hosts`: parsed from the engagement charter; HttpExecutor
        traffic goes here.
      - `llm_hosts`: the current LLM backend's endpoint host. Under
        sovereign mode this is always `localhost`-equivalent.
      - `collector_hosts`: third-party passive-recon sources the intel
        engine may query (a CT log, a DNS-over-HTTPS resolver, an RDAP
        server). These are DISJOINT from `target_hosts` by construction —
        recon sources are never the target itself — so a collector can
        reach a CT log without being able to reach the engagement's scope,
        and vice versa. Populated only when live collection is explicitly
        enabled; empty by default (offline recon uses fixtures).
      - `extra_hosts`: operator-supplied additions for one-off needs
        (e.g. an internal package mirror during install).

    Wildcard prefix `*.example.com` matches subdomains and the apex,
    matching the behaviour of `ethics.host_matches_scope()`.
    """

    target_hosts: tuple[str, ...] = ()
    llm_hosts: tuple[str, ...] = tuple(_LOCAL_LLM_HOSTS)
    collector_hosts: tuple[str, ...] = ()
    extra_hosts: tuple[str, ...] = ()

    def all_entries(self) -> tuple[str, ...]:
        return (tuple(self.target_hosts) + tuple(self.llm_hosts)
                + tuple(self.collector_hosts) + tuple(self.extra_hosts))

    def permits(self, host: str) -> bool:
        if not host:
            return False
        return ethics.host_matches_scope(host, list(self.all_entries()))


def build_engagement_allowlist(
    *,
    slug: str | None = None,
    extra_hosts: Iterable[str] = (),
) -> EgressAllowlist:
    """Construct an allowlist for one engagement.

    Reads the charter scope via `ethics.parse_scope()` if `slug` is
    given; falls back to an empty list otherwise (still permits
    `localhost`-equivalent for the LLM backend).

    Under sovereign-strict, `llm_hosts` never includes a public LLM
    vendor because `kernel.sovereignty` has already refused those
    backends. Under permissive, sovereign deployments shouldn't be
    constructing the guard anyway — the guard is a sovereign-mode
    feature.
    """
    target_hosts: tuple[str, ...] = ()
    if slug:
        try:
            target_hosts = tuple(ethics.parse_scope(slug))
        except Exception:
            # Charter not present yet (e.g. UTI is mid-scaffold). Empty
            # is correct: the scope_gate will refuse target requests
            # until the charter exists; the guard's job is to backstop,
            # not duplicate, that gate.
            target_hosts = ()
    return EgressAllowlist(
        target_hosts=target_hosts,
        llm_hosts=tuple(_LOCAL_LLM_HOSTS),
        extra_hosts=tuple(extra_hosts),
    )


class SovereignHttpxTransport(httpx.BaseTransport):
    """httpx transport that refuses requests to hosts outside the
    allowlist. Wraps an inner transport (defaults to a fresh
    `httpx.HTTPTransport`)."""

    def __init__(
        self,
        allowlist: EgressAllowlist,
        *,
        inner: httpx.BaseTransport | None = None,
        sovereign_only: bool = True,
    ) -> None:
        super().__init__()
        self._allowlist = allowlist
        self._inner: httpx.BaseTransport = inner or httpx.HTTPTransport()
        self._sovereign_only = sovereign_only

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        # In permissive mode the guard logs but does not refuse — the
        # operator may want development workflows that hit external
        # docs / package mirrors. In sovereign mode it always refuses.
        if self._sovereign_only and not sovereignty.current().strict:
            return self._inner.handle_request(request)

        host = request.url.host
        if not self._allowlist.permits(host):
            raise SovereigntyViolation(
                f"egress to {host!r} refused under sovereign mode "
                f"(URL={request.url}, method={request.method}). "
                f"Allowlist: target_hosts={self._allowlist.target_hosts}, "
                f"llm_hosts={self._allowlist.llm_hosts}, "
                f"collector_hosts={self._allowlist.collector_hosts}, "
                f"extra_hosts={self._allowlist.extra_hosts}. "
                f"If this host is legitimately required, add it to the "
                f"engagement charter scope or pass extra_hosts=... "
                f"explicitly when constructing the allowlist."
            )
        return self._inner.handle_request(request)

    def close(self) -> None:
        self._inner.close()
