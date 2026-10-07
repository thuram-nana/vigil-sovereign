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

from dataclasses import dataclass
from typing import Callable, Iterable

import httpcore
import httpx

from ..common import ethics, paths
from ..common.errors import SovereigntyViolation
from ..kernel import sovereignty

# The deterministic protected-domain scope floor (Slice 0 / vigil_core). Applied here as the last-mile
# unconditional floor on the raw request URL — ABOVE the permissive passthrough — so a protected host is
# refused even in non-sovereign/permissive mode. Toggle-gated (default ON) per the uniform owner toggle.
from vigil_core.hard_guardrail import assert_not_hard_blocked, protected_guard_enabled


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


# Common multi-label public suffixes — a wildcard whose base IS a public suffix opens an enormous egress
# range. Not a full PSL (collector hosts are operator-provisioned + explicit); just the frequent footguns.
_PUBLIC_2LABEL_SUFFIXES = frozenset({
    "co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "net.au", "org.au", "co.jp", "co.nz",
    "com.br", "co.in", "com.cn", "co.za", "com.mx", "com.sg", "co.kr",
})


def _collector_host_too_broad(h: str) -> bool:
    """A collector egress host that would open a whole TLD / public suffix (a C2/exfil footgun on a
    sovereignty boundary). A concrete apex or a wildcard whose base has ≥2 PRIVATE labels
    (e.g. ``*.amazonaws.com``) is fine; a bare ``*``, a single-TLD-label wildcard (``*.com``, ``*.internal``,
    ``*.local``), or a public-suffix wildcard (``*.co.uk``) is refused (H1)."""
    h = h.strip().strip(".").lower()
    if not h or h in ("*", "*.*"):
        return True
    if not h.startswith("*."):
        return False       # a concrete host/apex is exactly as narrow as it reads
    base = h[2:]
    if not base or "." not in base:
        return True        # '*.com', '*.internal' — a single label after the wildcard
    return base in _PUBLIC_2LABEL_SUFFIXES


def _slug_safe(slug: str) -> bool:
    """A slug is a single path component (mirrors the console guard). Reject traversal/absolute so a crafted
    slug can never read a collector-hosts file outside targets/<slug>/ (H2 defence-in-depth; slug is
    operator-supplied, but this makes THIS reader traversal-safe regardless of the shared paths layer)."""
    s = str(slug or "")
    return bool(s) and ".." not in s and "/" not in s and "\\" not in s and ":" not in s \
        and not s.startswith(".")


def provisioned_collector_hosts(slug: str | None) -> tuple[str, ...]:
    """The operator-provisioned live-collection egress hosts for ``slug`` — read from
    ``targets/<slug>/collector-hosts.txt`` (one host/wildcard per line; ``#`` comments; blanks ignored).

    This is a SEPARATE, explicit provisioning surface from the charter target scope: a live cloud/K8s
    collector must reach a third-party control plane (e.g. ``sts.amazonaws.com``, the kube-apiserver) that is
    deliberately NOT in the engagement's attack scope. DEFAULT EMPTY — absent file ⇒ no collector egress is
    permitted (fail-closed; live collection stays off until the operator provisions it). Never raises."""
    if not _slug_safe(slug):
        return ()
    try:
        p = paths.target_dir(slug) / "collector-hosts.txt"
        if not p.is_file():
            return ()
        out: list[str] = []
        for ln in p.read_text(encoding="utf-8", errors="replace").split("\n"):
            ln = ln.strip()
            if ln and not ln.startswith("#"):
                out.append(ln)
        return tuple(dict.fromkeys(out))       # de-dup, preserve order
    except OSError:
        return ()


def build_engagement_allowlist(
    *,
    slug: str | None = None,
    extra_hosts: Iterable[str] = (),
    collector_hosts: Iterable[str] = (),
) -> EgressAllowlist:
    """Construct an allowlist for one engagement.

    Reads the charter scope via `ethics.parse_scope()` if `slug` is
    given; falls back to an empty list otherwise (still permits
    `localhost`-equivalent for the LLM backend).

    ``collector_hosts`` (explicit, plus any provisioned in
    ``targets/<slug>/collector-hosts.txt``) enable a LIVE read-only collector to reach a third-party control
    plane. They are held in a SEPARATE allowlist axis from the target scope AND any that OVERLAP the target
    scope are DROPPED (the intel doctrine: a recon source must be a third party disjoint from the target —
    ``collector_scope_conflicts``). Empty by default ⇒ no collector egress is widened until the operator
    provisions it (fail-closed).

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
    # union the explicit + provisioned collector hosts, then DROP any that (a) conflict with the target
    # scope — a collector egress host must be a third party disjoint from what we are attacking — or
    # (b) are too broad (a bare '*' / whole-TLD / public-suffix wildcard, an exfil footgun). Fail-closed.
    requested = tuple(dict.fromkeys(tuple(collector_hosts) + provisioned_collector_hosts(slug)))
    conflicts = set(collector_scope_conflicts(requested, target_hosts))
    safe_collectors = tuple(h for h in requested
                            if h and h not in conflicts and not _collector_host_too_broad(h))
    return EgressAllowlist(
        target_hosts=target_hosts,
        llm_hosts=tuple(_LOCAL_LLM_HOSTS),
        collector_hosts=safe_collectors,
        extra_hosts=tuple(extra_hosts),
    )


def collector_scope_conflicts(
    collector_hosts: Iterable[str], target_hosts: Iterable[str],
) -> list[str]:
    """Collector hosts that OVERLAP the engagement's target scope, in either direction
    (a collector host covered by target scope, or a target host covered by a collector
    wildcard). The intel doctrine requires recon sources to be third parties disjoint
    from the target; this makes that property checkable rather than merely asserted.
    Empty list ⇒ genuinely disjoint."""
    targets = list(target_hosts)
    ch = list(collector_hosts)
    conflicts: list[str] = []
    for h in ch:
        if not h:
            continue
        if ethics.host_matches_scope(h, targets) or any(
                ethics.host_matches_scope(t, [h]) for t in targets if t):
            conflicts.append(h)
    return conflicts


# Loopback is the operator's OWN box: dialling 127.0.0.1/::1 adds no NEW network reach (it cannot reach
# the cloud metadata service, another host's RFC1918, or anything off-box), and the engine has always been
# able to engage loopback/MERIDIAN targets. So a loopback baseline is carried (mirrors
# ``scanner.race.raw_race``), on TOP of which the charter's IP literals lift the private tier for an exact
# literal. The metadata/link-local/RFC1918/multicast/CGNAT/reserved tier is NEVER in this set, so it is
# always refused regardless of slug.
_LOOPBACK_BASELINE: frozenset[str] = frozenset({"127.0.0.1", "::1"})


class _FloorPinnedBackend(httpcore.NetworkBackend):
    """httpcore network backend that enforces the never-liftable L3/L4 egress FLOOR with an anti-rebinding
    pin, reusing the SAME shared primitive the raw-socket capture paths use
    (``common.egress_pin.resolve_and_validate_all`` -> ``vigil_gateway.denylist.is_egress_denied``).

    Why a backend rather than a URL rewrite: the floor's resolution and the dial happen HERE, atomically,
    so there is NO check/connect TOCTOU — the host is resolved exactly ONCE, every resolved address must
    clear the floor, and the connection is then made ONLY to those validated addresses (create_connection-
    style fallback across them, so a dual-stack host still falls back across its validated IPs) and the name
    is NEVER re-resolved. A DNS-rebinding resolver therefore cannot present a safe answer to the check and a
    denied answer to the dialer. The ``Host`` header and TLS SNI are untouched (the origin host stays the
    original name), so a vhost still routes and presents + validates its real certificate.

    Fail-closed: a floor refusal raises :class:`SovereigntyViolation` BEFORE any socket is opened; an
    import/resolution error refuses too. The metadata/link-local/RFC1918/multicast/CGNAT/reserved tier is
    charter-independent and never lifted; loopback/private lift only for the loopback baseline + an exact
    charter IP literal from ``slug``."""

    def __init__(
        self,
        *,
        slug: str,
        resolver: Callable[..., object] | None,
        inner: httpcore.NetworkBackend,
    ) -> None:
        self._slug = slug
        self._resolver = resolver
        self._inner = inner

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: "Iterable[object] | None" = None,
    ) -> "httpcore.NetworkStream":
        try:
            from ..common.egress_pin import (
                EgressFloorRefused,
                charter_ip_literals,
                resolve_and_validate_all,
            )
        except Exception as exc:  # no floor importable => refuse rather than connect unguarded
            raise SovereigntyViolation(
                f"egress floor (common.egress_pin) not importable, so no destination can be authorized "
                f"(fail-closed): {type(exc).__name__}: {exc}") from exc
        allowed = _LOOPBACK_BASELINE | charter_ip_literals(self._slug)
        try:
            # Opt in to owner-scoped loopback; loopback + RFC1918 lift ONLY for the loopback baseline / an
            # exact charter literal. metadata/link-local/multicast/CGNAT/reserved are never in ``allowed``.
            validated = resolve_and_validate_all(
                host, int(port), allowed_ips=allowed,
                loopback_allowed_if_scoped=True, resolver=self._resolver)
        except EgressFloorRefused as exc:
            raise SovereigntyViolation(
                f"egress to {host!r}:{port} refused by the never-liftable L3/L4 egress floor "
                f"(metadata/link-local/RFC1918/multicast/CGNAT/reserved — directly or via a DNS-rebinding "
                f"answer; the floor is charter-independent and cannot be lifted by a scope listing). "
                f"Reason: {exc}") from exc
        # Dial the VALIDATED addresses only, in resolution order, with fallback — never the re-resolvable
        # name. Every address here already cleared the floor, so fallback cannot reach a denied address.
        last_exc: Exception | None = None
        for ip in validated:
            try:
                return self._inner.connect_tcp(
                    ip, port, timeout=timeout, local_address=local_address,
                    socket_options=socket_options)
            except (httpcore.ConnectError, httpcore.ConnectTimeout) as exc:
                last_exc = exc
        raise last_exc if last_exc is not None else httpcore.ConnectError(
            f"no validated address for {host!r}:{port} could be dialled")

    def connect_unix_socket(self, path, timeout=None, socket_options=None):  # noqa: ANN001, ANN201
        # No egress leaves the host over a unix socket; pass through (the LLM backend / local IPC case).
        return self._inner.connect_unix_socket(path, timeout=timeout, socket_options=socket_options)

    def sleep(self, seconds: float) -> None:
        self._inner.sleep(seconds)


class SovereignHttpxTransport(httpx.BaseTransport):
    """httpx transport that refuses requests to hosts outside the allowlist (the NAME control) AND
    enforces the never-liftable L3/L4 egress FLOOR with an anti-rebinding pin (the ADDRESS control).

    Wraps an inner transport (defaults to a fresh `httpx.HTTPTransport`).

    Two egress controls, both fail-closed:

      * NAME allowlist — refuses a host outside the engagement scope under sovereign mode (unchanged).
      * L3/L4 egress FLOOR + anti-rebinding pin (WS1.1b) — the NAME allowlist alone was a BYPASS: a
        charter-scoped name that resolves to the cloud metadata IP / an RFC1918 / link-local / multicast /
        CGNAT / reserved address (directly, or via a DNS-rebinding answer) passed ``permits()`` and the
        inner ``httpx.HTTPTransport`` then RE-RESOLVED the name and dialled the denied IP. The floor closes
        that by installing :class:`_FloorPinnedBackend` under the real ``httpx.HTTPTransport``: it resolves
        the host ONCE through the SAME shared primitive the raw-socket capture paths use
        (``common.egress_pin.resolve_and_validate_all`` -> ``vigil_gateway.denylist.is_egress_denied`` over
        EVERY resolved address), refuses on any denied address, and connects ONLY to the validated
        addresses — never the re-resolvable name. The ``Host`` header and TLS SNI stay the original
        hostname (the origin host is untouched) so a vhost still routes and presents + validates its real
        certificate. The metadata/link-local/multicast/CGNAT/reserved tier is charter-independent and NEVER
        lifted; loopback/RFC1918 lift ONLY for the loopback baseline / an exact charter IP literal taken
        from ``slug``. The floor runs in BOTH sovereign and permissive mode — a floor a mode could lift
        would not be a floor.

    Hermeticity (mirrors ``verify.reachability``'s "floor only when ``connect is None``" rule): the floor
    performs DNS + dials, so it is installed on the REAL egress path only — when the caller did not inject
    its own ``inner`` transport (production: ``inner is None`` -> a real ``httpx.HTTPTransport``). A caller
    that injects its own ``inner`` double (the existing unit tests, which dial non-resolving ``*.example``
    hosts through a ``MockTransport`` that never reaches the network backend) exercises only the NAME
    allowlist; the floor backend has its own resolver-injected tests."""

    def __init__(
        self,
        allowlist: EgressAllowlist,
        *,
        inner: httpx.BaseTransport | None = None,
        sovereign_only: bool = True,
        slug: str = "",
        resolver: Callable[..., object] | None = None,
    ) -> None:
        super().__init__()
        self._allowlist = allowlist
        self._sovereign_only = sovereign_only
        self._slug = slug
        if inner is not None:
            # Caller injected its own (test) transport: no network backend to pin; NAME control only.
            self._inner: httpx.BaseTransport = inner
        else:
            # Production egress path: install the never-liftable floor backend UNDER the real transport so
            # every connect resolves-once / validates-all / dials-only-validated (fail-closed). Reaching the
            # pool's network backend slot is the supported extension point for a pinned/SSRF-safe dialer.
            real = httpx.HTTPTransport()
            try:
                default_backend = real._pool._network_backend  # type: ignore[attr-defined]
                real._pool._network_backend = _FloorPinnedBackend(  # type: ignore[attr-defined]
                    slug=slug, resolver=resolver, inner=default_backend)
            except AttributeError as exc:  # fail-closed: never ship a transport without the floor
                raise SovereigntyViolation(
                    "cannot install the never-liftable egress floor on the httpx transport "
                    f"(fail-closed): {type(exc).__name__}: {exc}") from exc
            self._inner = real

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        # Protected-domain categorical floor (gov/mil/edu/IGO). This runs UNCONDITIONALLY — above the
        # permissive/sovereign passthrough below — so a request to a protected host raises even in
        # permissive mode. Fed the RAW request URL (not request.url.host) so the client-independent host
        # analysis applies. Gated only by the owner toggle (default ON); when OFF this pre-filter is
        # skipped and the sovereign allowlist below remains the sole egress control (scope not relaxed).
        if protected_guard_enabled():
            assert_not_hard_blocked(str(request.url))
        # NAME allowlist (unchanged semantics). In permissive mode the guard logs but does not refuse —
        # the operator may want development workflows that hit external docs / package mirrors — UNLESS
        # sovereign_only is False (always enforce). In sovereign mode it always refuses. The never-liftable
        # L3/L4 ADDRESS floor runs underneath, in the pinned network backend, in BOTH modes.
        if not (self._sovereign_only and not sovereignty.current().strict):
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
