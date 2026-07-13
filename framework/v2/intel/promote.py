"""intel.promote — the asset→endpoint promotion projector (the DISCOVERER keystone).

CRUCIBLE proves what it is pointed at. Its recon subsystem ROAMS (crt.sh / DoH / RDAP / RIPEstat
collectors, VOI ``ReconPlanner``, gated ``AssetPredictor``) and projects DOMAIN / HOST / SERVICE
facts onto the shared world-model, but those facts never reach the test loop: the autonomous OODA
loop's probe-leaves are seeded ONLY from ``NodeKind.ENDPOINT`` nodes carrying an http(s) ``url`` attr
(:func:`engage_autonomous._endpoint_probe_targets`), and NO minting site writes such a url-bearing
ENDPOINT on the real ``engage.run_engagement`` path. So a recon-discovered in-scope subdomain sits in
the world-model, testable in principle, but invisible to the loop.

This projector is the single missing edge. Given the shared world-model and the engagement slug, it
promotes each **in-scope** recon/sensor asset (a DOMAIN or HOST → its https root; a web-ish SERVICE →
its ``scheme://host[:port]/`` root) into a url-bearing ``endpoint:promoted:<url>`` ENDPOINT node that
:func:`_endpoint_probe_targets` then reads — turning the already-built OODA plumbing, gate discipline,
and deterministic fold into a live recon→test feed.

THREE invariants this holds:
  1. **In-scope BY CONSTRUCTION.** A host is promoted only when it matches the SIGNED charter scope
     via the EXACT predicate the live per-request gate uses (:func:`common.ethics.host_matches_scope`
     over :func:`common.ethics.parse_scope`) — so a promoted host is in-scope by the same definition
     that will re-authorize its probe. This narrowing is DEFENSE-IN-DEPTH, not the authority: every
     probe on a promoted endpoint is STILL re-gated fail-closed at ``agents.tools.invoker._gate``
     (kill-switch → entitlement → charter-scope → destructive → egress). An out-of-scope node that
     somehow slipped in would be refused there anyway.
  2. **A LEAD, never a fact.** Promotion writes a candidate ENDPOINT with an ``intel:promote:``
     provenance (GROUNDING_INTEL) — the oracle seam remains the SOLE fact authority; nothing here
     self-certifies. The endpoint is a place to LOOK, not a finding.
  3. **Deterministic + off the gate path.** Pure over ``(world nodes, parse_scope(slug))`` — id-sorted
     iteration, url-deduped, ``add_node`` upsert (idempotent), ``seq`` from the world's own monotonic
     clock (no wallclock / rng). The caller invokes it ONLY on the opt-in discover path, so it is
     structurally unreachable from ``benchmark --gate`` and the authoritative report stays
     byte-identical when discovery is off. Best-effort: any trouble → ``[]`` (never raises).
"""

from __future__ import annotations

import ipaddress
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..worldmodel.graph import WorldModel

# Web-ish SERVICE signals. A SERVICE node is promotable when its service name or port says "web".
_WEB_SCHEME_TOKENS = ("https", "http")   # substring test, https checked first (so "https" != "http")
_WEB_PORTS_HTTPS = frozenset({443, 8443, 4443, 9443})
_WEB_PORTS_HTTP = frozenset({80, 8080, 8000, 8008, 8888, 3000, 5000, 8081})
_WEB_PORTS = _WEB_PORTS_HTTPS | _WEB_PORTS_HTTP


def _key_of(node_id: str) -> str:
    """The canonical key of a ``{kind}:{key}`` node id — IPv6-safe (split once). ``host:fe80::1`` →
    ``fe80::1``; ``domain:api.example.com`` → ``api.example.com``."""
    return node_id.split(":", 1)[1] if ":" in node_id else node_id


def _bracket_host(host: str) -> str:
    """Bracket a bare IPv6 literal for a URL authority; every hostname / IPv4 is returned unchanged."""
    try:
        if ipaddress.ip_address(host).version == 6:
            return f"[{host}]"
    except ValueError:
        pass
    return host


def _url_for(host: str, scheme: str, port: int | None) -> str | None:
    """Build a root URL ``scheme://host[:port]/`` (IPv6 bracketed), omitting the default port for the
    scheme. Returns None for an empty host."""
    h = (host or "").strip().rstrip(".").lower()
    if not h:
        return None
    authority = _bracket_host(h)
    default = 443 if scheme == "https" else 80
    if port is not None and port != default:
        authority = f"{authority}:{port}"
    return f"{scheme}://{authority}/"


def _service_scheme_port(attrs: dict) -> tuple[str, int | None] | None:
    """(scheme, port) for a web-ish SERVICE from its attrs, or None when the service is not web.

    Web is decided by the service NAME first (``https``/``http`` substring), else the PORT membership.
    Scheme: an https-named or https-port service → ``https``; otherwise ``http``."""
    name = str(attrs.get("service") or "").strip().lower()
    port = attrs.get("port")
    try:
        port = int(port) if port is not None else None
    except (TypeError, ValueError):
        port = None

    is_https_name = "https" in name or "ssl" in name
    is_http_name = "http" in name  # note: "https" also contains "http"; is_https_name is checked first
    if is_https_name:
        return ("https", port)
    if is_http_name:
        return ("http", port)
    if port in _WEB_PORTS_HTTPS:
        return ("https", port)
    if port in _WEB_PORTS_HTTP:
        return ("http", port)
    return None


def _service_host(world: "WorldModel", svc_id: str, svc_key: str) -> str | None:
    """A SERVICE node's host: the src key of an incoming HOSTS edge (a HOST/NETBLOCK → SERVICE) when
    present (robust, avoids parsing an IPv6 service key), else the host portion of the service key
    ``{hostkey}:{port}/{proto}`` (strip the trailing ``:port/proto``). Deterministic."""
    try:
        from ..worldmodel.models import EdgeKind, NodeKind
        for e in world.neighbors(svc_id, [EdgeKind.HOSTS], incoming=True):
            src = world.get_node(e.src)
            # only a single HOST is a dialable authority — a NETBLOCK is a CIDR, never a URL host.
            if src is not None and src.kind is NodeKind.HOST:
                return _key_of(e.src)
    except Exception:
        pass
    # fallback: the service key is "{hostkey}:{port}/{proto}"; drop the last ":port/proto" segment.
    base = svc_key.rsplit(":", 1)[0] if ":" in svc_key else svc_key
    return base or None


def promote_to_endpoints(world: "WorldModel | None", slug: str, *, seq: int | None = None) -> list[tuple[str, str]]:
    """Promote every IN-SCOPE recon/sensor asset in ``world`` to a url-bearing candidate ENDPOINT node
    and return the ``(node_id, url)`` pairs minted/refreshed (id-sorted, url-deduped).

    Promotes: a **DOMAIN** or **HOST** (its key IS the host) → an ``https://<host>/`` root; a web-ish
    **SERVICE** (:func:`_service_scheme_port`) → its ``scheme://host[:port]/`` root. A host is promoted
    ONLY when :func:`common.ethics.host_matches_scope` accepts it against the charter (invariant 1).
    Each minted node is ``Node(id="endpoint:promoted:<url>", kind=ENDPOINT, attrs={"url","host",
    "promoted_from"}, provenance="intel:promote:<src>")`` — a LEAD (invariant 2), upserted idempotently
    (invariant 3). Best-effort: no charter / no scope / any error → ``[]`` (never raises)."""
    if world is None:
        return []
    try:
        from ..common.ethics import CharterMissing, extract_hostname, host_matches_scope, parse_scope
        from ..worldmodel.models import Node, NodeKind
    except Exception:
        return []
    try:
        scope = parse_scope(slug)
    except CharterMissing:
        return []
    except Exception:
        return []
    if not scope:
        return []

    # deterministic seq from the world's own monotonic clock (no wallclock / rng)
    if seq is None:
        try:
            seq = max((n.last_seen for n in world.all_nodes()), default=0) + 1
        except Exception:
            seq = 0

    # collect (src_node_id, host, url) candidates deterministically (id-sorted per kind)
    candidates: list[tuple[str, str, str]] = []

    def _consider(src_id: str, host: str, scheme: str, port: int | None) -> None:
        h = (host or "").strip().rstrip(".").lower()
        if not h or not host_matches_scope(h, scope):
            return
        url = _url_for(h, scheme, port)
        if url is None:
            return
        # ROUND-TRIP the built url through the SAME authority parser the live gate uses
        # (``extract_hostname`` / urlparse). ``host_matches_scope`` is pure string suffix/exact
        # matching, so a node key that string-matches scope but carries a URL-authority delimiter
        # (``#``/``/``/``?``/``@``/a stray ``:``) or a CIDR ``/nn`` would embed verbatim as the
        # authority yet PARSE to a DIFFERENT host — e.g. ``evil.com#.example.com`` matches
        # ``*.example.com`` but dials ``evil.com``; ``10.0.0.0/24`` dials ``10.0.0.0``. Requiring the
        # PARSED authority to equal the gated host (and to re-pass scope) makes promotion in-scope BY
        # CONSTRUCTION — the same authority the per-request gate will re-authorize — and keeps a bare
        # hostname / IPv4 / bracketed-IPv6 (which round-trip to themselves) promotable.
        authority = extract_hostname(url)
        if authority is None:
            return
        authority = authority.strip().rstrip(".").lower()
        if authority != h or not host_matches_scope(authority, scope):
            return
        candidates.append((src_id, authority, url))

    try:
        for n in world.nodes_of_kind(NodeKind.DOMAIN):
            _consider(n.id, _key_of(n.id), "https", None)
        for n in world.nodes_of_kind(NodeKind.HOST):
            _consider(n.id, _key_of(n.id), "https", None)
        for n in world.nodes_of_kind(NodeKind.SERVICE):
            sp = _service_scheme_port(n.attrs if isinstance(n.attrs, dict) else {})
            if sp is None:
                continue
            scheme, port = sp
            host = _service_host(world, n.id, _key_of(n.id))
            if host:
                _consider(n.id, host, scheme, port)
    except Exception:
        return []

    minted: list[tuple[str, str]] = []
    seen_urls: set[str] = set()
    for src_id, host, url in candidates:
        if url in seen_urls:
            continue
        seen_urls.add(url)
        node_id = f"endpoint:promoted:{url}"
        try:
            world.add_node(Node(
                id=node_id, kind=NodeKind.ENDPOINT,
                attrs={"url": url, "host": host, "promoted_from": src_id},
                provenance=f"intel:promote:{src_id}", confidence=0.5,
                first_seen=seq, last_seen=seq))
            minted.append((node_id, url))
        except Exception:
            continue
    return minted
