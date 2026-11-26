"""
aegis.gateway — the AEGIS Gateway: an inline reverse-proxy "provable firewall".

The gateway sits IN FRONT of the operator's own web app (point DNS / the load-balancer at it). For
each request it inspects the input with the deterministic ``verify/`` oracles and — ONLY under
``enforce`` mode AND only on a CONFIRMED verdict (a fired oracle + a re-runnable certificate,
doctrine D1) — returns 403 without forwarding. Otherwise it forwards to the configured upstream and
relays the response (response-side inspection lands in G4).

Doctrine (non-negotiable, enforced here and tested):
  * DEFENSIVE ONLY. Protects the operator's OWN app; never attacks anyone; not anti-defender.
  * PROVE-DON'T-GUESS. A block rides ONLY on ``verdict.decision == "confirmed"`` + a ``CertRef`` the
    operator/auditor can re-run offline. Nothing below a fired oracle is ever blocked.
  * FAIL-OPEN. Any inspection error, an unproven verdict, or ``observe`` mode lets traffic pass. The
    firewall never takes the app down. (An upstream that is itself down yields an honest 502 — the
    gateway cannot fabricate a response, but it never *blocks* on its own error.)
  * NO FORWARD-SSRF. The upstream host is operator-configured and fixed; only the request's
    path+query is appended, never a caller-supplied scheme/host.

The enforce ENTITLEMENT gate (``aegis.respond``), the kill-switch pass-through, and audit events are
layered on in G2; this module is the serving + forwarding + request-side-inspect core, defaulting to
read-only ``observe``.
"""

from __future__ import annotations

import errno
import itertools
import socket
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING, Any, Callable
from urllib.parse import urlsplit

if TYPE_CHECKING:
    from pathlib import Path

    from .authority_v2_check import (
        AuthorityEvent,
        AuthorityV2Decision,
        AuthorityV2Paths,
        MonotoneEpochFloor,
    )

from ..common.logging import get_logger
from .actor_graph import ActorGraph
from .inspect import inspect_request, inspect_response
from .models import AegisConfig, BeliefRef, Verdict
from .response_policy import feed_and_score, feed_oob_correlation, graduated_action

_log = get_logger("aegis.gateway")

# The errnos that PROVE a slug-keyed control file is genuinely ABSENT (vs present-but-unreadable). Kept
# byte-identical to authority.killswitch.KillSwitch._ABSENT_ERRNOS so the live-mode file and the kill-switch
# agree on what "no file" means: any OTHER read error is an ambiguous glitch that must fail toward NOT
# blocking, never be mistaken for "the operator cleared this control file".
_MODE_ABSENT_ERRNOS = frozenset({errno.ENOENT, errno.ENOTDIR, errno.ENAMETOOLONG})


# /readyz is UNAUTHENTICATED, so an untrusted caller could hammer it. Each check does a live TCP connect
# to the fixed upstream; without a bound that flood would AMPLIFY into a matching flood of upstream
# connects. Debounce it: the result is cached for a short TTL, shared across the ThreadingHTTPServer's
# request threads, so however fast /readyz is polled the gateway opens at most ~1 upstream connect per TTL
# per address. The window is tiny, so readiness still tracks reality for an orchestrator's probe.
_READYZ_TTL = 1.0
_readyz_lock = threading.Lock()
_readyz_cache: dict = {}


def _upstream_listening_debounced(host: str, port: int) -> bool:
    """A short-timeout TCP connect (no bytes sent) to (host, port), behind a short-TTL thread-safe cache,
    so an unauthenticated /readyz flood cannot amplify into a flood of upstream connects. Returns the cached
    result within the TTL, else does one live connect and caches it. Total: any error fails CLOSED."""
    key = (host, int(port))
    now = time.monotonic()
    with _readyz_lock:
        hit = _readyz_cache.get(key)
        if hit is not None and hit[0] > now:
            return hit[1]
    try:
        with socket.create_connection((host, int(port)), timeout=0.5):
            ok = True
    except (OSError, ValueError, OverflowError):
        ok = False
    with _readyz_lock:
        _readyz_cache[key] = (now + _READYZ_TTL, ok)
    return ok

# Hop-by-hop headers (RFC 7230 6.1) — never forwarded end-to-end in either direction.
_HOP_BY_HOP = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade", "host", "content-length",
})

# A11: client-supplied forwarding headers are STRIPPED before forwarding — the gateway is the trust boundary
# and sets its OWN X-Forwarded-For (the real client IP). Retaining a caller-forged forwarding header and
# appending another lets a downstream parser that disagrees pick the forged value (identity spoofing).
_CLIENT_FWD_HEADERS = frozenset({
    "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto", "x-forwarded-port",
    "x-real-ip", "forwarded",
})

_MAX_REQUEST_BODY = 10 * 1024 * 1024   # hard cap: a larger body is REFUSED (413), never truncated
_MAX_INSPECT_BYTES = 2 * 1024 * 1024    # only the first N bytes of the body are inspected (the whole body is forwarded)
_MAX_RESPONSE_BYTES = 25 * 1024 * 1024  # bounded upstream response we buffer
_FORWARD_TIMEOUT_S = 30.0
_CLIENT_TIMEOUT_S = 60.0                 # per-connection socket read deadline (slowloris bound)


SAAS_ENFORCE_ENV = "VIGIL_AEGIS_SAAS_ENFORCE"

# AS-2c (gateway v2): the default-OFF switch that selects the V2 authority data plane (dual-accept, the monotone
# epoch floor, signed V2 revocations, the lease⇒pass-through rule R16, the ≤1 s verify cache, release_valid, and
# 421 on a foreign Host). OFF ⇒ the gateway behaves BYTE-IDENTICALLY to the legacy / v1 SaaS path (the new code is
# inert). Strict, fail-closed: only an explicit affirmative token turns it on. ENFORCEMENT under V2 still
# additionally requires the production flag above AND a release — the V2 flag only selects the authority model.
GATEWAY_V2_ENV = "VIGIL_AEGIS_GATEWAY_V2"

# Override for the per-instance V2 publish root (the dir tree the sovereign reconciler publishes signed V2 grants /
# releases / epoch statements / revocations / fail-safe signals into); unset ⇒ a sibling of the v1 publish dir.
V2_PUBLISH_DIR_ENV = "VIGIL_AEGIS_V2_PUBLISH_DIR"


def _saas_enforce_flag() -> bool:
    """AEGIS-SaaS AE-3 production enforcement flag — strict, fail-closed, DEFAULT OFF. Only an explicit
    affirmative token turns it on; anything else (unset, typo) keeps SaaS enforcement off."""
    import os
    return (os.environ.get(SAAS_ENFORCE_ENV) or "").strip().lower() in ("1", "true", "yes", "on")


def _gateway_v2_flag() -> bool:
    """AS-2c V2 data-plane switch — strict, fail-closed, DEFAULT OFF (read per request so a deployment can be
    flipped without a restart, exactly like the enforce flag). OFF ⇒ the V2 path is never taken."""
    import os
    return (os.environ.get(GATEWAY_V2_ENV) or "").strip().lower() in ("1", "true", "yes", "on")


def load_owner_roots() -> "list":
    """The owner-root OVERLAP SET for V2 DUAL-ACCEPT. Today: the single pinned authority root; during an
    authority-root rotation the reconciler (6a/2h) extends this with the incoming/retiring root so a grant /
    revocation / epoch statement that verifies under EITHER root is accepted across the rotation seam, and no
    in-flight request is refused. Fail-CLOSED: an unreadable/absent root yields an EMPTY set ⇒ no authority."""
    try:
        from ..authority import store as _store
        root = _store.load_authority_root()
    except Exception:
        return []
    return [root] if root is not None else []


def load_release_roots() -> "list":
    """The release-root overlap set for ``release_valid`` (AS-29). The release root is the SEPARATE wall an
    owner-root signature can never satisfy. No release-root store exists yet (AS-29 pending), so absent a
    ``load_release_root`` this returns an EMPTY set ⇒ ``release_valid`` is always False ⇒ enforcement never
    renders and the gate degrades to OBSERVE (the safe default). Fail-closed throughout."""
    try:
        from ..authority import store as _store
        loader = getattr(_store, "load_release_root", None)
        if loader is None:
            return []
        root = loader()
    except Exception:
        return []
    return [root] if root is not None else []


def _v2_publish_root() -> "Path":
    """The V2 publish root (a :class:`pathlib.Path`). ``VIGIL_AEGIS_V2_PUBLISH_DIR`` wins; else a sibling
    ``authority_v2`` dir next to the v1 monitoring-authority publish dir, so the whole V2 tree stays inside the
    AEGIS seam the backup layer excludes wholesale."""
    import os
    from pathlib import Path
    override = (os.environ.get(V2_PUBLISH_DIR_ENV) or "").strip()
    if override:
        return Path(override)
    from .monitoring_authority_check import published_dir
    return published_dir().parent / "authority_v2"


class GatewaySettings:
    """Per-gateway runtime state, stored on the server instance (like ``api.server``'s handler
    state). ``on_verdict`` is an optional sink the operator wires for logging/metrics — the gateway
    calls it for EVERY non-None verdict (confirmed or observed), never blocking on it.

    Enforcement is doubly gated (defence in depth, both fail-safe toward *not blocking*):
      * ENTITLEMENT (once, at construction): active blocking needs the ``AEGIS_RESPOND`` capability.
        A GOVERNED deployment that has not granted it is DOWNGRADED to observe (fail-closed to safe);
        an ungoverned deployment permits it (flagged), like every non-baseline capability.
      * KILL-SWITCH (per request): a tripped kill-switch for ``slug`` drops enforcement to
        pass-through, so a misbehaving firewall can be neutralised instantly WITHOUT taking the app
        down (availability-first)."""

    def __init__(self, upstream: str, config: AegisConfig, *, slug: str = "aegis-gateway",
                 on_verdict: Callable[[Verdict], None] | None = None,
                 saas_tenant: str | None = None, saas_host: str | None = None,
                 instance_id: str = "gw", replica_index: int = 0, saas_v2_dir: "str | None" = None,
                 now_fn: "Callable[[], datetime] | None" = None,
                 monotonic_fn: "Callable[[], float] | None" = None,
                 on_authority_event: "Callable[[Any], None] | None" = None) -> None:
        u = urlsplit(upstream)
        if u.scheme not in ("http", "https") or not u.netloc:
            raise ValueError(f"upstream must be an http(s) URL with a host, got {upstream!r}")
        self.upstream_scheme = u.scheme
        self.upstream_netloc = u.netloc
        self.upstream_base = f"{u.scheme}://{u.netloc}"
        self.config = config
        self.slug = slug or "aegis-gateway"
        self.on_verdict = on_verdict
        # AEGIS-SaaS AE-3: when set, this gateway serves ONE customer tenant and every request is re-authorized
        # against that tenant's owner-signed monitoring authority (AE-2). None = the legacy self-hosted gateway,
        # whose behaviour is byte-identical to before.
        self.saas_tenant = saas_tenant or None
        # The PROTECTED host this tenant gateway is deployed for — the exact host the owner-signed grant names.
        # FIXED per gateway: authorization never reads the client-controlled Host header (which the gateway does
        # not route on — every request goes to the one configured upstream). Required whenever saas_tenant is set.
        self.saas_host = None
        if self.saas_tenant is not None:
            from .monitoring_authority_check import normalize_host
            h = normalize_host(saas_host or "")
            if h is None:
                raise ValueError("a SaaS (tenant-bound) gateway requires a valid saas_host: the protected host its "
                                 "monitoring authority names")
            self.saas_host = h
        # AS-2c (gateway v2) — the V2 data-plane state. Built once for a tenant-bound gateway (cheap + inert); it
        # is only USED when the per-request GATEWAY_V2 flag is on (``gateway_v2``), so a flag-OFF gateway behaves
        # byte-identically. The clocks are INJECTED for determinism (a fake clock in tests; the real monotonic /
        # UTC-now in production) — the verify cache must never key on a wallclock, and no signature path reads one.
        self.instance_id = instance_id
        self.replica_index = int(replica_index)
        self._v2_now = now_fn or (lambda: datetime.now(timezone.utc))
        self._v2_monotonic = monotonic_fn or time.monotonic
        self.on_authority_event = on_authority_event
        self._v2_subject = None
        self._v2_paths = None
        self._v2_cache = None
        self._v2_floor = None
        if self.saas_tenant is not None:
            try:
                from pathlib import Path

                from vigil_core.authority_v2 import AuthoritySubject, SubjectKind

                from .authority_v2_check import AuthorityV2Cache, AuthorityV2Paths, MonotoneEpochFloor
                base = Path(saas_v2_dir) if saas_v2_dir is not None else _v2_publish_root()
                self._v2_subject = AuthoritySubject(kind=SubjectKind.HOST, org_id=self.saas_tenant,
                                                    host=self.saas_host or "")
                # Per-subject isolation: each tenant-host subject gets its own subdir, so the fixed per-subject
                # document names (release / epoch / revocation) cannot collide across subjects sharing one root.
                from .authority_v2_check import _subject_dir_name
                self._v2_paths = AuthorityV2Paths(base=base / _subject_dir_name(self._v2_subject),
                                                  subject=self._v2_subject, instance_id=self.instance_id,
                                                  replica_index=self.replica_index)
                self._v2_floor = MonotoneEpochFloor()
                self._v2_cache = AuthorityV2Cache(self._v2_resolve_uncached, monotonic=self._v2_monotonic)
            except Exception:
                # The (tenant, host) is not a valid V2 subject (stricter V2 validators), or the V2 module is
                # unavailable: V2 is simply unavailable for this gateway. ``gateway_v2`` stays False ⇒ the flag,
                # even if set, degrades to the v1 path (never a crash, never a silent enforce).
                self._v2_subject = None
                self._v2_cache = None
        self._enforce_authorized = self._authorize_enforce()
        # G5 — the inline per-actor Beta belief graph + a monotonic sequence for its observations, and
        # a lock (the server is threaded, so belief updates must be serialised). ``actor_last_class``
        # remembers each tracked actor's most recent affirming class to label a graduated response.
        self.actor_graph = ActorGraph()
        self._belief_seq = itertools.count(1)
        self._belief_lock = threading.Lock()
        self.actor_last_class: dict[str, str] = {}
        # OPT-IN passive OOB belief elevation (default OFF). Started ONLY when the operator configured a
        # canary URL AND the AEGIS_RESPOND entitlement is available (like the rest of the response
        # layer). The receiver is the OFFENSE-FREE loopback-only primitive in ``common.oob_receiver``
        # (AS-28: NOT the deny-listed ``verify.oob``), so the defense serve path pulls no offense code to
        # run this; it binds LOOPBACK ONLY. Any error → the feature stays dormant (fail-open); the gateway
        # proxies exactly as before.
        self.oob_correlator = None   # type: ignore[var-annotated]
        self.oob_receiver = None     # type: ignore[var-annotated]
        if config.oob_canary and self._authorize_oob():
            try:
                from ..common.oob_receiver import OOBReceiver
                from .oob_correlator import OOBCorrelator
                self.oob_correlator = OOBCorrelator(config.oob_canary)
                self.oob_receiver = OOBReceiver().start()   # loopback-only, ephemeral port
                _log.info("aegis.gateway.oob_enabled", slug=self.slug,
                          canary_host=self.oob_correlator.canary_host)
            except Exception:
                self.oob_correlator = None
                self.oob_receiver = None
                _log.warning("aegis.gateway.oob_disabled", slug=self.slug, reason="start failed")

    def _authorize_oob(self) -> bool:
        """Entitlement check for the OOB belief-elevation feature — the SAME AEGIS_RESPOND gate the
        response layer uses (a governed deployment without the grant leaves it dormant). Total: any
        entitlement-subsystem error fails CLOSED (feature off)."""
        try:
            from ..entitlement import Capability
            from ..entitlement.policy import is_capability_available
            return bool(is_capability_available(Capability.AEGIS_RESPOND))
        except Exception:
            return False

    def stop_oob(self) -> None:
        """Clean shutdown of the loopback OOB receiver (idempotent, total). The gateway's CLI/callers
        invoke this in their teardown; the receiver thread is a daemon regardless, so a missed stop
        never hangs the process."""
        r = self.oob_receiver
        self.oob_receiver = None
        if r is not None:
            try:
                r.stop()
            except Exception:
                pass

    def _authorize_enforce(self) -> bool:
        """AEGIS_RESPOND entitlement check, independent of the CURRENT mode so a LIVE observe->enforce
        switch can take effect (the `enforce` property still requires the effective mode to be enforce;
        this term is purely 'is blocking entitled at all?'). A denied grant downgrades enforcement to
        observe. Total: any entitlement-subsystem error fails CLOSED (no enforcement)."""
        try:
            from ..entitlement import Capability
            from ..entitlement.policy import is_capability_available
            ok = bool(is_capability_available(Capability.AEGIS_RESPOND))
        except Exception:
            ok = False
        if not ok:
            _log.warning("aegis.gateway.enforce_downgraded_to_observe",
                         slug=self.slug, reason="AEGIS_RESPOND entitlement not available")
        return ok

    def _killswitch_tripped(self) -> bool:
        """Is the break-glass hard-stop engaged for this slug? A tripped kill-switch drops enforcement to
        pass-through, so this term must fail toward NOT blocking. ``KillSwitch.is_tripped`` is itself
        fail-closed (an ambiguous stat ⇒ TRIPPED); mirror that here for the one case it cannot cover — the
        kill-switch SUBSYSTEM being unreadable (an import / path-construction error). An unreadable
        kill-switch reads as TRIPPED, never CLEAR: the operator trips it precisely to stop the gateway
        blocking, so if we cannot read it we must assume it is set. Returning False here would instead let
        ``enforce`` keep blocking on an unreadable kill-switch — the exact fail-OPEN the break-glass
        mechanism exists to prevent (AS-27a)."""
        try:
            from ..authority.killswitch import KillSwitch
            return bool(KillSwitch(self.slug).is_tripped())
        except Exception:
            return True   # subsystem unreadable ⇒ assume tripped ⇒ pass-through (availability-first break-glass)

    def _mode_override(self) -> str | None:
        """LIVE mode override, re-read per request from a control file the console writes — the exact
        cross-process, restart-free pattern the kill-switch uses.

        Returns 'observe'/'enforce' when the file is read cleanly and holds a valid value; None when the
        override is genuinely ABSENT (or present-but-invalid), so the caller falls back to the configured
        startup --mode. The last cleanly-observed VALID override is remembered in ``_last_good_mode``.

        AS-27a break-glass (availability-first): a file that is PRESENT but unreadable — a permission / IO
        glitch, a decode error, or the mode subsystem itself failing — must never let a control-plane glitch
        silently ESCALATE to enforce. On such a glitch, hold the last cleanly-observed override, and if none,
        OBSERVE — never the startup --mode, which may itself be enforce.

        'Absent' vs 'glitch' is decided by errno, mirroring ``KillSwitch._ABSENT_ERRNOS`` so the mode file and
        the kill-switch agree on what 'no file' means: only an errno that PROVES the file cannot be there
        counts as absent. CRUCIALLY, whenever the live override is observed to be GONE (absent) or no longer a
        valid value (invalid content), ``_last_good_mode`` is CLEARED — otherwise a long-lived gateway keeps a
        stale 'enforce' after the operator has cleared the override and a later read glitch would resurrect it,
        silently resuming blocking against current intent (the exact availability-first violation AS-27a
        closes)."""
        try:
            from ..common.paths import aegis_mode_path
            path = aegis_mode_path(self.slug)
        except Exception:
            # the mode subsystem itself is unavailable (import / path construction): a glitch, not a reliable
            # 'no override' signal -> hold the last cleanly-observed override, else observe.
            return getattr(self, "_last_good_mode", None) or "observe"
        try:
            raw = path.read_text(encoding="utf-8").strip()
        except OSError as e:
            if e.errno in _MODE_ABSENT_ERRNOS:
                self._last_good_mode = None        # the override is genuinely gone -> forget it, never resurrect
                return None                        # -> the configured startup --mode (the normal no-override path)
            # present-but-unreadable (permission, IsADirectory, I/O, ...): a glitch -> never escalate to enforce.
            return getattr(self, "_last_good_mode", None) or "observe"
        except Exception:
            # a non-OSError read failure (e.g. a decode error on a corrupt file): present but unreadable -> glitch.
            return getattr(self, "_last_good_mode", None) or "observe"
        if raw in ("observe", "enforce"):
            self._last_good_mode = raw             # remember the last cleanly-read valid override
            return raw
        self._last_good_mode = None                # present but INVALID -> no valid live override to hold
        return None                                # -> the configured startup --mode

    def intended_mode(self) -> str:
        """The mode the operator has asked for: the live console-set override if present, else the
        startup --mode. (Whether it is actually ENFORCING is the `enforce` property.)"""
        return self._mode_override() or self.config.mode

    @property
    def enforce(self) -> bool:
        """Block ONLY when the EFFECTIVE mode is enforce AND entitled AND the kill-switch is not
        tripped. The effective mode is re-read per request (live observe<->enforce switch), exactly
        like the kill-switch. Every term fails toward NOT blocking (availability-first)."""
        return (self.intended_mode() == "enforce"
                and self._enforce_authorized
                and not self._killswitch_tripped())

    def saas_decision(self):
        """AE-3 per-request re-authorization. None when this is not a SaaS gateway; otherwise the AE-2
        ``MonitoringDecision`` for (saas_tenant, the gateway's FIXED protected saas_host). Deliberately takes no
        request input: the Host header is client-controlled and is not what the gateway forwards to, so keying
        authorization on it would let any client switch inspection off (or borrow another host's grant).
        Total: any failure is a refusal."""
        if self.saas_tenant is None:
            return None
        try:
            from .monitoring_authority_check import check_monitoring_authority
            return check_monitoring_authority(self.saas_tenant, self.saas_host or "")
        except Exception:
            from .monitoring_authority_check import MonitoringDecision
            return MonitoringDecision(ok=False, mode=None, reason="monitoring-authority check unavailable")

    def effective_enforce(self, decision) -> bool:
        """The per-request enforce term. Legacy gateway: exactly ``self.enforce``. SaaS gateway: blocking is
        NECESSARY-NOT-SUFFICIENT on the grant — it additionally needs a VERIFIED BLOCK-mode authority for this
        request AND the default-OFF production flag. OBSERVE never enforces; a refused authority never enforces."""
        if decision is None:
            return self.enforce
        return bool(decision.ok and decision.mode == "block" and _saas_enforce_flag() and self.enforce)

    # -- AS-2c (gateway v2) data plane -------------------------------------------------------------------

    @property
    def gateway_v2(self) -> bool:
        """Is the V2 authority data plane active for THIS request? Only when the gateway is tenant-bound, the V2
        subject was built successfully, AND the default-OFF per-request GATEWAY_V2 flag is on. Otherwise the v1
        path runs, byte-identically to before."""
        return self._v2_cache is not None and _gateway_v2_flag()

    def _v2_resolve_uncached(self, org_id: str, host: str) -> "AuthorityV2Decision":
        """One full V2 resolve (cache MISS body): reads the owner/release overlap sets + the injected wall-now
        fresh each time, so a rotation or a just-published release is picked up at the next cache refresh. Total:
        the resolver is itself fail-closed and never raises."""
        from .authority_v2_check import resolve_authority_v2
        assert self._v2_paths is not None and self._v2_floor is not None  # only reachable once V2 state is built
        return resolve_authority_v2(org_id, host, paths=self._v2_paths,
                                    owner_roots=load_owner_roots(), release_roots=load_release_roots(),
                                    floor=self._v2_floor, now=self._v2_now(),
                                    on_event=self._emit_authority_event)

    def v2_decision(self) -> "AuthorityV2Decision":
        """The cached (≤1 s) V2 decision for this gateway's fixed (tenant, host) subject. Deliberately takes no
        request input — authorization is keyed on the FIXED saas_host, never the client Host header, so no client
        can switch inspection off or borrow another subject's grant (the Host header only drives the 421
        misdirected-request check, which is a routing signal, not authorization)."""
        assert self._v2_cache is not None  # only reachable when gateway_v2 is True (⇒ the cache exists)
        return self._v2_cache.get(self.saas_tenant or "", self.saas_host or "")

    def effective_enforce_v2(self, v2: "AuthorityV2Decision") -> bool:
        """The per-request V2 enforce term. Blocking renders ONLY when the composed V2 decision is ENFORCE (the
        grant carries the enforcing capability AND a release-root release covers it and is live and at/above the
        floor — ``release_valid``) AND the default-OFF production flag is on AND the gateway's own enforce gate
        (enforce mode + entitlement + untripped kill-switch) holds. Every term fails toward NOT blocking."""
        return bool(v2.enforce and v2.release_valid and _saas_enforce_flag() and self.enforce)

    def _emit_authority_event(self, event: "AuthorityEvent") -> None:
        """Forward a de-duplicated authority-lifecycle event to the operator's optional sink, and audit it. Total
        (never breaks the request path)."""
        try:
            _log.info("aegis.gateway.authority_event", slug=self.slug, kind=getattr(event, "kind", ""),
                      host=getattr(event, "host", ""), epoch=getattr(event, "epoch", 0),
                      outcome=getattr(event, "outcome", ""))
        except Exception:
            pass
        if self.on_authority_event is not None:
            try:
                self.on_authority_event(event)
            except Exception:
                pass

    def enforcement_status(self) -> dict[str, object]:
        """A machine-readable, HONEST snapshot of the enforce gate — the structural guarantee that a
        downgrade is NEVER silent. A consumer (the CLI banner, the live status file the loopback console
        renders, an investor-eval readiness probe) reads this to learn not just the effective mode but,
        when enforce was REQUESTED yet is not active, exactly WHY.

        ``downgraded`` is True iff the operator asked to enforce but the gateway is only observing; when so,
        ``downgrade_reason`` names the fail-safe term(s) that kept it read-only — the AEGIS_RESPOND
        entitlement being unprovisioned in a governed deployment, and/or a tripped kill-switch. It is never
        an empty/None reason while downgraded (that would be the silent downgrade this method exists to
        forbid). Every term is read exactly as the ``enforce`` property reads it, so the status cannot
        disagree with the actual gate."""
        requested = self.intended_mode()
        entitled = bool(self._enforce_authorized)
        ks_tripped = bool(self._killswitch_tripped())
        enforcing = (requested == "enforce" and entitled and not ks_tripped)
        downgraded = (requested == "enforce" and not enforcing)
        reasons: list[str] = []
        if downgraded:
            if not entitled:
                reasons.append("AEGIS_RESPOND entitlement not provisioned in this governed deployment")
            if ks_tripped:
                reasons.append("kill-switch tripped")
            if not reasons:  # defence in depth: downgraded must ALWAYS carry a reason, never be silent
                reasons.append("enforcement inactive for an unclassified reason")
        return {
            "requested_mode": requested,
            "effective_mode": "enforce" if enforcing else "observe",
            "enforcing": enforcing,
            "entitled": entitled,
            "kill_switch_tripped": ks_tripped,
            "downgraded": downgraded,
            "downgrade_reason": "; ".join(reasons) if reasons else None,
        }


class AegisGatewayHandler(BaseHTTPRequestHandler):
    """One request: inspect -> (block under enforce+confirmed) -> forward -> relay. Total and
    fail-open; a handler error yields a best-effort pass-through, never a spurious block."""

    server_version = "AegisGateway/1.0"
    protocol_version = "HTTP/1.1"
    timeout = _CLIENT_TIMEOUT_S   # bound a slow/stalled client so it cannot hold a thread forever

    def log_message(self, *_args: Any) -> None:   # quiet by default; use on_verdict for telemetry
        return

    # every method funnels through _handle
    def do_GET(self) -> None: self._handle()
    def do_POST(self) -> None: self._handle()
    def do_PUT(self) -> None: self._handle()
    def do_DELETE(self) -> None: self._handle()
    def do_PATCH(self) -> None: self._handle()
    def do_HEAD(self) -> None: self._handle()
    def do_OPTIONS(self) -> None: self._handle()

    # -- helpers ----------------------------------------------------------

    @property
    def settings(self) -> GatewaySettings:
        return self.server.settings   # type: ignore[attr-defined]

    def _framing_unsupported(self) -> bool:
        """This stdlib handler cannot safely buffer+forward a body it does not delimit by a valid
        Content-Length: a chunked (Transfer-Encoding) body, or a malformed Content-Length. Such a
        request is REFUSED (411 + close) rather than read-as-empty (which would drop the body and
        desync the keep-alive stream). Returns True when the framing is unsupported."""
        if self.headers.get("Transfer-Encoding"):
            return True
        cl = self.headers.get("Content-Length")
        if cl is not None:
            try:
                int(cl)
            except ValueError:
                return True
        return False

    def _read_body(self) -> tuple[bytes, bool]:
        """Read the FULL request body (for forwarding intact). Returns ``(body, too_large)``. Callers
        must first check ``_framing_unsupported``; here Content-Length is known valid. A body over the
        hard cap is NOT read (``too_large=True``) so the caller sends 413 + closes — never a silent
        truncation (which would corrupt the upload and desync the keep-alive stream)."""
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length <= 0:
            return b"", False
        if length > _MAX_REQUEST_BODY:
            return b"", True
        try:
            return self.rfile.read(length), False
        except Exception:
            return b"", False

    def _request_headers(self) -> list[tuple[str, str]]:
        return [(k, v) for k, v in self.headers.items()]

    def _emit(self, verdict: Verdict | None) -> None:
        if verdict is not None and self.settings.on_verdict is not None:
            try:
                self.settings.on_verdict(verdict)
            except Exception:
                pass

    # -- G5: graduated challenge/throttle on the per-actor Beta belief -----

    def _actor_key(self) -> str:
        """The actor this request is attributed to — the client IP (stable + correlatable, per the
        doctrine). Total: an unknown peer folds to a shared ``anon`` bucket."""
        return (self.client_address[0] if self.client_address else "") or "anon"

    def _note_belief(self, verdict: Verdict | None) -> BeliefRef | None:
        """Fold this request's verdict into the actor's Beta belief and return it. Called EXACTLY ONCE
        per request (with its strongest verdict). Serialised (the server is threaded); total (a belief
        error must never break the request path)."""
        try:
            key = self._actor_key()
            with self.settings._belief_lock:
                belief = feed_and_score(self.settings.actor_graph, key, verdict,
                                        seq=next(self.settings._belief_seq))
                if verdict is not None and verdict.decision in ("confirmed", "lead"):
                    self.settings.actor_last_class[f"session:{key}"] = verdict.attack_class
            return belief
        except Exception:
            return None

    def _current_belief(self) -> BeliefRef | None:
        """The actor's belief accumulated from PRIOR requests (read-only; does NOT record this
        request). The graduated decision rides on this, so a request is never judged on its own
        contribution — 'sustained' means an established history."""
        try:
            with self.settings._belief_lock:
                return self.settings.actor_graph.belief(f"session:{self._actor_key()}")
        except Exception:
            return None

    # -- passive OOB belief elevation (opt-in; TRANSLATOR not generator) ---

    def _note_oob_lead(self, verdict: Verdict | None, inspect_body: str | None) -> None:
        """If this request tripped an SSRF/XXE LEAD, record a pending OOB observation IFF the
        attacker's OWN payload referenced the operator's canary host. Reads only the client's request
        (self.path + the inspected body); NEVER mutates or plants anything. Total (fail-open)."""
        corr = self.settings.oob_correlator
        if corr is None or verdict is None or verdict.decision != "lead":
            return
        if verdict.attack_class not in ("ssrf", "xxe"):
            return
        try:
            corr.note_lead(self._actor_key(), path=self.path, body=inspect_body,
                           attack_class=verdict.attack_class)
        except Exception:
            pass

    def _note_oob_elevation(self, actor_key: str, attack_class: str) -> None:
        """Fold ONE OOB-correlated elevation into the actor's Beta belief via the EXISTING belief path
        (``feed_oob_correlation``) — a strong AFFIRMING signal, NEVER a certificate, NEVER a block.
        Serialised under the belief lock (the server is threaded); total."""
        try:
            with self.settings._belief_lock:
                feed_oob_correlation(self.settings.actor_graph, actor_key, attack_class,
                                     seq=next(self.settings._belief_seq))
                self.settings.actor_last_class[f"session:{actor_key}"] = attack_class
        except Exception:
            pass

    def _oob_elevation_verdict(self, attack_class: str, referenced_host: str) -> Verdict:
        """A LEAD verdict for the on_verdict telemetry sink describing an OOB correlation — decision
        LEAD, action observe, NO certificate. It is belief-only; it drives no response by itself (the
        elevated belief surfaces on the actor's NEXT request as a graduated challenge/throttle)."""
        return Verdict(decision="lead", attack_class=attack_class, confidence=0.0, certificate=None,
                       provenance="intel:aegis:oob_correlation", action="observe",
                       contributing=[f"oob-canary:{referenced_host}"])

    def _drain_oob_elevations(self) -> None:
        """Poll the loopback OOB receiver for unsolicited canary hits, correlate them to pending
        SSRF/XXE observations, and elevate the tied actors' beliefs. Belief-only; total (any error
        forwards). Called pre-request so a PRIOR inbound hit raises belief the CURRENT/next request's
        graduated decision can act on."""
        s = self.settings
        corr, recv = s.oob_correlator, s.oob_receiver
        if corr is None or recv is None:
            return
        try:
            elevations = corr.poll_elevations(recv)
        except Exception:
            return
        for el in elevations:
            self._note_oob_elevation(el.actor_key, el.attack_class)
            try:
                self._emit(self._oob_elevation_verdict(el.attack_class, el.referenced_host))
            except Exception:
                pass

    def _graduated_verdict(self, action: str, current: Verdict | None) -> Verdict:
        """A lead Verdict carrying the graduated ``action`` (challenge/throttle) — for the on_verdict
        telemetry sink. It is a LEAD (no certificate): belief NEVER mints a certificate. Its
        attack_class names the actor's dominant suspicious class (honest attribution)."""
        cls = current.attack_class if (current is not None and current.decision == "lead") else None
        cls = cls or self.settings.actor_last_class.get(f"session:{self._actor_key()}") or "automated_access"
        return Verdict(decision="lead", attack_class=cls, confidence=0.0, certificate=None,
                       provenance=f"intel:aegis:belief:{action}", action=action, contributing=[])

    def _send_graduated(self, action: str, current: Verdict | None) -> None:
        """Send an availability-first 429 for a belief-driven ``challenge``/``throttle`` — NOT a block
        (no certificate, retryable). Emits the graduated verdict for telemetry and audits it."""
        retry_after = 30 if action == "throttle" else 5
        try:
            _log.info("aegis.gateway.graduated", slug=self.settings.slug, action=action,
                      client=self._actor_key(), method=self.command)
        except Exception:
            pass
        self._emit(self._graduated_verdict(action, current))
        body = (
            b'{"aegis":"' + action.encode() + b'","by":"aegis-gateway","reason":"sustained per-actor '
            b'suspicion crossed a belief threshold; this is an availability-first challenge/throttle, '
            b'NOT a proven block (no certificate) - retry after the interval"}'
        )
        self.send_response(429)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Aegis-Action", action)
        self.send_header("Retry-After", str(retry_after))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _send_block(self, verdict: Verdict) -> None:
        """403 with the certificate id — the honest, auditable block. The cert is re-runnable offline
        (``CertRef.reverify``), so the block is provable, not a guess."""
        cid = verdict.certificate.cert_id if verdict.certificate else ""
        # AUDIT — every aegis.respond block is recorded with its re-runnable certificate id, the
        # attack class, and the client, so the operator has a complete, provable enforcement trail.
        try:
            _log.info("aegis.gateway.blocked", slug=self.settings.slug,
                      attack_class=verdict.attack_class, certificate=cid,
                      client=(self.client_address[0] if self.client_address else ""),
                      method=self.command, provenance=verdict.provenance)
        except Exception:
            pass
        body = (
            b'{"blocked":true,"by":"aegis-gateway","attack_class":"' + verdict.attack_class.encode()
            + b'","certificate":"' + cid.encode() + b'","reason":"a deterministic oracle proved this '
            b'request is a structured attack; the certificate re-runs offline"}'
        )
        self.send_response(403)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Aegis-Block", verdict.attack_class)
        self.send_header("X-Aegis-Certificate", cid)
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _forward_url(self, raw_path: str) -> str:
        """Configured-upstream base + ONLY the request's path+query (scheme/host discarded) — closes
        forward-SSRF: a caller cannot redirect the forward to another host. The path is FORCED to
        begin with a single '/', so an origin-form target that does not start with '/' (e.g.
        `@evil.com/x`, which would otherwise splice as userinfo@host and re-home the forward) cannot
        escape the fixed upstream host. urlsplit failures (a malformed IPv6 target) fall back to '/'."""
        try:
            p = urlsplit(raw_path)
            pq = p.path or "/"
            if p.query:
                pq += "?" + p.query
        except Exception:
            pq = "/"
        # collapse any leading '/' or '\' runs to exactly one '/' so neither '@host', '//host', nor
        # '\\host' can be re-parsed as an authority against the upstream base.
        pq = "/" + pq.lstrip("/\\")
        return self.settings.upstream_base + pq

    def _forward(self, method: str, body: bytes) -> tuple[int, list[tuple[str, str]], bytes] | None:
        """Forward to the operator's upstream via httpx and CAPTURE the response ``(status, headers,
        content)``. Returns None on an upstream/transport error (caller sends a 502). Does not write
        to the client — the caller inspects the response, then relays or blocks."""
        try:
            import httpx
        except Exception:
            return None
        url = self._forward_url(self.path)
        # A11: strip client-supplied forwarding headers (the gateway sets its OWN X-Forwarded-For) so a
        # caller cannot inject a forged forwarding chain a downstream parser might trust.
        fwd_headers = [(k, v) for k, v in self._request_headers()
                       if k.lower() not in _HOP_BY_HOP and k.lower() not in _CLIENT_FWD_HEADERS]
        fwd_headers.append(("Host", self.settings.upstream_netloc))
        fwd_headers.append(("X-Forwarded-For", self.client_address[0] if self.client_address else ""))
        try:
            # trust_env=False: the operator-configured upstream is the ONLY transport authority. Without it,
            # httpx honours ambient ALL_PROXY/HTTP(S)_PROXY and SSL_CERT_FILE/SSL_CERT_DIR — so the host
            # environment could divert this forward through a proxy or swap the TLS trust store out from
            # under a security gateway (audit F-01). AEGIS exposes no operator proxy setting, so pinning the
            # environment off removes only the attack surface. (If a validated proxy is ever a feature, it
            # must be an explicit, provenance-bound config value, never inherited from the ambient env.)
            # verify=: an HTTPS upstream whose cert chains to a PRIVATE CA is supported ONLY through the
            # explicit `upstream_ca_bundle` config (not the ambient SSL_CERT_FILE, which trust_env=False now
            # ignores). Unset => True => the system trust store.
            _verify = self.settings.config.upstream_ca_bundle or True
            with httpx.Client(follow_redirects=False, timeout=_FORWARD_TIMEOUT_S, trust_env=False,
                              verify=_verify) as client:
                # A11: STREAM the response and bound PEAK memory (read at most _MAX_RESPONSE_BYTES); an
                # upstream response that EXCEEDS the bound is REFUSED (caller -> 502), never SILENTLY
                # truncated with a rewritten Content-Length (which would corrupt the body and mislead the
                # client into thinking it received a complete response).
                with client.stream(method, url, headers=fwd_headers, content=body or None) as resp:
                    chunks: list[bytes] = []
                    total = 0
                    for chunk in resp.iter_bytes():
                        total += len(chunk)
                        if total > _MAX_RESPONSE_BYTES:
                            return None
                        chunks.append(chunk)
                    return resp.status_code, list(resp.headers.items()), b"".join(chunks)
        except Exception:
            return None

    def _relay(self, status: int, headers: list[tuple[str, str]], content: bytes) -> None:
        """Send a captured upstream response to the client, stripping hop-by-hop headers."""
        self.send_response(status)
        for k, v in headers:
            if k.lower() not in _HOP_BY_HOP:
                self.send_header(k, v)
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(content)

    def _send_bad_gateway(self) -> None:
        body = b'{"error":"bad_gateway","by":"aegis-gateway"}'
        self.send_response(502)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _foreign_host(self) -> bool:
        """AS-2c: True iff the client sent a Host header that, normalized, does NOT match this gateway's FIXED
        protected host. A per-instance V2 gateway is fronted by an ALB that routes by Host to the target group
        for its ``instance_id``; a request whose Host names a different backend has been MISDIRECTED here, so the
        honest answer is 421 (retry on a fresh connection), never a silent forward of another host's traffic.

        A MISSING/empty Host is NOT treated as foreign — LB health probes and HTTP/1.0 clients omit it, and
        authorization is keyed on the fixed saas_host regardless, so a missing Host can switch nothing off. A
        present-but-unparseable Host IS foreign (it is certainly not this host)."""
        raw = (self.headers.get("Host") or "").strip()
        if not raw:
            return False
        from .monitoring_authority_check import normalize_host
        return normalize_host(raw) != self.settings.saas_host

    def _send_misdirected(self) -> None:
        """421 Misdirected Request (RFC 9110 §15.5.20): this gateway cannot serve the requested Host. Close the
        connection so the client re-resolves to the correct origin; the response carries no upstream address."""
        self.close_connection = True
        body = b'{"error":"misdirected_request","by":"aegis-gateway","reason":"this gateway serves a different host"}'
        self.send_response(421)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _send_too_large(self) -> None:
        """413 for a body over the hard cap, and CLOSE the connection — we did not read the body, so
        the residual bytes must not be mis-parsed as the next request (keep-alive desync)."""
        self._refuse_body(413, "payload_too_large")

    def _send_length_required(self) -> None:
        """411 for a body this handler cannot delimit (chunked / bad Content-Length) — CLOSE the
        connection so the un-read body cannot desync the keep-alive stream. A real deployment fronts
        the gateway with a proxy that de-chunks; unbuffered streaming is roadmap."""
        self._refuse_body(411, "length_required")

    def _refuse_body(self, status: int, err: str) -> None:
        self.close_connection = True
        body = ('{"error":"%s","by":"aegis-gateway"}' % err).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    # -- the request lifecycle --------------------------------------------

    def _handle(self) -> None:
        try:
            self._handle_inner()
        except Exception:
            # Total fail-safe: a handler error must not drop the connection with no response (that
            # would be a fail-CLOSED reset). Send an honest 502 instead. Best-effort.
            try:
                self._send_bad_gateway()
            except Exception:
                pass

    def _probe_path(self) -> str:
        """The request path with any query stripped — used only to match the exact probe routes."""
        try:
            return urlsplit(self.path).path
        except Exception:
            return self.path

    def _send_probe(self, status: int, payload: dict) -> None:
        import json as _json
        body = _json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _readyz_upstream_ok(self) -> bool:
        """A LIVE port probe of the operator's fixed upstream (a short-timeout TCP connect, no bytes sent):
        the gateway's whole job is to forward there, so it is NOT ready when the upstream is down. The
        connect is DEBOUNCED (`_upstream_listening_debounced`, `_READYZ_TTL`) so an unauthenticated /readyz
        flood cannot amplify into a flood of upstream connects. Total — any resolution/parse error fails
        CLOSED (not ready)."""
        try:
            u = urlsplit(self.settings.upstream_base)
            host = u.hostname or ""
            port = u.port or (443 if u.scheme == "https" else 80)
        except (ValueError, AttributeError):
            return False
        return _upstream_listening_debounced(host, port)

    def _handle_probe(self) -> bool:
        """Answer the UNAUTHENTICATED liveness/readiness probes LOCALLY (never forwarded), so a k8s/LB
        probe can reach the firewall itself. `/healthz` = liveness; `/readyz` = a live probe of the fixed
        upstream (the gateway's real dependency). Returns True when it handled the request. GET/HEAD only —
        a probe path under any other method falls through to the normal proxy path unchanged. Bodies carry
        no upstream address or secret."""
        if self.command not in ("GET", "HEAD"):
            return False
        path = self._probe_path()
        if path == "/healthz":
            self._send_probe(200, {"ok": True})
            return True
        if path == "/readyz":
            ok = self._readyz_upstream_ok()
            self._send_probe(200 if ok else 503, {"ok": ok, "checks": [{"name": "upstream", "ok": ok}]})
            return True
        return False

    def _handle_inner(self) -> None:
        settings = self.settings
        method = self.command
        # PROBE-SAFE FIRST: liveness/readiness are answered locally, before any body read, inspection, or
        # forward — a k8s/LB probe must reach the firewall without a credential and without shadowing the
        # upstream except on the two exact probe paths (GET/HEAD only).
        if self._handle_probe():
            return
        # (0) OPT-IN passive OOB belief elevation — drain any unsolicited canary hits and fold the
        #     correlated elevations into the tied actors' beliefs BEFORE the graduated decision, so a
        #     prior inbound hit is reflected in this/next request's belief. Belief-only; total; a no-op
        #     when the feature is off. Reads nothing from THIS request — never mutates it.
        self._drain_oob_elevations()
        # AS-2c (gateway v2): 421 on a FOREIGN Host, as EARLY as possible (before buffering a body). A per-instance
        # V2 gateway is fronted by an ALB that routes by Host; a request whose Host names a different backend has
        # been MISDIRECTED here, so the honest answer is 421 (retry on a fresh connection), never inspection or a
        # silent forward of another host's traffic. Inert unless the V2 flag is on (byte-identical v1 otherwise).
        if settings.gateway_v2 and self._foreign_host():
            self._send_misdirected()
            return
        if self._framing_unsupported():
            self._send_length_required()   # chunked/bad-CL: refuse+close, never drop-body+desync
            return
        body, too_large = self._read_body()
        if too_large:
            self._send_too_large()   # honest 413 + close; never a truncated/desynced forward
            return

        if settings.gateway_v2:
            # AS-2c (gateway v2) data plane. Re-authorize THIS request against the tenant's V2 authority
            # (dual-accept + monotone floor + signed revocation + lease R16 + release_valid), via the ≤1 s verify
            # cache. PASS_THROUGH (no grant, lapsed lease, stale/superseded, withdrawn/overridden) ⇒ uninspected
            # pass-through: no verdict, no belief, no block — shown visibly (R16), exactly mirroring the
            # kill-switch / v1 pass-through semantics.
            v2 = settings.v2_decision()
            if v2.pass_through:
                passthrough = self._forward(method, body)
                if passthrough is None:
                    self._send_bad_gateway()
                    return
                self._relay(*passthrough)
                return
            enforce = settings.effective_enforce_v2(v2)
        else:
            # AEGIS-SaaS AE-3 (v1): re-authorize THIS request against the tenant's monitoring authority. No valid
            # authority => AEGIS neither inspects nor acts: a plain pass-through (no verdict, no belief, no block).
            decision = settings.saas_decision()
            if decision is not None and not decision.ok:
                passthrough = self._forward(method, body)
                if passthrough is None:
                    self._send_bad_gateway()
                    return
                self._relay(*passthrough)
                return
            enforce = settings.effective_enforce(decision)

        # Inspect only a bounded prefix (the whole body is still forwarded intact).
        inspect_body = body[:_MAX_INSPECT_BYTES].decode("utf-8", "replace") if body else None

        # (1) REQUEST-SIDE inspection — pure, fail-open. Any error => verdict None => forward.
        verdict: Verdict | None = None
        try:
            verdict = inspect_request(
                method, self.path, self._request_headers(), inspect_body,
                honeypot_paths=settings.config.honeypot_paths,
                enforce=enforce,
            )
        except Exception:
            verdict = None
        self._emit(verdict)

        # (1b) OOB — if this is an SSRF/XXE LEAD whose payload referenced the operator's canary host,
        #      record a pending observation (reads the client's own request; NO injection). A later
        #      inbound hit on that canary will elevate this actor's belief via _drain_oob_elevations.
        self._note_oob_lead(verdict, inspect_body)

        # (2) ENFORCE (request-side) — block ONLY on a confirmed verdict whose action is "block" (D1).
        #     A PROVABLE block always wins over a belief-driven challenge (prove-don't-guess).
        #     Anything else forwards (fail-open). observe mode never sets action="block".
        if self._is_block(verdict):
            self._note_belief(verdict)   # a confirmed attack strongly raises the actor's belief (single feed)
            self._send_block(verdict)  # type: ignore[arg-type]
            return

        # (2b) G5 — a graduated challenge/throttle on SUSTAINED per-actor suspicion, riding on the
        #      belief accumulated from PRIOR requests (this request never counts toward its own
        #      escalation). NEVER a hard block on belief alone (prove-don't-guess) — only under enforce
        #      + entitlement, availability-first (a soft, retryable 429). observe mode never acts. This
        #      request's own verdict is recorded once, below, so challenge can graduate to throttle.
        if enforce:
            action = graduated_action(self._current_belief())
            if action is not None:
                self._note_belief(verdict)   # record this request (single feed) so belief keeps accruing
                self._send_graduated(action, verdict)
                return

        # (3) FORWARD the FULL body to the operator's upstream and CAPTURE the response.
        captured = self._forward(method, body)
        if captured is None:
            self._send_bad_gateway()
            return
        status, resp_headers, content = captured

        # (4) RESPONSE-SIDE inspection — the app's own answer can PROVE exploitation (reflected XSS /
        #     error-based SQLi). Pure, fail-open: any error => rverdict None => relay untouched.
        rverdict: Verdict | None = None
        try:
            rverdict = inspect_response(
                self.path, self._request_headers(), inspect_body,
                content.decode("utf-8", "replace") if content else None,
                enforce=enforce,
                canary=settings.config.canary,
            )
        except Exception:
            rverdict = None
        self._emit(rverdict)

        # (5) Record this request's belief ONCE, with its strongest verdict (a response-proven attack
        #     dominates a request-side lead/benign), then either withhold a response that PROVES
        #     exploitation (response-side block) or relay.
        self._note_belief(rverdict if self._is_block(rverdict) else verdict)
        if self._is_block(rverdict):
            self._send_block(rverdict)  # type: ignore[arg-type]
            return
        self._relay(status, resp_headers, content)

    @staticmethod
    def _is_block(verdict: Verdict | None) -> bool:
        return verdict is not None and verdict.decision == "confirmed" and verdict.action == "block"


def serve_gateway(upstream: str, *, config: AegisConfig, host: str = "127.0.0.1", port: int = 8080,
                  slug: str = "aegis-gateway",
                  on_verdict: Callable[[Verdict], None] | None = None,
                  saas_tenant: str | None = None, saas_host: str | None = None,
                  monitoring_spool: str | None = None,
                  monitoring_secret: bytes | None = None,
                  instance_id: str = "gw", replica_index: int = 0, saas_v2_dir: "str | None" = None,
                  now_fn: "Callable[[], datetime] | None" = None,
                  monotonic_fn: "Callable[[], float] | None" = None,
                  on_authority_event: "Callable[[Any], None] | None" = None) -> ThreadingHTTPServer:
    """Build (but do not start) the gateway server. The caller runs ``.serve_forever()``. Unlike the
    loopback-only ``api``/``console`` servers, a data-plane proxy must be reachable by real clients,
    so ``host`` is NOT forced to loopback — the compensating controls are the ``boundary``/inspect
    hardening, the ``AEGIS_RESPOND`` entitlement, and the per-request kill-switch. Default ``observe``
    is read-only: it inspects and forwards, never blocking. ``slug`` names the gateway for the
    kill-switch and the audit trail."""
    httpd = ThreadingHTTPServer((host, port), AegisGatewayHandler)
    # AEGIS-SaaS AE-4: a tenant gateway may additionally spool sealed, metadata-only monitoring reports for the
    # sovereign Monitoring surface. Both the spool and its per-(tenant, host) report secret are required together,
    # and only a tenant-bound gateway reports (a legacy gateway's sinks are unchanged).
    if (monitoring_spool is None) != (monitoring_secret is None):
        raise ValueError("monitoring_spool and monitoring_secret must be configured together")
    if monitoring_spool is not None and not saas_tenant:
        raise ValueError("monitoring reports require a tenant-bound gateway (saas_tenant + saas_host)")
    httpd.settings = GatewaySettings(upstream, config, slug=slug, on_verdict=on_verdict,  # type: ignore[attr-defined]
                                     saas_tenant=saas_tenant, saas_host=saas_host,
                                     instance_id=instance_id, replica_index=replica_index, saas_v2_dir=saas_v2_dir,
                                     now_fn=now_fn, monotonic_fn=monotonic_fn,
                                     on_authority_event=on_authority_event)
    if monitoring_spool is not None:
        from .monitoring_report import SpoolReporter, compose_sinks
        st = httpd.settings  # type: ignore[attr-defined]
        st.monitoring_reporter = SpoolReporter(monitoring_spool, org_id=st.saas_tenant, host=st.saas_host,
                                               secret=monitoring_secret)
        st.on_verdict = compose_sinks(on_verdict, st.monitoring_reporter)
    return httpd
