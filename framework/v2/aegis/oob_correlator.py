"""
aegis.oob_correlator — passive OOB→belief correlation for the AEGIS Gateway.

The AEGIS Gateway is a TRANSLATOR, not a generator: it forwards every inbound request
BYTE-FOR-BYTE and NEVER injects, rewrites, appends, or plants anything into traffic. This
module upholds that line by construction — it READS the attacker's own request bytes and the
receiver's own inbound-hit records, and produces only a per-actor *belief-elevation* signal. It
mints NO token, plants NO callback, and touches NO request.

The idea (passive, canary-based):

  * The operator PLANTS a STATIC canary — a host they control that (a) an app's server-side fetch
    can reach and which tunnels back to a LOOPBACK ``verify.oob.OOBReceiver`` (via the operator's
    own reverse tunnel, the operator's charter responsibility), and (b) trips AEGIS's existing
    SSRF/XXE *lead* when an attacker references it (an internal / RFC1918 / metadata-style host for
    SSRF; any external SYSTEM/PUBLIC host for XXE). AEGIS does NOT create or advertise the canary —
    the operator does.
  * When the gateway sees an SSRF/XXE LEAD whose payload REFERENCED the canary host (extracted from
    the attacker's OWN value — no injection), the correlator records a bounded pending observation
    ``(actor_key, attack_class, seq)``.
  * When the loopback receiver logs an UNSOLICITED inbound hit on the canary (something server-side
    dereferenced it), the correlator correlates that hit to the pending observation(s) that targeted
    the canary host and returns an ``Elevation`` for each such actor.

The caller folds an ``Elevation`` into the SAME per-actor Beta belief the gateway already keeps
(``feed_oob_correlation`` in ``response_policy``). That is a STRONG affirming signal — stronger than
a plain lead — but it is STILL belief-only: it mints NO certificate, and the graduated action a
belief warrants is only ever ``challenge`` / ``throttle`` (a soft, retryable 429), NEVER a block. A
hard block always rides ONLY a fired oracle certificate (prove-don't-guess). This feature can never
produce a ``block`` / ``confirmed`` verdict.

Everything here is pure-ish and total: bounded memory (LRU caps on pending records and seen hits),
deterministic (a monotonic internal sequence, no wallclock in the correlation logic beyond the
receiver's own hit timestamps), thread-safe (an internal lock — the gateway is threaded), and
fail-safe (any error returns "no pending"/"no elevation", never raises into the request path).

Honest scope / caveats:
  * Canary-HOST match is the PRIMARY, high-confidence correlation. There is NO timing/source
    fallback — it would be far harder to keep near-zero-FP, so it is deliberately omitted.
  * Coverage is NARROW: it fires only when an attacker actually targets the operator's canary host
    with a payload that trips the SSRF/XXE lead AND the app dereferences it back to the receiver.
  * If several actors target the canary before a hit lands, the hit elevates ALL of them. That is a
    mild over-attribution, but every such actor independently sent an SSRF/XXE payload at the trap
    host (they already carry a lead), and elevation only ever raises belief toward a soft, retryable
    challenge — never a block. We surface it rather than pretend precise per-hit attribution.
"""

from __future__ import annotations

import re
import threading
from collections import OrderedDict
from typing import NamedTuple
from urllib.parse import unquote, urlsplit

from ..verify.oob import OOBHit, OOBReceiver


class Elevation(NamedTuple):
    """A belief-elevation the caller folds into the actor's Beta belief. NOT a verdict, NOT a block —
    the caller feeds it via ``response_policy.feed_oob_correlation`` (strong affirming, no certificate)."""

    actor_key: str
    attack_class: str
    referenced_host: str
    hit_path: str


# Hosts referenced by a ``scheme://host…`` in an attacker value/body. Bounded operand + negated char
# class → non-backtracking (ReDoS-safe). We read only the attacker's OWN bytes; we never write them.
_URL_HOST_RE = re.compile(r"(?i)[a-z][a-z0-9+.\-]{0,15}://([^/\\?#\s'\"<>]{1,255})")
_MAX_SCAN_CHARS = 1 << 20      # bound the text we scan (DoS-safe)
_MAX_HOSTS = 64


def _host_of(authority: str) -> str:
    """The lowercase hostname of a URL authority (userinfo + port stripped). Total; pure."""
    a = authority
    if "@" in a:
        a = a.rsplit("@", 1)[1]
    if a.startswith("["):            # IPv6 literal: [::1]:80 -> ::1
        a = a[1:].split("]", 1)[0]
    else:
        a = a.split(":", 1)[0]
    return a.strip().rstrip(".").lower()


def referenced_hosts(raw: str) -> set[str]:
    """The set of hostnames referenced by any ``scheme://host`` in ``raw`` — scanned over the raw text
    AND its (double-)percent-decoded variants, so an encoded ``http%3A%2F%2Fcanary`` is still seen.
    Reads ONLY the given text; mutates nothing. Bounded + total (never raises)."""
    if not raw:
        return set()
    variants = {raw}
    try:
        u1 = unquote(raw)
        variants.add(u1)
        variants.add(unquote(u1))
    except Exception:
        pass
    out: set[str] = set()
    for text in variants:
        for m in _URL_HOST_RE.finditer(text[:_MAX_SCAN_CHARS]):
            host = _host_of(m.group(1))
            if host:
                out.add(host)
            if len(out) >= _MAX_HOSTS:
                return out
    return out


class OOBCorrelator:
    """Passive OOB→belief correlator for a single operator-planted canary. Thread-safe, bounded,
    deterministic, total. It NEVER touches inbound traffic — it reads attacker values + receiver hit
    records and emits belief-elevations only."""

    def __init__(self, canary_url: str, *, max_pending: int = 1024, max_seen_hits: int = 4096) -> None:
        raw = (canary_url or "").strip()
        parts = urlsplit(raw if "://" in raw else "http://" + raw)
        host = (parts.hostname or "").strip().rstrip(".").lower()
        if not host:
            raise ValueError(f"oob canary must carry a host, got {canary_url!r}")
        self.canary_host = host
        self.canary_path = parts.path or ""
        # The receiver routes/keys inbound hits by their FIRST path segment; the operator's canary
        # path gives us that poll key deterministically. We do NOT mint it — it is the operator's URL.
        seg = self.canary_path.strip("/").split("/")
        self._poll_token = seg[0] if seg and seg[0] else ""
        self._max_pending = max(1, int(max_pending))
        self._max_seen = max(1, int(max_seen_hits))
        self._lock = threading.Lock()
        self._seq = 0
        # pending obs: obs_key -> (actor_key, attack_class, seq). Bounded LRU (oldest evicted).
        self._pending: "OrderedDict[str, tuple[str, str, int]]" = OrderedDict()
        # inbound-hit identities already correlated (dedupe re-elevation across repeated polls).
        self._seen_hits: "OrderedDict[str, None]" = OrderedDict()

    # -- record a pending observation (attacker referenced the canary) -----------------------------

    def note_lead(self, actor_key: str, *, path: str, body: str | None, attack_class: str) -> bool:
        """Record a pending observation IFF the attacker's OWN payload (request path query + body)
        references the operator's canary host. Returns True when recorded. Reads only attacker bytes;
        NO injection, NO mutation. Bounded (LRU over ``max_pending``); total (never raises)."""
        try:
            text = path or ""
            if body:
                text = f"{text}\n{body}"
            if self.canary_host not in referenced_hosts(text):
                return False
            with self._lock:
                self._seq += 1
                key = f"{actor_key}|{self.canary_host}|{self._seq}"
                self._pending[key] = (actor_key, str(attack_class), self._seq)
                self._pending.move_to_end(key)
                while len(self._pending) > self._max_pending:
                    self._pending.popitem(last=False)
            return True
        except Exception:
            return False

    # -- correlate an inbound canary hit to pending observations -----------------------------------

    def poll_elevations(self, receiver: OOBReceiver) -> list[Elevation]:
        """Poll the LOOPBACK receiver for unsolicited hits on the canary and correlate each NEW hit to
        the pending SSRF/XXE observations that targeted the canary host. Returns one ``Elevation`` per
        (new hit × pending actor). Belief-only — the caller NEVER mints a certificate or a block from
        these. Total (never raises); deterministic (receiver record order + pending seq)."""
        try:
            hits = receiver.poll(self._poll_token)
        except Exception:
            return []
        out: list[Elevation] = []
        try:
            with self._lock:
                for hit in hits:
                    if not self._hit_matches(hit):
                        continue
                    hid = self._hit_id(hit)
                    if hid in self._seen_hits:
                        continue
                    # Mark EVERY new matching hit seen — including hits that arrive with NO pending —
                    # so a benign/early hit can never RETRO-correlate to a later probe (a real
                    # correlation's hit always lands AFTER its pending was recorded synchronously).
                    self._remember_hit(hid)
                    # ONE elevation per (new hit × DISTINCT actor): an actor who probed the canary N
                    # times is not counted N-fold for a single inbound hit (each probe already fed its
                    # own lead). The actor's earliest-seen attack_class labels the elevation.
                    seen_actors: set[str] = set()
                    for actor_key, attack_class, _seq in self._pending.values():
                        if actor_key in seen_actors:
                            continue
                        seen_actors.add(actor_key)
                        out.append(Elevation(actor_key=actor_key, attack_class=attack_class,
                                             referenced_host=self.canary_host, hit_path=hit.path))
        except Exception:
            return []
        return out

    # -- helpers -----------------------------------------------------------------------------------

    def _hit_matches(self, hit: OOBHit) -> bool:
        """An inbound hit belongs to the canary when its Host header carries the canary host, OR (a
        tunnel rewrote Host) it arrived on the operator's unique canary path segment — which is how we
        polled, so a non-empty token already implies a first-segment match. A bare-'/' canary (no
        path token) with no host match is too coincidental → not a match. Conservative by design."""
        host_hdr = (hit.host_header or "").split(":", 1)[0].strip().rstrip(".").lower()
        if host_hdr and host_hdr == self.canary_host:
            return True
        if self._poll_token and hit.path:
            return hit.path.strip("/").split("/")[0:1] == [self._poll_token]
        return False

    @staticmethod
    def _hit_id(hit: OOBHit) -> str:
        return f"{hit.received_at}|{hit.client_ip}|{hit.method}|{hit.path}|{hit.query}"

    def _remember_hit(self, hid: str) -> None:
        self._seen_hits[hid] = None
        self._seen_hits.move_to_end(hid)
        while len(self._seen_hits) > self._max_seen:
            self._seen_hits.popitem(last=False)
