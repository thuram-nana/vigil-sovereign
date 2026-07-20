"""
AEGIS Gateway G5 — graduated challenge / throttle on the per-actor Beta belief.

A LEAD never blocks and belief NEVER blocks (prove-don't-guess: only a fired oracle's certificate
blocks). But an actor that SUSTAINS suspicious behavior earns an availability-first, retryable
response short of a hard block: first ``challenge``, then (higher belief) ``throttle`` (HTTP 429).
These tests pin:

  * the response_policy escalates challenge -> throttle on the LCB, requires SUSTAINED evidence
    (a single hit never escalates), decays for an already-tracked actor, and NEVER returns "block",
  * end-to-end: repeated SSRF leads from one actor escalate to a 429 challenge; repeated confirmed
    attacks then a benign request escalate to a 429 throttle,
  * a single / benign actor is never challenged; observe mode never acts (belief is tracked only),
  * the Beta accumulation is order-independent for affirming inputs (determinism).
"""

from __future__ import annotations

import http.server
import socketserver
import threading
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterator

import pytest

from framework.v2.aegis.actor_graph import ActorGraph
from framework.v2.aegis.gateway import serve_gateway
from framework.v2.aegis.models import AegisConfig, Verdict
from framework.v2.aegis.response_policy import (
    CHALLENGE_LCB,
    THROTTLE_LCB,
    feed_and_score,
    graduated_action,
)


class _StubVerdict:
    """A minimal verdict stand-in — feed_and_score reads only ``.decision`` / ``.attack_class``, so a
    unit test need not mint a real certificate for a 'confirmed' verdict (the model requires one; the
    end-to-end gateway tests exercise real Verdicts)."""

    def __init__(self, decision: str, attack_class: str = "ssrf") -> None:
        self.decision = decision
        self.attack_class = attack_class


def _v(decision: str, attack_class: str = "ssrf") -> _StubVerdict:
    return _StubVerdict(decision, attack_class)


# --------------------------------------------------------------------------- response_policy unit

def test_single_hit_never_escalates():
    g = ActorGraph()
    b = feed_and_score(g, "1.1.1.1", _v("lead"), seq=1)
    assert graduated_action(b) is None   # MIN_SUSTAINED_OBS floor + low LCB


def test_sustained_leads_escalate_to_challenge():
    g = ActorGraph()
    actions = [graduated_action(feed_and_score(g, "1.1.1.1", _v("lead"), seq=i)) for i in range(1, 9)]
    assert "challenge" in actions
    # challenge appears only after several hits, never on the first.
    assert actions[0] is None
    assert actions.count("challenge") >= 2


def test_repeated_confirmed_escalates_to_throttle():
    g = ActorGraph()
    for i in range(1, 9):
        feed_and_score(g, "2.2.2.2", _v("confirmed", "sqli_attempt"), seq=i)
    b = feed_and_score(g, "2.2.2.2", None, seq=99)   # a later benign request
    assert graduated_action(b) == "throttle"


def test_challenge_threshold_below_throttle_threshold():
    # ordering guarantee: challenge always precedes throttle.
    assert CHALLENGE_LCB < THROTTLE_LCB


def test_benign_only_actor_is_never_tracked_or_challenged():
    g = ActorGraph()
    for i in range(1, 6):
        assert feed_and_score(g, "9.9.9.9", None, seq=i) is None   # no node, no belief
    assert g.belief("session:9.9.9.9") is None


def test_graduated_action_never_returns_block():
    # exhaustive sweep: whatever the belief, the graduated action is only ever challenge/throttle/None.
    g = ActorGraph()
    seen = set()
    for i in range(1, 40):
        b = feed_and_score(g, "5.5.5.5", _v("confirmed", "xss"), seq=i)
        seen.add(graduated_action(b))
    assert seen <= {None, "challenge", "throttle"}
    assert "block" not in seen


def test_belief_is_order_independent_for_affirming_inputs():
    seqs = [("lead", "ssrf"), ("confirmed", "sqli_attempt"), ("lead", "xxe"), ("confirmed", "xss")]
    g1 = ActorGraph()
    for i, (d, c) in enumerate(seqs, 1):
        feed_and_score(g1, "a", _v(d, c), seq=i)
    g2 = ActorGraph()
    for i, (d, c) in enumerate(reversed(seqs), 1):
        feed_and_score(g2, "a", _v(d, c), seq=i)
    b1, b2 = g1.belief("session:a"), g2.belief("session:a")
    assert abs(b1.lcb - b2.lcb) < 1e-9 and b1.n_observations == b2.n_observations


def test_already_tracked_actor_decays_on_benign_requests():
    g = ActorGraph()
    for i in range(1, 7):
        feed_and_score(g, "d", _v("lead"), seq=i)
    high = g.belief("session:d").mean
    for i in range(7, 20):
        feed_and_score(g, "d", None, seq=i)   # sustained benign traffic
    assert g.belief("session:d").mean < high   # belief decayed (recovery)


def test_one_lead_amid_sustained_benign_never_escalates():
    # Regression for the review's false positive: a single lead followed by a long run of BENIGN
    # requests must NEVER escalate. The 0.7-refute benign decay drives the mean down (~0.38) and the
    # CHALLENGE_MEAN gate keeps a mostly-benign actor below the escalation floor — belt AND suspenders.
    g = ActorGraph()
    feed_and_score(g, "nat", _v("lead"), seq=0)
    actions = [graduated_action(feed_and_score(g, "nat", None, seq=i)) for i in range(1, 41)]
    assert all(a is None for a in actions)
    # even a 50/50 lead/benign actor (mean tops out at 0.5) stays below the challenge floor.
    g2 = ActorGraph()
    fifty = [graduated_action(feed_and_score(g2, "even", _v("lead") if i % 2 == 0 else None, seq=i))
             for i in range(24)]
    assert all(a is None for a in fifty)


def test_leads_only_ever_challenge_never_throttle():
    # Doctrine: lead volume alone can reach `challenge` but the belief mean asymptotes below
    # THROTTLE_MEAN, so leads NEVER reach the harder `throttle` — only repeated CONFIRMED attacks do.
    g = ActorGraph()
    actions = {graduated_action(feed_and_score(g, "flood", _v("lead"), seq=i)) for i in range(300)}
    assert "throttle" not in actions
    assert "challenge" in actions


# --------------------------------------------------------------------------- end-to-end gateway

class _Echo(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_a):
        return

    def do_GET(self):
        body = b"UP"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture()
def upstream() -> Iterator[int]:
    srv = socketserver.TCPServer(("127.0.0.1", 0), _Echo)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield srv.server_address[1]
    finally:
        srv.shutdown()
        srv.server_close()


def _gw(upstream_port: int, *, mode: str, sink: list | None = None):
    gw = serve_gateway(f"http://127.0.0.1:{upstream_port}",
                       config=AegisConfig(deployment_secret="k", mode=mode),
                       host="127.0.0.1", port=0,
                       on_verdict=(sink.append if sink is not None else None))
    threading.Thread(target=gw.serve_forever, daemon=True).start()
    return gw, gw.server_address[1]


_SSRF = urllib.parse.quote("http://169.254.169.254/latest/meta-data/", safe="")


def _get(port: int, path: str):
    """Return (status, headers) — 200 for a relay, or the error status for a 4xx."""
    try:
        r = urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=5)
        return r.status, r.headers
    except urllib.error.HTTPError as e:
        return e.code, e.headers


def test_repeated_ssrf_leads_escalate_to_a_429_challenge(upstream):
    sink: list[Verdict] = []
    gw, port = _gw(upstream, mode="enforce", sink=sink)
    try:
        statuses = [_get(port, "/fetch?url=" + _SSRF) for _ in range(9)]
        codes = [s for s, _ in statuses]
        assert codes[0] == 200                        # the first probe is relayed (a lead never blocks)
        assert 429 in codes                           # sustained leads escalate to a challenge
        first_429 = next(h for s, h in statuses if s == 429)
        assert first_429.get("X-Aegis-Action") == "challenge"
        assert first_429.get("Retry-After") is not None
        assert any(v.action == "challenge" for v in sink)
    finally:
        gw.shutdown()


def test_repeated_confirmed_attacks_then_benign_is_throttled(upstream):
    gw, port = _gw(upstream, mode="enforce")
    try:
        # 8 confirmed request-side SQLi attacks: each 403 (blocked) AND raises belief.
        for _ in range(8):
            s, h = _get(port, "/x?q=" + urllib.parse.quote("a' OR '1'='1", safe=""))
            assert s == 403 and h.get("X-Aegis-Block") == "sqli_attempt"
        # a following benign request from the same actor is throttled (belief crossed the throttle LCB).
        s, h = _get(port, "/home")
        assert s == 429 and h.get("X-Aegis-Action") == "throttle"
    finally:
        gw.shutdown()


def test_single_benign_request_is_not_challenged(upstream):
    gw, port = _gw(upstream, mode="enforce")
    try:
        s, _ = _get(port, "/home")
        assert s == 200   # a benign actor is never tracked, never challenged
    finally:
        gw.shutdown()


def test_observe_mode_tracks_belief_but_never_challenges(upstream):
    gw, port = _gw(upstream, mode="observe")
    try:
        codes = [_get(port, "/fetch?url=" + _SSRF)[0] for _ in range(12)]
        assert all(c == 200 for c in codes)   # observe NEVER acts — every probe relays
        # belief was still tracked for telemetry.
        assert gw.settings.actor_graph.belief("session:127.0.0.1") is not None
    finally:
        gw.shutdown()
