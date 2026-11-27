"""AEGIS AS-2c (gateway v2) — the V2 data plane over REAL loopback sockets, deterministic and offline.

Drives a long-lived tenant gateway with the GATEWAY_V2 flag on and asserts the end-to-end behaviours that only
the socket path exercises:

  * flag-OFF ⇒ the V2 path is never taken (byte-identical v1 behaviour);
  * 421 Misdirected Request on a FOREIGN Host; a matching / missing Host is served;
  * an OBSERVE grant is inspected but never blocks;
  * a BLOCK grant blocks (403 + re-runnable certificate) ONLY with a valid release AND the production flag AND
    enforce mode — a BLOCK grant WITHOUT a release stays OBSERVE (release_valid default-off, AS-29);
  * a lapsed lease / no grant ⇒ uninspected pass-through (R16), nothing inspected;
  * ACCEPTANCE: re-planting an already-known authority produces NO duplicate authority event.

Determinism: the wall clock and the verify-cache monotonic clock are INJECTED; no test reads a wallclock.
"""
from __future__ import annotations

import http.client
import http.server
import itertools
import socketserver
import threading
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

import pytest
from vigil_core import AuthorizerKey, TrustRoot, generate_keypair
from vigil_core.authority_v2 import (
    AuthoritySubject,
    EnforceRelease,
    MonitoringAuthorityV2,
    MonitoringCapability,
    MonitoringLease,
    SubjectKind,
    sign_enforce_release,
    sign_monitoring_authority_v2,
)

from framework.v2.aegis import gateway as G
from framework.v2.aegis.authority_v2_check import AuthorityV2Paths, _subject_dir_name
from framework.v2.aegis.gateway import serve_gateway
from framework.v2.aegis.models import AegisConfig, Verdict

ORG, HOST = "org_a", "apme.cm"
OWNER = generate_keypair()
RELEASE = generate_keypair()
OWNER_ROOT = TrustRoot(threshold=1, authorizers=[AuthorizerKey(key_id="owner", name="owner",
                                                               public_key_b64=OWNER.public_key_b64)])
RELEASE_ROOT = TrustRoot(threshold=1, authorizers=[AuthorizerKey(key_id="rel", name="rel",
                                                                 public_key_b64=RELEASE.public_key_b64)])
B = MonitoringCapability.BLOCK
OBS = MonitoringCapability.OBSERVE
ATTACK = "/download?file=" + urllib.parse.quote("../../../../etc/passwd")
BENIGN = "/assets?file=" + urllib.parse.quote("../styles/app.css")


def _dt(ts: float) -> datetime:
    return datetime.fromtimestamp(ts, tz=timezone.utc)


def _subject() -> AuthoritySubject:
    return AuthoritySubject(kind=SubjectKind.HOST, org_id=ORG, host=HOST)


class _Upstream(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_a):
        return

    def do_GET(self):
        body = b"UPSTREAM-OK"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture()
def upstream():
    srv = socketserver.TCPServer(("127.0.0.1", 0), _Upstream)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield srv.server_address[1]
    finally:
        srv.shutdown()
        srv.server_close()


@pytest.fixture()
def v2dir(tmp_path, monkeypatch):
    """A clean V2 publish root with the pinned owner root wired; the GATEWAY_V2 flag ON; both production /
    release-root gates OFF by default (each test opts in)."""
    d = tmp_path / "v2"
    monkeypatch.setattr("framework.v2.authority.store.load_authority_root", lambda: OWNER_ROOT)
    monkeypatch.setattr(G, "load_release_roots", list)             # AS-29 pending by default (empty overlap set)
    monkeypatch.setenv(G.GATEWAY_V2_ENV, "1")
    monkeypatch.delenv(G.SAAS_ENFORCE_ENV, raising=False)
    return d


def _paths(v2dir: Path, *, instance="gw", replica=0) -> AuthorityV2Paths:
    base = v2dir / _subject_dir_name(_subject())
    base.mkdir(parents=True, exist_ok=True)
    return AuthorityV2Paths(base=base, subject=_subject(), instance_id=instance, replica_index=replica)


def _grant(*, epoch=1, caps=(OBS,), nb=0.0, na=4.0e9, lease_nb=0.0, lease_na=4.0e9):
    doc = MonitoringAuthorityV2(
        subject=_subject(), capabilities=list(caps), epoch=epoch, not_before=_dt(nb), not_after=_dt(na),
        lease=MonitoringLease(not_before=_dt(lease_nb), not_after=_dt(lease_na)), instance_id="gw")
    return sign_monitoring_authority_v2(doc, {"owner": OWNER.private_key_b64})


def _release(*, epoch=1):
    doc = EnforceRelease(subject=_subject(), released_capabilities=[B], epoch=epoch,
                         not_before=_dt(0.0), not_after=_dt(4.0e9))
    return sign_enforce_release(doc, {"rel": RELEASE.private_key_b64})


def _plant(paths: AuthorityV2Paths, attr: str, signed) -> None:
    getattr(paths, attr).write_bytes(signed.model_dump_json().encode())


class _GW:
    def __init__(self, upstream_port, v2dir: Path, *, mode="enforce", tenant=ORG, saas_host=HOST,
                 sink=None, events=None):
        # An incrementing monotonic clock (>TTL per call) so every request is a fresh resolve — the verify
        # cache is unit-tested separately; here we want each socket request to re-read the published docs.
        step = itertools.count()
        self.gw = serve_gateway(
            f"http://127.0.0.1:{upstream_port}", config=AegisConfig(deployment_secret="k", mode=mode),
            host="127.0.0.1", port=0, saas_tenant=tenant, saas_host=(saas_host if tenant else None),
            saas_v2_dir=str(v2dir), now_fn=lambda: _dt(1000.0),
            monotonic_fn=lambda: next(step) * 2.0,
            on_verdict=(sink.append if sink is not None else None),
            on_authority_event=(events.append if events is not None else None))
        threading.Thread(target=self.gw.serve_forever, daemon=True).start()

    @property
    def port(self):
        return self.gw.server_address[1]

    def get(self, path=ATTACK, host=HOST):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            if host is None:
                c.putrequest("GET", path, skip_host=True)
                c.endheaders()
            else:
                c.request("GET", path, headers={"Host": host})
            r = c.getresponse()
            return r.status, r.getheader("X-Aegis-Block"), r.read()
        finally:
            c.close()

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.gw.shutdown()
        self.gw.server_close()


# ---- flag OFF ⇒ V2 inert ----------------------------------------------------------------------------------
def test_flag_off_does_not_take_the_v2_path(upstream, v2dir, monkeypatch):
    monkeypatch.delenv(G.GATEWAY_V2_ENV, raising=False)       # flag OFF
    _plant(_paths(v2dir), "grant", _grant(caps=(OBS, B)))
    with _GW(upstream, v2dir) as gw:
        # No v1 authority published anywhere ⇒ the v1 path treats this as no-authority ⇒ pass-through. The
        # key point: the V2 grant is NOT consulted when the flag is off (gateway_v2 is False).
        assert gw.gw.settings.gateway_v2 is False
        assert gw.get(ATTACK)[0] == 200          # not blocked: V2 path inert, v1 sees no authority


# ---- 421 on a foreign Host --------------------------------------------------------------------------------
def test_foreign_host_gets_421(upstream, v2dir):
    _plant(_paths(v2dir), "grant", _grant())
    with _GW(upstream, v2dir) as gw:
        assert gw.get(BENIGN, host="evil.example")[0] == 421
        assert gw.get(BENIGN, host="apme.cm")[0] == 200          # the configured host is served
        assert gw.get(BENIGN, host=None)[0] == 200               # a missing Host is NOT foreign


def test_foreign_host_checked_before_authority(upstream, v2dir):
    # even with NO grant published, a foreign Host is 421 (routing correctness precedes authority).
    with _GW(upstream, v2dir) as gw:
        assert gw.get(BENIGN, host="other.example")[0] == 421


# ---- observe grant: inspected, never blocks ---------------------------------------------------------------
def test_observe_grant_inspects_but_never_blocks(upstream, v2dir, monkeypatch):
    monkeypatch.setenv(G.SAAS_ENFORCE_ENV, "1")
    _plant(_paths(v2dir), "grant", _grant(caps=(OBS,)))
    sink: list[Verdict] = []
    with _GW(upstream, v2dir, sink=sink) as gw:
        status, blocked, body = gw.get(ATTACK)
        assert status == 200 and blocked is None and body == b"UPSTREAM-OK"
        assert any(v.decision == "confirmed" for v in sink), "inspected + alerted, just not enforced"


# ---- block grant needs release + flag + enforce -----------------------------------------------------------
def test_block_grant_without_release_stays_observe(upstream, v2dir, monkeypatch):
    monkeypatch.setenv(G.SAAS_ENFORCE_ENV, "1")
    _plant(_paths(v2dir), "grant", _grant(caps=(OBS, B)))      # BLOCK capability but no release root (AS-29)
    sink: list[Verdict] = []
    with _GW(upstream, v2dir, sink=sink) as gw:
        assert gw.get(ATTACK)[0] == 200                         # release_valid false ⇒ never enforces
        assert any(v.decision == "confirmed" for v in sink)     # still inspected


def test_block_grant_with_release_and_every_flag_blocks(upstream, v2dir, monkeypatch):
    monkeypatch.setenv(G.SAAS_ENFORCE_ENV, "1")
    monkeypatch.setattr(G, "load_release_roots", lambda: [RELEASE_ROOT])
    p = _paths(v2dir)
    _plant(p, "grant", _grant(caps=(OBS, B), epoch=2))
    _plant(p, "release", _release(epoch=2))
    sink: list[Verdict] = []
    with _GW(upstream, v2dir, sink=sink) as gw:
        status, blocked, _ = gw.get(ATTACK)
        assert status == 403 and blocked == "path_traversal_attempt"
        v = next(v for v in sink if v.decision == "confirmed")
        assert v.certificate is not None and v.certificate.reverify() is True
        assert gw.get(BENIGN)[0] == 200                         # benign still forwarded


def test_block_with_release_but_flag_off_never_blocks(upstream, v2dir, monkeypatch):
    monkeypatch.setattr(G, "load_release_roots", lambda: [RELEASE_ROOT])
    p = _paths(v2dir)
    _plant(p, "grant", _grant(caps=(OBS, B), epoch=2))
    _plant(p, "release", _release(epoch=2))
    with _GW(upstream, v2dir) as gw:                            # SAAS_ENFORCE flag OFF
        assert gw.get(ATTACK)[0] == 200


def test_block_with_release_but_observe_mode_never_blocks(upstream, v2dir, monkeypatch):
    monkeypatch.setenv(G.SAAS_ENFORCE_ENV, "1")
    monkeypatch.setattr(G, "load_release_roots", lambda: [RELEASE_ROOT])
    p = _paths(v2dir)
    _plant(p, "grant", _grant(caps=(OBS, B), epoch=2))
    _plant(p, "release", _release(epoch=2))
    with _GW(upstream, v2dir, mode="observe") as gw:
        assert gw.get(ATTACK)[0] == 200


# ---- lease lapse / no grant ⇒ uninspected pass-through (R16) ----------------------------------------------
def test_lapsed_lease_is_uninspected_pass_through(upstream, v2dir, monkeypatch):
    monkeypatch.setenv(G.SAAS_ENFORCE_ENV, "1")
    monkeypatch.setattr(G, "load_release_roots", lambda: [RELEASE_ROOT])
    p = _paths(v2dir)
    _plant(p, "grant", _grant(caps=(OBS, B), lease_nb=0.0, lease_na=500.0))   # lease closed by t=500; now=1000
    _plant(p, "release", _release())
    sink: list[Verdict] = []
    with _GW(upstream, v2dir, sink=sink) as gw:
        status, blocked, body = gw.get(ATTACK)
        assert status == 200 and blocked is None and body == b"UPSTREAM-OK"
        assert sink == [], "R16: a lapsed lease is uninspected pass-through"


def test_no_grant_is_uninspected_pass_through(upstream, v2dir):
    sink: list[Verdict] = []
    with _GW(upstream, v2dir, sink=sink) as gw:
        assert gw.get(ATTACK, host=HOST)[0] == 200 and sink == []


# ---- ACCEPTANCE: re-plant produces no event ---------------------------------------------------------------
def test_re_plant_produces_no_event(upstream, v2dir):
    """AS-2c acceptance. A grant is planted and resolved (one authority event). Re-planting the SAME grant and
    issuing more traffic produces NO further authority event — the data-plane idempotency the sovereign events
    API relies on (an already-known authority is not re-emitted)."""
    p = _paths(v2dir)
    _plant(p, "grant", _grant(epoch=3))
    events = []
    with _GW(upstream, v2dir, events=events) as gw:
        assert gw.get(BENIGN)[0] == 200
        assert [e.epoch for e in events] == [3], "the first live resolve emits exactly one planted event"
        # RE-PLANT: re-write the identical grant and drive more traffic.
        _plant(p, "grant", _grant(epoch=3))
        for _ in range(4):
            assert gw.get(BENIGN)[0] == 200
        assert [e.epoch for e in events] == [3], "re-plant of an already-known authority produces no new event"
