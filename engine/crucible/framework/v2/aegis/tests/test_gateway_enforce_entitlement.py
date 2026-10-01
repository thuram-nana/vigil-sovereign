"""
INV3 — AEGIS Gateway enforce is REAL only once AEGIS_RESPOND is provisioned, and NEVER silent.

This is the investor-eval "firewall on" contract, proven end-to-end over real loopback sockets against a
GENUINELY governed deployment (a real trust root + real signed entitlement provisioned into an isolated
entitlement dir — not a monkeypatched decision function). The control pair differs ONLY by whether the
AEGIS_RESPOND grant is present:

  * PROVISIONED  → ``--mode enforce`` BLOCKS a CONFIRMED attack with 403 + a re-runnable certificate, and
    the malicious request never reaches the upstream; ``enforcement_status()`` reports enforcing.
  * NOT provisioned (governed, trust root present, grant absent) → the gateway HONESTLY downgrades to
    observe: it forwards (availability preserved) AND ``enforcement_status()`` reports the downgrade with a
    reason that names the missing entitlement — NO SILENT downgrade.

And the authority ladder: under enforce + entitled, a LEAD / inconclusive verdict is NEVER blocked — only a
CONFIRMED oracle verdict is. The block rides on ``decision == "confirmed"``, not on an ``action`` field a
non-oracle layer could set.
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

from framework.v2.aegis.gateway import serve_gateway
from framework.v2.aegis.models import AegisConfig, Verdict
from framework.v2.entitlement import policy, provision
from framework.v2.entitlement.models import CapabilityTier


class _Upstream(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_a):  # noqa: D401 - quiet
        return

    def _reply(self):
        body = f"UPSTREAM-OK path={self.path}".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    do_GET = _reply
    do_POST = _reply


@pytest.fixture()
def upstream() -> Iterator[int]:
    srv = socketserver.TCPServer(("127.0.0.1", 0), _Upstream)
    srv.daemon_threads = True
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield srv.server_address[1]
    finally:
        srv.shutdown()
        srv.server_close()


@pytest.fixture()
def governed(tmp_path, monkeypatch):
    """Isolate the entitlement material in a tmp dir and neutralise host state (kill-switch forced clear) so
    the enforce behaviour depends ONLY on whether this test provisions the AEGIS_RESPOND grant — never on the
    operator's real CRUCIBLE_ROOT. A trust root is always written (so enforcement is ACTIVE / governed); the
    entitlement is provisioned per-test."""
    monkeypatch.setenv("CRUCIBLE_ENTITLEMENT_DIR", str(tmp_path))
    monkeypatch.delenv("CRUCIBLE_ENTITLEMENT_ENFORCED", raising=False)
    monkeypatch.delenv("CRUCIBLE_ATTESTED_IDENTITY", raising=False)
    # the kill-switch is a SEPARATE fail-safe term; pin it clear so this test isolates the entitlement term.
    monkeypatch.setattr("framework.v2.authority.killswitch.KillSwitch.is_tripped", lambda self: False)
    # a single-authoriser trust root → enforcement ACTIVE (governed deployment).
    ak, priv = provision.new_authorizer("auth-0", "Eval Authoriser")
    tr = provision.build_trust_root([ak], threshold=1)
    provision.write_trust_root(tr)
    policy.reset_policy()

    def _grant(*, aegis_respond: bool) -> None:
        """Provision (or deliberately withhold) the AEGIS_RESPOND grant, then rebuild the policy. A STANDARD
        tier grants AEGIS_RESPOND; withholding means NO entitlement at all (trust root present, grant absent)
        — the exact governed-but-unentitled state the eval must detect."""
        if aegis_respond:
            doc = _entitlement_doc(tier=CapabilityTier.STANDARD)
            signed = provision.sign_entitlement(doc, {"auth-0": priv})
            provision.write_entitlement(signed)
        policy.reset_policy()

    yield _grant
    policy.reset_policy()


def _entitlement_doc(*, tier: CapabilityTier):
    from datetime import datetime, timedelta, timezone

    from framework.v2.entitlement.models import EntitlementDocument, EntitlementSubject

    now = datetime.now(timezone.utc)
    return EntitlementDocument(
        entitlement_id="eval-inv3-0001",
        issuer="VIGIL Eval Governance",
        subject=EntitlementSubject(institution_id="org-eval-0001",
                                   institution_name="Investor Eval Org"),
        capability_tier=tier,
        granted_capabilities=[],  # empty ⇒ everything the tier permits (STANDARD includes AEGIS_RESPOND)
        issued_at=now,
        not_before=now - timedelta(hours=1),
        not_after=now + timedelta(hours=1),
    )


def _run_gateway(upstream_port: int, *, mode: str, sink: list | None = None):
    cfg = AegisConfig(deployment_secret="k", mode=mode)
    gw = serve_gateway(f"http://127.0.0.1:{upstream_port}", config=cfg, host="127.0.0.1", port=0,
                       on_verdict=(sink.append if sink is not None else None))
    threading.Thread(target=gw.serve_forever, daemon=True).start()
    return gw, gw.server_address[1]


def _get(port: int, path: str):
    return urllib.request.urlopen(urllib.request.Request(f"http://127.0.0.1:{port}{path}"), timeout=5)


_SQLI = "/search?q=" + urllib.parse.quote("' OR '1'='1")


# --------------------------------------------------------------------------- positive: provisioned → block

def test_enforce_blocks_confirmed_when_aegis_respond_provisioned(governed, upstream):
    governed(aegis_respond=True)
    sink: list[Verdict] = []
    gw, port = _run_gateway(upstream, mode="enforce", sink=sink)
    try:
        # the gate is genuinely enforcing — the status says so, honestly.
        es = gw.settings.enforcement_status()
        assert es["enforcing"] is True and es["entitled"] is True and es["downgraded"] is False
        assert es["effective_mode"] == "enforce" and es["downgrade_reason"] is None

        with pytest.raises(urllib.error.HTTPError) as ei:
            _get(port, _SQLI)
        err = ei.value
        assert err.code == 403
        assert err.headers.get("X-Aegis-Block") == "sqli_attempt"
        cert = err.headers.get("X-Aegis-Certificate", "")
        assert cert.startswith("aegis-cert:")
        # the block is PROVABLE: the emitted verdict's certificate re-runs offline.
        v = next(v for v in sink if v.decision == "confirmed")
        assert v.certificate is not None and v.certificate.reverify() is True
    finally:
        gw.shutdown()


# --------------------------------------------------------------------- negative control: not provisioned

def test_enforce_observes_only_when_not_provisioned_and_reports_it(governed, upstream):
    """Governed, trust root present, AEGIS_RESPOND grant ABSENT: enforce must NOT block — it downgrades to
    observe, forwards both benign and malicious traffic (availability preserved), and the downgrade is
    machine-readably REPORTED with the missing-entitlement reason. That report is the whole point: NO
    SILENT downgrade."""
    governed(aegis_respond=False)
    sink: list[Verdict] = []
    gw, port = _run_gateway(upstream, mode="enforce", sink=sink)
    try:
        es = gw.settings.enforcement_status()
        assert es["requested_mode"] == "enforce"
        assert es["enforcing"] is False and es["entitled"] is False
        assert es["effective_mode"] == "observe"
        # the downgrade is explicit and names the missing entitlement — never None, never silent.
        assert es["downgraded"] is True
        assert es["downgrade_reason"] and "AEGIS_RESPOND" in es["downgrade_reason"]

        # the proven attack is still INSPECTED (confirmed verdict emitted) but FORWARDED, not blocked.
        body = _get(port, _SQLI).read().decode()
        assert "UPSTREAM-OK" in body, "unentitled enforce must downgrade to observe, not block"
        assert any(v.decision == "confirmed" for v in sink), "the attack must still be detected + reported"
        # benign traffic also forwards.
        assert "UPSTREAM-OK" in _get(port, "/hello?q=world").read().decode()
    finally:
        gw.shutdown()


# ---------------------------------------------------------- authority ladder: enforce never acts on a LEAD

def test_enforce_never_blocks_a_lead_even_when_entitled(governed, upstream, monkeypatch):
    """Even fully entitled + enforcing, a LEAD / inconclusive verdict is NEVER blocked — only a CONFIRMED
    oracle verdict is. The adversarial twist: the LEAD carries ``action='block'``; it must STILL forward,
    proving the gate rides on ``decision == 'confirmed'`` (an oracle fired), not on an action field a
    non-oracle (belief / heuristic) layer could set."""
    governed(aegis_respond=True)
    sink: list[Verdict] = []

    def _lead(*_a, **_k):
        return Verdict(decision="lead", attack_class="sqli_attempt", confidence=0.9,
                       certificate=None, provenance="intel:test:lead", action="block")

    # request-side inspection returns a LEAD-with-action-block; response-side returns nothing.
    monkeypatch.setattr("framework.v2.aegis.gateway.inspect_request", _lead)
    monkeypatch.setattr("framework.v2.aegis.gateway.inspect_response", lambda *_a, **_k: None)

    gw, port = _run_gateway(upstream, mode="enforce", sink=sink)
    try:
        assert gw.settings.enforcement_status()["enforcing"] is True  # non-vacuous: really enforcing
        body = _get(port, _SQLI).read().decode()
        assert "UPSTREAM-OK" in body, "a LEAD (even action=block) must forward — only a CONFIRMED verdict blocks"
        assert all(v.decision != "confirmed" for v in sink)
    finally:
        gw.shutdown()


# ---------------------------------------------------------------------------- unit: status is never silent

def test_enforcement_status_matrix_is_honest(governed, monkeypatch):
    """The honest-status unit: observe never claims enforce; a requested-enforce that is not active ALWAYS
    carries a non-empty downgrade_reason (the structural 'no silent downgrade' guarantee)."""
    governed(aegis_respond=False)   # governed, unentitled
    from framework.v2.aegis.gateway import GatewaySettings

    # observe: never downgraded (nothing was requested), never enforcing.
    s_obs = GatewaySettings("http://127.0.0.1:9", AegisConfig(deployment_secret="k", mode="observe"))
    es = s_obs.enforcement_status()
    assert es["enforcing"] is False and es["downgraded"] is False and es["downgrade_reason"] is None

    # enforce requested but unentitled → downgraded WITH a reason (never silent).
    s_enf = GatewaySettings("http://127.0.0.1:9", AegisConfig(deployment_secret="k", mode="enforce"))
    es = s_enf.enforcement_status()
    assert es["downgraded"] is True and es["downgrade_reason"], "a downgrade must never be silent"

    # entitled but kill-switch tripped → still downgraded, reason names the kill-switch.
    monkeypatch.setattr(s_enf, "_enforce_authorized", True)
    monkeypatch.setattr(s_enf, "_killswitch_tripped", lambda: True)
    es = s_enf.enforcement_status()
    assert es["downgraded"] is True and "kill-switch" in es["downgrade_reason"]

    # entitled + kill-switch clear → genuinely enforcing, no downgrade.
    monkeypatch.setattr(s_enf, "_killswitch_tripped", lambda: False)
    es = s_enf.enforcement_status()
    assert es["enforcing"] is True and es["downgraded"] is False and es["downgrade_reason"] is None
