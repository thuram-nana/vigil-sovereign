"""AEGIS AS-2d (broker + lock) — deterministic, offline acceptance tests (§4.4).

One test per acceptance behaviour from the capability matrix:

  * MERIDIAN lock enforced — the origin LOCK credential is required and verified; a missing/tampered/stale
    credential is refused; and a release requires ``crypto_verified`` (the startup refusal).
  * Z4 unauthenticated → 401 — a keyless, payload-free Z4/prover GET against a crypto lock returns 401.
  * No 2xx cross-tenant — a grant binding org A never serves uid B (tenant isolation at the broker), and a
    tenant's broker only ever dials its OWN origin, so a cross-tenant request can never reach a 2xx.
  * Forged source IP never arrives — the client IP is carried to the origin only when it is a trustworthy
    EDGE identity (edge-verified AND not loopback, R15); a forged / un-edge-verified / loopback source IP is
    dropped and never arrives at the origin.

Plus the §4.4 STARTUP REFUSAL (unbound / non-https / egress-refused origin, cross-tenant, release-without-
crypto-lock) and the default-OFF live-transport flag.

Everything is a pure function of its inputs with an INJECTED resolver + transport (no socket, no wallclock,
no RNG), so every assertion is reproducible. "MERIDIAN" is the loopback test-tenant harness the TT-CI rig
drives these lock checks from; here the lock logic it exercises is asserted directly.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone

import pytest
from vigil_core.authority_v2 import (
    AuthoritySubject,
    MonitoringAuthorityV2,
    MonitoringCapability,
    MonitoringLease,
    OriginTuple,
    SubjectKind,
)

from framework.v2.aegis import broker as B
from framework.v2.aegis.broker import (
    ArmedBroker,
    BrokerRefused,
    BrokerStartupRefused,
    BrokerTarget,
    LockMethod,
    LockState,
    OriginLock,
    arm_broker,
    broker_enabled,
    broker_forward,
    origin_lock_verify,
    resolve_broker_target,
    z4_payload_free_probe,
)

ORG_A, ORG_B = "org_a", "org_b"
HOST_A, HOST_B = "a.apme.cm", "b.apme.cm"
ORIGIN_A, ORIGIN_B = "origin-a.example.com", "origin-b.example.com"
ADDR_A, ADDR_B = "93.184.216.34", "93.184.216.35"
SECRET = b"meridian-origin-lock-secret"
NOW = 1_000_000


def _dt(ts: float) -> datetime:
    return datetime.fromtimestamp(ts, tz=timezone.utc)


def _binding(host: str, port: int) -> str:
    return hashlib.sha256(f"{host}:{port}".encode()).hexdigest()


def _grant(*, org: str = ORG_A, host: str = HOST_A, origin: str = ORIGIN_A, port: int = 443,
           with_origin: bool = True) -> MonitoringAuthorityV2:
    kw: dict = {}
    if with_origin:
        kw = {"origin": OriginTuple(host=origin, port=port), "origin_binding_sha256": _binding(origin, port)}
    return MonitoringAuthorityV2(
        subject=AuthoritySubject(kind=SubjectKind.HOST, org_id=org, host=host),
        capabilities=[MonitoringCapability.OBSERVE], epoch=1,
        not_before=_dt(0), not_after=_dt(4.0e9),
        lease=MonitoringLease(not_before=_dt(0), not_after=_dt(4.0e9)),
        instance_id="gw", **kw)


def _resolver(*addrs: str):
    """A fake getaddrinfo returning the given addresses for any name (no real DNS)."""

    def fake(host, port, proto=0):  # noqa: ANN001, ARG001
        return [(2, 1, 6, "", (a, port or 0)) for a in addrs]

    return fake


def _hmac_lock(secret: bytes = SECRET, *, ip_allowlist: bool = False) -> OriginLock:
    return OriginLock(method=LockMethod.HMAC, hmac_secret=secret, ip_allowlist=ip_allowlist)


def _origin_transport(lock: OriginLock, *, origin_only: str | None = None):
    """A fake origin-hop transport. Records what it received and returns the LOCKED origin's real behaviour:
    a 2xx ONLY when the lock credential verifies (and the dialled origin is the expected one). Lets a test
    prove both the served status and the exact headers the origin saw."""
    seen: dict = {}

    def transport(target: BrokerTarget, headers: dict[str, str], body: bytes):  # noqa: ANN202
        seen["target"] = target
        seen["headers"] = dict(headers)
        seen["body"] = body
        if origin_only is not None and target.origin.host != origin_only:
            return 421, b"misdirected"
        verdict = origin_lock_verify(headers, lock=lock, now_ts=NOW)
        return (200 if verdict.status == 200 else 401), b"served" if verdict.status == 200 else b"denied"

    return transport, seen


# ========================================================================================================
# Acceptance 1 — MERIDIAN lock enforced
# ========================================================================================================
def test_meridian_origin_lock_enforced():
    """The origin LOCK is enforced end to end: a correctly-signed broker credential verifies (200), while a
    missing, tampered, wrong-secret or stale credential is refused (401). This is the lock the MERIDIAN TT-CI
    rig drives against the locked origin."""
    lock = _hmac_lock()
    good = lock.sign(request_id="req-1", ts=NOW, client_ip="203.0.113.9")

    # a correct broker credential verifies, and the origin trusts the bound (edge) client IP.
    ok = origin_lock_verify(good, lock=lock, now_ts=NOW)
    assert ok.status == 200 and ok.client_ip == "203.0.113.9" and ok.client_ip_trusted is True
    assert lock.state is LockState.CRYPTO_VERIFIED and lock.crypto_verified is True

    # missing credential → 401.
    assert origin_lock_verify({}, lock=lock, now_ts=NOW).status == 401

    # tampered HMAC tag → 401.
    tampered = dict(good)
    tampered[B.HDR_ORIGIN_AUTH] = "v1=" + "0" * 64
    assert origin_lock_verify(tampered, lock=lock, now_ts=NOW).status == 401

    # a different origin secret cannot verify this broker's credential → 401.
    assert origin_lock_verify(good, lock=_hmac_lock(b"a-different-secret"), now_ts=NOW).status == 401

    # a stale timestamp (beyond the accepted skew) → 401 (replay bound).
    assert origin_lock_verify(good, lock=lock, now_ts=NOW + B.DEFAULT_MAX_SKEW_S + 1).status == 401

    # an IP allowlist alone never reaches crypto_verified, so a release is refused (startup refusal).
    ip_only = OriginLock(method=LockMethod.NONE, ip_allowlist=True)
    assert ip_only.state is LockState.IP_ALLOWLIST_ONLY and ip_only.crypto_verified is False
    with pytest.raises(BrokerStartupRefused, match="release requires"):
        arm_broker(_grant(), uid=ORG_A, lock=ip_only, require_crypto_lock=True, resolver=_resolver(ADDR_A))


# ========================================================================================================
# Acceptance 2 — Z4 unauthenticated → 401
# ========================================================================================================
def test_z4_unauthenticated_probe_is_401():
    """A keyless, PAYLOAD-FREE Z4 / prover GET against a crypto-locked origin returns 401 when unauthenticated,
    and 200 only with a valid credential. A tampered credential is also 401."""
    lock = _hmac_lock()
    # unauthenticated payload-free GET → 401.
    assert z4_payload_free_probe(lock, now_ts=NOW) == 401
    assert z4_payload_free_probe(lock, credential_headers={}, now_ts=NOW) == 401

    # a validly-credentialed probe → 200.
    cred = lock.sign(request_id="z4", ts=NOW, client_ip="")
    assert z4_payload_free_probe(lock, credential_headers=cred, now_ts=NOW) == 200

    # a tampered credential → 401.
    bad = dict(cred)
    bad[B.HDR_ORIGIN_AUTH] = "v1=deadbeef"
    assert z4_payload_free_probe(lock, credential_headers=bad, now_ts=NOW) == 401

    # mTLS lock: an unauthenticated probe (no client cert) → 401; a verified client cert → 200.
    mtls = OriginLock(method=LockMethod.MTLS)
    assert z4_payload_free_probe(mtls, now_ts=NOW) == 401
    assert z4_payload_free_probe(mtls, now_ts=NOW, mtls_client_verified=True) == 200


# ========================================================================================================
# Acceptance 3 — no 2xx cross-tenant
# ========================================================================================================
def test_no_2xx_cross_tenant():
    """Tenant isolation at the broker: a grant binding org A never serves uid B (so no armed broker, no
    forward, no 2xx), and each tenant's broker only ever dials its OWN origin — a cross-tenant request can
    never reach a 2xx."""
    grant_a = _grant(org=ORG_A, host=HOST_A, origin=ORIGIN_A)

    # the SAME grant cannot be armed for a different tenant uid — refused before any transport runs.
    with pytest.raises(BrokerStartupRefused, match="cross-tenant"):
        arm_broker(grant_a, uid=ORG_B, lock=_hmac_lock(), resolver=_resolver(ADDR_A))
    with pytest.raises(BrokerRefused, match="cross-tenant"):
        resolve_broker_target(grant_a, uid=ORG_B, resolver=_resolver(ADDR_A))

    # tenant A's armed broker resolves ONLY origin A (never origin B's host/address).
    lock = _hmac_lock()
    armed_a = arm_broker(grant_a, uid=ORG_A, lock=lock, resolver=_resolver(ADDR_A))
    assert armed_a.target.origin.host == ORIGIN_A and armed_a.target.addresses == (ADDR_A,)
    assert ORIGIN_B not in armed_a.target.origin.host and ADDR_B not in armed_a.target.addresses

    # a forward through A's broker only ever reaches origin A; a transport fronting ONLY origin B answers 421,
    # never a 2xx — a request bearing tenant A can never get a 2xx from tenant B's origin.
    only_b_transport, seen = _origin_transport(lock, origin_only=ORIGIN_B)
    res = broker_forward(armed_a, request_id="x", ts=NOW, client_ip="203.0.113.1",
                         edge_verified=True, transport=only_b_transport)
    assert seen["target"].origin.host == ORIGIN_A      # the broker dialled A, not B
    assert res.status == 421 and not (200 <= res.status < 300)

    # the matching tenant (A→A) DOES serve a 2xx, proving the 421 above is the isolation, not a broken path.
    a_transport, _ = _origin_transport(lock, origin_only=ORIGIN_A)
    ok = broker_forward(armed_a, request_id="y", ts=NOW, client_ip="203.0.113.1",
                        edge_verified=True, transport=a_transport)
    assert ok.status == 200


# ========================================================================================================
# Acceptance 4 — a forged source IP never arrives
# ========================================================================================================
def test_forged_source_ip_never_arrives():
    """The client IP is carried to the origin (and, for HMAC, cryptographically bound) ONLY when it is a
    trustworthy edge identity: edge-verified AND not loopback (R15: loopback is never edge identity). A forged
    / un-edge-verified / loopback source IP is dropped and never arrives at the origin — and an uncredentialed
    lock never emits a client-IP header at all."""
    lock = _hmac_lock()
    armed = arm_broker(_grant(), uid=ORG_A, lock=lock, require_crypto_lock=True, resolver=_resolver(ADDR_A))
    transport, seen = _origin_transport(lock, origin_only=ORIGIN_A)

    # (a) a forged client IP on an UN-edge-verified hop, even smuggled as a header, is dropped.
    res = broker_forward(
        armed, request_id="f1", ts=NOW, client_ip="6.6.6.6", edge_verified=False, transport=transport,
        extra_headers={B.HDR_CLIENT_IP: "6.6.6.6", "X-Forwarded-For": "6.6.6.6"})
    assert res.forwarded_client_ip == ""
    assert "6.6.6.6" not in (seen["headers"].get(B.HDR_CLIENT_IP) or "")
    assert seen["headers"].get(B.HDR_CLIENT_IP) in (None, "")
    # the origin still verifies the broker (the credential binds client_ip=""), but trusts NO client IP.
    assert res.status == 200
    assert origin_lock_verify(seen["headers"], lock=lock, now_ts=NOW).client_ip_trusted is False

    # (b) loopback presented as edge identity is refused as edge identity (R15) and dropped.
    assert B.is_valid_edge_identity("127.0.0.1") is False and B.is_valid_edge_identity("::1") is False
    res2 = broker_forward(armed, request_id="f2", ts=NOW, client_ip="127.0.0.1",
                          edge_verified=True, transport=transport)
    assert res2.forwarded_client_ip == "" and (seen["headers"].get(B.HDR_CLIENT_IP) in (None, ""))

    # (c) a genuine edge-verified public viewer IP IS carried and bound — the real path still works.
    res3 = broker_forward(armed, request_id="f3", ts=NOW, client_ip="203.0.113.9",
                          edge_verified=True, transport=transport)
    assert res3.forwarded_client_ip == "203.0.113.9"
    assert seen["headers"].get(B.HDR_CLIENT_IP) == "203.0.113.9"
    assert origin_lock_verify(seen["headers"], lock=lock, now_ts=NOW).client_ip_trusted is True

    # (d) an uncredentialed (none) lock cannot sign a forward at all — no client-IP header is ever emitted.
    none_armed = ArmedBroker(target=armed.target, lock=OriginLock(method=LockMethod.NONE))
    with pytest.raises(BrokerRefused, match="uncredentialed"):
        broker_forward(none_armed, request_id="f4", ts=NOW, client_ip="203.0.113.9",
                       edge_verified=True, transport=transport)


# ========================================================================================================
# §4.4 startup refusal + egress floor + default-OFF flag
# ========================================================================================================
def test_startup_refusal_and_egress_floor():
    lock = _hmac_lock()
    # a grant with NO origin → refused (no forward target).
    with pytest.raises(BrokerStartupRefused, match="no origin tuple"):
        arm_broker(_grant(with_origin=False), uid=ORG_A, lock=lock, resolver=_resolver(ADDR_A))

    # an origin that resolves to LOOPBACK is refused by the floor (loopback is never edge identity, R15).
    with pytest.raises(BrokerStartupRefused, match="egress refused"):
        arm_broker(_grant(origin="lo.example.com"), uid=ORG_A, lock=lock, resolver=_resolver("127.0.0.1"))

    # an origin that resolves to cloud METADATA / RFC1918 is refused by the never-liftable floor.
    for bad in ("169.254.169.254", "10.0.0.5", "fd00:ec2::254"):
        with pytest.raises(BrokerStartupRefused, match="egress refused"):
            arm_broker(_grant(origin="bad.example.com"), uid=ORG_A, lock=lock, resolver=_resolver(bad))

    # a well-formed public origin + a crypto lock arms cleanly.
    armed = arm_broker(_grant(), uid=ORG_A, lock=lock, require_crypto_lock=True, resolver=_resolver(ADDR_A))
    assert armed.target.sni == ORIGIN_A and armed.target.addresses == (ADDR_A,)


def test_live_transport_flag_is_default_off(monkeypatch):
    """The live-transport arming flag is strict + fail-closed + DEFAULT OFF (the ``_saas_enforce_flag``
    discipline). The deterministic resolve/floor/lock/compose plane does not depend on it."""
    monkeypatch.delenv(B.BROKER_ENV, raising=False)
    assert broker_enabled() is False
    for off in ("", "0", "no", "off", "nope", "TRUEish"):
        monkeypatch.setenv(B.BROKER_ENV, off)
        assert broker_enabled() is False
    for on in ("1", "true", "YES", "On"):
        monkeypatch.setenv(B.BROKER_ENV, on)
        assert broker_enabled() is True


def test_secret_header_lock_round_trips():
    """The secret-header lock method: a configured header value verifies; a missing/mismatched value is 401."""
    lock = OriginLock(method=LockMethod.SECRET_HEADER, secret_header_name="X-Vigil-Edge-Secret",
                      secret_header_value="s3cr3t")
    assert lock.crypto_verified is True and lock.state is LockState.CRYPTO_VERIFIED
    good = lock.sign(request_id="r", ts=NOW, client_ip="203.0.113.5")
    assert origin_lock_verify(good, lock=lock, now_ts=NOW).status == 200
    assert origin_lock_verify({}, lock=lock, now_ts=NOW).status == 401
    assert origin_lock_verify({"X-Vigil-Edge-Secret": "wrong"}, lock=lock, now_ts=NOW).status == 401


def test_module_is_fatal2_clean():
    """FATAL-2: the engine-leg broker imports only vigil_core + stdlib + framework-internal — never sigil / the
    integration layer."""
    import re
    from pathlib import Path

    src = Path(B.__file__).read_text(encoding="utf-8")
    assert not re.search(r"^\s*(from|import)\s+sigil\b", src, re.M)
    assert "vigil_integration" not in src and "apps.sigil" not in src
    # no wallclock / RNG on the signed paths or ids.
    assert "time.time" not in src and "random" not in src and "datetime.now" not in src


def test_broker_forward_strips_caller_supplied_secret_header_copy():
    """The broker is the SOLE setter of the secret-header lock. A caller-supplied copy of the credential
    header (ANY case) must be stripped before sign() applies the authentic value, so no ambiguous
    case-variant duplicate of the credential rides to the origin and the origin still verifies the real one."""
    lock = OriginLock(method=LockMethod.SECRET_HEADER,
                      secret_header_name="X-Vigil-Edge-Secret", secret_header_value="s3cr3t")
    armed = arm_broker(_grant(), uid=ORG_A, lock=lock, resolver=_resolver(ADDR_A))
    transport, _seen = _origin_transport(lock, origin_only=ORIGIN_A)
    res = broker_forward(armed, request_id="r", ts=NOW, client_ip="203.0.113.5",
                         edge_verified=True, transport=transport,
                         extra_headers={"X-VIGIL-EDGE-SECRET": "junk", "X-Other": "ok"})
    assert res.status == 200                                     # origin verified the AUTHENTIC credential
    sent = res.sent_headers
    secret_keys = [k for k in sent if k.lower() == "x-vigil-edge-secret"]
    assert secret_keys == ["X-Vigil-Edge-Secret"], sent         # exactly one copy, the broker's own casing
    assert sent["X-Vigil-Edge-Secret"] == "s3cr3t"
    assert "junk" not in set(sent.values())                     # the caller's forged copy is gone
    assert sent.get("X-Other") == "ok"                          # unrelated caller headers still pass
