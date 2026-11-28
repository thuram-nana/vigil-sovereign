"""AEGIS AS-20 (notify / SIEM outbound emitter) — deterministic, offline acceptance tests.

AS-20 is an EMITTER, not a detector, so DoD-1's "detector near-zero-FP" is N/A; it is substituted by
emission-correctness + a negative-emission control. The seven DoD points, mapped to the sections below:

  (1) e2e behavioral — a confirmed and a lead verdict each produce ONE sealed, broker-stamped POST with the
      correct header per scheme (HMAC_SIGNATURE => X-Vigil-Signature: v1=<hmac over the EXACT body>; BEARER =>
      Authorization: Bearer <tok>; HEADER_KEY => the configured header verbatim), metadata-only + hygiene-clean;
      and the negative-emission control: a "clear" verdict emits NOTHING.
  (2) gate-invariance — importing aegis leaves verify.verifier._ALL_ORACLES at exactly 15 (AS-20 adds NO
      OracleKind); notify.py is not import-reachable from aegis/__init__ or framework.v2.__main__.
  (3) FATAL-2 — notify.py imports only vigil_core + sibling framework.v2 + stdlib, never sigil/governor/strix.
  (4) determinism — same verdict => byte-identical signed body => byte-identical v1=<tag>; the injected ``now``
      is used ONLY for lease liveness, never in the signed body.
  (5) default-OFF + fail-closed — VIGIL_AEGIS_NOTIFY off => inert (no POST, no secret opened); the broker arm
      off => authorize refuses before plaintext; oversize / CR-LF-credential / non-http(s) fail CLOSED; a 5xx /
      timeout is FAIL-OPEN (data plane untouched, counted).
  (6) negative controls — mutation-sensitive per guard (hygiene gate, broker arm-check, SSRF routing, fail-open
      try/except, stale/rotated handle).
  (7) docs/registry sync — the SIEM/notify connector has an AS-7a licence-ledger record; the reported-decision
      policy stays in lockstep with the emission modules.

Every credential + KEK is generated at RUNTIME and sealed with the AS-2h primitives in-test — no real secret or
secret-shaped fixture is committed. Everything is a pure function of its inputs with an INJECTED clock.
"""
from __future__ import annotations

import ast
import hashlib
import hmac
import json
import os
import secrets
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from vigil_core.aegis_sealing import SecretKind, seal_secret
from vigil_core.authority_v2 import (
    AuthoritySubject,
    MonitoringAuthorityV2,
    MonitoringCapability,
    MonitoringLease,
    SubjectKind,
)

from framework.v2.aegis import notify as NY
from framework.v2.aegis.connector_secrets import (
    ConnectorConsumer,
    ConnectorScheme,
    ConnectorSecretBroker,
    ConsumerRegistry,
    SealedConnectorStore,
)
from framework.v2.aegis.notify import ConnectorNotifier, NotifyFormat, build_notification

ORG_A, ORG_B = "org_a", "org_b"
HOST_A = "apme.cm"
CONN = "siem_splunk_hec"
NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
URL = "https://siem.example/hook"


def _dt(offset_s: float) -> datetime:
    return NOW + timedelta(seconds=offset_s)


def _grant(*, org: str = ORG_A, nb: float = -10.0, na: float = 1.0e6) -> MonitoringAuthorityV2:
    return MonitoringAuthorityV2(
        subject=AuthoritySubject(kind=SubjectKind.HOST, org_id=org, host=HOST_A),
        capabilities=[MonitoringCapability.OBSERVE], epoch=1,
        not_before=_dt(nb), not_after=_dt(na),
        lease=MonitoringLease(not_before=_dt(nb), not_after=_dt(na)),
        instance_id="gw")


class _FixedKek:
    def __init__(self, kek: bytes) -> None:
        self._kek = kek

    def kek_for(self, org: str) -> bytes:  # noqa: ARG002
        return self._kek


class _RecordingKek:
    """A KEK source that records whether it was consulted — proves the default-OFF path opens no plaintext."""

    def __init__(self, kek: bytes) -> None:
        self._kek = kek
        self.called = False

    def kek_for(self, org: str) -> bytes:  # noqa: ARG002
        self.called = True
        return self._kek


def _seal(kek: bytes, org: str, conn: str, epoch: int, secret: bytes):
    return seal_secret(kek, SecretKind.CONNECTOR, org, conn, epoch, secret)


def _broker(scheme: ConnectorScheme, *, header: str, org: str = ORG_A, conn: str = CONN,
            credential: "bytes | None" = None, epoch: int = 1, enabled: bool = True,
            kek_source=None):
    kek = os.urandom(32)
    credential = credential if credential is not None else secrets.token_hex(24).encode("ascii")
    registry = ConsumerRegistry()
    registry.register(ConnectorConsumer(org=org, connector_id=conn, scheme=scheme, header_name=header))
    store = SealedConnectorStore()
    store.put(_seal(kek, org, conn, epoch, credential))
    ksrc = kek_source if kek_source is not None else _FixedKek(kek)
    broker = ConnectorSecretBroker(registry, store, ksrc, enabled=enabled)
    return broker, credential, store, kek


def _verdict(decision="confirmed", attack_class="sqli_attempt", action="observe", conf=0.97,
             cert=None, prov="grounded:x", contributing=None):
    return SimpleNamespace(decision=decision, attack_class=attack_class, action=action, confidence=conf,
                           certificate=cert, provenance=prov,
                           contributing=list(contributing or ["honeypot_fetch"]),
                           # raw content a leak would carry — must NEVER reach the payload:
                           path="/secret?token=abc", body="password=hunter2", actor="203.0.113.9")


class _Capture:
    """A capturing ``send`` with the push_via_urllib signature; records the one egress and returns 200."""

    def __init__(self, status: int = 200) -> None:
        self.calls: list[dict] = []
        self._status = status

    def __call__(self, url, headers, body, *, timeout=10.0):
        self.calls.append({"url": url, "headers": dict(headers or {}), "body": body})
        return {"status": self._status}


def _notifier(scheme, header, *, fmt="webhook", credential=None, enabled=True, broker_enabled=True,
              kek_source=None, **kw):
    broker, credential, store, kek = _broker(scheme, header=header, credential=credential,
                                             enabled=broker_enabled, kek_source=kek_source)
    send = kw.pop("send", None) or _Capture()
    n = ConnectorNotifier(broker, _grant(), org=ORG_A, connector_id=CONN, host=HOST_A, url=URL, fmt=fmt,
                          send=send, now_fn=lambda: NOW, enabled=enabled, **kw)
    return n, send, credential, store, kek


def _is_guarded_push(send) -> bool:
    """The default TENANT egress is ``push_via_urllib`` bound with ``block_internal=True`` (the fail-closed
    internal-destination SSRF host guard armed) — a ``functools.partial`` over the real sender, not the bare
    function."""
    import functools

    from framework.v2.report.push import push_via_urllib
    return (isinstance(send, functools.partial) and send.func is push_via_urllib
            and send.keywords.get("block_internal") is True)


# ==================================================================================================
# (1) e2e behavioral — one sealed, broker-stamped POST per confirmed/lead; the correct header per scheme;
#     metadata-only + hygiene-clean. Plus the negative-emission control (a "clear" emits NOTHING).
# ==================================================================================================
@pytest.mark.parametrize("decision", ["confirmed", "lead"])
def test_hmac_signature_posts_one_sealed_stamped_notification(decision):
    n, send, credential, _store, _kek = _notifier(ConnectorScheme.HMAC_SIGNATURE, "X-Vigil-Signature")
    n(_verdict(decision=decision))
    assert len(send.calls) == 1 and n.written == 1 and n.errors == 0
    call = send.calls[0]
    assert call["url"] == URL
    sig = call["headers"]["X-Vigil-Signature"]
    assert sig.startswith("v1=")
    # the signature is an HMAC over the EXACT bytes that were sent (sign == send).
    sent_bytes = json.dumps(call["body"]).encode("utf-8")
    expected = "v1=" + hmac.new(credential, sent_bytes, hashlib.sha256).hexdigest()
    assert sig == expected
    # the secret itself never leaves (only the tag).
    assert credential.decode() not in json.dumps(call["headers"]) + json.dumps(call["body"])


def test_bearer_scheme_stamps_authorization_bearer():
    n, send, credential, *_ = _notifier(ConnectorScheme.BEARER, "Authorization")
    n(_verdict())
    assert send.calls[0]["headers"]["Authorization"] == "Bearer " + credential.decode()


def test_header_key_scheme_stamps_configured_header_verbatim():
    n, send, credential, *_ = _notifier(ConnectorScheme.HEADER_KEY, "X-Api-Key")
    n(_verdict())
    assert send.calls[0]["headers"]["X-Api-Key"] == credential.decode()


def test_payload_is_metadata_only_and_hygiene_clean():
    n, send, _cred, *_ = _notifier(ConnectorScheme.HMAC_SIGNATURE, "X-Vigil-Signature",
                                   kek_source=None)
    # a verdict whose free-text carries a raw IP — the AS-2e scrub must redact it before egress.
    v = _verdict(attack_class="sqli from 203.0.113.9", prov="grounded:203.0.113.9")
    n(v)
    blob = json.dumps(send.calls[0]["body"])
    for leak in ("203.0.113.9", "/secret?token", "hunter2", "/secret"):
        assert leak not in blob, f"metadata-only / hygiene violated: {leak!r} leaked"
    assert "<ip>" in blob                                  # the IP WAS scrubbed, not merely absent
    ev = send.calls[0]["body"]["event"]
    assert set(ev) >= {"decision", "attack_class", "action", "confidence", "provenance_tier",
                       "certificate_sha256", "rule_refs", "event_id"}


def test_clear_verdict_emits_nothing_negative_emission_control():
    n, send, *_ = _notifier(ConnectorScheme.HMAC_SIGNATURE, "X-Vigil-Signature")
    n(_verdict(decision="clear"))
    n(None)
    n(SimpleNamespace(decision="allow"))                  # not a reported decision
    assert send.calls == [] and n.written == 0 and n.errors == 0 and n.leaked_dropped == 0


def test_canary_sentinel_is_redacted_from_the_payload():
    # a letters-only sentinel so the AS-2e literal pass is the control under test (a digit/colon-bearing token
    # would be caught first by the IP/digit scrub, which is a separate guard exercised elsewhere).
    canary = "AEGISXCANARYXSENTINELTOKEN"
    n, send, *_ = _notifier(ConnectorScheme.HMAC_SIGNATURE, "X-Vigil-Signature",
                            redact_literals=(canary,))
    n(_verdict(attack_class=f"leak of {canary} seen", contributing=[canary]))
    blob = json.dumps(send.calls[0]["body"])
    assert canary not in blob and "<redacted>" in blob


# ==================================================================================================
# (2) gate-invariance — AS-20 adds NO OracleKind; notify.py off the __init__/__main__ import path.
# ==================================================================================================
def test_importing_aegis_leaves_all_oracles_frozen_at_15():
    import framework.v2.aegis  # noqa: F401
    from framework.v2.verify import verifier as V
    assert len(V._ALL_ORACLES) == 15


def test_notify_not_import_reachable_from_init_or_main():
    root = Path(__file__).resolve().parents[4]        # repo .../engine/crucible
    code = (
        "import sys;"
        "import framework.v2.aegis;"
        "import framework.v2.__main__;"
        "assert 'framework.v2.aegis.notify' not in sys.modules, "
        "'notify.py must be OFF the __init__/__main__ import path (make-gate byte-identity)';"
        "print('OK')"
    )
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([str(root), str(root.parents[1] / "packages/core/vigil_core"),
                                         env.get("PYTHONPATH", "")])
    out = subprocess.run([sys.executable, "-c", code], cwd=str(root), env=env,
                         capture_output=True, text=True)
    assert out.returncode == 0, f"notify reachable from init/main:\n{out.stdout}\n{out.stderr}"


# ==================================================================================================
# (3) FATAL-2 — notify.py imports only vigil_core + sibling framework.v2 + stdlib (never sigil/governor).
# ==================================================================================================
def test_notify_imports_only_its_allowed_plane():
    src = Path(NY.__file__).read_text(encoding="utf-8")
    tree = ast.parse(src)
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            roots.add((node.module or "").split(".")[0])
    assert "sigil" not in roots, "notify must never import the sovereign plane (FATAL-2)"
    assert "governor" not in roots, "notify must never import the governor plane (FATAL-2)"
    assert "strix" not in roots, "notify must never import strix"
    # every ABSOLUTE root is either the shared integrity core or the stdlib — no stray third-party/engine import.
    allowed = {"vigil_core", "__future__", "functools", "itertools", "json", "os", "threading", "time",
               "datetime", "enum", "typing"}
    assert roots <= allowed, f"unexpected absolute import roots in notify.py: {sorted(roots - allowed)}"


# ==================================================================================================
# (4) determinism — same verdict => byte-identical signed body => byte-identical v1=<tag>; now only for lease.
# ==================================================================================================
def test_signed_body_is_deterministic_and_now_free():
    v = _verdict()
    b1 = NY.notification_body_bytes(build_notification(v, org=ORG_A, host=HOST_A, instance_id="gw",
                                                       epoch=1, seq=7, fmt="webhook"))
    b2 = NY.notification_body_bytes(build_notification(v, org=ORG_A, host=HOST_A, instance_id="gw",
                                                       epoch=1, seq=7, fmt="webhook"))
    assert b1 == b2                                        # same verdict+inputs -> byte-identical signed body
    # the signed tag is a pure function of (secret, body) — the injected ``now`` is used ONLY for lease
    # liveness, never in the signed bytes: two stamps over the SAME body at DIFFERENT ``now`` give one tag.
    broker, _credential, _store, _kek = _broker(ConnectorScheme.HMAC_SIGNATURE, header="X-Vigil-Signature")
    h1: dict = {}
    h2: dict = {}
    broker.stamp(broker.issue(_grant(), org=ORG_A, connector_id=CONN, now=NOW), h1, now=NOW, body=b1)
    broker.stamp(broker.issue(_grant(), org=ORG_A, connector_id=CONN, now=_dt(500.0)), h2,
                 now=_dt(500.0), body=b2)                  # DIFFERENT now, SAME body
    assert h1["X-Vigil-Signature"] == h2["X-Vigil-Signature"]


def test_signed_body_equals_sent_bytes():
    """The bytes the notifier SIGNS must equal the bytes push_via_urllib SENDS (json.dumps default)."""
    n, send, credential, *_ = _notifier(ConnectorScheme.HMAC_SIGNATURE, "X-Vigil-Signature")
    n(_verdict())
    call = send.calls[0]
    # recompute the tag over exactly what push_via_urllib would serialise from the dict it received.
    sent = json.dumps(call["body"]).encode("utf-8")
    assert call["headers"]["X-Vigil-Signature"] == "v1=" + hmac.new(credential, sent, hashlib.sha256).hexdigest()


# ==================================================================================================
# (5) default-OFF + fail-closed.
# ==================================================================================================
def test_notify_off_is_inert_no_post_no_secret_opened():
    kek = _RecordingKek(os.urandom(32))
    n, send, *_ = _notifier(ConnectorScheme.BEARER, "Authorization", enabled=False, kek_source=kek)
    n(_verdict())
    assert send.calls == [] and n.written == 0 and n.errors == 0
    assert kek.called is False, "an un-armed notifier must open NO sealed secret"


def test_notify_env_flag_is_strict_fail_closed(monkeypatch):
    monkeypatch.delenv(NY.NOTIFY_ENV, raising=False)
    assert NY.notify_enabled() is False
    monkeypatch.setenv(NY.NOTIFY_ENV, "1")
    assert NY.notify_enabled() is True
    monkeypatch.setenv(NY.NOTIFY_ENV, "on")
    assert NY.notify_enabled() is True
    monkeypatch.setenv(NY.NOTIFY_ENV, "nope")
    assert NY.notify_enabled() is False


def test_broker_arm_off_refuses_before_plaintext():
    # NOTIFY armed, BROKER default-OFF, a KEK that records if it is touched: the stamp must refuse BEFORE any open.
    kek = _RecordingKek(os.urandom(32))
    n, send, *_ = _notifier(ConnectorScheme.BEARER, "Authorization", enabled=True, broker_enabled=False,
                            kek_source=kek)
    n(_verdict())
    assert send.calls == [] and n.written == 0 and n.errors == 1
    assert kek.called is False, "the broker arm-check must refuse before any plaintext is opened"


def test_oversize_payload_is_dropped_fail_closed():
    n, send, *_ = _notifier(ConnectorScheme.HMAC_SIGNATURE, "X-Vigil-Signature", max_envelope_bytes=16)
    n(_verdict())
    assert send.calls == [] and n.written == 0 and n.errors == 1


def test_crlf_credential_is_refused_header_injection_guard():
    bad = b"token\r\nX-Injected: evil-" + secrets.token_hex(8).encode()
    n, send, *_ = _notifier(ConnectorScheme.HEADER_KEY, "X-Api-Key", credential=bad)
    n(_verdict())
    assert send.calls == [] and n.written == 0 and n.errors == 1   # dropped, no POST — the secret never leaves


def test_non_http_url_is_refused_ssrf_guard():
    # routed through the REAL push_via_urllib, a non-http(s) URL raises before any network -> no POST, counted.
    # (a PUBLIC host so the scheme refusal is the control under test; an internal-literal host would instead be
    # disarmed at construction — that fail-closed leg is test_internal_ip_literal_sink_url_never_arms.)
    broker, _cred, _store, _kek = _broker(ConnectorScheme.BEARER, header="Authorization")
    n = ConnectorNotifier(broker, _grant(), org=ORG_A, connector_id=CONN, host=HOST_A,
                          url="ftp://siem.example/x", now_fn=lambda: NOW, enabled=True)
    assert _is_guarded_push(n._send), "egress must route through push_via_urllib (the SSRF/redirect guard)"
    n(_verdict())                                       # must not raise
    assert n.written == 0 and n.errors == 1


def test_endpoint_5xx_is_fail_open_counted_never_raised():
    n, send, *_ = _notifier(ConnectorScheme.BEARER, "Authorization", send=_Capture(status=503))
    n(_verdict())                                       # a 5xx must NOT raise into the data plane
    assert n.written == 0 and n.errors == 1 and len(send.calls) == 1


def test_push_exception_is_fail_open_never_raised():
    def _boom(url, headers, body, *, timeout=10.0):
        raise RuntimeError("network down")
    n, _send, *_ = _notifier(ConnectorScheme.BEARER, "Authorization", send=_boom)
    n(_verdict())                                       # the exception must be swallowed, counted
    assert n.written == 0 and n.errors == 1


# ==================================================================================================
# (5b) SSRF internal-destination guard — the tenant egress REFUSES a loopback / link-local / RFC-1918 /
#      cloud-metadata sink (the host guard in report.push.push_via_urllib, armed via block_internal=True),
#      and a statically-internal IP-literal sink never even arms. These reds on the pre-fix code (which
#      validated only the URL *scheme* and never the destination host).
# ==================================================================================================
import framework.v2.report.push as PUSH  # noqa: E402


class _FakeResp:
    status = 202

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class _FakeOpener:
    def __init__(self) -> None:
        self.opened: list[str] = []

    def open(self, req, timeout=None):
        self.opened.append(req.full_url)
        return _FakeResp()


@pytest.mark.parametrize("bad_url", [
    "http://169.254.169.254/latest/meta-data/",          # cloud metadata (link-local)
    "http://127.0.0.1:8200/notify",                      # loopback + port
    "http://10.0.0.5/hook",                              # RFC-1918
    "http://[::1]:9200/x",                               # IPv6 loopback literal
])
def test_push_block_internal_refuses_internal_ip_literals(bad_url, monkeypatch):
    opened: list = []
    monkeypatch.setattr(PUSH.urllib.request, "build_opener",
                        lambda *a, **k: opened.append(a) or _FakeOpener())
    with pytest.raises(ValueError):                      # refused: the destination host, not just the scheme
        PUSH.push_via_urllib(bad_url, {}, {"x": 1}, block_internal=True)
    assert opened == []                                  # raised BEFORE any request was built or sent


def test_push_block_internal_refuses_hostname_resolving_to_loopback(monkeypatch):
    # a PUBLIC-looking name whose DNS resolves to loopback (classic DNS-rebind / SSRF) -> refused, no send.
    monkeypatch.setattr(PUSH.socket, "getaddrinfo",
                        lambda host, *a, **k: [(PUSH.socket.AF_INET, PUSH.socket.SOCK_STREAM, 6, "",
                                                ("127.0.0.1", 0))])
    opened: list = []
    monkeypatch.setattr(PUSH.urllib.request, "build_opener",
                        lambda *a, **k: opened.append(a) or _FakeOpener())
    with pytest.raises(ValueError):
        PUSH.push_via_urllib("http://notify.rebind.example/hook", {}, {"x": 1}, block_internal=True)
    assert opened == []


def test_push_default_block_internal_false_leaves_operator_path_unchanged(monkeypatch):
    # DEFAULT (block_internal=False): the operator-trusted report-push sink is UNCHANGED — the host guard is
    # NOT consulted even for an internal literal, and the POST proceeds (push_report / the report sink path).
    consulted: list = []
    monkeypatch.setattr(PUSH, "assert_external_destination", lambda url: consulted.append(url))
    opener = _FakeOpener()
    monkeypatch.setattr(PUSH.urllib.request, "build_opener", lambda *a, **k: opener)
    res = PUSH.push_via_urllib("http://127.0.0.1:9000/x", {}, {"a": 1})   # no block_internal
    assert res == {"status": 202}
    assert consulted == []                               # internal-host guard NOT applied on the default path
    assert opener.opened == ["http://127.0.0.1:9000/x"]


def test_push_block_internal_allows_a_public_destination(monkeypatch):
    # the guard is a *gate*, not a blanket block: a genuinely public host passes through and is delivered.
    monkeypatch.setattr(PUSH.socket, "getaddrinfo",
                        lambda host, *a, **k: [(PUSH.socket.AF_INET, PUSH.socket.SOCK_STREAM, 6, "",
                                                ("8.8.8.8", 0))])
    opener = _FakeOpener()
    monkeypatch.setattr(PUSH.urllib.request, "build_opener", lambda *a, **k: opener)
    res = PUSH.push_via_urllib("http://siem.example/hook", {}, {"a": 1}, block_internal=True)
    assert res == {"status": 202} and opener.opened == ["http://siem.example/hook"]


@pytest.mark.parametrize("bad_url", [
    "http://169.254.169.254/latest/meta-data/",
    "http://127.0.0.1:9200/",
    "http://10.0.0.5/hook",
    "http://[::1]:8080/x",
])
def test_internal_ip_literal_sink_url_never_arms_fail_closed(bad_url):
    # fail-closed at CONSTRUCTION: a statically-internal IP-literal sink is inert for life — even pinned on.
    broker, *_ = _broker(ConnectorScheme.BEARER, header="Authorization")
    send = _Capture()
    n = ConnectorNotifier(broker, _grant(), org=ORG_A, connector_id=CONN, host=HOST_A, url=bad_url,
                          send=send, now_fn=lambda: NOW, enabled=True)
    assert n._enabled is False                           # the internal-literal sink disarmed the notifier
    n(_verdict())
    assert send.calls == [] and n.written == 0 and n.errors == 0   # inert: no build, no secret, no POST


def test_notifier_egress_refuses_hostname_resolving_to_internal(monkeypatch):
    # a PUBLIC-looking sink host (construction does NOT disarm — it is not a literal): the egress guard
    # re-resolves at send and refuses the loopback -> no POST, counted (fail-open on the data plane).
    monkeypatch.setattr(PUSH.socket, "getaddrinfo",
                        lambda host, *a, **k: [(PUSH.socket.AF_INET, PUSH.socket.SOCK_STREAM, 6, "",
                                                ("127.0.0.1", 0))])
    broker, *_ = _broker(ConnectorScheme.BEARER, header="Authorization")
    n = ConnectorNotifier(broker, _grant(), org=ORG_A, connector_id=CONN, host=HOST_A,
                          url="http://notify.rebind.example/hook", now_fn=lambda: NOW, enabled=True)
    assert n._enabled is True and _is_guarded_push(n._send)
    n(_verdict())
    assert n.written == 0 and n.errors == 1


# ==================================================================================================
# (5c) added coverage — the rate-cap drop path, the lease-EXPIRY handle re-issue (distinct from epoch
#      rotation), the epoch_fn-raising fallback, and the atomic fan-out counters under thread fan-out.
# ==================================================================================================
def test_rate_cap_drop_path_counts_dropped_and_sends_nothing_extra():
    # over the per-minute cap: the surplus is DROPPED (self.dropped++), no POST, not an error. Fixed monotonic
    # clock pins the minute bucket so the count is deterministic.
    n, send, *_ = _notifier(ConnectorScheme.BEARER, "Authorization",
                            max_per_minute=2, monotonic_fn=lambda: 100.0)
    for _ in range(5):
        n(_verdict())
    assert len(send.calls) == 2 and n.written == 2 and n.dropped == 3 and n.errors == 0


def test_cached_handle_lease_expiry_reissues_distinct_from_rotation():
    # the TIME-expiry leg of _ensure_handle: when the cached handle's lease has lapsed (no rotation — the store
    # stays at epoch 1), a FRESH handle is issued and the emit succeeds. Remove the lease_live() re-issue and
    # the stale handle would reach the broker and be refused for an expired lease -> written stays 1.
    clock = {"t": NOW}
    broker, _credential, _store, _kek = _broker(ConnectorScheme.BEARER, header="Authorization")
    send = _Capture()
    n = ConnectorNotifier(broker, _grant(), org=ORG_A, connector_id=CONN, host=HOST_A, url=URL,
                          send=send, now_fn=lambda: clock["t"], enabled=True, lease_seconds=100.0)
    n(_verdict())                                        # issues a handle leased until NOW+100s
    first = n._handle
    assert n.written == 1 and first is not None and len(send.calls) == 1
    clock["t"] = _dt(500.0)                              # advance PAST the lease (pure time-expiry)
    n(_verdict())
    assert n.written == 2 and len(send.calls) == 2       # a fresh handle was re-issued and the emit succeeded
    assert n._handle is not first and n._handle.epoch == 1 and n.errors == 0  # same epoch => NOT a rotation


def test_epoch_fn_raising_falls_back_to_epoch_zero_and_still_emits():
    def _boom_epoch() -> int:
        raise RuntimeError("epoch source down")
    n, send, *_ = _notifier(ConnectorScheme.BEARER, "Authorization", epoch_fn=_boom_epoch)
    n(_verdict())                                        # a bad epoch_fn must NOT sink the notify
    assert n.written == 1 and len(send.calls) == 1 and n.errors == 0
    assert send.calls[0]["body"]["event"]["epoch"] == 0  # the emitted event carries the epoch=0 fallback


def test_fanout_counters_are_atomic_under_thread_fanout():
    # serve_gateway fans this sink across threads; a bare `self.written += 1` can lose updates. With the bumps
    # taken under self._lock the totals are EXACT. (On the pre-fix read-add-write this can under-count.)
    import threading as _threading

    n, send, *_ = _notifier(ConnectorScheme.BEARER, "Authorization",
                            max_per_minute=10_000, monotonic_fn=lambda: 0.0)
    total = 2000
    threads = [_threading.Thread(target=lambda: n(_verdict())) for _ in range(total)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(send.calls) == total                      # every admitted verdict POSTed (under the cap)
    assert n.written == total and n.errors == 0 and n.dropped == 0


# ==================================================================================================
# (6) negative controls — mutation-sensitive per guard.
# ==================================================================================================
def test_negative_control_final_hygiene_gate_drops_a_leaking_body(monkeypatch):
    """If a raw IP survives into the serialised body (e.g. a future field slips the pre-scrub), the FINAL
    fail-closed gate DROPS it with no POST. Remove the gate -> the leak is emitted -> this test reds."""
    n, send, *_ = _notifier(ConnectorScheme.HMAC_SIGNATURE, "X-Vigil-Signature")

    def _leaky_body(payload):
        return json.dumps({**dict(payload), "_leak": "203.0.113.9"}).encode("utf-8")

    monkeypatch.setattr(NY, "notification_body_bytes", _leaky_body)
    n(_verdict())
    assert send.calls == [] and n.leaked_dropped == 1 and n.written == 0


def test_negative_control_stale_rotated_handle_is_refused():
    """A rotation between emits makes the cached handle's epoch stale; the broker refuses and the notifier
    drops it with no POST (then re-issues). Remove the broker's epoch check -> the stale handle opens the new
    secret and POSTs -> this test reds."""
    n, send, _cred, store, kek = _notifier(ConnectorScheme.BEARER, "Authorization")
    n(_verdict())                                       # caches a handle pinned at epoch 1
    assert n.written == 1 and len(send.calls) == 1
    store.put(_seal(kek, ORG_A, CONN, 2, secrets.token_hex(24).encode("ascii")))   # supersede -> epoch 2
    n(_verdict())                                       # the cached epoch-1 handle is now stale
    assert len(send.calls) == 1 and n.errors == 1       # NO second POST; refused + counted
    # the stale handle was dropped -> a subsequent emit re-issues a fresh (epoch-2) handle and succeeds.
    n(_verdict())
    assert len(send.calls) == 2 and n.written == 2


def test_negative_control_default_send_is_push_via_urllib():
    broker, *_ = _broker(ConnectorScheme.BEARER, header="Authorization")
    n = ConnectorNotifier(broker, _grant(), org=ORG_A, connector_id=CONN, host=HOST_A, url=URL)
    assert _is_guarded_push(n._send)                     # push_via_urllib bound with block_internal=True


def test_cross_tenant_grant_is_refused_through_the_notifier():
    broker, _cred, _store, _kek = _broker(ConnectorScheme.BEARER, header="Authorization")
    # a grant that binds a DIFFERENT org can never issue this org's handle (tenant isolation at issue()).
    n = ConnectorNotifier(broker, _grant(org=ORG_B), org=ORG_A, connector_id=CONN, host=HOST_A, url=URL,
                          send=_Capture(), now_fn=lambda: NOW, enabled=True)
    n(_verdict())
    assert n.written == 0 and n.errors == 1


# ==================================================================================================
# (7) docs/registry sync — the SIEM/notify connector is ledgered (AS-7a); the policy stays in lockstep.
# ==================================================================================================
def test_reported_decisions_match_emission_policy():
    from framework.v2.aegis import monitoring_event_v2 as E
    from framework.v2.aegis import monitoring_report as R
    assert NY._REPORTED_DECISIONS == E._REPORTED_DECISIONS == R._REPORTED_DECISIONS


def test_siem_notify_connector_has_a_licence_ledger_record():
    from framework.v2.aegis.license_gate import LicenseGate, load_ledger
    ledger = load_ledger()
    artefacts = {r.artefact for r in ledger}
    assert "aegis-siem-notify-connector" in artefacts, "AS-20 needs an AS-7a licence record (R1 completeness)"
    # the ledger as a whole still passes the deploy-time gate (complete, consistent, policy-clean).
    assert LicenseGate().check(ledger).passed is True


def test_gateway_serve_seam_composes_the_notifier():
    """The notifier wires into the gateway serve seam via compose_sinks alongside the other on_verdict sinks."""
    from framework.v2.aegis.gateway import serve_gateway
    from framework.v2.aegis.models import AegisConfig

    seen: list[str] = []
    httpd = serve_gateway("http://127.0.0.1:3000", config=AegisConfig(deployment_secret="x" * 24),
                          host="127.0.0.1", port=0,
                          on_verdict=lambda v: seen.append("base"),
                          notify_notifier=lambda v: seen.append("notify"))
    try:
        httpd.settings.on_verdict(_verdict())
        assert seen == ["base", "notify"]               # both sinks fired, fan-out composed
        assert httpd.settings.notify_notifier is not None
    finally:
        httpd.server_close()


# ==================================================================================================
# CLI surface — the --notify-* gateway flags (operator intent + fail-closed validation).
# ==================================================================================================
def _gw_args(**over):
    import argparse
    base = dict(upstream="http://127.0.0.1:3000", host="127.0.0.1", port=0, mode="observe",
                slug="aegis-gateway", secret="realsecret-abc-123", honeypot=None, oob_canary=None,
                canary=None, verdicts_out=None, status_out=None, verdict_webhook=None, verdict_sink="webhook",
                notify_connector=None, notify_url=None, notify_format="webhook")
    base.update(over)
    return argparse.Namespace(**base)


def test_cli_notify_connector_requires_url_fail_closed(monkeypatch):
    from framework.v2.aegis import cli as C
    for k in ("AEGIS_GW_NOTIFY_URL", "AEGIS_GW_NOTIFY_CONNECTOR"):
        monkeypatch.delenv(k, raising=False)
    assert C._cmd_gateway(_gw_args(notify_connector="siem_x", notify_url=None)) == 2


def test_cli_notify_intent_recorded_without_a_provider(monkeypatch):
    from framework.v2.aegis import cli as C
    import framework.v2.aegis.cli as Cmod

    captured: dict = {}

    class _Httpd:
        class settings:  # noqa: N801
            enforce = False
            oob_receiver = None
            on_verdict = staticmethod(lambda v: None)
            notify_notifier = None

            @staticmethod
            def enforcement_status():
                return {"enforcing": False, "downgraded": False, "downgrade_reason": None}

            @staticmethod
            def stop_oob():
                pass

        def serve_forever(self):
            raise KeyboardInterrupt

        def server_close(self):
            pass

    def _fake_serve(upstream, **kw):
        captured["kw"] = kw
        return _Httpd()

    import framework.v2.aegis.gateway as Gmod
    monkeypatch.setattr(Gmod, "serve_gateway", _fake_serve)
    monkeypatch.setattr(Cmod, "_NOTIFY_BROKER_PROVIDER", None)
    rc = C._cmd_gateway(_gw_args(notify_connector="siem_x", notify_url="https://siem.example/hook",
                                 notify_format="slack"))
    assert rc == 0
    # no provider => the intent is recorded but no notifier is fabricated from bare flags (no secret handling).
    assert captured["kw"].get("notify_notifier") is None


def test_cli_notify_wires_notifier_when_a_provider_is_injected(monkeypatch):
    from framework.v2.aegis import cli as C
    import framework.v2.aegis.cli as Cmod

    captured: dict = {}

    class _Httpd:
        class settings:  # noqa: N801
            enforce = False
            oob_receiver = None
            on_verdict = staticmethod(lambda v: None)
            notify_notifier = None

            @staticmethod
            def enforcement_status():
                return {"enforcing": False, "downgraded": False, "downgrade_reason": None}

            @staticmethod
            def stop_oob():
                pass

        def serve_forever(self):
            raise KeyboardInterrupt

        def server_close(self):
            pass

    def _fake_serve(upstream, **kw):
        captured["kw"] = kw
        return _Httpd()

    broker, *_ = _broker(ConnectorScheme.BEARER, header="Authorization")

    def _provider(connector_id, tenant, host):
        return (broker, _grant())

    import framework.v2.aegis.gateway as Gmod
    monkeypatch.setattr(Gmod, "serve_gateway", _fake_serve)
    monkeypatch.setattr(Cmod, "_NOTIFY_BROKER_PROVIDER", _provider)
    rc = C._cmd_gateway(_gw_args(saas_tenant=ORG_A, saas_host=HOST_A, notify_connector=CONN,
                                 notify_url="https://siem.example/hook"))
    assert rc == 0
    assert isinstance(captured["kw"].get("notify_notifier"), ConnectorNotifier)
