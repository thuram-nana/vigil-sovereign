"""live_transport — the REAL httpx binding for the E-series ``Transport`` seam.

These tests are OFFLINE and deterministic: they exercise the provenance extractors — the part that decides
what a certificate will claim about the network — against hand-built stand-ins for a connection, including
the connections that CANNOT be characterised. The single property under test throughout is that no field
ever degrades to the permissive value: a socket we cannot introspect, a TLS object with no validated
certificate, a client that might read proxy env, a body too large to hold — each must produce the answer
that makes the oracle REFUSE.

The SigV4 signer is checked against botocore's independent implementation (a real known-answer
differential), not against itself.
"""
from __future__ import annotations

import ssl
from datetime import datetime, timezone

import pytest

from vigil_integration.live.live_transport import (
    _parse_json, _read_bounded, _sigv4_headers, _verifying_ssl_context,
    redirected_of, resolved_peer_of, tls_verified_of, via_proxy_of,
)


# -- stand-ins for a connection ---------------------------------------------------------------------
class _Stream:
    """A network stream that answers ``get_extra_info`` the way httpcore's does — or refuses to."""

    def __init__(self, info: dict, raises: bool = False) -> None:
        self._info, self._raises = info, raises

    def get_extra_info(self, key: str):
        if self._raises:
            raise OSError("socket is gone")
        return self._info.get(key)


class _SSLObject:
    def __init__(self, cert, raises: bool = False) -> None:
        self._cert, self._raises = cert, raises

    def getpeercert(self):
        if self._raises:
            raise ssl.SSLError("no session")
        return self._cert


class _Response:
    def __init__(self, *, stream=None, status=200, history=(), no_extensions=False) -> None:
        self.status_code = status
        self.history = list(history)
        if no_extensions:
            self.extensions = None            # attribute access will raise on .get
        else:
            self.extensions = {"network_stream": stream} if stream is not None else {}


class _Client:
    def __init__(self, mounts=None, trust_env=False) -> None:
        if mounts is not None:
            self._mounts = mounts
        if trust_env is not None:
            self.trust_env = trust_env


def _verifying() -> ssl.SSLContext:
    return _verifying_ssl_context()


# -- resolved_peer: the ACTUAL peer, or nothing -----------------------------------------------------
def test_resolved_peer_is_the_socket_peer_not_a_re_resolution() -> None:
    r = _Response(stream=_Stream({"server_addr": ("140.82.121.6", 443)}))
    assert resolved_peer_of(r) == "140.82.121.6"


def test_resolved_peer_accepts_a_bare_string_peer() -> None:
    assert resolved_peer_of(_Response(stream=_Stream({"server_addr": " 10.0.0.9 "}))) == "10.0.0.9"


@pytest.mark.parametrize("response", [
    _Response(),                                             # no network stream at all
    _Response(stream=_Stream({}, raises=True)),              # the socket refuses to say
    _Response(stream=_Stream({"server_addr": None})),        # nothing recorded
    _Response(stream=_Stream({"server_addr": ()})),          # an empty tuple is not an address
    _Response(no_extensions=True),                           # extensions unavailable
])
def test_resolved_peer_is_empty_when_it_cannot_be_established(response) -> None:
    # An unrecorded peer is the oracle's `confirming_call_peer_unrecorded` refusal — never a guess.
    assert resolved_peer_of(response) == ""


# -- tls_verified: derived from the connection, never asserted --------------------------------------
def test_tls_verified_true_only_with_a_validated_peer_certificate() -> None:
    stream = _Stream({"ssl_object": _SSLObject({"subject": ((("commonName", "api.github.com"),),)})})
    assert tls_verified_of(_Response(stream=stream), _verifying(), "https") is True


def test_tls_verified_false_for_plain_http_even_with_a_tls_object_present() -> None:
    stream = _Stream({"ssl_object": _SSLObject({"subject": "x"})})
    assert tls_verified_of(_Response(stream=stream), _verifying(), "http") is False


def test_tls_verified_false_when_the_peer_certificate_is_empty() -> None:
    # CPython returns {} from getpeercert() when the peer was NOT validated. That is the whole signal.
    stream = _Stream({"ssl_object": _SSLObject({})})
    assert tls_verified_of(_Response(stream=stream), _verifying(), "https") is False


def test_tls_verified_false_when_the_context_does_not_actually_verify() -> None:
    lax = ssl.create_default_context()
    lax.check_hostname = False
    lax.verify_mode = ssl.CERT_NONE
    stream = _Stream({"ssl_object": _SSLObject({"subject": "x"})})
    assert tls_verified_of(_Response(stream=stream), lax, "https") is False


def test_tls_verified_false_when_hostname_checking_is_off() -> None:
    no_host = ssl.create_default_context()
    no_host.check_hostname = False           # still CERT_REQUIRED, but the name is unchecked
    stream = _Stream({"ssl_object": _SSLObject({"subject": "x"})})
    assert tls_verified_of(_Response(stream=stream), no_host, "https") is False


@pytest.mark.parametrize("response", [
    _Response(),                                                    # no stream
    _Response(stream=_Stream({}, raises=True)),                     # socket refuses
    _Response(stream=_Stream({"ssl_object": None})),                # no TLS on this connection
    _Response(stream=_Stream({"ssl_object": _SSLObject(None, raises=True)})),   # cert unreadable
])
def test_tls_verified_false_when_it_cannot_be_established(response) -> None:
    assert tls_verified_of(response, _verifying(), "https") is False


def test_tls_verified_false_without_a_context() -> None:
    stream = _Stream({"ssl_object": _SSLObject({"subject": "x"})})
    assert tls_verified_of(_Response(stream=stream), None, "https") is False


def test_a_non_verifying_context_can_never_be_built() -> None:
    ctx = _verifying_ssl_context()
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname is True


# -- via_proxy: False only when provably impossible -------------------------------------------------
def test_no_proxy_only_when_env_is_untrusted_and_no_mounts_exist() -> None:
    assert via_proxy_of(_Client(mounts={}, trust_env=False)) is False


def test_proxy_reported_when_a_mount_exists() -> None:
    assert via_proxy_of(_Client(mounts={"all://": object()}, trust_env=False)) is True


def test_proxy_reported_when_the_client_reads_ambient_env() -> None:
    # trust_env=True means HTTPS_PROXY/ALL_PROXY could silently interpose; we cannot claim otherwise.
    assert via_proxy_of(_Client(mounts={}, trust_env=True)) is True


def test_proxy_reported_when_the_client_cannot_be_characterised() -> None:
    class _Opaque:
        pass
    assert via_proxy_of(_Opaque()) is True


# -- redirected: a 3xx is evidence, not something to chase ------------------------------------------
@pytest.mark.parametrize("status", [301, 302, 307, 308, 399])
def test_a_3xx_is_reported_as_redirected(status: int) -> None:
    assert redirected_of(_Response(status=status)) is True


def test_a_followed_redirect_history_is_reported() -> None:
    assert redirected_of(_Response(status=200, history=[object()])) is True


def test_a_direct_200_is_not_redirected() -> None:
    assert redirected_of(_Response(status=200)) is False


def test_redirected_when_the_status_cannot_be_read() -> None:
    class _Broken:
        history: list = []

        @property
        def status_code(self):
            raise RuntimeError("no status")
    assert redirected_of(_Broken()) is True


# -- bounded read: a truncated body is never parsed --------------------------------------------------
class _Body:
    def __init__(self, chunks) -> None:
        self._chunks = chunks

    def iter_bytes(self):
        yield from self._chunks


def test_a_body_within_the_cap_is_complete() -> None:
    body, truncated = _read_bounded(_Body([b'{"login":"x",', b'"id":1}']), 65536)
    assert body == b'{"login":"x","id":1}' and truncated is False


def test_an_oversized_body_is_capped_and_flagged_truncated() -> None:
    body, truncated = _read_bounded(_Body([b"a" * 40, b"b" * 40]), 50)
    assert len(body) == 50 and truncated is True


def test_a_truncated_body_is_never_parsed_into_an_identity_echo() -> None:
    # Half a JSON document cannot honestly supply an identity; a partial parse would be evidence
    # about bytes we do not have.
    assert _parse_json(b'{"login":"x","id":1}', truncated=True) is None
    assert _parse_json(b'{"login":"x","id":1}', truncated=False) == {"login": "x", "id": 1}


def test_unparseable_and_non_object_bodies_yield_no_json() -> None:
    assert _parse_json(b"not json", truncated=False) is None
    assert _parse_json(b"[1,2,3]", truncated=False) is None      # a list is not an identity echo
    assert _parse_json(b"", truncated=False) is None


# -- SigV4: checked against an independent implementation --------------------------------------------
def test_sigv4_matches_botocore_for_a_real_sts_getcalleridentity_request() -> None:
    botocore_auth = pytest.importorskip("botocore.auth", reason="botocore not installed here")
    from botocore.awsrequest import AWSRequest
    from botocore.credentials import Credentials

    url, body = "https://sts.amazonaws.com/", b"Action=GetCallerIdentity&Version=2011-06-15"
    akid, secret = "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"

    request = AWSRequest(method="POST", url=url, data=body,
                         headers={"Content-Type": "application/x-www-form-urlencoded"})
    signer = botocore_auth.SigV4Auth(Credentials(akid, secret), "sts", "us-east-1")
    signer.add_auth(request)
    # botocore stamps its own clock; adopt THAT instant so the two signatures are over the same request
    # and the comparison is a genuine known-answer differential rather than two clocks disagreeing.
    when = datetime.strptime(request.headers["X-Amz-Date"], "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)

    ours = _sigv4_headers(method="POST", url=url, body=body, access_key_id=akid,
                          secret_access_key=secret, session_token="", region="us-east-1",
                          service="sts", now=when)

    assert ours["X-Amz-Date"] == request.headers["X-Amz-Date"]
    assert ours["Authorization"] == request.headers["Authorization"]


def test_sigv4_binds_the_session_token_into_the_signature() -> None:
    when = datetime(2015, 8, 30, 12, 36, 0, tzinfo=timezone.utc)
    common = dict(method="POST", url="https://sts.us-east-2.amazonaws.com/", body=b"Action=X",
                  access_key_id="ASIAIOSFODNN7EXAMPLE",
                  secret_access_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
                  region="us-east-2", service="sts", now=when)
    without = _sigv4_headers(session_token="", **common)
    with_token = _sigv4_headers(session_token="FQoGZXIvYXdzEXAMPLE", **common)
    assert "x-amz-security-token" in with_token["Authorization"]
    assert with_token["X-Amz-Security-Token"] == "FQoGZXIvYXdzEXAMPLE"
    assert without["Authorization"] != with_token["Authorization"]


def test_sigv4_signature_changes_with_the_signed_body() -> None:
    when = datetime(2015, 8, 30, 12, 36, 0, tzinfo=timezone.utc)
    common = dict(method="POST", url="https://sts.amazonaws.com/", access_key_id="AKIAIOSFODNN7EXAMPLE",
                  secret_access_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", session_token="",
                  region="us-east-1", service="sts", now=when)
    a = _sigv4_headers(body=b"Action=GetCallerIdentity&Version=2011-06-15", **common)
    b = _sigv4_headers(body=b"Action=SomethingElse", **common)
    assert a["Authorization"] != b["Authorization"]
