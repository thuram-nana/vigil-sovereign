"""E5 — the WARDEN-gated exposed-secret VALIDATION runner (live half). Unit-tested with a MOCK transport
(no network): the runner produces a capture the OFFLINE oracle confirms as a valid exposed secret, performs
the secret lifecycle (no plaintext survives; the confirming call carries the same fingerprint as the
credential), REFUSES before any I/O when WARDEN, the charter scope gate, or the exfil floor denies, and
faithfully records a FAILED confirming call so the oracle correctly leaves it a LEAD.

The live-fire against the real provider is ``tools/livefire/secret_github_livefire.sh`` (credential-gated,
never run in CI).
"""
from __future__ import annotations

import pytest

pytest.importorskip("framework.v2.verify.confirmation", reason="CRUCIBLE not importable here")

from vigil_integration.live.imds_runner import TransportResult  # noqa: E402
from vigil_integration.live.secret_runner import (  # noqa: E402
    _SECRET_TYPES, run_secret_validation, secret_fingerprint,
)

_GH_ENDPOINT = "https://api.github.com/user"
_GH_TOKEN = "ghp_ThisIsAFakeTokenForTestsOnly000000"
_GH_USER = {"login": "octocat", "id": 583231, "type": "User"}
_STS_JSON = {"GetCallerIdentityResponse": {"GetCallerIdentityResult": {
    "Arn": "arn:aws:iam::123456789012:user/leaked", "Account": "123456789012",
    "UserId": "AIDAEXAMPLEUSERID"}}}


class _AllowGate:
    def authorize(self, *_a):
        return True, "in scope"


class _DenyGate:
    def authorize(self, *_a):
        return False, "resource not in signed charter scope"


def _factory(body, *, status=200, peer="140.82.121.6", tls=True, proxy=False, redirected=False,
             raw=b'{"login":"octocat","id":583231}'):
    """A mock credential-transport FACTORY. Records the secret it was handed and every call issued, so a
    test can prove the fingerprinted string is the one that authenticated."""
    seen: dict = {"secrets": [], "calls": []}

    def factory(secret: str):
        seen["secrets"].append(secret)

        def transport(method: str, url: str) -> TransportResult:
            seen["calls"].append((method, url))
            return TransportResult(status=status, body=raw, resolved_peer=peer, tls_verified=tls,
                                   via_proxy=proxy, redirected=redirected, json=body)
        return transport

    return factory, seen


def _run(factory, *, secret_type="github_pat", secret=_GH_TOKEN, authorize=lambda: (True, "ok"),
         gate=None, **kwargs):
    return run_secret_validation(
        secret_type, secret=secret, source="js:app.min.js:1024", authorize=authorize,
        scope_gate=gate or _AllowGate(), scope=("github", "octocat", "", "user"),
        credential_transport=factory, **kwargs)


# -- the happy path: a real capture the offline oracle confirms ---------------------------------------
def test_runner_produces_a_capture_the_oracle_confirms_for_a_github_pat() -> None:
    from framework.v2.verify import confirm_secret_capture, exposed_secret_validity_oracle

    factory, seen = _factory(_GH_USER)
    res = _run(factory)
    assert res.status == "captured" and res.capture is not None
    assert exposed_secret_validity_oracle(res.capture).fired
    assert confirm_secret_capture(res.capture).confirmed
    assert seen["calls"] == [("GET", _GH_ENDPOINT)]


def test_runner_produces_a_capture_the_oracle_confirms_for_an_aws_access_key() -> None:
    from framework.v2.verify import exposed_secret_validity_oracle

    factory, seen = _factory(_STS_JSON, peer="72.21.206.80", raw=b'{"GetCallerIdentityResponse":1}')
    res = _run(factory, secret_type="aws_access_key", secret="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEX",
               identifier="AKIAZZ7EXAMPLE0KEY01")
    assert res.status == "captured"
    # the nested STS JSON envelope is unwrapped to the flat identity the oracle's extractor reads
    assert res.capture["confirming_call"]["response"] == {
        "Arn": "arn:aws:iam::123456789012:user/leaked", "Account": "123456789012",
        "UserId": "AIDAEXAMPLEUSERID"}
    assert exposed_secret_validity_oracle(res.capture).fired
    assert seen["calls"] == [("POST", "https://sts.amazonaws.com/")]


def test_a_regional_sts_endpoint_is_used_when_a_region_is_given() -> None:
    factory, seen = _factory(_STS_JSON)
    _run(factory, secret_type="aws_access_key", secret="secretkey", identifier="AKIAZZ7EXAMPLE0KEY01",
         region="eu-west-1")
    assert seen["calls"] == [("POST", "https://sts.eu-west-1.amazonaws.com/")]


# -- the secret lifecycle -----------------------------------------------------------------------------
def test_no_plaintext_secret_survives_into_the_capture() -> None:
    factory, _ = _factory(_GH_USER)
    capture = _run(factory).capture
    assert _GH_TOKEN not in repr(capture)
    assert capture["credential"]["secret"] == "[REDACTED]"
    # only the structural PREFIX is retained as the non-secret identifier — never the token body
    assert capture["credential"]["identifier"] == "ghp_"


def test_the_confirming_call_is_bound_to_the_exact_secret_that_was_fingerprinted() -> None:
    factory, seen = _factory(_GH_USER)
    capture = _run(factory).capture
    expected = secret_fingerprint(_GH_TOKEN)
    assert capture["credential"]["credential_fingerprint"] == expected
    assert capture["confirming_call"]["credential_fingerprint"] == expected
    # the binding is CONSTRUCTED, not assumed: the transport was built from that same string.
    assert seen["secrets"] == [_GH_TOKEN]


def test_the_e5_fingerprint_domain_is_separated_from_e1() -> None:
    from vigil_integration.live.imds_runner import credential_fingerprint
    assert secret_fingerprint("same-bytes") != credential_fingerprint("same-bytes")


def test_transport_provenance_is_recorded_as_the_transport_reported_it() -> None:
    factory, _ = _factory(_GH_USER, peer="140.82.121.6", tls=True, proxy=False, redirected=False)
    call = _run(factory).capture["confirming_call"]
    assert call["resolved_peer"] == "140.82.121.6"
    assert call["tls_verified"] is True and call["no_proxy"] is True and call["no_redirect"] is True
    assert call["response_digest"].startswith("sha256:")
    assert call["action"] == "github:GET /user" and call["endpoint"] == _GH_ENDPOINT


# -- the gates, all BEFORE any I/O --------------------------------------------------------------------
def test_warden_refusal_happens_before_the_transport_is_ever_built() -> None:
    factory, seen = _factory(_GH_USER)
    res = _run(factory, authorize=lambda: (False, "kill-switch tripped"))
    assert res.status == "refused" and "kill-switch tripped" in res.reason
    assert res.capture is None                      # nothing to adjudicate ⇒ nothing to launder
    assert seen["secrets"] == [] and seen["calls"] == []


def test_scope_refusal_happens_before_the_transport_is_ever_built() -> None:
    factory, seen = _factory(_GH_USER)
    res = _run(factory, gate=_DenyGate())
    assert res.status == "refused" and "not in signed charter scope" in res.reason
    assert res.capture is None and seen["secrets"] == [] and seen["calls"] == []


def test_the_gates_run_in_order_warden_first() -> None:
    factory, _ = _factory(_GH_USER)
    res = _run(factory, authorize=lambda: (False, "kill-switch tripped"), gate=_DenyGate())
    assert res.reason.startswith("WARDEN refused")   # WARDEN is consulted before the charter scope


@pytest.mark.parametrize("endpoint", [
    "http://api.github.com/user",                    # plaintext: a live credential must never go in clear
    "https://attacker.example.com/user",             # a laundering endpoint
    "https://api.github.com.evil.test/user",         # a suffix-confusion lookalike
    "https://sts.amazonaws.com/",                    # right shape, WRONG type for a github_pat
    "not a url at all",
])
def test_the_exfil_floor_refuses_to_send_a_live_secret_off_the_allow_list(endpoint: str) -> None:
    factory, seen = _factory(_GH_USER)
    res = _run(factory, endpoint=endpoint)
    assert res.status == "refused" and res.capture is None
    assert seen["secrets"] == [] and seen["calls"] == []      # the credential never reached a transport


def test_an_unsupported_secret_type_is_refused_before_anything_else() -> None:
    factory, seen = _factory(_GH_USER)
    res = _run(factory, secret_type="slack_webhook")
    assert res.status == "unsupported_secret_type" and res.capture is None
    assert seen["secrets"] == []


def test_an_empty_secret_is_refused_rather_than_fingerprinted() -> None:
    factory, seen = _factory(_GH_USER)
    res = _run(factory, secret="   ")
    assert res.status == "no_secret" and res.capture is None and seen["secrets"] == []


# -- honest failures: the runner records, the ORACLE adjudicates ---------------------------------------
def test_a_401_confirming_call_is_captured_faithfully_and_does_not_fire() -> None:
    from framework.v2.verify import exposed_secret_validity_oracle

    factory, _ = _factory({"message": "Bad credentials"}, status=401,
                          raw=b'{"message":"Bad credentials"}')
    res = _run(factory)
    assert res.status == "captured"                              # the runner reports; it does not judge
    assert res.capture["confirming_call"]["status"] == 401
    signal = exposed_secret_validity_oracle(res.capture)
    assert not signal.fired and signal.observed["reason"] == "confirming_call_failed"


def test_a_token_whose_shape_is_unrecognised_yields_no_identifier_and_does_not_fire() -> None:
    from framework.v2.verify import exposed_secret_validity_oracle

    factory, _ = _factory(_GH_USER)
    res = _run(factory, secret="not-a-github-token")
    assert res.capture["credential"]["identifier"] == ""
    signal = exposed_secret_validity_oracle(res.capture)
    assert not signal.fired and signal.observed["reason"] == "secret_identifier_malformed"


@pytest.mark.parametrize("kwargs,expected", [
    ({"tls": False}, "confirming_call_tls_unverified"),
    ({"proxy": True}, "confirming_call_transport_not_direct"),
    ({"redirected": True}, "confirming_call_transport_not_direct"),
    ({"peer": ""}, "confirming_call_peer_unrecorded"),
])
def test_an_untrusted_transport_is_recorded_honestly_and_never_fires(kwargs, expected) -> None:
    from framework.v2.verify import exposed_secret_validity_oracle

    factory, _ = _factory(_GH_USER, **kwargs)
    signal = exposed_secret_validity_oracle(_run(factory).capture)
    assert not signal.fired and signal.observed["reason"] == expected


def test_an_identity_echo_the_extractor_rejects_never_fires() -> None:
    from framework.v2.verify import exposed_secret_validity_oracle

    factory, _ = _factory({"login": "", "id": 0})      # a degenerate identity is not proof of auth
    signal = exposed_secret_validity_oracle(_run(factory).capture)
    assert not signal.fired and signal.observed["reason"] == "identity_echo_absent"


# -- drift: the runner's table must agree with the oracle's recognizer set -----------------------------
def test_the_runner_table_does_not_drift_from_the_oracle_recognizer_set() -> None:
    """The runner duplicates the oracle's per-type table (it must stay offense-import-free). A one-sided
    edit would silently produce captures the oracle can never confirm, so pin them together here."""
    from framework.v2.verify.oracles import _SECRET_RECOGNIZERS

    assert set(_SECRET_TYPES) == set(_SECRET_RECOGNIZERS)
    for secret_type, spec in _SECRET_TYPES.items():
        recognizer = _SECRET_RECOGNIZERS[secret_type]
        # the oracle compares the action case-folded; the runner must emit a string that matches
        assert spec["action"].strip().lower() == recognizer["action"]
        for host in ("api.github.com", "sts.amazonaws.com", "sts.eu-west-1.amazonaws.com",
                     "attacker.example.com", "api.github.com.evil.test", "sts.amazonaws.com.evil.test"):
            assert spec["host_ok"](host) == recognizer["host_ok"](host), (secret_type, host)


def test_every_supported_type_defaults_to_an_endpoint_its_own_allow_list_accepts() -> None:
    from urllib.parse import urlsplit
    for secret_type, spec in _SECRET_TYPES.items():
        for region in ("", "us-east-1"):
            host = urlsplit(spec["endpoint"](region)).hostname
            assert spec["host_ok"](host), (secret_type, region, host)
