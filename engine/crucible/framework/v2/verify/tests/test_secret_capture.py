"""E5 exposed-secret VALIDITY oracle — the mutation-verified differential battery (BUILD-PLAN §E5).

The oracle asserts an achieved effect (an EXPOSED secret is VALID), so its whole worth is NOT over-claiming.
Every negative control here is MUTATION-VERIFIED: take the good fixture, break exactly ONE field, assert the
oracle does NOT fire AND names the specific reason, then assert the UNBROKEN fixture still fires — so each
control is proven load-bearing (a vacuous test that passed no matter what would be caught by the repair
assertion).

The soundness centre is the SOURCE-SEMANTICS INVERSION: unlike the IMDS oracle (which gates on the credential
coming FROM the metadata endpoint), E5 does NOT gate on the exposure source — it gates on the CONFIRMING
endpoint being on the per-TYPE allow-list. The `*_laundering_*` cases are the crux: an attacker who exposes a
string and stands up their own 'confirming' endpoint (even echoing a valid fingerprint they computed from the
secret they control) must NOT be able to mint a FACT.

IMDS content trips the red-pen AGENT safeguard, so soundness is verified by this in-loop battery (the same
approach that shipped the E1 oracle), not a red-pen subagent.
"""

import copy

import pytest

from framework.v2.verify.oracles import exposed_secret_validity_oracle as _oracle

# A good AWS-access-key capture: a structurally-recognized identifier + a fingerprint-bound sts:
# GetCallerIdentity confirming call over a trusted, allow-listed transport echoing a consistent identity.
_AWS = {
    "secret_type": "aws_access_key",
    "credential": {"identifier": "AKIA1234567890ABCDEF", "secret": "[REDACTED]",
                   "credential_fingerprint": "fp-aws-1", "source": "js:app.min.js:1024"},
    "confirming_call": {"action": "sts:GetCallerIdentity", "status": 200,
                        "credential_fingerprint": "fp-aws-1",
                        "endpoint": "https://sts.us-east-1.amazonaws.com/",
                        "tls_verified": True, "no_proxy": True, "no_redirect": True,
                        "resolved_peer": "1.2.3.4", "response_digest": "sha256:aaa",
                        "response": {"Arn": "arn:aws:iam::123456789012:user/leaked",
                                     "Account": "123456789012", "UserId": "AIDAEXAMPLE"}},
}

# A good GitHub-PAT capture: a recognized token prefix + a fingerprint-bound GET /user confirming call.
_GH = {
    "secret_type": "github_pat",
    "credential": {"identifier": "ghp_", "secret": "[REDACTED]",
                   "credential_fingerprint": "fp-gh-1", "source": "git:.github/workflows/ci.yml:5"},
    "confirming_call": {"action": "github:GET /user", "status": 200, "credential_fingerprint": "fp-gh-1",
                        "endpoint": "https://api.github.com/user",
                        "tls_verified": True, "no_proxy": True, "no_redirect": True,
                        "resolved_peer": "140.82.121.6", "response_digest": "sha256:bbb",
                        "response": {"login": "leakeduser", "id": 12345678}},
}

_DELETE = object()


def _fires(cap) -> bool:
    return _oracle(cap).fired


def _reason(cap) -> str:
    return _oracle(cap).observed.get("reason", "")


def _set(d: dict, path: str, value) -> None:
    keys = path.split(".")
    o = d
    for k in keys[:-1]:
        o = o[k]
    if value is _DELETE:
        del o[keys[-1]]
    else:
        o[keys[-1]] = value


def _mutation_verified(good: dict, path: str, bad_value, expect_reason: str) -> None:
    """Break ONE field -> assert LEAD with the exact reason -> assert the UNBROKEN fixture still fires (so the
    control is load-bearing, not vacuous)."""
    broken = copy.deepcopy(good)
    _set(broken, path, bad_value)
    assert not _fires(broken), f"{path}={bad_value!r} must NOT fire (it did)"
    assert _reason(broken) == expect_reason, f"{path}: reason {_reason(broken)!r} != {expect_reason!r}"
    assert _fires(copy.deepcopy(good)), f"repair check: the unbroken fixture must fire (control not load-bearing)"


def test_good_aws_and_github_captures_fire() -> None:
    for name, cap in (("aws", _AWS), ("github", _GH)):
        sig = _oracle(cap)
        assert sig.fired is True, f"{name}: {sig.observed}"
        assert sig.conclusive is True and sig.confidence == 0.95
        assert sig.observed["reason"] == "exposed_secret_validated"


@pytest.mark.parametrize("path,bad,reason", [
    ("secret_type", "mystery_token", "unrecognized_secret_type"),
    ("credential.identifier", "not-a-valid-key", "secret_identifier_malformed"),
    ("confirming_call", _DELETE, "no_confirming_call"),
    ("confirming_call.status", 403, "confirming_call_failed"),
    ("confirming_call.action", "sts:GetSessionToken", "confirming_action_mismatch"),
    ("confirming_call.response", {}, "identity_echo_absent"),
    ("confirming_call.credential_fingerprint", "a-different-fingerprint", "secret_not_bound_to_confirming_call"),
    # THE ANTI-LAUNDERING CONTROL: an attacker's own confirming endpoint must not mint a FACT.
    ("confirming_call.endpoint", "https://sts.evil.com/", "confirming_endpoint_not_allowlisted"),
    ("confirming_call.tls_verified", False, "confirming_call_tls_unverified"),
    ("confirming_call.no_proxy", False, "confirming_call_transport_not_direct"),
    ("confirming_call.no_redirect", False, "confirming_call_transport_not_direct"),
    ("confirming_call.resolved_peer", "", "confirming_call_peer_unrecorded"),
    ("confirming_call.response_digest", "", "confirming_call_response_undigested"),
])
def test_aws_single_field_breaks_are_mutation_verified(path, bad, reason) -> None:
    _mutation_verified(_AWS, path, bad, reason)


def test_aws_inconsistent_identity_echo_does_not_fire() -> None:
    # a fabricated Arn/Account pair (the Arn's account != the returned Account) is not a real authenticated
    # call — the reused E1 identity extractor's self-consistency check rejects it.
    _mutation_verified(_AWS, "confirming_call.response",
                       {"Arn": "arn:aws:iam::999999999999:user/x", "Account": "123456789012",
                        "UserId": "AIDAEXAMPLE"}, "identity_echo_absent")


def test_error_shaped_200_body_is_not_a_fact() -> None:
    # a 200 carrying an error marker (a real failure masquerading as success) must NOT confirm.
    _mutation_verified(_AWS, "confirming_call.response", {"error": "InvalidClientTokenId"},
                       "confirming_call_failed")


def test_github_anti_laundering_is_per_type() -> None:
    # a GitHub token confirmed against an attacker host is refused ...
    _mutation_verified(_GH, "confirming_call.endpoint", "https://api.evil.com/user",
                       "confirming_endpoint_not_allowlisted")
    # ... and CROSS-TYPE laundering (a GitHub token 'confirmed' at the AWS STS host) is also refused: the
    # per-type allow-list binds each secret type to its OWN provider endpoint.
    _mutation_verified(_GH, "confirming_call.endpoint", "https://sts.us-east-1.amazonaws.com/",
                       "confirming_endpoint_not_allowlisted")


def test_github_single_field_breaks_are_mutation_verified() -> None:
    _mutation_verified(_GH, "credential.identifier", "xyz_", "secret_identifier_malformed")
    _mutation_verified(_GH, "confirming_call.response", {"login": "u"}, "identity_echo_absent")  # id missing
    _mutation_verified(_GH, "confirming_call.response", {"id": 5}, "identity_echo_absent")       # login missing
    _mutation_verified(_GH, "confirming_call.credential_fingerprint", "nope",
                       "secret_not_bound_to_confirming_call")


def test_malformed_or_partial_capture_never_raises_and_never_fires() -> None:
    for bad in (None, "x", 123, [], {}, {"secret_type": "aws_access_key"},
                {"secret_type": "aws_access_key", "credential": {}}):
        sig = _oracle(bad)
        assert sig.fired is False and sig.conclusive is False


def test_confirmation_seam_routes_and_redacts_the_secret() -> None:
    from framework.v2.verify import confirm_secret_capture, secret_capture_context
    assert confirm_secret_capture(_AWS).confirmed is True
    # the retained ctx must be SECRET-SAFE: a plaintext secret is redacted to a presence marker.
    live = copy.deepcopy(_AWS)
    live["credential"]["secret"] = "wJalrXUtnFEMI_PLAINTEXT_SECRET_VALUE"
    ctx = secret_capture_context(live)
    assert ctx["secret_capture"]["credential"]["secret"] == "[REDACTED]"
    assert "PLAINTEXT_SECRET_VALUE" not in str(ctx)
    # and it still confirms over the redacted capture (validity is proven by the confirming call, not the
    # secret's content).
    assert confirm_secret_capture(live).confirmed is True
