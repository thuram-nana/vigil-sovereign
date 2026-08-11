"""E1-complete — the WARDEN-gated IMDS runner (live half). Unit-tested with a MOCK transport (no network):
the runner produces a capture that the OFFLINE oracle confirms as a FACT-capable credential capture, performs
the secret lifecycle (no plaintext secret survives; the exact credential->call binding fingerprint matches),
and REFUSES before any I/O when WARDEN or the charter scope gate denies. Live-fire (a real httpx transport +
an authorized lab credential) is a thin binding, deferred."""
from __future__ import annotations

import pytest

pytest.importorskip("framework.v2.verify.confirmation", reason="CRUCIBLE not importable here")

from vigil_integration.live.imds_runner import (  # noqa: E402
    TransportResult, credential_fingerprint, run_imds_capture,
)

_IMDS_URL = "http://169.254.169.254/latest/meta-data/iam/security-credentials/app-role"
_STS = "https://sts.amazonaws.com/"
_AWS_ID = {"Arn": "arn:aws:sts::123456789012:assumed-role/app-role/i-0abc",
           "Account": "123456789012", "UserId": "AROAEXAMPLEID:i-0abc"}


class _AllowGate:
    def authorize(self, *a):  # D5 scope gate stub — authorizes the lab scope
        return True, "in scope"


class _DenyGate:
    def authorize(self, *a):
        return False, "resource not in signed charter scope"


def _aws_transport(imds_json, confirm_json, *, imds_peer="169.254.169.254", confirm_peer="72.21.206.80",
                   confirm_tls=True, imds_proxy=False, confirm_proxy=False, redirected=False):
    """A mock transport: the IMDS GET returns the credential; the STS POST returns the identity echo."""
    calls: list[tuple[str, str]] = []

    def transport(method: str, url: str) -> TransportResult:
        calls.append((method, url))
        if url == _IMDS_URL:
            return TransportResult(status=200, body=b"{cred}", resolved_peer=imds_peer, tls_verified=False,
                                   via_proxy=imds_proxy, redirected=redirected, json=imds_json)
        return TransportResult(status=200, body=b'{"GetCallerIdentityResponse":1}', resolved_peer=confirm_peer,
                               tls_verified=confirm_tls, via_proxy=confirm_proxy, redirected=redirected,
                               json=confirm_json)

    return transport, calls


def _run(transport, authorize=lambda: (True, "ok"), gate=None):
    return run_imds_capture(
        "aws", imds_url=_IMDS_URL, confirm_endpoint=_STS, confirm_action="sts:GetCallerIdentity",
        authorize=authorize, scope_gate=gate or _AllowGate(),
        scope=("aws", "123456789012", "us-east-1", "role/app-role"),
        transport=transport, identity_of=lambda r: r.json or {})


def test_runner_produces_a_fact_capable_capture_the_oracle_confirms() -> None:
    from framework.v2.verify import confirm_imds_capture, imds_credential_capture_oracle
    cred = {"AccessKeyId": "ASIAZZ7EXAMPLE0KEY01", "SecretAccessKey": "wJalrXUtnFEXAMPLEKEY",
            "Token": "IQoJb3JpEXAMPLEtoken=="}
    transport, calls = _aws_transport(cred, _AWS_ID)
    res = _run(transport)
    assert res.status == "captured" and res.capture is not None
    # the OFFLINE oracle confirms the runner's capture as a FACT-capable credential capture.
    assert imds_credential_capture_oracle(res.capture).fired
    assert confirm_imds_capture(res.capture).confirmed
    # both network calls were made (IMDS GET + STS confirm).
    assert calls == [("GET", _IMDS_URL), ("POST", _STS)]


def test_runner_secret_lifecycle_no_plaintext_and_exact_binding() -> None:
    cred = {"AccessKeyId": "ASIAZZ7EXAMPLE0KEY01", "SecretAccessKey": "TOPSECRETVALUE",
            "Token": "TOPSECRETTOKEN"}
    transport, _ = _aws_transport(cred, _AWS_ID)
    cap = _run(transport).capture
    blob = repr(cap)
    assert "TOPSECRETVALUE" not in blob and "TOPSECRETTOKEN" not in blob   # no plaintext secret survived
    assert cap["credential"]["SecretAccessKey"] == "[REDACTED]" and cap["credential"]["Token"] == "[REDACTED]"
    # the EXACT binding: the same domain-separated fingerprint on the credential AND the confirming call.
    fp = credential_fingerprint("TOPSECRETVALUE\x1fTOPSECRETTOKEN")
    assert cap["credential"]["credential_fingerprint"] == fp
    assert cap["confirming_call"]["credential_fingerprint"] == fp
    # a bare hash of the secret is NOT the fingerprint (domain separation).
    import hashlib
    assert fp != "sha256:" + hashlib.sha256(b"TOPSECRETVALUE\x1fTOPSECRETTOKEN").hexdigest()


def test_runner_refuses_before_any_io_when_warden_denies() -> None:
    cred = {"AccessKeyId": "ASIAZZ7EXAMPLE0KEY01", "SecretAccessKey": "s", "Token": "t"}
    transport, calls = _aws_transport(cred, _AWS_ID)
    res = _run(transport, authorize=lambda: (False, "kill-switch engaged"))
    assert res.status == "refused" and res.capture is None
    assert calls == []                                    # NO network I/O happened


def test_runner_refuses_out_of_scope_before_any_io() -> None:
    cred = {"AccessKeyId": "ASIAZZ7EXAMPLE0KEY01", "SecretAccessKey": "s", "Token": "t"}
    transport, calls = _aws_transport(cred, _AWS_ID)
    res = _run(transport, gate=_DenyGate())
    assert res.status == "refused" and res.capture is None
    assert calls == []


def test_runner_untrusted_transport_capture_is_not_fact_capable() -> None:
    # if the confirming call went through a proxy (or TLS unverified), the runner still records it honestly —
    # and the oracle then refuses to confirm (structural LEAD), because the transport provenance is untrusted.
    from framework.v2.verify import imds_credential_capture_oracle
    cred = {"AccessKeyId": "ASIAZZ7EXAMPLE0KEY01", "SecretAccessKey": "s", "Token": "t"}
    transport, _ = _aws_transport(cred, _AWS_ID, confirm_proxy=True)
    cap = _run(transport).capture
    sig = imds_credential_capture_oracle(cap)
    assert not sig.fired and sig.observed["reason"] == "structural_only_not_bound"
