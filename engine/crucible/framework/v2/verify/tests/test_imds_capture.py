"""
BUILD-PLAN §E1 — the IMDS/metadata credential-capture oracle (SSRF/foothold -> IMDS credential capture,
the flagship EXPLOITATION-CHAIN oracle, built as a DEFENSIVE VERIFICATION oracle).

The oracle CONFIRMS an ACHIEVED EFFECT — role/SA credentials were actually retrieved from the instance
metadata endpoint AND proven usable — over a JSON-safe RETAINED capture ALONE (offline, ZERO network, NO
exploitation code). It is NOT an attack runner. It fires (0.95) ONLY when the capture carries BOTH a
structurally-valid credential FROM the metadata endpoint AND a retained confirming call
(sts:GetCallerIdentity / tokeninfo) proving the credential authenticated.

The negative controls are this deliverable's proof (each MUTATION-VERIFIED — a targeted change to the
benign twin makes the oracle fire, so the control is load-bearing, not trivially passing): a 401/timeout
metadata response, a valid credential with NO confirming call, a valid credential with a FAILED
GetCallerIdentity, a random JSON blob, and a valid credential whose source is NOT the metadata endpoint
(a normal env-var key) all correctly do NOT fire. Both a full AWS and a full GCP capture fire and
re-verify offline (secret-safe) from their retained context.
"""

from __future__ import annotations

import copy

from framework.v2.verify import (
    confirm_imds_capture,
    imds_capture_context,
    imds_credential_capture_oracle,
)
from framework.v2.verify.adapter import FindingContext
from framework.v2.verify.models import OracleKind
from framework.v2.verify.oracle_version import oracle_version
from framework.v2.verify.reverify import reverify_context
from framework.v2.verify.verifier import _ALL_ORACLES, OracleVerifier

# A full AWS capture: an STS-temporary instance-role credential retrieved from the IMDS
# security-credentials path, AND a successful sts:GetCallerIdentity that authenticated with it.
_AWS_CAP = {
    "provider": "aws",
    "credential": {
        "AccessKeyId": "ASIAZZ7EXAMPLE0KEY01",
        "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "Token": "IQoJb3JpZ2luX2VjEXAMPLEsessiontoken==",
        "source": "http://169.254.169.254/latest/meta-data/iam/security-credentials/app-role",
    },
    "confirming_call": {
        "action": "sts:GetCallerIdentity", "status": 200,
        "response": {
            "Arn": "arn:aws:sts::123456789012:assumed-role/app-role/i-0abc123def",
            "Account": "123456789012",
            "UserId": "AROAEXAMPLEID12345:i-0abc123def",
        },
    },
}

# A full GCP capture: a service-account access token from the compute-metadata token path, AND a
# successful tokeninfo that authenticated with it.
_GCP_CAP = {
    "provider": "gcp",
    "credential": {
        "access_token": "ya29.c.EXAMPLE-gcp-access-token-value-redacted",
        "token_type": "Bearer",
        "source": ("http://metadata.google.internal/computeMetadata/v1/instance/"
                   "service-accounts/default/token"),
    },
    "confirming_call": {
        "action": "tokeninfo", "status": 200,
        "response": {
            "email": "app-sa@my-project.iam.gserviceaccount.com",
            "sub": "104567890123456789012",
            "expires_in": 3599,
            "scope": "https://www.googleapis.com/auth/cloud-platform",
        },
    },
}


# ---- the oracle fires ONLY on a proven, confirmed IMDS credential capture ----


def test_fires_on_full_aws_capture() -> None:
    sig = imds_credential_capture_oracle(_AWS_CAP)
    assert sig.fired and sig.kind is OracleKind.IMDS_CREDENTIAL_CAPTURE
    assert sig.confidence >= 0.7 and sig.conclusive
    assert sig.observed["provider"] == "aws"
    assert sig.observed["reason"] == "imds_credential_authenticated"
    assert sig.observed["account"] == "123456789012"


def test_fires_on_full_gcp_capture() -> None:
    sig = imds_credential_capture_oracle(_GCP_CAP)
    assert sig.fired and sig.kind is OracleKind.IMDS_CREDENTIAL_CAPTURE
    assert sig.confidence >= 0.7
    assert sig.observed["provider"] == "gcp"
    assert sig.observed["reason"] == "imds_credential_authenticated"
    assert sig.observed["identity"] == "app-sa@my-project.iam.gserviceaccount.com"


def test_akia_long_term_key_also_matches_the_shape_when_from_imds() -> None:
    # the spec regex ^A[SK]IA... matches AKIA too; an IMDS capture still requires a Token + a
    # confirming call, so this only fires because both are present.
    cap = copy.deepcopy(_AWS_CAP)
    cap["credential"]["AccessKeyId"] = "AKIAZZ7EXAMPLE0KEY01"
    assert imds_credential_capture_oracle(cap).fired


# ---- S1 RECALL: SSRF IP encodings of the metadata host are a GENUINE IMDS reach and MUST fire ----

# 169.254.169.254 == 0xA9FEA9FE == 2852039166; ::ffff:a9fe:a9fe is its IPv4-mapped IPv6 form. An
# attacker reaches IMDS via any of these to dodge naive string filters — the reach is still real.
_IMDS_IP_ENCODINGS = (
    "http://2852039166/latest/meta-data/iam/security-credentials/role",           # 32-bit decimal
    "http://0xA9FEA9FE/latest/meta-data/iam/security-credentials/role",           # hex literal
    "http://[::ffff:a9fe:a9fe]/latest/meta-data/iam/security-credentials/role",   # IPv6-mapped
)


def test_fires_on_ssrf_ip_encodings_of_the_metadata_host() -> None:
    for src in _IMDS_IP_ENCODINGS:
        cap = copy.deepcopy(_AWS_CAP)
        cap["credential"]["source"] = src
        sig = imds_credential_capture_oracle(cap)
        assert sig.fired, f"IP-encoding must fire (genuine IMDS reach): {src!r}"
        assert sig.observed["reason"] == "imds_credential_authenticated"
        # MUTATION-VERIFIED the other way: a host that merely CONTAINS the encoded IP does NOT fire.
        rebind = copy.deepcopy(cap)
        rebind["credential"]["source"] = "http://2852039166.attacker.com/iam/security-credentials/role"
        assert not imds_credential_capture_oracle(rebind).fired


def test_fires_on_gcp_bare_metadata_host_and_userinfo_without_expiry() -> None:
    # the bare `metadata` host is the compute-metadata endpoint too (host-equality, not substring).
    bare = copy.deepcopy(_GCP_CAP)
    bare["credential"]["source"] = \
        "http://metadata/computeMetadata/v1/instance/service-accounts/default/token"
    assert imds_credential_capture_oracle(bare).fired
    # S3: a userinfo echo (email/sub, NO expiry) + lowercase token_type "bearer" still fires — the
    # docstring already claims userinfo, whose response omits an expiry.
    userinfo = copy.deepcopy(_GCP_CAP)
    userinfo["credential"]["token_type"] = "bearer"
    userinfo["confirming_call"]["action"] = "userinfo"
    userinfo["confirming_call"]["response"] = {"email": "app-sa@my-project.iam.gserviceaccount.com",
                                               "sub": "104567890123456789012"}
    sig = imds_credential_capture_oracle(userinfo)
    assert sig.fired and sig.observed["reason"] == "imds_credential_authenticated"
    assert sig.observed["identity"] == "app-sa@my-project.iam.gserviceaccount.com"


# ---- MANDATORY negative controls (each mutation-verified) --------------------


def test_negative_control_a_401_timeout_metadata_response() -> None:
    # (a) the metadata GET returned 401 / timed out — no credential was retrieved.
    control = {
        "provider": "aws",
        "credential": {"source": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                       "status": 401, "body": "Unauthorized"},
    }
    assert not imds_credential_capture_oracle(control).fired
    # MUTATION: the GET actually returned a credential (+ the confirming call) -> now fires.
    fired = copy.deepcopy(control)
    fired["credential"] = copy.deepcopy(_AWS_CAP["credential"])
    fired["confirming_call"] = copy.deepcopy(_AWS_CAP["confirming_call"])
    assert imds_credential_capture_oracle(fired).fired


def test_negative_control_b_valid_credential_but_no_confirming_call() -> None:
    # (b) a credential was retrieved from IMDS but NEVER confirmed usable — a LEAD, not a FACT.
    control = {"provider": "aws", "credential": copy.deepcopy(_AWS_CAP["credential"])}
    sig = imds_credential_capture_oracle(control)
    assert not sig.fired
    assert sig.observed["reason"] == "no_confirming_call"
    # MUTATION: attach the successful confirming call -> now fires.
    fired = copy.deepcopy(control)
    fired["confirming_call"] = copy.deepcopy(_AWS_CAP["confirming_call"])
    assert imds_credential_capture_oracle(fired).fired


def test_negative_control_c_valid_credential_but_failed_getcalleridentity() -> None:
    # (c) the confirming sts:GetCallerIdentity FAILED (403 + error) — the credential is not proven usable.
    control = {
        "provider": "aws", "credential": copy.deepcopy(_AWS_CAP["credential"]),
        "confirming_call": {
            "action": "sts:GetCallerIdentity", "status": 403,
            "response": {"Error": {"Code": "InvalidClientTokenId",
                                   "Message": "The security token included in the request is invalid."}},
        },
    }
    sig = imds_credential_capture_oracle(control)
    assert not sig.fired
    assert sig.observed["reason"] == "confirming_call_failed"
    # a 200 with a truthy error field but no identity also does NOT fire (error marker is load-bearing).
    err200 = copy.deepcopy(control)
    err200["confirming_call"] = {"action": "sts:GetCallerIdentity", "status": 200,
                                 "response": {"error": "AccessDenied"}}
    assert not imds_credential_capture_oracle(err200).fired
    # MUTATION: the confirming call succeeded -> now fires.
    fired = copy.deepcopy(control)
    fired["confirming_call"] = copy.deepcopy(_AWS_CAP["confirming_call"])
    assert imds_credential_capture_oracle(fired).fired


def test_negative_control_d_random_json_blob() -> None:
    # (d) a random JSON blob (and other junk) never fires and never raises.
    for junk in ({"foo": "bar", "nested": {"a": [1, 2, 3]}, "id": 42},
                 None, "", 123, [], {}, {"credential": "nope"}, {"credential": {}}):
        assert not imds_credential_capture_oracle(junk).fired
    # MUTATION: a blob shaped into a full IMDS capture fires (proves the blob was rejected on content).
    assert imds_credential_capture_oracle(copy.deepcopy(_AWS_CAP)).fired


def test_negative_control_e_credential_not_from_the_metadata_endpoint() -> None:
    # (e) a normal, fully-VALID, authenticating AWS key whose source is an env var — NOT a URL, so it has
    # no HOST that identifies the metadata endpoint. Even with a successful GetCallerIdentity it must NOT be
    # mistaken for an IMDS capture: the load-bearing discriminator is that the source URL's HOST resolves to
    # the metadata endpoint (169.254.169.254) — an env var / creds file / non-IMDS host never qualifies.
    control = {
        "provider": "aws",
        "credential": {
            "AccessKeyId": "AKIAZZ7EXAMPLE0KEY01",
            "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "Token": "session-token-value",
            "source": "env:AWS_ACCESS_KEY_ID",
        },
        "confirming_call": copy.deepcopy(_AWS_CAP["confirming_call"]),
    }
    sig = imds_credential_capture_oracle(control)
    assert not sig.fired
    assert sig.observed["reason"] == "no_imds_credential"
    # MUTATION: the SAME credential+call, but its source IS the IMDS security-credentials path -> fires.
    fired = copy.deepcopy(control)
    fired["credential"]["source"] = \
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/app-role"
    assert imds_credential_capture_oracle(fired).fired


# ---- the RED-PEN BLOCK: substring containment falsely fired these; a HOST check must reject them -----

# Each is a full, valid, authenticating AWS credential+call whose ONLY defect is a forged source that a
# naive `"169.254.169.254" in source and "iam/security-credentials" in source` check accepts but whose
# real host is NOT the metadata endpoint (or which is not a URL at all).
_BLOCK_SOURCES = (
    # userinfo-@ bypass: urlsplit host is evil.com, the IP is only the username.
    "http://169.254.169.254@evil.com/latest/meta-data/iam/security-credentials/role",
    # SSRF-proxy: host is evil.com, the IP + marker live only in the QUERY.
    "http://evil.com/proxy?u=http://169.254.169.254/iam/security-credentials",
    # rebind: the host merely CONTAINS the IP as a label under an attacker domain.
    "http://169.254.169.254.attacker.com/iam/security-credentials/role",
    # a CREDS FILE on disk, not a URL — no host at all.
    "/home/user/.aws/169.254.169.254-iam/security-credentials.txt",
    # a bare string, not a URL — no host at all.
    "169.254.169.254 iam/security-credentials",
    # Unicode-digit host (Arabic-Indic ٢٨٥٢٠٣٩١٦٦ == 2852039166): str.isdigit()/int() would parse it to the
    # metadata IP, but no resolver/inet_aton/IDNA does — it denotes no real reach (red-pen BLOCK-A).
    "http://٢٨٥٢٠٣٩١٦٦/latest/meta-data/iam/security-credentials/role",
    # Fullwidth-digit host (２８５２０３９１６６) — same class.
    "http://２８５２０３９１６６/iam/security-credentials",
)


def test_block_source_forgeries_do_not_fire_but_the_real_host_does() -> None:
    real = "http://169.254.169.254/latest/meta-data/iam/security-credentials/role"
    for bad in _BLOCK_SOURCES:
        cap = copy.deepcopy(_AWS_CAP)
        cap["credential"]["source"] = bad
        sig = imds_credential_capture_oracle(cap)
        assert not sig.fired, f"BLOCK source falsely fired (substring bypass): {bad!r}"
        assert sig.observed["reason"] == "no_imds_credential"
        # MUTATION-VERIFIED: the SAME full credential+call with a genuine IMDS URL host -> fires. Proves the
        # control was rejected purely on the forged source, not on any other missing element.
        cap["credential"]["source"] = real
        assert imds_credential_capture_oracle(cap).fired, f"real host must fire (mutation of {bad!r})"


def test_negative_control_f_200_body_with_error_keys_is_not_a_success() -> None:
    # (f) a 200 confirming call whose body carries a FAILURE marker is NOT a success — including the AWS
    # JSON error shape (__type + message) and the AWS query/XML shape (Error/Code/Message/Fault). Load-
    # bearing: each body ALSO carries a full, valid identity echo, so ONLY the error marker can reject it.
    identity = dict(_AWS_CAP["confirming_call"]["response"])
    for err_key, err_val in (("__type", "com.amazon.coral.service#InvalidClientTokenId"),
                             ("message", "The security token included in the request is invalid."),
                             ("errors", ["denied"]), ("code", "AccessDenied"), ("Fault", "Server")):
        control = copy.deepcopy(_AWS_CAP)
        body = dict(identity)
        body[err_key] = err_val
        control["confirming_call"] = {"action": "sts:GetCallerIdentity", "status": 200, "response": body}
        sig = imds_credential_capture_oracle(control)
        assert not sig.fired, f"200 body with {err_key!r} must not be a success"
        assert sig.observed["reason"] == "confirming_call_failed"
    # MUTATION: remove the failure marker (the clean identity echo) -> fires.
    assert imds_credential_capture_oracle(copy.deepcopy(_AWS_CAP)).fired


def test_builder_retains_error_markers_so_a_failed_200_reverifies_non_firing() -> None:
    # the mint-side failure gate MUST be mirrored at re-execution: a certificate built from a 200 whose body
    # is the AWS JSON error shape must retain the __type/message markers and re-verify as NON-firing.
    cap = copy.deepcopy(_AWS_CAP)
    cap["confirming_call"] = {"action": "sts:GetCallerIdentity", "status": 200,
                              "response": {"__type": "InvalidClientTokenId", "message": "invalid"}}
    emitted = FindingContext.from_imds_capture(cap).to_verifier_context()
    resp = emitted["imds_capture"]["confirming_call"]["response"]
    assert resp.get("__type") and resp.get("message")           # failure markers retained
    assert not OracleVerifier().confirm(emitted).confirmed      # ...so re-verify does not confirm


def test_gcp_negative_controls_mirror_the_aws_ones() -> None:
    # a GCP token NOT from the metadata endpoint does not fire...
    off_source = copy.deepcopy(_GCP_CAP)
    off_source["credential"]["source"] = "https://oauth2.example.com/token"
    assert not imds_credential_capture_oracle(off_source).fired
    # a GCP token with token_type != Bearer does not fire...
    not_bearer = copy.deepcopy(_GCP_CAP)
    not_bearer["credential"]["token_type"] = "mac"
    assert not imds_credential_capture_oracle(not_bearer).fired
    # a GCP token from metadata but with NO confirming call is a LEAD, not a FACT...
    no_call = {"provider": "gcp", "credential": copy.deepcopy(_GCP_CAP["credential"])}
    assert not imds_credential_capture_oracle(no_call).fired
    # a GCP confirming call whose body carries a FAILURE marker (an OAuth error) does not fire — a genuine
    # failure is the negative control (an identity echo WITHOUT an expiry now FIRES; see the S3 test).
    failed = copy.deepcopy(_GCP_CAP)
    failed["confirming_call"]["response"] = {"error": "invalid_token",
                                             "error_description": "Invalid Value"}
    sig_failed = imds_credential_capture_oracle(failed)
    assert not sig_failed.fired
    assert sig_failed.observed["reason"] == "confirming_call_failed"


def test_aws_missing_any_credential_component_does_not_fire() -> None:
    for drop in ("AccessKeyId", "SecretAccessKey", "Token"):
        cap = copy.deepcopy(_AWS_CAP)
        del cap["credential"][drop]
        assert not imds_credential_capture_oracle(cap).fired, f"missing {drop} must not fire"
    # a malformed AccessKeyId (not ^A[SK]IA...) does not fire even with a confirming call.
    bad = copy.deepcopy(_AWS_CAP)
    bad["credential"]["AccessKeyId"] = "NOTAREALKEYID000000"
    assert not imds_credential_capture_oracle(bad).fired


def test_aws_account_must_be_twelve_digits() -> None:
    bad = copy.deepcopy(_AWS_CAP)
    bad["confirming_call"]["response"]["Account"] = "12345"  # not 12 digits -> not a valid identity echo
    assert not imds_credential_capture_oracle(bad).fired


# ---- routing + the frozen-fallback invariant (make gate stays byte-identical) --


def test_routes_via_verifier_and_kind_is_out_of_the_frozen_fallback() -> None:
    v = OracleVerifier()
    assert v.oracles_for("imds_credential_capture") == (OracleKind.IMDS_CREDENTIAL_CAPTURE,)
    assert v.oracles_for("imds_capture") == (OracleKind.IMDS_CREDENTIAL_CAPTURE,)          # alias folds
    assert v.oracles_for("ssrf_to_imds") == (OracleKind.IMDS_CREDENTIAL_CAPTURE,)          # alias folds
    # the NEW kind is reachable ONLY via its explicit row — never the unknown-class fallback.
    assert OracleKind.IMDS_CREDENTIAL_CAPTURE not in _ALL_ORACLES
    assert len(_ALL_ORACLES) == 15
    assert OracleKind.IMDS_CREDENTIAL_CAPTURE not in v.oracles_for("some_unknown_class")


def test_kind_has_a_content_derived_oracle_version() -> None:
    # registered in oracle_version._ORACLE_FNS so a certificate can name id@version (PCF).
    assert oracle_version(OracleKind.IMDS_CREDENTIAL_CAPTURE).startswith("sha256:")


# ---- confirm via the seam + offline re-verification -------------------------


def test_confirm_via_seam_and_verifier() -> None:
    assert confirm_imds_capture(_AWS_CAP).confirmed
    assert confirm_imds_capture(_GCP_CAP).confirmed
    assert OracleVerifier().confirm(imds_capture_context(_AWS_CAP)).confirmed
    # a benign twin does not confirm through the seam.
    assert not confirm_imds_capture({"provider": "aws", "credential": _AWS_CAP["credential"]}).confirmed


def test_confirmed_capture_reverifies_offline_from_its_retained_context() -> None:
    for cap in (_AWS_CAP, _GCP_CAP):
        oracle_context = imds_capture_context(cap)
        r = reverify_context(oracle_context, bug_class="imds_credential_capture")
        assert r.reproduced and r.ok
        assert r.confirmed_by == OracleKind.IMDS_CREDENTIAL_CAPTURE.value


def test_reverify_refuses_a_relabelled_certificate() -> None:
    # a genuine IMDS certificate re-labelled as a cloud misconfiguration must NOT re-confirm as that class.
    oracle_context = imds_capture_context(_AWS_CAP)
    r = reverify_context(oracle_context, bug_class="cloud_misconfiguration")
    assert not r.reproduced
    assert r.matches_claim is False


# ---- the adapter builder is secret-safe + retains only structural fields -----


def test_builder_redacts_secret_material_but_still_reverifies() -> None:
    emitted = FindingContext.from_imds_capture(_AWS_CAP).to_verifier_context()
    assert "imds_capture" in emitted
    blob = str(emitted["imds_capture"])
    # NO live secret material is laundered into the certificate...
    assert _AWS_CAP["credential"]["SecretAccessKey"] not in blob
    assert _AWS_CAP["credential"]["Token"] not in blob
    assert "[REDACTED]" in blob
    # ...but the IDENTIFIERS load-bearing for the proof are retained verbatim.
    assert emitted["imds_capture"]["credential"]["AccessKeyId"] == "ASIAZZ7EXAMPLE0KEY01"
    assert "169.254.169.254" in emitted["imds_capture"]["credential"]["source"]
    assert emitted["imds_capture"]["confirming_call"]["response"]["Account"] == "123456789012"
    # and the redacted certificate STILL re-confirms (the oracle judges secret PRESENCE, not content).
    assert OracleVerifier().confirm(emitted).confirmed


def test_gcp_builder_redacts_the_access_token() -> None:
    emitted = FindingContext.from_imds_capture(_GCP_CAP).to_verifier_context()
    blob = str(emitted["imds_capture"])
    assert _GCP_CAP["credential"]["access_token"] not in blob
    assert emitted["imds_capture"]["credential"]["token_type"] == "Bearer"
    assert OracleVerifier().confirm(emitted).confirmed
