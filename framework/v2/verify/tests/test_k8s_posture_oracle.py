"""
Workstream-3 — the k8s-posture oracle (kube-bench CIS-control-failure -> FACT).

A kube-bench FAIL is a THIRD-PARTY CIS-checker's say-so — a LEAD. The k8s-posture oracle promotes it to
a FACT ONLY when the RETAINED control proves a CONCRETE insecure setting: a hard FAIL whose observed
value literally carries a dangerous flag (``--anonymous-auth=true``, ``--authorization-mode=…AlwaysAllow``,
a non-zero ``--insecure-port``, a static auth file, …). A PASSING/benign control, a WARN advisory, a FAIL
whose observed value shows the SECURE setting, and a FAIL with no captured value all correctly do NOT
fire — near-zero false positives. The confirmed fact re-verifies offline from its retained context.
"""

from __future__ import annotations

from framework.v2.verify import confirm_k8s_posture, k8s_posture_context, k8s_posture_oracle
from framework.v2.verify.adapter import FindingContext
from framework.v2.verify.models import OracleKind
from framework.v2.verify.reverify import reverify_context
from framework.v2.verify.verifier import _ALL_ORACLES, OracleVerifier

# A hard-FAIL apiserver control whose observed value literally carries the insecure flag.
_INSECURE_ANON = {
    "check_id": "1.2.1", "status": "FAIL",
    "description": "Ensure that the --anonymous-auth argument is set to false",
    "actual_value": "kube-apiserver --anonymous-auth=true --insecure-port=0 --profiling=false",
    "benchmark": "cis-kubernetes",
}


# ---- the oracle fires ONLY on a proven insecure setting ---------------------


def test_fires_on_failed_control_with_concrete_insecure_flag() -> None:
    sig = k8s_posture_oracle(_INSECURE_ANON)
    assert sig.fired and sig.kind is OracleKind.K8S_POSTURE
    assert sig.confidence >= 0.7
    assert sig.observed["rule"] == "anonymous_auth_enabled"
    assert "--anonymous-auth=true" in sig.observed["matched"]


def test_each_dangerous_flag_rule_fires() -> None:
    cases = {
        "anonymous_auth_enabled": "--anonymous-auth=true",
        "authz_mode_always_allow": "--authorization-mode=Node,RBAC,AlwaysAllow",
        "insecure_port_open": "--insecure-port=8080",
        "kubelet_read_only_port": "--read-only-port=10255",
        "basic_auth_file": "--basic-auth-file=/etc/k8s/basic-auth.csv",
        "token_auth_file": "--token-auth-file=/etc/k8s/tokens.csv",
        "etcd_no_client_cert_auth": "--client-cert-auth=false",
        "profiling_enabled": "--profiling=true",
    }
    for expected_rule, flag in cases.items():
        sig = k8s_posture_oracle({"check_id": "x", "status": "FAIL", "actual_value": f"proc {flag} --tls"})
        assert sig.fired, f"{expected_rule} should fire on {flag!r}"
        assert sig.observed["rule"] == expected_rule


def test_flag_renderings_are_matched() -> None:
    # kube-bench renders flags as --flag=value / --flag value / --flag: value
    for rendered in ("--anonymous-auth=true", "--anonymous-auth true", "--anonymous-auth: true"):
        assert k8s_posture_oracle({"check_id": "1.2.1", "status": "FAIL", "actual_value": rendered}).fired


# ---- the oracle does NOT fire on a benign / unprovable posture --------------


def test_passing_control_does_not_fire() -> None:
    # a PASS control's observed value shows the SECURE setting — never a fact
    secure = {"check_id": "1.2.1", "status": "PASS",
              "actual_value": "kube-apiserver --anonymous-auth=false"}
    assert not k8s_posture_oracle(secure).fired


def test_failed_control_with_secure_value_does_not_fire() -> None:
    # a FAIL whose observed value carries no dangerous flag (e.g. a manual/other control) stays a LEAD
    sig = k8s_posture_oracle({
        "check_id": "1.2.1", "status": "FAIL",
        "actual_value": "kube-apiserver --anonymous-auth=false --insecure-port=0 --profiling=false"})
    assert not sig.fired


def test_warn_and_missing_value_do_not_fire() -> None:
    # WARN is a manual-review advisory, not a proof
    assert not k8s_posture_oracle({"check_id": "1.2.6", "status": "WARN",
                                   "actual_value": "--anonymous-auth=true"}).fired
    # a FAIL with NO captured value has no concrete proof — stays a LEAD
    assert not k8s_posture_oracle({"check_id": "1.2.1", "status": "FAIL"}).fired
    assert not k8s_posture_oracle({"check_id": "1.2.1", "status": "FAIL", "actual_value": "  "}).fired


def test_garbage_and_empty_do_not_fire() -> None:
    for junk in (None, "", 123, [], {}, {"status": "FAIL"}):
        assert not k8s_posture_oracle(junk).fired


# ---- routing + the frozen-fallback invariant --------------------------------


def test_routes_via_verifier_and_kind_is_out_of_the_frozen_fallback() -> None:
    v = OracleVerifier()
    assert v.oracles_for("k8s_misconfiguration") == (OracleKind.K8S_POSTURE,)
    assert v.oracles_for("k8s_posture") == (OracleKind.K8S_POSTURE,)          # alias folds
    # the NEW kind is reachable ONLY via its explicit row — never the unknown-class fallback
    assert OracleKind.K8S_POSTURE not in _ALL_ORACLES
    assert OracleKind.K8S_POSTURE not in v.oracles_for("some_unknown_class")


def test_confirm_via_seam_and_verifier() -> None:
    assert confirm_k8s_posture(_INSECURE_ANON).confirmed
    assert OracleVerifier().confirm(k8s_posture_context(_INSECURE_ANON)).confirmed
    assert not confirm_k8s_posture({"check_id": "1.2.1", "status": "PASS"}).confirmed


# ---- offline re-verification (prove-don't-guess) ----------------------------


def test_confirmed_posture_reverifies_offline_from_its_retained_context() -> None:
    oracle_context = k8s_posture_context(_INSECURE_ANON)
    # no cluster, no trust in the scanner — re-run the pure oracle over the retained control
    r = reverify_context(oracle_context, bug_class="k8s_misconfiguration")
    assert r.reproduced and r.ok
    assert r.confirmed_by == OracleKind.K8S_POSTURE.value


def test_adapter_builder_retains_only_structural_fields() -> None:
    ctx = FindingContext.from_k8s_posture({**_INSECURE_ANON, "noise": "verbose scanner prose"})
    emitted = ctx.to_verifier_context()
    assert "k8s_control" in emitted
    assert "noise" not in emitted["k8s_control"]        # non-structural fields are NOT laundered in
    assert emitted["k8s_control"]["check_id"] == "1.2.1"
