"""
The AEGIS appends are additive and default-safe, so `make gate` stays byte-identical:

  * G1 — the unknown-class fallback `_ALL_ORACLES` is FROZEN to the pre-AEGIS OracleKind
    members; it did NOT grow when the AEGIS members were appended, and `oracles_for("<unknown>")`
    does not include an AEGIS oracle. This is the byte-identical gap the design's own test
    would otherwise miss — we assert the FALLBACK path, not just known classes.
  * every pre-existing bug_class maps to exactly its unchanged oracle set.
  * known_bug_classes() grew by EXACTLY the AEGIS classes/aliases.
"""

from __future__ import annotations

from framework.v2.verify import verifier as V
from framework.v2.verify.models import OracleKind
from framework.v2.verify.verifier import BUG_CLASS_ORACLES, OracleVerifier, known_bug_classes

_AEGIS_KINDS = {OracleKind.PROMPT_INJECTION, OracleKind.SYSTEM_PROMPT_DISCLOSURE,
                OracleKind.AUTOMATED_ACCESS, OracleKind.CREDENTIAL_STUFFING,
                # the request-side parse-proof kinds (the inline gateway) are defensive AEGIS
                # members too — reachable only via their explicit rows, never the fallback.
                OracleKind.SQL_INJECTION_BREAKOUT, OracleKind.COMMAND_INJECTION_BREAKOUT}
# Workstream-3 (dormant-sensor promotion) additive kinds/classes: the SAME frozen-fallback discipline
# as the AEGIS members — a NEW OracleKind kept OUT of _ALL_ORACLES, reachable ONLY via its explicit
# BUG_CLASS_ORACLES row. (The cloud/CSPM public-exposure & over-broad-trust reachability-PATH promotions
# reuse the EXISTING POLICY_PATH kind; the Wave-F1 achieved-STATE cloud promotion below adds its own.)
_WS3_KINDS = {OracleKind.K8S_POSTURE}
_WS3_CLASSES = {"k8s_misconfiguration"}
# Wave-F1 (cloud/CSPM achieved-state posture oracle) additive kind/class: SAME frozen-fallback discipline
# — a NEW OracleKind kept OUT of _ALL_ORACLES, reachable ONLY via its `cloud_misconfiguration`
# BUG_CLASS_ORACLES row (keyed on a `cloud_control` ctx field no benchmark/scan finding carries).
_WF1_KINDS = {OracleKind.CLOUD_POSTURE}
_WF1_CLASSES = {"cloud_misconfiguration"}
# Workstream-B (SSO/JWT structural-forgery oracle) additive kind/class: SAME frozen-fallback discipline
# — a NEW OracleKind kept OUT of _ALL_ORACLES, reachable ONLY via its `jwt_forgeable` BUG_CLASS_ORACLES
# row (keyed on a `jwt_token` ctx field no benchmark/scan finding carries).
_WSB_KINDS = {OracleKind.SSO_ASSERTION_FORGERY}
_WSB_CLASSES = {"jwt_forgeable"}
# NW-1 (offline SAML structural-forgery oracle) additive kind/class: SAME frozen-fallback discipline —
# held OUT of _ALL_ORACLES, reachable ONLY via its `saml_structural_forgery` row (keyed on a `saml_xml`
# ctx no benchmark/scan finding carries).
_NW1_KINDS = {OracleKind.SAML_STRUCTURAL_FORGERY}
_NW1_CLASSES = {"saml_structural_forgery"}
# Wave-G2 (request-side NoSQL operator-injection break-out oracle) additive kind/class: SAME
# frozen-fallback discipline — a NEW OracleKind kept OUT of _ALL_ORACLES, reachable ONLY via its
# `nosql_injection_attempt` BUG_CLASS_ORACLES row (keyed on the SAME `request_payload` ctx field the
# sqli/cmdi request-side parse-proof oracles use, which no benchmark/scan finding carries).
_G2_KINDS = {OracleKind.NOSQL_INJECTION_BREAKOUT}
_G2_CLASSES = {"nosql_injection_attempt"}
# Wave-G3 (offline service-mesh posture oracle) additive kind/class: SAME frozen-fallback discipline —
# held OUT of _ALL_ORACLES, reachable ONLY via its `mesh_misconfiguration` row (keyed on a `mesh_control`
# ctx field no benchmark/scan finding carries).
_G3_KINDS = {OracleKind.MESH_POSTURE}
_G3_CLASSES = {"mesh_misconfiguration"}
_CICD_KINDS = {OracleKind.CICD_POSTURE}   # Phase-2 CI/CD posture
_CICD_CLASSES = {"cicd_misconfiguration"}
_MOBILE_KINDS = {OracleKind.MOBILE_POSTURE}   # Phase-2 mobile static-posture
_MOBILE_CLASSES = {"mobile_misconfiguration"}
_EMAIL_KINDS = {OracleKind.EMAIL_AUTH_POSTURE}   # FORGE Domain 10 email-auth posture
_EMAIL_CLASSES = {"email_auth_misconfiguration"}
_IDENTITY_KINDS = {OracleKind.IDENTITY_POSTURE}   # FORGE Domain 7 identity posture
_IDENTITY_CLASSES = {"identity_misconfiguration"}
# Slice-C3 (live, gated, UNAUTHENTICATED active-exposure oracle) additive kind/class: SAME
# frozen-fallback discipline — a NEW OracleKind kept OUT of _ALL_ORACLES, reachable ONLY via its
# `anonymous_reachable` row (keyed on an `anon_get` ctx field no benchmark/scan finding carries).
_C3_KINDS = {OracleKind.ACTIVE_EXPOSURE}
_C3_CLASSES = {"anonymous_reachable"}
# TRUTHENOVATION-T4 (#209) k8s-workload posture oracle additive kind/class: SAME frozen-fallback
# discipline — a NEW OracleKind kept OUT of _ALL_ORACLES, reachable ONLY via its
# `k8s_workload_misconfiguration` BUG_CLASS_ORACLES row (keyed on a k8s-posture ctx no benchmark/scan
# finding carries). (K8S_POSTURE above is the earlier WS-3 kind; this is the distinct workload kind.)
_T4_KINDS = {OracleKind.K8S_WORKLOAD_POSTURE}
_T4_CLASSES = {"k8s_workload_misconfiguration"}
# BUILD-PLAN §E1 (IMDS/metadata credential-capture oracle — the flagship exploitation-chain oracle, built
# as a DEFENSIVE VERIFICATION oracle) additive kind/class: SAME frozen-fallback discipline — a NEW
# OracleKind kept OUT of _ALL_ORACLES, reachable ONLY via its `imds_credential_capture` BUG_CLASS_ORACLES
# row (keyed on an `imds_capture` ctx field no benchmark/scan/engage finding carries).
_E1_KINDS = {OracleKind.IMDS_CREDENTIAL_CAPTURE}
_E1_CLASSES = {"imds_credential_capture"}
# BUILD-PLAN §E5 (exposed-secret VALIDITY oracle — a DEFENSIVE VERIFICATION oracle) additive kind/class: SAME
# frozen-fallback discipline — kept OUT of _ALL_ORACLES, reachable ONLY via its `secret_credential_validity`
# BUG_CLASS_ORACLES row keyed on a `secret_capture` ctx field no benchmark/scan/engage finding carries.
_E5_KINDS = {OracleKind.SECRET_CREDENTIAL_VALIDITY}
_E5_CLASSES = {"secret_credential_validity"}
# BUILD-PLAN §E3 (GCP service-account IMPERSONATION oracle — a DEFENSIVE VERIFICATION oracle) additive
# kind/class: SAME frozen-fallback discipline — kept OUT of _ALL_ORACLES, reachable ONLY via its
# `gcp_sa_impersonation` BUG_CLASS_ORACLES row keyed on a `gcp_impersonation_capture` ctx field no
# benchmark/scan/engage finding carries.
_E3_KINDS = {OracleKind.GCP_SA_IMPERSONATION}
_E3_CLASSES = {"gcp_sa_impersonation"}
# BUILD-PLAN §E2 (IAM privilege-escalation PRIMITIVE — the strict-gain achieved-escalation dual of the
# POLICY_PATH reachability oracle) additive kind/class: SAME frozen-fallback discipline — a NEW OracleKind
# kept OUT of _ALL_ORACLES, reachable ONLY via its `iam_escalation_primitive` BUG_CLASS_ORACLES row (keyed on
# an `iam_escalation_capture` ctx field no benchmark/scan/engage finding carries). DISTINCT bug class from
# `iam_privilege_escalation` (which maps to POLICY_PATH reachability), so it never re-routes the weaker oracle.
_E2_KINDS = {OracleKind.IAM_ESCALATION_PRIMITIVE}
_E2_CLASSES = {"iam_escalation_primitive"}
# BUILD-PLAN §E4 TIER-2 (K8s dangerous-VERB / default-SA RBAC verb-grant — the rule-PARSING sibling of the
# TIER-1 anonymous_privileged_binding oracle, which only NAME-matches a built-in ClusterRole) additive
# kind/class: SAME frozen-fallback discipline — kept OUT of _ALL_ORACLES, reachable ONLY via its
# `k8s_rbac_privilege_grant` BUG_CLASS_ORACLES row keyed on a `k8s_rbac_grant_control` ctx field that no
# benchmark/scan/engage finding carries.
_E4T2_KINDS = {OracleKind.K8S_RBAC_VERB_GRANT}
_E4T2_CLASSES = {"k8s_rbac_privilege_grant"}
# W16-STD-5 client-side POSTURE-WEAKNESS oracles (constitution §V client-side classes) additive
# kinds/classes: SAME frozen-fallback discipline — each NEW OracleKind kept OUT of _ALL_ORACLES, reachable
# ONLY via its `clickjacking` / `csrf` / `postmessage` row (keyed on a `*_control` ctx field no
# benchmark/scan finding carries). Each proves a MISSING/WEAK defense, never an achieved-state exploit.
_CS_KINDS = {OracleKind.CLICKJACKING_POSTURE, OracleKind.CSRF_POSTURE, OracleKind.POSTMESSAGE_POSTURE}
_CS_CLASSES = {"clickjacking", "csrf", "postmessage"}
# Wave 2.2 client-side PROTOTYPE POLLUTION achieved-state oracle (plan §2.2): SAME frozen-fallback
# discipline — the NEW OracleKind is kept OUT of _ALL_ORACLES, reachable ONLY via its
# `prototype_pollution` BUG_CLASS_ORACLES row keyed on a `proto_pollution` ctx field no benchmark/scan
# finding carries. It proves the ACHIEVED Object.prototype state (CWE-1321), not a posture weakness.
_W22_KINDS = {OracleKind.PROTOTYPE_POLLUTION}
_W22_CLASSES = {"prototype_pollution"}
# Wave 2.4 CSP permissive-policy POSTURE oracle (plan §2.4): SAME frozen-fallback discipline — the NEW
# OracleKind is kept OUT of _ALL_ORACLES, reachable ONLY via its `csp_posture` BUG_CLASS_ORACLES row keyed
# on a `csp_control` ctx field no benchmark/scan finding carries. It proves the PARSED permissive weakness
# of the retained enforced CSP header (CWE-693/CWE-1021), not an achieved exploit. The achieved csp_bypass
# class reuses DOM_EXECUTION (already frozen) so it adds NO kind and is NOT an excluded class (like
# postmessage_exploited / stored_xss): its oracle set stays the pre-existing (DOM_EXECUTION, SIDE_EFFECT).
_W24_KINDS = {OracleKind.CSP_POSTURE}
_W24_CLASSES = {"csp_posture"}
# Wave 3.2 SESSION FIXATION achieved-state oracle (plan §3.2): SAME frozen-fallback discipline — the NEW
# OracleKind (its OWN dedicated kind so ACHIEVED_STATE's oracle_version is untouched) is kept OUT of
# _ALL_ORACLES, reachable ONLY via its `session_fixation` BUG_CLASS_ORACLES row keyed on a `session_fixation`
# ctx field no benchmark/scan finding carries. It proves the ACHIEVED fixation state (CWE-384) by a
# same-URL logged-out differential re-derived from raw bytes, not a posture weakness.
_W32_KINDS = {OracleKind.SESSION_FIXATION}
_W32_CLASSES = {"session_fixation"}
# every additive kind that must stay out of the frozen unknown-class fallback.
_EXCLUDED_KINDS = (_AEGIS_KINDS | _WS3_KINDS | _WSB_KINDS | _NW1_KINDS | _WF1_KINDS
                   | _G2_KINDS | _G3_KINDS | _CICD_KINDS | _MOBILE_KINDS | _EMAIL_KINDS | _IDENTITY_KINDS
                   | _C3_KINDS | _T4_KINDS | _E1_KINDS | _E5_KINDS | _E3_KINDS | _E2_KINDS | _E4T2_KINDS
                   | _CS_KINDS | _W22_KINDS | _W24_KINDS | _W32_KINDS)
_EXCLUDED_CLASSES = {"prompt_injection", "system_prompt_disclosure", "automated_access",
                     "credential_stuffing", "sqli_attempt", "command_injection_attempt"} | _WS3_CLASSES | _WSB_CLASSES | _NW1_CLASSES | _WF1_CLASSES | _G2_CLASSES | _G3_CLASSES | _CICD_CLASSES | _MOBILE_CLASSES | _EMAIL_CLASSES | _IDENTITY_CLASSES | _C3_CLASSES | _T4_CLASSES | _E1_CLASSES | _E5_CLASSES | _E3_CLASSES | _E2_CLASSES | _E4T2_CLASSES | _CS_CLASSES | _W22_CLASSES | _W24_CLASSES | _W32_CLASSES
_AEGIS_CLASSES = {"prompt_injection", "system_prompt_disclosure", "automated_access",
                  "credential_stuffing", "sqli_attempt", "command_injection_attempt"}
_AEGIS_ALIASES = {"jailbreak", "llm_prompt_injection", "indirect_prompt_injection",
                  "system_prompt_leak", "system_prompt_exfiltration", "canary_disclosure",
                  "automated_scraping", "honeypot_hit", "honeypot_fetch", "bot_access",
                  "account_takeover", "ato", "cred_stuffing", "credential_stuffing_attack",
                  "credential_stuffing_ato", "password_spraying"}


def test_all_oracles_fallback_is_frozen_to_pre_aegis_members():
    # G1: the fallback is the 15 pre-AEGIS members, NOT tuple(OracleKind) (which has grown far past 15 —
    # the 4 AEGIS telemetry kinds + the 3 request-side parse-proof kinds (sqli/cmdi/nosql) + the WS-3
    # k8s-posture kind + the WS-B sso-assertion-forgery kind + the NW-1 saml-structural-forgery kind +
    # the Wave-F1 cloud-posture + Wave-G3 mesh-posture + CI/CD + mobile + email-auth + identity + C3
    # active-exposure + T4 k8s-workload + the BUILD-PLAN §E1 IMDS credential-capture kind are all excluded).
    assert len(V._ALL_ORACLES) == 15
    assert set(V._ALL_ORACLES) == set(OracleKind) - _EXCLUDED_KINDS
    # and it is NOT derived from the enum (that would have grown it past 15).
    assert set(V._ALL_ORACLES) != set(OracleKind)


def test_unknown_class_fallback_excludes_aegis_oracles():
    # importing aegis must not let an AEGIS oracle leak into the unknown-class fallback.
    import framework.v2.aegis  # noqa: F401  (exercises the additive import)
    fallback = OracleVerifier().oracles_for("some_unknown_class_that_maps_to_nothing")
    assert fallback == V._ALL_ORACLES
    for kind in _EXCLUDED_KINDS:
        assert kind not in fallback


def test_preexisting_classes_map_to_unchanged_oracle_sets():
    # every non-additive class still resolves to exactly its BUG_CLASS_ORACLES row, and no pre-existing
    # class's oracle set intersects the additive-excluded kinds.
    ver = OracleVerifier()
    for bug_class, expected in BUG_CLASS_ORACLES.items():
        if bug_class in _EXCLUDED_CLASSES:
            continue
        assert ver.oracles_for(bug_class) == expected
        assert not (set(expected) & _EXCLUDED_KINDS)


def test_known_bug_classes_grew_by_exactly_the_aegis_vocabulary():
    known = known_bug_classes()
    for cls in _AEGIS_CLASSES:
        assert cls in known
    for alias in _AEGIS_ALIASES:
        assert alias in known


def test_aegis_classes_map_to_their_single_oracle():
    from framework.v2.aegis.registry import verify_registration
    verify_registration()   # asserts every additive append is present + folds correctly
    assert BUG_CLASS_ORACLES["prompt_injection"] == (OracleKind.PROMPT_INJECTION,)
    assert BUG_CLASS_ORACLES["system_prompt_disclosure"] == (OracleKind.SYSTEM_PROMPT_DISCLOSURE,)
    assert BUG_CLASS_ORACLES["automated_access"] == (OracleKind.AUTOMATED_ACCESS,)
    assert BUG_CLASS_ORACLES["credential_stuffing"] == (OracleKind.CREDENTIAL_STUFFING,)
