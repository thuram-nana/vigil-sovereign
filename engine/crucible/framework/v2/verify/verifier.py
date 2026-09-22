"""
verify.verifier — the confirmation authority.

`OracleVerifier.confirm(finding_context)` is the load-bearing gate. It selects
the oracle(s) appropriate to a finding's bug_class, runs each over the
already-observed data the context carries, and returns a VerificationResult
whose `confirmed` is True only when at least one oracle fired at or above the
high-confidence threshold.

This is the "prove, don't guess" contract in code: no oracle, no confirmation.
It is deliberately conservative — an absent input yields a non-firing signal,
never an assumed pass.
"""

from __future__ import annotations

from typing import Annotated, Any, Mapping

from pydantic import AfterValidator, BeforeValidator

from . import oracles
from .models import OracleKind, OracleSignal, VerificationResult

# A fired signal must reach this confidence to confirm a finding.
HIGH_CONFIDENCE = 0.7


# ---------------------------------------------------------------------------
# bug_class -> which oracle(s) can prove it
# ---------------------------------------------------------------------------

# Canonical bug classes to the ordered oracle kinds that can confirm them.
BUG_CLASS_ORACLES: dict[str, tuple[OracleKind, ...]] = {
    "boolean_sqli": (OracleKind.BOOLEAN_INFERENCE, OracleKind.DIFFERENTIAL_RESPONSE),
    "time_based_sqli": (OracleKind.TIMING, OracleKind.DIFFERENTIAL_RESPONSE),
    "time_based_command_injection": (OracleKind.TIMING, OracleKind.OOB_CALLBACK),
    "time_based": (OracleKind.TIMING,),
    "error_based_sqli": (OracleKind.ERROR_SIGNATURE, OracleKind.SIDE_EFFECT, OracleKind.DIFFERENTIAL_RESPONSE),
    "sqli": (OracleKind.ERROR_SIGNATURE, OracleKind.BOOLEAN_INFERENCE, OracleKind.DIFFERENTIAL_RESPONSE, OracleKind.OOB_CALLBACK, OracleKind.SIDE_EFFECT),
    "nosqli": (OracleKind.BOOLEAN_INFERENCE, OracleKind.DIFFERENTIAL_RESPONSE, OracleKind.ERROR_SIGNATURE),
    "ldap_injection": (OracleKind.BOOLEAN_INFERENCE, OracleKind.DIFFERENTIAL_RESPONSE, OracleKind.ERROR_SIGNATURE),
    "xpath_injection": (OracleKind.BOOLEAN_INFERENCE, OracleKind.DIFFERENTIAL_RESPONSE, OracleKind.ERROR_SIGNATURE),
    "idor": (OracleKind.ACHIEVED_STATE,),
    "bola": (OracleKind.ACHIEVED_STATE,),
    "bfla": (OracleKind.ACHIEVED_STATE,),
    "broken_access_control": (OracleKind.ACHIEVED_STATE,),
    "authorization": (OracleKind.ACHIEVED_STATE,),
    "auth_bypass": (OracleKind.ACHIEVED_STATE, OracleKind.DIFFERENTIAL_RESPONSE),
    "mass_assignment": (OracleKind.ACHIEVED_STATE,),
    "privilege_escalation": (OracleKind.ACHIEVED_STATE,),
    "open_redirect": (OracleKind.ACHIEVED_STATE,),
    "exposure": (OracleKind.ACHIEVED_STATE,),
    "sensitive_exposure": (OracleKind.ACHIEVED_STATE,),
    "security_misconfiguration": (OracleKind.ACHIEVED_STATE,),
    "cors": (OracleKind.ACHIEVED_STATE,),
    "host_header_injection": (OracleKind.ACHIEVED_STATE,),
    "jwt": (OracleKind.ACHIEVED_STATE,),
    "graphql_introspection": (OracleKind.ACHIEVED_STATE,),
    "graphql_suggestions": (OracleKind.ACHIEVED_STATE,),
    # GraphQL DoS / abuse surface (scanner.graphql, opt-in). Each is confirmed by the
    # predicate oracle over the RAW amplified response — an unbounded-depth query that
    # executed, N aliases that all resolved, an M-operation batch that ran — so it fires
    # only when the guard is actually absent (the amplification came back), never on the
    # mere presence of a /graphql path. (Query COST stays a LEAD in the scanner: a minimal
    # probe being accepted cannot prove a cost limit is absent.) Routed to the SAME
    # ACHIEVED_STATE kind as the other predicate checks, so _ALL_ORACLES is unchanged.
    "graphql_depth_limit": (OracleKind.ACHIEVED_STATE,),
    "graphql_alias_overloading": (OracleKind.ACHIEVED_STATE,),
    "graphql_batching": (OracleKind.ACHIEVED_STATE,),
    "graphql_cost": (OracleKind.ACHIEVED_STATE,),
    "request_smuggling": (OracleKind.DIFFERENTIAL_RESPONSE,),
    "dom_xss": (OracleKind.DOM_EXECUTION, OracleKind.SIDE_EFFECT),
    # Stored / second-order XSS (scanner.stored_xss, browser-backed, opt-in). Confirmed by the SAME
    # DOM_EXECUTION oracle as dom_xss — a payload WRITTEN at surface A that EXECUTES when surface B renders
    # the persisted value, observed via VIGIL's own __crucible_xss binding call carrying a unique per-(A,B,
    # payload) canary (never mere reflection/echo). Reuses DOM_EXECUTION (already in the frozen _ALL_ORACLES),
    # so this row adds NO new OracleKind and `make gate` stays byte-identical (stored-XSS is deep-only /
    # off-by-default and sends 0 benchmark requests through the default corpus). This is a REAL row, not the
    # former `stored_xss -> xss` alias: that alias routed stored_xss to REFLECTION_CONTEXT, which cannot
    # prove EXECUTION of a persisted payload; the browser-confirmed FACT this class now mints requires the
    # execution oracle, so the class maps to it directly. SIDE_EFFECT is retained as the secondary kind for
    # parity with dom_xss (a rendered-attribute side-effect confirmation).
    "stored_xss": (OracleKind.DOM_EXECUTION, OracleKind.SIDE_EFFECT),
    "cross_site_websocket_hijacking": (OracleKind.ACHIEVED_STATE,),
    "websocket_injection": (OracleKind.SIDE_EFFECT, OracleKind.DIFFERENTIAL_RESPONSE),
    "request_race": (OracleKind.ACHIEVED_STATE,),
    # business-logic / workflow abuse (scanner.bizlogic, OPT-IN — needs an operator
    # workflow spec, NOT in DEFAULT_CHECKS): a skipped required step, a sequentially
    # replayed one-time action, or price/qty tampering is a FACT only when the observed
    # post-state proves the illegitimate state was reached. The predicate/achieved-state
    # oracle judges the raw post-state — the detector never self-certifies. Additive row:
    # it routes an opt-in class and sends 0 benchmark requests, so `make gate` stays
    # byte-identical.
    "business_logic": (OracleKind.ACHIEVED_STATE,),
    "ssrf": (OracleKind.OOB_CALLBACK,),
    "xxe": (OracleKind.OOB_CALLBACK, OracleKind.SIDE_EFFECT),
    "blind_xxe": (OracleKind.OOB_CALLBACK,),
    "deserialization": (OracleKind.OOB_CALLBACK, OracleKind.SANITIZER_SIGNAL),
    "rce": (OracleKind.OOB_CALLBACK, OracleKind.SIDE_EFFECT, OracleKind.SANITIZER_SIGNAL),
    "command_injection": (OracleKind.OOB_CALLBACK, OracleKind.SIDE_EFFECT),
    "ssti": (OracleKind.EVALUATION, OracleKind.SIDE_EFFECT, OracleKind.DIFFERENTIAL_RESPONSE),
    "el_injection": (OracleKind.EVALUATION, OracleKind.SIDE_EFFECT),
    "xss": (OracleKind.REFLECTION_CONTEXT,),
    "path_traversal": (OracleKind.SIDE_EFFECT,),
    "lfi": (OracleKind.SIDE_EFFECT,),
    "memory_corruption": (OracleKind.SANITIZER_SIGNAL,),
    "buffer_overflow": (OracleKind.SANITIZER_SIGNAL,),
    "use_after_free": (OracleKind.SANITIZER_SIGNAL,),
    "crash": (OracleKind.SANITIZER_SIGNAL,),
    # network-service reachability: a scanner's "open port" observation is confirmed a FACT only when
    # a real transport handshake reproduces (verify.reachability captures it; the oracle judges it).
    "service_reachable": (OracleKind.SERVICE_REACHABILITY,),
    # Slice-C3 active exposure: a cloud resource a POSTURE already re-derived as PUBLIC (an anonymous
    # grant path, POLICY_PATH) becomes a PROVEN anonymously-reachable FACT only when a bounded, gated,
    # UNAUTHENTICATED HTTP GET actually reaches it (an unauthenticated 2xx with a present body). Like the
    # posture rows, this NEW OracleKind is reachable ONLY via this row — it is NOT in the frozen
    # _ALL_ORACLES fallback — and fires only when the ctx carries `anon_get`, which no benchmark/scan/engage
    # finding does. So appending it leaves the unknown-class fallback and `make gate` byte-identical.
    "anonymous_reachable": (OracleKind.ACTIVE_EXPOSURE,),
    # TLS posture: a deprecated protocol / weak cipher is a FACT only when a real handshake negotiated
    # it (verify.tls captures it; the oracle judges the negotiated version/suite).
    "weak_tls": (OracleKind.TLS_WEAKNESS,),
    # Phase-2 crypto: a parsed crypto ARTIFACT (an X.509 cert) signed with a BROKEN hash (MD5/SHA1) —
    # unconditionally weak (collision-forgeable), a FACT re-verified from the retained signatureAlgorithm
    # OID name. Reuses TLS_WEAKNESS (a weak-crypto FACT) via a distinct `crypto_artifact` ctx key no
    # benchmark finding carries, so the gate stays byte-identical. See verify/weak_crypto.py.
    "weak_crypto_artifact": (OracleKind.TLS_WEAKNESS,),
    # supply chain: a scanner's "package @ version is affected by CVE" is a FACT only when the version
    # provably falls in the advisory's affected range (verify.version's deterministic membership check).
    "vulnerable_dependency": (OracleKind.VERSION_RANGE,),
    # Cloud IAM privilege path: a cloud sensor's "over-privileged / can reach R" is a LEAD; it becomes
    # a FACT only when the policy-path oracle re-derives a real grant path over the retained policy
    # graph (verify.policy_path builds the graph; the oracle judges reachability). Distinct from the
    # generic ACHIEVED_STATE-backed `privilege_escalation` (a runtime state), this proves the IAM path.
    "privilege_path": (OracleKind.POLICY_PATH,),
    "iam_privilege_escalation": (OracleKind.POLICY_PATH,),
    "excessive_privilege": (OracleKind.POLICY_PATH,),
    # AEGIS (defensive dual) — the app's OWN LLM + the honeypot tripwire. These rows are the
    # ONLY path an AEGIS oracle reaches confirm(): they are NOT in the frozen unknown-class
    # fallback (_ALL_ORACLES below), so appending the AEGIS OracleKind members cannot grow the
    # oracle set any pre-existing / unknown class runs, and `make gate` stays byte-identical.
    # Honest scope: system_prompt_disclosure proves the SECRET LEAKED (canary substring);
    # prompt_injection is reserved for a provable control-vs-treatment behavior delta;
    # automated_access proves AUTOMATION (a honeypot fetch), never "scraping". See aegis/.
    "prompt_injection": (OracleKind.PROMPT_INJECTION,),
    "system_prompt_disclosure": (OracleKind.SYSTEM_PROMPT_DISCLOSURE,),
    "automated_access": (OracleKind.AUTOMATED_ACCESS,),
    # SSO / SAML / OIDC (scanner.sso) — testing the operator's OWN SP/RP integration.
    # Each proves an unauthorized/forged SSO artifact was ACCEPTED via the predicate
    # (achieved-state) oracle over raw statuses/redirects — never an AEGIS oracle, so
    # the unknown-class fallback and `make gate` are unchanged (additive rows only).
    "saml_signature_wrapping": (OracleKind.ACHIEVED_STATE,),
    "saml_assertion_tampering": (OracleKind.ACHIEVED_STATE,),
    "oidc_redirect_uri": (OracleKind.ACHIEVED_STATE,),
    "oidc_idtoken_forgery": (OracleKind.ACHIEVED_STATE,),
    # credential_stuffing proves a source achieved SPRT-significant successful logins across many
    # UNSEEN (account, source) pairs (ATO), Holm-controlled across identities. A failed-only burst
    # (NAT/CGNAT bulk) yields no SPRT round and stays a LEAD — never confirmed.
    "credential_stuffing": (OracleKind.CREDENTIAL_STUFFING,),
    # AEGIS request-side PARSE-PROOF (the inline "provable firewall" gateway). A request-parameter
    # value PROVABLY breaks out of a SQL string literal into query structure, or contains an
    # unambiguous shell command-execution construct — judged on the REQUEST ALONE. Proves a
    # STRUCTURED INJECTION ATTEMPT (re-runnable), NOT exploitation (an app that parameterises is still
    # safe; the response-side oracles prove exploitation). These NEW OracleKind members are reachable
    # ONLY via these rows — they are NOT in the frozen _ALL_ORACLES fallback — and fire only when the
    # ctx carries `request_payload`, which no benchmark/scan/engage finding does. So appending them
    # leaves the unknown-class fallback and `make gate` byte-identical.
    "sqli_attempt": (OracleKind.SQL_INJECTION_BREAKOUT,),
    "command_injection_attempt": (OracleKind.COMMAND_INJECTION_BREAKOUT,),
    # Wave-G2 NoSQL (MongoDB-style) operator injection — the request-side sibling of the two above. A
    # request value/param PROVABLY injects a MongoDB query operator as a KEY where a scalar was expected
    # (`user[$ne]=1`, `{"user":{"$ne":null}}`, `q[$gt]=0`, `$where`) — judged on the REQUEST ALONE. Proves
    # a STRUCTURED NoSQL operator-injection ATTEMPT (re-runnable), NOT exploitation (an app that coerces
    # the param to a string is still safe; the response-side oracles prove exploitation). This NEW
    # OracleKind is reachable ONLY via this row — it is NOT in the frozen _ALL_ORACLES fallback — and fires
    # only when the ctx carries `request_payload` (the SAME key sqli_attempt uses), which no
    # benchmark/scan/engage finding does. So appending it leaves the unknown-class fallback and `make gate`
    # byte-identical.
    "nosql_injection_attempt": (OracleKind.NOSQL_INJECTION_BREAKOUT,),
    # Workstream-3 (dormant-sensor promotion): a kube-bench CIS-control-failure LEAD
    # (sensors.k8s_runtime) becomes a FACT only when the k8s-posture oracle re-derives a CONCRETE
    # insecure setting over the RETAINED control (a hard FAIL whose observed value literally carries a
    # dangerous flag). Like the AEGIS rows, this NEW OracleKind is reachable ONLY via this row — it is
    # NOT in the frozen _ALL_ORACLES fallback — and fires only when the ctx carries `k8s_control`,
    # which no benchmark/scan/engage finding does. So appending it leaves the unknown-class fallback and
    # `make gate` byte-identical. (Cloud/CSPM public-exposure & over-broad-trust promotions reuse the
    # existing POLICY_PATH rows above; live reachability reuses `service_reachable` — no new rows.)
    "k8s_misconfiguration": (OracleKind.K8S_POSTURE,),
    # C2·K8s (live-RBAC achieved-state promotion): a retained live RBAC-binding LEAD (sensors.k8s_live)
    # becomes a FACT only when the k8s-workload-posture oracle re-derives a CONCRETE insecure ACHIEVED STATE
    # over the RETAINED binding (an ANONYMOUS subject — system:anonymous / system:unauthenticated — bound to a
    # dangerous built-in ClusterRole: cluster-admin / admin / edit). DISTINCT from `k8s_misconfiguration`
    # (K8S_POSTURE, kube-bench control-plane CLI flags): the RBAC achieved-STATE membership lens over a single
    # live binding record, no kube-bench. Like the k8s/cloud rows, this NEW OracleKind is reachable ONLY via
    # this row — it is NOT in the frozen _ALL_ORACLES fallback — and fires only when the ctx carries
    # `k8s_workload_control`, which no benchmark/scan/engage finding does. So appending it leaves the
    # unknown-class fallback and `make gate` byte-identical.
    "k8s_workload_misconfiguration": (OracleKind.K8S_WORKLOAD_POSTURE,),
    # Wave-F1 (cloud/CSPM achieved-state promotion): a retained cloud-posture LEAD (sensors.cloud)
    # becomes a FACT only when the cloud-posture oracle re-derives a CONCRETE insecure ACHIEVED STATE over
    # the RETAINED control (encryption-at-rest disabled on a sensitive datastore, an explicit
    # public-exposure flag, or a wildcard/anonymous principal named in the retained policy). Like the k8s
    # row, this NEW OracleKind is reachable ONLY via this row — it is NOT in the frozen _ALL_ORACLES
    # fallback — and fires only when the ctx carries `cloud_control`, which no benchmark/scan/engage
    # finding does. So appending it leaves the unknown-class fallback and `make gate` byte-identical.
    # COMPLEMENTARY to the POLICY_PATH rows above: those prove a reachability PATH over the policy GRAPH
    # (public_exposure / excessive_privilege); this proves the achieved STATE a reachability path cannot
    # (principally the misconfiguration / encryption-at-rest-disabled lead) over a single control record.
    "cloud_misconfiguration": (OracleKind.CLOUD_POSTURE,),
    # Wave-G3 (service-mesh achieved-state promotion): a retained mesh-config LEAD
    # (verify.mesh_posture.ingest_mesh_config) becomes a FACT only when the mesh-posture oracle re-derives a
    # CONCRETE insecure ACHIEVED STATE over the RETAINED control (Istio PeerAuthentication with
    # permissive/disabled mTLS, an ALLOW AuthorizationPolicy that admits every caller, or a Linkerd server
    # whose default-inbound-policy is all-unauthenticated). Like the k8s/cloud rows, this NEW OracleKind is
    # reachable ONLY via this row — it is NOT in the frozen _ALL_ORACLES fallback — and fires only when the
    # ctx carries `mesh_control`, which no benchmark/scan/engage finding does. So appending it leaves the
    # unknown-class fallback and `make gate` byte-identical. The MESH twin of the k8s/cloud achieved-state
    # promotions — a single-control membership/parse-proof, offline, ZERO mesh/kubectl calls, NO attack.
    "mesh_misconfiguration": (OracleKind.MESH_POSTURE,),
    # CI/CD-pipeline posture (Phase-2). A parsed GitHub-Actions control (verify.cicd_posture /
    # sensors.cicd) is a LEAD; it becomes a FACT only when cicd_posture_oracle re-derives a concrete
    # dangerous construct (unpinned third-party action / pwn-request / script-injection sink) over the
    # RETAINED control. NOT in the frozen _ALL_ORACLES, and fires only when the ctx carries `cicd_control`
    # (no benchmark finding does), so `make gate` stays byte-identical.
    "cicd_misconfiguration": (OracleKind.CICD_POSTURE,),
    # Mobile static-posture (Phase-2). A retained MobSF control (verify.mobile_posture / sensors.mobile)
    # is a LEAD; it becomes a FACT only when mobile_posture_oracle RE-DERIVES the weakness offline (this
    # slice: an embedded PEM private key that actually LOADS as an unencrypted key). NOT in the frozen
    # _ALL_ORACLES, and fires only when the ctx carries `mobile_control` (no benchmark finding does), so
    # `make gate` stays byte-identical.
    "mobile_misconfiguration": (OracleKind.MOBILE_POSTURE,),
    # Email-authentication posture (FORGE Domain 10). A retained DNS policy record (verify.email_auth /
    # sensors.email_auth) is a LEAD; it becomes a FACT only when email_auth_posture_oracle RE-DERIVES a
    # published policy that permits spoofing (no DMARC / p=none / SPF +all) over the RETAINED record. NOT in
    # the frozen _ALL_ORACLES, and fires only when the ctx carries `email_auth_control` (no benchmark finding
    # does), so `make gate` stays byte-identical.
    "email_auth_misconfiguration": (OracleKind.EMAIL_AUTH_POSTURE,),
    # Identity posture (FORGE Domain 7, slice 1): a retained IdP-export control (sensors.identity /
    # verify.identity_posture) is a LEAD; it becomes a FACT only when identity_posture_oracle RE-DERIVES a
    # weakness over STRICT-TYPED literal fields (a privileged identity with MFA provably off, or a credential
    # past its rotation policy). NOT in the frozen _ALL_ORACLES, and fires only when the ctx carries
    # `identity_control` (no benchmark finding does), so `make gate` stays byte-identical.
    "identity_misconfiguration": (OracleKind.IDENTITY_POSTURE,),
    # Workstream-B SSO/JWT structural-forgery: a captured JWT is a FACT (structurally forgeable) only
    # when the jwt-forgery oracle proves it from the token ALONE — alg=none/None, an HS* signature
    # recomputable from a supplied/weak key, or an RS256->HS256 confusion (the HS* sig verifies with a
    # supplied RSA public key as the HMAC secret). Like the AEGIS / k8s rows, this NEW OracleKind is
    # reachable ONLY via this row — it is NOT in the frozen _ALL_ORACLES fallback — and fires only when
    # the ctx carries `jwt_token`, which no benchmark/scan/engage finding does. So appending it leaves
    # the unknown-class fallback and `make gate` byte-identical. Distinct from the EXISTING `jwt` class
    # (alg:none ACCEPTANCE proved live via ACHIEVED_STATE) — this proves FORGEABILITY offline, no traffic.
    "jwt_forgeable": (OracleKind.SSO_ASSERTION_FORGERY,),
    # Workstream NW-1 SAML structural-forgery (the SAML SIBLING of `jwt_forgeable`): a captured SAML
    # Response is a FACT (structurally forgeable) only when the saml-forgery oracle proves it from the
    # captured XML ALONE — an unsigned consumed assertion, a ds:Reference/@URI that does not cover the
    # consumed element, or the signature-wrapping shape (the dual of scanner.sso.wrap_assertion_xsw).
    # Like the JWT / AEGIS / k8s rows, this NEW OracleKind is reachable ONLY via this row — it is NOT in
    # the frozen _ALL_ORACLES fallback — and fires only when the ctx carries `saml_xml`, which no
    # benchmark/scan/engage finding does. So appending it leaves the unknown-class fallback and `make
    # gate` byte-identical. DISTINCT from the LIVE `saml_signature_wrapping` / `saml_assertion_tampering`
    # classes (ACCEPTANCE proved live via ACHIEVED_STATE) — this proves FORGEABILITY offline, no traffic.
    "saml_structural_forgery": (OracleKind.SAML_STRUCTURAL_FORGERY,),
    # BUILD-PLAN §E1 (SSRF/foothold -> IMDS/metadata credential capture, the flagship exploitation-chain
    # oracle): a retrieved-from-IMDS credential LEAD becomes an achieved-effect FACT only when
    # imds_credential_capture_oracle re-derives, over the RETAINED capture ALONE (offline, ZERO network,
    # NO exploitation code), BOTH a structurally-valid credential FROM the metadata endpoint AND a
    # confirming call (sts:GetCallerIdentity / tokeninfo) that proves it authenticated. This is a DEFENSIVE
    # VERIFICATION oracle, never an attack runner. Like the posture rows, this NEW OracleKind is reachable
    # ONLY via this row — it is NOT in the frozen _ALL_ORACLES fallback — and fires only when the ctx
    # carries `imds_capture`, which no benchmark/scan/engage finding does. So appending it leaves the
    # unknown-class fallback and `make gate` byte-identical.
    "imds_credential_capture": (OracleKind.IMDS_CREDENTIAL_CAPTURE,),
    # E5 exposed-secret validity — SAME convention: NOT in the frozen _ALL_ORACLES fallback, fires ONLY when
    # the ctx carries `secret_capture` (no benchmark/scan/engage finding does), so appending it leaves the
    # unknown-class fallback and `make gate` byte-identical.
    "secret_credential_validity": (OracleKind.SECRET_CREDENTIAL_VALIDITY,),
    # E3 GCP service-account impersonation — SAME convention: NOT in the frozen _ALL_ORACLES fallback, fires
    # ONLY when the ctx carries `gcp_impersonation_capture` (no benchmark/scan/engage finding does), so
    # appending it leaves the unknown-class fallback and `make gate` byte-identical.
    "gcp_sa_impersonation": (OracleKind.GCP_SA_IMPERSONATION,),
    # E2 IAM privilege-escalation PRIMITIVE — SAME convention: NOT in the frozen _ALL_ORACLES fallback, fires
    # ONLY when the ctx carries `iam_escalation_capture` (no benchmark/scan/engage finding does), so appending
    # it leaves the unknown-class fallback and `make gate` byte-identical. DISTINCT bug class from
    # `iam_privilege_escalation` (which maps to POLICY_PATH reachability): this is the ACHIEVED-ESCALATION
    # (strict-gain) proof, its own evidence branch, a stronger claim than mere reachability.
    "iam_escalation_primitive": (OracleKind.IAM_ESCALATION_PRIMITIVE,),
    # E4 TIER-2 K8s dangerous-VERB / default-SA RBAC verb-grant — SAME convention: NOT in the frozen
    # _ALL_ORACLES fallback, fires ONLY when the ctx carries `k8s_rbac_grant_control` (no benchmark/scan/engage
    # finding does), so appending it leaves the unknown-class fallback and `make gate` byte-identical. Distinct
    # from the TIER-1 `k8s_workload_misconfiguration` row (K8S_WORKLOAD_POSTURE) — TIER-2 parses rules.
    "k8s_rbac_privilege_grant": (OracleKind.K8S_RBAC_VERB_GRANT,),
    # W16-STD-5 client-side POSTURE-WEAKNESS classes — the always-applicable constitution "Client-side"
    # classes (constitution §V: XSS [already mapped], CSRF, clickjacking, postMessage). Each proves a
    # MISSING/WEAK client-side DEFENSE (a posture weakness) — NEVER an achieved-state exploit. Like the
    # AEGIS/posture rows, each NEW OracleKind is reachable ONLY via its row — NOT in the frozen
    # _ALL_ORACLES fallback — and fires only when the ctx carries `clickjacking_control` /
    # `csrf_control` / `postmessage_control`, which no benchmark/scan/engage finding does, so appending
    # them leaves the unknown-class fallback and `make gate` byte-identical.
    "clickjacking": (OracleKind.CLICKJACKING_POSTURE,),
    "csrf": (OracleKind.CSRF_POSTURE,),
    "postmessage": (OracleKind.POSTMESSAGE_POSTURE,),
    # Wave-2.2 CLIENT-SIDE PROTOTYPE POLLUTION (scanner.proto_pollution, browser-backed, opt-in) — the
    # ACHIEVED-STATE client-side FACT (CWE-1321), not a posture check. A `__proto__[uniqKey]=uniqVal` gadget
    # driven across a client source (query/fragment/JSON) that actually POLLUTED Object.prototype in a real
    # headless DOM, read back via a planted binding and confirmed ONLY when Object.prototype[uniqKey] ===
    # uniqVal AND a benign-key control stayed undefined (never on the payload merely appearing). Like the
    # AEGIS / posture rows, this NEW OracleKind is reachable ONLY via this row — NOT in the frozen
    # _ALL_ORACLES fallback (stays EXACTLY 15) — and fires only when the ctx carries `proto_pollution`,
    # which no benchmark/scan/engage finding does, so appending it leaves the unknown-class fallback and
    # `make gate` byte-identical.
    "prototype_pollution": (OracleKind.PROTOTYPE_POLLUTION,),
    # Wave-2.3 CROSS-ORIGIN postMessage ACHIEVED-EXPLOIT (scanner.postmessage_exploited, browser-backed,
    # opt-in) — the strictly-stronger EXECUTION dual of the `postmessage` posture class above. A canary
    # gadget postMessage'd from a GENUINELY DIFFERENT (untrusted) origin — VIGIL's own attacker-origin sender
    # page on a fresh loopback port, framing the target — that the target's onmessage handler routed to an
    # EXECUTING sink, observed via VIGIL's own __crucible_xss binding call carrying a unique per-probe canary
    # in a real headless DOM (never on the handler merely receiving/echoing the message; a handler that CHECKS
    # event.origin, or routes to a non-executing sink, does not fire — that stays the `postmessage` posture /
    # data-leak residual). Reuses DOM_EXECUTION (already in the frozen _ALL_ORACLES) + SIDE_EFFECT for parity
    # with dom_xss/stored_xss, so this row adds NO new OracleKind and `make gate` stays byte-identical
    # (deep-only / off-by-default; it sends 0 requests through the default GET benchmark corpus). The
    # DOM_EXECUTION dispatch arm already keys on `dom_binding_calls`/`dom_canary`, which no benchmark/default
    # finding carries, so appending this row leaves the unknown-class fallback byte-identical.
    "postmessage_exploited": (OracleKind.DOM_EXECUTION, OracleKind.SIDE_EFFECT),
    # Wave-2.4 CSP PERMISSIVE-POLICY POSTURE (scanner.csp_bypass:capture_csp_posture / the retained enforced
    # CSP header, NO browser). The posture-FACT dual of the achieved bypass: the effective script-src of the
    # enforced (non-report-only) policy carries a real permissive weakness a browser honors — 'unsafe-inline'
    # with no neutralizing nonce/hash, a wildcard '*', an http:/data: scheme source, or 'unsafe-eval'. Like
    # the AEGIS / posture rows, this NEW OracleKind is reachable ONLY via this row — NOT in the frozen
    # _ALL_ORACLES fallback (stays EXACTLY 15) — and fires only when the ctx carries `csp_control`, which no
    # benchmark/scan/engage finding does, so appending it leaves the unknown-class fallback and `make gate`
    # byte-identical.
    "csp_posture": (OracleKind.CSP_POSTURE,),
    # Wave-2.4 ACHIEVED CSP BYPASS (scanner.csp_bypass, browser-backed, opt-in) — the strictly-stronger dual
    # of csp_posture. A canary that ACTUALLY EXECUTED in a real headless DOM (the __crucible_xss binding call,
    # DOM_EXECUTION) DESPITE a RETAINED enforced CSP whose effective script-src PURPORTED TO BLOCK it. Reuses
    # DOM_EXECUTION (+ SIDE_EFFECT for parity with dom_xss/stored_xss) — NO new OracleKind — but the
    # DOM_EXECUTION dispatch arm applies the `csp_purports_to_block` GUARD keyed on the `csp_block_control`
    # ctx field: if execution occurred with no enforced/purporting CSP (absent / report-only / permissive) it
    # is plain DOM-XSS and does NOT fire (the csp_posture class carries the permissive-weakness residual). No
    # benchmark/scan/default finding carries csp_block_control, so appending this row (deep-only /
    # off-by-default; 0 requests through the default GET corpus) leaves the fallback + `make gate`
    # byte-identical.
    "csp_bypass": (OracleKind.DOM_EXECUTION, OracleKind.SIDE_EFFECT),
}

# Spelling/format aliases folded onto canonical keys.
_ALIASES: dict[str, str] = {
    "sql_injection": "sqli",
    "blind_sqli": "boolean_sqli",
    "boolean_based_sqli": "boolean_sqli",
    "time_sqli": "time_based_sqli",
    "time_based_blind_sqli": "time_based_sqli",
    "blind_time_sqli": "time_based_sqli",
    "time_based_rce": "time_based_command_injection",
    "time_based_cmdi": "time_based_command_injection",
    "no_sqli": "nosqli",
    "nosql_injection": "nosqli",
    "ldap": "ldap_injection",
    "ldapi": "ldap_injection",
    "xpath": "xpath_injection",
    "xpathi": "xpath_injection",
    "xpath_injection_blind": "xpath_injection",
    "insecure_direct_object_reference": "idor",
    "broken_object_level_authorization": "bola",
    "broken_function_level_authorization": "bfla",
    "access_control": "broken_access_control",
    "authz": "authorization",
    "authentication_bypass": "auth_bypass",
    "privesc": "privilege_escalation",
    # business-logic / workflow-abuse spellings fold onto the single canonical class.
    "business_logic_abuse": "business_logic",
    "workflow_violation": "business_logic",
    "workflow_abuse": "business_logic",
    "state_machine_abuse": "business_logic",
    "parameter_tampering": "business_logic",
    "insufficient_workflow_validation": "business_logic",
    "server_side_request_forgery": "ssrf",
    "xml_external_entity": "xxe",
    "insecure_deserialization": "deserialization",
    "remote_code_execution": "rce",
    "os_command_injection": "command_injection",
    "cmdi": "command_injection",
    "server_side_template_injection": "ssti",
    "cross_site_scripting": "xss",
    "reflected_xss": "xss",
    # NOTE: `stored_xss` is NOT aliased to `xss` — it is a first-class BUG_CLASS_ORACLES entry routed to the
    # DOM_EXECUTION oracle (browser-confirmed execution of a persisted payload). Aliasing it to `xss` would
    # route it to REFLECTION_CONTEXT, which cannot prove execution of a stored payload and would silently
    # weaken the class. Second-order/persistent spellings fold onto the canonical `stored_xss` instead.
    "second_order_xss": "stored_xss",
    "persistent_xss": "stored_xss",
    # Client-side prototype-pollution spellings fold onto the canonical `prototype_pollution` key.
    "client_side_prototype_pollution": "prototype_pollution",
    "client_prototype_pollution": "prototype_pollution",
    "proto_pollution": "prototype_pollution",
    "prototype_pollution_client": "prototype_pollution",
    # Cross-origin postMessage ACHIEVED-EXPLOIT spellings fold onto the canonical `postmessage_exploited`
    # key (the EXECUTION dual). These are DISTINCT from the `postmessage` POSTURE spellings above (which fold
    # onto the data-leak/non-executing residual): an XSS-via-postMessage or cross-origin-postMessage exploit
    # is the browser-confirmed execution class, so it must route to DOM_EXECUTION, never POSTMESSAGE_POSTURE.
    "postmessage_xss": "postmessage_exploited",
    "post_message_xss": "postmessage_exploited",
    "postmessage_dom_xss": "postmessage_exploited",
    "cross_origin_postmessage": "postmessage_exploited",
    "cross_origin_postmessage_xss": "postmessage_exploited",
    "postmessage_code_execution": "postmessage_exploited",
    # CSP permissive-policy POSTURE spellings fold onto the canonical `csp_posture` key (the retained-header
    # weakness FACT). DISTINCT from `csp_bypass` (the browser-confirmed achieved-execution dual below): a
    # misconfiguration / weak-policy claim is the posture oracle, an achieved-bypass claim is DOM_EXECUTION.
    "content_security_policy": "csp_posture",
    "csp_weakness": "csp_posture",
    "csp_misconfiguration": "csp_posture",
    "csp_unsafe_inline": "csp_posture",
    "permissive_csp": "csp_posture",
    # Achieved CSP-bypass spellings fold onto the canonical `csp_bypass` key (execution DESPITE a blocking
    # CSP) — the browser-confirmed DOM_EXECUTION dual, never the posture oracle.
    "csp_bypass_xss": "csp_bypass",
    "content_security_policy_bypass": "csp_bypass",
    "directory_traversal": "path_traversal",
    "information_disclosure": "exposure",
    "sensitive_data_exposure": "sensitive_exposure",
    "misconfiguration": "security_misconfiguration",
    "framework_exposure": "exposure",
    "local_file_inclusion": "lfi",
    "file_read": "lfi",
    "port_open": "service_reachable",
    "reachable": "service_reachable",
    "service_reachability": "service_reachable",
    "open_port": "service_reachable",
    "tls_weakness": "weak_tls",
    "weak_cipher": "weak_tls",
    "deprecated_tls": "weak_tls",
    "ssl_weakness": "weak_tls",
    "weak_ssl": "weak_tls",
    # GraphQL DoS/abuse spelling variants folded onto the canonical classes.
    "graphql_depth": "graphql_depth_limit",
    "graphql_query_depth": "graphql_depth_limit",
    "graphql_deeply_nested_query": "graphql_depth_limit",
    "graphql_unbounded_depth": "graphql_depth_limit",
    "graphql_alias": "graphql_alias_overloading",
    "graphql_alias_abuse": "graphql_alias_overloading",
    "graphql_aliasing": "graphql_alias_overloading",
    "graphql_batching_abuse": "graphql_batching",
    "graphql_query_batching": "graphql_batching",
    "graphql_batch": "graphql_batching",
    "graphql_query_cost": "graphql_cost",
    "graphql_complexity": "graphql_cost",
    "graphql_resource_exhaustion": "graphql_cost",
    "vulnerable_component": "vulnerable_dependency",
    "known_vulnerable_dependency": "vulnerable_dependency",
    "outdated_dependency": "vulnerable_dependency",
    "sca": "vulnerable_dependency",
    "cve": "vulnerable_dependency",
    # cloud IAM privilege-path aliases (a cloud/IAM posture lead an oracle proves via a grant path)
    "iam_privesc": "iam_privilege_escalation",
    "iam_privilege_path": "privilege_path",
    "privilege_escalation_path": "privilege_path",
    "iam_path": "privilege_path",
    "over_privileged": "excessive_privilege",
    "overprivileged": "excessive_privilege",
    "excessive_permissions": "excessive_privilege",
    "excessive_privileges": "excessive_privilege",
    "over_permissioned": "excessive_privilege",
    # AEGIS aliases — spelling variants fold onto the HONEST canonical classes. Note
    # `automated_scraping` is deliberately an ALIAS onto `automated_access` (the honeypot
    # oracle proves AUTOMATION, not a "scraping" attack — P1), never its own confirmed class.
    "jailbreak": "prompt_injection",
    "llm_prompt_injection": "prompt_injection",
    "llm_injection": "prompt_injection",
    "indirect_prompt_injection": "prompt_injection",
    "system_prompt_leak": "system_prompt_disclosure",
    "system_prompt_exfiltration": "system_prompt_disclosure",
    "canary_disclosure": "system_prompt_disclosure",
    "automated_scraping": "automated_access",
    "honeypot_hit": "automated_access",
    "honeypot_fetch": "automated_access",
    "bot_access": "automated_access",
    # SSO / SAML / OIDC spelling variants (scanner.sso) fold onto the canonical classes.
    "xsw": "saml_signature_wrapping",
    "saml_xsw": "saml_signature_wrapping",
    "signature_wrapping": "saml_signature_wrapping",
    "xml_signature_wrapping": "saml_signature_wrapping",
    "saml_tampering": "saml_assertion_tampering",
    "saml_assertion_forgery": "saml_assertion_tampering",
    "saml_signature_bypass": "saml_assertion_tampering",
    "redirect_uri_validation": "oidc_redirect_uri",
    "oidc_open_redirect": "oidc_redirect_uri",
    "id_token_forgery": "oidc_idtoken_forgery",
    "idtoken_forgery": "oidc_idtoken_forgery",
    "oidc_idtoken_acceptance": "oidc_idtoken_forgery",
    # credential-stuffing / account-takeover spelling variants (the SAME provable signature:
    # one source achieving unseen-(account, source) successes across many accounts). Password
    # spraying is the same detection (breadth of compromise from one source), so it folds here.
    "account_takeover": "credential_stuffing",
    "ato": "credential_stuffing",
    "cred_stuffing": "credential_stuffing",
    "credential_stuffing_attack": "credential_stuffing",
    "credential_stuffing_ato": "credential_stuffing",
    "password_spraying": "credential_stuffing",
    # k8s-posture spelling variants (a kube-bench CIS-control failure an oracle proves via a concrete
    # observed insecure setting) fold onto the single canonical class.
    "k8s_posture": "k8s_misconfiguration",
    "kubernetes_misconfiguration": "k8s_misconfiguration",
    "cis_k8s_fail": "k8s_misconfiguration",
    "kube_bench_fail": "k8s_misconfiguration",
    "insecure_k8s_setting": "k8s_misconfiguration",
    # cloud/CSPM achieved-state posture spelling variants (a cloud-posture control an oracle proves via a
    # concrete insecure achieved state) fold onto the single canonical class. NOTE: the reachability-PATH
    # cloud classes (privilege_path / excessive_privilege, POLICY_PATH) are deliberately NOT aliased here
    # — achieved-STATE membership and reachability-PATH are distinct proofs and stay distinct classes.
    "cloud_posture": "cloud_misconfiguration",
    "cloud_misconfig": "cloud_misconfiguration",
    "cspm_finding": "cloud_misconfiguration",
    "cspm_misconfiguration": "cloud_misconfiguration",
    "cloud_security_misconfiguration": "cloud_misconfiguration",
    "public_bucket": "cloud_misconfiguration",
    "public_s3_bucket": "cloud_misconfiguration",
    "public_storage": "cloud_misconfiguration",
    "unencrypted_at_rest": "cloud_misconfiguration",
    "encryption_at_rest_disabled": "cloud_misconfiguration",
    "wildcard_principal": "cloud_misconfiguration",
    "anonymous_grant": "cloud_misconfiguration",
    "k8s_insecure_setting": "k8s_misconfiguration",
    # live-RBAC achieved-state posture spelling variants (an anonymous subject bound to a dangerous built-in
    # ClusterRole, re-derived over the retained binding) fold onto the single canonical class. NOTE: the
    # kube-bench control-plane class (`k8s_misconfiguration`, K8S_POSTURE) is deliberately NOT aliased here —
    # RBAC achieved-STATE and kube-bench CLI-flag proofs are distinct and stay distinct classes.
    "k8s_workload_posture": "k8s_workload_misconfiguration",
    "k8s_rbac_misconfiguration": "k8s_workload_misconfiguration",
    "anonymous_rbac_binding": "k8s_workload_misconfiguration",
    "anonymous_cluster_admin": "k8s_workload_misconfiguration",
    "rbac_anonymous_privileged_binding": "k8s_workload_misconfiguration",
    # E4 TIER-2 verb-grant spelling variants (a dangerous (verb,resource) grant PROVED over the referenced
    # role's PARSED rules) fold onto the single canonical class. Deliberately DISTINCT from the TIER-1
    # name-match class above — rule-parse and name-match are different proofs and stay different classes.
    "k8s_rbac_verb_grant": "k8s_rbac_privilege_grant",
    "k8s_rbac_dangerous_verb_grant": "k8s_rbac_privilege_grant",
    "k8s_dangerous_rbac_grant": "k8s_rbac_privilege_grant",
    "default_serviceaccount_privileged_binding": "k8s_rbac_privilege_grant",
    "rbac_dangerous_verb_grant": "k8s_rbac_privilege_grant",
    # service-mesh achieved-state posture spelling variants (a mesh-config control an oracle proves via a
    # concrete insecure achieved state) fold onto the single canonical class.
    "mesh_posture": "mesh_misconfiguration",
    "mesh_misconfig": "mesh_misconfiguration",
    "service_mesh_misconfiguration": "mesh_misconfiguration",
    "istio_misconfiguration": "mesh_misconfiguration",
    "linkerd_misconfiguration": "mesh_misconfiguration",
    "permissive_mtls": "mesh_misconfiguration",
    "peer_authentication_permissive": "mesh_misconfiguration",
    "authorization_policy_allow_all": "mesh_misconfiguration",
    "mesh_unauthenticated_inbound": "mesh_misconfiguration",
    # JWT structural-forgery spelling variants fold onto the single canonical class. NOTE: the existing
    # `jwt` class (alg:none ACCEPTANCE, ACHIEVED_STATE) is deliberately NOT aliased here — forgeability
    # (offline, token-alone) and acceptance (live) are distinct proofs and stay distinct classes.
    "jwt_forgery": "jwt_forgeable",
    "jwt_structural_forgery": "jwt_forgeable",
    "jwt_alg_none": "jwt_forgeable",
    "jwt_none_alg": "jwt_forgeable",
    "jwt_algorithm_confusion": "jwt_forgeable",
    "jwt_key_confusion": "jwt_forgeable",
    "rs256_hs256_confusion": "jwt_forgeable",
    "jwt_weak_secret": "jwt_forgeable",
    "jwt_weak_key": "jwt_forgeable",
    "jwt_signature_forgery": "jwt_forgeable",
    "sso_assertion_forgery": "jwt_forgeable",
    # SAML OFFLINE structural-forgery spelling variants fold onto the single canonical class. NOTE: the
    # LIVE `saml_signature_wrapping` / `saml_assertion_tampering` classes and their aliases (xsw,
    # signature_wrapping, saml_tampering, ...) are deliberately NOT aliased here — offline forgeability
    # (XML-alone) and live acceptance are distinct proofs and stay distinct classes.
    "saml_forgery": "saml_structural_forgery",
    "saml_forgeable": "saml_structural_forgery",
    "saml_structural_forgeability": "saml_structural_forgery",
    "saml_offline_forgery": "saml_structural_forgery",
    "saml_unsigned_assertion": "saml_structural_forgery",
    "saml_reference_mismatch": "saml_structural_forgery",
    # Wave-G2 NoSQL operator-injection ATTEMPT spelling variants fold onto the single canonical class.
    # NOTE: the LIVE `nosqli` class (and its `no_sqli`/`nosql_injection` aliases — response-side
    # boolean/differential/error proofs) is deliberately NOT aliased here: a request-side operator-as-key
    # ATTEMPT (a parse-proof on the request alone) and a live NoSQLi (proven on the app's response) are
    # distinct proofs and stay distinct classes, exactly as `sqli_attempt` is distinct from `sqli`.
    "nosqli_attempt": "nosql_injection_attempt",
    "nosql_operator_injection": "nosql_injection_attempt",
    "nosql_breakout": "nosql_injection_attempt",
    "mongo_injection_attempt": "nosql_injection_attempt",
    "mongodb_injection_attempt": "nosql_injection_attempt",
    "mongodb_operator_injection": "nosql_injection_attempt",
    # E1 IMDS/metadata credential-capture spelling variants fold onto the single canonical class. This is
    # the achieved-EFFECT proof (creds retrieved from IMDS AND proven usable), distinct from the cloud
    # posture classes above — a captured, authenticated credential, not a mis-configuration.
    "imds_capture": "imds_credential_capture",
    "imds_credential_theft": "imds_credential_capture",
    "metadata_credential_capture": "imds_credential_capture",
    "instance_metadata_credential_capture": "imds_credential_capture",
    "instance_metadata_credential_theft": "imds_credential_capture",
    "ssrf_to_imds": "imds_credential_capture",
    "imds_ssrf": "imds_credential_capture",
    "cloud_metadata_credential_capture": "imds_credential_capture",
    # E5 exposed-secret validity spellings.
    "exposed_secret_validity": "secret_credential_validity",
    "leaked_credential_validity": "secret_credential_validity",
    "secret_validity": "secret_credential_validity",
    "valid_exposed_secret": "secret_credential_validity",
    # E3 GCP service-account impersonation spellings.
    "gcp_service_account_impersonation": "gcp_sa_impersonation",
    "service_account_impersonation": "gcp_sa_impersonation",
    "sa_impersonation": "gcp_sa_impersonation",
    "gcp_impersonation": "gcp_sa_impersonation",
    "iam_serviceaccount_impersonation": "gcp_sa_impersonation",
    "iam_service_account_impersonation": "gcp_sa_impersonation",
    # E2 IAM escalation-PRIMITIVE spellings — DISTINCT from the reachability aliases above (`iam_privesc` /
    # `iam_privilege_path` fold onto the POLICY_PATH classes). These fold onto the achieved-escalation
    # (strict-gain) class. Audited for overlap: none of these keys exists elsewhere in BUG_CLASS_ORACLES /
    # _ALIASES, so no finding is silently re-routed to the weaker reachability oracle.
    "iam_escalation": "iam_escalation_primitive",
    "achieved_iam_escalation": "iam_escalation_primitive",
    "iam_privilege_escalation_primitive": "iam_escalation_primitive",
    # W16-STD-5 client-side posture spelling variants fold onto the single canonical class each.
    "clickjacking_posture": "clickjacking",
    "ui_redress": "clickjacking",
    "ui_redressing": "clickjacking",
    "frame_options_missing": "clickjacking",
    "missing_x_frame_options": "clickjacking",
    "frame_ancestors_missing": "clickjacking",
    "cross_site_request_forgery": "csrf",
    "csrf_posture": "csrf",
    "csrf_token_missing": "csrf",
    "missing_csrf_token": "csrf",
    "post_message": "postmessage",
    "post_message_misconfiguration": "postmessage",
    "postmessage_misconfiguration": "postmessage",
    "postmessage_posture": "postmessage",
    "postmessage_wildcard_origin": "postmessage",
    "insecure_postmessage": "postmessage",
}

# G1 (doctrine fix): the unknown-class fallback returned by `oracles_for()` is FROZEN to the
# pre-AEGIS OracleKind members — it is NOT `tuple(OracleKind)`. If it were derived from the
# enum, appending the AEGIS members would grow it, and every unknown-class finding in the
# benchmark would begin running the AEGIS oracles (they would skip for want of inputs but
# still land in `confirm()`'s `skipped` list and the serialized rationale), drifting the gate
# output. Keeping this list explicit means AEGIS oracle kinds are reachable ONLY through their
# explicit BUG_CLASS_ORACLES rows. A test asserts this tuple equals the members that existed
# before AEGIS and that `oracles_for("<unknown>")` is unchanged after `import aegis`.
_ALL_ORACLES: tuple[OracleKind, ...] = (
    OracleKind.DIFFERENTIAL_RESPONSE,
    OracleKind.ACHIEVED_STATE,
    OracleKind.SIDE_EFFECT,
    OracleKind.OOB_CALLBACK,
    OracleKind.SANITIZER_SIGNAL,
    OracleKind.TIMING,
    OracleKind.BOOLEAN_INFERENCE,
    OracleKind.REFLECTION_CONTEXT,
    OracleKind.EVALUATION,
    OracleKind.ERROR_SIGNATURE,
    OracleKind.DOM_EXECUTION,
    OracleKind.SERVICE_REACHABILITY,
    OracleKind.TLS_WEAKNESS,
    OracleKind.VERSION_RANGE,
    OracleKind.POLICY_PATH,
)


def normalize_bug_class(bug_class: str) -> str:
    key = (bug_class or "").strip().lower().replace("-", "_").replace(" ", "_")
    while "__" in key:
        key = key.replace("__", "_")
    return _ALIASES.get(key, key)


# ---------------------------------------------------------------------------
# Value-membership (anti-hallucination P6): the bug_class VOCABULARY, plus
# reusable pydantic validators so an INVENTED class cannot silently ride a
# structured LLM output. A class is "known" when it (canonically) maps to at
# least one oracle — i.e. it is something the deterministic substrate can
# actually adjudicate. Exploratory hypotheses may name broader classes (a
# race/cache-poisoning lead is legitimate); a class asserted as oracle-provable
# must be in this set or it is fabricated.
# ---------------------------------------------------------------------------


def known_bug_classes() -> frozenset[str]:
    """The canonical bug classes an oracle can prove (the value-membership universe).
    Includes the alias source spellings so a normalised alias also reads as known."""
    return frozenset(BUG_CLASS_ORACLES) | frozenset(_ALIASES) | frozenset(_ALIASES.values())


def is_known_bug_class(bug_class: str) -> bool:
    """True iff ``bug_class`` (after normalisation) is one the oracle vocabulary knows —
    i.e. a class the deterministic substrate can actually confirm."""
    return normalize_bug_class(bug_class) in known_bug_classes()


def canonical_bug_class(bug_class: str) -> str | None:
    """The canonical, oracle-provable class for ``bug_class``, or None if it is unknown
    (out of vocabulary → not something any oracle can prove)."""
    n = normalize_bug_class(bug_class)
    return n if n in known_bug_classes() else None


def canonical_oracle_for(bug_class: str) -> OracleKind | None:
    """The canonical (primary) oracle kind for a KNOWN bug class — the FIRST in its ``BUG_CLASS_ORACLES``
    tuple — used as the PCF certificate's ``oracle.binding`` reference. ``None`` for an out-of-vocabulary
    class (which a PCF verifier rejects at step 1). Several oracles may legitimately confirm one class; this
    names the canonical one for display/binding, while :func:`oracle_confirms_class` is the actual PCF
    step-5 membership check."""
    kinds = BUG_CLASS_ORACLES.get(normalize_bug_class(bug_class))
    return kinds[0] if kinds else None


def oracle_confirms_class(confirmed_by: str, bug_class: str) -> bool:
    """PCF step 5 (claim-grounded): ``True`` iff the oracle that fired is a VALID confirmer for the
    claimed class — i.e. it is in that class's acceptable oracle set. This defeats relabelling (you cannot
    claim class X with an oracle that does not confirm X). An out-of-vocabulary class returns ``False``
    (nothing in the substrate confirms it)."""
    kinds = BUG_CLASS_ORACLES.get(normalize_bug_class(bug_class))
    if not kinds:
        return False
    try:
        return OracleKind(str(confirmed_by)) in kinds
    except ValueError:
        return False


def require_known_bug_class(bug_class: str) -> str:
    """Pydantic AfterValidator: normalise, and REJECT an out-of-vocabulary class at PARSE
    time so an invented bug_class cannot survive into a schema field that asserts an
    oracle-provable subject. Use on fact/oracle-bound fields — NOT on exploratory
    hypotheses, whose class set is legitimately broader than the provable vocabulary."""
    n = normalize_bug_class(bug_class)
    if n not in known_bug_classes():
        raise ValueError(
            f"unknown bug_class {bug_class!r} (normalised {n!r}) — not in the oracle "
            f"vocabulary; an invented class cannot be asserted as oracle-provable")
    return n


# Reusable pydantic field types for structured LLM outputs:
#   NormalizedBugClass — canonicalise at parse (always; default-safe, no rejection).
#   KnownBugClass      — canonicalise AND reject an out-of-vocabulary class at parse
#                        (for fields that assert an oracle-provable subject).
NormalizedBugClass = Annotated[str, BeforeValidator(normalize_bug_class)]
KnownBugClass = Annotated[str, AfterValidator(require_known_bug_class)]


class OracleVerifier:
    """Runs deterministic oracles to confirm (or refuse) a finding."""

    def __init__(self, high_confidence: float = HIGH_CONFIDENCE,
                 oob_collector_pubkey: "str | None" = None, *,
                 oob_dns_collector_pubkey: "str | None" = None,
                 oob_ttl_seconds: "float | None" = None,
                 oob_skew_seconds: "float | None" = None,
                 oob_not_before: "float | None" = None,
                 oob_not_after: "float | None" = None) -> None:
        self.high_confidence = high_confidence
        # VF-2b OUT-OF-BAND pins: the collector public keys the OOB oracle checks each receipt against. These
        # are AUTHORITIES the caller supplies at construction — for OFFLINE re-verify, sourced from the SIGNED
        # engagement authority (available offline, never trusted from the producer ctx); on the live path, from
        # the in-process collector VIGIL itself runs (loopback-owned) or a charter-pinned remote relay. A
        # receipt-bearing hit re-verified with NO applicable pin fails CLOSED in the oracle (never a silent
        # token-only drop). ``oob_collector_pubkey`` checks HTTP receipts; ``oob_dns_collector_pubkey`` checks
        # DNS receipts (method == "DNS"). Both None ⇒ the intentional VF-2a token-only tier for UNSIGNED hits
        # (the default/benchmark path stays byte-identical).
        self.oob_collector_pubkey = oob_collector_pubkey
        self.oob_dns_collector_pubkey = oob_dns_collector_pubkey
        # The OWNER-SIGNED TTL DURATION + skew that bound a receipt-bearing hit's replay window. Taken OUT-OF-
        # BAND (from the signed authority), never from the producer ctx, so a producer-widened expires_at / huge
        # producer skew cannot re-confirm a stale receipt. None ⇒ the oracle's fixed default duration/skew.
        self.oob_ttl_seconds = oob_ttl_seconds
        self.oob_skew_seconds = oob_skew_seconds
        # The OWNER-SIGNED ENGAGEMENT WINDOW (epoch seconds) that is the ANTI-REPLAY BOUNDARY for a
        # receipt-bearing OOB hit. Sourced OUT-OF-BAND from the SAME signed EngagementAuthority as the pin +
        # TTL policy (via verifier_from_authority / the engage path), NEVER from the producer ctx. A receipt
        # whose TARGET-OBSERVED received_at falls outside [not_before - skew, not_after + skew] is EXPIRED /
        # REPLAY — this closes the year-1970 / prior-engagement slide a producer-controlled issued_at allowed.
        # None ⇒ no signed window threaded (direct/self-check call): only the advisory TTL bounds the hit.
        self.oob_not_before = oob_not_before
        self.oob_not_after = oob_not_after

    def oracles_for(self, bug_class: str) -> tuple[OracleKind, ...]:
        """The oracle kinds that can prove `bug_class`. Unknown classes fall
        back to every oracle; `confirm` then runs only those with inputs."""
        return BUG_CLASS_ORACLES.get(normalize_bug_class(bug_class), _ALL_ORACLES)

    def confirm(self, finding_context: Mapping[str, Any]) -> VerificationResult:
        """Confirm a finding from already-observed data.

        Recognised context keys (all optional; an oracle is skipped when its
        inputs are absent):

          bug_class                          str — selects the oracle set
          baseline, mutated, discriminator   -> differential_response_oracle
          expected_state, observed_state     -> achieved_state_oracle
          marker, observed_sink              -> side_effect_oracle
          process_output                     -> sanitizer_signal_oracle
          oob_hits                           -> oob_callback_oracle
          handshake                          -> service_reachability_oracle
          tls                                -> tls_weakness_oracle
          version_advisory                   -> version_range_oracle
          policy                             -> policy_path_oracle
        """
        ctx = dict(finding_context or {})
        bug_class = str(ctx.get("bug_class", ""))
        kinds = self.oracles_for(bug_class)

        signals: list[OracleSignal] = []
        skipped: list[str] = []
        for kind in kinds:
            sig = self._run(kind, ctx)
            if sig is None:
                skipped.append(kind.value)
            else:
                signals.append(sig)

        confirming = [s for s in signals if s.fired and s.confidence >= self.high_confidence]
        # ANTI-HALLUCINATION — unknown-class FAIL-CLOSED (audit A1). A confirmation is valid ONLY for a
        # bug_class the oracle vocabulary can actually prove. An INVENTED / out-of-vocabulary class must NEVER
        # become a confirmed FACT, even if a generic side-effect / OOB / reflection oracle fires over the
        # frozen ``_ALL_ORACLES`` fallback (that fallback runs for DIAGNOSTIC completeness in the rationale —
        # G1 — not to confirm a class no oracle is mapped to). Without this gate an unknown class rides a
        # fired fallback oracle to ``confirmed=True`` — a proof-soundness hole. This mirrors the PCF
        # verifier's step-1 vocabulary rejection, applied to the ORDINARY confirm path too.
        class_known = is_known_bug_class(bug_class)
        confirmed = class_known and len(confirming) > 0

        # Multi-oracle combine policy: any-high-confidence-fired (safety-monotone).
        # A non-firing oracle cannot veto a fired one, so when the finding is
        # confirmed we RECORD the oracles that ran but did not confirm as dissent
        # rather than treating them as a refutation. Dissent is only meaningful
        # once something confirmed (otherwise "not confirmed" already says it).
        confirming_kinds = {s.kind for s in confirming}
        dissent = (
            [s.kind.value for s in signals if s.kind not in confirming_kinds]
            if confirmed
            else []
        )

        rationale = self._rationale(bug_class, kinds, signals, confirming, skipped, dissent)
        if confirming and not class_known:
            # A would-be confirmation suppressed by the vocabulary gate — say so, loudly and auditable.
            rationale = (
                f"NOT CONFIRMED (fail-closed): bug_class {bug_class!r} is OUT OF the oracle vocabulary, so it "
                f"cannot be a FACT even though {[s.kind.value for s in confirming]} fired over the fallback "
                f"(an unknown class is a lead at most, never oracle-confirmed). " + rationale
            )

        return VerificationResult(
            confirmed=confirmed,
            bug_class=bug_class,
            signals=signals,
            combine_policy="any_high_confidence_fired",
            dissent=dissent,
            rationale=rationale,
        )

    # -- dispatch ----------------------------------------------------------

    def _run(self, kind: OracleKind, ctx: Mapping[str, Any]) -> OracleSignal | None:
        """Run one oracle if its inputs are present; else None (skipped)."""
        if kind is OracleKind.DIFFERENTIAL_RESPONSE:
            if "baseline" in ctx and "mutated" in ctx:
                return oracles.differential_response_oracle(
                    ctx["baseline"], ctx["mutated"], ctx.get("discriminator")
                )
            return None
        if kind is OracleKind.TIMING:
            if "baseline_latencies" in ctx and "treatment_latencies" in ctx:
                return oracles.timing_oracle(
                    ctx["baseline_latencies"], ctx["treatment_latencies"],
                    injected_ms=ctx.get("timing_injected_ms"),
                    alpha=float(ctx.get("timing_alpha", 0.01)),
                    dose=ctx.get("timing_dose"),
                )
            return None
        if kind is OracleKind.BOOLEAN_INFERENCE:
            if "probe_rounds" in ctx:
                return oracles.boolean_inference_oracle(
                    ctx["probe_rounds"],
                    discriminator=ctx.get("discriminator"),
                    **{k: ctx[f"sprt_{k}"] for k in ("alpha", "beta", "p1", "p0") if f"sprt_{k}" in ctx},
                )
            return None
        if kind is OracleKind.ACHIEVED_STATE:
            # Predicate mode (Wave 7): the oracle evaluates the dangerous
            # condition over raw observed values — no rubber-stamp.
            if "predicate" in ctx and "observed_evidence" in ctx:
                return oracles.predicate_oracle(ctx["observed_evidence"], ctx["predicate"])
            if "expected_state" in ctx and "observed_state" in ctx:
                return oracles.achieved_state_oracle(
                    ctx["expected_state"], ctx["observed_state"]
                )
            return None
        if kind is OracleKind.SIDE_EFFECT:
            if "marker" in ctx and "observed_sink" in ctx:
                return oracles.side_effect_oracle(ctx["marker"], ctx["observed_sink"])
            return None
        if kind is OracleKind.REFLECTION_CONTEXT:
            if "marker" in ctx and "observed_sink" in ctx:
                return oracles.reflection_context_oracle(ctx["marker"], ctx["observed_sink"])
            return None
        if kind is OracleKind.EVALUATION:
            if "eval_expected" in ctx and "eval_observed" in ctx:
                return oracles.evaluation_oracle(
                    ctx.get("eval_raw", ""), ctx["eval_expected"],
                    ctx["eval_observed"], ctx.get("eval_control"),
                )
            return None
        if kind is OracleKind.ERROR_SIGNATURE:
            if "error_observed" in ctx:
                return oracles.error_signature_oracle(ctx["error_observed"], ctx.get("error_control"))
            return None
        if kind is OracleKind.DOM_EXECUTION:
            if "dom_binding_calls" in ctx and "dom_canary" in ctx:
                # Wave-2.4 achieved CSP-bypass: when the ctx additionally carries `csp_block_control`
                # (ONLY the csp_bypass class sets it; no benchmark/scan/default finding does, so this is
                # inert on the gate path), the execution is a genuine BYPASS only if the retained ENFORCED
                # CSP purported to block it. A no-CSP / permissive / report-only execution is plain DOM-XSS
                # and the guarded oracle returns NON-firing — so a no-CSP execution can never be relabelled
                # a bypass and a tampered (permissive) CSP cannot mint the FACT offline.
                if "csp_block_control" in ctx:
                    return oracles.dom_execution_csp_bypass_oracle(
                        ctx["dom_binding_calls"], ctx["dom_canary"], ctx["csp_block_control"])
                return oracles.dom_execution_oracle(ctx["dom_binding_calls"], ctx["dom_canary"])
            return None
        # -- Wave-2.4 CSP permissive-policy posture — fire ONLY when the ctx carries `csp_control` (the
        #    retained enforced CSP header); no benchmark/scan/engage finding carries it, so it is inert on
        #    the gate path. Proves the PARSED permissive weakness, NEVER an achieved exploit.
        if kind is OracleKind.CSP_POSTURE:
            if "csp_control" in ctx:
                return oracles.csp_posture_oracle(ctx["csp_control"])
            return None
        if kind is OracleKind.SANITIZER_SIGNAL:
            if "process_output" in ctx:
                return oracles.sanitizer_signal_oracle(ctx["process_output"])
            return None
        if kind is OracleKind.OOB_CALLBACK:
            if "oob_hits" in ctx:
                # VF-2a: pass the retained registered token so the oracle fires only for a token-verified hit.
                # VF-2b (GAP A): the collector pin comes from the verifier's OUT-OF-BAND authority
                # (self.oob_collector_pubkey), NEVER from ctx (producer-controlled). None keeps the token-only
                # tier byte-identical; a pinned key demands an independent collector receipt.
                # TTL / replay (additive): the mint window is RETAINED on the ctx (producer-set at mint
                # time), so offline re-verify applies the SAME deterministic check over the receipt's
                # target-observed received_at. Both bounds absent ⇒ windowless ⇒ byte-identical. It is a
                # fail-open-safe refutation tool: a widened window only makes the TTL check more lenient —
                # the token + VF-2b receipt still gate firing.
                return oracles.oob_callback_oracle(
                    ctx["oob_hits"], ctx.get("oob_token"),
                    collector_pubkey=self.oob_collector_pubkey,
                    dns_collector_pubkey=self.oob_dns_collector_pubkey,
                    issued_at=ctx.get("oob_issued_at"), expires_at=ctx.get("oob_expires_at"),
                    skew=ctx.get("oob_skew"),
                    # TTL DURATION + skew for a receipt-bearing hit come from the OUT-OF-BAND authority, NOT
                    # the producer ctx — a widened ctx expires_at/skew is ignored on the VF-2b path.
                    authority_ttl=self.oob_ttl_seconds, authority_skew=self.oob_skew_seconds,
                    # The OWNER-SIGNED ENGAGEMENT WINDOW is the anti-replay boundary for a receipt-bearing
                    # hit — non-forgeable, from the signed authority, never the producer ctx.
                    authority_not_before=self.oob_not_before, authority_not_after=self.oob_not_after,
                )
            return None
        if kind is OracleKind.SERVICE_REACHABILITY:
            if "handshake" in ctx:
                return oracles.service_reachability_oracle(ctx["handshake"])
            return None
        # -- Slice-C3 active exposure — fire ONLY when the ctx carries `anon_get` (a retained
        #    unauthenticated GET); no benchmark/scan/engage finding does, so it is inert on the gate path.
        if kind is OracleKind.ACTIVE_EXPOSURE:
            if "anon_get" in ctx:
                return oracles.anonymous_reachable_oracle(ctx["anon_get"])
            return None
        if kind is OracleKind.TLS_WEAKNESS:
            if "tls" in ctx:
                return oracles.tls_weakness_oracle(ctx["tls"])
            if "crypto_artifact" in ctx:
                return oracles.weak_crypto_artifact_oracle(ctx["crypto_artifact"])
            return None
        if kind is OracleKind.VERSION_RANGE:
            if "version_advisory" in ctx:
                return oracles.version_range_oracle(ctx["version_advisory"])
        if kind is OracleKind.POLICY_PATH:
            if "policy" in ctx:
                return oracles.policy_path_oracle(ctx["policy"])
            return None
        # -- AEGIS (defensive dual) — fire ONLY when the ctx carries the AEGIS keys; no
        #    benchmark/scan/engage finding does, so these are inert on the gate path.
        if kind is OracleKind.SYSTEM_PROMPT_DISCLOSURE:
            if "canary" in ctx and "llm_output" in ctx:
                return oracles.system_prompt_disclosure_oracle(ctx["canary"], ctx["llm_output"])
            return None
        if kind is OracleKind.PROMPT_INJECTION:
            if "pi_control" in ctx and "pi_treatment" in ctx:
                return oracles.prompt_injection_oracle(ctx["pi_control"], ctx["pi_treatment"])
            return None
        if kind is OracleKind.AUTOMATED_ACCESS:
            if "requested_path" in ctx and "honeypot_paths" in ctx:
                return oracles.honeypot_hit_oracle(
                    ctx["requested_path"], ctx["honeypot_paths"],
                    crawler_allowlisted=bool(ctx.get("crawler_allowlisted", False)),
                )
            return None
        if kind is OracleKind.CREDENTIAL_STUFFING:
            if "auth_events" in ctx:
                return oracles.credential_stuffing_oracle(
                    ctx["auth_events"], benign_sources=ctx.get("benign_sources"),
                    **{k: ctx[f"credstuff_{k}"] for k in ("alpha", "beta", "p1", "p0", "fwer")
                       if f"credstuff_{k}" in ctx},
                )
            return None
        # -- AEGIS request-side parse-proof — fire ONLY when the ctx carries `request_payload`; no
        #    benchmark/scan/engage finding does, so these are inert on the gate path.
        if kind is OracleKind.SQL_INJECTION_BREAKOUT:
            if "request_payload" in ctx:
                return oracles.sql_injection_breakout_oracle(
                    ctx["request_payload"], param=str(ctx.get("payload_param", "")))
            return None
        if kind is OracleKind.COMMAND_INJECTION_BREAKOUT:
            if "request_payload" in ctx:
                return oracles.command_injection_breakout_oracle(
                    ctx["request_payload"], param=str(ctx.get("payload_param", "")))
            return None
        if kind is OracleKind.NOSQL_INJECTION_BREAKOUT:
            if "request_payload" in ctx:
                return oracles.nosql_injection_breakout_oracle(
                    ctx["request_payload"], param=str(ctx.get("payload_param", "")))
            return None
        # -- Workstream-3 k8s posture — fire ONLY when the ctx carries `k8s_control` (a retained
        #    kube-bench control); no benchmark/scan/engage finding does, so it is inert on the gate path.
        if kind is OracleKind.K8S_POSTURE:
            if "k8s_control" in ctx:
                return oracles.k8s_posture_oracle(ctx["k8s_control"])
            return None
        # -- C2·K8s live-RBAC posture — fire ONLY when the ctx carries `k8s_workload_control` (a retained live
        #    RBAC binding); no benchmark/scan/engage finding does, so it is inert on the gate path.
        if kind is OracleKind.K8S_WORKLOAD_POSTURE:
            if "k8s_workload_control" in ctx:
                return oracles.k8s_workload_posture_oracle(ctx["k8s_workload_control"])
            return None
        # -- Wave-F1 cloud/CSPM posture — fire ONLY when the ctx carries `cloud_control` (a retained cloud
        #    posture control); no benchmark/scan/engage finding does, so it is inert on the gate path.
        if kind is OracleKind.CLOUD_POSTURE:
            if "cloud_control" in ctx:
                return oracles.cloud_posture_oracle(ctx["cloud_control"])
            return None
        # -- Wave-G3 service-mesh posture — fire ONLY when the ctx carries `mesh_control` (a retained
        #    service-mesh config control); no benchmark/scan/engage finding does, so it is inert on the gate.
        if kind is OracleKind.MESH_POSTURE:
            if "mesh_control" in ctx:
                return oracles.mesh_posture_oracle(ctx["mesh_control"])
        # -- Phase-2 CI/CD posture — fire ONLY when the ctx carries `cicd_control` (a retained workflow
        # control), so this is inert on the benchmark/gate path.
        if kind is OracleKind.CICD_POSTURE:
            if "cicd_control" in ctx:
                return oracles.cicd_posture_oracle(ctx["cicd_control"])
            return None
        # -- Phase-2 mobile static-posture — fire ONLY when the ctx carries `mobile_control` (a retained
        # MobSF control), so this is inert on the benchmark/gate path.
        if kind is OracleKind.MOBILE_POSTURE:
            if "mobile_control" in ctx:
                return oracles.mobile_posture_oracle(ctx["mobile_control"])
            return None
        # -- FORGE Domain 10 email-auth posture — fire ONLY when the ctx carries `email_auth_control` (a
        # retained DNS policy record), so this is inert on the benchmark/gate path.
        if kind is OracleKind.EMAIL_AUTH_POSTURE:
            if "email_auth_control" in ctx:
                return oracles.email_auth_posture_oracle(ctx["email_auth_control"])
            return None
        # -- FORGE Domain 7 identity posture — fire ONLY when the ctx carries `identity_control` (a retained
        #    IdP-export control); no benchmark/scan/engage finding does, so it is inert on the gate path.
        if kind is OracleKind.IDENTITY_POSTURE:
            if "identity_control" in ctx:
                return oracles.identity_posture_oracle(ctx["identity_control"])
            return None
        # -- Workstream-B SSO/JWT structural-forgery — fire ONLY when the ctx carries `jwt_token` (a
        #    captured JWT string); no benchmark/scan/engage finding does, so it is inert on the gate path.
        if kind is OracleKind.SSO_ASSERTION_FORGERY:
            if "jwt_token" in ctx:
                return oracles.jwt_forgery_oracle(
                    ctx["jwt_token"], candidate_keys=ctx.get("jwt_candidate_keys", ()))
            return None
        # -- Workstream NW-1 SAML structural-forgery — fire ONLY when the ctx carries `saml_xml` (a
        #    captured SAML Response's decoded XML); no benchmark/scan/engage finding does, so it is inert
        #    on the gate path.
        if kind is OracleKind.SAML_STRUCTURAL_FORGERY:
            if "saml_xml" in ctx:
                # saml_candidate_certs (opt-in trusted IdP PEM certs) escalates to a real XML-DSig
                # verification when supplied AND signxml is importable; absent -> structural-only.
                return oracles.saml_forgery_oracle(
                    ctx["saml_xml"], candidate_certs=ctx.get("saml_candidate_certs", ()))
            return None
        # -- BUILD-PLAN §E1 IMDS/metadata credential capture — fire ONLY when the ctx carries
        #    `imds_capture` (a retained capture the WARDEN-gated runner produced); no benchmark/scan/engage
        #    finding does, so it is inert on the gate path. DEFENSIVE VERIFICATION, never an attack runner.
        if kind is OracleKind.IMDS_CREDENTIAL_CAPTURE:
            if "imds_capture" in ctx:
                return oracles.imds_credential_capture_oracle(ctx["imds_capture"])
            return None
        # -- BUILD-PLAN §E5 exposed-secret validity — fire ONLY when the ctx carries `secret_capture` (the
        #    WARDEN-gated secret-validation runner's retained evidence); no benchmark/scan/engage finding
        #    carries it, so it is inert on the gate path. DEFENSIVE VERIFICATION, never a validation runner.
        if kind is OracleKind.SECRET_CREDENTIAL_VALIDITY:
            if "secret_capture" in ctx:
                return oracles.exposed_secret_validity_oracle(ctx["secret_capture"])
            return None
        # -- BUILD-PLAN §E3 GCP service-account impersonation — fire ONLY when the ctx carries
        #    `gcp_impersonation_capture` (the WARDEN-gated impersonation runner's retained evidence); no
        #    benchmark/scan/engage finding carries it, so it is inert on the gate path. DEFENSIVE
        #    VERIFICATION, never an impersonation runner.
        if kind is OracleKind.GCP_SA_IMPERSONATION:
            if "gcp_impersonation_capture" in ctx:
                return oracles.gcp_sa_impersonation_oracle(ctx["gcp_impersonation_capture"])
        # -- BUILD-PLAN §E2 IAM privilege-escalation PRIMITIVE — fire ONLY when the ctx carries
        #    `iam_escalation_capture` (a retained IAM-policy capture); no benchmark/scan/engage finding
        #    carries it, so it is inert on the gate path. DEFENSIVE VERIFICATION over retained config, never
        #    an attack. Distinct from POLICY_PATH (`policy` ctx / reachability) — the strict-gain dual.
        if kind is OracleKind.IAM_ESCALATION_PRIMITIVE:
            if "iam_escalation_capture" in ctx:
                return oracles.iam_escalation_oracle(ctx["iam_escalation_capture"])
            return None
        # -- BUILD-PLAN §E4 TIER-2 K8s dangerous-verb / default-SA RBAC verb-grant — fire ONLY when the ctx
        #    carries `k8s_rbac_grant_control` (the WARDEN-gated RBAC runner's retained binding + role_object);
        #    no benchmark/scan/engage finding carries it, so it is inert on the gate path. DEFENSIVE
        #    VERIFICATION (a rule-parsing detector), never an RBAC-exploitation runner.
        if kind is OracleKind.K8S_RBAC_VERB_GRANT:
            if "k8s_rbac_grant_control" in ctx:
                return oracles.k8s_rbac_verb_grant_oracle(ctx["k8s_rbac_grant_control"])
            return None
        # -- W16-STD-5 client-side posture-weakness — fire ONLY when the ctx carries the retained
        #    client-side control; no benchmark/scan/engage finding carries these keys, so they are inert
        #    on the gate path. Each proves a MISSING/WEAK defense, NEVER an achieved-state exploit.
        if kind is OracleKind.CLICKJACKING_POSTURE:
            if "clickjacking_control" in ctx:
                return oracles.clickjacking_posture_oracle(ctx["clickjacking_control"])
            return None
        if kind is OracleKind.CSRF_POSTURE:
            if "csrf_control" in ctx:
                return oracles.csrf_posture_oracle(ctx["csrf_control"])
            return None
        if kind is OracleKind.POSTMESSAGE_POSTURE:
            if "postmessage_control" in ctx:
                return oracles.postmessage_posture_oracle(ctx["postmessage_control"])
            return None
        # -- Wave-2.2 client-side prototype pollution — fire ONLY when the ctx carries `proto_pollution`
        #    (the binding-reported achieved-state readback); no benchmark/scan/engage finding carries it,
        #    so it is inert on the gate path. Proves the ACHIEVED polluted state, NEVER "the payload
        #    appeared".
        if kind is OracleKind.PROTOTYPE_POLLUTION:
            if "proto_pollution" in ctx:
                return oracles.prototype_pollution_oracle(ctx["proto_pollution"])
            return None
        return None

    # -- rationale ---------------------------------------------------------

    def _rationale(
        self,
        bug_class: str,
        kinds: tuple[OracleKind, ...],
        signals: list[OracleSignal],
        confirming: list[OracleSignal],
        skipped: list[str],
        dissent: list[str] | None = None,
    ) -> str:
        if confirming:
            parts = "; ".join(
                f"{s.kind.value}@{s.confidence:.2f}: {s.evidence}" for s in confirming
            )
            msg = (
                f"CONFIRMED {bug_class or 'finding'} — "
                f"{len(confirming)} oracle(s) fired at high confidence: {parts}"
            )
            if dissent:
                # Record the disagreement without letting it veto (safety-monotone).
                msg += (
                    f". Dissent (ran, did not confirm, cannot veto): {dissent}"
                )
            return msg
        fired_low = [s for s in signals if s.fired]
        if fired_low:
            parts = "; ".join(
                f"{s.kind.value}@{s.confidence:.2f}" for s in fired_low
            )
            return (
                f"NOT confirmed — {len(fired_low)} oracle(s) fired but below the "
                f"{self.high_confidence:.2f} threshold: {parts}"
            )
        ran = [s.kind.value for s in signals]
        detail = f"ran {ran}" if ran else "no oracle had sufficient observed data"
        if skipped:
            detail += f"; skipped (no inputs): {skipped}"
        return f"NOT confirmed — no oracle fired for {bug_class or 'finding'}; {detail}"
