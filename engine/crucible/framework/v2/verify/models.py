"""
verify.models — Pydantic schemas for the deterministic verification layer.

Four shapes matter:

  OracleProbe          a passive description of what an oracle needs to
                       compare or observe. It names inputs abstractly
                       (references to already-collected responses/state,
                       a correlation token, a discriminator spec). It does
                       NOT generate payloads and it does NOT send traffic.
  OracleSignal         the verdict of one oracle over already-observed
                       data: did a real signal fire, how confident, and
                       the evidence that justifies it.
  VerificationResult   the aggregate: confirmed only when >=1 high-
                       confidence oracle fired, with every signal retained
                       for audit and a plain-language rationale.

Nothing here sends traffic or makes an LLM call. These are pure, validated
data shapes. The oracle logic lives in oracles.py; the out-of-band receiver
lives in oob.py; the dispatcher lives in verifier.py.
"""

from __future__ import annotations

import enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator


class OracleKind(str, enum.Enum):
    """The family of deterministic signal a finding can be confirmed by.

    Each kind maps to one pure oracle in oracles.py (plus the out-of-band
    receiver in oob.py for OOB_CALLBACK). A finding is confirmed by a real
    signal, never by an assertion."""

    DIFFERENTIAL_RESPONSE = "differential_response"  # boolean/time-based blind
    ACHIEVED_STATE = "achieved_state"                # unauthorized state reached
    SIDE_EFFECT = "side_effect"                       # unique marker reached a sink
    OOB_CALLBACK = "oob_callback"                     # blind out-of-band interaction
    SANITIZER_SIGNAL = "sanitizer_signal"             # ASAN/UBSAN/panic/traceback
    TIMING = "timing"                                 # statistical time-based blind
    BOOLEAN_INFERENCE = "boolean_inference"           # SPRT over repeated true/false probes
    REFLECTION_CONTEXT = "reflection_context"         # marker reached an executable HTML/JS context
    EVALUATION = "evaluation"                         # server evaluated an injected expression (SSTI/EL)
    ERROR_SIGNATURE = "error_signature"               # a datastore/parser error a payload provoked (error-based)
    DOM_EXECUTION = "dom_execution"                   # injected JS actually executed in a real DOM (DOM-XSS)
    SERVICE_REACHABILITY = "service_reachability"     # a real transport handshake reproduced (port open)
    TLS_WEAKNESS = "tls_weakness"                     # a real TLS handshake negotiated a weak protocol/cipher
    VERSION_RANGE = "version_range"                   # a package version provably falls in an advisory's affected range
    POLICY_PATH = "policy_path"                       # a real IAM grant path lets a principal reach a resource
    # AEGIS (the DEFENSIVE dual — prove-don't-guess pointed inward at the operator's OWN app).
    # These are ADDITIVE appends; they reach the verifier ONLY via their explicit
    # BUG_CLASS_ORACLES rows, never via the frozen unknown-class fallback (verifier._ALL_ORACLES).
    PROMPT_INJECTION = "prompt_injection"             # an injected directive PROVABLY flipped a structurally-detectable LLM behavior (control-vs-treatment)
    SYSTEM_PROMPT_DISCLOSURE = "system_prompt_disclosure"  # a planted high-entropy canary sentinel appeared VERBATIM in the app's own LLM output
    AUTOMATED_ACCESS = "automated_access"             # a non-interactive client fetched a honeypot resource no human UI links (set-membership)
    CREDENTIAL_STUFFING = "credential_stuffing"       # a source achieved SPRT-significant successful logins across many UNSEEN (account, source) pairs (ATO), Holm-controlled across identities
    # AEGIS request-side PARSE-PROOF (the inline "provable firewall" gateway) — judged on the REQUEST
    # ALONE (no app response). Each proves a STRUCTURED INJECTION ATTEMPT (a payload provably breaks
    # grammar), NOT that the app is exploited. Additive appends reachable ONLY via their explicit
    # BUG_CLASS_ORACLES rows (keyed on `request_payload`), never the frozen _ALL_ORACLES fallback.
    SQL_INJECTION_BREAKOUT = "sql_injection_breakout"        # a value provably closes a SQL string literal and introduces query STRUCTURE (tautology / UNION SELECT / stacked keyword)
    COMMAND_INJECTION_BREAKOUT = "command_injection_breakout"  # a value contains an unambiguous shell command-execution construct ($(cmd) / `cmd` / separator + known command)
    # Wave-G2 NoSQL (MongoDB-style) operator injection — the request-side sibling of the two above. Like
    # them, this is an ADDITIVE append reachable ONLY via its explicit BUG_CLASS_ORACLES row (keyed on the
    # SAME `request_payload` ctx field no benchmark/scan/engage finding carries), never via the frozen
    # unknown-class fallback (verifier._ALL_ORACLES stays EXACTLY 15). NOSQL_INJECTION_BREAKOUT proves a
    # STRUCTURED NoSQL operator-injection ATTEMPT (a payload provably injects MongoDB QUERY-OPERATOR
    # STRUCTURE), NOT that the app is exploited — a $-prefixed KNOWN query operator (`$ne`/`$gt`/`$where`/
    # `$regex`/`$in`/`$or`…) appearing as a KEY where a scalar was expected: (a) as a bracket/dot key
    # SEGMENT of the parameter NAME (`user[$ne]`, `q[$gt]`, `user.$ne`, a bare `$where`) — the framework
    # nests it into `{user:{$ne:…}}`; or (b) as an object KEY when the VALUE parses to JSON (`{"$ne":null}`,
    # `{"$gt":""}`). Near-zero-FP by STRUCTURE: the token must be a KNOWN query/logical operator (a curated
    # allowlist — NOT the EJSON/JSON-Schema/JSON-LD `$oid`/`$date`/`$schema`/`$ref` keys that legitimately
    # appear in bodies) AND a KEY. A price `$5.00`, `$net`, an email, a regex `^admin$`, a mid-word `$`
    # (`pass$word`), an operator as a string VALUE (`["$ne"]`), or a plain scalar do NOT fire.
    NOSQL_INJECTION_BREAKOUT = "nosql_injection_breakout"
    # Workstream-3 posture (the DORMANT-sensor promotions). Like the AEGIS members above, this is an
    # ADDITIVE append reachable ONLY via its explicit BUG_CLASS_ORACLES row (keyed on the `k8s_control`
    # ctx field no benchmark/scan/engage finding carries), never via the frozen unknown-class fallback
    # (verifier._ALL_ORACLES). K8S_POSTURE promotes a kube-bench CIS-control-failure LEAD to a FACT only
    # when the RETAINED control evidence proves a CONCRETE insecure setting — a FAILED control whose
    # observed value literally carries a dangerous flag (a benign/passing control never fires). (The
    # cloud/CSPM public-exposure & over-broad-trust promotions reuse the EXISTING POLICY_PATH oracle
    # over the retained policy graph, and live service-reachability the EXISTING SERVICE_REACHABILITY
    # oracle over a gated handshake — so neither adds a new kind.)
    K8S_POSTURE = "k8s_posture"                       # a kube-bench CIS control FAILED with a concrete observed insecure setting (membership/parse-proof over the retained control)
    # Kubernetes RBAC achieved-state posture — the LIVE-cluster (sensors.k8s_live) sibling of K8S_POSTURE and
    # the RBAC twin of CLOUD_POSTURE. Distinct from K8S_POSTURE (which judges kube-bench control-plane CLI
    # flags) so the two oracles carry DISTINCT versions and never collide in oracle_version / reverify. Like
    # the AEGIS / K8S_POSTURE / CLOUD_POSTURE members above, this is an ADDITIVE append reachable ONLY via its
    # explicit BUG_CLASS_ORACLES row (keyed on the `k8s_workload_control` ctx field NO benchmark/scan/engage
    # finding carries), never via the frozen unknown-class fallback (verifier._ALL_ORACLES stays EXACTLY 15).
    # K8S_WORKLOAD_POSTURE promotes a retained live RBAC-binding control to a FACT — judged over the control's
    # RETAINED raw subjects + role ALONE, offline, ZERO cluster calls — ONLY when an ANONYMOUS subject
    # (system:anonymous / system:unauthenticated) is bound to a genuinely DANGEROUS built-in ClusterRole
    # (cluster-admin / admin / edit): unauthenticated write/admin access no cluster ships by default. The
    # benign built-in system:public-info-viewer binding, an anonymous binding to a non-dangerous/custom role,
    # a binding with no anonymous subject, and malformed evidence do NOT fire (near-zero-FP).
    K8S_WORKLOAD_POSTURE = "k8s_workload_posture"
    # Workstream-B SSO/JWT structural-forgery. Like the AEGIS / K8S_POSTURE members above, this is an
    # ADDITIVE append reachable ONLY via its explicit BUG_CLASS_ORACLES row (keyed on the `jwt_token`
    # ctx field no benchmark/scan/engage finding carries), never via the frozen unknown-class fallback
    # (verifier._ALL_ORACLES stays EXACTLY 15). SSO_ASSERTION_FORGERY promotes a captured JWT to a
    # STRUCTURALLY-FORGEABLE FACT — judged on the token ALONE, offline, ZERO forged traffic — ONLY on a
    # re-runnable proof: (a) ``alg=none``/``None`` (a valid token needs NO secret, so anyone can mint
    # one); (b) an HS256 signature RECOMPUTABLE from a supplied/weak candidate key (the exact HMAC
    # reproduces — a deterministic fact); or (c) an RS256->HS256 algorithm confusion (the HS256 signature
    # verifies with a supplied RSA PUBLIC key as the HMAC secret — public material anyone holds). A
    # normal RS256 token with an unknown key, or an HS256 token whose secret is not recoverable, does NOT
    # fire (near-zero-FP). SAML XSW/c14n forgery is deliberately NOT attempted in this slice (JWT-only).
    SSO_ASSERTION_FORGERY = "sso_assertion_forgery"
    # Workstream NW-1 — the SAML SIBLING of SSO_ASSERTION_FORGERY (the offline STRUCTURAL complement to
    # the LIVE response-differential SAML checks in scanner.sso). Like the AEGIS / K8S_POSTURE / JWT
    # members above, this is an ADDITIVE append reachable ONLY via its explicit BUG_CLASS_ORACLES row
    # (keyed on the `saml_xml` ctx field NO benchmark/scan/engage finding carries), never via the frozen
    # unknown-class fallback (verifier._ALL_ORACLES stays EXACTLY 15). SAML_STRUCTURAL_FORGERY promotes a
    # captured SAML Response to a STRUCTURALLY-FORGEABLE FACT — judged on the captured XML ALONE, offline,
    # ZERO forged traffic, on the XXE-safe parse — ONLY on a coarse, c14n-free STRUCTURAL invariant a
    # validly signed assertion cannot exhibit: (a) the assertion carrying the consumed NameID has ZERO
    # ds:Signature anywhere (unsigned => anyone mints it); (b) every ds:Reference/@URI points at some id
    # OTHER than the consumed assertion (or an ancestor) — the signature does not cover the consumed
    # element; or (c) the signature-wrapping shape (>1 assertion, the unsigned consumed one supplies the
    # identity while a signature references a DIFFERENT assertion — the dual of scanner.sso's
    # wrap_assertion_xsw). A properly signed single assertion whose Reference covers it does NOT fire
    # (near-zero-FP). Full XML-DSig C14N/transform processing is deliberately NOT attempted (needs
    # lxml/signxml — out of scope); anything softer than these invariants stays an SsoLead.
    SAML_STRUCTURAL_FORGERY = "saml_structural_forgery"
    # Wave-F1 cloud/CSPM posture — the ACHIEVED-STATE sibling of K8S_POSTURE (the offline promotion of a
    # RETAINED cloud-posture LEAD, ``sensors.cloud.cloud_posture_leads``). Like the AEGIS / K8S_POSTURE /
    # JWT / SAML members above, this is an ADDITIVE append reachable ONLY via its explicit
    # BUG_CLASS_ORACLES row (keyed on the `cloud_control` ctx field NO benchmark/scan/engage finding
    # carries), never via the frozen unknown-class fallback (verifier._ALL_ORACLES stays EXACTLY 15).
    # CLOUD_POSTURE promotes a retained cloud-posture control to a FACT — judged over the control's
    # RETAINED achieved-state ALONE, offline, ZERO cloud calls — ONLY on a deterministic membership/
    # parse-proof that a COMPLIANT control cannot exhibit: (a) encryption-at-rest DISABLED on a sensitive
    # datastore (``encrypted`` explicitly ``false`` + ``sensitive`` — the un-oracle-provable
    # `misconfiguration` lead the policy-path oracle STRUCTURALLY cannot prove, now provable as an
    # achieved STATE); (b) an achieved PUBLIC-EXPOSURE flag (``public`` explicitly ``true``); or (c) a
    # WILDCARD/anonymous principal literally named in the retained resource policy. A compliant control
    # (encryption on, not public, no wildcard principal) or one with only ABSENT/unknown flags does NOT
    # fire (near-zero-FP). Distinct from the LIVE reachability-PATH proof (POLICY_PATH re-derives a grant
    # path over the whole policy GRAPH in ``confirm_cloud_posture_facts``): this is the single-control
    # achieved-STATE membership lens — a parse-proof over ONE retained control record, no graph traversal.
    CLOUD_POSTURE = "cloud_posture"
    # Wave-G3 service-mesh posture — the MESH twin of K8S_POSTURE / CLOUD_POSTURE (the offline promotion of
    # a RETAINED service-mesh-config LEAD, ``verify.mesh_posture.ingest_mesh_config``). Like the AEGIS /
    # K8S_POSTURE / CLOUD_POSTURE / JWT / SAML members above, this is an ADDITIVE append reachable ONLY via
    # its explicit BUG_CLASS_ORACLES row (keyed on the `mesh_control` ctx field NO benchmark/scan/engage
    # finding carries), never via the frozen unknown-class fallback (verifier._ALL_ORACLES stays EXACTLY
    # 15). MESH_POSTURE promotes a retained mesh-config control to a FACT — judged over the control's
    # RETAINED achieved-state ALONE, offline, ZERO mesh/kubectl calls — ONLY on a deterministic membership/
    # parse-proof that a HARDENED mesh cannot exhibit: (a) an Istio PeerAuthentication whose effective
    # ``mtls.mode`` is ``PERMISSIVE`` or ``DISABLE`` (plaintext is accepted — a STRICT-mTLS mesh cannot);
    # (b) an Istio AuthorizationPolicy with ``action: ALLOW`` whose rules provably admit EVERY caller (an
    # empty catch-all rule, or a ``*`` wildcard principal named in ``from.source.principals``); or (c) a
    # Linkerd server whose ``default-inbound-policy`` is ``all-unauthenticated`` (any client, unmeshed and
    # unauthenticated, may connect). A STRICT PeerAuthentication, a scoped/deny AuthorizationPolicy, an
    # ALLOW policy with no rules (deny-all), an authenticated Linkerd policy, or a control with only
    # ABSENT/unknown fields do NOT fire (near-zero-FP). NO live mesh call is ever made; a service-mesh
    # ATTACK is never performed — this is a pure re-derivation over already-ingested config.
    MESH_POSTURE = "mesh_posture"

    # CI/CD-pipeline posture (Phase-2 coverage). Reachable ONLY via its `cicd_misconfiguration`
    # BUG_CLASS_ORACLES row — NOT in the frozen _ALL_ORACLES fallback (stays EXACTLY 15) — and fires only
    # when the ctx carries `cicd_control` (a retained workflow control no benchmark finding carries), so
    # `make gate` stays byte-identical. Promotes a parsed GitHub-Actions control to a FACT via a
    # re-verifiable parse-proof over the RETAINED control: (a) a third-party action pinned to a MUTABLE
    # (non-SHA) ref (supply-chain); (b) a `pull_request_target` workflow that checks out the untrusted PR
    # head (pwn-request: attacker code runs with write-scoped secrets); (c) a `run:` shell step that
    # interpolates an UNTRUSTED `github.event.*` / `github.head_ref` expression (script-injection sink).
    # A SHA-pinned action, a plain `pull_request` trigger, a first-party (`actions/*`) action, and a
    # `run:` with no untrusted expression do NOT fire (near-zero-FP). NO repo is cloned, NO pipeline runs
    # — a pure re-derivation over the operator-supplied workflow YAML.
    CICD_POSTURE = "cicd_posture"
    # Mobile static-posture (Phase-2 coverage). BUG_CLASS_ORACLES row — NOT in the frozen _ALL_ORACLES
    # (stays EXACTLY 15) — fires only when the ctx carries `mobile_control` (a retained MobSF control no
    # benchmark finding carries), so `make gate` stays byte-identical. The adversarial soundness map ruled
    # nearly every mobile signal a LEAD (an Android precedence/gating chain the manifest omits: NSC-vs-attr
    # cleartext, min-vs-target-SDK, explicit-vs-default export). The ONE offline-re-derivable FACT this
    # oracle proves is an embedded PRIVATE-KEY PEM block: it RE-DERIVES by actually LOADING the key material
    # (`cryptography`), firing ONLY on an UNENCRYPTED, structurally-valid private key — an encrypted key, a
    # public key, a cert, a masked/partial blob, or an unparseable string do NOT fire (REFUSE, never assert
    # the negative). A distributed client that ships a loadable private key is a true, rarely-benign, fully
    # re-verifiable weakness (the key is extractable by anyone).
    MOBILE_POSTURE = "mobile_posture"
    # Email-authentication posture (FORGE Domain 10 — the first FORGE-built stream). BUG_CLASS_ORACLES row
    # — NOT in the frozen _ALL_ORACLES (stays EXACTLY 15) — fires only when the ctx carries
    # `email_auth_control` (a retained DNS policy record no benchmark finding carries), so `make gate` stays
    # byte-identical. Proves that a domain's PUBLISHED policy provably permits spoofing, re-derived from the
    # retained TXT records: DMARC `p=none` (explicitly instructs receivers NOT to enforce), SPF `+all` (any
    # host may send as the domain), or an absent DMARC record whose EFFECTIVE policy is resolvable as
    # absent/none. A hardened domain (`p=reject`/`p=quarantine`, SPF `-all`) does NOT fire — INCLUDING a
    # subdomain that publishes nothing and inherits an enforcing organizational policy (RFC 7489 §6.6.3
    # fallback, §6.3 `sp=`): that chain is resolved from RETAINED evidence or the oracle REFUSES, never
    # asserts. DELIBERATELY NOT message-level SPF/DKIM verification: DKIM canonicalisation
    # and SPF include-chains are a semantic layer this cannot soundly re-derive offline, and an
    # `Authentication-Results` header would be the receiving MTA's say-so (string trust) — those stay LEADs.
    # `spf_missing` alone does NOT fire either (DKIM+DMARC can still protect — a gating chain we refuse).
    EMAIL_AUTH_POSTURE = "email_auth_posture"
    # Identity posture (FORGE Domain 7, slice 1). BUG_CLASS_ORACLES row — NOT in the frozen _ALL_ORACLES
    # (stays EXACTLY 15) — fires only when the ctx carries `identity_control` (a retained IdP-export control
    # no benchmark finding carries), so `make gate` stays byte-identical. Proves an identity-posture weakness
    # by pure re-derivation over an export's STRICT-TYPED literal fields: `privileged_without_mfa` (a
    # producer-attested privileged identity with MFA provably absent — `privileged is True` AND
    # `mfa_enrolled is False`; an ABSENT mfa flag REFUSES, never asserts absence), or `stale_credential`
    # (`never_rotated is True`, or two retained integers `age_days >= max_age_days`). A compliant identity
    # (privileged + MFA on, credential within its rotation age) does NOT fire. DELIBERATELY out of scope
    # (REFUSE, never assert): anomaly/behavioral detection (probabilistic — cannot be a near-zero-FP FACT);
    # cloud-resource IAM (POLICY_PATH/CLOUD_POSTURE own that); privilege INFERENCE from role names (the oracle
    # requires the `privileged` producer attestation, never guesses). Offline; no IdP call, no auth attempt.
    # `privileged`/`mfa_enrolled`/`never_rotated` are read by STRICT identity (`is True`/`is False`), never
    # coerced; `max_age_days` is producer-supplied POLICY; `age_days` is a retained integer (no wall-clock).
    IDENTITY_POSTURE = "identity_posture"
    # Slice-C3 ACTIVE EXPOSURE — the LIVE, GATED, UNAUTHENTICATED confirmation that a cloud resource
    # POSTURE already re-derived as PUBLIC (an anonymous grant path, POLICY_PATH) is genuinely reachable
    # by an anonymous client: a bounded, credential-free HTTP GET is CAPTURED and this oracle judges the
    # RETAINED response ALONE (an unauthenticated 2xx with a present body). "Posture says public" ->
    # "PROVEN anonymously reachable". Like the posture members above, this NEW OracleKind is reachable ONLY
    # via its explicit BUG_CLASS_ORACLES row (keyed on the `anon_get` ctx field no benchmark/scan/engage
    # finding carries), never via the frozen unknown-class fallback (verifier._ALL_ORACLES) — so appending
    # it leaves that fallback and `make gate` byte-identical. It NEVER launders the live call into a fact:
    # the GET is the capture; this pure oracle is the sole authority over the retained capture, and the
    # confirmed FACT re-verifies OFFLINE from that JSON-safe capture with no network.
    ACTIVE_EXPOSURE = "active_exposure"
    # E1 (BUILD-PLAN §E1) — the flagship EXPLOITATION-CHAIN oracle: SSRF/foothold -> IMDS/metadata
    # credential capture. This is the DEFENSIVE-VERIFICATION dual of an attack, NOT an attack runner:
    # it CONFIRMS an ACHIEVED EFFECT (role/SA credentials were actually retrieved from the instance
    # metadata endpoint AND proven usable) over a JSON-safe RETAINED capture ALONE — offline, ZERO
    # network, NO exploitation code. The live "reach IMDS, use the token" action is a SEPARATE
    # WARDEN-A2-gated runner; this oracle is the sole authority over the evidence that runner retained,
    # so a confirmed FACT re-verifies offline from its certificate with no target. Like the posture
    # members above, this NEW OracleKind is reachable ONLY via its explicit BUG_CLASS_ORACLES row
    # (keyed on the `imds_capture` ctx field NO benchmark/scan/engage finding carries), never via the
    # frozen unknown-class fallback (verifier._ALL_ORACLES stays EXACTLY 15) — so appending it leaves
    # `make gate` byte-identical. IMDS_CREDENTIAL_CAPTURE fires (0.95) ONLY when the retained capture
    # carries BOTH halves (near-zero-FP by construction): (a) a STRUCTURALLY-VALID credential whose source
    # is a URL that HOST-IDENTIFIES the metadata endpoint — the source is parsed with urllib.parse.urlsplit
    # and its HOST (never a substring of the raw string) must be the metadata endpoint, with the credential
    # marker in the URL PATH — AWS: AccessKeyId matching ^A[SK]IA[0-9A-Z]{16,}$ + a non-empty
    # SecretAccessKey + a non-empty Token, whose source URL's HOST canonicalizes to 169.254.169.254 (incl.
    # the decimal/hex/IPv6-mapped SSRF IP encodings) and whose PATH carries iam/security-credentials; OR
    # GCP: a non-empty access_token + token_type==bearer (case-insensitive), whose source URL's HOST is
    # metadata.google.internal/metadata (or the same link-local IP) and whose PATH carries
    # computeMetadata/v1 + service-accounts + token; AND (b) a retained CONFIRMING-CALL response proving the
    # credential AUTHENTICATED — AWS: an sts:GetCallerIdentity response carrying an Arn + a 12-digit Account
    # + a UserId; OR GCP: a tokeninfo/userinfo success carrying an email/sub (expiry optional — userinfo
    # omits it) — with NO failure signal (no 4xx/5xx, no error/errors/message/code/__type/Fault field), and
    # the credential's provider and the confirming call's provider agree. Because the source is HOST-checked
    # with a real URL parser (not substring containment), a userinfo-@ host, a query-param IP, a rebind host
    # that merely CONTAINS the IP, and a creds-file path are all NOT an IMDS reach. A retrieved-but-
    # unconfirmed credential is a LEAD; a 401/timeout, a FAILED confirming call, a credential whose source
    # does not host-identify the metadata endpoint, a random blob, or malformed/absent evidence do NOT fire.
    IMDS_CREDENTIAL_CAPTURE = "imds_credential_capture"

    # E5 (BUILD-PLAN §E5) exposed-secret VALIDITY. Like IMDS, kept OUT of the frozen _ALL_ORACLES fallback
    # (verifier._ALL_ORACLES stays EXACTLY 15) and fired ONLY via its bug_class row keyed on the
    # `secret_capture` ctx field that NO benchmark/scan/engage finding carries — so appending it leaves
    # `make gate` byte-identical and it never auto-fires on a scan. SECRET_CREDENTIAL_VALIDITY fires (0.95)
    # ONLY when a RETAINED, secret-safe capture proves an EXPOSED secret is VALID: (a) a structurally-
    # recognized secret TYPE (the closed four-row set aws_access_key / github_pat / gitlab_pat / slack_token)
    # whose non-secret IDENTIFIER shape checks pass
    # (the secret value itself is a [REDACTED] presence marker, never validated for content); AND (b) a
    # retained CONFIRMING-CALL response proving the secret AUTHENTICATED as a real identity (AWS
    # sts:GetCallerIdentity Arn/Account/UserId; GitHub GET /user login+numeric-id; GitLab GET /api/v4/user
    # username+numeric-id; Slack auth.test ok:true+user_id) with NO failure marker,
    # the confirming call's action matching the type, the confirming endpoint on the per-TYPE allow-list (the
    # ANTI-LAUNDERING gate — an attacker-controlled 'confirming' endpoint can never mint a FACT), and the
    # secret fingerprint-BOUND to that call over a trusted transport. SOURCE-SEMANTICS INVERSION vs IMDS: the
    # exposure `source` (a JS literal, a git blob, a config path, an ARN) is RETAINED as evidence but is NOT
    # a firing gate — E5 asserts VALIDITY, not provenance. A recognized-but-unconfirmed secret is a LEAD; a
    # failed/4xx/error-shaped confirming call, a fingerprint mismatch, an un-allow-listed confirming host, an
    # unverified/proxied/redirected transport, an unrecognized type, or malformed evidence do NOT fire.
    SECRET_CREDENTIAL_VALIDITY = "secret_credential_validity"

    # E3 (BUILD-PLAN §E3) GCP service-account IMPERSONATION. SAME convention as E1/E5: kept OUT of the frozen
    # _ALL_ORACLES fallback (verifier._ALL_ORACLES stays EXACTLY 15) and fired ONLY via its bug_class row
    # keyed on the `gcp_impersonation_capture` ctx field that NO benchmark/scan/engage finding carries — so
    # appending it leaves `make gate` byte-identical and it never auto-fires on a scan. GCP_SA_IMPERSONATION
    # fires (0.95) ONLY when a RETAINED, secret-safe capture proves ALL of: (a) an impersonation TOKEN was
    # minted AS a named target service-account B (an iamcredentials getAccessToken/generateAccessToken/
    # generateIdToken/signJwt/signBlob verb, or an actAs / roles/iam.serviceAccountTokenCreator flow) targeting
    # a well-formed *.gserviceaccount.com email or numeric unique-id; (b) a confirming tokeninfo/userinfo call
    # SUCCEEDED (explicit 2xx, no failure marker at any depth) whose identity echo (email/sub) EQUALS the named
    # target B (an echo of a DIFFERENT SA does NOT confirm); and (c) the minted token is fingerprint-BOUND to
    # that call (a domain-separated fingerprint in BOTH and EQUAL — the token is never retained) AND the call
    # used a TRUSTED, allow-listed Google introspection endpoint (oauth2/www/iamcredentials/openidconnect
    # .googleapis.com) over a validated-TLS, no-proxy, no-redirect transport. E3 is the OPPOSITE shape to E1:
    # E1 gates on the credential SOURCE host (retrieved FROM the metadata endpoint); E3 makes no source claim
    # and gates entirely on the CONFIRMING-side identity echo + endpoint allow-list (the ANTI-LAUNDERING gate,
    # so an attacker-controlled 'tokeninfo' host can never mint a FACT). A non-impersonation mint, no minted
    # token, a malformed target, a minted-but-unconfirmed token, a failed/4xx confirming call, an echo of a
    # DIFFERENT SA, a fingerprint mismatch, an un-allow-listed confirming host, an unverified/proxied/redirected
    # transport, or malformed evidence do NOT fire (stay an honest LEAD).
    GCP_SA_IMPERSONATION = "gcp_sa_impersonation"
    # E2 (BUILD-PLAN §E2) IAM privilege-escalation PRIMITIVE. Like IMDS/E5, kept OUT of the frozen
    # _ALL_ORACLES fallback (verifier._ALL_ORACLES stays EXACTLY 15) and fired ONLY via its bug_class row
    # keyed on the `iam_escalation_capture` ctx field that NO benchmark/scan/engage finding carries — so
    # appending it leaves `make gate` byte-identical and it never auto-fires on a scan. The ACHIEVED-
    # ESCALATION dual of POLICY_PATH (which proves mere REACHABILITY): IAM_ESCALATION_PRIMITIVE fires (0.95)
    # ONLY when retained IAM statements grant a base principal an UNCONDITIONAL escalation primitive from a
    # FIXED, auditable set (trust-policy rewrite = sts:AssumeRole + iam:UpdateAssumeRolePolicy; iam:PassRole
    # to a compute service; self policy-attach = iam:AttachUserPolicy / iam:PutUserPolicy; add-to-privileged-
    # group = iam:AddUserToGroup; create-credential-for-target = iam:CreateAccessKey / iam:CreateLoginProfile)
    # that STRICTLY increases what it can reach — the target is reachable in the escalation-CLOSED closure but
    # NOT in the base closure (an EXPLICIT differential of two BFS closures, the central anti-overclaim
    # guard). Fail-closed on every FP trap: a Condition, a NotAction, an explicit Deny (deny-precedence across
    # identity policy + permissions boundary + SCP), a restricting boundary/SCP, or a Resource wildcard that
    # does NOT cover the target contributes NO edge; an ambiguous/unparseable statement contributes NO edge.
    # A target a plain reachability path already reaches is NOT escalation (stays a LEAD). Pure + deterministic
    # (re-verifies offline from the retained statements). Distinct from the `iam_privilege_escalation` bug
    # class (which maps to POLICY_PATH reachability): the escalation-primitive bug class is
    # `iam_escalation_primitive`, so the two never collide in oracle_version / reverify.
    IAM_ESCALATION_PRIMITIVE = "iam_escalation_primitive"

    # E4 TIER-2 (BUILD-PLAN §E4·TIER-2) K8s dangerous-VERB / default-ServiceAccount RBAC verb-GRANT. A
    # SEPARATE, STRONGER oracle than TIER-1 (K8S_WORKLOAD_POSTURE, which only NAME-matches a dangerous built-in
    # ClusterRole for an ANONYMOUS subject and never parses rules). SAME frozen-fallback convention as E1/E3/E5:
    # kept OUT of the frozen _ALL_ORACLES fallback (verifier._ALL_ORACLES stays EXACTLY 15) and fired ONLY via
    # its bug_class row keyed on the `k8s_rbac_grant_control` ctx field that NO benchmark/scan/engage finding
    # carries — so appending it leaves `make gate` byte-identical and it never auto-fires on a scan.
    # K8S_RBAC_VERB_GRANT fires (0.9) ONLY when a RETAINED `binding` + its SEPARATELY-retained `role_object`
    # PROVE a dangerous (verb,resource) grant to an attacker-occupiable subject, under a MANDATORY near-zero-FP
    # gate: (I) the roleRef->role_object identity linkage is RE-CHECKED (name/kind/apiGroup EXACT, no empty-
    # string tolerance; a namespaced Role requires a same-namespace RoleBinding; a ClusterRole an empty
    # namespace); (IV) the role's rules are AUTHORITATIVE (a live API GET, or a static manifest with NO
    # aggregationRule); (III) a dangerous rule shape is present — (a) full-wildcard */*/*, (b) secret-read
    # get/list/watch on secrets, (c) priv-esc escalate/bind/impersonate; (II) an attacker-occupiable subject is
    # bound — an ANONYMOUS subject (system:anonymous/system:unauthenticated) MAY FACT on ANY shape, but the
    # namespace-default ServiceAccount / system:authenticated MAY FACT ONLY on a FULL-WILDCARD grant via a
    # ClusterRoleBinding (the built-in `admin` legitimately grants Secrets get/list/watch, and cluster-read
    # backup/monitoring roles legitimately grant */* get/list/watch, so those most-common legitimate
    # delegations stay LEAD). Everything else (a named subject; a resourceNames-scoped single-secret get;
    # default-SA×secret-read; authenticated×broad-read; a linkage break; aggregated static rules; malformed
    # evidence) stays an honest LEAD.
    K8S_RBAC_VERB_GRANT = "k8s_rbac_verb_grant"
    # W16-STD-5 client-side POSTURE-WEAKNESS kinds (the always-applicable constitution client-side classes:
    # clickjacking / CSRF / postMessage). Like the AEGIS / K8S / posture members above, these are ADDITIVE
    # appends reachable ONLY via their explicit BUG_CLASS_ORACLES rows (keyed on the `clickjacking_control` /
    # `csrf_control` / `postmessage_control` ctx fields NO benchmark/scan/engage finding carries), never via
    # the frozen unknown-class fallback (verifier._ALL_ORACLES stays EXACTLY 15). Each proves the MISSING /
    # WEAK DEFENSE (a posture weakness) — NEVER a proven achieved-state exploit — from a RETAINED artifact
    # alone, offline, ZERO traffic. DELIBERATELY NOT an achieved-state clickjacking oracle: a single-response
    # "the page was framed" signal is FP-prone (legitimate framing / intentional embedding), so VIGIL refuses
    # it and proves the posture weakness instead (docs/DELIBERATE-REFUSALS.md refusal 8).
    #   * CLICKJACKING_POSTURE fires (0.9) ONLY when a RETAINED response's OBSERVED headers carry NEITHER a
    #     framing X-Frame-Options (DENY/SAMEORIGIN) NOR a CSP `frame-ancestors` directive — the two framing
    #     defenses a browser actually enforces are both absent (a pure header check, sound). A page that ships
    #     either defense does NOT fire.
    CLICKJACKING_POSTURE = "clickjacking_posture"
    #   * CSRF_POSTURE fires (0.9) ONLY on a control-DIFFERENTIAL over TWO retained responses to the SAME
    #     state-changing request: the anti-CSRF token PRESENT+valid was accepted (2xx) AND the token
    #     REMOVED-or-FORGED was accepted IDENTICALLY (2xx) — proving the synchronizer token is NOT enforced
    #     (a posture weakness). If stripping/forging the token changes acceptance (a reject / status
    #     divergence), the defense holds and it does NOT fire. Proves the token is not validated, NEVER that a
    #     cross-site attack succeeded (SameSite/origin defenses are a separate layer).
    CSRF_POSTURE = "csrf_posture"
    #   * POSTMESSAGE_POSTURE fires (0.9) ONLY when a RETAINED handler source re-derives a wildcard cross-origin
    #     weakness: (a) a `postMessage(<data>, "*")` call whose targetOrigin literal is `*` (data broadcast to
    #     ANY origin); or (b) a `message`-event handler that CONSUMES `event.data` yet references NO `origin`
    #     anywhere (no origin validation). A send to a specific origin, or a handler that checks `event.origin`,
    #     does NOT fire (near-zero-FP). A sound static check over the retained source, NEVER a proven exploit.
    POSTMESSAGE_POSTURE = "postmessage_posture"
    # Wave-2.2 CLIENT-SIDE PROTOTYPE POLLUTION — the ACHIEVED-STATE (not posture) client-side FACT. Unlike the
    # posture members above (which prove a MISSING/WEAK defense from a retained artifact), this proves a real
    # achieved exploit: a `__proto__[uniqKey]=uniqVal` gadget driven across a client source (URL query /
    # fragment / JSON) actually POLLUTED `Object.prototype` in a real headless DOM. Like the AEGIS / posture
    # members above, this is an ADDITIVE append reachable ONLY via its explicit BUG_CLASS_ORACLES row (keyed
    # on the `proto_pollution` ctx field NO benchmark/scan/engage finding carries), never via the frozen
    # unknown-class fallback (verifier._ALL_ORACLES stays EXACTLY 15), so `make gate` stays byte-identical.
    # PROTOTYPE_POLLUTION fires (0.96) ONLY when the binding-reported readback proves the ACHIEVED polluted
    # state — `Object.prototype[uniqKey] === uniqVal` (the per-probe key+val are unique so they cannot
    # pre-exist / collide) AND a BENIGN-KEY control (a different key never injected) stayed `undefined`
    # (attribution: the pollution is caused by THIS probe, not ambient). The evidence reads as the achieved
    # state ("Object.prototype.<key> was polluted to <val>"), NOT "a script ran" and NOT "the payload
    # appeared in the DOM". A page that merely REFLECTS the key without assigning it onto Object.prototype
    # (the benign twin), a mismatched value, or a benign-key that is NOT undefined (ambient) do NOT fire.
    PROTOTYPE_POLLUTION = "prototype_pollution"


class OracleProbe(BaseModel):
    """A passive, abstract description of what an oracle must compare.

    This is deliberately not a payload. It names *what to look at* — which
    already-collected responses, which expected state, which correlation
    token — so a caller can wire observed data into the right oracle. The
    verification layer is a judge of collected evidence, not a sender."""

    model_config = ConfigDict(extra="forbid")

    kind: OracleKind
    description: str = Field(
        default="",
        description="Human-readable statement of the signal being probed for.",
    )
    inputs: dict[str, Any] = Field(
        default_factory=dict,
        description="Abstract references to observed data the oracle consumes "
        "(e.g. {'baseline_ref': 'resp_A', 'mutated_ref': 'resp_B'}). Never a payload.",
    )
    discriminator: dict[str, Any] | None = Field(
        default=None,
        description="Optional comparison spec for the differential oracle "
        "(dimensions, thresholds, markers, expect).",
    )
    correlation_token: str | None = Field(
        default=None,
        description="For OOB_CALLBACK: the unique token minted by the oob receiver.",
    )


class OracleSignal(BaseModel):
    """The verdict of a single oracle over already-observed data."""

    model_config = ConfigDict(extra="forbid")

    kind: OracleKind
    fired: bool = Field(description="True iff a real signal was detected.")
    confidence: float = Field(
        ge=0.0,
        le=1.0,
        description="Calibrated strength of the signal. High-confidence "
        "(>= the verifier threshold) fired signals are what confirm a finding.",
    )
    evidence: str = Field(
        default="",
        description="The concrete artifact justifying the verdict — the "
        "matched marker, the diverging dimensions, the crash line, the hit.",
    )
    observed: dict[str, Any] = Field(
        default_factory=dict,
        description="Structured detail of what was observed, for the audit trail.",
    )
    conclusive: bool = Field(
        default=False,
        description=(
            "Whether this signal is a DECISIVE adjudication of the surface for "
            "coverage/completeness accounting (scanner.engine.probe_verdict). It is "
            "True when the oracle had an OBSERVABLE CHANNEL and rendered a definite "
            "verdict: a positive fire (always conclusive — see the validator below), "
            "OR a channel-confirmed NEGATIVE — an SPRT that reached the refute "
            "boundary, an adequate-sample timing test that found no shift, a definite "
            "predicate/achieved-state proposition over observed values, or a payload "
            "OBSERVED reaching the sink but neutralised (a marker reflected only into "
            "an inert/encoded context, a template expression echoed raw-not-evaluated). "
            "It is False for a ONE-SIDED oracle that merely did not fire with no "
            "observable channel — a single-shot differential over indistinguishable "
            "responses, a marker/error/callback simply absent (a blind, second-order, "
            "or input-ignoring sink). Such a non-signal is 'inconclusive', NEVER "
            "'clean': absence of a positive channel is not proof the surface is safe."
        ),
    )

    @model_validator(mode="after")
    def _fired_implies_conclusive(self) -> "OracleSignal":
        """A FIRED signal is, by construction, a decisive positive adjudication (the
        oracle observed a real channel and it carried the signal), so it is always
        conclusive. Only a NON-firing signal must EARN ``conclusive`` by proving it
        had a channel — the honesty line the coverage certificate rests on."""
        if self.fired and not self.conclusive:
            self.conclusive = True
        return self


class VerificationResult(BaseModel):
    """The aggregate verdict for one finding.

    `confirmed` is True only when at least one oracle fired at or above the
    verifier's high-confidence threshold. Every signal — fired or not — is
    retained so the decision is reconstructable."""

    model_config = ConfigDict(extra="forbid")

    confirmed: bool
    bug_class: str = Field(default="", description="The class the finding claimed.")
    signals: list[OracleSignal] = Field(default_factory=list)
    combine_policy: str = Field(
        default="any_high_confidence_fired",
        description=(
            "How multiple applicable oracles were combined into `confirmed`. "
            "'any_high_confidence_fired' is safety-monotone: one deterministic "
            "oracle firing at/above the threshold is sufficient proof, and a "
            "non-firing oracle CANNOT veto a fired one (absence of a signal is "
            "not evidence of absence). A disagreeing oracle is recorded as "
            "dissent, never treated as a refutation."
        ),
    )
    dissent: list[str] = Field(
        default_factory=list,
        description=(
            "When the finding was confirmed, the applicable oracle kinds that "
            "RAN over observed data but did not confirm (did not fire, or fired "
            "below the threshold) — the recorded disagreement among oracles. "
            "Empty when a lone oracle confirmed or when nothing confirmed."
        ),
    )
    rationale: str = Field(
        default="",
        description="Plain-language account of why the finding was or was not confirmed.",
    )

    @property
    def confirming_signals(self) -> list[OracleSignal]:
        """The fired signals; the subset that carried the confirmation."""
        return [s for s in self.signals if s.fired]
