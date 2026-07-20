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

from pydantic import BaseModel, ConfigDict, Field


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
