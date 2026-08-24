# A — Findings & bug classes: the technical inventory

**Purpose.** A raw, verified fact-collection for the writers who will translate this into plain English.
Everything here was read from source in `/home/kali/vigil` at commit `1487e03a`
("Merge pull request #293 … e4-tier2-verb-grant"). Nothing is inferred from prose or memory.
Where a claim could not be verified from code it is marked **[NOT VERIFIED]**.

> **Warning for translators.** `docs/FEATURES.md` §4 is STALE on this subject (see §9). It says
> "`OracleKind` has **32 members**" (`FEATURES.md:435`); the code at this commit has **38**. It also says
> `k8s_workload_posture_oracle` "is NOT wired into `verifier._run`" — it is (`verify/verifier.py:856-859`),
> under its own distinct `K8S_WORKLOAD_POSTURE` kind. **Do not copy numbers out of FEATURES.md.**
>
> **Second-pass note (independent re-derivation, same commit).** Every count in §0 was re-derived a second
> time from a separate reading of the source and **all matched**: 38 oracle kinds · 85 canonical classes ·
> 190 aliases · 275 accepted strings · 15 frozen fallback · 26 branches (26 FACT-capable, 6 CLEAN-capable,
> 17 with `blocking_work`) · 172 library entries · 11 default checks · threshold 0.70 · noisy-OR clamp 0.99.
> Sections **2.6, 4.5, 5.11, 8.1 and 11** were added by that pass; the drifted line refs it found are
> corrected in place.

---

## 0. Headline counts (all mechanically re-derived at this commit)

| Thing | Count | Source of truth |
|---|---:|---|
| Oracle kinds (`OracleKind` enum members) | **38** | `engine/crucible/framework/v2/verify/models.py:31-336` |
| Oracle kinds registered for version-hashing (`_ORACLE_FNS`) | **38** | `verify/oracle_version.py:36-74` (a test pins `set(_ORACLE_FNS) == set(OracleKind)`) |
| Distinct pure oracle *functions* in `oracles.py` | **40** | two kinds dispatch 2 functions each: `ACHIEVED_STATE` → `predicate_oracle` + `achieved_state_oracle`; `TLS_WEAKNESS` → `tls_weakness_oracle` + `weak_crypto_artifact_oracle` |
| Frozen unknown-class fallback `_ALL_ORACLES` | **15** | `verify/verifier.py:518-534` |
| Canonical bug classes in `BUG_CLASS_ORACLES` | **85** | `verify/verifier.py:33-281` |
| Spelling aliases in `_ALIASES` | **190** | `verify/verifier.py` |
| Total accepted bug-class strings (`known_bug_classes()`) | **275** | canonical ∪ alias-keys ∪ alias-targets |
| Registered evidence branches | **26** | `docs/capability-matrix/evidence-branches.json` |
| …of which `fact_capable: true` | **26** (all) | same |
| …of which `clean_capable: true` | **6** | same |
| …with a deliberate `target_clean_capable: false` + rationale | **6** | same |
| …carrying named `blocking_work` | **17** | same |
| Seed checks always run (`DEFAULT_CHECKS`) | **11** | `scanner/checks.py:1055-1067` |
| Data-driven check-library entries (JSON) | **172** | `scanner/library_entries/*.json` |
| Verdict vocabulary (closed enum) | **4** | `integration/vigil_integration/live/verdict.py:34-41` |
| Coverage verdicts (closed set) | **3** | `scanner/engine.py:143-174` |
| Posture-certificate statuses | **3** | `integration/vigil_integration/posture/certificate.py:63` |
| Remediation-certificate states | **4** | `integration/vigil_integration/remediation/prove_driver.py:85-88` |
| Confirmation threshold `HIGH_CONFIDENCE` | **0.70** | `verify/verifier.py:25` |
| Max confidence any oracle may emit | **0.99** (noisy-OR clamp) | `verify/oracles.py:_noisy_or` (line ~181) |

---

## 1. The verdict vocabulary — the four words the system is allowed to say

`integration/vigil_integration/live/verdict.py:34-45`. `Verdict` is a **closed Python enum**, so
"only these four appear in output" is a property of the type, not a convention.

| Verdict | Definition (from `docs/CLAIM-DISCIPLINE.md` §1, enforced) | What it takes to say it |
|---|---|---|
| **FACT** | the declared predicate was **established** under the certified target, inputs, system state and observation interval | a deterministic VIGIL-owned oracle re-derived it over evidence VIGIL itself captured live through a gated channel, and the certificate re-verifies offline |
| **LEAD** | something suggests this; we did not prove it | any weaker signal — a third-party tool's assertion, a heuristic, an LLM's opinion, a regex over a context we cannot fully parse |
| **CLEAN** | the declared predicate was **conclusively refuted** under the certified target, inputs, system state and observation interval | a real channel existed, the evidence was *semantically available* for that branch, and a conclusive oracle refuted the predicate |
| **INCONCLUSIVE** | we could not tell | everything else — a first-class result, never rounded toward CLEAN |

Adjacent closed vocabularies:

- **Coverage verdicts** (`scanner/engine.py:probe_verdict`, lines 143-174): `finding` | `clean` | `inconclusive`.
- **Posture statuses** (`posture/certificate.py:63`): `OPEN` | `CLOSED` | `UNPROVEN`.
- **Remediation states** (`remediation/prove_driver.py:85-88`): `REMEDIATED` | `STILL_VULNERABLE` | `INCONCLUSIVE` | `REFUSED`.
- **Veracity verdicts** (`veracity/claims.py:28-32`): `GROUNDED` | `UNGROUNDED` | `CONTRADICTED` | `ABSTAIN`;
  render labels are `fact` | `hypothesis` | `contradicted` | `analyst-commentary` (`claims.py:77-86`).
- **World-model grounding tiers** (`worldmodel/models.py:168-171`): `grounded` | `intel` | `ungrounded` | `unclassified`.

Both FACT and CLEAN are explicitly **bounded observations, not timeless properties** of the target
(`CLAIM-DISCIPLINE.md` §1).

---

## 2. THE ORACLE CATALOGUE — all 38 kinds

Definitions: `verify/models.py:31-336` (enum + per-member doc comments);
implementations `verify/oracles.py`; dispatch `verify/verifier.py:_run` (**def at line 716**, body to 951);
version-hash registry `verify/oracle_version.py:36-74`.

**Structural rule (load-bearing).** `_ALL_ORACLES` (**`verifier.py:531-548`**) is a **frozen list of exactly the
15 pre-AEGIS kinds** used as the fallback for an *unknown* bug class. It is deliberately NOT
`tuple(OracleKind)`. Every kind added since is reachable **only** through an explicit `BUG_CLASS_ORACLES`
row, and each fires only when the finding context carries a class-specific key that no benchmark / scan /
engage finding carries. Consequence: adding an oracle cannot change what a scan does (`make gate` stays
byte-identical), and none of the newer oracles can auto-fire on an ordinary web scan.

**Universal contract for every oracle** (`verify/oracles.py` module docstring; `verify/README.md`):
pure · deterministic · no I/O · no clock · no RNG · offline. It judges evidence someone else already
collected; it never sends traffic. An absent input yields a *skip*, never an assumed pass. Confidence
inside an oracle combines corroborating dimensions with a noisy-OR clamped to **0.99** — "a deterministic
oracle never claims certainty it cannot have." The one stateful sibling that is *not* a pure oracle is
`verify/oob.py`, the loopback out-of-band **receiver** that mints the correlation token `oob_callback_oracle`
later judges.

### 2.1 The frozen core 15 (`_ALL_ORACLES` — the only oracles an unknown class may run)

| # | Kind (enum value) | Function (`oracles.py`) | Ctx key(s) | Proves (real-world) | Deliberately does NOT prove |
|---|---|---|---|---|---|
| 1 | `differential_response` | `differential_response_oracle` (L195) | `baseline`,`mutated`,`discriminator` | two observed responses are materially distinguishable across `{status,length,lexical,structural,latency,marker}` — the boolean/time-blind signal | *why* they differ; a single-shot non-difference proves nothing (one-sided) |
| 2 | `achieved_state` | `predicate_oracle` (L665) **or** `achieved_state_oracle` (L701) | `predicate`+`observed_evidence`, or `expected_state`+`observed_state` | a dangerous **condition** evaluated by the oracle over RAW observed values (headers/bodies/statuses/identities); or a full match of a non-empty attacker-predicted state | a partial match (informational only, does not fire). `predicate_oracle` exists precisely to stop a check "rubber-stamping" its own boolean |
| 3 | `side_effect` | `side_effect_oracle` (L754) | `marker`,`observed_sink` | a unique attacker-chosen marker (≥4 chars) reached a sink it must never touch | that the reflection is *executable* (that is `reflection_context`) |
| 4 | `oob_callback` | `oob_callback_oracle` (L1471) | `oob_hits`(+`oob_token`) | a blind server-side execution: an inbound interaction carried the finding's **registered per-finding secret token** (`secrets.token_hex(16)`) | anything without the token. Fail-closed: no hits → no fire; hits but no registered token → no fire. Optional `collector_pubkey` (VF-2b) adds an out-of-band-pinned collector signature; without it the honest limit is that it does not defeat a *fully dishonest producer* |
| 5 | `sanitizer_signal` | `sanitizer_signal_oracle` (L1316) | `process_output` | a memory-safety/crash marker in captured stdout/stderr (ASAN/MSAN/TSAN/UBSAN/LSAN, stack-smashing, glibc abort, Rust/Go panic, SIGSEGV) | a bare Python traceback is only moderate confidence — it can be an ordinary handled error |
| 6 | `timing` | `timing_oracle` (L370) | `baseline_latencies`,`treatment_latencies`(+`timing_injected_ms`,`timing_alpha`,`timing_dose`) | a **real hypothesis test**: one-sided Mann-Whitney U at α, AND a Hodges-Lehmann effect-size floor, AND (optional) dose-response scaling | a fixed latency threshold or a single averaged comparison (explicitly named as what sqlmap/Burp largely do and why they false-positive). Needs ≥5 samples/arm |
| 7 | `boolean_inference` | `boolean_inference_oracle` (L521) | `probe_rounds`(+`sprt_*`) | Wald **SPRT** over repeated rounds; per-round signal = (TRUE differs from FALSE) **AND** (the two FALSE responses agree) — the second clause is a dynamic-page control | a page that simply changes every request (it trips the control). Neither SPRT boundary reached ⇒ inconclusive, never a guess |
| 8 | `reflection_context` | `reflection_context_oracle` (L835) | `marker`,`observed_sink` | the marker landed in an **executable** position — became (part of) a tag name, sits inside `<script>`, or in an event-handler / `javascript:` attribute (stdlib HTML parse) | an HTML-encoded, comment, or plain-text reflection (inert — correctly does not fire) |
| 9 | `evaluation` | `evaluation_oracle` (L899) | `eval_expected`,`eval_observed`(+`eval_raw`,`eval_control`) | the server **evaluated** an injected expression: the computed result appears AND the raw expression does not survive verbatim AND the result is absent from a benign control | a reflected-but-unevaluated payload (that is the whole point of guard 2) |
| 10 | `error_signature` | `error_signature_oracle` (L1430) | `error_observed`(+`error_control`) | a distinctive **engine-specific** datastore/parser error a malformed payload provoked (MySQL/Postgres/MSSQL/Oracle/SQLite/JDBC/Mongo/LDAP/XPath) | a generic "error" word; and a page that *always* shows a stack trace (the control body must lack the same signature) |
| 11 | `dom_execution` | `dom_execution_oracle` (L1355) | `dom_binding_calls`,`dom_canary` | injected JS **actually executed** in a real browser DOM — a canary appeared among the arguments passed to a CDP `Runtime.addBinding` function only the driver registered | a reflected-but-inert or encoded payload (no binding call). Described in-code as "the strongest possible XSS evidence and near-unforgeable" |
| 12 | `service_reachability` | `service_reachability_oracle` (L1577) | `handshake` | a real transport handshake reproduced — a completed TCP connect to the named host:port (0.90; a captured application-layer **banner** raises it to 0.97) | anything from a scanner's parsed "open" row. The captured `peer` deliberately does NOT raise confidence (`getpeername` returns the port we dialled — self-referential). UDP without a banner does not fire |
| 13 | `tls_weakness` | `tls_weakness_oracle` (L1738) **or** `weak_crypto_artifact_oracle` (L1812) | `tls`, or `crypto_artifact` | a real TLS handshake **negotiated** a deprecated protocol (0.95) or weak cipher (0.92); or a parsed X.509 cert signed with a broken hash (MD2/4/5, SHA-1) | that the server would accept *every* legacy suite — the branch limitation says it is "scoped to what a modern client still negotiates; it does not enumerate every legacy suite" |
| 14 | `version_range` | `version_range_oracle` (L1858) | `version_advisory` | a concrete pinned version **provably falls inside** a pinned advisory's affected range (0.95) — deterministic membership | that a matching CVE is *exploitable*; and absence from the snapshot is not absence of vulnerability. Unparseable/empty range ⇒ fail-closed non-fire |
| 15 | `policy_path` | `policy_path_oracle` (L1942) | `policy` | a **real IAM grant path** re-derived by BFS over the retained assume/member closure + grants graph; the ordered hop chain IS the evidence | a CSPM tool's "over-privileged" judgement (never trusted); an unknown access token degrades to read-tier, never admin |

### 2.2 AEGIS defensive-dual kinds (the operator's own app, pointed inward)

| # | Kind | Function | Ctx key(s) | Proves | Does NOT prove |
|---|---|---|---|---|---|
| 16 | `prompt_injection` | `prompt_injection_oracle` (L1048) | `pi_control`,`pi_treatment` | an injected directive **flipped a structurally-detectable behavior** vs a clean control turn: refusal flipped, a sensitive tool coerced, or the instruction/data boundary token echoed only under the directive | structural override markers alone ("ignore the above") — those stay LEADs, because users legitimately paste them |
| 17 | `system_prompt_disclosure` | `system_prompt_disclosure_oracle` (L993) | `canary`,`llm_output` | a planted high-entropy canary (≥16 chars AND ≥2.5 bits/char Shannon) appeared **verbatim** in the app's own LLM output — the secret provably crossed the boundary | that an *injection caused it* — a benign "repeat your instructions" or the app's own debug path echoes the same sentinel |
| 18 | `automated_access` | `honeypot_hit_oracle` (L1085) | `requested_path`,`honeypot_paths`(+`crawler_allowlisted`) | **automation**: a client fetched a seeded honeypot resource no human UI links | "scraping" — link-unfurl bots, prefetch, AV URL scanners and uptime monitors also trip it; the operator allowlist REFUTES. `automated_scraping` is an *alias*, never its own confirmed class |
| 19 | `credential_stuffing` | `credential_stuffing_oracle` (L1160) | `auth_events`(+`benign_sources`,`credstuff_*`) | an ATO campaign: per-source Wald SPRT over **unseen-(account,source) auth successes**, with **Holm-Bonferroni** family-wise correction across distinct source identities. Identifiers are already keyed-HMAC pseudonyms — the oracle never sees a raw username/IP | a failed-only burst (NAT/CGNAT bulk) — failures produce **no SPRT round**, so it can never confirm. Multiplicity across thousands of sources cannot manufacture a hit |

### 2.3 Request-side parse-proofs (the inline "provable firewall" — judged on the REQUEST alone)

All three key on the same ctx field `request_payload`, which no benchmark/scan/engage finding carries.

| # | Kind | Function | Proves | Does NOT prove |
|---|---|---|---|---|
| 20 | `sql_injection_breakout` | `sql_injection_breakout_oracle` (L3600) | a value placed in a SQL string literal **provably closes it and introduces query STRUCTURE anchored to the break-out** (tautology / UNION SELECT / stacked statement / terminating comment) | **exploitation** — an app that parameterises is still safe. Ordinary apostrophe prose (`O'Brien`, `it's fine`, `Don't drop the ball; I'll update you`) never fires |
| 21 | `command_injection_breakout` | `command_injection_breakout_oracle` (L3655) | an unambiguous OS-command-execution construct: a dangerous command **with a shell argument** inside `$(…)`/backticks, or after a separator (first segment skipped) | exploitation. `$(id)`, `` `code` ``, `dog\|cat`, `id > 1000`, `python-requests/2.25.1` do not fire |
| 22 | `nosql_injection_breakout` | `nosql_injection_breakout_oracle` (L3808) | a **known** MongoDB query operator injected as a **KEY** where a scalar was expected — a bracket/dot key segment of the param name (`user[$ne]`, `q[$gt]`, `$where`) or an object key in JSON-parsing value (`{"$ne":null}`) | exploitation. Curated allowlist deliberately excludes EJSON/JSON-Schema/DBRef keys (`$oid`,`$date`,`$schema`,`$ref`) and the dual-use `$type`/`$regex`. A price `$5.00`, `$net`, `^admin$`, `pass$word`, an operator as a string *value* (`["$ne"]`) all stay inert |

### 2.4 Posture oracles (offline re-derivation over a RETAINED artifact — zero live calls)

| # | Kind | Function | Ctx key | Proves | Does NOT prove |
|---|---|---|---|---|---|
| 23 | `k8s_posture` | `k8s_posture_oracle` (L2096) | `k8s_control` | a kube-bench CIS control **hard-FAILED** *and* its retained `actual_value` literally carries a dangerous flag (`--anonymous-auth=true`, `--authorization-mode=…AlwaysAllow`, non-zero `--insecure-port`/`--read-only-port`, a static auth file) | a `WARN` (manual-review advisory → LEAD); a FAIL whose value shows the *secure* setting; a FAIL with no captured value. Bounded to the parsed export, never the live cluster |
| 24 | `k8s_workload_posture` | `k8s_workload_posture_oracle` (L2231) | `k8s_workload_control` | an **anonymous** subject (`system:anonymous`/`system:unauthenticated`) bound to a dangerous **built-in** ClusterRole (`cluster-admin`/`admin`/`edit`) — re-derived from the raw retained `subjects` + `role` | the benign built-in `system:public-info-viewer` binding; an anonymous binding to a custom/non-dangerous role; a namespaced Role merely *named* `admin`/`edit`; a ServiceAccount merely *named* `system:anonymous` |
| 25 | `sso_assertion_forgery` | `jwt_forgery_oracle` (L3902) | `jwt_token`(+`jwt_candidate_keys`) | a captured JWT is **structurally forgeable**, offline, from the token alone: (a) `alg=none`/`None`; (b) an HS\* signature recomputable from a supplied/weak candidate secret; (c) RS256→HS256 confusion (HS\* verifies with a supplied RSA/EC **public** key as HMAC secret) | a normal RS256 token with an unknown key; an HS\* token whose secret is not recoverable. Distinct from the live `jwt` class (alg:none **acceptance**, ACHIEVED_STATE) — this is forgeability, no traffic |
| 26 | `saml_structural_forgery` | `saml_forgery_oracle` (L4224) | `saml_xml`(+`saml_candidate_certs`) | a captured SAML Response exhibits a coarse, **c14n-free** structural invariant a validly signed assertion cannot: (a) the assertion carrying the consumed NameID has **zero** `ds:Signature`; (b) every `ds:Reference/@URI` points elsewhere than the consumed element/ancestor; (c) the signature-wrapping shape | full XML-DSig C14N/transform processing (deliberately out of scope — needs lxml/signxml). Opt-in escalation: with operator-supplied **trusted** IdP PEM certs AND `signxml` importable, non-firing structural paths escalate to a real XML-DSig check, firing only on a **definitively invalid** signature; the document's own embedded `ds:X509Certificate` is NEVER trusted; an unverifiable signature is REFUSED, not fired |
| 27 | `cloud_posture` | `cloud_posture_oracle` (L2503) | `cloud_control` | an explicit insecure **achieved state** on one retained control, in fixed rule order: (1) encryption-at-rest disabled on a *sensitive* store; (2) an explicit `public: true`; (3) a wildcard/anonymous principal literally named in the retained policy; (4) `named_cross_account_principal` — a named principal whose parsed account is **not** in the charter-supplied owner-account set | a compliant control; a control with only ABSENT/unknown flags (unknown is never an insecure fact). Rule 4 fires **only** when the owner-account set was threaded in — the owner is never guessed. Deliberately not FACT-capable for GCP `serviceAccount` members (Google-managed service agents are indistinguishable by email and cannot be enumerated → any allow/deny list is fail-open) |
| 28 | `mesh_posture` | `mesh_posture_oracle` (L2710) | `mesh_control` | a retained Istio/Linkerd config **declares** a permissive state: (1) PeerAuthentication effective `mtls.mode` `PERMISSIVE`/`DISABLE`; (2) an `action: ALLOW` AuthorizationPolicy whose rules admit every caller (empty catch-all, or `*` principal in `from.source.principals`); (3) a Linkerd server `default-inbound-policy: all-unauthenticated` | **effective runtime posture** — policy precedence, namespace/workload selectors and more-specific policies are not evaluated. An absent `mtls_mode` inherits a parent this slice does not resolve → never promoted. `requestPrincipals: ['*']` is JWT-gated, not allow-all, and does not fire |
| 29 | `cicd_posture` | `cicd_posture_oracle` (L2861) | `cicd_control` | a parsed GitHub-Actions workflow contains a dangerous construct: (a) a third-party action pinned to a **mutable** (non-SHA) ref; (b) a `pull_request_target` that checks out the untrusted PR head (pwn-request); (c) a `run:` step interpolating an untrusted `github.event.*`/`github.head_ref` expression | that the pipeline **was** exploited. No repo is cloned, no pipeline runs. A SHA-pinned action, a first-party `actions/*` action, a plain `pull_request`, and a quoted-literal-only interpolation do not fire |
| 30 | `mobile_posture` | `mobile_posture_oracle` (L2932) | `mobile_control` | exactly **one** rule: an embedded PEM **private key** that actually LOADS (via `cryptography`) as an unencrypted, structurally-valid private key | almost every other mobile signal. The adversarial soundness map ruled NSC-vs-attribute cleartext, min-vs-target-SDK and explicit-vs-default export all LEADs (they depend on an Android precedence/gating chain the manifest omits). An encrypted key, a public key, a cert, a masked blob, or an unparseable string REFUSE |
| 31 | `email_auth_posture` | `email_auth_posture_oracle` (L3215) | `email_auth_control` | a domain's **published** DNS policy provably permits spoofing: `dmarc_missing`, `dmarc_none` (`p=none`), or `spf_permissive` (`+all`/`all`) | message-level SPF/DKIM/DMARC verification (DKIM canonicalisation + SPF include/macro chains are a semantic layer it cannot soundly re-derive offline; an `Authentication-Results` header would be the receiving MTA's say-so). `spf_missing` alone does NOT fire (DKIM+DMARC may still protect). A subdomain inheriting an enforcing org policy (RFC 7489 §6.6.3 / §6.3 `sp=`) does not fire |
| 32 | `identity_posture` | `identity_posture_oracle` (L3393) | `identity_control` | two rules over an IdP export's **strict-typed literal** fields: `privileged_without_mfa` (`privileged is True` AND `mfa_enrolled is False`), or `stale_credential` (`never_rotated is True`, or two retained integers `age_days >= max_age_days`) | anomaly/behavioural detection (probabilistic — cannot be a near-zero-FP FACT); cloud-resource IAM (owned by POLICY_PATH/CLOUD_POSTURE); privilege **inference** from role names (the `privileged` producer attestation is required, never guessed). An **absent** `mfa_enrolled` REFUSES — a missing field is not proof MFA is absent. `age_days` is a retained integer, no wall-clock |

### 2.5 Live-capture / achieved-effect oracles (the exploitation-chain tier)

Each judges a JSON-safe capture retained by a separate **WARDEN-gated runner**. The oracle itself never
touches the network. Every one of these is deliberately kept out of `_ALL_ORACLES` and keys on a ctx field
no scan produces.

| # | Kind | Function | Ctx key | Proves | Does NOT prove |
|---|---|---|---|---|---|
| 33 | `active_exposure` | `anonymous_reachable_oracle` (L1645) | `anon_get` | a resource posture already re-derived as *public* is **provably fetchable by anyone**: a bounded, credential-free GET returned an unauthenticated HTTP **2xx with a non-empty body** | anything from a posture tool's `public=true`. Does not fire on a 3xx, 401/403 (present-but-protected — the opposite of the claim), 404, `None` (gate refusal/connect failure), an empty body, or a capture that admits it carried auth |
| 34 | `imds_credential_capture` | `imds_credential_capture_oracle` (L4857) | `imds_capture` | (E1) BOTH halves: (a) a structurally-valid credential whose `source` **URL host** (parsed with `urlsplit`, never substring) is the metadata endpoint — AWS `ASIA[0-9A-Z]{16}` + SecretAccessKey + Token from a 169.254.169.254-canonicalising host with `iam/security-credentials` as a path segment; or GCP `access_token`+`token_type: bearer` from `metadata.google.internal` with the ordered `computeMetadata/v1/…/service-accounts/<sa>/token` grammar — AND (b) a confirming call (`sts:GetCallerIdentity` Arn+12-digit Account+UserId, or GCP tokeninfo/userinfo email/sub) with **no** failure marker at any depth, providers agreeing | that the exact captured credential produced the confirming call (the in-code note: firing proves the capture is **structurally consistent**; the binding + trusted-endpoint provenance are the gated runner's job). A retrieved-but-unconfirmed credential is a LEAD. A userinfo-`@` host, a query-param IP, a rebind host that merely *contains* the IP, and a creds-file path are all correctly not an IMDS reach |
| 35 | `secret_credential_validity` | `exposed_secret_validity_oracle` (L5145) | `secret_capture` | (E5) an exposed secret is **VALID**: a structurally-recognised type (one of the closed four-row set `aws_access_key`/`github_pat`/`gitlab_pat`/`slack_token`) whose confirming call authenticated as a real identity, fingerprint-BOUND to that call, over a validated-TLS / no-proxy / no-redirect transport, at an endpoint on the **per-type allow-list** (the anti-laundering gate) | the secret's *content* (it is a `[REDACTED]` presence marker) and its **provenance** — source semantics are INVERTED vs E1: the exposure source is retained as evidence but is **not** a firing gate. An un-allow-listed "confirming" endpoint can never mint a FACT |
| 36 | `gcp_sa_impersonation` | `gcp_sa_impersonation_oracle` (L5368) | `gcp_impersonation_capture` | (E3) a principal minted a short-lived token **as** a named target service-account B (iamcredentials `getAccessToken`/`generateAccessToken`/`generateIdToken`/`signJwt`/`signBlob`, or an `actAs` / `roles/iam.serviceAccountTokenCreator` flow) AND a confirming tokeninfo/userinfo call at an **allow-listed Google** introspection endpoint echoed **B's** identity, fingerprint-bound to the mint | any claim about the token's **source** (opposite shape to E1). An echo of a *different* SA does not confirm. A minted-but-unconfirmed token stays a LEAD |
| 37 | `iam_escalation_primitive` | `iam_escalation_oracle` (L5873) | `iam_escalation_capture` | (E2) the retained configuration **unconditionally permits** an escalation primitive from a fixed auditable set (trust-policy rewrite = `sts:AssumeRole`+`iam:UpdateAssumeRolePolicy`; `iam:PassRole` to a compute service; self policy-attach `iam:AttachUserPolicy`/`PutUserPolicy`; `iam:AddUserToGroup`; `iam:CreateAccessKey`/`CreateLoginProfile`) that **strictly increases** reach — an explicit differential of two BFS closures (target reachable in the escalation-closed closure but NOT in the base closure) | that the attacker **executed** it; or that any principal is escalation-capable. Effective IAM permission is identity ∩ SCP ∩ boundary ∩ resource-policy: a resource-based policy the capture omits could nullify the identity-side Allow. Fail-closed on every FP trap — a Condition, a NotAction, an explicit Deny (deny-precedence across identity policy + boundary + SCP), a restricting boundary/SCP, or a Resource wildcard not covering the target contributes **no edge**. A target already reachable in the base closure is not escalation |
| 38 | `k8s_rbac_verb_grant` | `k8s_rbac_verb_grant_oracle` (L6215) | `k8s_rbac_grant_control` | (E4 TIER-2, the rule-**parsing** sibling of #24) a retained `binding` **plus its separately retained `role_object`** grant a dangerous (verb,resource) capability to an attacker-occupiable subject. Four conjuncts: (I) the roleRef→role identity join is re-checked, not trusted; (IV) rules are AUTHORITATIVE (a live API GET, or a static manifest with **no** `aggregationRule`); (III) the rules contain a dangerous shape; (II) subject-gated eligibility | under the **subject gate** that is the near-zero-FP fix: an *anonymous* subject may FACT on any dangerous shape (full-wildcard `*/*/*`, secret-read `get/list/watch` on secrets, or priv-esc `escalate/bind/impersonate`); the **default ServiceAccount / `system:authenticated`** may FACT **only** on a full-wildcard `*/*/*` grant **and only** via a ClusterRoleBinding — never secret-read, never priv-esc, never a namespaced RoleBinding (because the built-in `admin` legitimately grants Secrets get/list/watch and cluster-read backup/monitoring roles legitimately grant `*/*` get/list/watch). A named subject, a `resourceNames`-scoped single-secret get, a broken join, and aggregated static rules all stay LEAD |

### 2.6 How the 38 kinds are spread across the 85 classes (mechanically derived)

Counting how many canonical bug classes list each kind in its `BUG_CLASS_ORACLES` tuple. **Every one of the
38 kinds is referenced by at least one class** (no orphan oracles), and **17 of the 85 classes list more than
one acceptable oracle** (the rest have exactly one).

| Oracle kind | # of bug classes it may confirm |
|---|---:|
| `achieved_state` | 28 |
| `differential_response` | 11 |
| `side_effect` | 11 |
| `oob_callback` | 8 |
| `sanitizer_signal` | 6 |
| `boolean_inference` | 5 |
| `error_signature` | 5 |
| `timing` | 3 |
| `policy_path` | 3 |
| `evaluation` | 2 |
| `tls_weakness` | 2 |
| each of the remaining **27** kinds | 1 each |

Reading for translators: `achieved_state` is the workhorse — one general-purpose *predicate over raw observed
values* oracle backing a third of the catalogue. The long tail of 27 single-class oracles is the opposite
design: each is a purpose-built, near-zero-false-positive judge for exactly one kind of proof.

---

## 3. THE BUG-CLASS CATALOGUE — 85 canonical classes

`verify/verifier.py:33-281`. Left column = the canonical key. Right = the ordered oracle set that may
confirm it (`oracle_confirms_class` is the PCF step-5 membership check that defeats relabelling).

### 3.1 Injection

| Bug class | Plain meaning | Oracle(s) |
|---|---|---|
| `sqli` | SQL injection, generic | `error_signature`, `boolean_inference`, `differential_response`, `oob_callback`, `side_effect` |
| `boolean_sqli` | blind SQLi read one bit at a time from response differences | `boolean_inference`, `differential_response` |
| `time_based_sqli` | blind SQLi read from injected delays | `timing`, `differential_response` |
| `error_based_sqli` | SQLi that leaks via a database error message | `error_signature`, `side_effect`, `differential_response` |
| `time_based` | any blind bug inferred purely from injected delay | `timing` |
| `nosqli` | NoSQL (Mongo-style) injection proven on the app's **response** | `boolean_inference`, `differential_response`, `error_signature` |
| `ldap_injection` | LDAP filter injection | `boolean_inference`, `differential_response`, `error_signature` |
| `xpath_injection` | XPath query injection | `boolean_inference`, `differential_response`, `error_signature` |
| `command_injection` | OS command injection | `oob_callback`, `side_effect` |
| `time_based_command_injection` | blind OS command injection inferred from delay | `timing`, `oob_callback` |
| `rce` | remote code execution | `oob_callback`, `side_effect`, `sanitizer_signal` |
| `ssti` | server-side template injection (server evaluated the expression) | `evaluation`, `side_effect`, `differential_response` |
| `el_injection` | expression-language injection (SpEL etc.) | `evaluation`, `side_effect` |
| `ssrf` | server-side request forgery — the server fetched an attacker URL | `oob_callback` |
| `xxe` | XML external entity | `oob_callback`, `side_effect` |
| `blind_xxe` | XXE with no in-band output | `oob_callback` |
| `deserialization` | unsafe deserialization | `oob_callback`, `sanitizer_signal` |
| `path_traversal` | escaping a directory to read arbitrary files | `side_effect` |
| `lfi` | local file inclusion | `side_effect` |
| `xss` | cross-site scripting (reflected/stored) | `reflection_context` |
| `dom_xss` | XSS realised entirely in the browser DOM | `dom_execution`, `side_effect` |

### 3.2 Request-side ATTEMPT classes (structured attempt proven; exploitation NOT claimed)

| Bug class | Plain meaning | Oracle |
|---|---|---|
| `sqli_attempt` | a request value provably breaks SQL grammar | `sql_injection_breakout` |
| `command_injection_attempt` | a request value carries a shell command-execution construct | `command_injection_breakout` |
| `nosql_injection_attempt` | a request injects a Mongo query operator as a key | `nosql_injection_breakout` |

### 3.3 Authorization / access control / business logic

| Bug class | Plain meaning | Oracle |
|---|---|---|
| `idor` | insecure direct object reference — reading another user's record by changing an id | `achieved_state` |
| `bola` | broken object-level authorization (the API name for IDOR) | `achieved_state` |
| `bfla` | broken function-level authorization — calling an endpoint your role must not | `achieved_state` |
| `broken_access_control` | access control missing/ineffective | `achieved_state` |
| `authorization` | generic authz failure | `achieved_state` |
| `auth_bypass` | authentication bypassed entirely | `achieved_state`, `differential_response` |
| `mass_assignment` | a client-supplied field wrote a server-controlled attribute | `achieved_state` |
| `privilege_escalation` | a runtime state where a low-privilege actor gained more | `achieved_state` |
| `business_logic` | workflow abuse: a skipped required step, a replayed one-time action, price/qty tampering (OPT-IN; needs an operator workflow spec) | `achieved_state` |
| `request_race` | a concurrency/TOCTOU window abused | `achieved_state` |

### 3.4 Web / protocol surface

| Bug class | Plain meaning | Oracle |
|---|---|---|
| `open_redirect` | the app sends a user to an attacker-chosen host | `achieved_state` |
| `cors` | CORS reflects a hostile origin **with credentials** | `achieved_state` |
| `host_header_injection` | the app trusts the `Host` header to build URLs | `achieved_state` |
| `request_smuggling` | front-end and back-end disagree on request framing | `differential_response` |
| `cross_site_websocket_hijacking` | a WS handshake accepts a cross-origin caller with credentials | `achieved_state` |
| `websocket_injection` | injecting into a WebSocket message stream | `side_effect`, `differential_response` |
| `exposure` / `sensitive_exposure` | information disclosure / sensitive data left reachable | `achieved_state` |
| `security_misconfiguration` | an insecure setting reachable over the app surface | `achieved_state` |
| `jwt` | a forged/none-alg JWT was **accepted** (live) | `achieved_state` |

### 3.5 GraphQL

| Bug class | Plain meaning | Oracle |
|---|---|---|
| `graphql_introspection` | the schema is publicly introspectable | `achieved_state` |
| `graphql_suggestions` | field "did you mean" suggestions leak the schema | `achieved_state` |
| `graphql_depth_limit` | an unbounded-depth query executed (no depth guard) | `achieved_state` |
| `graphql_alias_overloading` | N aliases all resolved (no alias guard) | `achieved_state` |
| `graphql_batching` | an M-operation batch ran (no batch guard) | `achieved_state` |
| `graphql_cost` | query-cost/complexity abuse | `achieved_state` |

*(Note in code: query COST stays a LEAD in the scanner — a minimal probe being accepted cannot prove a cost
limit is absent.)*

### 3.6 SSO / federated identity

| Bug class | Plain meaning | Oracle |
|---|---|---|
| `saml_signature_wrapping` | XSW accepted **live** by the operator's SP | `achieved_state` |
| `saml_assertion_tampering` | a tampered assertion accepted **live** | `achieved_state` |
| `oidc_redirect_uri` | the authorization endpoint honours an attacker `redirect_uri` | `achieved_state` |
| `oidc_idtoken_forgery` | a forged ID token accepted | `achieved_state` |
| `jwt_forgeable` | a captured JWT is **structurally forgeable offline** (no traffic) | `sso_assertion_forgery` |
| `saml_structural_forgery` | a captured SAML Response is structurally forgeable offline | `saml_structural_forgery` |

Deliberate design point: forgeABILITY (offline, artifact-alone) and ACCEPTANCE (live) are **kept as
distinct classes**, never aliased onto each other.

### 3.7 Memory safety / binaries

`memory_corruption`, `buffer_overflow`, `use_after_free`, `crash` → all `sanitizer_signal`.

### 3.8 Network, crypto, supply chain

| Bug class | Plain meaning | Oracle |
|---|---|---|
| `service_reachable` | a port is genuinely open (VIGIL's own handshake) | `service_reachability` |
| `anonymous_reachable` | a resource is fetchable with no credentials at all | `active_exposure` |
| `weak_tls` | a deprecated TLS protocol / weak cipher was negotiated | `tls_weakness` |
| `weak_crypto_artifact` | an X.509 cert signed with a collision-forgeable hash | `tls_weakness` |
| `vulnerable_dependency` | a pinned package version falls in an advisory's affected range | `version_range` |

### 3.9 Cloud, Kubernetes, mesh, CI/CD, mobile, identity, email

| Bug class | Plain meaning | Oracle |
|---|---|---|
| `privilege_path` | an IAM grant path exists to a resource | `policy_path` |
| `iam_privilege_escalation` | IAM privesc, reachability sense | `policy_path` |
| `excessive_privilege` | a principal holds more than it needs (path-proven) | `policy_path` |
| `iam_escalation_primitive` | an achieved **strict-gain** escalation primitive (stronger than reachability) | `iam_escalation_primitive` |
| `cloud_misconfiguration` | an insecure cloud achieved state on one control | `cloud_posture` |
| `k8s_misconfiguration` | a kube-bench CIS control failed with a concrete dangerous flag | `k8s_posture` |
| `k8s_workload_misconfiguration` | an anonymous subject bound to a dangerous built-in ClusterRole | `k8s_workload_posture` |
| `k8s_rbac_privilege_grant` | a parsed RBAC role's **rules** grant a dangerous verb to an attacker-occupiable subject | `k8s_rbac_verb_grant` |
| `mesh_misconfiguration` | a service mesh declares permissive mTLS / allow-all authz | `mesh_posture` |
| `cicd_misconfiguration` | a CI workflow contains an unpinned action / pwn-request / script-injection sink | `cicd_posture` |
| `mobile_misconfiguration` | a mobile app ships a loadable unencrypted private key | `mobile_posture` |
| `identity_misconfiguration` | a privileged identity without MFA, or a stale/never-rotated credential | `identity_posture` |
| `email_auth_misconfiguration` | the domain's published DMARC/SPF policy permits spoofing | `email_auth_posture` |
| `imds_credential_capture` | instance-metadata credentials were captured **and** proven usable | `imds_credential_capture` |
| `secret_credential_validity` | an exposed secret was proven still valid | `secret_credential_validity` |
| `gcp_sa_impersonation` | a token was minted **as** another GCP service account and confirmed | `gcp_sa_impersonation` |

### 3.10 AEGIS (defensive, over the operator's own app + telemetry)

| Bug class | Plain meaning | Oracle |
|---|---|---|
| `prompt_injection` | an injected directive changed the app's LLM behaviour | `prompt_injection` |
| `system_prompt_disclosure` | the app's hidden system prompt leaked verbatim | `system_prompt_disclosure` |
| `automated_access` | a non-human client fetched a honeypot resource | `automated_access` |
| `credential_stuffing` | one source achieved statistically significant logins across many unseen accounts | `credential_stuffing` |

### 3.11 Aliases (190) — spelling normalisation, and the deliberate NON-aliases

`normalize_bug_class` lowercases, `-`/space → `_`, collapses `__`, then maps through `_ALIASES`.
Examples: `sql_injection`→`sqli`, `blind_sqli`→`boolean_sqli`, `cross_site_scripting`/`reflected_xss`/
`stored_xss`→`xss`, `directory_traversal`→`path_traversal`, `port_open`/`open_port`→`service_reachable`,
`cve`/`sca`/`outdated_dependency`→`vulnerable_dependency`, `password_spraying`/`ato`→`credential_stuffing`,
`automated_scraping`→`automated_access`.

**Deliberate non-aliases, documented in the code as load-bearing** (these are the honesty seams):

- `nosqli` (live, response-proven) is **not** aliased to `nosql_injection_attempt` (request parse-proof).
- `jwt` (live acceptance) is **not** aliased to `jwt_forgeable` (offline forgeability).
- The live SAML classes are **not** aliased to `saml_structural_forgery`.
- `k8s_misconfiguration` (kube-bench CLI flags) is **not** aliased to `k8s_workload_misconfiguration` (RBAC).
- The reachability cloud classes (`privilege_path`/`excessive_privilege`) are **not** aliased to the
  achieved-state `cloud_misconfiguration`, nor to `iam_escalation_primitive`.

---

## 4. THE SCANNER'S CHECK INVENTORY (what actually generates candidate findings)

### 4.1 Check shapes (`scanner/checks.py`)

`DifferentialCheck`, `BooleanInferenceCheck`, `TimingCheck`, `MarkerReflectionCheck`, `OOBCheck`,
`EvaluationCheck`, `ErrorSignatureCheck`, `ContentSignatureCheck`, `PathProbeCheck`, `IdorCheck`, plus the
request-level `CorsActiveCheck`, `HostHeaderCheck`, `OpenRedirectCheck`.

### 4.2 `DEFAULT_CHECKS` — the 11 seed checks that always run (`checks.py:1055-1067`)

| id | bug_class | Shape |
|---|---|---|
| `boolean-sqli` | `boolean_sqli` | DifferentialCheck |
| `reflected-xss` | `xss` | MarkerReflectionCheck |
| `ssti-eval-braces` | `ssti` | EvaluationCheck (`{{7331*7331}}` → `53743561`) |
| `ssti-eval-dollar` | `ssti` | EvaluationCheck (`${7331*7331}`) |
| `path-traversal` | `path_traversal` | ContentSignatureCheck (`root:x:0:0:`) |
| `error-based-injection` | `error_based_sqli` | ErrorSignatureCheck |
| `open-redirect` | `open_redirect` | OpenRedirectCheck |
| `ssrf-oob` | `ssrf` | OOBCheck |
| `xxe-oob` | `blind_xxe` | OOBCheck |
| `rce-oob` | `command_injection` | OOBCheck |
| `deserialization-oob` | `deserialization` | OOBCheck |

**A documented historical correction, worth telling** (`checks.py:988-999`): SSTI, path-traversal and
error-based used to confirm on bare canary **reflection**, which false-positived on any endpoint that
echoes input. They were rewritten to evidence-carrying oracles — SSTI now confirms only when the server
*computed* the arithmetic, path-traversal only when the target file's *content* appears, error-based only
when a datastore error appears in the probe but not the benign control.

### 4.3 The data-driven check library — 172 JSON entries (`scanner/library_entries/`)

Distribution by bug class:

| bug_class | entries | | bug_class | entries |
|---|---:|---|---|---:|
| `boolean_sqli` | 21 | | `error_based_sqli` | 8 |
| `exposure` | 20 | | `path_traversal` | 7 |
| `xss` | 18 | | `nosqli` | 5 |
| `command_injection` | 17 | | `sqli` | 3 |
| `deserialization` | 14 | | `lfi` | 2 |
| `ssrf` | 13 | | `auth_bypass` | 2 |
| `time_based_sqli` | 11 | | `rce` | 2 |
| `ssti` | 11 | | `time_based_command_injection` | 2 |
| `blind_xxe` | 10 | | `el_injection`, `sensitive_exposure`, `ldap_injection`, `time_based`, `xpath_injection`, `xxe` | 1 each |

Coverage inside those families includes per-engine SQLi (MySQL/Postgres/MSSQL/Oracle/SQLite), 11 template
engines for SSTI (Jinja2/Twig/Freemarker/Velocity/ERB/Smarty/Mako/Thymeleaf/Razor/Pug/generic), Windows +
Unix command-injection variants, JNDI/log4shell obfuscations, and 20 framework-exposure paths
(`.git/config`, `.env`, Spring actuator env/heapdump/mappings, phpinfo, Jenkins script console,
Elasticsearch, Docker registry, `wp-json/users`, Swagger/OpenAPI, Laravel log, Rails routes, SVN entries…).

### 4.4 Opt-in / conditional scanner modules

| Module | Classes it produces | Gate |
|---|---|---|
| `scanner/sso.py` | `saml_assertion_tampering`, `saml_signature_wrapping`, `oidc_redirect_uri`, `oidc_idtoken_forgery`, `saml_structural_forgery` | `SSO_REQUEST_CHECKS`, enabled via `enable_sso` (`campaign.py:264`) |
| `scanner/graphql.py` | the 6 `graphql_*` classes | opt-in |
| `scanner/jwt.py` | `jwt` (live acceptance), `jwt_forgeable` (offline) | conditional |
| `scanner/access_control.py` | `idor`/`bola`/`bfla`/`broken_access_control` via two-identity cross-access specs, plus `mass_assignment` | needs operator-supplied victim identity headers + `--ac-ref bug_class:ref_param:victim_ref` |
| `scanner/bizlogic.py` | `business_logic` | OPT-IN, needs an operator workflow spec; **not** in `DEFAULT_CHECKS` |
| `scanner/race.py` | `request_race` | opt-in |
| `scanner/smuggling.py` | `request_smuggling` | opt-in |
| `scanner/websocket.py` | `cross_site_websocket_hijacking`, `websocket_injection` | opt-in |
| `scanner/browser.py`, `browser_xss.py`, `domxss.py` | `dom_xss` | needs a real headless browser + CDP |

### 4.5 The full producer inventory — everything that can raise a LEAD

Producers **only ever raise LEADs**, whatever they call their own output. Nothing in this list can confirm
anything; each merely supplies retained evidence for an oracle to judge.

**Sensors / collectors** (`engine/crucible/framework/v2/sensors/`, 22 modules):
`web_scanner`, `nmap`, `tls_cert`, `tshark`, `sbom`, `fuzz`, `cloud`, `cloud_live`, `azure_live`, `gcp_live`,
`k8s_live`, `k8s_runtime`, `mesh`, `cicd`, `identity`, `email_auth`, `mobile`, `android_manifest`,
`pipeline`, `builtin`, `base`, plus tests.

**Scanner modules beyond `checks.py` / `library.py`:** `graphql`, `sso`, `jwt`, `race`, `smuggling`,
`websocket`, `domxss`, `browser`/`browser_xss`/`cdp`, `access_control`, `bizlogic`, `passive`,
`crawler`/`spa_crawler`/`browser_crawler`, `discovery`, `insertion`, `targeting`, `waf_evasion`,
`quantum_era`, `nuclei_compile`, `lateral`, `session`, `fingerprint`, `coverage`, `grammar`,
`check_synthesis`, `self_improve`, `adaptive`, `learning`, `sequencer`, `campaign`, `orchestrator`.

**Gated live runners + verify seams** (`integration/vigil_integration/live/`):
`imds_runner` → `imds_verify`, `secret_verify`, `gcp_impersonation_verify`, `iam_escalation_verify`,
`k8s_rbac_verify` (TIER-1), `k8s_rbac_grant_verify` (TIER-2), `cloud_live_posture`, `iac_posture`,
`mesh_cicd_posture`, `k8s_posture`, `sbom`, `external_tool`, `cloud_benchmark`, `conformance` — with the
gating machinery beside them: `cloud_scope` (the D5 scope gate), `approval_broker`, `approval_token`,
`nonce_ledger`, `sandbox_exec`, `dns_pin`, `safe_parse`, `executor`, `governance_identity`.

**Verify-side capture helpers** (`engine/crucible/framework/v2/verify/`): `reachability` (TCP handshake),
`reachability_cloud` (the bounded anonymous GET), `tls` (TLS handshake), `oob` (the loopback OOB receiver
that mints the correlation token), `collaborator` (+`collaborator_cli`), `replay_harness`, `drift`,
`plan_integrity`, `poc_translate`, and the per-domain ingest/confirm seams (`cloud_posture`, `k8s_posture`,
`k8s_workload_posture`, `k8s_rbac_grant`, `mesh_posture`, `cicd_posture`, `mobile_posture`, `email_auth`,
`identity_posture`, `imds_capture`, `secret_capture`, `gcp_impersonation_capture`,
`iam_escalation_capture`, `jwt_forgery`, `saml_forgery`, `weak_crypto`, `version`, `policy_path`).

**AEGIS defensive registry** (`aegis/registry.py:26`): a separate, deliberately tiny map —
`AEGIS_BUG_CLASS_ORACLES` binds exactly **4** classes to exactly **one** oracle each
(`prompt_injection`, `system_prompt_disclosure`, `automated_access`, `credential_stuffing`), with
`AEGIS_ALIASES` folding `jailbreak`, `system_prompt_leak`, `automated_scraping` and `account_takeover` onto
them — "never their own confirmed class". Inbound telemetry (`AEGIS_SOURCE_KINDS`:
`REQUEST_TELEMETRY`, `LLM_INTERACTION`, `AUTH_TELEMETRY`) is explicitly the **LEAD tier**.

---

## 5. LEAD vs FACT — the exact machinery

### 5.1 The one-sentence rule

A LEAD is *anything anyone said*. A FACT is *a verdict VIGIL re-derived itself, deterministically, over
evidence VIGIL retained, which anyone can re-derive again offline.* The gap between them is closed only by
**re-execution**, never by string trust.

### 5.2 The pipeline, stage by stage

```
 producer (scanner check / sensor / external tool / LLM)
     │  emits an Observation / a proposed finding + a retained oracle_context
     ▼
 [1] OracleVerifier.confirm(ctx)            verify/verifier.py:643-714
     │   • select oracle set from bug_class (BUG_CLASS_ORACLES, else the frozen 15)
     │   • run only the oracles whose inputs are PRESENT (absent input → skip, never a pass)
     │   • confirmed = class_known AND ≥1 oracle fired at confidence ≥ 0.70
     │   • UNKNOWN-CLASS FAIL-CLOSED: an out-of-vocabulary class can never be confirmed even
     │     if a fallback oracle fires (verifier.py:661-690) — it says so loudly in the rationale
     │   • combine policy = "any_high_confidence_fired" (safety-monotone): a non-firing oracle
     │     CANNOT veto a fired one; it is recorded as `dissent`, never a refutation
     ▼
 [2] confirm_finding(...) -> ConfirmedFinding | None     verify/confirmation.py
     │   the TYPE is the proof — an instance only exists when an oracle fired
     ▼
 [3] verdict.admit(branch_id, fired, conclusive, observed)   integration/.../live/verdict.py:131-167
     │   the REGISTRY is load-bearing here, not descriptive:
     │     • unregistered branch  -> UnregisteredBranch (fatal)
     │     • preconditions unmet  -> INCONCLUSIVE
     │     • fired & fact_capable -> FACT ; fired & NOT fact_capable -> LEAD
     │     • not conclusive       -> INCONCLUSIVE
     │     • conclusive non-fire & clean_capable -> CLEAN ; else INCONCLUSIVE
     ▼
 [4] evidence/certify.py  build + m-of-n Ed25519 sign an EvidenceCertificate
     ▼
 [5] veracity/firewall.py::admit(claim)  — the DEMOTE-ONLY choke point
     ▼
 [6] verify/reverify.py — anyone, offline, re-runs the pure oracle over the retained bytes
     ▼
 [7] report/grounding.py::grade_finding — re-executes the proof AGAIN at render time
     │   re-fires -> FACT | recorded-confirmed but no longer re-fires -> DEMOTED | else LEAD
     ▼
                                  what the reader is finally shown
```

Note the shape: **the proof is re-executed at every stage that could otherwise inherit trust** — at
confirmation, at admission, at certification, at claim admission, at offline re-verification, and once more
at render. Nothing between stages is taken on the previous stage's word.

### 5.3 The admission gate (`live/verdict.py`) — three anti-forgery properties

1. **`AdmittedVerdict` can only be built inside `admit()`.** Authorization is a **construction-scope
   contextvar**, not a field — because a field is copied by `dataclasses.replace`, and a red-pen review
   found that a token *field* let `replace(inconclusive, verdict=FACT)` forge a FACT carrying a valid token.
   Direct construction, `replace`, `copy`/`deepcopy` and `pickle` all raise `DirectVerdictConstruction`
   (`verdict.py:47-58, 94-99`).
2. **Preconditions are per-branch, per-observation** — "the body was readable" is meaningless to a
   header-derived branch and decisive to a markup one, so one capture can legitimately yield a
   header-derived CLEAN *and* a body-derived INCONCLUSIVE simultaneously. A precondition declared but
   **absent** from the observation counts as NOT held: "an unknown is not a yes" (`verdict.py:115-128`).
3. **Family composition is conservative** (`verdict.py:185-206`): `any FACT → FACT`, else `any LEAD → LEAD`,
   else `any INCONCLUSIVE → INCONCLUSIVE`, else `all CLEAN → CLEAN`. **An empty set composes to
   INCONCLUSIVE, not CLEAN** — "nothing examined is not the same as nothing found."
   `web_redrive.py:197-245` deliberately emits **one admission per atomic branch outcome** rather than one
   per response, so a strong sibling cannot hide a weaker branch's limitation.

### 5.4 The veracity firewall (`veracity/firewall.py`) — it can only DEMOTE

`admit(claim)` turns a `Claim` into an `AdmittedClaim` by **re-executing every cited ground**. Order:

1. world-model **contradiction** → `CONTRADICTED`;
2. a named entity **absent from the graph** → `UNGROUNDED` (a fabricated target);
3. validate each ground **bound to this claim's own subject**:
   - `ORACLE` — must re-fire via `reverify_context` **for the claim's own `bug_class`** (a SQLi proof cannot
     ground an RCE claim) (`firewall.py:50-63`);
   - `CERT` — the signed certificate must certify **that** bug class (`firewall.py:66-79`);
   - `WORLDMODEL` — the node must be one the claim **names**, its belief lower-credible-bound ≥ `0.5`, and
     its provenance must classify as `grounded` (traces to a fired oracle / signed cert / promoted finding);
     collected intel and derivations are legitimate but do **not** reach fact strength (`firewall.py:82-93`);
   - `HYPOTHESIS` — gated + prior ≤ cap; grounded but **labelled a hypothesis, never a fact**;
4. a `from_dryrun` claim may stand **only** on re-executable oracle/cert grounds, never its own LLM
   reasoning (`firewall.py:154-155`);
5. a FACT claim must declare a subject — **"an unbound proof grounds nothing"** (`firewall.py:163-167`);
6. the reported confidence of a fact is the **re-executed** oracle value, not the proposer's number
   (`firewall.py:168-169`).

An ungrounded claim is **stamped, not dropped** — rendered as `analyst-commentary`, so "the operator loses
framing, never information" (`veracity/claims.py:1-16, 77-86`).

**Honest phasing, stated in the module's own docstring (`firewall.py:27-30`):** this is the caller-less
**primitive** (veracity P0). Runtime enforcement is wired in subsequent phases (the world-model admission
gate P2, the reporting gate P4). Until those land, `admit()` is exercised by its tests — "that is by design,
not a gap." **It is not today a universal live choke point every claim crosses.** `docs/FEATURES.md` marks
this section `SCAFFOLDED/PHASED` and translators must preserve that.

### 5.5 Re-verification (`verify/reverify.py`) — the offline proof

Every confirmed finding retains the exact evidence the oracle judged as a serialized `FindingContext`
(`oracle_context`). Because the oracles are pure, that certificate can be re-checked by **anyone, offline,
with no target and no trust in the tool that produced it**:

- `reverify_context` reconstructs, re-runs the pure oracle, and checks the verdict reproduces **and matches
  the claimed `confirmed_by`/`confidence` within `1e-6`** (`_CLAIM_EPS`, `reverify.py:36, 173-176`);
  a mismatch is annotated "DIFFERS from the claimed certificate (tampered?)".
- **Class binding is load-bearing** (`reverify.py:145-158`): the retained evidence adjudicates its **own**
  bug class; a requested class that differs is REFUSED at the re-execution boundary — so a finding whose
  `bug_class` was flipped (SQLi evidence relabelled `rce`) cannot re-confirm as the flip.
- CLI: `python3 -m framework.v2 verify <report.json>` — **exit 0 iff every certificate reproduces and
  matches its claim**, else 2 (`reverify.py:218-245`).
- Memoized on canonical evidence JSON; determinism-safe (a pure function of its key), always returns a
  fresh copy.

### 5.6 The evidence certificate (`evidence/certify.py`) — four independent checks

`verify_certificate` is sound only if **all four** hold:

1. **Authenticity** — an m-of-n Ed25519 governance signature over the canonical bytes;
2. **Binding** — the certificate's `oracle_context_digest` matches the sha256 of the presented context, so
   a signature cannot be lifted onto different evidence;
3. **Artifact integrity** — every raw file in the manifest still hashes to its recorded digest;
4. **Reproduction** — the pure oracle re-fires over the `oracle_context` and matches the claimed verdict.

The trust root is pinned **out of band** by a `sha256:` fingerprint the operator publishes, "not the copy of
`trust-root.json` shipped alongside a bundle" — so a forger who re-signs tampered evidence with a fresh key
is rejected before any signature is checked (`certify.py:trust_root_fingerprint`).

### 5.7 Oracle versioning (`verify/oracle_version.py`) — staleness is detectable

`oracle_version(kind)` = `sha256:` over the canonical **source** of the oracle function(s) **plus the
transitive closure** of every module-level helper function and validation constant its decision procedure
reaches (an IP set, a regex, a path marker). So editing a helper or a constant changes the version — "the
entry function alone no longer hides a changed procedure." The version is signed into the certificate at
mint; a verifier compares it against the current value and a PCF verifier treats a mismatch **fail-closed**.
If the source is unavailable (a frozen deployment) the version is `""` and the verifier **reports it cannot
confirm rather than guessing**.

### 5.8 PCF — Proof-Carrying Findings (`evidence/pcf.py`, `docs/proof-carrying-finding/`)

`verify_pcf` runs five ordered, fail-closed steps, each **delegating to a real primitive**, never a
reimplementation:

1. schema + vocabulary via `require_known_bug_class` (an invented class is rejected at step 1);
2. the m-of-n Ed25519 signature over the domain-separated bytes, plus a **view-consistency** check so the
   PCF projection cannot misrepresent the signed certificate ("a lying wrapper");
3. evidence-digest integrity;
4. oracle reproduction via `reverify_context` **plus** the `id@version` staleness check;
5. claim-grounded: `oracle_confirms_class` — the oracle that fired must be a valid confirmer for the claimed
   class, which **defeats relabelling**.

### 5.9 Anti-hallucination: the bug-class vocabulary as a type

`known_bug_classes()` / `is_known_bug_class()` / `require_known_bug_class()` (`verifier.py:555-616`) expose
the 275 accepted strings as a **pydantic field type** (`KnownBugClass = Annotated[str, AfterValidator(...)]`),
so an invented class cannot survive parsing into a field that asserts an oracle-provable subject. Exploratory
hypotheses may legitimately name a broader set; only *fact*-bound fields are constrained.

### 5.10 What an LLM is allowed to do

- The LLM **proposes**; the oracle **confirms**. `FEATURES.md` (verified against
  `integration/vigil_integration/oracle_adapter.py` line refs it cites): `confirm_and_certify` demands
  (1) an oracle fired at ≥0.7, (2) the class be oracle-mapped, and (3) the `oracle_context` **provenance**
  be in `{reproduced, live_redrive}` — the default `"llm"` provenance is **demoted to a LEAD even when the
  oracle fires**, because a crafted-but-firing context is an LLM-influenced route to a FACT.
- Terminal/agent output is advisory-only and never enters oracle intake.
- `veracity/firewall.py` additionally strips non-re-executable grounds from any `from_dryrun` claim.

### 5.11 Report-time re-grading (`report/grounding.py`) — the last gate before a human reads it

This is the stage that makes the whole chain visible in the output, and it is easy to miss.
`report/__init__.py:9-15`: *"Prove-don't-guess is enforced IN THE OUTPUT."* Every finding is **re-graded at
report time by re-executing its proof** — offline, deterministic, no traffic; the same finding grades
identically every time. `grade_finding` (`grounding.py:111-147`) mirrors `agents/reporter_agent.py` exactly,
so a report and the reporter agent can never disagree.

Three **mutually exclusive** grades (`grounding.py:36-38`):

| Grade | Trigger | Rendered as | Extra fields |
|---|---|---|---|
| `fact` | the finding's own retained oracle proof **re-fired at report time** for its own bug class | a proven fact | `confidence` + `certificate_digest` — populated **only** here (`grounding.py:89-92`) |
| `demoted` | the finding was **recorded** oracle-confirmed (`verified_by_oracle`) but its proof **no longer re-fires** | a LEAD, with the admission reason attached | none |
| `lead` | no deterministic oracle signal at all (LLM-advisory) | a lead to verify | reason distinguishes an ordinary advisory lead from one produced by a **DRY-RUN** model call |

`GradedFinding.is_lead` deliberately returns True for **both** `demoted` and `lead`
(`grounding.py:104-107`): *"a lead is anything not proven — both the LLM-advisory and the demoted case."*
The two are kept as separate grades only so the reader can see *which* kind of unproven it is.

`report/priority.py:160` prioritises over `g.is_fact` only — an unproven finding cannot occupy a top
remediation slot on strength it does not have.

The same rule is enforced on the AEGIS side by **withholding the evidence rather than adding a label**
(`aegis/integrate.py:150-163`): a LEAD verdict projects a finding payload with **no `oracle_context` at
all**, so the grader structurally *cannot* render it as a fact — "the report grader renders it as an
unconfirmed lead, never a fact." A confirmed verdict projects the retained certificate
(`oracle_context` + `verified_by_oracle=True`) and the grader re-executes it. Belief tiers ride along
(`grounded:aegis:*` for confirmed, `intel:aegis:*` for a lead), and the source reliability differs:
`_FACT_RELIABILITY` vs `_LEAD_RELIABILITY = SourceReliability(C, C3)` (`integrate.py:74`).

---

## 6. THE EVIDENCE-BRANCH REGISTRY — 26 branches, FACT- vs CLEAN-capability

`docs/capability-matrix/evidence-branches.json` (schema `vigil-evidence-branches/1`), enforced by
`engine/crucible/framework/v2/scanner/tests/test_claim_discipline.py` **and** at runtime by
`live/verdict.py::admit`.

Registry semantics (from the file's own `note`): `fact_capable`/`clean_capable` describe what is TRUE
**today**; `target_fact_capable`/`target_clean_capable` are what the branch **must become**. Any gap
**requires** `blocking_work` naming the concrete engineering that closes it — *a gap without blocking work
fails the enforcement test, so a capability can never be quietly abandoned by downgrading the claim.*
Lowering a **target** requires an explicit `target_downgrade_rationale` arguing the capability is not
achievable at all. `evidence_surface` is a **closed type** so rules key off the declared surface, never the
branch name. `implementation_refs` are `path:symbol` and the lint checks they resolve.

| # | Branch id | Surface | FACT | CLEAN | Notes |
|---|---|---|:--:|:--:|---|
| 1 | `open_redirect.location_header` | response_headers | ✅ | ✅ | 3xx + Location host == canary. Header-derived, independent of body decoding |
| 2 | `open_redirect.body_markup` | response_body | ✅ | ❌ | meta-refresh target host == canary |
| 3 | `open_redirect.js_sink` | response_body | ✅ | ❌ | a JS location sink in a region the lexer proved executable |
| 4 | `cors.reflected_origin_with_credentials` | response_headers | ✅ | ✅ | ACAO reflects probe Origin AND ACAC true. Deliberately excludes ACAO `*` + credentials (browsers refuse it — a misconfig, not credential-readable) |
| 5 | `host_header.location_header` | response_headers | ✅ | ✅ | redirect Location authority == injected hostile Host |
| 6 | `host_header.body_emission` | response_body | ✅ | ❌ | hostile Host is the authority of a URL the app EMITS (href/src/action/canonical) |
| 7 | `oidc_redirect_uri.location_header` | response_headers | ✅ | ✅ | opt-in (`SSO_REQUEST_CHECKS`); operator's own endpoint only |
| 8 | `oidc_redirect_uri.body_markup` | response_body | ✅ | ❌ | |
| 9 | `service_reachability.tcp_handshake` | transport | ✅ | ✅ | **a closed port IS a channel-confirmed negative** |
| 10 | `tls_weakness.tls_handshake` | tls_handshake | ✅ | ✅ | scoped to what a modern client still negotiates |
| 11 | `version_range.manifest_membership` | artifact | ✅ | ❌ | absence from a **pinned** advisory snapshot is not absence of vulnerability; non-pinned constraints are skipped, not resolved |
| 12 | `k8s_posture.cis_control` | artifact | ✅ | ❌ | a kube-bench export is a partial point-in-time snapshot |
| 13 | `k8s_workload_posture.rbac_binding` | artifact | ✅ | ❌ | a manifest export is a partial snapshot of the bindings handed to us |
| 14 | `mesh_posture.declared_configuration` | artifact | ✅ | ❌ | **DECLARED** configuration, not proven effective runtime posture |
| 15 | `cicd_posture.workflow_construct` | artifact | ✅ | ❌ | one workflow file cannot prove absence across other workflows / reusable-workflow callees / composite actions |
| 16 | `iac.cloud_posture.achieved_state` | artifact | ✅ | ❌ | bounded to the represented state; an ambiguous attribute is UNKNOWN, never a guessed insecure fact (`block_public_access=false` → `public=None`; a missing SSE block → `encrypted=None`; a CloudFormation intrinsic principal → the grant is dropped) |
| 17 | `iac.policy_path.iam_grant_path` | artifact | ✅ | ❌ | graph re-derived from the raw artifact, never laundered from a scanner |
| 18 | `cloud_live.cloud_posture.achieved_state` | live_capture | ✅ | ❌ | D5 scope-gate authorises (provider, account[, region][, resource]) against the signed charter BEFORE any capture is adjudicated |
| 19 | `cloud_live.cloud_posture.cross_account_principal` | live_capture | ✅ | ❌ | **sound only when the owner's own account id(s) are threaded in from the charter**; with no owner set it stays a LEAD — it never guesses the owner. GCP `serviceAccount` cross-project is deliberately NOT fact-capable (Google-managed service agents are indistinguishable by email and cannot be enumerated → any list is fail-open) |
| 20 | `cloud_live.policy_path.iam_grant_path` | live_capture | ✅ | ❌ | |
| 21 | `cloud_exploit.imds.credential_capture` | live_capture | ✅ | ❌ (target ❌ + rationale) | **real-transport LIVE-FIRE deferred on an operator-provisioned lab credential** |
| 22 | `cloud_exploit.secret.credential_validity` | live_capture | ✅ | ❌ (target ❌ + rationale) | **live-fire deferred on an operator-provisioned credential** |
| 23 | `cloud_exploit.gcp.sa_impersonation` | live_capture | ✅ | ❌ (target ❌ + rationale) | **live-fire deferred on operator-provisioned GCP creds** |
| 24 | `k8s_exploit.rbac.anonymous_privileged_binding` | live_capture | ✅ | ❌ (target ❌ + rationale) | **live-fire deferred on an operator-provisioned kubeconfig** |
| 25 | `cloud_exploit.iam.privilege_escalation` | live_capture | ✅ | ❌ (target ❌ + rationale) | offline re-derivation over the operator's own retained policy; live-fire is deliberately **not** part of this branch — "a defensive verification oracle never executes the escalation" |
| 26 | `k8s_exploit.rbac.dangerous_verb_grant` | live_capture | ✅ | ❌ (target ❌ + rationale) | TIER-2 rule-parsing; **live-fire deferred on an operator-provisioned kubeconfig** |

**Only 6 of 26 branches may currently say CLEAN**, and all six are header/transport/TLS-derived. Every
body-derived, artifact-derived and live-capture-derived branch may only say FACT / LEAD / INCONCLUSIVE.

---

## 7. WHY "NOTHING IS WRONG" IS HARDER THAN "SOMETHING IS WRONG"

This is the system's central epistemic asymmetry, and it is stated in four independent places in the code.

### 7.1 The logical asymmetry

A FACT is an **existential** claim: one positive observation discharges it. A CLEAN is a **universal**
claim: it asserts something about every way the bug could have manifested, so it needs a proof that the
observation channel was *capable of seeing the bug had it been there*. Absence of a positive signal is not
proof of absence.

### 7.2 `OracleSignal.conclusive` — the honesty flag CLEAN rests on

`verify/models.py:370-398`. A signal is `conclusive` only when the oracle had an **observable channel** and
rendered a definite verdict:

- a positive fire (always conclusive — enforced by a model validator that flips `conclusive=True` whenever
  `fired=True`);
- **or** a channel-confirmed NEGATIVE: an SPRT that reached the *refute* boundary; an adequate-sample timing
  test that found no shift; a definite predicate/achieved-state proposition over observed values; or a
  payload **observed reaching the sink but neutralised** (a marker reflected only into an inert/encoded
  context, a template expression echoed raw-not-evaluated).

It is `False` for a **one-sided** oracle that merely did not fire with no observable channel — a single-shot
differential over indistinguishable responses, a marker/error/callback simply absent (a blind, second-order,
or input-ignoring sink). *"Such a non-signal is 'inconclusive', NEVER 'clean': absence of a positive channel
is not proof the surface is safe."*

### 7.3 `probe_verdict` — the coverage honesty rule (`scanner/engine.py:143-174`)

```
confirmed                          -> "finding"       (an oracle fired at/above threshold)
a conclusive signal, none fired    -> "clean"         (channel-confirmed negative)
only non-conclusive non-signals    -> "inconclusive"  (payload sent, no oracle had a channel — NEVER clean)
```

`oracle_kinds_run` for a `clean` verdict names **only** the oracles that conclusively adjudicated;
`inconclusive` carries none. In-code: *"This is the line M2 exists to hold: a payload sent with no
adjudicating channel is inconclusive, never clean."*
`coverage_oracle.tested_bug_classes` likewise **excludes** `inconclusive` probes — "no oracle adjudicated
it, so it was not tested clean."

### 7.4 CLEAN needs a *completeness* proof, which is a different capability

Read the `blocking_work` strings in the registry: every one of them is a **completeness** requirement, not a
detection improvement.

| Branch | What CLEAN additionally requires (verbatim theme) |
|---|---|
| `open_redirect.body_markup` | a **spec-compliant** HTML encoding-determination implementation (a vendored reference, *not* a regex — a hand-approximated `<meta>` prescan is rejected under Claim-Discipline rule 4); vendored, version-pinned, bounded **streaming brotli/zstd** decoders whose versions are bound into oracle provenance; bounded **concatenated-member** decoding; a **truncation-free** read under the cap. Only then is a non-firing a channel-confirmed negative |
| `open_redirect.js_sink` | lexing cannot prove absence — a redirect assembled at runtime never appears literally. Closing it needs the **headless-browser** path to observe actual navigation |
| `version_range.manifest_membership` | resolve non-pinned constraints and record **snapshot coverage**, so "no advisory matched" becomes a bounded negative |
| `k8s_posture.cis_control` | a **control-coverage manifest** (the expected CIS control IDs per node role + kube-bench version) checked against the parsed export |
| `k8s_workload_posture.rbac_binding` | proof the manifest enumerates **every** ClusterRoleBinding/RoleBinding, **and** that the dangerous-role set is exhaustive (transitive `aggregationRule`, custom roles granting `*` on `*`) |
| `mesh_posture.declared_configuration` | enumerate every namespace/workload, resolve mTLS **inheritance** to an effective mode per workload, and record the export as complete |
| `cicd_posture.workflow_construct` | enumerate every workflow **plus** reusable-workflow and composite-action callees, resolved transitively |
| `iac.*`, `cloud_live.*` | prove the parse/capture enumerated the resource's **full achieved policy surface** (bucket-policy/ACL/public-access-block/SSE/security-group all resolved and cross-linked; intrinsics/parameters fully resolved) |

Additionally, three of the four insertion-coverage `blocking_work` notes are about **where we inserted**,
not what we detected: the live re-drive probes `QUERY_VALUE` and `URL_PATH_SEG` only — **cookie, urlencoded-
body and JSON-body redirect parameters are not yet probed**, so a redirect taken only from those surfaces is
*currently unexamined, reported as such, never as CLEAN*.

### 7.5 The five branches whose CLEAN target is deliberately lowered — with the argument

`cloud_exploit.imds.*`, `cloud_exploit.secret.*`, `cloud_exploit.gcp.*`, `k8s_exploit.rbac.*` (×2),
`cloud_exploit.iam.*` carry `target_clean_capable: false` with a `target_downgrade_rationale`. The argument
in every case is the same and is worth reproducing in plain English: *these are achieved-effect exploitation
confirmations over a single scoped capture. Proving the ABSENCE of a capturable credential / a valid secret /
an impersonation path / a dangerous binding / an escalation path is a **different capability** — a POSTURE
enumeration with a completeness proof — not this branch's target.* So the CLEAN side is routed to the
posture branches, not abandoned.

### 7.6 The negative that IS shipped — three artifacts

| Artifact | What it proves | Honest bound |
|---|---|---|
| **Coverage certificate** (`verify/coverage_oracle.py`) | for each `(surface, param, class)` the audit reached, whether an applicable oracle actually **ran and adjudicated** — turning a silent surface from *merely untested* into *provably tested clean*. Signed m-of-n Ed25519 over deterministic canonical bytes; trust root pinned out of band | the honest scope string is baked **verbatim into the signed bytes**: it certifies coverage of the surfaces the scanner **reached**, and is **not** proof of surface completeness. The denominator cites `max_pages`/`max_depth`/`frontier.truncated`/`budget_exhausted` so a reader cannot mistake reach for the whole app |
| **PostureCertificate** — the *Certificate of Non-Exploitability* (`integration/vigil_integration/posture/`) | a signed projection of the coverage oracle into `CLOSED` / `OPEN` / `UNPROVEN` per `(surface, parameter, vuln-class)`, bound to an owner-signed target attestation, carrying its coverage denominator and residual **verbatim in the signed bytes**. Two verification tiers: `binding` (a third party re-checks signature + out-of-band fingerprint pin + coverage-projection binding + owner target-binding, **offline with no VIGIL installed**) and `re-executable` (the cert embeds each clean probe's pure JSON-AST predicate + the observed evidence, and the standalone verifier **re-derives** the verdict) | CLOSED means non-exploitability **by the oracle family, over the reached surface, as of the freshness bound** — never "secure against everything". A structural invariant refuses to mint a CLOSED that names no conclusive oracle. **UNPROVEN never counts as CLOSED.** Even the `re-executable` tier's honest bound is stated: the retained values are still **producer-supplied**, so re-execution proves the verdict↔evidence binding, **not** that the evidence reflects the live target |
| **RemediationCertificate** (`integration/vigil_integration/remediation/`) | "the exploit that provably worked is now provably dead" — the ORIGINAL oracle went **silent** over the patched build's freshly re-captured bytes, cross-bound to the original positive certificate. Four states: `REMEDIATED` / `STILL_VULNERABLE` / `INCONCLUSIVE` / `REFUSED`, all four **signed**, so an INCONCLUSIVE reason cannot be stripped and re-read as success | silence is only a fix when **controlled**: a positive-control twin must still FIRE (the harness is alive), the target must have ANSWERED (liveness — measured only on **target-produced** response keys, never producer-set fields), across a per-class repeat policy. A **fail-closed allowlist of 13 oracle kinds** is the only set for which silence is a sound negative; TIMING, CREDENTIAL_STUFFING, PROMPT_INJECTION, SYSTEM_PROMPT_DISCLOSURE, SANITIZER_SIGNAL, VERSION_RANGE, POLICY_PATH, all `*_POSTURE`, SAML/SSO forgery, AUTOMATED_ACCESS, SERVICE_REACHABILITY, ACTIVE_EXPOSURE and TLS_WEAKNESS are **excluded, each with a written reason**; race/smuggling/desync classes are excluded as non-deterministically-reproducible phenomena; an unknown class is fail-closed. Freshness: `STILL_VULNERABLE` can reach tier F2; **`REMEDIATED` caps at F1** — "a fixed sink's traversal is unprovable", and an F2-demanding verifier gets INCONCLUSIVE, never a false F2 |

The 13 certifiable-by-silence oracle kinds: `error_signature`, `side_effect`, `differential_response`,
`boolean_inference`, `reflection_context`, `dom_execution`, `evaluation`, `achieved_state`, `predicate`,
`oob_callback`, `sql_injection_breakout`, `command_injection_breakout`, `nosql_injection_breakout`
(`prove_driver.py:179-192`). Two written invariants those rest on: (1) `differential_response` qualifies
**only** because no certifiable class attaches a *latency* discriminator — if one ever does, silence becomes
unsound and latency-mode must be excluded; (2) `boolean_inference` and `oob_callback` silence is sound
**only** because a mandatory positive-control fire proves the round/callback budget was adequate before any
silence is credited.

### 7.7 The doctrine in one quote

`docs/CLAIM-DISCIPLINE.md` §0: *"Asserting a vulnerability that is not there (**false FACT**) destroys trust
in every finding. Asserting safety that was not established (**false CLEAN**) is worse, because nobody goes
looking again."*

---

## 8. WHAT IS BUILT vs. WHAT HAS BEEN FIRED IN ANGER — the honesty ledger

Translators must carry these distinctions. They come from the code and registry, not from marketing.

| Capability | Status as written in the source |
|---|---|
| The 15 core oracles on a live web target | **Working end-to-end.** `confirm_against_local_target` stands up a real loopback vulnerable app and confirms; pointed at a parameterised safe twin it returns `None` — a shipped negative control proving the authority does not rubber-stamp |
| `service_reachability`, `tls_weakness`, `version_range`, web `achieved_state` branches | **FACT-capable and CLEAN-capable (the first two/four) against real captures** |
| E1 IMDS credential capture | **OFFLINE-WIRED; real-transport LIVE-FIRE deferred** on an operator-provisioned lab credential. Runner, evidence branch, admission/verdict route, certificate mint and world-model projection are all built and fixture-proven. *"There is no live FACT yet."* |
| E5 exposed-secret validity | producer + admission/certificate/world-model wiring **complete and fixture-proven offline**; live-fire deferred on an operator-provisioned credential |
| E3 GCP SA impersonation | same: **offline-wired, live-fire deferred** on operator-provisioned GCP creds |
| E4 k8s RBAC (TIER-1 + TIER-2) | same: **offline-wired, live-fire deferred** on an operator-provisioned kubeconfig |
| E2 IAM escalation primitive | pure offline re-derivation over the operator's own retained policy. Live-fire is **deliberately not part of this branch** — a defensive verification oracle never executes the escalation |
| `saml_structural_forgery` crypto escalation | **DORMANT unless** the operator supplies trusted IdP certs AND `signxml` is importable; full XML-DSig C14N/transform processing is explicitly out of scope |
| `veracity/firewall.py` runtime enforcement | the module's own docstring: this is the **caller-less primitive**; runtime wiring (world-model admission P2, reporting gate P4) is phased. **Not today a universal live choke point** |
| Neo4j-backed graph store | a real reviewable client body behind the same interface, but the `neo4j` driver and a running service are **both absent** in this environment; a live store raises `NotImplementedError` and the parity test is behind a **loud skip** |
| LLM→FACT path in the agentic engine | `FEATURES.md` (self-describing, matching `oracle_adapter.py`): minting a FACT requires reproducing the finding from **executor-captured raw output**; until that live re-drive lands, that seam yields **LEADs** — "the correct fail-closed disposition" |

### 8.1 The one sentence translators must not soften

For the five deferred cloud/K8s capabilities the registry says the same thing in the same words, and it is
the exact honesty line a national-agency reader depends on. Verbatim from `evidence-branches.json`:

> *"Real-transport LIVE-FIRE (the runner against a real metadata endpoint / real provider endpoints / real
> GCP iamcredentials-oauth2 endpoints / a real cluster's kube-apiserver) is deferred on an
> operator-provisioned credential (lab credential / GCP creds / kubeconfig); the producer and this admission
> / certificate / world-model wiring are complete and fixture-proven offline."*

Two things follow, and both must survive translation:

1. **What is deferred is the act of pointing it at someone else's live account** — not the detection logic,
   not the evidence handling, not the certificates, not the safety gates. Those are built and proven.
2. **All six E-series branches carry `blocking_work: null`.** Under this repository's own enforcement rule
   (§6: a gap between current and target capability *must* name its blocking engineering, or the test
   fails), a null means **no engineering gap is recorded against them**. The deferral is operational —
   waiting on customer credentials — and the registry says so by construction, not by assertion.
3. **E2 is the exception and must be described differently.** `cloud_exploit.iam.privilege_escalation` says:
   *"Real-transport LIVE-FIRE (running the escalation primitive against a real account) is deliberately NOT
   part of this branch — a defensive verification oracle never executes the escalation."* Do not describe E2
   as "awaiting live fire". It is a pure offline re-derivation over the operator's own retained policy, and
   never executing the escalation is the design, not a limitation.

### 8.2 Supply-chain hardening of VIGIL's OWN build and release — verification status

The task brief describes dependency hash-locking, container base-image pinning, an SBOM, and a vulnerability
gate that blocks on CRITICAL as **being delivered today**. Status as actually observed in this tree at
inventory time — translators must re-check before publishing:

| Item | Verified state in-tree at `1487e03a` |
|---|---|
| Branch `a14-supply-chain` | **exists** and is checked out as a worktree, but `git diff main...a14-supply-chain` is **empty** — the work is in flight this session and not yet on `main` |
| Hash-locked dependency file | **[NOT VERIFIED]** — no `requirements*.txt` with hashes, no lockfile beyond `apps/sigil/requirements.txt` and `apps/sigil/kernel/Cargo.lock` |
| Pinned container base image | **[NOT VERIFIED]** in this tree |
| Generated SBOM artifact | **[NOT VERIFIED]** as a committed artifact (the SBOM *producer path* exists — see below) |
| CI gate blocking on CRITICAL | **[NOT VERIFIED]** — the only workflow file present is `.github/workflows/ci.yml` |

What **is** verified in-tree and is the directly adjacent machinery (this is safe to describe today):

- **`docs/capability-matrix/osv-snapshot.json`** — a **pinned, hand-curated slice of OSV.dev advisories,
  captured 2026-08-08**, covering the `PyPI` and `npm` ecosystems. Its own provenance string states:
  *"VIGIL's SBOM FACT path re-derives version membership from THIS snapshot + the operator's own manifest
  parse — it never trusts a scanner's CVE match. Refresh deliberately (a pinned data artifact, like the
  vendored oracle version)."* Ranges are OSV `{introduced, fixed}` events, semver/PEP-440 ordered.
- **`verify/version.py`** — the deterministic PEP-440 (via `packaging`) plus loose-semver comparator and
  range-membership evaluator behind the `version_range` oracle. Explicitly **fail-closed**: an unparseable
  version or range does not confirm, *"so a scanner's say-so can never be laundered into a fact and a mangled
  range can never fabricate one."* No I/O, no wall-clock — so a confirmed vulnerable dependency re-verifies
  offline from its certificate.
- **Evidence branch `version_range.manifest_membership`** (`sbom_verify`) — FACT-capable today, **not**
  CLEAN-capable, `target_clean_capable: true`, with named blocking work (resolve non-pinned constraints and
  record snapshot coverage, so "no advisory matched" becomes a bounded negative rather than an absence).
- **SBOM producer path**: `integration/vigil_integration/live/sbom.py` and
  `engine/crucible/framework/v2/sensors/sbom.py`.

The honest framing for a reader: VIGIL already applies its own prove-don't-guess discipline to dependency
vulnerabilities *as a finding class* — a CVE match from any scanner is a LEAD until the deterministic
comparator re-derives that the concrete pinned version really falls inside the advisory's range. The
build-and-release safeguards that apply that same discipline to VIGIL's **own** shipped artifacts are the
work landing today, and were not yet observable on `main` when this inventory was taken.

---

## 9. KNOWN DOCUMENTATION STALENESS (do not propagate)

| Doc | Stale claim | Reality at `1487e03a` |
|---|---|---|
| `docs/FEATURES.md` §4 | "`OracleKind` has **32 members**" | **38** |
| `docs/FEATURES.md:435` | cites `_ALL_ORACLES` at `verifier.py:445-461` | it is at **`verifier.py:531-548`** |
| `docs/FEATURES.md` §4 item 23 | "`k8s_workload_posture_oracle` … **is NOT wired into `verifier._run`**" and shares the `K8S_POSTURE` kind | it has its **own** `K8S_WORKLOAD_POSTURE` kind (`models.py:102`) and **is** dispatched (**`verifier.py:856-859`**) |
| `docs/FEATURES.md:503` | "`BUG_CLASS_ORACLES` (`verifier.py:33-242`) maps **~80** canonical bug classes"; cites `confirm` at `557-611` and `_run` at `613-802` | **85** classes, at `verifier.py:33-281`; `confirm` at **643-714**, `_run` at **716-951** |
| `docs/FEATURES.md` §4 item 27 | notes the `MESH_POSTURE` and `VERSION_RANGE` dispatch branches lack a trailing `return None` and fall through | **re-confirmed true** at this commit: `VERSION_RANGE` (`verifier.py:800-801`, next `if` at 802), `MESH_POSTURE` (`869-870`, next at 871), and likewise `GCP_SA_IMPERSONATION` (`931-932`, next at 933). All three are harmless because every subsequent branch keys on a **different** ctx field, so the fall-through can only reach branches whose inputs are absent — but they are a latent trap if two kinds ever share a ctx key |
| `engine/crucible/framework/v2/verify/README.md` | "The **five** oracles" | that table documents only the original five; there are 38 kinds / 40 functions |

Note for accuracy: the repository was being actively committed to during this inventory (commits
`d34e4398` E2 → `fa7d148f` E4-T2 WIP → merge `1487e03a`). **Re-run the counts in §0 before publishing.**

---

## 10. RE-DERIVATION COMMANDS (so a later writer can re-check every count)

```bash
cd /home/kali/vigil/engine/crucible/framework/v2/verify
python3 - <<'EOF'
import re
m=open('models.py').read()
print("OracleKind:",len(re.findall(r'^\s{4}[A-Z0-9_]+\s*=\s*"[a-z0-9_]+"',m,re.M)))
s=open('verifier.py').read()
b=s.split('BUG_CLASS_ORACLES: dict[str, tuple[OracleKind, ...]] = {',1)[1].split('\n}\n',1)[0]
a=s.split('_ALIASES: dict[str, str] = {',1)[1].split('\n}\n',1)[0]
canon=set(re.findall(r'^\s{4}"([a-z0-9_]+)":',b,re.M))
al=re.findall(r'"([a-z0-9_]+)":\s*"([a-z0-9_]+)"',a)
print("canonical:",len(canon),"aliases:",len(al),
      "known:",len(canon|{k for k,_ in al}|{v for _,v in al}))
f=s.split('_ALL_ORACLES: tuple[OracleKind, ...] = (',1)[1].split(')',1)[0]
print("frozen fallback:",len(re.findall(r'OracleKind\.',f)))
EOF

cd /home/kali/vigil
python3 -c "import json;d=json.load(open('docs/capability-matrix/evidence-branches.json'));b=d['branches'];
print('branches',len(b),'fact',sum(x['fact_capable'] for x in b),'clean',sum(x['clean_capable'] for x in b))"

ls engine/crucible/framework/v2/scanner/library_entries/*.json | wc -l
pytest engine/crucible/framework/v2/scanner/tests/test_claim_discipline.py   # the registry enforcement
python3 -m framework.v2 verify <report.json>                                  # offline re-verification CLI

# oracle-kind → bug-class spread (§2.6), and the orphan check
cd /home/kali/vigil/engine/crucible && python3 -c "
import sys,collections; sys.path.insert(0,'.')
from framework.v2.verify.verifier import BUG_CLASS_ORACLES
from framework.v2.verify.models import OracleKind
c=collections.Counter(k.value for v in BUG_CLASS_ORACLES.values() for k in v)
print('kinds referenced:',len(c),'of',len(list(OracleKind)))
print('multi-oracle classes:',sum(1 for v in BUG_CLASS_ORACLES.values() if len(v)>1))
print(c.most_common(11))"
```

---

## 11. VOCABULARY TRAPS — the phrasings a translator must not fall into

Each of these is a distinction the code holds deliberately and at real engineering cost. Collapsing any of
them in plain English would undo the thing that makes the product worth having.

| Do not write | Because |
|---|---|
| "the scanner confirmed X" | The **oracle** confirms. A scanner, a sensor, an external tool and an LLM can only ever *propose*. The whole architecture exists to keep those two verbs apart |
| "no vulnerabilities found" / "the app is secure" | Only 6 of 26 branches may say CLEAN at all, and even then only as a **bounded** statement (this target, these inputs, this observation interval). Everything else must read as INCONCLUSIVE. `CLAIM-DISCIPLINE.md` §1: "Probably safe", "no issues found", "secure" are **not verdicts** |
| "we scanned everything" | The coverage certificate certifies the surface the scanner **reached**, and says so inside its own signed bytes. Undiscovered endpoints are a discovery/recall question, not a coverage one |
| "detected scraping" | `automated_access` proves **automation** — a honeypot fetch. Link-unfurl bots, prefetch, AV URL scanners and uptime monitors trip it too. `automated_scraping` is an alias, never a confirmable class |
| "blocked a SQL injection" (for the request-side oracles) | `sqli_attempt` / `command_injection_attempt` / `nosql_injection_attempt` prove a structured **attempt**. An app that parameterises is still safe; only the response-side oracles prove exploitation |
| merging `jwt` with `jwt_forgeable`, or the live SAML classes with `saml_structural_forgery` | Live **acceptance** and offline **forgeability** are different proofs of different strength, kept as separate classes with deliberately non-overlapping alias sets so a finding cannot be re-routed to the weaker one |
| merging `iam_privilege_escalation` with `iam_escalation_primitive` | The first is **reachability** (a path exists). The second is an **achieved strict gain** proven by differencing two closures. Different claims, deliberately non-aliased |
| merging the two Kubernetes RBAC tiers | TIER-1 (`k8s_workload_misconfiguration`) only **name-matches** a built-in role. TIER-2 (`k8s_rbac_privilege_grant`) **parses the role's actual rules**. TIER-2 is the stronger claim |
| "38 oracles run on every scan" | The **15** frozen fallback kinds are what an *unknown* class may run. The other 23 fire only when a class-specific evidence key is present — which no ordinary web scan produces |
| "the veracity firewall checks every claim in production" | Its own docstring says it is the caller-less **primitive**; runtime wiring is phased. It is not today a universal live choke point (§5.4) |
| "live-fire proven" for the cloud/K8s exploitation chains | They are **built, wired end to end and fixture-proven offline**. Pointing them at a live third-party account waits on customer credentials, by design (§8.1) |
| "E2 needs live fire" | E2 deliberately never executes the escalation. Saying it awaits live fire misrepresents a design decision as a gap (§8.1) |
