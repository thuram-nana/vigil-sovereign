# BUILD PLAN — closing the cloud gap end-to-end (P1–P4 posture + E1–E5 exploitation)

> Detailed, critical build plan for raising VIGIL to meet every claim the [gap analysis](./gap-analysis.md)
> names as a target. Governed by [`docs/CLAIM-DISCIPLINE.md`](../../CLAIM-DISCIPLINE.md) (raise the system,
> never downgrade the claim) and the CRUCIBLE constitution (oracle-confirmed FACTs, WARDEN-gated offense,
> no evasion, charter-scoped). Nothing here is asserted as done; each capability is built, gate-marshalled,
> and independently red-penned before it lands, and the truly irreducible is honestly marked.

## The build unit (every capability follows this)

Each of the 9 capabilities is one wave built to the SAME standard as Phase B — no shortcuts:

1. **Oracle** — a pure, deterministic function that CONFIRMS a fact by re-deriving it over RETAINED evidence
   (never trusting a scanner/LLM say-so). It fires ONLY on positive evidence of the insecure/achieved state;
   an absent/unknown/truncated signal stays a LEAD (near-zero-FP by construction). *(agent: oracle-smith)*
2. **Mandatory negative control** — a benign input the oracle must NOT fire on, mutation-verified. *(prover)*
3. **Evidence branch** — a row in `docs/capability-matrix/evidence-branches.json` with `fact_capable`,
   `clean_capable` (a partial/live capture is never CLEAN-capable), `preconditions`, `limitation`,
   `implementation_refs`, and — for anything not yet fully true — `target_*` + `blocking_work`. *(oracle-smith)*
4. **Admission routing** — the verdict flows through `verdict.admit()` → `certify_admitted`; a fired oracle
   over a `fact_capable` branch mints a signed FACT, else a labelled LEAD; non-fire → INCONCLUSIVE never CLEAN.
5. **D2 binding + signed cert** — the achieved-effect evidence sha256, capture method, scope, completeness,
   `artifact_recheck_required`, bound into an Ed25519 m-of-n signed certificate that re-verifies OFFLINE
   (the keyless-forgery-hardened verifier). *(crypto-notary)*
6. **Attack-path edge** — the achieved effect becomes a node/edge in the world-model so chains compose
   (E1 IMDS-cred → E2 privesc → E5 secret-exfil). *(graph-keeper)*
7. **Veracity-firewall admission** — the FACT re-executes its retained context; the firewall can only demote.
   *(veracity-ward)*
8. **Fixtures + tests** — fixture-first (a captured/synth-from-real-format evidence stands in), so the wave
   is complete offline; live-fire is a separate, gated proof. *(prover)*
9. **Gate-marshal** — for the E-waves (offense), audit the diff for offensive-capability drift beyond the
   authorized, oracle-confirmed primitive; confirm WARDEN-A2 gating + kill-switch on the runner. *(gate-marshal)*
10. **Independent red-pen** — adversarially try to mint a false FACT / miss a real one / bypass the gate,
    BEFORE merge, and re-attack the fix. *(red-pen)*
11. **FATAL-2** — framework imports function-local; verify in `.venv-sovereign`. **make gate** byte-identical.

The **runner** (the live action: reach IMDS, mint a token, create a pod) is WARDEN-A2-gated + kill-switch +
scoped to the authorized lab, correlatable, NO evasion. The **oracle** judges retained evidence and is built +
red-penned first; the runner is proven live only against an authorized lab (needs valid creds — currently
blocked, see §Live-fire).

---

## P-waves — posture-detection targets (defensive; buildable without a lab)

### P1 — K8s secret-encryption-at-rest
- **Oracle:** extend `k8s_posture` — fire on a kube-bench control (CIS 1.2.x) whose retained `actual_value`
  shows the encryption provider is the no-op `identity` (POSITIVE evidence of plaintext), or an
  EncryptionConfiguration whose first provider is `identity`.
- **Soundness constraint (critical):** encryption-off is often an *absence* of `--encryption-provider-config`;
  proving absence from a possibly-truncated `actual_value` is UNSOUND (false FACT). So P1 fires ONLY on the
  positive `identity`-provider signal; absence stays a LEAD. **blocking_work:** a REAL kube-bench report to
  pin the `actual_value` format (rule 4 — no hand-approximation) + a negative control that a real
  `aescbc`/`kms` config does not fire. Source the format from the kube-bench CIS master config (open source).

### P2 — broader CIS coverage
- **Oracle:** add per-control rules to `_INSECURE_SETTING_RULES` for other soundly-parseable CIS controls
  (audit-log path/maxage/maxbackup, `--service-account-lookup=false`, admission plugins
  `AlwaysAdmit`/missing `NodeRestriction`, `--kubelet-certificate-authority` unset shown positively).
- **Soundness:** each rule is positive-evidence + a mutation-verified negative control + a real kube-bench
  fixture. The claim is scoped to the IMPLEMENTED control set (never "any CIS control") and grows.

### P3 — over-permissive RBAC to a named subject
- **Oracle:** extend `k8s_workload_posture` — fire when a low-trust NAMED identity is bound to a dangerous
  built-in role (`cluster-admin`/`admin`/`edit`).
- **Soundness constraint:** a named SA/user with `admin` may be INTENDED, so firing on all mints false FACTs.
  **blocking_work:** a charter-supplied allow-list of legitimate operator principals; the oracle fires only on
  an UNEXPECTED over-permissive binding (subject ∉ allow-list). Sound, near-zero-FP.

### P4 — named cross-account resource principal
- **Oracle:** extend `cloud_posture` — fire when a resource policy grants a NAMED principal in a DIFFERENT
  account than the owner.
- **Soundness constraint:** distinguishing an intended same-account grant from cross-account needs the
  engagement's own-account id(s). **blocking_work:** thread the charter's authorized account id(s) into the
  capture context so the oracle compares a named principal's account to the owner's.

---

## E-waves — exploitation-chain oracles (offense; runner gated; oracle fixture-first)

### E1 — SSRF/foothold → IMDS/metadata credential capture  *(flagship, first)*
- **Achieved effect the oracle CONFIRMS:** role/SA credentials were actually retrieved from the metadata
  endpoint AND are usable — i.e. the retained evidence carries a well-formed credential (AWS
  `AccessKeyId`+`SecretAccessKey`+`Token` from `169.254.169.254/latest/meta-data/iam/security-credentials/…`,
  or a GCP `access_token` from `computeMetadata/v1/.../token`) AND a confirming call (e.g. `sts:GetCallerIdentity`
  / a `tokeninfo` / a scoped list) succeeded with it.
- **Oracle predicate (positive-only):** fire iff the retained capture contains a structurally-valid credential
  from the metadata endpoint AND a retained confirming-call response proves it authenticated (identity echoed).
  A retrieved-but-unconfirmed credential is a LEAD; a 401/timeout is INCONCLUSIVE.
- **Runner (gated):** a WARDEN-A2-gated request to the metadata IP from the authorized foothold; the confirming
  call uses the captured credential read-only (GetCallerIdentity / whoami) — never a mutating/abusive action.
- **evidence branch:** `cloud_exploit.imds.credential_capture` (fact_capable:true, clean_capable:false).

### E2 — IAM privilege-escalation PATH proven exploitable
- **Achieved effect:** a specific escalation edge was EXERCISED and elevated the identity (e.g. `iam:PassRole`
  +`RunInstances` yielded instance-role creds; `CreatePolicyVersion --set-as-default` granted `*:*`; a GCP
  `setIamPolicy` self-grant took effect) — confirmed by a retained before/after permission delta.
- **Oracle:** extends `policy_path` from "a grant path exists" to "the identity now holds a permission it did
  not before, via the exercised edge," proven over retained enumerations (before) + the confirming call (after).
- **Soundness:** the escalation must be REVERSIBLE / non-destructive in the lab; the oracle confirms the delta,
  the runner performs the minimal confirming action, and cleans up (records the created artifact for teardown).

### E3 — GCP service-account impersonation / token forgery
- **Achieved effect:** a token minted for a target SA (getAccessToken / signJwt→exchange / signBlob) was used
  to perform an action the caller could not — confirmed by the elevated action's retained success response.
- **Oracle:** `cloud_exploit.gcp.sa_impersonation` — fire iff a retained minted-token + a retained
  elevated-call success (that the caller's own identity is proven unable to make) are both present.

### E4 — Kubernetes RBAC exploitation
- **Achieved effect:** a TokenRequest-minted SA token / a created privileged/hostPath pod / a `pods/exec` was
  used to obtain real cluster/node access — confirmed by e.g. reading a node-only file or a cross-namespace
  secret the original identity could not.
- **Oracle:** extends `k8s_workload_posture` to a confirmed achieved effect (`cloud_exploit.k8s.rbac_exploited`).
- **Runner:** creates only a benign confirming pod (read a marker), records it for teardown; NO persistence.

### E5 — exposed-secret validation & exfil-path
- **Achieved effect:** a discovered secret (leaked key / SA JSON / SecretsManager value) actually
  authenticates — confirmed by a read-only confirming call — NEVER abused beyond confirmation.
- **Oracle:** `cloud_exploit.secret.credential_validity` — fire iff a retained confirming-call success proves
  the secret is live; the secret itself is redacted in evidence (minimum needed to prove impact).

---

## Orchestration — specialized agents per capability

Each wave is driven by the CRUCIBLE/AEGIS specialized agents in sequence, one wave at a time so the human stays
in the loop and each lands independently:

`oracle-smith` (oracle + negative control) → `prover` (tests + corpus + fixtures) → `graph-keeper` (attack-path
edge) → `crypto-notary` (signed evidence cert) → `veracity-ward` (firewall admission) → `report-wright`
(SARIF/JSON export + standards mapping) → `gate-marshal` (offense-drift audit, E-waves) → `red-pen` (adversarial
pre-merge) → orchestrator integrates + `make gate` + FATAL-2 + merge on a clean verdict.

P-waves and E-waves proceed in parallel tracks (P is defensive, no offense gate); within each track the waves
are sequential (each builds on the prior, and the merge gate is serial to keep `main` always-green).

## Sequencing & checkpoints

1. **Now (no creds):** build P1→P4 and E1→E5 oracles FIXTURE-FIRST, each fully (oracle + branch + admission +
   D2 + attack-path + tests + gate-marshal + red-pen), landing wave by wave. E-wave runners are built + unit-
   tested but their live action stays WARDEN-gated and unproven-live.
2. **Per E-wave checkpoint:** confirm the offensive-capability scope with the operator before that wave lands.
3. **Live-fire (needs valid creds):** once a Pwned Labs lab is provisioned and its cloud credentials configured
   as ambient (AWS env / GCP ADC / kubeconfig) with a `## 2b. Cloud scope` charter + `collector-hosts.txt`,
   each wave is proven live against the authorized lab and its FACTs re-verified offline (L3).

## Live-fire blocker (honest status)

The Pwned Labs account credentials provided return **HTTP 422 "credentials do not match"** on a clean login
(the login mechanism itself is solved — Laravel Sanctum, `POST /api/v1/auth/login`, no CAPTCHA). Live-fire
("firing") cannot proceed until a working credential is supplied and a lab is started (which mints the per-lab
cloud credentials the read-only collectors need). All oracle/branch/test build work above is unblocked and
proceeds fixture-first meanwhile.
