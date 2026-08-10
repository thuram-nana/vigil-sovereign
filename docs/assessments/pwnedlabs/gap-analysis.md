# VIGIL cloud-capability gap analysis (AWS / GCP / Kubernetes)

> Source of truth: [`technique-catalogue.json`](./technique-catalogue.json) — 120 techniques (AWS 56,
> GCP 35, K8s 29; 97 exploitation-class, 23 posture-class) built from the Pwned Labs public catalogue +
> the public cloud-attack taxonomy (MITRE ATT&CK Cloud/Containers, HackTricks Cloud, Rhino IAM-privesc,
> PACU, CIS). Every "VIGIL detects X" below is tied to the EXACT firing predicate in the oracle source
> (`engine/crucible/framework/v2/verify/oracles.py`), not a docstring — and was independently red-penned
> against that source. The DETECTS / PARTIAL / MISSES buckets are VIGIL's own categorization; another rubric
> could re-bucket them.

## What VIGIL actually detects today (the honest capability floor)

VIGIL's cloud verdicts come from five deterministic oracle seams. Each CONFIRMS a fact by re-deriving it over
retained evidence; none performs a live exploitation action. Exact firing predicates (from source):

| Capability (oracle) | Fires ONLY when… | Evidence surface |
|---|---|---|
| `cloud_posture` (`cloud_posture_oracle`, oracles.py:2381) | a resource's retained achieved state is **`public is True`**, OR **`encrypted is False ∧ sensitive is True`** (both via `_cloud_tri_bool` — absent/unknown never fires), OR a **literal wildcard/anonymous principal** (`AllUsers`/`AuthenticatedUsers`/`*`/`arn:aws:iam::*:root`, `_CLOUD_ANON_PRINCIPALS`) appears in `principals`/`grants[].principal` | ingested native inventory (Track A) or a **VIGIL-owned live capture** (Track B) |
| `policy_path` (`policy_path_oracle`, oracles.py:1940) | a **concrete IAM grant PATH** exists (principal → resource via `assume`/`member_of` closure + a dominating grant) over the **static** retained policy graph — pure BFS, provider-agnostic, no probe | retained policy export / graph |
| `iac_posture` (iac_posture.py) | an IaC resource is public-ACL (`public-read`/`-write`), or explicit-encryption-off + sensitive, or grants a wildcard principal — **driving all three `cloud_posture` rules AND `policy_path`** over a tfstate/CFN template | IaC artifact |
| `k8s_posture` (oracles.py:2127) | a kube-bench control has `status=="FAIL"` **AND** its retained `actual_value` literally matches one of **8** flags: `--anonymous-auth=true`, authz-mode `AlwaysAllow`, non-zero `--insecure-port`, non-zero kubelet `--read-only-port`, `--basic-auth-file`, `--token-auth-file`, etcd `--client-cert-auth=false`, `--profiling=true` | kube-bench report (a third-party assertion → LEAD unless VIGIL-captured) |
| `k8s_workload_posture` (oracles.py:2271) | an **anonymous** subject (`system:anonymous`/`system:unauthenticated`) is bound to a **dangerous built-in** role (`cluster-admin`/`admin`/`edit`) — exact typed subjects | RBAC manifest |

**The through-line:** VIGIL proves **static, achieved-state POSTURE** and **static grant PATHS**. It does not
perform, or oracle-confirm, any **exploitation chain** — the live action that turns a dangerous configuration
into a proven compromise (retrieve the credential, mint the token, escape the container, read the secret).
This is by design (prove-don't-guess over retained evidence), and it is the gap this program closes.

**What VIGIL does not YET detect** — stated as NAMED BUILD TARGETS, not abandoned capabilities (per
[`docs/CLAIM-DISCIPLINE.md`](../../CLAIM-DISCIPLINE.md): "the claim stands and the engineering comes up to
meet it"). These are the CSPM-breadth gaps VIGIL commits to closing (the P-targets below), not a lowered
scope: K8s secret-encryption-at-rest and CIS controls outside the 8 flags above; over-permissive RBAC to a
**named** identity / anonymous binding to a non-dangerous role; named cross-account resource principals;
IMDSv1-enabled, public snapshot-share attributes, CloudTrail gaps, GKE legacy metadata. None is asserted as a
present-tense capability (that would be a false FACT — rule 0); each is a target with named `blocking_work`.

## Posture-detection build targets (P1–P4) — raising the system, not lowering the claim

The red-pen of this document found four places the DRAFT credited VIGIL with a detection its oracle does not
yet make. Per CLAIM-DISCIPLINE, the fix is not to delete the capability but to name the build work that makes
it a sound FACT. Each target states WHY it is not a present-tense FACT (so it is not force-built unsoundly) and
the concrete engineering that closes it:

- **P1 — K8s secret-encryption-at-rest.** Target: fire on a kube-bench control (CIS 1.2.x) whose retained
  `actual_value` shows encryption is the no-op `identity` provider (POSITIVE evidence), promoting the LEAD to
  a FACT. **Why not today:** the existing `k8s_posture` rules all match a *dangerous flag present with a bad
  value*; encryption-off is often an *absence* of `--encryption-provider-config`, and proving absence from a
  possibly-truncated `actual_value` is unsound (a false FACT). **blocking_work:** capture a real kube-bench
  report to pin the `actual_value` format, then add a rule that fires only on the positive `identity`-provider
  signal (+ a mandatory negative control that a real `aescbc`/`kms` config does NOT fire); absence stays LEAD.
- **P2 — broader CIS coverage.** Target: extend `_INSECURE_SETTING_RULES` beyond the 8 control-plane/kubelet/
  etcd flags to the other soundly-parseable CIS controls (audit-log flags, admission plugins, service-account
  lookup). **Why not today:** many CIS controls are not oracle-confirmable from a single flag value; each
  needs a positive-evidence pattern + negative control. **blocking_work:** per-control rules, each with a
  kube-bench fixture and a mutation-verified negative control; the claim is scoped to the implemented set
  (never "any CIS control") and the set grows.
- **P3 — over-permissive RBAC to a named subject.** Target: fire when a low-trust *named* identity is bound to
  a dangerous built-in role. **Why not today:** a named ServiceAccount/user with `admin`/`cluster-admin` may
  be *intended* (a cluster operator), so firing on all of them mints false FACTs. **blocking_work:** a trust
  model of which subjects legitimately hold which roles (e.g. an allow-list of operator principals from the
  charter), so the oracle fires only on an *unexpected* over-permissive binding — sound, near-zero-FP.
- **P4 — named cross-account resource principal.** Target: fire when a resource policy grants a *named*
  principal in a DIFFERENT account. **Why not today:** `cloud_posture` only fires on literal wildcard/anon
  principals; distinguishing an intended same-account grant from a cross-account one needs the engagement's
  own-account set, which the oracle is not given. **blocking_work:** thread the charter's authorized
  account id(s) into the capture context so the oracle can compare a named principal's account to the owner's.

These P-targets are the CSPM-breadth ladder; the E1–E5 waves below are the exploitation-chain ladder. Both are
"the engineering comes up to meet the claim."

## The gap, by the numbers (recomputed from the catalogue)

- **23 posture-class techniques** — VIGIL DETECTS the ones whose primitive maps to a firing predicate above
  (public buckets, wildcard/anon resource policies, encryption-off-on-sensitive, the 8 K8s control-plane
  flags, anon→dangerous-role RBAC, IaC public/encryption/wildcard). Posture-class techniques whose precursor
  the narrow oracles don't model (IMDSv1-enabled, public-snapshot-share, CloudTrail gaps, GKE legacy
  metadata) are **MISSES** even though they are "posture."
- **97 exploitation-class techniques** — VIGIL oracle-confirms the achieved exploit in **none** of them. For a
  subset it flags the **posture precursor** (PARTIAL): the dangerous IAM grant behind a privesc method
  (`policy_path`, provider-agnostic — covers AWS PACU *and* GCP grant/actAs privesc), the public/wildcard
  resource behind an exfil (`cloud_posture`), the anon→dangerous-role binding behind an anonymous-API abuse
  (`k8s_workload_posture`). But "a dangerous grant exists" is a LEAD-grade posture signal, not proof the
  escalation is exploitable — which is what an enterprise assessment (and Pwned Labs) grades.
- **25 exploitation techniques have empty `detectable_by`** (no third-party scanner in the catalogue). Of
  these, **~14 are genuinely precursor-free** — invisible to any static scanner, VIGIL included, and provable
  only by a live achieved-effect oracle (runtime metadata/SSRF cred theft, XXE/path-traversal→creds, CI-server
  pivot, orphaned-bucket takeover, brute-force/enum, `testIamPermissions`, KMS ransomware). The other **~11
  are GCP privesc-via-grant / actAs** (`gcp-iam-roles-update`, `-deploymentmanager-create`,
  `-cloudbuild-create`, `-cloudfunctions-*`, `-cloudrun-deploy-actas`, `-compute-*`, `-cloudscheduler-*`,
  `-oslogin-*`, `-sa-implicit-delegation`): no third-party scanner, but a **VIGIL static `policy_path`
  precursor** exists → PARTIAL, the same treatment as AWS PACU privesc.

## DETECTS / PARTIAL / MISSES by category

| Category (representative techniques) | VIGIL today | Why |
|---|---|---|
| Public object store (S3/GCS public read/write) | **DETECTS** | `cloud_posture` `public is True` / anon-principal grant |
| Wildcard-principal resource policy (`Principal:*` on bucket/KMS/role-trust) | **DETECTS wildcard/anon** | `cloud_posture` `_CLOUD_ANON_PRINCIPALS`; a **named** cross-account principal → build **P4** (only `policy_path` covers it today) |
| Encryption-at-rest off on a sensitive datastore | **DETECTS** | `cloud_posture` `encrypted is False ∧ sensitive is True` |
| Anonymous K8s RBAC binding to a dangerous built-in role | **DETECTS** | `k8s_workload_posture` anon→`{cluster-admin,admin,edit}` (named-identity over-permissive binding → build **P3**) |
| K8s control-plane/kubelet/etcd flags (the 8 in the table) | **DETECTS (LEAD/FACT if VIGIL-captured)** | `k8s_posture` (kube-bench); secret-encryption → build **P1**, broader CIS → build **P2** |
| IaC public / encryption-off-sensitive / wildcard-principal / anon grant-path | **DETECTS** | `iac_posture` → `cloud_posture` + `policy_path` |
| IAM privilege-escalation methods (AWS PACU + GCP grant/actAs) | **PARTIAL → build E2/E3** | `policy_path` sees the *grant*, never confirms the *escalation is exploitable* |
| GCP SA impersonation / token/JWT minting (getAccessToken/signJwt/signBlob/keys.create) | **MISSES → build E3** | no token-minting oracle; a grant may show in `policy_path` but the achieved token is never confirmed |
| K8s RBAC exploitation (token mint, privileged/hostPath pod, exec, escape) | **PARTIAL/MISSES → build E4** | posture flags a narrow binding; the *achieved* cluster/node access is never confirmed |
| SSRF/RCE → IMDS/metadata credential theft (AWS/GCP/ECS/EKS) | **MISSES → build E1** | runtime; no static precursor for most; the *retrieved, usable* credential is the fact |
| Exposed / leaked secret validated as usable (keys in git/images, SSM/SecretsManager/Secret Manager) | **MISSES → build E5** | VIGIL never confirms a discovered credential actually authenticates |
| Snapshot/RDS/EBS public-share looting, KMS ransomware, CloudTrail tamper | **MISSES → deprioritized target** | impact/persistence-class; named + ranked-low in the build ladder, not abandoned |

## Build prioritization → the E1–E5 waves

Ranked primarily by **build-feasibility** (how cleanly a VIGIL-owned oracle can CONFIRM the achieved effect
over gated live evidence) and severity; prevalence is a secondary, judgement-based input (privesc is the
single largest primitive at 61/120, which favours E2/E3):

1. **E1 — SSRF/foothold → IMDS/metadata credential capture** (AWS `ssrf-imdsv1-cred-theft`,
   `ec2-command-injection…`, `ecs-task-metadata…`, GCP `gcp-metadata-sa-token`, `gcp-ssrf-gopher…`,
   K8s `k8s-pod-imds-node-role`). **Feasibility-led first**: the achieved effect — "role/SA credentials
   actually retrieved and usable" — is the most cleanly oracle-confirmable, and ~14 of these have no static
   precursor at all, so they are pure MISSES today.
2. **E2 — IAM privilege-escalation PATH proven exploitable** (the ~20 AWS PACU methods + GCP
   setIamPolicy/roles.update). Highest-prevalence primitive (privesc). Extends `policy_path` from "a grant
   path exists" to "this specific escalation edge was exercised and elevated the identity."
3. **E3 — GCP service-account impersonation / token forgery** (getAccessToken/getOpenIdToken/signJwt/signBlob/
   implicitDelegation/keys.create + the ~11 GCP actAs privesc). The minted token performs an action the caller
   could not; the oracle confirms the elevated action succeeded.
4. **E4 — K8s RBAC exploitation** (TokenRequest mint, privileged/hostPath pod create → node read, pods/exec
   token theft, impersonate). Extends `k8s_workload_posture` to a confirmed achieved cluster/node effect.
5. **E5 — exposed-secret validation & exfil-path** (leaked keys/SA-JSON/SecretsManager/SSM). The discovered
   secret is proven to authenticate (structural + confirming call) — never abused beyond confirmation.

Each E-wave adds a deterministic **achieved-effect oracle** + a `fact_capable:true` evidence branch +
admission routing + D2 binding + an attack-path edge, is **WARDEN-A2-gated + kill-switch**, scoped to the
authorized lab, carries NO evasion, and is independently red-penned. Its offensive-capability scope is
confirmed with the operator before the wave lands. The remaining catalogue misses (snapshot looting, KMS
ransomware, CloudTrail tampering — impact/persistence-class) are logged here as known, deprioritized gaps,
not silently dropped.

## Honesty caveats (anti-overclaim)

- "DETECTS" means a VIGIL oracle FIRES on the primitive's achieved state — not that VIGIL matches a full
  CSPM's breadth. Several posture-class techniques prowler/scout-suite catch are VIGIL MISSES (listed above).
- `k8s_posture` consumes a **kube-bench** report; that is a third-party assertion (subject = `kube_bench_report`,
  → LEAD) unless the report is a VIGIL-owned capture, and it fires only on the 8 flags — not any failing CIS
  control, and not secret-encryption-at-rest.
- `policy_path` proves a grant PATH exists over a **static** graph; it does not prove the identity can
  *exercise* an escalation — so IAM privesc is PARTIAL, never a confirmed-exploit FACT, until E2/E3.
- The DETECTS / PARTIAL / MISSES mapping is VIGIL's own categorization against this catalogue; a different
  rubric (e.g. a compliance framework) could re-bucket individual rows.
- Prevalence is a reasoned blend of Pwned-Labs-set frequency and real-cloud frequency, not a measured
  statistic; E1's first rank is feasibility-led, not prevalence-led.
- Per [`docs/CLAIM-DISCIPLINE.md`](../../CLAIM-DISCIPLINE.md), every "MISSES" here is a **named build target**
  (P1–P4 posture-detection, E1–E5 exploitation, or an explicitly deprioritized target) — the claim/target
  stands and the engineering comes up to meet it. No capability is abandoned by wording a detection down; and
  no gap is asserted as a present-tense FACT (that would be a false FACT — rule 0). Where a sound present-tense
  build is not yet possible, the gap is stated as the target plus its `blocking_work`, never as silent absence.
