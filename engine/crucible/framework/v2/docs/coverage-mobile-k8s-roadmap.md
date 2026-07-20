# Coverage roadmap — the Mobile and Kubernetes-runtime mega-domains

*Workstream C design note. Status: first slice shipped (kube-bench LEAD ingest); the rest is roadmap.*

CRUCIBLE is a reasoning OS: every external tool is a **gated sensor** whose output enters the ONE
world-model as a provenance-tagged **observation — a LEAD (`GROUNDING_INTEL`), never a fact**. A LEAD
becomes a FACT only when a deterministic **oracle re-verifies** it. This note maps two large uncovered
surfaces onto that spine and ships the first, safest slice of one of them.

The canonical exemplar we mirror is **SBOM/SCA** (`sensors/sbom.py` +
`verify/version.py::confirm_vulnerable_dependency`): grype/osv-scanner says "package X @ V is affected by
CVE-Y" (a third-party LEAD); the version-range oracle promotes it to a FACT **only** when it proves V
falls inside the advisory's affected range, fail-closed. Sensor mints the lead; oracle proves the fact.
Both halves are pure, offline, and JSON-safe so a confirmed finding re-verifies from its certificate.

---

## 1. Why these are *mega-domains*

**Kubernetes-runtime.** A modern target is rarely one host; it is a cluster whose real attack surface is
its *runtime posture* — API-server flags, kubelet auth, RBAC bindings, admission control, PodSecurity,
secrets-at-rest, network policy, workload capabilities. This is orthogonal to the container *image*
supply-chain (already covered by the SBOM sensor). It spans control-plane, worker-node, etcd, and policy
layers, each with dozens of CIS controls — a whole coverage domain, not a single check. The framework's
own coverage doctrine already lists `14-container-kubernetes.md` as a first-class surface.

**Mobile.** An Android/iOS app is a self-contained attack surface the network scanners never see:
manifest-declared permissions and exported components, ATS/cleartext-traffic policy, certificate
pinning, hard-coded secrets, insecure local storage, deep-link/intent handling, WebView bridges, and the
back-end APIs the binary talks to. It is a distinct mega-domain (`17-mobile.md`) with its own tools
(MobSF, apktool, jadx, class-dump) and its own evidence shapes (APK/IPA manifests, static-analysis JSON).

Both are **broad** (many checks, many layers) and **evidence-rich** (mature third-party tools emit
structured JSON). That is exactly the shape the sensor→oracle spine was built for.

---

## 2. What shipped (first slice) — kube-bench LEAD ingest

`sensors/k8s_runtime.py :: KubeBenchSensor` — a method-for-method mirror of `SbomVulnSensor`:

- **`parse_kube_bench(text) -> list[dict]`** — pure/total parser for kube-bench `--json`. Handles BOTH
  top-level shapes: the object `{"Controls":[{"tests":[{"results":[…]}]}]}` and the newer LIST
  `[{"Controls":[…]}, …]` (master/node/etcd/policies concatenated). Returns only **FAIL/WARN** controls
  as `{check_id, description, status, section?, remediation?}` (PASS/INFO dropped). Invalid JSON / unknown
  shape → `[]`, never a crash.
- **`kube_bench_observations(controls, *, seq, source)`** — mints one **LEAD** per failed/warned control:
  subject = `NodeKind.CONTROL` keyed `cis-k8s:<check_id>` (a failed CIS control *is* a missing/misconfigured
  defensive control — the faithful existing node kind, no new enum member); `source_kind =
  IntelSourceKind.CLOUD_POSTURE` (the closest existing kind — a posture/misconfig export, reused rather
  than adding an enum member); reliability **Admiralty B2** (reliable tool, a claim not a proof);
  confidence **< 1.0**, status-derived (FAIL 0.85 > WARN 0.6). The control's evidence rides in `attrs`
  (status/section/remediation/benchmark) so a future oracle can re-derive the weakness — exactly as
  `sca_observations` carries advisory evidence for the version-range oracle.
- **Determinism / doctrine:** `obs_id` IS the `(source, seq, subject-claim)` key — no positional index,
  no wallclock, no rng — so re-ingest, reorder, and an intra-batch duplicate check_id all collapse to one
  observation (belief never inflates). Tier-1, `capability=None`, `destructive=False`, `egress_hosts=()`:
  reads a local operator-supplied file only. No network, no cluster egress, no device control. Still
  kill-switch-gated via `run_sensor`. Registered additively in `register_builtin_sensors`.

**This slice STOPS at LEADs.** No oracle is created and nothing is confirmed. A kube-bench FAIL enters the
world-model as `GROUNDING_INTEL`, queryable and rankable, but explicitly *not* oracle-proof.

---

## 3. The LEAD→FACT gap — the oracles this roadmap defers

### 3.1 A future k8s-posture oracle (`verify.k8s_posture`)

Mirrors `verify.version` exactly. Input: the JSON-safe control evidence a `KubeBenchSensor` lead carries
(check_id, benchmark, status, and — the key addition — the *observed configuration value* the operator
attaches). Proof obligation, fail-closed and pure:

- Re-evaluate the CIS rule deterministically over the observed value. E.g. control 1.2.1 ("`--anonymous-auth`
  must be false"): the fact is confirmed **only** if the observed API-server flag string provably parses
  to `--anonymous-auth=true` (or the flag is absent and the default is permissive). A missing/unparseable
  value does NOT confirm — the finding stays a lead, exactly like an unparseable version range.
- RBAC controls: re-derive over the retained IAM/policy graph (the same substrate the cloud
  `policy_path` oracle already walks) — a dangerous binding is a FACT only when a subject→verb→resource
  path is re-computed, never on kube-bench's say-so.

The evidence stays JSON-safe so a confirmed control re-verifies offline from its certificate
(`verify.reverify`), matching the SBOM/cloud oracle contract. kube-bench's FAIL is the LEAD; this oracle
is the PROOF.

### 3.2 A future mobile static-analysis sensor + oracle (`sensors.mobile` + `verify.mobile`)

- **`MobsfSensor` + `parse_mobsf(text)`** (offline MobSF JSON ingest) — deliberately **deferred**, not
  half-built, to keep this slice clean. It would mirror `SbomVulnSensor`: MobSF's findings (exported
  component, cleartext traffic allowed, no cert pinning, hard-coded secret regex hit) are third-party
  LEADS. Subject kinds reuse `APPLICATION` for the app and `ENDPOINT`/`SERVICE` for the back-end URLs the
  binary embeds.
- **An APK/IPA manifest parser** — pure/offline parse of `AndroidManifest.xml` (exported activities/
  services/receivers/providers, `permission`, `usesCleartextTraffic`, `networkSecurityConfig`,
  `debuggable`) and the iOS `Info.plist` (`NSAppTransportSecurity`/`NSAllowsArbitraryLoads`, URL schemes,
  ATS exceptions). These mint *first-party* LEADS (like the manifest itself, not a scanner's heuristic).
- **`verify.mobile` oracle** — promotes leads to facts deterministically: an *exported, unprotected*
  component is a FACT only when the manifest provably declares `exported="true"` with no `permission`
  guard; a *cleartext-traffic* fact only when ATS/`usesCleartextTraffic` provably permits it for a domain
  the binary actually contacts; a *pinning-absent* fact only when no pin set is present for that domain.
  A `certificate` cross-check (the pinned leaf vs. the live cert) reuses the existing `NodeKind.CERTIFICATE`
  substrate and the TLS oracle. Fail-closed: an ambiguous manifest stays a lead.

---

## 4. Scope and doctrine boundaries (non-negotiable)

- **Offline only.** Every sensor here ingests an operator-supplied local report/artifact (kube-bench JSON,
  MobSF JSON, an APK/IPA the operator provides). Tier-1, no egress, no entitlement.
- **No device or cluster control.** CRUCIBLE never drives `kubectl`, never talks to the API server, never
  installs an agent, never touches a device/emulator. Collection of the report is the operator's job
  (their `kube-bench`/`MobSF` run, under their charter); CRUCIBLE reasons over the artifact.
- **A live/gated k8s collector is a separate, later, opt-in slice** (Tier-2, egress-allowlisted, charter-
  scoped) — the exact shape of `CloudInventoryPullSensor` vs. `CloudPostureImportSensor`. It is out of
  scope for this workstream and only ever runs behind the same fail-closed gate chain.
- **LEAD-only here.** Sensors mint observations; oracles (deferred) mint facts. No sensor writes a Finding.

---

## 5. Next slices (in order)

1. **`verify.k8s_posture` oracle** — the highest-value follow-up: turns the kube-bench LEADs this slice
   already produces into FACTS (mirrors `verify.version`). Requires the operator to attach observed config
   values to the report ingest.
2. **`MobsfSensor` + `parse_mobsf`** — offline MobSF JSON → mobile LEADS (mirrors `SbomVulnSensor`).
3. **APK/IPA manifest parser** — pure/offline first-party manifest LEADS (exported components, ATS,
   pinning, permissions).
4. **`verify.mobile` oracle** — promotes the manifest/MobSF leads to facts, fail-closed.
5. **(Later, opt-in, gated)** a live kube-posture collector — Tier-2, egress-allowlisted, charter-scoped,
   the `CloudInventoryPullSensor` shape.

Each slice is additive, mirrors the SBOM sensor→oracle pattern, and preserves the invariant that a
third-party tool's say-so is a LEAD until a deterministic CRUCIBLE oracle proves the FACT.
