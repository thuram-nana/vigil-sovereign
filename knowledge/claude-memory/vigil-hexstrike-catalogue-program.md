---
name: vigil-hexstrike-catalogue-program
description: "VIGIL program to integrate the HexStrike tool catalogue under a 12-point verification standard — substrate hardening (Phase 0) then FACT-capable oracle families (Phase 1); + the operator's certify.py review"
metadata: 
  node_type: memory
  type: project
  originSessionId: 7758e121-f349-47d5-886b-6bb5a1d60e27
  modified: 2026-08-10T12:13:42.745Z
---

VIGIL (repo thuram-nana/vigil-sovereign, @ /home/kali/vigil). APPROVED plan (plan file
`parsed-popping-lemur.md`): make the vendored hexstrike-ai catalogue *fully compatible* with VIGIL's
verification architecture, where "integrated" means a **12-point standard** (reproducible isolated install ·
documented version/license/deps/privs · invoked only via the gated runner · normalized observation schema ·
explicit claim types · **an independent VIGIL-owned oracle re-derives each FACT without trusting the tool** ·
distinct positive/clean/inconclusive/error/skipped/unsupported outcomes · retained re-verify evidence · a FACT
carrying scope/target/timestamps/tool-version/evidence-hashes/predicate/freshness/signature · pos+neg+deceptive+
malformed+failure tests · no bypass of charter/scope/approval/rate-limits/egress/killswitch · docs+tests).
Install/wrapping/a green run is explicitly NOT integration.

**HONEST DENOMINATOR (research):** upstream = **79 distinct external tools** (90 routes − 7 in-house − aliases),
NOT the README's "150+". 17 MUST-EXCLUDE (12 exploitation + 5 credential-access), already unproposable by the
brain. **The load-bearing principle** (proven by a red-pen BLOCK on the posture re-exec tier): re-deriving a
verdict over PRODUCER-SUPPLIED retained bytes proves internal consistency, NOT reality — a FACT needs a
VIGIL-OWNED **live gated capture** (nmap→own TCP handshake, sslscan→own TLS handshake). Exemplars: nmap→
SERVICE_REACHABILITY, sslscan→weak_tls/weak_crypto_artifact.

**Operator decisions:** first wave = SBOM/VERSION_RANGE; do ALL 6 Phase-0 substrate gaps before onboarding new
tools; merge order B then A.

**MERGED so far (each: build → INDEPENDENT red-pen → fix → CI green → squash-merge; the red-pen caught a REAL
defect on MULTIPLE slices):**
- #241 posture **re-executable tier** (open_redirect predicate_oracle, not SQLi — empirically SQLi never
  reaches CLOSED). RE-red-pen BLOCKED the first fix: "producer-independent" overclaim survived in ~10 places +
  POSTURE.md falsely claimed embedding raw bytes/TLS-transcript + a projection crash on non-iterable
  oracle_kinds_run → all fixed, grep-verified, test-pinned.
- #242 **TLS ToolSpec** (brain-slot slice 4) — lifted `Redrive(bug_class,capture,context)` onto ToolSpec; empty
  redrives = legacy reachability (nmap unchanged). CI gotcha: a live weak-crypto test needs a **2048-bit key +
  SHA1 sig** (CI OpenSSL seclevel 2 rejects <2048-bit at handshake; `cryptography` refuses to SIGN SHA1 → mint
  via the `openssl` CLI, skip if refused).
- #243 **typed outcome taxonomy** (crit 7) — Outcome enum + AdapterResult.outcome; confirm_and_certify runs
  adjudicate_finding+confirmed_from_result (== confirm_finding, behaviour-preserving) to classify CLEAN vs
  INCONCLUSIVE; runner ERROR/SKIPPED. red-pen PASS.
- #244 **cert fields + evidence-verification hardening** (crit 9 + THE OPERATOR'S certify.py REVIEW): added
  tool_version + freshness_ttl (signed, dropped-when-empty → byte-identical) + time_anchor sidecar; and
  ENFORCED: `BundleVerification.head_anchored` REQUIRED in ok (unsigned-head bundle no longer passes) ·
  oracle_version_current (surfaced, NOT gated — reproducibility) · currently_fresh 3-state (authenticated
  time; authenticity survives expiry) · expected_trust_root_fingerprint pin · SUPPORTED_SCHEMA_VERSIONS ·
  render_as Literal · duplicate-finding_ref + cross-engagement refusal · manifest symlink/non-regular/
  O_NOFOLLOW. red-pen PASS (27 PoCs); LOWs (single_engagement empty-discard, producer refs_unique) tracked in
  DEFERRED-INFRA.
- #245 **runner pre-flight gate** (crit 3/11) — kill-switch + charter-slug + ACTIVE_RECON entitlement into
  run_external_tool so the TOOL SUBPROCESS is gated, not just the oracle re-drive; WARDEN A2 + m-of-n
  conjunctive stay at the body layer (FATAL-2 — offense runner can't import the sovereign gate). red-pen PASS.
- #246 **conformance battery + tool manifest + capability-matrix seed** (crit 2/10/12) —
  `live.conformance.run_toolspec_conformance` (positive→verifiable FACT / deceptive→no-fact / tool-error /
  killswitch / out-of-scope, through the REAL runner) + `live.tool_manifest` + `docs/capability-matrix/
  hexstrike.json` (fact_capable pinned to {nmap,sslscan}). red-pen BLOCKED it: `conformant` was vacuous when
  killswitch omitted + deceptive passed on a no-proposal backend → fixed with a REQUIRED_PROPERTIES set +
  `deceptive_proposed` + a known-offense-name backstop. Now green.

**PHASE 0 + PHASE 1 COMPLETE — the whole approved plan merged (9 PRs #241-#249, each red-penned):**
- #247 Phase 0.3 canonical **Observation** schema (crit 4) — one normalized record per tool run (tool
  identity+version, target, LENGTH-PREFIXED sha256 of raw output = injective, proposals, outcome_class);
  attached to RunnerResult.observation, firewalled from the fact path. red-pen LOW: null-boundary digest
  collision → length-prefixed.
- #248 Phase 0.4 **runner isolation** (crit 1/11) — DockerTopologyBackend --memory/--memory-swap/--cpus/
  --pids-limit/--user(nobody)/--read-only+tmpfs + fail-closed @sha256 digest pin (hex-validated); a
  loopback-only guard refuses LocalSubprocessBackend against a non-loopback target. Live docker run = the
  documented residual. red-pen LOW: hex-validate the pin predicate.
- #249 **Phase 1 SBOM/VERSION_RANGE** — the FIRST FACT-capable family beyond nmap/TLS, VIGIL-DIRECT (no
  tool install): `live/sbom.py` parses requirements.txt + package-lock.json (v1/v2/v3) for CONCRETE
  versions, looks each up in a PINNED vendored OSV snapshot (`docs/capability-matrix/osv-snapshot.json`),
  and the existing `version_range` oracle mints a signed, offline-re-verifiable FACT via confirm_and_certify
  (provenance="reproduced") ONLY when version_in_affected PROVES membership. A grype/trivy CVE match is a
  proposer only — the advisory merely EXISTING mints nothing (crit-6). red-pen LOW: reject comparator-string
  ranges at snapshot load (only dict {introduced,fixed}); cap lockfile recursion. `make gate` PASS (11/0/0).

**WAVE #3 (gated HTTP re-drive → ACHIEVED_STATE, the web column) — ✅ MERGED @ad2f3fc3 (PR #250).** `integration/vigil_integration/live/web_redrive.py`:
a runner-owned GATED, no-redirect HTTP capture (reuses the URL-shaped `reachability_cloud._authorize`) drives
the SHIPPED `scanner/checks.py` probes (open_redirect / cors / host_header_injection) and the existing
`predicate_oracle` mints a signed, offline-re-verifiable FACT. httpx = URL PROPOSER only; `fact_capable` stays
{nmap, sslscan} (VIGIL-direct, like SBOM). Pre-flight refusal ⇒ `refused=True` + ZERO adjudications; a probe
with NO channel ⇒ INCONCLUSIVE, never CLEAN.

**⚠️⚠️ THE ARCHITECTURAL LESSON OF WAVE #3 — DON'T HAND-APPROXIMATE A SPECIFIED ALGORITHM FOR A SECURITY
DECISION.** **45 proven defects across 11 adversarial rounds** (round 7 = the first PASS, verified against
Chromium; its 3 residuals were fixed rather than deferred). THREE separate times I hand-approximated a
*specified* algorithm — HTML tokenization, then the script-data escape states, then the declarative-refresh
steps — and each time was wrong in **BOTH directions at once**: a benign page minted a signed FALSE FACT
*and* a genuinely vulnerable page was certified CLEAN. Each converged only by implementing the real spec
steps or delegating to a real parser. Two fixes for a *performance* defect introduced *correctness* defects,
and one "hardening" change dropped a real sink — so always re-check a fix in BOTH directions.
About **15 of them lived in ONE hand-written "inert markup masker"** that answered "is this URL live markup
or inert text?" — leaking in BOTH directions (a benign page minting a signed FALSE FACT; a real vuln
silently DROPPED) plus **three separate super-linear blowups** (429s, 36s, 18s at a 512KB cap) — twice
introduced BY a fix. It never converged. **The fix was to DELETE it** (~19k chars: `_mask_inert`,
`_tag_end`, `_close_tag`, `_find_tag`, `_inert_content_end` + the structural regexes) and delegate to
**stdlib `html.parser`** (`_MarkupScan`), keeping only two documented layers the tokenizer doesn't model
(`<template>` content is an inert fragment, depth-tracked on real tokenizer events; the WHATWG script-data
double-escape). That fixed all 7 outstanding defects at once, fixed 2 backlog false-CLEAN gaps for FREE
(unquoted `href=` / `content=` — regexes had silently missed them), and cut worst-case parse to 648ms.
**Rules to carry:** (a) if a check needs to know how a browser parses, USE A REAL PARSER — a regex/find
approximation of a tokenizer over adversary-controlled bytes does not converge; (b) pair it with a
**DIFFERENTIAL TEST** against the real parser asserting BOTH directions (inert-counted = false-FACT surface;
live-masked = dropped sink) + a non-vacuous-corpus guard — it immediately caught a WRONG ASSERTION IN MY OWN
TEST (`<noembed>`/`<noframes>` are RAWTEXT per spec; only `<noscript>` is live when scripting is off);
(c) **check the suite is actually IN CI** — `framework/v2/scanner` (76 test files, incl. every predicate
regression test) was referenced ZERO times in `ci.yml`, so "CI green" never covered it.

**⚠️ THE PROCESS LESSON — EVERY ROUND FOUND A REAL DEFECT IN THE PREVIOUS ROUND'S FIX** (each caught AFTER
my inline review + full green tests + `make gate`):
R1 → false FACT on a benign HTML page (the open_redirect body branch tested "canary reflected somewhere" AND
"`http-equiv` somewhere" INDEPENDENTLY, not co-located) · false CLEAN over a target never contacted (a
transport error returned the same empty capture as a real "nothing found", and `predicate_oracle` is ALWAYS
`conclusive=True`) · `ACAO:*`+creds minted a cors FACT though browsers refuse `*`+creds · a green-washed
negative control (text/plain, dodging every FP surface). R2 → the SAME loose predicate survived untouched in
`sso.py::OidcRedirectUriCheck` (class-bug not propagated) · the FIX's own new regex was **O(n²)** on a hostile
unterminated-`<meta>` body (240KB→8.6s) over an UNBOUNDED `resp.read()`. R3 → `_META_CONTENT` matched inside
**`data-content=`** → signed false FACT on BOTH redirect oracles (**a plain `\b` does NOT fix this — `-` is a
non-word char; need `(?<![-\w])`, which must still ALLOW `.` so `top.location.href` matches**). R4-prep →
`contains(body, "//"+evil_host)` in HostHeaderCheck is a SUBSTRING test that also fires on
`//evil.cdn.example.com` (a different, non-attacker-controlled host) → replaced with whole-authority exact
match (`_absolute_url_hosts`), which also BROADENED true coverage (JSON `reset_url`).
**Transferable rules:** (a) a co-location predicate must bind the marker to the ACTUAL sink (a navigation
target / a whole URL authority), never two independent substring hits; (b) fix a class at ONE shared helper
and grep for every twin; (c) replacing substring tests with regex parsing is a *performance* risk over
attacker-controlled bodies — bound every window + cap the body AND the read; (d) `predicate_oracle` is always
`conclusive=True`, so the RUNNER must track channel establishment or "no channel" becomes a false CLEAN;
(e) a derived value stored in `observed_evidence` (`markup_redirect_hosts`, `location_host`) is re-fired
verbatim at re-verify, so the firewall CANNOT demote a mint-time derivation bug — pin the parser with
explicit TP+negative tests and say so honestly (this is pre-existing across ALL shipped predicates).

**FACT-capable families now: SERVICE_REACHABILITY (nmap), TLS_WEAKNESS (sslscan), VERSION_RANGE (VIGIL-direct
SBOM), ACHIEVED_STATE web (wave #3 — open_redirect / cors / host_header_injection / oidc_redirect_uri).**
**WAVE #3 CARRIED BACKLOG:** (1) JS-sink-in-comment/string → **CLOSED by RAMPART** (js_lex tokenizer, js_sink
now FACT-capable); (2) gzip/UTF-16 false-CLEAN → **CLOSED by RAMPART** (body_decode + WHATWG charset); (3)
insertion coverage → **NARROWED by RAMPART** to QUERY_VALUE+URL_PATH_SEG, rest = blocking_work. **REMAINING:**
#4 posture family (CLOUD/K8S/IaC),
#5 web-vuln predicate re-drives (SQLi/XSS/SSTI, SSRF last); SERVICE_REACHABILITY expansion
(masscan/rustscan/naabu reuse capture_handshake — near-free); the full 79-tool capability matrix + a CI
sync-check. Then the held Slices C-F (budget price-table/recall harness/autonomous loop/A2·A3·H2 deploy).

**RAMPART HARDENING WAVE (PR #251, MERGED @fc5caf17, main CI green) — the reviewer's BLOCK on Wave #3's web
column made a blocking slice.** Reviewer verdict: "merge it as a header-evidence slice or mark the body-
dependent branches experimental; the encoding fix is the next BLOCKING slice." Delivered as three adversarial
rounds, EACH round's fix independently re-attacked (single red-pens → a 4-lens Workflow → a 2-lens Workflow):
- **Decode (backlog #2 CLOSED):** replaced `raw.decode("utf-8","replace")` with a first-class
  `live/body_decode.py`. Contract: `body_semantically_available` True ONLY over the COMPLETE served doc under a
  DETERMINISTICALLY-determined charset; every heuristic/host-dependent path → INCONCLUSIVE (never CLEAN/FACT).
  Completeness = `obj.eof` + empty `obj.unused_data` + bomb bounds (a truncated gzip has EMPTY unconsumed_tail;
  only eof separates it; concatenated members silently dropped member 2 = false-CLEAN). Charset resolved the
  **WHATWG "get an encoding" way** — a `_LABEL_TO_CODEC` map to codecs PROVEN byte-faithful to the WHATWG index
  (exhaustive byte-differential vs the live index files, positive-controlled on koi8-u), NOT Python's codec
  registry. br/zstd unsupported host-independently; `RFC-7230 §3.2.2` comma-combine repeated Content-Encoding.
- **JS-sink (backlog #1 CLOSED, promoted to FACT-capable):** deleted the LEAD-only quarantine; `scanner/js_lex.py`
  is an ECMA-262 lexical region classifier (CODE/COMMENT/STRING/TEMPLATE/AMBIGUOUS, fail-closed on
  NUL/oversized). A sink mints only in proven executable CODE. `_REGEX_KEYWORDS` must be COMPLETE (a `/` after
  an operand/statement-boundary keyword is a regex, not division).
- **Admission:** centralized `live/verdict.py::admit()` (closed Verdict enum; per-branch `admit` → certify only a
  FACT); authorization is a CONSTRUCTION-SCOPE contextvar, NOT a copyable field (a `_token` field let
  `dataclasses.replace(inconclusive, verdict=FACT)` forge a FACT).
- **Manifest:** `tools/verification_manifest.py --check` re-derives counts+suite from the bound JUnit artifact
  (was checking the manifest against itself).

**⚠️ THE RE-ATTACK-THE-FIX DISCIPLINE PAID OFF EVERY ROUND (each defect passed my inline review + green tests +
CI + gate):** Round-1 rewrites HELD but the 4-lens panel found a HIGH false-signed-FACT (`_REGEX_KEYWORDS`
missing `export default`/`extends`/`debugger` → a `/`-after-keyword regex lexed as division → sink minted) and
a **CRITICAL charset class** (Python codecs ≠ WHATWG: `utf-7` `+ADw-` → false FACT; EBCDIC `cp037` over an
ASCII sink → false CLEAN; bare `utf-16` no-BOM → HOST-DEPENDENT via `sys.byteorder`; `latin1` → C1 controls vs
WHATWG windows-1252). Round-2's fix was re-attacked → a HIGH duplicate-`Content-Encoding` false-availability
(two `gzip` headers ≡ `gzip, gzip` = double-encode, but set-dedup collapsed them to one layer) + MEDIUM
`gb18030`/`koi8-u` CPython-vs-WHATWG table divergence → REFUSED. Round-3's exhaustive differential found only a
LOW doc nit → converged. **The verdict guard HELD under a full forge battery** (replace/copy/pickle/contextvar-
leak/concurrency); a residual `object.__new__` forge is CONTAINED because minting re-executes the oracle.
**TRANSFERABLE RULES:** (a) a keyword/spec heuristic for a security decision must be COMPLETE — enumerate the
whole class or a gap is a false-FACT seam; (b) charset/encoding is a SPECIFIED algorithm — resolve labels the
WHATWG way and refuse anything not proven byte-faithful (Python's registry accepts labels a browser rejects);
(c) prove faithfulness by an EXHAUSTIVE differential vs the ground-truth spec, positive-controlled on a KNOWN
divergence; (d) authorization must be construction-scope, never a field a copy/replace duplicates — and back it
with a re-execution containment so no in-process forge mints; (e) RFC-combine repeated list-headers before
parsing (repeated == comma-list); (f) availability over an incomplete stream needs `eof`+`unused_data`, not
just `unconsumed_tail`. Backlog #3 (insertion coverage) narrowed to QUERY_VALUE+URL_PATH_SEG with the rest
recorded as `blocking_work` in `docs/capability-matrix/evidence-branches.json` (the per-branch ladder:
fact_capable/clean_capable current-vs-target + blocking_work). A multi-lens re-attack WORKFLOW (parallel
adversarial lenses + in-script synthesis) is the ultracode-preferred force multiplier over a single red-pen.
GOTCHA: `gh pr merge` hit a transient "unexpected EOF" (rc=0 but the merge DIDN'T land) — always verify the
merge via `git fetch origin main` + `git merge-base --is-ancestor <head> origin/main`, then retry.

**WAVE #4 — POSTURE ASSURANCE (cloud/K8s/IaC), PHASE D MERGED (PR #252 @a1d1e582, main CI 7/7 green).** A
reviewer critique REFRAMED the wave from "parsers" to EVIDENCE AUTHORITY: existing parser + existing oracle
≠ a signed FACT. The failure mode to prevent — "a tool-claim / normalized boolean / unevaluated config
laundered through a deterministic predicate into a signed statement about live infra." AUTHORITY LADDER:
primary artifact VIGIL parses → FACT about those bytes; Terraform plan-JSON/tfstate → represented state; CFN
processed template → resolved template; **scanner report (prowler/scout-suite/kube-bench/checkov/terrascan)
→ LEAD only** (a tool's say-so can't confirm itself); VIGIL-owned live capture → FACT about scoped live
state; incomplete inventory → positive FACTs, NOT CLEAN. Operator chose **L3 standalone-VIGIL-free** verify +
**ALL tracks A+B+C+D, strict**. Phase D (the assurance FOUNDATION that gates every posture FACT branch) =
5 slices, built by a parallel governed Workflow (5 build + 5 red-pen), integrated by me:
- **D1** admission-routing: SBOM migrated off direct `confirm_and_certify` → `admit()`+`certify_admitted()`;
  an **AST** static guard (test_claim_discipline) fails if any sovereign `live/*` mints directly (catches
  alias/attr/getattr/`build_certificate`); `_PENDING_MIGRATION` frontier {wiring.py, external_tool.py}
  shrink-only. **BLOCKER-1 (reviewer):** raw `confirm_and_certify` bypasses branch policy (clean_capable) —
  so EVERY FACT path must route through admission; Phase A/B/C mints via admit()/certify_admitted().
- **D2** cert **artifact/scope/freshness/completeness binding** (10 optional drop-when-empty
  EvidenceCertificate fields + validators; `binding=` kwarg through oracle_adapter, key-allowlisted; surfaced
  by verify_certificate.bound_identity, non-gating; byte-identity preserved).
- **D3** **L3 standalone replay**: the six posture oracles re-implemented in `verify_vf.py` (VIGIL-free) +
  180k-input differential test vs the in-tree oracle.
- **D4** resource-governed **safe_parse** (size/depth/alias/**merge-key**/node bombs → typed error).
- **D5** cloud-native **scope gate** (provider+account+region+resource, fail-closed).
**⚠️ CRITICAL ORCHESTRATION LESSON: Workflow `isolation:'worktree'` forks the SESSION git root
(/home/kali/Pictures/PENTEST-main = the standalone CRUCIBLE repo), NOT /home/kali/vigil.** D2's agent worked
in the wrong repo (edited PENTEST-main's framework/v2/evidence copy; it has NO integration/oracle_adapter) →
its cert-binding landed misplaced + incomplete → I SALVAGED it (git show the branch, port to vigil's
engine/crucible/framework/v2/evidence + COMPLETE the oracle_adapter threading myself). D1/D3/D4/D5 agents
self-detected the mismatch and `git worktree add` off /home/kali/vigil. **FUTURE parallel builds targeting
vigil MUST pin agents to /home/kali/vigil explicitly (create a vigil worktree; do NOT rely on
isolation:'worktree').** Also: **local `main` was stale** (behind origin/main) — `git diff main..branch`
showed all of RAMPART; fast-forward local main to origin/main before diffing agent branches.
**RED-PEN wins this wave:** the existing anti-overclaim guard AUTO-caught a D3 "producer-independent"
overclaim (reworded); the final INTEGRATION red-pen (cross-slice) found a real D4 **YAML merge-key (`<<`)
bomb** — exponential at PyYAML `flatten_mapping`, invisible to the alias-counter (linear events) AND the
post-parse walk (merged dict collapses) → fixed by REFUSING merge keys; and a flat-doc parse hang (node
budget was post-parse only) → fixed by counting nodes DURING compose. Both re-attested. Per-slice red-pen
(all HELD) missed the cross-slice merge-bomb — the INTEGRATION red-pen is a distinct, necessary pass.
**WAVE #4 PHASE A — MERGED (PR #253 @d681936d, gate 11/0/0, main CI green).** Track A (primary-artifact
posture FACT tracks) built pinned to /home/kali/vigil + integrated: A1 K8s (ingest_k8s_rbac →
K8S_WORKLOAD_POSTURE + kube-bench → K8S_POSTURE), A2 mesh+cicd (MESH_POSTURE/CICD_POSTURE), A3
Terraform-plan-JSON/tfstate + CFN → CLOUD_POSTURE/POLICY_PATH. Near-zero-FP held: TF `public`≠oracle-public,
encryption-unknown=None, CFN intrinsics=unknown, planned_values (desired) NEVER read.

**⚠️ 14 CONFIRMED DEFECTS across ~5 adversarial rounds, EACH caught after my inline review + green tests + gate
+ (usually) CI — the multi-lens re-attack WORKFLOW earned its cost every round; the crypto core needed TWO
independent red-pens before it was clean.** The recurring **CLASS: a normalization/canonicalization step on
one path diverges from the oracle (or the reducer), minting a false FACT — and fixing it on one path leaves a
twin.**
- **Round-1 (truncation-window CRITICAL):** the A1 whitespace roleRef fix tested emptiness over the FULL
  string, but the oracle `_k8s_norm` TRUNCATES `[:4096]` THEN strips → `(" "*4096)+"x"` re-entered the
  empty-tolerance → signed false FACT. Fix mirrors truncate-then-strip.
- **Round-2 (IaC Condition-blindness CRITICAL + role-NAME case-fold HIGH + 3 finding_ref collisions MEDIUM):**
  IaM `Principal:"*"` scoped by a restricting `Condition` minted an UNCONDITIONAL public FACT (skip any
  non-empty Condition); the dangerous-role NAME was `.lower()`'d so `Cluster-Admin` (a DISTINCT custom role)
  folded onto the built-in (match role NAME EXACTLY, case+whitespace); finding_refs collided (RBAC/CIS/mesh/
  cicd) → content-digest + retain res.contexts only for facts.
- **Round-3 (mesh `from`-inversion HIGH):** `from_mesh_control` DROPPED a truthy-non-list `from` clause,
  collapsing a source-restricted AuthorizationPolicy to `{}` → oracle read an empty catch-all → "admits EVERY
  caller" false FACT. Mirror the oracle's `not froms` truthiness (a truthy `from` = presence marker).

**REVIEWER BLOCK #3 (the governing FACT-readiness critique) — ALL CLEARED, crypto core passed TWO independent
red-pens with ZERO findings:** "admission+signatures don't make a claim SOUND; the SUBJECT of every posture
FACT must be the artifact/construct, NEVER the live system."
- **Artifact re-check (the MAIN blocker, crypto):** a signed `artifact_sha256` only proved the cert CONTAINS a
  digest. Added OPT-IN SIGNED `EvidenceCertificate.artifact_recheck_required`+`artifact_encoding` (drop-when-
  empty → existing certs byte-identical, gate stays 11/0/0); `verify_certificate(artifact_bytes=…)` RECOMPUTES
  sha256, cross-checks, gates `.ok` via `primary_artifact_ok`, FAILS CLOSED on missing bytes; a 1-byte swap
  fails; downgrade-resistant (fields are signed). All 6 families opt in + retain `res.artifact_bytes`; `bytes`
  authoritative, a `str` input is `canonical_text`. `verify_bundle` threads `artifact_bytes_by_ref`.
- **Claim-scoping (subject honesty):** mesh branch renamed `mesh_posture.declared_configuration` (declared
  config, NOT runtime — precedence/selectors not evaluated); kube-bench FACT subject = `kube_bench_report`
  ("declares control X failed… not an independent observation of the live cluster"); RBAC evidence source-
  neutral (`claim_scope="binding"`, "where in effect", no present-tense "HAS access"); cicd names precise
  constructs. (IaC "publicly exposed"/"grants access" over a tfstate/plan is the REPRESENTED achieved state —
  the red-pen REFUTED those as flawed expectations; left as-is.)
- **`on:` YAML SILENT FALSE NEGATIVE (reviewer-predicted):** the YAML-1.1 SafeLoader coerced the GitHub-Actions
  `on:` trigger KEY to Python `True`, so pull_request_target pwn-requests NEVER fired (0 facts). Fixed at the
  parser (rebuild the loader's implicit resolvers → only `true/false` are bool; `on/off/yes/no` stay strings).
- **RBAC typed subjects:** replaced the kind-qualified-STRING workaround with typed `{kind,name,api_group}`; the
  RBAC apiGroup is REQUIRED; kind/name/apiGroup compared EXACTLY (case+whitespace) on BOTH the typed path AND
  the legacy live-read STRING path (a padded `"system:anonymous\n"` / `"System:Anonymous"` is a DIFFERENT
  principal). Caught a SILENT FN: `from_k8s_workload_control` was `_coerce_text`-flattening typed subjects to a
  stringified-dict the oracle couldn't match (retain typed).
- **Finding identity:** replaced the 48-bit `default=str` digest with the project canonical `digest_payload`
  (full sha256, REJECTS non-JSON) over the control's STRUCTURAL LOCATION (parse ordinal) + retained context —
  so identical controls at DIFFERENT positions are DISTINCT findings; a re-parse is order-stable.

**FACT-capable families now:** SERVICE_REACHABILITY(nmap) · TLS_WEAKNESS(sslscan) · VERSION_RANGE(SBOM) ·
ACHIEVED_STATE-web(open_redirect/cors/host_header/oidc/js_sink) · **+ CLOUD_POSTURE · POLICY_PATH · K8S_POSTURE
· K8S_WORKLOAD_POSTURE · MESH_POSTURE(declared_configuration) · CICD_POSTURE** (all ARTIFACT-scoped: declared
manifest / represented tfstate-plan / report-declaration — never live infra). Tool `fact_capable` stays
{nmap,sslscan} (posture is VIGIL-direct; FACT lives in evidence-branch rows, pinned by
test_claim_discipline+test_tool_manifest).

**REMAINING (Wave #4):** **L3-parity enhancement** (the offline BUNDLE must CARRY the raw artifacts + the
`framework.v2 evidence verify` CLI must thread `artifact_bytes_by_ref`; today posture-FACT bundles fail-CLOSED
via the CLI — SAFE but incomplete). **PHASE B** live cloud/K8s (D5-gated; collectors cloud_live/gcp_live/
azure_live/k8s_live + live/cloud_scope.py EXIST; live-fire deferred no-creds → FACT about scoped captured live
state). **PHASE C** tool-reports (prowler/checkov/kube-bench/…) → LEAD-only normalization (NO fact_capable
flip). Then #5 web-vuln re-drives (SSRF last), SERVICE_REACHABILITY expansion (masscan/rustscan/naabu), full
79-tool matrix + CI sync-check; held Slices C-F. Full per-slice specs in `parsed-popping-lemur.md`.

**⚠️ NEW ORCHESTRATION LESSONS (Wave #4 Phase A):** (a) a re-attack WORKFLOW's separate VERIFY phase can STALL
(~agent-stall gotcha) — a 0-byte output + a stale journal mtime = stalled; SALVAGE the completed attack lenses
from `journal.jsonl` (grep `"type":"result"`), self-verify each finding, `TaskStop` the run. Later re-attacks
FOLDED verification into each lens (self-verify, no separate phase) → no stall. (b) An adversarial VERIFY pass
correctly REFUTES ~1/3 of reported findings (the 2 IaC "overclaims") — keep it, it filters false red-pen
findings. (c) The re-attacks CONVERGE (4 findings → 1 → 0) — keep going until a round is clean, but they do end.
(d) A cert-SCHEMA change is safe for byte-identity ONLY via drop-when-empty + a make-gate check.

**KEY LESSONS:** an INDEPENDENT red-pen caught a real BLOCK on ~half the slices my inline review + green tests
MISSED — INCLUDING the re-check of a fix (never merge a soundness/crypto/gate verdict on green+self-review).
The gate/harness ITSELF must be adversarially tested (a conformance harness can green-wash). Build inline +
red-pen via agent (build-agents die on session limits per prior programs; red-pen agents are read-only, low
risk). CI: framework-dependent tests go in BOTH the sovereign --ignore list AND the offense-process include
list. `dangerouslyDisableSandbox: true` for git push/gh/openssl. Builds on [[vigil-posture-and-brain-slot]] +
[[vigil-truthenovation-program]]; repo policy NO `Co-Authored-By: Claude` ([[vigil-authorship-contributors]]).
