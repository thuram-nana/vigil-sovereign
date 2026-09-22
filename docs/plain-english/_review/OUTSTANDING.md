# OUTSTANDING — a complete, honest census of what is left

**Repo:** `/home/kali/vigil` @ `fa68f289` (main, clean working tree)
**Date:** 2026-08-13
**Question answered:** *apart from the work already in flight, is there any pending, deferred, or to-be-done work left in this codebase?*

**Answer: yes — 78 items. 10 of them would block a national-agency deployment. 3 are security or safety
defects that are written down nowhere in this repository.** The rest is either honest, well-declared
engineering debt or correctly-deferred work that no amount of engineering can close.

This census was built by reading code, not documents. Every load-bearing claim below was re-verified
against source or reproduced live; where a document and the code disagreed, the code won and the document
is listed as a defect. Items that today's 14 merges already closed are listed in bucket 4 so nobody
re-works them.

---

## What I verified, and what I refuted

**Reproduced live (not inferred):**

| Claim | Method | Result |
|---|---|---|
| `CRUCIBLE_ROOT` escapes to `$HOME` | ran the resolver with `sys.argv[0]` set to the real console script | **CONFIRMED** — `root = /home/kali` from `.venv-offense/bin/vigil`; `root = /home/kali/vigil/engine/crucible` when run from the repo |
| Branch protection is weak | live GitHub API `branches/main/protection` | **CONFIRMED** — `enforce_admins: false`, `required_pull_request_reviews: null`, `required_signatures: false`, `strict: false`, 9 contexts, `CRUCIBLE eval + benchmark corpus` **not** among them |
| ~900 CRUCIBLE tests are green but not in CI | ran the 12 omitted suites | **CONFIRMED** — ~900 collected, **all pass, 1 skip** (a live-intake test needing an env var) |
| Governance grants are replayable | read `_CORE` in all three governor files | **CONFIRMED** — the anti-replay pattern exists in one file and is absent from its two siblings |
| SBOM drift is checked against `sbom.json` | read the script the doc points at | **REFUTED** — the doc is wrong; see B-8 |

**Refuted / corrected from the lens reports:**

- The claim that `framework/v2/tests` contains 59 tests and `intel` 14 files was folded into a single
  verified number: **~900 tests across 12 suites**, run and green.
- A lens reported `spine_domains.py` at `integration/vigil_integration/`. It is at
  `packages/core/vigil_core/vigil_core/spine_domains.py`. The substance held: the file says
  `owner_rooted=True, file_backed=True` (`:157`) while `docs/FEATURES.md:773` says both are `False` and
  "NOT wired into the live engine".
- The claim that `verify/verifier.py` does not wire `k8s_workload_posture_oracle` is **false** — it is
  wired at `verify/verifier.py:856-858`, gated on `k8s_workload_control` in the ctx. The *document*
  claiming it is unwired (`docs/FEATURES.md:481`) is the defect.
- The E-series "callers" that appear in sibling `live/*.py` files are **docstring cross-references only**,
  not imports. The invocation gap is real.

---

## BUCKET 1 — BLOCKS AN AGENCY DEPLOYMENT

*A real customer could not put this into service without these. Ordered by how badly they hurt.*

### A-1. Signed governance grants are replayable — promotion **and** capability latches — HIGH · **2–3 days**

**Written down nowhere in this repository.**

`apps/sigil/sigil/governor/promotion.py:23` signs a core of exactly:

```python
_CORE = ("signal", "state", "agent", "scope")
```

No nonce, no epoch, no `issued_at`. `is_promoted` (`:72-100`) and `state_all` (`:45-71`) fold
last-write-wins over the spine. A captured, **genuinely owner-signed** `granted` record, re-appended after
a `revoke`, resurrects a revoked promotion with a valid signature and an intact hash chain. The identical
shape is in `apps/sigil/sigil/governor/capability.py:33` — `_CORE = ("signal", "capability", "state")` —
and `_scan_enabled` (`:107-130`) honours any later signed `enabled`, so a replayed enable revives a
disabled gesture/voice/autolearn capability.

**The fix already exists eleven lines away in a sibling file and was not mirrored.**
`apps/sigil/sigil/governor/offense_gate.py:40-44` documents this exact attack and defends against it:

```python
# ``issued_at`` MUST be here so a captured OPEN cannot be REPLAYED to reverse a later CLOSE — the
# fold rejects any OPEN whose ``issued_at`` does not strictly exceed the highest already seen...
_CORE = ("signal", "state", "charter_id", "charter_hash", "not_after", "issued_at")
```

and enforces it at `:125-128` with a `max_issued` high-water.

The threat model is in-scope by the repo's own words — `promotion.py:50` reasons explicitly about a grant
"one a prompt-injected agent wrote via the shared `store`". The append path (`spine/store.py:688`) has no
content-dedup, so a byte-identical re-append succeeds.

**Fix:** add `issued_at` (or a nonce) to `_CORE` in both files; mirror `offense_gate`'s high-water in
`is_promoted`, `state_all` and `_scan_enabled`; mirror it in the snapshot folds
(`promotion_map()`, `capability_latch_map()`) or the prune fold will re-open the hole.
**This is the one finding that contradicts a claim the system makes about itself. It should not be
discovered by the agency.**

### A-2. The kill-switch, trust root and charter live at `$HOME` when the CLI is launched the documented way — **0.5–1 day**

`engine/crucible/framework/v2/common/paths.py:51-58` resolves the root by walking up from `sys.argv[0]`
**first**, looking for a `CLAUDE.md` sentinel — before `__file__` and before `cwd`. `/home/kali/vigil` has
no `CLAUDE.md`; `/home/kali` does. Reproduced against the real console script at
`/home/kali/vigil/.venv-offense/bin/vigil`:

```
root  : /home/kali            # ← kill-switch, .entitlement/trust-root.json and targets/ (the charter) all resolve here
```

Run from inside `engine/crucible` it correctly resolves to the repo. **So the kill-switch path, the
entitlement trust root and the authorization-document location depend on how you invoked the CLI** — a
halt file written under one resolution is invisible under the other.

Bounded: needs `CRUCIBLE_ROOT` unset *and* a `CLAUDE.md` above the repo, and a missing charter fails
closed. A local branch `fix-crucible-root-escapes-to-home` exists **with zero commits** — known,
unstarted, and unwritten anywhere.

**Fix:** anchor on the installed package (or an explicit repo marker) before `sys.argv[0]`; refuse a root
outside the checkout unless `CRUCIBLE_ROOT` was set deliberately.

### A-3. The "always-on" who/when attestation ledger is bypassable through the documented entry point — **1–2 days**

`integration/vigil_integration/attestation/ledger.py:5` describes `require_attestation` as fail-closed
before any engagement. Grep confirms its only production wiring is the super-CLI path
(`live/engine.py:404`, via `live/wiring.py`). **`engine/crucible/framework/v2/engage.py` and
`framework/v2/scanner/cli.py` contain no attestation call at all** — and
`python3 -m framework.v2 engage <slug> <url> --arsenal --spine` is exactly the invocation
`docs/CONTINUATION.md:88` documents as the way to run a real engagement.

The word "always-on" does not survive contact with an auditor. **Fix:** call `require_attestation` on the
CRUCIBLE `engage`/`scan` entry points too, or remove those entry points from operator-facing docs.

### A-4. The production `engage` path loads the EngagementAuthority **unsigned** — **1 day**

`engage.py:748-753` and `:1054-1059` (and `repeater/tool.py:110-121`) construct
`HttpExecutor(auto_load_authority=True)` with no `trust_root`. `agents/http_executor.py:286-294` then
takes the unsigned `load_authority()` path, and `_authority_gate` (`:326-339`) fails closed **only when a
trust root was pinned**. That unsigned JSON governs the validity window, `allow_destructive`,
`live_destructive_acknowledged` and `max_actions` (`authority/gate.py:84-125`).

The VIGIL plane refuses exactly this configuration, in as many words:

```python
# integration/vigil_integration/conjunctive_gate.py:116-121
if trust_root is None:
    raise ValueError(
        "build_offense_gate requires the governance trust_root: a None trust_root loads the "
        "CRUCIBLE authority UNSIGNED/unverified, so a tampered scope/window/destructive flag "
        "would pass the gate. Fail-closed refusal.")
```

**The two planes disagree and the CRUCIBLE plane is the weaker one.** Mitigating: the file is 0600
(`authority/store.py:33-36`) and charter scope is separately enforced by `agents/scope_gate.validate_action`,
so what is exposed is the time-box, the action budget and the destructive flags — not scope. Written down
nowhere.

### A-5. No backup or restore for any offense-side state — **1 week**

`apps/sigil/sigil/backup.py` is a genuinely good passphrase-encrypted off-box DR backup **of the SIGIL
spine and trust root only**. Nothing covers the offense side: the blackboard `.blackboard/store.sqlite`,
`targets/<slug>/evidence/`, the attestation ledger, or the posture/re-proof attestation logs. There is no
`backup` verb in the super-CLI (verified: `grep '"backup"' integration/vigil_integration/cli.py` → empty).

**A disk failure loses every engagement's evidence and the entire who/when ledger.** No customer can
operate a system of record without this.

### A-6. No data retention, deletion, or erasure path — **1–2 weeks, plus a policy decision first**

The spine is append-only *by database trigger* (`bb_events_no_delete`, `agents/blackboard.py:158-162`) —
deletion is structurally impossible. Captured evidence contains real `Authorization`/`Cookie` headers and
response bodies (`common/paths.py:74-79` says so explicitly). There is no purge command, no retention
policy, no subject-erasure mechanism. `common/ephemeral.py` is per-run and opt-in.

**This is a policy collision, not a missing feature.** The tamper-evidence guarantee and a
retention/erasure mandate are in direct tension and nobody has written down which wins. An agency will
ask. Decide first, then build; the likely answer is cryptographic erasure (destroy the per-record key,
keep the hash chain intact) which the field-level AEAD at `spine/store.py:726` already makes feasible.

### A-7. No multi-user model, at all — **architectural; 4–8 weeks if required**

The console is loopback-only with a CSRF header and host allowlist (`console/server.py:33-46, 342-367`).
The API's only auth is a **single shared bearer secret, opt-in and off by default** —
`api/authn.py:28-45`: unset `CRUCIBLE_API_KEY` ⇒ no enforcement. There are no users, no roles, no
separation of duties, no session management.

Operator identity compounds it: `attestation/identity.py:1-22` derives identity from OS login +
`git config user.name/email` + hostname, signed by a keypair **generated on first use**. No CA, no
enrolment, no revocation list, no binding to an agency credential. Non-repudiation holds against the
box's key; it does not establish *which human*.

**State this as an architectural boundary up front — "one sovereign owner, one box" — rather than let it
be discovered in questioning.** If the agency needs multi-operator with separation of duties, it is weeks
of work and touches the trust model.

**Update (W16-12, #518) — the offense API is now wired to the existing multi-user model; the "only auth is a
shared bearer" statement above is superseded for it.** The sovereign plane already had an enforced multi-user
RBAC (Claim 6: `viewer ⊂ analyst ⊂ operator ⊂ owner` over an owner-signed accounts spine, per-user
bearers/sessions, MFA/TOTP, keypair PoP), and the offense **console** already enforced it per-action. This
change closes the remaining surface: the loopback gated **API** (`framework.v2.api`) now enforces
`role_can(role, offense_perm_for(path))` and **attributes** every action to the authenticated principal, with
a role lacking the permission **refused-and-attributed** (`api/server.py ApiHandler._authorize`;
`docs/decisions/W16-12-offense-api-multiuser.md`). **Residual (unchanged, stated honestly):** a **direct**
on-host loopback credential-holder is still **owner-equivalent** (the per-user gate protects the
proxy-forwarded path); "sessions" are the sovereign per-user bearer sessions surfaced via the proxy, not an
api-side session store; and `attestation/identity.py`'s first-use operator keypair — with no CA / enrolment /
external revocation binding to an agency credential — remains the "one sovereign owner, one box" boundary for
the spine's own non-repudiation. So the architectural boundary still holds; what is no longer true is that the
API has *no* users/roles/attribution.

### A-8. Six cloud/Kubernetes exploitation confirmations have no invocation path — **RESOLVED (W16-16, #522)**

> **RESOLVED (W16-16, #522).** The six confirmations are now invocable via **`vigil cloud-exploit
> <imds|secret|gcp-sa|iam-escalation|k8s-rbac|k8s-rbac-grant>`** (`cli.py:_cmd_cloud_exploit`), the H4 audit
> package via **`evidence audit-package`**, and the AI-Gauntlet via **`vigil gauntlet`** (its live garak/PyRIT
> runner honestly deferred). A framework-free structural guard
> (`integration/tests/test_capability_invocation_paths.py`, required P5 job) enumerates the registered
> capabilities and reddens if any becomes orphaned again; the invocation paths are recorded in
> `docs/capability-matrix/invocation-paths.json` and `docs/decisions/W16-16-orphan-capabilities-invocation-paths.md`.
> The MCP-sensor sub-point is answered there too: MCP is an additional read-only surface, never the sole
> interface (the sensors are driven by the engagement loop + the `capabilities` verb). The paragraphs below are
> the ORIGINAL finding, kept for the audit trail.

The headline capability that merged today is real, tested, and **unreachable from any command, route or
button.** `integration/vigil_integration/live/{imds_verify, secret_verify, iam_escalation_verify,
gcp_impersonation_verify, k8s_rbac_grant_verify}.py` are imported **only by their own tests**. None of the
`vigil` CLI's subcommands reaches them (verified against the full `add_parser` list); neither does
`live/engine.py`, `console/api.py`, nor the UI. The single exception is
`tools/livefire/k8s_rbac_livefire.py:83`, a hand-run script.

Same class, one level up: `console/actions.py:62-66` maps the UI's three cloud modes to the **offline
importers** (`cloud_import`, `kube_bench`, `declared_service`) — the live sensors `cloud_live`, `gcp_live`,
`azure_live`, `k8s_live` are registered in the fusion registry but have no UI or CLI path. `MESH_POSTURE`,
`CICD_POSTURE`, `MOBILE_POSTURE`, `EMAIL_AUTH_POSTURE`, `IDENTITY_POSTURE` are reachable only by
hand-authoring `targets/<slug>/fusion.json`.

**Today the honest sentence is: "we built six cloud-exploitation confirmations that nothing can currently
call."** One gated verb (`vigil cloud-exploit <imds|secret|gcp-sa|iam-escalation>`) plus wiring
`k8s_rbac_grant_verify` into `_reverify_k8s_live` closes it.

*Note on the in-flight work:* `readiness-should-fix` adds 63 lines to `docs/DEFERRED-INFRA.md` about the
E-series residual, but frames it purely as "the runner against a real endpoint" and asserts the admission
wiring is built. **After that branch merges, the invocation gap will still be unwritten anywhere.**

### A-9. Enabling cloud/K8s without the undocumented prerequisites produces a **silent clean result** — **1–2 days**

`sensors/cloud_live.py:26-33` and `sensors/k8s_live.py:24-30` require (a) ambient credentials — boto3
default chain, GCP ADC, `DefaultAzureCredential`, or a kubeconfig — and (b) a per-target egress allowlist
file **`targets/<slug>/collector-hosts.txt`**, without which the run is refused fail-closed.

That file is named in exactly two places in the whole repo: `engine/crucible/SECURITY.md:195` and
`docs/assessments/pwnedlabs/BUILD-PLAN.md:144`. Verified: **zero occurrences in `README.md` (90 KB) and
zero in `docs/DEPLOY.md`.**

**What happens if the operator supplies nothing: a silent, clean no-op** (`sensors/k8s_live.py:245` —
"fail-closed no-op"). For a product whose entire thesis is a *sound negative*, a missing prerequisite
that is indistinguishable from "clean" is the worst possible failure mode. Make it a loud refusal with a
named remediation, and document the prerequisites in `DEPLOY.md` and `README.md`.

### A-10. The two documents the handoff tells a reader to open first are materially wrong — **1–2 days**

`docs/CONTINUATION.md` says "Read this FIRST when resuming." Its section **"STATE — what is NEXT (build in
this order)"** (`:108-157`) still lists as unbuilt: **P5** two-environment boundary, **P6** hard egress
gate, **P7** WARDEN gate, **P8** Claude runtime, **P9** oracle confirmation pipeline, **P10** spine-sign,
and **I1–I5**. All are merged and shipping. It still carries the warning *"do not run fused offense before
P6."*

An agency reviewer who opens the handoff doc will conclude the two **FATAL-flagged safety gates are
missing from the product.** That is a worse outcome than any real gap on this list.

`DEVELOPER-HANDOFF.md:169` states "CI runs **six jobs**"; there are ten.

---

## BUCKET 2 — SHOULD BE DONE, NOT BLOCKING

*Genuine work. No deployment depends on it.*

### Assurance and CI

| # | Item | Evidence | Size |
|---|---|---|---|
| B-1 | **~900 CRUCIBLE tests never run in CI.** `ci.yml:105-116` hand-lists suites; 12 are absent — `agents` (28 of 29 files omitted, incl. the executor kill-switch, egress redirect re-gate, oracle-authority and spine-chain tests), `intel` (14 of 15), `tests` (the flagship engage/fusion e2e), `intake`, `knowledge`, `improve`, `mcp`, `repeater`, `intruder`, `plugins`, `socialdefense`, `imports`. **I ran them: all pass, 1 skip.** This rots in practice — today's `bc9dd051` repaired a RED flagship e2e test that was red precisely because nothing ran it | ran; `ci.yml:42,105-116` | 0.5–1 d |
| B-2 | **~50 of 82 SIGIL test files never run in CI**, incl. `test_integrity.py`, `test_spine_floor.py`, `test_spine_crashfuzz.py`, `test_snapshot_fold_killswitch.py`, `test_snapshot_fold_promotion.py`. Only a handful need the Rust kernel; most could run in the existing job today | `ci.yml:379-411`; 82 files on disk | 0.5 d |
| B-3 | **`crucible-eval` cannot block a merge.** Declared only in a YAML comment (`ci.yml:129-134`); confirmed against the live API — the benchmark corpus and the committed recall/precision baselines are advisory | live API | 1 h |
| B-4 | **Branch protection does not bind the owner.** `enforce_admins:false`, `required_pull_request_reviews:null`, `required_signatures:false`, `strict:false`. In a product whose thesis is cryptographic provenance, **commits are not required to be signed** | live API | 1 h |
| B-5 | **The supply-chain CVE gate never re-runs on a frozen tree.** `supply-chain.yml:27-32` triggers on push/PR to main only — no `schedule:`. The CRITICAL-blocking gate that landed today will not fire against a CVE published tomorrow unless someone pushes | `supply-chain.yml:27-32` | 30 m |
| B-6 | **The k3s live-fire — the only real-infrastructure proof in the repo — is not in CI.** `grep livefire .github/workflows/ci.yml` → nothing. A manual proof no job re-runs will rot | verified | 0.5 d |
| B-7 | **No lint or type gate in CI** — zero `ruff`/`mypy` hits in either workflow, despite `docs/CONTINUATION.md:163` claiming "ruff + mypy clean where configured" as the standard | verified | 1–3 d |
| B-8 | **`sbom.json` is still the hand-written scaffold and `SECURITY.md` makes a false claim about it.** `framework/v2/sbom.json:7-13` carries `"timestamp": "0000-00-00T00:00:00Z"`, tool name `"scaffold (operator regenerates with cyclonedx-bom)"`, and version *ranges*. `SECURITY.md:93` claims "Re-generates the SBOM and compares the component set to `sbom.json` — drift fails the build" — but `bin/verify-supply-chain.sh:195-224` compares a **temp** SBOM against the **lock**, never against the committed file. The scaffold is cited as authoritative at `SECURITY.md:29,57`, `SOVEREIGNTY-THREAT-MODEL.md:173`, `V2-LIMITATIONS.md:518,534` and offered as a user input at `USAGE-GUIDE.md:251` | read both | 0.5 d |
| B-9 | **Supply-chain FU1** — CI actions are not SHA-pinned (`actions/checkout@v4`, `actions/setup-python@v5` throughout) | `ci.yml` | 0.5 d |
| B-10 | **Supply-chain FU2** — CI jobs still `pip install -e ...` rather than installing from the hash-locked requirements the same repo now ships | `ci.yml:19,57,143,192,213,369` | 0.5 d |
| B-11 | **Supply-chain FU3 residual** — first-party locks are on `cryptography==50.0.0` (both), but **`vendor/strix/uv.lock:471-472` is still `cryptography 46.0.7`**; the gate threshold is still CRITICAL, not HIGH | verified both locks | 0.5 d |
| B-12 | **Supply-chain FU4** — no PEP 740 / sigstore publisher-attestation verification; hashes only | `SUPPLY-CHAIN.md:267` | 2–3 d |
| B-13 | **`bootstrap.sh` — the one-command fresh-machine promise — is never exercised by CI**, and is Debian-shaped (`:114-133`: non-Linux unsupported, non-Debian degrades to manual tool install) | verified | 1 d |
| B-14 | **No parser fuzzing** of CRUCIBLE's own charter/fingerprint/JSON parsers, **no reproducible-build verification** (today's work delivered *pinning*, not multi-builder bit-identical builds), and **no third-party audit**. All three are already named honestly at `SECURITY.md:323-331` | verified | 1 w / 2–4 w / external |

### Correctness and reachability

| # | Item | Evidence | Size |
|---|---|---|---|
| B-15 | ~~**Every scan launched from the UI silently skips 93% of the check corpus.**~~ **FIXED.** `console.actions.launch_scan` now honours `use_library=True` and appends `--library` to the spawned command, so a UI-launched scan runs the declarative library. `DEFAULT_CHECKS` is 11 checks (`scanner/checks.py:1055`); the library holds ~172 across 23 bug classes. | fixed | done |
| B-16 | **`--library` is off by default in both CLI entry points** (`scanner/cli.py:102`, `engage.py`, both `store_true`) — a deliberate decision, recorded in [`docs/decisions/W16-4-default-check-corpus.md`](../../decisions/W16-4-default-check-corpus.md) (W16-4 / #509). The `TIMING` oracle fires only under `--library`, which the run now discloses; a default-run CLEAN is bounded (`ScanReport.coverage_bounds` / `verdict_by_class`): every library-only class is reported `inconclusive`, never `clean`. | addressed (W16-4) | done |
| B-17 | **`vigil posture` does not exist.** `docs/TRUTHENOVATION.md:231` promises "`vigil posture attest\|verify`" for the flagship artifact. The verb is absent from the CLI; the capability works as `python -m vigil_integration.posture attest` (correctly documented at `docs/POSTURE.md:56`). **A reviewer will type the documented command and get an error** | verified | 1 h |
| B-18 | **The H4 external-audit package has no CLI verb.** `evidence/audit_package.py:151,284` + the shipped VIGIL-free `evidence/audit_offline_verifier.py` are the artifact an auditor actually receives, and can only be produced by calling Python by hand — `docs/H3-FIELD-RECORD-RUNBOOK.md:41` literally instructs that. `evidence/cli.py:311-344` offers keygen/certify/verify/pcf-export/pcf-verify and nothing that builds a package | verified | 0.5 d |
| B-19 | **`web_redrive` — Wave-3's gated HTTP re-drive to an `ACHIEVED_STATE` web FACT — has zero production callers.** Repo-wide: its own test plus three docstring cross-references. It is named as a headline capability in `docs/capability-matrix/hexstrike.json` | verified | 2–3 d |
| B-20 | **The AI-Gauntlet** (`gauntlet/adapters.py`, `live/gauntlet_subproc.py`) has no verb and no caller | verified | 2–3 d |
| B-21 | **20 registered sensors are reachable only by starting the stdio MCP server.** `sensors/builtin.py:57-131` registers nmap, tshark, nuclei ×3, ZAP, Burp, the fuzz harness, MobSF, cert-scan; its only production callers are `mcp/server.py:110-114` and `plugins/registry.py`. None is on `_SAFE_SENSORS`, so `engage --fuse-only` cannot run them. This is the sole route to the `SANITIZER_SIGNAL` oracle | verified | 2–3 d |
| B-22 | ~~**`postmortem.run()` double-counts calibrated priors.**~~ **FIXED (W16-STD-5).** `_update_priors_from_engagement` now MERGES outcomes per `(bug_class, surface)` (a finding recorded as both a confirmed hypothesis AND a successful payload is credited once, not twice — it used to read `succ=2/att=2`) and applies an engagement's priors at most once via a `schema_meta` marker (`priors_applied:<eid>`). Pinned by `memory/tests/test_postmortem_priors.py`. | fixed | done |
| B-23 | ~~**CSRF, clickjacking and postMessage have no detection at all**~~ **FIXED (W16-STD-5).** All three now have a `BUG_CLASS_ORACLES` row + a SOUND POSTURE-WEAKNESS oracle (clickjacking = missing X-Frame-Options/CSP frame-ancestors; CSRF = anti-CSRF-token-not-enforced control-differential; postMessage = wildcard target-origin / missing origin check) — each proving a MISSING DEFENSE, NEVER an achieved-state exploit (`verify/oracles.py`, seam `verify/client_side_posture.py`, `docs/DELIBERATE-REFUSALS.md` refusal 8). An imported finding of each class is now adjudicated; per-class negative controls in `verify/tests/test_client_side_posture.py`; a structural test asserts every always-applicable constitution class has an oracle row. | fixed | done |
| B-24 | **Stage 9's deliverable `reports/retest.md` has no renderer.** `ENGAGEMENT-LIFECYCLE.md:232-249` names it; `report/cli.py:36-40` `_DOC_FILENAMES` has only executive / technical / remediation-roadmap. The re-proof *machinery* is strong; the *document* an agency receives does not exist | verified | 1–2 d |
| B-25 | **Playbook 26 (incident-response pivot) has no implementation** — prose only, no module, no verb, no oracle. `CLAUDE.md` §II makes it a *hard-stop behaviour*, so a mandatory constitutional rule is enforced only by prompt | verified | 1–2 w |
| B-26 | **Stage 11 engagement closure is unimplemented** — no artifact cleanup, no credential rotation, no archival; `targets/_template/notes/test-artifacts.md` is a form a human fills in | verified | 3–5 d |
| B-27 | ~~`verify/reachability.py` rejects IPv6 targets outright~~ **FIXED (W16-STD-5).** `_is_single_host` now accepts a single IPv4 **or IPv6** literal (bare or bracketed); the scope layer's `bracket_bare_ipv6` / canonical IPv6 matching validates the same address dialled. Pinned by `verify/tests/test_reachability.py::test_ipv6_single_host_is_accepted_and_reachable` (an IPv6 CIDR is still rejected — not a blanket accept). | fixed | done |
| B-28 | `agents/chain_synthesizer.py` (multi-hop exploit-chain synthesis) has zero production callers; `analysis/smt.py`'s SMT path is unexercised everywhere because z3 is in neither venv nor CI | verified | 2–3 d |

### Operational hygiene

| # | Item | Evidence | Size |
|---|---|---|---|
| B-29 | **No DR, key-rotation or restore runbook.** `docs/DEPLOY.md` is 156 lines with no backup, restore, rotation or DR heading. Rotation is *supported by the data model* (1-of-n over multiple authorizers — `live/spine_verify.py:130`, `governor/identity.py:60`) but there is no ceremony, no runbook, no command | verified | 3–5 d |
| B-30 | **No incident-response plan for compromise of the tool itself** — kill-switch and device revocation exist; no key-compromise procedure, evidence-quarantine step, or attestation re-anchoring guidance | verified | 3–5 d |
| B-31 | **No crash-resume.** `live/engine.py:609-619` writes checkpoints into the spine; nothing reads them back (`cli.py:131` only counts them). A killed run restarts from zero | verified | 3–5 d |
| B-32 | **The engagement log silently discards history.** `common/logging.py:28` caps at 64 MiB and `:66-72` rotates to exactly one `.1`. Past ~128 MiB audit lines are deleted. The signed spine is separate and unaffected, but the operational record is not complete | verified | 0.5 d |
| B-33 | **CWD-dependent state.** `console/sessions.py:59` — `VIGIL_LIVE_DIR` defaults to the **relative** `.vigil-live`. Running `vigil` from a different directory silently uses a different session store | verified | 1 h |
| B-34 | **No corruption detection for the SQLite stores** — no `PRAGMA integrity_check`, no `sqlite3.DatabaseError` handling in `agents/blackboard.py`. A torn store surfaces as a raw traceback. (Schema *migration* is done well: `:111-186` is transactional and FK-checked) | verified | 1 d |
| B-35 | **Single-process assumption, stated in code.** `common/logging.py:36-38` — "v2 today is single-threaded". Two concurrent engagements in one process cross-log | verified | 1–2 d |
| B-36 | **No uninstall path** (`V2-LIMITATIONS.md:814-821`, still accurate) | verified | 0.5 d |
| B-37 | **Legal-discovery export exists in substance but not in name** — the H4 package is strong but has no chain-of-custody metadata, custodian log, or discovery-format export. Reframing effort, not build effort | verified | 2–3 d |
| B-38 | Orphaned surfaces: `/api/v1/*` (`api/server.py:40-57`) has zero UI consumers — defensible as a programmatic API, but it is a second authenticated HTTP surface with no operator-visible affordance; `/api/inbox` and `/api/telemetry` are routed with no consumer; `engagement_detail`/`reports_data` have no route; the command palette (`packages/vigil-ui/app.js:152`) is a roadmap toast | verified | 1 d |

### Documentation that lags or overruns the code

Every row verified against source. **Note that half of these understate shipped controls — in front of a
national agency that is as damaging as overstating one, because it invites "what else is your
documentation wrong about?"**

| Document | Claim | Reality | Size |
|---|---|---|---|
| `docs/FEATURES.md:481` | `k8s_workload_posture_oracle` "is **NOT** wired into `verifier._run`" | It is — `verify/verifier.py:856-858` | 2 h total |
| `docs/FEATURES.md:773` | `crucible-blackboard-chain` is `owner_rooted=False`, `file_backed=False`, "NOT wired into the live engine" | `vigil_core/spine_domains.py:157` says `True`/`True`, and `:158-160` names the wiring | |
| `docs/FEATURES.md:587` | differential remediation "Implementation **deferred**" | `remediation/differential_adapter.py` ships it | |
| `docs/AS-BUILT-LIVE.md:119-121` | `Neo4jGraphStore` is a `[SCAFFOLD]` (every method raises) | Real client body issuing Cypher since H2 — `graph/store.py:340-400`; only construction without an injected driver raises, because the `neo4j` package is absent | |
| `docs/AS-BUILT-LIVE.md:140` | per-action signed approval token "**genuinely not built**" | `live/approval_token.py` (15 KB) + `live/approval_broker.py` (20 KB) + `vigil approve provision-authority\|list\|sign` (`cli.py:1812-1835`) | |
| `docs/AS-BUILT.md:102` | same Neo4j `[SCAFFOLD]` claim | same | |
| `DEVELOPER-HANDOFF.md:169` | "CI runs **six** jobs" | Ten | |
| `docs/CONTINUATION.md:108-157` | P5–P10 and I1–I5 listed as still to build; "do not run fused offense before P6" | All merged (see A-10 — this one is a blocker) | |
| `oracle_adapter.py:31-34` | live re-drive is "a documented refinement for a later slice" | `live_redrive` is an accepted FACT provenance today | |
| `capability-matrix/hexstrike.json:4` | "the JS-redirect branch is LEAD-only" | `open_redirect.js_sink` is `fact_capable: true` | |
| `V2-LIMITATIONS.md` items 6–7 | reconciled to 2026-07-11/12; "SSO/SAML, Kubernetes, service-mesh, mobile absent" | All four oracle families exist | |
| `improve/patcher.py:50` | proposes edits to `framework/playbooks/03-surface-mapping.md` | The file is `03-attack-surface-mapping.md` | |
| `docs/CONTINUATION.md:22` | standard is "NO scaffolds, stubs, demos, placeholder code" | `docs/DEFERRED-INFRA.md` formally registers three scaffolds. Needs an explicit carve-out for registered, honestly-labelled hardware/research gates, or a reviewer reads the contradiction as an overclaim | |
| **`.env.example:13`** | ships `NEO4J_AUTH=neo4j/change-me` | A default credential in a file an agency reviewer will read | |

### The constitution vs. the engine

| # | Item | Evidence | Size |
|---|---|---|---|
| B-39 | `CLAUDE.md` §VII mandates a `findings/NNN-slug.md` per finding and a row in `notes/command-log.md` per command. **No code writes either** — the engine writes the signed spine, the evidence tree and a JSONL log. Arguably better, but the two documents disagree and an agency reading the constitution will look for those files | verified | 1 d (reconcile the doc) |
| B-40 | `CLAUDE.md` §III.7 names `notes/{hypotheses,command-log,opsec,source-questions}.md`; `targets/_template/notes/` has no `opsec.md` and no `source-questions.md` | verified | 1 h |

### The declared capability ladder (`docs/capability-matrix/`)

This is the strongest single artifact in the repo and it should be shown to the agency directly: **26
evidence branches, each declaring `fact_capable`/`clean_capable` today vs. target, with a mandatory
`blocking_work` string for every gap, lint-enforced by `scanner/tests/test_claim_discipline.py`.**
Verified counts: 26 branches, **14 with an open clean-capability gap**, 17 carrying `blocking_work`, 6
carrying a `target_downgrade_rationale`. No branch has a gap without naming the engineering that closes it.

The recurring theme is honest and worth saying out loud: **VIGIL can prove the positive; the bounded
negative is the frontier.**

| # | Group | Blocking work | Size |
|---|---|---|---|
| B-41 | Body-decode completeness (3 branches: `open_redirect.body_markup`, `host_header.body_emission`, `oidc_redirect_uri.body_markup`) | A vendored spec-compliant WHATWG encoding-determination implementation (a regex is explicitly forbidden) + vendored, version-pinned, bounded streaming brotli/zstd decoders whose versions bind into oracle provenance | 3–4 w |
| B-42 | JS-sink CLEAN (`open_redirect.js_sink`) | Headless-browser `render_dom` observing actual navigation — lexing cannot prove a runtime-assembled redirect does not exist | 2–3 w |
| ~~B-43~~ **DONE (W16-STD-1)** | Insertion coverage | The `open_redirect` re-drive now synthesises cookie / urlencoded-body / JSON-body carriers and probes all five insertion surfaces (`web_redrive.py:_redirect_templates`); a JSON-body-only redirect is found and a clean target names its coverage in a bounded CLEAN. RESIDUAL: OIDC non-query `redirect_uri` remains query-only (opt-in SSO check). | ✓ |
| B-44 | Advisory-snapshot completeness (`version_range.manifest_membership`) | Resolve non-pinned constraints + record advisory-snapshot coverage so "no advisory matched" is a bounded negative | 1–2 w |
| B-45 | Artifact-completeness proofs (6 posture/IaC branches) | Per-branch enumeration manifests: full CIS control set per node role + kube-bench version manifest; every ClusterRoleBinding/RoleBinding + transitive `aggregationRule`; PeerAuthentication mTLS inheritance per workload; transitive reusable-workflow resolution; full policy/ACL/PAB/SSE/SG cross-link with intrinsics resolved; every policy/role/attachment/assume/member edge | 6–10 w |
| B-46 | Live-capture completeness (3 `cloud_live` branches) | Requested-vs-returned scope completeness record; plus, for cross-account, threading the charter's own-account id(s) into every retained control's `owner_account` | 2–3 w |
| B-47 | **46 of the 79 declared hexstrike tools are uncatalogued** — verified: 33 entries, of which exactly **2 are `fact_capable`** (nmap, sslscan), matching `external_tool.py:370,392` and `brains/hexstrike_body.py:50`. The other 46 are neither included nor excluded | 1–2 w |
| B-48 | `gobuster` — "existence+anon-reach is FACT-capable via a **future ACTIVE_EXPOSURE re-drive**; LEAD-only today" | 1 w |

### The Pwned Labs cloud roadmap (`docs/assessments/pwnedlabs/`)

E1–E5 merged today (stale — bucket 4). **P1–P4 checked against code, not the plan:**

| # | Item | Verified state | Size |
|---|---|---|---|
| B-49 | **P1** K8s secret-encryption-at-rest | **Not done** — no `identity`-provider / `EncryptionConfiguration` rule anywhere in `verify/oracles.py` | 3–5 d |
| B-50 | **P2** broader CIS coverage | **Not done** — `_INSECURE_SETTING_RULES` (`oracles.py:2076-2093`) is still the original 8 flags | 1–2 w |
| B-51 | **P3** named-subject over-permissive RBAC | **Not done** — `k8s_workload_posture` still fires only on `system:anonymous`/`system:unauthenticated` (`verify/k8s_workload_posture.py:47`) | 3–5 d |
| B-52 | **P4** named cross-account principal | **Half done** — the oracle is built and the adapter reads `owner_account`/`owner_accounts` (`verify/adapter.py:850-866`), but **no live sensor populates it** (zero hits in `sensors/cloud_live.py` and `integration/.../live/`), so it can never fire on a live capture | 1–2 d |
| B-53 | Deprioritised catalogue misses: IMDSv1-enabled, public snapshot-share, CloudTrail gaps, GKE legacy metadata, snapshot/RDS/EBS looting, KMS ransomware, CloudTrail tampering | An achieved-effect oracle each | 1–2 w each |

### Small named residuals (all verified still open)

| # | Item | Size |
|---|---|---|
| B-54 | `evidence/certify.py:498-507` — `engagements.discard("")` lets an empty-slug cert ride a named bundle (tracked LOW; defence-in-depth only) | 0.5 d |
| B-55 | `evidence/certify.py:492-496` — `refs_unique` has no producer-side guarantee; `proof/bundle.py:117` still falls back through `bug_class` | 1 d |
| B-56 | SIGIL cold-archive hard-prune **Slice E** genuinely unbuilt — `apps/sigil/sigil/spine/prune.py:1-4`: "NOTHING here deletes a live record or commits a head — Slice E wires these into the crash-safe cutover" | 1–2 w |
| B-57 | `apps/sigil/sigil/spine/manifest.py:72` — `manifest_sig` "reserved for the deferred signed-manifest tier"; the segment manifest is unsigned | 2–3 d |
| B-58 | `apps/sigil/sigil/cli.py:85-90` — "monotonic head guard deferred"; `sigil sign` exits 2 rather than resolving | 1–2 d |
| B-59 | `sensors/cloud_live.py:69` IAM trust-policy `Condition` evaluation deferred; `sensors/gcp_live.py:26` restricted-sharing org policy unresolved; `remediation/triage.py:12` live Neo4j deferred; `fsjob/traffic.py:7` live-traffic actions not implemented; `scanner/fingerprint.py:364,384` favicon corpus is future work | 1 w total |
| B-60 | M2 residual — coarse `tested_clear` roll-up needs per-probe `oracle_kinds_run` granularity in `standards.py` | 2–3 d |
| B-61 | R2 residual — HTTPS origin-SNI re-drive; `DifferentialHttpAdapter` is plaintext-HTTP only | 3–5 d |
| B-62 | FROST signature aggregation + OpenTimestamps anchoring (deliberate; does not change the m-of-n property) | 1 w |
| B-63 | **The readiness audit has no committed artifact.** The `MUST-FIX #1..N` and `readiness 2.1–2.10` numbering exists only in commit messages; items **2.4, 2.7 and 2.9 are unaccounted for** across the three commits on `readiness-should-fix`. I cannot verify what they are | 0.5 d |
| B-64 | `docs/VISION.md` roadmap, genuinely open: time-travel replay, autonomous provable pivots, multi-tenant/RBAC, finding-template marketplace, phased surface breadth, **LLM/AI-app red-teaming as an oracle-backed surface** (self-tagged high priority), session-omniscient copilot T2b | named programs |

---

## BUCKET 3 — DELIBERATELY DEFERRED, AND CORRECTLY SO

*With the sentence to say out loud when asked. The first six cannot be engineered away.*

| Item | Say this |
|---|---|
| **X1 — TEE / SEV-SNP / TDX attestation** (`attest/provider.py:149,162,177,238` stubbed) | "Hardware-gated. The software and TPM attestation providers are built and running; the confidential-computing backend needs silicon we don't have. It plugs into the same seam unchanged." |
| **H3 — the field record** | "It accrues only over real authorized engagements. The harness and runbook are built; you cannot manufacture a track record, and we won't pretend to." |
| **H4 — third-party external audit** | "The audit *package* is built and offline-verifiable by a party with none of our software. What's missing is an independent auditor, which is your side of the table, not ours." |
| **A1 / A3 / Z1 — third-party time-stamping, witnesses, zkTLS notary** | "The mechanism is built and shippable. What makes it meaningful is *independent operators*, and we won't stand up our own second signer and call it independence." |
| **AWS / GCP / Azure live-fire** | "Kubernetes is proven against a real k3s cluster. Cloud is proven against moto and LocalStack. Real-cloud proof needs your credentials in your account — that's the first thing we'd do in a pilot." |
| **H2 — live Neo4j deploy** | "The client body is built and issues real Cypher (`graph/store.py:340-400`); the embedded file-backed graph store is the working default. Only the external service is unprovisioned." |
| **X2 — general binary patch synthesis** (`remediation_binary/tier.py:117-123`) | "Research-gated. The narrow `strcpy` path is real and ASan-verified; general symbolic synthesis is an open research problem and we've labelled it as one." |
| **X3 — next-gen agent body** (`agent_body/interface.py`) | "Interface only, by design — Strix is welded to a different SDK, and a rewrite is a multi-week project with no security payoff." |
| **R4 — garak / PyRIT / promptfoo live-fire** | "The tools aren't installed. Verified absent, not assumed." |
| **E-series `clean_capable: false`** | "Correctly closed. All six carry a `target_downgrade_rationale`: proving *absence* of cloud exposure is a posture capability, not an exploitation branch's job. We refused to claim it." |
| **Post-exploitation is inference-only** (`engage.py:857-861` projects lateral paths; nothing walks them) | "By design and by rules of engagement. We prove a path exists; we don't walk it in your production." |
| **Mobile is passive-only** | "We ingest a MobSF report or a decoded manifest. No instrumentation, no traffic interception — say so rather than let the coverage table imply it." |
| **Source-code review has no SAST** | "The path is an LLM agent over the codebase (`vigil strix --target`), with no deterministic oracle behind it. It produces leads, not facts, and it's labelled that way." |
| **Scan stays serial; anti-defender evasion declined** | "Deliberate. A tool that evades the customer's own detection is not a tool a customer should buy." |

**A note on evidence tiers, because the agency will ask** (this one-line split is GENERATED from the
registry — see W16-STD-2(d) — not maintained by hand, which is why it can no longer drift as the earlier
prose here had):

<!-- BEGIN GENERATED coverage-tiers-sentence (source: docs/capability-matrix/coverage-tiers.json; regenerate: python3 docs/capability-matrix/gen_coverage_tiers.py) -->
Of the 43 registered oracle kinds (the ``OracleKind`` detector registry), 3 external (real bytes from a third-party target), 2 own-infra (real infrastructure the system builds and destroys), 14 loopback (a real local service over a real socket), and 24 fixtures-only (hand-written evidence). This split is GENERATED from docs/capability-matrix/coverage-tiers.json (keyed by the OracleKind registry) by docs/capability-matrix/gen_coverage_tiers.py — not maintained by hand — and docs/tests/test_coverage_tiers_drift.py asserts it matches the registry.
<!-- END GENERATED coverage-tiers-sentence -->

The external tier is testasp.vulnweb.com plus the GitHub live-fire; the own-infrastructure tier is the
k3s cluster (with negative controls); the fixtures-only tier is the cloud, mesh, CI/CD, mobile, identity,
SAML, TLS and version-range families. That is not a defect; it is the honest coverage statement, and
volunteering it is far stronger than being asked.

---

## BUCKET 4 — STALE / ALREADY DONE

*Closed. Stop worrying about these; do not let an older list resurrect them.*

**Closed by today's 14 merges** (all present in `main` @ `fa68f289`):

- **E1–E5 plus E4 TIER-2** — all six cloud/K8s exploitation confirmations (`#286`–`#293`). *(The capability
  is built and tested. Its invocation gap is A-8 — a different problem.)*
- **Supply-chain hardening** — hash-locked dependencies (both first-party locks), digest-pinned images,
  SBOM generation, `.trivyignore` with enforced written justifications, and a CRITICAL-blocking CVE gate
  **with a proven negative control** (`supply-chain.yml:245`).
- **`cryptography` CVE-2026-69247** — upgraded to 50.0.0 in both first-party environments. *(The vendored
  Strix lock still lags — B-11.)*
- **The WARDEN gate on Strix's shell is fail-closed.**
- **Kubernetes live-fire proven against a real k3s cluster** (`tools/livefire/`). *(Not in CI — B-6.)*
- **The sovereignty tier governs every LLM egress** (`vigil engage`, `patch`, console).
- **CI coverage extended** to veracity / kernel / planner / sensors / eval / defender / memory / analysis,
  and the RED flagship e2e test repaired.
- **Branch protection enabled with 9 required checks.** *(Its weaknesses are B-3/B-4.)*

**Closed earlier, still appearing on stale lists:**

- **P5–P10 and I1–I5 are all built and shipping** — the two-environment boundary, the hard egress gate
  (`gateway/vigil_gateway/{nftables,proxy,denylist}.py`), the WARDEN tool gate, the Claude runtime, the
  oracle confirmation pipeline, spine-signing, the challenge oracles, the witnessed transparency log,
  threshold destruction, SCITT/OpenVEX. `docs/CONTINUATION.md` still lists them as next — the *doc* is the
  defect (A-10), not the work.
- **`PathCertificate`** — built (`evidence/certify.py:152-165,431`), despite `VISION.md:119`.
- **Cloud/IaC provable privesc paths** — delivered by E2, despite `VISION.md:205`.
- **Differential remediation** — `remediation/differential_adapter.py` ships, despite `FEATURES.md:587`.
- **The live witness co-sign transport** — `vigil witness serve` (`cli.py:721-733`) +
  `infra/systemd/vigil-witness@.service`, despite `spine/witness.py:37-39`. Only third-party operators
  remain, honestly marked.
- **The remote-engage browser path / CDP request allowlist** — `scanner/cdp.py:226-233`
  (`enable_request_allowlist`, fail-closed), wired from `engage.py:693-694,770-772`, despite
  `scanner/campaign.py:299-300`.
- **`k8s_workload_posture_oracle` is wired** into `verifier._run` (`:856-858`), despite `FEATURES.md:481`.
- **The `crucible-blackboard-chain` is owner-rooted, file-backed and wired** into the live engine
  (`spine_domains.py:157-164`), despite `FEATURES.md:773`.
- **`Neo4jGraphStore` has a real client body** (`graph/store.py:340-400`), despite the `[SCAFFOLD]` claims
  in `AS-BUILT.md:102` and `AS-BUILT-LIVE.md:119`.
- **The signed per-action approval token is built** — `live/approval_token.py`, `live/approval_broker.py`,
  `vigil approve provision-authority|list|sign`, despite `AS-BUILT-LIVE.md:140`.
- **Console orphan routes cleaned** (B7/A6) — `console/tests/test_orphan_routes_b7.py` removed three while
  keeping the providers. That class of debt was paid.
- **`execute_sandbox` / `vigil sandbox` wiring and the G2 telemetry sidecar** — done (`#170`, `#171`).
- **`V2-LIMITATIONS.md` items 6–7 superseded** — the skip-marker count is wrong (255 skip lines now) and
  the "SSO/SAML, Kubernetes, service-mesh, mobile absent" claim is false; all four oracle families exist.

**In flight — excluded from this census by instruction:** PR #301 (readable case file), PR #302 (briefing
corrections), and local branches `readiness-should-fix` (the ten should-fix findings),
`engagement-library`, `dossier-v2-case-file`, `fix-claim-discipline-admit-frontier`. Note that
`case-file-contract` and `engage-case-file` have **zero commits** — planned, not started.

---

## BOTTOM LINE

**Is there anything left that would embarrass them in front of an agency? Yes — three things, and all
three are fixable this week.** The first is the governance replay gap (A-1): a genuine security defect in
the sovereign trust core, where a captured, legitimately-signed grant can resurrect a revoked promotion or
re-enable a disabled capability, and where the correct fix already exists eleven lines away in a sibling
file and simply was not mirrored. It is the one finding in this census that contradicts a claim the system
makes about itself, and it should be closed by the owner rather than discovered by the reviewer. The
second is `docs/CONTINUATION.md` (A-10) — the file that says "read this FIRST" — which still lists the two
FATAL-flagged safety gates as unbuilt; a reviewer who opens it will conclude the egress gate and the
two-environment boundary are missing from a product that has shipped both for weeks. The third is the
invocation gap (A-8): the six cloud and Kubernetes exploitation confirmations that merged today are real,
tested, and cannot be run by any command, route or button, so the honest current sentence is "we built six
confirmations that nothing can call." Alongside those sit three quieter credibility risks worth pre-empting
in the briefing rather than defending under questioning: the who/when attestation ledger is described as
always-on but is absent from the documented `python3 -m framework.v2 engage` path (A-3); enabling the cloud
sensors without two undocumented prerequisites yields a *silent clean result* rather than a refusal (A-9),
which is the worst failure mode for a product whose thesis is a sound negative; and ~900 green tests
covering the blackboard, the scope gate, the executor kill-switch and the spine floor are not run by CI at
all (B-1).

**How much work before this is a finished product rather than a strong one?** The security engine is
finished — that is the striking finding here, and it is worth saying plainly: stages 0–5 and 8–10 of the
promised lifecycle are implemented, the oracle layer is correctly wired with no routing gaps, schema
migration is transactional, the capability ladder is machine-enforced so no gap can be quietly sawn off,
and the veracity, gate, spine and evidence layers are genuinely strong. **What is unfinished is the
product around the engine, and it is concentrated in operations and governance-of-the-tool** — which is
the right place for it to be. Roughly: **1 week** closes the three embarrassments and the three
credibility risks (A-1 through A-4, A-8 through A-10, B-1 through B-6 are all hours-to-days). **4–6 weeks**
of one engineer gets you a deployable product for a single sovereign operator — that adds backup and
restore (A-5), a DR and key-rotation runbook, crash-resume, the retest document, the missing verbs, and
the documentation reconciliation. **Beyond that, two items are genuinely open-ended and neither is a
defect:** a multi-user model with separation of duties (A-7) is 4–8 weeks and changes the trust model, so
find out whether the agency actually needs it before building it; and the retention/erasure question (A-6)
needs a *policy decision* before a line of code — the append-only tamper-evidence guarantee and a
government erasure mandate are in direct tension, and whoever raises it first controls the framing. The
capability-ladder work in B-41 through B-48 is months, but it is the *frontier* — proving the bounded
negative — not a gap between what is claimed and what exists.

---

*Compiled by reading source. Working tree unchanged; test suites were run read-only and `git status` was
clean afterwards.*

---

# Addendum — 10 further items, found while writing the plain-English briefing

**Date:** 2026-08-13. **Method:** these were not found by auditing. They were found by *writing down
what the system does in plain English and then checking each sentence against the code and against
this machine* — which turns out to be an unusually effective way to find defects, because a claim a
document must state precisely is a claim someone finally has to verify.

None of these appear in the 78 items above. Severity is my own; the evidence is stated so it can be
disputed.

## A. The memory projections have drifted from the signed record — HIGH

The similarity index and the entity map were both built from a record far larger than the one now in
use. Measured on this host: the signed chain holds **16 entries**; the similarity index holds
**13,667 points with a high-water entry number of 43,350**; the entity map's own health note records
a rebuild at entry **43,332**. A live memory search returned citations numbered 41266 / 6584 / 38783
— **entry numbers that do not resolve against the current chain**.

Why it matters more than it looks: *citing the source* is the property the whole sovereign design
rests on. The mechanism is sound and tested — the gate re-fetches the cited record and checks the
quotation verbatim — but on this machine a citation can point at nothing. The chain itself verifies;
the two derived views are simply views of a record that is no longer there.

**Not the same thing** as the index legitimately holding fewer points than the record has entries:
only seven recall-valuable entry kinds are embedded by design, so index < record is normal and
expected. The drift here is the opposite direction and is not by design.

*Fix:* rebuild both projections from the current chain, or restore the record they were built from.

## B. The record on this host has no signed head — MEDIUM

The status check returns `no signed head`. The chain links cleanly, but nothing has attested "this
is the record and it ends here", so growth and truncation are indistinguishable to an outside
checker. This is an operational omission, not a code defect: the signing command exists.

## C. Curated-document ingestion is not idempotent — MEDIUM

Assistant transcripts, sub-agent transcripts and code commits are all cursor-guarded and safe to
re-run. The curated-document pass has **no cursor entry and no duplicate detection**, and the append
path does not de-duplicate, so a second run files every chunk again. It is opt-in rather than
automatic, which is the only reason this has not already polluted the record. The project's own
summary describes all four sources as incremental and idempotent; that is wrong for the fourth.

## D. The agent gate does not cover a registered, target-touching tool — HIGH

The gate in front of the vendored testing agent classifies `exec_command` and `write_stdin` at the
top tier — correctly, since every command-line invocation flows through them — and **everything else
at auto**. Its own comment says this "targets the shell and only the shell", which is honest about
scope but leaves a gap: the proxy tool `repeat_request` is **registered on the agent** and sends a
*modified* captured request to the target (its own documentation calls this an auth-bypass test). It
reaches the target over the network without going through the shell, so it auto-runs ungated.

*Mitigating control, not yet confirmed:* the sandbox is pinned to an internal network whose only exit
is the gateway, so gateway-level scope enforcement may still apply. **Someone should confirm whether
the gateway scope-checks proxy traffic.** If it does, this is a defence-in-depth gap; if it does not,
it is a scope-enforcement gap. `web_search` is auto for the same reason and is also outbound.

## E. The web-research crawl cannot be stopped mid-flight — MEDIUM

**Confirmed independently by a second reader, with a sharper account than the first.** The
point-at-a-URL learning path passes the emergency stop in as a cancel hook that aborts between page
fetches. The plain web-research path calls the crawler with no cancel argument at all, so the
constructor's "no hook" default applies and the loop's cancel check can never fire. Same subsystem,
same risk, one of two paths wired.

The nuance matters, and the first account missed it: **the emergency stop still bites at the end.**
A halted general research run files nothing, because the resulting proposal goes through the normal
governor path and is denied under the stop, with a refusal recorded. So the failure is not "a halted
run publishes anyway" — it is that **the already-queued pages are still fetched** after the owner has
pressed stop. Outbound requests continue against a halt; the record stays clean.

*Fix:* pass the same cancel hook on the general path. It is one argument.

## F. The query/passage embedding asymmetry is implemented but unused — MEDIUM (quality, not safety)

The embedding module defines a query-side function that applies the retrieval-instruction prefix the
model expects, and the search path calls the plain passage-side function instead. The asymmetry the
model was trained with is therefore lost on every search. This is a silent retrieval-quality defect:
nothing fails, results are just worse than they should be, which is the hardest kind to notice.

## G. Not every structural node in the entity map carries a provenance anchor — LOW

The schema's own documentation says each structural node stores an anchor back into the record. The
session, document and commit tables do. **The project table does not** — it holds a name and four
tallies. The blanket claim is broader than the schema delivers.

## H. A stored confidence value is never read — LOW

The promoted-fact payload carries a model-confidence field commented "may lower ranking, never
promote". Nothing in the gate, the promotion path or the query path reads it. The field is inert and
the comment describes behaviour that does not exist — which is worse than no comment, because a
reader takes it as a control that is operating.

## I. The consolidation pass writes no entity-map nodes — LOW (documentation)

The schema documentation's present tense implies the nightly pass adds semantic nodes. It does not:
the rebuild reads only structural record kinds, and promoted decisions, commitments and
contradictions are served by the recall tools alone. The absence of semantic node kinds is a
deliberate and defensible choice; the documentation implying otherwise is not.

## J. The nightly consolidation is not scheduled on this host — LOW (operations)

The scheduler units ship in the repository and are not installed here; the cursor shows hand runs
only, most recently 17 July. The live open-threads tool returns empty, consistent with the pass never
having run against the current record.

## K. The interface header does not reflow, hiding the primary action — LOW (usability)

Found while capturing screenshots of the four screens that had none. At the documented capture width
of 1600×900, when an alert chip is present in the header (here, "1 API key failing"), the header row
overflows instead of wrapping or shrinking, and the primary "New Assessment" button is pushed off
the right edge. The page gains a horizontal scrollbar, so nothing is permanently unreachable — but
the main call to action is invisible until the user scrolls sideways, which is not a thing people do.

Reproducible on every screen, since the header is global. It does not appear in the older
screenshots because no alert chip was present when those were taken. On a 1920-wide display it fits.

*Fix:* let the header wrap, or collapse the status chips to icons below a width threshold.

## L. The memory search index is readable by anything on the machine — HIGH

Surfaced by an adversarial reviewer checking a sovereignty claim, and reproduced directly:

```
$ curl -s http://127.0.0.1:6333/collections
{"result":{"collections":[{"name":"sigil_memory"}]},"status":"ok"}
```

No credential is asked for. A scroll request against that collection returns the indexed text of the
owner's own memory — the content of assistant conversations, commits and documents. The directory
holding the record is owner-only (`drwx------`), which is what the briefing rightly claims; the
search index built from it is not, because as deployed here it is a separate service listening on a
loopback port with authentication switched off.

Loopback is a real boundary and this is not remotely reachable. But "only the owner can read it" is
the claim the sovereign design rests on, and on this machine **any process running as any user on
this box can read the owner's memory** without asking anyone. Browser-based attacks on loopback
services are also a known class, which is why the phone bridge — a sibling service — implements an
origin allowlist specifically to resist them.

Note the shipped default is not this: the code's default is an embedded file-backed store with no
listener at all. A setting in the environment file switches it to the networked server, and that is
what is running here.

*Fix, in order of preference:* return to the embedded store; or enable the service's API-key
authentication and give the key to the indexer; or bind it to a socket the owner alone can open.
