# READINESS AUDIT — verification and synthesis

**Repo:** `/home/kali/vigil` · **HEAD:** `280d8d38` (= `origin/main`, in sync) · **Date:** 2026-08-12
**Role:** independent verifier over four upstream audit lenses. Every finding below was re-derived by
reading the cited source or executing the cited command. Findings that did not survive are recorded as
REFUTED, with evidence, because a false alarm in a readiness audit costs the operator more than silence.

**Standard applied** — this system's own doctrine:
1. A claim is a FACT only when a deterministic oracle fires over data a real target produced.
2. Refuse honestly, FAIL CLOSED. Hard limits are inviolable.
3. Never silently skip an authorized attack surface.
4. An audited overclaim is fixed by BUILDING THE CAPABILITY UP, never by softening the claim.

---

## 0. State correction — two upstream findings were already stale

The tree moved while the lenses were running. Recording this first, because two of Lens 2's three
top findings rest on a git state that no longer exists.

| Upstream claim | Reality at `280d8d38` | Verdict |
|---|---|---|
| "PR #296 is OPEN; the fail-closed commit exists only in the local tree" | `git log origin/main..HEAD` is **empty**. `280d8d38` is the merge of #296 and is `origin/main`. | **REFUTED — stale** |
| "PR #296's CI is RED (`integration two-env boundary (P5)` FAILURE)" | Fixed by `ed6a2c4d` ("use the fake SDK so it runs in the sovereign leg too"). Re-run by me: `PYTHONPATH=integration:gateway python3 -m pytest integration/tests/test_warden_gate.py -q` → **20 passed, 1 skipped**. | **REFUTED — fixed** |

The `ed6a2c4d` fix is also *correct in the doctrinal sense*, not merely green: it routes the control
through the module's existing `_install_fake_agents` helper so the mutation control is load-bearing in the
environment where the SDK is absent — precisely where the fail-closed path matters most. Relying on the
real SDK would have made the control silently skip there. That is rule 6 ("tests must be able to fail")
applied properly.

**What this does not rescue:** the branch-protection finding (§1) is independent of PR #296 and is fully
confirmed live.

---

## 1. MUST FIX BEFORE PRESENTING

### 1.1 — CRITICAL: the repo claims an enforced merge gate. `main` has no protection of any kind.

**Verified live, unauthenticated:**
```
GET /repos/thuram-nana/vigil-sovereign/branches/main/protection → 404 "Branch not protected"
GET /repos/thuram-nana/vigil-sovereign/rulesets                 → []
```

**The claims:**
- `docs/AS-BUILT.md:17-18` — "merged only after adversarial red-pen + all 6 required CI jobs green
  (required status checks are now enforced on protected `main` — nothing merges without them)"
- `README.md:514`, `:516` — "Required status checks are enforced on protected `main`."
- `.github/workflows/supply-chain.yml:15` — "CRITICAL -> BLOCKS the pull request."

Every CI check on this repository is **advisory**. Nothing blocks anything.

**The count is also wrong.** `.github/workflows/ci.yml` defines **8** jobs (`vigil-core:10`,
`crucible-core:23`, `gateway:57`, `integration:80`, `strix-vigil:212`, `sigil-governor:234`,
`formal-verification:291`, `warden-kernel:310`) plus `supply-chain.yml:48` = **9**. Three documents say
six.

**What a sceptical evaluator gets:** the single cheapest possible refutation of a process-integrity claim
— one unauthenticated API call, no clone required. It retroactively devalues every "merged & CI-green
behind the required checks" sentence in the repo, and this system's entire pitch is that its process
claims are verifiable. An evaluator who catches this will re-read every other claim as marketing.

**Honest counterweight, verified:** the A14 gate itself is *real*. `supply-chain.yml:270-277` runs
`trivy fs --severity CRITICAL --exit-code 1` over the locks, and the negative control at `:239-265`
executes that exact configuration against a known-CRITICAL fixture and hard-fails if it exits 0. The
mechanism is genuine; only the word "BLOCKS" is unearned.

**Fix (build up, do not soften):** enable branch protection, mark all 9 checks required, then correct
"6" → "9". Do not edit the sentence down.

---

### 1.2 — CRITICAL: the sovereignty ladder does not govern the engine the operator actually runs

This is the first question a national agency asks, and today the repo answers it three ways.

**The claim:** `README.md:159` — "**Sovereign / air-gappable** — runs on your hardware, under your key,
offline-capable" (one of five headline differentiators).
`engine/crucible/SECURITY.md:175-178` publishes a four-tier table promising which LLM backends each tier
permits; `:243` states "Sovereign deployments are NEVER PERMISSIVE."

**Verified call chain:** `cli.py:109` passes `api_key=None` → `wiring.py:494` `think(..., api_key=config.api_key)`
→ `think_claude.py:449` `_resolve_key(None)` → `think_claude.py:363` reads `ANTHROPIC_API_KEY` from the
environment → `think_claude.py:379` constructs `anthropic.Anthropic(api_key=key)` → direct egress to
`api.anthropic.com`.

**No tier is consulted anywhere on that path.** I grepped all of `integration/` for `sovereignty` /
`SOVEREIGNTY_TIER`: two hits, both unrelated (`offense_worker.py:88` is an error string about the
signing seam; `test_two_env_boundary.py:203` is a test assertion). The tier default is
`Tier.PERMISSIVE` (`kernel/sovereignty.py:165`), which that module's own header calls "equivalent to no
policy enforcement", with `anthropic` first in its preference order.

**The egress guard does not cover this.** `is_sovereign_mode()` / `egress_guard` are consumed only by
`framework/v2/agents/http_executor.py:61` and `framework/v2/intel/transport.py:168,197` — CRUCIBLE's own
httpx paths. The Anthropic SDK client is not routed through them, and no `HTTPS_PROXY` is set for it
anywhere in the tree (grepped; the only proxy references are `web_redrive.py:114` and
`apps/sigil/sigil/agents/sources.py:158`, both *disabling* proxy env vars). The nftables ruleset
(`gateway/vigil_gateway/cli.py:48-50`) targets the sandbox network, not the sovereign host process.

**`CRUCIBLE_SOVEREIGNTY_TIER` appears in zero install-path files** — not `bootstrap.sh`, not
`.env.example`, not `docs/DEPLOY.md`, not the systemd units. It exists only inside `engine/crucible/*.md`
and tests.

**What an evaluator gets:** they set `CRUCIBLE_SOVEREIGNTY_TIER=AIR_GAPPED`, believe the system is
constrained, run `vigil engage`, and the engine calls a US commercial cloud LLM. That is a documented
security control that does not cover the primary code path — the exact fail-open class this system
exists to eliminate, in the one dimension a national agency cares about most.

**Honest mitigations — say these out loud rather than let them be discovered:**
- With no key set, nothing egresses: `think_claude.py:462-467` falls to replay, then to `_safest`
  (deny-by-default). The system genuinely *can* run offline.
- What leaves when a key *is* set is a compact digest, not raw target bytes:
  `_build_messages` (`think_claude.py:195-227`) sends slug, phase, iteration, fact/lead **counts**,
  objective, and a redacted recent-actions digest — untrusted regions nonce-framed.
- Strix's upstream telemetry is genuinely removed (`vendor/strix/strix/telemetry/sink.py`), and the
  passive-intel collectors are opt-in behind a host allowlist (`framework/v2/intel/live.py`).

**Fix (build up):** consult `kernel.sovereignty` in `think_claude`/`wiring` and refuse a non-PERMISSIVE
tier from reaching `anthropic.Anthropic`; make `bootstrap.sh` require an explicit tier and persist it;
publish one operator-facing "what leaves this machine" page. Do not edit `README.md:159` down.

---

### 1.3 — HIGH: the shipped briefing says the most dangerous surface is fail-OPEN. It is fail-CLOSED.

The code fix landed (`280d8d38`) and is correct:
- `integration/vigil_integration/warden_gate.py:454-460` — `except Exception as exc: raise
  WardenGateUnavailable(...)`, with a message naming the cause and the deliberate opt-out.
- `vendor/strix/strix/core/runner.py:245-249` — only `except ImportError` is swallowed (bare vendored
  Strix, nothing to govern); every other failure propagates.

**Nine prose locations still state the opposite.** Lens 2 found five; there are **more**, because
`VIGIL-EXPLAINED.md` — the concatenated mega-briefing — carries every one of them a second time:

| File | Line(s) | Now false |
|---|---|---|
| `08-safety-and-authorization.md` | 757, 779-780, 1715 | "attached on a best-effort basis"; "**No warning is printed and nothing fails**"; listed as honest-limit #2 |
| `11-the-agents-and-learning.md` | 754, 767, 1298 | "deliberately best-effort"; "ungated, with no signal to the operator" |
| `02-the-parts.md` | 483 | "deliberately *best-effort*… falls back… silently" |
| `12-tools-and-what-you-need.md` | 391 | "falls back to the ungated original rather than stopping the scan" |
| `VIGIL-EXPLAINED.md` | 2185, 11580, 12538, 16961, 16974, 17505, 17930 | all of the above, duplicated |
| `00-glossary.md` | 156 | meta-claim: "the briefing names each such place" |

**What an evaluator gets:** the briefing hands them a written confession of a fail-open on
`exec_command`/`write_stdin` that no longer exists. Either they believe it and score the system down on
its own most dangerous surface, or they check the code, find the briefing wrong, and stop trusting the
briefing. The glossary line makes it worse by asserting the briefing is exhaustive about fail-open
places.

This is an **underclaim**, and `docs/CLAIM-DISCIPLINE.md:5-18` forbids that ratchet as explicitly as it
forbids an overclaim. Reverse all nine passages to "fails closed", keeping `VIGIL_WARDEN_STRIX_GATE=0`
described as the one visible, deliberate escape hatch.

---

### 1.4 — HIGH: the flagship end-to-end test is RED, and the anti-hallucination module is not in CI

**Reproduced:**
```
$ .venv-offense/bin/python -m pytest framework/v2/planner/tests/test_full_integration.py::test_full_pipeline_url_to_report -q
FAILED  assert tech_path.is_file()   # targets/<slug>/reports/technical.md
framework/v2/planner/tests/test_full_integration.py:218
```
This is the URL → attack-tree → agent-mesh → technical-report pipeline. The fixture asserts a
pre-hardening behaviour: it drives `bug_class="webhook_forgery"`, which is outside the oracle
vocabulary, so the confirmation is refused fail-closed, the critique agent raises objections, and the
reporter correctly never writes the report. **The veracity layer is working; the test is stale.**

**Why nobody saw it:** `ci.yml:45-55` names 20 explicit paths. Absent from that list:
`framework/v2/veracity`, `kernel`, `planner`, `sensors`, `eval`, `defender`, `memory`, `analysis`.
`veracity` is the anti-hallucination firewall — the module the whole product is named for.

**I ran the excluded suites:** `pytest framework/v2/veracity framework/v2/kernel -q` → **211 passed,
1 skipped** (`test_live_claude_code.py:38`, env-gated). So there is no hidden rot — moving them into CI
is cheap and safe, which makes the omission harder to defend, not easier.

**What an evaluator gets:** they clone, run the suite, and hit a failing flagship test on day one. There
is no `make test` target to tell them which subset is meant to be green (`Makefile` has
`setup/up/down/services/bench/smoke`). The natural conclusion — "your green CI does not cover your core
module" — is correct.

---

### 1.5 — HIGH: on a clean install, `vigil` writes findings, evidence and the governance key into `$HOME`

`framework/v2/common/paths.py:52-56` orders root-discovery candidates `sys.argv[0].parent` **before**
`__file__.parent`, walking up for a `CLAUDE.md` sentinel (`paths.py:26`).

**Two facts make this bite, and the second is worse than the upstream lens reported:**
1. `bootstrap.sh:354` installs the launcher as a **bare symlink** into `.venv-offense/bin/vigil`
   (`install_launcher()`, `bootstrap.sh:348-353`) — not a wrapper script, so no `CRUCIBLE_ROOT` export.
   `bootstrap.sh:35` exports it only into bootstrap's own process; `sigil.env` (`:318-331`) persists
   only `SIGIL_HOME`/`SIGIL_QDRANT_URL`; `.env.example` never mentions it.
2. **The repo root has no `CLAUDE.md` sentinel at all** — `ls /home/kali/vigil/CLAUDE.md` → no such
   file; only `engine/crucible/CLAUDE.md` exists. So the walk-up *cannot* stop at the repo. It runs past
   it to `$HOME`.

**Reproduced both ways, `CRUCIBLE_ROOT` unset:**
```
sys.argv[0] = /home/kali/.local/bin/vigil          → crucible_root() = /home/kali
sys.argv[0] = /home/kali/vigil/.venv-offense/bin/vigil → crucible_root() = /home/kali
target_dir('demo')                                  → /home/kali/targets/demo
```
(An earlier run of mine returned `/home/kali/Music/PENTEST/crucible` — that was contamination from
`CRUCIBLE_ROOT` set in my own shell. Recorded so the result is not mis-read.)

`bootstrap.sh:401` cannot catch this: its smoke test explicitly passes `CRUCIBLE_ROOT="$SMOKE_TMP"`
(with a hand-made sentinel), so the unset case is never exercised.

**What an evaluator gets:** a live demo on a clean box silently scatters engagement artifacts —
findings, evidence, reports, and the minted governance key — into the presenter's home directory. On a
host with no `~/CLAUDE.md` it instead raises `CrucibleRootNotFound` and the demo dies. Either outcome is
bad in a room.

**Fix:** one line — put `__file__.parent` before `sys.argv[0].parent` — or persist `CRUCIBLE_ROOT` in
`sigil.env`. Adding a repo-root sentinel alone is not sufficient while the ordering is argv-first.

---

### 1.6 — HIGH: the claim-discipline doctrine contains the exact overclaim it exists to forbid

`docs/CLAIM-DISCIPLINE.md:85`:
> "**A branch with no declaration may not produce a verdict.** This is enforced at RUNTIME, not by a
> lint: **every verdict passes through** `integration/vigil_integration/live/verdict.py::admit`…"

**Not true of the two production mint paths.** The system's own enforcement test allowlists them:
`engine/crucible/framework/v2/scanner/tests/test_claim_discipline.py:396` —
`_PENDING_MIGRATION = {"wiring.py", "external_tool.py"}`.

Those modules call `confirm_and_certify` directly — `external_tool.py:655`, `wiring.py:830`, `:936` —
and `confirm_and_certify` reaches `Outcome.CLEAN` with **no registry consultation**:
`oracle_adapter.py:268-269` (`verdict, _kinds = probe_verdict(result)` → `oc = Outcome.CLEAN if verdict
== "clean"`). `admit()` would have raised `UnregisteredBranch` or returned INCONCLUSIVE.

**Rule 8 ("Residuals are published, not buried", `:170`) is violated by its own document.** I grepped
`docs/CLAIM-DISCIPLINE.md` for `PENDING_MIGRATION`, `external_tool`, `wiring.py`, `frontier`: **zero
hits**. The frontier is named only in a test-file docstring (`test_claim_discipline.py:355-359`, which
is otherwise an exemplary explanation of why each module is pending).

**Honest bounding — verified, and it matters:** *no false CLEAN ships today.*
- `wiring.py:833` and `:939` discard everything but `res.finding_ref if res.is_fact` — no CLEAN escapes.
- `RunnerResult.outcomes` (`external_tool.py:475,661`) has **no non-test consumer**: I grepped
  `\.outcomes\b` across `integration/ engine/ packages/ apps/ gateway/` excluding tests — the only hit
  is an unrelated dict in `agents/executor_proto.py:89`.

So this is a **latent** hole plus a live doctrinal overclaim, not a live false FACT. It is in this
section anyway because of *where* it is: the document whose entire purpose is preventing overclaims
makes a universal claim its own test file refutes in the first five minutes of reading. `:199` does
hedge ("What it does **not** verify: that every verdict-producing code path calls `admit()`") — which
means the document contradicts itself 114 lines apart, and the enforcement bullet list at `:189-197`
omits the static routing guard (`test_claim_discipline.py:347`) that genuinely does exist.

**Fix (build up):** give each `Redrive` a `branch` field, route `external_tool.py` through
`verdict.admit()` + `certify_admitted` as `sbom.py` already was, then delete it from `_PENDING_MIGRATION`
— the anti-rot assert at `:412-416` already forces that hygiene. Until that lands, `:85` must name the
frontier.

---

## 2. SHOULD FIX SOON

**2.1 — `docs/capability-matrix/hexstrike.json` advertises a soundness bug the code no longer has.**
`:51` states "the capture **does not process Content-Encoding or the declared charset**… a realistic
false-CLEAN on ordinary CDN infrastructure" and "The JS-redirect branch is **LEAD-only**… needs a real
JS tokenizer." Both stale: `integration/vigil_integration/live/body_decode.py` implements WHATWG charset
determination + bounded gzip/deflate with `body_semantically_available` gated on complete
reversal (its own docstring at :4-9 quotes that same sentence as the *motivation for the fix*), and
`engine/crucible/framework/v2/scanner/js_lex.py:301 sink_is_executable` is that tokenizer —
`open_redirect.js_sink` is declared `fact_capable: true`.
*Correction to the upstream lens:* its claim that "Body-derived branches are not CLEAN-capable" is also
false is **wrong** — I checked the registry: `open_redirect.body_markup`, `open_redirect.js_sink` and
`oidc_redirect_uri.body_markup` are all still `clean_capable: false`. That half of the matrix is
accurate. Likewise, `test_claim_discipline.py:494-496` does **not** pin the stale text — it requires the
substring `"not clean-capable"` or `"lead-only"`, and "not clean-capable" remains true. Fix the two
genuinely stale sentences (`:4` and `:51`); add a *lag* assertion to complement `:481`, which today only
checks the matrix does not exceed the registry.

**2.2 — `veracity/firewall.py`'s docstring is wrong in both directions, in the same docstring.**
Overclaim at `:2` — "admit(): the one choke point every claim must cross." I grepped
`worldmodel/graph.py` for `admit`/`firewall`: **zero hits**; `add_node` (`:101`) has no admission gate.
Underclaim at `:28-31` — "this is the caller-less PRIMITIVE… Until then admit() is exercised only by its
tests; that is by design, not a gap." False: production callers include `agents/cognitive_refusal.py:44`,
`agents/critics.py:70`, `aegis/pipeline.py:132`, `report/grounding.py:54`, `evidence/certify.py:247`.
A reviewer opening the flagship anti-hallucination module reads a universal claim in sentence one and a
"not wired yet" disclaimer two programs out of date in sentence twenty-seven.

**2.3 — `spine_domains.py:18-22` contradicts the machine-checked data below it.** The prose says the
offense-spine is `owner_rooted=False` today and "**Only** `offense-finding-anchor1` is
`owner_rooted=True` among the offense segments." The `DOMAINS` tuple says **three** are:
`offense-finding-anchor1` (`:114`), `offense-spine` (`:125`), `crucible-blackboard-chain` (`:157`) — and
`verify_registration()` (`:229-232`) *enforces* `owner_rooted ⟺ a named consumer`. Underclaim, in the
crypto substrate.

**2.4 — `docs/AS-BUILT.md` contradicts itself about the Strix gate, 74 lines apart.** `:21` says
"gated by default" (correct — `warden_gate.py:448` is `if not _strix_gate_on(): return base_hooks`, an
opt-*out*). `:95` says "*gateable*, **not** gated by default"; `README.md:532` repeats the wrong half.

**2.5 — The "authoritative map of what is merged" is silent on everything merged today.** Grep across
`docs/AS-BUILT.md`, `README.md`, `docs/FEATURES.md`: `supply-chain`/`hash-lock`/`SUPPLY-CHAIN` → **0 hits
in all three**; `gcp_sa_impersonation`/`iam_escalation`/`k8s_rbac` → **0 hits**. A14 (#294), E2–E5
(#288–#293) and the cryptography CVE upgrade (#295) are invisible in the status map. An agency that asks
"show me your supply-chain hardening" and is handed `AS-BUILT.md` will not find it.

**2.6 — The ENFORCED claim-discipline lint covers 3 files; rule 3 says "any document".**
`test_claim_discipline.py:466-467` parametrises exactly `docs/CLAIM-DISCIPLINE.md`,
`docs/capability-matrix/hexstrike.json`, `docs/capability-matrix/evidence-branches.json`.
`README.md`, `AS-BUILT.md`, `FEATURES.md`, `SUPPLY-CHAIN.md` and the plain-english chapters — the
documents the agency actually reads — are outside it, while `:95` claims "**Any document**" and `:197`
summarises enforcement as "capability-describing documents contain no unqualified absolute claims."
Either widen the list (doctrine-compliant) or name the three files.

**2.7 — A registry branch no code path can cite.** `cloud_live.cloud_posture.cross_account_principal`
(`evidence-branches.json:337`) appears in **no non-vendor Python source** — verified by grep.
`cloud_live_posture.py:60-61` declares only `_BRANCH_CLOUD` and `_BRANCH_POLICY`, and every cross-account
FACT is admitted under `_BRANCH_CLOUD` (`:241`). Consequences: the declared precondition
`owner_account_supplied` (`:344`) is never evaluated by admission, and every cross-account certificate is
attributed to a branch whose declared evidence describes encryption/public-flag state. **Not a live
false FACT** — the oracle fails closed internally (`oracles.py:2600-2601`, `if owner_accounts:`) — but it
is a missing defence-in-depth layer and a mis-attribution. One edit: a third branch constant keyed on
`observed["rule"] == "named_cross_account_principal"`.

**2.8 — The E-series has no entry in the deferral runbook.** `docs/DEFERRED-INFRA.md` has sections
G1, X1, X2, X3, H3, H4, R4 and Phase 0.2 — verified by listing its `^## ` headings — and **no E-series
section**. The five branches' live-fire deferral is disclosed only in `evidence-branches.json`
`limitation` strings and module docstrings. "Have you ever run the cloud exploitation suite against a
real cloud?" is question one; the answer must be in the runbook, with provisioning steps and pass
criteria.

**2.9 — The plain-English briefing is not in the repository.** `git ls-files docs/plain-english` returns
**0** of 18 entries; it is untracked, not gitignored (`git check-ignore` returns nothing). A clone the agency
receives contains none of it — including `07-signing-and-keys.md` (per-key table with a "what happens if
it is lost" column) and `08-safety-and-authorization.md`. *Mitigating, verified:* no tracked document
links to `docs/plain-english`, so this creates no broken links — it is a packaging/handover gap, not a
dangling reference. Commit it (after the §1.3 corrections) or ship it as a separate signed deliverable.

**2.10 — A14 hardening does not cover the operator's install path.** `docs/SUPPLY-CHAIN.md:245-249` is
admirably honest that `ci.yml` installs unpinned ranges. It omits the bigger case: **`bootstrap.sh` —
the only documented install path — also installs unpinned.** `envs/build_envs.sh:14-23` runs
`uv pip install -r` / `pip install -r` over `envs/offense.txt` and `envs/sovereign.txt`, which are five
`-e ./…` editable lines each with no hashes; transitive deps resolve live from PyPI. The hash-locked
`infra/supply-chain/sovereign.lock.txt` and `framework/v2/requirements.lock.txt` are consumed **only** by
`.github/workflows/supply-chain.yml:125-182`. So the locks are proven installable in CI and are never
what an operator installs. Extend the honest-scope note to `bootstrap.sh`, or install from the locks.

---

## 3. HONESTLY DEFERRED — present these as deliberate limits, in these words

These are defensible. Say them plainly and first; each is stronger stated by the operator than
discovered by the evaluator.

**3.1 — Cloud/K8s exploitation oracles are fixture-proven, not live-fired.**
> "Five of the six E-series oracles have never touched real cloud transport. The runner, admission,
> certificate and world-model wiring are complete and proven offline against fixtures; real-transport
> live-fire is deferred on an operator-provisioned lab credential. We have not claimed a live cloud FACT
> and none exists in our evidence store."

**3.2 — IAM privilege escalation is deliberately never live-fired.** Lead with this one; it is the
strongest soundness argument in the registry (`evidence-branches.json:464`).
> "A defensive verification oracle never executes the escalation. We prove the grant path exists; we do
> not use it. That is a design commitment, not a missing feature."

**3.3 — Insertion-point coverage is query and path only.** `web_redrive.py:168-178` builds a bare GET
template, so cookie, urlencoded-body and JSON-body parameters are unexamined — declared as
`blocking_work` on seven branches.
> "Our web re-drive currently probes query-string and URL-path insertion points. Cookie and request-body
> parameters are declared unexamined in the capability registry rather than silently skipped — if you
> have a redirect on a POST body, we will report it as uncovered, not as clean."
This is the **highest-ROI closeable gap** in the registry; consider closing it before the meeting if
time allows.

**3.4 — CLEAN over an operator-supplied artifact is scoped to that artifact.** Ten branches
(version_range, CIS controls, RBAC bindings, mesh/CI-CD/IaC posture, live cloud posture).
> "For an exported artifact we claim exactly 'this artifact declares X'. We do not claim completeness of
> the export itself. Closing that needs a coverage manifest per surface, which we have specified and not
> built."

**3.5 — A statically-undecidable JS redirect cannot be proven absent.**
> "Our JS sink analysis is FACT-capable — a real tokenizer, not a regex — but a runtime-assembled
> redirect is undecidable statically, so `js_sink` will never assert CLEAN. Absence there requires DOM
> rendering, which we have not wired."

**3.6 — Brotli/zstd bodies decode to INCONCLUSIVE, not CLEAN.** Ordinary CDN traffic will land here.
> "We decode gzip/deflate and determine charset the way a browser does. Brotli and zstd need a
> version-pinned streaming decoder bound into oracle provenance, which we have not vendored — so those
> responses are INCONCLUSIVE. We chose an honest abstention over a decode we cannot attest."

**3.7 — GCP service-agent cross-project attribution stays a LEAD.**
> "Any allow/deny list of Google service agents is fail-open, because Google adds agents. A benign agent
> would produce a false FACT, so we hold it at LEAD until an authoritative registry or a charter-supplied
> allowlist exists."

**3.8 — Hardware- and third-party-gated items.** Confidential-computing silicon, a live external
Neo4j/OTLP service, independent third-party time-anchoring and witness co-signing, and a field record on
diverse real targets. All already tracked in `docs/DEFERRED-INFRA.md`.

**3.9 — `engine/crucible/framework/v2/sbom.json` is a scaffold.** Its
`metadata.tools[0].name = "scaffold (operator regenerates with cyclonedx-bom)"` and
`timestamp 0000-00-00T00:00:00Z`. Already correctly disclosed in the briefing.

---

## 4. What I checked and found clean

Stated because a padded audit is its own dishonesty.

- **No fabricated capability anywhere across four lenses.** Every code path opened matched its
  docstring's *mechanism*. Every defect above is staleness, scope, or wiring — never invention.
- **The A14 negative control is real and substantive** (`supply-chain.yml:239-265`): it runs the exact
  blocking trivy configuration against a known-CRITICAL fixture and hard-fails if it exits 0.
- **The CRITICAL-blocks / HIGH-advisory threshold is honestly argued** at `docs/SUPPLY-CHAIN.md:191-195`,
  with the reasoning stated rather than hidden.
- **`veracity` and `kernel` suites are green** (211 passed, 1 env-gated skip) — the CI gap is an
  omission, not concealment.
- **The stale-"not-yet-wired"-docstring sweep is otherwise empty** — `firewall.py` is the only live
  instance across `engine/ integration/ packages/ apps/ gateway/`.
- **`docs/CLAIM-DISCIPLINE.md` is unusually well-calibrated about itself** — `:29-33` pre-emptively
  narrows its own enforcement claim; `:163-168` explains why rule 7 is `[REVIEW]` rather than claiming
  enforcement it lacks. §1.6 and §2.6 are the two places its self-description outruns its tests.
- **TODO/FIXME sweep clean** across ~1,100 non-vendor files (the only matches are the scanner's own
  detection *pattern* for such comments, `scanner/passive.py:583,589`).
- **The fail-closed reflex is real where it counts** — `wiring.py:832-834`, `:937-940`
  (`except Exception → return None`, "an oracle/cert error confirms nothing"), `oracle_adapter.py:262-266`
  (unknown-class → labelled lead, never a clean negative), `sovereignty.py:155-160` (an unknown tier name
  fails closed to AIR_GAPPED). The defects above are the exceptions to a genuinely disciplined pattern.

---

## 5. Bottom line

**Not ready today — but the gap is one working session, not one release.** Six items must land first:
branch protection (§1.1), the sovereignty wiring (§1.2), the nine inverted prose passages (§1.3), the red
flagship test plus `veracity` into CI (§1.4), the `paths.py` ordering (§1.5), and naming the
`_PENDING_MIGRATION` frontier in `CLAIM-DISCIPLINE.md` (§1.6). Five of the six are hours of work; only
§1.2 is a genuine build. Nothing in this audit touches the architecture, and no fabricated capability
was found anywhere across four independent lenses — the system's core discipline (oracle-confirmed FACTs,
signed evidence, fail-closed gates) held up under adversarial reading. What did not hold up is the
*perimeter*: process claims that outran the process, documentation that outran or lagged the code, and
CI that did not cover the module the product is named for.
