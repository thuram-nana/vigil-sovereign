# E — Today's landings, and the four exhaustive catalogues

**Purpose.** A verified reference for the chapter writers. Every statement below was checked against
source code in `/home/kali/vigil` and is cited `file:line`. Where a document in this repository
disagrees with the code, the code wins and the disagreement is named.

**Repository state when this was written.** `main` = `origin/main` = `05b81e9f` ("Merge pull request
#308 from thuram-nana/wire-dossier-label"). **`main` moved four times during the compilation of this
file** — PRs #306, #301, #307 and #308 all merged mid-session. Corrections that follow from that are
flagged with **[MOVED]**.

**How to read the honesty markers used throughout:**

| Marker | Means |
|---|---|
| **BUILT** | code exists and is unit-tested |
| **EXERCISED (loopback)** | adjudicated over bytes a real local process produced over a real socket on this host |
| **EXERCISED (own infra)** | adjudicated over bytes real infrastructure the system itself creates and destroys produced |
| **EXERCISED (external)** | adjudicated over bytes a real third-party system on the public internet produced |
| **FIXTURE** | only ever adjudicated over evidence a human wrote by hand |

---

## PART 0 — WHAT ACTUALLY LANDED (verified merge by merge)

`git log --oneline --merges` on `main`. The task brief listed twelve items; all twelve are confirmed
present, and three more landed while this was being written.

| PR | Merge | Subject | Verified how |
|---|---|---|---|
| #286–#293 | `ebeea24e`…`1487e03a` | The six E-series cloud/Kubernetes confirmations | `OracleKind` members at `engine/crucible/framework/v2/verify/models.py:256,274,295,314,336` + `verify/models.py:102` (TIER-1); registry rows at `verify/verifier.py:258,264,268,275,282` |
| #294 | `dc2994d6` | Supply-chain hardening | `.github/workflows/supply-chain.yml` (287 lines, new); `infra/supply-chain/{sovereign.in,sovereign.lock.txt,image_pins.py}`; `.trivyignore`; `integration/tests/test_supply_chain.py` |
| #295 | `3f44debc` | `cryptography` upgraded past CVE-2026-69247 (HIGH) | `engine/crucible/framework/v2/requirements.in:46` `cryptography>=50,<51`; `packages/core/vigil_core/pyproject.toml:9` `>=50`; `apps/sigil/requirements.txt:1` `==50.0.0`; `infra/supply-chain/sovereign.in:40` |
| #296 | `280d8d38` | WARDEN gate on the arbitrary shell made fail-closed | `integration/vigil_integration/warden_gate.py:423-460` — `attach_from_env` now raises `WardenGateUnavailable` instead of returning ungated hooks |
| #297 | `02b65ea5` | Kubernetes live-fire against a real k3s cluster | `tools/livefire/k8s_rbac_livefire.sh` (117 lines) + `.py` (157 lines) |
| #298 | `fa68f289` | Docs matched to reality | docs only |
| #299 | `d927fa87` | CI coverage extended + a RED flagship test repaired | `.github/workflows/ci.yml:46-54` (`CRUCIBLE_UNCOVERED_SUITES`) + `ci.yml:65-96` (a *collection guard*) |
| #300 | `e342b4ed` | Sovereignty tier governs every model call | `integration/vigil_integration/live/think_claude.py:203-244`; `engine/crucible/framework/v2/console/actions.py:1740`; `engine/crucible/framework/v2/kernel/llm.py:148` |
| #303 | `15287183` | Readiness "should-fix" doc corrections | docs only |
| #304 | `e4d1be2a` | Console dropped the check-library flag | `engine/crucible/framework/v2/console/actions.py:331-339` |
| #305 | `9438b6b8` | GitHub secret-validity live-fire against real `api.github.com` | `tools/livefire/secret_github_livefire.{sh,py}`; `integration/vigil_integration/live/live_transport.py`; `live/secret_runner.py` |
| #302 | `e9ef6597` | Briefing corrections | docs only |
| **#306** | `b9ca10e3` | **[MOVED]** Engagement library (past jobs, human labels, credentialed console) | `engine/crucible/framework/v2/console/labels.py` (new, 204 lines); `console/api.py` +176 |
| **#301** | `37090acd` | **[MOVED]** The readable numbered case file | `engine/crucible/framework/v2/report/case_file.py` (new, 1819 lines) + `catalogue.py`, `plainspeak.py`, `runinfo.py`, `adapt.py`, `authorization.py` |
| **#307** | `380bbe33` | **[MOVED]** Anti-replay high-water on five signed governance ledgers | `apps/sigil/sigil/governor/{killswitch,promotion,capability}.py`, `apps/sigil/sigil/mesh/registry.py`, `apps/sigil/sigil/governor/authn.py:16-31`, `apps/sigil/sigil/spine/snapshot.py` |
| **#308** | `05b81e9f` | **[MOVED]** Engagement label wired into the downloaded case file | `console/actions.py` +14 |

**Nothing is left open.** `gh pr list --state open` returned three PRs at the start of this session
(#301, #306, #307); all three have since merged. There are now no open pull requests.

### 0.1 Corrections the writers must apply to earlier inventories

1. **`docs/plain-english/_inventory/A-findings-and-bug-classes.md:811-814` is now STALE.** It says E4
   (Kubernetes RBAC) and E5 (exposed-secret validity) are "offline-wired, live-fire deferred". Both
   have since been live-fire proven. E1 (metadata credentials) and E3 (GCP impersonation) remain
   correctly described as deferred.
2. **`docs/plain-english/_review/OUTSTANDING.md:397-403` — the evidence-tier census — is now stale
   in two ways**, both corrected in Part 4 below: it names `BOOLEAN_INFERENCE` as the externally-
   adjudicated SQL-injection oracle (the run record says `differential_response`), and it predates
   the GitHub live-fire.
3. **`OUTSTANDING.md:456` excludes PRs #301/#302 "by instruction" and treats #307 as in flight.** All
   are merged. Do not describe any of them as pending.

### 0.2 The three today-landings that most need careful wording

**The WARDEN shell gate (#296).** The previous code caught *any* exception during wiring and returned
the ungated hooks, on the reasoning that a wiring error must never stop a scan. Its own new docstring
is the honest description and is worth quoting almost verbatim to an official
(`integration/vigil_integration/warden_gate.py:434-439`): the effect was "an UNGATED shell with NO
signal to the operator — an accident, not a decision, and indistinguishable from a healthy governed
run." There remains exactly one way to run ungated deliberately: setting
`VIGIL_WARDEN_STRIX_GATE` to `0`/`off`/`false`/`no` (`warden_gate.py:276-286`).

**The console check-library defect (#304).** `launch_scan` accepted `use_library: bool = True` and
never read it, so every scan started from the interface ran the built-in checks only and never the
declarative library. **The library holds exactly 172 entries** (counted:
`ls engine/crucible/framework/v2/scanner/library_entries/*.json | wc -l` → 172), spanning 23 distinct
weakness categories, the largest being boolean SQL injection (21), information exposure (20),
cross-site scripting (18) and command injection (17). The fix is `console/actions.py:338-339`. Say
plainly what the defect was: nothing failed, nothing errored, and the report looked reasonable — it
was simply drawn from a narrower corpus than a reader would assume.

**The anti-replay guard (#307) [MOVED].** Five signed *last-writer-wins* governance records carried
no anti-replay field, so an old, genuinely-signed record could be re-appended verbatim to resurrect a
revoked state: the signature is real and the hash chain extends cleanly, so every check the system had
passed. The five are `governor.killswitch`, `governor.capability`, `governor.promotion`, `mesh.device`
and `mesh.host_capability`. The fix puts `issued_at` inside the *signed core* and gives each fold a
per-key high-water (`apps/sigil/sigil/governor/killswitch.py:34,66-72,106-127`;
`promotion.py:33,42-55,87-98`; `apps/sigil/sigil/mesh/registry.py:47-49,62-74,111-128`). Two points an
evaluator will value: **only the dangerous direction is gated** — engage, disable, revoke and
revoke-device carry a fixed `issued_at` of `0.0` and are honoured exactly as before, because gating a
fail-*safe* direction would convert it into a fail-*open*; and the parser is fail-closed against a
signed-but-insane value — a NaN would poison the guard permanently, so NaN and infinity both map to the
bottom (`apps/sigil/sigil/governor/authn.py:19-31`).

---

## PART 1 — EVERY WARDEN TIER, EXHAUSTIVELY

### 1.1 What WARDEN is, in one paragraph

WARDEN is the authorization kernel: the single chokepoint every tool invocation crosses. It classifies
the tool into one of four tiers from its *name*, derives a fail-closed gate decision from that tier,
and — after the caller has run or blocked the tool — appends a signed, hash-chained record of what
happened. Its own header states the boundary: "WARDEN never executes tools itself; it decides and it
records" (`apps/sigil/kernel/src/warden.rs:1-4`).

There are **two implementations of the classifier and they are pinned to each other**: a Rust one in
the sovereign kernel (`apps/sigil/kernel/src/tiers.rs`) and a byte-faithful Python port
(`packages/core/vigil_core/vigil_core/warden_tiers.py`). Both load the same golden vector file
(`packages/core/vigil_core/vigil_core/warden_golden.json`) in their own test suites, so a divergence
fails one side's test — they cannot silently drift (`tiers.rs:185-197`).

### 1.2 The four tiers

| Tier | Rust name / meaning | Gate decision | What it permits | Examples that classify here |
|---|---|---|---|---|
| **A0** | Observe / answer — memory queries, screen read, voice reply (`tiers.rs:14`) | **auto** (`tiers.rs:174`) | Runs immediately, un-queued | `memory.search`, `graph.query`, `http.get`, `dns.query`, `port.list` |
| **A1** | Reversible internal act — write a report, draft a branch, raise an alert (`tiers.rs:16`) | **auto**, and logged | Runs immediately, recorded | `memory.write`, `brief.compose`, `hid.pointer.move` |
| **A2** | External-visible / semi-reversible — send email, calendar write, purchase under cap (`tiers.rs:18`) | **queued** (`tiers.rs:176`) | Does not run until a human approves | `email.send`, `memory.export`, `memory.dump`, `hid.type` |
| **A3** | Destructive / financial / security (`tiers.rs:20`) | **explicit-required** (`tiers.rs:177`) | Does not run without an explicit, per-action authorization | `git.push`, `data.delete`, `secrets.read`, `iam.policy.write`, and *anything unrecognised* |

The tiers are **ordered** (`A0 < A1 < A2 < A3`, `warden_tiers.py:24-30`), which is what makes "raise
only" expressible as an arithmetic maximum.

### 1.3 How a name is classified — the exact algorithm

`warden_tiers.py:103-123` / `tiers.rs:142-170`, in order:

1. **Tokenise.** The name is split into *whole tokens* on `.` `_` `-` `/` whitespace **and** the C0
   information separators U+001C–U+001F, then lowercased ASCII-only (`warden_tiers.py:88-100`;
   `tiers.rs:132-138`). Whole tokens, never substrings — so `overwrite` is not `write` and `forget`
   is not `get`. The control-character separators are split deliberately so `read.log\x1cdelete`
   cannot hide a `delete` behind an invisible byte. Both files carry the same proof sketch: every
   dictionary token is itself delimiter-free, so *more* splitting can only ever expose a danger token,
   never break one apart — danger exposure is monotone.
2. **Empty → A3.**
3. **Danger first.** Any token in the A3 set → **A3** (`warden_tiers.py:41-52`; `tiers.rs:64-79`).
   **72 tokens**, in five groups: destructive verbs (`push deploy delete destroy drop remove purge
   wipe truncate overwrite erase format kill shutdown reboot reset disable enable override force sudo
   exec eval chmod chown patch install uninstall`); crypto and restore (`encrypt decrypt restore
   revert rollback recover`); financial (`spend purchase pay payment transaction transfer refund
   invoice allocate budget release sign`); security / identity / infrastructure **targets**, dangerous
   regardless of verb (`secret secrets credential credentials token tokens key keys iam policy
   firewall acl role grant revoke rotate escalate infra prod production env master root admin`); and
   secret stores (`vault keyring keychain keystore hsm`).
4. Any token in the A2 set → **A2** (`warden_tiers.py:55-58`). **21 tokens**: `send email smtp publish
   post message outbound webhook sms notify share upload invite calendar tweet dm export dump download
   sync`.
5. Any token in the A1 set → **A1** (`warden_tiers.py:61-64`). **12 tokens**: `write note brief report
   draft alert consolidate commit branch annotate tag label`.
6. Exact-name gesture-input tables: four pointer names → A1, three keyboard/launch names → A2
   (`warden_tiers.py:79-80`). Checked *after* the danger pass, so `hid.pointer.delete` is already A3.
7. **A0 only by positive allowlist** — one of 17 safe read verbs (`read search query get list status
   recall observe answer view show find frame peek describe inspect lookup`) or one of 8 exact
   read-only memory tool names (`warden_tiers.py:67-76`).
8. **Everything else → A3.** Not-positively-classified is the same as dangerous.

**The property to put in front of an official:** absence of danger is *not* sufficient for automatic
execution. A name must be positively recognised as safe, or it is treated as maximally dangerous.
`tiers.rs:213-218` pins `""`, `"weird"` and `"something.unclassified"` all to A3.

The unit tests in `tiers.rs:221-284` are themselves good briefing material, because they are the list
of mistakes the design refuses to make: `config.overwrite` is A3 not A1; `budget.get` is A3 because the
*target* is financial; `secrets.read` is A3 not A0; `memory.encrypt` is A3 ("ransomware-shaped op must
NOT be A0"); `entity.merge` is A3 because an irreversible rewrite has no honest safe verb;
`memory.export` is A2 because bulk egress must be human-seen; `snapshot.restore` is A3 because a
restore silently reverts state.

### 1.4 Floor, ceiling, and the pin — the three things that can move a tier

| Mechanism | Where | Direction | Why it is safe |
|---|---|---|---|
| **Registry pin** | `apps/sigil/kernel/src/registry.rs:54-60` | **Raise only** — effective tier is `max(pin, inferred)` | The pin file (`~/.sigil/warden/tools.json`) is unsigned plain text a file-write attacker could edit. Raise-only means editing it can only make a tool *more* gated. `registry.rs:73-75` pins the test: an attacker pinning `git.push` to A0 still gets A3. Case-colliding keys resolve to the **higher** tier, never last-writer-wins (`registry.rs:40-47`) |
| **Floor** | `integration/vigil_integration/warden_gate.py:60,124` | **Raise only** — `tier = max(classify(name), floor)` | Offence tool names read *low*: `http.get`, `dns.query`, `port.list` all contain an A0 verb and would auto-run. Default offence floor is **A2** (`warden_gate.py:60`), so nothing offensive auto-runs on a live target |
| **Ceiling** | `warden_gate.py:61,126` | Caps what may auto-run | Default offence ceiling is **A1**. With an A2 floor and an A1 ceiling, **every offence tool queues for owner approval** — offence never auto-runs |

The auto-bar is A1 (`warden_gate.py:62`): auto requires `tier <= A1` **and** `tier <= ceiling`.

### 1.5 What happens when something is refused

Three distinct outcomes, and the distinction matters (`warden_gate.py:83-93,99-131`):

| Outcome | Trigger | Effect |
|---|---|---|
| `auto` | tier at or below both the auto-bar and the ceiling | The call runs |
| `queue` | tier ≥ A2, or above the ceiling | The call is routed to the per-action approval broker and **waits**. A valid, single-use, owner-signed token for *this exact call* lets it run once. No authority provisioned, or no token inside the window, and it is blocked (`warden_gate.py:239-265`) |
| `deny` | empty name, or a name on the hard denylist | Raises `WardenDenied` immediately; never runs, never queues |

Fail-closed behaviour is explicit at every branch: an unknown classifier output is treated as A3
(`warden_gate.py:121-122`); an unrecognised floor value is treated as A3 (`warden_gate.py:123`); the
subprocess kernel classifier returns A3 on a missing binary, timeout, non-zero exit or unparseable
output, and **refuses to execute a bare `sigil-kernel` name resolved through `PATH`** because an
attacker who plants a binary there would control tier decisions (`warden_gate.py:150,157`); an
approver that raises is a block, not a pass (`warden_gate.py:257-260`).

### 1.6 The specific gate on the agent's arbitrary shell

The autonomous agent (Strix) has one chokepoint through which every command-line invocation flows —
`exec_command`, with `write_stdin` streaming into a still-running one (`warden_gate.py:322-328`). The
gate classifies **exactly those two names as A3 and every other Strix tool as A0**
(`warden_gate.py:331-336`), so the agent's benign, sandbox-contained tools (thinking, notes, todo, web
search, patch application, reporting, image viewing) keep running while its shell is governed. Floor
A0, ceiling A1 (`warden_gate.py:452`). It is **on by default** for any governed run, no opt-in
(`warden_gate.py:280-286`).

**This is the surface #296 hardened.** A wiring failure now stops the run
(`WardenGateUnavailable`, `warden_gate.py:454-460`).

### 1.7 The recording half

After the decision, WARDEN appends a signed record — agent, tool, argument hash, tier, decision,
approver, result hash, timestamp — to a hash-chained action log
(`apps/sigil/kernel/src/warden.rs:44-59`). `verify()` re-checks the whole log against the persisted
public key (`warden.rs:61-63`), and `head()` exposes the signed `(count, head_hash)` used as the
anti-rollback anchor (`warden.rs:70-72`). On this host that log exists and holds real records:
`~/.sigil/warden/actionlog.jsonl` (5,590 bytes) plus `actionlog.head.json`.

### 1.8 The offence-side classifier, stated honestly

`vigil engage` does not use the Rust binary by default. It uses a pure in-process function
(`integration/vigil_integration/live/wiring.py:85-99`) that **derives its danger determination from
the shared classifier of record** (`has_danger_token`, `warden_tiers.py:126-131`) and then applies its
own offence vocabulary: a curated, danger-free reconnaissance name (`nmap httpx nuclei ffuf curl
subfinder gau katana`, `wiring.py:82`) is A1; anything carrying a danger token is A3; everything else
is A2. The important property is that the *danger* half can never drift from the kernel — only the
benign half is local.

---

## PART 2 — EVERY WEAKNESS TYPE AND EVERY DETECTOR KIND

### 2.1 The exact counts, computed from the registries

Run against `main` @ `05b81e9f` with the offence virtualenv:

| Quantity | Count | Source |
|---|---|---|
| Detector kinds (`OracleKind` members) | **38** | `engine/crucible/framework/v2/verify/models.py:31-337` |
| Canonical weakness categories (`BUG_CLASS_ORACLES` rows) | **85** | `verify/verifier.py:33-283` |
| Spelling aliases folded onto those 85 | **190** | `verify/verifier.py:284-519` |
| Total recognised vocabulary (categories + aliases) | **275** | `verifier.known_bug_classes()` |
| The frozen fallback set for an *unrecognised* category | **15** | `verify/verifier.py:531-547` |
| Detector kinds reachable *only* through an explicit category row | **23** | 38 − 15 |
| Declarative check-library entries | **172** | `scanner/library_entries/*.json` |
| Distinct weakness categories those entries cover | **23** | counted from the same files |

**Every one of the 38 detector kinds is referenced by at least one category row** — there are no
orphans (verified programmatically).

### 2.2 Why the "frozen 15" matters, and how to explain it

`verify/verifier.py:522-547` carries the reasoning verbatim. When a finding arrives with a category
the system does not recognise, it is run against a *fallback* set of detectors. That fallback is
**hard-coded to the fifteen detectors that existed before the defensive and posture families were
added**, and is deliberately *not* derived from the enumeration. Had it been derived, every later
addition would have silently grown the set every unknown finding is tested against, changing the
benchmark's output. The 23 later detector kinds are reachable **only** through their own explicit
category row, and each of those rows is keyed on an evidence field no ordinary scan produces
(`imds_capture`, `secret_capture`, `k8s_control`, `jwt_token`, `saml_xml`, `request_payload`, …). This
is the mechanism by which adding a capability provably cannot perturb existing results.

### 2.3 The 15 core detector kinds (production-reachable for any finding)

| # | Kind | What it means in plain words | What it proves | What it deliberately does NOT prove |
|---|---|---|---|---|
| 1 | `differential_response` | The system answered differently to a true statement than to a false one | The input reaches a decision the system makes | Nothing about *what* was reached |
| 2 | `achieved_state` | A state that should have been unreachable was reached | The unauthorised state occurred | Not how it occurred |
| 3 | `side_effect` | A unique marker planted in the input turned up somewhere it should not | Data crossed a boundary | Not code execution |
| 4 | `oob_callback` | A blind probe caused the target to call a listener the system controls | The target initiated an outbound connection under attacker influence | Not what it could reach |
| 5 | `sanitizer_signal` | A memory-safety tool, panic or traceback fired in the target process | The program entered an undefined state | Not exploitability |
| 6 | `timing` | A statistical hypothesis test over repeated timings, not a fixed threshold: Mann-Whitney U plus an effect-size floor plus Holm-Bonferroni across parameters (`verify/tests/test_timing_oracle.py:1-8`) | An injected delay is real under jitter | Refuses a significant-but-tiny drift on purpose |
| 7 | `boolean_inference` | A Wald sequential probability ratio test over repeated true/false probes, with a per-round control for pages that simply change every request | The behaviour tracks the injected truth value | Not the content behind it |
| 8 | `reflection_context` | A marker reached a place in the page where a browser would execute it | The output context is executable | Not that a browser executed it |
| 9 | `evaluation` | The server computed an expression it was given | Server-side evaluation happened | Not what else can be evaluated |
| 10 | `error_signature` | A datastore or parser error a specific payload provoked | The payload reached that parser | Not data extraction |
| 11 | `dom_execution` | Injected JavaScript actually ran in a real browser | Execution, not mere reflection | Only for the drivable path |
| 12 | `service_reachability` | A real transport handshake completed | The port is open at capture time | Nothing about later |
| 13 | `tls_weakness` | A real handshake negotiated a deprecated protocol or weak cipher | The server accepts it | Does not enumerate every legacy suite it *might* accept |
| 14 | `version_range` | A pinned version provably falls inside a pinned advisory's affected range | Membership | Absence from a pinned snapshot is **not** absence of vulnerability |
| 15 | `policy_path` | A real permission path exists from a principal to a resource | Reachability | Not that anyone walked it |

### 2.4 The 23 restricted detector kinds

Grouped by family. All are reachable only via an explicit category row.

**Defensive (AEGIS — pointed inward at the operator's own application), 4:**

| Kind | Proves | Does NOT prove | Line |
|---|---|---|---|
| `prompt_injection` | An injected instruction provably flipped a structurally-detectable behaviour, control against treatment | Not "the model was jailbroken" | `models.py:56` |
| `system_prompt_disclosure` | A planted high-entropy sentinel appeared verbatim in the application's own model output | Proves the secret leaked, not how | `models.py:57` |
| `automated_access` | A non-interactive client fetched a honeypot resource nothing in the human interface links to | Proves **automation**; the alias `automated_scraping` is deliberately folded onto this rather than being its own confirmable class (`verifier.py:370-372`) | `models.py:58` |
| `credential_stuffing` | One source achieved statistically significant successful logins across many previously-unseen account/source pairs | A failed-only burst — carrier-grade NAT, for instance — produces no test round and stays a lead | `models.py:59` |

**Request-side parse proofs (judged on the request alone, no response), 3:**

| Kind | Proves | Line |
|---|---|---|
| `sql_injection_breakout` | A value provably closes a SQL string literal and introduces query *structure* | `models.py:64` |
| `command_injection_breakout` | A value contains an unambiguous shell command-execution construct | `models.py:65` |
| `nosql_injection_breakout` | A known MongoDB query operator appears as a *key* where a scalar was expected | `models.py:79` |

All three prove an **attempt**, never exploitation: an application that parameterises its queries is
still safe. The negative controls are named in the source and are excellent briefing material — a
price `$5.00`, an email address, a regex `^admin$`, a mid-word `$` in `pass$word`, and an operator
appearing as a data *value* rather than a key all correctly do not fire (`models.py:66-79`).

**Posture — configuration re-derived offline, zero calls to anything, 8:**

| Kind | Domain | Fires only when | Line |
|---|---|---|---|
| `k8s_posture` | Kubernetes control plane | A CIS control failed *and* its recorded observed value literally carries a dangerous flag | `models.py:89` |
| `k8s_workload_posture` | Kubernetes RBAC, name match | An **anonymous** subject is bound to a dangerous built-in role. The benign `system:public-info-viewer` binding every cluster ships does not fire | `models.py:102` |
| `cloud_posture` | Cloud configuration | Encryption-at-rest explicitly false on a sensitive store, an explicit public flag, or a literal wildcard principal | `models.py:147` |
| `mesh_posture` | Service mesh | Permissive/disabled mutual TLS, an allow-everyone authorization policy, or an all-unauthenticated inbound default | `models.py:164` |
| `cicd_posture` | Build pipelines | A third-party action pinned to a mutable ref, a `pull_request_target` that checks out untrusted code, or an untrusted expression interpolated into a shell step | `models.py:177` |
| `mobile_posture` | Mobile applications | An embedded private key that **actually loads** as unencrypted key material | `models.py:188` |
| `email_auth_posture` | Email spoofing policy | Published DMARC `p=none`, SPF `+all`, or a resolvably-absent DMARC policy | `models.py:202` |
| `identity_posture` | Identity provider exports | A privileged identity with multi-factor provably absent, or a credential past its rotation policy | `models.py:216` |

The mobile row deserves quoting: the adversarial design review ruled *nearly every* mobile signal a
lead, because Android's cleartext, SDK-version and export-default rules form a precedence chain a
manifest alone does not settle. The one thing that survived is an embedded private key, and the
detector proves it by **loading the key material**, refusing on an encrypted key, a public key, a
certificate or a masked blob (`models.py:178-188`).

The identity row shows the same discipline: an *absent* multi-factor flag **refuses**, it never asserts
absence; privilege is never inferred from a role name, it must be attested by the producer
(`models.py:203-216`).

**Structural forgery — proved from a captured artefact offline, zero forged traffic, 2:**

| Kind | Fires on | Explicitly out of scope | Line |
|---|---|---|---|
| `sso_assertion_forgery` | A JSON web token with `alg=none`, an HMAC signature recomputable from a supplied or weak key, or an RS256→HS256 algorithm confusion | SAML wrapping is not attempted here | `models.py:114` |
| `saml_structural_forgery` | The consumed assertion carries no signature, every signature reference points at something else, or the wrapping shape | Full XML digital-signature canonicalisation is deliberately not attempted — that needs libraries this build does not carry, and anything softer stays a lead | `models.py:130` |

**Live-capture achieved effects, 6 — the E-series, and the flagship of today:**

| Kind | Confirms | The anti-laundering gate | Line |
|---|---|---|---|
| `active_exposure` | A resource whose *configuration* says public is genuinely reachable by an anonymous client — a bounded credential-free GET returning 2xx with a body | The GET is the capture; the pure detector is the sole authority over it | `models.py:227` |
| `imds_credential_capture` (E1) | Cloud instance credentials were retrieved from the metadata endpoint **and** proven usable | Gates on the credential's **source host**, parsed with a real URL parser, never substring containment — so a look-alike host, a query-parameter address or a credentials file are not a metadata reach | `models.py:256` |
| `secret_credential_validity` (E5) | An exposed secret is **valid** — a confirming call authenticated it as a real identity | Gates on the **confirming endpoint** against a per-type allow-list, plus a fingerprint binding the confirming call to the captured secret. The exposure *source* is retained as evidence but is deliberately **not** a firing gate, because E5 asserts validity, not provenance | `models.py:274` |
| `gcp_sa_impersonation` (E3) | A principal minted a token as a named target service account, and a confirming call echoed **that** identity | Confirming-side only: an allow-listed Google introspection endpoint, over verified TLS with no proxy and no redirect, and the echo must equal the named target — an echo of a *different* service account does not confirm | `models.py:295` |
| `iam_escalation_primitive` (E2) | Retained permission statements grant an **unconditional escalation primitive** from a fixed, auditable set, that **strictly increases** what the principal can reach | An explicit differential of two reachability closures: the target must be reachable in the escalation-closed closure and **not** in the base closure. A condition, a `NotAction`, an explicit deny, a restricting boundary or a non-covering resource wildcard each contribute **no** edge | `models.py:314` |
| `k8s_rbac_verb_grant` (E4 tier 2) | A binding **and, separately, the role it names** prove a dangerous verb/resource grant to an occupiable subject | The subject gate, described below | `models.py:336` |

### 2.5 The single best control story in the codebase

`K8S_RBAC_VERB_GRANT` (`models.py:317-336`) is the example to put in the briefing, because it shows
the system refusing to fire on the most common legitimate configuration in real Kubernetes.

An anonymous subject may confirm on any dangerous shape. But the namespace-default service account and
`system:authenticated` may confirm **only** on a genuine full-wildcard grant delivered through a
cluster-wide binding. The reason is stated in the source: the built-in `admin` role *legitimately*
grants get/list/watch on Secrets, and cluster-read backup and monitoring roles *legitimately* grant
`*/*` read. So "let this application own its own namespace" — the single most common delegation in
Kubernetes — must stay a lead. A naive detector would flag it as critical on a completely normal
cluster.

**And this is exactly what the live-fire run measured against a real cluster** (Part 4.3).

### 2.6 Notes the writers will need on the 85 categories

- The 85 canonical categories are not 85 different detectors: many share one. `achieved_state` alone
  backs 24 categories (`idor`, `bola`, `bfla`, broken access control, mass assignment, open redirect,
  CORS, host-header injection, four GraphQL denial-of-service categories, four SSO categories, business
  logic, and more).
- Several pairs are *deliberately* kept distinct rather than aliased, and the source explains each:
  `jwt` (acceptance proved live) versus `jwt_forgeable` (forgeability proved offline)
  (`verifier.py:239-244`); `sqli` versus `sqli_attempt`; `iam_privilege_escalation` (reachability, via
  `policy_path`) versus `iam_escalation_primitive` (achieved strict-gain escalation) — with a note that
  the aliases were audited for overlap so no finding is silently re-routed to the weaker detector
  (`verifier.py:514-519`).
- The alias table is a real anti-hallucination control, not convenience: it is used with pydantic
  validators so an *invented* category cannot ride in on a structured model output
  (`verifier.py:549-575`).

---

## PART 3 — EVERY KEY AND EVERY SIGNATURE

### 3.1 The primitive

One algorithm, one library. Ed25519 from `pyca/cryptography`
(`packages/core/vigil_core/vigil_core/crypto.py:14-24`), with the stated rule "We do not roll our own
crypto" (`crypto.py:5`). Two hardening details worth a sentence in the briefing:

- **Non-canonical public keys are rejected.** A y-coordinate at or above the field prime is refused,
  because the library would otherwise accept it and preserve its bytes, giving one point several
  encodings and an identity ambiguity (`crypto.py:43-70`).
- **Low-order public keys are rejected.** A low-order point admits a *keyless* signature forgery — the
  identity point with a zero scalar verifies for any message — so such a key could forge signatures for
  its own identifier. The libsodium blocklist is checked sign-bit-agnostically (`crypto.py:49-73`).

Threshold verification counts **distinct** authorisers with a valid signature and compares to the
threshold, with a defence-in-depth floor so that a hand-mutated trust root claiming a threshold below 1
still cannot be satisfied by zero signatures (`crypto.py:101-124`).

**Domain separation.** Every signing purpose prepends a distinct tag, so a signature made for one
purpose can never verify as another. The registry of tags is
`packages/core/vigil_core/vigil_core/spine_domains.py:77-88`; the full set found in the tree:

| Tag | Purpose | Defined at |
|---|---|---|
| `crucible-evidence-v1\x00` | Evidence certificates and signed chain heads | `vigil_core/canonical.py:14` |
| `crucible-authority-v1\x00` | The signed engagement authority | `engine/.../authority/canonical.py:19` |
| `crucible-entitlement-v1\x00` / `crucible-revocation-v1\x00` | Capability grants and their revocation | `engine/.../entitlement/canonical.py:33-34` |
| `crucible-proposal-v1\x00` | Self-improvement proposals | `engine/.../improve/canonical.py:19` |
| `sigil-floor-v1\x00` | The durable anti-rollback floor | `apps/sigil/sigil/spine/floor.py:89` |
| `sigil-witness-roster-v1\x00` | The witness roster | `apps/sigil/sigil/spine/witness.py:79` |
| `sigil/spine-field/v1` | Field-level encryption of spine payloads | `apps/sigil/sigil/spine/envelope.py:45` |
| `vigil-delegation-v1\x00` | Owner delegation of a governance key | `vigil_core/delegation.py:38` |
| `vigil-transparency-checkpoint-v1\x00` | Witness countersignature | `integration/.../transparency.py:53` |
| `vigil-destruction-authorization-v1\x00` | m-of-n destruction authorization | `integration/.../destruction_gate.py:79` |
| `vigil-peraction-approval-v1\x00` | Per-action owner approval token | `integration/.../live/approval_token.py:55` |
| `vigil-identity-attestation-v1\x00`, `vigil-capability-v1\x00`, `vigil-capability-attenuation-v1\x00`, `vigil-capability-wielder-pop-v1\x00` | Target identity policy, re-verification capability, its narrowing, and proof of possession | `vigil_core/spine_domains.py:84-87` |
| `vigil-oob-receipt-v1\x00` | Out-of-band callback receipts | `engine/.../verify/oob.py:54` |
| `vigil-zktls-channel-binding-v1\x00` | Channel binding to a TLS session | `integration/.../channel_binding.py:63` |
| `vigil-authority-envelope-v1\x00` | The "the AI stayed in bounds" envelope | `integration/.../posture/authority.py:34` |
| `vigil-remediation-cert-v2\x00`, `vigil-remediation-prove-cert-v1\x00`, `vigil-remediation-freshness-challenge-v1\x00`, `vigil-attestation-witness-time-v1\x00` | Remediation certificates, re-proof, freshness challenge, witness time | `integration/.../remediation/*` |
| `vigil-witness-producer-submit-v1\x00` | Producer submission to a witness service | `integration/.../witness_service.py:141` |
| `vigil-core/sealing/v1` | Authenticated encryption of secrets at rest | `vigil_core/sealing.py:38` |
| `vigil.e1.imds.credential-fingerprint.v1\x00`, `vigil.e5.secret.credential-fingerprint.v1\x00` | Credential fingerprints — deliberately distinct so an E1 and an E5 fingerprint can never collide even for identical bytes | `live/imds_runner.py:39`, `live/secret_runner.py:51` |

### 3.2 Every key, exhaustively

| Key | What it signs or protects | Where it lives | Created how | Held by | If lost | Third-party verification |
|---|---|---|---|---|---|---|
| **Owner key** (the 1-of-1 sovereign trust root) | The spine head, the durable floor, the witness roster, owner delegations, transparency checkpoints, all governance events (promotions, kill-switch release, capability grants, device authorisations), and the per-action approval token | `~/.sigil/spine/keys/owner.priv` + `.pub` (`apps/sigil/sigil/config.py:93`) | Generated once, on the owner's first signing action; verification never mints it (`apps/sigil/sigil/governor/identity.py:5-8`) | The owner, sovereign side only. Never crosses to the offence process | Everything owner-signed becomes unverifiable and no new governance event can be minted. There is no recovery mechanism in the code | Anyone holding the public key can verify any of it offline |
| **Offence governance key(s)** (m-of-n) | Evidence certificates, the finding anchor, the blackboard chain head | Provisioned per engagement (`integration/.../live/wiring.py:112-124`) | `generate_keypair()` at provisioning | The offence side | Existing certificates still verify; new ones cannot be minted | `verify_certificate` with the trust root (`evidence/certify.py:254`) |
| **Offence spine key** (stable, one per deployment) | The checkpoint spine, executor records, detection certificates | `<base_dir>/offense-spine.key`, mode `0600` (`live/spine_identity.py:31`) | Load-or-create on first use (`vigil_core/keystore.py:29-46`) | The offence process only | The prior spine becomes unverifiable — which is precisely the pre-fix failure this key exists to close (`spine_identity.py:1-11`) | `live/spine_verify.py:verify_offense_spine`, deriving the trusted key from an owner-signed delegation |
| **Operator key** | The usage-attestation ledger (who, when, what) | Sealed with context `b"vigil/operator.key"` (`attestation/identity.py:45`) | Same shared load-or-create helper | The offence side | The ledger becomes unverifiable | Public key only; **honestly not owner-rooted today** (`spine_domains.py:143-149`) |
| **WARDEN kernel key** | The action log | `<dir>/keys` beside the log (`apps/sigil/kernel/src/warden.rs:29`) | Load-or-create on kernel open | The sovereign kernel | The action log becomes unverifiable | `Warden::verify()` against the persisted public key |
| **Device keys** (phone, 1-of-N) | Each request the phone makes to the desktop bridge, and each approval it gives | On the device. **The phone never holds the trust-root key** (`apps/sigil/sigil/mesh/registry.py:5-9`) | Generated on the device; the **owner** authorises the public key with a signed ledger record | The device | That device can no longer approve; the owner revokes and re-pairs | The bridge verifies against the owner-minted authorised-device set (`apps/sigil/sigil/bridge/envelope.py:1-8`) |
| **Witness keys** (transparency log) | A countersignature that a new checkpoint consistently extends the previous one | Independent witnesses | Per witness | Independent operators | Split-view detection weakens | `verify_witnessed` (`transparency.py:234`) |
| **Destruction authorisers** (m-of-n, owner mandatory) | An authorization for one irreversible action | Immutable deployment configuration (`destruction_gate.py:94`) | Provisioning | The owner plus independent authorisers | No destructive action can be authorised — fail-safe | `authorize_destruction` (`destruction_gate.py:231`) |
| **Notary key** | A co-signature over a channel-bound response | A notary | Provisioning | A notary | The channel-binding evidence loses its independent leg | `verify_channel_binding_evidence` (`channel_binding.py:237`) |
| **Key-encryption key (KEK)** | Wraps **every** at-rest secret and private key | Sealed to this machine's TPM; only the sealed public and private blobs touch disk (`vigil_core/kek.py:31-32`) | `provision_kek`, once per machine | Nobody — it is never in plaintext at rest | Every sealed secret becomes unopenable. **There is no plaintext fallback**: a TPM that cannot unseal raises rather than degrading confidentiality (`kek.py:12-16,110-134`) | Not applicable; this is confidentiality, not signing |

### 3.3 The six signed append-only records, and which reach the owner

`vigil_core/spine_domains.py:109-190` is a registry with a self-check that makes an overclaim
*impossible to write down*: a segment may declare `owner_rooted=True` **if and only if** it names the
specific function that consumes the owner tie, and `verify_registration()` refuses the registry
otherwise, in **both** directions — an underclaim is refused too (`spine_domains.py:215-240`).

| Segment | Signer | Reaches the owner? | Offline-verifiable? | Consumer |
|---|---|---|---|---|
| `sovereign-spine` | Owner | **Yes** | Yes | `spine/checkpoint.py:verify_checkpoint` |
| `offense-finding-anchor1` | Offence governance (m-of-n) | **Yes** | Yes | `finding_receiver.from_delegation` |
| `offense-spine` | Offence spine | **Yes** | Yes | `live/spine_verify.py:verify_offense_spine` |
| `crucible-blackboard-chain` | Offence governance | **Yes** | Yes | `live/spine_verify.py:verify_blackboard_chain` |
| `offense-usage-ledger` | Operator | **No** — stated, not glossed | Yes | none |
| `continuous-attestation-log` | Offence governance | **No** — the trust root is pinned by the caller out of band; no delegation consumer derives it | Yes | none |

**Four of six reach the owner. Two do not, and the file says so in its own docstring**
(`spine_domains.py:26-29`).

### 3.4 What an evidence certificate is, precisely

`verify_certificate` checks **four independent things**, and the certificate is sound only if all four
hold (`engine/crucible/framework/v2/evidence/certify.py:5-18`):

1. **Authenticity** — an m-of-n governance signature over the certificate's canonical bytes.
2. **Binding** — the certificate's digest matches the evidence presented, so a signature cannot be
   lifted onto different evidence.
3. **Artefact integrity** — every raw file in the manifest still hashes to its recorded digest.
4. **Reproduction** — the pure detector **re-fires** over the retained evidence and matches the claimed
   verdict.

Signing is provisioning-only and offline; the runtime **only ever verifies** (`certify.py:16-17`). That
sentence is worth reproducing in the briefing verbatim.

### 3.5 The three authorization tokens, and how they differ

| | Per-action approval token | Destruction authorization | Delegation certificate |
|---|---|---|---|
| Quorum | 1-of-1, the owner | **m-of-n with the owner mandatory** | 1-of-1, the owner |
| Binds to | `(tool, target, digest-of-arguments)` | `(engagement, target, blast class, action id)` | `(role, scope, authoriser set, threshold, expiry)` |
| Window | Bounded, with a policy-capped lifetime | Same — a pre-signed long-lived "sleeper" is void | `not_after` only |
| Single use | Yes — one nonce, burned atomically by an `O_EXCL` file create, so of N concurrent callers exactly one wins | Yes, same mechanism | No — it is a bearer certificate |
| Can it widen scope? | **No.** It upgrades a WARDEN *queue* to *allow* and nothing else. A refusal for scope, kill-switch or budget is a *deny*, not a *queue*, and is returned untouched | No | It narrows, never widens |
| Verification key | **Pinned at deployment**, not per call — a per-call key identifier could be renamed to a compromised worker's own registered identifier | Same, and the mandatory-signer set is likewise fixed at deployment | The owner public key |
| Source | `live/approval_token.py:1-42,166,208,275` | `destruction_gate.py:1-56,231,297` | `vigil_core/delegation.py:89,115` |

Two honest limits the source itself states. The destruction gate's action identifier is **opaque to the
gate**: binding it to the real command depends on the signer computing it and the executor re-deriving
it, and the gate never sees the command (`destruction_gate.py:31-35`). And a delegation has **no
pre-expiry revocation** — `not_after` is its only bound, so the owner must size that window to the
shortest practical horizon (`delegation.py:29-31`).

### 3.6 Encryption at rest — and the honest state of it on this machine

The primitive is ChaCha20-Poly1305 authenticated encryption with a domain tag and a caller-supplied
context bound into the authenticated data, so a blob sealed as an owner key cannot be opened as an
operator key (`vigil_core/sealing.py:16-23`). A fresh 96-bit random nonce per seal, with the
volume assumption stated explicitly (`sealing.py:25-29`).

**On this host, right now, sealing is not active.** Verified directly:

- `/dev/tpm0` and `/dev/tpmrm0` **exist**, but `tpm2-tools` is **not installed**, so `tpm_available()`
  returns false and the key-encryption key cannot be provisioned (`kek.py:70-74`).
- There is no `~/.sigil/vault/` directory.
- `~/.sigil/spine/keys/owner.priv` is 44 bytes, mode `0600`, in a `0700` directory — **plaintext behind
  file permissions only**.

The code is honest about this posture rather than hiding it: "the DEFAULT is PLAINTEXT at rest (`0600`)
until the vault is provisioned … `vault.status()` reports the unsealed state loudly"
(`live/spine_identity.py:17-21`). The one-time operator setup is named in `kek.py:12-16`:
`sudo apt install tpm2-tools` plus adding the user to the `tss` group. **Writers must not describe
at-rest encryption as active in this deployment.**

### 3.7 The transparency log's guarantee is conditional — say so

`integration/vigil_integration/transparency.py:11-21` is unusually careful and should be quoted rather
than paraphrased. Split-view resistance — an operator being unable to obtain witness approval for two
different versions of history — holds **only when the witness set is a strict majority** (`2·threshold
> n`). Below that, and in particular at `threshold == 1` which the trust model permits, two disjoint
quorums can each countersign a different fork with no witness ever equivocating. What remains is
per-witness non-equivocation and **detection after the fact**, not prevention. The code provides three
distinct functions so a caller must choose which claim it is making: `verify_witnessed`,
`verify_split_view_resistant`, and `is_split` (`transparency.py:234,274,301`).

---

## PART 4 — THE EVIDENCE TIERS (the census, corrected)

**This is the number an evaluator will ask for.** The earlier census in
`docs/plain-english/_review/OUTSTANDING.md:397-403` gave roughly **2 / 2 / 14 / 20**. It was correct in
shape and is now wrong in two specifics. The corrected census:

### 4.1 The headline

Each of the 38 detector kinds is counted **once, at its strongest tier**, so the four numbers sum to 38.

| Tier | Count | Kinds |
|---|---|---|
| **(a) Adjudicated over bytes from a real EXTERNAL third-party system** | **3** | `differential_response`, `achieved_state`, `secret_credential_validity` |
| **(b) Adjudicated over bytes from real infrastructure the system creates and owns** | **2** | `k8s_workload_posture`, `k8s_rbac_verb_grant` |
| **(c) Strongest evidence is a real local process over a real socket, or a real compiled binary** | **12** | listed in 4.4 |
| **(d) Hand-written fixtures only** | **21** | listed in 4.5 |

**3 + 2 + 12 + 21 = 38.** If a reader instead asks "how many have *ever* been adjudicated over a real
local socket", the answer is **14** — the twelve above plus `differential_response` and
`achieved_state`, which were independently exercised on loopback as well as externally.

### 4.2 Correction 1 — the external SQL-injection detector

`OUTSTANDING.md:398` names `BOOLEAN_INFERENCE`. The engagement record disagrees.
`targets/testasp/charter.md:89-90` records the two facts minted against `testasp.vulnweb.com` as:

| Category | Detector that fired | Confidence | Where |
|---|---|---|---|
| `boolean_sqli` | **`differential_response`** | 0.987 | `search.asp`, parameter `tfSearch` |
| `open_redirect` | `achieved_state` | 0.900 | `query_value:0` |

Both re-verified offline, 2 of 2, with a tampered byte rejected
(`docs/AS-BUILT-LIVE.md:123-133`). Two honest nuances the same passage records: the companion target
`testphp.vulnweb.com` was **offline** at run time, so the error-based detector never fired externally;
and the external re-verification was corroborated through the full gate plus a rejected tamper, not
through the loopback run's self-contained 3-of-3.

### 4.3 Correction 2 — two live-fires that did not exist when the earlier census was written

**Kubernetes, against real infrastructure the system creates and owns** (`tools/livefire/k8s_rbac_livefire.sh`).
The script pulls `rancher/k3s:v1.31.5-k3s1`, starts a single-node cluster bound to `127.0.0.1:6443`,
plants four bindings, captures what the real API server returns, adjudicates those real bytes through
the production path, and destroys the cluster (`k8s_rbac_livefire.sh:64-115`). The results
(`k8s_rbac_livefire.py:108-141`):

| Configuration planted in the real cluster | Expected | Why it matters |
|---|---|---|
| anonymous user → `cluster-admin` | **CONFIRMED**, certificate re-verifies offline | The genuine problem |
| anonymous user → `view` | **not confirmed** | Anonymous is not automatically dangerous |
| named user `alice` → `cluster-admin` | **not confirmed** | A real administrator is not a finding |
| anonymous → `cluster-admin`, reading the role's **real** `*/*` rules (tier 2) | **CONFIRMED**, re-verifies offline | Rule parsing, not name matching |
| **default service account → `admin`, one namespace** | **not confirmed** | The control that matters |

The last row is the whole argument. This cluster's real built-in `admin` role grants
`["get","list","watch"]` on Secrets — the harness prints the value it actually read
(`k8s_rbac_livefire.py:130-132`) — so a naive detector would flag the most common legitimate delegation
in Kubernetes as critical, on a completely normal cluster.

Two engineering details worth mentioning because they show the harness is a proof and not a demo: every
expectation is asserted and the script exits non-zero on any deviation
(`k8s_rbac_livefire.py:9-10`), and it **refuses to draw a conclusion** when the cluster's role
controller has not finished assembling the aggregated built-in roles, because an empty role would make
the namespace-owner control pass for the wrong reason — nothing read, rather than the gate holding
(`k8s_rbac_livefire.py:121-129`).

**GitHub secret validity, against the real `api.github.com`** (`tools/livefire/secret_github_livefire.sh`).
It uses the operator's own credential from `gh auth token`, piped on standard input — never to disk,
never to an argument vector, never to the environment (`secret_github_livefire.sh:20-24,85-86`) —
against the operator's own least-privileged identity endpoint. Four things in the same run
(`secret_github_livefire.py:110-215`):

| | Outcome |
|---|---|
| A valid credential | **CONFIRMED**; the certificate re-verifies offline |
| A bogus token of the same **shape**, sent **live** to the same real endpoint | GitHub itself answers 401 → correctly a lead. Structure is not validity, measured against the real provider |
| The same confirmed capture with its confirming endpoint swapped to an attacker host, and to a suffix-confusion look-alike | Not confirmed — the anti-laundering gate. The runner's own exfiltration floor also refuses to send the live token there |
| The same capture with credential and confirming call carrying **different** fingerprints | Not confirmed |

The transport provenance is derived from the connection, never asserted
(`integration/vigil_integration/live/live_transport.py:1-45`): TLS counts as verified only when the
request was https, the connection really carries a TLS object, that object yields a peer certificate,
and the context is genuinely verifying; "no proxy" is recorded only when the client can be
affirmatively shown unable to interpose one; a 3xx is *reported* as redirected rather than followed;
and the peer address is read from the live socket rather than re-resolved afterwards.

### 4.4 Tier (c) — the twelve kinds whose strongest evidence is a real local process

Each was verified for this document either by running it or by reading the harness.

| Kind | How it was exercised | Verified |
|---|---|---|
| `error_signature` | The labelled benchmark application over a real loopback HTTP socket | **Ran it.** 11 findings, 0 false positives |
| `side_effect` | Same (path traversal) | **Ran it** |
| `evaluation` | Same (server-side template injection) | **Ran it** |
| `reflection_context` | Same (reflected cross-site scripting) | **Ran it** |
| `oob_callback` | A real localhost callback round trip through the receiver, with the detector firing on the signed receipt — and **not** firing against a wrong pinned key or a fabricated hit | `verify/tests/test_oob.py:138-160` |
| `service_reachability` | A real loopback TCP listener, the **real host `nmap`** run through the gated runner, re-proven by an independent handshake, minting a certificate that survives full verification | `integration/tests/test_external_tool_runner.py:1-16,77-95` |
| `tls_weakness` | A real loopback TLS handshake | `verify/tests/test_tls_weakness.py:1-8` |
| `dom_execution` | A real headless Chromium driven over the Chrome DevTools Protocol against a loopback page; the safe twin using `textContent` produces nothing | **Ran it — 2 passed.** `scanner/tests/test_browser_xss.py:1-10` |
| `active_exposure` | A real loopback HTTP server and a genuine anonymous request | `verify/tests/test_reachability_cloud.py:1-10` |
| `sanitizer_signal` | A C program the system **compiles itself** with `gcc -fsanitize=address` and runs on a crashing input | **Ran it — 18 passed.** `remediation_binary/asan_repair.py:43-44` |
| `sql_injection_breakout` | The inline gateway over real loopback sockets: a real request through a real socket produces a confirmed verdict, a 403, and a certificate that re-verifies | `aegis/tests/test_gateway.py:1-16,103-117` |
| `cloud_posture` **and** `policy_path` (two kinds, one harness) | The collector's **actual** cloud SDK path against `moto`, an in-process AWS simulator, over a seeded account that **includes the traps** — an ignored access-control list and a condition-narrowed role | **Ran it — 24 passed, 1 skipped.** `sensors/tests/test_cloud_live.py:1-18` |

That last row needs care and is the one place a sceptical evaluator will push. `moto` is an in-process
mock; it is **not** a real cloud provider and no packet leaves the machine. It is materially better
than a hand-written fixture — it exercises the real SDK code path and the real response shapes,
including the adversarial negatives — and materially weaker than a real account. **The LocalStack test,
which would run over a real socket against a real container, skipped: "LocalStack not running on
127.0.0.1:4566".** A writer who prefers not to credit an in-process simulator should move
`cloud_posture` and `policy_path` to tier (d), making the census **3 / 2 / 10 / 23**. State whichever
convention is used.

### 4.5 Tier (d) — the twenty-one kinds with fixture evidence only

`timing`, `boolean_inference`, `version_range`, `prompt_injection`, `system_prompt_disclosure`,
`automated_access`, `credential_stuffing`, `command_injection_breakout`, `nosql_injection_breakout`,
`k8s_posture`, `sso_assertion_forgery`, `saml_structural_forgery`, `mesh_posture`, `cicd_posture`,
`mobile_posture`, `email_auth_posture`, `identity_posture`, `imds_credential_capture`,
`gcp_sa_impersonation`, `iam_escalation_primitive`, `k8s_workload_posture`'s kube-bench sibling —
precisely: the 21 kinds not named in 4.1(a), 4.1(b) or 4.4.

Four qualifications that keep this from over-reading as weakness:

1. **The three request-side parse proofs judge the request alone.** A real socket adds nothing to their
   soundness; `sql_injection_breakout` has socket evidence only because the gateway test happens to use
   one.
2. **`iam_escalation_primitive` will never have live-fire, by design.** The registry says so:
   "Real-transport LIVE-FIRE … is deliberately NOT part of this branch — a defensive verification
   oracle never executes the escalation" (`docs/capability-matrix/evidence-branches.json`,
   `cloud_exploit.iam.privilege_escalation`). Do not describe it as awaiting anything.
3. **The eight posture kinds re-derive configuration offline with zero calls.** For them, "fixture" and
   "real export" differ only in who wrote the file.
4. **`boolean_inference` and `timing` are statistical procedures.** Their correctness is a property of
   the test, and the fixtures exercise the refusals — a page that simply changes every request, a
   significant-but-tiny drift — which is where the risk lives.

### 4.6 The two E-series capabilities still genuinely awaiting a live credential

| Capability | Status verbatim from the registry | Say this |
|---|---|---|
| **E1** metadata credential capture | "Real-transport LIVE-FIRE (the runner against a real metadata endpoint) is deferred on an operator-provisioned lab credential; the runner and this admission / certificate / world-model wiring are complete and fixture-proven offline." | Built, wired end to end, fixture-proven. There is no live fact yet |
| **E3** GCP service-account impersonation | Same words, for GCP credentials | Same |

And the one **row-level** split, which is the sharpest honesty point of the day and must not be blurred:

> **The `github_pat` row of E5 is live-fire proven against the real provider. The `aws_access_key` row
> of the same capability is NOT.** Its runner dispatch and its SigV4-signed confirming call are built
> and unit-proven — the signer tested against botocore's independent implementation — but have **never**
> been exercised against real AWS. It still requires a real, operator-provisioned access key, and
> **nothing about the GitHub run transfers to it.**
> (`docs/capability-matrix/evidence-branches.json`, `cloud_exploit.secret.credential_validity`.)

### 4.7 What the two live-fire runs did NOT exercise

Both harnesses stop short of the full production invocation path, and the difference should be stated
rather than left to be discovered.

- **The Kubernetes run captured with `kubectl` in the shell script and fed the evidence straight to the
  adjudication functions** (`k8s_rbac_livefire.sh:102-108` → `k8s_rbac_livefire.py:109-141`). It did
  **not** go through the gated live sensor. A gated sensor exists —
  `engine/crucible/framework/v2/sensors/k8s_live.py`, tier 2, entitlement-gated, with a fail-closed
  rule that refuses unless the API-server host it actually loaded is one the operator declared
  (`k8s_live.py:26-31`) — but **its Python client is not installed on this host** (verified: `import
  kubernetes` fails). The registry states the same gap: the harness reads named objects it planted; a
  scope-gated **enumeration** runner that discovers bindings across a cluster is still not covered, nor
  is a managed control plane (EKS/GKE/AKS).
- **The GitHub run did drive the real production runner over the real transport**
  (`secret_github_livefire.py:105-110`), which is the stronger of the two. But the WARDEN authorizer and
  the charter scope gate were **harness-supplied stand-ins** — `lambda: (True, "authorized owner-test,
  WARDEN A2 approved")` and a local `_AllowGate` (`secret_github_livefire.py:35-46,108-109`). The
  *refusal* legs were genuinely exercised, with a tripped kill-switch and a `_DenyGate`
  (`secret_github_livefire.py:204-212`), so the gate seam is proven to bite — but no signed charter was
  loaded in that run.

### 4.8 The capability registry that enforces all of this

`docs/capability-matrix/evidence-branches.json` holds **26 evidence branches**, each declaring what is
true today (`fact_capable`, `clean_capable`), what it must become (`target_*`), the code that realises
it (`implementation_refs` — a test checks the referenced file and symbol actually exist), and, when
current falls short of target, the concrete engineering that closes the gap (`blocking_work`). Its own
note states the rule: *a gap without blocking work fails the enforcement test, so a capability can never
be quietly abandoned by downgrading the claim; the claim stays, and the system is built up to meet it.*
Enforced by `scanner/tests/test_claim_discipline.py`.

Of the 26 branches, **11 are `fact_capable` and `clean_capable`; 15 are `fact_capable` only**. Every
one of the six E-series branches is `clean_capable: false` deliberately: proving the *absence* of cloud
exposure is a posture capability, not an exploitation branch's job.

---

## PART 5 — THE GATE CHAIN, IN ORDER

There is no single gate. There are four distinct chains for four distinct kinds of action, plus a
network boundary and a model-egress gate. A writer who conflates them will produce something an
engineer can falsify.

### 5.1 An HTTP action the engine takes against a target (5 gates)

`engine/crucible/framework/v2/agents/http_executor.py:395-456`. The docstring says the order is
load-bearing, and that both `execute` and `execute_differential` share this function **so no action path
can skip a gate — a new confirmation mode cannot become a hole in the safety stack**
(`http_executor.py:401-406`).

| # | Gate | Refuses when | Effect |
|---|---|---|---|
| 1 | Authority / kill-switch | The engagement is halted | Halts at the very next action, before any input/output |
| 2 | Scope | The target is not in the signed charter | Refused, counter incremented |
| 3 | Destructive confirmation | Classified destructive and the prompt is declined **or times out** | Default-deny |
| 4 | Budget | Requests made ≥ the per-engagement budget | Refused |
| 5 | Rate limit | — | Sleeps; posture-aware |

### 5.2 A registered tool or sensor (5 gates)

`engine/crucible/framework/v2/agents/tools/invoker.py:1-19,143-180`.

| # | Gate | Notes |
|---|---|---|
| 1 | Kill-switch | |
| 2 | Entitlement | Against the tool's **declared** capability |
| 3 | Charter scope | Only if the tool names a concrete host; reads `target` then `host`, so a *sensor* is scope-gated exactly like a tool (`invoker.py:37-49`) |
| 4 | Destructive confirmation | |
| 5 | Egress allowlist | Only if the tool declares hosts it will reach |

Two properties: **every gate is fail-closed — a denial *or an internal error inside a gate* refuses the
invocation**; and the intent is recorded on the immutable stream **before** the gates run, so a refused
call is on the record too (`invoker.py:10-16,161-168`).

### 5.3 The unified authorization decision (3 conjuncts)

`packages/core/vigil_core/vigil_core/gate.py:63-120` — the composition of record, shared by both
processes. An action is allowed only if **all** hold; first failure wins.

| # | Conjunct | Refuses when |
|---|---|---|
| 1 | Domain authority (`authorize_action`) | Checked first because its kill-switch step is the absolute stop |
| 2 | WARDEN tool tier | Anything other than an explicit `"auto"` |
| 3 | Threshold destruction (destructive actions only) | No quorum, no gate wired, an errored gate, or an `authorized` value that is not **exactly** `True` |

Four fail-closed invariants are pinned by tests and are worth naming: a conjunct that *raises* is a
deny, never a caught-and-continued pass; the destructive conjunct uses a strict `is True` identity
check so a truthy-but-not-boolean value cannot open an irreversible action; an **unrecognised** WARDEN
outcome is a deny, so a future outcome string can never silently allow; and a destructive action with
no destruction gate wired is a deny (`gate.py:18-21,102-104,118-120`).

### 5.4 Inside conjunct 1 — the engagement authority (7 checks)

`engine/crucible/framework/v2/authority/gate.py:60-124`, first failure wins:

| # | Check | Denial code |
|---|---|---|
| 1 | Kill-switch tripped | `halted` |
| 2 | Before `not_before` or after `not_after` | `expired` |
| 3 | Target host not in scope | `out_of_scope` |
| 4 | Destructive but the authority does not permit destructive actions | `destructive` |
| 5 | Destructive against a **LIVE** environment without a second explicit acknowledgement | `live_destructive` — "run it against the TWIN first" |
| 6 | Action budget exhausted | `budget` |
| 7 | Otherwise | allowed |

Each denial code maps to a typed exception that must not be silently caught — "it is the engagement
refusing to act" (`authority/gate.py:127-147`). And the authority itself is loaded **verified**: pass a
trust root and the document must carry the threshold of valid governance signatures or the load fails
closed, so an unsigned or tampered charter cannot arm an engagement (`authority/gate.py:155-180`). The
offence wrapper **refuses a `None` trust root outright** rather than loading unsigned
(`integration/vigil_integration/conjunctive_gate.py:116-120`).

### 5.5 An E-series live capture (2 gates, before any network input/output)

`integration/vigil_integration/live/imds_runner.py:131-149`; the same shape in
`live/secret_runner.py:11-15`.

| # | Gate | Effect on refusal |
|---|---|---|
| 1 | WARDEN A2 authorizer plus kill-switch | Returns a **refused** result and **no capture** |
| 2 | Charter cloud-scope gate | Same |

The design note is the point: a refusal produces nothing to adjudicate, **so there is nothing to
launder**. No network call is built, let alone sent, before both gates pass.

The cloud-scope gate authorises by **cloud-native identity, not by URL host**
(`live/cloud_scope.py:1-10`), for a reason an official will immediately grasp: authorising
`ec2.amazonaws.com` must not authorise every AWS account that shares that endpoint. A wildcard, blank
or `any` in the tenant column authorises **nothing** — the tenant must be named explicitly
(`cloud_scope.py:30-35`).

### 5.6 The network boundary underneath all of it

`gateway/vigil_gateway/__init__.py:1-15` — two enforcement layers over one charter scope:

- **Layer 3/4, nftables, deny-default.** The sandbox's only route out is the gateway proxy; metadata,
  link-local and reserved ranges are hard-dropped even on the gateway's own egress.
- **Layer 7, a filtering forward proxy.** Per-connection hostname scope check, then a resolved-IP
  denylist re-check (defence against DNS rebinding), then the exact validated address is pinned so the
  name cannot be re-resolved between check and connect.

The sandbox sits on a Docker network marked `internal: true`, so Docker installs **no route out** at
all, and `NET_ADMIN` is dropped so it cannot rewrite its own firewall
(`gateway/README.md:20-38`). The denylist covers IPv4-mapped, 6to4, NAT64 **and** IPv4-compatible IPv6
forms, so neither `::ffff:169.254.169.254` nor `::169.254.169.254` slips past.

### 5.7 The model-egress gate (added today, #300)

Before any model client is constructed, the sovereignty tier is consulted
(`integration/vigil_integration/live/think_claude.py:203-244`). Four tiers
(`engine/crucible/framework/v2/kernel/sovereignty.py:98-111`):

| Tier | Permits |
|---|---|
| `AIR_GAPPED` | Local backends only. Cloud refused **at construction** |
| `SOVEREIGN_CLOUD` | Local plus jurisdictionally-bounded cloud (Bedrock, Vertex, Mistral) |
| `TRUSTED_CLOUD` | Adds a zero-data-retention Anthropic offering, and **only** on an explicit operator attestation |
| `PERMISSIVE` | Everything. The development default |

Fail-closed at four separate points, which is why this is a good example of the house style: an
**unknown** tier name resolves to `AIR_GAPPED`, the strictest (`sovereignty.py:186-191`); an unknown
backend name classifies `cloud_only`, refused under every sovereign tier (`sovereignty.py:86-90`); if
the policy module is not importable, any configured tier refuses (`think_claude.py:172-199`); and if
the gate itself throws, that is a refusal, never a permission (`think_claude.py:220-226`). The refusal
returns the safest action rather than raising, so the reasoning loop stays total — and, in the words of
the source, "the client is never constructed, the SDK is never imported, and nothing leaves the host"
(`think_claude.py:249-257`).

There is also an optional **seal**: setting `CRUCIBLE_SOVEREIGNTY_SEALED` latches the tier once for the
process lifetime, so a later environment change cannot relax it mid-engagement. It can only pin, never
loosen (`sovereignty.py:383-416`).

---

## PART 6 — SUPPLY CHAIN, BUILD GATES, AND WHAT CI ACTUALLY GUARANTEES

### 6.1 Branch protection — read from the live API

> **[SUPERSEDED SNAPSHOT]** This records the config as read during the session that produced this
> inventory (nine required checks, and at the time protection was later found to be OFF — see the
> W0-1 correction). The LIVE config is now **13** required checks with protection enabled; the
> authoritative source is `.github/required-status-checks.txt`, pinned by
> `docs/tests/test_required_checks_canonical.py` and `.github/workflows/branch-protection-verify.yml`.

`GET /repos/thuram-nana/vigil-sovereign/branches/main/protection`, checked twice during this session
with identical results:

**Nine required checks:** `vigil_core — shared integrity substrate`; `CRUCIBLE core on vigil_core`;
`strix Claude-runtime (P8)`; `SIGIL governor gates (P7 — offense gate + authn)`; `A14 supply-chain
gate`; `gateway egress gate (P6)`; `integration two-env boundary (P5)`; `formal (TLA+ core-invariant
model check, F1)`; `WARDEN Rust kernel (A10 durability)`.

Force pushes and branch deletion are **disabled**. Three things are **not** enabled, and an evaluator
will ask, so volunteer them: `enforce_admins` is **false** (an administrator can merge without the
checks); required pull-request reviews are **not configured**; commit-signature verification is **not
required**.

**One CI job runs but is not required:** `CRUCIBLE eval + benchmark corpus` (`.github/workflows/ci.yml:124`).

### 6.2 The supply-chain gate (#294)

`.github/workflows/supply-chain.yml` is a separate workflow, and its header explains why: the jobs in
`ci.yml` prove the *system* behaves; this one proves the *inputs* are the ones that were chosen — base
images, third-party wheels, and the transitive tree underneath them, "the parts an attacker can change
without touching this repository at all" (`supply-chain.yml:1-6`).

| Control | Detail |
|---|---|
| Threshold | **CRITICAL blocks the pull request. HIGH is reported in full, advisory** (`supply-chain.yml:14-19`) |
| Suppressions | `.trivyignore`; every entry carries a written justification and **a test enforces that** |
| Scanner pinning | Version **and** the SHA-256 of the release tarball — "installing a security scanner via `curl \| sh` from an unpinned URL would be its own supply-chain hole" (`supply-chain.yml:41-44`) |
| Action pinning | Third-party actions pinned to full commit SHAs, not mutable tags, **and a test asserts this stays true** (`supply-chain.yml:53-58`) |
| Hash-locked dependencies | `engine/crucible/framework/v2/requirements.lock.txt` (+746 lines) and `infra/supply-chain/sovereign.lock.txt` (1,348 lines, new) |
| Digest-pinned images | `infra/supply-chain/image_pins.py` (306 lines); five Dockerfiles plus `docker-compose.yml` updated |
| Static half | `integration/tests/test_supply_chain.py` (464 lines) also runs in the ordinary integration job, so it holds on a runner with no network |

**The negative control is the part to lead with.** The commit message for `fce6ad12` documents two
defects the *first live run* exposed, and both are the same species of failure this whole system exists
to prevent:

1. **The scanner was not scanning the locks.** Its Python analyser matches by filename and silently
   skipped both `*.lock.txt` files — the two artefacts the job exists to produce. Run 31643595375
   reported three language-specific files, and neither lock was among them. "A gate that does not scan
   what the change adds is hollow."
2. **The gate had never fired.** It passed with an empty allow-list because the tree has no critical
   findings — the right outcome, and *indistinguishable from a scanner misconfigured into reporting
   nothing*. A negative control now runs the exact blocking configuration against a fixture of
   known-critical packages and **requires** it to fail.

### 6.3 The cryptography upgrade (#295)

`cryptography` moved past CVE-2026-69247 (HIGH) in **both** environments: `>=50,<51` in the engine
requirements, `>=50` in the shared core and the sovereign lock input, `==50.0.0` pinned for SIGIL.
Ten files. Note for honesty: `OUTSTANDING.md` records that the **vendored Strix lock still lags** —
verify before publishing.

### 6.4 The CI coverage extension (#299)

Eight previously-uncovered suites were added (`.github/workflows/ci.yml:46-54`): `veracity`, `kernel`,
`planner`, `sensors`, `defender`, `memory`, `analysis`, and the engagement-library test.

The **collection guard** is the interesting part and generalises the lesson of 6.2. A test path that
silently matches nothing is worse than not adding it, because the job stays green and the log looks
like coverage. So the job runs each newly-listed suite with `--collect-only` and treats pytest's exit
code 5 (nothing collected) and 4 (path does not exist) as **hard errors**, printing the per-suite counts
so the run shows the coverage it actually bought (`ci.yml:65-96`).

### 6.5 The case file (#301) [MOVED]

`engine/crucible/framework/v2/report/case_file.py` (1,819 lines) produces **nine numbered documents**,
numbered so the reading order is obvious from the filenames (`case_file.py:11-19`): `00-START-HERE.html`,
`01-executive-summary.md`, `02-approach-and-scope.md`, `03-findings.md`, `04-leads.md`,
`05-what-was-looked-for.md`, `06-what-to-do.md`, `07-verify-it-yourself.md`, `08-glossary.md`.

Its three stated rules are the same doctrine as the rest of the system: meaning before mechanism; say
the limits out loud; never assert what was not measured — where a value was not recorded the documents
say "not recorded" (`case_file.py:21-35`).

The companion module `report/catalogue.py` is the one to describe carefully. It derives the catalogue of
weakness categories **from `BUG_CLASS_ORACLES` itself**, not from a hand-written list, so a category
added to the engine appears on the next build (`catalogue.py:9-15`). Its status column has exactly three
values — `confirmed`, `reported`, `not_recorded` — and **there is deliberately no "examined and found
clean" state**, because the run record does not support one: a scan writes what it found, not the list
of checks it attempted. Inferring "examined and clean" from an absence would convert a gap in the record
into an assurance, "the single most dangerous thing a security document can do" (`catalogue.py:16-31`).
The specific, fixable gap is named as `COVERAGE_GAP_NOTE` rather than left vague.

---

## PART 7 — THINGS A WRITER COULD EASILY GET WRONG

| Tempting sentence | Why it is wrong | Say instead |
|---|---|---|
| "WARDEN blocks dangerous commands" | WARDEN classifies and records; it never executes and never blocks by itself. The *gate* blocks | "WARDEN decides a tier; the gate refuses or queues on that decision" |
| "Unknown tools are blocked" | They are classified A3, which means explicit authorization required — not permanently forbidden | "Anything not positively recognised as safe is treated as maximally dangerous" |
| "The system proved the Kubernetes finding on a live cluster" | True, but the capture path was `kubectl`, not the gated sensor, and the gated sensor's client is not installed here | "…against a real cluster it creates and owns; the gated enumeration runner is separate and not yet exercised" |
| "Exposed-secret validation is live-fire proven" | Only the GitHub row. The AWS row has never touched real AWS | Name the row |
| "38 detectors are available on every scan" | 15 are; 23 need an explicit category row keyed on evidence an ordinary scan does not produce | "15 core, 23 that only a specific kind of evidence can reach" |
| "Keys are encrypted at rest" | Not on this deployment. The TPM device is present but `tpm2-tools` is absent, so no key-encryption key is provisioned | "The mechanism is built and fail-closed; it is not provisioned on this machine, and the owner key rests as plaintext behind `0600`" |
| "The transparency log prevents a split view" | Only with a strict-majority witness set. Below that, detection only | Quote the conditional |
| "Every check passes before a merge" | Nine of ten are required, and administrators are exempt | State both |
| "The oracle found it" | A scanner, a sensor, an external tool and a model can only ever *propose*. The oracle confirms | Keep the two verbs apart — the whole architecture exists to |
| "Zero false positives means it finds everything" | Soundness is orthogonal to recall. `BENCHMARK.md:31-34` says so explicitly | "No false alarms is not the same as no misses; recall is measured separately" |

---

## PART 8 — RAW MATERIAL: NUMBERS THAT ARE SAFE TO QUOTE

Every one verified for this document on `main` @ `05b81e9f`.

| Number | What |
|---|---|
| **38** | Detector kinds |
| **85** | Canonical weakness categories |
| **190** | Spelling aliases folded onto them |
| **275** | Total recognised category vocabulary |
| **15** | Detectors reachable for an unrecognised category (frozen) |
| **172** | Declarative check-library entries, across 23 categories |
| **4** | WARDEN tiers |
| **72 / 21 / 12 / 17** | Tokens in the A3 / A2 / A1 sets and A0 safe verbs |
| **6** | Signed append-only record types; **4** reach the owner; **6** verify offline |
| **26** | Evidence branches in the capability registry; **11** both fact- and clean-capable |
| **9** | Required checks on `main`; **1** more CI job runs but is not required |
| **11 / 0 / 0** | Benchmark true positives / false positives / false negatives — re-run for this document, precision, recall and F1 all 1.000 |
| **5** | Governance record types that gained an anti-replay high-water today |
| **9** | Documents in the case file |
| **3 / 2 / 12 / 21** | Detector kinds with external / own-infrastructure / local-socket / fixture-only evidence |

---

### Appendix — how to reproduce the runs cited above

```
# the benchmark, on a real loopback socket (11 findings, 0 false positives)
cd /home/kali/vigil && PYTHONPATH=engine/crucible .venv-offense/bin/python -m framework.v2 benchmark --gate --no-incumbents

# real browser execution, real socket
.venv-offense/bin/python -m pytest engine/crucible/framework/v2/scanner/tests/test_browser_xss.py -q

# a real compiled AddressSanitizer binary
.venv-offense/bin/python -m pytest engine/crucible/framework/v2/remediation_binary/tests/test_asan_repair.py -q

# the real cloud SDK path against an in-process AWS simulator (LocalStack skips unless running)
.venv-offense/bin/python -m pytest engine/crucible/framework/v2/sensors/tests/test_cloud_live.py -q

# the two live-fires (neither runs in CI, deliberately — there are no credentials in CI,
# and a live-fire that fabricates a result when it cannot run is worse than no live-fire)
tools/livefire/k8s_rbac_livefire.sh          # needs docker
tools/livefire/secret_github_livefire.sh     # needs an authenticated `gh`; skips cleanly otherwise
```
