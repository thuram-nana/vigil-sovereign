<!-- GROUND TRUTH for the plain-English briefing. Produced by a read-only
     research pass over the repository; every claim is cited file:line.
     Writers: do not restate anything here you have not re-read in the code. -->

# SIGIL — Complete Capability & Agent Inventory

**Authoritative tree:** `/home/kali/vigil/apps/sigil/` (Python package `sigil/`, Rust kernel `kernel/`, 83 test files).
**The sibling `/home/kali/sigil` is a STALE FORK** — last commit Jul 20 (`19d33d8`). It is missing `sigil/knowledge/` (K2b), `sigil/inbound/`, `governor/capability.py`, `governor/offense_gate.py`, `gesture/navmode.py`, `governor/integrity.py`, `backup.py`. **Do not cite it in a briefing.** Everything below is from `/home/kali/vigil/apps/sigil/`.

---

## 0. The frame everything hangs on: tiers, and who may act

Four autonomy tiers, defined in Rust and mirrored in Python:

- `/home/kali/vigil/apps/sigil/kernel/src/tiers.rs:12-22` — **A0** observe/answer · **A1** reversible internal act · **A2** external-visible/semi-reversible · **A3** destructive/financial/security.
- `/home/kali/vigil/apps/sigil/kernel/src/tiers.rs:1-6` — the classifier is **token-based and danger-first**, fail-closed: A0 is reachable *only* via a positive safe-verb allowlist; anything unknown → **A3**.
- `/home/kali/vigil/apps/sigil/sigil/agents/base.py:24-35` — Python mirror; `AUTO_BAR = Tier.A1`. **A0/A1 auto-apply. A2/A3 are written to the spine as `status: "awaiting-approval"` and never executed.**
- `/home/kali/vigil/apps/sigil/sigil/agents/base.py:76-116` — the single dispatch path every agent goes through: governor decides AUTO / QUEUE / DENY; a DENY writes a `refusal` record and consumes no budget.
- `/home/kali/vigil/apps/sigil/sigil/agents/base.py:5-9` — the doctrine sentence for a lay audience: *"an agent literally cannot take an external-effect action, because no agent has a send/deploy/spend code path."*
- `/home/kali/vigil/apps/sigil/sigil/agents/__init__.py:5-7` — `assert_no_offense()` runs at import of the agent package. SIGIL processes cannot load offensive modules.

**Approval is cryptographic, not a button.** `/home/kali/vigil/apps/sigil/sigil/agents/approvals.py:33-40` — an approval counts only if Ed25519-signed by the **persisted** owner key (or an owner-authorized device key), bound to the exact `target_seq`. An attacker bringing their own key self-certifies nothing.

**Two agents can never be promoted to autonomy.** `/home/kali/vigil/apps/sigil/sigil/governor/promotion.py:30`:
```python
NO_PROMOTION_AGENTS = frozenset({"ENVOY", "DELEGATE"})   # outbound + account actions stay human-gated forever
```
The UI surfaces a refusal, not a false success: `/home/kali/vigil/apps/sigil/sigil/ui/actions.py:24-25`.

---

## 1. EVERY AGENT

Verified ceilings (`grep "ceiling = Tier"` across `agents/`, `perception/`, `scrape/`):

| Agent | Ceiling | File |
|---|---|---|
| ARCHIVIST | A1 | `agents/archivist.py:15` |
| SENTINEL | A1 | `agents/sentinel.py:59` |
| STEWARD | A2 | `agents/steward.py:85` |
| ENVOY | A2 (hard, no promotion) | `agents/envoy.py:66` |
| SCHOLAR | A1 | `agents/scholar.py:113` |
| SCRIBE / WebResearcher | A1 (inherits SCHOLAR) | `scrape/researcher.py:21` |
| ARTIFICER | A2 | `agents/artificer.py:71` |
| BASTION | A1 | `agents/bastion.py:132` |
| OPERATOR | A2 | `agents/operator.py:95` |
| DELEGATE | A2 + no-promotion | `agents/actor.py:83` |
| PERCEPTION (Perceptor) | A1 | `perception/perceive.py:72` |

### ARCHIVIST — memory
`/home/kali/vigil/apps/sigil/sigil/agents/archivist.py:1-31`. Mandate: *"the world model: ingest, consolidate nightly, keep the graph true."* Runs the consolidation pass, emits a `finding` summarising what it promoted/demoted. **Allowed:** A1 internal writes. **Forbidden:** deleting source records is A3 and, in the docstring's words, *"effectively never"* (`archivist.py:2`). **Autonomous** within A1.

### SENTINEL — monitoring
`/home/kali/vigil/apps/sigil/sigil/agents/sentinel.py:56-81`. *"See everything, report only what matters."* Its named failure mode is NOISE, so it applies a **salience floor** (default 0.5) and an **alert budget** (default 10/run) — highest salience first, the rest suppressed and honestly counted (`sentinel.py:78-80`). Built-in watchers: spine commit-bursts + unresolved contradictions (`sentinel.py:20-36`), low disk (`sentinel.py:39-53`). **Allowed:** writes `event` records only. **Forbidden:** everything else. **Autonomous.**

### STEWARD — the life layer / morning brief
`/home/kali/vigil/apps/sigil/sigil/agents/steward.py:82-93`, brief composer at `:21-79`. Produces an **unprompted, prioritised sitrep composed only from grounded memory** — due commitments, open threads, flagged contradictions, SENTINEL alerts, BASTION infrastructure posture, recent activity. **Every line cites a spine seq** (`steward.py:5`). BASTION findings are deduped to the latest per (asset, check, CVE) and resolved ones dropped, so a fixed problem never lingers as current (`steward.py:56-72`). **Ceiling A2** — calendar writes queue until the owner promotes them; the brief itself is A1 and auto (`steward.py:89-90`). **Autonomous for the brief; gated for calendar writes.**

### ENVOY — communications. **DRAFTS ONLY, FOREVER.**
`/home/kali/vigil/apps/sigil/sigil/agents/envoy.py:1-87`. This is the single most important agent to explain correctly to a non-technical audience:

> `envoy.py:3-5`: *"This is enforced STRUCTURALLY: ENVOY has no method that transmits anything… There is deliberately no `send()`."*
> `envoy.py:87`: *"NOTE: there is intentionally no send()/transmit() method. Outbound is human-only, forever."*

It triages inbound into urgent/normal/fyi/spam by deterministic keyword rules (`envoy.py:41-51`) and writes a **draft** record at A2 which always queues (`envoy.py:79-82`). Drafts carry a visible marker: `"[DRAFT — SIGIL/ENVOY. Review and send manually; nothing is sent automatically.]"` (`envoy.py:60`). **Ceiling A2 with no promotion path** (`envoy.py:66` + `promotion.py:30`). Inbox is a pluggable source; the shipped one is a JSON file (`envoy.py:26-38`) — **real IMAP is explicitly not built** (`envoy.py:7`).

### SCHOLAR — sourced research
`/home/kali/vigil/apps/sigil/sigil/agents/scholar.py:110-127`. Focus is **epistemics**: every claim must carry a source and a verbatim quote; a claim whose quote is not byte-verbatim in the cited source is **demoted, not asserted** (`scholar.py:31-37`, requires ≥2 salient tokens). The report separates *"Source-verified spans (the authoritative evidence, verbatim)"* from *"Model's reading (ADVISORY, not verified)"* and an explicit *"Unverified … NOT relied upon"* section (`scholar.py:88-107`). **Ceiling A1** — research never touches external state. **Autonomous.**

### SCRIBE — the grounded web-research engine
`/home/kali/vigil/apps/sigil/sigil/scrape/__init__.py:1-5`. *"Crawls PUBLIC content only, SSRF-gated + IP-pinned on every hop, RESPECTS robots.txt + per-host rate limits, scope-gates to owner-authorized domains… Correlatable (never evasive), GET-only, never an attack tool."*
**Important nuance for the briefing:** SCRIBE is not a separate identity on the record — `/home/kali/vigil/apps/sigil/sigil/scrape/researcher.py:1-2,21` defines `WebResearcher` as a **subclass of Scholar with `name="SCHOLAR"`**. Every fetched page becomes a cited `web_page` spine record and every claim passes the same demote-only gate (`researcher.py:29-50`). **Ceiling A1. Autonomous within scope; cannot widen its own scope.**

### ARTIFICER — engineering
`/home/kali/vigil/apps/sigil/sigil/agents/artificer.py:68-125`. Drives headless Claude Code (`claude -p`, `artificer.py:46-65`) inside a **dedicated git worktree** so the real working tree is never touched (`artificer.py:79-84`). Correctness discipline: it **runs the tests before claiming done**; a failing change is reported, not shipped (`artificer.py:106-112`); with no *real* test command it records `UNVERIFIED, PR withheld` (`artificer.py:95-102`, with a hardcoded rejection of trivial no-op test commands at `:26`). On success it commits on a branch and proposes a **PR at A2 → queued**. **Forbidden:** `git push` to a protected branch, deploys, dependency additions are A3 — *"ARTIFICER NEVER pushes"* (`artificer.py:2-3`, and the record itself says so at `:120`). **Proposes only.**

### BASTION — defensive posture, own infrastructure only
`/home/kali/vigil/apps/sigil/sigil/agents/bastion.py:1-11, 129-153`. Checks TLS cert expiry, dependency CVE exposure, uptime — **all observational**. The allowlist *is* the authorization: `self._allow = {a.ref for a in self.inventory}` (`bastion.py:140`); anything not in it is refused and logged with the doctrine string *"BASTION observes only the allowlisted own-infra inventory… no third-party scanning, no exploit tooling"* (`bastion.py:148-152`). Two hardening details worth quoting: a **CVE is flagged only when the parsed version provably falls in the affected range** — an unparseable version is an honest non-assessment, never a fabricated CVE (`bastion.py:38-76`); and uptime probes **refuse to follow redirects**, because a redirect target is chosen by a possibly-compromised server and is not itself allowlisted (`bastion.py:104-108`). **Ceiling A1 — it observes; remediation/patching is A3 and never taken here.** Inventory is loaded from `~/.sigil/bastion-assets.json`; with no file, BASTION simply doesn't run (`agents/runner.py:25-50`).

### OPERATOR — files and terminal, on request
`/home/kali/vigil/apps/sigil/sigil/agents/operator.py:1-18, 92-100`. The full transaction: **PLAN → PREVIEW → APPROVE → EXECUTE → VERIFY → ROLLBACK/UNDO**. Key properties, all in the header docstring:
- tier is **derived, never declared** — each step's honest tool token (`fs.read`/`fs.write`/`fs.delete`/`shell.exec.<argv0>`) is classified by the fail-closed Rust oracle, and re-derived at execute (`operator.py:5-7`);
- **two scope rings** — reads/writes must resolve inside the READ ring; a write auto-applies (A1) only inside the narrower AUTO-WRITE ring, else A2/queued; **empty rings = deny-all** (`operator.py:8-9`);
- **preview mutates nothing** and the approval binds to the previewed content hash; execute re-previews and aborts on mismatch (anti-TOCTOU) (`operator.py:10-12`);
- file bytes live in a 0700 journal **off** the append-only spine; the spine carries only hashes (`operator.py:12-13`);
- rollback is **honest about a restore that failed or an irreversible shell that already ran**; undo is hash-bound and single-shot (`operator.py:16-18`).

**Ceiling A2 — proposes; destructive steps queue.**

### DELEGATE — the owner's own accounts, per-action approved
`/home/kali/vigil/apps/sigil/sigil/agents/actor.py:1-22, 80-90`. Manages the owner's own credentials and, **with per-action owner approval, creates accounts / logs in / fills forms / submits**. Every account/login/submit/purchase is **A3: explicit, per-action, owner-signed, no promotion** (`actor.py:3-5`). Offense-free by construction, four structural properties (`actor.py:8-19`):
1. **No `as_identity`/impersonate parameter exists** — fields resolve only from the owner's own vault; there is no identity field on `WebStep` (`actor.py:77`).
2. A detected block (CAPTCHA / 403 / 429) **stops** and is surfaced as a positive control; there is **no browser-escalation code path at all** (HTTP-only), so "use a browser to beat a block" is structurally unreachable.
3. **One approval authorises exactly one action** — execute is single-shot; a re-execute of an applied step is refused, so an approval can never be replayed into repeated POSTs.
4. **Per-service creation cap** (mass creation is out of doctrine), enforced at preview *and* re-checked at execute; plus an origin allowlist that defaults deny-all.

Credentials resolve from the OS keyring **only at the last instant of execute, into a local variable** — never a proposal payload, never logged (`actor.py:20-22`). The vault record has **no password field, only a keyring reference** (`agents/vault.py:27-34`), and a credential rotation bumps a version that **invalidates any outstanding approval** (`vault.py:8-10`).

### PERCEPTION (Perceptor) — the vision agent
`/home/kali/vigil/apps/sigil/sigil/perception/perceive.py:69-72`. *"answer screen/camera queries from captured ground truth; VLM reading is advisory."* Ceiling A1. Detailed in §4.

### Supporting components that are **not** agents (don't list them as such)
- **CredentialVault** — `agents/vault.py:36`, a store, not an actor.
- **CapabilityGate / KillSwitch / PromotionPolicy / OffenseGate** — `governor/`, the enforcement layer.
- **agents/runner.py:1-3** — the v1 orchestration order: ARCHIVIST → SENTINEL → STEWARD → ENVOY, plus BASTION if an inventory file exists.

### The offense-side agents (separate trust domain — say so)
These live in the CRUCIBLE engine at `/home/kali/vigil/engine/crucible/framework/v2/agents/` and **never share a process with SIGIL**:
- `recon_agent.py` — probes paths, posts Observations; *"recon does not exploit, does not generate hypotheses, does not write findings."*
- `hypothesis_agent.py` — turns each Observation into ≥5 candidate hypotheses.
- `exploit_agent.py` — claims hypotheses, runs them, posts Plan→Action→Result→Finding; *"Findings are NEVER promoted to the report from this agent."*
- `critique_agent.py` — *"adversarial review of every Finding before promotion… is NOT optional… the guard against confident hallucination."*
- `reporter_agent.py` — synthesises only `critique_status='confirmed'` findings; does not promote objected findings.
- `memory_agent.py` — forwards blackboard events into the cross-engagement learning store.
- `coordinator.py` — schedules ticks; *"does not have authority to suppress critique-agent objections."*

The boundary is structural, not procedural — `docs/FEATURES.md:117` describes `vigil <subsystem>` passthrough stripping `PYTHONPATH`/`PYTHONHOME` from the child env *"so a parent-injected path can never inject the other trust domain's modules."*

---

## 2. VOICE

**Pipeline:** `/home/kali/vigil/apps/sigil/sigil/voice/pipeline.py:1-15`
```
IDLE ──wake word──▶ LISTENING ──end-of-speech──▶ THINKING ──▶ SPEAKING ──done──▶ IDLE
  ▲                    │                                          │
  └────timeout─────────┘                       barge-in (VAD)─────┘  (cancel TTS, re-LISTEN)
```
Frame-driven (20 ms @ 16 kHz, `voice/components.py:18-20`), timing in frame counts not wallclock, so it is deterministically testable with no audio hardware. Barge-in requires `barge_in_frames` consecutive speech frames (hysteresis) to cancel TTS.

**Voice is not a privileged channel.** `/home/kali/vigil/apps/sigil/sigil/voice/dispatch.py:1-4` — recognised text is routed through the same Rust KERNEL (`sigil-kernel ask`), so a spoken request crosses *the same T0 router + WARDEN gate + signed action log* as any typed one.

**Gating.** The live mic loop refuses to start when the owner-signed `voice` capability latch is off (`voice/run.py:73-77`), and the dispatch is separately gated mid-session (`voice/dispatch.py:29-37`). The kernel binary is integrity-pinned — a binary failing its owner-signed pin **is not run** (`voice/dispatch.py:19-22`).

### What works / what needs hardware / what is deferred

| Component | Status |
|---|---|
| FSM, full-duplex, barge-in logic | **Working**, tested offline against WAV files (`voice/run.py:1-2` `run_file`) |
| VAD | **Working** zero-dep RMS `EnergyVad` (`voice/backends.py:21-31`); Silero is the optional upgrade |
| **Wake word** | **STAND-IN.** `EnergyWake` fires after N consecutive speech frames — `voice/backends.py:34-37` calls it *"a stand-in for the real custom-'SIGIL' openWakeWord model (which needs training data)."* Hands-free "say SIGIL" wake is **not built**. |
| ASR | `faster_whisper` **is installed** in `~/.sigil/venv`; ElevenLabs cloud STT is the CLI default (`cli.py:1281-1283`). With neither, a `_StubAsr` returns a placeholder rather than fabricating (`voice/run.py:8-12`). |
| TTS | ElevenLabs cloud is default with a pinned voice id; Piper is the local option; `SilenceTts` is the honest fallback (`voice/run.py:33-45`). **Cloud TTS/ASR is network egress** — worth flagging to a national-agency audience. |
| **Barge-in on real hardware** | **Needs hardware mitigation.** `voice/pipeline.py:12-15`: *"on a real mic+speaker the assistant's own TTS is captured by the mic, so barge-in needs acoustic-echo cancellation (AEC) or output ducking; without it, run the live loop half-duplex… AEC is the real fix and is a runtime/hardware concern."* |
| Mic/speaker | Needs a physical mic + speaker. `vigil up --with-voice` spawns `sigil voice --mic` and `docs/FEATURES.md:135` flags **"needs a mic."** |

### Voice-driven UI navigation — slice S2
`/home/kali/vigil/apps/sigil/sigil/voice/nav.py:1-22`. A thin **additional intent class layered ahead of the untouched cognition path**:
- **A1, injects nothing** — it emits a `sigil.nav` spine signal that tells the owner's own browser to switch screens. *"it runs no tool, touches no target, and cannot type or launch"* (`nav.py:12-13`).
- **Gated** — emitted only when the `voice` latch is ON and the kill-switch is OFF; otherwise the utterance falls through to the kernel (`nav.py:14-16`).
- **Strict resolver** — exact match against a screen's id/label/synonyms after stripping a nav verb; **zero or ambiguous matches → no nav**, so it never hijacks a real question (`nav.py:17-19`, verbs at `:38`).
- **Manifest-driven** — screens come from the S1 map, CI drift-checked, so *"SIGIL can only navigate to screens that actually exist"* (`nav.py:20-21`).

Wired at `/home/kali/vigil/apps/sigil/sigil/voice/run.py:75-77` (`RoutingDispatch(KernelDispatch(voice_channel=True))`). The map: `/home/kali/vigil/knowledge/system-map/screens.yaml` (22 screens) + generated `system-map.json`; CI asserts `screens.yaml ids == app.js NAV ids == route() ids` (`knowledge/system-map/README.md:10-12`), and `docs/FEATURES.md:285` records the sets as **"In sync."** Tests: `apps/sigil/tests/test_voice_nav.py`, `test_system_map_sync.py`.

---

## 3. GESTURE + HUD

### SIGIL-HAND
`/home/kali/vigil/apps/sigil/sigil/gesture/__init__.py:1-5` — *"a device camera → on-box deep-learning hand tracking → a debounced intent FSM → WARDEN-gated input injection. Observes the owner's OWN hand and controls the owner's OWN device."*

Stages: warm camera stream (`perception/camera_stream.py:1-6`, one persistent ffmpeg pipe, drop-to-latest) → 21-keypoint ONNX landmark model (`gesture/landmark.py:1-6`) → translation/scale/rotation-**invariant** feature vector + rule classifier (`gesture/features.py:1-7`) → debounced FSM (`gesture/pipeline.py:1-13`).

**Fail-safe FSM** (`gesture/pipeline.py:5-10`): a discrete gesture fires only after 4 consecutive identical high-confidence, high-margin readings, then a cooldown; **low confidence or a small top-1/top-2 margin ⇒ neutral ⇒ nothing fires — ambiguity does nothing**; 8 frames of no-hand emits `hand_lost` and the session **auto-disarms**.

### The arming / approval model — this is the keystone
`/home/kali/vigil/apps/sigil/sigil/gesture/session.py:1-16`. **Two enforcement layers:**

- **Layer 1, the session.** `arm()` **requires the owner key** — it cannot be armed without the owner identity — and appends a signed `gesture.session_armed` record (tamper-evident proof of authorization, indicator lit). The injection gate is the live in-memory session held only by the owner's own running daemon, bounded by TTL, ended by disarm / hand-loss / expiry. **Injection is refused with no live session.**
- **Layer 2, per intent.** Tier is **derived from the WARDEN oracle** on honest `hid.*` tool names (`session.py:42-46`). **A1** (pointer move / click / scroll / drag) injects within the session. **A2** (`hid.type`, `hid.combo`, `hid.app.launch`) is **queued for a verified owner/device approval bound to `sha256(session_id|tool|args)` and never auto-injected** — *"so a gesture alone can never type a password or launch an app"* (`session.py:10-13`, enforced at `:57-64`).

**What a gesture CAN trigger:** cursor move, click, scroll, drag — inside a live armed session only.
**What it CANNOT:** type anything, press key combos, launch an app, approve anything, act with no armed session, act after expiry, act after hand-loss.

**Five per-frame kill paths, all bounded to ~1–2 frames rather than TTL** (`session.py:370-390`): kill-switch engaged → disarm; `capability gesture off` latch → disarm; **arming device revoked → disarm**; no live session → refuse; session expired → disarm.

**Audit discipline:** only arm/disarm and *discrete* actions hit the spine; 30 fps pointer moves are telemetry — *"30 FPS records would DoS the append-only log"* (`session.py:15-16`). And it never lies about what happened: when the input backend is inert the record says `"gesture <tool> NOT injected — input backend inert"` with `backend_inert: True` and returns `injected=False` (`session.py:41-56` of the excerpt / `session.py:409-425`).

**Device-authorization requirement for remote arm** (`session.py:38-40, 86-101`): a device-armed session has a **shorter TTL (300 s vs 1800 s local)**, the arm request must be **fresh within 30 s**, is signed by the **phone's own key** (never the owner trust-root), and the device must be in the owner-signed mesh ledger. Replay is blocked by a consumed-nonce set (`session.py:56-83`).

### Gesture navigation — slice S3
`/home/kali/vigil/apps/sigil/sigil/gesture/navmode.py:1-12`. An **opt-in, default-OFF** latch: while on, a live armed session's discrete gestures **navigate the UI instead of clicking/scrolling** — an A1 `sigil.nav` signal that injects nothing. Map (`session.py:52-53`): swipe-right → next screen, swipe-left → previous, pinch → home. It is *"a MODE, not a safety capability, so — unlike the default-enabled voice/gesture latches — it defaults OFF."* Reached **only after every per-frame gate above**, and maps to **no `hid.*` tool at all** (`session.py:394-400` / `_emit_nav_gesture` at `:436-440`): *"the OS is untouched."* Cached only on discrete gestures, so a 30 fps move never reads the latch. Test: `apps/sigil/tests/test_gesture_nav.py`.

### The HUD — slice S4
`/home/kali/vigil/apps/sigil/sigil/voice/hud_status.py:1-7`. The voice FSM churns state many times per interaction, so **that telemetry must never hit the signed audit spine** — the same telemetry-vs-audit split gesture enforces for frames. State goes to a small **owner-only 0600 ephemeral file** (`~/.sigil/sigil-hud.json`), atomically replaced; a write error is swallowed so it can never break the voice loop (`hud_status.py:27-45`). The pipeline observer is optional and defaults to None, keeping the FSM byte-identical and pure (`voice/pipeline.py:38-41`).

The cockpit tails it and fans out over SSE at `/api/sigil/hud` (`ui/server.py:257-284`). Browser side (`docs/FEATURES.md:267-268`): a persistent SSE started at boot; **`nav` signals navigate only to a known in-app NAV id** — an `Object.create(null)` membership test blocks prototype-pollution and arbitrary-URL navigation; `state` events render a dismissible corner overlay of listening/thinking/speaking. Test: `apps/sigil/tests/test_hud_status.py`.

### ⚠️ Gesture status — the single biggest honesty flag in this inventory

**On-box camera gesture control is NOT operational.** Three independent confirmations:

1. `/home/kali/vigil/apps/sigil/sigil/gesture/landmark.py:37-42` — `operational()` is True *"ONLY when a real ONNX session is available (runtime importable AND the checksum-pinned model is present)… When False, `detect()` is a DOCUMENTED no-op that always returns \[\] — the local camera gesture path is NOT functional."* The preprocessing body is deliberately minimal: *"with no bundled .onnx this path returns \[\] (honest gap)"* (`landmark.py:50-52`).
2. `/home/kali/vigil/apps/sigil/sigil/gesture/run.py:38-49` — the daemon emits a loud warning: *"local camera gesture is NOT operational: no hand-landmark model… the loop will process frames but can never fire a gesture intent."*
3. `/home/kali/vigil/docs/FEATURES.md:136` — *"**Local camera gesture is NOT functional — gesture input is the phone companion**"* (`uiproxy.py:804-819`). `vigil up --with-gesture` is not a process; it just flips the S3 nav-mode latch.

**Verified on this host:** `~/.sigil/models/` does not exist. `onnxruntime` is installed but there is no model to run.

**The working gesture path today is the phone as trackpad** (§7). Also note `ydotool` is absent and only `xdotool` is present on this box, so injection would be X11-only (`platform/input.py:20-23`; a backend with neither is honestly inert, `:1-5`).

---

## 4. PERCEPTION

**The core rule, stated three times in the code:** the **captured OCR/accessibility TEXT is authoritative**; the **vision model is advisory**.

- `/home/kali/vigil/apps/sigil/sigil/perception/__init__.py:1-8` — *"the CAPTURED TEXT… is the AUTHORITATIVE ground truth; the VLM's visual reading is ADVISORY only, never asserted as the screen's content."*
- `/home/kali/vigil/apps/sigil/sigil/perception/perceive.py:4-8` — an object the VLM names is a **LEAD**, promoted to a grounded claim only if the OCR corroborates it.
- `/home/kali/vigil/apps/sigil/sigil/perception/veracity.py:1-9` — grounding means the mention appears **verbatim as a salient token in the captured text**, and a grounded claim is phrased as *corroboration* — *"corroborated by on-screen text 'Firefox'"* — **never "there is physically a Firefox."** With no captured text, **everything is a lead**: an image-only frame can never yield a grounded object claim (`veracity.py:26-31`).

**Anti-injection detail worth citing.** `perception/perceive.py:27-33`: section headers are rendered at column 0 and every captured screen line is guard-prefixed `"  │ "`, so **attacker-controlled on-screen text can never forge a section boundary** and promote itself from advisory to authoritative.

**Capture** (`perception/capture.py:1-9`): a `Frame` is the image sha256 + the OCR text + a path. Every backend returns `None` on failure — *"a missing camera is no capture, never a fabricated one."* Documented gaps: headless hosts often lack a screenshot tool / tesseract / a camera; the richer **OS accessibility tree is a documented seam, not wired** (`capture.py:7-9`, `:58`).

**Ambient watching** (`perception/perceive.py:14-16`) is **opt-in and indicator-lit**, escalating only on a *perceptual* change over the OCR token set rather than raw byte-identity, so lighting jitter fires nothing (`perception/delta.py:1-6`). **Unchanged frames never leave the machine.**

**Recall — "where did I last see X?"** (`perception/recall.py:1-6`): scans perception events for the most recent whose authoritative OCR contains the subject and serves the **verbatim OCR span** + frame ref + timestamp. A2-hardening: all the subject's salient tokens must appear on **a single line**, so scattered tokens across a frame are **not** a grounded sighting (`recall.py:17-24`). A0, on-box.

### Egress gating around the vision model
`/home/kali/vigil/apps/sigil/sigil/perception/egress.py:1-14` — the doctrine sentence:
> *"Sending a screen/camera frame to the frontier Anthropic VLM uploads private bytes off the owned machine — that is A2 data-egress, not a free 'try local then frontier' quality bump."*

- Tier is **derived** from the WARDEN oracle on `vision.frontier.upload` → A2, never self-declared.
- Nothing uploads until a **verified owner approval bound to that exact egress** — `egress_token = sha256(frame.sha256 | question)`. An approval of a different egress does not match and authorizes nothing (`egress.py:25-33`).
- Absent approval the egress is **queued and the frontier reading withheld**; the local reading still stands.
- The model interface carries an `egresses` flag; `perceive`/`ambient_watch` **structurally refuse an egressing model** on the auto path (`perception/vision.py:27-33`), and `ClaudeVision.describe` carries *"Never call… on an auto path"* (`vision.py:10-13`).
- The gesture loop is even stricter — it refuses unless the landmarker is **explicitly** `egresses is False` (`gesture/run.py:25-37`).

**CLI shape:** `sigil agents perceive --frontier` **queues** the egress and uploads nothing; `--approved <seq>` runs it **only if verified** (`cli.py:1270-1273`).

### ⚠️ Perception status on this host
| Dependency | Present? | Consequence |
|---|---|---|
| screenshot tool (scrot / gnome-screenshot / spectacle / import) | **PRESENT** — ImageMagick's `import` is at `/usr/bin/import` and `DISPLAY=:0.0`; `LinuxBackend().capabilities()` returns `has_screen=True` (CORRECTED 2026-08-13: an earlier pass recorded all four as missing; the host and the code win) | `grab_screen()` works here; the missing piece is downstream (`tesseract`) |
| `tesseract` | **MISSING** | no OCR ⇒ no authoritative text ⇒ **every VLM output would be a lead, nothing groundable** |
| `ollama` (local Moondream VLM) | **MISSING** | local advisory reading returns `""` (honest empty) |
| `ffmpeg` + `/dev/video0` | ffmpeg present | camera path viable if a device exists |

The logic is built and tested (`tests/test_vision.py`, `test_perception_bastion.py`); the *sensors* are not installed here.

---

## 5. THE KNOWLEDGE ENGINE (K1–K6)

The definitive internal reference is `/home/kali/vigil/knowledge/kb/knowledge-engine.md` (319 lines). Its thesis line, ideal for a briefing (`:5-17`):

> *"how VIGIL **learns about vulnerabilities without ever learning them into truth**… it is allowed to point at where a bug might be, and forbidden from asserting one is there."*

Plane map (`knowledge-engine.md:21-29`) — **note K2b and K4 are the SIGIL/sovereign half:**

| Stage | Role | Plane |
|---|---|---|
| K1 | Intel feed — pull advisories as LEADS | offense |
| K2 | Propose — rank leads into a learn queue | offense |
| **K2b** | **Owner Accept → signed grant** | **sovereign (SIGIL)** |
| K3 | Deep-learn FIND/DETECT/PREVENT | offense |
| **K4** | **Point-at-a-URL learner** | **sovereign (SIGIL)** |
| K5 | Self-evolve — gaps → draft proposals + calibration | offense |
| K6 | Knowledge git-sync | integration |

**The cross-plane bridge is a signed inert file spool, not a shared process** (`knowledge-engine.md:31-32`, invariant at `:186-205`). The two environments **never co-load in one interpreter**; the offense side holds only the owner **public** key.

### K1 — vulnerability-intelligence feed
`framework/v2/intel/vulnfeed.py`. A **fixed registry** of three hosts — NVD, OSV, CISA-KEV — and *"There is **no arbitrary-URL pull** here"* (`knowledge-engine.md:42-45`). Each pull is scoped to a single concrete apex host and **refuses a source that overlaps the engagement's charter scope**. Everything mints as an intel-tier **LEAD**, never a fact; the scheduler is a pure tick predicate with no thread/sleep/wallclock, so it is *"deterministic and trivially stoppable"* (`:55-58`). **Off by default — live traffic only under an explicit `--live`** (`:59-63`, `docs/FEATURES.md:689`).
**Changes on its own:** adds LEAD records. **Needs the owner:** nothing here — but nothing here is usable either.

### K2 / K2b — propose-to-learn (the queue + latch + owner accept)
- **K2 (offense, drafts only):** ranks leads known-exploited → severity → CVSS → id; a `LearnProposal` is **always `status="proposed"`** and *"authorizes NOTHING"* (`docs/FEATURES.md:698`).
- **K2b (SIGIL):** `/home/kali/vigil/apps/sigil/sigil/knowledge/proposals.py:1-8` — *"Enqueuing grants nothing; the owner-signed approval is the sole trust operation… Accepting authorises LEARNING (K3), never a fact."* The enqueued record is an ordinary A2 `awaiting-approval` spine record, **idempotent by `vuln_id`, capped at `_MAX_PENDING=200`** so a distinct-CVE flood cannot pile up (`proposals.py:21-24`), with slug sanitisation because the slug later becomes an argv value and a path component (`knowledge-engine.md:92-93`).
- **The latch:** `/home/kali/vigil/apps/sigil/sigil/governor/capability.py:36-42` — `autolearn` joins `gesture` and `voice` as an owner-signed capability. **Asymmetric authentication** (`capability.py:5-10`): *"DISABLING is always the SAFE direction, so ANY disabled record takes effect (even unsigned)… RE-ENABLING is honored ONLY if it carries a valid OWNER signature."* Default (no record) = enabled; a **read error resolves to DISABLED**. Anti-replay: `issued_at` is inside the signed core with a per-capability high-water, so a captured owner-signed enable cannot be re-appended after a disable (`capability.py:17-25`). Explicit scope note at `capability.py:40-41`: *"`autolearn` enabled only permits DRAFTING/showing learn proposals — it never learns, applies, or mints a fact."*
- **The accept:** the existing owner-signed `ApprovalQueue.approve`, *"never re-implemented or weakened here"* (`knowledge-engine.md:97-98`). UI entry `ui/actions.py:27-43` refuses if the kill-switch is engaged **or** autolearn is off.
- **The grant:** `/home/kali/vigil/apps/sigil/sigil/knowledge/learn_grant.py:1-6` signs an **inert** `{schema,kind,slug,vuln_id,approval_seq}` core into a spool. **Fail-closed:** exports nothing unless kill-switch released **AND** autolearn enabled **AND** an owner key exists (`knowledge-engine.md:108-112`). A forged/replayed/non-owner approval produces no grant.
- **The known gotcha, stated plainly** (`knowledge-engine.md:294-297`): *"The approval binds `target_seq`, not the payload"* — slug and vuln_id are re-read by joining back to the queued record and re-sanitized at mint. *"If you ever trust slug/vuln_id straight off the approval record, you've opened a forgery seam."*

**Owner signature required:** yes — the accept is the sole trust operation, and it authorizes *learning*, not a fact.

### K3 — deep-learn FIND / DETECT / PREVENT
`framework/v2/knowledge_engine/deeplearn.py`. Turns one accepted lead into **three markdown advisory skills** with frontmatter carrying **no tier/authority key** — *"a skill is guidance, it authorizes nothing"* (`knowledge-engine.md:127-130`; `docs/FEATURES.md:701`). DETECT resolution: if the bug class maps onto an **existing** deterministic oracle, the skill names it (advisory); if not, it drafts a **`status=DRAFT`, empty-patch `ImprovementProposal`** for a *real* deterministic oracle — **authorize ≠ apply**, never a soft/LLM oracle, never touches the tree (`:138-141`). An invented oracle kind **raises** rather than being emitted (`:135-137`).

The load-bearing negative: **K3 does not bump the calibrated priors.** *"A learned-about vuln is not a test outcome; injecting one would pollute the calibration"* (`knowledge-engine.md:249-251`).

The offense-side consumer re-verifies the owner signature under the owner **public** key, re-derives the lead from the offense's **own** intel, quarantines a bad grant to `rejected/`, and a tripped per-slug kill-switch **defers** (moves back to `incoming/`) rather than dropping (`knowledge-engine.md:120-126`).

**Changes on its own:** writes advisory skill files and draft proposals. **Needs the owner:** the K2b signature to run at all; and a separate human merge gate to ever apply a proposal.

### K4 — point-at-a-URL learning (**SIGIL side**)
`/home/kali/vigil/apps/sigil/sigil/scrape/learn_source.py:1-11`:
> *"K4 scopes the crawl to that host, fetches PUBLIC pages through the existing scope/robots/rate-limit/SSRF gate, and runs EVERY claim through the identical demote-only `consolidate.gate.admit`. So nothing a page asserts becomes a fact."*

- Single-host scope, **deny-all otherwise**; a non-http(s) URL raises (`learn_source.py:60-67`).
- Bounded: **4 pages, depth 1** (`learn_source.py:33`) — *"the owner-action plane is synchronous."*
- **STOP-able:** the kill-switch is passed as a `cancel` hook that aborts the crawl between hops (`learn_source.py:9-10`, wired at `ui/actions.py:57`).
- Topic mode uses a **curated list of concrete apex hosts** — OWASP, CWE/CAPEC/ATT&CK MITRE, NVD, OSV — *"These are references, never the target"* (`learn_source.py:23-29`).
- Gated identically: refuses on kill-switch or autolearn-off (`ui/actions.py:44-64`).

**Changes on its own:** writes cited `web_page` records and a demote-only grounded/advisory report. **Cannot** mint a fact. Test: `apps/sigil/tests/test_learn_source.py`.

### K5 — the bounded self-evolve loop
`framework/v2/knowledge_engine/evolve.py`. *"a **bounded, honest** loop… It does not forecast undiscovered CVEs, prove anything, fire an oracle, mint a fact, or self-apply a change"* (`knowledge-engine.md:148-151`). `plan_evolution` is **pure/read-only** — writes no skill, mutates no ledger. It **never merges or applies anything**; the merge gate (capability + eval + m-of-n approvals) is a separate human-applied gate K5 does not call (`docs/FEATURES.md:707`).

Two phrases to reproduce verbatim in any briefing:
- **`studied_enough` means "drafted everything for the *disclosed* leads", explicitly NOT "the system is complete"** (`knowledge-engine.md:160-163`, `:310-312`).
- **`record_predictions` writes `oracle_confirmed=False`. "The forecast is not an outcome."** The outcome is recorded later by a real engagement firing or not firing the mapped oracle — *"The engine cannot mark its own prediction correct"* (`:164-168`, `:254-256`).

The read (`evolve_data`, GET) **persists nothing** and uses a fixed epoch for determinism; the tick (`run_evolve_tick`, POST) is kill-switch-gated and persists (`knowledge-engine.md:169-177`, `:300-302`).

**The non-circularity invariant** (`knowledge-engine.md:245-263`) — the strongest sentence in the whole document:
> *"The causal arrow is one-way: **oracle outcome → prior / calibration → ranking**. Learning never flows the other way."*

### K6 — knowledge → GitHub sync
`vigil knowledge sync|push|status`, `docs/FEATURES.md:103-104`. `sync` regenerates the manifest, **scans `knowledge/` for secrets and refuses the commit if any is found** (prints each and returns exit 3), then commits. **`push` is a separate, explicit outward act** — commit and push are not the same button. And: *"**Committing a file makes nothing a FACT** (the graph counterparts stay intel/ungrounded)."* Operator-gated throughout.

### Whole-loop summary for a lay reader
`docs/FEATURES.md:609`: *"feed → propose → accept → deep-learn → evolve… **At no step is a lead promoted or a fact minted.**"* Only a fired deterministic oracle over executor-captured non-LLM bytes mints a signed FACT (`knowledge-engine.md:207-214`).

---

## 6. MEMORY + THE SPINE

### The hash-chained record spine
`/home/kali/vigil/apps/sigil/sigil/spine/store.py:1-8` — append-only hash-chained JSONL; each line carries `{seq, prev_hash, entry_hash}`. The digest is over **content only, not the wallclock timestamp**, so the chain is replay-stable. Cross-process appends are serialized by a POSIX advisory lock so the chain cannot fork (`store.py:37-40`).

Around it: `spine/verify.py`, `spine/merkle.py`, `spine/checkpoint.py`, `spine/snapshot.py` (folded pruned-prefix state), `spine/floor.py` (durable external anti-rollback floor), `spine/witness.py`, `spine/prune.py`, `spine/manifest.py` (segment rotation). Per the top-level README (`apps/sigil/README.md:95-97`): two-layer integrity — payload binding + chain linkage — plus an **Ed25519-signed head that distinguishes benign growth from truncation/rewrite**; ~43k records.

**Nothing is edited, only superseded** (`apps/sigil/README.md:38-41`).

### Vector search
`/home/kali/vigil/apps/sigil/sigil/vectors/index.py:1-6` — one Qdrant point per spine record, id = spine seq, payload carries `entry_hash`/seq/kind/session/project **so every retrieval is citable**. Incremental. Embeddings are on-CPU via fastembed/bge-small — **no API, no cost** (`apps/sigil/README.md:100-101`). An unreachable backend **raises rather than reporting an empty cursor**, so a transient outage never silently re-embeds the whole corpus (`index.py:27-31`). **Qdrant is running on this host** (`sigil-qdrant`, up 18h).

### The graph store
`/home/kali/vigil/apps/sigil/sigil/graph/rebuild.py:1-9` — a **deterministic Kùzu mirror**: replay the spine in seq order into a fresh staging DB, then atomically swap to `current/`. *"the graph is therefore always regenerable from the signed spine, never edited in place… two rebuilds over the same spine produce identical node/edge sets."* Every node records the seq + entry_hash that minted it, so **a graph answer cites memory**. Mirror health = highest seq replayed vs spine head. `kuzu` is installed.

### Consolidation (ARCHIVIST's nightly pass)
`/home/kali/vigil/apps/sigil/sigil/consolidate/__init__.py:1-6` and the gate at `consolidate/gate.py:1-18`. **The most quotable passage in the codebase:**

> *"The gate grounds the QUOTE, and the quote — the verbatim record span — is what becomes the served fact. The model's free-text `statement` is NEVER the authoritative content (a red-team re-check proved a token-subset check over the statement is not entailment: an extractor can drop a negation or reorder words to invert meaning while staying a token subset). By certifying and serving the verbatim quote instead, a fabricated or inverted statement can never be presented as a grounded fact — **the owner only ever sees their own words**."*

A candidate grounds iff (`gate.py:11-16`): every cited seq is inside the exact window fed to the extractor; the quote is verbatim in a record **re-fetched from the spine, never the model's copy**; and the quote is *specific* — ≥2 salient non-stopword tokens, Unicode-aware. **The gate can only ever DEMOTE**; model confidence never enters; anything failing is recorded honestly as commentary, **never dropped**.

Providers are the owner's choice (`consolidate/__init__.py:21-28`): `heuristic` (offline, zero cost, default), `claude` (headless), `api`, `local` (Ollama), `replay` (fixtures).

### How a quote is served, end to end
1. A raw record lands on the spine (chat, commit, transcript, web page, perception event).
2. Consolidation proposes a candidate fact carrying a quote + cited seqs.
3. `gate.admit` **re-fetches the cited record from the spine** and checks the quote byte-verbatim.
4. Grounded → promoted as a provenance-linked record. Ungrounded → recorded as commentary.
5. Recall (MCP / cockpit / brief) serves **the verbatim span plus the seq**; the model's paraphrase, where shown, is labelled advisory.

### The MCP tools — 8, read-only, cited
`/home/kali/vigil/apps/sigil/sigil/mcp/server.py:1-8` — *"a fail-closed tool allowlist, no write path, and provenance on every result… an empty result says so rather than inviting fabrication."* The eight (`server.py:35, 68, 108, 136, 153, 171, 183, 198`):

`memory_search` · `episodic_range` · `ingest_status` · `graph_entity` · `graph_query` · `threads_open` · `commitments_due` · `contradictions_pending`

The anti-fabrication contract is in the tool description the model reads (`server.py:50-52`): *"No strongly-grounded match… Do not fabricate — tell the owner memory has nothing solid on this."* Registered in Claude Code and Claude Desktop, so any Claude session gains cited recall of the owner's own history. **These are live in this session** (the `mcp__sigil-memory__*` tools are attached).

**Ingestion** (`sigil/ingest/`): Claude Code history, git commits via live post-commit/post-merge hooks, subagent transcripts, curated docs — incremental and idempotent.

**Inbound from the offense side** (`sigil/inbound/finding_receiver.py:1-31`) — the two-anchor seam: anchor 1 is CRUCIBLE's m-of-n governance signature over the evidence certificate, verified here with `vigil_core` alone before admission; anchor 2 is the owner's signature over the spine head. *"the offense side proves WHAT was found; the owner attests WHEN it entered the personal record. Neither can forge the other's."* This package **imports no offense module** — an incoming finding is *"opaque signed DATA, never code."* Production wiring must use `from_delegation` (owner-signed delegation + scope confinement); the raw path has no production caller (`finding_receiver.py:24-30`).

---

## 7. THE COMPANION / PHONE

**One sentence for the briefing** (`apps/sigil/README.md:254-256`): *"the phone holds only its own Ed25519 device key — your owner trust-root never leaves the desktop, and the desktop verifies every request (it never signs on the phone's behalf)."*

### What the phone holds
Its own device Ed25519 key, authorized once by the owner into a signed mesh ledger (`sigil/mesh/registry.py:1-9`). **It never holds the owner trust-root.** It can approve offline.

### What it can do
The authenticated action allowlist, `/home/kali/vigil/apps/sigil/sigil/bridge/envelope.py:31-32`:
```python
ACTIONS = frozenset({"panic", "relay", "read:snapshot", "read:pending", "read:record",
                     "read:stream", "read:recall"})
```
Plus (from `apps/sigil/README.md:272-277`): approve/deny queued A2·A3 items, **panic-halt**, relay a command to the WARDEN-gated kernel, browse a read-only cockpit + live push feed, recall grounded on-screen history, and — opt-in — **arm a gesture session and act as a remote trackpad**.

### What it cannot do
- **Release a halt.** Panic is fail-safe and any engage halts; **release stays owner-only** (`bridge/daemon.py:1-4`; asymmetric kill switch in `governor/killswitch.py`).
- **Sign as the owner.** *"The owner trust-root is NEVER used to sign anything here — the phone signs, the server only verifies"* (`bridge/server.py:17-19`).
- **Widen a gesture's authority.** Every guarantee holds over the wire: A1 pointer only, `type`/`launch` always queue, owner disarm/panic/revoke always wins (`README.md:276-277`).
- **See anything sensitive over the tunnel.** `/api/pending` and the SSE stream carry only `{seq, tier, kind}` — *"never a subject, never a payload, never a secret"* (`bridge/server.py:24-26`; also `bridge/daemon.py:56-60`).
- **Upload owner pixels.** In trackpad mode the **phone runs its own on-device hand detection** and streams tiny landmark batches — *"landmark DATA, never owner pixels"* — so `RemoteLandmarker.egresses = False` is honest (`gesture/remote.py:1-21`). Malformed batches decode to an honest `[]`, never a fabricated hand (`remote.py:46-58`); foreign-session, replayed, reordered and stale batches are dropped with a bounded monotonic `seq` (no unbounded buffer).
- **Outlive a revoke.** A revoked device's **in-flight** session is killed within ~1–2 frames, not at TTL (`gesture/session.py:384-388`).

### Network posture
- **Bind:** loopback, RFC1918, Tailscale CGNAT `100.64.0.0/10`, IPv6 ULA/link-local **only** — never `0.0.0.0`, never globally routable. IPv6 uses a **positive allowlist** because Python misclassifies Teredo/6to4 as private (`bridge/daemon.py:25-42`).
- **Auth:** **no wire bearer secret.** Authentication *is* a per-request Ed25519 signature; the authorized-device set is **recomputed per request so a revocation takes effect at once**; the envelope's `action` is bound to the endpoint it hit (a `read:pending` envelope can never reach `read:recall`); effectful actions additionally pass a strict monotonic-nonce replay gate (`bridge/server.py:11-19`).
- **TLS:** owner-**pinned** self-signed cert, fingerprint printed once, stable across restarts (needed for the PWA's secure context) (`bridge/server.py:26-30`).
- **Anti-DNS-rebinding** Host/Origin allowlist derived from the real bound address (`bridge/server.py:21-22`).
- **Audit without leakage:** accepted effectful actions logged at INFO, denials at WARNING, **device pubkey prefix only**, never the envelope/signature/token/body (`bridge/server.py:56-60`).

### Status
The PWA **exists and ships**: `/home/kali/vigil/apps/sigil/sigil/bridge/webapp/` (index.html, app.js, canonical.js, service-worker.js, manifest.json, style.css). A runnable end-to-end demo against the real server on loopback needs **no phone and no tunnel**: `/home/kali/vigil/apps/sigil/demo/companion_demo.py` — *"pair → approve → relay → recall → arm → panic."*
⚠️ One stale docstring: `bridge/daemon.py:6-9` still says the network transport *"is a documented NEXT slice, not shipped here"* — that was superseded by `bridge/server.py` (Phase 9 W1-B). The transport **is** built. Do not quote the daemon docstring.

---

## Flags — what a document would be WRONG to describe as live

**Hard blockers (built but non-functional on this host):**

1. **On-box camera gesture control.** No hand-landmark ONNX model exists (`~/.sigil/models/` absent); `detect()` is a documented no-op. `gesture/landmark.py:37-42`, `gesture/run.py:38-49`, `docs/FEATURES.md:136`. **The working gesture path is the phone companion.**
2. **OCR.** A screenshot tool IS installed (ImageMagick's `import`) so the grab step works; `tesseract` is NOT → no authoritative text → nothing groundable. `perception/capture.py:7-9`. (CORRECTED 2026-08-13: an earlier pass wrongly recorded the screenshot tools as missing.)
3. **Local VLM.** No `ollama` → Moondream advisory reading returns empty. `perception/vision.py:8`.
4. **Hands-free "SIGIL" wake word.** `EnergyWake` is explicitly *"a stand-in for the real custom-'SIGIL' openWakeWord model (which needs training data)"* — `voice/backends.py:34-37`.

**Needs hardware or a mitigation:**

5. **Full-duplex barge-in on real speakers.** Needs AEC or ducking, or run half-duplex. `voice/pipeline.py:12-15`.
6. **Live voice** needs a mic + speaker. `docs/FEATURES.md:135`.
7. **Cloud ASR/TTS is network egress.** ElevenLabs is the CLI default for both (`cli.py:1281-1287`) and a key is present in `~/.sigil/sigil.env`. Piper (local) and the silence fallback are the sovereign options.
8. **Input injection** is X11-only here (`ydotool` absent, `xdotool` present); a backend with neither is honestly inert — but then the audit record says `backend_inert`, not "injected". `platform/input.py:20-26`, `gesture/session.py:409-425`.

**Deliberately deferred:**

9. **ENVOY's real IMAP inbox** — the shipped source is a JSON file. `envoy.py:7, 26-38`.
10. **OS accessibility-tree screen reading** (the richest source) — documented seam, not wired. `perception/capture.py:9, 58`.
11. **Live witness co-sign transport** for spine checkpoints — an independent witness currently co-signs manually on its own box. `spine/witness.py:38, 274`.
12. **Signed spine manifest tier** — field reserved, not implemented. `spine/manifest.py:72`.
13. **Device-signed *remote* gesture arm** was carved out of the landmark-stream slice as separately authorized (`gesture/remote.py:5-6`); the `device_arm=True` path now exists in `gesture/run.py:21-26` but is trust-widening and off by default.
14. **Neo4j per-session knowledge graph (Phase F)** — real client body, but *"the `neo4j` driver package and a running Neo4j service are **both ABSENT** in this environment"*; a live store raises `NotImplementedError`. `docs/DEFERRED-INFRA.md:45-66`.
15. **Split-view-resistant transparency is CONDITIONAL, not automatic** — at the blessed `threshold==1` only detection remains, not prevention. **OpenTimestamps Bitcoin anchoring is deferred** (needs a live calendar server). `docs/FEATURES.md:580`.
16. **macOS / Windows / Android backends and the browser-fallback web engine are honest, documented seams — Linux is the proven path.** `apps/sigil/README.md:328`.

**Framing errors to avoid:**

17. Don't call **SCRIBE a distinct agent identity** — it is `WebResearcher(Scholar)` with `name="SCHOLAR"` (`scrape/researcher.py:21`). Describe it as SCHOLAR's web-research mode.
18. Don't say the Knowledge Engine **learns facts**. Every K1–K5 artifact is advisory. *"Only a fired deterministic oracle… mints a signed FACT."* `knowledge-engine.md:207-214`.
19. Don't say **"studied enough" = complete**. `knowledge-engine.md:310-312`.
20. Don't say the phone **"controls"** the desktop. It *signs requests* the desktop *verifies*; it cannot release a halt, cannot sign as owner, cannot escape the A1/A2 gesture bound.
21. Don't cite `/home/kali/sigil` — stale fork, missing the entire K2b/capability-latch/nav-mode/offense-gate layer.
22. Don't cite `bridge/daemon.py:6-9`'s "transport is a NEXT slice" line — superseded.

**Independently verified running on this host:** Qdrant (`sigil-qdrant`, up 18h) · `fastembed`, `faster_whisper`, `kuzu`, `onnxruntime`, `qdrant_client`, `mcp`, `numpy` in `~/.sigil/venv` · live spine at `~/.sigil/spine/` · `ffmpeg`, `xdotool`, `docker`, `cargo` · the 8 `sigil-memory` MCP tools are attached to this session.