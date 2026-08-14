# VIGIL COMMAND — End-to-End UI User Guide

This is the complete operator's guide to the VIGIL COMMAND web interface: every screen,
what it is for, how it works, and what each button does. It is written for the person
sitting in front of the console, not for the engine's authors.

If you read one thing first, read **[The one rule](#the-one-rule-leads-vs-facts)** and
**[The safety model](#the-safety-model)** below. Everything else in the interface is built
on those two ideas.

---

## Contents

- [What VIGIL COMMAND is](#what-vigil-command-is)
- [Opening it](#opening-it)
- [The one rule: leads vs facts](#the-one-rule-leads-vs-facts)
- [The safety model](#the-safety-model)
- [The layout: top bar, sidebar, main area](#the-layout)
- [The top bar — every control](#the-top-bar--every-control)
- [Navigation: the three groups](#navigation-the-three-groups)
- **DO — running work**
  - [Home (Command)](#home) · [New Assessment](#new-assessment) · [Chat](#chat) · [Terminal](#terminal)
  - [Live](#live) · [Findings](#findings) · [Proof Studio](#proof-studio) · [Report](#report) · [Fixes](#fixes)
  - [Defense (AEGIS)](#defense-aegis) · [Replay Proof](#replay-proof)
- **MANAGE — records, safety, configuration**
  - [Engagement Library](#engagement-library) · [Sessions](#sessions) · [Activity](#activity)
  - [Approvals & Safety](#approvals--safety) · [Charter & Attestation](#charter--attestation) · [API Keys](#api-keys)
  - [Tools](#tools) · [Brain](#brain) · [MCP Servers](#mcp-servers) · [System & Services](#system--services)
  - [Compliance](#compliance) · [Assurance](#assurance) · [Settings](#settings) · [Governance](#governance)
- **LEARN — understand & verify**
  - [Trust Center](#trust-center) · [Proof of Posture](#proof-of-posture) · [Manual](#manual) · [Knowledge Engine](#knowledge-engine)
- [Three ways to stop things](#three-ways-to-stop-things)
- [End-to-end walkthroughs](#end-to-end-walkthroughs)
- [Glossary](#glossary)

---

## What VIGIL COMMAND is

VIGIL COMMAND is one browser interface over **two separate engines**:

- The **offense** side — reconnaissance, scanning, exploitation, findings, proof. It answers
  under `/offense/*` (an internal read/stream console and a gated action API).
- The **sovereign / defense** side — your approvals, keys, the kill-switch, the AEGIS defensive
  gateway, governance. It answers under `/sovereign/*`.

The two never run in the same process. `vigil up` puts a small reverse proxy in front of both
so you see **one origin, one login**, while the isolation between offense and sovereign is kept
underneath. When this guide says "offense plane" or "sovereign plane," that is the boundary it
means.

---

## Opening it

Start it from a terminal:

```
vigil up            # loopback only, prints a URL that carries your session token
```

It prints a line like `http://127.0.0.1:8770/?token=…`. Open that URL. The token gates the
sovereign plane, so keep it to yourself; it is bound to loopback and rotates every time you
run `vigil up`. If it is managed by the `vigil-command.service` systemd unit, the service
restarts it for you and mints a fresh token each time — reload with the new URL after a restart.

> If a screen ever says **"Offense engine offline"**, the offense backends are not answering.
> The top bar's offense indicator (below) tells you the same thing and offers a one-click start.

---

## The one rule: leads vs facts

> **A tool result, a scanner hit, or anything the model says is a LEAD. Only a deterministic
> oracle that fires over data a real target produced makes it a FACT.**

Every screen keeps this line visible. A **LEAD** is a suspicion worth chasing; a **FACT** is a
proven finding whose proof you (or anyone) can re-run offline. You will see this as:

- a green **FACT** / **CONFIRMED** shield versus a muted **LEAD** shield on findings and verdicts;
- separate **Facts** and **Leads** counters on Home, Live and Findings;
- "clear" on the Defense screen meaning *nothing was proven* — explicitly **not** a claim of safety.

Nothing in the interface can promote a lead to a fact except a fired oracle. Your confidence,
the AI's confidence, and a critic's endorsement never do.

---

## The safety model

Three ideas govern every action that could touch a target:

1. **Approve-then-run.** Offensive steps **queue for your approval**; nothing auto-fires. You
   approve or deny from **[Approvals & Safety](#approvals--safety)** or inline on **[Live](#live)**.
2. **The kill-switch.** One switch halts the whole agent mesh immediately. Engaging it never needs
   a signature (halting is always safe); **releasing** it requires your signed request. While
   engaged, the engine still perceives and reads memory but takes no action.
3. **Owner-gold controls.** Anything tinted **gold** involves *you* — your approval, your keys,
   your kill-switch. The browser never holds key material; the sovereign side signs with your
   owner key server-side.

Screens marked **owner** in the sidebar (Approvals & Safety, Charter, API Keys, Settings) live on
the sovereign plane and act only with your authority.

---

## The layout

Three regions:

- **Top bar** (always visible) — plane switcher, search, which job you are scoped to, live/idle
  state, counts, the offense start/stop control, key health, the kill-switch state, and the theme
  toggle.
- **Left sidebar** — navigation, grouped **DO / MANAGE / LEARN**. It filters with the plane switcher.
- **Main area** — the current screen.

---

## The top bar — every control

Left to right:

- **Plane switcher — `All` / `Offense` / `Defense`.** Filters the sidebar (and where relevant the
  screens) to one plane's work. `All` shows everything; `Offense` shows the run screens (New
  Assessment, Live, Findings, Fixes) plus the shared screens; `Defense` shows the AEGIS screen plus
  the shared screens. Clicking a tab now correctly moves the highlight and re-filters the sidebar;
  if you were on a screen the new plane hides, it returns you to Home rather than stranding you.
- **Search / command palette** — click it or press **⌘K / Ctrl-K** anywhere. Type to filter every
  screen, use the arrow keys to move, **Enter** or click to jump, **Esc** to close. It also carries
  the light/dark theme toggle. Its entries come from the same navigation model the sidebar uses, so
  it can never list a screen that does not exist.
- **Scope chip** — the job every screen is showing. It reads *"All engagements"* or the name of the
  one you opened. Click it to go to the **[Engagement Library](#engagement-library)** and switch job
  or widen back to all.
- **Live / Idle pill** — **Live** (green) when at least one run is actively executing; **Idle**
  otherwise; **Kill-switch** (red) when the kill-switch is engaged. This reflects *active runs*, not
  whether the offense side is merely up.
- **Counts** — agents, tools, findings currently known.
- **Offense indicator (start / stop the offense side).** When the offense backends are **down**, this
  is a gold **"Start offense side"** button — one click re-runs the same command `vigil up` uses at
  boot (no argument travels in the request). When they are **up**, it is a quiet green **"Offense up"**
  indicator carrying a small **"Stop"** button that shuts the offense console + API down (your
  findings, reports and proof stay on disk; start them again here or with `vigil up`). While either is
  in progress it shows **"Starting offense…"** / **"Stopping offense…"**. *This is why you may not see
  a "start" button: when offense is already up there is nothing to start — you see "Offense up" with a
  Stop instead.*
- **Keys badge** — how many configured secrets are healthy; click through to **[API Keys](#api-keys)**.
- **Safety / kill-switch state** — shows **Kill-switch** in red when engaged; a shortcut to
  **[Approvals & Safety](#approvals--safety)**.
- **Theme toggle** — light / dark (also in the palette).

---

## Navigation: the three groups

- **DO** — the work: Home, New Assessment, Chat, Terminal, Live, Findings, Proof Studio, Report,
  Fixes, Defense (AEGIS), Replay Proof.
- **MANAGE** — records, safety and configuration: Engagement Library, Sessions, Activity,
  Approvals & Safety, Charter & Attestation, API Keys, Tools, Brain, MCP Servers, System & Services,
  Compliance, Assurance, Settings, Governance.
- **LEARN** — understand and verify: Trust Center, Proof of Posture, Manual, Knowledge Engine.

---

# DO — running work

## Home
*(the "Command" landing screen — shared plane)*

**What it's for.** A one-glance dashboard: how many runs are active, what needs your approval, how
many findings are proven, and today's spend, plus quick-launch shortcuts.

**What it shows.** Four tiles — **Active runs**, **Waiting for you** (turns red when >0),
**Confirmed findings** ("proven by oracle" — only oracle-confirmed findings are counted), and
**Budget today** (spent / cap). A **Quick start** card and a **Recent activity** card. If one plane
is offline the page still renders; the tiles that need it show "—".

**Controls.**
- **Scan a codebase** → opens New Assessment.
- **Scan a website** → opens New Assessment.
- **Defend an app** → opens the Defense (AEGIS) screen.

The tiles and the recent-activity list are display-only. Recent activity is a snapshot taken when
the page loads (it is not a live-updating feed — use **[Activity](#activity)** or **[Live](#live)**
for that).

---

## New Assessment
*(offense plane)*

**What it's for.** A five-step wizard to configure and launch **one** assessment. Steps:
**Target · Where · Scope · How · Model.** Everything the wizard offers is pulled live from the
engine — capability packs, model backends, your host's real tool roster, your sessions — never
hardcoded.

**Step 1 — Target type.** Six choices: *Scan a codebase*, *Scan a website / API*, *Run one tool*,
*Full autonomous suite*, *Cloud / K8s posture*, *Defend an app (AEGIS)*.

**Step 2 — Where.** Fields depend on the target: a codebase path (with a *bind-mount instead of copy*
option for big monorepos), a telemetry/log file for AEGIS, a cloud assessment type + provider, or a
URL and engagement slug. An **"I am authorized to test this target"** checkbox gates the wizard only
— it is deliberately **not** sent with the launch. An optional **Objective** steers a codebase run.

**Step 3 — Scope.** For a loopback target, scope is fixed to `127.0.0.1`. For a remote target you add
scope entries as chips (CIDR ranges are rejected — scope is signed into the charter, not passed by
the console).

**Step 4 — How.** Choose **Depth** (quick / standard / deep). For "Run one tool," pick the tool from
your real roster (only tools the engine can actually drive are selectable; the rest are greyed with a
reason). Otherwise tick **"Run the engine's standard set"** or add specific **capability packs**. A
**"Flag this run as one I want fixed"** checkbox is recorded for later.

**Step 5 — Model & keys.** A read-only panel shows whether the run needs a model and which backends
are live (keys are never entered here — that is the API Keys screen). Optionally attach the run to a
permanent **Session**; for a loopback + session run you can request a **graph-backed** run.

**Footer.** **Back** (disabled on step 1), a live **"What will happen"** summary that updates as you
type, and **Next** / **Launch assessment** (each disabled until the step is valid). The safety note
"Steps queue for approval — nothing auto-fires" is always shown.

**On launch** it files the run under its engagement, scopes every screen to that job, and takes you to
**[Live](#live)** to watch it.

---

## Chat
*(offense plane)*

**What it's for.** A plain-language front door to the engine: ask in natural language, or attach a
zip / files / images and ask questions about them. Every model-authored answer is labelled a
**LEAD**; only a gated, oracle-confirmed run mints a fact.

**What it shows.** A sessions sidebar (your chats, each with a turn count and a link-count when it
draws on others), the transcript, a system model/effort strip, an attachments area, and a
"draws on" panel of linked chats.

**Controls.**
- **New chat** — start a blank conversation.
- **Session rows** — open a past chat.
- **Set system model** / **Set system effort** (owner-gated) — change the engine's reasoning model /
  effort for future runs ("effective on the next `vigil up`"); these do **not** change the current
  conversation.
- **Attach** (＋) — pick files; they upload immediately but their bytes do **not** reach the model
  until you consent at send-time. Max 12 attachments. Each attachment chip has a **✕** that deletes it
  on the console.
- **Target** (URL or codebase path) and **Mode** (`auto`, `url / API / infra`, `codebase`,
  `suite (autonomous)`, `one tool`) selectors; when mode is "one tool," a **Tool** picker appears.
- **Send** (or Enter) — before anything leaves the machine, an **egress-consent modal** lists the file
  count, byte total, file names, a sha256 prefix, and the destination model, with **Cancel** and
  **Send them**. Consent is once per attachment.
- **Link another chat** / the **✕** on a "draws on" chip — connect / disconnect chats so a live run can
  use another session's knowledge as advisory priors (never facts).
- In assistant replies: **Watch live** (jumps to Live for a launched run) and **Run the gated scan on
  these files** (launches a codebase run over an extracted path).

Conversations are stored locally under `.vigil-live/chats/`.

---

## Terminal
*(offense plane)*

**What it's for.** A local, **read-only** command surface. The AI can propose an allowlisted command,
answer a question from retained findings, or route you to a scan screen — but **only local read-only
tools run, and only after you approve.** No network, no file changes, no shell; injection-safe by
construction.

**What it shows.** A guardrail legend, an "Ask in plain English" dock, a direct-command box with a
live verdict badge, a signed **Output** panel, and a **Recent commands** history (each row: sequence #,
argv, tier, `exit N · signed`).

**Controls.**
- **Ask** (dock) — describe what you want; the engine proposes. A **command** proposal shows a verdict
  badge and **Run / Edit / Cancel**; an **answer** proposal is a read-only bubble ("NOTHING RAN"); a
  **route** proposal offers a button to the right screen (also "NOTHING RAN").
- **Direct command box** — type a command; it dry-runs continuously and shows a verdict; Enter or **Run**
  executes it. Every run appends a **signed record** (tier, exit code, signature) to history.
- **Minimize / Maximize / Restore** the ask-dock (state is remembered).

Anything that would crawl, scan or exploit is pushed to the gated engagement path with its own
approvals — the terminal never does it.

---

## Live
*(offense plane; approvals come from the sovereign plane)*

**What it's for.** Watch a single run unfold in real time — every reasoning event, tool call, finding
and refusal — with explicit **FACT vs LEAD** labelling and inline owner approvals.

**What it shows.** A run picker; a header card with status, target, elapsed time and four tiles
(**Actions / Facts / Leads / Refusals**); an **Approvals** card (owner); a live **Reasoning graph**
laid out in OODA lanes; and a filterable **Timeline**. Events stream live (Server-Sent Events) for
spine/progress runs, or poll for sandboxed (Strix/AEGIS) runs.

**Controls.**
- **Run selector** — switch which run you are watching.
- **Stop run** (red) — trips the engagement's kill-switch, stopping that run. Enabled only while a run
  is actually running. *(This is the per-engagement stop; see [Three ways to stop things](#three-ways-to-stop-things).)*
- **Filter** — All / Facts / Leads / Inbox.
- **Approve / Deny** on each approval card (owner) — sign off or refuse a queued action; the sovereign
  side signs it.
- **Click a timeline row** — a drawer with the event's kind, ids, a FACT/LEAD verdict, the confirming
  oracle and confidence, and the raw payload.
- **Click a graph node** — its label and summary.

The **Inbox** filter shows agent-to-agent coordination messages, explicitly labelled "NOT evidence" —
nothing there can promote a finding.

---

## Findings
*(offense plane)*

**What it's for.** The post-run analysis hub: proven bugs, the attack graph, re-checkable evidence, a
coverage map, and an investigation replay — all oracle-gated. Five tabs.

**Tabs & what each shows.**
- **Findings** — tiles (Confirmed FACTs / Leads / Endpoints / Requests audited); a filter (All / Facts /
  Leads); a table (Severity · Bug class · Surface · Oracle · Status). Click a row for a drawer with the
  verdict (CONFIRMED / CONTRADICTED / UNGROUNDED / LEAD), CVSS, impact, the oracle's rationale, a
  **HOW-TO-VERIFY** note and remediation. The drawer's **"Re-verify this run (offline)"** button
  re-fires every retained certificate with **no target traffic** and shows an *N / total reproduced*
  badge.
- **Attack Graph** — nodes/edges/attack-paths/choke-points as a graph; click a node for its belief,
  grounding and provenance, with each edge marked FACT or LEAD.
- **Evidence** — per-certificate cards (Sound / Tampered / Claim-mismatch / No-certificate); each has an
  **"Offline re-verify"** button that re-runs the certificate and reports its honest state. A prominent
  **"Traffic sent: 0"** tile underlines that re-verification touches nothing.
- **Coverage** — pages crawled, requests audited, endpoints, detected stack; passive hygiene and
  DOM-XSS items are explicitly labelled LEADS, with a blind-spots legend.
- **Timeline** — a slider scrubbing the attack graph's growth over time ("Pure reconstruction — no
  traffic").

**Controls.** Run selector, tab buttons, the Findings filter, the two re-verify buttons above, and the
graph/timeline interactions. Runs that have no saved web report (Strix/AEGIS sandbox runs) show an
honest redirect to Live instead of empty tabs.

---

## Proof Studio
*(offense plane)*

**What it's for.** Turn a generated exploit into a **signed, replayable proof bundle**. Per run it
shows which reproductions an oracle confirmed (**FACT**), which were honestly not reproduced
(**LEAD**), and which had dangerous PoC content refused before any mint (**DENIED**).

**Controls.**
- **Run selector** — pick a run; its proof summary and per-proof cards load.
- **Export verifiable bundle** — enabled only when the run has at least one oracle-confirmed FACT.
  Writes a bundle and shows its path, the **trust-root fingerprint** (publish it out-of-band so a bundle
  re-signed under another key is refused), and the exact **offline verify** command.

Each proof card shows its disposition, the confirming oracle, the reproduction channels, and whether it
crossed to the signed spine (only a FACT does).

---

## Report
*(offense plane)*

**What it's for.** A live, always-current client report. Every finding is **re-verified offline on
load**, so "sound" is a re-checkable certificate, not a stale PDF or the AI's word. Only proven
findings appear.

**Controls.**
- **Run selector** — pick the run.
- **⤓ Download dossier** — packages the reports + proof bundle + a signed manifest and downloads a
  tamper-evident, offline-verifiable `.zip`.

Each proven finding card shows its surface, the confirming oracle and confidence, the certificate id,
and standards pills (OWASP / CWE / ATT&CK / PCI) where mapped.

---

## Fixes
*(offense plane)*

**What it's for.** What to remediate after discovery: a run's oracle-confirmed fixable findings with
real remediation guidance, plus the gated ladder any auto-fix must follow. **Only proven FACTs are
fixable — unproven leads are never auto-fixed.** The screen never clones, builds, or opens a PR by
itself; live auto-apply is a separate, sovereign-gated capability that is **OFF** by default.

**What it shows.** Overview tiles (**Fixable / Unproven / Live auto-fix = OFF / Verify**); the gated
fix **ladder** (the stages an auto-fix passes through); the fixable findings with remediation text; and
the **highest-impact fix points** from the world model (choke-points that sever the most attack paths).

**Controls.**
- **Run selector.**
- **Apply fix (gated)** — per fixable finding; runs the gated, **non-destructive** patch ladder when the
  run has a signed offense spine, otherwise shows exactly what is required. It never opens a PR.

---

## Defense (AEGIS)
*(sovereign / defense plane)*

**What it's for.** Put VIGIL as a reverse proxy in front of an app you run and **prove AI attacks
against it in real time.** A **CONFIRMED** verdict is a proven attack (an oracle fired); a **lead** is a
suspicion; **clear** means nothing was proven — explicitly **not** proof of safety.

**What it shows.** Status tiles (Gateway running/stopped, Mode ENFORCE/Observe, Upstream, Actors seen),
a setup form or a running panel, an actor-belief list, and a live **verdict** stream.

**Controls (setup form, when stopped).** Your app's upstream URL; bind host (a non-loopback bind warns
you first); port; **Mode** (Observe — blocks nothing, default; or Enforce — blocks proven attacks, needs
the `AEGIS_RESPOND` entitlement and silently downgrades to Observe without it); optional honeypot paths; a
per-deployment **secret** with a **Generate** button; a gateway slug; and **Start defense**.

**Controls (running panel).** A status line, a downgrade note if Enforce was requested but not available,
and a **Stop gateway** button. A **"Run on your edge"** drawer gives a copyable production command for a
routable edge (bind the public interface *there*, never in the console).

Verdict rows badge **ATTACK PROVEN / lead / clear**; clicking a row with a certificate opens the attack
certificate (the matched span stays server-side, not streamed to the browser). This local gateway is for
testing; real protection runs the production command on your own edge.

---

## Replay Proof
*(offense plane; fully offline)*

**What it's for.** Paste any VIGIL report or finding (`report.json`) and **re-fire its retained oracle
proofs offline** — pure re-computation, no target, no traffic. A tampered proof surfaces as
**CONTRADICTED**, never as a green reproduction.

**Controls.**
- A textarea to paste the JSON.
- **Re-fire proofs offline** — runs each finding's retained proof and shows four tiles (Findings /
  Reproduced / Contradicted / Ungrounded) plus a per-finding verdict (**REPRODUCED** / **CONTRADICTED** /
  **UNGROUNDED**).

The tool cannot be tricked into a false green: only a genuine, re-runnable proof reproduces.

---

# MANAGE — records, safety, configuration

## Engagement Library
*(shared plane)*

**What it's for.** The archive of every past job, most-recently-worked first, so you can return to a
job months later and get back into its runs, findings and proof. **Opening a job scopes the whole
console to it.**

**What it shows.** A table (Job, Last worked on, First seen, Kind, Subject, Runs, Findings). The job you
are currently scoped to carries an **"active"** badge. Times are in your timezone; a "· N proven" suffix
counts oracle-proven findings. Opening a job shows its detail: identity, timestamps, counts, charter/
safety pills, and its runs.

**Controls.**
- **Open** (or click a row) — makes that job the active scope for every screen.
- **Rename** — a friendly name (changes nothing signed — certificates still verify).
- **All engagements** — widen back to seeing every job.
- Per run (in detail): **Findings**, **Evidence**, **Dossier** (download), **Rename**.

Scoping hides nothing permanently and deletes nothing.

---

## Sessions
*(offense plane)*

**What it's for.** Manage permanent **sessions** — every chat and assessment is a session you can
rename, reopen, connect to other sessions (so a live run can draw on their knowledge as advisory
priors), and remove.

**What it shows.** A grid of session cards, each with a **kind** label (Engagement / Chat / Mixed), a run
count, run-id chips (linking into Live), and any connected sessions.

> **Note on the "kind" label.** The kind (e.g. *Engagement*) is a category, **not** a running state. An
> engagement-kind session is created automatically the moment the console or a chat starts — it does not
> mean a scan is running. The label is shown in a neutral colour for exactly this reason; whether a
> session has work is shown by its run count, and whether anything is *executing* is shown by the top
> bar's Live/Idle pill and the Active runs tile.

**Controls.**
- **New session** — create a named session.
- **Rename** — a friendly name.
- **Connect…** / the **✕** on a "draws on" chip — link / unlink sessions.
- **Delete** — remove from your list (reversible).
- **Delete permanently** (red) — remove from history; your runs and the signed record are kept.

---

## Activity
*(shared plane; read-only)*

**What it's for.** A live, read-only, cross-plane operations view — active offense runs, the sovereign
agent mesh and spine, and a live event stream — so you can see how VIGIL is working in the background.
**Nothing here changes anything.**

**What it shows.** A system-status header (offense / sovereign / kill-switch), four tiles (Active runs,
Agents active, Ingest lag, Kill-switch), an "Active work" panel of offense runs, an "Agent mesh & spine"
panel, and a live event stream (deduped, newest first). It polls every few seconds and streams new
events from the current spine head.

**Controls.** **Watch live** on a run (jumps to Live) and, in the empty state, **New Assessment**. There
are no mutating controls — to act, use Live, Approvals & Safety, or New Assessment.

---

## Approvals & Safety
*(sovereign plane — **owner**)*

**What it's for.** Your live safety console: everything awaiting your sign-off, the master kill-switch,
capability toggles, agent trust-promotions, and a live governance feed.

**What it shows.** Four tiles (Kill-switch, Waiting, Spine head, Budget today); a **"Waiting for your
approval"** queue; a **Capabilities** card; an **Agent promotions** card; the **Kill-switch** card; a live
governance feed; and a separate read-only **"Pending approvals"** list from the offense plane.

**Controls.**
- **Approve** / **Deny** (owner) — sign off or refuse a queued action; the sovereign side signs it.
- **Engage kill-switch** (red) — halts the agent mesh immediately (no signature needed).
- **Release** (owner) — clears the kill-switch; this **requires your signed request**.
- **Enable / Disable** — gesture and voice capabilities.
- **Grant promotion** / **Revoke** (owner) — widen or narrow an agent's auto-approval scope. Scope `*`
  covers every kind; a per-kind revoke does not reduce a `*` grant; ENVOY and DELEGATE can never be
  promoted.
- **Copy** (in the read-only offense list) — copies the CLI command to sign that request out-of-band; this
  console is keyless and can never sign.

The two approval lists are distinct: the top one is the sovereign queue with working Approve/Deny; the
bottom one is a keyless offense-plane display that only shows the CLI sign command.

---

## Charter & Attestation
*(sovereign context — **owner**)*

**What it's for.** Manage the signed engagement **charter** and usage attestation that gate every
target-touching action. *No attestation, no run.* The UI can mint only a **loopback** authority; a remote
target needs an out-of-band signed charter the UI can only verify and guide.

**What it shows.** An engagement-slug picker; an **Authorization status** card (charter present, authorized
scope, reach, window, gate chain); a **Provision a loopback authority** card; a **Remote target — charter
required** card with the exact out-of-band CLI ceremony; and a **usage attestation ledger**.

**Controls.**
- **Load** — read a given engagement's charter.
- **Provision (loopback only)** (owner) — mint + sign an authority with scope **hard-fixed to 127.0.0.1**.
- **Target host** — an advisory "authorized for this target?" check (the gate is what enforces).
- **Re-check charter** — re-read after you provision a remote charter out-of-band.
- **Load ledger + verify chain** — show the attestation ledger and confirm it is signed, monotonic and
  not back-dated.

The UI can never mint or widen a remote charter — that is a deliberate CLI act on a host holding your key.

---

## API Keys
*(sovereign plane — **owner**)*

**What it's for.** Manage every secret the system uses — model-provider keys, cloud credentials,
integrations — sealed on the machine with a live health check. **Keys are never shown back to the
browser.**

**What it shows.** An owner banner, a **Test all keys** button, a failing-keys warning if any, and grouped
secret sections (model/integration keys as cards; cloud/graph credentials as provider cards). Each set key
shows its backend, a fingerprint, and a live health chip.

**Controls.**
- **Test all keys** — probes every set key and reports which fail.
- **Seal** (owner) — store a secret on the machine (keyring / TPM); only a fingerprint is recorded, never
  the value. Sealing over a set key is how you **rotate** it.
- **Test** — live-probe one key.
- Cloud credentials: **Seal** (line or pasted-file credentials), **Save** (non-secret config like region /
  role ARN), and **Test connection**.

The system runs keyless (deterministic oracles only) until a model key is added.

---

## Tools
*(offense plane)*

**What it's for.** An inventory of the external security CLIs the offense engine can run on this host,
probed live, plus an advisory "tool consciousness" view of which tools the engine actually recognises and
can drive.

**What it shows.** Summary tiles (Installed / Missing / Failed / Required missing); per-tool cards (status,
core/optional, version, path, install hints, and a red warning if a same-named impostor shadows a tool on
PATH); a reference list of Strix sandbox tools (not host-installed); and the **Tool consciousness** panel
(Adopted / Refused / Installed / Installable, with per-tool "playbook ✓" / "typed argv ✓" / verdict).

**Controls.**
- **Copy** — copy a tool's install command (the plain list never installs for you).
- In Tool consciousness: **Install** → the server replies with the exact command → an owner **Run it**
  button installs it and the screen re-probes; **Research** shows the canonical query and official docs.

A tool is "adopted" only if it is globally recognised **and** drivable; everything here is advisory — a
real run still passes the safety gate.

---

## Brain
*(offense plane)*

**What it's for.** A tabbed view of the **propose-only** decision engine and what the system has learned.
Reasoning is **advisory** — it re-ranks and defers, but **never promotes a finding; only a fired oracle
confirms.**

**Tabs.**
- **Decision engine** — the active brain, its gate posture, and (only when a real proposal exists) a target
  profile and a proposed attack chain of LEADs, each step showing its danger, an effectiveness prior, and a
  per-step gate verdict (recon in staging auto-eligible; everything else queues for your approval).
- **Memory** — engagements / findings / priors / dead-ends, and learned priors with honest success bounds
  (never a fabricated score).
- **Benchmark** — a **Run the soundness benchmark (LIVE)** card (owner) that re-derives this host's
  true/false-positive/false-negative counts against the built-in corpus, loopback-only with no egress; a
  flagged false positive is shown in red.
- **Catalog** — a filterable list of capabilities (advisory only).
- **Intel** / **Planner** (per engagement, owner) — **Compute plan projection** ranks a plan with no traffic;
  **Run offline recon** ingests passive collectors over bundled fixtures with no egress (live collection is a
  charter-gated engagement, never one-click).

---

## MCP Servers
*(offense plane; read-only)*

**What it's for.** A read-only catalog of the gated capabilities this offense engine exposes to an external
MCP (Model Context Protocol) client over an on-host stdio server.

**What it shows.** One card per exposed tool ("GATED"), each with its safety tier, gated status, provenance
and a read-only hint, plus how to start the server (`crucible mcp serve --slug <engagement>`). The transport
is on-host stdio — no network surface.

**Controls.** None — this screen is informational.

---

## System & Services
*(offense plane)*

**What it's for.** A readiness dashboard for the offense engine's host: whether prerequisites are installed,
whether the UI ports are free, and the state of every Docker service.

**What it shows.** A **Prerequisites** card (binaries, venvs, writable dirs), a **UI ports** card, a **Docker
services** card (running / absent / other), an **Action needed** list when something is wrong, and notes.

**Controls.**
- **Bring up missing services** (owner) — idempotently creates the absent services (running ones are left
  alone), then re-checks.
- **include Neo4j + otel** — a checkbox that also brings up those two heavier services.

---

## Compliance
*(offense plane)*

**What it's for.** Map each oracle-**confirmed** finding of a run onto compliance / standards controls;
unproven leads are shown but assert **no** control coverage.

**What it shows.** A run picker and a "findings → standards controls" list. Each proven finding shows control
pills — **OWASP, CWE, MITRE ATT&CK, PCI-DSS** (SOC 2 / ISO 27001 are named in the mapping families) — and a
status badge (**proven** vs **advisory**). A lead or unmapped class asserts no coverage.

**Controls.** The run selector. This screen is read-only.

---

## Assurance
*(offense plane)*

**What it's for.** Continuous-proof / drift: it diffs the set of oracle-confirmed FACTs between **two runs of
the same engagement** — a fact that newly appears is a regression (new exposure); one that disappears is a fix
— plus a live read-only telemetry projection over the signed spine. Deterministic and offline; certificates
are re-fired, never re-attacked.

**What it shows.** A **live assurance projection** card (Facts / Leads / Refusals / Tool calls, per-engagement
and by-kind, when the telemetry collector is running); a two-run picker ("Now" vs "baseline"); and a drift
summary listing **Regressions**, **Fixed**, and **Stable** findings.

**Controls.**
- **Now** / **vs baseline** selectors.
- **Re-verify now** — re-fires the retained certificates offline (no traffic).
- **Download drift (JSON)** — a browser export of the already-fetched drift result.

---

## Settings
*(sovereign plane — **owner**)*

**What it's for.** Control the reasoning **model** and system configuration. (API keys have their own screen.)

**What it shows.** Cards for the reasoning model, a link out to API Keys, reasoning **effort**, "bring your own
model" (Bedrock / Vertex / Azure / Mistral / self-hosted / Ollama / Claude), and non-secret system configuration
grouped by subsystem.

**Controls (all owner-signed server-side).**
- **Use this model** — set the engine's model.
- **Apply effort** — set the reasoning effort (blank resets to the model default).
- **Use this provider** — configure a bring-your-own-model provider and the keys it needs.
- **Save** (per config field) — set a non-secret env var; blank clears it. The server type-validates and
  refuses unknown variables.
- **Manage API keys** — jumps to API Keys.

Changes take effect on the next `vigil up` / service restart.

---

## Governance
*(offense plane; **read-only audit**)*

**What it's for.** A strictly read-only view of runtime governance posture: whether exploitation runs
**GOVERNED** vs **UNGOVERNED**, the sovereignty tier, the conjunctive safety gate, and the m-of-n destruction
quorum. It **cannot provision, authorize, or fire anything.**

**What it shows.** An exploitation-governance card (entitlement enforced? granted tier?), a sovereignty-tier
card (sealed / not), the **conjunctive gate** (all conjuncts a target-touching action must clear, fail-closed),
and a **destruction authority** audit (threshold, authorizers, consumed nonces, pending authorizations).

**Controls.** None — this screen has no buttons. Minting / consuming a destructive authorization happens only
via the gated CLI with m-of-n independent signatures.

---

# LEARN — understand & verify

## Trust Center
*(offense plane; verify-only)*

**What it's for.** Render VIGIL's signed, offline-verifiable **certificates as certificates** — each one's
trust root (m-of-n authorizers + threshold), its out-of-band fingerprint pin, the signed digest and accuracy
numbers — and run the certificate's real offline verifier live for a PASS / FAIL. No mint, no target, no
traffic.

**What it shows.** A doctrine block and one card per certificate: schema, signed digest, trust root, authorizers,
an honest fingerprint label (source-**pinned** vs per-run self-asserted), and a recall/coverage/plan-integrity
summary.

**Controls.**
- **Out-of-band pin (optional)** — for a per-run cert, supply the pin you hold independently to bind the trust
  root (a fresh-key re-sign then fails the pin).
- **Verify offline** — re-derive the digest, check the signature (and the source pin), and show a green
  **PASS** or red **FAIL** with an honest tri-state for the pin (matches / does not match / **unpinned**, never
  shown green).

---

## Proof of Posture
*(offense plane; verify-only)*

**What it's for.** Render each signed **Certificate of Non-Exploitability**: a coverage-bounded, offline-
verifiable proof that, over the surface the scanner *reached*, an applicable oracle had a live channel and did
not fire. **CLOSED is never a claim of security against everything** — the certificate states its coverage
denominator and its honest residual.

**What it shows.** One card per certificate: the target, a freshness note, four tiles (**Closed / Open /
Unproven / Re-executable**), a **coverage denominator** ("what this proof covers — and what it does not"), the
residual boundary, per-surface claims (with re-executable vs binding-only tier), the trust root and pin, and the
exact offline-verify command.

**Controls.**
- **Refresh** — reload the certificates.
- **Download certificate (JSON)** — a browser export.
- **Copy** / **Copy path** — copy the offline-verify command and the portable bundle path for third-party
  offline re-verification (the bundle carries its own verifier and refuses a forged CLOSED).

---

## Manual
*(shared; static reference)*

**What it's for.** The in-app, plain-language manual: a two-column reference (sticky contents + content)
explaining how every part of VIGIL works — the safety model, running an assessment, watching it live, findings
& evidence, fixes, arming live auto-patch, defense, approvals, settings, brain, deploying, and a glossary.

**Controls.** The contents links smooth-scroll to each section. It is documentation — no API calls, no actions.

---

## Knowledge Engine
*(both planes)*

**What it's for.** An auto-updating feed of vulnerability intelligence (NVD, OSV, CISA-KEV) alongside the
defensive knowledge catalog, plus the owner-signed autolearn / self-evolve controls. Every feed entry is an
intel-tier **LEAD, never a fact**; the live pull is a **gated, opt-in egress act** (offline is the default).

**What it shows.** An engagement picker; feed sources; vulnerability leads (KEV / lead); the defensive knowledge
catalog (advisory operators, never facts); the propose-to-learn and add-a-source cards; the self-evolve card;
and the **knowledge/ folder → git** card.

**Controls.**
- **Pull now** — one-shot gated egress refreshing the feeds (disabled when the kill-switch is engaged).
- Recurring **feed sidecar**: **Interval**, **Start**, **Stop** — opt-in, kill-switch-gated, leads only.
- **Autolearn** toggle, **STOP (emergency halt)** / **Release**, and per-proposal **Accept / Deny / Queue for
  approval** (owner) — accepting authorizes *learning*, never a fact.
- **Add a source**: queue a CVE, or **Learn from URL** (fetched through the scope / robots / SSRF gate; grounded
  claims are verbatim source spans, else advisory).
- **Self-evolve**: **Draft skills (deep-learn)** and **Run evolve tick** — draft advisory skills and record
  calibration; authorize ≠ apply, mints no fact, fires no oracle.
- **knowledge/ folder → git**: **Status** and **Regenerate + commit** (owner) — regenerate the system-map,
  secret-scan, and commit the `knowledge/` folder **locally** (a secret hit refuses the commit and lists files to
  redact); pushing to GitHub stays a deliberate `vigil knowledge push` CLI act — this never pushes.

---

## Three ways to stop things

There is no single "stop" because there are three different things you might want to stop:

1. **Stop one running assessment.** On **[Live](#live)**, the **"Stop run"** button trips *that engagement's*
   kill-switch. Use this to halt the run you are watching.
2. **Halt everything now.** On **[Approvals & Safety](#approvals--safety)**, **"Engage kill-switch"** halts the
   whole agent mesh immediately (no signature needed). Releasing it needs your signed request. This is the
   emergency stop.
3. **Stop the offense side entirely.** In the **top bar**, when offense is up, the **"Stop"** button beside
   "Offense up" shuts down the offense console + API (findings, reports and proof stay on disk). Start it again
   from the same spot or with `vigil up`. This is the counterpart to "Start offense side."

A **session** on the [Sessions](#sessions) screen is not a running scan — deleting it does not stop anything;
it just removes a record.

---

## End-to-end walkthroughs

**Run your first assessment.**
1. Top bar → confirm **Offense up** (if it says "Start offense side," click it).
2. **New Assessment** → pick a target type → fill *Where* → set *Scope* → choose *Depth* / packs → *Launch*.
3. You land on **Live**. Approve any queued step (owner). Watch Facts vs Leads accrue.
4. When it finishes, open **Findings** → review CONFIRMED findings → open a finding → **Re-verify (offline)**.
5. **Report** → **Download dossier** for a client-ready, offline-verifiable package; or **Proof Studio** →
   **Export verifiable bundle** for a single proven exploit.

**Verify a finding without trusting the tool.**
- **Replay Proof** → paste the `report.json` → **Re-fire proofs offline**. Reproduced = genuine; Contradicted =
  tampered. Or open the finding's drawer in **Findings** and use its offline re-verify. Or run the printed
  offline-verify command from **Trust Center** / **Proof of Posture** on another machine.

**Defend a live app.**
- **Defense (AEGIS)** → enter your app's upstream → start in **Observe** → watch verdicts. Move to **Enforce**
  (needs the entitlement) only when you are ready to block proven attacks, and run the production command on your
  own edge.

**Stop everything fast.**
- **Approvals & Safety** → **Engage kill-switch**. Everything halts; release it (signed) when ready.

---

## Glossary

- **LEAD** — a suspicion (tool hit, scanner result, or model claim). Not proof.
- **FACT** — a finding a deterministic **oracle** confirmed over real target data; its proof re-runs offline.
- **Oracle** — a small deterministic program that fires only on genuine evidence; the sole thing that mints a fact.
- **Engagement (job)** — one authorized piece of work; every run, finding and certificate belongs to one.
- **Run** — one execution within an engagement.
- **Session** — a permanent, renamable container for chats and runs (a *kind*, not a run-state).
- **Charter / attestation** — the signed authorization that gates every target-touching action.
- **Kill-switch** — the master halt; engage needs no signature, release does.
- **Owner (gold)** — a control that acts with *your* authority; the browser never holds your keys.
- **Offense plane / sovereign plane** — the two isolated engines federated behind one origin by `vigil up`.
- **Certificate of Non-Exploitability** — a coverage-bounded, offline-verifiable proof that a reached surface
  was CLOSED (an oracle had a channel and did not fire).

---

*This guide reflects the interface as built. If a screen or button behaves differently from what is written
here, trust the interface and tell the operator — a wrong line in a security tool's guide is a bug.*
