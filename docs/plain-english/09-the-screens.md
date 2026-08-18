# Every Screen, And How An Operator Uses It

This chapter is a guided tour. It walks through every screen the operator sees, one at a time, and
says three things about each one: what is on it, what the operator can do on it, and what actually
happens as a result. It is written for a reader who has never seen the software and has no software
background.

At the end there are three further sections: the capabilities that exist but have no screen at all;
the other ways into the system, including two routes intended for another piece of software rather
than a person; and the command line — the way of driving the same system by typing instructions
instead of clicking — with a plain comparison of which jobs suit which method.

Where a screen exists but a control on it does not yet do anything, that is said plainly. Where a
capability is real but has only been exercised on the operator's own machine and not yet against an
outside system, that is said plainly too. Nothing in this chapter is aspirational.

---

## 1. Before the tour: how the operator gets to a screen at all

### 1.1 One command, one web address

The operator types one instruction into their terminal:

```
vigil up
```

The system then prints a box on screen that says, in effect, "VIGIL COMMAND is up — open ONE origin
in your browser", followed by a web address. By default that address is
`http://127.0.0.1:8770/?token=…`.

Two things about that address matter.

**`127.0.0.1` means "this computer and no other."** It is the address a computer uses to talk to
itself. A machine anywhere else on the internet cannot reach it. This is not a setting the operator
has to remember to switch on; it is the default.

**The `?token=…` part is a one-time session key.** It is generated fresh each time the system starts
and it is what unlocks the owner-only screens. Think of it as the key to the filing cabinet rather
than the key to the building.

If the operator does not want a browser window to open automatically, they add `--no-browser`. To
shut everything down again they type `vigil down`, or press Ctrl-C.

### 1.2 What is running behind that single address

This detail matters to a reviewer because it explains a security property that shows up repeatedly
in the tour.

The one web address the operator opens is a **reverse proxy** — a switchboard. It is the only thing
listening for a human. Behind it sit three separate programs, each on its own internal channel, each
only reachable from the same machine:

| Behind-the-scenes program | Internal address | What it is for |
|---|---|---|
| The sovereign cockpit | `127.0.0.1:8733` | The owner's side. Holds the owner's signing key. Approvals, the emergency stop, settings, API keys. |
| The offence console | `127.0.0.1:8787` | The reading side of the security engine. Reports, findings, live event streams. |
| The offence action plane | `127.0.0.1:8799` | The gated channel for things that actually *do* something. It is also the programmatic way in for another piece of software; described in full in §9.2. |

The switchboard routes by address: anything under the sovereign path goes to the cockpit, one
specific family of addresses under the offence path goes to the action plane, and everything else
under the offence path goes to the offence console. The screens use the console for their reading;
the action plane exists for actions and for programs.

The switchboard code contains a deliberate refusal: it will not bind itself to a publicly reachable
network address. It permits only loopback (this machine), ordinary private home/office network
ranges, and the address ranges used by private tunnels. A private tunnel is an encrypted link that
makes two machines in different buildings behave as though they were plugged into the same office
network; the two common products of that kind are named Tailscale and WireGuard, and the address
ranges they use are reserved for that purpose and are not reachable from the open internet. It
explicitly refuses
`0.0.0.0` and `::` — the two ways a program normally says "accept connections from anywhere" — and
refuses globally routable addresses. The code even carries a note explaining that it uses a positive
allow-list for the newer IPv6 addressing scheme, because the standard library mislabels two
particular transitional address ranges as private when they are actually routable.

Before it starts anything, the command checks that all four ports are free. If one is occupied it
refuses to start rather than leaving half-started background programs behind.

The switchboard also answers **two addresses of its own**, which it forwards to nobody. One reports
which of the programs behind it are answering; the other starts the two attack-side ones. It is the
only process that can honestly do either, because it serves the interface itself and therefore is
still running when they are not, and because it is what started them in the first place. The request
that starts them **names no command**: any body sent with it is discarded unread, and the instruction
the switchboard runs is rebuilt from its own start-up configuration, so no path, port or command can
ever travel in a request — anything else would be a way of running arbitrary programs wearing the
costume of a button. Both addresses are behind the same checks as everything else, and starting
something already running is a no-op that says so. As §8 records, **no screen offers this today**:
the control exists in the interface's code but is placed nowhere, so in practice the operator still
starts the attack side by typing.

### 1.3 An honest caveat about which interface you get

There are, in fact, **three different web interfaces** committed in this system, plus one
terminal-based interface that comes from a third-party tool. (There are also two ways in that are
not interfaces for a person at all, meant instead for another program to use; they are described in
§9.2.)

The main product — the 29-screen application described in this chapter — is called **VIGIL COMMAND**.
It is assembled and served *by the `vigil up` switchboard*.

If an operator instead points their browser directly at the internal offence console
(`127.0.0.1:8787`) or directly at the sovereign cockpit (`127.0.0.1:8733`), they will get an
**older, smaller interface** — not VIGIL COMMAND. A change that would have made all three routes
serve the same modern interface was made and then reverted, because it broke the sovereign side's
automated tests. The older interfaces are still present and still served on their own addresses.

The practical instruction is simple: **always go in through `vigil up`.** The older interfaces are
described briefly later in this chapter, in §9.1 on the other ways into the system, but they are not
the product interface.

### 1.4 What the interface is allowed to be

Two design rules constrain everything that follows, and they are worth stating once so the tour makes
sense.

**The screen is a driver, not an authority.** The web interface never decides that a security
weakness is real. It never sets the boundaries of what may be tested. When the operator presses a
button that starts work, the button asks a back-end program to re-run the same gated command-line
tool the operator could have run themselves. Whether something counts as proven is decided elsewhere,
by an automatic deterministic test, and the screen simply displays that decision.

**The browser never holds a key.** The owner's cryptographic signing key lives on the server side of
the sovereign cockpit. When the operator clicks "Approve", the browser sends an authenticated
*request*; the server does the signing. A person who steals the browser session cannot walk away with
the key.

There are also two ordinary web-security protections worth naming in plain terms. Every request the
interface makes carries a custom marker header; the back end refuses any action request that does not
carry it. This blocks a classic attack where a malicious website in another browser tab silently
submits commands to a local program. Separately, the back end refuses read requests whose claimed
address is not the expected local one, which blocks a related trick where an attacker's domain name
is re-pointed at the operator's own machine.

---

## 2. The furniture that appears on every screen

Before the individual screens, here is the frame that surrounds all of them. It never changes.

**Left side — the navigation list.** Twenty-nine entries, grouped under three headings: **DO**
(eleven entries), **MANAGE** (fourteen), **LEARN** (four).

**Top bar, from left to right:**

- **Plane toggle** — three buttons: *All*, *Offense*, *Defense*. This filters the navigation list.
  "Offense" hides the defensive screen; "Defense" hides the attack-side screens. It is purely a
  view filter; it changes nothing about what the system is doing.
- **The job chip** — the name of the job every screen is currently showing, or the words *All
  engagements*. Clicking it opens the Engagement Library, which is where a different job is chosen
  or the view is widened back to everything. It is described in full at the end of this section,
  because it changes what the operator sees on nine of the twenty-nine screens.
- **A "Search or run a command" box.** It carries a keyboard-shortcut hint printed as `⌘K` — the
  Macintosh command-key symbol followed by the letter K. (On a Windows or Linux keyboard the
  equivalent key is Control; the interface only ever prints the Macintosh symbol, which is itself a
  small rough edge.) *The box does not work yet.* Clicking it shows a small message reading "Command
  palette is on the roadmap — for now use the sidebar. Start a run from New Assessment." It is a
  visible control with no function behind it. It is the clearest example in the whole interface of a
  placeholder, and it is listed again in the section below on where the interface is honestly
  incomplete.
- **Three live counters** — agents, tools, findings.
- **A status pill** reading **Live**, **Idle**, or **Kill-switch**.
- **A failing-key warning badge** — hidden unless at least one stored API key failed its last live
  check, in which case it reads "N API keys failing" and links to the API Keys screen. Note that this
  is refreshed when the system starts and after any key change; it is not continuously polled.
- **The safety button** — the most important item in the bar. It has exactly three states:
  **"KILL-SWITCH TRIPPED"** (everything is halted), **"N waiting for you"** (N decisions need the
  operator's sign-off), or **"Safe · 0 waiting"**. Clicking it goes straight to the Approvals &
  Safety screen.
- **A light/dark theme toggle**, remembered between visits.
- **A "New Assessment" button** — the primary call to action, on every screen.

**A right-hand detail drawer.** Several screens open a panel that slides in from the right when the
operator clicks a row. It is used for finding details, live-event details, attack certificates and
the AEGIS production command.

**A corner status card for the voice assistant (the "SIGIL HUD").** When the optional voice or
gesture companion is running, a small card appears in a corner showing whether it is *listening*,
*thinking*, *speaking*, or *idle*, along with the live transcript. It has a minimise button and a
dismiss button; a new interaction brings a dismissed card back. Voice and gesture navigation are
**off by default** and must be started deliberately (`vigil up --with-voice` / `--with-gesture`).
When enabled, spoken navigation can only move the operator to a screen that already exists in the
navigation list — the code uses a strict list of known screen identifiers, so a malicious or
malformed voice command cannot make the interface go somewhere unintended. Note for accuracy: no
gesture input reaches this card today. Local camera-based gesture control is *not* functional — the
hand-tracking model is absent — and the phone-as-trackpad route, which is the design's answer to
that, is built and tested on the desktop side but has nothing sending it hand movement. Chapter 14
sets out what each is waiting on.

**Small transient message strips ("toasts")** confirm actions.

### One job at a time

The interface used to show every run the machine had ever produced, on every screen, mixed together.
It is now **scoped to one engagement** — the job the operator is actually working on — and the job
chip in the top bar always says which.

| Question | The answer |
|---|---|
| Which screens are scoped? | Nine: Live, Activity, Findings, Fixes, Proof Studio, Report, Compliance, Assurance, and the two per-engagement tabs of the Brain screen. The rest are not about a particular job. |
| How does a job become the active one? | Launching a run makes that run's job the active one. Opening a job in the Engagement Library does the same. Nothing else changes it. |
| What happens to everything else? | **Nothing.** Scoping hides rows; it deletes nothing, moves nothing and rewrites nothing. Every past job, run, finding and certificate stays exactly where it was. |
| How does the operator get back? | Always. The chip leads to the library, the library has an *All engagements* button, and every screen that is empty *because* of the scope says so by name and offers the same way out. |
| Does the browser decide which runs belong to a job? | No. The scope is a **filter**: the back end selects among the runs that already record that job as their own, so a screen can narrow what it lists and can never claim a run into a job it does not belong to. |

Two consequences are worth stating for a reader who has seen software make this mistake. First,
starting a new job leaves a **clean desk rather than a wiped one** — the new job's screens are
honestly empty until it produces something, and each empty screen says which job it is showing and
that the others are still on disk. A blank panel and a broken screen look identical unless the
screen says which it is. Second, a link or a bookmark that names a run belonging to a *different*
job is not silently swapped for a neighbouring one: the screen says the run is not part of the job
in view, and offers to widen.

The chosen job is remembered between visits, so a refresh or a restart lands the operator back on
the work they were doing.

---

## 3. Two words that appear on almost every screen: FACT and LEAD

The tour will not make sense without these two words, so here they are once, plainly.

A **LEAD** is a suspicion. The AI, or a scanning tool, or an intelligence feed thinks something might
be wrong. It has not been proven.

A **FACT** is a proven finding. It is proven because a small, deterministic, non-AI test program — the
system calls it an **oracle** — looked at the actual bytes that came back from the target and
confirmed the weakness. Deterministic means it always gives the same answer for the same input; it
does not guess and it does not have opinions.

The useful analogy is medicine. A LEAD is a symptom a doctor notices. A FACT is a laboratory result.
The doctor can be persuasive and still be wrong; the lab test is the lab test.

Throughout the interface, a FACT is displayed as *confirmed*, and a LEAD is displayed with wording
that never implies proof. Several screens carry a printed legend reminding the reader of the
difference. On the Findings screen, opening a LEAD produces an explicit note reading, in effect: a
LEAD is a proposal; it becomes a FACT only when a deterministic test re-runs and confirms it.

---

## 4. Group DO — the eleven screens for doing the work

### 4.1 Home (titled "Command")

*Subtitle on screen: "One place to run, watch, and govern every VIGIL assessment."*

**What the operator sees.** Four summary tiles across the top:

| Tile | Meaning |
|---|---|
| **Active runs** | How many assessments are in progress right now. |
| **Waiting for you** | How many decisions need the operator's approval. |
| **Confirmed findings** | How many proven security weaknesses exist — labelled "proven by oracle". |
| **Budget today** | How much has been spent so far today (AI usage costs money). |

Below that, a **Quick start** card with three big buttons — *Scan a codebase*, *Scan a website*,
*Defend an app* — and a **Recent activity** feed showing the most recent decisions the system made
(up to eight).

**What the operator can do.** Only navigate. The three quick-start buttons jump to the New Assessment
screen or the Defense screen.

**What happens as a result.** Nothing changes. This screen only reads.

**Worth noting for reliability:** the screen fetches from both back-end halves independently and
tolerates either one being down. If the sovereign side is offline, the page still renders with the
offence numbers rather than going blank.

---

### 4.2 New Assessment

*Subtitle: "Set up a run in five short steps. Everything stays on your machine."*

This is the screen where work begins. It is a five-step form with a clickable step rail across the
top — **Target · Where · Scope · How · Model** — a running "What will happen" summary card on the
right, and Back / Next / **Launch assessment** buttons at the bottom.

**Step 1 — "What do you want to assess?"** Six choices, each with a one-line description:

| Choice | What it does |
|---|---|
| **Scan a codebase** | Point at a folder on disk or a code repository; the AI reads and reasons over the source. |
| **Scan a website / API** | Give a web address; the system engages it through the full permission gate. A target of `127.0.0.1` (this machine) runs a quick local scan. |
| **Run one tool** | Run a single approved capability against a target — the narrow, focused option. |
| **Full autonomous suite** | The self-directing loop drives the whole toolset. Still gated; still adjudicated by the deterministic tests. |
| **Cloud / K8s posture** | A settings review of a cloud account or a container cluster. Requires a signed engagement charter. |
| **Defend an app (AEGIS)** | The defensive counterpart: run the same detection logic over the operator's own logs. |

"K8s" is the usual short way of writing **Kubernetes**, the standard software for running many small
packaged applications ("containers") across a group of machines. The screen uses the short form; this
chapter will use the full word from here on.

**Step 2 — "Where is it?"** The fields change depending on step 1. A codebase asks for a path or a
repository address, plus a tick-box labelled *bind-mount instead of copy* for very large
repositories. A defensive run asks for a log file. A cloud run asks for the assessment type (cloud
account / Kubernetes / declared service), the cloud provider (AWS, Google Cloud, or Azure), a label,
and a short engagement name. A website run asks for the address and an engagement name, which the
form fills in automatically from the web address.

*Bind-mount* needs a plain explanation, because the phrase means nothing outside software. Normally
the system copies the code it is about to read into its own sealed workspace, file by file. For a
very large codebase that copying is slow — the third-party analysis tool refuses to do it at all
above about one gigabyte. A "bind-mount" is the alternative: instead of copying the folder, the
workspace is given a window onto the folder where it already sits on disk. The window is **read-only**
in the tool's own configuration, so the analysis can read the code but cannot write to it. The
everyday equivalent is the difference between photocopying a file of papers and being allowed to read
the original through a glass panel.

For every mode except the defensive one there is a **required tick-box**: *"I am authorized to test
this target (I own it or have written permission)."* The screen is now exact about what that
tick-box is and is not, and the change is worth quoting because it removed a promise the software
did not keep: the box **gates the wizard, is not sent with the launch, and is stored nowhere.** The
binding authorisation is the signed charter and scope the engine enforces for that job — which is
the only thing that could ever have been binding. The screen used to say the declaration was
"recorded with the run"; nothing recorded it, and a reassurance no file keeps is worse than no
reassurance.

Every mode also offers an optional free-text **Objective** box, and it too now says something
different depending on the mode, because it *does* something different. For a codebase review the
objective is handed to the source-reading agent as its instruction — it really steers the work. For
every other mode the gated engagement takes no free-text objective at all, so the screen says the
text is recorded with the run for the operator's own record and **does not steer it**; depth and
capability packs are what steer those. Both wordings carry the same caution: it never widens scope.

**Step 3 — "Scope".** Scope means the list of machines the system is permitted to touch. For a
network run against something other than this machine, the operator sees a list of authorised hosts
and can add more. **Whole address ranges are refused right there in the form** — the message reads
"No CIDR — use a literal host or a `*.wildcard`."

*CIDR* is the standard shorthand for writing a whole block of network addresses in one go. Written
out it looks like `10.0.0.0/8`, and that single short string covers about sixteen million separate
machines. The form refuses that shorthand on purpose: "everything in this block of sixteen million
addresses" is exactly the kind of over-broad permission that causes accidents, and it is impossible
for an operator to know by eye what is inside such a block. The operator must instead name each host
literally (`app.example.com`) or use a name-based wildcard (`*.example.com`), which is still a broad
grant but at least a legible one. For a this-machine target, scope is fixed to `127.0.0.1`. For
codebase, cloud and defensive runs the screen explains that there is no network scope to set.

The printed legend on this step is important and honest: the scope is signed into the engagement
charter and authority; the web interface never passes scope to the engine as an argument. In other
words, the operator cannot widen their own permissions by editing a form.

**Step 4 — "How should it run?"** A depth choice (Quick / Standard / Deep, read live from the
engine's own catalogue rather than hard-coded in the page). Then, depending on what is being
assessed, either a set of **capability packs** or a **picker over this machine's real tools**. This
step was rebuilt in this round, and two of the defects it fixed are worth setting out in full.

*Capability packs, and the two things that used to go wrong.* A pack is not a tool; it is one
already-gated option on the engagement command — a named bundle of checks. A tick-box, on by
default, now reads *"Run the engine's standard set (recommended)"*. It used to read "Let the AI
choose the tools", which was simply untrue: nothing chooses packs for the operator. On means no
extra options are added and the engagement runs its standard audit; off reveals the real catalogue
of packs with their permission tiers, and the printed note is that a pack can never widen authority
— it only adds an option the gate already governs.

- **The first defect: a selection that was accepted and then silently discarded.** The launcher used
  to walk the chosen list and quietly append only what it recognised. A name it did not recognise
  vanished, and the run started anyway, reporting *running*. In "run one tool" mode it was worse:
  only the *first* entry was ever used, so a request naming an unrecognised item followed by a valid
  one threw away the valid one as well, and a run the operator believed was driving a specific tool
  started with no tool option at all. **An unrecognised capability is now a refusal, stated before
  anything is started**, and the one-tool mode requires exactly one — because the alternative to
  refusing is starting something narrower than what was asked for and calling it the same thing.
- **The second defect: packs dropped entirely on the commonest target of all.** Only one of the
  engine's several starting paths ever turns a pack into an option. A run against this machine —
  which is the ordinary way an operator tries the product, and the target used for every local
  proving-range exercise — goes to a different, self-contained scanner that has never taken pack
  options at all. So did a graph-backed run, a codebase review and a defensive run. Five ticked packs
  produced a run with none of them, answering *running*, with nothing anywhere saying the work was
  narrower than the form that configured it. Two fixes, in opposite directions. The back end now
  **names the gap**: it reports which packs were not applied and why, in the response and in the run's
  own record, and the screen shows that message. And the wizard **stops asking for what cannot be
  carried**: on those targets the pack picker is replaced by a plain statement of why there is
  nothing to pick and what to do instead. What the screen offers and what the request sends are now
  decided by one and the same rule, written once, so the two cannot drift apart again.

*The tool picker.* Choosing "Run one tool" now lists **this host's actual tools, exactly as the
engine's own roster reports them** — not capability packs, which is what the step used to offer.
Each entry shows the tool's name, whether it is installed, what it is for, and — this is the new
part — **how it is driven**: by its own command line, by a gated sensor, by the source-analysis
pass, or as the scanner's headless browser. A tool this particular screen cannot start is **listed
anyway, greyed, with the reason printed on it**, rather than hidden: not installed, not supported on
this platform, not among the tools the system will claim to control, or — most often — no option on
*this* starting path runs it on its own, followed by a list of what does drive it. The screen prints
the arithmetic honestly: how many of the roster can be started here, out of how many there are.

That number is small, and the chapter will not dress it up. On this machine the roster holds
**thirteen tools, all installed, all admitted — and exactly one of them can be started from this
screen as a single tool**: the headless browser, which one capability starts in order to confirm a
browser-side scripting flaw by really executing it. The other twelve are driven by the engine during
an engagement and are not startable on their own from the wizard, and the screen says so tool by
tool. A reader who wants the fuller picture of what drives each tool should read chapter 12.

Finally a tick-box that was renamed for the same reason as the others: *"Flag this run as one I want
fixed"*. It used to read "Apply fixes after discovery", which read like scheduling work. Ticking it
applies nothing; it is recorded with the run and shown on the Fixes screen, which lists the fixable
findings and the gated ladder either way.

**Step 5 — "Does this run need a model?"** This step used to be headed "Model & keys" and to offer a
"Run keyless" tick-box. That box is gone, and its removal is a small lesson in the discipline this
document keeps describing: it was accepted, written into the run's record, and read by nothing. The
attack-side commands call no AI model at all, so those runs were already keyless whether or not the
box was ticked; and a codebase review needs the source-reading agent's model whether or not it was.
A control that changed nothing has been replaced by a **statement, per mode, of whether a model is
involved at all**:

| Mode | What the screen states |
|---|---|
| Scan a website / API, run one tool | Deterministic end to end — the engine calls no model. Findings come from the automatic tests, not from a model. |
| Full autonomous suite | The audit is deterministic; the self-directing loop additionally takes one bounded **advisory** reasoning step per cycle, and with no AI back end it falls back to the engine's own deterministic advice and still completes. Advice never confirms a finding. |
| Scan a codebase | **The model is the run** — the source-reading agent is the thing that reads the source. Without a working back end it has nothing to run. |
| Cloud / Kubernetes posture, Defend an app | Deterministic. Neither calls a model. |

The step also shows the live status of whichever AI back ends are configured, states that keys are
never shown or entered here, and offers a **Session** selector (sessions have their own screen
below). For a this-machine target with a session selected there is a "Graph-backed run" option that
routes the run so its results are stored in that session's own knowledge graph. A cloud posture is
offered no session at all, because its launcher takes none and offering one would have quietly
detached the run instead of linking it.

**What happens on Launch.** The page sends the whole form to the back end, which starts a gated run,
and the operator is redirected to the Live screen for that run. Three further things now happen, and
each exists so the operator is never left believing the run was something it was not:

- **The new job becomes the active one**, so every scoped screen shows the work just started and
  nothing else. The job used is the one the *server* reports — the one the run recorded for itself —
  not the one the form asked for.
- If capability packs could not be carried by the path that actually ran, **the message saying so is
  shown**.
- If a graph-backed run was asked for and the graph database was not available, the screen says the
  run went to the ordinary engine instead. It falls back rather than failing, and it says so; a
  silent fallback would leave the operator believing a knowledge graph had been written that was
  never touched.

**One field the wizard does not have, and it matters.** Most of a real application's interesting
surface sits *behind a login*. The engine does contain the machinery for logging in and staying
logged in while it tests — it can hold a set of login cookies, perform a login sequence, notice when
the application has logged it out again, and log back in before retrying. That machinery is a
building block inside the engine; it is used directly by the engine's own tests. **There is no field
anywhere in these five steps where an operator can type a test account's username and password**, and
none of the twenty-nine screens offers one. In practice this means a run launched from the wizard
against a login-protected application exercises the public, logged-out surface of that application.

There is **one narrow exception, and it is a typed one.** The tests that ask "can user A read user
B's data?" cannot work at all without two genuine identities, so the typed commands do accept a
second identity — an option that supplies the header carrying the victim account's session, together
with the specific records the attacker identity should try to reach. That is a deliberate, narrow
input for one family of tests, not a general "log in as this user and scan everything" setting.
Nothing in the interface exposes even that.

So the accurate statement is: the login machinery is built and used; the two-identity tests can be
given a real second identity from the command line; and there is no way, from any screen, to hand
the system a test account and have it scan the logged-in surface of an application. This is an
interface gap rather than a missing capability, and it is listed again in the section on where the
interface is honestly incomplete.

**Status: fully working and actionable.**

---

### 4.3 Chat

*Subtitle: "Ask in plain language, or attach a zip, files and images and ask about them. Answers are
leads; the gated run is what mints facts."*

This screen changed more than any other in this round, and it is the one place in the product where
an operator can hand over material that has never been near the engine and ask a question about it.
It therefore gets the longest treatment in this chapter.

Every other screen is about **certainty** — things an automatic test has already confirmed. Chat is
the room where **uncertainty** lives: where an operator says "that login flow smells wrong" before
anything is proven, drops in a codebase they were handed an hour ago, and thinks out loud. Everything
below follows from that, including the limits.

**What the operator sees.** A left column of saved conversations — each with its title, how many
exchanges it holds, and, when it draws on other conversations, how many. A "New chat" button. The
transcript in speech bubbles. Below the transcript: a strip of attached material, a **Draws on**
panel, an optional target box, a mode dropdown (*auto*, *url / API / infra*, *codebase*, *suite
(autonomous)*, *one tool*), an **Attach** button, and the message box (Enter sends, Shift+Enter
starts a new line). Above the transcript sit two system-wide dropdowns, described at the end of this
section because what they do is not what their position suggests.

#### What the operator can hand it, and how each behaves

The distinction matters: some of these start work, some become material the conversation reads, and
one does both.

| What is handed over | What happens |
|---|---|
| **A web address** — typed in the target box, or simply pasted into the message | The screen asks the back end to start the same gated engagement the wizard starts, against that address. The reply is a pointer to the run and a **Watch live** button. Nothing here is answered by a model. |
| **A folder on this machine** — likewise | The same, as a codebase review over that folder. A path is accepted only when it really exists and really is a folder, so a message that merely *mentions* a path stays a question rather than becoming a launch. |
| **An archive** — dropped onto the transcript, chosen with **Attach**, or named as a path | Unpacked here, under the guards below, and attached to this conversation as material it can be asked about. An archive named as a *path* does both: it is unpacked and attached, **and** its extracted copy becomes the target of a gated codebase review. |
| **Loose files and images** | Attached, and read when the conversation is asked something. |

Every failure in that table produces a reply that says what was looked for and what was found
instead — "I looked for this on this machine and there is nothing there"; "that is a file, not a
folder or a supported archive"; "that is named like an archive, but its contents are not one I can
read". Before this round, a path that was not a folder was passed on as though it were, and the run
failed somewhere downstream with nothing on screen connecting the failure to the fact that the
material was still packed.

#### What happens to an upload

The console refuses any single request larger than about a megabyte, and that limit is deliberately
**not** raised for uploads — raising it would raise the ceiling for every other request the console
answers. So a file is sliced in the browser and sent as an ordinary sequence of small requests, each
one carrying the same session credential and the same anti-forgery marker as every other action.
Cancelling tells the server, so the part-uploaded material is really discarded rather than left on
disk until a sweep.

When the last slice arrives the material is assembled, fingerprinted, and — if it is an archive —
extracted. **What kind of thing it is gets decided by reading the first bytes of the file, never by
its name**, so a document named as an archive is treated as the document it is, and an oddly named
archive still works.

#### What is refused, and why

An archive is the most dangerous thing a person can be invited to upload, because a crafted one
attacks the program that opens it. The extractor's rule is absolute and worth stating before the
list: **a refusal throws the whole archive away.** Nothing is half-unpacked, because half-unpacked
material is a lie about what the operator handed over. Each refusal comes back in plain English,
naming the entry that caused it.

| What is refused | Why it matters |
|---|---|
| **An entry that would be written outside the upload folder** | The classic archive attack: an entry whose path climbs out of the folder it is being unpacked into and overwrites something else on the machine. It is refused twice over — once when the path is read, and again by checking where the file would actually land. |
| **An entry that is a link, a device or a pipe rather than a real file or folder** | A link is a signpost to somewhere else, and following one is how an extractor is tricked into writing outside its own folder. Only ordinary files and folders are accepted. The check does not rely on the archive's own claim about what an entry is, and it refuses a *folder* in the path that is a link, not merely a link at the end of it. |
| **A decompression bomb** | A small archive that expands to something enormous. Two ceilings: a total size, and a ratio between what arrived and what came out. The ratio only begins to bind past a few megabytes of output, so an ordinary, efficiently compressed archive is never refused for merely being efficient. |
| **An archive whose header understates its real size** | This is the subtle one. Every archive carries its own claim about how big each entry is, and a crafted archive lies. The obvious implementation trusts that claim, checks it, and only then reads — by which time the whole thing has been allocated. Here the claim is used only for a cheap early refusal; **the ceilings that actually bind are checked against the bytes as they really arrive**, block by block. An entry that keeps producing bytes past the limit is stopped at the limit, not after it. |
| **A flood of entries** | An archive of tens of thousands of tiny files, which costs far more to unpack than to build. |
| **Two entries with the same path** | Refused rather than one silently overwriting the other. Which one won would be the attacker's choice, not the operator's. |
| **A path that is absurd in shape** | Too long, too deeply nested, or containing a character that is not printable. The last one is subtler than it sounds and is covered below. |
| **An archive inside an archive** | Stored as it is, never opened. One level only. |

Two more properties belong here, because they are what a reviewer would ask about next.

**Nothing uploaded is ever executed.** Nothing is marked runnable — the permissions come from the
system, never from the archive — nothing is placed anywhere a program would be looked for, and
nothing is started. The only thing that can later act on those files is the gated codebase
assessment, which the operator starts deliberately and which runs inside the sandbox with the
ordinary approval gate in front of it.

**Nothing is silently skipped.** An entry that cannot be handled is a refusal, not a quiet omission.
An operator cannot check a total they were never shown, and a silently skipped file is how an
unscanned secret leaves a building.

#### What leaves the machine, and what does not

Uploading does not send anything to a model. The material sits on the operator's own machine, in a
folder only their own account can read, until they send a message that asks about it — and the first
time that happens the screen **stops and asks**. The dialog names how many files, how many bytes and
how many attachments are about to go, lists the file names, names the model they are going to, and
states in as many words that nothing else on the machine goes with them — not the other
conversations, not the findings, not the keys. It is answered once per attachment rather than once
per message, so it informs without nagging. Removing an attachment is the way to stop it going, and
removing really deletes it on the machine rather than merely taking the label off the row — because
every answer in a conversation is given over everything that conversation still holds, and an
attachment the screen said was gone but the machine had kept would keep going to the model on every
later turn.

Three protections travel with the material itself:

- **Credential-shaped values are masked before anything leaves.** A password or key sitting in the
  operator's own source does not go to the model. What survives is the *fact* of it: the file is
  flagged as having had something masked, so "this file commits a credential" still reaches the
  operator even though the credential does not leave the host.
- **Uploaded text is fenced as quoted material.** The block is introduced as untrusted data that is
  there to be analysed and never to be obeyed, each file gets its own label, and every quoted line is
  prefixed so that no line of an uploaded file can ever occupy the position a heading occupies. The
  reason this is not merely decoration: without it, a file — or even a crafted file *name* — could
  forge a section boundary and impersonate the operator. The characters that count as a line break
  for this purpose are the ones a *reader* honours, not merely the ordinary one, which is precisely
  where a first attempt at this had two measurable holes.
- **Instructions hidden in uploaded material are reported, not followed.** The model is told, in the
  standing instruction it always receives, that anything looking like an instruction inside an
  attached file is itself a finding to be quoted and reported.

#### It says how much it read, and how much it did not

A model's attention is finite, so a large codebase is read in part: the most security-relevant files
are chosen first, and the rest lose the budget race. That is fine, and it must be said. **Silence
implies whole-repository coverage, and that is a lie the operator cannot detect.**

So every answer grounded in an attached codebase ends with the arithmetic — for example: *I read 47
of 312 files in the attached codebase — 265 were not read (binary, over-long, or the reading budget
ran out). Everything above covers only those 47.* When it did read everything, it says that instead.
The same two numbers are given to the model, so it cannot describe a partial read as a review of the
whole tree without contradicting what it was handed. Three details make the count trustworthy rather
than decorative:

- It is the number of files **the model actually received**, not the number the machine set out to
  send. When the block has to be trimmed to fit, it is trimmed on a file boundary and the count is
  corrected downward — a half-quoted file is not a file read.
- The sentence lives **in the reply itself**, not in a note beside it. The screen redraws the
  transcript from the saved record, so a caveat carried only alongside a reply is gone by the next
  redraw, and a partial read that stops announcing itself reads from then on exactly like a complete
  one.
- A conversation holding only a screenshot makes **no coverage claim at all**, because "I read 0 of
  1 files" about a picture is noise, and noise is how a statement that matters stops being read.

And the honest route to completeness is offered, not merely mentioned: an answer that read an
extracted codebase carries a **Run the gated scan on these files** button, which starts the ordinary
gated assessment over the same files — the one that walks the whole tree and whose findings an
automatic test either confirms or does not. The folder it points at is *computed* from the
conversation's own identity rather than read out of a stored record, so nothing that could edit that
record could aim a real scan at some other directory on the machine.

#### An answer here is a LEAD, never a finding

Every model-authored bubble carries a printed marker reading **"Lead — not a confirmed finding"**.
The standing instruction the model receives forbids the words "confirmed" and "proven", forbids
assigning a severity score as though the matter were settled, requires each observation to cite the
file it came from, and states that an honest "I cannot tell from what is attached" is a correct
answer while a plausible guess is a defect. The consent dialog says the same thing in its own words
before anything is sent.

This is the whole discipline of the product applied to its most tempting surface. The material is
whatever the operator handed over, checked by nothing. Only an automatic test over real evidence
makes a fact.

#### Linking one conversation to another

A conversation can be told to **draw on** other conversations, so that reasoning done last week is
available as background this week. The panel under the transcript lists what this one draws on, with
a cross beside each to disconnect, and a picker to add another. Four properties, all printed on the
screen and all exercised by tests that run on this machine:

| Property | What it means |
|---|---|
| **One-way** | This conversation draws on the other. The other is not changed, does not draw on this one, and cannot see it. Linking in the other direction is a separate, deliberate act. |
| **Several at once** | A conversation may draw on many others — the limit is thirty-two — and each is removed individually. |
| **Nothing is copied** | The link stores only the other conversation's identity. It is a permission to read at the moment of answering, not a merge. |
| **Disconnecting takes effect immediately** | Because nothing was copied, there is no residue: the very next answer is given without the other conversation's history. |

Two further limits are worth stating, because a reader would assume both the other way. A linked
conversation's **uploaded files are declared but their contents are not shared**: the answer learns
that the other conversation holds an upload, not what is inside it. And the borrowed history is
bounded, says how much of itself was left out, and passes the same masking as everything else before
it leaves the host — so a credential pasted into a conversation last week does not travel through a
link this week.

#### The two dropdowns above the transcript

These set the model and the reasoning effort **for the engine as a whole** — the same controls as the
Settings screen, taking effect the next time the system is started. They do **not** change the answer
in this conversation, which comes from a model the console pins itself. Sitting unlabelled above a
transcript, controls named "Use model" and "Apply effort" read as "answer me with this", which is the
one thing they do not do; they are now named for what they change and print a line saying what they
do not. If the owner side is offline they degrade to an explanatory hint rather than failing silently.

#### Status, stated exactly

**Working and actionable.** The upload path, the extraction refusals, the deletion, the linking and
the coverage arithmetic are all exercised by tests that pass on this machine, and the upload path has
also been driven through the real interface here — this machine's saved conversations include a real
file uploaded in slices, recorded, and later removed, with the removal really deleting it.

What is **not** established is the answering step against the live service: every test puts a
stand-in in place of the model, so no request leaves the host during them, and no answer produced by
the live model over uploaded material is recorded anywhere on this machine. The reasoning call
itself is new in this round — before it, this screen could only launch a run or ask for a target.
Without an AI key it says so plainly and keeps the gated run on offer; under a sovereignty setting
that forbids anything leaving the host it refuses the model call outright and says the gated
assessment still runs.

One capability exists in the back end with no way to reach it from a screen: attaching a file that
already sits on this machine *as an attachment*, by naming its path. The route is written but is not
exposed, so today the way to hand over something already on disk is to name it in the target box —
which, for an archive, unpacks it, attaches it, and starts a gated review of the extracted copy.

---

### 4.4 Terminal

*Subtitle: "Ask in plain English or type a command. The AI proposes; you approve; only local
read-only commands run."*

This screen deserves close attention from a reviewer, because it is where an AI system is closest to
executing instructions on a real machine — and it is built so that closeness is safe.

**What the operator sees.** Three sections:

1. **An "Ask in plain English" chat box**, which can be minimised and restored (the state is
   remembered; the Escape key restores it).
2. **"Or type a command"** — a direct command box. As the operator types, after a short pause, the
   system shows a **live verdict badge** telling them in advance what would happen: allowed, queued
   for approval, or refused. Then a **Run** button.
3. **Output** and **Recent commands**.

**The three ways the AI can respond:**

- **command** — it proposes a specific command, shows its verdict badge (**ALLOWED**, **QUEUES FOR
  YOU**, or **REFUSED**), and offers Run / Edit / Cancel. Nothing runs until the operator clicks.
- **answer** — a read-only reply, labelled **"READ-ONLY · NOTHING RAN"**, with a line citing what it
  drew on.
- **route** — a message reading **"USE THE ENGAGEMENT PATH"** and a button to the correct screen.
  Nothing runs.

**The safety property, stated as the screen itself states it.** Only a fixed list of local
inspect-and-read programs may run: things like `ls`, `cat`, `head`, `tail`, `grep`, `find`, `stat`,
`wc`. No networking. No programs that write files. No general-purpose interpreters. No shell. Every
run produces a signed record.

The screen puts the point directly: *"Even if the AI is wrong or prompt-injected, the allowlist
refuses it and nothing runs without your approval."* Prompt injection means hiding instructions in
text the AI reads, in the hope the AI will obey them. The allow-list makes that attack useless here,
because the check is not on what the AI intended — it is on what the command actually is.

**How that list was built is worth a paragraph, because it shows the standard of care.** The obvious
way to build such a protection is a list of forbidden things. The team rejected that approach, and
the reason is recorded in the code: a list of forbidden spellings can never be proven complete. The
standard command-line convention accepts any unambiguous abbreviation of an option name, so blocking
one spelling leaves several others open. The list is therefore built the other way round — only
named things are permitted, and everything else is refused by simple absence.

Several individual decisions follow from that, and each of them is a small, checkable act of care:

- The programs that can only read and print — listing files, showing their contents, searching text,
  computing checksums, reporting machine statistics — are admitted outright, because no combination
  of options can make them write a file or reach the network.
- The hex-dump utility `xxd` was **removed**, because one of its forms writes its output to a file
  named as its second argument.
- The lookup utility `getent` was **removed**, because one of its forms performs a network lookup,
  which would breach the rule that this path can never reach the network.
- The utilities that print the date and the machine name are admitted **only in their bare form**,
  with no arguments at all, because with an argument they *set* the system clock or the machine name.
- Four genuinely useful but capable utilities — the file-finder, the two sorting utilities, and the
  file-type identifier — are admitted through a positive list of their read-only options only, so
  their file-writing and program-launching forms are excluded by not being on the list rather than by
  someone having remembered to forbid them.

The result is a property that can be stated as an absolute rather than as a mitigation: on this path,
reaching the network and writing to the machine are impossible by construction, not merely guarded
against.

**Output shows** the command, the outcome, its permission tier, whether it ran, the reason, the *exit
code*, and a signed record identifier — then the actual output. An exit code is simply the number a
program hands back when it stops: zero means "finished normally", any other number means "something
went wrong", and the particular number tells the initiated what. The screen prints it so that a
failure is visible as a failure rather than as an empty result.

Without a paid AI key, the plain-English half reports that it needs a key; the direct command box
still works.

**Status: fully working, allow-list gated.**

---

### 4.5 Live

*Subtitle: "Every action, as it happens — with proof-grade FACT vs LEAD clarity."*

**What the operator sees.** A run selector. A header card with a status pill, the target, the mode,
an elapsed-time counter that ticks, and a **Stop run** button. Four tiles: **Actions**, **Facts**,
**Leads**, **Refusals**. A printed legend explaining who has the authority to declare something
proven. An approvals card. Then the main body in two columns:

- **Reasoning graph (LIVE)** — a diagram drawn live as the system thinks, with seven lanes:
  *Observe · Orient · Plan · Act · Result · Finding · Review*. Each lane holds up to 22 boxes, joined
  by curved lines from parent step to child step. It is a picture of the system's reasoning as it
  happens.
- **Timeline** — a scrolling feed of events with a filter across the top: **All / Facts / Leads /
  Inbox**.

**The fifteen kinds of event shown:** Observed · Hypothesis · Plan · Decision · Action · Tool call ·
Result · Tool result · Finding · Critique · Critic · Reflection · Reward · Refusal · Message. The
last one — agent-to-agent messages — is explicitly marked **advisory** and drawn in the review lane.
It is never treated as a finding.

**How the live data arrives.** Three different shapes, chosen automatically:

- Full reasoning runs stream from the **reasoning spine**. The spine is this system's permanent
  written record: an add-only journal in which every step the system takes is appended in order and
  never edited or deleted afterwards, like a bound ship's log rather than a whiteboard. The screen
  reads from it with a position marker, so if the browser connection drops it resumes exactly where
  it left off rather than replaying everything or losing events.
- Quick local scans stream a simpler progress log, normalised into the same timeline shape.
- Runs that have no live reasoning stream — the third-party agent and the defensive gateway — are
  polled every three seconds, and **the screen says so honestly** rather than pretending to be live.

**What the operator can do:**

- **Stop run** — trips the emergency stop for that engagement, recording the reason "stopped from Live
  view".
- **Approve / Deny** any pending approval, without leaving the screen.
- **Click any timeline row** to open the detail drawer, showing the kind, the agent, the timestamp,
  the event identity, its parent, the verdict, which deterministic test adjudicated it, the
  confidence, and the raw underlying data. A LEAD gets the explicit "this is a proposal, not a proof"
  note.
- **Open the Inbox tab** to see agent-to-agent messages. It carries a banner reading, in effect:
  advisory coordination only; these are not evidence; nothing that builds a fact reads them.

**Status: fully working and actionable — stop, approve, deny.**

---

### 4.6 Findings

*Subtitle: "Proven bugs, the attack graph, re-checkable evidence, coverage and replay — all
oracle-gated."*

This is the largest screen. It has a run selector and **five tabs**. The tab is reflected in the web
address, so a particular view can be bookmarked or shared.

#### Tab 1 — Findings

Four tiles: **Confirmed**, **Leads**, **Endpoints**, **Requests**. A filter — All / Facts / Leads.
Then a table with columns *Severity · Bug class · Surface · Oracle · Status*.

Clicking a row opens the detail drawer. It contains, in order:

- the verdict — CONFIRMED, CONTRADICTED, UNGROUNDED, or LEAD
- severity, bug class, and which part of the system it affects
- which deterministic test adjudicated it, and the confidence
- the standard industry severity score, together with the short coded string that severity is
  calculated from. The scoring system is CVSS — the Common Vulnerability Scoring System, the
  internationally used method for rating how bad a security weakness is on a scale from 0 to 10. The
  coded string (the industry calls it a *vector*) is a compressed line recording the answers that
  produced the number: can it be exploited over the network or only locally, does the attacker need
  an account, does the user have to be tricked into clicking something, and how much damage follows.
  Publishing the string as well as the number matters, because it lets a reader check the arithmetic
  rather than take the score on trust.
- which hypothesis it came from
- whether it carries a re-runnable certificate
- **IMPACT** — what it means in practice
- **ORACLE RATIONALE** — why the deterministic test concluded what it concluded
- **HOW TO VERIFY & TEST** — instructions for the operator to check it themselves. The code takes
  care that this text never implies that an unproven lead is proven.
- **REMEDIATION** — how to fix it
- **REFERENCES**
- **RE-VERIFY** — a button reading *"Re-verify this run (offline)"*

That last button carries the mechanism the whole chapter keeps referring back to, so it deserves a
plain explanation here. When the system finds
something, it keeps a copy of the exact evidence it collected — the actual bytes that came back. The
re-verify button runs the same deterministic test again over that saved evidence. It sends no traffic
to the target at all. If a result does not come out the same, it is not reported as reproduced. The
screen shows "N / M reproduced" and lists each certificate individually.

The everyday analogy: it is a sealed evidence bag. The bag can be re-opened and the same test re-run,
by the operator, later, without going back to the scene.

#### Tab 2 — Attack Graph

A diagram of how the target is put together and how an attacker could move through it. Nodes are
colour-coded by kind: endpoint, finding, host, datastore, credential, principal, cloud resource,
service, web application, session, control, network segment, attacker. The layout is deterministic —
the same data always draws the same picture, so two people looking at it see the same thing.

#### Tab 3 — Evidence

Four tiles: **Certificates**, **Sound**, **Not sound**, and one reading **Traffic sent = 0, "pure
re-run"**.

Then one card per certificate, each with a four-state badge and, crucially, a sentence explaining
*why*:

| Badge | Meaning |
|---|---|
| **Sound**, with a tick mark | The signed evidence checks out. |
| **Tampered**, with a cross | The evidence has been altered since it was signed. |
| **Claim mismatch**, with a warning triangle | The signature is fine but it does not match the claim being made. |
| **No certificate**, with a dash | There is no signed evidence for this item. |

Each card has its own **Offline re-verify** button. Fields shown include the finding, the surface,
the kind of deterministic test, the confidence, and the certificate identity — which is a content
hash, meaning a fingerprint computed from the content itself, so any change at all produces a
different fingerprint.

#### Tab 4 — Coverage

This tab exists to answer the question a serious reviewer always asks: *what did you not look at?*

Tiles for **Pages crawled**, **Requests audited**, **Endpoints**, **Confirmed**. A **detected
technology stack** list. A list of the endpoints seen (first 200). A separate list of passive hygiene
observations, labelled **LEADS · not proven**. A list of browser-side scripting candidates, labelled
**STATIC · candidates**. And an explicit **blind-spot legend** naming what a quick local scan does
*not* exercise.

#### Tab 5 — Timeline

An **investigation replay** slider. Dragging it scrubs backwards and forwards through the growth of
the attack graph, in the order things were first seen. Attack paths and choke-points are only
highlighted once they are fully formed at that point in time — the code is careful not to highlight a
path before the evidence for it existed. The counter reads "Step N of M · N nodes · M edges · P
paths". It is pure reconstruction from stored data; no traffic is sent.

**Honest empty states.** A run whose results live on the reasoning spine says so and offers a button
to open it in the Live view. A run from the third-party agent or the defensive gateway says it runs
in its own sandbox, rather than showing an empty table as if nothing had been found.

**Status: read-only, plus an offline re-verify that issues zero traffic to the target.**

---

### 4.7 Proof Studio

*Subtitle, verbatim from the screen: "Strix generates an exploit; VIGIL turns it into PROOF. A FACT
here means a deterministic oracle FIRED over the executor-captured raw bytes of the reproduction —
not the model's word. A LEAD is an honest 'not reproduced'. A DENIED proof had dangerous PoC content
refused BEFORE any mint. Read-only."*

In plain terms: a third-party AI agent (Strix) tries to build a working demonstration of a weakness.
This screen shows what happened to each attempt after the system tried to *prove* it.

**What the operator sees.** A run selector; a summary line reading "N FACT / N lead / N denied"; then
one card per attempted proof showing:

- the class of bug and which finding it refers to
- a status badge, one of three:
  - **FACT — oracle re-fired over captured bytes** (proven)
  - **DENIED — dangerous PoC refused** (the demonstration itself contained something the system
    refuses to handle, and it was refused *before* anything was recorded)
  - **LEAD — not reproduced** (honest failure to prove)
- which deterministic test adjudicated it, and the confidence
- which channels the reproduction was captured from
- whether it **crossed to the signed record** — only a FACT does

**What the operator can do.** One action: **Export verifiable bundle**. It is disabled unless the run
has at least one proven finding. On success the screen shows three things: the path to the bundle,
the **trust-root fingerprint**, and the exact command a recipient would type to check it themselves.

The instruction printed next to the fingerprint is precise and important: *publish this out of band*.
"Out of band" means through a different channel from the bundle itself — a website, a letterhead, a
phone call. The recipient pins that fingerprint, so a bundle re-signed under a different key is
refused. Without an independently published fingerprint, a forger who can produce a whole bundle can
also produce a matching fingerprint inside it. The system says this out loud rather than glossing
over it.

**Status: working — read-only plus one export action.**

---

### 4.8 Report (titled "Client Report")

*Subtitle: "A LIVE, always-current report: every finding is re-verified OFFLINE on load, so a FACT is
a re-checkable certificate — not a stale PDF, and not the AI's word. Read-only."*

**What the operator sees.** A run selector. An **executive summary** card reading "N sound of M
total" — the result of re-checking every finding at the moment the page loaded. Then one card per
proven finding, showing the affected surface, the adjudicating test and its confidence, the
certificate identity, and **standards control pills** — OWASP, CWE, MITRE ATT&CK, PCI — mapping the
finding onto the recognised industry frameworks.

**What the operator can do.** One button: **Download dossier**, marked with a downward arrow (the
conventional download symbol, `⤓`). It packages the reports, the proof bundle and a signed list of
everything in the package into a single file and downloads it. The status line reads "Packaging
the dossier…" and then "Dossier downloaded — tamper-evident + offline-verifiable."

The distinction from an ordinary security report is worth stating for a procurement reader: a
conventional PDF is a claim about the past. This is a package a third party can re-check without
trusting the vendor and without network access.

**Status: working — read-only plus the dossier download.**

---

### 4.9 Fixes

*Subtitle: "What to fix after discovery, and the gated process an auto-fix follows."*

**What the operator sees.** A run selector and four tiles: **Fixable**, **Unproven**, and two that
report the current posture honestly — **"Live auto-fix: OFF — provision + authorize"** and
**"Verify: oracle-silent — proof required"**.

Then **the gated fix ladder** — a numbered horizontal strip showing the stages a fix must climb,
rendered from what the server reports rather than hard-coded into the page. Then cards for each
**fixable, confirmed** finding. Then **highest-impact fix points**: the choke-points in the attack
graph, each labelled with what it connects and how many attack paths fixing it would sever.

**What the operator can do.** Per finding, an **Apply fix (gated)** button — but only when the server
says this run can actually run the ladder. When it cannot, there is no button: the screen prints the
server's own reason and the command line that does work, so the page never offers an action the back
end is guaranteed to refuse. Where the button is shown, the hint is exact: the click is the operator
approval every gated stage of the ladder waits for, and at the same time a single up-front approval of
every proposed edit — there is no per-file prompt. The edits land in a throwaway copy, so the original
tree is untouched, and in bold: **never opens a pull request** (that is, it never raises a proposed code
change for a human to review and approve). The result panel prints the command that ran, a note, and the
ladder's raw output.

**The honesty that matters here.** The screen states that only oracle-confirmed findings are eligible
— unproven leads are never auto-fixed. Nothing runs by itself: every gated stage of the ladder sits
above the automatic-approval ceiling, so each one waits for the owner, and the Apply click is what
releases them. Opening a real code-change request is a **separate capability that must be provisioned
and authorised**, and it does not happen from this screen at all. In the command line, opening a code-change
request is off by default and requires a signed authorisation from multiple independent key-holders
plus a single-use record so the same authorisation cannot be replayed.

**Status: working and actionable — gated, and non-destructive.**

---

### 4.10 Defense (AEGIS)

*Subtitle: "Put VIGIL in front of an app you run and watch it prove AI attacks in real time."*

This screen inverts the product: instead of testing a system, it defends one.

**The legend the screen leads with**, and this is a direct paraphrase of what is printed: a
CONFIRMED verdict here is a *proven* attack on your application — a deterministic test fired. A
"lead" is a suspicion. **"Clear" means nothing was proven — it is NOT proof of safety.**

**What the operator sees.** Four tiles: **Gateway**, **Mode**, **Upstream**, **Actors seen**. A setup
form or a running panel. A card showing what the system currently believes about each actor. And a
live feed of verdicts.

**The setup form:**

| Field | Notes |
|---|---|
| **Your app's URL (upstream)** | Required — the application to sit in front of. |
| **Bind host** and **Port** | Default `127.0.0.1` and `8080`. Choosing a non-local address triggers a confirmation warning. |
| **Mode** | *Observe* — watch only, blocks nothing (the default). *Enforce* — block proven attacks (requires an entitlement). |
| **Honeypot paths** | Optional. Decoy addresses that a legitimate user would never visit. |
| **Deployment secret** | With a **Generate** button that produces cryptographically random bytes. |
| **Gateway name** | Default `aegis-gateway`. |

Two printed clarifications on this form are examples of the project's honesty discipline and should
be quoted to a reviewer:

- The **deployment secret is not a password.** It is used to pseudonymise identifiers on the data
  ingest path. The screen says so, so an operator cannot mistake it for access control.
- **Canary and prompt-injection detection for an AI application is the in-process SDK path, not this
  reverse proxy.** A reader who assumed this screen protected an AI chatbot from prompt injection
  would be wrong, and the screen tells them so.

**What the operator can do.** **Start defense**, which on success opens a drawer titled *"Run on your
edge"* with a copyable command for running it in front of the real deployment. **Stop gateway**. And
clicking any verdict row that carries a certificate opens an **attack certificate** drawer with the
attack, what confirmed it, the certificate identity, and the confidence. A note explains that the
matched detail is kept on the server and not streamed to the browser.

**The downgrade is surfaced, not hidden.** If the operator asked for *enforce* mode but the required
entitlement is not present, the panel says plainly: you requested ENFORCE but it downgraded to
observe — nothing is being blocked. A system that quietly ran in a weaker mode than requested would
be dangerous; this one refuses to be quiet about it.

**Actor rows** show the client's source address (with an internal prefix stripped), a belief bar from
0 to 100 per cent, and how many observations that belief rests on.

**Status: working and actionable.**

---

### 4.11 Replay Proof (titled "Replay the Proof")

*Subtitle: "Paste a VIGIL report or finding (report.json) and re-fire its retained oracle proofs
OFFLINE — pure re-computation, no target, no traffic. A tampered proof shows as CONTRADICTED, never a
green reproduction."*

This is the screen a sceptical third party would use.

**What the operator sees.** A large text box, a **Re-fire proofs offline** button, then four tiles —
**Findings**, **Reproduced**, **Contradicted**, **Ungrounded** — and a card per finding with one of
three badges:

- **REPRODUCED** — the deterministic test ran again over the retained evidence and gave the same
  answer.
- **CONTRADICTED (tampered / won't re-fire)** — it did not.
- **UNGROUNDED (no re-runnable claim)** — there was nothing here that could be re-run.

**What the operator can do.** Paste a report and press the button. Invalid text is caught immediately
with a refuted badge rather than an error message.

**What happens.** Nothing leaves the machine and nothing is sent to any target. This is pure
re-computation over the pasted evidence.

The plain framing: this is the "check the receipt" screen. Anyone handed a VIGIL report can paste it
back in and see whether its proofs still hold.

**Status: working and actionable, and its action is entirely offline.**

---

## 5. Group MANAGE — the fourteen screens for running the system

### 5.1 Sessions

**What the operator sees.** A **New session** button. A hint explaining that connecting one session
to another lets a live run draw on the other session's knowledge as **advisory priors — never
facts**. Then a grid of session cards, each showing its kind, how many runs it holds, up to eight
clickable run identities (which jump to the Live view), and a "draws on:" row listing connected
sessions, each with a small cross beside it to disconnect.

**What the operator can do.** Create a session, rename it, connect it to another, disconnect,
delete it from the list (reversible), or delete it permanently. These controls use the browser's own
prompt and confirm dialogs rather than custom forms.

**The same connection, seen from the other end.** A conversation on the Chat screen *is* a session,
so the "draws on" rows here and the **Draws on** panel described in §4.3 are two views of one thing,
with the same four properties: one-way, several at once, nothing copied, and disconnection effective
immediately. The difference is presentation, and this screen is the weaker of the two — connecting
from here means typing an identity into a browser prompt, while the Chat screen offers a searchable
list of conversations by name. Neither can mint a fact: a connected session's knowledge arrives as
**advisory prior context**, and only an automatic test over real evidence confirms anything.

The permanent-delete wording deserves quoting because it is precise: it is removed from the history,
but **the runs and the signed record are kept**. A system that let an operator erase its own audit
trail from a web interface would defeat the purpose of having one.

**Status: working and actionable.**

---

### 5.2 Activity

*Subtitle: "How VIGIL is working in the background — active runs, the SIGIL agent mesh, spine
activity, and a live event stream."*

**What the operator sees.** A status strip for both halves of the system (*Offense: online/offline*,
*Sovereign: online/offline*, *Kill-switch: engaged/released*). A printed legend reading, in effect:
this is a read-only view across both planes; nothing here changes anything. Four tiles: **Active
runs**, **Agents active**, **Ingest lag**, **Kill-switch**.

Then three panels: **Active work** (up to twelve runs with status, mode, target, elapsed time,
finding count and a *Watch live* button); **Agent mesh and record activity** on the sovereign side
(per-agent recent activity and per-agent budgets, plus the record head, how many records since the
last checkpoint, and when the last consolidation happened); and a **live event stream**.

**A technical detail worth stating for accuracy:** the event stream attaches from the *current*
position rather than replaying the entire history, and de-duplicates by sequence number. This is why
opening the screen does not flood it with old events.

**Status: read-only. The only button is "Watch live", which is navigation.**

---

### 5.3 Approvals & Safety *(owner screen)*

*Subtitle: "Everything that needs your sign-off, the kill-switch, capabilities, and the live
governance feed."*

This is the screen the safety button in the top bar leads to, and the most consequential screen in
the system. It carries an owner banner: approvals, the kill-switch and capability changes are all
signed with the operator's key **on the server**.

**Four tiles:** Kill-switch, Waiting, record head, Budget today. **Six cards:**

| Card | What it shows | What the operator can do |
|---|---|---|
| **Waiting for your approval** | One card per pending decision: kind, sequence number, permission tier, and which agent wants to do what to what. | **Approve** or **Deny**. |
| **Capabilities** | Rows for *gesture* and *voice* with an enabled/disabled state. | **Enable** or **Disable**. |
| **Agent promotions** | The verified list of owner-signed permission grants — which agent, and over what scope. | **Revoke** per row; or grant a new promotion by typing an agent and a scope. |
| **Kill-switch** | Engaged or released. | **Engage kill-switch** or **Release**. |
| **Live governance feed** | The last sixty governance events, streaming. | Read only. |
| **Pending approvals (read-only)** | The offence side's queue of actions waiting for a signature. | **Copy** only. |

Two printed rules on this screen matter.

**On the kill-switch:** *"Halting is always safe and immediate. Releasing requires your signed
request."* Stopping is easy; restarting is deliberate. That asymmetry is the correct one.

**On promotions:** a scope of `*` covers every kind of action, and revoking a single kind does *not*
reduce a `*` grant — the operator must revoke the `*` row itself. And two agents, ENVOY and DELEGATE,
**can never be promoted at all**. This is enforced on the server: an attempt to grant them a
promotion returns an explicit error, so a refused grant can never be mistaken for a successful one.

**The read-only approvals card needs the clearest possible explanation**, because it looks like an
omission and is in fact a deliberate safety property. The offence side queues actions that need the
owner's signature. This console **has no key and can never sign.** It lists the pending requests and
shows the exact command the operator would run — `vigil approve sign --request-id …` — so they can
copy it and run it where the key actually lives. The code carries a comment saying exactly this:
there is no submission route here; it is read-only by construction.

**Status: working and actionable — signed on the server; the browser never holds a key.**

---

### 5.4 Charter & Attestation *(owner screen)*

*Subtitle, condensed: every target-touching action is gated on a signed engagement charter plus a
who/when/what usage record minted before anything runs — no record, no run. This screen provisions a
local authority; a remote target needs a signed charter this screen cannot mint, so it verifies and
guides instead.*

A **charter** is the written, signed authorisation for an engagement: what may be tested, by whom,
between what dates. Nothing that touches a target happens without one.

**What the operator sees and does, in order:**

1. An **engagement name** box and a **Load** button (default: `loopback`).
2. **Authorization status** — is a charter present, what scope does it authorise, what reach does it
   grant (remote authorised with the specific hosts / local only / none), what time window and
   environment does it cover, and which gates are in the chain.
3. **Provision a loopback authority** — a button that mints an authority for this machine only. Its
   scope is hard-fixed to `127.0.0.1` in the code; it is not a field the operator can edit.
4. **Remote target — charter required (out of band).** A host input; an advisory verdict on whether
   that host falls inside the authorised scope, computed in the browser and **explicitly labelled as
   advisory — the gate is what enforces**; a copy-ready ceremony command; and the instruction *"Run
   this on a TRUSTED host that holds the owner key — NOT in this UI."* Plus a **Re-check charter**
   button.
5. **Usage attestation ledger — who / when / what** — a **Load ledger + verify chain** button, which
   reports either "verified — signed, monotonic, not back-dated" or "unverified", along with the raw
   record.

"Monotonic and not back-dated" means the entries only ever move forward in time and none has been
inserted retrospectively. It is what stops someone writing themselves an authorisation after the
fact.

**Status: working and actionable — but structurally limited by design.** This screen **cannot mint or
widen a remote charter.** That is a deliberate boundary: the authority to test somebody else's system
cannot be granted from inside a web page.

---

### 5.5 API Keys *(owner screen)*

*Subtitle: "Every key the system uses — sealed on this machine, never shown back to the browser.
Press Test to check a key is live; a failing key always shows here."*

**What the operator sees.** An owner banner. A **Test all keys** button. A red banner if anything is
failing. Then sections by category.

For a plain secret: a status row showing **Set** (with which storage back end holds it, a
fingerprint, and a health chip) or **Not set** with an explanation; an explicit red line if the last
live check failed; a masked input box; a **Seal** button; and a **Test** button, offered only for a
key that is both set and testable.

For cloud and knowledge-graph providers: a two-column grid mixing sealed secrets (masked boxes, or a
text area for pasting a service-account file or a cluster configuration) with non-secret settings
(region, role identifier, tenant, subscription — these are shown in plain view because they are not
secret). One **Test connection** button per provider.

**Health chip states:** Working / Failing / Can't verify / Not tested. The distinction between
"Failing" and "Can't verify" is deliberate — a system that reported an unknown state as a failure, or
as a success, would be lying in one direction or the other.

**The printed hint states the storage model:** keys are sealed to the operating system's keyring, or
to a hardware-sealed store where one is available; the value never enters the signed record, a log,
or any response — only a fingerprint is recorded.

**Status: working and actionable.** If the owner side is offline or unauthenticated, the screen says
so explicitly and offers nothing, rather than presenting controls that would silently fail.

---

### 5.6 Tools

*Subtitle: "External security tools the offense engine runs on this host — installed live."*

**What the operator sees.** Four tiles: **Installed**, **Missing**, **Failed**, **Required missing**.
A line naming the detected operating system. Then one card per tool with its status badge, name, a
*core* or *optional* label, its version, what it is for, where it was found on disk, and — when
something needs doing — a copyable install command with a **Copy** button.

**The status vocabulary is deliberately honest**, and one state in particular deserves calling out:

| Status | Meaning |
|---|---|
| **installed** | Found and confirmed working. |
| **missing** | Not present. |
| **failed** | Present but did not run correctly. |
| **shadowed** | *A different program with the same name is earlier on the system path and is masking the real tool. It is NOT usable.* |
| **unsupported** | Not supported on this host. |

The "shadowed" state matters because a simpler check would look for the tool's name, find something
answering to it, and report success — while the tool the engine would actually run is a different
program entirely.

On a non-Linux host the screen states plainly that these are Linux packages and that nothing is being
probed, rather than showing everything as missing.

On this machine the screen currently reports **thirteen tools, all thirteen installed**, with none
missing, failed or shadowed.

**A separately labelled card, "NOT HOST-INSTALLED"**, lists the **twenty-four** tools that live
inside the third-party agent's container image. The screen says they are neither probed nor installed
on this machine and are listed for reference only, which remains exactly right: they are in the
image, not on the host. Chapter 12 sets out what has since been established about that image itself.

**The "tool consciousness" panel (advisory).** Four tiles — Adopted, Refused, Installed, Installable
— and one row per tool, each carrying a verdict chip reading **Controllable** or **Refused** with the
reason behind it. It carries more rows than the roster above it — eighteen on this machine — because
it also lists the tools the third-party testing agent holds a written playbook for and which are not
installed on this host. **All eighteen are currently marked controllable and none is refused**, which
was not true earlier the same day; a reader should treat a full house as the result of the work
described in the next two paragraphs rather than as the natural state of that panel.

The vocabulary behind that verdict widened in this round, and the widening is the interesting part.
The system will not claim to control a tool it has no way to drive, so a tool with nothing driving it
is refused outright. It used to recognise only two ways of driving one: a written playbook the agent
reads, or a typed builder that assembles and gates the command itself. But parts of the engine
resolve and start tools on their own — a gated sensor does, the source-analysis pass does, and the
scanner starts a headless browser to confirm a browser-side flaw by really executing it. Those tools
were genuinely being driven and were being reported as undrivable. That is a reporting defect rather
than a missing capability, and its effect was to show the operator installed tools marked *refused*
while the engine was demonstrably running them.

So the verdict chip now **names the surface** — *Controllable (its own command line)*, *(a gated
sensor)*, *(the source-analysis pass)*, *(the headless browser)* — rather than merely asserting that
the tool is controllable. The list of admitting surfaces is closed: a label that is not on it
refuses, so "give it a name" can never become "admit everything". Two things are deliberately **not**
counted as control, and the reasoning is worth quoting because it is what keeps the gate meaningful:
being able to *read* another tool's report is not being able to drive it, and the offline benchmark
harness does start rival scanners in order to score against them, but that is a measurement rig
rather than the engagement pipeline — counting it would let this screen claim an engagement
capability that does not exist.

**One honest wrinkle on this screen.** The verdict chip carries the new vocabulary, but the panel's
own printed explanation underneath it, and its per-tool signal markers, still name only the original
two — a playbook and a typed builder. So a tool driven by a sensor is correctly labelled in its
verdict and unmentioned in the explanation beside it. The complete, per-tool statement of what drives
each one is on the New Assessment tool picker (§4.2), not here. It is stale wording rather than a
wrong verdict, and it is listed with the other honest gaps in §8.

**What the operator can do.** For an adopted-but-missing tool, two buttons:

- **Install** — which does *not* immediately install. The server replies with "needs consent" and the
  exact command; the interface then displays that command next to a **Run it** button which re-sends
  the request with consent. This is a deliberate two-step: the operator sees the exact command before
  anything runs.
- **Research** — shows the canonical search query and links to the official documentation.

**Status: working and actionable, with gated installation.**

---

### 5.7 Brain

*Subtitle: "The propose-only decision engine, plus what the system has learned, how well it scores,
and the capabilities it can bring to bear."*

Six tabs.

**Decision engine.** A banner stating that every step crosses both the permission gate and the
network-egress gate — "egress" meaning traffic leaving this machine, so that gate is the check on
what the system is allowed to reach out and touch — and that a finding becomes a fact only when a
deterministic test fires. An
**active brain** card naming the decision module in use. The gate posture. And — **only if a real
proposal has been persisted** — an observed target profile and the proposed attack chain: each step
with its priority, its tool, a danger label (*recon* or *active*), a per-step gate verdict
(automatically eligible only for reconnaissance in a staging or duplicate environment; otherwise it
queues for the owner's approval), an effectiveness bar, and the raw parameters.

**When there is no live proposal, the screen says so: "No live proposal wired."** It does not draw a
plausible-looking example. An empty state that says "nothing here yet" cannot be mistaken for data; a
worked example rendered in the same style can.

**Memory.** Four tiles — Engagements, Findings, Priors, Dead ends — and a list of learned priors: for
each combination of bug class, target archetype and surface, a success rate with a lower confidence
bound and the underlying successes-out-of-attempts. The empty state states that it never fabricates a
score.

**Benchmark.** A card explaining the test corpus: eleven deliberately planted bugs and five safe
controls, run against this machine only, with no external target, no scope and no network traffic
leaving the machine. A **Run benchmark now** button, which shows "Running… (up to ~5 min)" while in
flight. Results render as four tiles — **True positives**, **False positives**, **False negatives**,
and **F1**, with precision and recall printed underneath it — plus a verdict line. Below it, a
calibration list of recorded results per application and engine.

Those five words are the headline measurement of the whole product, so each one is worth setting out
plainly. Imagine a medical screening programme run over sixteen people, eleven of whom really are
ill and five of whom are perfectly healthy.

| Term | Plain meaning | In this benchmark |
|---|---|---|
| **True positive** | A real problem, correctly found. | One of the eleven planted bugs, detected. |
| **False positive** | An alarm about something that is not a problem at all. | One of the five safe controls, wrongly flagged. |
| **False negative** | A real problem, missed. | One of the eleven planted bugs, not detected. |
| **Precision** | Of everything the system raised the alarm about, what share was real? | High precision means "when it speaks, believe it." A system that flags everything has terrible precision. |
| **Recall** | Of everything that was really there, what share did it find? | High recall means "it does not miss much." A system that flags everything has perfect recall and is still useless. |
| **F1** | A single number combining precision and recall, so neither can be improved by sacrificing the other. | It is closer to the *worse* of the two than to the average, so it cannot be gamed. 1.0 is perfect; 0 is worthless. |

Precision and recall pull against each other, which is exactly why both are shown. A scanner that
shouts about everything scores perfectly on recall and abysmally on precision. A scanner that never
says anything scores perfectly on precision and zero on recall. F1 is the number that refuses both
tricks, and it is the reason the five deliberately safe controls are in the corpus at all: they exist
so that over-alarming has somewhere to show up.

**Catalog.** A searchable list of the real capability catalogue, each entry with its label,
permission tier and purpose. Two printed legends: capabilities map onto already-gated engagement
options; and the reasoning layer (critics, learning, reflection) is **advisory only** — it re-ranks
and defers, but it never promotes a finding to proven.

**Intel.** Per engagement: the raw intelligence data, plus a **Run offline recon** action taking a
seed domain name. The printed text is exact: this ingests passive reconnaissance from bundled files —
no network. Live collection is a charter-gated engagement decision, never a one-click button, so this
control cannot reach the internet.

**Planner.** Per engagement: the raw planner data plus a **Compute plan projection** button.
"It sends no traffic and drives no tools."

**Status: working. Three owner-side actions — run the benchmark, compute a plan projection, ingest
offline intelligence — all explicitly non-networking.**

---

### 5.8 MCP Servers

*Subtitle: "The gated capabilities this engine exposes to an external MCP (Model Context Protocol)
client over an on-host stdio server."*

MCP — the Model Context Protocol — is a published standard way for an external AI assistant to
discover and call tools that live in somebody else's software. This screen answers one question: what
does VIGIL let an outside AI do?

**What the operator sees.** A note from the server, then one card per exposed tool with its
description and labels: its permission tier, that it is gated, where its data comes from, and whether
it is read-only. A footer explains that the transport is on-host standard input/output — the plain
text channel one program on a machine uses to talk to another program on the same machine, with no
network listener and therefore no network surface at all — and gives the command to start the server.

**The verified answer to "what is exposed": exactly two tools** — one that re-verifies a finding, and
one that describes a service the operator has declared. It is important to state the nature of that
list precisely.

The list is a **default allow-list, and an operator can widen it deliberately.** It is not frozen
into the software. What *is* structural is the way the list works: it is an allow-list rather than a
block-list, so it **fails closed** — anything not named on it is refused, rather than being permitted
because nobody thought to forbid it. On top of the list the server independently re-checks four
properties of every tool before advertising or running it: the tool must be in the lowest permission
tier, must require no special entitlement, must not be destructive, and must reach no outside network
address. If a tool that is on the list later acquires any offensive capability, that re-check hides it
automatically. So the honest statement is: **two tools by default; widenable only by a deliberate
operator act; refusing everything else by construction; and re-checked for safety properties even
when it has been named.**

The code also records what is *deliberately* excluded and why, which is worth quoting in substance:
no tool that reads a file path chosen by the caller is exposed, because that would turn the channel
into a way for an outside AI to probe what files exist on the operator's machine. Every active,
network-reaching or exploit-capable tool is excluded too.

**There is a second direction to this seam, and the screen does not show it.** The same part of the
system can also work the other way round: VIGIL can *use* an external MCP tool belonging to somebody
else. When it does, that external tool is wrapped so that whatever it reports enters the system as a
**LEAD carrying a label saying where it came from — never as a proven fact** — until one of VIGIL's
own deterministic tests confirms it independently. This is the same discipline applied to another
vendor's tool that the system applies to its own AI. This inward half is a building block inside the
engine — it has no command and no screen of its own — and this screen covers only the outward-facing
half.

**Status: read-only. There is no start/stop control here.** Starting the server is a command-line
act. The source code says so in a comment: a start/stop toggle in the interface is a later piece of
work. This is one of the places where a screen exists but does not yet do everything a reader might
expect, and it is stated openly.

---

### 5.9 System & Services

*Subtitle: "Everything the system needs, at a glance — prerequisites, the UI ports, and every docker
service's state."*

**What the operator sees.** Four cards:

- **Prerequisites** — a header reading READY or ACTION NEEDED, then a row per required program
  (present or missing), a row per software environment (built, or "not built — run ./bootstrap.sh"),
  and a row per directory with its path and whether it is writable.
- **UI ports** — each of the four internal ports, marked free or in use.
- **Docker services** — per service, a state (running / absent / other) and its purpose. The hint
  reads: "Create the absent ones — idempotent, running ones are left alone." *Idempotent* means
  running it twice does nothing extra; it is safe to press again.
- **Action needed** — appears only when there is something to fix, as a bulleted list.

**What the operator can do.** One button: **Bring up missing services**, with a tick-box for
"include Neo4j + otel" (a graph database and a telemetry collector). The screen re-checks itself a
couple of seconds later.

This screen is the graphical face of the same readiness report the `vigil doctor` command produces.

**Status: a read-only report plus one bring-up action.**

---

### 5.10 Compliance & ATT&CK

*Subtitle: "Every oracle-confirmed FACT mapped to OWASP / CWE / PCI-DSS / SOC 2 / ISO 27001 + MITRE
ATT&CK. A lead never asserts control coverage — only a proven fact does."*

Those names are the standard frameworks auditors and regulators work from. OWASP is the standard
catalogue of web application risks. CWE is the standard catalogue of software weakness types.
PCI-DSS is the payment-card security standard. SOC 2 and ISO 27001 are the two common organisational
security certifications. MITRE ATT&CK is the standard catalogue of real-world attacker techniques.

**What the operator sees.** A run selector and a list. Each row is a finding with either a **proven**
badge or an **advisory** badge. A proven row shows its mapped controls as small pills: the OWASP
identifier, up to three CWE identifiers, up to three ATT&CK techniques, and up to two PCI
requirements.

**A row that is not proven shows no control pills at all** — only the sentence "advisory note only —
a lead / unmapped class asserts no control coverage."

This is the compliance discipline in one sentence: an unproven suspicion is never allowed to claim
that a regulatory control is or is not satisfied. The practical consequence for an auditor is that
the coverage figures on this screen count proven findings only, so they will normally be smaller
than a figure produced by counting every alert a scanner raised.

**Status: read-only.**

---

### 5.11 Assurance — continuous proof / drift

*Subtitle: "Diff the ORACLE-CONFIRMED fact set between two runs: a fact that newly appears is a
regression (a new exposure); one that disappears is a fix. Deterministic + offline — each run's
certificates are re-fired, never re-attacked. A lead is never counted."*

This screen answers the question that matters after the first assessment: **is it getting better or
worse?**

**What the operator sees.** First, a **live assurance projection** card with a badge reading
*collector running* or *collector not running*. When running, it shows four tiles (Facts, Leads,
Refusals, Tool calls), a breakdown per engagement, and a histogram by event kind. When not running,
**it says so and tells the operator how to start it** (`vigil up --with-telemetry`) — rather than
showing zeros that a reader might mistake for measurements. The card is framed as a one-way read-only
projection of the signed record: it mints no fact and widens no permission.

Then, a **Now** run selector and a **vs baseline** run selector, and a summary reading either "drift
detected" or "no drift — same proven set", followed by three lists:

- **Regressions — newly-proven exposures** (a proven weakness that was not there before)
- **Fixed — no longer proven** (it has gone)
- **Stable — proven in both**

**What the operator can do.** **Re-verify now**, which re-fires the retained certificates offline;
and **Download drift (JSON)**, which is a pure export of what is already on screen — no back-end call,
no new data exposure.

A note on the screen states that attack-path and asset graphs are per-run and live on the Findings
screen. This panel does not fabricate one.

**Status: read-only, plus offline re-verification and a client-side export.**

---

### 5.12 Settings *(owner screen)*

*Subtitle: "The model the AI reasons with. API keys have moved to their own screen."*

Banner: every change is signed with the operator's key on the server; the browser never holds or
receives key material.

**Five cards:**

1. **Reasoning model** — a list of available AI models, each with a label, a *current* marker, a *no
   key needed* marker for the free options, and a note. Button: **Use this model**. The hint explains
   that mechanical helper tasks always use a fast model, and that a running engine picks up the change
   the next time it is started.
2. **API keys** — a hint and a **Manage API keys** button pointing at the API Keys screen.
3. **Reasoning effort** — a dropdown offering low / medium / high / xhigh / max plus "Model default",
   and an **Apply effort** button. The hint explains it applies to the offence reasoning engine, the
   sovereign side's thinking step and the third-party codebase agent, and that older models simply
   ignore it.
4. **Bring your own model** — a provider selector, then that provider's model field with suggested
   identifiers, its configuration fields, a "Needs: …" line naming which keys that provider requires
   and their live health, a link to the API Keys screen, and a **Use this provider** button. A
   provider that needs no key says so.
5. **System configuration** — every non-secret operational setting the server chooses to expose,
   grouped by subsystem, each rendered as a dropdown, tick-box or text field with its own **Save**
   button. Leaving a field blank clears it back to its built-in default.

**One property of that last card is worth stating precisely.** The server type-checks every value —
number ranges, web addresses, network ranges, host names, port lists, fixed choices — and refuses any
setting name it does not recognise. **The interface cannot write arbitrary configuration.** A web
page that could set any environment value on the host would be a serious hole; this one cannot.

**Status: working and actionable.**

---

### 5.13 Governance & Gate Audit

*Subtitle: "Read-only: whether exploitation runs GOVERNED (capability entitlement enforced) or
UNGOVERNED, the sovereignty tier, the safety-gate conjuncts every action must clear, and the m-of-n
destruction quorum. This screen cannot provision, authorize, or fire anything."*

**Four cards:**

- **Posture** — a confirmed or refuted badge and one of two sentences: **"GOVERNED — capability
  entitlement is ENFORCED"** or **"UNGOVERNED — entitlement not enforced"**, plus the granted tier and
  an explanation.
- **Sovereignty** — the tier, and whether it is *sealed (latched)* or not sealed. Latched means it
  cannot be loosened again without a deliberate act.
- **Safety gate** — the set of conditions that every target-touching action must clear, shown as
  pills, with the note **fail-closed**. Fail-closed means that if any check cannot be completed, the
  action is refused rather than allowed.
- **Destruction authority (read-only audit)** — the *m-of-n* threshold, the identities of the
  authorising keys, the count of consumed single-use authorisations, and any pending authorisations
  with their action identifier, blast class, target and how many of the required signatures they have.
  When nothing has been set up, it says so: no trust root provisioned, so no quorum exists here.

"m-of-n" means a destructive action needs, say, two signatures out of three named key-holders. No
single person can authorise it alone.

**Status: read-only by construction.** The screen states it: the interface cannot provision,
authorise or fire a destructive action. Minting and consuming such an authorisation happens only
through the gated command line with multiple independent signatures. This is not a missing feature.
It is the point.

---

### 5.14 Engagement Library

*Subtitle: "Every past job, most recently worked first — open one to get back to its runs, findings
and proof."*

This screen answers a question none of the others answer: **what did we do last spring?** Months
after a piece of work, an operator usually remembers the customer's name and roughly when the work
happened, and nothing else. Everything the system produced is still on the machine and still sealed —
but the way back to it used to be an alphabetical list of folder names carrying no dates at all, and a
job that had only ever been written into the signed record, without a folder of its own, did not
appear on that list at all. The library is the way back in.

**What the operator sees.** One table, one row per past job, **most recently worked on first**. Dates
and times are shown in the reader's own time zone, and the screen prints which zone that is rather
than leaving it to be guessed at.

| Column | What it holds |
|---|---|
| **Job** | The human name, if one has been given, with the machine identity printed underneath it in small type — so the name a person chose and the identity the system works from are never mistaken for one another. A job that exists only as a folder on disk, with no entry in the tamper-evident record, is marked "not on the spine" (*spine* is this system's word for that record). |
| **Last worked on** | The most recent real activity: an entry in the signed record, the moment a run started, or the time the authorisation document was last written. |
| **First seen** | The earliest of those same three signals. |
| **Kind** | What sort of work it was — a website or interface assessment, a codebase review, a single tool, the autonomous suite, a cloud or Kubernetes posture review, or a defensive run — read from each run's own record rather than inferred. |
| **Subject** | What the work was pointed at, up to five entries. |
| **Runs** | How many separate runs the job holds. |
| **Findings** | How many findings are stored, and beside it — for a job recorded in the signed record — how many of those are proven facts rather than leads. |

**Where those numbers come from, and what they are not.** The list is the union of two real sources on
the machine — the signed record's own roster of engagements, and the folder of authorisation documents
and evidence — together with the runs this interface itself launched, each filed under the job that
that run recorded for *itself*. Two consequences are worth stating in plain terms. First, every date
on this screen is derived from something that exists on disk, and **a job with no recorded activity is
shown with a dash rather than back-dated to today**; the screen would rather admit it does not know
than invent a plausible date. Second, a run belongs to a job because the run's own record says so, not
because the request asked for it: **the browser cannot claim a run into a job it does not belong to.**

Ordering is by most recent activity. Because the stored times are only accurate to the second, several
jobs created by one command can carry the identical stamp; the tie is then broken by which was started
more recently, and only as a last resort by identity, so the order is stable rather than flickering
between two equally recent rows. When there are no past jobs at all the screen says so — "No past jobs
yet" — and offers the New Assessment button instead of an empty table.

**This screen is also the switch.** Because the interface is now scoped to one job at a time (§2),
the library is where that job is chosen and where the view is widened back to everything. A line
above the table says which it is — "Every screen is showing *Acme — Q3 external review* only", or
"Every screen is showing all engagements. Open a job below to work on just that one" — and, when a
job is in scope, an **All engagements** button beside it. Opening a job from the table, from a
bookmark, or from a shared link makes it the active one. Widening is a presentation switch and
nothing more: every job, run, finding and certificate stays exactly where it was.

**Opening one job.** Clicking a row opens that job on its own. Four tiles: the machine identity,
labelled *never changes*; when it was last worked on; how many runs it holds; how many findings, with
how many of those oracle-proven. Then badges for the state a reader needs before trusting anything
below them: charter on file or no charter, kill-switch tripped, on the signed record. Then a table of
the runs inside the job — name, when it started, status, what it was pointed at, finding count — and
against each run four buttons: **Findings**, **Evidence**, **Dossier**, **Rename**. The first two
navigate into the screens described earlier in this chapter; the third downloads that run's dossier,
the sealed package described in chapter 6.

**What the operator can do.** Open a job, rename a job, rename a run, jump into a run's findings or
its evidence, and download a run's dossier. Renaming uses the browser's own prompt box, as the
Sessions screen does, and the prompt carries its own one-line disclaimer: *"The name is for you — it
changes nothing that is signed."* Nothing else here changes anything. The screen cannot launch a run,
cannot approve anything, and cannot alter a finding.

**The load-bearing property: a rename is presentation only.** This is the part of the screen that this
briefing exists to explain, so it is worth being precise about.

Every past job has two names. The **machine identity** — a date-stamped identifier, or the short name
the engagement was created under — is the name every certificate, every dossier and every entry in the
signed record was written against. It never changes. The **human name** is a separate thing entirely:
it is stored on its own, in one small file beside the interface's own records, keyed by that machine
identity. Renaming writes one entry in that file and nothing else. **It touches no run's files, no
evidence certificate, no part of the proof bundle and no entry in the tamper-evident record**, and it
rewrites nothing that already exists. The consequence is the one a customer cares about: a job can be
relabelled "Acme — Q3 external review" for the convenience of the people who have to find it again,
and the proof package already handed to that customer still verifies, byte for byte, exactly as it
did before.

There is one place the human name deliberately does travel, and precision about it matters more than
a clean slogan. If a **run** is renamed and its dossier is then downloaded *again*, the fresh archive
is **titled** by the human name: the name heads the readable documents inside it, so that whoever
opens the archive months later recognises the job instead of reading a date-stamped machine
identifier. Titles are part of the readable material that the archive's own list of hashes covers, so
that list is recomputed and the archive re-signed on every build, as it must be. What does not change
is the proof: the sealed evidence inside is byte-identical either way, and its certificates carry the
same fingerprints. Renaming a **job** does not travel even that far — only a run's name is carried
into a download.

That is not a claim resting on a comment in the code. It is exercised by tests that run on this
machine and passed while this section was being written:

| The test | What it establishes |
|---|---|
| **Change the stored name between two builds of the same run's dossier** | The proof re-verifies both times with the same verdict and the same certificate identity; the two archives are **byte-for-byte identical**; and neither name appears anywhere inside either archive. The test drives the packager directly, without the title the download button hands it, so what it pins is that nothing the packager gathers of its own accord can pick the name up. |
| **Run the real offline verification a recipient runs** | Not a simulation of it: the pinned trust root, the signature checks, the hash chain, the artifact list and the deterministic re-firing of the checker, over two archives built while the stored name changed between them. Both must pass, with identical certificate fingerprints. |
| **A deliberate control** | Make a genuine content change between two builds and the byte-identical check *must fail*; corrupt one entry in an archive and the tamper check *must fail*. Without this, the two tests above could be green because they were measuring nothing. |
| **Photograph every file before and after** | A complete copy of every file the interface owns is taken before a rename and compared after it. The only thing permitted to differ is the file of names itself. |

**Honest limits, stated plainly.** Four of them, and the first is the price of the property above.

- **The human name is not signed.** It is convenience metadata held outside the tamper-evident record,
  and nothing in the renaming path writes to that record. So the signed history does not show that a
  job was renamed, or by whom. This is a deliberate trade: a name that *could* reach the signed
  material is exactly the thing the design forbids, and one of the two cannot be had without losing
  the other. What protects the name file is ordinary and worth naming honestly: it is readable only by
  the account running the software, it is written in a way a crash cannot leave half-finished, and the
  renaming request passes the same protections as every other action this interface can take — it is
  not an owner-key act.
- **The runs table lists the runs this interface launched.** A job driven entirely from the typed
  commands still appears in the library, with real dates and counts read from the signed record, but
  its detail view says so rather than showing an empty table: this job has an authorisation document
  or a record entry, but no run launched from here yet.
- **Refusals, not best guesses.** A malformed or unknown job identity is refused outright rather than
  stored, a run can be named only if that run actually exists on disk, names are length-capped and
  stripped of control characters, and the store of names is bounded — so repeated requests cannot grow
  it without limit.
- **The screenshot of this screen was taken in this round**, closing what had been a documentation
  gap. The picture is therefore current; several older screens' pictures are not (§8).

Everything on this screen is read from this machine. Nothing here reaches the network.

**Status: read-only apart from the two rename actions — and neither of those changes anything that is
signed.**

---

## 6. Group LEARN — the four screens for understanding and staying current

### 6.1 Trust Center

*Subtitle: "VIGIL's signed, offline-verifiable certificates — rendered as certificates: trust root,
out-of-band fingerprint pin, and a live offline PASS/FAIL verification."*

**What the operator sees.** A statement of doctrine, then a grid of certificate cards. Each shows its
kind and name, which run it belongs to, its schema, its signed digest, its trust root with the m-of-n
threshold, and the authorising keys.

Then, critically, one of two things:

- **"Fingerprint pin (out-of-band)"** — for a certificate whose trust root is pinned in the source
  code, with the note that re-signing under a fresh key fails the pin.
- **"Fingerprint (self-asserted, in-bundle — NOT a pin)"** — for a per-run certificate, with the
  explicit caveat that it proves only tamper-after-signing, plus an input box for supplying a real
  out-of-band pin.

That distinction is the most important sentence on the screen. A fingerprint carried *inside* the
same package it is supposed to protect proves only that the package has not been altered since it was
sealed. It does not prove who sealed it. Only a fingerprint published independently does that. The
interface refuses to blur the two.

A recall-type certificate additionally shows, for each tool, its recall, precision and F1 — the three
measurements defined in the Brain section above — together with the raw counts behind them and how
large the known-answer set was. A coverage or plan-integrity certificate shows its scope, target
and summary. A certificate that has not been produced yet shows an idle badge and instructions for
minting it.

**What the operator can do.** **Verify offline** — with an optional out-of-band pin. The result
shows:

- **PASS — signature re-verified offline** or **FAIL — did not verify**
- and then a deliberately **three-state** row about the pin: *matches the out-of-band pin*; *does NOT
  match the pin*; or *trust root UNPINNED — no out-of-band pin supplied (origin not bound)*.

That third state is drawn in a neutral colour and, per an explicit comment in the code, is **never
green**. An unpinned root is not a pass: the signature is intact, but nothing independent ties it to
a known signer, and the screen refuses to let those two situations look the same.

**Status: working — reading plus a pure offline re-computation.**

---

### 6.2 Proof of Posture

*Subtitle: "The Certificate of Non-Exploitability — a signed, coverage-bounded, offline-verifiable
proof that, over the surface the scanner REACHED, an applicable oracle had a live channel and did not
fire. The boundary (denominator + residual) is the point."*

This is the screen for proving a **negative** — that specific weaknesses were tested for and were not
found. Proving a negative honestly is much harder than proving a positive, and this screen is built
around admitting the limits.

**What the operator sees.** **Refresh** and **Download certificate (JSON)** buttons, a doctrine
block, then one card per posture certificate containing:

- the target, the engagement and the run
- **a freshness caveat, stated openly**: the signed core of the certificate is deterministic and
  contains no wall-clock time; the freshness bound comes from an external timestamp attached
  alongside, not from a field inside the signed bytes
- **four tiles**:

| Tile | Meaning |
|---|---|
| **Closed** | An applicable test had a live channel and did *not* fire. This is the proven-negative count. |
| **Open** | A test *did* fire — that is a finding. |
| **Unproven** | A probe was sent but no test adjudicated the result. |
| **Re-executable** | Of the Closed items, how many can be re-run entirely offline; the rest are binding-only. |

- **a coverage denominator panel** — how many surfaces were reached, how many insertion points were
  probed, how many distinct weakness classes were probed, the crawl limits in pages and depth,
  whether the frontier was truncated, and whether the budget was exhausted. It closes with a
  red-toned line stating that CLOSED is bounded to the surface the scanner actually reached; that
  undiscovered endpoints and parameters are out of the denominator and **not** covered; and that a
  CLOSED certificate is never a claim of security against everything.
- **the residual** — the honest statement of what remains uncertain, printed verbatim from the
  certificate
- **posture claims by surface** — tables with columns *Parameter · Class · Status · Evidence
  oracle(s) · Verification · Probes*, statuses of CLOSED / OPEN / UNPROVEN, and a two-value
  verification column distinguishing **re-executable** (the raw bytes are embedded and a pinned test
  kernel re-runs them) from **binding** (the offline checker re-checks the signed verdict, but
  re-firing the test itself needs VIGIL). A comment in the code reads: *never dress binding up as
  re-exec.*
- **trust root and out-of-band pin** details, with publication guidance
- **verify offline (no VIGIL, no trust in us)** — the exact multi-line command with a Copy button,
  and a precise statement of what a successful exit does and does **not** prove: it does **not**
  re-fire the deterministic test, which needs VIGIL, and the certificate states that limitation on
  its face
- when a portable package exists, its path with a Copy button

**The empty state is explicitly non-fabricating:** "Nothing here is fabricated", followed by the
command to mint a real certificate.

**Status: read-only, plus a client-side export.**

For a procurement reader, the difference in kind is worth stating plainly, because the two outputs
answer different questions. A list of findings answers "what did you find?" This screen answers
"what did you look for, what did you not find, and where exactly does your coverage stop?" — as a
bounded, signed statement a third party can check without trusting us.

---

### 6.3 Manual

*Subtitle: "How every part of VIGIL works — in plain language."*

A two-column reading view: a sticky contents index on the left, the text on the right. The content is
static documentation shipped with the interface; it contains no live data.

**Thirteen sections:** What VIGIL COMMAND is · The safety model (read this first) · Running an
assessment · Watching it live · Findings & evidence · Fixes · Arming live auto-patch (opening real
PRs) · Defense — AEGIS · Approvals & Safety · Settings — keys & model · Brain — memory, benchmark &
catalog · Deploying — local & hosted · Glossary.

**An honest gap, worth stating plainly:** the manual covers thirteen topics, not all twenty-nine
screens. There is currently **no manual section** for Terminal, Chat, Sessions, Engagement Library,
Proof Studio, Report, Compliance, Assurance, Charter & Attestation, API Keys, Knowledge Engine, MCP
Servers, System & Services, Governance, Trust Center, Proof of Posture, or Replay Proof. Those screens carry their own
in-screen explanatory text — which, as this tour shows, is substantial — but they are not written up
in the manual.

**Status: read-only.**

---

### 6.4 Knowledge Engine

An engagement selector drives the whole screen. The opening hint sets the frame: this is an
auto-updating feed of vulnerability intelligence from trusted public sources (the US National
Vulnerability Database, the Open Source Vulnerabilities database, and the US agency's
Known-Exploited-Vulnerabilities catalogue), alongside the defensive knowledge catalogue. **Every feed
entry is an intelligence-tier LEAD, never a fact** — only a fired deterministic test confirms
anything. Live pulling of the feed is a deliberate, opt-in act that reaches the internet; **offline is
the default.**

**Eight cards:**

| Card | What it shows | What the operator can do |
|---|---|---|
| **Propose-to-learn** *(owner)* | Whether automatic learning is on; a ranked list of proposals with known-exploited badges, severity and rationale. | Activate or deactivate automatic learning; **STOP (emergency halt)** and Release; queue a proposal for approval; then Accept or Deny it. |
| **Add & learn a source** *(owner, shown only when automatic learning is on)* | A vulnerability-identifier box and a web-address box. | Add to the learn queue; or **Learn from URL**, which reports how many claims were *grounded* and how many *advisory*, the host, the page count, and up to 4,000 characters of the extracted text. |
| **Self-evolve** | Whether everything in scope has been studied; gaps in horizon and in bug-class coverage; draft counts; unlearned leads; calibration figures including a Brier score (explained below). | Draft skills for an unlearned lead; run an evolve tick. Both are disabled while the emergency stop is engaged. |
| **Feed sources** | Name, mode and host per source. | Read only. |
| **Vuln-feed pull** | A label reading "egress offline by default" — meaning the system does not reach out to the internet unless told to. | **Pull now** (one-shot, gated by the emergency stop). Or start a recurring background pull, with an interval the operator chooses between one minute and twenty-four hours (the default is one hour). And stop it again. Status shows either running, with the identifying number of the background process and the chosen interval, or stopped. |
| **Vulnerability leads** | Per vulnerability: a known-exploited or lead label, the identifier, severity, summary and source feed. | Read only. |
| **Defensive knowledge catalog** | The defensive detection operators with their mapped attacker techniques and weakness types (first 200). | Read only. Labelled "Never facts." |
| **knowledge/ folder → git** *(owner)* | — | **Status**; or **Regenerate + commit**, which regenerates the system map, scans the folder for secrets, and commits locally. |

**What the "Learn from URL" button actually does.** That one row covers a whole subsystem, and a
reader of this chapter should not have to guess at it. Pressing it hands the pasted web address to the
sovereign side's own page-reading component, which fetches **public pages only, by ordinary retrieval,
never anything a site owner would recognise as probing** — and which identifies itself with one fixed,
never-varied label rather than disguising its traffic. Each fetch passes four gates before a connection
opens: the address must be on the site the owner typed and nowhere else; every address that site name
resolves to must be a public one, with the connection then pinned to it, which is what stops a web
address being used to reach the machine's own private network; the site's own published rules for
automated readers are respected, and are treated as *forbidding everything* if they cannot be read; and
a minimum pause is taken between requests to the same site. The run is deliberately tiny — **at most
four pages, one step from the address given** — because it happens while the operator waits, and the
emergency stop is wired into it as a signal checked *between* page fetches, so a halt takes effect
promptly rather than after the crawl would have ended anyway. The keystone is the grounded/advisory
split named in the table: every claim goes through **the identical demote-only admission check that
governs the owner's own memory**, so **nothing a page asserts ever becomes a fact** — a page is a
source of quotations, never of truth, and what is served for a grounded claim is the page's own
passage rather than the model's sentence about it. Chapter 14, "Learning from a page the owner points
at", sets out the gates, the topic-based variant that reads a fixed list of public reference works, and
the honest status of the route — including the fact that it has never been run against a live outside
site on this machine.

**The Brier score, in plain words.** It appears on the Self-evolve card and nowhere else in this
chapter, and it is not a term a general reader will know. When the system predicts something, it does
not only say yes or no — it attaches a probability ("I am 70 per cent sure this will turn out to be
real"). Later, the deterministic test settles the matter one way or the other. The Brier score
measures how well those stated probabilities matched what actually happened, across every prediction
that has since been settled. Zero is perfect; a higher number is worse. It is a measure of
**honesty about uncertainty**, not of skill: a system that says "90 per cent sure" and is right nine
times in ten scores well, and so does a system that says "30 per cent sure" and is right three times
in ten. What scores badly is confident wrongness. This is the number that tells the operator whether
the system's own confidence figures can be taken at face value.

Four printed statements on this screen are worth repeating verbatim in substance, because each closes
a way the system could otherwise be tricked:

- URL-learning fetches public pages **through the scope, robots and server-side-request-forgery
  gate**; nothing a page asserts becomes a fact. Grounded claims are verbatim spans quoted from the
  source; everything else is marked advisory.
- The self-evolve controls produce **drafts only** — they never merge, never apply, and mint no fact.
- The recurring feed has **no persisted schedule** — only the live process and the interval the
  operator chose. It does not silently resurrect itself.
- The git sync **refuses the commit** if the secret scan finds anything, and lists the files to
  redact. And **pushing to a remote repository stays a deliberate command-line act** — this screen
  never pushes.

**Status: working and actionable — gated, and leads-only.**

---

## 7. Capabilities that have no screen at all

A tour of the screens would leave a false impression if it stopped at the screens. A number of
significant parts of the system are reached in some other way — through the ordinary flow of a run,
through a typed command, or through the build pipeline. A reader who went looking for a button and
did not find one might otherwise conclude the capability does not exist. It does.

This section covers them in three groups: the cloud and Kubernetes exploitation confirmations
(§7.1), the safeguards around how the software itself is built and shipped (§7.2), and a set of
seven further capabilities that are real, are in the software, and appear on none of the
twenty-nine screens (§7.3).

### 7.1 The six cloud and Kubernetes exploitation confirmations

Most security tooling, when it looks at a cloud account, reports *configuration*: this permission is
too broad, this bucket is readable, this role is over-privileged. That is a useful thing to report,
but it is a statement about settings, not about consequences. This system additionally contains six
confirmations that a weakness was not merely *present* but actually *achieved*.

| Confirmation | What it establishes, in plain terms |
|---|---|
| **Instance-metadata credential capture** | A cloud machine has an internal service that hands out credentials to whatever is running on it. This confirms a credential was actually retrieved from that service and actually worked — not that the service was reachable. |
| **Exposed-secret validity** | A password or key found lying somewhere it should not be is only a real problem if it still works. This confirms the secret is currently valid, rather than expired or revoked. It recognises two kinds of credential, and the two are at different stages — see below. |
| **Google service-account impersonation** | One machine identity was able to act as a different, more privileged identity. |
| **IAM privilege escalation** | A strict, achieved increase in privilege. The distinction matters: it confirms the step was taken, not that a path to it could be drawn on a diagram. |
| **Kubernetes access control, tier one** | An anonymous, unauthenticated caller is bound to a dangerous built-in role on a container cluster. |
| **Kubernetes access control, tier two** | A dangerous permission verb, or the cluster's default identity, has been granted rights it should not have. This one works by reading and parsing the permission rules themselves. |

**Status, stated exactly.** All six are complete and part of the released software. Each is built
from two halves: a deterministic automatic checker — the same kind of fixed, non-AI test that
adjudicates every other result in this system — and a capture module owned by this project that
produces the evidence the checker judges. All six are wired end to end. The two Kubernetes ones are
proven against a real single-node cluster the system stands up, owns and destroys itself: the
dangerous binding confirmed with a certificate that re-verifies offline, and the benign bindings in
the same cluster — including the namespace's own default identity bound to the built-in `admin`
role, whose real rules do grant secret reads — correctly left as leads. What that run does not cover
is
discovering bindings across a whole cluster, and a managed provider's control plane (Amazon EKS,
Google GKE, Azure AKS). A third has since joined them: the **GitHub half** of exposed-secret
validity is proven against the real GitHub service, using the operator's own credential against
GitHub's own least-privileged identity endpoint, with the certificate re-verifying offline and a
live bogus credential of the same shape correctly left as a lead. That capability's **Amazon Web
Services half is not proven** — it is built and unit-tested but has never touched real Amazon
infrastructure, and nothing from the GitHub run transfers to it. The remaining cloud ones are
proven offline with fixture evidence, meaning recorded sample data standing in for a live cloud
account.

**There is no dedicated screen for any of them, and no dedicated typed command either.** This was
checked directly: none of the twenty-nine screens names any of these capabilities, and the six
verification modules are referenced nowhere outside their own folder and their own tests. They are
internal verification paths, not buttons.

**So where does an operator see one?** Exactly where every other confirmed result appears. When one
of these checkers fires during a run, the result flows through the ordinary path: it appears on
**Live** as a finding marked as confirmed by a checker, in the **Findings** table with its
certificate in the Evidence tab, in **Proof Studio**, in the **Client Report**, in the **Compliance**
mapping, and in the **Assurance** comparison between runs. Nothing bespoke, nothing separate.

**What the interface does offer for cloud is the posture path** — and it is honest about being
posture rather than exploitation. The "Cloud / K8s posture" option in the New Assessment wizard
requires a signed engagement charter, validates that what was entered is a *label* rather than an
address or a network range (the code is explicit that it is "never a seed"), and runs an offline
review. The wizard's own field hint states that the sensor "reads your imported inventory, never the
live account." There is no button in this product that says "run a cloud exploit", and this chapter
will not imply there is one.

**What remains deferred, stated exactly — and what no longer is.** For the remaining **cloud**
capabilities — the metadata-credential capture, the Google service-account impersonation, the
permission-escalation re-derivation, and the Amazon Web Services half of exposed-secret validity —
what has not yet happened is **real-world live fire against a third-party cloud
account**. That step waits on the customer supplying their own cloud credentials. The detection logic,
the evidence handling, the certificates and the safety gates are all built and proven. The code says so
in its own words: the module that would reach a live metadata service records in its own documentation
that the network half is "deferred until an authorized lab credential is available."

The **two Kubernetes** capabilities are no longer in that position, and neither is the **GitHub half
of exposed-secret validity**. Both Kubernetes ones are proven against a **real
Kubernetes cluster**: a repository script stands up a genuine single-node cluster (k3s 1.31.5, in a
container on the machine's own internal address) which the system creates, owns and destroys, plants
known-dangerous and known-benign access rules in it, and adjudicates what the real Kubernetes interface
returns through the ordinary production path. The dangerous binding is confirmed and its certificate
re-verifies offline; the benign ones — including the namespace's own default identity bound to the
built-in `admin` role, whose real rules do grant secret reads — correctly stay leads. What that run
does not cover is a scope-gated *enumeration* capability discovering bindings across a cluster, and a
managed provider's control plane (Amazon EKS, Google GKE, Azure AKS).

Two framings should both be avoided, because each is inaccurate in a different direction. Saying the
capabilities are unfinished understates the system: they are built, gated, and proven. Saying the cloud
ones have been field-proven in customer clouds overstates it: none has been pointed at a customer's
account. The accurate statement, and the one this document uses, is: **the Kubernetes confirmations
are proven against a real cluster the system stands up itself; the GitHub half of exposed-secret
validity is proven against the real GitHub service and its Amazon half is not; and the remaining cloud
confirmations are built, gated, and proven offline, with live fire awaiting operator-supplied
credentials, by design.**

That design point is worth drawing out for a procurement reader, and the two halves show it from
opposite sides. For cloud, it would have been technically easy to ship a demonstration against an
account of our own and call it field-proven; that was not done, for the same reason the rest of the
system behaves as it does: a claim that cannot be re-checked by the customer is not worth making. The
customer's own account, under the customer's own credentials, inside the customer's own authorisation,
is the only test that means anything — and that test is theirs to authorise, not ours to assume. For
Kubernetes the same principle pointed the other way: a cluster can be created from nothing on any
machine in seconds, so the proof was built to create one, and its whole value is that the customer can
run the identical script and get the identical result.

### 7.2 Build and release safeguards

The safeguards that protect how this software is *built and shipped* — pinning every dependency to
an exact verified copy, pinning container base images to exact content rather than to a movable
label, publishing a bill of materials for the software itself, and failing the build when a critical
vulnerability is found in a dependency — are properties of the build pipeline, not features an
operator clicks.

Accordingly there is **no screen for them** among the twenty-nine, and no typed command for them
either. Their evidence is the build pipeline's own record, and a reviewer should read the build
configuration directly rather than look for a control in the interface. This work was still being
delivered at the moment this chapter was written, and the state of a repository at a particular
moment is exactly the sort of claim this chapter should not make from memory, so it is deliberately
not enumerated here. It has since been accepted into the released version of the software: chapters
1 and 6 of this briefing were revised afterwards and give the position in detail, item by item,
including the one inventory file that is still a placeholder.

One closely related item is easy to confuse and worth separating explicitly, because the two point in
opposite directions:

- **A bill of materials for VIGIL itself** is a build-and-release safeguard. It answers "what is
  inside the thing we ship to you?"
- **The system's own dependency-scanning capability** is an *offensive* feature. It reads a
  **target's** dependency manifest and checks those versions against a pinned, offline vulnerability
  snapshot in order to produce a version-range finding about somebody else's software. Its own
  documentation is blunt that an external scanner's match "is only a PROPOSER of where to look — its
  CVE match never mints a FACT."

Same subject matter, opposite directions. They should never be quoted as one another.

### 7.3 Seven further capabilities with no screen of their own

These are real, working parts of the system that a reader touring the twenty-nine screens would
never meet. Five are reached by typing a command; two are reached only from inside a run. None of
them is a placeholder, and none of them is hidden — they simply were not given a page in the
interface.

#### Five reached by typing a command

**The out-of-band relay.** Some weaknesses are invisible from the front: the target gives nothing
away in its reply, so there is nothing to read. The test for these works sideways. It gets the target
to reach out and contact a machine of the operator's choosing; if that outward call arrives, the
weakness is proven. The everyday equivalent is handing someone a stamped, addressed postcard: if it
turns up in your letterbox, you know for certain they posted it, even though they told you nothing.
The relay is the small server that sits and waits for that postcard. It is one the operator
**hosts themselves**,
on a machine they own and have written into the signed engagement authorisation — not a rented
service belonging to a vendor. Polling it requires a shared secret, so nobody else can read the
operator's results. Started with `vigil crucible collaborator serve`, and the engagement is then
pointed at it.

**Entitlement provisioning.** The system's most dangerous capabilities do not run merely because the
software is sitting on the disk. They run only against a signed permission slip that is tied to a
particular machine, expires, and can be revoked. Possession of the code without a matching slip
yields only the safe baseline. This is the direct answer to the question every government buyer of an
offensive tool asks — *if this software is copied or stolen, what can the thief do with it?* The
typed command is `vigil crucible entitlement`, which offers three read-only actions: show the current
status, list what each permission tier permits, and check a slip. The Governance screen (§5.13)
displays whether this enforcement is switched on, but cannot provision it.

**Target intake.** This turns a single web address into a fully prepared engagement folder: a draft
authorisation document, a draft threat model, a draft attack tree, and a fingerprint of the
technology the site appears to use. It works from a deliberately polite, capped fetch — a small fixed
number of requests, no login attempts, no probing — of the standard files a site publishes for any
visitor to read. **Nothing is scaffolded without the operator's recorded attestation that they are
authorised, and no active testing happens until the operator signs the charter.** The command is
`vigil crucible intake`.

**Importing another tool's results.** An organisation that already runs other security tools can feed
those tools' output into VIGIL. The results of Nuclei, ZAP, Burp, sqlmap or a generic findings file
enter the shared picture as **leads labelled with where they came from — never as facts**. Another
vendor's tool is treated exactly as the system treats its own AI: a place to look, not a proof.
Writing them into the durable store is a separate opt-in step, so simply inspecting a file changes
nothing. The command is `vigil crucible imports`; the same import can also be driven through the
gated on-machine service described in §9.2.

**Social-engineering defence.** This is the defensive inverse of a capability the project refuses to
build. Rather than *generating* phishing or impersonation, it scores *incoming* content for the signs
of one — urgency, harvesting of credentials, pretended authority, lookalike domain names, a sender
address that does not match the reply address, requests for money, requests for secrecy, dangerous
attachments — and produces a weighted risk score and a recommendation. It is deterministic and works
offline. Its output is explicitly **leads for a human to judge, not verdicts**, because this kind of
detection is inherently a matter of probability and the tool says so on its face. The command is
`vigil crucible socialdefense assess`.

#### Two reached only from inside a run

**The fuzzing engine (the industry calls this an "Intruder").** The ordinary checks send one
carefully chosen test input per weakness type. This is the other axis: many hundreds of variations
pushed through marked positions in a request, with the results sifted automatically for the one
response that behaves differently from all the others. In the tools a human tester normally uses for
this, a person sits and reads down a table of results looking for the odd one out; here an
automatic outlier detector does that step. This is what allows brute-force attempts, enumeration of hidden values, and attacks
that depend on two things happening at the same instant to run without somebody watching. It has no
command and no screen; the engine drives it during a run.

**The request replayer (the industry calls this a "Repeater").** Capture one request to an in-scope
target, edit it by hand, send it again, and compare the answers. It is one of the most useful manual
techniques in web security testing, and also one of the most dangerous things an operator can do by
hand. Here
it never opens a raw network connection of its own: every replay is routed through the same
fail-closed permission chain as everything else, is checked against the engagement scope at *both*
the sending and the executing end, requires the higher-tier permission slip, and records every
refusal as evidence. Its own documentation states the posture in three words — **correlatable, not
evasive** — meaning it makes no attempt to hide from the target's own logs. It has no command and no
screen; it is invoked as a gated capability.

**The honest summary of this group.** Each of these is built and working. What none of them has is a
place in the interface. For the five with a command, an operator can use them today by typing. For
the two without, they are internal capabilities that the engine brings to bear on the operator's
behalf, and the operator sees only the result — a lead or a proven finding — through the ordinary
path.

---

## 8. Where the interface is honestly incomplete

A briefing that lists only what works is not a briefing. This section lists every place in the
*interface* where a screen shows something that does not do what a reader might reasonably assume,
together with the interface's known gaps in coverage. It is a statement about the twenty-nine
screens. It is not a claim that the system as a whole has no other limits — the capabilities that
have no screen at all are set out in §7, and the ways of driving the system that are not screens at
all are set out in §9 and §10.

| Item | The honest position |
|---|---|
| **The command palette** | Visible in the top bar on every single screen, marked with the Macintosh shortcut symbol. Clicking it shows a message saying it is "on the roadmap". It has no function. This is the one clearly non-functional visible control in the product interface. |
| **MCP start/stop** | The MCP screen lists what is exposed but cannot start or stop the server. A source comment records that a toggle is later work. |
| **The offence-side pending-approvals list** | Read-only and keyless *by design*, not by omission. It shows the exact command to run elsewhere. There is deliberately no way to sign from the browser. |
| **The Governance screen** | Read-only by design. Destructive authorisations are minted and consumed only through the command line with multiple independent signatures. |
| **The Charter screen** | Can provision a *this-machine* authority only. A remote charter requires an out-of-band ceremony on a host that holds the owner key. Its in-browser "is this host authorized?" check is labelled advisory; the gate is what enforces. |
| **The Fixes screen** | Never opens a code-change request. That is a separate, off-by-default command-line capability requiring multi-party signed authorisation. |
| **The Manual** | Covers 13 topics, not all 29 screens (the uncovered ones are listed in the Manual entry earlier in this chapter). |
| **Credentials for a login-protected target** | The wizard has no field for a test account's username and password, and no screen offers one. A run launched from the interface therefore exercises the public, logged-out surface of an application. The engine contains the login-and-stay-logged-in machinery, and the typed commands accept a second identity for the "can user A read user B's data?" tests — but neither is reachable from a screen. |
| **Cloud and Kubernetes exploitation** | Built and gated, with no screen and no typed command of its own. Three of the six have been fired at something real, and the three are not of equal weight — the two Kubernetes ones against a real cluster the system stands up, owns and destroys itself, which is real infrastructure but the project's own; and the GitHub half of exposed-secret validity against the real GitHub service, the only one of the six to have judged material from a real outside system. The rest, including that capability's Amazon half, are proven offline with recorded sample evidence, with live fire against a real third-party cloud account still deferred. See the note below the table. |
| **Seven further capabilities** | The out-of-band relay, entitlement provisioning, target intake, importing another tool's results, social-engineering defence, the fuzzing engine and the request replayer all exist and none has a screen. Five have a typed command; two run only inside an engagement. Set out in full in §7.3. |
| **Build and release safeguards** | A property of the build pipeline, not a screen. There is no control for them anywhere in the interface, by design. |
| **The unified interface's reach** | Reachable only through `vigil up`. Of the three back-end programs, two serve pages of their own, and pointing a browser at either gets an older interface rather than this one. The third serves no pages at all. |
| **Screenshots** | **36 screenshots now exist on disk, and every one of the 29 screens has one** — the four that were missing (MCP Servers, System & Services, Proof of Posture, the Engagement Library) were taken in this round. The remaining six cover sub-tabs and the cloud setup view. The honest residue is age rather than absence: most were taken a fortnight ago, so the Chat and New Assessment pictures show those screens as they were before the changes described in §4.2 and §4.3. |
| **Starting the attack side from a screen** | Half built, and the missing half is the visible one. The switchboard that serves the interface now answers two addresses of its own — say which programs behind it are answering, and start the two attack-side ones — behind the same machine-only, address, session-key and anti-forgery checks as everything else, and with **no command, path or port travelling in the request** (§1.2). The browser-side indicator and its Start button are written but are **placed on no screen**: nothing displays them, they carry no styling, and the System & Services screen still tells the operator to start the attack side in a terminal. Neither half has an automated test. So the control exists in the code and is not reachable by a person today. |
| **The Tools screen's driver wording** | The per-tool verdict chip names the new, wider vocabulary correctly; the printed explanation and the signal markers beside it still name only the original two ways of driving a tool. Stale wording, not a wrong verdict. The complete per-tool statement is on the New Assessment tool picker. |
| **Attaching a file already on the machine** | A conversation can be handed material by upload or by naming an archive as its target. Naming a file *as an attachment*, without also starting a run, exists in the back end but is not exposed as a route or a control. |
| **What a single tool run can actually start** | The New Assessment tool picker lists this host's whole roster and says how each tool is driven, but of the thirteen tools installed here exactly **one** — the headless browser — can be started from that screen as a single tool. The other twelve are driven by the engine during an engagement. The screen states this itself, tool by tool and as a count. |
| **Gesture control, by camera or by phone** | Neither route produces movement. The local camera route is not functional (the hand-tracking model is absent); the phone-as-trackpad route is built and tested on the desktop side but has nothing sending it hand movement. Chapter 14 lists what each is waiting on. |
| **The telemetry collector** | Off by default. The Assurance screen says "collector not running" rather than showing zeros. |
| **Vulnerability-feed egress** | Off by default. Both the one-shot pull and the recurring pull are conscious opt-ins, gated by the emergency stop. |
| **Accessibility and browser support** | **Not assessed.** No accessibility standard is claimed, no audit has been carried out, and no supported-browser list is published anywhere in the software or its documentation. See the note below the table. |
| **Documentation drift** | Five internal reference documents are stale on the screen count, at two different wrong figures: the interface package's own read-me and the internal knowledge note still say twenty-one; the repository's front page, the exhaustive feature catalogue and the working note that tells a developer how to add a screen still say twenty-eight. Older programme records quote twenty-five and twenty-six, but those are dated accounts of the count on the day rather than claims about the software as it now stands. **The verified number, agreed by three independent lists that are checked against each other automatically, is 29.** |

**On the cloud row.** All six cloud and Kubernetes exploitation confirmations are complete and part
of the released software, and they are wired end to end. The two Kubernetes ones are proven against a
real single-node cluster the system creates, owns and destroys — dangerous binding confirmed and
re-verified offline, benign ones correctly left as leads — with cluster-wide enumeration and managed
provider control planes (EKS, GKE, AKS) explicitly outside what that run shows. The GitHub half of
exposed-secret validity is proven against the real GitHub service, with its Amazon Web Services half
built, unit-tested and never exercised against real Amazon infrastructure — nothing from the GitHub
run transfers to it. The remaining cloud ones are proven offline with recorded sample data standing in
for a live cloud account; what has not happened for them is live fire against a real third-party cloud
account, which waits on the customer supplying their own cloud credentials. There is no screen and no
typed command for any of the six; they reach the operator through the ordinary confirmed-finding path.
The full account, including why the remaining deferral is deliberate, is in §7.1.

**On the accessibility row, stated carefully.** The interface does carry some of the standard
markings that assistive software such as a screen reader relies on — labels on the theme switch, the
navigation region, the close button on the detail panel and the chat dock controls. There are twelve
such markings in the application code, on nine lines. There are no descriptive alternatives on
images, and no declared page landmarks beyond those twelve. That is a start, not a programme.
Nothing in the repository
claims conformance to a recognised accessibility standard, no audit has been performed, and no list
of supported browsers or minimum versions exists. A government buyer will normally require an
accessibility conformance statement; the honest position today is that one has not been produced.

**On the documentation-drift row, and how the count is enforced.** Three separate lists must agree:
the navigation list in the application code, the routing logic in the same file, and a
human-maintained screen map used by the voice assistant. An automated check fails the build if the
three sets diverge, applies a guard so that a duplicated or unreadable entry cannot silently vanish,
and requires at least one spoken synonym per screen. All three lists currently contain 29 entries;
this was independently counted during the writing of this chapter. The two stale documents both say
21, in five places between them. There is also a "22" in circulation, and it is worth separating: 22
is not a stale figure for the modern interface at all — it is the **correct** count of screens in the
older offence console described in §9. The two numbers refer to two different pieces of software.

---

## 9. The other ways into the system

The twenty-nine screens are one way in. The typed commands in §10 are a second. There are three
more human interfaces in the box that are not the product interface, and two **programmatic** ways in
— routes intended for another piece of software rather than a person. A reviewer inventorying what
can be talked to, and an integrator asking "can we drive this from our own systems", both need the
whole list, so here it is.

### 9.1 The three other human interfaces

These exist, are committed, and are served — but they are not the product interface. They are
described here for completeness so that a reviewer who encounters them is not surprised.

**The legacy CRUCIBLE Ops Console** — 22 screens, served on the internal offence port, grouped into
Operations (overview, live run, engagements, findings, attack graph, evidence, timeline, coverage),
Intelligence (reasoning brain, intelligence, planner, memory, kernel), Assurance (benchmark,
analysis, improve, intake) and Governance (authority & safety, defender, social defense, reports,
system status). It is an older design that builds its pages in a way incompatible with the strict
content-security policy the modern interface uses, which is why the modern policy is deliberately not
applied to it. *Inventoried from source; not exercised at runtime during the preparation of this
chapter.*

**The SIGIL cockpit's own page** — a single page with five panels, served on the internal sovereign
port:
an approval queue with approve/deny buttons; agent activity, budgets and ingest lag; a capabilities
panel with toggles; a live event stream where every row is chipped *anchored*, *tail* or *broken*;
and a detail overlay that, when a record is clicked, fetches it and shows an *integrity verified* or
*INTEGRITY BROKEN* chip along with the reason. *Inventoried from source; not exercised at runtime
during the preparation of this chapter.*

**One distinction matters here and chapter 14 settles it.** The word "legacy" applies to this *page*,
not to the program that serves it. The cockpit program is the sovereign half's live back end: `vigil
up` starts it first and refuses to continue if it does not come up, and the modern interface makes
sixteen calls into it — including the single owner-signed channel through which every owner-plane
change in the whole interface passes. So the accurate statement is that **the cockpit program is
current and load-bearing; its own five-panel page is a superseded front end that is still shipped and
still served.** Chapter 14, section 8.3, sets out the evidence.

**The Strix terminal interface** — a third-party, Apache-licensed agentic pentest tool that has been
vendored into the repository (that is, a copy of somebody else's software kept inside this one) and
is reachable as `vigil strix …`. It runs in the terminal rather than a browser and has five pop-up
screens (splash, help, stop agent, vulnerability detail, quit) and fifteen display renderers. It
requires Docker. *This is third-party code, not written by this project; inventoried from source and
not exercised at runtime during the preparation of this chapter.*

### 9.2 The two programmatic ways in

Neither of these is a screen, and neither is meant for a person. Both are ways for *another program*
to drive or read the system. They are listed here because a security reviewer asking "what can be
talked to?" and a buyer asking "can this plug into what we already run?" would otherwise not find
them.

**The gated on-machine service (the API daemon).** This is the third of the three back-end programs
named in §1.2 — the one described there as "the offence action plane", on the internal address
`127.0.0.1:8799`. It is worth being precise about when it is running, because the answer is not
"never unless asked":

- Starting the product with `vigil up` starts this service too, as one of the three back-end
  processes, and the switchboard forwards a specific family of addresses to it. It is therefore
  running during an ordinary session — but only ever reachable from this machine, and only through
  the switchboard.
- It can also be started **on its own**, without the interface, with `vigil crucible api`. That is
  the case that matters to an integrator: a program on the same machine can drive VIGIL without a
  browser being involved at all.
- It does not exist until one of those two things happens. Nothing starts it in the background.

It offers two kinds of route. The larger, safer half is **reading**: list the engagements, read one
engagement, read its authorisation, list runs, read a run's report, read its picture of the target,
read its evidence, read its intelligence, list the available capabilities, list what has been
imported. Those reads send no traffic anywhere and change nothing. The smaller half is **acting**:
invoke one capability, or import another tool's report. Every action goes through exactly the same
fail-closed permission chain as the same action performed by hand — an unauthorised one is refused,
and the capability never runs.

Its safety properties are worth stating plainly, because this is the most obvious thing a reviewer
would worry about:

- It **binds to this machine only** and refuses to start on any address reachable from elsewhere.
- It **serves no files at all**, so there is no way to trick it into handing over a file from the
  operator's disk.
- A submission from another website in another browser tab is refused, using the same checks the main
  interface uses: a custom marker header that a form on a hostile page physically cannot set, plus a
  strict check that the address the request claims to be for is the expected local one.
- The body of a request is size-limited and read strictly as data — never executed.
- The set of capabilities it will invoke is deliberately narrow: re-verification and import only. No
  tool that reaches out to a target is on it.
- Optionally, and off by default, a shared secret can be required on **every** request, read from a
  request header rather than the web address so it never lands in a log. This exists for the one case
  the machine-only binding does not cover: an operator who deliberately puts the service behind a
  proxy. The secret is stacked on top of the other protections and never replaces them.

**The MCP tool server.** This is the outward half of the screen described in §5.8: a channel over
which an external AI assistant can call two named, gated, read-only capabilities. It speaks over the
plain text channel between two programs on the same machine, so it opens no network port at all.
Unlike the service above, **it is not started by `vigil up`** — it does not exist until the operator
starts it deliberately with `vigil crucible mcp serve`. It has a screen showing what it exposes but,
as §8 records, no control to start or stop it.

### 9.3 What the screens themselves talk to

One more thing belongs here, because a reader asking about "the back end" will look for it and this
chapter is where the interface is described.

Every screen in this chapter is a **client**. It draws nothing from its own knowledge; it asks the
back end and displays the answer. There are **81 distinct addresses** it can ask — 76 on the offence
side and 5 on the sovereign (owner) side, counted by reading the interface code — and each one
corresponds to something in
this tour: the run list, one run's findings, its evidence, its coverage, its attack graph, the
compliance mapping, the drift comparison, the posture certificates, the tool inventory, the
capability catalogue, the chat conversations and the pieces of an upload, the terminal's dry-run
verdict, the defensive gateway's status, the approvals queue, the settings, and so on. (The
switchboard's own two addresses, described in §1.2, are not among them: no screen calls either.)

Two consequences follow, and both are load-bearing.

First, **the same information is available without the interface.** The screens are a convenience
over a back end that already exists; nothing is trapped inside the browser.

Second, **the addresses are not a way around the rules.** Every one of them sits behind the same
switchboard, on the same machine-only binding, behind the same two anti-forgery checks described in
§1.4; the ones that do anything rather than merely read go through the same permission gate as the
equivalent typed command. Reaching the back end directly instead of through a screen does not get an
operator — or an attacker — a single capability that the screen would not have had.

---

## 10. The command line — the same system, typed instead of clicked

Some operators prefer to type. More importantly, some tasks **can only** be done by typing, and that
is a security decision rather than an oversight.

### 10.1 The main command: `vigil`

There is one main command, `vigil`, with **26 native verbs**. Here is the complete list, with what
each is for in plain terms.

| Verb | What it does |
|---|---|
| `engage <url>` | Run an assessment against an authorised target. Scope is given as literal host names or `*.wildcard` patterns — **address ranges are refused**, and the help text calls a wildcard "a deliberate BROAD grant". |
| `engage-instruct` | Add a plain-language instruction to a run that is already in progress. Advisory — anything it prompts still waits for approval. |
| `ledger who\|when` | Query the who/when/what usage record. |
| `verify-ledger` | Check that the usage record is intact. |
| `verify` | Check the signed record segments, segment by segment, aware of which owner they are tied to. |
| `provision` | Mint and sign an authority for a *this-machine* engagement. |
| `identity` | Export the system's public keys so an owner can delegate to them. |
| `patch` | Run the gated auto-patch ladder over a confirmed finding. The finding must come from a signed envelope or the signed record — **a raw file is never accepted**. Editing happens in a disposable copy. Opening a code-change request is off by default and needs a signed authorisation, a pinned trust root, a mandatory signer and a single-use record. |
| `remediate --prove` | Run the four-state live remediation proof over a finding whose provenance is established. The `--prove` flag is mandatory; there is no other mode. |
| `reprove` | Run that re-proof continuously, on a loop. |
| `witness` | Run the co-signing witness service. |
| `provision-destruction` | Mint the multi-party keys required for opening real code-change requests. Prints the keys once. |
| `authorize-destruction` | Sign one destructive action, producing a single-use authorisation. |
| `approve` | List pending per-action approvals and sign one with the owner key. |
| `proof-export` | Assemble a client-verifiable proof package from a run's proven findings. |
| `dossier` | Compile everything a run produced into one self-contained, tamper-evident archive. Can package a whole session. |
| `detect` | Run the defensive detection logic over log files. |
| `up` | Bring the whole interface up at one address. |
| `down` | Stop it again. |
| `services` | Create, inspect, stop or re-render the supporting container services. Idempotent. |
| `doctor` | A read-only readiness report — programs, environments, writable directories, ports, services. Exits non-zero if a hard prerequisite is missing. |
| `telemetry` | Run the live assurance collector over the signed record. |
| `knowledge` | Operator-gated sync of the knowledge folder to version control. **Pushing to a remote is a separate act.** |
| `learn-drain` | Move learning grants from the sovereign side to the offence side. |
| `terminal` | Run one governed local read/inspect command through the gate. Classified as tier A2, which **queues for approval and never runs automatically**; `--approve` runs it. Allow-listed programs only — no network, no writers, no interpreters. |
| `sandbox` | Run an arbitrary command inside a sandbox that is cut off from the network and confined to one workspace folder. Classified as tier A3 — again, queues; `--approve` runs it. It needs a separate sandboxing program to be installed on the machine (the one it uses is called `bwrap`, short for "bubblewrap"); without it the command refuses to run rather than running unconfined. |

In addition, five **passthrough** verbs hand off to the specialised consoles. Each one runs in its own
isolated software environment, so a single running program never loads both trust domains at once:

| Passthrough | Goes to | Environment |
|---|---|---|
| `vigil sigil …` | The sovereign console (38 verbs) | sovereign |
| `vigil crucible …` | The offence arsenal (31 subcommands) | offence |
| `vigil aegis …` | The defensive tool (3 subcommands: detect, gateway, demo) | offence |
| `vigil strix …` | The third-party agent | offence |
| `vigil gateway …` | The host network gate (6 subcommands) | offence |

### 10.2 What is behind the passthrough verbs

The table above says "31 subcommands" and "38 verbs" and then moves on. That is not good enough for a
reader who has been told this is a complete tour, because several capabilities in this system are
reachable *only* through one of those subcommands. So all **78** of them are set out below in four
tables, with what each is for in plain terms. A reader who does not intend to type anything can skip
to §10.3; nobody needs to memorise this. It is here so that no capability in the system is
undocumented, and so that a reviewer can see there is no unlisted back door.

Here is the offence arsenal first — the 31 subcommands behind `vigil crucible …`.

| Subcommand | What it is for |
|---|---|
| `engage` | Run a full reasoning-driven assessment against an authorised target. |
| `scan` | Run a self-contained web scan against this machine — crawl, passive observation, active checks. |
| `intake` | Turn a web address into a prepared engagement folder with draft authorisation, threat model and attack tree (§7.3). |
| `authority` | Manage the scoped, time-limited engagement authority and the emergency stop. |
| `entitlement` | Show and check the signed permission slips that unlock the dangerous capabilities (§7.3). |
| `capabilities` | List the whole catalogue of capabilities the system holds, read-only. |
| `verify` | Re-run a finding's retained proof offline and report whether it still holds. |
| `drift` | Compare the proven findings of two runs, to show what is new and what is fixed. |
| `plan-integrity` | Check a signed statement that the plan actually carried out matches the plan that was approved. |
| `attack-paths` | Work out the shortest routes an attacker could take, and which single points would sever the most of them. |
| `evidence` | Manage the signed, hash-linked evidence certificates: create signing keys, sign, check. |
| `report` | Assemble the executive, technical and remediation reports from proven findings only. |
| `plan` | Produce a read-only projection of what a plan would do. Sends no traffic, drives no tools. |
| `intel` | Reason over collected intelligence about a target. Offline unless deliberately told otherwise. |
| `imports` | Ingest another security tool's report as leads (§7.3). |
| `memory` | Query the store of past engagements, findings, dead ends and learned rates. |
| `knowledge` | Propose, study and retrieve vulnerability knowledge. Advisory only. |
| `kernel` | The reasoning layer that turns the written doctrine into callable steps. |
| `benchmark` | Run the planted-bug test corpus and score the result (§5.7). |
| `eval` | Score a run against a known-answer corpus. |
| `calibration` | Report how well the system's stated confidence has matched reality. It re-scores displayed confidence only; it never promotes a lead to a fact. |
| `improve` | Mine gaps and draft reviewable improvement proposals. Drafts only. |
| `analysis` | Deep static analysis of source code and symbol indexing. |
| `defender` | Model what a given action would look like in defensive logs, and which detections would fire. |
| `socialdefense` | Score inbound content for social-engineering indicators (§7.3). |
| `aegis` | The defensive counterpart: run detections over the operator's own logs, or the protective gateway. |
| `collaborator` | Run the operator-hosted out-of-band relay (§7.3). |
| `console` | Start the older read-only offence console described in §9.1. |
| `api` | Start the gated on-machine service described in §9.2. |
| `mcp` | Start, or list the contents of, the external-AI tool server described in §5.8 and §9.2. |
| `status` | One-shot summary: which reasoning back ends are reachable, which paths resolve, and — importantly — whether capability enforcement is switched on or the deployment is running ungoverned. |

#### The owner's side — the 38 verbs behind `vigil sigil …`

This is the sovereign console: the half of the system that holds the owner's signing key, keeps the
signed record, and decides what any agent is allowed to do. A reader who only ever uses the screens
will not need these; a reader responsible for custody of the keys will need most of them.

| Verb | What it is for |
|---|---|
| `doctor` | Self-check the installation: is the home directory present, is the permission kernel there, is the search index reachable, is the key store working. |
| `status` | A one-line health summary of the owner's side. |
| `dashboard` | A read-only operator view over the signed record. |
| `verify` | Re-check the signed record end to end. |
| `sign` | Re-sign the current head of the signed record. |
| `audit` | Self-audit: what the agents did, and why, read back out of the log. |
| `budget` | How much each agent spent in a day — actions, interruptions, words and money. |
| `approve` | Approve one queued proposal, by its sequence number, with the owner's key. |
| `deny` | Refuse one queued proposal the same way. |
| `warden` | The governor: engage or release the emergency stop, promote or revoke an agent's standing permission, or show the current state. |
| `capability` | Turn gesture, voice or automatic learning on or off. Each change is a signed, latched decision. |
| `gesture-nav` | Turn the gesture navigation mode on or off, and show its state. |
| `delegate-offense` | The owner signs a time-limited delegation to the attack side, tied to one engagement. |
| `owner-pubkey` | Print the owner's public key, so another part of the system can pin it. |
| `mesh` | Authorise, revoke or list the phone device keys that may act as a companion. |
| `host` | Report what this machine is capable of, for the companion mesh. |
| `bridge` | Run the encrypted phone link. Binds only to loopback or a private tunnel address. |
| `serve` | Start the older single-page cockpit described in §9.1. |
| `voice` | Run the speech pipeline, from a recorded file or a live microphone. |
| `agents` | Run one of the owner-side agents by name — the daily brief, triage, the watcher, research, background coding, own-infrastructure checks, or perception. |
| `scrape` | Grounded web research that stays inside a declared list of allowed sites and respects each site's published crawling rules. |
| `ingest` | Load new material into the memory: transcripts, curated notes, code history. |
| `index` | Rebuild the search index over that memory. |
| `search` | Search the memory. |
| `graph` | Query the relationship map of projects, sessions, commits and documents; or report its health. |
| `consolidate` | Fold raw recent history into durable memory. Runs offline by default; a reasoning model is opt-in. |
| `knowledge` | Export the learning permissions the owner has approved, so the attack side can pick them up. |
| `inbound` | Drain the one-way tray of inert findings coming from the attack side onto the signed record. There is no network endpoint; it reads a directory. |
| `spine` | Housekeeping on the signed record: migrate, rotate, compact, convert, report status, plan a prune, or check an archive. |
| `checkpoint` | Emit, verify, or have an outside witness counter-sign a checkpoint of the record, so it cannot be quietly rewound. |
| `floor` | The durable anti-rollback marker: show it, or deliberately re-seed it downward. |
| `warden-anchor-set` | Record the permission kernel's signed statement of where the record head is. |
| `warden-anchor-get` | Read that statement back. |
| `vault` | The at-rest sealing of the trust root in hardware, where hardware sealing is available: show status, or provision it. |
| `kernel` | Pin the permission kernel program to an exact verified copy, so a swapped binary is detected. |
| `backup` | Make a portable, passphrase-encrypted copy of the trust root and the signed record, for storage off the machine. |
| `restore` | Restore such a backup onto a fresh installation. It verifies before it writes anything. |
| `settings` | Show the settings with secrets hidden, export the runtime environment for the launcher, or live-check one named secret. |

#### The defensive tool — the 3 subcommands behind `vigil aegis …`

| Subcommand | What it is for |
|---|---|
| `detect` | Run the defensive detections over one bundle of the operator's own telemetry. |
| `gateway` | Run the protective reverse proxy in front of the operator's application — the same thing the Defense screen starts. |
| `demo` | Run one detection flow end to end as a demonstration. |

#### The host network gate — the 6 subcommands behind `vigil gateway …`

These are all concerned with confining what the machine itself may reach. They are infrastructure
controls, not testing controls.

| Subcommand | What it is for |
|---|---|
| `serve-proxy` | Run the filtering forward proxy that all outbound traffic is meant to pass through. |
| `render-firewall` | Print the firewall rules it wants, without applying them. |
| `check-firewall` | Ask the operating system to validate those rules, without applying them. |
| `apply-firewall` | Apply them. This needs administrator rights and is the only one of the six that changes the machine. |
| `render-compose` | Print the container arrangement for the same topology. |
| `ensure-networks` | Create the two container networks — one confined, one permitted to reach out. |

### 10.3 Which to use for what

| Task | Best done | Why |
|---|---|---|
| Starting an assessment | **Screen** | The wizard collects authorisation, scope and depth in a guided way and shows a running summary of what will happen. |
| Watching a run unfold | **Screen** | The live reasoning graph and event timeline have no useful text equivalent. |
| Reading findings and evidence | **Screen** | The detail drawer, the attack graph and the coverage view are visual by nature. |
| Approving or denying a decision | **Either** | The Approvals screen for speed; the command line when the signing key is held on a different machine. |
| **Signing an offence-side queued action** | **Command line only** | The web console holds no key and has no route to sign. This is deliberate. |
| **Authorising a destructive action (opening a real code-change request)** | **Command line only** | Requires multiple independent signatures and a single-use record. The Governance screen shows the state but cannot act. |
| **Minting a charter for a remote target** | **Command line only, on a trusted host** | The web interface can provision a this-machine authority only. |
| **Starting the MCP server for an external AI client** | **Command line only** | No toggle exists in the interface. |
| **Pushing the knowledge folder to a remote repository** | **Command line only** | The screen commits locally; pushing is a separate deliberate act. |
| **Supplying a test account's login for an authenticated scan** | **Command line, and only for one family of tests** | No screen has a field for it. The typed commands accept a second identity for the "can user A read user B's data?" tests, and nothing more. The general login-and-stay-logged-in machinery exists inside the engine but is not exposed by any screen or any option. |
| Checking readiness before a session | **Either** | `vigil doctor` and the System & Services screen show the same report. |
| **Starting the system, or restarting the offence side after it has stopped** | **Command line** | `vigil up` brings the whole thing up. The launcher's own switchboard will also restart the offence side on request — a fixed, named action whose command comes from the launcher's own configuration and never from the request — but no screen offers that control today, so in practice this is still a terminal act (§8). |
| **Working on one job at a time** | **Screen** | The job chip and the Engagement Library scope every screen to one job and widen back again. There is no typed equivalent, and none is needed: scoping is presentation and changes nothing the commands act on. |
| **Asking a question about a codebase nobody has scanned yet** | **Screen** | Only the Chat screen takes an upload. The answer is a lead; the typed commands are what turn it into a fact. |
| Re-checking a proof someone sent you | **Screen** | The Replay Proof screen takes a pasted report and needs nothing else. |
| Automating anything on a schedule | **Command line** | Every verb is scriptable; screens are not. |
| **Driving the system from another piece of software** | **The gated on-machine service** | It runs already under `vigil up`, and can be started on its own with `vigil crucible api`. It gives a program the same reads and the same gated actions, on this machine only. See §9.2. |
| **Letting an external AI assistant call a capability** | **The MCP tool server** | Start it with `vigil crucible mcp serve`. Two read-only capabilities, gated on every call. See §5.8 and §9.2. |
| **Feeding another security tool's report in** | **Command line, or the on-machine service** | `vigil crucible imports`, or the service's import route. It arrives as leads, never as facts. See §7.3. |
| Running on a machine with no display | **Command line** | There is no browser to open. The typed commands cover the whole engagement from authorisation to dossier; a few conveniences exist only as screens (the chat, the session manager, the tool installer) and have no typed equivalent. |

The pattern behind that table is worth naming, because it is the design and not an accident: **every
irreversible or authority-granting act is command-line only.** The screen can start work, watch work,
read results, and ask for permission. It cannot grant itself permission, cannot sign, and cannot
destroy.

---

## 11. What a first session actually looks like

To make the tour concrete, here is a plausible first hour, using only actions verified above.

1. The operator runs `vigil doctor` in a terminal, or opens **System & Services** after starting up,
   and fixes anything marked ACTION NEEDED — a missing program, an unbuilt environment, an occupied
   port.
2. They run `vigil up` and open the printed address in a browser. They land on **Home**.
3. They go to **API Keys** and seal whichever AI provider key they intend to use, then press **Test**
   and confirm the health chip reads *Working*.
4. They go to **Tools** and check that the required tools show *installed* rather than *missing* or
   *shadowed*, using the two-step consent install for anything absent.
5. They go to **Charter & Attestation** and press **Provision (loopback only)** to mint a
   this-machine authority. If they intend to test a remote system, they instead copy the printed
   ceremony command and run it on the machine that holds the owner key.
6. They press **New Assessment** and walk the five steps — choose *Scan a website / API*, enter the
   address, tick the authorisation declaration, set the scope, choose a depth, and read the line
   telling them whether this kind of run uses a model at all — and press **Launch assessment**.
7. They land on **Live** and watch the reasoning graph fill in. The job chip in the top bar now names
   the job they just started, and every screen from here on shows that job and nothing else. When the
   safety button changes to "N waiting for you", they approve or deny in place.
8. When the run finishes they open **Findings**, read the confirmed items, and press **Re-verify this
   run (offline)** to watch the system re-check its own conclusions with no traffic sent.
9. They open **Coverage** and read the blind-spot legend, so they know what was *not* examined.
10. They open **Report** and press **Download dossier**, producing a single archive they can hand to
    a third party.
11. That third party, on a different machine with no VIGIL installed, opens **Replay Proof** on their
    own copy — or runs the offline verification command printed on the **Proof of Posture** and
    **Trust Center** screens — and checks the work independently.

Step 11 is the step everything before it exists to make possible: a result the customer can check
for themselves, on their own machine, without taking our word for anything.

Three things a first-hour operator should know that this sequence does not show. If the application
being tested sits behind a login, the wizard has nowhere to put a test account, so the run will
cover the logged-out surface only (§4.2). If the target is somewhere other than this machine,
certain findings that depend on the target calling out to a listener need that listener to be
running and named in the signed authorisation first (§7.3). And there is a shorter, looser first
half-hour than this one: drop a codebase into **Chat** and ask what looks wrong. That answer is a
lead, it says how many files it read, and the button underneath it starts exactly the run described
in step 6 over the same files (§4.3).

---

## 12. Summary of verified counts

Two tables. The first holds the numbers that mean something to a reader deciding whether to buy or
deploy this system — each one answers a question somebody actually asks. The second holds the
inventory counts, which are here so a technical reviewer can check the chapter against the software,
and which a general reader can ignore entirely.

**The numbers that carry meaning.**

| Question a reader asks | The answer |
|---|---|
| How many screens is an operator learning? | **29** — and the number is not a guess: three separate lists inside the software must agree, and an automatic check fails the build if they do not. |
| How many of those can change anything only with the owner's key? | **4** — Approvals & Safety, Charter & Attestation, API Keys, Settings. |
| How many controls look functional but are not? | **1** — the command palette, which shows a "on the roadmap" message. Everything else on every screen does what it appears to do. A second control, the one that would start the offence side, is written in the interface's code but placed on no screen, so it is invisible rather than misleading (§8). |
| Which screens show only the job being worked on? | **9 of 29** — Live, Activity, Findings, Fixes, Proof Studio, Report, Compliance, Assurance and two tabs of Brain. Scoping hides rows and deletes nothing, and every scoped screen offers the way back to all engagements. |
| Of this host's security tools, how many can be started as a single tool from a screen? | **1 of 13** — the headless browser. The other twelve are driven by the engine during an engagement, and the picker says so for each one rather than hiding them. |
| How much of what the system can do has no screen at all? | **7 further capabilities** (§7.3) plus the **6 cloud and Kubernetes confirmations** (§7.1). Of those thirteen, **0** have a screen; five have a typed command; the rest run inside an engagement or reach the operator as an ordinary confirmed finding. |
| What can an outside AI assistant do through this system? | **2 read-only capabilities by default**, and the operator can widen that list deliberately. Anything not on the list is refused. |
| What can another piece of software drive? | **2 programmatic ways in**, both off until started, both on this machine only: the gated on-machine service and the tool server for an external AI (§9.2). |
| What can the owner's side be asked to do at all? | **25 kinds of action.** Anything else is refused outright, not merely denied. |
| Has the interface been assessed for accessibility? | **No.** Twelve assistive-software markings exist in the code; no standard is claimed and no audit has been done. |
| How much of the software is documented for the operator inside the product? | **13 manual sections**, covering thirteen topics rather than all twenty-nine screens. |

**Inventory counts, for a reviewer checking this chapter against the software.**

| Thing | Count |
|---|---|
| Web interfaces in the repository | 3, plus 1 terminal interface copied in from a third party |
| Sub-tabs inside screens | 11 (5 in Findings, 6 in Brain) |
| Distinct back-end addresses the screens call | 81 — 76 on the offence side, 5 on the owner's side. Two further addresses are answered by the launcher's own switchboard rather than by a back end (plane status, and starting the offence side); no screen calls either today. |
| Screens in the older offence console | 22 |
| Panels in the older owner-side cockpit | 5 |
| Screenshots on disk | 36 — one for each of the 29 screens, plus 7 sub-views |
| Tools in this host's roster | 13, all installed; 24 more inside the third-party agent's container image, listed for reference and not installed here |
| Ways of driving a tool the admission gate recognises | 4 named surfaces — its own command line (a playbook or a typed builder), a gated sensor, the source-analysis pass, the headless browser — up from 2 |
| `vigil` native command verbs | 26, plus 5 that hand off to another console |
| Subcommands behind those 5 | 78 in total — 31 offence, 38 owner-side, 3 defensive, 6 network gate. All are listed in §10.2. |

Every number in both tables was read out of the source code during the writing of this chapter.

---

## 13. The single idea behind all twenty-nine screens

If a reader remembers one thing from this chapter, it should be this. Every screen in this system
does one of exactly three things: it **shows evidence**, it **requests a signature**, or it
**refuses**. None of them asserts.

The interface can start work, watch work, read results, package results for a third party, and ask
the owner for permission. It cannot grant itself permission — the authorisation is signed outside
it. It cannot sign — the key never enters the browser. It cannot call something proven — only a
fixed, deterministic, non-AI checker can do that, and every screen that displays a result displays
which checker did so.

That is why the honest gaps in this chapter — a placeholder button, a manual that covers thirteen
topics rather than twenty-nine, a control for starting the offence side that is written but placed on
no screen, screenshots that are complete but in places older than the screens they show, no field for
a test account's login, no accessibility audit, seven working capabilities with no page of their own,
and cloud capabilities that are built and proven but not yet fired at a live third-party account —
can be listed openly. They are gaps in convenience and in coverage of the field record. None of them
changes what the system is willing to call proven.

The newest surface in the product is the clearest illustration of that last sentence. An operator can
now drop a customer's codebase into a conversation and ask what is wrong with it, and get a reasoned
answer in seconds. That answer is marked a lead on its face, states how many files it read and how
many it did not, and carries a button to the gated scan that walks the rest — because the difference
between an opinion and a fact is the only thing this product actually sells.
