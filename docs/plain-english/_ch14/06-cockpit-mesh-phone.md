## 8. The cockpit and the status overlay

### 8.1 What this is, and why it matters

The sovereign side has its own small web program — the system calls it the **cockpit** — serving two
things: a read view of the permanent record, and one narrow channel through which the owner can
change something. Its most important property comes before any mechanism. **Every item shown on
screen can be clicked, and clicking it re-checks that item's integrity there and then rather than
repeating what was cached.** The reply carries either a verified marker or the specific reason the
check failed. Ask for a record that does not exist and the reply says so in words — *"no grounded
record — not fabricated"* — rather than showing an empty screen a reader might mistake for an answer.

### 8.2 How the cockpit protects itself

Four properties, all enforced in the program rather than in a configuration file a deployment could
get wrong:

| Property | What it means in plain words |
|---|---|
| **It refuses a public address** | The program will not start on an address reachable from the wider internet, or on the catch-all "listen everywhere" address. To serve a real domain name an operator puts a separate front door in front of a private address: the tunnel or proxy is the network boundary, never the listener. |
| **A session pass-phrase printed to the terminal** | Generated at start-up, so only somebody at the machine can pick it up. The served page carries it; a page belonging to any other website cannot read it. |
| **Reading and acting are separate planes** | Reading needs the pass-phrase. Acting needs the pass-phrase **and** an exactly-matching record of which page the request came from **and** an approved address in the request header — the combination that defeats a hostile website re-pointing a name at a private address. |
| **The signing key never enters the browser** | The browser sends a request; the *server* signs. A stolen browser session cannot walk away with the ability to sign. |

One smaller detail shows the same instinct: the "ask a question" route is a *read* that starts a real
reasoning process, so it carries the full action gate.

### 8.3 A contradiction in this briefing, resolved

Chapter 9 of this briefing calls this cockpit **legacy** — "an older design", "a single page with
five panels". The sovereign side's own documentation calls it the **current** interface, its "glass
cockpit". Both sit in the repository at once, and a document whose value is checkability cannot leave
that standing.

**Two different things share the name:** the cockpit *program*, and the cockpit's own *page*. Three
pieces of evidence settle which is which.

1. **Starting the whole product starts this program first, and the product refuses to run without
   it.** The launcher brings up three back-end programs; the cockpit is the first, and if it does not
   come up and announce its session pass-phrase the launcher prints an error and stops.
2. **The modern unified interface is a client of this program.** It makes sixteen calls to
   sovereign-plane addresses, every one served here: the summary read that fills the dashboards, the
   settings read, the **single** owner-signed channel through which every owner-plane change in the
   whole interface passes, the governance event stream, and the status-overlay stream below. Remove
   this program and the modern interface loses its entire sovereign half.
3. **The five-panel page does still exist and is still served** at the program's own root address —
   approval queue, agent activity and budgets, a capability panel, a live event feed, a detail
   overlay.

The precise statement is therefore: **the sovereign cockpit is the current and load-bearing back end
of the modern interface; its own five-panel page is a superseded front end that is still shipped and
still served.** Chapter 9's "legacy" is right about the page and wrong about the program; the
sovereign documentation is right about the program and overstates the page.

### 8.4 The status overlay, and why it is a cross-plane channel

The **overlay** is a small card in the corner of the unified interface showing what the sovereign
assistant is doing right now — listening, thinking, speaking — with the line it heard or is saying.
It can be minimised to a dot or dismissed; a new interaction brings a dismissed card back.

Described that way it sounds like decoration. It is not: it is **the one live channel that crosses
from the sovereign side to the unified interface**, and it carries two kinds of traffic from two
different places. **Navigation signals** come from the signed permanent record — when the owner says
"go to findings" or makes a navigating gesture, the sovereign side appends a signal, the cockpit
tails the record and passes it on, and the interface changes screen. Nothing is typed and no program
is launched; the signal is a request to the owner's own browser, and that is its entire power.
**State events** — the listening/thinking/speaking updates — come from a small scrap file.

The navigation half is deliberately hemmed in. **The interface will navigate only to a screen that
exists in its own navigation list**, and the membership test is built on a lookup object created with
no inherited properties at all — so a signal naming one of the internal property names every ordinary
object carries cannot come back "true" and steer the browser somewhere it should not go. A garbled or
spoofed signal navigates nowhere.

### 8.5 Why fast-changing state goes to a scrap file and not the record

This design point generalises far beyond an overlay. The speech state machine changes state many
times in a single exchange, and the gesture layer moves the pointer about **thirty times a second**.
Written to the signed, append-only history, either would render it useless — the code says so in as
many words: thirty-per-second records "would swamp the append-only log". A reviewer months later
would be scrolling past hundreds of thousands of cursor positions looking for the three decisions
that mattered. So the system draws a hard line between **telemetry** and **audit**:

| | Telemetry | Audit |
|---|---|---|
| **What it is** | What is happening right now | What was decided, and by whom |
| **Where it goes** | A small file readable only by the owner's own account, replaced whole each time so a reader never sees a half-written state | The signed, hash-linked, append-only record |
| **What survives** | Only the latest value — nothing is history | Everything, permanently, in order |
| **If writing fails** | Swallowed on purpose, so telemetry can never break what it reports on | A failed append is a real failure |

The code is blunt about that file's status: *"The file is ephemeral state, not a record of truth."*

The consequence for an auditor is the thing to hold on to. **The permanent record contains what was
decided, not what was displayed.** A ten-minute spoken conversation adds a handful of entries, not
tens of thousands. The same split governs gestures: arming, disarming and discrete actions are
recorded; per-frame pointer movement is not.

### 8.6 What is honest about this today

The channel is built, wired at both ends and tested; the cockpit's tests and the status-file tests
were run on this machine during the preparation of this section and passed. Its two **producers**
belong to this chapter's earlier sections: the listening/thinking/speaking events exist only while a
live speech loop is running, which needs a microphone; the navigation signals come from speech or a
gesture session, on-box camera gesture being inert here for want of a model file. **Neither producer
has been run against live hardware on this machine.**

---

## 10. The mesh, and the phone

### 10.1 The plain-English version

**An authorised official can approve a live action from their phone, and the owner's master key never
leaves the desktop.**

Every mechanism below exists to make that sentence literally true rather than approximately true. A
phone gets lost, stolen, sold and handed to a repair shop; a design that puts the master key on it —
even encrypted, even behind a fingerprint — has made the phone into the crown jewels. This one does
not. And one correction before the mechanism, because the natural phrase is the wrong one: **the
phone does not "control" the desktop.** It *signs requests, and the desktop verifies them*. That is
not pedantry — everything the phone is not allowed to do follows from it.

### 10.2 What the phone holds

The phone holds exactly one secret: **its own key**, and nothing else. That key is created in the
phone's own browser the first time the companion app is opened, in a mode that tells the browser to
use it for signing but never to hand it back — not to a website, not to the companion app itself, not
to anything. The phone then displays its public half plus a short human-readable fingerprint; the
owner, at the desktop, compares that fingerprint against what the desktop computes and authorises the
device once, as an entry in a signed ledger on the permanent record. The desktop's own master key
stays on the desktop. In the code's words: *"the phone signs, the server only verifies."*

The companion app is a normal installable web app served by the desktop. It needs a browser whose
built-in cryptography supports the signature scheme in use — recent versions of the major browsers —
and if it does not find it, **the app says so plainly and refuses to operate** rather than dropping
to something weaker. That is a real deployment constraint, written down as one.

### 10.3 There is no password on the wire

A security reviewer should look here first. **There is no shared secret travelling between the phone
and the desktop at all** — no password, no bearer token, nothing that could be captured in transit
and reused. **Authentication *is* the signature.** Every request the phone makes carries a small
signed envelope, and the desktop rebuilds, byte for byte, exactly what the phone claims to have
signed. Because the two sides are written in different programming languages, the rule for producing
those bytes is a formal agreement between them with a fixed worked example pinned in the tests — get
it wrong by one character and every signature is rejected, which is the right failure direction.

Seven properties then bound what a captured request can do:

| Property | What it protects against |
|---|---|
| **The authorised-device list is recomputed on every single request** | A revoked phone stops working on its *next* request. Revocation is immediate by construction, not by a timer. |
| **The signed request names the one thing it authorises, checked against the door it arrived at** | A captured request for the low-sensitivity queue listing cannot be re-aimed at the route returning the owner's own recorded on-screen text. A lesser permission cannot be pointed at a greater one. |
| **Each request carries a timestamp, checked against a two-minute window** | A captured request goes stale. |
| **Requests that *change* something also carry a counter that must beat the highest ever recorded for that phone — checked and recorded together, under a lock** | The same captured request can never be replayed, not even by two copies racing at the same instant. |
| **The listener refuses any publicly reachable address** | A misconfiguration cannot expose the service, because it will not start. The private tunnel is the boundary. |
| **The check for modern internet addresses is a positive list, not a "not public" test** | Two globally routable transition ranges are misclassified as private by the standard library the code would otherwise have trusted. |
| **The transport certificate is self-signed, its fingerprint printed once and stable across restarts** | The owner compares it once, on the phone. A change later means interception, not a restart. |

One honest limit sits inside that list. Requests that only *read* are bound by the freshness window
and by their permission scope, but they consume no counter — a read changes nothing, and recording
every one would write to the permanent history on every screen refresh. So a captured read request
could in principle be replayed **within two minutes, by someone already inside the private tunnel, to
re-read the same thing.** That is the stated bound, not an accident.

### 10.4 What crosses the tunnel, and what does not

The notification feed and the pending-items list carry **three fields and no more**: a sequence
number, a consequence level, and a kind. The code's own summary is *"never a subject, never a
payload, never a secret."*

So the phone learns that item 412 is awaiting approval, at the higher of the two supervised levels,
and is a draft message. **It does not learn who the message is to, or what it says.** Approving from
a phone is approving a *numbered item*. That is a deliberate confidentiality choice and equally a
usability limit — an approver working from a phone is confirming a decision they already understand,
not reading a case for the first time.

One route is different, and the code flags it as different: the "where did I last see this?" recall
route does return content, the owner's own verbatim recorded on-screen text. Precisely because it
reveals more, it is bound to its own separate permission a lesser request cannot reach.

### 10.5 What the phone can do, and what it cannot

| The phone **can** | Notes |
|---|---|
| Approve or deny a queued item at the two supervised levels | The phone signs; the desktop verifies and only then records. Approvals can be signed **with no connection at all** and queued, flushing when the tunnel returns. |
| **Panic-halt** the whole agent mesh | Signed like every other request from the phone — the desktop still checks the phone's key, the freshness window and the replay counter before it acts, and a failure at any of those halts nothing. What needs no signature is the halt *entry once it is on the record*: see below. |
| Relay a typed command to the reasoning kernel | Through the same classification gate and signed action log as a command typed at the desktop or spoken aloud. |
| Browse a read-only view | Queue, summary, budgets, recent agent activity, one record at a time, memory-graph health. |
| Recall grounded on-screen history | Verbatim captured text, never a paraphrase or a model's guess. |
| Arm a gesture session and act as a remote trackpad | Opt-in, off by default. |

| The phone **cannot** | Why |
|---|---|
| **Release a halt** | Halting is the safe direction, so the check that folds up the record honours *any* halt entry it finds there, whoever wrote it — a nuisance halt is at worst an inconvenience. Un-halting is the dangerous direction: a release counts only if it verifies against the owner's own key and its issue time exceeds every release already honoured, and it stays with the owner at the desktop. The switch is deliberately asymmetric. The asymmetry is in how the *record* is read, not in how the phone's door is guarded — the door checks a signature either way. |
| **Sign as the owner** | The master key is never used on this path at all. |
| **Widen a gesture's authority** | Pointer movement, clicking, scrolling and dragging stay at the reversible level; typing, key combinations and launching an application always queue for a separate approval. A gesture, from a phone or a camera, can never type a password or start a program. |
| **See anything sensitive on the feed** | Three fields only. |
| **Upload the owner's pixels** | See below. |
| **Outlive a revocation** | A revoked phone's *in-flight* gesture session dies within about one or two frames of video, not when its time limit expires. |

### 10.6 The trackpad, and the pixels that never leave the phone

Using a phone as a trackpad is the one place the design could easily have leaked something serious — a
camera feed of the owner's room, streamed to a desktop. It does not.

**The phone runs its own hand detection, on the phone, and sends only the result.** What crosses the
tunnel is a small batch of landmark coordinates — at most two hands, exactly twenty-one points each —
described in the code as *"landmark data, never owner pixels"*. Because the phone already did the
recognition, the desktop's declaration that this source sends nothing off the machine is honest
rather than aspirational, and the strict gate refusing any vision component that would upload imagery
lets this one through for a real reason. A malformed batch decodes to an honest *nothing* rather than
a fabricated hand, and batches from another session, duplicated, out of order or stale are dropped.

Arming such a session shows the pattern the whole design uses. **The phone signs an arm request. The
desktop only *records* it.** The gesture daemon then re-verifies everything independently — device
still authorised, request fresh within thirty seconds, never used before, no other session live, halt
switch not engaged — and it is that re-verification, not the request's arrival over the network, that
arms anything. A phone-armed session also gets a deliberately **shorter life than one armed at the
desktop**: five minutes against thirty. This remote-arm path widens trust, and is off by default.

### 10.7 What is proven here, and what has not been done here

**Proven on this machine.** Ninety-five automated tests — the phone bridge, the signed envelope, the
companion app, the transport certificate, remote recall, device pairing, the remote landmark stream,
the status file and the cockpit — were run during the preparation of this section and all passed.

**Demonstrated end to end on this machine.** There is a runnable demonstration that needs **no phone
and no tunnel**: it stands up the real bridge program on the machine's own internal address and
drives it exactly as a phone would, with a stand-in phone key signing every request. It was run to
completion here and walked the whole flow — pair, approve a queued action, relay a command, recall
on-screen history, arm a gesture session, panic-halt — with the real transport, the real signature
checks and every real gate. Only the tunnel and the phone app are stood in for; everything else is
the shipped code.

**Not done here.** No phone has ever been paired with this machine: the device ledger on its
permanent record contains no entry, and no transport certificate has ever been minted — which means
**the phone bridge has never been served for real on this host**. Read the phone story as *proven in
code and in a faithful loopback rehearsal, and not yet demonstrated on a real device here*.

---

## 11. What is proven on one platform, and what is a seam

### 11.1 The sentence, without euphemism

The sovereign side's own documentation ends with this: the other operating-system backends and the
browser-based web engine "are honest, documented seams (Linux is the proven path)." That is
procurement-relevant, so it is repeated without softening. **Linux is the proven path; everything
else in this part of the system is an interface with a deliberately incomplete implementation behind
it.** A seam is neither a bug nor vapour — it is a place where the shape of the work is defined, the
surrounding machinery already talks to it, and the platform-specific piece has not been written.

### 11.2 Where each platform actually stands

| Capability | Linux | macOS | Windows | A phone running the core itself |
|---|---|---|---|---|
| **Screen capture** | Via one of four common screenshot tools — **one of which is installed on this machine**, with a graphical display running, so the grab step is available here. What is missing is downstream: the text reader that would make a grab groundable | Via the operating system's own built-in capture command | Via an optional add-on package that may or may not be installed | Via the system capture command, which is usually unavailable without deep device access |
| **Camera capture** | Via the standard video device | **Not built** — declared an honest gap, with the optional tool named for anyone who wants it | **Not built** — honest gap | Via an optional add-on package |
| **Cursor and keyboard injection** | Two possible tools; one is present on this machine, which limits injection to one of the two display systems | **Interface only.** It permanently reports itself unavailable and does nothing | **Interface only.** Same | **Declared absent**, so no injection work is ever routed to it |

One property in that table deserves pulling out. **Nothing fabricates a result.** Every capture path
returns *nothing* when its tool is missing, rather than an empty picture or a guess, and the two
unfinished injection backends neither crash nor pretend: they report themselves unavailable and do
nothing. That matters because of what then appears in the permanent record — when the injection
backend is inert, the record says the action was **not** injected and names the reason. It does not
say "injected".

### 11.3 The browser that was deliberately not built

The documentation lists "the browser-based web engine" alongside the platform backends as a seam. The
code is more specific, and where the two differ the code is what a reviewer can check. A browser
could have appeared in two places, and they are in different states.

**On the research path** there is a defined interface for rendering a page that runs its own code,
with exactly one shipped implementation: one that returns nothing. A page that only assembles itself
in a browser is therefore an *honest gap* — the system reports that it could not read it, rather than
silently reading half of it. The accompanying note explains why the obvious implementation was not
written: a real browser follows redirections, loads material from third parties and executes the
page's own code, all of which would go around the pinned-address protections the fetching layer
depends on. It lists the conditions a future implementation would have to meet, then calls itself a
design note rather than a shipped capability.

**On the account-acting path it is stronger than a seam — it is a structural absence.** The agent that
logs into the owner's own accounts speaks only the plain request-and-response protocol; there is no
browser code path in it at all. When it meets a "prove you are human" challenge and stops, its failure
to escalate to a real browser is not a rule that could be relaxed. There is nothing there to call.

### 11.4 What this means for a buyer

**Deploy on Linux** — that is where the whole path has been exercised, and it is the vendor's own
assessment as well as this document's. **The hardware-facing capabilities are the ones that vary, and
they degrade loudly:** screen capture, camera capture and cursor injection differ by platform, and
every one reports its own absence rather than working around it. And **no claim is made from
measurement about macOS or Windows** — the parts of the sovereign side that are pure calculation over
the permanent record carry no platform-specific code and one would expect them to run, but they have
not been exercised on either platform here, and this briefing does not assert what it has not seen.
