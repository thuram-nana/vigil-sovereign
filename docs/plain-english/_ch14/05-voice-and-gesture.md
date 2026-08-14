## 7. Speaking to it, and pointing at it

There are two ways to reach the sovereign side that are not a keyboard: talking to it, and moving a
hand in front of a camera. Both sound like novelties. They are neither novelties nor conveniences —
they are **control surfaces**, and the only question that matters about a control surface is what
authority it carries.

The answer, in both cases, is **none of its own**. A spoken request is not a faster route to a
dangerous action; it is the same route with a microphone bolted to the front. A gesture is not a
shortcut past the approval queue; it is a pointer movement inside a session the owner had to unlock
with a key. What follows elaborates those two sentences, and says frankly which parts are running on
this machine and which are not.

---

### Voice is not a privileged channel

This is the load-bearing property, and it belongs before any description of microphones. When speech
is recognised, the resulting text is handed to **the same program that handles a typed request** — the
small, fast component that classifies what is being asked, decides what permission level it needs, and
writes a signed entry into the tamper-evident record of actions. The code's own summary: "voice is
just another interface onto the one authorized path."

The consequence is precise. **Saying something out loud buys exactly what typing it would buy.** If
the classified action is at one of the two automatic levels, it runs and a signed record is written.
If it is at either gated level it does not run: a record is written marking it awaiting approval, and
the spoken reply is a plain refusal — the action needs approval and was not carried out. A spoken
sentence cannot reach a level a typed sentence could not.

Three further details are worth an assessor's attention:

- **The record is written either way.** A permitted action and a blocked one both produce a chained,
  signed entry. If that entry cannot be written the program does not shrug: it prints a loud integrity
  warning and exits with a failure code, so no wrapper can read the result as a clean success. "The
  action happened but was not audited" is treated as an incident, not a logging inconvenience.
- **The program that does this can be fingerprint-checked before it runs.** Once the owner has taken
  its fingerprint, it is compared against that owner-signed fingerprint on every use, and a binary
  that fails the check **is not executed at all**; the spoken reply says so and tells the owner how to
  re-fingerprint it deliberately. The check is opt-in, and **on the machine this chapter was checked
  against no fingerprint has been taken**: with none on file the system prints a loud warning that the
  program is unpinned and then runs it unverified. That is the documented posture before setup rather
  than a silent failure, and it is one owner command away from being switched on — but until it is,
  this particular protection is present and dormant here.
- **There is a separate switch for voice alone.** The live microphone loop refuses to start when the
  owner-signed voice setting is off, and is checked again mid-conversation, so turning voice off
  part-way through stops it. Typed requests are deliberately *not* affected — turning off voice
  control never breaks the keyboard.

An honest scope note, because it is easy to imagine more than is there. With an ordinary spoken
sentence that program does one of three things: answers from the owner's own memory, escalates to a
reasoning model, or records the request as an intent for the agent mesh to pick up. **It holds no
general-purpose tool executors of its own.** The things that actually touch files, terminals, accounts
and infrastructure are the agents, each with its own ceiling and approval path. Voice reaches those
the way everything else does — by asking, and waiting.

### The pipeline, and why it can be tested with no audio hardware

The speech loop is a four-state machine:

| State | What is happening | How it leaves |
|---|---|---|
| **Waiting** | Nothing is being captured for meaning. | A trigger moves it to listening. |
| **Listening** | Audio is being collected as an utterance. | Enough trailing silence after real speech ends it; a timeout with no speech at all returns it to waiting; an absolute cap always ends it. |
| **Thinking** | The captured audio is transcribed and handed to the permission-gated path. | Immediately, once there is an answer. |
| **Speaking** | The answer is being played back in chunks. | Playback finishes; **or the owner starts talking over it**. |

Talking over the assistant mid-answer — "barge-in" — is the acceptance bar the design set itself, and
it is handled with deliberate stubbornness: a single cough or click does not abort the answer. Only
**four consecutive frames of detected speech** count as a genuine interruption, at which point
playback is cancelled and the machine returns to listening, keeping the frames that caused the
interruption so the first words are not lost.

The property that matters for evaluation is this: **the machine is driven one small frame of audio at
a time — twenty thousandths of a second each — and every one of its timings is counted in frames
rather than read from a clock.** Nothing in it depends on real time passing, and it holds no audio or
machine-learning components itself; those are supplied from outside. So the whole behaviour is
reproducible with no microphone and no speaker: feed it a recorded file, or a scripted list of "this
frame is speech, this one is not", and it does the same thing every time.

That is not theoretical. On this machine, with no working audio path in the loop and no hand-tracking
model installed, **ninety-six tests covering the speech and gesture pipelines run and pass** —
including the interruption behaviour, the absolute listening cap, and the case where the detector is
stuck reporting speech on ambient noise.

**The honest limit on real hardware.** In a room with an open microphone and a real speaker, the
assistant hears itself, and the code says so plainly rather than hiding it: interruption handling
needs acoustic echo cancellation or output ducking, and without either the live loop should be run
**half-duplex** — microphone muted while speaking. The doctrine sentence is blunt about where the fix
lives: "hysteresis alone does not defeat sustained self-echo — echo cancellation is the real fix and
is a runtime and hardware concern, not a state-machine one." **The state machine is finished; the room
is not solved.**

### Navigating by voice — the narrowest capability in the system

There is one thing a spoken phrase can do that a typed one usually would not: change which screen the
owner is looking at. It deserves precision, because it is the smallest capability in this document and
its smallness is the point.

**What it does:** on an unambiguous command naming a known screen, it writes one signal into the
owner's record, which the interface is watching, and the owner's own browser switches screens. That is
the entire effect.

**What it does not do**, in the code's words: "it runs no tool, touches no target, and cannot type or
launch." It reaches nothing outside the browser tab the owner already has open.

**When it is allowed:** only while the voice setting is on and the emergency stop is off. If either
fails, the phrase is not treated as navigation at all — it falls through to the ordinary path, which
applies its own gate. Navigation can never be a way round the switch or the stop.

**How strictly it matches.** One leading verb is stripped ("open", "show me", "go to", "switch to" and
a few more), then a trailing "screen", "page" or "tab"; the remainder must then match a screen's short
name, its printed label, or one of its listed alternative names — **exactly**. And then the decisive
rule:

> **Zero matches, or more than one match, produces no navigation at all.**

An ambiguous phrase does not guess and does not pick a favourite; it is handed on as an ordinary
question. That is what stops it hijacking real speech: a sentence that merely contains the word
"findings" is a question about findings, not a command to open a screen.

**Where the list of screens comes from.** Not from the model, and not from anything the speaker says.
It is a committed list of the interface's real screens, checked in the build against the interface's
own navigation menu, so — in the code's words — the system "can only navigate to screens that actually
exist." The browser applies the same discipline at the other end: an incoming screen name is checked
against its own list of known screens before anything moves, so an unrecognised or malicious name
navigates nowhere.

**One separation worth naming here.** The on-screen indicator showing whether the assistant is idle,
listening, thinking or speaking changes several times a sentence, and that churn is **never** written
to the signed record; it goes to a small owner-only file instead. *Audit* is what was authorised and
done; *telemetry* is what a light on the front panel shows.

### Voice: what is built, what needs hardware, what is not built

| Component | Honest status |
|---|---|
| The four-state machine, full-duplex handling, interruption | **Built and tested**, offline, against recorded audio files and scripted frames. |
| Detecting that someone is speaking | **Built and working** — a simple loudness measure with no model. A better model-based detector is an optional upgrade; **its library is not installed on this machine**. |
| **Hands-free wake word** | **NOT BUILT.** What is there fires after a few consecutive loud frames. The code calls it "a stand-in for the real custom-'SIGIL' … model (which needs training data)." Loudness is not word recognition. **"Say SIGIL and it wakes up" does not exist.** The optional real wake-word library is also not installed here. |
| Turning speech into text | A cloud service is the command-line default. A local transcription model is supported, but **it is not installed in the sovereign environment on this machine** — and the small model it would load was never fully downloaded, so even where the library is present the weights are a half-finished file. On this host the local route therefore falls through to a visible placeholder saying no model is installed. **It does not invent a transcript.** |
| Turning text into speech | The cloud service is the default; a local alternative exists in the code but **its library is not installed here**; the honest fallback is silence of realistic length, so the loop still runs and can still be interrupted. |
| The live microphone loop | **Cannot start on this machine.** The optional audio-device package is not installed in the sovereign environment, so the live loop cannot open a microphone or a speaker regardless of what hardware is attached. Everything above was exercised through files and scripted frames. |

**The sovereignty point an agency will care about most.** The cloud transcription option sends the
**captured audio** off the machine; the cloud speech option sends the **reply text** off the machine.
Both are third-party services, both are the current command-line defaults, and a key for them is
configured on this host. The code marks each with an explicit note that a third party is involved and
names the local alternative. **Neither is required by the design** — a local transcription model and
a local synthesiser are both supported, and the silent fallback is always available.

**But neither local option can run on the machine this chapter was checked against, and that must be
said plainly, because it is the sentence an agency will act on.** The transcription library is not
installed in the sovereign environment the shipped command actually uses; the small model it would
load was never fully downloaded, so even the copy of the library that does exist elsewhere on this
host has nothing to load; and the local synthesiser's library is not installed either. The local
route therefore returns the honest placeholder rather than a transcript, and the local speech route
returns silence. **On this host the only working speech services are the two commercial ones.** Both
gaps close with a package installation and a completed download — this is a deployment gap, not a
design gap — but until they are closed, sovereignty over voice is a property of the design and not of
this deployment, and a deployment that leaves the defaults alone is sending audio to a commercial
provider. That must be a decision rather than an accident.

---

### Pointing at it: the one sentence to remember

> **A gesture alone can never type a password or launch a program.**

That is not a policy in a manual; it is the shape of the code, and it comes from two enforcement
layers that must be read together.

**Layer one: nothing is injected outside an owner-armed session.** Arming locally **requires the owner
key** — there is no way to arm it without the owner identity — and arming writes a signed record, so
the fact that gesture control was authorised at a particular moment is itself tamper-evident evidence,
with the indicator lit while it lasts. The session lives only in the memory of the owner's own running
process, carries a deadline, and ends on disarm, on losing sight of the hand, or on expiry. **With no
live session, injection is refused.** If the owner has turned the gesture setting off, arming is
refused outright, loudly, and the refusal is recorded.

**Layer two: every intent's permission level is worked out, never declared.** Each gesture is turned
into an honest name for what it would do, and that name is classified by the same fail-closed
component that classifies everything else on the sovereign side. The result:

| Gesture intent | Level | What happens |
|---|---|---|
| Pointer move | Reversible internal act | Injected inside the live session. Not recorded individually — see below. |
| Click | Reversible internal act | Injected inside the live session, and recorded. |
| Scroll | Reversible internal act | Injected inside the live session, and recorded. |
| Drag | Reversible internal act | Injected inside the live session, and recorded. |
| **Typing text** | **Externally visible** | **Queued for a verified owner or device approval bound to that exact action. Never injected automatically.** |
| **A key combination** | **Externally visible** | **Queued, as above.** |
| **Launching an application** | **Externally visible** | **Queued, as above.** |

The classifier's design is what makes this hold. Input injection has no honest safe verb in its
vocabulary, so it is **dangerous by default**; the four pointer names and three keyboard names are
exact-name exceptions checked **after** the dangerous-word pass, so a dangerous word anywhere in a
name always wins. The bare words "move" and "type" are deliberately never added to the general
vocabulary, so an unrelated tool whose name contains them stays at the strictest level.

A limit stronger than the design claims, found by reading the injection routine itself: **the gesture
subsystem contains no code that types text, presses a key combination, or launches an application at
all.** The routine that reaches the operating system has branches only for move, drag, click and
scroll. A queued item is therefore a *record of an intent*, not a keystroke waiting on a timer —
approving it releases no stored password into the keyboard, because nothing here would carry it out.

### Ambiguity does nothing

A gesture becomes an intent only after passing a debouncing machine built on the same frame-counted
principle as the speech loop. A discrete gesture fires only after **four consecutive identical
readings** that are both **confidently classified** and **clearly ahead of the runner-up
interpretation**, followed by a cooldown before another can fire. If confidence is low, or the best
and second-best interpretations are close, the reading is treated as neutral, the counter resets and
**nothing happens**. Eight frames with no hand in view produce a "hand lost" signal and the session
disarms itself.

The audit discipline mirrors the speech layer. Arming, disarming and discrete actions go on the signed
record; pointer movements at thirty frames a second do not, because records at that rate would
overwhelm an append-only log, so they are treated as telemetry. And when the underlying input
mechanism cannot actually inject anything, the record does not lie about it: it says the action was
**not** injected because the input path is inert. **A log entry claiming an injection that physically
did not happen is treated as a defect, not an acceptable approximation.**

### Five ways a live gesture session dies within a frame or two

Every frame, before anything can be injected, five conditions are checked in order. Each is bounded to
roughly one or two frames — **not to the session deadline** — so an owner who wants it stopped does
not wait.

| What the owner (or the system) does | What happens |
|---|---|
| Engages the emergency stop — including from the phone | Session disarms; nothing is injected. |
| Turns the gesture setting off, from the interface, the command line or the phone | Session disarms; nothing is injected. |
| Revokes the device that armed the session — a lost or stolen phone | That device's in-flight session disarms immediately, rather than running to its deadline. |
| Nothing is armed | Injection refused. |
| The session's deadline passes | Session disarms. |

The mechanism is worth a sentence, because it is why the guarantee is real rather than aspirational:
the checks re-read the record **only when the record has grown**, and engaging the stop, flipping the
setting or revoking a device each *append* something — which is exactly what triggers the re-read. A
pure stream of pointer movements appends nothing, so a thirty-frames-a-second loop does no repeated
scanning at all. Every one of these checks fails toward *stopping*: if the system cannot determine
whether a device is still authorised, it treats it as revoked.

### The honest status of gesture — the largest caveat in this chapter

**On-box camera gesture control is not operational, and this document will not describe it as though
it were.** Three independent confirmations, all in the code:

1. The hand-tracking stage reports itself as working only when a checksum-pinned model file is present.
   When it is not, its detection routine is a **documented no-op that always returns an empty result**
   — never a fabricated hand.
2. The daemon that would run the camera loop warns loudly at startup that local camera gesture is not
   operational for want of a model, and that "the loop will process frames but can never fire a
   gesture intent."
3. The project's own feature inventory states flatly that local camera gesture is not functional and
   that gesture input is the phone companion.

**Verified on this machine: the model directory does not exist.** The runtime that would execute such
a model is installed; there is no model for it to run.

Three further limits a sceptical reader would find:

- **There is no shipped command that starts the local gesture daemon.** The function exists and is
  driven by the test suite; the sovereign command-line interface offers no verb that launches it. The
  "with gesture" switch on the system's bring-up command is **not a process at all** — it flips the
  navigate-by-gesture setting on, one shot, and exits.
- **The phone-as-trackpad path is built and unit-tested but not wired end to end in this tree.** The
  design is deliberately private: the phone runs its own hand detection and sends **tiny landmark
  measurements, never the owner's pictures**, which is why that path can honestly declare it uploads
  nothing; the decoder is strict, any malformation yields an honest empty result rather than a
  fabricated hand, and stale, duplicated, reordered and foreign-session batches are dropped. But the
  phone bridge's list of permitted actions does not include a landmark stream, and nothing outside the
  test suite feeds landmarks into the loop. **What is wired end to end from the phone is the signed
  request to *arm* a session** — signed with the phone's own key, re-verified in full by the desktop
  for freshness, the emergency stop, the gesture setting, replay, a single live session, and a
  deliberately shorter deadline than a local arm. The phone's own screen says as much: this only
  records a signed request; it is not armed yet; the desktop decides.
- **Injection on this machine would be limited to one display system**, because only one of the two
  supported injection tools is present. A machine with neither is honestly inert and says so in the
  record instead of claiming success.

Finally, **navigating by gesture is a mode, not a capability.** Unlike the voice and gesture settings,
which default to on, it defaults to **off** and is entered only by explicit owner action. While on, a
live armed session's swipes and pinch change screens instead of scrolling and clicking — reached only
after all five per-frame checks above, and mapped to **no input action at all**, so the operating
system is untouched.

### What both surfaces have in common

Voice and gesture make the same argument twice: **a new way of asking is not a new authority.** The
microphone gets no permission table of its own; it borrows the one every other path uses and inherits
the signed record with it. The camera does not decide what a wave of a hand is worth; the same
fail-closed classifier that refuses to auto-approve an unknown command name also refuses to let a hand
gesture become a keystroke.

Both are governed by a switch with a deliberate asymmetry. **Turning either capability off always
takes effect**, even unsigned — off is the safe direction, and the worst a forged "off" can do is
inconvenience the owner. **Turning either back on requires the owner's signature** and a strictly
increasing stamp inside the signed portion, so a genuine "on" captured last week cannot be replayed
after the owner switched it off. If the setting cannot be read at all, it resolves to off.

That, rather than the hands-free demonstration, is the part worth taking away.
