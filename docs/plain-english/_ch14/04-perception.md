## 6. Seeing the screen, and why the reading is not trusted

The sovereign side can look at the owner's own screen, or at a frame from the owner's own camera, and
answer a question about it. That sounds like the most ordinary feature in the chapter, and it carries
the most careful rules about truth in the whole system — because looking at a picture is the one place
where a machine is most likely to describe something that is not there.

Two quite different things happen when a frame is captured. First, software reads the letters out of
the picture — **optical character recognition**, usually shortened to OCR, the technology behind
scanning a document and getting editable text back. Second, an AI **vision model** — a model that takes
an image and describes it in ordinary prose — is asked what it sees. The system treats those two
outputs as different *kinds* of thing, permanently, and never lets one become the other.

### 6.1 The rule, written into the code three times

**The captured text is authoritative. The model's reading is advisory.** That single sentence is
written into three separate parts of the perception code — the subsystem's own front page, the agent
that answers the question, and the small module that decides what may be called grounded. It is stated
in the code as:

> "the CAPTURED TEXT … is the AUTHORITATIVE ground truth; the VLM's visual reading is ADVISORY only,
> never asserted as the screen's content."

In plain terms: the words the OCR actually read off the picture are what the answer is made of. The
vision model's prose is shown, but it is shown under a heading that says it is a guess about the image
and has not been checked against anything.

This is the same discipline the research agent uses on documents — serve the quote, never the
paraphrase — applied to a picture, and it is what that discipline looks like when the source is a
screen rather than a web page.

### 6.2 A lead, and what it takes to become a grounded claim

When the vision model says *"a Firefox window, a laptop, a coffee mug"*, each of those objects is a
**lead** — a thing worth looking into, asserted by nobody. A lead is promoted to a **grounded claim**
only if the same distinctive word appears, letter for letter, in the text the OCR read off the frame.
Words too short or too common to mean anything — under three characters, or ordinary connecting words —
do not count for this purpose, which is the same rule the memory system uses when it decides whether a
quote is specific enough to be worth anything.

And here is the part that matters most, and that most systems get wrong. A promoted claim is **phrased
as corroboration, never as a fact about the world**. The code's own example is the wording it produces:

> "corroborated by on-screen text 'Firefox'"

— never *"there is physically a Firefox."* The distinction is not pedantry. All the system has actually
established is that the word appeared on the screen: not that a browser is running, not that the window
is real rather than a picture of a window. The claim is kept exactly as strong as the evidence behind
it, and no stronger.

The answer the owner gets back is a short document with three clearly separated parts:

| Part of the answer | What it contains | What it is worth |
|---|---|---|
| **On-screen text** | The lines the OCR read, reproduced verbatim | Authoritative. This is the ground truth the answer is made of. |
| **Corroborated objects** | Each object the model named that the captured text independently confirms, each carrying the actual on-screen words that confirm it | Grounded, and phrased as corroboration — never as a statement about the physical world. |
| **The model's visual reading** | The vision model's prose, whole and unedited | **Advisory.** Labelled in the answer itself as a guess about the image, not verified against captured text. |

They are never merged. There is no fourth section in which a helpful summary blends them together.

### 6.3 With no captured text, nothing is grounded — by construction

If the OCR read nothing — a photograph with no writing in it, a machine with no OCR software installed,
a failed read — then there is nothing to corroborate against, and **every object the model named stays
a lead**. Not some of them; all of them. An image-only frame can never produce a grounded claim, in any
circumstance, because the half of the design that does the grounding produced nothing.

The answer says so on its face. Instead of the authoritative section it prints a line stating that no
text was captured, that the frame was image-only, and that there is therefore nothing grounded to
serve. The one-line label written onto the permanent record is equally blunt: an image with an
unverified reading and no OCR.

This is worth pausing on, because it is the shape of the whole system in miniature. When the trusted
input is missing, the output does not quietly fall back to the untrusted one. **It falls back to saying
less.**

### 6.4 Text on a screen can be hostile

A screen is not a neutral surface. It shows web pages, emails and documents written by other people,
some of whom would be delighted if what they wrote could be mistaken for the system's own conclusions.
This is the attack usually called prompt injection: put words on a surface an AI reads, and get them
treated as instructions or as findings.

The perception answer defends against it with a small, very effective piece of formatting discipline.
The section headings are the only lines allowed to start at the left-hand margin. **Every captured line
is written with a short indent guard in front of it**, so a line of screen text can never begin at the
margin. A page that contains the exact heading "On-screen text (authoritative — captured verbatim from
the frame)" therefore appears in the answer indented and quoted, as content, and does not become a
section boundary. The boundary is unforgeable not because the system checks for forgery attempts, but
because the forged version is structurally incapable of occupying the position that matters.

The vision model's own prose is indented the same way, and the code is explicit about why: the reading
is *the most attacker-influenceable channel of the three* — a compromised local model, or an honest
model faithfully transcribing hostile words it saw on the screen, both arrive by that route. Two tests
in the suite construct exactly that attack — a hostile reading containing both heading lines verbatim —
and confirm that the finished answer contains precisely one real authoritative heading and that the
hostile copies appear indented, as quoted content.

One further detail about what gets stored. The permanent record of a perception carries the captured
text, the model's reading, the corroborated objects and the leads as **sealed fields** — encrypted at
rest, so an auditor reading the log without the key sees that a perception happened and how much text
was involved, but not what was on the owner's screen. The short label that stays readable is
deliberately a description of the event, never a sample of its content.

### 6.5 Ambient watching — and the fact that nothing leaves an unchanged screen

There is a second mode, in which the system watches a stream of frames rather than answering one
question. It is **opt-in**: it does not run unless it is started. Starting it and stopping it each
write a marker to the permanent record, so a period of ambient watching is visible afterwards as a
bounded, timestamped span with a count of how many times it escalated.

The mechanism that makes it tolerable is the definition of "something changed". It is not a comparison
of the pixels — comparing pixels means a cursor blink or a compression artefact counts as a change, and
a watcher that fires on everything is a watcher that has to send everything somewhere. Instead the
comparison is over **the distinctive words the OCR read**: a change is a meaningful divergence in that
set of words, or the arrival of enough new words to matter even on a busy screen. A single new warning
line on a screen already full of text still fires; the same screen re-rendered slightly differently
does not.

The consequence is the sentence worth remembering: **an unchanged frame produces nothing at all.** No
reading, no record, no request. It does not leave the machine, because nothing is done with it.

The ambient loop also refuses outright to run with a model that uploads. Not "asks first" — refuses,
and writes the refusal to the record. Continuous watching and off-machine upload are never combined on
an automatic path.

**An honest limit the reader should have.** Ambient watching has no shipped way to start it: no
command-line switch, no button in the interface. It exists as a capability other code can call, and it
is exercised by the test suite. And "indicator" in the code's own description means a marker written to
the permanent log at start and stop — not a lamp on the machine and not a light on a camera. A reader
who pictured a hardware indicator should replace that picture with an audit-trail entry.

### 6.6 Recall — "where did I last see that?"

The most useful thing built on top of all this is a question the owner can ask their own machine:
*where did I last see this?* The system searches its perception history, finds the most recent event
whose **captured text** contains the subject, and serves back the actual line — the owner's own screen
text, verbatim — with the record number it came from, the time, and the frame's fingerprint. It reads
history and writes nothing.

It never serves the vision model's reading. A thing the model once claimed to see, which the OCR never
confirmed, is not a sighting and cannot be recalled as one.

There is one further restriction that is easy to miss and is exactly right. **All of the subject's
distinctive words must appear on a single line.** The test that pins this behaviour uses a frame
containing "AWS console open" on one line and "far below: secret bucket keys" on another, and asks for
"AWS bucket". Both words are somewhere on that screen. The answer is *no sighting*, because the only
thing recall is permitted to hand back is a verbatim line, and no line on that screen shows what was
asked about. Serving either line would misrepresent the frame. The same request against a screen
showing "AWS bucket browser view" returns that line, because that line genuinely contains the subject.

### 6.7 Sending a frame to an outside model: the egress gate

There are two vision models in the design. One runs entirely on the owner's own machine and sends
nothing anywhere. The other is a frontier model — better at describing images, and reached by
**uploading the picture to another company's service**. The code refuses to treat that as a quality
setting:

> "Sending a screen/camera frame to the frontier … VLM uploads private bytes off the owned machine —
> that is A2 data-egress, not a free 'try local then frontier' quality bump."

In plain words: a screenshot of the owner's desktop may contain anything that was open at that moment.
Sending it out is an externally visible act with consequences that cannot be taken back, and it is
classified as one.

**The classification is worked out, not declared.** The perception agent does not get to state how
serious the upload is. The name of the action is handed to the same fail-closed classifier the rest of
the system uses, and that classifier answers. Run directly against the classifier on this machine, the
upload action returns the externally-visible tier with the verdict *queued* — the agent's own opinion
never enters into it. If the classifier cannot be reached at all, the answer is the most restricted
tier, not the least.

**The approval is bound to that exact upload.** Before anything is sent, the system computes a
fingerprint over the image's fingerprint together with the question being asked, and the owner's
approval must match it. An approval of a *different* upload — a different screen, or the same screen
with a different question — does not match and authorises nothing. There is no general "yes, you may
use the frontier model" permission to be obtained once and reused.

**Absent an approval, the request queues and nothing is uploaded.** The request is written to the
permanent record as awaiting approval, the frontier reading is withheld, and — this is the part that
makes the gate liveable — **the local reading still stands**. The owner still gets an answer; they
simply do not get the outside model's opinion until they have said yes to that specific frame.

Two structural refusals sit around the gate. The ordinary question-answering path and the ambient loop
both check the model they were handed and **refuse an uploading model outright**, writing a note or a
refusal rather than performing the upload. So the only route to an upload is the gated one; there is no
second door to close.

And one property that is stronger than a rule, because it cannot be granted away. Trust in this system
can be extended to an agent over time, letting some of its externally-visible work go through without
asking. That mechanism requires the action to be at or below the agent's **permanent ceiling**. The
perception agent's ceiling is the reversible-internal-act level, and an upload sits one level above it.
**No grant of trust can therefore ever make a frame upload automatic** — not by promoting the agent,
not by any setting. Each upload needs its own approval, permanently. Under the emergency stop the
upload is not even queued: it is refused outright and the refusal recorded, while the local, on-machine
perception keeps working, because observation is the one thing the halt is designed to leave alive.

Who may sign the approval: the owner's own key, or a device key the owner has explicitly authorised —
which is how an approval can be given from the paired phone. The device ledger and what the phone can
and cannot do are covered later in this chapter.

### 6.8 What is actually running on this machine — and why the gap is safe

Everything above is built and tested. Nineteen tests cover this subsystem specifically, and they pass:
that an image-only frame grounds nothing; that hostile screen text and a hostile model reading cannot
forge a section boundary; that a queued upload uploads nothing; that an upload runs only after a
verified approval bound to that exact frame and question; that an approval of a different upload does
not authorise it; that both automatic paths refuse an uploading model; that jitter is not a change but
a small meaningful addition is; and that scattered words are not a sighting.

What is **not** live is the hardware and software chain that feeds it. Checked directly on this
machine:

| What perception needs | State on this machine | Consequence |
|---|---|---|
| Something to take a screenshot | **Present** — one of the four utilities the capture code recognises is installed, and a graphical display is running | The grab step is available here. It has not been exercised: capturing the operator's own screen to prove a documentation point is not a reasonable thing to do. |
| A camera | **Present** — a USB camera is attached, and the video tool the code uses is installed | Same: available, deliberately not exercised. |
| **OCR software** | **ABSENT** | **This is the one that matters.** No OCR means no captured text, which means no authoritative half, which means **nothing can be grounded at all**. |
| A local vision model | **ABSENT** | The on-machine advisory reading comes back empty rather than invented. |
| The operating system's own description of the screen | **Not wired** | The richest source of screen text — what the accessibility layer knows about every window and button, without any character recognition at all — is a documented, deliberately unfinished seam. |

So the honest status is: **built, tested, and not live on this machine** — and the missing piece is
precisely the authoritative one.

That is a worse-sounding sentence than it deserves to be, because of what the failure actually produces.
A perception system whose reader is missing does not describe screens badly. It describes screens
**advisorily** — every object the model names stays a lead, the answer prints "no text captured", and
the record says plainly that this was an unverified reading with no OCR. There is no configuration in
which a missing sensor produces a confident false statement about what was on the owner's screen. The
grounding rule was written so that absence degrades into silence rather than into invention, and on
this machine that is not a claim about the design — it is the observable behaviour.

**What this section does not establish.** It does not establish that the OCR, once installed, reads any
particular screen correctly; character recognition makes its own mistakes, and a mistake it makes
becomes part of the authoritative half. It does not establish that a corroborated object is physically
present — only that its name appeared in the text read off the frame. It does not establish that an
approved frontier reading is accurate; that reading stays labelled advisory after the upload exactly as
it was before. And it says nothing about any screen but the owner's own: this subsystem observes the
owner's own screen and the owner's own camera, and has no path to any other.
