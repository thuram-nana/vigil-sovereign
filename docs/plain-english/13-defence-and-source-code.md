# The Defensive Side, Source-Code Review, And Network Handling

This chapter covers four things that sit slightly apart from the main job of finding
weaknesses in a running system, but which any serious buyer will ask about.

1. **The defensive side.** The same machinery, turned around to watch and protect a
   system you run, rather than to attack one. Inside the product this side is called
   **AEGIS**.
2. **Reading the source code.** What happens when the organisation being assessed hands
   over the actual program text, and how that changes what the system can say.
3. **Encrypted connections and certificates.** What the system checks about the padlock
   in the browser bar, and — just as important — how the system controls and labels its
   *own* network traffic so that a defender can recognise it rather than be fooled by it.
4. **Proving a fix worked.** How the system establishes that a problem is genuinely gone,
   instead of accepting somebody's word that it was patched.

## The words used throughout this chapter

**The four verdicts.** The system is only allowed to say four things about any security
claim:

| Word | Plain meaning |
|---|---|
| **FACT** | We proved it. A mechanical, rule-based test re-derived this result from evidence the system itself captured, and anyone can re-run that test later and get the same answer. |
| **LEAD** | Something suggests it. A tool said so, a pattern matched, or an AI thought so. Worth investigating. Not proven. |
| **CLEAN** | We proved it is *not* the case, here, now, on this exact thing we looked at. This is much harder to earn than FACT. |
| **INCONCLUSIVE** | We could not tell. This is a real answer, reported as such, and never quietly rounded up to "CLEAN". |

These four words are enforced by the software itself: the list is a fixed, closed set in
code, so "probably fine" or "no issues found" cannot appear in output. The rule the
project holds itself to is written down in its own documentation
(`docs/CLAIM-DISCIPLINE.md`): *"Asserting a vulnerability that is not there destroys trust
in every finding. Asserting safety that was not established is worse, because nobody goes
looking again."*

**The checker.** A **checker** is a small, fixed, non-AI program that looks at saved
evidence and answers one narrow question — yes or no, by a fixed procedure, with no
judgement, no guessing, no access to the internet, and no clock. It behaves like a
laboratory test on a sealed sample: the same sample always produces the same reading,
whoever runs it and whenever they run it. The project's own name for a checker, in the
code and on some screens, is an **oracle**; other chapters in this briefing sometimes call
it an *automatic test*. All three words mean this one thing.

At the time of writing the system has **38** checkers covering **85** distinct categories
of weakness. **Seven** of the 38 belong to the defensive side described below, and they
fall into two groups:

- **Four** that watch the customer's own application from the inside, using the records
  that application already keeps: attacks on an AI feature, machine crawling of the site,
  and stolen-password campaigns against the login system.
- **Three** that judge a single incoming web request on its own, without waiting to see
  what the application then did with it. These three sit in the live traffic path as an
  inline protective layer, and they are the ones that can block.

Chapters 4 and 5 group the same seven the same way. The other thirty-one were written for
the offensive side — proving findings against a system the customer has authorised the tool
to test — but three of them are **also** used, unchanged, by the defensive firewall, as the
next Part explains. "Defensive" here means *written for defence*, not *used only in
defence*. The Detection Mirror's twelve log-reading procedures, described later in this
Part, are a separate catalogue and are not part of the 38.

Two further ideas recur, so they are worth a plain sentence each:

- **Deterministic.** A recipe, not a chef. Follow it twice with the same ingredients and
  you get the same dish — no mood, no improvisation, no different answer on a Tuesday.
- **Fail-closed.** Like a drawbridge held up by power: cut the power and it falls shut. If
  a check cannot be completed, the answer is "no", never "probably fine".

---

## Part 1 — The Defensive Side (AEGIS)

### Why it exists

Most security products either attack a system to find holes, or sit in front of a system
and try to stop attacks. These are usually different products from different vendors,
using different logic, disagreeing about what counts as an attack.

AEGIS is the same judge, pointed the other way. The exact same rule-based checkers that the
offensive engine uses to *prove* it broke into something are used, unchanged, to *prove*
that somebody else is breaking into you. This matters for a specific and unglamorous
reason: the two halves cannot disagree about what an attack is, because they are running
the identical code. The design document for the defensive side lists, item by item, which
components are reused **without modification** — the verifier, the evidence translator,
the offline re-check routine, and the anti-fabrication layer are all shared, not copied.

AEGIS is not a separate application. It lives in three places in the codebase:

- an embeddable library and a reverse-proxy "provable firewall"
  (`engine/crucible/framework/v2/aegis/`);
- a detection-engineering toolkit that reasons about your alarms
  (`engine/crucible/framework/v2/defender/`);
- the **Detection Mirror**, which proves from your own log files that an attack happened
  (`integration/vigil_integration/detection/`).

A fourth, smaller defensive component — a scorer for suspicious inbound email and
messages — is described later in this Part.

### The core promise, and its exact limit

The deployment guide states the promise and the limit in the same breath, and both should
be quoted to any evaluator:

> "No firewall 'totally' protects an app, and AEGIS does not claim to."

What it does claim is narrower and much stronger than the usual firewall claim. A normal
web firewall blocks anything that *looks* suspicious. That is why normal web firewalls
break real customers: a person called O'Brien, a company called AT&T, a developer pasting
a snippet of database code into a support ticket — all of these look like attacks to a
pattern-matcher.

AEGIS blocks a request **only when a mechanical checker proves it is an attack**, and it
attaches a certificate to the block. The certificate is a small file that any third party
can re-check later, offline, with no network and no trust in AEGIS itself. In the words of
the module that produces it: *"RAMPART's differentiator is not that it blocks — every
firewall blocks — it is that every block is a re-runnable certificate."*

The everyday analogy is a breathalyser versus a police officer's opinion. Both can stop a
driver. Only one of them produces a numbered reading that a laboratory can reproduce in
court.

### The three answers AEGIS gives, and what "clear" does not mean

For every request it inspects, AEGIS returns one of three decisions:

| Decision | Meaning | What happens to the traffic |
|---|---|---|
| **confirmed** | A checker fired. This is a proven attack, and a certificate exists. | Blocked, but only in enforce mode (see below). |
| **lead** | Suspicious. Not proven. | Always forwarded. Logged. May raise the sender's suspicion score. |
| **clear** | No checker fired and the softer signals were below the noise band. | Forwarded. |

The software enforces a structural link between the first two columns: a "confirmed"
decision **cannot exist without a certificate**, and a certificate cannot exist without a
checker having genuinely fired. This is checked by the data type itself, not by convention.

**"Clear" does not mean "safe."** The design document says so in plain words, the running
user interface says so on the screen, and the deployment guide repeats it:
a "clear" decision means *nothing was proven*, not *nothing is wrong*. This is the same
discipline that governs the offensive side, and it is deliberately uncomfortable.

### What the inline firewall can prove and block today

This is the complete current list for the **inline firewall** — the part that sits in the
live request path in front of a web application. **Four** of these are judged from the
incoming request alone; **three** require seeing what the application sent back.

(A note that removes an apparent contradiction with chapter 2: chapter 2 says the
embeddable AEGIS library "can confirm four classes today", and lists a different four —
system-prompt disclosure, prompt injection, automated access and credential stuffing.
Both statements are correct because they describe **different surfaces**. The seven below
are the inline web firewall's classes. The four in chapter 2 are the ones the library
proves from an application's own telemetry — the record an application keeps of its AI
conversations and its login attempts. They are described later in this Part, and the table
of installation methods says exactly which route gives you which.)

| Attack class | Plain-English meaning | Proved by | Judged from |
|---|---|---|---|
| Database-command injection attempt | Someone sent a value that provably escapes out of a database text field and starts issuing database commands of their own (for example a self-true condition, a merged second query, or a stacked extra statement). | The structure of the value itself | The request alone |
| Operating-system command injection attempt | Someone sent a value containing a genuine operating-system command with an argument, wrapped in shell syntax or placed after a command separator. | The structure of the value itself | The request alone |
| Document-database operator injection attempt | Someone injected a known database *operator* into a position where the application expected a plain value (for example a field name written as `user[$ne]`, or a value of `{"$ne": null}`). | The structure of the value itself | The request alone |
| Automated access | A client fetched a decoy address that no human-visible page links to. Only a machine could have found it. | The decoy was fetched | The request alone |
| Reflected cross-site scripting | A value the attacker sent came back inside the page in a position where a browser would *execute* it. | The application's own response | The response |
| Server-side template injection | The application actually *calculated* an arithmetic expression the attacker embedded — the answer appears in the page and the original expression is gone. | The application's own response | The response |
| Path traversal | A value walked up out of its folder toward a system file, and a strict system-password-file signature then appeared in the response. | The application's own response | The response |

The **first four** prove that a **structured attack attempt** occurred. They do not prove
the application was harmed — a properly written application is safe from all of them. The
**last three** prove **actual exploitation**: the application really did reflect, calculate,
or leak.

One point of arithmetic, because two different sevens appear in this chapter and they are
not the same seven. **Seven defensive checkers** was the count at the start of the chapter:
three request-only break-out judgements plus the four inward-facing detections. **Seven
inline classes** is the list above. They overlap but do not coincide, because the inline
firewall reuses offensive checkers for the response side. Written out:

| The seven classes above | Which checker proves it | Built for |
|---|---|---|
| The three injection-attempt rows | The three request-only break-out checkers | Defence |
| Automated access | One of the four inward-facing detections | Defence |
| Reflected cross-site scripting, path traversal | The offensive "a planted marker reached somewhere it should not" checker, unchanged | Offence, reused |
| Server-side template injection | The offensive "the server calculated the attacker's sum" checker, unchanged | Offence, reused |

That reuse is the point made at the start of this Part: the defensive side does not carry
its own private idea of what counts as an attack. It runs the offensive engine's own
checkers — the same code, not a copy of it — which is why the two halves cannot drift apart
about what an attack is.

The conservatism is deliberate and is tested. The published list of things that are
explicitly *not* blocked includes: an apostrophe in a surname, `AT&T`, a comparison such as
`id > 1000`, a software version string such as `python-requests/2.28.1`, pipe-delimited
data such as `Name | Age`, a pasted database query, a price written `$5.00`, a database
export containing `{"$oid": ...}`, an operator name appearing as ordinary data
(`["$ne"]`), an HTML-escaped reflection, a page that merely *documents* the system password
file, and a prose em-dash.

There is one honest warning for a specific kind of customer. Applications whose whole
purpose is to accept code — paste bins, developer question-and-answer sites, bug trackers —
legitimately carry attack syntax as ordinary user content. The guide says plainly: run
those in watch-only mode and review before enforcing.

### Why growing the offensive engine cannot change what the firewall blocks

The reuse described above raises the obvious opposite worry. The offensive engine keeps
growing: a run of new confirmations for cloud and Kubernetes attacks was completed on
12 August 2026. If the defensive side runs the offensive side's checkers, does the firewall
quietly start blocking more things every time the offensive side learns a new trick?

It does not, and the arrangement that prevents it is structural rather than a promise of
care.

When a finding arrives carrying a weakness category the system does not recognise, it is
tested against a **fallback** set of checkers. That fallback set is **frozen**: it is the
fifteen checkers that existed before the defensive and cloud families were added, and it is
deliberately *not* derived from the full list. Had it been derived, every later addition
would have quietly widened the set that every unrecognised finding is tested against. The
other twenty-three checkers — the four inward-facing detections, the three request-only
break-out judgements, the eight configuration-posture checks, the two document-forgery
checks and the six live-capture checks — are reachable **only** through their own explicit
category entry, and every one of those entries is keyed on a kind of evidence an ordinary
web scan never produces.

Two tests hold this in place, and they are deliberately different in kind so that one
refactoring cannot defeat both. One asserts the arithmetic. The other **writes out the
fifteen permitted names by hand**, so a drift fails the build with an explicit list of what
moved rather than against a set the test itself recomputed. The same file also pins the
benchmark result as a fixed row — eleven true findings, no false alarms, no misses — so an
addition that shifted the engine's measured behaviour by even one finding would fail before
it could be merged. That file was amended, visibly and by hand, for each new checker added
in August. The fifteen did not move, and the benchmark row did not move.

### What AEGIS deliberately refuses to block, and why that is a feature

Three attack families are deliberately kept off the blocking path, each for a stated
reason. This is worth reading closely, because it is the clearest illustration of the
product's philosophy.

Two words are needed to read the table. A **payload** is simply the test input an attacker
(or the system) sends — the crafted value inside an otherwise ordinary request. **In-band**
means the evidence arrives in the same reply the attacker was already going to get;
**out-of-band** means the evidence arrives by a separate route, such as the target's server
making its own contact with a listener elsewhere. Out-of-band evidence is much stronger,
because the attacker cannot manufacture it by simply echoing text back.

| Family | Why it is not blocked |
|---|---|
| **Server-side request forgery** (tricking the server into fetching a web address of the attacker's choosing) | A single request and response cannot prove the server actually went and fetched anything. Proof requires an *out-of-band* signal — a callback arriving at a separate listener the attacker's payload pointed at. So AEGIS records it as a lead. |
| **XML external entity attacks** (tricking a document parser into opening a file on the server) | The in-band version *looks* provable — a system password line appears in the response — but that line could equally be user-submitted content being echoed back by a security wiki or a code-review page. Treating it as proof would produce a circular self-proof and would wrongly block legitimate content. |
| **Error-based database injection** | A single response cannot prove that a database error was *caused* by the payload rather than merely displayed near it. |

The documentation states the underlying principle directly: *"A LEAD that can't be a
near-zero-FP block is a success"* — in plain words, a signal that cannot be turned into a
block with almost no false alarms is better left as an unproven lead than shipped as a
verdict.

There is one opt-in bridge for the first two families, and it is described honestly in the
deployment guide. An operator may plant a **decoy address of their own** on a machine they
control, and switch on a passive correlation feature. AEGIS never injects, advertises or
plants that decoy in anyone's traffic — it forwards every inbound byte unchanged. But if an
attacker's *own* payload names that decoy, and something on the server side really does
reach out to it, the resulting unsolicited contact raises that sender's suspicion score. It
still **never** blocks and never produces a "confirmed" verdict. The feature is off by
default, is separately permissioned, and its receiver listens only on the machine itself.

### The soft response ladder — suspicion never blocks

AEGIS keeps a running belief about each source of traffic, expressed as a statistical
distribution rather than a counter. When a source *sustains* suspicious behaviour, it earns
a graduated, retryable response short of a block: first a **challenge**, then at higher
sustained belief a **throttle**. Both are HTTP 429 responses — the polite "slow down,
try again" — so a legitimate user caught in a burst simply retries.

Two thresholds must both be crossed before any escalation: the *lower* bound of the belief
must cross a floor (0.40 for challenge, 0.50 for throttle) **and** the belief's average must
show that suspicion dominates the source's whole history (0.55 and 0.66 respectively). The
code comments record why the second condition exists: without it, a single suspicious
request amid a large volume of ordinary traffic could shrink the statistical uncertainty
enough to trip the first condition and challenge a perfectly innocent visitor. That was
found by an adversarial review and fixed.

The load-bearing rule: **belief never produces a hard block.** Only a fired checker's
certificate blocks. Repeated leads, however many, can only ever reach "challenge" — the
mathematics is arranged so that a pure-lead source's average belief has a ceiling below the
throttle threshold.

### The safety rails

These are the properties an operations team will care about most.

- **Watch-only by default.** The default mode is `observe`: inspect, log, forward
  everything, block nothing. The recommended rollout is to run in observe against real
  traffic until it produces zero verdicts on legitimate requests, and only then switch to
  `enforce`.
- **Fail-open, always.** Any inspection error, an unproven request, or a tripped stop
  switch results in the traffic being forwarded. An application that is itself down
  produces an honest gateway error, never a block. The stated rule: *"The firewall never
  takes your app down."*
- **An instant off-ramp.** Tripping the kill switch for the gateway's name drops it to
  pure pass-through with no restart and no downtime. The kill switch is a file on disk, so a
  tripped switch survives a crash or a reboot, and it is read fail-closed — if the software
  cannot positively determine that the file is absent (permission denied, a broken symbolic
  link, a disk error), it treats itself as halted.
- **Blocking is separately licensed inside the product.** Active blocking requires an
  internal permission — the product's "respond" capability. A governed deployment that has
  not granted it runs in observe only and says why. Detection is always available; only
  blocking is gated.
- **No forward-request forgery.** The address of the protected application is fixed by the
  operator. Only the incoming path and query are appended. A caller can never redirect the
  gateway at a different host.
- **Client-supplied forwarding headers are stripped.** The gateway is the trust boundary
  and sets its own record of the real client address, rather than trusting and appending to
  a header the client could have forged.
- **Bounded by construction.** Request bodies over 10 megabytes are refused outright rather
  than truncated (the connection is closed with an honest "too large" reply); only the first
  2 megabytes of a body is inspected; and there is a 60-second per-connection read deadline
  to bound slow-drip denial-of-service attempts.

Two honest caveats the product surfaces itself, both visible on screen in the running
interface:

- **Enforce mode can silently become observe mode.** If you ask for enforce and the
  internal blocking permission is not available, the deployment downgrades to observe. The
  screen says: "You requested ENFORCE but it downgraded to observe — nothing is being
  blocked."
- **The "deployment secret" is not a password.** It is used to scramble identifiers so that
  a client address is stored as a pseudonym rather than in the clear. The interface states
  this explicitly so no one mistakes it for request authentication.

### How a defender installs it — and exactly what each route detects

This is the table to read before choosing. The three installation routes do **not** all give
the same detections, and choosing the easiest one because it needs no code changes gets you
a different set from the one an AI-application owner probably wants.

| Method | Who it suits | What it costs | What it can prove in this position |
|---|---|---|---|
| **Reverse proxy** — put the gateway in front of the application and point the load balancer at it | Any application, any programming language | No code changes at all | **All seven** inline classes. It is the only route that sees the application's *response*, so it is the only one that can prove reflected cross-site scripting, template injection and path traversal. |
| **Sidecar detect service** — the application sends a description of each request and receives a verdict it acts on itself | Any language, where the team wants to keep control of enforcement | One integration point in the application | The **four request-only** classes. The service is handed a request description; there is no response for it to judge. |
| **In-process middleware** — a small piece of code that wraps a Python application so that every request passes through it before the application sees it | Python applications wanting the lowest delay | A one-line change; the request body is buffered and restored so the application reads it normally | The **four request-only** classes. A proven attack is refused before the application runs. (A lighter, passive version of the same wrapper watches only for decoy-address fetches and never alters a response.) |

One condition applies to the automated-access class on all three routes: it can only fire if
the operator has first told AEGIS which decoy addresses to watch for. With no decoy seeded,
there is nothing for a crawler to trip over, and the class simply never fires. This is a
configuration step, not a defect, but a defender who never performs it should not expect the
detection.

**None of these three routes provides the AI or the stolen-password detections.** (Automated
access is the exception among the four inward-facing detections: it is a request-side class,
so all three routes above do provide it.) The other three run on a separate route: the
application hands AEGIS a record of one AI conversation turn, one
request event, or one batch of login attempts, and AEGIS returns a verdict. That is reached
either from inside a Python application by calling the library directly, from any language
by posting that record to a small detect endpoint, or from the command line for a saved
file of such records. The running interface says the same thing on screen, so an operator
who assumed the reverse proxy protected their AI chatbot from prompt injection is corrected
there too.

There is also a five-minute offline demonstration that plants a decoy secret, feeds it a
manipulated conversation that leaks the decoy, and prints a confirmed verdict plus a
certificate, with no network involved at all.

The data plane is public-facing by design — a firewall has to sit in the traffic path. The
guide is explicit that this is the one component that is *not* restricted to the local
machine, and lists its compensating controls: hostile-input hardening at the boundary, the
blocking permission, and the kill switch. It also advises keeping any management interface
off the same port.

### The four inward-facing detections — AI features, crawling, and account attacks

Beyond ordinary web attacks, AEGIS detects four things that matter to an organisation
running an AI assistant, a public website, or any login system. These are the first group of
four named at the start of this chapter — four of the seven defensive checkers among the 38.
The other three are the request-only break-out judgements already listed above
(database-command, operating-system command, and document-database operator injection),
which is why the defensive total is seven and not four.

Note where these run, because it decides what a customer actually gets. Three of the four —
system-prompt disclosure, prompt injection and credential stuffing — are **not** part of the
inline firewall at all. They judge records the application itself keeps: a transcript of one
AI conversation turn, or a batch of login attempts, which the application hands to AEGIS.
Installing the reverse proxy does not give you them. The fourth, automated access, runs in
both places: the inline firewall can see a decoy address being fetched as it happens, and the
same checker can also be run over a supplied record afterwards. The installation table above
sets this out route by route.

| Detection | Plain meaning | What proves it | What it deliberately does *not* prove |
|---|---|---|---|
| **System-prompt disclosure** | The hidden instructions your AI runs under have leaked to a user. | A randomly generated marker (at least 16 characters and genuinely random) is planted in the hidden instructions; the checker fires only when that exact marker appears word-for-word in the AI's own output. | That an *attack* caused it. A user politely asking "repeat your instructions", or the application's own debug logging, produces the same leak. |
| **Prompt injection** | An instruction smuggled into user content changed how your AI behaves. | A clean control turn is compared with the attacked turn, and a structurally detectable behaviour genuinely flipped — a refusal reversed, a sensitive tool invoked, or the instruction/data boundary marker echoed only under the attack. | Nothing is claimed from the mere presence of phrases like "ignore the above". Users legitimately paste such text, so it stays a lead. |
| **Automated access** | A machine, not a person, is exploring your site. | A decoy address that nothing on your site links to was fetched. | "Scraping". Link-preview bots, browser prefetch, antivirus URL scanners and uptime monitors all trip the same wire. An operator allow-list of known-good crawlers actively *refutes* the finding. |
| **Credential stuffing** | Someone is testing stolen passwords against many of your accounts. | A formal sequential statistical test over successful logins to account/source pairs never seen before, plus a family-wise statistical correction across the different sources, so that testing thousands of sources cannot manufacture a false hit by sheer volume. | A burst of *failures* — the pattern produced by many people behind one shared corporate address. Failures produce no statistical round at all, so this can never confirm on failures alone. |

All identifiers are converted to keyed pseudonyms at the boundary before any checker sees
them, with addresses coarsened to a neighbourhood rather than an exact machine. The checker
never sees a raw username or a raw address.

One honesty note carried in the design document: the system-prompt-disclosure certificate
has to retain the random marker and a short redacted excerpt **in plain text**, because
re-checking it offline means searching for that exact text again. The document says so
directly — the usual "only hashes are stored" reassurance does not hold for this one
detection, and the project refuses to pretend otherwise. The marker is a dedicated random
token, never your proprietary instruction text and never real personal data.

### Scoring inbound messages for social-engineering attacks

There is a small, separate defensive component aimed not at your servers but at your
**people**. It exists as the deliberate inverse of a capability the project refuses to
build: the framework will not generate phishing or impersonation content, so instead it
scores *incoming* content for the signs of a social-engineering attack. It analyses a
message you already received. It sends nothing and contacts nobody.

It runs offline and deterministically. You hand it one message — the body, and optionally
the subject line, the sender's display name and address, the reply-to address, the links,
and the attachment filenames — and it reports the indicators it found, a risk score and a
recommendation. Nine indicators are checked:

| Indicator | What it looks for |
|---|---|
| Urgency | "act now", "within 24 hours", "your account will be suspended", "final notice". |
| Credential harvesting | "verify your account", "confirm your password", "unusual sign-in". Scored higher when the message also carries a link — that combination is the classic harvest pattern. |
| Authority impersonation | "this is your CEO", "from the IT helpdesk", "payroll department". |
| Financial request | Wire transfers, gift cards, changing bank details, "process this payment", cryptocurrency. |
| Secrecy request | "keep this between us", "strictly confidential", "handle this discreetly". |
| Reply-to mismatch | The address a reply would go to belongs to a different domain from the address the message claims to come from. |
| Display-name mismatch | The friendly sender name claims a well-known brand that the actual sending domain does not belong to. |
| Lookalike link | A link whose host embeds a well-known brand name but is not that brand's real domain, or uses the encoding trick that lets non-Latin characters imitate Latin ones. |
| Dangerous attachment | An attachment whose file type can execute — programs, scripts, shortcuts, macro-enabled office documents, disk images. |

The indicator weights combine so that several weak signals accumulate without any single
one dominating, and the total is placed in one of five bands from minimal to critical. The
recommendations are practical and escalate with the band, up to "quarantine and report to
the security team; verify any payment or credential request through a known channel".

**The honesty line here is drawn explicitly in the source.** These are *leads for a human
or for a downstream classifier, not verdicts*. Phishing detection is inherently
probabilistic; the recommendation text says so even at the lowest band ("this is a
heuristic, not proof"). Nothing here mints a FACT, and nothing here is claimed to. A
production deployment would add machine-learning or AI classifiers on top; the built-in
indicator set is offered as an honest, testable first filter. Detecting **faked audio or
video** is out of scope and stated as such — that needs media-forensic models this
component does not have.

It is reachable as a command (`socialdefense assess`, which exits with a failure code on a
high or critical band so it can be wired into a mail pipeline as a gate) and it has a
read-only descriptive panel in the older console interface.

### The Detection Mirror — proving from your own logs that an attack happened

This is the piece a security operations centre will care about. For each offensive move,
there is a matching mechanical checker that reads the log files the protected systems
themselves produced and proves the attack occurred — delivered as a re-checkable
certificate, not as an alert.

The distinction between an alert and a certificate is the whole point. An alert is a claim.
A certificate is a claim plus the evidence plus a repeatable procedure, so a third party can
re-run the check over the embedded evidence and confirm the answer without trusting the
tool that raised it. The code calls this *"proof by re-execution, not string trust."*

It is run with `vigil detect`, pointed at ordinary log files: a web access log, an
authentication log, and a network connection log.

The complete current catalogue:

| Check | Plain meaning | Grade | The look-alike that must stay silent |
|---|---|---|---|
| Port scan | One source contacted many different network ports in a short window. | FACT | An uptime monitor hits one or two fixed ports. |
| Forced browsing | One source produced many *distinct* "page not found" results — dictionary-guessing for hidden content. | FACT | A search-engine crawler fetches real pages; a monitor repeats one address. |
| Scanner fingerprint | A scanning tool identified itself in its request headers. | FACT (self-identified) or LEAD (pattern only) | A pattern of paths alone is graded LEAD, because a path pattern is not proof. |
| Content-system enumeration | One source walked through many distinct content-management-system addresses — plugin, theme and user enumeration. | FACT | An ordinary visitor touches a couple of such addresses for one theme. |
| Web-firewall probing | Someone is fingerprinting your web firewall, or throwing many different attack classes to see what gets blocked. | LEAD (always) | Deliberately graded LEAD, because the same pattern is exactly what a genuine multi-vector attacker produces — the individual attack checks below mint the facts. |
| Database-injection structure | A request carried a genuine database-injection construct: a numeric or self-equal always-true condition, a merged query, a timing or error function, or a quote-break-and-comment. | FACT | A legitimate filter such as `type=novel and year=2024`, the word "select" in prose, or the surname `O'Reilly`. |
| Script-injection structure | A request carried a real script tag, a genuine event-handler attribute, or a JavaScript-scheme call. | FACT | HTML-escaped text (`&lt;script&gt;`), or the bare words "javascript" or "onload" in prose. |
| Path traversal | A request tried to climb out of its folder, or named a known sensitive absolute path. | FACT | A filename that merely contains dots, such as `report..2024.pdf`. |
| Line-break injection | A request smuggled a real line-break or null character, encoded or raw. | FACT | The literal hexadecimal text "0a" appearing in a value. |
| Command injection | A request carried shell substitution syntax, or a separator followed by a real program name carrying genuine command structure. | FACT | A lone `&` used as a normal address separator, or a list such as `;id=123` where the token merely matches a program name. |
| Brute force | One account accumulated many authentication failures in a window. | FACT | A forgetful user mistyping three or four times stays under the threshold. |
| Password spraying | One source failed against many *different* accounts, shallowly — the broad-and-thin pattern. | FACT | A deep attack on one account has a spread of one and does not fire here; a benign login surge is *successes*, so there are no cross-account failures. |

Two engineering disciplines make this list trustworthy.

**Every check ships with a "benign twin".** For each one, a legitimate look-alike is written
into the test suite and must produce silence. If a benign twin ever fires, the change is
blocked from being merged into the released software. These are visible in the test file:
benign colour values that resemble encoded line breaks, ordinary referring web addresses,
prose containing "use version 0a of the library", and so on.

**A fire only becomes a FACT if its certificate re-checks.** The check must fire, a
certificate must be produced, and that certificate must then re-verify — signature,
evidence fingerprint, and a fresh re-run of the named check over the embedded evidence.
If any of that fails, the result is **downgraded to a LEAD**, never silently blocked, never
silently promoted.

**Where there is no log, there is no proof — and it says so.** Four whole domains are
represented by honest placeholders that *cannot* produce a fact, by construction: outbound
command-and-control traffic, the directory/identity graph, cloud audit trails, and session
activity. No network-flow, proxy, DNS, domain-controller, cloud-audit or identity-provider
data is being read. Each placeholder returns a single lead that names the exact missing data
source and lists the detections it would provide once that data is available. The code's own
phrasing: *"a quiet plane is reported as UNMONITORED, never as SAFE."*

### Detection engineering — "would my alarms have caught this?"

A further defensive component answers a purple-team question rather than a blue-team one.
Given the actions the offensive engine actually took and proved, what evidence would those
actions have left in the logs, and would the organisation's existing detection rules have
fired?

- It reads the organisation's own rules in **Sigma**, the community-standard portable
  detection-rule format, and evaluates a well-defined subset of that format.
- It ingests the organisation's own logs offline from files: system logs in both common
  formats, ArcSight-style alert records, and Windows event-log exports. Nothing reaches the
  network; nothing touches a target.
- For every technique the current rules would **miss**, it writes a candidate rule that
  *would* catch it, in drop-in Sigma format. The stated purpose is that the organisation
  leaves the engagement with concrete detections to add, not merely a list of what got
  through.
- Everything is mapped to the MITRE ATT&CK framework — the standard public catalogue of
  attacker techniques, maintained by the MITRE Corporation, which gives every known
  technique a stable name and number so that two organisations can talk about the same
  behaviour.

Three honesty properties are built into this component:

- **It fails closed.** If a rule uses a Sigma construct this runtime does not implement, the
  rule simply **does not match**. The reasoning is written into the source: *"a false
  'detected' is worse than an honest 'unsupported → not detected', because it would tell the
  blue team they are covered when they are not."*
- **It does not claim to model any particular product.** The built-in rule set is described
  in code as "a sensible baseline of well-known detections, not a claim to model any
  specific product". In particular it does not model any specific **SIEM** — the
  security-information-and-event-management system, the central product a security team
  uses to collect logs from everywhere and run alert rules over them. Operators load their
  own rules to reflect their real environment.
- **It never produces an evasion recipe.** The package explicitly excludes a working library
  for defeating any named commercial defence product. Its output is self-assessment ("this
  action is highly detectable"), and under the adversary-emulation posture it states which
  detections fire and how loud the action was, while *explicitly refusing* to generate a
  bypass. There is one caveat the gap report itself flags: detecting the system's own
  recognisable identifying header is "a feature, not real coverage" — an organisation should
  not count that as a detection win.

---

## Part 2 — Reading The Source Code

### Why source access changes the picture

Testing a running system from the outside is like assessing a building by walking around it
and trying the doors. Reading the source code is like being handed the architectural plans.
You see rooms you did not know existed and wiring that is invisible from the street.

But plans are not the building. A door drawn on a plan may have been bricked up. This is
the central discipline of the source-review layer, and the code states it in one sentence:
*"Static analysis cannot prove reachability; the framework confirms it."* "Static" here
simply means reading the program text without running it.

### There are two different ways to point this system at a codebase

This distinction matters more than any other in this Part, because the interface offers
both and they have different trust properties.

| | **The analysis pipeline** | **The "Scan a codebase" wizard mode** |
|---|---|---|
| What it is | A fixed pipeline the product owns: pattern matching, optional deep flow analysis, a symbol map, and a conversion of findings into testable questions. | An AI agent (Strix — third-party software kept inside the product, described in chapter 2) that reads and reasons over the source with a toolbox of its own. |
| Where it runs | In the product's own process, on the analysis machine. | Entirely inside a container — an isolated, disposable copy of an operating system. It requires Docker and refuses to start without it. |
| How it is reached | The `analysis` commands (`scan`, `index`, `analyzers`, `review`). | The **Scan a codebase** option in the new-assessment wizard, or `vigil strix --target <repository or path>` from the command line. |
| What its output is worth | Leads, by design. A single deep-analysis finding can be turned into a testable question for the running system. | Leads. The deployment guide says it in one line — *"strix output is **leads, not FACTs**"* — and explains why: the machinery that turns a finding into a signed proven fact does not run over this agent's output at all. |
| What you get at the end | A merged, de-duplicated report, plus which analysers ran and which were skipped and why. | A report produced inside the agent's own sandbox. The interface says so on screen: a codebase run produces no re-checkable web report of the kind a live web assessment produces. |

Three further facts about the wizard route, all verified in the code:

- **The agent's ability to run arbitrary commands is governed, and since 12 August 2026 that
  governance fails closed.** The agent has exactly one route to a command line, and the
  product's authorisation layer classifies that one route — and only that one — as maximally
  dangerous, so each invocation of it stops and waits for a single-use, owner-signed approval
  covering that exact call. If no approval authority has been set up at all, the call is
  blocked rather than allowed through. Every other tool the agent has (thinking, notes, web
  search, patch application, reporting) is left to run freely, so the agent stays useful while
  its shell is held. This is on by default for any governed run. What changed in August is the
  failure behaviour: the wiring code previously caught *any* error while attaching the
  governor and carried on with the agent ungoverned, on the reasoning that a wiring fault
  must never stop a scan. Its replacement states the problem in its own words — the effect
  was "an UNGATED shell with NO signal to the operator — an accident, not a decision, and
  indistinguishable from a healthy governed run." A wiring failure now halts the run. There
  remains exactly one way to run ungoverned: a single named setting an operator has to switch
  off deliberately, which leaves a visible, auditable record of the choice.
- The interface **pre-checks for Docker before launching** — it looks for the Docker command
  and asks the Docker service whether it is alive, with an eight-second limit — and returns
  a plain error naming the reason rather than hanging. It also runs the agent in headless
  mode; without that flag the agent opens a terminal interface and a background launch would
  wait forever.
- The container the agent runs in carries a broad third-party toolbox of its own, including
  two well-known **repository secret scanners** (`gitleaks` and `trufflehog`, which look for
  passwords, keys and tokens accidentally committed into a code repository and its history),
  an industry static-analysis tool, a structural code-search tool, and a container/filesystem
  vulnerability scanner. Chapter 12 lists that toolbox in full. Everything those tools report
  arrives as a lead.

The rest of this Part describes the analysis pipeline.

### What files it reads

By default the pipeline walks a code tree and considers files with any of fifteen
extensions: Python, JavaScript, TypeScript (including the two React variants), Go, Ruby,
PHP, Java, Rust, YAML, Terraform, shell scripts and SQL. An operator can narrow or widen
that list per run. Two safety caps apply by default: at most 5,000 files per run, and files
larger than 2 megabytes are skipped rather than read into memory. The file list is sorted
before it is used, so two runs over the same tree examine the same files in the same order —
the same recipe, the same dish.

### Three layers of reading

The source-review subsystem runs up to three analysers over a supplied code tree and merges
their output into one report, removing duplicates.

| Layer | What it is | Available when | What each finding is worth |
|---|---|---|---|
| **Built-in pattern analyser** | A curated list of genuinely dangerous code patterns, matched line by line. Needs nothing installed and is always available. | Always | A lead. The code says why: pattern matching can see that a dangerous instruction *appears* in the file, but it cannot show that untrusted data ever *reaches* it. |
| **Semgrep, in taint mode** | An industry static-analysis tool run against a rule set shipped with the product, in *taint* mode — meaning it traces untrusted input as it flows through the program to a dangerous destination. | When the `semgrep` program is installed on the analysis machine | A stronger lead: it means untrusted input provably reaches a dangerous point, not merely that a dangerous word appeared. |
| **Joern** | A heavyweight tool that builds a full graph of the program and runs whole-program, across-function, across-file flow queries. Roughly two gigabytes and requires a Java runtime. | When Joern is provisioned separately on the analysis machine | The deepest available: cross-function flows, and languages the others handle poorly, including C and C++. |

A word that recurs in this Part: a **sink** is the dangerous destination — the point in a
program where data stops being merely data and starts having an effect, such as being run
as a command, used to build a database query, or written to a file path. "Untrusted input
reaches a sink" is the shape of almost every serious software vulnerability.

Three properties matter for procurement:

- **The product does not install these tools.** A deployment that wants deep external
  analysis provisions them on the analysis machine. This is stated in the source.
- **A missing tool is reported as skipped, with a reason.** It is never silently omitted.
  The code phrase is: *"capability degrades visibly, never silently."* There is a command
  that simply prints which analysers are available on this machine and why the others are
  not.
- **An honest comparison is recorded in the code, not just in marketing.** The Joern adapter
  notes that for typical Python web source, Semgrep's taint mode is already competitive, so
  Joern is most valuable on harder targets — native code, large cross-file flows, custom
  queries — "not as a strict upgrade on every codebase."

Every external tool is run with a fixed argument list, no shell interpretation, JSON-only
output, and a hard timeout (five minutes for Semgrep, ten for Joern). Joern is run inside a
temporary directory so that its large working output never pollutes the repository being
examined. An analyser that fails mid-run is recorded as skipped with the error; it does not
abort the whole report.

### What the built-in pattern list actually contains

Every other catalogue in this briefing is counted, so this one is too. The built-in analyser
carries **thirteen** patterns. They are deliberately few and high-signal rather than
exhaustive; the external analysers are what add breadth.

| Pattern | Plain meaning | Severity | Languages |
|---|---|---|---|
| Use of `eval` | Text is handed to the language to be executed as code. | High | Python, JavaScript, TypeScript, Ruby, PHP |
| Use of `exec` | The same idea, by the other common name. | High | Python, PHP |
| Shell mode enabled on a sub-process call | The program launches another program *through a shell*, which turns any injected punctuation into commands. | High | Python |
| Unsafe object loading (`pickle`) | Data is turned back into live objects by a mechanism that can execute code while doing so. | Medium | Python |
| Database query built by string joining | A query is assembled by gluing text together rather than by using placeholders — the classic shape of database injection. | High | Python |
| Template rendered from non-constant input | User-supplied text is treated as a page template, which lets it be evaluated rather than displayed. | High | Python |
| Configuration file loaded without a safe reader | The same object-construction risk as unsafe object loading, in a configuration format. | Medium | Python |
| Weak hash function (MD5 or SHA-1) | An outdated mathematical fingerprint, unsuitable for security use. | Low | All |
| Possible hard-coded secret | A password, key or token written literally into the source. | High | All |
| Certificate checking switched off | A network call that will accept any certificate, so the other end is not authenticated. | Medium | Python |
| Insecure transport flag in a script | The command-line equivalent of the above (`-k` / `--insecure`). | Medium | Shell scripts |
| Debug mode enabled | Development mode left on, which leaks internal detail in production. | Low | Python |
| Direct assignment of page HTML in the browser | Content written straight into the page in a way that lets injected script run. | Medium | JavaScript, TypeScript, React |

### The dataflow rules shipped with the product

When the industry static-analysis tool is present, it is run against **fourteen rules the
product ships itself**, rather than against a public rule registry that would need network
access. Each rule traces attacker-controlled input from where a web request enters the
program to a dangerous destination — which is what separates "this file mentions a
dangerous function" from "user input reaches it".

- **Eight Python rules**: operating-system command execution, database query, outbound
  request forgery, code evaluation, file-path traversal, page-template rendering, unsafe
  deserialisation, and XML entity resolution.
- **Six JavaScript/TypeScript rules**: operating-system command execution, code evaluation,
  outbound request forgery, database query, file-path traversal, and document-database
  query injection.

The rule files carry the reasoning in their own comments: *"These are DATAFLOW rules, not
pattern matches… That is the difference between 'regex saw os.system' and 'untrusted data
reaches os.system'."* They also say plainly that the source and destination lists are for
common web frameworks and should be extended per target stack — the shipped set is a strong
default, not a claim of completeness.

### The symbol index — a map of the codebase

Alongside the findings, the system can build a **symbol index**: a structured map of the
codebase rather than a list of suspicious lines. For every file it records where each
function and class is defined, what the file imports, and every place a given function is
called.

The purpose is grounding. A statement like "user input reaches a command execution" can then
be attached to *actual* places in the code where that function is called, instead of being
asserted in the abstract. The reasoning layer queries the index by kind (functions, classes,
imports, call sites), by function name, or by call site.

Two honest limits, both stated in the source:

- **It is Python-only today.** It uses Python's own built-in parser. The record shape is
  written to be language-agnostic so other languages can be added behind the same index, but
  no other language parser is present.
- **Files it cannot parse are recorded, not ignored.** A file with a syntax error or a read
  error is listed by name with the reason, and the count of files successfully indexed is
  reported alongside.

It is reached with an `index` command, which prints a summary by default and the full symbol
list on request.

### A small arithmetic helper, and what it is explicitly not

There is one further, optional piece worth naming because a technical reviewer will find it:
a bounded feasibility checker. It answers questions of the form "is there any whole-number
value that satisfies all of these conditions at once?" — for example, a validation rule says
an identifier must be between 0 and 100, and a business rule only triggers when it equals
another user's identifier: is there a value that satisfies both? A "no" prunes a dead line of
enquiry cheaply; a "yes" says a region is worth probing.

Its doctrine is written into the file itself, and it is the doctrine of the whole product in
miniature:

- It is **advisory only**. Neither answer promotes a finding, and it is explicitly forbidden
  from feeding the checker layer or the confidence calculations.
- Its **default path needs nothing installed**: when the space of possibilities is small
  enough to enumerate exhaustively — up to a million combinations — it searches them in a
  fixed order and returns an exact answer with a worked example.
- An optional third-party solver is used **only** to extend reach to spaces too large to
  enumerate. It never changes an answer the built-in search already decided.
- If the space is too large and the solver is absent, it returns **UNKNOWN** — never a guess.
- Nothing on the default assessment path uses it at all.

### From a static finding to a testable question

The payoff of reading code is not the list of suspicious lines. It is that each suspicious
line can be turned into a **falsifiable question** that the rest of the system knows how to
answer against the running application.

Each high-signal static finding is converted into a structured hypothesis with a fixed
shape: what was observed, what action would test it, what observation would confirm it,
**what observation would refute it**, and the cheapest test that could settle it. That
hypothesis enters the ordinary pipeline at status "open" and must survive execution and
adversarial critique like any other. The code is explicit: *"A seeded hypothesis is a
starting point, not a confirmed bug."*

The mapping from a built-in pattern to a weakness category is fixed and small — eleven of
the thirteen patterns map to a named weakness class (dangerous evaluation and execution
constructs map to code injection, unsafe object-loading and unsafe configuration loading map
to deserialisation, disabled certificate checking maps to improper certificate validation,
and so on). A finding from an external analyser carries that tool's own weakness identifier
instead, and where there is none it is labelled simply as a static-analysis lead.

### The automated review loop, and its honest limit

There is a further step (`analysis review`) that takes the deepest findings — the flow-based
ones from Semgrep and Joern first — and has an AI model examine the actual source lines
around each one and return confirm, object, or "more evidence needed".

**This is the one place in the source-review chain where the word "confirmed" does not mean
what it means elsewhere in the product.** Here it is a *model's* judgement over source text,
not a mechanical check over captured evidence. The command's own output comments say so:
a non-confirm decision is "the rigorous critique refusing to call a static finding proven
without a proof-of-concept. That is correct." A reader should treat the output of this loop
as a well-argued triage of leads, not as proof.

The safety rails on the loop are real and worth listing:

- Whole-tree source analysis requires an internal permission — the product's "deep static
  analysis" capability. Reading a customer's whole source tree is treated as a genuine
  capability that an unlicensed deployment should not exercise.
- The kill switch is checked **before every single model call**, so an operator can halt a
  running review instantly and persistently.
- There is a hard budget on model calls (default five), because each one costs real time and
  money.
- **The loop sends no traffic to any target.** It reads source and reasons about it.
- **Since 13 August 2026, a jurisdiction setting decides whether the model call may leave the
  machine at all** — and it is decided *before* the AI provider's software is even loaded.

That last rail deserves its own paragraph, because for an organisation with data-residency
obligations it is the one that matters most about source review: this step is the point at
which a customer's actual program text would be sent to an AI model.

The product carries four **sovereignty tiers**, an operator setting that says where a model
call is allowed to go. *Air-gapped* permits locally-run models only. *Sovereign cloud* adds
model services that run inside a defined legal jurisdiction. *Trusted cloud* additionally
allows a hosted service that contractually retains no data, and only on an explicit operator
attestation. *Permissive* allows anything. The tier is consulted at the moment the system
chooses which model to talk to, before the provider's software library is imported and
before any client is built, so under a strict tier nothing is constructed, nothing is
imported, and nothing leaves the host. Across the places where a model is called, four
separate failure paths all resolve to refusal: an unrecognised tier name resolves to the
*strictest* tier; an unrecognised model service is treated as ordinary public cloud and
refused under every strict tier; a policy that cannot be read at all refuses whenever a tier
is configured; and an error raised inside the check itself is a refusal, never a permission.
There is an optional latch that fixes the tier for the life of the process, so a later
change to the machine's settings cannot loosen it mid-run.

**The honest qualification: the shipped default is permissive.** With no tier configured, the
deployment behaves as it always did. This is a control an operator turns on, not a property
a customer gets by installing the product, and an evaluator should ask to see it set.

### Where the source-review output goes

Findings from source review do not become facts on their own. Independently of this, the
capability register records that static-analysis tools are **lead-only sources** by design:
their output can propose where to look; it can never mint a proven fact. The proof still has
to come from exercising the running system.

### The libraries the code is built from

Modern software is mostly other people's code, so reading a codebase includes reading its
list of dependencies. Here the system applies exactly the same discipline it applies
everywhere else, and the result is one of the few source-derived findings that can reach the
strength of a proven fact.

The sequence is deliberate:

1. The system parses the target's **own** dependency manifest or lock file itself.
2. It looks each pinned version up in a **pinned, dated snapshot** of the public advisory
   database — deliberately captured and version-controlled rather than fetched live, so the
   same input always yields the same answer and the data source is auditable.
3. It mints a proven fact **only** when its own deterministic comparator re-derives that the
   concrete pinned version genuinely falls inside an advisory's affected range.

The rule recorded in the capability register is blunt: a run of *any* commercial or
open-source vulnerability scanner is only a **proposer of where to look**. Its assertion that
a package matches a published vulnerability never becomes a fact on its own say-so. Because
the comparison is a pure calculation over retained data, a confirmed vulnerable dependency
**re-checks offline** from its certificate, with no network and no scanner installed.

Two honest limits are registered rather than buried:

- **An unparseable version or an unparseable range does not confirm.** It fails closed, so a
  mangled input can never fabricate a finding — and, equally, a version the system cannot
  parse is recorded as a non-assessment rather than waved through.
- **Absence from the snapshot is not absence of vulnerability.** This route may currently
  say "vulnerable"; it may not yet say "clean". Turning "no advisory matched" into a bounded
  negative requires resolving non-pinned version constraints and recording the snapshot's own
  coverage. That work is named explicitly in the register as outstanding, rather than the
  claim being quietly narrowed to hide the gap.

A related but opposite-facing subject, covered in full in its own chapter, should not be
confused with this one. Everything above is the system examining **a customer's** libraries.
The same discipline is also applied to **the product's own build and release** — the
safeguards that stop somebody tampering with VIGIL itself on its way from source code to
delivered software. Four pieces, in plain words:

- **Every dependency is hash-locked.** The list of outside libraries VIGIL uses records not
  just each library's name and version but a cryptographic fingerprint of its exact contents.
  If the downloaded file does not match that fingerprint to the byte, the build stops. It is
  the difference between ordering "one kilogram of flour" and ordering "this specific sealed
  bag, and here is its tamper seal".
- **Container starting images are pinned by content, not by label.** Software is built on top
  of a prepared base system. Naming that base by a label such as "latest stable" means the
  thing you get can change underneath you without warning. VIGIL names its base by a
  fingerprint of the exact contents instead, so it always builds on the identical foundation.
- **A bill of materials is produced.** This is a machine-readable list of every component
  inside the delivered software and its version — the equivalent of a full ingredients label.
  A customer can hand it to their own tooling and ask "does anything in here have a published
  vulnerability?" without needing VIGIL's cooperation.
- **A release gate blocks on a critical vulnerability.** Before a change can be accepted, an
  automated step scans those locked dependency lists. If it finds a vulnerability rated
  CRITICAL, the change is refused rather than flagged for later. Vulnerabilities rated HIGH
  are reported in full but do not block — the policy is written down and the reason given: a
  gate whose exception list has to grow without limit to stay green stops meaning anything.
  There are, at the time of writing, **no exceptions on that list at all**, and every future
  entry is required by a test to carry a written justification, a named reason from a fixed
  set, and the condition that should end it. The gate carries a self-test that deliberately
  fires it, so a silently broken gate cannot pass as a clean one.

**Status, stated plainly.** All four exist in the released software today. They were accepted
into the released version on 12 August 2026, and the automated build gate now runs against
every proposed change. Chapter 6 gives the detail and the honest account of what these
safeguards do *not* prove.

Three further points landed alongside them and belong here, because they are what makes the
above enforceable rather than merely present.

- **A known-vulnerable cryptography library was replaced, in both halves of the product.**
  The outside library that performs every signature and every encryption operation on the
  Python side of the system was moved past a published high-severity vulnerability; the change
  was accepted on 12 August 2026, in the offensive engine, the shared core and the sovereign
  half alike. A security product that lags its own cryptography library is in no position to
  lecture anyone about dependencies.
- **The gate is a required check, not an advisory one.** The repository's main branch is
  protected, and nine automated checks — including the supply-chain gate — must pass before a
  change can be merged. Rewriting or deleting the branch's history is disabled. Three honest
  gaps go with that, and an evaluator should be told them rather than left to find them:
  repository administrators are **exempt** from the required checks; independent review of a
  change by a second person is **not** required by the configuration; and commit signatures
  are **not** required. The checks are real; the human process around them rests on the
  operator's own discipline.
- **The two subsystems described in this chapter are now covered by those checks.** Until
  13 August 2026, eight areas of the codebase had test suites that were never run by the
  automated build — among them the source-analysis subsystem described in this Part and the
  detection-engineering subsystem described in Part 1. Both now run on every proposed change.
  The way that was done is itself the point: a test path that matches no files at all leaves
  the build green and the log looking like coverage, so the build first runs each newly added
  path in a mode that only *collects* tests, treats "collected nothing" and "path does not
  exist" as hard errors, and prints the count each path actually contributed. Coverage that
  cannot be counted is not claimed.

---

## Part 3 — Producing And Verifying A Fix

### The rule that governs everything else

**Only proven problems are eligible for an automatic fix.** This is enforced twice over: at
the data-type level, so a "confirmed" finding without a signed evidence reference cannot even
be constructed from a file; and again at the moment a fix is requested. The code phrase is
blunt: *"A LEAD can never trigger a codefix."*

There is a second gate on where the finding came from. The fix command refuses to accept a
finding handed to it as ordinary data. It accepts exactly one of two things: a
**cryptographically signed sealed record**, verified under an owner-signed delegation; or a
finding **rebuilt from the engagement's own signed, tamper-evident log** after a fail-closed
integrity audit. The rule in the source: *"A raw-JSON finding is never accepted."*

### The ladder, and the permission each rung needs

The fix pipeline is a ladder of stages, and each rung sits at a different permission level.
The last rung mentions a **proposed code change** — the ordinary way software teams make
changes, where an author raises a change for colleagues to review and approve before it
becomes part of the real software. (Software teams call this a "pull request".)

| Stage | What happens | Permission level |
|---|---|---|
| Clone and branch | A **disposable copy** of the repository is made. The organisation's actual source tree is never touched. | Reversible internal action — automatic |
| Edit | The proposed change is written into the disposable copy. | Externally visible / semi-reversible — queued for a human |
| Build | The patched copy is compiled and tested inside an isolated sandbox. | Destructive tier — explicit approval required |
| Raise a proposed code change | A real change proposal is raised against the real repository. | Destructive tier **plus** a multi-signature quorum that must include the owner |

Two design choices deserve highlighting, because they are inversions of what the
open-source component this was adapted from originally did.

- **A timeout rejects.** In the original, an edit that received no human answer within
  five minutes was **automatically accepted**. Here, a timeout, a rejection, a modification,
  a missing approval mechanism, or an error in the approval path all **reject**. Only an
  explicit approval applies an edit.
- **It never stages everything.** Only explicit, path-validated files are committed. A
  wildcard path is refused, and an empty set of edits never raises a change proposal.

A third property was added on 13 August 2026, and it matters to any organisation that cannot
let its source code leave its own premises. The step that comes before the ladder — proposing
the fix in the first place — is a call to an AI model, and what that call carries is **real
source text from the organisation's own repository**. It now passes the same jurisdiction
check described in Part 2: the sovereignty tier is consulted before the model provider's
software is loaded and before any client is built, so under a strict tier no client exists and
nothing leaves the machine. A refusal degrades to "no proposal" — exactly as a missing key to
the model service already did — rather than to an unguarded call, so the loop still finishes
cleanly and never patches on a refusal. The same honest qualification carries over: the
shipped default is permissive, so this is a control an operator sets.

Every action is recorded with the sensitive arguments scrubbed out, so no credential ever
reaches the audit trail, and stage numbering comes from a counter rather than a clock, so
the same inputs produce the same record.

### What is fully working, and what waits on the customer

This is a place where honesty matters more than enthusiasm.

- **Working today.** Proposing a fix; applying it into a disposable clone; building it in a
  sandbox; and verifying by re-test (described in Part 5). With every optional leg switched
  off, a run is a **non-destructive, propose-only dry run**. The button in the interface is
  labelled "Apply fix (gated)" and its own hint states: *"Non-destructive — never opens a
  PR."* The interface literally has no route that can raise a change proposal.
- **Built, but not yet exercised for real.** The leg that raises an actual change proposal
  against a real repository is **off by default** and requires all of: a signed
  authorisation, a trust anchor, at least one mandatory signer including the owner, a durable
  single-use ledger so that one authorisation can produce exactly one request, and a
  repository access token in the environment. Live use of this leg requires the operator to
  first provision the multi-signature keys. Until they do, this is a **capability, not a
  completed field deployment**, and should be described that way.

There is one more honest note the project caught in its own review and wrote down: the
command that mints a destructive authorisation writes its output file in a way that
overwrites any earlier file at that path. Single use is enforced downstream by the ledger
that the change-proposal leg checks, not by that file write.

---

## Part 4 — Encrypted Connections, Certificates, And Network Manners

### What is being talked about

When a browser shows a padlock, the connection is protected by **TLS** — Transport Layer
Security, the modern standard for encrypting traffic between a browser and a server. Its
obsolete predecessor was called **SSL** — Secure Sockets Layer — and many people still say
"SSL" for both. Behind the padlock, two separate things have happened. First, the browser
and the server agreed on a **protocol version** and a **cipher suite** — the rules and the
mathematics they will use to scramble the conversation. Second, the server presented a
**certificate** — a signed document asserting who it is.

Both can be wrong in ways that matter, and they fail differently. An old protocol version or
a broken cipher means the conversation can potentially be read or altered by someone in the
middle. A certificate signed with a broken mathematical fingerprint means the identity
assertion can potentially be forged.

### How the system checks the connection

The system does not take a scanner's word for it. It **performs its own handshake**: one
bounded attempt, with a hard timeout, through exactly the same audited permission chain used
for any other network contact — stop switch, single named host, active-reconnaissance
permission, then the written scope of the engagement. It then keeps the two facts the server
actually agreed to (the protocol version and the cipher name) and judges them with a
mechanical check.

Because the retained evidence is a small, plain record, a confirmed weakness **re-checks
offline** from its certificate later, with no network at all. The endpoint really did agree
to that protocol and that cipher, and the record proves it.

A refused or failed handshake returns an honest "not connected" with a reason. It never
raises an error and it never invents a negotiation.

**Deprecated protocols that cause a confirmed finding** (confidence 0.95):

| Protocol | Why |
|---|---|
| SSL 2.0 | Long obsolete and fundamentally broken. |
| SSL 3.0 | Broken (the POODLE class of attacks). |
| TLS 1.0 | Deprecated by every standards body and card-payment rule. |
| TLS 1.1 | Deprecated. |

**Weak cipher constructions that cause a confirmed finding** (confidence 0.92).

The table below lists the specific names the system looks for. **A general reader does not
need to recognise any of them** — they are the trade names of encryption methods that were
once standard and are now known to be breakable. What matters is the shape of the rule: the
system does not guess, and it does not object to modern encryption. It reports a weakness
only when the server *actually agreed* to use one of these, in a real connection the system
made itself and kept a record of. Three deserve a plain word each: `NULL` means no
encryption at all; the anonymous family means the server does not prove who it is, so anyone
can stand in the middle; and `EXPORT` refers to encryption deliberately weakened to comply
with 1990s export law.

| Marker in the cipher name | Plain reason |
|---|---|
| `RC4` | Statistical biases in the keystream allow recovery of data. |
| `RC2` | Broken. |
| `3DES` / `DES-CBC3` | The Sweet32 class of attacks against 64-bit block sizes. |
| `DES-CBC` | Single-DES: a 56-bit key, trivially breakable today. |
| `EXPORT` / `EXP-` | Deliberately weakened 1990s "export-grade" cryptography. |
| `NULL` | No encryption at all. |
| `ADH` / `AECDH` / `ANON` | Anonymous key exchange — no authentication, so anyone can sit in the middle. |
| `MD5` | The message-integrity function is broken. |
| `IDEA` | Deprecated. |
| `SEED` | Deprecated. |

Those ten rows cover **fourteen** distinct names the system looks for, because several rows
carry more than one spelling of the same construction.

A strong, modern handshake does **not** produce a finding. Good posture is not reported as a
problem.

### How the system checks the certificate itself

A certificate can be examined entirely offline, from a file. Two conditions produce a
confirmed finding:

| Condition | Plain meaning | Confidence |
|---|---|---|
| **Broken signature hash** — MD2, MD4, MD5, or SHA-1 | The mathematical fingerprint used to sign the certificate can be forged by an attacker who can produce a collision — two different documents with the same fingerprint. There is no legitimate reason to sign a certificate this way today. | 0.95 |
| **Undersized public key** — RSA or DSA below 2048 bits, or an elliptic curve below 224 bits | In plain terms: the lock is too small. The numbers are the minimum key sizes every standards body has required since 2013, and a key below them can be broken by an attacker with enough computing power — which means the certificate's identity claim can be forged and the traffic it protects decrypted. | 0.90 |

Modern certificates — SHA-256 or better, a 2048-bit RSA key, a P-256 curve, or an Ed25519
key — do not fire. The check is written to avoid the classic mistake of matching "SHA-1"
inside "SHA-256"; a deliberate guard prevents it. Certificate bundles are handled one
certificate at a time, so a weak *intermediate* certificate in a chain is judged too.

Certificates can be ingested from a local file or a directory of files, with **no network
contact at all** — a live scan is a separate, separately permissioned activity.

### Why certificate validation is deliberately switched off for one specific probe

This looks alarming out of context, so it is worth stating precisely.

For the *crypto-posture probe only* — the handshake whose sole purpose is to discover what
protocol and cipher a standard client would be given — the system deliberately turns off
hostname checking and certificate-trust validation. The reason is documented in the source:
this probe is a measurement of what the server negotiates, **not a trust decision**, and it
must therefore work against self-signed certificates and internal endpoints. If it validated
trust, it would simply refuse to measure exactly the internal systems most likely to have a
weak configuration.

Even with validation off, the certificate the server presented is still retrieved and judged
by the certificate check above.

In the reading done for this chapter, exactly three places in the engine's own code switch
certificate validation off, and all three are **measurement probes pointed at the target**:
this crypto-posture handshake, the quantum-exposure probe described below, and a WebSocket
connection check. (Two older stand-alone probe scripts shipped alongside the engine do the
same, and are likewise target-facing.) The WebSocket check is the clearest illustration of
the discipline: when it runs over an encrypted connection it *records in the finding itself*
that the other end's identity was not validated, and it refuses to call the result a
confirmed session hijack without a genuine authenticated session.

**Elsewhere, validation is required rather than disabled.** One family of cloud capabilities
described in other chapters proves that a credential really worked — that it was accepted by
the provider as a live identity. The step that collects that evidence must report that
certificate checking was on, that nothing sat in the middle of the connection, and that no
redirection was followed — and the checker that judges the result **requires** all three
before it will confirm anything. Evidence gathered over a sloppy connection cannot become a
proven fact. The two settings are opposites for good reasons, and both are written down.

### The real network binding, and the first run against a real outside provider

That requirement was enforced from the day it was written, but until 13 August 2026 it had
never been exercised, because **the only things that had ever supplied those connection facts
were stand-ins written for the tests**. The code that actually makes such a request — the piece
that joins these cloud capabilities to a real network — did not exist. The module that closes
the gap says so in its own opening lines: that absence is "exactly why no [cloud] runner had
ever fired against a real provider."

The rule the new code holds itself to is one sentence: **every connection fact is derived from
the connection, never asserted.** Concretely:

- "Certificate checking was on" is recorded only when the request was over HTTPS, the
  connection genuinely carries an encrypted session, that session yields a peer certificate at
  all (which it does not unless the chain was validated), and the client's own settings are
  genuinely in verifying mode. Any step that cannot be established records the negative.
- "Nothing sat in the middle" is recorded only when the client can be *affirmatively shown*
  unable to route through an intermediary — it was built ignoring the machine's ambient proxy
  settings and carries no intermediary of its own. If that cannot be shown, the record says an
  intermediary was possible, which is the answer that makes the checker refuse.
- "No redirection was followed" is guaranteed by construction: the client does not follow
  redirections, so a redirect is *reported* rather than obeyed.
- The other end's address is read **from the live socket carrying the response**, not looked up
  again afterwards. A later lookup can return a different address from the one the bytes
  actually came from, which would be evidence about the wrong thing.
- The response is read up to a fixed limit. A response over that limit is marked truncated and
  is **not** parsed, so a partial — and therefore unsound — identity answer can never reach a
  checker.

The discipline is that **no field ever falls back to the permissive value**. A missing
connection, an error while inspecting it, an unencrypted address, an over-long response: each
degrades to the value that makes the checker refuse, never to the one that lets it confirm.

**And one of these capabilities has now been exercised against a real third party.** On
13 August 2026 the exposed-credential capability — "this leaked secret is not merely
well-formed, it is *valid*" — was run against the real GitHub API. Four things happened in the
same run, and the three that did *not* confirm are the ones worth reading:

| What was tried | What happened |
|---|---|
| The operator's own genuine credential, against the operator's own least-privileged identity address | **Confirmed**, and the signed certificate re-checks offline |
| A bogus credential of the same *shape*, sent live to the same real address | GitHub itself answered "unauthorised" — correctly left an unproven lead. Structure is not validity, and here that is measured against the real provider rather than assumed |
| The same confirmed capture, with the address that would confirm it swapped for an attacker's host, and again for a near-identical lookalike name | Not confirmed. If any address could confirm a secret, anyone who controlled an address could manufacture facts. The collecting step separately refuses to send a live credential anywhere but that credential type's own confirming address, so the credential is protected as well as the verdict |
| The same capture where the credential and the confirming call carry *different* fingerprints — "some other secret authenticated" | Not confirmed |

The credential was piped into the harness on standard input from the operator's own logged-in
session. It is never written to a file, never placed where a process listing would show it, and
never put into the environment; the harness asserts it appears in neither the capture, nor the
evidence, nor the signed certificate. The harness asserts every one of its expectations and
exits with a failure code on any deviation, and a third party can re-run it on their own
machine with their own account. That last property is what makes this a re-checkable claim
rather than a demonstration.

The same run also exercised the two gates that sit in front of any such capture, in the
direction that matters: with the stop switch tripped, and again with the target ruled out of
scope, the run **refused and produced no capture at all**. That is the design point stated in
the source — a refusal leaves nothing to adjudicate, so there is nothing that could later be
laundered into a fact.

**What that run does not cover, stated exactly.**

- **Only the GitHub row.** The Amazon Web Services row of the same capability is built and
  unit-tested — its request-signing code was checked against Amazon's own independent
  implementation — but has **never** been exercised against real AWS. It still needs a real,
  operator-provided access key, and **nothing about the GitHub run transfers to it.**
- **Not credential types outside the two it recognises**, and **not a hunt for exposed
  credentials** across a customer's estate: the harness validates a credential the operator
  handed it, it does not go looking for one.
- **The two gates were harness-supplied stand-ins, not a signed engagement charter.** The
  permitting and scope objects in that run were written into the harness, and the harness says
  so in its own comments. Their *refusing* behaviour was genuinely exercised, as just
  described, so the seam is proven to bite — but a signed charter was not loaded, and nobody
  should read this run as proving the charter machinery end to end.

The sibling capability — proving a credential was taken from a cloud machine's own credential
service — remains where the rest of this briefing places it: the detection logic, the evidence
handling, the certificates and the safety gates are **built and proven against recorded sample
data**, and it now has a real network binding underneath it, but it has **not** been pointed at
a live cloud account. That waits on the customer supplying their own cloud credentials — a
thing only the account holder can supply, and which the system is deliberately built not to
obtain any other way. Calling it unfinished understates the system; calling it field-proven in
a customer's cloud overstates it.

### An identity that survives certificate renewal

The system also records a fingerprint of the **public key** the endpoint actually presented,
rather than of the whole certificate. This survives a certificate being reissued with the
same key, and changes the moment the key changes. The source calls it *"a sound observed-key
identity for a target — stronger than a producer-asserted host string."* In plain terms: it
is a way of saying "this is the same machine" that does not depend on anyone's paperwork.

### Quantum-era exposure

There is a separate, honestly-named capability that reports how exposed an endpoint's
encryption is to a future quantum computer. **Nothing here runs, simulates or requires a
quantum computer.** The name describes the threat, not the hardware.

The concern is specific and worth stating in plain terms. The mathematics that protects
almost all traffic today would be broken by a large, fault-tolerant quantum computer. No such
machine is known to exist. The risk that exists *today* is therefore "harvest now, decrypt
later": an adversary records an encrypted conversation now and decrypts it years later once
such a machine exists — but only if the **key exchange** that protected that conversation was
of the classical kind. Signatures are a different matter: a forged signature has to be
produced live, so it is a future-authentication risk rather than a recording risk. The
component classifies both, and the report distinguishes them.

Its honest limit is written into the source in the same breath. The standard library this
runs on cannot offer post-quantum key groups and does not report which group was chosen. So
the probe can prove a server **accepts** a classical, quantum-vulnerable key exchange with an
ordinary client — it **cannot** prove the server lacks post-quantum support for clients that
can ask for it. When the classification has to be inferred rather than read directly, the
report says so in the finding itself.

### Binding evidence to the target's own connection — a capability, honestly labelled

There is one residual limit this briefing states repeatedly: re-running a check over retained
evidence proves the verdict follows from that evidence, but not that the evidence truly came
off the wire from the target. A dishonest producer could in principle fabricate a response
the target never sent.

The product contains a built and tested mechanism aimed squarely at that gap. It ties a
finding's response bytes to **one specific encrypted session** with the target — using the
standard key-material export that a TLS session can produce — and has a notary key co-sign
the pair of "this session" and "these exact bytes". A standalone verifier, given the notary's
public key supplied out of band, then checks offline that the carried bytes hash to the bound
value and that the co-signature is genuine. Bytes from a different session, different bytes,
or a missing co-signature are rejected, without trusting the producer at all.

**The status must be stated carefully, and the source states it carefully itself.** This is a
**capability**, not an achieved proof of unforgeability. The notary here is software that the
product itself runs, so the product could in principle hand "its own" notary a fabricated
pair. What is proven is the *mechanism and the verifier shape*. Genuine unforgeability needs
two things this environment does not have: a toolchain in which the notary participates in
the encrypted handshake itself, and a notary operated by a genuinely independent third party.
The source names both, names the specific missing toolchains, and explicitly forbids
upgrading the claim. A place-holder for the third-party notary marks the seam.

### Honest limits on the TLS work

- The connection check is **scoped to what a modern client still negotiates**. It does not
  enumerate every legacy cipher suite a server might accept if asked differently. This limit
  is written into the capability register, not buried.
- TLS is, however, one of only **six** evidence routes in the whole system currently
  permitted to say **CLEAN** — a channel-confirmed negative. A completed handshake with a
  modern protocol and cipher genuinely refutes the claim "this endpoint negotiates weak
  cryptography", for that endpoint, at that time. Like a roadworthiness certificate, it says
  the vehicle passed on that date — not that it is safe forever.
- Certificate **expiry** monitoring exists, but on the other side of the product. The
  sovereign personal-assistant half includes a defensive monitor (`BASTION`) that checks
  certificate expiry, dependency exposure, and uptime — over an **allow-listed inventory of
  the owner's own assets only**. Any target not on that list is refused and the refusal is
  recorded. It performs no exploitation and no port sweeping, and it flags a vulnerable
  dependency only when the parsed version provably falls inside a published advisory's
  affected range; a version it cannot parse is recorded as a non-assessment, never as an
  invented vulnerability.

### How the system's own traffic behaves

This is the part that distinguishes an authorised assessment tool from an intruder's
toolkit. The governing instruction in the project's operating doctrine is that the system
should be **correlatable, not stealthy** — the customer must be able to search their own
logs and find every request the tool made.

**A recognisable identity on every request.** The system sets a distinctive identifying
header — the short text every web client sends to say what it is:

| Posture | Identifying header | Intent |
|---|---|---|
| `TEST` (the default) | `OBSIDIAN/1.0 (authorized owner-test <date>)`, optionally with an operator label | Full footprint is intended and wanted. |
| `AUDIT` | The same, plus `control-test` | Moderate pace, still fully identifiable. |
| `EMULATE` | A realistic browser string | Only when the customer has explicitly asked to understand how an adversary would appear in their logs. |

**Deliberate pacing.** Rate limiting is tied to the same posture:

| Posture | Minimum gap between requests | Jitter | The same figure as a rate |
|---|---|---|---|
| `TEST` | 0.2 seconds | none | 5 requests per second |
| `AUDIT` | 1.0 second | none | 1 request per second |
| `EMULATE` | 5.0 seconds | up to 3 seconds | about 0.2 requests per second |

(The right-hand column is there because chapter 11 states the same three postures as *rates*
rather than as *gaps*. The numbers are the same numbers; only the presentation differs.
Chapter 11 also calls the first posture "aggressive" where this chapter calls it `TEST`.)

The initial passive fingerprinting pass is stricter still: a hard cap of 50 requests, a
0.3-second delay, no concurrency, and it never logs in, submits a form, fuzzes, or scans.
Every request is written to the engagement log.

**Six gates before any request leaves.** Every action from the live executor passes, in
order: the charter-signature check, the scope check, an explicit human confirmation for
anything destructive (which **defaults to deny on timeout**), the per-engagement request
budget, the pacing limit, and the identity header. None is bypassable without changing code.
If a gate refuses, the refusal itself is recorded as evidence that the framework chose not to
act.

### The manual replay tool

An operator sometimes needs to take one captured request, change something in it by hand,
and send it again. That is the single most dangerous thing an operator can do manually, so
the product ships it as a governed capability rather than as a raw utility. Inside the
product it is called the **Repeater**.

- It never opens a raw network connection of its own. Every replay is routed through the same
  gate chain as everything else.
- It requires the offensive-tier execution permission, and it is scope-checked **twice** —
  once by the caller and again by the executor. An out-of-scope target is refused and nothing
  is sent.
- It fails closed: a tripped kill switch, a missing permission, an out-of-scope target or a
  declined destructive confirmation all refuse the replay, and **every refusal is recorded as
  evidence**.
- It **strips any operator-supplied identifying header and forces the recognisable one back
  on**. The comment in the source reads: "CORRELATABLE, NOT EVASIVE". An operator cannot
  quietly disguise the tool's traffic through this route.
- A captured response is a labelled observation, never a fact. It becomes a finding only when
  a mechanical check re-verifies it.

### The system's own outbound connections

A reviewer will reasonably ask the mirror-image question: when the system itself reaches out
to the internet, how careful is it? The honest answer, verified by reading the code for this
chapter:

- **It reaches out to very few places.** Four public look-up services used for passive
  research about a target (a DNS-over-HTTPS resolver, a certificate-transparency log, a
  domain-registration lookup, and a network-numbering statistics service); whichever AI model
  provider the operator has configured; and any endpoint the operator explicitly configures,
  such as their own timestamping or witness service.
- **The look-up services are addressed over HTTPS at fixed, allow-listed hostnames**, and the
  transport refuses to be constructed at all if that allow-list overlaps the engagement's
  target scope — a research source may never be pointed at the target itself. Any address not
  on the list is refused before a single byte leaves the process.
- **Certificate checking is left on.** These calls use the standard clients at their default
  settings, which verify the server's certificate and hostname. In the reading done for this
  chapter, no outbound call in the engine's own code disables that; the only three places
  that switch it off are the target-facing measurement probes named earlier, and each records
  that it did.
- **The AI-provider endpoint is validated, not merely accepted.** For the Azure-hosted
  provider, for example, the operator-supplied endpoint must be HTTPS, must end in that
  provider's own domain, and must carry no embedded credentials — a deliberately strict check
  written to defeat lookalike addresses. The Mistral provider defaults to that vendor's own
  HTTPS endpoint.
- **One honest exception, deliberately allowed.** An operator running their *own* model server
  may configure a plain, unencrypted local address. The source says why in its own comment:
  for a server on the same machine or the same private network, plain local traffic is normal,
  so encryption is not forced there. It is a local-server allowance, not a general one.

### Where a packet may go

Two independent layers enforce this, and they share a single list so they cannot drift apart:

- A **permanently forbidden list** that no engagement document can ever re-enable: the
  loopback range, the link-local range (which includes the cloud instance-metadata address
  `169.254.169.254`), the reserved and test ranges, multicast, and all their IPv6
  equivalents. Addresses that wrap an IPv4 address inside an IPv6 form are unwrapped and
  re-checked, so a disguised metadata address cannot slip through. The stated reason: a
  document listing these "is far more likely to be an injection or a mistake than a real
  intent to let the agent read the host's cloud credentials."
- A **conditionally forbidden list**: private corporate ranges, denied unless the exact
  resolved address appears in the authorised list.

Enforcement happens at two levels. At the network level, a firewall drops everything from
the sandbox except two destinations — the filtering proxy and the resolver — so an agent
that unsets its own proxy setting gains nothing; the packets are dropped by the host. At the
application level, a filtering proxy that runs *outside* the sandbox's control resolves each
destination **once**, refuses the whole connection if **any** returned address is on the
forbidden list (which defeats an answer that mixes a public and an internal address), and
then pins the connection to that exact verified address so it cannot be switched between the
check and the connection. Refusals are logged so the operator can correlate them.

### The stance on web firewalls

The system contains a bypass search — but it is framed and bounded as a verification aid, not
a weapon. It is off by default and opt-in per engagement; every request still goes through the
gated executor's budget and pacing; and a bypass that does not then trigger a real mechanical
check is not a finding at all, so precision is unaffected. The source states the purpose: to
prove a filter is bypassable, "not an escalation weapon". The coverage scheduler carries an
even blunter statement: *"This is not an evasion engine. It explores the target's response
behavior; it does not hide from a defender, rotate identity, or shape traffic to evade
detection."*

---

## Part 5 — Proving A Fix Actually Worked

### Why "we fixed it" is not evidence

After a report is delivered, the usual sequence is: the engineering team makes a change, the
ticket is closed, and everybody assumes the problem is gone. Sometimes it is. Sometimes the
change addressed a symptom, or a different code path was missed, or the deployment did not
reach the affected server.

The system replaces the assumption with a test. The principle is stated in the source: *"the
exploit that provably worked is now provably dead."*

### The method: silence, under control

The method is deliberately simple. Take the **original** check — the exact one that proved
the problem — and re-run it against **freshly captured** traffic from the patched system. If
it fires, the problem is still there. If it goes silent, the problem may be fixed.

The word "may" is doing real work, and this is the smoke-detector problem: a smoke detector
that is silent because the fire is out and one that is silent because its battery is dead
sound exactly the same. Silence has many causes that are not a fix:

| Reason for silence | Is it a fix? | The control that catches it |
|---|---|---|
| The system was down or unreachable | No | **Liveness** — the target must have genuinely answered during this run |
| An old cached response was replayed | No | **Freshness** — a fresh, unpredictable marker must be echoed back by the target during this run |
| The endpoint was moved or deleted | No | **Scope equivalence** — the same surface, same parameter, same check family |
| The problem is intermittent and simply did not appear | No | **Repetition** — several consistent silences, not one |
| The check itself was changed or broken | No | **A positive control** — the same check must still fire on known-vulnerable reference evidence, proving the test apparatus is alive; and a version fingerprint of the check is pinned from the original proof |

The liveness control is measured only on fields the **target itself produced**. Fields the
testing tool set are explicitly excluded, so the tool cannot satisfy its own control.

### The four possible answers

The result is always exactly one of four, and — this is important — **all four are signed**,
so an inconclusive reason cannot be stripped off and re-read as a success.

| Answer | Meaning |
|---|---|
| **REMEDIATED** | Under the recorded authorisation, identity, freshness, control and observation conditions, the original check did not reproduce across the required number of trials. |
| **STILL_VULNERABLE** | The original check fired again. It is not fixed. |
| **INCONCLUSIVE** | Testing happened, but the negative claim was not earned — a control failed, freshness was not established, the target's identity changed mid-run, or there were too few valid trials. |
| **REFUSED** | Testing must not begin at all: authorisation failed, or this mode cannot certify this family of check. |

The distinction between the last two carries real weight and is called out in the source:
REFUSED means *we were not allowed to look*; INCONCLUSIVE means *we looked and could not
tell*.

The default requirement is **three valid trials** for the families that can be certified this
way.

### Where silence is sound, and where it is explicitly not

Silence is only meaningful for certain families of check. The system holds a fail-closed
allow-list of exactly **13** kinds for which a silent re-run is a sound negative. In plain
English they are: error signature, side effect, differential response, boolean inference,
reflection context, DOM execution, evaluation, achieved state, predicate, out-of-band
callback, and the three request-parsing break-out tests (database, operating-system command,
and document-database). Chapter 6 describes what each of these families proves.

Everything else is excluded, each with a written reason:

| Excluded family | Reason recorded in code |
|---|---|
| Timing, credential stuffing, prompt injection, system-prompt disclosure | These are statistical tests, or they rest on an AI model's own variable output. A sound "it stopped" rule for a statistical detector is a separate piece of mathematics that has not been implemented, so the system refuses rather than guesses. |
| Memory-error sanitiser signals | One sub-case — a thread data race detected at run time — is not reliably reproducible, so the whole family is excluded as unaudited rather than partly trusted. |
| Version range, privilege path, all posture families, single-sign-on forgery, automated access | These are offline or configuration judgements, not a live re-test with a freshness marker. They are outside this mode's scope. |
| Service reachability, active exposure, TLS weakness | Connection-level classes whose liveness control has not been soundly defined yet. Excluded until it is. |
| The cloud and Kubernetes achieved-effect families — metadata-credential capture, exposed-credential validity, service-account impersonation, permission escalation, Kubernetes permission grant, anonymous reachability | No family-specific reason is written for these, and that is the honest description: they are simply not on the closed allow-list, so they land in the same catch-all refusal as anything unaudited, and the code returns its generic "not a sound negative" note. A sound rule for "this credential no longer works" or "that permission grant is gone" is a separate piece of reasoning nobody has done. |
| Races, timing desynchronisation, request smuggling | Genuinely non-reproducible phenomena: a real vulnerability may simply not manifest on a given attempt, so "silent across N attempts" is unsound. |
| Any unrecognised family | Fail-closed. |

The cloud and Kubernetes row is worth pausing on, because it shows the allow-list working in
the direction that costs the vendor something. Six confirmations for cloud and Kubernetes
attacks were added to the offensive engine on 12 August 2026. **Not one of them was added to
this allow-list**, so not one of them can currently produce a "the fix worked" verdict from
silence — checked directly for this chapter, family by family. The allow-list is closed, so
the new families fell straight through to the refusal branch, which is what fail-closed means
when it is real rather than decorative. A vendor optimising for the demonstration would have
widened the list; widening it would have been a claim nobody had earned.

Two further conditions are written into the code as load-bearing and must not be relaxed:
the differential-response family qualifies **only** because no certifiable class currently
attaches a *latency* comparison — if one ever does, silence becomes unsound for it; and the
boolean-inference and callback families qualify **only** because a mandatory positive-control
fire first proves the round budget was adequate.

### The freshness gradient, and why a fix caps below the top

The system grades how strongly a fresh observation is tied to the vulnerable code path.

- **Level F1** — the target answered during this run and echoed the run's fresh marker. It is
  alive and responsive right now.
- **Level F2** — the fresh marker came back *through the vulnerability's own channel*.

A **still-vulnerable** verdict can reach F2: if the check fires and the fresh marker appears
inside the very error line that constitutes the firing signal, the marker travelled the same
path the proof did.

A **remediated** verdict is capped at **F1**, permanently and by design, and the reason is
elegant: once the vulnerable code path is removed, it cannot carry anything, so there is no
way for a marker to travel through it. As the source puts it, *"a fixed sink's traversal is
unprovable"* — once the dangerous destination is gone, nothing can be shown to have reached
it. A verifier that insists on F2 for a remediation therefore receives **INCONCLUSIVE** —
never a falsely strong "remediated".

The residual risks of an F1 remediation are written down rather than hidden. An F1
remediation does not, by itself, distinguish a genuine fix from (a) a web firewall that
blocks the exploit's characteristic characters while still passing a benign probe, or (b) a
dead origin server behind a gateway that echoes the marker. The differential channel — the
second live re-test method — attacks exactly this problem by sending four probes per round
that are deliberately *identical in attack characters* and differ only in a data-dependent
condition the database must evaluate, so a content-inspecting firewall that blocks one blocks
all of them.

### What comes out at the end

- A **remediation certificate** that pairs the negative with the positive. It references the
  signed certificate of the original proof, so a reader sees the whole life cycle —
  "exploitable, then remediated" — bound together in one artefact.
- Verification of that certificate independently re-derives the answer in three steps:
  re-run the check over the retained patched evidence and require silence; check that the
  evidence fingerprint matches the signed record; and check the signature against a pinned
  public key. All three must hold.
- A **stand-alone verifier** that a third party can run with **zero product code installed**.
  It imports only the Python standard library and one cryptography library, and
  re-implements every byte format from the published specification rather than by importing
  the producer. A test in the repository proves it agrees byte-for-byte with the in-house
  verifiers on real artefacts and on a whole battery of deliberate tampering. It is
  verification only: it contains no offensive capability, never writes, and never contacts
  anything.[^verifier]
- **Its documented boundary.** For general check bodies, this stand-alone verifier does *not*
  re-run the check — that requires the check's code and is the product's own job. What it does
  check standalone is authenticity, cross-binding, evidence fingerprints, the append-only
  chain, the anti-rollback floor, the witness quorum, and the time bound. A single flipped
  byte anywhere flips the verdict to NOT SOUND. There is one exception: the posture family's
  checks are pure offline functions, and those the stand-alone verifier *does* re-run, with a
  parity test pinning it to the in-house version.

[^verifier]: The stand-alone verifier is `docs/proof-carrying-finding/verify_vf.py` in the
repository.

### Watching for regression over time

Two further mechanisms address the "it was fixed, then it came back" problem.

**Drift.** The system can compare the **proven-fact set** of two runs. A fact that newly
appears is a regression — a new exposure. One that disappears is a fix. The honesty rule
here is exact: only a finding whose retained evidence **still re-fires** counts as a proven
fact and may enter the comparison. A finding that is merely listed, or whose certificate no
longer reproduces, is excluded. So the comparison cannot manufacture a regression out of a
lead, a heuristic, or a tampered certificate. The comparison itself is a pure set difference
with no clock and no randomness, so the drift result re-verifies too. It can be wired into a
build pipeline as a regression gate that fails the build on any change to the proven set.

**Continuous re-proof.** There is a service that loops the four-answer live re-test on a
schedule and appends signed, independently co-signed entries to a tamper-evident log, so that
"continuously re-proven" becomes a property of a running system rather than a slogan.

What is actually shipped, so an operations team can see what they would deploy: a one-shot
runner (`vigil reprove --once`) that performs exactly one re-proof cycle, and a pair of
scheduled-job definitions for the standard Linux service manager — one that runs that cycle
and one that fires it on a cadence (every six hours by default, catching up after the machine
has been off, with a small random spread so many hosts do not fire at once). A matching pair
exists for the posture certificate, at a thirty-minute cadence by default. The service
definition is deliberately hardened: it may write only inside the engagement's own directory,
gains no new privileges, and network access is left on precisely because the re-proof has to
re-drive the live target.

The status of this last item must be stated carefully, and the product states it carefully
itself, in both its command help text and the comments inside the scheduled-job files: the
loop, the one-shot runner and the schedule definitions are **built and deployable**;
"continuously re-proven" becomes an **operating property once the schedule is enabled on a
host** — until then it is honestly a **capability**. The timer file adds its own honest
residual: freshness is only ever as current as the last time the schedule fired, so
"continuously re-proven" means "re-proven on this cadence", not "provably true at this
instant".

---

## What A Reviewer Should Take Away

The table below is a summary; the detail behind each cell is in the Part above.

| Area | Fully working today | Built, awaiting something from the customer or the world | Deliberately not attempted |
|---|---|---|---|
| **Defensive firewall (AEGIS)** | Watch-only and enforcing modes; seven proof-backed inline block classes; graduated soft responses; certificates that re-check offline; kill switch; three integration routes with a stated detection set each; a frozen fifteen-checker fallback and two name-pinned build tests, so growing the offensive engine provably cannot change what the firewall blocks | Enforcement in a governed deployment needs the internal blocking permission granted, otherwise it downgrades to watch-only and says so | Blocking server-side request forgery, XML external entity attacks, or error-based database injection inline — each needs out-of-band confirmation a single response cannot supply |
| **Inward-facing detections** | Four — prompt-instruction leakage, prompt injection, automated access, credential stuffing — each with a stated false-positive control. Three of the four need the route where the application hands over its own records; automated access also runs inline, once a decoy address is seeded | — | Detecting "human-mimicking bots", single-input evasion, and membership inference. These are documented as permanently lead-only |
| **Social-engineering defence** | Nine offline indicators over an inbound message, a weighted score, five risk bands, a recommendation, and a command that can gate a mail pipeline | Machine-learning or AI classifiers on top are described as what a production deployment adds | Any generation of phishing or impersonation content; detection of faked audio or video |
| **Detection Mirror** | Twelve checks over web access, authentication, and connection logs, each with a benign twin; certificates that re-check offline; downgrade to lead if a certificate fails | Four whole domains (outbound command-and-control, directory/identity, cloud audit, session) are honest placeholders that name the missing data source | Nothing is fabricated for a domain with no log source |
| **Detection engineering** | Sigma-subset rule evaluation over your own logs; gap report; candidate rules for every miss; ATT&CK mapping; its test suite now runs on every proposed change to the product | — | Any working bypass for a named commercial defence product; any evasion recipe; any claim to model a specific log-and-alert platform |
| **Source-code review** | Thirteen built-in patterns, each scoped to the languages it applies to, matched across a default walk of fifteen source-file types and always available; fourteen shipped dataflow rules when Semgrep is present; Joern when provisioned; a Python symbol index; conversion of findings into testable questions; permission gate, kill switch, budget; the AI review step's model call now passes a jurisdiction check before any provider software is loaded; its test suite now runs on every proposed change to the product | Semgrep and Joern must be installed by the deployment; absence is reported, never hidden. The symbol index covers Python only. The jurisdiction tier ships **permissive** by default — it is a control the operator sets, not one the customer inherits | Treating a static finding as proof. Static analysis output is a lead by design |
| **The agent-driven "scan a codebase" route** | The agent's single route to a command line is held for per-call, single-use, owner-signed approval while its other tools run freely; on by default; since 12 August 2026 a wiring failure halts the run rather than silently leaving that surface ungoverned | Requires Docker; the run happens inside a disposable container and produces no re-checkable web report | Treating the agent's output as anything but leads — the machinery that mints a signed proven fact does not run over it |
| **Dependency review** | Vulnerable dependencies are proven by the system's own version comparator against a pinned advisory snapshot, and re-check offline | Saying "no vulnerable dependency" — as opposed to "this one is vulnerable" — needs non-pinned constraints resolved and snapshot coverage recorded; named as outstanding work | Trusting any scanner's own vulnerability match |
| **Fix production** | Propose; apply into a disposable clone; sandbox build; timeout-rejects approval; explicit file staging only; the proposal step's model call — the one carrying real repository source — passes the jurisdiction check, and a refusal degrades to "no proposal" | The leg that raises a real change proposal is off by default and requires multi-signature keys the operator must first provision, plus a repository token — a capability, not a field deployment. The jurisdiction tier ships permissive by default | Applying a fix to a lead. Only proven findings are eligible |
| **TLS and certificates** | Own gated handshake; four deprecated protocols and fourteen weak-cipher markers; broken-hash and undersized-key certificate checks; observed-key fingerprint; quantum-exposure classification; offline re-check; one of only six routes permitted to say CLEAN | Session-bound evidence with a notary co-signature is built and tested, but needs a handshake-participating toolchain and an independent notary operator before it proves producer-unforgeability | Enumerating every legacy cipher a server might accept if asked differently — the limit is registered, not hidden |
| **Connection provenance for cloud credential checks** | A real network binding that derives every connection fact from the connection itself and never from an assertion, with every unestablishable fact defaulting to refusal; exercised against the real GitHub API on 13 August 2026, including live negative controls and an anti-laundering control, with the certificate re-checking offline | The Amazon Web Services row of the same capability is built and unit-tested but has **never** been run against real AWS, and nothing from the GitHub run transfers to it; the metadata-credential capability likewise awaits an operator-provided cloud credential | Obtaining a customer's cloud credentials by any route other than the customer handing them over |
| **Network manners** | Recognisable identifying header forced on, including through the manual replay tool; posture-based pacing; six gates per request; permanently forbidden address ranges; resolve-once-and-pin; certificate checking left on for the system's own outbound calls | — | Stealth, identity rotation, traffic shaping to evade detection. The system is built to be found in your logs |
| **Fix verification** | Four signed answers; controls for liveness, freshness, positive control and repetition; a 13-family allow-list with every exclusion reasoned; a remediation certificate cross-bound to the original proof; a stand-alone third-party verifier needing no product code | Continuous re-proof ships as a one-shot runner plus scheduled-job definitions; it becomes an operating property once the schedule is enabled on a host. A sound "it stopped working" rule for the new cloud and Kubernetes families has not been written, so they cannot be certified this way | Claiming a remediation at the higher freshness level. Once the vulnerable path is removed nothing can travel through it, so the system caps lower and returns INCONCLUSIVE to anyone demanding more. Widening the allow-list to cover the six confirmations added in August — none was added, and the closed list refused them |

The single sentence that connects all four subjects in this chapter: **nothing here asks you
to trust the tool.** A block, a detection, a fix, and a "this is now safe" claim each arrive
with the evidence attached and a repeatable procedure for checking it — and where a claim
cannot be earned that way, the system says so rather than making it.
